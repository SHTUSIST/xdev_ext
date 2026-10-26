# SPDX-License-Identifier: GPL-2.0
"""Independent assertions over real E2 guest artifacts; no mechanism model.

E2_CAPTURE_DIR must contain capture.json and the files it references. Absence
is a failure, never a skip or a synthetic-success fallback. The signature and
literal slot tables here must not be imported by either BPF program.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest


SLOTS = {
    "reverse": (0, 4, 2, 6, 1, 5, 3, 7),
    "gray": (0, 1, 3, 2, 6, 7, 5, 4),
}


def signed_lba(lba):
    """512 bytes, independent per absolute LBA and 32-byte piece."""
    return b"".join(hashlib.sha256(
        b"xdev-ext-e2-lba-v1\0" + struct.pack("<QI", lba, piece)
    ).digest() for piece in range(16))


class GuestCapture(unittest.TestCase):
    def artifact(self, name):
        path = (self.directory / name).resolve()
        self.assertTrue(path.is_relative_to(self.directory), "artifact escapes capture directory")
        self.assertTrue(path.is_file(), f"missing actual artifact: {name}")
        return path.read_bytes()

    def test_actual_bpf_provider_and_successor_bytes(self):
        self.directory = Path(os.environ.get("E2_CAPTURE_DIR", ".missing-e2-capture")).resolve()
        self.assertTrue((self.directory / "capture.json").is_file(),
                        "no E2 guest capture; host callback tests cannot satisfy this gate")
        data = json.loads(self.artifact("capture.json"))
        self.assertEqual(data["schema"], "xdev-ext-e2-v1")
        self.assertEqual(data["evidence_kind"], "guest-correctness")
        self.assertEqual(data["timing_claim"], "none")
        self.assertIn(data["chain"], ("nvme_nic", "nvme_ce_ce_nic"))
        self.assertEqual(set(data["runs"]), set(SLOTS))
        a, b = (data["runs"][v] for v in SLOTS)
        # Compare actual normalized CREATE and policy, not a claimed same_setup bit.
        self.assertEqual(a["configuration"], b["configuration"],
                         "A/B differ outside the loaded BPF object")
        cfg = a["configuration"]
        self.assertRegex(cfg["kernel_git_sha"], r"^[0-9a-f]{40}$")
        for key in ("core_sha256", "nvme_provider_sha256"):
            self.assertRegex(cfg[key], r"^[0-9a-f]{64}$")
        self.assertIsInstance(cfg["create"], dict)
        self.assertTrue(cfg["create"], "normalized CREATE must contain actual fixed fields")
        self.assertIsInstance(cfg["policy"], dict)
        self.assertEqual(cfg["nvme"], {
            "window_slba": 2048, "window_nlb": 64, "group_bytes": 4096,
            "lba_shift": 9, "direction": "read",
        })
        source = self.artifact(data["source"])
        self.assertEqual(source, b"".join(signed_lba(lba) for lba in range(2048, 2112)),
                         "source is not the independent absolute-LBA signature image")
        source_digest = hashlib.sha256(source).hexdigest()
        self.assertEqual(source_digest, cfg["input_sha256"])
        self.assertEqual(a["request_ids"], b["request_ids"], "actual callback IDs differ")
        ids = a["request_ids"]
        self.assertEqual(len(ids), 16)
        self.assertIn(ids[0], (0, 1), "record actual numbering origin; do not silently renumber")
        self.assertEqual(ids, list(range(ids[0], ids[0] + 16)))
        sequences = {}
        for variant, run in data["runs"].items():
            with self.subTest(variant=variant):
                obj = self.artifact(run["bpf_object"])
                self.assertEqual(obj[:4], b"\x7fELF")
                self.assertEqual(obj[5], 1, "expected little-endian BPF ELF")
                self.assertEqual(struct.unpack_from("<H", obj, 18)[0], 247,
                                 "host object is not a BPF target object")
                self.assertEqual(hashlib.sha256(obj).hexdigest(), run["bpf_sha256"])
                self.assertTrue(self.artifact(run["verifier_log"]).strip())
                self.assertGreater(run["program_id"], 0)
                self.assertIs(run["verifier_accepted"], True)
                self.assertTrue(self.artifact(run["raw_trace"]).strip())
                events = json.loads(self.artifact(run["events"]))
                self.assertEqual([e["seq"] for e in events], sorted(set(e["seq"] for e in events)))
                session_id = events[0]["session_id"]
                self.assertGreater(session_id, 0)
                self.assertTrue(all(e["session_id"] == session_id for e in events),
                                "events from another session cannot satisfy this run")
                accepted = [e for e in events if e["event"] == "provider_accept"]
                self.assertEqual([e["request_id"] for e in accepted], ids,
                                 "missing, duplicated, reordered or unaccounted accepted NVMe request")
                expected_slbas = [2048 + 8 * SLOTS[variant][rid & 7] for rid in ids]
                sequences[variant] = [e["slba"] for e in accepted]
                self.assertEqual(sequences[variant], expected_slbas)
                expected_payload = bytearray()
                for rid, slba in zip(ids, expected_slbas):
                    per_request = [e for e in events if e.get("request_id") == rid]
                    names = [e["event"] for e in per_request]
                    self.assertEqual(names, ["class_validate", "provider_accept", "native_complete",
                                             "downstream_complete", "frame_recycle"])
                    validation, accepted_event, completed, downstream, recycled = per_request
                    for event in per_request:
                        self.assertEqual(event["batch_id"], rid,
                                         "callback request_id must be actual batch_id")
                        self.assertTrue(event["frames"], "no actual frame correlation")
                        self.assertEqual(len(event["frames"]), len(event["frame_generations"]))
                        self.assertTrue(all(isinstance(index, int) and index >= 0
                                            for index in event["frames"]))
                        self.assertTrue(all(isinstance(gen, int) and gen >= 0
                                            for gen in event["frame_generations"]))
                    # BUILD validation precedes life acquire and completion_begin.
                    # Link its authorized plan, not an as-yet-unallocated ticket.
                    plan_keys = ("session_id", "batch_id", "request_id", "stage",
                                 "slba", "nlb", "bytes", "direction")
                    self.assertEqual(tuple(validation[key] for key in plan_keys),
                                     tuple(accepted_event[key] for key in plan_keys),
                                     "accepted native request differs from its validated plan")
                    self.assertEqual(validation["ticket"], 0,
                                     "validation must not borrow a future native ticket")
                    self.assertEqual(validation["frames"], accepted_event["frames"])
                    self.assertEqual(validation["result"], 0)
                    self.assertEqual(accepted_event["stage"], 0)
                    # Immutable native-operation identity holds only from the
                    # accepted request to its matching native completion.
                    native_keys = ("session_id", "batch_id", "request_id", "stage", "ticket",
                                   "cookie", "frames", "frame_generations")
                    self.assertEqual(tuple(accepted_event[key] for key in native_keys),
                                     tuple(completed[key] for key in native_keys),
                                     "native completion changed accepted ticket/cookie/frame claim")
                    self.assertGreater(accepted_event["ticket"], 0)
                    self.assertGreater(accepted_event["cookie"], 0)
                    self.assertTrue(all(type(gen) is int and 0 <= gen < (1 << 64)
                                        for gen in accepted_event["frame_generations"]))
                    final_stage = 1 if data["chain"] == "nvme_nic" else 3
                    self.assertEqual(downstream["stage"], final_stage)
                    self.assertEqual(recycled["stage"], final_stage)
                    # Downstream/recycle carry their actual stage-local ticket
                    # and frame generations, not a copy of the NVMe snapshot.
                    self.assertGreater(downstream["ticket"], 0)
                    self.assertGreater(recycled["ticket"], 0)
                    for event in per_request[:2]:
                        self.assertEqual((event["slba"], event["nlb"], event["bytes"], event["direction"]),
                                         (slba, 8, 4096, "read"))
                    expected_payload.extend(b"".join(signed_lba(lba) for lba in range(slba, slba + 8)))
                self.assertEqual(self.artifact(run["sink"]), bytes(expected_payload),
                                 "full independent downstream bytes differ (not a sender-side checksum oracle)")
        self.assertNotEqual(sequences["reverse"], sequences["gray"])
        self.assertNotEqual(a["bpf_sha256"], b["bpf_sha256"])
        # Illegal scratch and stale native completion enter different boundaries.
        negatives = data["negatives"]
        self.assertEqual(set(negatives), {"outside_window", "reserved_cdw2", "old_ticket"})
        for name, errno in (("outside_window", -34), ("reserved_cdw2", -1)):
            negative = negatives[name]
            self.assertEqual(negative["entry"], "class_validate")
            self.assertEqual(negative["result"], errno)
            self.assertEqual(negative["accepted_before"], negative["accepted_after"])
            self.assertTrue(self.artifact(negative["trace"]).strip())
        old = negatives["old_ticket"]
        self.assertEqual(old["entry"], "xdev_ext_mech_batch_complete")
        self.assertNotEqual(old["old_ticket"], old["current_ticket"])
        self.assertIsInstance(old["current_state_before"], dict)
        self.assertTrue(old["current_state_before"], "empty custody snapshot")
        self.assertEqual(old["accepted_before"], old["accepted_after"])
        self.assertEqual(old["current_state_before"], old["current_state_after"])
        self.assertEqual(old["published_before"], old["published_after"])
        self.assertTrue(self.artifact(old["trace"]).strip())


if __name__ == "__main__":
    unittest.main()

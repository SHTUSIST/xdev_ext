# SPDX-License-Identifier: GPL-2.0
"""Synthetic fixture checks of the assertions, never guest execution evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import test_guest_capture as contract


def fixture(directory):
    """Deliberately generated evidence-shaped data to test gate sensitivity."""
    def write(name, payload):
        (directory / name).write_bytes(payload)
        return name

    source = b"".join(contract.signed_lba(lba) for lba in range(2048, 2112))
    configuration = {
        "kernel_git_sha": "a" * 40, "core_sha256": "b" * 64,
        "nvme_provider_sha256": "c" * 64, "input_sha256": hashlib.sha256(source).hexdigest(),
        "create": {"pool": "fixture-only", "depth": 1, "chain": ["nvme", "afxdp"]},
        "policy": {}, "nvme": {"window_slba": 2048, "window_nlb": 64,
                                  "group_bytes": 4096, "lba_shift": 9, "direction": "read"},
    }
    data = {"schema": "xdev-ext-e2-v1", "evidence_kind": "guest-correctness",
            "timing_claim": "none", "chain": "nvme_nic", "source": write("source.bin", source),
            "runs": {}, "negatives": {}}
    for index, (variant, slots) in enumerate(contract.SLOTS.items()):
        # Header-shaped fixture, not a loadable object or verifier evidence.
        elf = bytearray(64)
        elf[:4] = b"\x7fELF"
        elf[5] = 1
        struct.pack_into("<H", elf, 18, 247)
        elf[-1] = index
        events, payload = [], bytearray()
        for rid in range(1, 17):
            slba = 2048 + 8 * slots[rid & 7]
            for name in ("class_validate", "provider_accept", "native_complete",
                         "downstream_complete", "frame_recycle"):
                events.append({"seq": len(events), "event": name, "request_id": rid,
                               "batch_id": rid, "ticket": 100 + rid, "ops_generation": 1,
                               "frames": [0, 1, 2], "slba": slba, "nlb": 8, "bytes": 4096,
                               "direction": "read", "result": 0})
            payload.extend(b"".join(contract.signed_lba(lba) for lba in range(slba, slba + 8)))
        data["runs"][variant] = {
            "configuration": copy.deepcopy(configuration), "request_ids": list(range(1, 17)),
            "bpf_object": write(variant + ".o", bytes(elf)),
            "bpf_sha256": hashlib.sha256(elf).hexdigest(),
            "verifier_log": write(variant + ".verifier", b"SYNTHETIC ASSERTION SELFTEST ONLY\n"),
            "raw_trace": write(variant + ".raw", b"SYNTHETIC ASSERTION SELFTEST ONLY\n"),
            "program_id": index + 1, "verifier_accepted": True,
            "events": write(variant + ".events", json.dumps(events).encode()),
            "sink": write(variant + ".sink", bytes(payload)),
        }
    for name, result in (("outside_window", -34), ("reserved_cdw2", -1)):
        data["negatives"][name] = {
            "entry": "class_validate", "result": result, "accepted_before": 0, "accepted_after": 0,
            "trace": write(name + ".trace", b"SYNTHETIC ASSERTION SELFTEST ONLY\n"),
        }
    data["negatives"]["old_ticket"] = {
        "entry": "xdev_ext_mech_batch_complete", "old_ticket": 1, "current_ticket": 2,
        "accepted_before": 1, "accepted_after": 1, "published_before": 1, "published_after": 1,
        "current_state_before": {"ticket": 2}, "current_state_after": {"ticket": 2},
        "trace": write("old.trace", b"SYNTHETIC ASSERTION SELFTEST ONLY\n"),
    }
    return data


class AssertionSelfcheck(unittest.TestCase):
    def check_capture(self, directory, data):
        (directory / "capture.json").write_text(json.dumps(data))
        with patch.dict(os.environ, {"E2_CAPTURE_DIR": str(directory)}):
            contract.GuestCapture("test_actual_bpf_provider_and_successor_bytes").test_actual_bpf_provider_and_successor_bytes()

    def test_synthetic_fixture_and_required_rejections(self):
        with tempfile.TemporaryDirectory(prefix="e2-assertions-") as temporary:
            directory = Path(temporary)
            good = fixture(directory)
            self.check_capture(directory, good)
            for mutation in ("setup", "source", "sink", "guest_timing", "accepted_slba", "early_recycle", "negative_accept"):
                with self.subTest(mutation=mutation):
                    data = fixture(directory)
                    if mutation == "setup":
                        data["runs"]["gray"]["configuration"]["create"]["depth"] = 2
                    elif mutation in ("source", "sink"):
                        name = data["source"] if mutation == "source" else data["runs"]["gray"]["sink"]
                        raw = bytearray((directory / name).read_bytes())
                        raw[-1] ^= 1
                        (directory / name).write_bytes(raw)
                    elif mutation == "guest_timing":
                        data["timing_claim"] = "performance"
                    elif mutation in ("accepted_slba", "early_recycle"):
                        path = directory / data["runs"]["gray"]["events"]
                        events = json.loads(path.read_text())
                        if mutation == "accepted_slba":
                            events[1]["slba"] += 8
                        else:
                            events[2]["event"], events[4]["event"] = events[4]["event"], events[2]["event"]
                        path.write_text(json.dumps(events))
                    else:
                        data["negatives"]["outside_window"]["accepted_after"] = 1
                    with self.assertRaises(AssertionError):
                        self.check_capture(directory, data)


if __name__ == "__main__":
    unittest.main()

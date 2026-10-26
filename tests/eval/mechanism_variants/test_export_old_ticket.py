# SPDX-License-Identifier: GPL-2.0
"""Exercise the real actual-core old-ticket exporter, without replacement data.

The integration contract requires a usable export from the current kernel and
preservation of an existing evidence directory. Compiler/export failures must
remain failures; they cannot be replaced by fabricated completion snapshots.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
PRODUCT = HERE.parents[2]
KERNEL = PRODUCT / "kernel"
EXPORTER = HERE / "export_old_ticket.py"
STATE_FIELDS = {
    "life_ctrl", "life_phase", "life_refs", "life_busy", "life_owner",
    "life_gen", "valid_len", "completion_ctrl", "completion_result",
    "ticket", "queued", "life_active", "life_token", "frame_custody",
    "present", "status", "retired", "released",
}


class ExportOldTicket(unittest.TestCase):
    def invoke(self, output):
        return subprocess.run(
            [sys.executable, "-B", str(EXPORTER), str(KERNEL), str(output),
             "--cc", "gcc"],
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=60,
        )

    def test_current_core_exports_real_stale_completion_and_source_evidence(self):
        # A generator/shim incompatibility, empty fabricated observation, or
        # changed current custody must prevent a successful evidence export.
        with tempfile.TemporaryDirectory(prefix="e2-old-ticket-test-") as tmp:
            output = Path(tmp) / "new-evidence"
            self.assertFalse(output.exists())
            run = self.invoke(output)
            build_log = output / "build.log"
            diagnostics = run.stdout
            if build_log.is_file():
                diagnostics += "\nActual compiler output:\n" + build_log.read_text()
            self.assertEqual(run.returncode, 0, diagnostics)
            self.assertIn("E2_OLD_TICKET_HOST=PASS", run.stdout)

            negative = json.loads((output / "old_ticket.json").read_text())
            self.assertEqual(negative["entry"], "xdev_ext_mech_batch_complete")
            self.assertEqual(negative["evidence_kind"], "actual-core-host-fixture")
            self.assertGreater(negative["old_ticket"], 0)
            self.assertGreater(negative["current_ticket"], 0)
            self.assertNotEqual(negative["old_ticket"], negative["current_ticket"])
            self.assertEqual(negative["trace"], "old-ticket.log")

            raw = (output / negative["trace"]).read_text()
            snapshots = [json.loads(line.split(" ", 1)[1])
                         for line in raw.splitlines()
                         if line.startswith("E2_OLD_TICKET_SNAPSHOT ")]
            self.assertEqual(len(snapshots), 2, raw)
            self.assertEqual([row["phase"] for row in snapshots], ["before", "after"])
            before, after = snapshots
            self.assertTrue(STATE_FIELDS.issubset(before["state"]))
            self.assertEqual(before["state"], after["state"])
            self.assertEqual(before["state"]["ticket"], negative["current_ticket"])
            for phase, row in zip(("before", "after"), snapshots):
                self.assertEqual(row["old_ticket"], negative["old_ticket"])
                self.assertEqual(row["current_ticket"], negative["current_ticket"])
                self.assertEqual(negative["current_state_" + phase], row["state"])
                self.assertGreater(row["accepted"], 0)
                # The current native request is accepted but its final callback
                # and drain occur after the stale-ticket observation. Publication
                # may still be zero; replay must preserve its actual value.
                self.assertGreaterEqual(row["published"], 0)
                for raw_key, exported_key in (("accepted", "accepted_"),
                                              ("published", "published_")):
                    self.assertEqual(negative[exported_key + phase], row[raw_key])
            self.assertEqual(before["accepted"], after["accepted"])
            self.assertEqual(before["published"], after["published"])

            # Archive the actual generated translation unit, binary, compiler
            # invocation/log and source hashes, rather than only a PASS line.
            cfile = output / "old-ticket-fixture.c"
            binary = output / "old-ticket-fixture"
            self.assertGreater(cfile.stat().st_size, 0)
            self.assertEqual(binary.read_bytes()[:4], b"\x7fELF")
            self.assertTrue(build_log.is_file())
            command = json.loads((output / "command.json").read_text())
            self.assertEqual(command[0], "gcc")
            self.assertIn(str(cfile), command)
            self.assertIn("-o", command)
            self.assertEqual(command[command.index("-o") + 1], str(binary))

            ledger = json.loads((output / "source.json").read_text())
            self.assertEqual(ledger["evidence_kind"], "actual-core-host-fixture")
            expected_sha = subprocess.check_output(
                ["git", "-C", str(PRODUCT), "rev-parse", "HEAD"], text=True,
            ).strip()
            self.assertEqual(ledger["kernel_git_sha"], expected_sha)
            hashes = ledger["source_sha256"]
            self.assertTrue({
                "io_uring/xdev_ext_mech.c",
                "include/linux/xdev_ext_mech.h",
                "include/uapi/linux/xdev_ext_mech.h",
                "tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/recycle_input_test.py",
                "tools/testing/selftests/xdev_ext_mech/fanout_scheduler/run.py",
                "tools/testing/selftests/xdev_ext_mech/fanout_scheduler/fixture.c",
                "tools/testing/selftests/xdev_ext_mech/fanout_scheduler/shim.h",
            }.issubset(hashes))
            for relative, digest in hashes.items():
                path = KERNEL / relative
                self.assertFalse(Path(relative).is_absolute())
                self.assertTrue(path.resolve().is_relative_to(KERNEL.resolve()))
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest,
                                 relative)

    def test_existing_evidence_is_refused_without_changing_any_file(self):
        # Re-running an export must not replace or add files to retained proof.
        with tempfile.TemporaryDirectory(prefix="e2-old-ticket-retain-") as tmp:
            output = Path(tmp) / "existing-evidence"
            output.mkdir()
            (output / "old_ticket.json").write_bytes(b"retained proof\x00\xff\n")
            (output / "nested").mkdir()
            (output / "nested" / "raw.log").write_bytes(b"original raw observation\n")
            before = {p.relative_to(output): p.read_bytes()
                      for p in output.rglob("*") if p.is_file()}
            run = self.invoke(output)
            self.assertNotEqual(run.returncode, 0, run.stdout)
            self.assertIn("refuse existing software-evidence directory", run.stdout)
            after = {p.relative_to(output): p.read_bytes()
                     for p in output.rglob("*") if p.is_file()}
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()

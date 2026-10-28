#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent native-capture C++ API tests; only tracefs mkdir/rmdir mocked."""
from pathlib import Path
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parent


class NativeTraceOwnerTests(unittest.TestCase):
    def run_case(self, name):
        with tempfile.TemporaryDirectory(prefix="c2-native-owner-") as tmp:
            root = Path(tmp)
            binary = root / "capture-test"
            command = ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
                       "-I", str(BASE), str(BASE / "native_trace_owner_test.cc"),
                       str(BASE / "native_trace_owner.cc"), "-Wl,--wrap=mkdir",
                       "-Wl,--wrap=rmdir", "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0,
                             "NativeTraceCapture production implementation missing or invalid:\n" + built.stderr)
            result = subprocess.run([str(binary), name, str(root / "files")],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS " + name, result.stdout)

    def test_private_capture_configuration_and_complete_raw_snapshot(self):
        self.run_case("setup")

    def test_loss_and_missing_per_cpu_stats_never_mean_lossless(self):
        self.run_case("loss")
        self.run_case("missing-stats")

    def test_oversized_raw_trace_is_rejected_without_truncation(self):
        self.run_case("oversize")

    def test_seal_and_explicit_safe_close_preserve_other_instances(self):
        self.run_case("seal")

    def test_destructor_preserves_active_capture_for_held_owner(self):
        self.run_case("destructor")

    def test_invalid_reused_names_and_unavailable_tracefs_fail_closed(self):
        self.run_case("names")
        self.run_case("unavailable")


if __name__ == "__main__":
    unittest.main(verbosity=2)

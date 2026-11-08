#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host checks of the internal CE submission diagnostic (ce_submit_diag.c).

Requirement: the tool builds from the generated view exactly as on the GPU
host, refuses the CPU stand-in and malformed sizes/depths as usage errors,
and without a GPU exits as unavailable without printing any result line.
No GPU, DMA or timing is exercised here.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

for _parent in Path(__file__).resolve().parents:
    if (_parent / "tools/layout.py").is_file():
        sys.path.insert(0, str(_parent / "tools"))
        break
else:
    raise RuntimeError("owned project layout is unavailable")
from layout import canonical_root, materialize_view

ROOT = canonical_root(Path(__file__))


class DiagCommandLine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="ce-submit-diag-", dir=build)
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        view = materialize_view(ROOT, work / "view")
        cls.binary = work / "ce_submit_diag"
        result = subprocess.run(
            ["gcc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             str(view.root / "tests/eval/nvme_gpu/ce_submit_diag.c"),
             str(view.root / "kernel/tools/xdev_ext_gpu_identity.c"),
             "-ldl", "-lpthread", "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=60)
        cls.build_failure = None if result.returncode == 0 else result.stdout + result.stderr

    def run_diag(self, *args):
        self.assertIsNone(self.build_failure, "diagnostic build failed: " + str(self.build_failure))
        return subprocess.run([str(self.binary), *args], capture_output=True,
                              text=True, timeout=20)

    def test_help_lists_every_option(self):
        result = self.run_diag("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for option in ("--ce-dev", "--sizes", "--batches", "--depth", "--reps",
                       "--frame-bytes", "--dir", "--kprobe-profile", "--link-bdf"):
            self.assertIn(option, result.stdout)
        self.assertIn("never a paper result", result.stdout)

    def test_cpu_stand_in_is_refused(self):
        result = self.run_diag("--ce-dev", "/dev/xdev_ext_ce_sim")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("CE_SUBMIT_DIAG ", result.stdout)

    def test_malformed_sizes_and_depth_are_usage_errors(self):
        for args in (("--sizes", "3000"), ("--sizes", "2048"), ("--sizes", "4096,x"),
                     ("--sizes", ""), ("--batches", "4", "--depth", "8"),
                     ("--depth", "0"), ("--depth", "65"), ("--frame-bytes", "6000"),
                     ("--dir", "sideways")):
            with self.subTest(args=args):
                result = self.run_diag(*args)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("CE_SUBMIT_DIAG ", result.stdout)

    def test_without_cuda_or_gpu_nothing_is_reported(self):
        result = self.run_diag("--sizes", "4096", "--batches", "8",
                               "--ce-dev", "/dev/nvidia-does-not-exist")
        self.assertIn(result.returncode, (2, 4), result.stdout + result.stderr)
        self.assertNotIn("CE_SUBMIT_DIAG ", result.stdout)
        self.assertNotIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()

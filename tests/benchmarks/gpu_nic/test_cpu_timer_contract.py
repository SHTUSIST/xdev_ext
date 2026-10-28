#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent CPU planning/command contract; no build, SDK, peer or device."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
for ancestor in HERE.parents:
    choices = (ancestor / "tests/support/benchmarks/test_cpu_timer.py",
               ancestor / "tests/eval/common/test_cpu_timer.py")
    support = next((path for path in choices if path.is_file()), None)
    if support:
        break
else:
    raise RuntimeError("SETUP: CPU timer test support is not mapped")
spec = importlib.util.spec_from_file_location("independent_cpu_timer_test_support", support)
SUPPORT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SUPPORT)

class GpuNicCpuPlanning(SUPPORT.RunnerContract):
    runner = HERE / "run.py"

    def test_all_three_arms_in_both_directions_without_starting_a_peer(self):
        for arm in ("session", "afxdp-cuda", "udp-pinned-cuda"):
            for direction in ("nic-gpu", "gpu-nic"):
                with self.subTest(arm=arm, direction=direction):
                    def options(root):
                        return ["--arms", arm, "--direction", direction, "--sizes", "4096",
                                "--messages", "32", "--depth", "8", "--pairs", "1",
                                "--completion-wait", "block", "--streams", "2",
                                "--ifname", "cpu-no-such-nic", "--local-ip", "192.0.2.1",
                                "--peer-ip", "192.0.2.2", "--peer-mac", "02:00:00:00:00:02",
                                "--ce-dev", "/nonexistent/ce", "--build-dir", str(root / "original-build")]
                    documents, root = self.execute_plan(options)
                    self.assert_cpu_disclosure(documents, root, clock="CLOCK_MONOTONIC")


if __name__ == "__main__":
    unittest.main()

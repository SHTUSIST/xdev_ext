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

class NvmeNicCpuPlanning(SUPPORT.RunnerContract):
    runner = HERE / "run.py"

    def test_four_forward_and_three_reverse_arms(self):
        for direction, arms in (("fwd", ("posix", "uring", "splice", "session")),
                                ("rev", ("posix", "uring", "session"))):
            for arm in arms:
                with self.subTest(direction=direction, arm=arm):
                    def options(root):
                        return ["--direction", direction, "--arms", arm, "--sizes", "4096", "--qd", "8",
                                "--pairs", "2", "--warmup", "1", "--units", "32", "--order-seed", "17",
                                "--window-mib", "8", "--source", "/nonexistent/nvme0n1",
                                "--ng", "/nonexistent/ng0n1", "--ifname", "cpu-no-such-nic",
                                "--peer", "192.0.2.2:47001", "--peer-ip", "192.0.2.2",
                                "--local-ip", "192.0.2.1", "--local-mac", "02:00:00:00:00:01",
                                "--peer-mac", "02:00:00:00:00:02", "--allow-window-write",
                                "--build-dir", str(root / "original-build")]
                    documents, root = self.execute_plan(options)
                    self.assert_cpu_disclosure(documents, root, clock="CLOCK_MONOTONIC_RAW")


if __name__ == "__main__":
    unittest.main()

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

class NvmeGpuCpuPlanning(SUPPORT.RunnerContract):
    runner = HERE / "run.py"

    def test_all_five_arms_in_both_directions(self):
        for arm in ("session", "uring-cuda", "gds-batch", "gds-async", "gds-direct"):
            for direction in ("load", "save"):
                with self.subTest(arm=arm, direction=direction):
                    def options(root):
                        return ["--arms", arm, "--directions", direction, "--sizes", "4096",
                                "--qd", "1" if arm == "gds-direct" else "8", "--pattern", "seq",
                                "--destination", "window" if arm == "gds-direct" else "slot-ring",
                                "--completion-wait", "block", "--passes", "2", "--pairs", "1",
                                "--window-bytes", "4194304", "--directory", str(root),
                                "--build-dir", str(root / "original-build"), "--ng", "/nonexistent/ng0n1",
                                "--ce-dev", "/nonexistent/ce"]
                    documents, root = self.execute_plan(options)
                    self.assert_cpu_disclosure(documents, root, clock="CLOCK_MONOTONIC")

    def test_cpu_flags_do_not_change_original_commands(self):
        spec = importlib.util.spec_from_file_location("cpu_contract_nvme_gpu_runner", self.runner)
        run = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(run)
        for arm in ("session", "uring-cuda", "gds-batch", "gds-async", "gds-direct"):
            for direction in ("load", "save"):
                with self.subTest(arm=arm, direction=direction):
                    base = ["--arms", arm, "--sizes", "4096", "--qd", "1", "--passes", "2",
                            "--streams", "3", "--ng", "/nonexistent/ng0n1", "--ce-dev", "/nonexistent/ce",
                            "--destination", "window", "--completion-wait", "block", "--directory", str(HERE)]
                    before = run.arguments(base)
                    # Only parsing is isolated from hardware. The same real builder must
                    # produce the byte-identical command after measurement CLI options.
                    try:
                        after = run.arguments(base + ["--cpu-set", str(self.online_cpus()[0]),
                                                      "--cpu-output", "/nonexistent/cpu-contract-output"])
                    except SystemExit as error:
                        self.fail("CPU CLI flags rejected before unchanged command construction: exit %s" % error.code)
                    left = run.arm_command(arm, "/original/binary", before, direction, 4096, 1,
                                           "seq", "/original/window", 65536, (2048, 512))
                    right = run.arm_command(arm, "/original/binary", after, direction, 4096, 1,
                                            "seq", "/original/window", 65536, (2048, 512))
                    self.assertEqual(left, right)
                    self.assertNotIn("--cpu-set", right)
                    self.assertNotIn("--cpu-output", right)
                    if arm == "gds-direct":
                        self.assertEqual(right[right.index("--workload")+1],
                                         "llm-load" if direction == "load" else "checkpoint")
                        self.assertEqual(right[right.index("--iterations")+1], "2")


if __name__ == "__main__":
    unittest.main()

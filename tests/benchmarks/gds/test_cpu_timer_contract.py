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

class GdsCpuPlanning(SUPPORT.RunnerContract):
    runner = HERE / "run.py"

    def test_both_workloads_preserve_multichunk_multiiteration_plans(self):
        for workload in ("llm-load", "checkpoint"):
            with self.subTest(workload=workload):
                def options(root):
                    return ["--mode", "cufile-direct", "--workload", workload, "--bytes", "12288",
                            "--chunk", "8192", "--iterations", "2", "--directory", str(root)]
                documents, root = self.execute_plan(options)
                self.assert_cpu_disclosure(documents, root, clock="CLOCK_MONOTONIC")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real runtime-begin C and real FD-check behavior at a fake CUDA boundary.

The old source must explicitly fail missing actual es_ce_runtime_begin.
The fixture never allocates CUDA memory or runs a device/session workload.
"""
from pathlib import Path
import re
import sys
import unittest

for _parent in Path(__file__).resolve().parents:
    if (_parent / "tools/layout.py").is_file():
        sys.path.insert(0, str(_parent / "tools"))
        break
else:
    raise RuntimeError("owned project layout is unavailable")
from layout import canonical_root
ROOT = canonical_root(Path(__file__))
sys.path.insert(0, str(ROOT / "tests/support/benchmarks"))
from ce_vmm_contract import function, runtime


class RuntimeBehavior(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = runtime(ROOT)
        if cls.actual is not None:
            cls.addClassCleanup(cls.actual.close)

    def run_case(self, failure=0, sim=0):
        self.assertIsNotNone(self.actual,
                             "missing actual es_ce_runtime_begin: old-source feature RED")
        return self.actual.run(failure, sim)

    def test_gpu_baseline_includes_real_process_initialization_fd(self):
        record = self.run_case()
        self.assertEqual(record["rc"], 0)
        self.assertGreaterEqual(record["process_fd"], 0)
        self.assertEqual(record["before"], record["initial"] + 1,
                         "the one fixture process FD must precede the baseline")
        self.assertEqual((record["open"], record["symbol"], record["init"], record["close"]),
                         (1, 1, 1, 1))
        self.assertEqual((record["repeat_rc"], record["repeated"], record["after"]),
                         (0, record["before"], record["before"]))

    def test_owned_fd_after_baseline_still_fails_unchanged_fd_checker(self):
        record = self.run_case()
        self.assertEqual((record["clean"], record["leaked"], record["repaired"]), (0, 1, 0),
                         "initialization must not whitelist any later owned fd")

    def test_simulator_never_loads_or_initializes_cuda(self):
        record = self.run_case(sim=1)
        self.assertEqual((record["rc"], record["before"]), (0, record["initial"]))
        self.assertEqual((record["open"], record["symbol"], record["init"], record["close"]),
                         (0, 0, 0, 0))
        self.assertEqual(record["process_fd"], -1)

    def test_dlopen_failure_cannot_supply_a_passing_baseline(self):
        record = self.run_case(failure=1)
        self.assertNotEqual(record["rc"], 0)
        self.assertEqual((record["before"], record["init"], record["close"]), (-1, 0, 0))

    def test_dlsym_failure_closes_library_and_cannot_pass(self):
        record = self.run_case(failure=2)
        self.assertNotEqual(record["rc"], 0)
        self.assertEqual((record["before"], record["init"], record["close"]), (-1, 0, 1))

    def test_init_failure_closes_library_and_cannot_pass(self):
        record = self.run_case(failure=3)
        self.assertNotEqual(record["rc"], 0)
        self.assertEqual((record["before"], record["init"], record["close"]), (-1, 1, 1))

    def test_dlclose_failure_cannot_turn_initialization_into_success(self):
        record = self.run_case(failure=4)
        self.assertNotEqual(record["rc"], 0)
        self.assertEqual((record["before"], record["init"], record["close"]), (-1, 1, 1))


class ArmPlacement(unittest.TestCase):
    def test_actual_arms_initialize_after_valid_parse_before_owned_acquisition(self):
        cases = (
            ("nvme_gpu/session_nvme_ce.c", "sn_parse", ("open(o.file", "open(o.ng", "es_ce_open(")),
            ("gpu_nic/session_gpu_nic.c", "sg_parse", ("sg_if_query(o.ifname", "es_ce_open(", "xp_open(")),
        )
        for path, parse, boundaries in cases:
            with self.subTest(arm=path):
                main = function((ROOT / "tests/benchmarks" / path).read_text(), "main")
                call = re.search(r"ret\s*=\s*es_ce_runtime_begin\s*\(\s*o\.ce_dev\s*,\s*&fd_before\s*\)\s*;", main)
                self.assertIsNotNone(call, "actual arm must call runtime begin, not bypass the new boundary")
                position = call.start()
                self.assertLess(main.index(parse + "("), position)
                self.assertIn("return ret;", main[main.index(parse + "("):position],
                              "invalid parser results must leave before CUDA initialization")
                self.assertNotIn("eval_fd_count(", main[:position],
                                 "the CUDA-before-init snapshot must be removed")
                for boundary in boundaries:
                    self.assertGreater(main.index(boundary), position,
                                       "owned acquisition must remain inside FD scope: " + boundary)
                first_owned = min(main.index(boundary) for boundary in boundaries)
                self.assertRegex(main[call.end():first_owned],
                                 r"if\s*\(ret\)\s*(?:\{\s*)?return\s+ret\s*;",
                                 "failed process initialization must return before acquiring owned resources")
                self.assertIn("eval_fd_check(fd_before)", main[first_owned:],
                              "the original complete owned-FD check must remain")


if __name__ == "__main__":
    unittest.main()

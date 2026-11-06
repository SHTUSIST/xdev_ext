#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Explicit VMM selection for the existing session arm; no device/performance run.

Expected RED on old source: --ce-vmm is rejected, and allocation mode 2 calls
the native helper with no fd attachment. Real parser/helper functions execute;
neither source token assertions nor a copied allocation algorithm supply results.
"""
from pathlib import Path
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
from ce_vmm_contract import helper, parser


class Options(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = parser(ROOT, "nvme_gpu")
        cls.addClassCleanup(cls.actual.close)

    def parse(self, *selection):
        return self.actual.run("--direction", "load", "--ng", "/unused/ng",
                               "--slba", "0", "--lba-size", "512", "--file", "/unused/window",
                               "--ce-dev", "/dev/nvidia0", "--size", "8192", "--qd", "4",
                               "--window-bytes", "65536", *selection)

    def test_explicit_vmm_is_accepted(self):
        result = self.parse("--ce-vmm")
        self.assertEqual((result["rc"], result["vmm"]), (0, 1),
                         "actual NVMe arm must recognize VMM rather than reject its option")

    def test_native_alloc_and_offset_keep_their_meaning(self):
        native = self.parse("--ce-alloc")
        offset = self.parse("--ce-va", "0")
        self.assertEqual((native["rc"], native["alloc"], native["vmm"]), (0, 1, 0))
        self.assertEqual((offset["rc"], offset["alloc"], offset["vmm"]), (0, 0, 0))

    def test_allocation_selections_are_exclusive(self):
        for selection in ((), ("--ce-alloc", "--ce-vmm"),
                          ("--ce-va", "0", "--ce-vmm"),
                          ("--ce-va", "0", "--ce-alloc")):
            with self.subTest(selection=selection):
                self.assertEqual(self.parse(*selection)["rc"], 2)


class ActualCeHelper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = helper(ROOT)
        cls.addClassCleanup(cls.actual.close)

    def run_helper(self, mode, stages=1, fail_attach=0, mismatch=0, fail_close=0, sim=0):
        return self.actual.run(mode, stages, fail_attach, mismatch, fail_close, sim)

    def test_vmm_allocates_once_and_attaches_same_export_to_every_stage(self):
        for stages in (1, 2):
            with self.subTest(stages=stages):
                result = self.run_helper(2, stages)
                self.assertEqual((result["rc"], result["native"], result["vmm"]), (0, 0, 1),
                                 "old bool alloc takes native path for mode 2: intended behavioral RED")
                self.assertEqual((result["attach"], result["attach_bad"]), (stages, 0),
                                 "each CE fd must carry the same export, VA and rounded mapped size")
                self.assertEqual((result["identity"], result["va"], result["len"]),
                                 (stages, 0x200000, 8192))
                self.assertEqual((result["close_rc"], result["retry_rc"], result["close_order"]), (0, 0, 1))
                self.assertEqual((result["closed"], result["remaining"]), (stages, 0))

    def test_native_still_uses_only_existing_native_helper(self):
        result = self.run_helper(1)
        self.assertEqual((result["rc"], result["native"], result["vmm"], result["attach"]), (0, 1, 0, 0))
        self.assertEqual((result["va"], result["len"], result["remaining"]), (0x100000, 8192, 0))

    def test_simulator_still_uses_offset_and_rejects_vmm(self):
        offset = self.run_helper(0, sim=1)
        self.assertEqual((offset["rc"], offset["native"], offset["vmm"], offset["attach"], offset["va"]),
                         (0, 0, 0, 0, 4096))
        refused = self.run_helper(2, sim=1)
        self.assertEqual((refused["rc"], refused["opened"], refused["vmm"]), (2, 0, 0))

    def test_mismatched_stage_device_is_refused_before_allocation_or_attach(self):
        result = self.run_helper(2, stages=2, mismatch=1)
        self.assertEqual((result["rc"], result["native"], result["vmm"], result["attach"]), (4, 0, 0, 0))
        self.assertEqual((result["closed"], result["remaining"]), (2, 0))

    def test_partial_attach_failure_closes_setup_resources_without_create(self):
        for failed_stage in (1, 2):
            with self.subTest(failed_stage=failed_stage):
                result = self.run_helper(2, stages=2, fail_attach=failed_stage)
                self.assertEqual((result["rc"], result["attach"], result["attach_bad"]),
                                 (4, failed_stage, 0))
                self.assertEqual((result["close_rc"], result["closed"], result["remaining"], result["close_order"]),
                                 (0, 2, 0, 1))

    def test_cuda_cleanup_error_retains_ownership_for_retry(self):
        result = self.run_helper(2, stages=2, fail_close=1)
        self.assertEqual((result["rc"], result["vmm"]), (0, 1))
        self.assertEqual((result["close_rc"], result["owned_after_fail"]), (-5, 1))
        self.assertEqual((result["retry_rc"], result["closed"], result["remaining"], result["close_order"]),
                         (0, 2, 0, 1))


if __name__ == "__main__":
    unittest.main()

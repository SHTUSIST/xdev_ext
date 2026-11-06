#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise the actual GPU NIC session parser; no GPU, NIC or timed campaign."""
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
from ce_vmm_contract import parser


class Options(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = parser(ROOT, "gpu_nic")
        cls.addClassCleanup(cls.actual.close)

    def parse(self, direction, *selection):
        return self.actual.run("--direction", direction, "--ifname", "unused0",
                               "--ce-dev", "/dev/nvidia0", "--size", "4096",
                               "--messages", "8", "--depth", "4", "--wire-session", "270019",
                               "--local-ip", "192.0.2.2", "--peer-ip", "192.0.2.1",
                               "--local-port", "12345", "--peer-port", "54321",
                               "--peer-mac", "02:00:00:00:00:01", "--local-mac", "02:00:00:00:00:02",
                               *selection)

    def test_explicit_vmm_is_accepted_in_both_directions(self):
        for direction in ("ingest", "egress"):
            with self.subTest(direction=direction):
                result = self.parse(direction, "--ce-vmm")
                self.assertEqual((result["rc"], result["vmm"]), (0, 1),
                                 "actual GPU NIC arm must accept explicit VMM selection")

    def test_existing_native_and_offset_choices_remain_distinct(self):
        for direction in ("ingest", "egress"):
            native = self.parse(direction, "--ce-alloc")
            offset = self.parse(direction, "--ce-va", "0")
            self.assertEqual((native["rc"], native["alloc"], native["vmm"]), (0, 1, 0))
            self.assertEqual((offset["rc"], offset["alloc"], offset["vmm"]), (0, 0, 0))

    def test_conflicting_or_missing_choices_are_usage_errors(self):
        for direction in ("ingest", "egress"):
            for selection in ((), ("--ce-alloc", "--ce-vmm"),
                              ("--ce-va", "0", "--ce-vmm"),
                              ("--ce-va", "0", "--ce-alloc")):
                with self.subTest(direction=direction, selection=selection):
                    self.assertEqual(self.parse(direction, *selection)["rc"], 2)


if __name__ == "__main__":
    unittest.main()

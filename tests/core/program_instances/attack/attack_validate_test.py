#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests for attack_validate.py, the independent whole-disk oracle.

The images here are built from the test's stated layout, not from the
validator. A correct run must PASS; every way an attacker byte, a misplaced or
misordered victim group, or a wrong detach outcome could land on the
destination disk must FAIL. Run: python3 -I attack_validate_test.py
"""
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATOR = os.path.join(HERE, "attack_validate.py")

LBA = 512
GROUP = 4096
GROUPS = 8
WIN = GROUPS * GROUP              # bytes of one 64-LBA window
WIN_NLB = WIN // LBA
SPAN = 4 << 20                    # whole image
GUARD = 0x6B
DETACH_DONE = 2                   # groups the detach attacker completes
CASES = ("reserved", "outside", "outside-after", "frame", "verdict", "user-stall", "detach")
DETACH = CASES.index("detach")
SEED = 0x5EED1234


def source_image(seed=SEED):
    words = bytearray(SPAN)
    for o in range(0, SPAN, 8):
        low = ((o // LBA) << 7) | (((o % LBA) // 8) << 1) | 1
        struct.pack_into("<II", words, o, low, seed)
    return bytes(words)


def attacker_win(c):
    return 3 * c * WIN


def victim_win(c):
    return (3 * c + 1) * WIN


def spare_win(c):
    return (3 * c + 2) * WIN


def victim_src(c):
    return 2 * c * WIN


def attacker_src(c):
    return (2 * c + 1) * WIN


def expected_destination(src, detach_slots=(0, 1)):
    d = bytearray([GUARD]) * SPAN
    for c in range(len(CASES)):
        d[victim_win(c):victim_win(c) + WIN] = src[victim_src(c):victim_src(c) + WIN]
    for g in detach_slots:
        a, s = attacker_win(DETACH) + g * GROUP, attacker_src(DETACH) + g * GROUP
        d[a:a + GROUP] = src[s:s + GROUP]
    return d


class ValidatorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.src = source_image()
        cls.src_path = os.path.join(cls.tmp.name, "source-before.raw")
        with open(cls.src_path, "wb") as f:
            f.write(cls.src)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_validator(self, dest, src_path=None):
        path = os.path.join(self.tmp.name, "destination.raw")
        with open(path, "wb") as f:
            f.write(bytes(dest))
        r = subprocess.run([sys.executable, "-I", VALIDATOR, src_path or self.src_path, path],
                           capture_output=True, text=True)
        os.unlink(path)
        return r.returncode, r.stdout

    def assert_pass(self, dest):
        code, out = self.run_validator(dest)
        self.assertEqual(code, 0, out)
        self.assertIn('"state": "PASS"', out)

    def assert_fail(self, dest, what, src_path=None):
        code, out = self.run_validator(dest, src_path)
        self.assertNotEqual(code, 0, "%s was accepted: %s" % (what, out))
        self.assertNotIn('"state": "PASS"', out, what)

    def test_correct_run_passes(self):
        self.assert_pass(expected_destination(self.src))

    def test_detach_slots_other_than_first_two_pass(self):
        # Unordered completion: any DETACH_DONE slots, each at its own place.
        self.assert_pass(expected_destination(self.src, detach_slots=(3, 6)))

    def test_attacker_source_in_each_victim_window_fails(self):
        # What an accepted OUTSIDE SQE (or any cross-window write) would leave:
        # the attacker's own source bytes over one victim group.
        for c in range(len(CASES)):
            for g in (0, GROUPS - 1):
                d = expected_destination(self.src)
                v, a = victim_win(c) + g * GROUP, attacker_src(c) + g * GROUP
                d[v:v + GROUP] = self.src[a:a + GROUP]
                self.assert_fail(d, "attacker source in victim window case %d group %d" % (c, g))

    def test_victim_groups_reversed_fails(self):
        d = expected_destination(self.src)
        v, s = victim_win(1), victim_src(1)
        for g in range(GROUPS):
            r = GROUPS - 1 - g
            d[v + g * GROUP:v + (g + 1) * GROUP] = self.src[s + r * GROUP:s + (r + 1) * GROUP]
        self.assert_fail(d, "reversed victim groups")

    def test_victim_window_from_another_source_position_fails(self):
        # The reviewer's reproduction: source groups from LBA 1000, reversed.
        d = expected_destination(self.src)
        v = victim_win(1)
        for g in range(GROUPS):
            s = 1000 * LBA + (GROUPS - 1 - g) * GROUP
            d[v + g * GROUP:v + (g + 1) * GROUP] = self.src[s:s + GROUP]
        self.assert_fail(d, "victim window filled from LBA 1000")

    def test_victim_data_in_another_cases_victim_window_fails(self):
        d = expected_destination(self.src)
        d[victim_win(2):victim_win(2) + WIN] = self.src[victim_src(1):victim_src(1) + WIN]
        self.assert_fail(d, "case 1 victim bytes in case 2 victim window")

    def test_detach_group_at_wrong_slot_fails(self):
        d = expected_destination(self.src, detach_slots=(0,))
        a, s = attacker_win(DETACH) + 2 * GROUP, attacker_src(DETACH) + 1 * GROUP
        d[a:a + GROUP] = self.src[s:s + GROUP]
        self.assert_fail(d, "detach group 1 written at slot 2")

    def test_detach_count_not_exact_fails(self):
        self.assert_fail(expected_destination(self.src, detach_slots=(0,)), "one detach group")
        self.assert_fail(expected_destination(self.src, detach_slots=(0, 1, 2)), "three detach groups")
        self.assert_fail(expected_destination(self.src, detach_slots=()), "no detach group")

    def test_detach_partial_group_fails(self):
        d = expected_destination(self.src)
        a = attacker_win(DETACH) + 4 * GROUP
        d[a:a + LBA] = self.src[attacker_src(DETACH) + 4 * GROUP:attacker_src(DETACH) + 4 * GROUP + LBA]
        self.assert_fail(d, "half-written detach group")

    def test_byte_in_attacker_or_spare_window_fails(self):
        for off in (attacker_win(0) + 17, attacker_win(5) + 4095, spare_win(3), SPAN - 1):
            d = expected_destination(self.src)
            d[off] ^= 0x01
            self.assert_fail(d, "changed byte at %d" % off)

    def test_source_image_off_formula_is_rejected(self):
        bad = bytearray(self.src)
        bad[victim_src(4) + 100] ^= 0x10
        path = os.path.join(self.tmp.name, "bad-source.raw")
        with open(path, "wb") as f:
            f.write(bytes(bad))
        self.assert_fail(expected_destination(bytes(bad)), "source off the formula", path)
        os.unlink(path)

    def test_short_image_is_rejected(self):
        self.assert_fail(expected_destination(self.src)[:SPAN // 2], "short destination")


if __name__ == "__main__":
    unittest.main()

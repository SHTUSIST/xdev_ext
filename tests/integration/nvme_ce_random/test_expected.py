#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Frozen independent whole-allocation oracle requirements; no device execution."""
import sys
import unittest
import importlib.util
from pathlib import Path

expected = None
expected_error = None
try:
    source = Path(__file__).with_name('expected.py')
    if source.is_file():
        spec = importlib.util.spec_from_file_location('random_independent_expected', source)
        expected = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(expected)
except Exception as error:
    expected_error = error


class ExpectedContract(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(expected, 'missing feature: independent whole-allocation replay')

    def test_load_guards_holes_and_phase_repeat(self):
        rows = [dict(key=100, phase=0, nvme_offset=4, gpu_offset=1, bytes=3),
                dict(key=101, phase=1, nvme_offset=10, gpu_offset=1, bytes=3)]
        self.assertEqual(expected.load_image(b'GGabcdefghHH', b'0123456789ABCDEF', rows, 2),
                         b'GGaABCefghHH')

    def test_save_uses_independent_gpu_source_and_preserves_disk_holes(self):
        rows = [dict(key=100, phase=0, nvme_offset=4, gpu_offset=1, bytes=3),
                dict(key=101, phase=1, nvme_offset=4, gpu_offset=4, bytes=3)]
        self.assertEqual(expected.save_image(b'0123456789ABCDEF', b'GGabcdefghHH', rows, 2),
                         b'0123efg789ABCDEF')

    def test_compare_checks_every_guard_hole_and_payload_byte(self):
        want = b'GGaABCefghHH'
        self.assertEqual(expected.compare(want, want),
                         dict(equal=True, mismatch_count=0, first_mismatch=None))
        for index in (0, 2, 4, 8, 11):
            got = bytearray(want)
            got[index] ^= 1
            self.assertEqual(expected.compare(bytes(got), want),
                             dict(equal=False, mismatch_count=1, first_mismatch=index))
        with self.assertRaises(ValueError):
            expected.compare(want[:-1], want)

    def test_model_does_not_clip_invalid_intervals(self):
        for gpu in (-1, 8, (1 << 64)-1):
            rows = [dict(key=100, phase=0, nvme_offset=0, gpu_offset=gpu, bytes=3)]
            with self.assertRaises(ValueError):
                expected.load_image(b'GGabcdefghHH', b'0123456789ABCDEF', rows, 2)

    def test_fixture_source_patterns_frozen_by_absolute_byte_position(self):
        self.assertEqual(expected.gpu_initial(4), bytes((0x5a, 0x7f, 0xa4, 0xc9)))
        self.assertEqual(expected.disk_initial(4), bytes((0x93, 0xa4, 0xb5, 0xc6)))

    def test_fixture_distinguishes_megabyte_source_addresses(self):
        for generator in (expected.gpu_initial, expected.disk_initial):
            image = generator(1048584)
            self.assertNotEqual(image[:8], image[1048576:1048584])


if __name__ == '__main__':
    try:
        if expected_error is not None:
            raise expected_error
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ExpectedContract))
        status = 0 if result.wasSuccessful() else 1
        if result.errors:
            status = 2
    except Exception as error:
        print('SETUP: ' + str(error), file=sys.stderr)
        status = 2
    raise SystemExit(status)

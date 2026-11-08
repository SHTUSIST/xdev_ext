#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject stale, misplaced or torn data after reuse of the same UMEM frame."""
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
V = runpy.run_path(str(HERE / 'window_validate.py'))
GROUP = 4096
WIN = 32768
SPAN = 4 << 20


def images(old_landed=False):
    source = V['expected_source'](0x1234abcd)
    dest = bytearray([0x6b]) * SPAN
    if old_landed:
        dest[:GROUP] = source[:GROUP]
    dest[WIN:WIN + GROUP] = source[WIN:WIN + GROUP]
    return source, dest, bytearray([0x3c]) * SPAN


class ReuseOracle(unittest.TestCase):
    def state(self, source, dest, aux):
        self.assertIn('validate_reuse', V, 'frame-reuse whole-disk oracle is missing')
        return V['validate_reuse'](bytes(source), bytes(dest), bytes(aux))['state']

    def test_old_write_not_landed(self):
        self.assertEqual(self.state(*images()), 'PASS')

    def test_old_write_landed_only_in_its_first_group(self):
        self.assertEqual(self.state(*images(True)), 'PASS')

    def test_stale_old_frame_data_in_new_write(self):
        s, d, a = images()
        d[WIN:WIN + GROUP] = s[:GROUP]
        self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_missing_new_write(self):
        s, d, a = images()
        d[WIN:WIN + GROUP] = bytes([0x6b]) * GROUP
        self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_new_write_wrong_group(self):
        s, d, a = images()
        d[WIN:WIN + GROUP] = s[WIN + GROUP:WIN + 2 * GROUP]
        self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_new_write_torn(self):
        s, d, a = images()
        d[WIN + 511] ^= 1
        self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_old_write_torn(self):
        s, d, a = images(True)
        d[511] ^= 1
        self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_old_write_from_new_source(self):
        s, d, a = images()
        d[:GROUP] = s[WIN:WIN + GROUP]
        self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_only_first_group_of_each_window_may_change(self):
        for off in (GROUP, WIN - 1, WIN + GROUP, 2 * WIN, SPAN - 1):
            with self.subTest(off=off):
                s, d, a = images()
                d[off] ^= 1
                self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_source_must_remain_position_unique(self):
        s, d, a = images()
        s[GROUP + 7] ^= 1
        self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_aux_must_remain_untouched(self):
        s, d, a = images()
        a[SPAN - 1] ^= 1
        self.assertEqual(self.state(s, d, a), 'FAIL')

    def test_all_images_must_have_exact_size(self):
        for index in range(3):
            with self.subTest(image=index):
                value = list(images())
                value[index] = value[index][:-1]
                self.assertEqual(self.state(*value), 'FAIL')

    def test_cli_pass_and_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp) / name for name in ('source', 'dest', 'aux')]
            data = images()
            for path, content in zip(paths, data):
                path.write_bytes(content)
            cmd = [sys.executable, '-I', str(HERE / 'window_validate.py'), '--frame-reuse',
                   *map(str, paths)]
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            paths[1].write_bytes(bytes([0x6b]) * SPAN)
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 1)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fault-inject the independently reconstructed whole-image oracle."""
from pathlib import Path
import tempfile
import unittest
from ordered_frames_validate import validate


class WholeImage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.before = Path(self.tmp.name) / 'before'
        self.after = Path(self.tmp.name) / 'after'
        # C guest uses a formula; this fixture instead creates each complete
        # allocation frame and takes explicit span slices in exact order.
        frames = [bytes(((0x43 + 37 * i + 11 * j + 19 * (j >> 8)) & 255)
                        for j in range(4096)) for i in range(16)]
        disk = bytearray([0x6b] * 65536)
        self.before.write_bytes(disk)
        ordered = b''.join(frames[i][512:3584] for i in [7, 3, 9, 1, 7, 3, 9, 1, 7, 3, 9, 1])
        disk[4096:4096 + len(ordered)] = ordered
        self.disk = disk
        self.after.write_bytes(disk)

    def test_exact_all_bytes(self):
        self.assertEqual(validate(self.before, self.after, 8)['whole_image_bytes'], 65536)

    def test_one_wrong_payload_byte_rejected(self):
        self.disk[4096 + 3072 + 33] ^= 1
        self.after.write_bytes(self.disk)
        with self.assertRaisesRegex(ValueError, 'within output=True'):
            validate(self.before, self.after, 8)

    def test_one_nonselected_disk_byte_rejected(self):
        self.disk[-1] ^= 1
        self.after.write_bytes(self.disk)
        with self.assertRaisesRegex(ValueError, 'within output=False'):
            validate(self.before, self.after, 8)

    def test_wrong_selected_frame_order_rejected(self):
        self.disk[4096:7168], self.disk[7168:10240] = self.disk[7168:10240], self.disk[4096:7168]
        self.after.write_bytes(self.disk)
        with self.assertRaises(ValueError):
            validate(self.before, self.after, 8)

    def test_missing_recycle_cycle_rejected(self):
        self.disk[4096 + 5 * 6144:4096 + 6 * 6144] = bytes([0x6b] * 6144)
        self.after.write_bytes(self.disk)
        with self.assertRaises(ValueError):
            validate(self.before, self.after, 8)

    def test_truncated_image_rejected(self):
        self.after.write_bytes(self.disk[:-4096])
        with self.assertRaisesRegex(ValueError, 'same nonzero'):
            validate(self.before, self.after, 8)


if __name__ == '__main__':
    unittest.main(verbosity=2)

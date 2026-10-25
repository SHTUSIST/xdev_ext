#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests of user_validate.py: CRC32C, the expected destination and the
log rules, on synthetic inputs. Nothing here runs a guest."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import user_validate as v  # noqa: E402

GOOD = '\n'.join(['ok 1 - x', *('XDEV_EXT_USER_CASE=PASS case=' + c for c in v.CASES), *v.MARKERS]) + '\n'


class Validate(unittest.TestCase):
    def test_crc32c_check_value(self):
        self.assertEqual(v.crc32c(b'123456789'), 0xE3069283)
        self.assertEqual(v.crc32c(b''), 0)

    def test_expected_destination(self):
        source = v.pattern('source', v.DISK_BYTES)
        expected = v.expected_destination(source)
        dst, src, group, groups = v.SEAL
        frame = expected[dst * v.LBA:dst * v.LBA + v.FRAME]
        self.assertEqual(frame[:-4], source[src * v.LBA:src * v.LBA + v.FRAME - 4])
        self.assertEqual(int.from_bytes(frame[-4:], 'little'), v.crc32c(frame[:-4]))
        dst, src, group, groups, failed = v.COPIES['deadline']
        self.assertEqual(expected[dst * v.LBA + 3 * group:dst * v.LBA + 4 * group], bytes([v.GUARD]) * group)
        self.assertEqual(expected[dst * v.LBA + 2 * group:dst * v.LBA + 3 * group],
                         source[src * v.LBA + 2 * group:src * v.LBA + 3 * group])
        for start, nlb in v.UNTOUCHED.values():
            self.assertEqual(expected[start * v.LBA:(start + nlb) * v.LBA], bytes([v.GUARD]) * nlb * v.LBA)
        self.assertEqual(expected[:2048 * v.LBA], bytes([v.GUARD]) * 2048 * v.LBA)

    def test_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            v.make_images(tmp)
            self.assertIn('differs', v.check_images(tmp))
            source = (Path(tmp) / 'source.raw').read_bytes()
            (Path(tmp) / 'destination.raw').write_bytes(bytes(v.expected_destination(source)))
            self.assertIsNone(v.check_images(tmp))
            bad = bytearray(v.expected_destination(source))
            bad[12288 * v.LBA] ^= 1
            (Path(tmp) / 'destination.raw').write_bytes(bytes(bad))
            self.assertIn('lba 12288', v.check_images(tmp))

    def test_log(self):
        self.assertEqual(v.check_log(GOOD), [])
        self.assertTrue(v.check_log(GOOD.replace('case=kill\n', 'case=kil\n')))
        self.assertTrue(v.check_log(GOOD + 'not ok 2 - y\n'))
        self.assertTrue(v.check_log(GOOD + '[ 1.0] WARNING: CPU: 0 PID: 1 at x\n'))
        self.assertTrue(v.check_log(GOOD + '[ 1.0] BUG: KASAN: slab-use-after-free in x\n'))
        self.assertTrue(v.check_log(GOOD + 'WARNING: possible circular locking dependency detected\n'))


if __name__ == '__main__':
    unittest.main(verbosity=2)

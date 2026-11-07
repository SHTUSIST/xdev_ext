#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Additional native layout qualification; original expected tests stay frozen."""
import unittest
from test_expected import expected, expected_error


class NativeWindowBounds(unittest.TestCase):
    def test_roundup_padding_is_guarded_outside_authorized_window(self):
        rows=[dict(key=100,phase=0,nvme_offset=4,gpu_offset=1,bytes=3)]
        self.assertEqual(expected.load_image(b'GGabcdefghHHpp',b'DD0123456789ABCDEFZZ',rows,2,
                         window_length=8,disk_guard=2,disk_window_length=16),b'GGa456efghHHpp')
        self.assertEqual(expected.save_image(b'DD0123456789ABCDEFZZ',b'GGabcdefghHHpp',rows,2,
                         window_length=8,disk_guard=2,disk_window_length=16),b'DD0123bcd789ABCDEFZZ')
        rows[0]['gpu_offset']=8;rows[0]['bytes']=1
        with self.assertRaises(ValueError):
            expected.load_image(b'GGabcdefghHHpp',b'DD0123456789ABCDEFZZ',rows,2,
                                window_length=8,disk_guard=2,disk_window_length=16)

    def test_disk_guards_do_not_expand_storage_authority(self):
        rows=[dict(key=100,phase=0,nvme_offset=16,gpu_offset=0,bytes=1)]
        with self.assertRaises(ValueError):
            expected.save_image(b'DD0123456789ABCDEFZZ',b'GGabcdefghHHpp',rows,2,
                                window_length=8,disk_guard=2,disk_window_length=16)

    def test_undefined_samephase_overlap_is_not_replayed_as_last_writer(self):
        rows=[dict(key=100,phase=0,nvme_offset=0,gpu_offset=0,bytes=3),
              dict(key=101,phase=0,nvme_offset=4,gpu_offset=2,bytes=3)]
        with self.assertRaises(ValueError):
            expected.load_image(b'GGabcdefghHH',b'0123456789ABCDEF',rows,2)


if __name__=='__main__':
    try:
        if expected_error is not None: raise expected_error
        if expected is None: raise ValueError('missing actual expected module')
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeWindowBounds))
        code=2 if result.errors else 0 if result.wasSuccessful() else 1
    except Exception as error:
        print('SETUP:',error)
        code=2
    raise SystemExit(code)

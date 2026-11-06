#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The reset-recovery host oracle rejects every single-defect console."""
from pathlib import Path
import importlib.util
import unittest

spec = importlib.util.spec_from_file_location('reset_validate', Path(__file__).resolve().parent / 'reset_validate.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def console(cases=oracle.CASES):
    lines = ['XDEV_EXT_RESET_GUEST_BEGIN']
    for name, count in cases:
        lines += ['ok %d - %s: check %d' % (i, name, i) for i in range(1, count + 1)]
        lines.append('XDEV_EXT_PEER_RESET_CASE=%s PASS checks=%d' % (name, count))
    lines += [oracle.UNLOAD_MARKER, 'XDEV_EXT_RESET_GUEST_EXIT=0', 'XDEV_EXT_RESET_DMESG_BEGIN',
              '[    1.0] nvme nvme0: 4/0/0 default/read/poll queues', 'XDEV_EXT_RESET_DMESG_END']
    return '\n'.join(lines) + '\n'


class ResetOracle(unittest.TestCase):
    def test_complete_console_passes(self):
        self.assertEqual(oracle.check_log(console())['checks'], 47)

    def rejects(self, text):
        with self.assertRaises(ValueError):
            oracle.check_log(text)

    def test_not_ok(self):
        self.rejects(console().replace('ok 13 - error-status: check 13',
                                       'not ok 13 - error-status: check 13', 1))

    def test_failed_case_verdict(self):
        self.rejects(console().replace('XDEV_EXT_PEER_RESET_CASE=owner-open PASS checks=11',
                                       'XDEV_EXT_PEER_RESET_CASE=owner-open FAIL', 1))

    def test_missing_case(self):
        self.rejects(console(oracle.CASES[:2] + oracle.CASES[3:]))

    def test_reordered_cases(self):
        self.rejects(console((oracle.CASES[1], oracle.CASES[0]) + oracle.CASES[2:]))

    def test_skipped_check(self):
        self.rejects(console().replace('ok 7 - error-status: check 7\n', '', 1))

    def test_count_mismatch(self):
        self.rejects(console().replace('timeout-cancel PASS checks=11', 'timeout-cancel PASS checks=10', 1))

    def test_skip_directive(self):
        self.rejects(console().replace('ok 3 - control: check 3', 'ok 3 - control: check 3 # SKIP', 1))

    def test_module_still_loaded(self):
        self.rejects(console().replace(oracle.UNLOAD_MARKER + '\n', '', 1))

    def test_guest_exit(self):
        self.rejects(console().replace('XDEV_EXT_RESET_GUEST_EXIT=0', 'XDEV_EXT_RESET_GUEST_EXIT=1', 1))

    def test_kasan_report(self):
        self.rejects(console().replace('XDEV_EXT_RESET_DMESG_END',
                                       'BUG: KASAN: slab-use-after-free in xdev_ext_peer_unpin\nXDEV_EXT_RESET_DMESG_END', 1))

    def test_kernel_warning(self):
        self.rejects(console().replace('XDEV_EXT_RESET_DMESG_END',
                                       'WARNING: CPU: 1 PID: 7 at io_uring/xdev_ext_peer.c:400\nXDEV_EXT_RESET_DMESG_END', 1))


if __name__ == '__main__':
    unittest.main()

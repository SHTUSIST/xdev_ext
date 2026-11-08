#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual libxdev_ext close/free boundary under ASan/UBSan, no devices."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[2] / 'kernel'


class SessionCleanup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = HERE / 'build'
        build.mkdir(exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(prefix='session-close-', dir=build)
        cls.bin = Path(cls.tmp.name) / 'check'
        lib = KERNEL / 'tools/xdev_ext_mech/lib'
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                   '-no-pie', '-ffunction-sections', '-fdata-sections', '-I' + str(KERNEL),
                   str(HERE / 'test_session_cleanup.c'), str(lib / 'xdev_ext_session.c'),
                   *[str(KERNEL / 'tools' / name) for name in
                     ('xdev_ext_xsk_shared.c', 'xdev_ext_xsk_steer.c', 'xdev_ext_xsk_redirect.c')],
                   '-Wl,--gc-sections', '-Wl,--wrap=dlclose', '-lbpf', '-lelf', '-lz', '-ldl',
                   '-o', str(cls.bin)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.bin), name], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_success_frees_handle_without_reading_it(self):
        self.scenario('success')

    def test_retained_close_preserves_owners_and_can_retry(self):
        self.scenario('retained')

    def test_eagain_keeps_live_handle_without_retained_flag(self):
        self.scenario('eagain')

    def test_released_error_is_preserved_after_handle_freed(self):
        self.scenario('released-error')

    def test_never_created_handle_is_freed(self):
        self.scenario('uncreated')

    def test_absent_session_is_safe(self):
        self.scenario('none')

    def test_retained_session_keeps_cuda_ce_and_control_until_retry(self):
        self.scenario('resources-retained')

    def test_eagain_session_keeps_cuda_ce_and_control_until_retry(self):
        self.scenario('resources-eagain')

    def test_rx_retained_keeps_control_after_tx_closed(self):
        self.scenario('mixed-rx')

    def test_resources_without_session_close_once(self):
        self.scenario('resources-none')

    def test_cuda_close_error_preserves_window_for_retry(self):
        self.scenario('cuda-retry')


if __name__ == '__main__':
    unittest.main()

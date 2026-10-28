#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host regression of run_procs; no guest/device/DMA claim."""
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import unittest

import lib_validate as v


class ProcessBarrierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        guest = Path(__file__).resolve().parent
        kernel = guest.parents[4]
        build_root = Path(os.environ.get('XDEV_EXT_TEST_TMPDIR', guest / '.build'))
        build_root.mkdir(parents=True, exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(prefix='iou-procs-', dir=build_root)
        cls.binary = Path(cls.tmp.name) / 'iou_procs_test'
        subprocess.run(shlex.split(os.environ.get('CC', 'gcc')) + [
            '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-ffunction-sections', '-fdata-sections', f'-I{kernel}',
            f'-I{kernel / "tools/xdev_ext_mech/lib"}', str(guest / 'iou_procs_test.c'),
            '-Wl,--gc-sections', '-pthread', '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_mode(self, mode):
        p = subprocess.Popen([str(self.binary), mode], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            output, _ = p.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            output, _ = p.communicate()
            self.fail(f'{mode}: coordinator did not bound/reap children:\n{output}')
        print(output, end='')
        self.assertEqual(p.returncode, 0, output)
        return output.splitlines()

    def test_two_created_sessions_before_start(self):
        lines = self.run_mode('ok')
        v.check_iou_exact(lines, next(p for p in v.IOU_PLANS if p['kind'] == 'procs'))

    def test_strictly_serial_creates_cannot_pass(self):
        self.run_mode('serial')

    def test_create_failure_does_not_release_peer(self):
        self.run_mode('fail')

    def test_child_exit_does_not_release_peer(self):
        self.run_mode('exit')

    def test_stalled_setup_is_bounded_and_reaped(self):
        self.run_mode('stall')

    def test_duplicate_identity_does_not_release(self):
        self.run_mode('duplicate')


if __name__ == '__main__':
    unittest.main()

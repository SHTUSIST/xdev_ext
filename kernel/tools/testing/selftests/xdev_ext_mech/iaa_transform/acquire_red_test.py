#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Pre-feature regression: execute the unchanged production acquisition path.

IAA transforms read source bytes regardless of the transform's output direction.
This deliberately diagnoses the old single-set interface before implementing the
separate destination lease. The C fixture supplies only kernel boundary types.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def function(text, name):
    m = re.search(r'^\w[^;{}]*\b' + name + r'\([^;{}]*\)\n\{\n.*?^\}', text, re.M | re.S)
    if not m:
        raise RuntimeError('missing production function: ' + name)
    return m[0]


class AcquisitionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = Path(os.environ.get('XDEV_EXT_IAA_ACQUIRE_SOURCE', ROOT / 'io_uring/xdev_ext_mech.c')).read_text()
        source = (HERE / 'acquire_fixture.c').read_text()
        for name in ('xdev_ext_mech_life_undo', 'xdev_ext_mech_life_acquire'):
            source = source.replace('/* ' + name + ' */', function(text, name))
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev_ext-iaa-acquire-')
        cls.addClassCleanup(cls.tmp.cleanup)
        path = Path(cls.tmp.name)
        (path / 'probe.c').write_text(source)
        cls.probe = path / 'probe'
        build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                '-I' + str(ROOT), str(path / 'probe.c'), '-o', str(cls.probe)],
                               capture_output=True, text=True)
        if build.returncode:
            raise RuntimeError(build.stdout + build.stderr)

    def run_case(self, case):
        run = subprocess.run([str(self.probe), case], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_transform_source_is_a_consumer_even_for_from_device_stage(self):
        self.run_case('consumer')

    def test_transform_source_valid_length_is_checked_before_acceptance(self):
        self.run_case('short_source')

    def test_to_device_transform_also_acquires_read_only_source(self):
        self.run_case('to_device')

    def test_short_second_source_rolls_back_first_acquisition(self):
        self.run_case('short_second')

    def test_busy_second_source_rolls_back_first_acquisition(self):
        self.run_case('busy_second')

    def test_source_generation_exhaustion_is_rejected(self):
        self.run_case('saturated')

    def test_ordinary_from_device_producer_semantics_are_preserved(self):
        self.run_case('ordinary_producer')


if __name__ == '__main__':
    unittest.main(verbosity=2)

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
import sys

HERE = Path(__file__).resolve().parent
for _base in (HERE, *HERE.parents):
    if (_base / 'view.json').is_file() or (_base / 'source-layout.json').is_file():
        _shared = _base / 'tests/compute/transform_source.py'
        if not _shared.is_file():
            raise RuntimeError('missing owned transform source helper')
        sys.path.insert(0, str(_shared.parent))
        break
else:
    raise RuntimeError('missing owned checkout/view')
from transform_source import TransformSource, read_native, select_core, owned_dependency, source_root, verify_entry, compiler_headers  # noqa: E402
verify_entry(__file__, 'tests/compute/iaa/transform/acquire_red_test.py')
ROOT = source_root(__file__, os.environ.get('KERNEL_SRC'))


def function(text, name):
    m = re.search(r'^\w[^;{}]*\b' + name + r'\([^;{}]*\)\n\{\n.*?^\}', text, re.M | re.S)
    if not m:
        raise RuntimeError('missing production function: ' + name)
    return m[0]


def session_helpers(text, bodies, extractor=function):
    """Follow actual session-helper calls; a called missing definition is fatal."""
    helpers = ('xdev_ext_mech_session_stage_role', 'xdev_ext_mech_session_rows',
               'xdev_ext_mech_session_chain_refs', 'xdev_ext_mech_session_start_queue_check')
    bodies, selected = list(bodies), set()
    for _ in helpers:
        for name in helpers:
            if name not in selected and any(re.search(r'\b' + name + r'\s*\(', body) for body in bodies):
                bodies.append(extractor(text, name))
                selected.add(name)
    return [name for name in helpers if name in selected]


class AcquisitionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = select_core(ROOT, os.environ.get('XDEV_EXT_IAA_ACQUIRE_SOURCE'))
        source = owned_dependency(__file__, 'tests/compute/iaa/transform/acquire_fixture.c').read_text()
        names = ('xdev_ext_mech_life_undo', 'xdev_ext_mech_batch_acquire')
        names = session_helpers(text, [function(text, name) for name in names]) + list(names)
        for name in names:
            source = source.replace('/* ' + name + ' */', function(text, name))
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev_ext-iaa-acquire-')
        cls.addClassCleanup(cls.tmp.cleanup)
        path = Path(cls.tmp.name)
        include_root = compiler_headers(ROOT, path / 'qualified-include', source)
        (path / 'probe.c').write_text(source)
        cls.probe = path / 'probe'
        build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                '-I' + str(include_root), str(path / 'probe.c'), '-o', str(cls.probe)],
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

    def test_consumer_last_generation_preserves_generation(self):
        self.run_case('saturated')

    def test_ordinary_from_device_producer_semantics_are_preserved(self):
        self.run_case('ordinary_producer')


if __name__ == '__main__':
    unittest.main(verbosity=2)

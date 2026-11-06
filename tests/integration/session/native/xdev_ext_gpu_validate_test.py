#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Console oracle of the real-GPU guest cases."""

import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location('gpu_validate', HERE / 'xdev_ext_gpu_validate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CASES = ('ce-chain-d', 'ce-chain-a', 'peer-nvme', 'dmabuf-peer')


def console(results=None, modules='PASS', unload='XDEV_EXT_GPU_UNLOAD=PASS', extra=''):
    results = dict.fromkeys(CASES, 'PASS') if results is None else results
    failed = sum(value != 'PASS' for value in results.values())
    lines = ['[    1.0] boot',
             f'XDEV_EXT_GPU_MODULES={modules} release=590.48.01 device=10de:2b85 bdf=0000:01:00.0']
    lines += [f'XDEV_EXT_GPU_CASE name={name} result={value} bytes=32768'
              for name, value in results.items()]
    lines.append(f'XDEV_EXT_GPU_GUEST={"PASS" if not failed else "FAIL"} failed={failed}')
    lines.append(extra)
    lines.append(unload)
    return '\n'.join(lines) + '\n'


class GpuConsole(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_all_cases_and_clean_unload_pass(self):
        result = self.mod.validate(console(), release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'PASS')
        self.assertEqual(result['cases'], dict.fromkeys(CASES, 'PASS'))

    def test_failed_case_is_reported_by_name(self):
        text = console(dict(zip(CASES, ('PASS', 'PASS', 'FAIL', 'PASS'))))
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual(result['cases']['peer-nvme'], 'FAIL')
        self.assertIn('peer-nvme', ' '.join(result['problems']))

    def test_missing_case_line_fails(self):
        text = console({'ce-chain-d': 'PASS', 'ce-chain-a': 'PASS', 'peer-nvme': 'PASS'})
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual(result['cases']['dmabuf-peer'], 'MISSING')

    def test_unclean_unload_fails_even_when_cases_pass(self):
        text = console(unload='XDEV_EXT_GPU_UNLOAD=FAIL module=nvidia refcnt=1 holders=')
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertFalse(result['unload_clean'])

    def test_wrong_release_or_device_fails(self):
        for kwargs in (dict(release='595.99.02', device='10de:2b85'),
                       dict(release='590.48.01', device='10de:2bb1')):
            with self.subTest(**kwargs):
                self.assertEqual(self.mod.validate(console(), **kwargs)['verdict'], 'FAIL')

    def test_module_load_failure_fails(self):
        text = 'XDEV_EXT_GPU_MODULES=FAIL step=insmod-nvidia release=590.48.01\nXDEV_EXT_GPU_UNLOAD=PASS\n'
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual(result['modules'], 'FAIL')

    def test_gpu_fault_reports_fail(self):
        for line in ('NVRM: Xid (PCI:0000:01:00): 31, pid=12, name=ctl, Ch 00000008',
                     'NVRM: RmInitAdapter failed! (0x22:0x56:885)',
                     'NVRM: GPU 0000:01:00.0: RmInitAdapter failed!'):
            with self.subTest(line=line):
                result = self.mod.validate(console(extra=line), release='590.48.01',
                                           device='10de:2b85')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertTrue(result['gpu_errors'])

    def test_duplicate_case_line_fails(self):
        text = console() + 'XDEV_EXT_GPU_CASE name=ce-chain-a result=PASS\n'
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')

    def test_prefixed_tool_output_is_not_mistaken_for_verdicts(self):
        text = console({'ce-chain-d': 'PASS', 'ce-chain-a': 'PASS', 'peer-nvme': 'PASS'})
        text += 'XDEV_EXT_GPU_LOG peer: XDEV_EXT_GPU_CASE name=dmabuf-peer result=PASS\n'
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['cases']['dmabuf-peer'], 'MISSING')


if __name__ == '__main__':
    unittest.main()

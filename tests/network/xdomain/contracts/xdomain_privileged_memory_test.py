#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""X7 privileged uninitialized-stack generation and receipt contract.

Plan/requirement: rename both uninitialized local-buffer cases to explicit
privileged ALLOW, retaining 41 cases and the other memory DENY boundaries; keep
the generated buffers genuinely uninitialized with the exact info/verdict kfunc
sizes; reject receipts using the old misleading DENY names. This is a generator
and inventory contract, never proof that an actual kernel verifier ran.
"""
import json
from pathlib import Path
import re
import runpy
import unittest

GUEST = Path(__file__).resolve().parent.parent / 'xdomain/guest'
RENAMES = {
    'memory-uninit-info-deny': 'memory-uninit-info-privileged-allow',
    'memory-uninit-verdict-deny': 'memory-uninit-verdict-privileged-allow',
}


class PrivilegedMemory(unittest.TestCase):
    def inventory(self):
        return json.loads((GUEST / 'cases.json').read_text())['cases']

    def desired_names(self):
        return [RENAMES.get(row['name'], row['name']) for row in self.inventory()]

    @staticmethod
    def receipt(names):
        return '\n'.join('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name for name in names) + '\n'

    def test_inventory_keeps_41_cases_with_explicit_privileged_allow_and_other_denials(self):
        rows = self.inventory()
        names = [row['name'] for row in rows]
        self.assertEqual(len(names), 41)
        self.assertEqual(len(set(names)), 41)
        by_name = {row['name']: row['expected'] for row in rows}
        for old, new in RENAMES.items():
            with self.subTest(case=new):
                self.assertNotIn(old, by_name, 'misleading uninitialized-stack DENY name remains')
                self.assertEqual(by_name.get(new), 'ALLOW')
        for name in ('memory-ctx-write-deny', 'memory-oob-info-deny', 'memory-oob-verdict-deny',
                     'memory-readonly-map-info-deny', 'memory-readonly-map-verdict-deny'):
            self.assertEqual(by_name.get(name), 'DENY', 'other memory safety boundaries must remain')
        for name in ('memory-initialized-local-info-allow', 'memory-initialized-local-verdict-allow'):
            self.assertEqual(by_name.get(name), 'ALLOW')

    def test_generator_preserves_truly_uninitialized_complete_buffers_and_correct_kfunc_sizes(self):
        source = runpy.run_path(str(GUEST / 'generate.py'))['source']
        for name, kind, words, size in (
                ('memory-uninit-info-privileged-allow', 'info', 32, 256),
                ('memory-uninit-verdict-privileged-allow', 'verdict', 8, 64)):
            with self.subTest(case=name):
                generated = source(name)
                self.assertRegex(generated, r'__u64\s+v\s*\[\s*' + str(words) + r'\s*\]\s*;')
                self.assertNotRegex(generated, r'__u64\s+v\s*\[[^\]]+\]\s*=')
                self.assertNotRegex(generated, r'\bmemset\s*\(\s*v\s*,')
                self.assertRegex(generated, r'bpf_xdev_ext_xdomain_' + kind +
                                 r'\s*\(\s*mctx\s*,\s*v\s*,\s*' + str(size) + r'\s*\)')
                self.assertIn('SEC("struct_ops/probe_complete")', generated)
                self.assertIn('.complete = (void *)probe_complete', generated)

    def test_required_receipt_inventory_uses_only_new_names(self):
        required = runpy.run_path(str(GUEST / 'verdict.py'))['REQUIRED']
        self.assertEqual(len(required), 41)
        self.assertTrue(set(RENAMES.values()) <= set(required), 'new privileged ALLOW cases are not required')
        self.assertFalse(set(RENAMES) & set(required), 'old misleading DENY cases are still required')

    def test_receipt_accepts_complete_new_41_case_inventory(self):
        validate = runpy.run_path(str(GUEST / 'verdict.py'))['validate']
        names = self.desired_names()
        try:
            result = validate(self.receipt(names))
        except ValueError as error:
            self.fail('complete privileged ALLOW inventory was rejected: ' + str(error))
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(set(result['cases']), set(names))

    def test_receipt_rejects_old_misleading_deny_names(self):
        validate = runpy.run_path(str(GUEST / 'verdict.py'))['validate']
        desired = self.desired_names()
        reverse = {new: old for old, new in RENAMES.items()}
        for obsolete in (set(reverse), {next(iter(reverse))}, {list(reverse)[1]}):
            names = [reverse[name] if name in obsolete else name for name in desired]
            with self.subTest(obsolete=sorted(obsolete)), self.assertRaises(ValueError):
                validate(self.receipt(names))


if __name__ == '__main__':
    unittest.main(verbosity=2)

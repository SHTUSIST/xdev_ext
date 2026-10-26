#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Partition typed backing diagnostics without weakening native command audit.

Requirement/plan: start from the existing independent one-command positive
fixture; add each explicitly allowed origin-U backing phase to its bound pool;
require unchanged native counts/bindings and a separate complete raw receipt.
Then corrupt origin/phase/ABI/width/status and remove actual K commands. Metadata
must neither satisfy native commands nor bypass the existing parser validation.
These parser selfchecks do not establish complete DMA mapping or device evidence.
"""
import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_driver_audit as existing
from test_decode import row

PHASES = ('pool_bind', 'region_span', 'dma_span', 'dma_seal')
POOL = 9000


class BackingDiagnostics(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('driver_backing_audit', HERE / 'driver_audit.py')
        self.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.driver)
        self.commands = existing.Driver().positive()

    def backing(self, phase, timestamp=12):
        return (row(phase, 0, 0, 0, POOL, stage=0, ts=timestamp)
                .replace('origin=K', 'origin=U')
                .replace('session_id=7', 'session_id=0')
                .replace('class_id=3', 'class_id=2')
                .replace('batch_id=1', 'batch_id=0')
                .replace('batch_key=1', 'batch_key=0'))

    def journal(self, diagnostics, commands=None):
        lines = (self.commands if commands is None else commands).splitlines()
        return '\n'.join([lines[0], *diagnostics, *lines[1:]])

    def test_typed_backing_rows_have_separate_raw_receipts_and_no_native_credit(self):
        baseline = self.driver.audit(self.commands, 7)
        diagnostics = [self.backing(phase, 11 + i) for i, phase in enumerate(PHASES)]
        journal = self.journal(diagnostics)
        try:
            result = self.driver.audit(journal, 7)
        except ValueError as error:
            self.fail('valid typed backing diagnostics must be partitioned, not rejected: ' + str(error))
        self.assertEqual(result['native_submits'], 1)
        self.assertEqual(result['native_completes'], 1)
        coordinates = {'bind_raw_line', 'submit_raw_line', 'complete_raw_line'}
        def identity(binding):
            return {key: value for key, value in binding.items() if key not in coordinates}
        self.assertEqual([identity(binding) for binding in result['bindings']],
                         [identity(binding) for binding in baseline['bindings']],
                         'backing metadata must not alter actual K command identity/address/length/sequence')
        # Four rows were inserted immediately after descriptor_bind. Coordinates
        # must point into this new input, never retain obsolete baseline lines.
        original = self.commands.splitlines()
        expected_coordinates = {'bind_raw_line': (1, original[0]),
                                'submit_raw_line': (6, original[1]),
                                'complete_raw_line': (7, original[2])}
        raw_lines = journal.splitlines()
        for binding in result['bindings']:
            for field, (number, raw) in expected_coordinates.items():
                self.assertEqual(binding[field], number, 'wrong input coordinate: ' + field)
                self.assertEqual(raw_lines[binding[field] - 1], raw,
                                 field + ' must resolve to the exact original K/bind row')
        receipts = result['excluded_backing_diagnostics']
        self.assertEqual(len(receipts), 4)
        by_raw = {receipt['raw']: receipt for receipt in receipts}
        self.assertEqual(set(by_raw), set(diagnostics), 'raw diagnostics must survive unchanged')
        for phase, raw in zip(PHASES, diagnostics):
            receipt = by_raw[raw]
            self.assertEqual(receipt['origin'], 'U')
            self.assertEqual(receipt['phase'], phase)
            self.assertEqual(receipt['pool'], POOL)
            self.assertIsInstance(receipt['reason'], str)
            self.assertTrue(receipt['reason'].strip(), 'exclusion requires an explicit reason')

    def test_backing_exclusion_does_not_hide_bad_origin_phase_abi_width_or_status(self):
        for phase in PHASES:
            valid = self.backing(phase)
            corruptions = {
                'kernel-origin': valid.replace('origin=U', 'origin=K'),
                'unknown-origin': valid.replace('origin=U', 'origin=X'),
                'unknown-phase': valid.replace('phase=' + phase, 'phase=other_backing'),
                'user-submit': valid.replace('phase=' + phase, 'phase=native_submit'),
                'user-complete': valid.replace('phase=' + phase, 'phase=native_complete'),
                'bad-abi': valid.replace('abi=xdev-native-v1-nvme-xsk-batch', 'abi=unknown'),
                'u64-overflow': valid.replace('cookie=9000', 'cookie=18446744073709551616'),
                'u32-overflow': valid.replace('stage=0', 'stage=4294967296'),
                'nonnumeric': valid.replace('cookie=9000', 'cookie=invalid'),
                'not-accepted': valid.replace('accepted=1', 'accepted=0'),
                'failed-status': valid.replace('status=0', 'status=-5'),
                'positive-status': valid.replace('status=0', 'status=5'),
                'signed-overflow': valid.replace('status=0', 'status=-2147483649'),
            }
            for problem, corrupt in corruptions.items():
                with self.subTest(phase=phase, problem=problem), self.assertRaises(ValueError):
                    self.driver.audit(self.journal([corrupt]), 7)

    def test_metadata_never_replaces_missing_kernel_submit_or_complete(self):
        diagnostics = [self.backing(phase) for phase in PHASES]
        for missing in ('native_submit', 'native_complete'):
            commands = '\n'.join(line for line in self.commands.splitlines()
                                 if 'phase=' + missing + ' ' not in line)
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                self.driver.audit(self.journal(diagnostics, commands), 7)

    def test_backing_exclusion_preserves_kernel_command_validation(self):
        diagnostics = [self.backing(phase) for phase in PHASES]
        for problem in ('failed-complete', 'changed-address', 'duplicate-submit'):
            lines = self.commands.splitlines()
            if problem == 'failed-complete':
                lines = [line.replace('status=0', 'status=-5')
                         if 'phase=native_complete ' in line else line for line in lines]
            elif problem == 'changed-address':
                lines = [line.replace('address=32774', 'address=9999')
                         if 'phase=native_complete ' in line else line for line in lines]
            else:
                lines.append(lines[1])
            with self.subTest(problem=problem), self.assertRaises(ValueError):
                self.driver.audit(self.journal(diagnostics, '\n'.join(lines)), 7)


if __name__ == '__main__':
    unittest.main(verbosity=2)

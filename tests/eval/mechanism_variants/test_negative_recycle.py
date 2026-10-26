# SPDX-License-Identifier: GPL-2.0
"""Parser selfchecks: rejection cleanup is not physical DMA acceptance evidence.

Requirement: accept complete, identity-matched recycling after class rejection,
while rejecting unsafe native operations and corrupt/incomplete cleanup cohorts.
Plan: hand-build the recorded lifecycle shape, check acceptance, then mutate one
identity, cohort, payload span, or ordering constraint at a time. No DMA is run.
"""
import importlib.util
from pathlib import Path
import unittest

from test_decode import row


HERE = Path(__file__).resolve().parent


def changed(line, **fields):
    """Change complete trace tokens, without substring/prefix substitutions."""
    return ' '.join(
        f'{part.split("=", 1)[0]}={fields[part.split("=", 1)[0]]}'
        if '=' in part and part.split('=', 1)[0] in fields else part
        for part in line.split()
    )


def lifecycle(status=-34, records=True):
    """Three rejected frames; validation address/bytes describe the NVMe command."""
    result = []
    phases = [('record_admit', 10), ('class_validate', 20),
              ('frame_recycle', 30), ('record_terminal', 40)]
    for phase, timestamp in phases:
        if not records and phase.startswith('record_'):
            continue
        for ordinal, (frame, length, offset) in enumerate(
                [(2048, 1432, 0), (2049, 1432, 1432), (2050, 1232, 2864)]):
            rejecting = phase == 'class_validate'
            code = status if phase in ('class_validate', 'record_terminal') else 0
            result.append(changed(
                row(phase, frame, 0, 0, 0, status=code,
                    ts=timestamp + ordinal),
                accepted=0 if rejecting else 1,
                address=2120 if rejecting else frame * 4096 + 360,
                bytes=4096 if rejecting else length,
                aux=1794 if rejecting else 0,
            ) + f' frame_ordinal={ordinal} frame_offset={offset} frame_length={length}')
    return result


class NegativeRecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('negative_decoder', HERE / 'decode_trace.py')
        cls.decoder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.decoder)

    def decode(self, lines):
        return self.decoder.decode_negative('\n'.join(lines))

    def assert_rejected(self, lines):
        with self.assertRaises(ValueError):
            self.decode(lines)

    def accepted_rejection(self, lines):
        try:
            return self.decode(lines)
        except ValueError as error:
            self.fail(f'valid rejection cleanup was refused: {error}')

    def test_matched_recycle_keeps_rejection_and_zero_native_acceptance(self):
        for status in (-34, -1):
            for records in (False, True):
                with self.subTest(status=status, records=records):
                    result = self.accepted_rejection(lifecycle(status, records))
                    self.assertEqual(result['result'], status)
                    self.assertEqual(result['accepted_during_capture'], 0)

    def test_equal_phase_timestamps_are_allowed(self):
        result = self.accepted_rejection([changed(line, ts_ns=100) for line in lifecycle()])
        self.assertEqual(result['result'], -34)
        self.assertEqual(result['accepted_during_capture'], 0)

    def test_legacy_validation_only_remains_supported(self):
        lines = [line for line in lifecycle() if 'phase=class_validate ' in line]
        result = self.decode(lines)
        self.assertEqual(result['result'], -34)
        self.assertEqual(result['accepted_during_capture'], 0)

    def test_cleanup_must_match_every_identity_field(self):
        for field, value in (
                ('session_id', 8), ('batch_id', 2), ('batch_key', 2),
                ('frame_id', 2051), ('generation', 1), ('stage', 1),
                ('class_id', 2), ('ticket', 1), ('cookie', 1), ('origin', 'U')):
            with self.subTest(field=field):
                lines = lifecycle()
                lines[6] = changed(lines[6], **{field: value})
                self.assert_rejected(lines)

    def test_cleanup_requires_success_and_complete_unique_cohort(self):
        for field, value in (('status', -1), ('accepted', 0), ('accepted', 2)):
            with self.subTest(field=field, value=value):
                lines = lifecycle()
                lines[6] = changed(lines[6], **{field: value})
                self.assert_rejected(lines)
        lines = lifecycle()
        for phase, start in (('admit', 0), ('validate', 3), ('recycle', 6), ('terminal', 9)):
            with self.subTest(missing=phase):
                self.assert_rejected(lines[:start] + lines[start + 1:])
            with self.subTest(duplicate=phase):
                self.assert_rejected(lines[:start] + [lines[start]] + lines[start:])

    def test_record_cohorts_match_cleanup_identity_span_and_outcome(self):
        for index in (0, 6, 9):
            for field, value in (
                    ('session_id', 8), ('batch_id', 2), ('batch_key', 2),
                    ('frame_id', 2051), ('generation', 1), ('stage', 1),
                    ('class_id', 2), ('ticket', 1), ('cookie', 1),
                    ('address', 8388969), ('bytes', 1431),
                    ('frame_ordinal', 1), ('frame_offset', 1), ('frame_length', 1431)):
                with self.subTest(index=index, field=field):
                    lines = lifecycle()
                    lines[index] = changed(lines[index], **{field: value})
                    self.assert_rejected(lines)
        lines = lifecycle()
        lines[9] = changed(lines[9], status=-1)
        self.assert_rejected(lines)

    def test_cleanup_cannot_hide_successful_class_validation(self):
        for fields in ({'accepted': 1}, {'accepted': 1, 'status': 0}):
            with self.subTest(fields=fields):
                lines = lifecycle()
                lines[3] = changed(lines[3], **fields)
                self.assert_rejected(lines)

    def test_lifecycle_timestamps_must_follow_rejection_then_cleanup(self):
        for index, timestamp in ((0, 21), (6, 19), (9, 29)):
            with self.subTest(index=index):
                lines = lifecycle()
                lines[index] = changed(lines[index], ts_ns=timestamp)
                self.assert_rejected(lines)

    def test_cleanup_never_permits_unknown_or_native_operations(self):
        for phase in ('unknown_cleanup', 'native_submit', 'native_complete'):
            for accepted, status in ((1, 0), (0, -1)):
                with self.subTest(phase=phase, accepted=accepted):
                    lines = lifecycle()
                    lines.append(changed(row(phase, 2048, 0, 0, 0, ts=50),
                                         accepted=accepted, status=status))
                    self.assert_rejected(lines)


if __name__ == '__main__':
    unittest.main()

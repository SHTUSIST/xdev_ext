#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent synthetic regressions for the existing CREATE diagnostic.

These fixtures are parser tests, not target execution or DMA evidence.
Contract: results/E2-session-bind-red/contract.md, frozen before this file.
"""
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import decode_trace as decoder


def trace_row(**changes):
    fields = dict(abi='xdev-native-v1-nvme-xsk-batch', phase='session_bind',
                  origin='K', session_id=7, batch_id=0, batch_key=0,
                  frame_id=0, generation=0, stage=0, ticket=0, class_id=0,
                  accepted=1, status=0, cookie=140737488355328, address=0,
                  bytes=2, aux=0, sequence=0, ts_ns=1,
                  origin_tgid=512, process_start_ticks=12345,
                  native_user_data=0, frame_ordinal=0, frame_offset=0,
                  frame_length=0)
    fields.update(changes)
    return ' worker-512 [001] ... 1.0: native_event: ' + ' '.join(
        f'{key}={value}' for key, value in fields.items())


def lifecycle(final_stage=1, frames=(8, 9)):
    """Hand-specified five-phase NVMe READ lifecycle with one fixed cohort."""
    lines = []
    phases = [('class_validate', 0, 0, 0, 0),
              ('native_submit', 0, 1, 10, 4096),
              ('native_complete', 0, 1, 10, 4096),
              ('downstream_complete', final_stage, 2, 11, 0),
              ('frame_recycle', final_stage, 2, 11, 0)]
    for index, (phase, stage, generation, ticket, cookie) in enumerate(phases):
        for ordinal, frame in enumerate(frames):
            lines.append(trace_row(
                phase=phase, batch_id=1, batch_key=1, frame_id=frame,
                generation=generation, stage=stage, ticket=ticket,
                class_id=3 if stage == 0 else 2, cookie=cookie,
                address=2080 if stage == 0 else frame * 4096 + 88,
                bytes=4096 if stage == 0 else 2048,
                aux=2 | (7 << 8), ts_ns=1000 * (index + 1) + ordinal,
                origin_tgid=0, process_start_ticks=0))
    return '\n'.join(lines)


def rejection():
    return '\n'.join(trace_row(
        phase='class_validate', batch_id=1, batch_key=1, frame_id=frame,
        class_id=3, accepted=0, status=-34, cookie=0, address=2080,
        bytes=4096, aux=2 | (7 << 8), ts_ns=1000 + frame,
        origin_tgid=0, process_start_ticks=0) for frame in (8, 9))


class SessionBind(unittest.TestCase):
    def decode(self, raw, chain='nvme_nic', audit=None):
        return decoder.decode(raw, chain, session_id=7, audit=audit)

    def test_valid_bind_is_audited_without_becoming_a_lifecycle_phase(self):
        for chain, final_stage in [('nvme_nic', 1), ('nvme_ce_ce_nic', 3)]:
            with self.subTest(chain=chain):
                baseline = self.decode(lifecycle(final_stage), chain)
                audit = {}
                events = self.decode(trace_row() + '\n' + lifecycle(final_stage), chain, audit)
                self.assertEqual([e['event'] for e in events], [
                    'class_validate', 'provider_accept', 'native_complete',
                    'downstream_complete', 'frame_recycle'])
                self.assertEqual([e['frames'] for e in events], [[8, 9]] * 5)
                self.assertEqual([{k: v for k, v in e.items() if k != 'raw_lines'} for e in events],
                                 [{k: v for k, v in e.items() if k != 'raw_lines'} for e in baseline])
                bind_audit = [e for e in audit['excluded'] if e.get('phase') == 'session_bind']
                self.assertEqual(len(bind_audit), 1)
                self.assertEqual(bind_audit[0]['raw_line'], 1)
                self.assertTrue(bind_audit[0]['reason'])
                self.assertTrue(all(1 not in e['raw_lines'] for e in events))

    def test_bind_frame_count_boundary_is_not_a_stage_count(self):
        for count in (1, 32):
            with self.subTest(count=count):
                events = self.decode(trace_row(bytes=count) + '\n' +
                                     lifecycle(3, tuple(range(8, 8 + count))),
                                     'nvme_ce_ce_nic')
                self.assertEqual(len(events[0]['frames']), count)

    def test_legacy_capture_does_not_require_bind_or_optional_creator_fields(self):
        self.assertEqual(len(self.decode(lifecycle())), 5)
        bind = trace_row().split(' origin_tgid=', 1)[0]
        self.assertEqual(len(self.decode(bind + '\n' + lifecycle())), 5)

    def test_bind_does_not_turn_negative_rejection_into_native_acceptance(self):
        audit = {}
        result = decoder.decode_negative(trace_row() + '\n' + rejection(), 7, audit)
        self.assertEqual((result['result'], result['accepted_during_capture']), (-34, 0))
        self.assertEqual(result['raw_lines'], [2, 3])
        self.assertEqual(audit['excluded'][0]['phase'], 'session_bind')
        self.assertEqual(audit['excluded'][0]['raw_line'], 1)

    def test_nonzero_zero_initialized_fields_are_rejected(self):
        for field in ('batch_id', 'batch_key', 'frame_id', 'generation',
                      'stage', 'ticket', 'class_id', 'address', 'aux', 'sequence',
                      'native_user_data', 'frame_ordinal', 'frame_offset', 'frame_length'):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.decode(trace_row(**{field: 1}) + '\n' + lifecycle())

    def test_bind_failure_unknown_origin_or_unknown_phase_is_rejected(self):
        mutants = [dict(accepted=0), dict(status=-5), dict(status=1),
                   dict(origin='U'), dict(origin='arbitrary'),
                   dict(phase='session_bind_unknown'), dict(phase='unknown')]
        for fields in mutants:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    self.decode(trace_row(**fields) + '\n' + lifecycle())

    def test_zero_overflow_and_cohort_mismatched_counts_are_rejected(self):
        for count in (0, 1, 3, 33, 4294967296):
            with self.subTest(count=count):
                with self.assertRaises(ValueError):
                    self.decode(trace_row(bytes=count) + '\n' + lifecycle())

    def test_invalid_cookie_and_optional_creator_fields_are_rejected(self):
        for fields in [dict(cookie=0), dict(cookie=-1), dict(cookie=1 << 64),
                       dict(origin_tgid=0), dict(origin_tgid='bad'),
                       dict(origin_tgid=1 << 32), dict(process_start_ticks=-1),
                       dict(process_start_ticks='bad'), dict(process_start_ticks=1 << 64)]:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    self.decode(trace_row(**fields) + '\n' + lifecycle())

    def test_duplicate_bind_is_rejected_even_when_identical(self):
        for duplicate in (trace_row(), trace_row(cookie=8192, ts_ns=2)):
            with self.subTest(duplicate=duplicate):
                with self.assertRaises(ValueError):
                    self.decode(trace_row() + '\n' + duplicate + '\n' + lifecycle())

    def test_different_session_bind_is_excluded_with_scope_audit(self):
        audit = {}
        events = self.decode(trace_row(session_id=99) + '\n' + lifecycle(), audit=audit)
        self.assertEqual(len(events), 5)
        self.assertEqual(audit['excluded'][0]['session_id'], 99)
        self.assertEqual(audit['excluded'][0]['raw_line'], 1)
        self.assertIn('session', audit['excluded'][0]['reason'])
        with self.assertRaises(ValueError):
            self.decode(trace_row(session_id=99))

    def test_valid_bind_cannot_hide_class_failure_or_incomplete_lifecycle(self):
        original = lifecycle().splitlines()
        mutants = [lifecycle().replace('class_id=3', 'class_id=0', 1),
                   lifecycle().replace('status=0', 'status=-5', 1),
                   '\n'.join(original[:-1]),
                   lifecycle() + '\n' + trace_row(phase='future_diagnostic')]
        for raw in mutants:
            with self.subTest(raw=raw[-100:]):
                with self.assertRaises(ValueError):
                    self.decode(trace_row() + '\n' + raw)

    def test_negative_bind_validation_stays_strict(self):
        for bind in (trace_row(status=-5), trace_row(class_id=3),
                     trace_row(bytes=3), trace_row() + '\n' + trace_row()):
            with self.subTest(bind=bind[-100:]):
                with self.assertRaises(ValueError):
                    decoder.decode_negative(bind + '\n' + rejection(), 7)
        accepted = trace_row(phase='native_submit', batch_id=1, batch_key=1,
                             frame_id=8, generation=1, ticket=10, class_id=3,
                             cookie=4096, address=2080, bytes=4096,
                             aux=2 | (7 << 8), ts_ns=2000)
        with self.assertRaises(ValueError):
            decoder.decode_negative(trace_row() + '\n' + rejection() + '\n' + accepted, 7)


if __name__ == '__main__':
    unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Raw parser contracts; these fixtures are never physical DMA evidence."""
from decimal import Decimal
import hashlib
import json
import importlib.util
from pathlib import Path
import sys
import os
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load():
    path = HERE / 'collector.py'
    if not path.exists():
        raise AssertionError('native collector and raw decoder not implemented')
    spec = importlib.util.spec_from_file_location('collector_behavior', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def manifest():
    return dict(run_id='parser-only', arm='K-BPF', clock='CLOCK_MONOTONIC',
                clock_domain='test-local', endpoint='local_tx_complete',
                trace=dict(record_mapping='batch_key_div_burst', burst=2,
                           stage_map={'0': 'read'}),
                stages=[dict(id='read', after=[])],
                records=[dict(session_id=7, record_id=3, generation=8, frame_ids=[1])])


def raw(phase, stamp, **changes):
    fields = dict(phase=phase, origin='K', session_id=7, batch_id=4, batch_key=6,
                  frame_id=1, generation=8, stage=0, ticket=19, class_id=3,
                  accepted=1, status=0, cookie=42, address=64, bytes=4096,
                  aux=0, sequence=0, origin_tgid=0, process_start_ticks=0, native_user_data=0, frame_ordinal=1, frame_offset=0, frame_length=4096)
    fields.update(changes)
    return 'worker-12 [001] .... %s: native_event: %s\n' % (
        stamp, ' '.join('%s=%s' % item for item in fields.items()))


class RawDecoder(unittest.TestCase):
    def setUp(self):
        self.c = load()
        self.metadata = dict(clock='CLOCK_MONOTONIC', clock_domain='test-local',
                             trace_dropped=0, abi='xdev-native-fixture-text-v0',
                             evidence_kind='fixture', physical=False, performance_eligible=False)

    def test_decodes_actual_text_precision_and_immutable_mapping(self):
        rows = self.c.decode_trace(manifest(), raw('native_submit', '12.000000001') +
                                  raw('native_complete', '12.000000019'), self.metadata)
        self.assertEqual([r['ts_ns'] for r in rows], [12000000001, 12000000019])
        self.assertEqual([r['record_id'] for r in rows], [3, 3])
        self.assertEqual(rows[0]['stage'], 'read')
        self.assertEqual(rows[1]['event'], 'native_complete')
        self.assertEqual(rows[0]['ticket'], 19)
        self.assertEqual(rows[0]['cookie'], 42)

    def test_absent_record_endpoints_are_not_fabricated(self):
        rows = self.c.decode_trace(manifest(), raw('native_submit', '1.0') +
                                  raw('native_complete', '1.1'), self.metadata)
        self.assertEqual(len(rows), 2)
        self.assertFalse(any(r['event'] == 'record_terminal' for r in rows))

    def test_event_monotonic_nanoseconds_override_quantized_text(self):
        text = raw('native_submit', '1.000000', ts_ns=1000000001) + raw('native_complete', '1.000000', ts_ns=1000000019)
        rows = self.c.decode_trace(manifest(), text, self.metadata)
        self.assertEqual([r['ts_ns'] for r in rows], [1000000001, 1000000019])

    def test_native_error_status_is_preserved(self):
        rows = self.c.decode_trace(manifest(), raw('native_submit', '1.0') +
                                  raw('native_complete', '1.1', status=-5), self.metadata)
        self.assertEqual(rows[-1]['status'], -5)

    def test_rejects_incomplete_or_ambiguous_native_request(self):
        for text in (raw('native_complete', '1.0'), raw('native_submit', '1.0'),
                     raw('native_submit', '1.0') * 2 + raw('native_complete', '1.1'),
                     raw('native_submit', '1.0', cookie=0) + raw('native_complete', '1.1', cookie=0),
                     raw('native_submit', '1.0') + raw('trace_invalid', '1.1')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.c.decode_trace(manifest(), text, self.metadata)

    def test_rejects_loss_and_identity_not_in_declared_record_set(self):
        text = raw('native_submit', '1.0') + raw('native_complete', '1.1')
        for metadata in (dict(self.metadata, trace_dropped=1),
                         dict(self.metadata, clock='CLOCK_MONOTONIC_RAW')):
            with self.assertRaises(ValueError):
                self.c.decode_trace(manifest(), text, metadata)
        with self.assertRaises(ValueError):
            self.c.decode_trace(manifest(), raw('native_submit', '1.0', generation=9) +
                                raw('native_complete', '1.1', generation=9), self.metadata)

    def test_rejects_bounded_correlation_overflow(self):
        m = manifest()
        m['trace']['max_pending'] = 1
        text = (raw('native_submit', '1.0') + raw('native_submit', '1.1', ticket=20, cookie=43) +
                raw('native_complete', '1.2') + raw('native_complete', '1.3', ticket=20, cookie=43))
        with self.assertRaises(ValueError):
            self.c.decode_trace(m, text, self.metadata)

    def test_u_sideband_maps_unique_cookie_without_slot_guessing(self):
        m = manifest()
        m['arm'] = 'U-poll'
        entry = dict(kind='nvme', cookie=42, session_id=7, record_id=3, slot=0,
                     generation=8, frame_id=1, stage=0, lba=64, bytes=4096)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        journal_path = Path(temp.name) / 'journal.jsonl'
        header = dict(kind='metadata', abi='xdev-native-v1', clock='CLOCK_MONOTONIC', lost=False, fixed_io=False, rx=False, pid=7)
        journal_path.write_text(json.dumps(header) + '\n' + json.dumps(entry) + '\n')
        meta = dict(self.metadata, journal_artifact=self.c.artifact(journal_path))
        text = raw('native_submit', '1.0', origin='U', session_id=0,
                   batch_key=0, generation=0, frame_id=0) + raw(
                       'native_complete', '1.1', origin='U', session_id=0,
                       batch_key=0, generation=0, frame_id=0)
        rows = self.c.decode_trace(m, text, meta)
        self.assertEqual(rows[0]['record_id'], 3)
        self.assertEqual(rows[0]['generation'], 8)
        with self.assertRaises(ValueError):
            journal_path.write_text(json.dumps(header) + '\n' + (json.dumps(entry) + '\n') * 2)
            self.c.decode_trace(m, text, dict(meta, journal_artifact=self.c.artifact(journal_path)))

    def test_rejects_inline_journal_without_retained_raw_source(self):
        m = manifest()
        m['arm'] = 'U-poll'
        text = raw('native_submit', '1.0', origin='U') + raw('native_complete', '1.1', origin='U')
        with self.assertRaises(ValueError):
            self.c.decode_trace(m, text, dict(self.metadata, journal=[dict(
                kind='nvme', cookie=42, session_id=7, record_id=3, slot=0,
                generation=8, frame_id=1, stage=0, lba=64, bytes=4096)]))

    def decode_accepted(self, m, text, metadata):
        try:
            return self.c.decode_trace(m, text, metadata)
        except ValueError as error:
            self.fail('supported immutable native mapping refused: ' + str(error))

    def journal_metadata(self, rows):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / 'journal.jsonl'
        header = dict(kind='metadata', abi='xdev-native-v1', clock='CLOCK_MONOTONIC',
                      lost=False, fixed_io=False, rx=False, pid=7)
        path.write_text(''.join(json.dumps(row) + '\n' for row in [header, *rows]))
        return dict(self.metadata, journal_artifact=self.c.artifact(path))

    def test_k_lifecycle_generation_is_preserved_but_not_logical_record_generation(self):
        m = manifest()
        m['trace']['generation_mapping'] = 'batch_key'
        m['records'][0]['generation'] = 6
        rows = self.decode_accepted(m, raw('native_submit', '1.0', generation=1) +
                                  raw('native_complete', '1.1', generation=1), self.metadata)
        self.assertEqual([row['generation'] for row in rows], [6, 6])
        self.assertEqual([row['frame_generation'] for row in rows], [1, 1])
        with self.assertRaises(ValueError):
            self.c.decode_trace(m, raw('native_submit', '1.0', generation=1) +
                                raw('native_complete', '1.1', generation=2), self.metadata)

    def test_k_driver_descriptor_joins_actual_prequeue_binding(self):
        m = manifest()
        m['trace']['generation_mapping'] = 'batch_key'
        m['records'][0]['generation'] = 6
        bind = raw('descriptor_bind', '1.0', class_id=2, generation=2)
        submit = raw('native_submit', '1.1', class_id=2, session_id=0, batch_key=0,
                     generation=0, frame_id=0, ticket=0, sequence=1)
        complete = raw('native_complete', '1.2', class_id=2, session_id=0, batch_key=0,
                       generation=0, frame_id=0, ticket=0, sequence=1)
        rows = self.decode_accepted(m, bind + submit + complete, self.metadata)
        self.assertEqual([row['event'] for row in rows], ['native_submit', 'native_complete'])
        self.assertEqual(rows[0]['session_id'], 7)
        self.assertEqual(rows[0]['frame_generation'], 2)
        with self.assertRaises(ValueError):
            self.c.decode_trace(m, submit + complete, self.metadata)

    def test_u_native_vector_expands_multiple_actual_frame_spans(self):
        m = manifest()
        m['arm'] = 'U-poll'
        m['records'][0]['frame_ids'] = [1, 2]
        bindings = [dict(kind='nvme', cookie=42, session_id=7, record_id=3, slot=0,
                         generation=8, frame_id=frame, stage=0, lba=64,
                         bytes=2048, command_bytes=4096, address=frame * 4096)
                    for frame in (1, 2)]
        text = raw('native_submit', '1.0', origin='U') + raw('native_complete', '1.1', origin='U')
        rows = self.decode_accepted(m, text, self.journal_metadata(bindings))
        self.assertEqual(len(rows), 4)
        self.assertEqual([row['frame_id'] for row in rows], [1, 2, 1, 2])

    def test_u_tx_address_mapping_checks_span_and_never_uses_user_completion(self):
        m = manifest()
        m['arm'] = 'U-poll'
        entry = dict(kind='tx', cookie=999, session_id=7, record_id=3, slot=0,
                     generation=8, frame_id=1, stage=0, lba=64, bytes=4000,
                     descriptor_bytes=4096, address=64, ts_ns=999999999)
        text = raw('native_submit', '1.0', origin='U', class_id=2, cookie=222,
                   sequence=1) + raw('native_complete', '1.1', origin='U',
                                    class_id=2, cookie=222, sequence=1)
        rows = self.decode_accepted(m, text, self.journal_metadata([entry]))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]['cookie'], 222)
        self.assertEqual(rows[1]['frame_id'], 1)
        bad = dict(entry, descriptor_bytes=4000)
        with self.assertRaises(ValueError):
            self.c.decode_trace(m, text, self.journal_metadata([bad]))

    def test_resource_and_validation_probes_stay_explicit_nonwork_diagnostics(self):
        text = (raw('pool_bind', '0.5', session_id=0, class_id=2) +
                raw('region_span', '0.6', session_id=0, class_id=2) +
                raw('class_validate', '0.7') + raw('native_span', '0.8') +
                raw('native_submit', '1.0') + raw('native_complete', '1.1') +
                raw('downstream_complete', '1.2') + raw('frame_recycle', '1.3'))
        rows = self.decode_accepted(manifest(), text, self.metadata)
        native = [r for r in rows if r['event'] in ('native_submit', 'native_complete')]
        diagnostic = [r for r in rows if r not in native]
        self.assertEqual(len(native), 2)
        self.assertEqual(len(diagnostic), 6)
        self.assertTrue(all(r['accepted'] is False and r['probe_accepted'] == 1 for r in diagnostic))
        self.assertTrue(all(r['observation_only'] is True for r in diagnostic))

    def test_u_journal_loss_and_unsupported_fixed_io_are_rejected(self):
        m = manifest()
        m['arm'] = 'U-poll'
        entry = dict(kind='nvme', cookie=42, session_id=7, record_id=3, slot=0,
                     generation=8, frame_id=1, stage=0, lba=64, bytes=4096)
        text = raw('native_submit', '1.0', origin='U') + raw('native_complete', '1.1', origin='U')
        for changes in (dict(lost=True), dict(fixed_io=True), dict(clock='CLOCK_MONOTONIC_RAW')):
            metadata = self.journal_metadata([entry])
            path = Path(metadata['journal_artifact']['path'])
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            rows[0].update(changes)
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            metadata['journal_artifact'] = self.c.artifact(path)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.c.decode_trace(m, text, metadata)

    def test_logical_frame_ordinal_is_declared_and_native_slot_is_preserved(self):
        m = manifest()
        m['record_bytes'] = 4096
        m['trace']['layout'] = [dict(frame_id=0, offset_bytes=0, length_bytes=4096)]
        m['records'][0]['frame_ids'] = [0]
        text = raw('native_submit', '1.0', frame_id=99, frame_ordinal=0) + raw(
            'native_complete', '1.1', frame_id=99, frame_ordinal=0)
        rows = self.decode_accepted(m, text, self.metadata)
        self.assertEqual([row['frame_id'] for row in rows], [0, 0])
        self.assertEqual([row['native_frame_id'] for row in rows], [99, 99])
        self.assertEqual(rows[0]['frame_offset'], 0)
        self.assertEqual(rows[0]['frame_length'], 4096)
        for changes in (dict(frame_ordinal=1), dict(frame_offset=1), dict(frame_length=1)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.c.decode_trace(m, raw('native_submit', '1.0', **dict(dict(frame_id=99, frame_ordinal=0), **changes)) + raw('native_complete', '1.1',
                    frame_id=99, frame_ordinal=0), self.metadata)

    def test_runtime_k_binding_replaces_only_session_identity_from_actual_create(self):
        m = manifest()
        m['trace'].update(sessions=[dict(logical_id=7, role='sender'), dict(logical_id=8, role='receiver', measured=False)],
                          batch_key_origin=1, generation_mapping='batch_key_relative')
        m['trace']['burst'] = 1
        m['records'][0].update(record_id=0, generation=0)
        m['records'].append(dict(session_id=7, record_id=1, generation=1, frame_ids=[1]))
        m['recipe'] = dict(records=1, warmup_records=1)
        sideband = dict(kind='session_bind', native_session_id=99, session_id=99,
                        logical_session_id=7, role='sender', pid=47,
                        process_start_ticks=123, user_hz=os.sysconf('SC_CLK_TCK'),
                        first_batch_key=1, groups=2, warmup=1, burst=1)
        receiver = dict(sideband, native_session_id=100, session_id=100, logical_session_id=8, role='receiver', pid=48, process_start_ticks=124)
        meta = self.journal_metadata([sideband, receiver])
        text = (raw('session_bind', '0.05', session_id=100, origin_tgid=48, process_start_ticks=124) + raw('session_bind', '0.1', session_id=99, origin_tgid=47,
                    process_start_ticks=123) +
                raw('native_submit', '1.0', session_id=99, batch_key=1, generation=1) +
                raw('native_complete', '1.1', session_id=99, batch_key=1, generation=1))
        rows = self.decode_accepted(m, text, meta)
        work = [row for row in rows if row['event'] == 'native_submit'][0]
        self.assertEqual(work['session_id'], 7)
        self.assertEqual(work['native_session_id'], 99)
        self.assertEqual(work['origin_tgid'], 47)
        self.assertEqual(work['process_start_ticks'], 123)
        self.assertEqual(work['record_id'], 0)
        self.assertEqual(work['generation'], 0)
        self.assertEqual(len(m['records']), 2, 'missing observed work must not reduce expected records')
        self.assertTrue(callable(getattr(self.c, 'derive_mapped_manifest', None)), 'runtime mapping artifact API missing')
        mapped = self.c.derive_mapped_manifest(m, text, meta)
        self.assertEqual(mapped['records'], m['records'])
        self.assertEqual(mapped['recipe'], m['recipe'])
        self.assertEqual(len(mapped['runtime_bindings']), 2)
        self.assertEqual(mapped['runtime_bindings'][0]['native_session_id'], 99)
        self.assertEqual(mapped['runtime_frames'][0]['native_frame_id'], 1)
        with self.assertRaises(ValueError):
            self.c.decode_trace(m, text.replace('process_start_ticks=123', 'process_start_ticks=124'), meta)

    def test_runtime_u_owner_binding_does_not_mix_same_cookie_across_processes(self):
        m = manifest()
        m['arm'] = 'U-poll'
        m['trace']['sessions'] = [dict(logical_id=7, role='sender', protocol_session_id=270019),
                                  dict(logical_id=8, role='receiver', measured=False, protocol_session_id=270019)]
        entry = dict(kind='nvme', cookie=42, session_id=270019, record_id=3, slot=0,
                     generation=8, frame_id=1, stage=0, lba=64, bytes=4096)
        metadata = self.journal_metadata([entry])
        path = Path(metadata['journal_artifact']['path'])
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0].update(pid=47, process_start_ticks=123, user_hz=os.sysconf('SC_CLK_TCK'),
                       role='sender', session_id=270019)
        receiver = dict(rows[0], pid=48, role='receiver', rx=True, process_start_ticks=124)
        path.write_text(''.join(json.dumps(row) + '\n' for row in [*rows, receiver]))
        metadata['journal_artifact'] = self.c.artifact(path)
        text = (raw('pool_bind', '0.1', origin='U', class_id=2, cookie=222,
                    origin_tgid=47, process_start_ticks=123) +
                raw('pool_bind', '0.2', origin='U', class_id=2, cookie=333,
                    origin_tgid=48, process_start_ticks=124) +
                raw('native_submit', '1.0', origin='U', origin_tgid=47,
                    process_start_ticks=123, native_user_data=42) +
                raw('native_complete', '1.1', origin='U', origin_tgid=47,
                    process_start_ticks=123, native_user_data=42) +
                raw('native_submit', '1.2', origin='U', origin_tgid=48,
                    process_start_ticks=124, native_user_data=42, sequence=777) +
                raw('native_complete', '1.3', origin='U', origin_tgid=48,
                    process_start_ticks=124, native_user_data=42, sequence=777))
        decoded = self.decode_accepted(m, text, metadata)
        work = [row for row in decoded if row['event'] in ('native_submit', 'native_complete') and row['accepted']]
        self.assertEqual(len(work), 2)
        self.assertTrue(all(row['origin_tgid'] == 47 for row in work))
        self.assertEqual(work[0]['session_id'], 7)
        self.assertEqual(work[0]['native_session_id'], 270019)

    def test_runtime_binding_missing_create_or_sideband_is_unavailable(self):
        m = manifest()
        m['trace']['sessions'] = [dict(logical_id=7, role='sender')]
        text = raw('native_submit', '1.0') + raw('native_complete', '1.1')
        with self.assertRaises(ValueError):
            self.c.decode_trace(m, text, self.metadata)

    def test_all_cpu_loss_parser_checks_each_cpu(self):
        self.assertEqual(self.c.trace_loss({'cpu0': 'overrun: 0\ndropped events: 0\ncommit overrun: 0\n',
                                           'cpu9': 'overrun: 3\ndropped events: 2\ncommit overrun: 0\n'}), 5)
        with self.assertRaises(ValueError):
            self.c.trace_loss({'cpu0': 'entries: 0\n'})


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.c = load()
        self.metadata = dict(clock='CLOCK_MONOTONIC', clock_domain='test-local',
                             trace_dropped=0, abi='xdev-native-v1-nvme-xsk-batch')

    def row(self, phase, stamp, **changes):
        changes.setdefault('ts_ns', int(Decimal(stamp) * 1000000000))
        changes.setdefault('aux', 2)
        return raw(phase, stamp, **changes)

    def pair(self, **changes):
        return self.row('native_submit', '1.0', **changes) + self.row('native_complete', '1.1', **changes)

    def two_frames(self):
        m = manifest()
        m['record_bytes'] = 4096
        m['trace']['layout'] = [dict(frame_id=i, offset_bytes=i * 2048, length_bytes=2048) for i in (0, 1)]
        m['records'][0]['frame_ids'] = [0, 1]
        return m

    def frame_row(self, phase, stamp, frame, **changes):
        values = dict(frame_id=10 + frame, frame_ordinal=frame,
                      frame_offset=frame * 2048, frame_length=2048)
        values.update(changes)
        return self.row(phase, stamp, **values)

    def test_current_abi_requires_typed_native_ns_even_for_other_origin(self):
        missing = raw('native_submit', '1.000000') + raw('native_complete', '1.000001')
        with self.assertRaisesRegex(ValueError, 'ts_ns'):
            self.c.decode_trace(manifest(), missing, self.metadata)
        with self.assertRaisesRegex(ValueError, 'ts_ns'):
            self.c.decode_trace(manifest(), self.pair() + raw('native_submit', '2.0', origin='U'), self.metadata)
        with self.assertRaisesRegex(ValueError, 'ts_ns'):
            self.c.decode_trace(manifest(), self.pair() + self.row('native_complete', '2.0', ts_ns='bad'), self.metadata)

    def test_fixture_fallback_cannot_enable_current_physical_abi(self):
        missing = raw('native_submit', '1.0') + raw('native_complete', '1.1')
        legacy = dict(self.metadata, abi='xdev-native-fixture-text-v0', evidence_kind='fixture',
                      physical=False, performance_eligible=False)
        self.assertEqual(len(self.c.decode_trace(manifest(), missing, legacy)), 2)
        for changes in (dict(physical=True), dict(performance_eligible=True),
                        dict(formats={'xdev_ext:native_event': 'abi=xdev-native-v1-nvme-xsk-batch'})):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'ts_ns'):
                self.c.decode_trace(manifest(), missing, dict(legacy, **changes))

    def test_duplicate_endpoint_is_rejected_before_aggregation(self):
        text = (self.row('record_admit', '0.8') + self.row('record_admit', '0.9') +
                self.pair() + self.row('record_terminal', '1.2'))
        with self.assertRaisesRegex(ValueError, 'endpoint'):
            self.c.decode_trace(manifest(), text, self.metadata)

    def test_partial_endpoint_set_cannot_become_a_complete_record(self):
        text = self.frame_row('record_admit', '0.8', 0)
        for phase, stamp in (('native_submit', '1.0'), ('native_complete', '1.1')):
            text += ''.join(self.frame_row(phase, stamp, frame) for frame in (0, 1))
        text += self.frame_row('record_terminal', '1.2', 1)
        with self.assertRaisesRegex(ValueError, 'endpoint'):
            self.c.decode_trace(self.two_frames(), text, self.metadata)

    def test_full_unique_endpoint_set_retains_each_frame_audit(self):
        text = ''
        for phase, stamp in (('record_admit', '0.8'), ('native_submit', '1.0'),
                             ('native_complete', '1.1'), ('record_terminal', '1.2')):
            text += ''.join(self.frame_row(phase, stamp, frame) for frame in (0, 1))
        rows = self.c.decode_trace(self.two_frames(), text, self.metadata)
        endpoints = [row for row in rows if row['event'].startswith('record_')]
        self.assertEqual(len(endpoints), 2)
        for endpoint in endpoints:
            self.assertIn('endpoint_frames', endpoint, 'complete per-frame endpoint audit is missing')
            self.assertEqual([row['endpoint_frame_id'] for row in endpoint['endpoint_frames']], [0, 1])
            self.assertEqual([row['native_frame_id'] for row in endpoint['endpoint_frames']], [10, 11])

    def test_endpoint_status_acceptance_and_unbound_owner_conflicts_are_rejected(self):
        for changes in (dict(status=-5), dict(accepted=0), dict(origin_tgid=99)):
            text = self.frame_row('record_admit', '0.8', 0) + self.frame_row('record_admit', '0.9', 1, **changes)
            for phase, stamp in (('native_submit', '1.0'), ('native_complete', '1.1')):
                text += ''.join(self.frame_row(phase, stamp, frame) for frame in (0, 1))
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'endpoint'):
                self.c.decode_trace(self.two_frames(), text, self.metadata)

    def test_nvme_direction_and_encoded_length_are_immutable(self):
        for aux in (1, 2 | (7 << 8)):
            with self.subTest(aux=aux), self.assertRaisesRegex(ValueError, 'NVMe'):
                self.c.decode_trace(manifest(), self.row('native_submit', '1.0', aux=2) +
                                    self.row('native_complete', '1.1', aux=aux), self.metadata)
        m = manifest()
        m['trace']['native_directions'] = {'read': 'read'}
        with self.assertRaisesRegex(ValueError, 'direction'):
            self.c.decode_trace(m, self.pair(aux=1), self.metadata)

    def test_tx_batch_aux_may_differ_without_changing_descriptor_identity(self):
        m = manifest()
        m['trace']['generation_mapping'] = 'batch_key'
        m['records'][0]['generation'] = 6
        bind = self.row('descriptor_bind', '0.9', class_id=2, generation=2)
        args = dict(class_id=2, session_id=0, batch_key=0, generation=0,
                    frame_id=0, ticket=0, sequence=1)
        text = bind + self.row('native_submit', '1.0', aux=1, **args) + self.row('native_complete', '1.1', aux=4, **args)
        rows = self.c.decode_trace(m, text, self.metadata)
        self.assertEqual([row['aux'] for row in rows], [1, 4])


class CaptureEvidence(unittest.TestCase):
    def setUp(self):
        self.c = load()

    def test_native_format_checks_real_fields_and_batch_coverage_marker(self):
        fmt = 'name: native_event\n' + ''.join(
            'field:u64 %s; offset:0; size:8; signed:0;\n' % f
            for f in (*self.c.FIELDS, 'ts_ns')) + 'field:__data_loc char[] phase;\nfield:__data_loc char[] origin;\n'
        self.assertTrue(callable(getattr(self.c, 'validate_format', None)),
                        'native event format admission not implemented')
        with self.assertRaises(ValueError):
            self.c.validate_format(fmt)
        good = fmt + 'print fmt: "abi=xdev-native-v1-nvme-xsk-batch"\n'
        self.c.validate_format(good)
        with self.assertRaises(ValueError):
            self.c.validate_format(good.replace('u64 cookie;', 'u64 bogus;'))

    def test_correctness_scope_reads_real_host_but_never_claims_physical_performance(self):
        self.assertTrue(callable(getattr(self.c, 'software_environment', None)),
                        'real software-only environment observation is missing')
        result = self.c.software_environment()
        self.assertIs(result['physical'], False)
        self.assertIn(result['environment'], ('vm', 'host-contract'))
        self.assertEqual(result['evidence_kind'], 'correctness-only')
        self.assertIn('cpuinfo_sha256', result['observations'])
        self.assertEqual(result['observations']['kernel_release'], os.uname().release)

    def test_timeout_stops_owned_process_group_and_preserves_real_output(self):
        self.assertTrue(callable(getattr(self.c, 'execute_command', None)),
                        'owned process group timeout handling is not implemented')
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            command = [sys.executable, '-c',
                       'import os,time; print(os.getpid(), flush=True); time.sleep(30)']
            with (root / 'stdout').open('wb') as out, (root / 'stderr').open('wb') as err:
                result = self.c.execute_command(command, out, err, os.environ.copy(), 0.2)
            self.assertTrue(result['timed_out'])
            self.assertLess(result['returncode'], 0)
            pid = int((root / 'stdout').read_text().strip())
            self.assertFalse(Path('/proc/%d' % pid).exists())

    def test_readback_is_actual_bytes_and_retained_not_campaign_boolean(self):
        self.assertTrue(callable(getattr(self.c, 'retain_readback', None)),
                        'actual postoracle readback not implemented')
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            expected, destination = root / 'expected.bin', root / 'destination.bin'
            expected.write_bytes(bytes(range(256)) * 4)
            destination.write_bytes(b'prefix' + expected.read_bytes())
            spec = dict(oracle=dict(kind='file', path=str(destination), offset=6,
                                    reference=str(expected)))
            result = self.c.retain_readback(spec, root / 'capture')
            self.assertEqual(Path(result['readback']['path']).read_bytes(), expected.read_bytes())
            self.assertEqual(result['readback']['sha256'], result['expected']['sha256'])
            destination.write_bytes(b'prefix' + bytes(1024))
            with self.assertRaises(ValueError):
                self.c.retain_readback(spec, root / 'corrupt')


if __name__ == '__main__':
    unittest.main()

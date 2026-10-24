#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Raw parser contracts; these fixtures are never physical DMA evidence."""
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
                  aux=0, sequence=0)
    fields.update(changes)
    return 'worker-12 [001] .... %s: native_event: %s\n' % (
        stamp, ' '.join('%s=%s' % item for item in fields.items()))


class RawDecoder(unittest.TestCase):
    def setUp(self):
        self.c = load()
        self.metadata = dict(clock='CLOCK_MONOTONIC', clock_domain='test-local',
                             trace_dropped=0)

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

    def test_all_cpu_loss_parser_checks_each_cpu(self):
        self.assertEqual(self.c.trace_loss({'cpu0': 'overrun: 0\ndropped events: 0\ncommit overrun: 0\n',
                                           'cpu9': 'overrun: 3\ndropped events: 2\ncommit overrun: 0\n'}), 5)
        with self.assertRaises(ValueError):
            self.c.trace_loss({'cpu0': 'entries: 0\n'})


class CaptureEvidence(unittest.TestCase):
    def setUp(self):
        self.c = load()

    def test_native_format_checks_real_fields_and_batch_coverage_marker(self):
        fmt = 'name: native_event\n' + ''.join(
            'field:u64 %s; offset:0; size:8; signed:0;\n' % f
            for f in self.c.FIELDS) + 'field:__data_loc char[] phase;\nfield:__data_loc char[] origin;\n'
        self.assertTrue(callable(getattr(self.c, 'validate_format', None)),
                        'native event format admission not implemented')
        with self.assertRaises(ValueError):
            self.c.validate_format(fmt)
        good = fmt + 'print fmt: "abi=xdev-native-v1-nvme-xsk-batch"\n'
        self.c.validate_format(good)
        with self.assertRaises(ValueError):
            self.c.validate_format(good.replace('u64 cookie;', 'u64 bogus;'))

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

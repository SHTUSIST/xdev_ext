#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Runtime binding against the real collector's decoder; fixture provenance only.

An isolated implementer can set NATIVE_TRACE_COLLECTOR to the read-only collector
checkout. In the integrated tree the normal sibling implementation is used.
"""
import copy
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import analyze
import contract
import run as runner
from fixtures.builders import run_fixture

HERE = Path(__file__).resolve().parent


class RuntimeImport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.runtime-import-', dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.collector_path = Path(os.environ.get('NATIVE_TRACE_COLLECTOR', HERE.parent / 'native_trace/collector.py'))
        self.assertTrue(self.collector_path.is_file(), 'real collector dependency must be integrated or explicitly located')
        spec = importlib.util.spec_from_file_location('runtime_import_real_collector', self.collector_path)
        self.collector = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.collector
        spec.loader.exec_module(self.collector)
        spec = importlib.util.spec_from_file_location('runtime_import_abi_fixture', self.collector_path.with_name('test_collector_behavior.py'))
        self.abi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.abi)
        self.manifest = run_fixture('K-BPF')
        self.manifest.update(endpoint='local_native_complete',
            stages=[dict(id='read', after=[])],
            records=[dict(session_id=7, record_id=0, generation=0, frame_ids=[0], measured=True)],
            recipe=dict(chain='nvme-nic', rig='/synthetic/rig.json', records=1,
                        warmup_records=0, pairs=1, arms=['K-BPF'], seed=17),
            trace=dict(record_mapping='batch_key_div_burst', burst=1,
                stage_map={'0': 'read'}, generation_mapping='batch_key_relative', batch_key_origin=1,
                sessions=[dict(logical_id=7, role='sender', measured=True),
                          dict(logical_id=8, role='receiver', measured=False)],
                layout=[dict(frame_id=0, offset_bytes=0, length_bytes=4096)]))
        self.receipt = dict(status='ok', returncode=0, artifacts={})
        self.metadata = {key: self.manifest[key] for key in ('run_id', 'exact_sha', 'config_hash', 'arm',
            'clock', 'clock_domain', 'endpoint', 'physical', 'environment', 'evidence_kind',
            'complete_boundary', 'submit_boundary')}
        self.metadata.update(schema_version=1, trace_dropped=0, cpu_tick_hz=os.sysconf('SC_CLK_TCK'),
                             cpu_interval_scope='whole_command')
        self.prepare()

    def artifact(self, kind, text):
        path = self.directory / (kind + '.txt')
        path.write_bytes(text if isinstance(text, bytes) else text.encode())
        self.receipt['artifacts'][kind] = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    def prepare(self):
        recipe = self.manifest['recipe']
        total = recipe['records'] + recipe['warmup_records']
        binds = [dict(kind='session_bind', native_session_id=native, session_id=native,
                      logical_session_id=logical, role=role, pid=pid, process_start_ticks=start,
                      user_hz=os.sysconf('SC_CLK_TCK'), first_batch_key=1, groups=total,
                      warmup=recipe['warmup_records'], burst=1)
                 for native, logical, role, pid, start in
                 ((99, 7, 'sender', 47, 123), (100, 8, 'receiver', 48, 124))]
        self.artifact('journal', ''.join(json.dumps(row) + '\n' for row in binds))
        self.metadata['journal_artifact'] = self.receipt['artifacts']['journal']
        def raw(phase, stamp, **changes):
            return self.abi.raw(phase, stamp, ts_ns=int(Decimal(stamp) * 1_000_000_000),
                                aux=2, **changes)
        text = ''.join(raw('session_bind', '0.%d' % i, session_id=native, origin_tgid=pid,
                          process_start_ticks=start) for i, native, pid, start in
                       ((1, 99, 47, 123), (2, 100, 48, 124)))
        for key in range(total):
            common = dict(session_id=99, origin_tgid=47, process_start_ticks=123,
                          frame_id=501 + key, frame_ordinal=0, frame_offset=0, frame_length=4096,
                          batch_key=key + 1, cookie=500 + key)
            for phase, stamp, token in (('record_admit', 1, 0), ('native_submit', 2, 11),
                                        ('native_complete', 3, 11), ('record_terminal', 4, 11)):
                text += raw(phase, str(key * 10 + stamp) + '.0', generation=token, **common)
        self.text = text
        self.artifact('raw_trace', text)
        events = self.collector.decode_trace(self.manifest, text, self.metadata)
        self.artifact('events', ''.join(json.dumps(row) + '\n' for row in events))
        mapped = self.collector.derive_mapped_manifest(self.manifest, text, self.metadata)
        self.artifact('mapped_manifest', json.dumps(mapped))
        self.artifact('trace_metadata', json.dumps(self.metadata))
        self.events, self.mapped = events, mapped

    def inspect(self):
        self.assertTrue(hasattr(contract, 'COLLECTOR_ENTRY'), 'runtime raw mapper import not connected')
        with patch.object(contract, 'COLLECTOR_ENTRY', self.collector_path):
            return contract.inspect_collection(self.manifest, self.receipt)

    def import_run(self):
        self.assertTrue(hasattr(contract, 'COLLECTOR_ENTRY'), 'runtime raw mapper import not connected')
        with patch.object(contract, 'COLLECTOR_ENTRY', self.collector_path):
            return analyze.import_collection(self.manifest, self.receipt)

    def test_unknown_native_ids_bind_without_changing_expected_work(self):
        result = self.inspect()
        self.assertIn('mapped_manifest', result)
        self.assertEqual(result['mapped_manifest'], self.mapped)
        self.assertFalse(any('runtime_mapping' in e for e in result['errors']))
        result = self.import_run()
        self.assertEqual(result['manifest']['records'], self.manifest['records'])
        self.assertEqual(result['manifest']['runtime_bindings'], self.mapped['runtime_bindings'])
        self.assertEqual(result['manifest']['runtime_frames'][0]['native_frame_id'], 501)
        self.assertEqual(result['summary']['records'][0]['latency_ns'], 3_000_000_000)
        self.assertFalse(result['performance_eligible'])

    def test_hash_valid_but_changed_expectations_or_runtime_ids_are_rejected(self):
        for field in ('records', 'recipe', 'runtime_frames', 'typed_record'):
            with self.subTest(field=field):
                mapped = copy.deepcopy(self.mapped)
                if field == 'records':
                    mapped[field] = []
                elif field == 'recipe':
                    mapped[field]['seed'] = 18
                elif field == 'typed_record':
                    mapped['records'][0]['generation'] = False
                else:
                    mapped[field][0]['native_frame_id'] = 999
                self.artifact('mapped_manifest', json.dumps(mapped))
                result = self.inspect()
                self.assertTrue(any('runtime_mapping' in e for e in result['errors']))

    def test_k_journal_hash_cannot_be_bypassed(self):
        self.receipt['artifacts']['journal']['sha256'] = '0' * 64
        self.assertTrue(any('journal' in e and 'sha256' in e for e in self.inspect()['errors']))

    def test_predeclared_count_and_origin_are_not_reduced_to_observed_successes(self):
        self.manifest['recipe']['records'] = 2  # The raw capture only contains one.
        result = self.import_run()
        self.assertTrue(any('runtime' in e or 'record' in e for e in result['errors']))
        self.assertEqual(result['manifest']['recipe']['records'], 2)
        self.manifest['recipe']['records'] = 1
        self.manifest['trace']['batch_key_origin'] = 2
        self.assertTrue(any('raw_trace' in e or 'runtime' in e for e in self.inspect()['errors']))

    def test_missing_expected_record_stays_missing_and_warmup_is_not_in_measured_denominator(self):
        self.manifest['recipe']['warmup_records'] = 1
        self.manifest['records'] = [dict(session_id=7, record_id=i, generation=i,
            frame_ids=[0], measured=i == 1) for i in (0, 1)]
        self.prepare()
        result = self.import_run()
        self.assertEqual(result['manifest']['completed_records'], 1)
        self.assertEqual(len(result['manifest']['records']), 2)
        self.assertEqual(len(result['summary']['records']), 2)
        events = [e for e in self.events if e.get('record_id') != 1 or e.get('observation_only')]
        self.artifact('events', ''.join(json.dumps(e) + '\n' for e in events))
        result = self.import_run()
        self.assertTrue(result['errors'])
        self.assertEqual(len(result['manifest']['records']), 2)

    def test_frame_span_and_owner_changes_cannot_be_self_certified(self):
        for old, new in (('frame_offset=0', 'frame_offset=1'),
                         ('process_start_ticks=123', 'process_start_ticks=999')):
            with self.subTest(field=old):
                self.artifact('raw_trace', self.text.replace(old, new))
                self.assertTrue(any('raw_trace' in e or 'runtime' in e for e in self.inspect()['errors']))

    def test_actual_decoder_rejects_missing_or_duplicate_record_endpoints(self):
        for phase in ('record_admit', 'record_terminal'):
            lines = self.text.splitlines(keepends=True)
            endpoint = next(line for line in lines if 'phase=' + phase + ' ' in line)
            for variant in ('missing', 'duplicate'):
                with self.subTest(phase=phase, variant=variant):
                    raw = self.text.replace(endpoint, '') if variant == 'missing' else self.text + endpoint
                    self.artifact('raw_trace', raw)
                    result = self.import_run()
                    self.assertTrue(result['errors'])
                    self.assertIsNone(result['summary']['records'][0]['latency_ns'])
                    self.assertFalse(result['performance_eligible'])

    def test_native_backing_cannot_change_predeclared_logical_frame_spans(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['records'][0]['frame_ids'] = [0, 1]
        manifest['trace']['layout'] = [dict(frame_id=0, offset_bytes=0, length_bytes=1024),
                                     dict(frame_id=1, offset_bytes=1024, length_bytes=3072)]
        proof = dict(schema_version=1, source='native_provider', run_id=manifest['run_id'],
                     exact_sha=manifest['exact_sha'], afxdp_mode='zc', nvme_bounces=0,
                     payload_copy_bytes=0, frames=[])
        for frame in (0, 1):
            proof['frames'].append(dict(session_id=7, record_id=0, generation=0, frame_id=frame,
                backing_id='pages-%d' % frame, valid_bytes=2048, record_offset_bytes=frame * 2048,
                payload_offset_bytes=0, payload_bytes=2048,
                native_views=[dict(kind=kind, backing_id='pages-%d' % frame,
                                   offset_bytes=0, length_bytes=2048) for kind in ('nvme', 'afxdp')]))
        self.assertTrue(contract._check_backing(manifest, proof))

    def test_postoracle_compares_actual_retained_bytes_not_a_pass_flag(self):
        spec_loader = importlib.util.spec_from_file_location('runtime_plan_expected_bytes', HERE.parent / 'chains/run.py')
        oracle = importlib.util.module_from_spec(spec_loader)
        spec_loader.loader.exec_module(oracle)
        expected = oracle.group_bytes(self.manifest['recipe']['seed'], 0, 4096)
        self.artifact('oracle_expected', expected)
        self.artifact('oracle_readback', expected)
        spec = dict(schema='xdev-chain-spec-v1', seed=17, depth=self.manifest['depth'],
                    load=self.manifest['load'], chain='nic-nvme', arm='session', mode='timing', group_bytes=4096,
                    batches=1, warmup=0, burst=1,
                    oracle=dict(kind='file', path='/synthetic/nvme', offset=0,
                                reference=self.receipt['artifacts']['oracle_expected']['path']))
        self.artifact('oracle_spec', json.dumps(spec))
        self.assertFalse(any('postoracle' in e for e in self.inspect()['errors']))
        changed = bytearray(expected)
        changed[-1] ^= 1
        self.artifact('oracle_readback', bytes(changed))
        self.assertTrue(any('postoracle' in e for e in self.inspect()['errors']))
        self.artifact('oracle_readback', expected)
        for field, value in (('seed', 18), ('depth', 99), ('load', 'open'), ('arm', 'staged')):
            with self.subTest(actual_field=field):
                altered = dict(spec, **{field: value})
                self.artifact('oracle_spec', json.dumps(altered))
                self.assertTrue(any('postoracle.' + field in e for e in self.inspect()['errors']))
        self.artifact('oracle_spec', json.dumps(spec))
        wrong = oracle.group_bytes(18, 0, 4096)
        self.artifact('oracle_expected', wrong)
        self.artifact('oracle_readback', wrong)
        self.assertTrue(any('frozen plan seed' in e for e in self.inspect()['errors']))
        # The real UO spec represents arm choice by schema+wait, without arm.
        self.artifact('oracle_expected', expected)
        self.artifact('oracle_readback', expected)
        userspace = dict(self.manifest, arm='U-event')
        userspace_spec = dict(spec, schema='xdev-uo-spec-v1', wait='eventfd')
        del userspace_spec['arm']
        self.assertEqual(contract._check_postoracle(userspace, self.receipt['artifacts'], userspace_spec), [])

    def test_real_software_process_receipt_can_be_imported_without_physical_claims(self):
        receipt = runner.execute_command([sys.executable, '-c',
            'print("software fixture only; no physical DMA")'], self.directory / 'actual-child')
        self.assertEqual(receipt['returncode'], 0)
        receipt['artifacts'] = copy.deepcopy(self.receipt['artifacts'])
        receipt['artifacts']['workload_stdout'] = self.collector.artifact(receipt['stdout_path'])
        receipt['artifacts']['workload_stderr'] = self.collector.artifact(receipt['stderr_path'])
        self.receipt = receipt
        result = self.import_run()
        self.assertEqual(result['manifest']['records'], self.manifest['records'])
        self.assertEqual(result['manifest']['runtime_frames'], self.mapped['runtime_frames'])
        self.assertFalse(result['performance_eligible'])


if __name__ == '__main__':
    unittest.main()

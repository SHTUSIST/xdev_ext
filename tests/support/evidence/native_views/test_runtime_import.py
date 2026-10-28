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
from types import SimpleNamespace

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

    def cpu_samples(self):
        self.metadata.update(cpu_tick_hz=100, cpu_interval_scope='native_interval_counter_bounds')
        self.artifact('trace_metadata', json.dumps(self.metadata))
        samples = [dict(before_ns=a, after_ns=b,
                        stat='cpu %d 0 0 100 0 0 0 0 0 0\ncpu0 %d 0 0 100 0 0 0 0 0 0\n' % (n, n))
                   for a, b, n in [(500_000_000, 600_000_000, 1),
                                    (2_000_000_000, 2_100_000_000, 4),
                                    (3_000_000_000, 3_100_000_000, 7),
                                    (4_500_000_000, 4_600_000_000, 11)]]
        self.artifact('cpu_samples', ''.join(json.dumps(row) + '\n' for row in samples))

    def test_cpu_bounds_replay_raw_samples_and_keep_point_unknown(self):
        self.cpu_samples()
        result = self.import_run()
        bounds = result['manifest'].get('total_cpu_ns_bounds')
        self.assertIsNotNone(bounds, 'raw samples must produce counter bounds')
        self.assertEqual((bounds['lower'], bounds['upper']), (30_000_000, 100_000_000))
        self.assertIsNone(result['manifest']['total_cpu_ns'])
        self.assertIsNone(result['manifest']['metrics']['cpu_ns_per_record'])
        self.assertEqual(result['manifest']['metrics']['cpu_ns_per_record_bounds'],
                         dict(lower=30_000_000, upper=100_000_000))
        self.assertFalse(any('system_cpu:' in e for e in result['errors']))

    def test_cpu_samples_missing_or_tampered_stay_unknown(self):
        for variant in ('missing', 'tampered', 'forged_events', 'sampler_error'):
            with self.subTest(variant=variant):
                self.prepare()
                self.cpu_samples()
                if variant == 'missing':
                    del self.receipt['artifacts']['cpu_samples']
                elif variant == 'tampered':
                    Path(self.receipt['artifacts']['cpu_samples']['path']).write_text('{}\n')
                elif variant == 'forged_events':
                    self.artifact('events', ''.join(json.dumps(e) + '\n' for e in self.events[:-1]))
                else:
                    self.metadata['cpu_sampler_error'] = 'CPU sample byte limit exceeded'
                    self.artifact('trace_metadata', json.dumps(self.metadata))
                result = self.import_run()
                self.assertIsNone(result['manifest'].get('total_cpu_ns_bounds'))
                self.assertIsNone(result['manifest']['metrics']['cpu_ns_per_record'])
                self.assertFalse(result['performance_eligible'])
                self.metadata.pop('cpu_sampler_error', None)

    def test_cpu_bound_metrics_cannot_be_edited_after_import(self):
        self.cpu_samples()
        imported = self.import_run()['manifest']
        original_errors = contract.validate_run(imported, performance=True)
        self.assertFalse(any('cpu_ns_per_record' in e for e in original_errors), original_errors)
        for field in ('cpu_ns_per_record', 'cpu_ns_per_record_bounds'):
            edited = copy.deepcopy(imported)
            edited['metrics'][field] = (123 if field == 'cpu_ns_per_record' else dict(lower=1, upper=2))
            errors = contract.validate_run(edited, performance=True)
            self.assertTrue(any('metrics.' + field in e for e in errors), errors)

    def test_claimed_cpu_bounds_are_replaced_by_raw_replay_or_unknown(self):
        self.manifest['total_cpu_ns_bounds'] = dict(lower=999, upper=999)
        self.cpu_samples()
        result = self.import_run()
        self.assertEqual(result['manifest']['total_cpu_ns_bounds']['lower'], 30_000_000)
        del self.receipt['artifacts']['cpu_samples']
        result = self.import_run()
        self.assertIsNone(result['manifest']['total_cpu_ns_bounds'])
        self.assertIsNone(result['manifest']['metrics']['cpu_ns_per_record'])

    def test_real_whole_command_snapshots_cannot_promote_by_metadata(self):
        self.manifest.update(physical=True, environment='physical', evidence_kind='physical')
        self.metadata.update(physical=True, environment='physical', evidence_kind='physical',
                             cpu_interval_scope='steady_state', cpu_tick_hz=100)
        self.prepare()
        self.artifact('system_cpu_before', 'cpu 1 0 0 100 0 0 0 0\ncpu0 1 0 0 100 0 0 0 0\n')
        self.artifact('system_cpu_after', 'cpu 9 0 0 100 0 0 0 0\ncpu0 9 0 0 100 0 0 0 0\n')
        result = self.import_run()
        self.assertIsNone(result['manifest']['total_cpu_ns'])
        self.assertIsNone(result['manifest']['metrics']['cpu_ns_per_record'])
        self.assertTrue(any('system_cpu:' in e for e in result['errors']))

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
        rig = dict(nvme_dst=dict(ng='/synthetic/ng', block='/synthetic/nvme', slba=0, nlb=8, lba_bytes=512),
                   rx=dict(ifname='synthetic0', queue=0, mac='02:00:00:00:00:01', ip='192.0.2.1', port=1111),
                   tx=dict(mac='02:00:00:00:00:02', ip='192.0.2.2', port=2222))
        for arm, wait in (('U-poll', 'poll'), ('U-event', 'eventfd')):
            with self.subTest(actual_uo_arm=arm):
                userspace = dict(self.manifest, arm=arm)
                case = dict(wait=wait, load=userspace['load'], var=dict(afxdp_mode='zc', depth=userspace['depth']))
                userspace_spec = oracle.uo_spec(case, 'nic-nvme', rig,
                    SimpleNamespace(correctness_only=False, records=1, warmup_records=0),
                    (4096, 1, 4096), 17, self.directory)
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


    # Scope replay uses the real importer/decoder, with synthetic provenance only.
    def selected_samples(self, subset=False, status='qualified', selected=(0,)):
        self.cpu_samples()
        online = [0, 1] if subset else list(selected)
        scope = dict(schema=1, selected_cpus=list(selected), online_cpus=online,
                     possible_cpus=[0, 1], boot_id='01234567-89ab-4cde-8f01-23456789abcd',
                     clock=self.manifest['clock'], clock_domain=self.manifest['clock_domain'],
                     selection='subset' if subset else 'all-online', status=status,
                     hold_reasons=['worker/IRQ containment unavailable'] if status == 'hold' else [])
        self.manifest.update(cpu_accounting='cpu_set_total', cpu_budget=1,
                             measurement_cpu_count=len(selected), cpu_scope=copy.deepcopy(scope))
        self.metadata.update(cpu_accounting='cpu_set_total', cpu_budget=1,
                             measurement_cpu_count=len(selected), cpu_scope=copy.deepcopy(scope))
        path = Path(self.receipt['artifacts']['cpu_samples']['path'])
        samples = [json.loads(line) for line in path.read_text().splitlines()]
        for sample in samples:
            sample.update(boot_id=scope['boot_id'], online_cpus=online, possible_cpus=[0, 1],
                          clock=scope['clock'], clock_domain=scope['clock_domain'])
            if subset:
                sample['stat'] += 'cpu1 0 0 0 100 0 0 0 0 0 0\n'
            elif selected == (0, 1):
                n = int(sample['stat'].splitlines()[1].split()[1])
                sample['stat'] = ('cpu %d 0 0 200 0 0 0 0 0 0\n'
                                  'cpu0 %d 0 0 100 0 0 0 0 0 0\n'
                                  'cpu1 %d 0 0 100 0 0 0 0 0 0\n') % (2 * n, n, n)
        self.artifact('cpu_samples', ''.join(json.dumps(row) + '\n' for row in samples))
        self.artifact('trace_metadata', json.dumps(self.metadata))

    def test_all_online_raw_bounds_remain_fixture_arithmetic_not_physical_evidence(self):
        self.selected_samples()
        result = self.import_run()
        bounds = result['manifest']['total_cpu_ns_bounds']
        self.assertIsNotNone(bounds)
        self.assertEqual((bounds['lower'], bounds['upper']), (30_000_000, 100_000_000))
        self.assertFalse(result['performance_eligible'])

    def test_held_subset_exposes_no_primary_cpu_cost_or_bounds(self):
        self.selected_samples(subset=True, status='hold')
        result = self.import_run()
        self.assertIsNone(result['manifest']['total_cpu_ns'])
        self.assertIsNone(result['manifest']['total_cpu_ns_bounds'])
        self.assertIsNone(result['manifest']['metrics'].get('cpu_ns_per_record'))
        self.assertIsNone(result['manifest']['metrics'].get('cpu_ns_per_record_bounds'))
        self.assertFalse(result['performance_eligible'])
        self.assertIn('cpu_samples', self.receipt['artifacts'])

    def test_subset_qualified_label_without_observed_containment_cannot_promote(self):
        self.selected_samples(subset=True)
        result = self.import_run()
        self.assertIsNone(result['manifest']['total_cpu_ns_bounds'])
        self.assertIsNone(result['manifest']['metrics'].get('cpu_ns_per_record_bounds'))
        self.assertTrue(any('cpu' in error.lower() for error in result['errors']), result['errors'])

    def test_selected_result_cannot_relabel_legacy_identityless_samples(self):
        self.selected_samples()
        path = Path(self.receipt['artifacts']['cpu_samples']['path'])
        samples = [json.loads(line) for line in path.read_text().splitlines()]
        for sample in samples:
            for key in ('boot_id', 'online_cpus', 'possible_cpus', 'clock', 'clock_domain'):
                sample.pop(key)
        self.artifact('cpu_samples', ''.join(json.dumps(row) + '\n' for row in samples))
        result = self.import_run()
        self.assertIsNone(result['manifest']['total_cpu_ns_bounds'])
        self.assertTrue(any('cpu' in error.lower() for error in result['errors']), result['errors'])

    def test_scope_metadata_and_raw_boot_identity_are_independently_replayed(self):
        for mutation in ('metadata_set', 'metadata_boot', 'raw_boot'):
            with self.subTest(mutation=mutation):
                self.selected_samples()
                if mutation.startswith('metadata'):
                    scope = self.metadata['cpu_scope']
                    scope['selected_cpus' if mutation == 'metadata_set' else 'boot_id'] = (
                        [1] if mutation == 'metadata_set' else 'fedcba98-7654-4321-8abc-0123456789ab')
                    self.artifact('trace_metadata', json.dumps(self.metadata))
                else:
                    path = Path(self.receipt['artifacts']['cpu_samples']['path'])
                    samples = [json.loads(line) for line in path.read_text().splitlines()]
                    samples[1]['boot_id'] = 'fedcba98-7654-4321-8abc-0123456789ab'
                    self.artifact('cpu_samples', ''.join(json.dumps(row) + '\n' for row in samples))
                result = self.import_run()
                self.assertIsNone(result['manifest']['total_cpu_ns_bounds'])
                self.assertTrue(any('cpu' in error.lower() for error in result['errors']), result['errors'])

    def test_equal_cpu_budget_does_not_pair_different_selected_cpu_ids(self):
        self.selected_samples()
        left, right = run_fixture(), run_fixture('K-BPF')
        for run in (left, right):
            run.update(cpu_accounting='cpu_set_total', cpu_budget=1, measurement_cpu_count=1,
                       cpu_scope=copy.deepcopy(self.manifest['cpu_scope']))
        right['cpu_scope']['selected_cpus'] = [1]
        right['cpu_scope']['online_cpus'] = [1]
        result = analyze.compare_runs(left, right)
        self.assertFalse(result['eligible'])
        self.assertIsNone(result['delta'])
        self.assertTrue(any('cpu' in error.lower() for error in result['errors']), result['errors'])

    def test_nonobject_selected_cpu_jsonl_returns_unavailable_without_exception(self):
        for malformed in ([], None):
            with self.subTest(malformed=malformed):
                self.selected_samples()
                path = Path(self.receipt['artifacts']['cpu_samples']['path'])
                samples = [json.loads(line) for line in path.read_text().splitlines()]
                samples[1] = malformed
                self.artifact('cpu_samples', ''.join(json.dumps(row) + '\n' for row in samples))
                try:
                    observed = self.inspect()
                    result = self.import_run()
                except Exception as error:
                    self.fail('malformed CPU evidence escaped admission as %s: %s' %
                              (type(error).__name__, error))
                self.assertIsNone(observed['total_cpu_ns'])
                self.assertIsNone(observed['total_cpu_ns_bounds'])
                self.assertTrue(any('cpu' in error.lower() for error in observed['errors']),
                                observed['errors'])
                self.assertIsNone(result['manifest']['total_cpu_ns'])
                self.assertIsNone(result['manifest']['total_cpu_ns_bounds'])
                self.assertIsNone(result['manifest']['metrics'].get('cpu_ns_per_record'))
                self.assertIsNone(result['manifest']['metrics'].get('cpu_ns_per_record_bounds'))
                self.assertFalse(result['performance_eligible'])

    def test_same_cpu_ids_cannot_pair_held_primary_bounds_but_legacy_diagnostics_survive(self):
        self.selected_samples(status='hold')
        scope = copy.deepcopy(self.manifest['cpu_scope'])
        scope['hold_reasons'] = ['unqualified']
        left, right = run_fixture(), run_fixture('K-BPF')
        for run, lower, upper in ((left, 10, 20), (right, 20, 30)):
            run['total_cpu_ns'] = None
            run['total_cpu_ns_bounds'] = dict(lower=lower, upper=upper)
            run['metrics']['cpu_ns_per_record'] = None
            run['metrics']['cpu_ns_per_record_bounds'] = dict(lower=lower, upper=upper)
        legacy = analyze.compare_runs(left, right)
        self.assertTrue(legacy['eligible'], legacy['errors'])
        self.assertEqual(legacy['delta']['cpu_ns_per_record_bounds'], dict(lower=0, upper=20))
        self.assertFalse(legacy['performance_eligible'])
        for run in (left, right):
            run.update(cpu_scope=copy.deepcopy(scope), cpu_budget=1, measurement_cpu_count=1)
        held = analyze.compare_runs(left, right)
        self.assertFalse(held['eligible'], 'same selected CPUs bypassed HOLD qualification')
        self.assertIsNone(held['delta'])
        self.assertTrue(any('cpu' in error.lower() for error in held['errors']), held['errors'])
        self.assertFalse(held['performance_eligible'])

    def test_measurement_count_two_with_legacy_budget_one_preserves_both_meanings(self):
        recipe = copy.deepcopy(self.manifest['recipe'])
        self.selected_samples(selected=(0, 1))
        result = self.import_run()
        bounds = result['manifest']['total_cpu_ns_bounds']
        self.assertIsNotNone(bounds, result['errors'])
        self.assertEqual((bounds['lower'], bounds['upper']), (60_000_000, 200_000_000))
        self.assertEqual(result['manifest']['cpu_budget'], 1)
        self.assertEqual(result['manifest']['measurement_cpu_count'], 2)
        self.assertEqual(result['manifest']['cpu_scope']['selected_cpus'], [0, 1])
        self.assertEqual(result['manifest']['recipe'], recipe)
        self.assertEqual(self.metadata['cpu_budget'], 1)
        self.assertEqual(self.metadata['measurement_cpu_count'], 2)
        self.assertFalse(any(error.startswith('system_cpu:') for error in result['errors']), result['errors'])
        self.assertFalse(result['performance_eligible'])

    def test_selected_count_missing_bool_or_wrong_value_never_falls_back_to_budget(self):
        for count in ('missing', True, 1, 0, -1, 2.0):
            with self.subTest(count=count):
                self.selected_samples(selected=(0, 1))
                # Legacy budget happens to equal selected cardinality here.
                # It must not rescue a missing or malformed measurement count.
                self.manifest['cpu_budget'] = self.metadata['cpu_budget'] = 2
                for record in (self.manifest, self.metadata):
                    if count == 'missing':
                        record.pop('measurement_cpu_count')
                    else:
                        record['measurement_cpu_count'] = count
                self.artifact('trace_metadata', json.dumps(self.metadata))
                result = self.import_run()
                self.assertIsNone(result['manifest']['total_cpu_ns_bounds'])
                self.assertIsNone(result['manifest']['metrics'].get('cpu_ns_per_record_bounds'))
                self.assertTrue(any('cpu' in error.lower() for error in result['errors']), result['errors'])
                self.assertFalse(result['performance_eligible'])

    def test_selected_count_must_match_manifest_and_trace_metadata_independently(self):
        for changed in ('manifest', 'metadata'):
            for count in ('missing', True, 1):
                with self.subTest(changed=changed, count=count):
                    self.selected_samples(selected=(0, 1))
                    self.manifest['cpu_budget'] = self.metadata['cpu_budget'] = 2
                    record = self.manifest if changed == 'manifest' else self.metadata
                    if count == 'missing':
                        record.pop('measurement_cpu_count')
                    else:
                        record['measurement_cpu_count'] = count
                    self.artifact('trace_metadata', json.dumps(self.metadata))
                    result = self.import_run()
                    self.assertIsNone(result['manifest']['total_cpu_ns_bounds'])
                    self.assertTrue(any('cpu' in error.lower() for error in result['errors']), result['errors'])

    def test_selected_pair_requires_measurement_count_and_keeps_legacy_budget_matching(self):
        self.selected_samples()
        left, right = run_fixture(), run_fixture('K-BPF')
        for run in (left, right):
            run.update(cpu_accounting='cpu_set_total', cpu_budget=1, measurement_cpu_count=1,
                       cpu_scope=copy.deepcopy(self.manifest['cpu_scope']))
        matched = analyze.compare_runs(left, right)
        self.assertTrue(matched['eligible'], matched['errors'])
        self.assertFalse(matched['performance_eligible'])
        for changed, value in (('measurement_cpu_count', 'missing'),
                               ('measurement_cpu_count', True),
                               ('measurement_cpu_count', 2), ('cpu_budget', 2)):
            with self.subTest(changed=changed, value=value):
                different = copy.deepcopy(right)
                if value == 'missing':
                    different.pop(changed)
                else:
                    different[changed] = value
                report = analyze.compare_runs(left, different)
                self.assertFalse(report['eligible'])
                self.assertIsNone(report['delta'])
                self.assertTrue(any('cpu' in error.lower() for error in report['errors']), report['errors'])


if __name__ == '__main__':
    unittest.main()

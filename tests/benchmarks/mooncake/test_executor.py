"""Independent V3 assertions; all numeric values below are parser fixtures.

No devices, sockets, CUDA runtime or loader. Missing component is SETUP, not RED.
"""
import copy
from dataclasses import FrozenInstanceError
import importlib
import importlib.util
import io
from contextlib import redirect_stdout, redirect_stderr
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
CHILD = HERE / 'fixtures' / 'executor' / 'child.py'
SEGMENT = 'file:///fixture/input'


def component():
    try:
        return importlib.import_module('executor')
    except ModuleNotFoundError as error:
        raise RuntimeError('NEW_COMPONENT_SETUP: executor is absent; no semantic RED') from error


def shape(experiment='e4'):
    value = dict(schema_version=1, experiment=experiment, block_bytes=[4096],
                 batch_requests=[8], worker_threads=2, buffer_bytes=1048576,
                 target_bytes=1048576, target_offset=0, duration_seconds=1,
                 repetitions=1, op_type='read', target_access='random',
                 pinned_slot_kib=4, pinned_slots=16, gpu_ordinal=0)
    if experiment == 'e7':
        value.update(op_type='write', target_access='fixed')
        del value['pinned_slot_kib'], value['pinned_slots']
    return value


def cell(experiment='e4', arm='iouring-default'):
    return dict(cell_id='native-' + arm + '-b4096-q8-r0', profile='native',
                experiment=experiment, arm=arm, block_bytes=4096,
                batch_requests=8, repetition=0, shape=shape(experiment),
                rig_identity={'gpu_uuid': 'fixture-gpu', 'gpu_pci_bdf': '0000:00:00.0'},
                expected_segment=SEGMENT if experiment == 'e4' else 'opaque:live')


def native(experiment='e4', segment=SEGMENT):
    # Independently hand-derived: 100 batches × 8 × 4096 = 3276800 bytes.
    return dict(schema_version=1, record_type='target_metrics', backend='tent',
                op_type='read' if experiment == 'e4' else 'write', block_size=4096,
                batch_size=8, num_threads=2, aggregate_operations=100,
                aggregate_transferred_bytes=3276800,
                aggregate_throughput_gbps=0.0016384, targets=[dict(
                    index=0, segment_name=segment, threads=2, operations=100,
                    transferred_bytes=3276800, total_duration_us=2000000.0,
                    throughput_gbps=0.0016384, avg_latency_us=40000.0,
                    avg_transfer_us=0.0, p99_us=0.0, p999_us=0.0,
                    avg_instant_gbps=0.005)])


class NativeAdmission(unittest.TestCase):
    def setUp(self):
        self.ex = component()
        self.temp = tempfile.TemporaryDirectory(prefix='mooncake-native-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'native.jsonl'

    def qualify(self, record=None, raw=None, request=None, segment=SEGMENT):
        self.path.write_bytes(raw if raw is not None else
                             (json.dumps(record if record is not None else native()) + '\n').encode())
        return self.ex.qualify_native(self.path, request or cell(), segment)

    def test_completed_batches_are_admitted_with_native_units(self):
        result = self.qualify()
        self.assertEqual(result['result_qualification'], 'qualified')
        self.assertFalse(result['ratio_eligible'])
        self.assertEqual(self.path.read_bytes(), (json.dumps(native()) + '\n').encode())

    def test_e7_write_must_match_fresh_opaque_segment(self):
        self.assertEqual(self.qualify(native('e7', 'opaque:live'), request=cell('e7', 'tcp'),
                                     segment='opaque:live')['result_qualification'], 'qualified')
        self.assertNotEqual(self.qualify(native('e7', 'opaque:stale'), request=cell('e7', 'tcp'),
                                        segment='opaque:live')['result_qualification'], 'qualified')

    def test_every_identity_count_and_formula_corruption_refuses(self):
        root = {'schema_version': 2, 'record_type': 'other', 'backend': 'rdma',
                'op_type': 'write', 'block_size': 8192, 'batch_size': 1,
                'num_threads': 1, 'aggregate_operations': 800,
                'aggregate_transferred_bytes': 1, 'aggregate_throughput_gbps': 0.1}
        target = {'index': 1, 'segment_name': SEGMENT + ' ', 'threads': 1,
                  'operations': 800, 'transferred_bytes': 1,
                  'total_duration_us': 999999., 'throughput_gbps': 0.1,
                  'avg_latency_us': 1, 'avg_transfer_us': -1,
                  'p99_us': -1, 'p999_us': -1, 'avg_instant_gbps': -1}
        for scope, values in [('root', root), ('target', target)]:
            for key, value in values.items():
                with self.subTest(scope=scope, key=key):
                    record = native()
                    (record if scope == 'root' else record['targets'][0])[key] = value
                    self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')

    def test_uint64_int32_and_boolean_type_bounds(self):
        cases = [('aggregate_operations', True), ('aggregate_operations', 0),
                 ('aggregate_operations', 2**64), ('block_size', True),
                 ('num_threads', True), ('num_threads', 2**31),
                 ('aggregate_transferred_bytes', 2**64)]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                record = native(); record[key] = value
                self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')
        for key in ('operations', 'threads', 'index', 'transferred_bytes', 'total_duration_us',
                    'throughput_gbps', 'avg_latency_us', 'avg_transfer_us', 'p99_us', 'p999_us',
                    'avg_instant_gbps'):
            with self.subTest(target_boolean=key):
                record = native(); record['targets'][0][key] = True
                self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')
        record = native()
        record['aggregate_operations'] = record['targets'][0]['operations'] = 2**63
        record['aggregate_transferred_bytes'] = record['targets'][0]['transferred_bytes'] = 1
        self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')

    def test_exact_keys_one_target_and_all_fields_required(self):
        for scope in ('root', 'target'):
            keys = native().keys() if scope == 'root' else native()['targets'][0].keys()
            for key in keys:
                with self.subTest(scope=scope, missing=key):
                    record = native(); del (record if scope == 'root' else record['targets'][0])[key]
                    self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')
            record = native(); (record if scope == 'root' else record['targets'][0])['extra'] = 0
            self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')
        for targets in ([], [native()['targets'][0], native()['targets'][0]]):
            record = native(); record['targets'] = targets
            self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')

    def test_nonfinite_duplicate_partial_multiline_and_limits_refuse(self):
        good = json.dumps(native()).encode()
        payloads = [b'', b'\n', good[:-1], good, good + b'\n' + good + b'\n',
                    good.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1') + b'\n',
                    good.replace(b'"index": 0', b'"index": 0, "index": 0') + b'\n',
                    good.replace(b'2000000.0', b'NaN') + b'\n',
                    good.replace(b'2000000.0', b'Infinity') + b'\n',
                    good.replace(b'2000000.0', b'1e999') + b'\n',
                    b'\xff\n', b' ' * (1024 * 1024 + 1) + b'\n']
        for index, raw in enumerate(payloads):
            with self.subTest(corruption=index):
                self.assertNotEqual(self.qualify(raw=raw)['result_qualification'], 'qualified')

    def test_zero_tx_and_slow_final_batch_are_legal_without_percentile_guess(self):
        record = native()
        record['targets'][0].update(total_duration_us=4000000.0, throughput_gbps=0.0008192,
                                    avg_latency_us=80000., p99_us=1., p999_us=2., avg_transfer_us=300.)
        record['aggregate_throughput_gbps'] = 0.0008192
        self.assertEqual(self.qualify(record)['result_qualification'], 'qualified')
        record['targets'][0]['p999_us'] = .5
        self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')

    def test_duration_is_mean_worker_duration_and_tolerance_is_not_display_rounding(self):
        record = native()
        # Reported mean worker duration 0.5M us < requested one second.
        record['targets'][0].update(total_duration_us=500000., throughput_gbps=0.0065536,
                                    avg_latency_us=10000.)
        record['aggregate_throughput_gbps'] = 0.0065536
        self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')
        record = native(); record['aggregate_throughput_gbps'] = .00164
        self.assertNotEqual(self.qualify(record)['result_qualification'], 'qualified')


class BannerAdmission(unittest.TestCase):
    def setUp(self):
        self.ex = component()
        self.temp = tempfile.TemporaryDirectory(prefix='mooncake-banner-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'stdout.raw'

    def parse(self, line):
        self.path.write_bytes(line)
        return self.ex.parse_target_ready(self.path)

    def test_source_banner_allows_opaque_token_and_color_only(self):
        for color in (b'', b'\x1b[32m'):
            self.assertEqual(self.parse(color + b'To start initiators, run\n'
                b'  ./tebench --target_seg_name=opaque:fresh/seg-42 --seg_type=VRAM --backend=tent\n'
                b'Press Ctrl-C to terminate\x1b[0m\n'), 'opaque:fresh/seg-42')

    def test_missing_ambiguous_placeholder_or_unsafe_segment_never_readies(self):
        bad = [b'', b'x' * (1024 * 1024 + 1) + b'\n', b'file://old\n',
               b'./tebench --target_seg_name=x --seg_type=DRAM --backend=tent\n',
               b'./tebench --target_seg_name=x --seg_type=VRAM --backend=tcp\n']
        for token in (b'', b'x,y', b'x y', b'$(id)', b'`id`',
                      b'{FRESH_TARGET_SEGMENT_NAME}', b'x\x00y', b'x\xffy'):
            bad.append(b'  ./tebench --target_seg_name=' + token + b' --seg_type=VRAM --backend=tent\n')
        bad.append(b'  ./tebench --target_seg_name=x --seg_type=VRAM --backend=tent\n'
                   b'  ./tebench --target_seg_name=y --seg_type=VRAM --backend=tent\n')
        for index, payload in enumerate(bad):
            with self.subTest(payload=index):
                with self.assertRaises((ValueError, RuntimeError)):
                    self.parse(payload)


class RealChildBoundary(unittest.TestCase):
    def setUp(self):
        self.ex = component()
        self.temp = tempfile.TemporaryDirectory(prefix='mooncake-child-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / 'payload.jsonl'
        self.payload.write_text(json.dumps(native()) + '\n')
        self.context = self.ex.ExecutionContext(kind='contract-fixture', profile='native',
            qualified_receipt={'qualified': True, 'mechanically_checked': [],
                               'evidence_declared': []}, endpoint='local')

    def run_child(self, behavior='success', log='', arm='iouring-default', timeout=5, literal=''):
        output = self.root / ('cell-' + str(time.monotonic_ns()))
        config = self.root / ('config-' + str(time.monotonic_ns()) + '.json')
        config.write_text(json.dumps({'transports': {'io_uring': {
            'pinned_staging': arm == 'iouring-pinned', 'staging_slot_kb': 4, 'staging_slots': 16}}}))
        argv = [sys.executable, str(CHILD), '--behavior=' + behavior,
                '--payload=' + str(self.payload), '--result_output_jsonl=' + str(output / 'native.jsonl'),
                '--target_seg_name=' + SEGMENT, '--literal=' + literal, '--log=' + log]
        command = dict(schema_version=1, cell_id=cell(arm=arm)['cell_id'], profile='native', arm=arm,
                       argv=argv, env={'MC_TENT_CONF': str(config)}, config_file=str(config), needs_build=False)
        result = self.ex.execute_cell(command, cell(arm=arm), self.context, output, timeout)
        return result, output

    def assert_fixture(self, result):
        self.assertEqual(result['execution'], 'contract-fixture')
        self.assertEqual(result['performance_claim'], 'none')
        self.assertFalse(result['ratio_eligible'])

    def test_real_success_preserves_raw_streams_and_never_promotes_fixture(self):
        result, output = self.run_child('physical-looking')
        self.assertEqual(result['status'], 'fixture_completed')
        self.assert_fixture(result)
        self.assertIn(b'\xff', (output / 'stdout.raw').read_bytes())
        self.assertIn(b'\xfe', (output / 'stderr.raw').read_bytes())
        process = json.loads((output / 'process.json').read_text())
        self.assertEqual(process['returncode'], 0)
        self.assertTrue(process['cleanup_complete'])
        self.assertGreater(process['elapsed_monotonic_ns'], 0)
        # Metrics belong only to the nested fixture artifact, never flat benchmark fields.
        for key in ('aggregate_throughput_gbps', 'throughput_gbps', 'avg_latency_us', 'p99_us'):
            self.assertNotIn(key, result)

    def test_nonzero_missing_partial_and_failure_logs_override_valid_number(self):
        cases = [('exit17', ''), ('missing', ''), ('partial', '')]
        for fragment in ('Failed to allocate transfer batch', 'Failed to submit transfer:',
                         'Failed to poll transfer:', 'Failed transfer detected', 'Skipped for block_size',
                         'target range is smaller than one operation', 'E1101 12:00:00.000 test.cc:1] fatal'):
            cases.append(('success', fragment + '\n'))
        for behavior, log in cases:
            with self.subTest(behavior=behavior, log=log):
                result, output = self.run_child(behavior, log)
                self.assertNotEqual(result['status'], 'fixture_completed')
                self.assert_fixture(result)
                self.assertTrue((output / 'receipt.json').is_file())

    def test_minimal_environment_stdin_and_literal_argv_are_real(self):
        poison = {'MC_IOURING_SECRET': 'never-record-this-secret', 'MOONCAKE_LOCAL_HOSTNAME': 'bad',
                  'CUDA_VISIBLE_DEVICES': 'bad', 'CUFILE_ENV_PATH_JSON': 'bad', 'GFLAGS_X': 'bad',
                  'LD_PRELOAD': '/nonexistent-secret', 'LD_LIBRARY_PATH': '/tmp/stubs'}
        literal = 'ordinary spaces; $(touch forbidden) `touch forbidden2`'
        with mock.patch.dict(os.environ, poison):
            result, output = self.run_child(literal=literal)
        self.assertEqual(result['status'], 'fixture_completed')
        observed = json.loads((output / 'fixture-observation.json').read_text())
        self.assertEqual(observed['literal'], literal)
        self.assertTrue(observed['stdin_eof'])
        self.assertEqual(observed['cwd'], str(output))
        self.assertEqual(observed['pgid'], observed['pid'])
        for key in poison:
            self.assertNotIn(key, observed['environment'])
        self.assertEqual(observed['environment']['LC_ALL'], 'C')
        self.assertFalse((output / 'forbidden').exists())
        self.assertFalse((output / 'forbidden2').exists())
        self.assertNotIn('never-record-this-secret', (output / 'receipt.json').read_text())

    def test_pinned_and_buffered_fallbacks_cannot_keep_requested_route(self):
        good = 'IOUringTransport: pinned staging pool of 16 x 4 KiB\n'
        result, _ = self.run_child(log=good, arm='iouring-pinned')
        self.assertEqual(result['route_qualification'], 'qualified')
        for fragment in ('', 'no pinned staging pool', 'no free pinned staging slot',
                         'using a pageable buffer', 'staging with pageable buffers',
                         'opened in Buffered I/O mode',
                         'IOUringTransport: pinned staging pool of 15 x 4 KiB'):
            with self.subTest(fallback=fragment):
                log = '' if not fragment else good + fragment + '\n'
                result, _ = self.run_child(log=log, arm='iouring-pinned')
                self.assertNotEqual(result['route_qualification'], 'qualified')
                self.assertNotEqual(result['status'], 'fixture_completed')
        for log in (good, 'opened in Buffered I/O mode\n'):
            result, _ = self.run_child(log=log)
            self.assertNotEqual(result['route_qualification'], 'qualified')

    def test_gds_environment_request_without_route_evidence_stays_unqualified(self):
        result, _ = self.run_child(arm='gds-compat')
        self.assertNotEqual(result['route_qualification'], 'qualified')
        self.assertNotEqual(result['status'], 'fixture_completed')
        self.assert_fixture(result)

    def test_unknown_warning_requires_owner_route_review(self):
        result, _ = self.run_child(log='W1101 12:00:00.000 test.cc:1] unknown transport warning\n')
        self.assertNotEqual(result['route_qualification'], 'qualified')
        self.assertTrue(result['warnings'])

    def test_timeout_kills_only_owned_group_and_reaps_real_children(self):
        bystander = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                    stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            result, output = self.run_child('descendant', timeout=.25)
            self.assertNotEqual(result['status'], 'fixture_completed')
            process = json.loads((output / 'process.json').read_text())
            self.assertEqual(process['termination'], 'timeout')
            self.assertTrue(process['cleanup_complete'])
            self.assertEqual(json.dumps(process['signals']).count('SIGTERM'), 1)
            self.assertEqual(json.dumps(process['signals']).count('SIGKILL'), 1)
            self.assertIsNotNone(process['returncode'])
            self.assertIsNone(bystander.poll(), 'executor signaled a preexisting unowned child')
            observed = json.loads((output / 'fixture-observation.json').read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(observed['pid'], 0)
            descendant = int((output / 'descendant.pid').read_text())
            # A dead orphan may briefly remain a zombie until PID1 reaps it.
            stat_path = Path('/proc') / str(descendant) / 'stat'
            if stat_path.exists():
                self.assertEqual(stat_path.read_text().split()[2], 'Z')
        finally:
            if bystander.poll() is None:
                bystander.kill()
            bystander.wait(timeout=5)

    def test_flood_drains_both_streams_boundedly_and_fails(self):
        result, output = self.run_child('flood', timeout=20)
        self.assertNotEqual(result['status'], 'fixture_completed')
        process = json.loads((output / 'process.json').read_text())
        self.assertEqual(process['termination'], 'output_limit')
        self.assertTrue(process['cleanup_complete'])
        self.assertGreater(max(process['stdout_bytes'], process['stderr_bytes']), 64 * 1024 * 1024)
        for name in ('stdout.raw', 'stderr.raw'):
            size = (output / name).stat().st_size
            self.assertGreater(size, 0)
            self.assertLessEqual(size, 64 * 1024 * 1024)

    def test_oversized_native_output_terminates_child_before_wall_timeout(self):
        result, output = self.run_child('native-flood', timeout=10)
        self.assertNotEqual(result['status'], 'fixture_completed')
        process = json.loads((output / 'process.json').read_text())
        self.assertEqual(process['termination'], 'output_limit')
        self.assertTrue(process['cleanup_complete'])
        self.assertLess(process['elapsed_monotonic_ns'], 10 * 1000000000)

    def test_execution_kind_is_immutable(self):
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            self.context.kind = 'physical'

    def test_existing_artifacts_and_symlink_output_are_preserved(self):
        # Path refusal must happen before a fixture child could write its observation.
        protected = self.root / 'protected'; protected.mkdir()
        (protected / 'native.jsonl').write_text('retained original\n')
        link = self.root / 'alias'; link.symlink_to(protected, target_is_directory=True)
        for output in (protected, link):
            command = {'argv': [sys.executable, str(CHILD)], 'env': {}}
            try:
                result = self.ex.execute_cell(command, cell(), self.context, output, 1)
            except (ValueError, OSError):
                pass
            else:
                self.assertNotEqual(result['status'], 'fixture_completed')
        self.assertEqual((protected / 'native.jsonl').read_text(), 'retained original\n')
        self.assertFalse((protected / 'fixture-observation.json').exists())


class OwnedTargetBoundary(unittest.TestCase):
    def setUp(self):
        self.ex = component()
        self.temp = tempfile.TemporaryDirectory(prefix='mooncake-target-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.context = self.ex.ExecutionContext(kind='contract-fixture', profile='native',
            qualified_receipt={'qualified': True, 'route_qualified': True, 'campaign_id': 'fixture-campaign',
                               'mechanically_checked': [], 'evidence_declared': []},
            endpoint='destination')

    def start(self, behavior='target'):
        output = self.root / ('target-' + str(time.monotonic_ns()))
        config = self.root / ('config-' + str(time.monotonic_ns()) + '.json')
        config.write_text('{"rpc_server_hostname":"fixture-no-socket"}\n')
        request = cell('e7', 'tcp')
        request['rig_identity']['endpoints'] = {
            'destination': {'host_id': 'fixture-destination', 'address': 'fixture-no-socket'}}
        request.update(expected_segment='opaque:live', campaign_id='fixture-campaign',
                       source_host_id='fixture-source', destination_host_id='fixture-destination')
        command = dict(argv=[sys.executable, str(CHILD), '--behavior=' + behavior,
                            '--segment=opaque:live'], env={'MC_TENT_CONF': str(config)},
                       config_file=str(config), profile='native', arm='tcp',
                       cell_id=request['cell_id'])
        handle = self.ex.start_target(command, request, self.context, output)
        self.addCleanup(self.cleanup_handle, handle)
        return handle

    @staticmethod
    def cleanup_handle(handle):
        # Last-resort test cleanup owns only the returned fixture process group.
        if handle.process.poll() is None:
            os.killpg(handle.process.pid, signal.SIGKILL)
        handle.process.wait(timeout=10)

    @staticmethod
    def completion(handle):
        ready = handle.ready_receipt
        return dict(schema_version=1, campaign_id=ready['campaign_id'],
                    cell_id=ready['cell_id'], profile=ready['profile'],
                    destination_host_id=ready['host_id'], launch_id=ready['launch_id'],
                    segment_name=ready['segment_name'], source_host_id='fixture-source',
                    endpoint='source', execution='contract-fixture', status='source_completed',
                    source_returncode=0, source_cleanup_complete=True,
                    source_receipt='/other-host/fixture/source-receipt.json')

    def test_matched_source_completion_gracefully_stops_exact_owned_target(self):
        handle = self.start()
        result = self.ex.stop_target(handle, self.completion(handle))
        self.assertEqual(handle.process.poll(), 0)
        self.assertTrue(result['target_alive_through_source_completion'])
        self.assertEqual(result['execution'], 'contract-fixture')
        self.assertEqual(result['performance_claim'], 'none')
        self.assertFalse(result['ratio_eligible'])
        process = json.loads((Path(handle.output_dir) / 'process.json').read_text())
        self.assertTrue(process['cleanup_complete'])
        self.assertEqual(process['returncode'], 0)
        self.assertEqual(json.dumps(process['signals']).count('SIGTERM'), 1)
        self.assertEqual(json.dumps(process['signals']).count('SIGKILL'), 0)

    def test_forced_target_kill_is_failed_cleanup(self):
        handle = self.start('target-ignore-term')
        result = self.ex.stop_target(handle, self.completion(handle))
        self.assertIsNotNone(handle.process.poll())
        self.assertNotEqual(result.get('status'), 'fixture_completed')
        self.assertNotEqual(result.get('status'), 'completed')
        process = json.loads((Path(handle.output_dir) / 'process.json').read_text())
        self.assertEqual(json.dumps(process['signals']).count('SIGTERM'), 1)
        self.assertEqual(json.dumps(process['signals']).count('SIGKILL'), 1)

    def test_ready_receipt_is_current_owned_and_collector_stays_live(self):
        handle = self.start()
        ready = handle.ready_receipt
        self.assertEqual(ready['schema_version'], 1)
        self.assertEqual(ready['cell_id'], 'native-tcp-b4096-q8-r0')
        self.assertEqual(ready['profile'], 'native')
        self.assertEqual(ready['segment_name'], 'opaque:live')
        self.assertTrue(ready['target_alive'])
        self.assertEqual(ready['campaign_id'], 'fixture-campaign')
        self.assertEqual(ready['host_id'], 'fixture-destination')
        self.assertTrue(ready['launch_id'])
        self.assertEqual(ready['allocation_receipt'], {'scope': 'upstream-target-ready-banner',
                          'buffer_bytes': 1048576, 'gpu_ordinal': 0, 'residency': 'VRAM'})
        self.assertIsNone(handle.process.poll())
        stderr = Path(handle.output_dir) / 'stderr.raw'
        before = stderr.stat().st_size
        time.sleep(.15)
        self.assertGreater(stderr.stat().st_size, before, 'readiness must not stop stream draining')

    def test_early_exit_with_banner_never_yields_owned_live_target(self):
        try:
            handle = self.start('target-exit')
        except (ValueError, RuntimeError):
            return
        # A process that exits right after flushing its banner is not live evidence.
        handle.process.wait(timeout=3)
        source = self.completion(handle)
        result = self.ex.stop_target(handle, source)
        self.assertNotEqual(result.get('status'), 'fixture_completed')
        self.assertFalse(result.get('target_alive_through_source_completion', False))

    def test_private_source_cli_uses_fresh_owned_segment_and_no_fixture_summary_metrics(self):
        payload = self.root / 'source-payload.jsonl'
        payload.write_text(json.dumps(native('e7', 'opaque:live')) + '\n')
        wrapper = self.root / 'harmless-tebench'
        wrapper.write_text('#!' + sys.executable + '\nimport runpy,sys\n'
                           'sys.argv += ["--payload=" + ' + repr(str(payload)) + ']\n'
                           'if "--seg_type=VRAM" in sys.argv:\n'
                           '    sys.argv += ["--behavior=target","--segment=opaque:live"]\n'
                           'runpy.run_path(' + repr(str(CHILD)) + ',run_name="__main__")\n')
        wrapper.chmod(0o700)
        cpus = str(min(os.sched_getaffinity(0)))
        evidence = self.root / 'fixture-route.log'
        evidence.write_text('synthetic fixture only; no hardware or network\n')
        endpoints = {}
        for role in ('source', 'destination'):
            endpoints[role] = dict(host_id='fixture-' + role, address='192.0.2.' +
                ('1' if role == 'source' else '2'), rpc_port=12345 if role == 'source' else 12346,
                interface='fixture-no-device', mtu=1500, cpuset=cpus, numa_node=0,
                cpu_budget_description='fixture all-thread declaration', kernel_release=os.uname().release,
                kernel_source_revision='fixture-kernel', route_receipt={'evidence':[str(evidence)]},
                usb4_link_receipt={'evidence':[str(evidence)]})
        rig = dict(schema_version=1, execution='physical', physical_run_authorized=True,
                   kernel_release=os.uname().release, kernel_source_revision='fixture-kernel',
                   nvidia_driver_version='fixture-driver', cuda_version='fixture-cuda',
                   gpu_uuid='fixture-gpu', gpu_pci_bdf='0000:00:00.0', gpu_model='fixture-model',
                   cpuset=cpus, numa_node=0, cpu_budget_description='fixture all-thread declaration',
                   source_revision='d01447808d10af78011e9203d53796a15a032a03', source_tree_verified=True,
                   build_receipt={'USE_TENT':True,'USE_CUDA':True,'liburing':True}, endpoints=endpoints)
        # Launch target only after destination facts and canonical semantics are fixed.
        target_output = self.root / 'canonical-target'
        target_config = self.root / 'canonical-target-config.json'
        target_config.write_text(json.dumps({'rpc_server_hostname':endpoints['destination']['address']}) + '\n')
        target_request = cell('e7','tcp')
        target_request.update(rig_identity=copy.deepcopy(rig), expected_segment='opaque:live',
            campaign_id='fixture-campaign', source_host_id='fixture-source',
            destination_host_id='fixture-destination')
        target_command = dict(schema_version=1, cell_id=target_request['cell_id'], profile='native', arm='tcp',
            argv=['taskset','--cpu-list',cpus,str(wrapper),'--backend=tent','--metadata_type=p2p',
                  '--xport_type=tcp','--seg_type=VRAM','--local_gpu_id=0',
                  '--total_buffer_size=1048576','--rpc_server_port=12346'],
            env={'MC_TENT_CONF':str(target_config)}, config_file=str(target_config), needs_build=False)
        handle = self.ex.start_target(target_command,target_request,self.context,target_output)
        self.addCleanup(self.cleanup_handle,handle)
        ready_file = self.root / 'copied-ready.json'
        ready_file.write_text(json.dumps(handle.ready_receipt) + '\n')
        shape_file = self.root / 'shape.json'; shape_file.write_text(json.dumps(shape('e7')))
        rig_file = self.root / 'rig.json'; rig_file.write_text(json.dumps(rig))
        source_root = self.root / 'upstream-source'; source_root.mkdir()
        output = self.root / 'source-output'
        context = self.ex.ExecutionContext(kind='contract-fixture', profile='native',
            qualified_receipt={'qualified':True, 'route_qualified':True, 'campaign_id':'fixture-campaign',
                               'mechanically_checked':[], 'evidence_declared':[]}, endpoint='source')
        spec = importlib.util.spec_from_file_location('mooncake_fixture_source_cli', HERE / 'run.py')
        run = importlib.util.module_from_spec(spec); sys.modules[spec.name] = run
        spec.loader.exec_module(run)
        args = ['--mode','run','--experiment','e7','--shape',str(shape_file), '--rig',str(rig_file),
                '--source-root',str(source_root), '--tebench',str(wrapper), '--profile','native',
                '--cell-id','native-tcp-b4096-q8-r0', '--campaign-id','fixture-campaign',
                '--endpoint','source','--ready-receipt',str(ready_file), '--output-dir',str(output)]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = run.main(args, execution_context=context)
        self.assertEqual(code, 0)
        observations = list(output.rglob('fixture-observation.json'))
        self.assertEqual(len(observations), 1, 'only selected source cell may launch')
        argv = json.loads(observations[0].read_text())['argv']
        self.assertIn('--target_seg_name=opaque:live', argv)
        self.assertFalse(any('{FRESH_TARGET_SEGMENT_NAME}' in arg for arg in argv))
        completions = list(output.rglob('source-completion.json'))
        self.assertEqual(len(completions), 1)
        completion = json.loads(completions[0].read_text())
        self.assertEqual(completion['status'], 'source_completed')
        self.assertEqual(completion['launch_id'], handle.ready_receipt['launch_id'])
        self.assertEqual(completion['execution'], 'contract-fixture')
        self.assertIsNone(handle.process.poll())
        for field, bad in [('campaign_id','old-campaign'), ('cell_id','other-cell'),
                           ('profile','xdev_ext'), ('target_alive',False)]:
            with self.subTest(stale_ready=field):
                stale = dict(handle.ready_receipt); stale[field] = bad
                ready_file.write_text(json.dumps(stale) + '\n')
                refused_output = self.root / ('refused-' + field)
                refused_args = list(args)
                refused_args[-1] = str(refused_output)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    refused_code = run.main(refused_args, execution_context=context)
                self.assertIn(refused_code, (1, 4))
                self.assertFalse(list(refused_output.rglob('fixture-observation.json')))
        final = self.ex.stop_target(handle, completion)
        self.assertTrue(final['target_alive_through_source_completion'])
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['performance_claim'], 'none')
        self.assertFalse(summary['ratio_eligible'])
        # Fixture numeric payload must never escape into summary rows.
        self.assertNotIn('aggregate_throughput_gbps', json.dumps(summary))
        self.assertNotIn('avg_latency_us', json.dumps(summary))

    def test_mismatched_source_completion_cannot_qualify_target_stop(self):
        for field, value in [('campaign_id', 'stale-campaign'), ('cell_id', 'other-cell'),
                             ('profile', 'xdev_ext'), ('segment_name', 'opaque:old'),
                             ('launch_id', 'old-launch'), ('destination_host_id', 'wrong-host'),
                             ('source_host_id', 'wrong-source'), ('endpoint', 'destination'),
                             ('execution', 'physical'), ('status', 'source_failed'),
                             ('source_returncode', 17), ('source_cleanup_complete', False)]:
            with self.subTest(field=field):
                handle = self.start()
                source = self.completion(handle)
                source[field] = value
                try:
                    result = self.ex.stop_target(handle, source)
                except (ValueError, RuntimeError):
                    self.assertIsNotNone(handle.process.poll(), 'bad handoff left owned target running')
                    continue
                self.assertIsNotNone(handle.process.poll(), 'bad handoff left owned target running')
                self.assertNotEqual(result.get('status'), 'fixture_completed')
                self.assertNotEqual(result.get('status'), 'completed')


if __name__ == '__main__':
    unittest.main()

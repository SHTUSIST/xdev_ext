"""Independent root-reviewed V3 regressions; no producer/control code imported.

Only public validation/execution boundaries are exercised. All subprocesses are
harmless fixture children or static qualification tools; never sockets/devices.
"""
from contextlib import redirect_stdout, redirect_stderr
import copy
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

import test_executor as executor_cases
import test_qualification as qualification_cases
from test_executor import CHILD, HERE, cell, component, native, shape


class ReviewNativeRouteAndLogLimits(unittest.TestCase):
    setUp = executor_cases.RealChildBoundary.setUp
    run_child = executor_cases.RealChildBoundary.run_child

    def test_r4_exact_source_pool_message_qualifies_but_prefix_extension_does_not(self):
        exact = 'IOUringTransport: pinned staging pool of 16 x 4 KiB'
        result, _ = self.run_child(log=exact + '\n', arm='iouring-pinned')
        self.assertEqual(result['route_qualification'], 'qualified')
        for suffix in ('0', 'garbage'):
            with self.subTest(suffix=suffix):
                result, _ = self.run_child(log=exact + suffix + '\n', arm='iouring-pinned')
                self.assertNotEqual(result['route_qualification'], 'qualified')
                self.assertNotEqual(result['status'], 'fixture_completed')
                self.assertEqual(result['execution'], 'contract-fixture')
                self.assertEqual(result['performance_claim'], 'none')
                self.assertFalse(result['ratio_eligible'])

    def test_r5_valid_banner_cannot_hide_oversized_line_before_or_after(self):
        path = self.root / 'ready.raw'
        banner = (b'To start initiators, run\n'
                  b'  ./tebench --target_seg_name=opaque:live --seg_type=VRAM --backend=tent\n'
                  b'Press Ctrl-C to terminate\n')
        path.write_bytes(banner)
        self.assertEqual(self.ex.parse_target_ready(path), 'opaque:live')
        long_line = b'x' * (1024 * 1024 + 1) + b'\n'
        for before in (True, False):
            with self.subTest(oversized_before=before):
                path.write_bytes(long_line + banner if before else banner + long_line)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.ex.parse_target_ready(path)


class ReviewRecordedInputFacts(unittest.TestCase):
    setUp = qualification_cases.QualificationAdmission.setUp
    validate = qualification_cases.QualificationAdmission.validate
    assert_refused = qualification_cases.QualificationAdmission.assert_refused

    def record_current_facts(self):
        info = self.corpus.input.stat()
        facts = {name:getattr(info,name) for name in
                 ('st_dev','st_ino','st_size','st_mtime_ns')}
        for key in ('input_validation_receipt','file_extent_receipt','exclusive_window_receipt'):
            self.corpus.rig[key].update(target_offset=0,target_bytes=1048576,stat=dict(facts))
        self.corpus.correctness['rig_identity'] = copy.deepcopy(self.corpus.rig)
        return facts

    def test_r1_matching_recorded_range_and_current_stat_remains_qualified(self):
        self.record_current_facts()
        self.assertTrue(self.validate()['qualified'])

    def test_r1_any_recorded_range_or_known_stat_conflict_refuses(self):
        facts = self.record_current_facts()
        for receipt_key in ('input_validation_receipt','file_extent_receipt','exclusive_window_receipt'):
            original = copy.deepcopy(self.corpus.rig[receipt_key])
            for field, bad in [('target_offset',4096),('target_bytes',524288)]:
                with self.subTest(receipt=receipt_key,range_field=field):
                    self.corpus.rig[receipt_key] = copy.deepcopy(original)
                    self.corpus.rig[receipt_key][field] = bad
                    self.assert_refused()
            for field, value in facts.items():
                with self.subTest(receipt=receipt_key,stat_field=field):
                    self.corpus.rig[receipt_key] = copy.deepcopy(original)
                    self.corpus.rig[receipt_key]['stat'][field] = value + 1
                    self.assert_refused()
                with self.subTest(receipt=receipt_key,top_level_stat=field):
                    self.corpus.rig[receipt_key] = copy.deepcopy(original)
                    self.corpus.rig[receipt_key][field] = value + 1
                    self.assert_refused()
            self.corpus.rig[receipt_key] = original


class ReviewReadyBindingAndReportCleanup(unittest.TestCase):
    cleanup_handle = staticmethod(executor_cases.OwnedTargetBoundary.cleanup_handle)
    completion = staticmethod(executor_cases.OwnedTargetBoundary.completion)

    def setUp(self):
        self.ex = component()
        self.temp = tempfile.TemporaryDirectory(prefix='mooncake-review-e7-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cpus = str(min(os.sched_getaffinity(0)))
        self.payload = self.root / 'source-payload.jsonl'
        self.payload.write_text(json.dumps(native('e7', 'opaque:live')) + '\n')
        self.wrapper = self.root / 'harmless-tebench'
        self.wrapper.write_text('#!' + sys.executable + '\nimport runpy,sys\n'
            'sys.argv += ["--payload=" + ' + repr(str(self.payload)) + ']\n'
            'if "--seg_type=VRAM" in sys.argv:\n'
            '    sys.argv += ["--behavior=target","--segment=opaque:live"]\n'
            'runpy.run_path(' + repr(str(CHILD)) + ',run_name="__main__")\n')
        self.wrapper.chmod(0o700)
        destination_bin = self.root / 'destination-bin'; destination_bin.mkdir()
        self.target_wrapper = destination_bin / 'harmless-tebench'
        self.target_wrapper.write_bytes(self.wrapper.read_bytes())
        self.target_wrapper.chmod(0o700)
        self.evidence = self.root / 'fixture-evidence.log'
        self.evidence.write_text('fixture declarations only; no socket/device/hardware\n')
        self.endpoints = {}
        for role in ('source', 'destination'):
            self.endpoints[role] = dict(host_id='fixture-' + role,
                address='192.0.2.1' if role == 'source' else '192.0.2.2',
                rpc_port=12345 if role == 'source' else 12346,
                interface='fixture-no-device', mtu=1500, cpuset=self.cpus, numa_node=0,
                cpu_budget_description='fixture declared all-thread RPC/poll/IRQ budget',
                kernel_release=os.uname().release, kernel_source_revision='fixture-kernel',
                route_receipt={'evidence':[str(self.evidence)]},
                usb4_link_receipt={'evidence':[str(self.evidence)]})
        self.rig = dict(schema_version=1, execution='physical', physical_run_authorized=True,
            kernel_release=os.uname().release, kernel_source_revision='fixture-kernel',
            nvidia_driver_version='fixture-driver', cuda_version='fixture-cuda',
            gpu_uuid='fixture-gpu', gpu_pci_bdf='0000:00:00.0', gpu_model='fixture-model',
            cpuset=self.cpus, numa_node=0, cpu_budget_description='fixture all-thread declaration',
            source_revision='d01447808d10af78011e9203d53796a15a032a03', source_tree_verified=True,
            build_receipt={'USE_TENT':True,'USE_CUDA':True,'liburing':True}, endpoints=self.endpoints)
        self.shape_file = self.root / 'shape.json'; self.shape_file.write_text(json.dumps(shape('e7')))
        self.rig_file = self.root / 'rig.json'; self.rig_file.write_text(json.dumps(self.rig))
        self.source_root = self.root / 'source'; self.source_root.mkdir()
        spec = importlib.util.spec_from_file_location('mooncake_review_cli', HERE / 'run.py')
        self.run = importlib.util.module_from_spec(spec); sys.modules[spec.name] = self.run
        spec.loader.exec_module(self.run)
        self.counter = 0

    def context(self, endpoint):
        return self.ex.ExecutionContext(kind='contract-fixture', profile='native',
            qualified_receipt={'qualified':True, 'route_qualified':True, 'campaign_id':'fixture-campaign',
                               'mechanically_checked':[], 'evidence_declared':[]}, endpoint=endpoint)

    def args(self, output, endpoint, ready=None):
        args = ['--mode','run','--experiment','e7','--shape',str(self.shape_file),
                '--rig',str(self.rig_file), '--source-root',str(self.source_root),
                '--tebench',str(self.wrapper), '--profile','native',
                '--cell-id','native-tcp-b4096-q8-r0', '--campaign-id','fixture-campaign',
                '--endpoint',endpoint, '--output-dir',str(output)]
        if endpoint == 'source':
            args += ['--ready-receipt',str(ready)]
        else:
            args += ['--source-completion',str(output / 'source-inbox.json')]
        return args

    def start_canonical_target(self):
        output = self.root / 'owned-target'
        config = self.root / 'target-config.json'
        config.write_text(json.dumps({'rpc_server_hostname':'192.0.2.2'}) + '\n')
        request = cell('e7', 'tcp')
        request.update(rig_identity=copy.deepcopy(self.rig), expected_segment='opaque:live',
                       campaign_id='fixture-campaign', source_host_id='fixture-source',
                       destination_host_id='fixture-destination')
        command = dict(schema_version=1, cell_id=request['cell_id'], profile='native', arm='tcp',
            argv=['taskset','--cpu-list',self.cpus,str(self.target_wrapper),'--backend=tent',
                  '--metadata_type=p2p','--xport_type=tcp','--seg_type=VRAM','--local_gpu_id=0',
                  '--total_buffer_size=1048576','--rpc_server_port=12346'],
            env={'MC_TENT_CONF':str(config)}, config_file=str(config), needs_build=False)
        handle = self.ex.start_target(command, request, self.context('destination'), output)
        self.addCleanup(self.cleanup_handle, handle)
        return handle

    def source(self, ready):
        self.counter += 1
        output = self.root / ('source-output-' + str(self.counter))
        ready_path = self.root / ('ready-' + str(self.counter) + '.json')
        ready_path.write_text(json.dumps(ready) + '\n')
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = self.run.main(self.args(output,'source',ready_path),
                                 execution_context=self.context('source'))
        return code, output

    def test_r2_source_accepts_matching_target_and_cross_host_path_relocation(self):
        handle = self.start_canonical_target()
        ready = copy.deepcopy(handle.ready_receipt)
        self.assertEqual(ready['target_config']['rpc_server_hostname'], '192.0.2.2')
        # Actual destination and source executables have different absolute paths.
        # The copied ready facts remain exactly those observed by target owner.
        self.assertIn(str(self.target_wrapper), ready['command_argv'])
        self.assertNotIn(str(self.wrapper), ready['command_argv'])
        code, output = self.source(ready)
        self.assertEqual(code, 0)
        self.assertEqual(len(list(output.rglob('fixture-observation.json'))), 1)
        self.assertIsNone(handle.process.poll())

    def test_r2_wrong_target_command_semantics_or_rpc_address_refuses_before_source(self):
        handle = self.start_canonical_target()
        original = copy.deepcopy(handle.ready_receipt)
        mutations = [('config_address','rpc_server_hostname','192.0.2.99'),
                     ('argv','--backend=tent','--backend=legacy'),
                     ('argv','--metadata_type=p2p','--metadata_type=etcd'),
                     ('argv','--xport_type=tcp','--xport_type=hp_tcp'),
                     ('argv','--seg_type=VRAM','--seg_type=DRAM'),
                     ('argv','--local_gpu_id=0','--local_gpu_id=1'),
                     ('argv','--total_buffer_size=1048576','--total_buffer_size=2097152'),
                     ('argv','--rpc_server_port=12346','--rpc_server_port=12347'),
                     ('taskset',self.cpus,'999999')]
        for kind, old, new in mutations:
            with self.subTest(binding=old):
                changed = copy.deepcopy(original)
                if kind == 'config_address':
                    changed['target_config'][old] = new
                else:
                    changed['command_argv'] = [new if token == old else token
                                               for token in changed['command_argv']]
                code, output = self.source(changed)
                self.assertIn(code, (1,4))
                self.assertFalse(list(output.rglob('fixture-observation.json')))
                self.assertIsNone(handle.process.poll(), 'source does not own destination target shutdown')

    def test_r3_broken_ready_report_after_spawn_cleans_owned_destination(self):
        output = self.root / 'destination-output'
        class BrokenReadySink:
            def write(sink, text):
                # Do not let a pre-spawn diagnostic satisfy this regression.
                observed = list(output.rglob('fixture-observation.json'))
                if observed:
                    raise BrokenPipeError('fixture ready consumer closed')
                return len(text)
            def flush(sink):
                pass
        try:
            with redirect_stdout(BrokenReadySink()), redirect_stderr(io.StringIO()):
                try:
                    code = self.run.main(self.args(output,'destination'),
                                         execution_context=self.context('destination'))
                except BrokenPipeError:
                    code = 1
            self.assertNotEqual(code, 0)
            observations = list(output.rglob('fixture-observation.json'))
            self.assertEqual(len(observations), 1, 'regression needs a real owned target before broken report')
            observed = json.loads(observations[0].read_text())
            pid = observed['pid']
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(pid,0)
                except ProcessLookupError:
                    break
                time.sleep(.02)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid,0)
            process_files = list(output.rglob('process.json'))
            self.assertEqual(len(process_files), 1)
            self.assertTrue(json.loads(process_files[0].read_text())['cleanup_complete'])
        finally:
            # Test-only emergency cleanup cannot turn a failed assertion into success.
            for observation in output.rglob('fixture-observation.json'):
                observed = json.loads(observation.read_text())
                try:
                    os.killpg(observed['pgid'],signal.SIGKILL)
                except ProcessLookupError:
                    pass


class ReviewRetainedResolverRawBytes(unittest.TestCase):
    """Raw evidence is not globally UTF-8; necessary parsed lines still are."""
    setUp = qualification_cases.QualificationAdmission.setUp
    assert_refused = qualification_cases.QualificationAdmission.assert_refused

    def validate(self):
        # Each activation owns fresh tool-capture paths. Reusing one directory
        # would let EEXIST hide the actual resolver/receipt decision.
        counter = getattr(self, 'activation_counter', 0) + 1
        self.activation_counter = counter
        self.corpus.args.output_dir = self.corpus.root / ('activation-' + str(counter))
        return qualification_cases.QualificationAdmission.validate(self)

    def test_r6_unrelated_non_utf8_resolver_lines_do_not_refuse_complete_evidence(self):
        original = self.corpus.evidence.read_bytes()
        for before in (True, False):
            with self.subTest(unrelated_bytes_before=before):
                unrelated = b'unrelated retained diagnostic: \xff\xfe\x80\n'
                raw = unrelated + original if before else original + unrelated
                self.corpus.evidence.write_bytes(raw)
                try:
                    verdict = self.validate()
                except UnicodeError as error:
                    self.fail('unrelated non-UTF8 evidence rejected: ' + str(error))
                self.assertTrue(verdict['qualified'], verdict.get('missing'))
                self.assertEqual(self.corpus.evidence.read_bytes(), raw)

    def test_r6_non_utf8_required_resolver_line_refuses(self):
        original = self.corpus.evidence.read_bytes()
        entry = self.corpus.runtime['libraries'][0]
        required = (entry['needed'] + ' => ' + entry['path']).encode()
        self.assertEqual(original.count(required), 1,
                         'negative control removes the sole required valid resolver line')
        raw = original.replace(required, required + b' \xff', 1)
        self.corpus.evidence.write_bytes(raw)
        self.assert_refused()
        self.assertEqual(self.corpus.evidence.read_bytes(), raw)


class ReviewRecordedE7RouteFacts(unittest.TestCase):
    """Selected endpoint facts constrain existing route/link evidence objects."""
    def setUp(self):
        qualification_cases.QualificationAdmission.setUp(self)
        common = self.corpus.rig
        endpoints = {}
        for role, address, port in (('source', '192.0.2.31', 12345),
                                    ('destination', '192.0.2.32', 12346)):
            endpoints[role] = dict(
                host_id='fixture-' + role, address=address, rpc_port=port,
                interface='fixture-' + role + '-if', mtu=1500,
                cpuset=common['cpuset'], numa_node=common['numa_node'],
                cpu_budget_description=common['cpu_budget_description'],
                kernel_release=common['kernel_release'],
                kernel_source_revision=common['kernel_source_revision'],
                route_receipt={'evidence':[str(self.corpus.evidence)]},
                usb4_link_receipt={'evidence':[str(self.corpus.evidence)]})
        self.corpus.rig['endpoints'] = endpoints
        self.corpus.runtime['endpoint'] = 'source'
        self.corpus.budget['endpoint'] = 'source'
        self.corpus.args.endpoint = 'source'
        self.corpus.args.experiment = 'e7'
        self.corpus.args.cell_id = 'native-tcp-b4096-q8-r0'
        self.corpus.correctness.update(experiment='e7', arm='tcp', shape=shape('e7'))

    def validate(self):
        counter = getattr(self, 'activation_counter', 0) + 1
        self.activation_counter = counter
        self.corpus.args.output_dir = self.corpus.root / ('activation-' + str(counter))
        # Synchronizing this identity prevents stale correctness metadata from
        # independently refusing a contradictory route/link receipt mutation.
        self.corpus.correctness['rig_identity'] = copy.deepcopy(self.corpus.rig)
        self.corpus.save()
        request = cell('e7', 'tcp')
        request.update(rig_identity=copy.deepcopy(self.corpus.rig),
                       source_host_id='fixture-source',
                       destination_host_id='fixture-destination')
        with mock.patch('subprocess.Popen', side_effect=self.corpus.tools):
            return self.qual.validate_qualification(self.corpus.path, self.corpus.args,
                                                   shape('e7'), self.corpus.rig, request)

    assert_refused = qualification_cases.QualificationAdmission.assert_refused

    def record_matching_facts(self):
        for endpoint in self.corpus.rig['endpoints'].values():
            for key in ('route_receipt', 'usb4_link_receipt'):
                endpoint[key].update(
                    {name:endpoint[name] for name in ('host_id','address','interface','rpc_port')})
                endpoint[key].update(source_host_id='fixture-source',
                                     destination_host_id='fixture-destination')

    def test_r7_evidence_only_route_and_link_receipts_keep_existing_qualification(self):
        self.assertTrue(self.validate()['qualified'])

    def test_r7_matching_recorded_route_and_link_endpoint_facts_qualify(self):
        self.record_matching_facts()
        self.assertTrue(self.validate()['qualified'])

    def test_r7_recorded_route_and_link_endpoint_conflicts_refuse(self):
        self.record_matching_facts()
        conflicting = dict(host_id='fixture-unselected-host', address='192.0.2.99',
                           interface='fixture-unselected-if', rpc_port=12444,
                           source_host_id='fixture-unselected-source',
                           destination_host_id='fixture-unselected-destination')
        for role in ('source', 'destination'):
            for key in ('route_receipt', 'usb4_link_receipt'):
                receipt = self.corpus.rig['endpoints'][role][key]
                for name, bad in conflicting.items():
                    with self.subTest(endpoint=role, receipt=key, recorded_field=name):
                        original = receipt[name]
                        receipt[name] = bad
                        try:
                            self.assert_refused()
                        finally:
                            receipt[name] = original


if __name__ == '__main__':
    unittest.main()

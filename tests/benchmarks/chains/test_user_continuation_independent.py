#!/usr/bin/env python3
"""Independent contract tests. Invoke with --source-root CANONICAL --artifact-dir DIR.

Expected values originate in the frozen USER continuation prose contract.
No implementation-owner files or baseline golden outputs are test inputs.
"""
import argparse
import copy
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE_ROOT = Path(__file__).resolve().parents[3]
ARTIFACT_DIR = Path(tempfile.mkdtemp(prefix='user-continuation-independent-'))
LIBBPF_INCLUDE = os.environ.get('LIBBPF_INCLUDE')
LIBBPF_A = os.environ.get('LIBBPF_A')


def libbpf_make_args():
    """Build transport only: explicit paths override pkg-config/system lookup."""
    def pkg_config(option, fallback):
        try:
            p = subprocess.run(['pkg-config', option, 'libbpf'], capture_output=True,
                               text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return fallback
        return p.stdout.strip() if p.returncode == 0 else fallback

    cflags = ('-I' + shlex.quote(str(Path(LIBBPF_INCLUDE).resolve()))
              if LIBBPF_INCLUDE else pkg_config('--cflags', ''))
    libs = (shlex.quote(str(Path(LIBBPF_A).resolve()))
            if LIBBPF_A else pkg_config('--libs', '-lbpf'))
    return ['LIBBPF_CFLAGS=' + cflags, 'LIBBPF_LIBS=' + libs]


def rig():
    return {
        'nvme_src': {'ng': '/dev/ng_contract_src', 'block': '/dev/nvme_contract_src',
                     'slba': 128, 'nlb': 8192, 'lba_bytes': 512},
        'nvme_dst': {'ng': '/dev/ng_contract_dst', 'block': '/dev/nvme_contract_dst',
                     'slba': 256, 'nlb': 8192, 'lba_bytes': 512},
        'tx': {'ifname': 'contract_tx', 'queue': 3, 'mac': '02:00:00:00:00:11',
               'ip': '192.0.2.11', 'port': 12341, 'mtu': 1500},
        'rx': {'ifname': 'contract_rx', 'queue': 4, 'mac': '02:00:00:00:00:22',
               'ip': '192.0.2.22', 'port': 12342, 'mtu': 1500},
        'ce': {'dev': '/dev/xdev_ext_ce_sim', 'len': 2097152,
               'tx_va': 4096, 'rx_va': 4194304, 'alloc': 'given', 'bdf': ''},
        'attached': ['nxp_nvme_ops', 'nxp_afxdp_ops', 'ce_plan_ops'],
        'plans': {'user': '/contract/chain_plan.bpf.o', 'nxp': '/contract/nxp.bpf.o',
                  'ce': '/contract/ce.bpf.o'},
        'timeout_ms': 17, 'nxp_session': 270019,
    }


class PlannerContract(unittest.TestCase):
    def invoke(self, chains='nvme-nic', arms='user-continuation', *, config=None,
               depth='3', cpus=None, extra=(), correct=True, dry=True):
        case_dir = ARTIFACT_DIR / self.id().split('.')[-1]
        case_dir.mkdir(parents=True, exist_ok=True)
        invocation = len(list(case_dir.glob('invoke-*')))
        case_dir = case_dir / ('invoke-%03d' % invocation)
        case_dir.mkdir()
        rig_file = case_dir / 'rig.json'
        rig_file.write_text(json.dumps(config if config is not None else rig(), indent=2))
        cmd = [sys.executable, str(SOURCE_ROOT / 'tests/benchmarks/chains/run.py'),
               '--rig', str(rig_file), '--chain', chains, '--arms', arms,
               '--sizes', '4096', '--records', '5', '--warmup-records', '2',
               '--seed', '37', '--depth', depth, '--load', 'closed',
               '--out-dir', str(case_dir / 'output')]
        if correct:
            cmd.append('--correctness-only')
        if dry:
            cmd.append('--dry-run')
        if cpus is not None:
            cmd += ['--cpu-set', cpus]
        cmd += list(extra)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        (case_dir / 'command.json').write_text(json.dumps(cmd, indent=2))
        (case_dir / 'stdout').write_text(p.stdout)
        (case_dir / 'stderr').write_text(p.stderr)
        (case_dir / 'exit').write_text(str(p.returncode) + '\n')
        rows = [json.loads(line) for line in p.stdout.splitlines() if line.startswith('{')]
        specs = [json.loads(f.read_text()) for f in (case_dir / 'output').rglob('*.spec.json')]
        return p, rows, specs

    def assert_planned(self, p, rows):
        self.assertEqual(p.returncode, 0, 'valid new-arm request rejected: ' + p.stderr + p.stdout)
        self.assertTrue(rows, 'no planned case output')
        self.assertTrue(all(x['status'] == 'planned' for x in rows), rows)

    def test_new_arm_nvme_nic_is_a_real_chain_bench_plan(self):
        # Break caught: CLI arm catalog omits the required same-binding arm.
        p, rows, specs = self.invoke()
        self.assert_planned(p, rows)
        sender = next(x for x in specs if x['chain'] == 'nvme-nic')
        receiver = next(x for x in specs if x['chain'] == 'nic-nvme')
        self.assertEqual(sender['schema'], 'xdev-chain-spec-v1')
        self.assertEqual(sender['arm'], 'user-continuation')
        self.assertEqual([(s['class'], s['dir']) for s in sender['stages']],
                         [('nvme', 'from'), ('user', 'to'), ('afxdp', 'to')])
        self.assertEqual(receiver['arm'], 'session')
        self.assertEqual([(s['class'], s['dir']) for s in receiver['stages']],
                         [('afxdp', 'from'), ('nvme', 'to')])
        self.assertIn({'obj': '/contract/chain_plan.bpf.o', 'map': 'chain_user_ops'}, sender['plans'])
        self.assertFalse(any(x.get('map') == 'chain_user_ops' for x in receiver.get('plans', [])))

    def test_three_arms_publish_equal_controlled_geometry_and_bindings(self):
        # Break caught: comparison reports a different workload or CPU budget.
        cpu = min(os.sched_getaffinity(0))
        cpus = '%d-%d' % (cpu, cpu)
        p, rows, specs = self.invoke('nvme-nic,nvme-gpu', 'staged,user-continuation,session', cpus=cpus)
        self.assert_planned(p, rows)
        self.assertEqual(len(rows), 6)
        for chain in ('nvme-nic', 'nvme-gpu'):
            controls = []
            for arm, site, same in [('staged', 'existing-interfaces', False),
                                    ('user-continuation', 'userspace-continuation', True),
                                    ('session', 'kernel-continuation', True)]:
                row = next(x for x in rows if x['chain'] == chain and x['arm'] == arm)
                c = row['comparison_contract']
                self.assertEqual(c['schema'], 'xdev-chain-comparison-v1')
                self.assertEqual(c['execution_site'], site)
                self.assertIs(c['same_binding'], same)
                self.assertEqual(c['input'], {'seed': 37, 'record_bytes': 4096,
                                             'records': 5, 'warmup_records': 2})
                self.assertEqual(c['cpu_set'], cpus)
                self.assertEqual(c['completion'], 'terminal-device-completion-and-output-oracle')
                for key, value in {'group_bytes': 4096, 'burst': 1, 'logical_depth': 3}.items():
                    self.assertEqual(c['geometry'][key], value)
                for key in ('frame_size', 'pool_frames', 'hdr_room'):
                    self.assertIn(key, c['geometry'])
                self.assertGreater(c['geometry']['frame_size'], 0)
                self.assertGreater(c['geometry']['pool_frames'], 0)
                # Contract fixes binding content, but not its nesting/key spelling.
                values = json.dumps(c['bindings'], sort_keys=True)
                for value in ('/dev/ng_contract_src', '/dev/nvme_contract_src'):
                    self.assertIn(value, values)
                if chain == 'nvme-nic':
                    self.assertIn('contract_tx', values)
                else:
                    self.assertIn('/dev/xdev_ext_ce_sim', values)
                controls.append({k: c[k] for k in ('input', 'geometry', 'bindings', 'cpu_set', 'completion')})
            self.assertEqual(controls[0], controls[1])
            self.assertEqual(controls[1], controls[2])
            ss = next(x for x in specs if x['chain'] == chain and x['arm'] == 'session')
            us = next(x for x in specs if x['chain'] == chain and x['arm'] == 'user-continuation')
            self.assertEqual(us['stages'][0], ss['stages'][0])
            self.assertEqual(us['stages'][2:], ss['stages'][1:])
            for key in ('group_bytes', 'batches', 'warmup', 'burst', 'depth', 'seed', 'pool', 'peer', 'ce'):
                self.assertEqual(us.get(key), ss.get(key), key)

    def test_gpu_new_arm_and_staged_end_after_h2d(self):
        # Break caught: accidentally reusing nvme-gpu-nic adds D2H or a NIC sink.
        p, rows, specs = self.invoke('nvme-gpu', 'staged,user-continuation,session')
        self.assert_planned(p, rows)
        self.assertEqual(len(specs), 3)
        for spec in specs:
            expected = [('nvme', 'from'), ('ce', 'to')]
            if spec['arm'] == 'user-continuation':
                expected.insert(1, ('user', 'to'))
            self.assertEqual([(x['class'], x['dir']) for x in spec['stages']], expected)
            self.assertEqual(spec['oracle']['kind'], 'ce-window')
            self.assertTrue(spec['oracle']['every_window'])
            self.assertEqual(spec['ce']['va'], 4096)
            self.assertEqual(spec['ce']['len'], 2097152)

    def test_missing_user_plan_refuses_explicitly(self):
        cfg = rig()
        del cfg['plans']['user']
        p, rows, specs = self.invoke(config=cfg)
        self.assertEqual(p.returncode, 4, p.stderr + p.stdout)
        self.assertTrue(rows)
        self.assertTrue(all(x['status'] == 'not_run' for x in rows))
        self.assertIn('user', json.dumps(rows).lower())
        self.assertFalse(specs)

    def test_attached_user_plan_needs_no_object(self):
        cfg = rig()
        del cfg['plans']['user']
        cfg['attached'].append('chain_user_ops')
        p, rows, specs = self.invoke(config=cfg)
        self.assert_planned(p, rows)
        self.assertFalse(any(x['map'] == 'chain_user_ops' for spec in specs for x in spec.get('plans', [])))

    def test_other_new_arm_chains_refuse_without_substitution(self):
        control, control_rows, _ = self.invoke()
        self.assert_planned(control, control_rows)
        p, rows, specs = self.invoke('nic-nvme,nvme-gpu-nic,nic-gpu-nvme,nvme-iaa-gpu,nic-iaa-gpu')
        self.assertEqual(p.returncode, 4, p.stderr + p.stdout)
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(x['status'] == 'not_run' and 'unsupported' in x['failure'].lower() for x in rows), rows)
        self.assertFalse(specs)

    def test_legacy_uo_gpu_refuses_explicitly(self):
        control, control_rows, _ = self.invoke()
        self.assert_planned(control, control_rows)
        p, rows, specs = self.invoke('nvme-gpu', 'userspace-shared')
        self.assertEqual(p.returncode, 4, p.stderr + p.stdout)
        self.assertEqual(rows[0]['status'], 'not_run')
        self.assertIn('unsupported', rows[0]['failure'].lower())
        self.assertFalse(specs)

    def test_depth_65_is_not_planned(self):
        control, control_rows, _ = self.invoke()
        self.assert_planned(control, control_rows)
        p, rows, specs = self.invoke(depth='65')
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(any(x.get('status') == 'planned' for x in rows))
        self.assertFalse(specs)

    def test_unspecified_cpu_remains_null(self):
        p, rows, _ = self.invoke()
        self.assert_planned(p, rows)
        self.assertIsNone(rows[0]['comparison_contract']['cpu_set'])

    def test_invalid_cpu_string_cannot_plan_a_comparison(self):
        control, control_rows, _ = self.invoke()
        self.assert_planned(control, control_rows)
        p, rows, _ = self.invoke(cpus='not-a-cpu')
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(any(x.get('status') == 'planned' for x in rows))


def literal_spec(chain='nvme-gpu', arm='user-continuation'):
    # Hand-authored semantic workload. No planner output is used as the C oracle.
    spec = {'schema': 'xdev-chain-spec-v1', 'chain': chain, 'arm': arm,
            'mode': 'correctness', 'group_bytes': 4096, 'batches': 2,
            'warmup': 1, 'burst': 1, 'depth': 3, 'timeout_ms': 17,
            'seed': 37, 'start_per': 'batch', 'load': 'closed',
            'pool': {'frame_size': 4096, 'frames': 3, 'hdr_room': 0, 'hugepage': False},
            'ce': {'dev': '/dev/xdev_ext_ce_sim', 'va': 4096, 'len': 12288, 'alloc': 'given'},
            'stages': [{'class': 'nvme', 'dir': 'from', 'dev': '/dev/ng_contract_src',
                        'block': '/dev/nvme_contract_src', 'slba': 128, 'nlb': 8192},
                       {'class': 'user', 'dir': 'to'}, {'class': 'ce', 'dir': 'to'}],
            'oracle': {'kind': 'ce-window', 'reference': '/contract/reference.bin', 'every_window': True}}
    if arm != 'user-continuation':
        del spec['stages'][1]
    if arm == 'staged':
        spec['staged_gpu'] = 'ce-sim'
    return spec


class CCheckContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ARTIFACT_DIR / 'build'
        cls.view = ARTIFACT_DIR / 'source-view'
        cmd = [sys.executable, str(SOURCE_ROOT / 'tools/run.py'), '--root', str(SOURCE_ROOT),
               '--view', str(cls.view), '--cwd', 'tests/benchmarks/chains',
               'make', 'bench', 'BUILD=' + str(cls.build),
               *libbpf_make_args()]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        (ARTIFACT_DIR / 'build-command.json').write_text(json.dumps(cmd, indent=2))
        (ARTIFACT_DIR / 'build.log').write_text(p.stdout + p.stderr)
        if p.returncode:
            raise RuntimeError('SETUP: real C production build failed; see build.log')
        cls.bench = cls.build / 'chain_bench'

    def check(self, spec):
        case_dir = ARTIFACT_DIR / self.id().split('.')[-1]
        case_dir.mkdir(exist_ok=True)
        check_index = len(list(case_dir.glob('check-*')))
        case_dir = case_dir / ('check-%02d' % check_index)
        case_dir.mkdir()
        fixture = case_dir / 'literal.spec.json'
        fixture.write_text(json.dumps(spec, indent=2))
        p = subprocess.run([str(self.bench), '--check', str(fixture)], text=True,
                           capture_output=True, timeout=5)
        (case_dir / 'stdout').write_text(p.stdout)
        (case_dir / 'stderr').write_text(p.stderr)
        (case_dir / 'exit').write_text(str(p.returncode) + '\n')
        return p

    def test_literal_new_arm_gpu_passes_real_c_check(self):
        p = self.check(literal_spec())
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        plan = json.loads(p.stdout)
        self.assertEqual(plan['pool'], 'iou_umem')
        self.assertEqual(plan['pool_frames'], 3)
        self.assertEqual(plan['stages'][1]['class_id'], 10)
        self.assertEqual(plan['stages'][1]['flags'], 0)
        self.assertEqual(plan['stages'][1]['arg0'], 17)
        self.assertEqual(plan['stages'][1]['arg1'], 0)

    def test_literal_session_gpu_passes_real_c_check(self):
        p = self.check(literal_spec(arm='session'))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_literal_staged_gpu_passes_real_c_check(self):
        p = self.check(literal_spec(arm='staged'))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_bad_user_direction_is_invalid(self):
        control = self.check(literal_spec())
        self.assertEqual(control.returncode, 0, 'valid USER arm prerequisite: ' + control.stdout + control.stderr)
        spec = literal_spec()
        spec['stages'][1]['dir'] = 'from'
        self.assertEqual(self.check(spec).returncode, 2)

    def test_user_before_nvme_is_invalid(self):
        control = self.check(literal_spec())
        self.assertEqual(control.returncode, 0, 'valid USER arm prerequisite: ' + control.stdout + control.stderr)
        spec = literal_spec()
        spec['stages'][0], spec['stages'][1] = spec['stages'][1], spec['stages'][0]
        self.assertEqual(self.check(spec).returncode, 2)

    def test_missing_user_is_invalid(self):
        control = self.check(literal_spec())
        self.assertEqual(control.returncode, 0, 'valid USER arm prerequisite: ' + control.stdout + control.stderr)
        spec = literal_spec()
        del spec['stages'][1]
        self.assertEqual(self.check(spec).returncode, 2)

    def test_duplicate_user_is_invalid(self):
        control = self.check(literal_spec())
        self.assertEqual(control.returncode, 0, 'valid USER arm prerequisite: ' + control.stdout + control.stderr)
        spec = literal_spec()
        spec['stages'].insert(2, {'class': 'user', 'dir': 'to'})
        self.assertEqual(self.check(spec).returncode, 2)

    def test_session_cannot_insert_user(self):
        control = self.check(literal_spec())
        self.assertEqual(control.returncode, 0, 'valid USER arm prerequisite: ' + control.stdout + control.stderr)
        spec = literal_spec()
        spec['arm'] = 'session'
        self.assertEqual(self.check(spec).returncode, 2)

    def test_zero_and_excess_depth_are_invalid(self):
        control = self.check(literal_spec())
        self.assertEqual(control.returncode, 0, 'valid USER arm prerequisite: ' + control.stdout + control.stderr)
        for depth in (0, 65):
            with self.subTest(depth=depth):
                spec = literal_spec()
                spec['depth'] = depth
                self.assertEqual(self.check(spec).returncode, 2)

    def test_virtual_gpu_timing_is_refused_by_c(self):
        control = self.check(literal_spec())
        self.assertEqual(control.returncode, 0, 'valid USER arm prerequisite: ' + control.stdout + control.stderr)
        spec = literal_spec()
        spec['mode'] = 'timing'
        spec['oracle']['every_window'] = False
        p = self.check(spec)
        self.assertEqual(p.returncode, 4, p.stdout + p.stderr)


class HardwareGateContract(unittest.TestCase):
    def test_virtual_environment_is_refused_before_devices(self):
        # Kernel/OS evidence boundary only; the real gate consumes the evidence.
        import importlib.util
        spec = importlib.util.spec_from_file_location('independent_gate', SOURCE_ROOT / 'tests/benchmarks/chains/hardware_gate.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        root = ARTIFACT_DIR / 'virtual-os-evidence'
        (root / 'sys/hypervisor').mkdir(parents=True, exist_ok=True)
        (root / 'sys/hypervisor/type').write_text('kvm\n')
        with self.assertRaises(gate.Refusal):
            gate.environment(root)


class RuntimeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Fixture comes from independent test owner's directory, never the candidate.
        cls.build = ARTIFACT_DIR / 'runtime-build'
        cls.build.mkdir(parents=True, exist_ok=True)
        cls.view = ARTIFACT_DIR / 'runtime-source-view'
        fixture_source = Path(__file__).with_name('user_continuation_kernel_fixture.c')
        fixture_snapshot = cls.build / fixture_source.name
        fixture_snapshot.write_bytes(fixture_source.read_bytes())
        # Materialize real C source/include view without using candidate tests.
        cmd = [sys.executable, str(SOURCE_ROOT / 'tools/run.py'), '--root', str(SOURCE_ROOT),
               '--view', str(cls.view), '--cwd', 'tests/benchmarks/chains', 'true']
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        if p.returncode:
            raise RuntimeError('SETUP source view: ' + p.stdout + p.stderr)
        obj = cls.build / 'kernel-boundary.o'
        cmd = ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I' + str(cls.view), '-c', str(fixture_snapshot), '-o', str(obj)]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        (cls.build / 'fixture-build.log').write_text(p.stdout + p.stderr)
        if p.returncode:
            raise RuntimeError('SETUP kernel boundary fixture compile; see fixture-build.log')
        wraps = ('syscall', 'open', 'open64', '__open64_2', '__open_2', 'close', 'ioctl', 'mmap64', 'munmap',
                 'pthread_create', 'sched_setaffinity')
        flags = str(obj) + ' -pthread ' + ' '.join('-Wl,--wrap=' + x for x in wraps)
        cmd = [sys.executable, str(SOURCE_ROOT / 'tools/run.py'), '--root', str(SOURCE_ROOT),
               '--view', str(cls.view), '--cwd', 'tests/benchmarks/chains',
               'make', 'bench', 'BUILD=' + str(cls.build), 'LDFLAGS=' + flags,
               *libbpf_make_args()]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        (cls.build / 'command.json').write_text(json.dumps(cmd, indent=2))
        (cls.build / 'production-build.log').write_text(p.stdout + p.stderr)
        if p.returncode:
            raise RuntimeError('SETUP actual production C link; see production-build.log')
        cls.bench = cls.build / 'chain_bench'

    def run_scenario(self, scenario='success'):
        case_dir = ARTIFACT_DIR / self.id().split('.')[-1] / scenario
        case_dir.mkdir(parents=True, exist_ok=True)
        # Literal distinct full-frame contents, independently supplied reference.
        reference = b''.join(i.to_bytes(8, 'little') + bytes([31 + i]) * 4088 for i in range(3))
        (case_dir / 'reference.bin').write_bytes(reference)
        (case_dir / 'source.bin').write_bytes(bytes(128 * 512) + reference)
        (case_dir / 'ce.bin').write_bytes(bytes(16384))
        spec = literal_spec()
        spec['oracle']['reference'] = str(case_dir / 'reference.bin')
        (case_dir / 'literal.spec.json').write_text(json.dumps(spec, indent=2))
        env = dict(os.environ, UC_SCENARIO=scenario, UC_SOURCE=str(case_dir / 'source.bin'),
                   UC_CE=str(case_dir / 'ce.bin'), UC_RECEIPT=str(case_dir / 'boundary-receipt.json'))
        cpu = min(os.sched_getaffinity(0))
        cmd = [str(self.bench), '--spec', str(case_dir / 'literal.spec.json')]
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=5,
                           preexec_fn=lambda: os.sched_setaffinity(0, {cpu}))
        (case_dir / 'stdout').write_text(p.stdout)
        (case_dir / 'stderr').write_text(p.stderr)
        (case_dir / 'exit').write_text(str(p.returncode) + '\n')
        (case_dir / 'command.json').write_text(json.dumps(cmd, indent=2))
        rows = [json.loads(x) for x in p.stdout.splitlines() if x.startswith('{')]
        self.assertTrue(rows, 'actual C production executable emitted no JSON: ' + p.stderr)
        receipt = json.loads((case_dir / 'boundary-receipt.json').read_text())
        return p, rows[-1], receipt, case_dir, reference

    def test_actual_worker_preserves_payload_lengths_and_terminal_oracle(self):
        p, result, r, directory, reference = self.run_scenario()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['execution_site'], 'userspace-continuation')
        self.assertIs(result['same_binding'], True)
        self.assertEqual(result['user_continuation'], {'ready_batches': 3, 'completed_batches': 3, 'failure': 0})
        self.assertEqual(result['cost']['syscalls_scope'], 'main-thread-explicit')
        self.assertNotIn('timing', result)
        self.assertEqual(result['counters']['batches_done'], 3)
        self.assertEqual(result['counters']['completed'], [3, 3, 3])
        self.assertEqual(result['oracle']['verdict'], 'pass')
        self.assertGreaterEqual(result['oracle']['bytes'], 4096)
        self.assertEqual((directory / 'ce.bin').read_bytes()[4096:8192], reference[-4096:])
        self.assertEqual(r['completed'], 3)
        self.assertEqual(r['user_done_calls'], 3)
        self.assertEqual(r['bad_lengths'], 0)
        self.assertEqual(r['bad_payload'], 0)
        self.assertEqual(r['ack_errors'], 0)
        self.assertEqual(r['rings'], 1)
        self.assertEqual(r['pools'], 1)
        self.assertEqual(r['creates'], 1)
        self.assertEqual(r['user_opens'], 1)

    def test_single_helper_inherits_shared_cpu_affinity(self):
        p, _, r, _, _ = self.run_scenario()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(r['threads'], 1)
        self.assertEqual(r['worker_affinity_ok'], 1)
        self.assertEqual(r['worker_before_create'], 0)
        self.assertEqual(r['affinity_overrides'], 0)

    def test_successful_stop_precedes_user_and_native_resource_release(self):
        p, _, r, _, _ = self.run_scenario()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(r['stop_calls'], 1)
        self.assertTrue(r['stop_succeeded'])
        self.assertEqual(r['release_before_stop'], 0)
        self.assertEqual(r['token_closes'], 1)
        self.assertEqual(r['user_unmaps'], 1)
        self.assertEqual(r['pool_unmaps'], 1)

    def test_failed_stop_retains_user_token_and_native_mappings(self):
        p, result, r, _, _ = self.run_scenario('stop-fails')
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(r['stop_calls'], 1)
        self.assertFalse(r['stop_succeeded'])
        for key in ('token_closes', 'user_unmaps', 'pool_unmaps', 'release_after_failed_stop'):
            self.assertEqual(r[key], 0, key)

    def test_user_kernel_errors_propagate_despite_terminal_success(self):
        for scenario in ('completion-error', 'completion-stale', 'completion-short', 'malformed-ready'):
            with self.subTest(scenario=scenario):
                p, result, r, _, _ = self.run_scenario(scenario)
                self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                self.assertEqual(result['status'], 'fail')
                self.assertLess(result['user_continuation']['failure'], 0)
                self.assertEqual(r['stop_calls'], 1)

    def test_timeout_and_stale_ticket_cannot_be_hidden_by_terminal_notification(self):
        for scenario in ('timeout', 'stale-ready'):
            with self.subTest(scenario=scenario):
                p, result, r, _, _ = self.run_scenario(scenario)
                self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                self.assertEqual(result['status'], 'fail')
                self.assertLess(result['user_continuation']['failure'], 0)
                self.assertEqual(r['completed'], 0)
                self.assertGreater(r['premature_terminal'], 0)

    def test_user_acknowledgement_does_not_replace_terminal_completion(self):
        p, result, r, _, _ = self.run_scenario('no-terminal')
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual(result['status'], 'fail')
        self.assertGreater(r['completed'], 0)

    def test_terminal_stats_error_defeats_user_success(self):
        p, result, r, _, _ = self.run_scenario('terminal-error')
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual(result['status'], 'fail')
        self.assertGreater(r['completed'], 0)


class StagedGpuContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ARTIFACT_DIR / 'staged-function-build'
        cls.build.mkdir(parents=True, exist_ok=True)
        cls.view = ARTIFACT_DIR / 'staged-source-view'
        cmd = [sys.executable, str(SOURCE_ROOT / 'tools/run.py'), '--root', str(SOURCE_ROOT),
               '--view', str(cls.view), '--cwd', 'tests/benchmarks/chains', 'true']
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        if p.returncode:
            raise RuntimeError('SETUP staged source view: ' + p.stdout + p.stderr)
        src = Path(__file__).with_name('user_continuation_staged_fixture.c')
        snapshot = cls.build / src.name
        snapshot.write_bytes(src.read_bytes())
        cls.binary = cls.build / 'actual-staged-functions'
        cmd = ['gcc', '-O2', '-g', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
               '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
               '-DUC_STAGED_SOURCE="' + str(cls.view / 'tests/eval/chains/chain_staged.c') + '"',
               str(snapshot), '-o', str(cls.binary), '-ldl', '-lz']
        # The view's logical location is source-map-defined, not inferred from a golden test.
        if not (cls.view / 'tests/eval/chains/chain_staged.c').exists():
            layout = json.loads((SOURCE_ROOT / 'source-layout.json').read_text())
            matches = [entry for entry in layout['files'] if entry.get('source') == 'tests/benchmarks/chains/chain_staged.c']
            if len(matches) != 1:
                raise RuntimeError('SETUP source map cannot locate staged production input')
            # Current mapper uses component/native; fallback resolved by view file name uniqueness.
            candidates = list(cls.view.rglob('chain_staged.c'))
            if len(candidates) != 1:
                raise RuntimeError('SETUP ambiguous staged production input')
            cmd[10] = '-DUC_STAGED_SOURCE="' + str(candidates[0]) + '"'
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        (cls.build / 'command.json').write_text(json.dumps(cmd, indent=2))
        (cls.build / 'build.log').write_text(p.stdout + p.stderr)
        if p.returncode:
            raise RuntimeError('SETUP staged real C function build; see build.log')

    def run_gpu(self, chain):
        p = subprocess.run([str(self.binary), chain], capture_output=True, text=True, timeout=5)
        (self.build / (chain + '.stdout')).write_text(p.stdout)
        (self.build / (chain + '.stderr')).write_text(p.stderr)
        self.assertEqual(p.returncode, 0, 'actual GPU transition failed: ' + p.stderr)
        return json.loads(p.stdout)

    def test_nvme_gpu_h2d_only_waits_for_real_driver_completion(self):
        r = self.run_gpu('nvme-gpu')
        self.assertEqual(r, {'h2d_calls': 1, 'd2h_calls': 0, 'queries': 2,
                             'device_matches': True, 'return_untouched': True})

    def test_existing_gpu_nic_keeps_its_d2h_composition(self):
        r = self.run_gpu('nvme-gpu-nic')
        self.assertEqual(r, {'h2d_calls': 1, 'd2h_calls': 1, 'queries': 2,
                             'device_matches': True, 'return_untouched': False})


class ResultMetadataContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ARTIFACT_DIR / 'result-function-build'
        cls.build.mkdir(parents=True, exist_ok=True)
        cls.view = ARTIFACT_DIR / 'result-source-view'
        cmd = [sys.executable, str(SOURCE_ROOT / 'tools/run.py'), '--root', str(SOURCE_ROOT),
               '--view', str(cls.view), '--cwd', 'tests/benchmarks/chains', 'true']
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        if p.returncode:
            raise RuntimeError('SETUP result source view: ' + p.stdout + p.stderr)
        src = Path(__file__).with_name('user_continuation_result_fixture.c')
        snapshot = cls.build / src.name
        snapshot.write_bytes(src.read_bytes())
        cls.binary = cls.build / 'actual-result-serializer'
        candidates = list(cls.view.rglob('chain_bench.c'))
        if len(candidates) != 1:
            raise RuntimeError('SETUP ambiguous production serializer source')
        cmd = ['gcc', '-O2', '-g', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
               '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
               '-DUC_BENCH_SOURCE="' + str(candidates[0]) + '"',
               str(snapshot), '-o', str(cls.binary), '-ldl', '-lz']
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        (cls.build / 'command.json').write_text(json.dumps(cmd, indent=2))
        (cls.build / 'build.log').write_text(p.stdout + p.stderr)
        if p.returncode:
            raise RuntimeError('SETUP real production serializer compile; see build.log')

    def emit(self, arm):
        p = subprocess.run([str(self.binary), arm], capture_output=True, text=True, timeout=5)
        self.assertEqual(p.returncode, 0, p.stderr)
        (self.build / (arm + '.stdout')).write_text(p.stdout)
        return json.loads(p.stdout)

    def test_session_syscall_scope_never_claims_whole_arm(self):
        r = self.emit('session')
        self.assertEqual(r['cost']['syscalls'], 9)
        self.assertIn('syscalls_scope', r['cost'], 'session serializer must label explicit main-thread counts')
        self.assertEqual(r['cost']['syscalls_scope'], 'main-thread-explicit')
        self.assertIn('execution_site', r, 'session serializer must identify continuation site')
        self.assertEqual(r['execution_site'], 'kernel-continuation')
        self.assertIs(r['same_binding'], True)
        self.assertNotIn('timing', r)

    def test_staged_result_has_existing_interface_identity(self):
        r = self.emit('staged')
        self.assertIn('execution_site', r, 'staged serializer must identify existing interfaces')
        self.assertEqual(r['execution_site'], 'existing-interfaces')
        self.assertIs(r['same_binding'], False)
        self.assertNotIn('timing', r)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=SOURCE_ROOT)
    parser.add_argument('--artifact-dir', type=Path, default=ARTIFACT_DIR)
    parser.add_argument('--libbpf-include', type=Path, default=LIBBPF_INCLUDE,
                        help='libbpf include directory (default: LIBBPF_INCLUDE, pkg-config, system)')
    parser.add_argument('--libbpf-a', type=Path, default=LIBBPF_A,
                        help='libbpf library/archive (default: LIBBPF_A, pkg-config, -lbpf)')
    opts, rest = parser.parse_known_args()
    LIBBPF_INCLUDE = opts.libbpf_include
    LIBBPF_A = opts.libbpf_a
    SOURCE_ROOT = opts.source_root.resolve()
    ARTIFACT_DIR = opts.artifact_dir.resolve()
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    unittest.main(argv=[sys.argv[0]] + rest, verbosity=2)

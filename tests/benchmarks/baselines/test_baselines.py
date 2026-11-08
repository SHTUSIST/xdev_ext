#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests of the generated baseline commands and configs (no hardware).

Expected values come from the pinned upstream sources named in pins.json:
LMCache v0.5.7 (lmcache server flags, mooncake_store L2 adapter, the
LMCacheMPConnector defaults tcp://localhost:5555), vLLM v0.33.0
(MooncakeStoreConfig.from_file keys, VLLM_HOST_IP), Mooncake v0.3.14
(mooncake_master/mooncake_client flags, MOONCAKE_OFFLOAD_FILE_STORAGE_PATH)
and vLLM v0.10.2 (multi-node runs require Ray).
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bp = _load('baseline_plan', HERE / 'baseline_plan.py')
tp_run = _load('xdev_tp_run', HERE.parent / 'tp' / 'run.py')

RIG = dict(host1='tb-host1', host2='tb-host2', host1_ip='10.77.0.1', host2_ip='10.77.0.2',
           workdir='/srv/xdev-baselines')
MODEL = 'Qwen/Qwen3-8B'
E1 = dict(model=MODEL, l1_size_gb=8.0, host1_ssd_dir='/nvme/mooncake_offload')
E2 = dict(model='Qwen/Qwen3-32B-FP8')
RUNNERS = {'lmcache-mooncake': 'lmcache_mooncake.py', 'mooncake-store': 'mooncake_store.py',
           'recompute': 'recompute.py', 'tp2-nccl': 'tp2_nccl.py', 'pp2-nccl': 'pp2_nccl.py'}

# vLLM / NCCL / Mooncake options that would change the comparison if set.
FORBIDDEN_VLLM = {
    '--gpu-memory-utilization', '--max-num-seqs', '--max-num-batched-tokens', '--block-size',
    '--enable-chunked-prefill', '--no-enable-chunked-prefill', '--enable-prefix-caching',
    '--no-enable-prefix-caching', '--enforce-eager', '--dtype', '--kv-cache-dtype',
    '--compilation-config', '-O', '--max-model-len', '--swap-space', '--cpu-offload-gb',
    '--quantization', '--async-scheduling', '--disable-custom-all-reduce'}
FORBIDDEN_ENV = {'NCCL_ALGO', 'NCCL_PROTO', 'NCCL_NCHANNELS', 'NCCL_MIN_NCHANNELS',
                 'NCCL_MAX_NCHANNELS', 'NCCL_BUFFSIZE', 'NCCL_P2P_NET_CHUNKSIZE',
                 'NCCL_SOCKET_NTHREADS', 'NCCL_NSOCKS_PERTHREAD', 'MOONCAKE_PREFERRED_SEGMENT',
                 'MOONCAKE_OFFLOAD_USE_URING', 'MC_STORE_MEMCPY', 'VLLM_ATTENTION_BACKEND'}


def plan(name, **extra):
    options = dict(E2 if name.endswith('nccl') else E1)
    options.update(extra)
    return bp.build(name, bp.Rig(**RIG), **options)


def one(p, name):
    found = [s for s in p.steps if s.name == name]
    if len(found) != 1:
        raise AssertionError(f'{name}: {len(found)} steps')
    return found[0]


def flag(argv, name):
    """Value of '--name value' or '--name=value'; KeyError if absent."""
    for i, word in enumerate(argv):
        if word == name:
            return argv[i + 1]
        if word.startswith(name + '='):
            return word.split('=', 1)[1]
    raise KeyError(name)


def option_names(argv):
    return {w.split('=', 1)[0] for w in argv if w.startswith('-')}


class Pins(unittest.TestCase):
    def test_exact_upstream_revisions(self):
        pins = bp.PINS
        self.assertEqual(pins['lmcache']['tag'], 'v0.5.7')
        self.assertEqual(pins['lmcache']['commit'], '236f3eec32a2d330662a1795d90a01a1e0782c49')
        self.assertEqual(pins['mooncake']['tag'], 'v0.3.14')
        self.assertEqual(pins['mooncake']['commit'], 'e1ea5d31bb5e46ff2df9f90e7c2fbaf52fcdee8c')
        self.assertEqual(pins['vllm_e1']['version'], '0.33.0')
        self.assertEqual(pins['vllm_e1']['commit'], '4ba787ec9959e566d3b587a796dff07673324da5')
        self.assertEqual(pins['vllm_e2']['version'], '0.10.2')
        self.assertEqual(pins['vllm_e2']['commit'], '01efc7ef781391e744ed08c3292817a773d654e6')
        self.assertEqual(pins['ray']['version'], '2.48.0')

    def test_install_steps_use_the_pins(self):
        text = '\n'.join(bp.remote_command(s) for s in plan('lmcache-mooncake').steps
                         if s.phase == 'install')
        self.assertIn('vllm==0.33.0', text)
        self.assertIn('236f3eec32a2d330662a1795d90a01a1e0782c49', text)
        self.assertIn('e1ea5d31bb5e46ff2df9f90e7c2fbaf52fcdee8c', text)
        self.assertIn('BUILD_MOONCAKE=1', text)  # prebuilt wheels lack lmcache_mooncake
        self.assertNotIn('pip install lmcache', text)
        e2 = '\n'.join(bp.remote_command(s) for s in plan('tp2-nccl').steps
                       if s.phase == 'install')
        self.assertIn('vllm==0.10.2', e2)
        self.assertIn('ray[cgraph]==2.48.0', e2)
        self.assertNotIn('0.33.0', e2)


class LMCacheMooncake(unittest.TestCase):
    def setUp(self):
        self.p = plan('lmcache-mooncake')

    def test_host1_mooncake_master_and_offload_owner(self):
        master = one(self.p, 'mooncake-master')
        self.assertEqual(master.host, 'host1')
        self.assertTrue(master.argv[0].endswith('mooncake_master'))
        self.assertEqual(flag(master.argv, '--enable_offload'), 'true')
        self.assertEqual(len(master.argv), 2, master.argv)  # nothing but enable_offload
        owner = one(self.p, 'mooncake-client')
        self.assertEqual(owner.host, 'host1')
        self.assertEqual(flag(owner.argv, '--enable_offload'), 'true')
        self.assertEqual(flag(owner.argv, '--host'), '10.77.0.1')
        self.assertEqual(flag(owner.argv, '--master_server_address'), '10.77.0.1:50051')
        self.assertEqual(flag(owner.argv, '--metadata_server'), 'P2PHANDSHAKE')
        for default in ('--global_segment_size', '--protocol', '--threads', '--port'):
            self.assertRaises(KeyError, flag, owner.argv, default)
        self.assertEqual(dict(owner.env)['MOONCAKE_OFFLOAD_FILE_STORAGE_PATH'],
                         '/nvme/mooncake_offload')

    def test_lmcache_server_and_l2_adapter(self):
        server = one(self.p, 'lmcache-server')
        self.assertEqual(server.host, 'host2')
        self.assertEqual(server.argv[1], 'server')
        self.assertEqual(flag(server.argv, '--l1-size-gb'), '8.0')
        self.assertEqual(flag(server.argv, '--eviction-policy'), 'LRU')
        adapter = json.loads(flag(server.argv, '--l2-adapter'))
        self.assertEqual(adapter, {
            'type': 'mooncake_store', 'local_hostname': '10.77.0.2',
            'metadata_server': 'P2PHANDSHAKE', 'master_server_addr': '10.77.0.1:50051',
            'protocol': 'tcp', 'global_segment_size': '0'})
        for default in ('--host', '--port', '--chunk-size', '--max-workers', '--l1-use-lazy',
                        '--no-l1-use-lazy', '--http-port'):
            self.assertRaises(KeyError, flag, server.argv, default)

    def test_vllm_uses_mp_connector_with_defaults(self):
        serve = one(self.p, 'vllm-serve')
        self.assertEqual(serve.host, 'host2')
        self.assertEqual(serve.argv[1:3], ('serve', MODEL))
        self.assertEqual(json.loads(flag(serve.argv, '--kv-transfer-config')),
                         {'kv_connector': 'LMCacheMPConnector', 'kv_role': 'kv_both'})
        self.assertNotIn('LMCACHE_USE_UPSTREAM_MP', dict(serve.env))

    def test_start_order_and_readiness(self):
        up = [s.name for s in self.p.steps if s.phase == 'up']
        self.assertEqual(up, ['mooncake-master', 'mooncake-client', 'lmcache-server', 'vllm-serve'])
        for s in self.p.steps:
            if s.phase == 'up':
                self.assertTrue(s.background and s.ready, s.name)
        self.assertEqual(one(self.p, 'lmcache-server').ready,
                         ('http', 'http://127.0.0.1:8080/healthcheck'))
        self.assertEqual(one(self.p, 'vllm-serve').ready, ('http', 'http://127.0.0.1:8000/health'))
        self.assertEqual(one(self.p, 'mooncake-master').ready, ('tcp', 50051))
        self.assertEqual(one(self.p, 'mooncake-client').ready, ('tcp', 50052))

    def test_route_invariant_on_both_hosts(self):
        self.assertEqual(self.p.route_hosts, ('host1', 'host2'))
        self.assertEqual(self.p.smoke_host, 'host2')

    def test_l1_size_and_ssd_dir_required(self):
        self.assertRaises(ValueError, bp.build, 'lmcache-mooncake', bp.Rig(**RIG),
                          model=MODEL, host1_ssd_dir='/nvme/x')
        self.assertRaises(ValueError, bp.build, 'lmcache-mooncake', bp.Rig(**RIG),
                          model=MODEL, l1_size_gb=8.0)


class MooncakeStore(unittest.TestCase):
    def setUp(self):
        self.p = plan('mooncake-store')

    def test_vllm_side_config_file(self):
        serve = one(self.p, 'vllm-serve')
        env = dict(serve.env)
        path = env['MOONCAKE_CONFIG_PATH']
        files = dict(self.p.files)
        self.assertEqual(json.loads(files[('host2', path)]), {
            'mode': 'standalone-store', 'metadata_server': 'P2PHANDSHAKE',
            'master_server_address': '10.77.0.1:50051', 'global_segment_size': 0,
            'protocol': 'tcp', 'device_name': '', 'enable_offload': True})
        self.assertEqual(env['VLLM_HOST_IP'], '10.77.0.2')
        self.assertEqual(json.loads(flag(serve.argv, '--kv-transfer-config')),
                         {'kv_connector': 'MooncakeStoreConnector', 'kv_role': 'kv_both'})

    def test_same_host1_owner_as_lmcache_arm(self):
        lm = plan('lmcache-mooncake')
        for name in ('mooncake-master', 'mooncake-client'):
            self.assertEqual(one(self.p, name), one(lm, name))
        self.assertEqual([s.name for s in self.p.steps if s.phase == 'up'],
                         ['mooncake-master', 'mooncake-client', 'vllm-serve'])


class Recompute(unittest.TestCase):
    def test_single_host_no_connector(self):
        p = plan('recompute')
        self.assertEqual({s.host for s in p.steps}, {'host2'})
        serve = one(p, 'vllm-serve')
        self.assertEqual(serve.argv[1:], ('serve', MODEL))
        self.assertEqual(p.route_hosts, ())
        self.assertEqual(serve.phase, 'cold')
        self.assertEqual({Path(path).name for (_, path), _ in p.files},
                         {'cold_request.py', 'recompute-request.json'})

    def test_same_vllm_as_connector_arms(self):
        inst = [bp.remote_command(s) for s in plan('recompute').steps if s.phase == 'install']
        self.assertTrue(any('vllm==0.33.0' in c for c in inst))


class NcclArms(unittest.TestCase):
    def test_tp2_ray_cluster_and_serve(self):
        p = plan('tp2-nccl')
        head, worker = one(p, 'ray-head'), one(p, 'ray-worker')
        self.assertEqual((head.host, worker.host), ('host1', 'host2'))
        self.assertIn('--head', head.argv)
        self.assertEqual(flag(head.argv, '--node-ip-address'), '10.77.0.1')
        self.assertEqual(flag(worker.argv, '--address'), '10.77.0.1:6379')
        self.assertEqual(flag(worker.argv, '--node-ip-address'), '10.77.0.2')
        serve = one(p, 'vllm-serve')
        self.assertEqual(serve.host, 'host1')
        self.assertEqual(flag(serve.argv, '--tensor-parallel-size'), '2')
        self.assertEqual(flag(serve.argv, '--distributed-executor-backend'), 'ray')
        self.assertRaises(KeyError, flag, serve.argv, '--pipeline-parallel-size')
        self.assertEqual([s.name for s in p.steps if s.phase == 'up'],
                         ['ray-head', 'ray-worker', 'vllm-serve'])
        self.assertEqual(p.route_hosts, ('host1', 'host2'))
        self.assertEqual(p.smoke_host, 'host1')

    def test_pp2(self):
        serve = one(plan('pp2-nccl'), 'vllm-serve')
        self.assertEqual(flag(serve.argv, '--pipeline-parallel-size'), '2')
        self.assertRaises(KeyError, flag, serve.argv, '--tensor-parallel-size')

    def test_nccl_env_passes_existing_qualifier(self):
        log = 'x (RayWorkerWrapper pid=1) NCCL INFO NET/Socket : Using [0]thunderbolt0:10.77.0.2<0>\n'
        for name in ('tp2-nccl', 'pp2-nccl'):
            p = plan(name)
            for s in (one(p, 'ray-head'), one(p, 'ray-worker'), one(p, 'vllm-serve')):
                env = dict(s.env)
                self.assertEqual(env['NCCL_NET'], 'Socket')
                self.assertEqual(env['NCCL_SOCKET_IFNAME'], '=thunderbolt0')
                self.assertEqual(env['GLOO_SOCKET_IFNAME'], 'thunderbolt0')
                self.assertEqual(env['NCCL_DEBUG'], 'INFO')
                got = tp_run.qualify_nccl_route(env, log, {'thunderbolt0': dict(
                    addresses=['10.77.0.1'], rx_bytes=1, tx_bytes=1)})
                self.assertTrue(got['qualified'])
            self.assertEqual(dict(one(p, 'ray-head').env)['VLLM_HOST_IP'], '10.77.0.1')
            self.assertEqual(dict(one(p, 'ray-worker').env)['VLLM_HOST_IP'], '10.77.0.2')

    def test_nccl_log_route_is_checked(self):
        self.assertTrue(plan('tp2-nccl').nccl_route)
        self.assertFalse(plan('lmcache-mooncake').nccl_route)


class NoTuning(unittest.TestCase):
    def test_no_tuning_flags_or_env_anywhere(self):
        for name in RUNNERS:
            p = plan(name)
            serve = one(p, 'vllm-serve')
            self.assertFalse(option_names(serve.argv) & FORBIDDEN_VLLM, (name, serve.argv))
            self.assertTrue(option_names(serve.argv) <= {
                '--kv-transfer-config', '--tensor-parallel-size',
                '--pipeline-parallel-size', '--distributed-executor-backend'}, serve.argv)
            for s in p.steps:
                self.assertFalse(set(dict(s.env)) & FORBIDDEN_ENV, (name, s.name))


class Validation(unittest.TestCase):
    def test_rig_addresses(self):
        self.assertRaises(ValueError, bp.Rig, **dict(RIG, host1_ip='thunderbolt0'))
        self.assertRaises(ValueError, bp.Rig, **dict(RIG, host2_ip=RIG['host1_ip']))
        self.assertRaises(ValueError, bp.Rig, **dict(RIG, workdir='relative/dir'))

    def test_unknown_baseline(self):
        self.assertRaises(ValueError, bp.build, 'gds', bp.Rig(**RIG), model=MODEL)


class RouteCheck(unittest.TestCase):
    def test_counters(self):
        before = {'host1': (100, 200), 'host2': (300, 400)}
        after = {'host1': (150, 260), 'host2': (390, 401)}
        got = bp.route_check(before, after, expected_kv_bytes=50)
        self.assertEqual(got['host1'], dict(rx_bytes=50, tx_bytes=60))
        self.assertTrue(got['increased'])
        self.assertRaises(bp.RouteError, bp.route_check, before, dict(after, host2=(300, 401)), 50)
        self.assertRaises(bp.RouteError, bp.route_check, before, {'host1': (150, 260)}, 50)

    def test_counter_parse(self):
        self.assertEqual(bp.parse_counters('123\n456\n'), (123, 456))
        self.assertRaises(bp.RouteError, bp.parse_counters, 'cat: no such file\n')


class Smoke(unittest.TestCase):
    def test_request_is_long_enough_to_store_kv(self):
        # LMCache stores 256-token chunks and vLLM blocks are 16 tokens: a short
        # prompt stores nothing, so the route check would see only heartbeats.
        body = json.loads(shlex.split(bp.smoke_command(plan('mooncake-store')))[-1])
        self.assertGreaterEqual(len(body['prompt'].split()), 600)
        self.assertEqual(body['temperature'], 0)

    def test_counters_read_after_settle(self):
        slept = []
        ex = FakeExecutor(['1\n1\n', '1\n1\n', '5\n6\n', '7\n8\n'])
        bp.execute(plan('mooncake-store'), ['check'], ex, sleep=slept.append, expected_kv_bytes=4)
        self.assertEqual(slept, [bp.SETTLE_SECONDS])


class FakeExecutor:
    """Records (host, command, stdin); answers counter reads, PID echoes and log cats."""

    def __init__(self, counters):
        self.calls, self.counters, self.pid = [], list(counters), 1000

    def __call__(self, host, command, stdin=None):
        self.calls.append((host, command, stdin))
        if 'statistics/rx_bytes' in command:
            return 0, self.counters.pop(0)
        if command.endswith('echo $!'):
            self.pid += 1
            return 0, f'{self.pid}\n'
        if command.startswith('cat ') and command.endswith('.log'):
            return 0, 'NCCL INFO NET/Socket : Using [0]thunderbolt0:10.77.0.2<0>\n'
        return 0, ''


class Execute(unittest.TestCase):
    def test_up_check_down(self):
        p = plan('mooncake-store')
        ex = FakeExecutor(['1\n1\n', '1\n1\n', '5\n6\n', '7\n8\n'])
        state = bp.execute(p, ['up', 'check', 'down'], ex, sleep=lambda s: None, expected_kv_bytes=4)
        commands = [c for _, c, _ in ex.calls]
        self.assertTrue(any('MOONCAKE_CONFIG_PATH' in c for c in commands))
        self.assertEqual([h for h, c, stdin in ex.calls if stdin is not None], ['host2'])
        self.assertEqual(state['pids'], {})  # nothing left running after down
        self.assertEqual(state['stopped'], {'vllm-serve': 1003, 'mooncake-client': 1002,
                                            'mooncake-master': 1001})
        self.assertTrue(state['route']['increased'])
        kills = [c for _, c, _ in ex.calls if c.startswith('kill ')]
        self.assertEqual(len(kills), 3)
        self.assertTrue(kills[0].startswith('kill 1003'))  # reverse start order

    def test_check_fails_without_traffic(self):
        ex = FakeExecutor(['1\n1\n', '1\n1\n', '1\n1\n', '1\n1\n'])
        with self.assertRaises(bp.RouteError):
            bp.execute(plan('mooncake-store'), ['up', 'check'], ex, sleep=lambda s: None,
                       expected_kv_bytes=4)

    def test_nccl_check_reads_log(self):
        ex = FakeExecutor(['1\n1\n', '1\n1\n', '5\n6\n', '7\n8\n'])
        state = bp.execute(plan('tp2-nccl'), ['up', 'check'], ex, sleep=lambda s: None)
        self.assertTrue(state['nccl_route']['qualified'])


class DryRunCli(unittest.TestCase):
    def test_every_runner_prints_and_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp, 'executed')
            fake = Path(tmp, 'ssh')
            fake.write_text(f'#!/bin/sh\ntouch {marker}\n')
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            env = dict(os.environ, PATH=f'{tmp}:{os.environ["PATH"]}')
            for name, script in RUNNERS.items():
                args = [sys.executable, '-I', str(HERE / script), '--dry-run',
                        '--host1', 'tb-host1', '--host2', 'tb-host2',
                        '--host1-ip', '10.77.0.1', '--host2-ip', '10.77.0.2',
                        '--workdir', '/srv/xdev-baselines']
                if name.endswith('nccl'):
                    args += ['--model', 'Qwen/Qwen3-32B-FP8']
                    p = plan(name)
                else:
                    args += ['--model', MODEL]
                    if name != 'recompute':
                        args += ['--host1-ssd-dir', '/nvme/mc']
                    if name == 'lmcache-mooncake':
                        args += ['--l1-size-gb', '8']
                    p = plan(name, l1_size_gb=8.0, host1_ssd_dir='/nvme/mc')
                out = subprocess.run(args, env=env, text=True, capture_output=True, timeout=60)
                self.assertEqual(out.returncode, 0, out.stderr)
                for s in p.steps:
                    self.assertIn(bp.remote_command(s), out.stdout, (name, s.name))
                self.assertIn('vllm==', out.stdout)
                self.assertIn('performance_claim: none', out.stdout)
            self.assertFalse(marker.exists())

    def test_execute_requires_explicit_phase(self):
        out = subprocess.run([sys.executable, '-I', str(HERE / 'recompute.py'),
                              '--host1', 'a', '--host2', 'b', '--host1-ip', '10.0.0.1',
                              '--host2-ip', '10.0.0.2', '--workdir', '/w', '--model', MODEL],
                             text=True, capture_output=True, timeout=60)
        self.assertNotEqual(out.returncode, 0)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Deployment plans for the RQ1 baselines (E1 K-KV and E2 M-TP), defaults only.

A plan is the exact list of shell commands, per host, that install the pinned
versions (phase install), start the services in order (phase up), check the
route invariant with one request (phase check) and stop what was started
(phase down). Every runner prints the whole plan with --dry-run and executes
nothing. No runner sets a performance option: every value below is either an
upstream default, an address/interface selection, a value the upstream code
requires without a default, or the topology the experiment defines.

Upstream sources (all pinned in pins.json):
- LMCache v0.5.7: `lmcache server` (lmcache/cli/commands/server.py),
  --l1-size-gb and --eviction-policy are required in legacy L1 mode
  (lmcache/v1/distributed/config.py:1065), the mooncake_store adapter forwards
  every non-LMCache key to Mooncake's setup_internal
  (l2_adapters/mooncake_store_l2_adapter.py), the vLLM connector defaults to
  tcp://localhost:5555 like the server (integration/vllm/lmcache_mp_connector.py).
- Mooncake v0.3.14: setup_internal defaults protocol=tcp, segments 16 MiB
  (mooncake-store/include/types.h:259-262); SSD offload lives in the real
  client, enabled with --enable_offload=true on master and client and
  MOONCAKE_OFFLOAD_FILE_STORAGE_PATH (docs/source/deployment/ssd/ssd-offload.md).
- vLLM 0.33.0: MooncakeStoreConfig.from_file (vllm/distributed/mooncake_store.py)
  defaults protocol to "rdma", so "tcp" is written; standalone-store mode needs
  global_segment_size 0; the requester hostname is get_ip(), i.e. VLLM_HOST_IP.
- vLLM 0.10.2: multi-node runs require Ray (docs/serving/parallelism_scaling.md).
"""
import argparse
from dataclasses import dataclass
import importlib.util
import ipaddress
import json
from pathlib import Path, PurePosixPath
import shlex
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / 'pins.json').read_text())
IFACE = 'thunderbolt0'
BASELINES = ('lmcache-mooncake', 'mooncake-store', 'recompute', 'tp2-nccl', 'pp2-nccl')
PHASES = ('install', 'up', 'check', 'down')
MASTER_PORT = 50051       # mooncake_master default rpc port
CLIENT_PORT = 50052       # mooncake_client default rpc port
VLLM_PORT = 8000          # vllm serve default port
LMCACHE_HTTP = 8080       # lmcache server default --http-port
RAY_PORT = 6379           # vLLM run_cluster.sh head port
NCCL_ENV = (('NCCL_NET', 'Socket'), ('NCCL_SOCKET_IFNAME', '=' + IFACE),
            ('GLOO_SOCKET_IFNAME', IFACE), ('NCCL_DEBUG', 'INFO'),
            ('NCCL_DEBUG_SUBSYS', 'INIT,NET'))
# About 1,000 tokens: several LMCache 256-token chunks and many 16-token vLLM
# blocks, so the KV connector actually stores something over thunderbolt0.
SMOKE_PROMPT = 'The quick brown fox jumps over the lazy dog. ' * 70 + 'Summarize:'
SETTLE_SECONDS = 5.0       # let an asynchronous KV store finish before re-reading counters


class RouteError(RuntimeError):
    """The thunderbolt0 route invariant does not hold."""


@dataclass(frozen=True)
class Rig:
    host1: str          # ssh alias of host 1 (NVMe, Mooncake owner, Ray head)
    host2: str          # ssh alias of host 2 (GPU serving host for E1)
    host1_ip: str       # host 1 thunderbolt0 IPv4
    host2_ip: str       # host 2 thunderbolt0 IPv4
    workdir: str        # absolute directory on both hosts for venvs/sources/logs

    def __post_init__(self):
        for name in ('host1_ip', 'host2_ip'):
            try:
                ipaddress.IPv4Address(getattr(self, name))
            except ValueError:
                raise ValueError(f'{name} must be the IPv4 address of {IFACE}') from None
        if self.host1_ip == self.host2_ip:
            raise ValueError('host1_ip and host2_ip must differ')
        if not PurePosixPath(self.workdir).is_absolute():
            raise ValueError('workdir must be absolute')
        for name in ('host1', 'host2'):
            if not getattr(self, name) or getattr(self, name).startswith('-'):
                raise ValueError(f'{name} must be an ssh destination')


@dataclass(frozen=True)
class Step:
    phase: str
    host: str
    name: str
    argv: tuple
    env: tuple = ()
    cwd: str = None
    background: bool = False
    ready: tuple = None     # ('http', url) | ('tcp', port) | ('cmd', host, command)
    log: str = None


@dataclass(frozen=True)
class Plan:
    baseline: str
    rig: Rig
    model: str
    steps: tuple
    files: tuple = ()           # (((host, path), content), ...)
    route_hosts: tuple = ()     # hosts whose thunderbolt0 counters must increase
    smoke_host: str = 'host2'
    nccl_route: bool = False    # also apply tests/benchmarks/tp qualify_nccl_route


def venv_bin(workdir, venv, exe):
    return f'{workdir}/{venv}/bin/{exe}'


def _install_venv(host, workdir, venv, python, packages):
    pip = venv_bin(workdir, venv, 'pip')
    return [Step('install', host, f'create-{venv}', (python, '-m', 'venv', f'{workdir}/{venv}')),
            Step('install', host, f'pip-{venv}', (pip, 'install', *packages))]


def _clone(host, url, commit, dest):
    return [Step('install', host, f'clone-{PurePosixPath(dest).name}',
                 ('git', 'clone', '--filter=blob:none', url, dest)),
            Step('install', host, f'checkout-{PurePosixPath(dest).name}',
                 ('git', '-C', dest, 'checkout', '--detach', commit))]


def _service(host, name, argv, workdir, env=(), ready=None):
    return Step('up', host, name, tuple(argv), tuple(env), background=True, ready=ready,
                log=f'{workdir}/logs/{name}.log')


def _host1_mooncake(rig, ssd_dir):
    """Host 1: Mooncake master plus the standalone real client that owns DRAM and SSD."""
    venv = 'venv-mooncake-host1'
    install = _install_venv('host1', rig.workdir, venv, 'python3.12',
                            (PINS['mooncake']['wheel'],))
    master = _service('host1', 'mooncake-master',
                      (venv_bin(rig.workdir, venv, 'mooncake_master'), '--enable_offload=true'),
                      rig.workdir, ready=('tcp', MASTER_PORT))
    owner = _service('host1', 'mooncake-client', (
        venv_bin(rig.workdir, venv, 'mooncake_client'),
        f'--master_server_address={rig.host1_ip}:{MASTER_PORT}', f'--host={rig.host1_ip}',
        '--metadata_server=P2PHANDSHAKE', '--enable_offload=true'), rig.workdir,
        env=(('MOONCAKE_OFFLOAD_FILE_STORAGE_PATH', ssd_dir),), ready=('tcp', CLIENT_PORT))
    return install, [master, owner]


def _vllm_serve(host, venv, rig, model, args=(), env=()):
    return _service(host, 'vllm-serve', (venv_bin(rig.workdir, venv, 'vllm'), 'serve', model,
                                         *args), rig.workdir, env=env,
                    ready=('http', f'http://127.0.0.1:{VLLM_PORT}/health'))


def _kv_config(connector):
    return json.dumps({'kv_connector': connector, 'kv_role': 'kv_both'}, separators=(',', ':'))


def _lmcache_mooncake(rig, model, l1_size_gb, host1_ssd_dir):
    w, venv = rig.workdir, 'venv-lmcache'
    mc_src, mc_build, lm_src = f'{w}/src/Mooncake', f'{w}/build/Mooncake', f'{w}/src/LMCache'
    pip = venv_bin(w, venv, 'pip')
    include = ';'.join((f'{mc_src}/mooncake-store/include',
                        f'{mc_src}/mooncake-store/include/cachelib_memory_allocator',
                        f'{mc_src}/mooncake-store/include/cachelib_memory_allocator/include',
                        f'{mc_src}/mooncake-transfer-engine/include',
                        f'{mc_src}/mooncake-common/include',
                        f'{mc_build}/mooncake-transfer-engine/include'))
    host1_install, host1_up = _host1_mooncake(rig, host1_ssd_dir)
    install = host1_install + [
        *_clone('host2', PINS['mooncake']['repo'], PINS['mooncake']['commit'], mc_src),
        Step('install', 'host2', 'mooncake-dependencies', ('sudo', 'bash', 'dependencies.sh'),
             cwd=mc_src),
        Step('install', 'host2', 'mooncake-configure',
             ('cmake', '-S', mc_src, '-B', mc_build, '-DBUILD_SHARED_LIBS=ON')),
        Step('install', 'host2', 'mooncake-build', ('cmake', '--build', mc_build, '-j')),
        *_clone('host2', PINS['lmcache']['repo'], PINS['lmcache']['commit'], lm_src),
        *_install_venv('host2', w, venv, PINS['vllm_e1']['python'],
                       ('-r', f'{lm_src}/requirements/build.txt')),
        Step('install', 'host2', 'pip-vllm', (pip, 'install', f"vllm=={PINS['vllm_e1']['version']}")),
        Step('install', 'host2', 'pip-lmcache-source',
             (pip, 'install', '-e', lm_src, '--no-build-isolation'),
             env=(('BUILD_MOONCAKE', '1'), ('MOONCAKE_INCLUDE_DIR', include),
                  ('MOONCAKE_LIB_DIR', f'{mc_build}/mooncake-store/src'))),
    ]
    adapter = json.dumps({'type': 'mooncake_store', 'local_hostname': rig.host2_ip,
                          'metadata_server': 'P2PHANDSHAKE',
                          'master_server_addr': f'{rig.host1_ip}:{MASTER_PORT}',
                          'protocol': 'tcp', 'global_segment_size': '0'},
                         separators=(',', ':'))
    server = _service('host2', 'lmcache-server', (
        venv_bin(w, venv, 'lmcache'), 'server', '--l1-size-gb', str(float(l1_size_gb)),
        '--eviction-policy', 'LRU', '--l2-adapter', adapter), w,
        ready=('http', f'http://127.0.0.1:{LMCACHE_HTTP}/healthcheck'))
    serve = _vllm_serve('host2', venv, rig, model,
                        ('--kv-transfer-config', _kv_config('LMCacheMPConnector')))
    return Plan('lmcache-mooncake', rig, model, tuple(install + host1_up + [server, serve]),
                route_hosts=('host1', 'host2'), smoke_host='host2')


def _mooncake_store(rig, model, host1_ssd_dir):
    w, venv = rig.workdir, 'venv-mooncake-store'
    host1_install, host1_up = _host1_mooncake(rig, host1_ssd_dir)
    install = host1_install + _install_venv(
        'host2', w, venv, PINS['vllm_e1']['python'],
        (f"vllm=={PINS['vllm_e1']['version']}", PINS['mooncake']['wheel']))
    path = f'{w}/config/mooncake-store-host2.json'
    config = json.dumps({'mode': 'standalone-store', 'metadata_server': 'P2PHANDSHAKE',
                         'master_server_address': f'{rig.host1_ip}:{MASTER_PORT}',
                         'global_segment_size': 0, 'protocol': 'tcp', 'device_name': '',
                         'enable_offload': True}, indent=2) + '\n'
    serve = _vllm_serve('host2', venv, rig, model,
                        ('--kv-transfer-config', _kv_config('MooncakeStoreConnector')),
                        env=(('MOONCAKE_CONFIG_PATH', path), ('VLLM_HOST_IP', rig.host2_ip)))
    return Plan('mooncake-store', rig, model, tuple(install + host1_up + [serve]),
                files=((('host2', path), config),), route_hosts=('host1', 'host2'),
                smoke_host='host2')


def _recompute(rig, model):
    venv = 'venv-recompute'
    install = _install_venv('host2', rig.workdir, venv, PINS['vllm_e1']['python'],
                            (f"vllm=={PINS['vllm_e1']['version']}",))
    return Plan('recompute', rig, model,
                tuple(install + [_vllm_serve('host2', venv, rig, model)]), smoke_host='host2')


def _nccl(rig, model, parallel):
    w, venv = rig.workdir, 'venv-vllm-0.10.2'
    install = []
    for host in ('host1', 'host2'):
        install += _install_venv(host, w, venv, PINS['vllm_e2']['python'], (
            f"vllm=={PINS['vllm_e2']['version']}", f"ray[cgraph]=={PINS['ray']['version']}"))
    ray = venv_bin(w, venv, 'ray')
    alive = (f"{venv_bin(w, venv, 'python')} -c "
             + shlex.quote("import ray,sys; ray.init(address='auto'); "
                           "sys.exit(0 if sum(n['Alive'] for n in ray.nodes()) >= 2 else 1)"))
    head = _service('host1', 'ray-head', (ray, 'start', '--block', '--head', f'--port={RAY_PORT}',
                                          f'--node-ip-address={rig.host1_ip}'), w,
                    env=NCCL_ENV + (('VLLM_HOST_IP', rig.host1_ip),), ready=('tcp', RAY_PORT))
    worker = _service('host2', 'ray-worker', (
        ray, 'start', '--block', f'--address={rig.host1_ip}:{RAY_PORT}',
        f'--node-ip-address={rig.host2_ip}'), w, env=NCCL_ENV + (('VLLM_HOST_IP', rig.host2_ip),),
        ready=('cmd', 'host1', alive))
    serve = _vllm_serve('host1', venv, rig, model,
                        (parallel, '2', '--distributed-executor-backend', 'ray'),
                        env=NCCL_ENV + (('VLLM_HOST_IP', rig.host1_ip),))
    name = 'tp2-nccl' if parallel == '--tensor-parallel-size' else 'pp2-nccl'
    return Plan(name, rig, model, tuple(install + [head, worker, serve]),
                route_hosts=('host1', 'host2'), smoke_host='host1', nccl_route=True)


def build(baseline, rig, model, l1_size_gb=None, host1_ssd_dir=None):
    if not model:
        raise ValueError('model is required')
    if baseline in ('lmcache-mooncake', 'mooncake-store'):
        if not host1_ssd_dir or not PurePosixPath(host1_ssd_dir).is_absolute():
            raise ValueError('host1_ssd_dir (absolute directory on host 1 NVMe) is required')
    if baseline == 'lmcache-mooncake':
        if l1_size_gb is None or float(l1_size_gb) <= 0:
            raise ValueError('l1_size_gb is required (same value in every LMCache arm)')
        return _lmcache_mooncake(rig, model, l1_size_gb, host1_ssd_dir)
    if baseline == 'mooncake-store':
        return _mooncake_store(rig, model, host1_ssd_dir)
    if baseline == 'recompute':
        return _recompute(rig, model)
    if baseline == 'tp2-nccl':
        return _nccl(rig, model, '--tensor-parallel-size')
    if baseline == 'pp2-nccl':
        return _nccl(rig, model, '--pipeline-parallel-size')
    raise ValueError(f'unknown baseline {baseline!r}; choose from {BASELINES}')


def remote_command(step):
    """The exact shell command sent to the step's host."""
    words = shlex.join(step.argv)
    if step.env:
        words = 'env ' + ' '.join(f'{k}={shlex.quote(v)}' for k, v in step.env) + ' ' + words
    if step.background:
        log = shlex.quote(step.log)
        words = (f'mkdir -p {shlex.quote(str(PurePosixPath(step.log).parent))}; '
                 f'nohup {words} > {log} 2>&1 < /dev/null & echo $!')
    if step.cwd:
        words = f'cd {shlex.quote(step.cwd)} || exit 1; {words}'
    return words


def ready_command(step):
    kind = step.ready[0]
    if kind == 'http':
        return step.host, f'curl -sf -o /dev/null {shlex.quote(step.ready[1])}'
    if kind == 'tcp':
        return step.host, f"bash -c 'exec 3<>/dev/tcp/127.0.0.1/{int(step.ready[1])}'"
    return step.ready[1], step.ready[2]


def counter_command():
    base = f'/sys/class/net/{IFACE}/statistics'
    return f'cat {base}/rx_bytes {base}/tx_bytes'


def smoke_command(plan):
    body = json.dumps({'model': plan.model, 'prompt': SMOKE_PROMPT, 'max_tokens': 16,
                       'temperature': 0})
    return (f'curl -sf -X POST http://127.0.0.1:{VLLM_PORT}/v1/completions '
            f"-H 'Content-Type: application/json' -d {shlex.quote(body)}")


def file_command(path):
    return f'mkdir -p {shlex.quote(str(PurePosixPath(path).parent))} && cat > {shlex.quote(path)}'


def parse_counters(text):
    words = text.split()
    if len(words) != 2 or not all(w.isdigit() for w in words):
        raise RouteError(f'cannot read {IFACE} counters: {text.strip()[:200]!r}')
    return int(words[0]), int(words[1])


def route_check(before, after):
    """Positive rx and tx deltas on every host; an invariant, not a measurement."""
    result = {}
    for host, (rx, tx) in before.items():
        if host not in after:
            raise RouteError(f'no {IFACE} counters after the request on {host}')
        delta = dict(rx_bytes=after[host][0] - rx, tx_bytes=after[host][1] - tx)
        if delta['rx_bytes'] <= 0 or delta['tx_bytes'] <= 0:
            raise RouteError(f'{IFACE} bytes did not increase on {host}: {delta}')
        result[host] = delta
    result['increased'] = True
    return result


def _qualify_nccl():
    spec = importlib.util.spec_from_file_location('xdev_tp_run', HERE.parent / 'tp' / 'run.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.qualify_nccl_route


def _must(executor, host, command, stdin=None, what=''):
    code, out = executor(host, command, stdin)
    if code:
        raise RuntimeError(f'{what or command} failed on {host} ({code}): {out.strip()[:400]}')
    return out


def execute(plan, phases, executor, sleep=time.sleep, state=None, ready_timeout=1800.0,
            poll_interval=5.0):
    """Run the selected phases in PHASES order; executor(host, command, stdin) -> (rc, out)."""
    state = {} if state is None else state      # updated in place, also on failure
    state.update(baseline=plan.baseline, performance_claim='none')
    state.setdefault('pids', {})
    by_name = {s.name: s for s in plan.steps}
    for phase in [p for p in PHASES if p in phases]:
        if phase == 'install':
            for s in (s for s in plan.steps if s.phase == 'install'):
                _must(executor, s.host, remote_command(s), what=s.name)
        elif phase == 'up':
            for (host, path), content in plan.files:
                _must(executor, host, file_command(path), stdin=content, what=f'write {path}')
            for s in (s for s in plan.steps if s.phase == 'up'):
                pid = _must(executor, s.host, remote_command(s), what=s.name).strip()
                if not pid.isdigit():
                    raise RuntimeError(f'{s.name}: no PID from {s.host}: {pid[:200]!r}')
                state['pids'][s.name] = int(pid)
                host, command = ready_command(s)
                waited = 0.0
                while executor(host, command, None)[0]:
                    if waited >= ready_timeout:
                        raise RuntimeError(f'{s.name} not ready after {ready_timeout:.0f} s; '
                                           f'see {s.log} on {s.host}')
                    sleep(poll_interval)
                    waited += poll_interval
        elif phase == 'check':
            before = {h: parse_counters(_must(executor, h, counter_command()))
                      for h in plan.route_hosts}
            reply = _must(executor, plan.smoke_host, smoke_command(plan), what='smoke request')
            sleep(SETTLE_SECONDS)
            after = {h: parse_counters(_must(executor, h, counter_command()))
                     for h in plan.route_hosts}
            state['smoke_reply'] = reply[:4096]
            if plan.route_hosts:
                state['route'] = route_check(before, after)
            if plan.nccl_route:
                serve = by_name['vllm-serve']
                log = _must(executor, serve.host, f'cat {shlex.quote(serve.log)}')
                ip = plan.rig.host1_ip if serve.host == 'host1' else plan.rig.host2_ip
                delta = state['route'][serve.host]
                state['nccl_route'] = _qualify_nccl()(dict(serve.env), log, {IFACE: dict(
                    addresses=[ip], **delta)})
        elif phase == 'down':
            for name in reversed([s.name for s in plan.steps if s.phase == 'up']):
                pid = state['pids'].pop(name, None)
                if pid is not None:
                    executor(by_name[name].host, f'kill {int(pid)}', None)
                    state.setdefault('stopped', {})[name] = pid
    return state


def ssh_executor(rig, timeout=None):
    aliases = {'host1': rig.host1, 'host2': rig.host2}

    def run(host, command, stdin=None):
        out = subprocess.run(['ssh', '-o', 'BatchMode=yes', aliases[host], command],
                             input=stdin, text=True, capture_output=True, timeout=timeout)
        return out.returncode, out.stdout + out.stderr
    return run


def render(plan):
    lines = [f'# baseline: {plan.baseline}', 'performance_claim: none',
             f'model: {plan.model}',
             f'hosts: host1={plan.rig.host1} ({IFACE} {plan.rig.host1_ip}) '
             f'host2={plan.rig.host2} ({IFACE} {plan.rig.host2_ip})',
             'pins: ' + json.dumps({k: v for k, v in PINS.items() if isinstance(v, dict)},
                                   sort_keys=True)]
    for phase in ('install', 'up'):
        if phase == 'up':
            for (host, path), content in plan.files:
                lines += [f'\n# [up] {host}: write {path}', f'  $ {file_command(path)} <<EOF',
                          content.rstrip('\n'), 'EOF']
        for s in (s for s in plan.steps if s.phase == phase):
            lines += [f'\n# [{phase}] {s.host}: {s.name}', f'  $ {remote_command(s)}']
            if s.ready:
                host, command = ready_command(s)
                lines += [f'  # ready when this exits 0 on {host}:', f'  $ {command}']
    lines.append('\n# [check]')
    for h in plan.route_hosts:
        lines.append(f'  $ {counter_command()}   # on {h}, before and after the request')
    lines.append(f'  $ {smoke_command(plan)}   # on {plan.smoke_host}')
    if plan.route_hosts:
        lines.append(f'  invariant: rx_bytes and tx_bytes of {IFACE} increase on '
                     + ', '.join(plan.route_hosts))
    if plan.nccl_route:
        lines.append('  invariant: tests/benchmarks/tp/run.py qualify_nccl_route on the '
                     'vllm-serve log (NET/Socket using thunderbolt0 only, no NCCL tuning)')
    lines.append('\n# [down]')
    for s in reversed([s for s in plan.steps if s.phase == 'up']):
        lines.append(f'  $ kill <pid of {s.name}>   # on {s.host}')
    return '\n'.join(lines) + '\n'


def main(baseline, argv=None):
    p = argparse.ArgumentParser(description=f'{baseline} baseline deployment (defaults only)')
    p.add_argument('--dry-run', action='store_true', help='print every command; run nothing')
    p.add_argument('--phase', action='append', choices=PHASES,
                   help='phase to execute (repeatable); required unless --dry-run')
    p.add_argument('--host1', required=True, help='ssh destination of host 1')
    p.add_argument('--host2', required=True, help='ssh destination of host 2')
    p.add_argument('--host1-ip', required=True, help=f"host 1's {IFACE} IPv4 address")
    p.add_argument('--host2-ip', required=True, help=f"host 2's {IFACE} IPv4 address")
    p.add_argument('--workdir', required=True, help='absolute directory on both hosts')
    p.add_argument('--model', required=True, help='model id or path (same on both hosts)')
    if baseline in ('lmcache-mooncake', 'mooncake-store'):
        p.add_argument('--host1-ssd-dir', required=True,
                       help='Mooncake SSD offload directory on host 1 NVMe')
    if baseline == 'lmcache-mooncake':
        p.add_argument('--l1-size-gb', required=True, type=float,
                       help='LMCache L1 size (required by lmcache server; same in every arm)')
    p.add_argument('--state', help='JSON state file (written by up/check, read by down)')
    p.add_argument('--ready-timeout', type=float, default=1800.0)
    args = p.parse_args(argv)
    if not args.dry_run and not args.phase:
        p.error('choose --dry-run or at least one --phase')
    rig = Rig(args.host1, args.host2, args.host1_ip, args.host2_ip, args.workdir)
    plan = build(baseline, rig, args.model, getattr(args, 'l1_size_gb', None),
                 getattr(args, 'host1_ssd_dir', None))
    if args.dry_run:
        sys.stdout.write(render(plan))
        return 0
    state = {}
    if args.state and Path(args.state).exists():
        state = json.loads(Path(args.state).read_text())
    try:
        execute(plan, args.phase, ssh_executor(rig), state=state,
                ready_timeout=args.ready_timeout)
    finally:
        if args.state:
            Path(args.state).write_text(json.dumps(state, indent=2, sort_keys=True) + '\n')
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0

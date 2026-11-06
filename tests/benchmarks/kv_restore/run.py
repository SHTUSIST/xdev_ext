#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""K-KV orchestrator: one command per experiment step, every step recorded.

  plan           restore plans of objects/prefixes (no device)
  prepare-nvme   host 1: write each KV object's pattern to its LBAs (overwrites!)
  nvmeof-target  host 1: kernel NVMe-oF/TCP target up/down through nvmet configfs
  run            host 2: start one arm's worker once, then per restore: drop
                 caches, host-1 and host-2 CPU markers, optional perf memory
                 counters, one GO, one KV_RESULT line in results.jsonl
  recompute      host 2: time an operator-provided prefill command per prefix

`run` and `recompute` write raw records only; analyze.py derives metrics.
--dry-run prints what would happen and touches nothing. Nothing here
interprets a guest or fixture record as a performance result.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import shlex
import signal
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kl, kp, kc = _load('kv_layout'), _load('kv_protocol'), _load('kv_cpu')
KIB, MIB = 1 << 10, 1 << 20
WRITE_CHUNK = 64 * MIB


def _prefixes(text):
    try:
        values = [int(v) for v in text.split(',')]
    except ValueError:
        raise argparse.ArgumentTypeError('comma-separated token counts') from None
    if not values or any(v <= 0 for v in values):
        raise argparse.ArgumentTypeError('token counts must be positive')
    return values


def geometry(args):
    return kl.Geometry(args.group_bytes, args.frame_bytes, args.depth, args.window, not args.no_early)


def new_output(path):
    p = Path(path)
    if p.exists() and (not p.is_dir() or any(p.iterdir())):
        raise SystemExit(f'output {p} exists and is not empty; choose a new directory')
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    return p


# ---- plan --------------------------------------------------------------------

def cmd_plan(args):
    m = kl.load_manifest(args.manifest)
    out = [kl.plan_restore(m, args.object, t, geometry(args), args.ordinal + i,
                           args.dst_frame0).to_json() for i, t in enumerate(args.prefixes)]
    print(json.dumps(out, indent=2))
    return 0


# ---- prepare-nvme ---------------------------------------------------------------

def cmd_prepare_nvme(args):
    m = kl.load_manifest(args.manifest)
    extents = [dict(object=o.name, slba=o.slba, bytes=o.bytes, offset=o.slba * m.lba_bytes)
               for o in m.objects]
    if args.dry_run:
        print(json.dumps(dict(device=args.device, writes=extents), indent=2))
        return 0
    if not args.i_understand_this_overwrites:
        raise SystemExit('prepare-nvme overwrites the KV extents of the device: '
                         'pass --i-understand-this-overwrites')
    fd = os.open(args.device, os.O_WRONLY | os.O_CLOEXEC)
    try:
        for o in m.objects:
            base = o.slba * m.lba_bytes
            for off in range(0, o.bytes, WRITE_CHUNK):
                data = kl.pattern_bytes(o.seed, off, min(WRITE_CHUNK, o.bytes - off))
                if os.pwrite(fd, data, base + off) != len(data):
                    raise SystemExit(f'short write at {base + off}')
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(args.device, os.O_RDONLY | os.O_CLOEXEC)
    try:
        for o in m.objects:
            base = o.slba * m.lba_bytes
            for off in sorted({0, max(0, o.bytes - 4096)}):
                n = min(4096, o.bytes - off)
                if os.pread(fd, n, base + off) != kl.pattern_bytes(o.seed, off, n):
                    raise SystemExit(f'read-back mismatch in {o.name} at {off}')
    finally:
        os.close(fd)
    print(json.dumps(dict(device=args.device, written=extents)))
    return 0


# ---- nvmeof-target ----------------------------------------------------------------

def nvmet_steps(action, device, addr, port, nqn, port_id):
    """nvmet configfs operations (drivers/nvme/target/configfs.c), relative to the configfs root."""
    sub = f'nvmet/subsystems/{nqn}'
    ns = f'{sub}/namespaces/1'
    prt = f'nvmet/ports/{port_id}'
    link = f'{prt}/subsystems/{nqn}'
    if action == 'up':
        return [('mkdir', sub), ('write', f'{sub}/attr_allow_any_host', '1'), ('mkdir', ns),
                ('write', f'{ns}/device_path', device), ('write', f'{ns}/enable', '1'),
                ('mkdir', prt), ('write', f'{prt}/addr_trtype', 'tcp'),
                ('write', f'{prt}/addr_adrfam', 'ipv4'), ('write', f'{prt}/addr_traddr', addr),
                ('write', f'{prt}/addr_trsvcid', str(port)), ('symlink', link, sub)]
    return [('unlink', link), ('rmdir', prt), ('write', f'{ns}/enable', '0'), ('rmdir', ns),
            ('rmdir', sub)]


def _mkdir(path):
    os.mkdir(path)


def cmd_nvmeof_target(args):
    steps = nvmet_steps(args.action, args.device, args.addr, args.port, args.nqn, args.port_id)
    root = Path(args.configfs_root)
    if args.dry_run:
        print(json.dumps(dict(configfs_root=str(root), steps=steps), indent=2))
        return 0
    if args.action == 'up' and str(root) == '/sys/kernel/config':
        subprocess.run(['modprobe', 'nvmet-tcp'], check=True)
    for step in steps:
        op, path = step[0], root / step[1]
        if op == 'mkdir':
            _mkdir(path)
        elif op == 'write':
            path.write_text(step[2] + '\n')
        elif op == 'symlink':
            os.symlink(root / step[2], path)
        elif op == 'unlink':
            os.unlink(path)
        elif op == 'rmdir':
            os.rmdir(path)
    print(json.dumps(dict(action=args.action, steps=len(steps))))
    return 0


# ---- run ---------------------------------------------------------------------------

def worker_argv(args, m):
    g = geometry(args)
    if args.arm == 'custom':
        argv = json.loads(args.worker_argv)
    elif args.arm == 'xdev-ext':
        argv = [args.worker_bin or str(HERE / 'build/kv_restore'), 'restore',
                '--window-slba', m.window_slba, '--window-nlb', m.window_nlb,
                '--lba-bytes', m.lba_bytes, '--group-bytes', g.group_bytes,
                '--frame-bytes', g.frame_bytes, '--depth', g.depth, '--window', g.window,
                '--gpu-bdf', args.gpu_bdf, '--gpu-node', args.gpu_node,
                '--pool-bytes', args.pool_bytes, '--peer', args.peer,
                '--timeout-ms', args.timeout_ms, '--token', args.request_token]
        argv += ['--service', args.service] if args.service else ['--link-token', args.link_token]
        if args.xdomain_prog:
            argv += ['--xdomain-prog', args.xdomain_prog]
        if g.early:
            argv.append('--early')
    elif args.arm == 'nvmeof':
        argv = [args.worker_bin or str(HERE / 'build/nvmeof_worker'), '--device', args.device,
                '--lba-bytes', m.lba_bytes, '--frame-bytes', g.frame_bytes,
                '--pool-bytes', args.pool_bytes, '--gpu-bdf', args.gpu_bdf]
    else:
        argv = [sys.executable, '-I', str(HERE / 'mooncake_worker.py'), 'host2-restore',
                '--manifest', args.manifest, '--local-hostname', args.local_hostname,
                '--master', args.master, '--pool-bytes', args.pool_bytes,
                '--gpu-bdf', args.gpu_bdf, '--frame-bytes', g.frame_bytes]
    argv += json.loads(args.worker_extra)
    return [str(a) for a in argv]


def schedule(prefixes, repetitions, seed, first_ordinal):
    rng = random.Random(seed)
    out, ordinal, seen = [], first_ordinal, set()
    for rep in range(repetitions):
        order = list(prefixes)
        rng.shuffle(order)
        for tokens in order:
            out.append(dict(rep=rep, prefix_tokens=tokens, ordinal=ordinal,
                            verify=tokens not in seen))
            seen.add(tokens)
            ordinal += 1
    return out


class Perf:
    """perf stat -a with events disabled until 'enable' (perf-stat --control/--delay=-1)."""

    def __init__(self, perf, events, workdir, tag):
        self.dir = Path(tempfile.mkdtemp(prefix=f'perf-{tag}-', dir=workdir))
        self.ctl, self.ack, self.out = self.dir / 'ctl', self.dir / 'ack', self.dir / 'stat.csv'
        os.mkfifo(self.ctl)
        os.mkfifo(self.ack)
        self.proc = subprocess.Popen([perf, 'stat', '-a', '-x', ',', '-e', events, '--delay=-1',
                                      f'--control=fifo:{self.ctl},{self.ack}', '-o', str(self.out),
                                      '--', 'sleep', '3600'], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        # O_RDWR opens of a FIFO do not block on Linux, whatever order perf opens them in.
        self.ctl_f = os.fdopen(os.open(self.ctl, os.O_RDWR | os.O_CLOEXEC), 'w')
        self.ack_f = os.fdopen(os.open(self.ack, os.O_RDWR | os.O_CLOEXEC), 'r')

    def _cmd(self, word):
        self.ctl_f.write(word + '\n')
        self.ctl_f.flush()
        if self.ack_f.readline().strip() != 'ack':
            raise RuntimeError(f'perf did not acknowledge {word}')

    def enable(self):
        self._cmd('enable')

    def disable(self):
        self._cmd('disable')

    def finish(self):
        self.proc.send_signal(signal.SIGINT)
        self.proc.wait(timeout=30)
        self.ctl_f.close()
        self.ack_f.close()
        counts = {}
        for line in self.out.read_text().splitlines():
            parts = line.split(',')
            if len(parts) >= 3 and parts[0].strip().isdigit():
                counts[parts[2]] = int(parts[0])
        return counts


def cmd_run(args):
    m = kl.load_manifest(args.manifest)
    obj = m.object(args.object)
    for t in args.prefixes:
        if t > obj.tokens or kl.kv_bytes(obj.model, t) % args.group_bytes:
            raise SystemExit(f'prefix {t} is not whole groups of object {obj.name}')
    argv = worker_argv(args, m)
    plan = schedule(args.prefixes, args.repetitions, args.seed, args.first_ordinal)
    if args.dry_run:
        print(json.dumps(dict(worker_argv=argv, schedule=plan), indent=2))
        return 0
    token = Path(args.token_file).read_text().strip()
    out = new_output(args.output)
    agent = kc.AgentClient(kc.parse_address(args.host1_agent), token=token, timeout=args.agent_timeout)
    agent.ping()
    meta = dict(schema=1, arm=args.arm, performance_claim='none', worker_argv=argv,
                manifest=json.loads(Path(args.manifest).read_text()), object=obj.name,
                geometry=geometry(args).__dict__, prefixes=args.prefixes,
                repetitions=args.repetitions, schedule=plan, host2=dict(
                    node=platform.node(), release=platform.release()),
                drop_caches=dict(host1=args.drop_caches_host1, host2=args.drop_caches_host2),
                perf_events=args.perf_events, started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                                                       time.gmtime()))
    worker = kp.Worker(argv, ready_timeout=args.ready_timeout, log=out / 'worker.log')
    meta['worker_ready'] = worker.ready
    agent.begin('idle')
    local = kc.snapshot()
    time.sleep(args.idle_seconds)
    meta['idle'] = dict(host2=kc.delta(local, kc.snapshot()), host1=agent.end('idle'))
    failures = 0
    with open(out / 'results.jsonl', 'w') as rows:
        for item in plan:
            run = f'{args.arm}-{obj.name}-{item["prefix_tokens"]}-r{item["rep"]}-o{item["ordinal"]}'
            if args.drop_caches_host2:
                kc.drop_caches()
            if args.drop_caches_host1:
                agent.drop_caches()
            perf = Perf(args.perf, args.perf_events, out, run) if args.perf_events else None
            agent.begin(run)
            before = kc.snapshot()
            if perf:
                perf.enable()
            try:
                result = worker.go(run, item['ordinal'], obj.slba,
                                   kl.kv_bytes(obj.model, item['prefix_tokens']), args.dst_frame0,
                                   obj.seed, item['verify'] or args.verify_every,
                                   timeout=args.run_timeout)
                error = None
            except (kp.WorkerError, kp.ProtocolError) as e:
                result, error = None, str(e)
            if perf:
                perf.disable()
            after = kc.snapshot()
            host1 = agent.end(run)
            row = dict(run=run, arm=args.arm, object=obj.name, model=obj.model,
                       prefix_tokens=item['prefix_tokens'], rep=item['rep'],
                       ordinal=item['ordinal'], bytes=kl.kv_bytes(obj.model, item['prefix_tokens']),
                       ok=bool(result and result['ok']), latency_ns=result['latency_ns'] if result else 0,
                       worker=result, worker_error=error, host2_cpu=kc.delta(before, after),
                       host1_cpu=host1, host1_drop_caches=args.drop_caches_host1,
                       host2_drop_caches=args.drop_caches_host2,
                       perf=perf.finish() if perf else None)
            failures += not row['ok']
            rows.write(json.dumps(row, sort_keys=True) + '\n')
            rows.flush()
            if error:
                break
    try:
        meta['worker_bye'] = worker.quit(timeout=args.ready_timeout)
    except (kp.WorkerError, kp.ProtocolError) as e:
        meta['worker_bye'] = dict(error=str(e))
    meta['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    meta['failed_runs'] = failures
    (out / 'run.json').write_text(json.dumps(meta, indent=2, sort_keys=True) + '\n')
    agent.close()
    return 1 if failures else 0


# ---- recompute ------------------------------------------------------------------------

def cmd_recompute(args):
    kl.kv_bytes(args.model, 1)
    out = new_output(args.output)
    failures = 0
    with open(out / 'results.jsonl', 'w') as rows:
        for rep in range(args.repetitions):
            for tokens in args.prefixes:
                argv = shlex.split(args.command.format(model=args.model, prompt_tokens=tokens))
                t0 = time.monotonic_ns()
                try:
                    r = subprocess.run(argv, capture_output=True, text=True, timeout=args.timeout)
                    code, stdout, stderr = r.returncode, r.stdout, r.stderr
                except subprocess.TimeoutExpired:
                    code, stdout, stderr = None, '', 'timeout'
                t1 = time.monotonic_ns()
                reported = None
                lines = [l for l in stdout.splitlines() if l.strip()]
                if lines:
                    try:
                        reported = json.loads(lines[-1])
                    except json.JSONDecodeError:
                        reported = None
                row = dict(model=args.model, prefix_tokens=tokens, rep=rep, argv=argv,
                           ok=code == 0, returncode=code, wall_ns=t1 - t0, reported=reported,
                           stderr_tail=stderr[-2000:])
                failures += not row['ok']
                rows.write(json.dumps(row, sort_keys=True) + '\n')
    (out / 'run.json').write_text(json.dumps(dict(schema=1, kind='recompute', command=args.command,
                                                  performance_claim='none'), indent=2) + '\n')
    return 1 if failures else 0


# ---- arguments -----------------------------------------------------------------------

def add_geometry(p):
    # 128 KiB: nvme-pci caps one transfer at dma_opt_mapping_size(), 128 KiB with an
    # IOMMU DMA domain; a larger group is refused at BUILD on such a host.
    p.add_argument('--group-bytes', type=int, default=128 * KIB)
    p.add_argument('--frame-bytes', type=int, default=128 * KIB)
    p.add_argument('--depth', type=int, default=32)
    p.add_argument('--window', type=int, default=32)
    p.add_argument('--no-early', action='store_true')


def parser():
    top = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = top.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('plan')
    p.add_argument('--manifest', required=True)
    p.add_argument('--object', required=True)
    p.add_argument('--prefixes', type=_prefixes, default=list(kl.PREFIX_TOKENS))
    p.add_argument('--ordinal', type=int, default=1)
    p.add_argument('--dst-frame0', type=int, default=0)
    add_geometry(p)
    p = sub.add_parser('prepare-nvme')
    p.add_argument('--manifest', required=True)
    p.add_argument('--device', required=True)
    p.add_argument('--i-understand-this-overwrites', action='store_true')
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('nvmeof-target')
    p.add_argument('action', choices=('up', 'down'))
    p.add_argument('--device', required=True)
    p.add_argument('--addr', required=True, help="host 1's thunderbolt0 IPv4 address")
    p.add_argument('--port', type=int, default=4420)
    p.add_argument('--nqn', required=True)
    p.add_argument('--port-id', type=int, default=1)
    p.add_argument('--configfs-root', default='/sys/kernel/config')
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('run')
    p.add_argument('--arm', required=True, choices=('xdev-ext', 'nvmeof', 'mooncake', 'custom'))
    p.add_argument('--manifest', required=True)
    p.add_argument('--object', required=True)
    p.add_argument('--prefixes', type=_prefixes, default=list(kl.PREFIX_TOKENS))
    p.add_argument('--repetitions', type=int, default=10)
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--first-ordinal', type=int, default=1)
    p.add_argument('--dst-frame0', type=int, default=0)
    p.add_argument('--host1-agent', required=True)
    p.add_argument('--token-file', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--idle-seconds', type=float, default=5.0)
    p.add_argument('--drop-caches-host1', action='store_true')
    p.add_argument('--drop-caches-host2', action='store_true')
    p.add_argument('--verify-every', action='store_true')
    p.add_argument('--perf', default='perf')
    p.add_argument('--perf-events', help='comma-separated events, e.g. amd_umc_0/.../ (verify at G0)')
    p.add_argument('--worker-argv', help='custom arm: JSON argv')
    p.add_argument('--worker-extra', default='[]', help='JSON list appended to the worker argv')
    p.add_argument('--worker-bin')
    p.add_argument('--gpu-bdf')
    p.add_argument('--gpu-node')
    p.add_argument('--pool-bytes', type=int)
    p.add_argument('--peer', help='xdev-ext: host 1 worker HOST:PORT')
    p.add_argument('--service')
    p.add_argument('--link-token')
    p.add_argument('--xdomain-prog')
    p.add_argument('--request-token', default='kv')
    p.add_argument('--device', help='nvmeof: the connected NVMe-oF namespace on host 2')
    p.add_argument('--local-hostname', help="mooncake: host 2's thunderbolt0 address")
    p.add_argument('--master', help="mooncake: host 1's thunderbolt0 address:50051")
    p.add_argument('--timeout-ms', type=int, default=120000)
    p.add_argument('--ready-timeout', type=float, default=600.0)
    p.add_argument('--run-timeout', type=float, default=600.0)
    p.add_argument('--agent-timeout', type=float, default=60.0)
    p.add_argument('--dry-run', action='store_true')
    add_geometry(p)
    p = sub.add_parser('recompute')
    p.add_argument('--command', required=True,
                   help='template with {model} and {prompt_tokens}; may print a JSON last line')
    p.add_argument('--model', required=True, choices=sorted(kl.MODELS))
    p.add_argument('--prefixes', type=_prefixes, default=list(kl.PREFIX_TOKENS))
    p.add_argument('--repetitions', type=int, default=10)
    p.add_argument('--timeout', type=float, default=3600.0)
    p.add_argument('--output', required=True)
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    if args.cmd == 'run' and args.arm == 'custom' and not args.worker_argv:
        raise SystemExit('--arm custom needs --worker-argv')
    return dict(plan=cmd_plan, **{'prepare-nvme': cmd_prepare_nvme,
                                  'nvmeof-target': cmd_nvmeof_target}, run=cmd_run,
                recompute=cmd_recompute)[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())

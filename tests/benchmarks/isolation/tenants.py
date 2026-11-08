#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""E8 multi-tenant runner: N tenants share one NVMe namespace on C CPUs.

  run        for every repetition and tenant count N: start N tenant
             processes, each restricted (sched_setaffinity) to the same C
             CPUs and given its own disjoint window of one prepared region;
             contract tenants print TENANT_READY, wait, and all receive GO
             together; one row per (repetition, N) in results.jsonl
  prepare    write the position-encoding payload over the region (uring
             tenant --write-pattern); overwrites it
  validate-guest  host-side check of a KVM functional run (guest/e8_kvm.sh):
             every tenant of every N reported, on the expected CPU set, with
             verified payload and a histogram covering every request
  summarize  per N: median, min and max over repetitions of the aggregate
             throughput (verified bytes only) and of the share of requests
             that took >= 1 ms

Arms (ordinary default configurations; none is tuned here):
  uring     uring_tenant: O_DIRECT 4 KiB random reads with READ_FIXED into
            registered host buffers, per-request latency (host destination,
            the plan's control (ii); the GPU io_uring arm is bench_uring_cuda)
  spdk      one spdk_nvme_perf process per tenant (-i shared shm group, one
            core each, -LL histogram); SPDK processes may not share cores, so
            N > C is refused in this multi-process shape
  xdev-ext  one session_nvme_ce process per tenant on its window; that
            program has a linear plan and whole-pass timing, so its tenants
            report no per-request latency (share: not measured)
  custom    --tenant-cmd: any program speaking the tenant contract

CPU control is affinity inside the running kernel: CPUs are never taken
offline here. Nothing in this directory interprets a VM or fixture run as a
performance result; run.json records performance_claim "none".
"""
import argparse
import json
import os
from pathlib import Path
import platform
import select
import statistics
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
MS_NS = 1_000_000


# ---- plan ------------------------------------------------------------------------

def tenant_counts(cores):
    """{1, C/2, C, C+1, 1.5C, 2C, 3C, 4C} (evaluation plan, E8)."""
    c = int(cores)
    want = [1, c // 2, c, c + 1, (3 * c) // 2, 2 * c, 3 * c, 4 * c]
    return sorted({n for n in want if n >= 1})


def parse_cpus(text):
    out = []
    for part in text.split(','):
        if not part:
            raise ValueError('empty CPU list item')
        if '-' in part:
            lo, hi = (int(v) for v in part.split('-', 1))
            if hi < lo:
                raise ValueError(f'descending range {part}')
            out.extend(range(lo, hi + 1))
        else:
            out.append(int(part))
    if not out or len(set(out)) != len(out) or min(out) < 0:
        raise ValueError(f'bad CPU list {text!r}')
    return out


def windows(region_offset, region_bytes, n, io_bytes):
    """n equal, disjoint, io-aligned windows filling the region from its start."""
    size = (region_bytes // n) // io_bytes * io_bytes
    if size < io_bytes or region_offset % io_bytes:
        raise ValueError(f'region of {region_bytes} bytes cannot hold {n} windows of {io_bytes}')
    return [(region_offset + i * size, size) for i in range(n)]


def order(counts, rep):
    return list(counts) if rep % 2 == 0 else list(reversed(counts))


# ---- tenant results ------------------------------------------------------------------

def parse_line(line):
    word, _, rest = line.strip().partition(' ')
    try:
        return word, json.loads(rest) if rest else {}
    except json.JSONDecodeError:
        return word, {'error': f'bad JSON: {rest[:200]}'}


def aggregate(results):
    """Sum of per-tenant verified rates; share of requests >= 1 ms."""
    ok = all('error' not in r and r.get('measured_ns') for r in results)
    out = dict(tenants=len(results), ok=ok, bytes_per_s=None, gb_per_s=None, ops=None,
               share_ge_1ms=None)
    if not ok:
        return out
    rate = sum(r['bytes_ok'] / (r['measured_ns'] / 1e9) for r in results)
    ops = sum(r['ops'] for r in results)
    out.update(bytes_per_s=rate, gb_per_s=rate / 1e9, ops=ops)
    if all(r.get('ge_1ms') is not None for r in results) and ops:
        out['share_ge_1ms'] = sum(r['ge_1ms'] for r in results) / ops
    return out


def parse_spdk_perf(text, io_bytes, seconds):
    """spdk_nvme_perf -LL: completions and >= 1 ms counts from its histogram."""
    out = dict(ops=None, bytes_ok=None, measured_ns=int(seconds * 1e9), ge_1ms=None,
               straddle_1ms=None, reported_iops=None)
    hist = False
    ops = ge = straddle = 0
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('Total') and ':' in s:
            try:
                out['reported_iops'] = float(s.split(':', 1)[1].split()[0])
            except (ValueError, IndexError):
                pass
        if s.startswith('Latency histogram'):
            hist = True
            continue
        if not hist or ' - ' not in s or '(' not in s:
            continue
        try:
            lo = float(s.split(' - ', 1)[0])
            hi = float(s.split(' - ', 1)[1].split(':', 1)[0])
            count = int(s.rsplit('(', 1)[1].rstrip(')').strip())
        except (ValueError, IndexError):
            continue
        ops += count
        if lo >= 1000.0:
            ge += count
        elif hi > 1000.0:
            straddle += count
    if hist and ops:
        out.update(ops=ops, bytes_ok=ops * io_bytes, ge_1ms=ge, straddle_1ms=straddle)
    elif not hist:
        out['error'] = 'no latency histogram (-LL) in the output'
    return out


def parse_session(text):
    for line in reversed(text.splitlines()):
        word, rec = line.strip(), None
        if word.startswith('{'):
            try:
                rec = json.loads(word)
            except json.JSONDecodeError:
                rec = None
        if rec and rec.get('arm') == 'session':
            if rec.get('status') != 'pass':
                return dict(error=f'session status {rec.get("status")}')
            return dict(ops=rec['operations'], bytes_ok=rec['verified_bytes'],
                        measured_ns=rec['io_ns'], ge_1ms=None, session=rec)
    return dict(error='no session record')


def spdk_commands(perf, traddr, cpus, n, depth, io_bytes, seconds, warmup, shm_id):
    """One spdk_nvme_perf per tenant, one core each, sharing one shm group."""
    if n > len(cpus):
        raise SystemExit(f'{n} SPDK processes on {len(cpus)} CPUs: SPDK processes may not '
                         'share cores (SPDK multi-process documentation); N > C needs the '
                         'single-process N-thread arm of the plan')
    return [[perf, '-q', str(depth), '-o', str(io_bytes), '-w', 'randread', '-t', str(seconds),
             '-a', str(warmup), '-LL', '-i', str(shm_id), '-c', hex(1 << cpus[t]),
             '-r', f'trtype:PCIe traddr:{traddr} ns:1'] for t in range(n)]


# ---- running ------------------------------------------------------------------------

def tenant_argv(args, t, n, window):
    off, size = window
    seed = args.seed + t
    if args.arm == 'custom':
        fields = dict(tenant=t, tenants=n, offset=off, window_bytes=size, depth=args.depth,
                      io_bytes=args.io_bytes, seconds=args.seconds, warmup=args.warmup, seed=seed,
                      region_offset=args.region_offset, device=args.device or '')
        return [str(a).format(**fields) for a in json.loads(args.tenant_cmd)]
    if args.arm == 'uring':
        argv = [args.tenant_bin or str(HERE / 'build/uring_tenant'), '--device', args.device,
                '--region-offset', args.region_offset, '--offset', off, '--bytes', size,
                '--io-bytes', args.io_bytes, '--depth', args.depth, '--seconds', args.seconds,
                '--warmup', args.warmup, '--seed', args.pattern_seed]
        if args.verify:
            argv.append('--verify')
        return [str(a) for a in argv]
    if args.arm == 'xdev-ext':
        argv = json.loads(args.session_cmd) + [
            '--slba', str(off // args.lba_bytes), '--window-bytes', str(size),
            '--size', str(args.io_bytes), '--qd', str(args.depth), '--passes', str(args.passes),
            '--pattern', 'seq', '--seed', str(args.pattern_seed)]
        return [str(a) for a in argv]
    raise SystemExit(f'no per-tenant argv for arm {args.arm}')


def contract(args):
    return args.arm in ('uring', 'custom')


def commands(args, n):
    if args.arm == 'spdk':
        return spdk_commands(args.spdk_perf, args.traddr, args.cpus, n, args.depth, args.io_bytes,
                             args.seconds, args.warmup, args.shm_id)
    w = windows(args.region_offset, args.region_bytes, n, args.io_bytes)
    return [tenant_argv(args, t, n, w[t]) for t in range(n)]


def proc_stat():
    with open('/proc/stat') as f:
        v = [int(x) for x in f.readline().split()[1:]]
    busy = sum(v[i] for i in (0, 1, 2, 5, 6, 7) if i < len(v))
    return busy, sum(v[:8])


def run_point(args, n, cmds):
    """Start n tenants, release them together, collect one result each."""
    procs = []
    for t, argv in enumerate(cmds):
        cpus = {args.cpus[t]} if args.arm == 'spdk' else set(args.cpus)
        procs.append(subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True,
                                      preexec_fn=lambda c=cpus: os.sched_setaffinity(0, c)))
    ready = [None] * n
    deadline = time.monotonic() + args.ready_timeout
    if contract(args):
        for t, p in enumerate(procs):
            while ready[t] is None:
                left = deadline - time.monotonic()
                r, _, _ = select.select([p.stdout], [], [], max(left, 0))
                line = p.stdout.readline() if r else ''
                if not line:
                    ready[t] = {'error': 'no TENANT_READY'}
                    break
                kind, body = parse_line(line)
                if kind == 'TENANT_READY':
                    ready[t] = body
    stat0 = proc_stat()
    t_go = time.monotonic_ns()
    if contract(args) and all('error' not in r for r in ready):
        for p in procs:
            p.stdin.write('GO\n')
            p.stdin.flush()
    results = []
    for t, p in enumerate(procs):
        try:
            out, err = p.communicate(timeout=args.seconds + args.warmup + args.run_timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
        res = None
        if args.arm == 'spdk':
            res = parse_spdk_perf(out, args.io_bytes, args.seconds)
        elif args.arm == 'xdev-ext':
            res = parse_session(out)
        else:
            for line in out.splitlines():
                kind, body = parse_line(line)
                if kind == 'TENANT_RESULT':
                    res = body
            res = res or {'error': 'no TENANT_RESULT'}
        if ready[t] is not None:
            res['ready'] = ready[t]
            if 'error' in ready[t]:
                res.setdefault('error', ready[t]['error'])
        if p.returncode:
            res.setdefault('error', f'exit {p.returncode}')
        res['stderr_tail'] = err[-1000:]
        res['argv'] = cmds[t]
        results.append(res)
    stat1 = proc_stat()
    hz = os.sysconf('SC_CLK_TCK')
    cpu = dict(busy_core_seconds=(stat1[0] - stat0[0]) / hz,
               wall_seconds=(time.monotonic_ns() - t_go) / 1e9,
               scope='whole machine /proc/stat cpu line, from GO to the last exit')
    return results, cpu


def check_cpus(cpus):
    allowed = os.sched_getaffinity(0)
    missing = [c for c in cpus if c not in allowed]
    if missing:
        raise SystemExit(f'CPUs {missing} are offline or outside this process; this runner '
                         'restricts tenants by affinity and never takes CPUs offline')


def new_output(path):
    p = Path(path)
    if p.exists() and (not p.is_dir() or any(p.iterdir())):
        raise SystemExit(f'output {p} exists and is not empty')
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    return p


def cmd_run(args):
    args.cpus = parse_cpus(args.cpus)
    check_cpus(args.cpus)
    counts = [int(v) for v in args.tenants.split(',')] if args.tenants else \
        tenant_counts(len(args.cpus))
    if args.arm in ('uring', 'spdk') and not (args.device or args.traddr):
        raise SystemExit(f'--arm {args.arm} needs --device (uring) or --traddr (spdk)')
    if args.arm == 'custom' and not args.tenant_cmd:
        raise SystemExit('--arm custom needs --tenant-cmd')
    if args.arm == 'xdev-ext' and not args.session_cmd:
        raise SystemExit('--arm xdev-ext needs --session-cmd (session_nvme_ce and its options)')
    if args.dry_run:
        print(json.dumps(dict(cpus=args.cpus, points=[dict(n=n, commands=commands(args, n))
                                                      for n in counts]), indent=2))
        return 0
    out = new_output(args.output)
    meta = dict(schema=1, kind='e8-multitenant', arm=args.arm, performance_claim='none',
                cpus=args.cpus, cores=len(args.cpus), cpu_control='affinity', tenants=counts,
                repetitions=args.repetitions, io_bytes=args.io_bytes, depth=args.depth,
                seconds=args.seconds, warmup=args.warmup, region_offset=args.region_offset,
                region_bytes=args.region_bytes, device=args.device, traddr=args.traddr,
                barrier='TENANT_READY/GO' if contract(args) else 'none (started together)',
                host=dict(node=platform.node(), release=platform.release()),
                started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    failures = 0
    with open(out / 'results.jsonl', 'w') as rows:
        for rep in range(args.repetitions):
            for n in order(counts, rep):
                cmds = commands(args, n)
                results, cpu = run_point(args, n, cmds)
                agg = aggregate(results)
                failures += not agg['ok']
                rows.write(json.dumps(dict(rep=rep, n=n, arm=args.arm, cores=len(args.cpus),
                                           aggregate=agg, cpu=cpu, tenant_results=results),
                                      sort_keys=True) + '\n')
                rows.flush()
    meta['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    meta['failed_points'] = failures
    (out / 'run.json').write_text(json.dumps(meta, indent=2, sort_keys=True) + '\n')
    return 1 if failures else 0


def cmd_prepare(args):
    argv = [args.tenant_bin or str(HERE / 'build/uring_tenant'), '--write-pattern',
            '--device', args.device, '--region-offset', str(args.region_offset),
            '--bytes', str(args.region_bytes), '--seed', str(args.pattern_seed)]
    if args.dry_run:
        print(json.dumps(argv))
        return 0
    if not args.i_understand_this_overwrites:
        raise SystemExit('prepare overwrites the region: pass --i-understand-this-overwrites')
    return subprocess.run(argv).returncode


def validate_guest(text, counts, cpus):
    """KVM functional check of uring_tenant xN under one CPU set (no timing claim)."""
    errors, tenants = [], {}
    if 'E8_GUEST_BEGIN' not in text or 'E8_GUEST_END' not in text:
        errors.append('guest begin/end markers missing')
    for line in text.splitlines():
        if not line.startswith('E8_GUEST n='):
            continue
        head, _, rest = line.partition(' TENANT_') if ' TENANT_' in line else (line, '', '')
        fields = dict(f.split('=', 1) for f in head.split()[1:3])
        key = (int(fields['n']), int(fields['t']))
        entry = tenants.setdefault(key, {})
        if rest:
            kind, body = parse_line('TENANT_' + rest)
            entry[kind] = body
        elif ' EXIT ' in line:
            entry['exit'] = int(line.rsplit(' ', 1)[1])
    points = []
    for n in counts:
        results = []
        for t in range(n):
            e = tenants.get((n, t), {})
            ready, res = e.get('TENANT_READY'), e.get('TENANT_RESULT')
            where = f'n={n} t={t}'
            if not ready or not res:
                errors.append(f'{where}: no READY/RESULT')
                continue
            if e.get('exit') != 0:
                errors.append(f'{where}: exit {e.get("exit")}')
            if ready.get('cpus') != cpus:
                errors.append(f'{where}: CPUs {ready.get("cpus")} != {cpus}')
            if not res.get('verify') or res.get('verify_fail') or res.get('errors'):
                errors.append(f'{where}: payload check failed or off')
            if not res.get('ops') or sum(res.get('hist_log2_us', [])) != res['ops']:
                errors.append(f'{where}: histogram does not cover every request')
            if res.get('bytes_ok') != res.get('ops', 0) * ready.get('io_bytes', 0):
                errors.append(f'{where}: unverified bytes counted')
            results.append(res)
        points.append(dict(n=n, aggregate=aggregate(results) if len(results) == n else None))
    return dict(schema=1, kind='e8-kvm-functional', performance_claim='none', cpus=cpus,
                counts=counts, verdict='FAIL' if errors else 'PASS', errors=errors, points=points)


def describe(values):
    if not values:
        return None
    return dict(median=statistics.median(values), min=min(values), max=max(values), n=len(values))


def summarize(dirs):
    points = {}
    arms = set()
    for d in dirs:
        meta = json.loads((Path(d) / 'run.json').read_text())
        arms.add(meta['arm'])
        for line in (Path(d) / 'results.jsonl').read_text().splitlines():
            r = json.loads(line)
            points.setdefault(r['n'], []).append(r)
    if len(arms) > 1:
        raise SystemExit(f'one summary per arm, got {sorted(arms)}')
    out = []
    for n, rows in sorted(points.items()):
        ok = [r['aggregate'] for r in rows if r['aggregate']['ok']]
        shares = [a['share_ge_1ms'] for a in ok if a['share_ge_1ms'] is not None]
        out.append(dict(n=n, repetitions=len(rows), failed=len(rows) - len(ok),
                        gb_per_s=describe([a['gb_per_s'] for a in ok]),
                        share_ge_1ms=describe(shares) if len(shares) == len(ok) else None,
                        busy_core_seconds=describe([r['cpu']['busy_core_seconds'] for r in rows])))
    return dict(schema=1, arm=arms.pop() if arms else None, points=out)


def parser():
    top = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = top.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('run')
    p.add_argument('--arm', required=True, choices=('uring', 'spdk', 'xdev-ext', 'custom'))
    p.add_argument('--cpus', required=True, help='the C CPUs every tenant is restricted to')
    p.add_argument('--tenants', help='comma-separated N; default {1, C/2, C, C+1, 1.5C, 2C, 3C, 4C}')
    p.add_argument('--device', help='uring: the NVMe namespace block device')
    p.add_argument('--traddr', help='spdk: PCIe address of the controller')
    p.add_argument('--region-offset', type=int, default=0)
    p.add_argument('--region-bytes', type=int, required=True)
    p.add_argument('--io-bytes', type=int, default=4096)
    p.add_argument('--depth', type=int, default=32, help='per-tenant closed-loop depth')
    p.add_argument('--seconds', type=float, default=30.0)
    p.add_argument('--warmup', type=float, default=5.0)
    p.add_argument('--repetitions', type=int, default=5)
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--pattern-seed', type=int, default=1)
    p.add_argument('--verify', action='store_true', help='uring: check every read payload')
    p.add_argument('--tenant-bin')
    p.add_argument('--tenant-cmd', help='custom: JSON argv template with {tenant} {offset} ...')
    p.add_argument('--spdk-perf', default='spdk_nvme_perf')
    p.add_argument('--shm-id', type=int, default=1)
    p.add_argument('--session-cmd', help='xdev-ext: JSON argv of session_nvme_ce up to its '
                                         'geometry options (device, programs, CE device)')
    p.add_argument('--lba-bytes', type=int, default=512)
    p.add_argument('--passes', type=int, default=1)
    p.add_argument('--ready-timeout', type=float, default=120.0)
    p.add_argument('--run-timeout', type=float, default=120.0)
    p.add_argument('--output', required=True)
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('prepare')
    p.add_argument('--device', required=True)
    p.add_argument('--region-offset', type=int, default=0)
    p.add_argument('--region-bytes', type=int, required=True)
    p.add_argument('--pattern-seed', type=int, default=1)
    p.add_argument('--tenant-bin')
    p.add_argument('--i-understand-this-overwrites', action='store_true')
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('validate-guest')
    p.add_argument('--log', required=True)
    p.add_argument('--counts', required=True, help='comma-separated N the guest ran')
    p.add_argument('--cpus', required=True)
    p.add_argument('--result', help='write the verdict JSON here')
    p = sub.add_parser('summarize')
    p.add_argument('dirs', nargs='+')
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    if args.cmd == 'validate-guest':
        r = validate_guest(Path(args.log).read_text(errors='replace'),
                           [int(v) for v in args.counts.split(',')], parse_cpus(args.cpus))
        text = json.dumps(r, indent=2, sort_keys=True) + '\n'
        if args.result:
            Path(args.result).write_text(text)
        print(text, end='')
        return 0 if r['verdict'] == 'PASS' else 1
    if args.cmd == 'summarize':
        print(json.dumps(summarize(args.dirs), indent=2, sort_keys=True))
        return 0
    return dict(run=cmd_run, prepare=cmd_prepare)[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())

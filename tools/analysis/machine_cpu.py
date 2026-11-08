#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Machine-wide host CPU of one harness run, minus an idle window.

    machine_cpu.py --arm NAME [--idle-s S] [--idle-after]
                   [--max-idle-drift-cores C] [--remote HOST:PORT
                   --remote-token-file F] [--out RECORD.json]
                   [--allow-vm] [--dry-run] -- HARNESS ARGV...

The CPU figure of the evaluation (plan section 3.0, used by E1, E5, E6 and
E8) is the aggregate "cpu" line of /proc/stat: busy = user + nice + system +
irq + softirq + steal, in USER_HZ ticks.  It counts every process of an arm,
kernel threads, kworkers, hard and soft interrupts and busy polling, which a
per-process or per-cgroup figure misses.  Parsing reuses kv_cpu.py.

One record per run:
  1. idle window: --idle-s seconds with nothing started (both hosts when
     --remote is given), giving the background rate idle_cores;
  2. run: the harness, bracketed by snapshots (and by BEGIN/END of the
     kv_cpu.py agent on the remote host);
  3. optional --idle-after window; the change of the idle rate between the
     two windows is idle_drift_cores, and a drift above
     --max-idle-drift-cores rejects the run (verdict idle_drift).
net_core_seconds = run busy core-seconds - idle_cores * run wall seconds;
net_cores = net_core_seconds / run wall seconds.  A run below the idle rate
is reported as a negative number (below_idle), never clamped.  The raw
ticks of every window are kept so the subtraction can be redone.

The tool tunes nothing and starts no load of its own.  It records whether
the running kernel was built with CONFIG_IRQ_TIME_ACCOUNTING (without it
irq/softirq time is sampled at the tick).  A virtual machine is refused
(exit 4) unless --allow-vm, and then the record says performance_claim
none: VM counters are correctness evidence only.

Exit status: 0 accounted, 1 harness failure or idle drift, 2 usage,
4 refused (hypervisor, missing /proc/stat or agent).
"""
import argparse
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

_KV = Path(__file__).resolve().parents[2] / 'tests/benchmarks/kv_restore/kv_cpu.py'
if not _KV.is_file():
    _KV = Path(__file__).resolve().parent.parent / 'kv_restore/kv_cpu.py'
_spec = importlib.util.spec_from_file_location('machine_cpu_kv_cpu', _KV)
KV_CPU = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(KV_CPU)

SCHEMA = 'xdev-eval-machine-cpu-v1'
BUSY_FORMULA = 'user+nice+system+irq+softirq+steal'


class Refused(RuntimeError):
    pass


def subtract_idle(idle, run):
    """Net machine CPU of @run after the background rate of @idle (kv_cpu deltas)."""
    idle_cores = idle['busy_core_seconds'] / idle['wall_seconds']
    background = idle_cores * run['wall_seconds']
    net = run['busy_core_seconds'] - background
    return dict(idle_cores=idle_cores, background_core_seconds=background,
                raw_core_seconds=run['busy_core_seconds'],
                raw_cores=run['busy_core_seconds'] / run['wall_seconds'],
                net_core_seconds=net, net_cores=net / run['wall_seconds'],
                below_idle=net < 0)


def idle_drift(before, after):
    """Absolute change of the idle rate, in cores, between two idle windows."""
    return abs(after['busy_core_seconds'] / after['wall_seconds'] -
               before['busy_core_seconds'] / before['wall_seconds'])


def hypervisor(root):
    if (root / 'sys/hypervisor/type').exists():
        return True
    try:
        cpuinfo = (root / 'proc/cpuinfo').read_text()
    except OSError:
        return False
    return any('hypervisor' in line.split()
               for line in cpuinfo.splitlines() if line.startswith('flags'))


def irq_time_accounting(root):
    """True/False from the running kernel's config, None when no config is readable."""
    release = os.uname().release
    for path in (root / 'proc/config.gz', root / f'boot/config-{release}'):
        try:
            text = (gzip.open(path, 'rt').read() if path.suffix == '.gz'
                    else path.read_text())
        except OSError:
            continue
        for line in text.splitlines():
            if line.strip() == 'CONFIG_IRQ_TIME_ACCOUNTING=y':
                return True
        return False
    return None


class Remote:
    def __init__(self, address, token_file):
        self.address = address
        token = Path(token_file).read_text().strip()
        self.client = KV_CPU.AgentClient(KV_CPU.parse_address(address), token)
        self.client.ping()

    def begin(self, run):
        self.client.begin(run)

    def end(self, run):
        reply = self.client.end(run)
        return {k: reply[k] for k in ('busy_ticks', 'hz', 'busy_core_seconds',
                                      'wall_seconds', 'cpus')}


def _window(args, proc, remote, tag, hook):
    """One idle window on this host and (bracketed by the agent) the remote one."""
    if remote:
        remote.begin(tag)
    a = KV_CPU.snapshot(proc)
    if hook:
        subprocess.run(shlex.split(hook), check=True)
    time.sleep(args.idle_s)
    b = KV_CPU.snapshot(proc)
    local = KV_CPU.delta(a, b)
    return local, remote.end(tag) if remote else None


def measure(args):
    proc, host = Path(args.proc_root), Path(args.host_root)
    vm = hypervisor(host)
    if vm and not args.allow_vm:
        raise Refused('hypervisor detected; VM counters are not performance evidence '
                      '(--allow-vm records a correctness-only run)')
    if not (proc / 'stat').is_file():
        raise Refused(f'{proc}/stat is not readable')
    remote = Remote(args.remote, args.remote_token_file) if args.remote else None
    tag = f'{args.arm}-{os.getpid()}-{time.monotonic_ns() % 10**9}'[:56]
    idle_l, idle_r = _window(args, proc, remote, tag + '-i0', None)
    if remote:
        remote.begin(tag + '-run')
    a = KV_CPU.snapshot(proc)
    start = time.monotonic_ns()
    result = subprocess.run(args.harness)
    b = KV_CPU.snapshot(proc)
    run_l = KV_CPU.delta(a, b)
    run_r = remote.end(tag + '-run') if remote else None
    local = dict(idle_before=idle_l, run=run_l, net=subtract_idle(idle_l, run_l))
    rem = None
    if remote:
        rem = dict(address=args.remote, idle_before=idle_r, run=run_r,
                   net=subtract_idle(idle_r, run_r))
    drift = 0.0
    if args.idle_after:
        after_l, after_r = _window(args, proc, remote, tag + '-i1', args.idle_after_hook)
        local['idle_after'] = after_l
        local['idle_drift_cores'] = idle_drift(idle_l, after_l)
        drift = local['idle_drift_cores']
        if rem:
            rem['idle_after'] = after_r
            rem['idle_drift_cores'] = idle_drift(idle_r, after_r)
            drift = max(drift, rem['idle_drift_cores'])
    if result.returncode:
        verdict = 'harness_failed'
    elif args.max_idle_drift_cores is not None and drift > args.max_idle_drift_cores:
        verdict = 'idle_drift'
    else:
        verdict = 'ok'
    return dict(schema=SCHEMA, arm=args.arm, verdict=verdict,
                execution='vm' if vm else 'bare-metal',
                performance_claim='none' if vm else 'machine-wide-host-cpu',
                busy_formula=BUSY_FORMULA, irq_time_accounting=irq_time_accounting(host),
                idle_s=args.idle_s, max_idle_drift_cores=args.max_idle_drift_cores,
                clock='CLOCK_MONOTONIC', harness=dict(argv=args.harness,
                                                      exit=result.returncode,
                                                      start_mono_ns=start),
                local=local, remote=rem)


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--arm', required=True)
    p.add_argument('--idle-s', type=float, default=10.0)
    p.add_argument('--idle-after', action='store_true')
    p.add_argument('--max-idle-drift-cores', type=float)
    p.add_argument('--remote')
    p.add_argument('--remote-token-file')
    p.add_argument('--proc-root', default='/proc')
    p.add_argument('--host-root', default='/')
    p.add_argument('--idle-after-hook', help=argparse.SUPPRESS)	# test fixture: background load
    p.add_argument('--out')
    p.add_argument('--allow-vm', action='store_true')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('harness', nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    if args.harness[:1] == ['--']:
        args.harness = args.harness[1:]
    if not args.harness:
        p.error('the harness command follows --')
    if args.idle_s <= 0:
        p.error('--idle-s must be positive')
    if bool(args.remote) != bool(args.remote_token_file):
        p.error('--remote and --remote-token-file go together')
    return args


def main(argv=None):
    args = parse(argv)
    if args.dry_run:
        print(json.dumps(dict(dry_run=True, arm=args.arm, idle_s=args.idle_s,
                              idle_after=args.idle_after, remote=args.remote,
                              harness=args.harness)))
        return 0
    try:
        record = measure(args)
    except (Refused, KV_CPU.CpuError, OSError) as error:
        print(f'machine_cpu: refused: {error}', file=sys.stderr)
        return 4
    text = json.dumps(record, indent=1, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + '\n')
    else:
        print(text)
    return 0 if record['verdict'] == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())

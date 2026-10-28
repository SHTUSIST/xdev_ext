#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""CPU, DRAM and PCIe accounting around one evaluation arm.

    cpu_account.py --arm NAME (--payload-bytes N | --payload-json-key KEY)
                   [--elapsed-json-key KEY] [--min-wall-s S]
                   [--poller-cpus LIST] [--kthread-comm REGEX ...]
                   [--uncore [--imc-event READ --imc-event WRITE]]
                   [--pcie-event EVT ...]
                   [--target-rate BYTES_PER_S [--rate-flag=FLAG | --rate-env VAR]]
                   [--out RECEIPT.json] [--dry-run] -- HARNESS ARGV...

The harness runs in its own cgroup v2 (xdev_eval/NAME-PID).  An inner perf
stat counts cycles, user and kernel cycles, instructions and task-clock per
CPU for that cgroup only.  Kernel threads never belong to that cgroup: the
session worker (kthread_run_worker "xdev_ext_mech/%llu" in
io_uring/xdev_ext_mech.c) and every kthread a provider creates live in the
root cgroup.  Their runtime is therefore sampled from /proc/<pid>/schedstat
(or stat utime+stime) for every task whose comm matches --kthread-comm, and
added to the arm.  An outer system-wide perf stat counts cycles and kernel
cycles of the whole machine, and /proc/stat gives the system-wide busy,
hardirq and softirq time of the same interval, so the work no attribution
reaches (shared workqueue kworkers, interrupts, other tenants) is reported
beside the arm.  With --uncore the outer perf stat also counts the
memory-controller reads/writes and any --pcie-event, so DRAM and PCIe bytes
can be divided by the payload bytes the harness moved.

A CPU listed in --poller-cpus is charged as one full core for the whole run,
whatever its measured busy time: a pinned polling core is unavailable to
other work even when it spins idle.  A matched kthread whose affinity lies
inside the poller CPUs is not charged again.

Equal-throughput comparisons: --target-rate passes a byte rate to the
harness, as FLAG VALUE appended to its argv (--rate-flag) or as an
environment variable (--rate-env), and checks the achieved payload rate
against it.  The rate uses the harness's own timed span (--elapsed-json-key)
when it prints one, otherwise the outer wall time, which also contains perf
and shell startup and teardown.  A run outside --rate-tolerance is reported
as rate_mismatch, and a run shorter than --min-wall-s as too_short, both
with exit 1, so neither can enter a figure by accident.

Exit status: 0 accounted, 1 harness failure, rate mismatch or too short,
2 usage error, 4 refused: hypervisor, no cgroup v2, missing perf/PMU events
or privilege.  Virtual machines are refused because their counters are not
used as performance evidence.  --dry-run prints the exact commands without
running.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

SCHEMA = 'xdev-eval-cpu-account-v2'
SEP = ';'
CORE_EVENTS = ['cycles', 'cycles:u', 'cycles:k', 'instructions', 'task-clock']
# Outer, system-wide: no -G.  task-clock is not used system-wide (under -a
# it runs on idle CPUs too); /proc/stat gives the busy time instead.
SYSTEM_EVENTS = ['cycles', 'cycles:k']
IMC_EVENTS = ['uncore_imc/cas_count_read/', 'uncore_imc/cas_count_write/']
CAS_BYTES = 64	# one cache line per CAS command
DEFAULT_KTHREAD_COMM = r'xdev_ext_mech/\d+'
# $0 is a label, $1 the cgroup directory; the workload enters it, then execs.
JOIN_SCRIPT = 'echo $$ > "$1/cgroup.procs" && shift && exec "$@"'
BYTE_UNITS = {'B': 1, 'Bytes': 1, 'KiB': 2**10, 'MiB': 2**20, 'GiB': 2**30}
TIME_UNITS = {'msec': 1e-3, 'usec': 1e-6, 'nsec': 1e-9, 'ns': 1e-9, 'sec': 1.0}
NOT_COUNTED = ('<not counted>', '<not supported>')
# /proc/stat per-CPU fields (fs/proc/stat.c):
# user nice system idle iowait irq softirq steal guest guest_nice
IRQ_FIELD, SOFTIRQ_FIELD = 5, 6
BUSY_FIELDS = (0, 1, 2, 5, 6, 7)	# guest time is already inside user
ATTRIBUTION = dict(
    cycles='cgroup only: cycles, user/kernel cycles and instructions count arm tasks '
           '(including io_uring io-wq/SQPOLL threads, which stay in the cgroup); '
           'kthread cycles are not counted, see system_cycles',
    cores_charged='cgroup task-clock on non-poller CPUs + one core per poller CPU + '
                  'runtime of matched kthreads not confined to poller CPUs',
    system_only='shared workqueue kworkers (system_unbound_wq work of the CE progress '
                'poll, peer NET and session reap), hardirq and softirq time, and other '
                'tenants appear only in the system_* figures and unattributed_busy_cores; '
                'interrupt time that hit an arm task or kthread may be in both',
)


class ParseError(ValueError):
    pass


class Refused(Exception):
    pass


def cpu_list(text):
    """'0-2,5' -> [0, 1, 2, 5]; empty -> []."""
    result = []
    if not text:
        return result
    for part in text.split(','):
        m = re.fullmatch(r'(\d+)(?:-(\d+))?', part)
        if not m:
            raise ValueError('bad CPU list element: %r' % part)
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if hi < lo:
            raise ValueError('descending CPU range: %r' % part)
        result.extend(range(lo, hi + 1))
    return sorted(set(result))


def normalize_event(name):
    """Drop a PMU instance suffix: uncore_imc_3/x/ -> uncore_imc/x/."""
    name = name.strip()
    if '/' not in name:
        return name
    pmu, rest = name.split('/', 1)
    pmu = re.sub(r'_\d+$', '', pmu)
    return pmu + '/' + rest.rstrip('/') + '/'


def parse_perf_csv(text, events, cgroups=None):
    """Rows of perf stat -x';' output, optionally per CPU (-A) and cgroup (-G).

    Field order (tools/perf/util/stat-display.c): [CPUn;] value; unit; event;
    [cgroup;] run time; running %; metric.  Every row must name one of
    @events, and with @cgroups one of those cgroups; anything else means the
    output is not what was asked for.
    """
    wanted = {normalize_event(e): e for e in events}
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split(SEP)
        cpu = None
        m = re.fullmatch(r'CPU(\d+)', fields[0])
        if m:
            cpu = int(m.group(1))
            fields = fields[1:]
        if len(fields) < 3:
            raise ParseError('short perf row: %r' % line)
        raw, unit, printed = fields[0].strip(), fields[1].strip(), fields[2].strip()
        event = wanted.get(normalize_event(printed))
        if event is None:
            raise ParseError('unrequested event %r' % printed)
        cgroup = None
        if cgroups is not None:
            if len(fields) < 4 or fields[3] not in cgroups:
                raise ParseError('row outside the requested cgroups: %r' % line)
            cgroup = fields[3]
        if raw in NOT_COUNTED:
            value = None
        else:
            try:
                value = float(raw)
            except ValueError:
                raise ParseError('bad counter value %r' % raw) from None
        rows.append(dict(cpu=cpu, value=value, unit=unit, event=event,
                         printed=printed, cgroup=cgroup))
    return rows


def aggregate(rows):
    """Per requested event: total, per-CPU values, unit, uncounted CPUs."""
    out = {}
    for r in rows:
        e = out.setdefault(r['event'], dict(event=r['event'], total=None, per_cpu={},
                                            unit='', not_counted_cpus=[], rows=0))
        e['rows'] += 1
        if r['unit'] and not e['unit']:
            e['unit'] = r['unit']
        if r['value'] is None:
            if r['cpu'] is not None:
                e['not_counted_cpus'].append(r['cpu'])
            continue
        e['total'] = (e['total'] or 0.0) + r['value']
        if r['cpu'] is not None:
            e['per_cpu'][r['cpu']] = e['per_cpu'].get(r['cpu'], 0.0) + r['value']
    for e in out.values():
        e['not_counted_cpus'].sort()
    return out


def event_bytes(entry, count_bytes=None):
    """Bytes of an uncore event, or None when its unit is not a byte unit.

    A unitless count is converted only with @count_bytes (the IMC role) or
    when it is a CAS count, one 64-byte line each.
    """
    if entry is None or entry['total'] is None:
        return None
    if entry['unit'] in BYTE_UNITS:
        return entry['total'] * BYTE_UNITS[entry['unit']]
    if entry['unit']:
        return None
    if count_bytes is not None:
        return entry['total'] * count_bytes
    if re.search(r'/cas_count_(read|write)/$', normalize_event(entry['event'])):
        return entry['total'] * CAS_BYTES
    return None


def parse_proc_stat(text):
    cpus = {}
    for line in text.splitlines():
        m = re.match(r'cpu(\d+)\s+(.*)', line)
        if m:
            cpus[int(m.group(1))] = [int(x) for x in m.group(2).split()]
    if not cpus:
        raise ParseError('no per-CPU lines in /proc/stat')
    return cpus


def _stat_delta(before, after, hz, fields):
    per_cpu = {cpu: sum(after[cpu][f] - before[cpu][f] for f in fields) / hz
               for cpu in sorted(set(before) & set(after))}
    return dict(total=sum(per_cpu.values()), per_cpu=per_cpu)


def proc_stat_seconds(before, after, hz):
    """System-wide hardirq, softirq and busy seconds between two snapshots."""
    return dict(irq=_stat_delta(before, after, hz, (IRQ_FIELD,)),
                softirq=_stat_delta(before, after, hz, (SOFTIRQ_FIELD,)),
                busy=_stat_delta(before, after, hz, BUSY_FIELDS))


def softirq_seconds(before, after, hz):
    return _stat_delta(before, after, hz, (SOFTIRQ_FIELD,))


# --- kernel threads outside the cgroup ----------------------------------

def _read(path):
    try:
        return path.read_text()
    except OSError:
        return None


def scan_threads(root, patterns, arm_cgroup, hz):
    """Tasks whose comm fully matches one of @patterns, outside @arm_cgroup.

    Returns {(pid, starttime): dict(pid, comm, runtime_ns, source, cpus)}.
    Kernel threads are their own thread-group leaders, so /proc/<pid> is
    enough.  runtime_ns is se.sum_exec_runtime from schedstat
    (fs/proc/base.c), or stat utime+stime ticks when schedstat is absent.
    """
    regex = [re.compile(p) for p in patterns]
    found = {}
    try:
        entries = [d for d in (root / 'proc').iterdir() if d.name.isdigit()]
    except OSError:
        return found
    for d in entries:
        comm = _read(d / 'comm')
        if comm is None or not any(r.fullmatch(comm.strip()) for r in regex):
            continue
        cgroup = _read(d / 'cgroup') or ''
        if arm_cgroup and any(line.endswith('/' + arm_cgroup) for line in cgroup.split()):
            continue	# already counted by perf -G
        stat = _read(d / 'stat')
        if stat is None or ')' not in stat:
            continue
        # After "pid (comm)" the first field is field 3 (state), so utime and
        # stime (fields 14, 15) are rest[11:13] and starttime (22) rest[19].
        rest = stat.rsplit(')', 1)[1].split()
        try:
            ticks = int(rest[11]) + int(rest[12])
            start = int(rest[19])
        except (IndexError, ValueError):
            continue
        sched = (_read(d / 'schedstat') or '').split()
        if sched and sched[0].isdigit() and sched != ['0', '0', '0']:
            runtime, source = int(sched[0]), 'schedstat'
        else:
            runtime, source = ticks * 10**9 // hz, 'stat_ticks'
        m = re.search(r'^Cpus_allowed_list:\s*(\S+)', _read(d / 'status') or '', re.M)
        try:
            cpus = cpu_list(m.group(1)) if m else []
        except ValueError:
            cpus = []
        found[(int(d.name), start)] = dict(pid=int(d.name), comm=comm.strip(),
                                           runtime_ns=runtime, source=source, cpus=cpus)
    return found


class KthreadTracker:
    """Runtime of matched kthreads during the run, from repeated snapshots.

    A thread present in the start snapshot is charged from its start value;
    one born during the run (session CREATE starts the worker) from zero.
    A thread that exits between two samples keeps its last observed value:
    it may have run at most one interval more, reported as tail_bound_s.
    """

    def __init__(self, start, interval_s):
        self.start = {k: v['runtime_ns'] for k, v in start.items()}
        self.interval_s = interval_s
        self.last = {}
        self.present = set()

    def observe(self, snapshot):
        for key, t in snapshot.items():
            self.last[key] = t
        self.present = set(snapshot)

    def summary(self, pollers):
        pollers = set(pollers)
        threads, charged, on_poller, exited = [], 0.0, 0.0, 0
        for key, t in sorted(self.last.items()):
            runtime = (t['runtime_ns'] - self.start.get(key, 0)) / 1e9
            pinned = bool(t['cpus']) and set(t['cpus']) <= pollers
            gone = key not in self.present
            exited += gone
            threads.append(dict(pid=t['pid'], comm=t['comm'], runtime_s=runtime,
                                source=t['source'], cpus=t['cpus'], on_poller=pinned,
                                born_during_run=key not in self.start, exited=gone))
            if pinned:
                on_poller += runtime
            else:
                charged += runtime
        return dict(threads=threads, charged_s=charged, on_poller_s=on_poller,
                    exited_threads=exited, sample_interval_s=self.interval_s,
                    tail_bound_s=exited * self.interval_s)


class Sampler(threading.Thread):
    """Samples the matched kthreads every interval while the harness runs."""

    def __init__(self, root, patterns, cgroup, hz, tracker):
        super().__init__(daemon=True)
        self.scan = (root, patterns, cgroup, hz)
        self.tracker = tracker
        self.done = threading.Event()

    def run(self):
        while not self.done.wait(self.tracker.interval_s):
            self.tracker.observe(scan_threads(*self.scan))

    def stop(self):
        self.done.set()
        self.join()
        self.tracker.observe(scan_threads(*self.scan))


# --- arithmetic ---------------------------------------------------------

def _total(core, name):
    e = core.get(name) if core else None
    return None if e is None else e['total']


def _per(value, payload):
    return None if value is None else value / payload


def _seconds(entry, value):
    return value * TIME_UNITS.get(entry['unit'] or 'msec', 1e-3)


def account(core, uncore, times, wall_s, payload_bytes, poller_cpus, system=None,
            kthreads=None, imc=IMC_EVENTS, imc_count_bytes=CAS_BYTES):
    """Per-arm and system-wide figures; @wall_s is the counting window."""
    if wall_s <= 0 or payload_bytes <= 0:
        raise ValueError('wall time and payload bytes must be positive')
    cycles = _total(core, 'cycles')
    user = _total(core, 'cycles:u')
    kernel = _total(core, 'cycles:k')
    instructions = _total(core, 'instructions')
    clock = core['task-clock']
    pollers = sorted(set(poller_cpus))
    task_s = _seconds(clock, clock['total'] or 0.0)
    other_s = sum(_seconds(clock, v) for cpu, v in clock['per_cpu'].items()
                  if cpu not in pollers)
    kthread_s = kthreads['charged_s'] if kthreads else 0.0
    kthread_poller_s = kthreads['on_poller_s'] if kthreads else 0.0
    charged = other_s / wall_s + len(pollers) + kthread_s / wall_s
    sys_cycles = _total(system, 'cycles')
    busy = times['busy']['total'] / wall_s
    r = dict(
        wall_s=wall_s, payload_bytes=payload_bytes,
        cycles=cycles, user_cycles=user, kernel_cycles=kernel, instructions=instructions,
        ipc=None if not cycles or instructions is None else instructions / cycles,
        cycles_per_payload_byte=_per(cycles, payload_bytes),
        user_cycles_per_payload_byte=_per(user, payload_bytes),
        kernel_cycles_per_payload_byte=_per(kernel, payload_bytes),
        task_clock_s=task_s,
        cores_measured=task_s / wall_s,
        poller_cpus=pollers, poller_cores=len(pollers),
        kthread_s=kthread_s, kthread_cores=kthread_s / wall_s, kthread_cycles=None,
        kthreads=kthreads,
        cores_charged=charged,
        core_seconds_charged_per_GB=charged * wall_s / (payload_bytes / 1e9),
        system_cycles=sys_cycles, system_kernel_cycles=_total(system, 'cycles:k'),
        system_cycles_per_payload_byte=_per(sys_cycles, payload_bytes),
        system_busy_cores=busy,
        unattributed_busy_cores=busy - (task_s + kthread_s + kthread_poller_s) / wall_s,
        hardirq_s_system=times['irq']['total'],
        hardirq_cores_system=times['irq']['total'] / wall_s,
        softirq_s_system=times['softirq']['total'],
        softirq_cores_system=times['softirq']['total'] / wall_s,
        not_counted_cpus=sorted({c for e in core.values() for c in e['not_counted_cpus']}),
        attribution=ATTRIBUTION,
        dram_read_bytes=None, dram_write_bytes=None, dram_bytes_per_payload_byte=None,
        imc_events=list(imc), uncore_other={})
    if uncore:
        read = event_bytes(uncore.get(imc[0]), imc_count_bytes)
        write = event_bytes(uncore.get(imc[1]), imc_count_bytes)
        r['dram_read_bytes'], r['dram_write_bytes'] = read, write
        if read is not None and write is not None:
            r['dram_bytes_per_payload_byte'] = (read + write) / payload_bytes
        for name, e in uncore.items():
            if name in imc:
                continue
            b = event_bytes(e)
            r['uncore_other'][name] = dict(value=e['total'], unit=e['unit'], bytes=b,
                                           bytes_per_payload_byte=_per(b, payload_bytes))
    return r


def walls(outer_wall_s, harness_elapsed_s, min_wall_s):
    """Counting window and rate denominator.

    perf counts from its own start to the child's exit, so the outer wall
    time is the window of every counter (slightly longer: it also holds perf
    and shell startup and teardown, which perf -x does not print).  The rate
    uses the harness's own timed span when it prints one.
    """
    rate = harness_elapsed_s if harness_elapsed_s else outer_wall_s
    return dict(counting_wall_s=outer_wall_s, rate_wall_s=rate,
                rate_wall_source='harness' if harness_elapsed_s else 'outer',
                short_run=outer_wall_s < min_wall_s)


def rate_check(payload_bytes, wall_s, target, tolerance):
    if target is None:
        return None
    achieved = payload_bytes / wall_s
    error = abs(achieved - target) / target
    return dict(target_bytes_per_s=target, achieved_bytes_per_s=achieved,
                relative_error=error, matched=error <= tolerance)


def json_from_output(text, key):
    """Value at dotted @key of the last JSON object line of the harness."""
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        for part in key.split('.'):
            if not isinstance(value, dict) or part not in value:
                raise ParseError('harness JSON has no %s' % key)
            value = value[part]
        return value
    raise ParseError('harness printed no JSON object line')


def number_from_output(text, key):
    """Positive number at dotted @key (the harness's timed span in seconds)."""
    value = json_from_output(text, key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ParseError('%s is not a positive number' % key)
    return float(value)


def payload_from_output(text, key):
    """Integer at dotted @key of the last JSON object line of the harness."""
    value = json_from_output(text, key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or \
            value < 0 or int(value) != value:
        raise ParseError('%s is not a byte count' % key)
    return int(value)


# --- host gates ---------------------------------------------------------

def hypervisor(root):
    if (root / 'sys/hypervisor/type').exists():
        return True
    try:
        cpuinfo = (root / 'proc/cpuinfo').read_text()
    except OSError:
        return False
    return any('hypervisor' in line.split()
               for line in cpuinfo.splitlines() if line.startswith('flags'))


def pmu_has(root, event):
    """An uncore event names an observed PMU and, if symbolic, its sysfs event."""
    if '/' not in event:
        return True
    pmu, rest = event.split('/', 1)
    term = rest.rstrip('/')
    devices = root / 'sys/bus/event_source/devices'
    try:
        names = [d for d in devices.iterdir() if d.name == pmu or
                 re.fullmatch(re.escape(pmu) + r'_\d+', d.name)]
    except OSError:
        return False
    if not names:
        return False
    if '=' in term:
        return True
    return any((d / 'events' / term).exists() for d in names)


def gate(args, root):
    if not args.dry_run and hypervisor(root):
        raise Refused('hypervisor detected; VM counters are not performance evidence')
    cgroot = root / 'sys/fs/cgroup'
    if not (cgroot / 'cgroup.controllers').is_file():
        raise Refused('cgroup v2 is not mounted at /sys/fs/cgroup')
    for event in args.uncore_events:
        if not pmu_has(root, event):
            raise Refused('uncore event %s has no observed PMU/sysfs event '
                          '(for example .../events/cas_count_read)' % event)
    if args.dry_run:
        return
    if not os.access(cgroot, os.W_OK):
        raise Refused('no write access to the cgroup v2 root')
    if not args.perf_path:
        raise Refused('perf is not installed')


# --- plan and run -------------------------------------------------------

def plan(args, root, work):
    name = '%s-%d' % (args.arm, os.getpid())
    cgroup = 'xdev_eval/' + name
    cgdir = root / 'sys/fs/cgroup' / cgroup
    harness = list(args.cmd)
    if args.rate_flag:
        harness += [args.rate_flag, '%.0f' % args.target_rate]
    core_out = str(work / 'core.csv')
    system_out = str(work / 'system.csv')
    perf = args.perf_path or args.perf
    inner = [perf, 'stat', '-a', '-A', '-x', SEP, '-o', core_out,
             '-e', ','.join(CORE_EVENTS), '-G', ','.join([cgroup] * len(CORE_EVENTS)),
             '--', '/bin/sh', '-c', JOIN_SCRIPT, 'xdev-eval-join', str(cgdir)] + harness
    argv = [perf, 'stat', '-a', '-A', '-x', SEP, '-o', system_out,
            '-e', ','.join(SYSTEM_EVENTS + args.uncore_events), '--'] + inner
    return dict(schema=SCHEMA, arm=args.arm, cgroup=cgroup, cgroup_dir=str(cgdir),
                argv=argv, harness=harness, core_output=core_out, system_output=system_out,
                core_events=CORE_EVENTS, system_events=SYSTEM_EVENTS,
                uncore_events=args.uncore_events, imc_events=args.imc,
                poller_cpus=args.pollers, kthread_comm=args.kthread_comm,
                kthread_interval_s=args.kthread_interval, target_rate=args.target_rate,
                rate_env=args.rate_env, min_wall_s=args.min_wall_s)


def execute(args, root, p):
    cgdir = Path(p['cgroup_dir'])
    cgdir.parent.mkdir(exist_ok=True)
    cgdir.mkdir()
    env = dict(os.environ)
    if args.rate_env:
        env[args.rate_env] = '%.0f' % args.target_rate
    hz = os.sysconf('SC_CLK_TCK')
    scan = (root, args.kthread_comm, p['cgroup'], hz)
    try:
        tracker = KthreadTracker(scan_threads(*scan), args.kthread_interval)
        sampler = Sampler(*scan, tracker)
        before = parse_proc_stat((root / 'proc/stat').read_text())
        start = time.monotonic()
        sampler.start()
        try:
            done = subprocess.run(p['argv'], stdout=subprocess.PIPE, env=env, text=True)
        finally:
            wall = time.monotonic() - start
            sampler.stop()
        after = parse_proc_stat((root / 'proc/stat').read_text())
    finally:
        try:
            cgdir.rmdir()
        except OSError:
            pass
    sys.stderr.write(done.stdout)
    if args.harness_stdout:
        Path(args.harness_stdout).write_text(done.stdout)
    receipt = dict(p, exit_status=done.returncode, wall_s=wall)
    if done.returncode:
        receipt['status'] = 'harness_failed'
        return receipt, 1
    payload = args.payload_bytes if args.payload_bytes is not None else \
        payload_from_output(done.stdout, args.payload_json_key)
    elapsed = number_from_output(done.stdout, args.elapsed_json_key) \
        if args.elapsed_json_key else None
    w = walls(wall, elapsed, args.min_wall_s)
    core = aggregate(parse_perf_csv(Path(p['core_output']).read_text(), CORE_EVENTS,
                                    cgroups=[p['cgroup']]))
    outer = parse_perf_csv(Path(p['system_output']).read_text(),
                           SYSTEM_EVENTS + args.uncore_events)
    system = aggregate([r for r in outer if r['event'] in SYSTEM_EVENTS])
    uncore = aggregate([r for r in outer if r['event'] not in SYSTEM_EVENTS]) \
        if args.uncore_events else None
    receipt['walls'] = w
    receipt['account'] = account(core, uncore, proc_stat_seconds(before, after, hz),
                                 wall, payload, args.pollers, system=system,
                                 kthreads=tracker.summary(args.pollers), imc=args.imc,
                                 imc_count_bytes=args.imc_count_bytes)
    receipt['rate'] = rate_check(payload, w['rate_wall_s'], args.target_rate,
                                 args.rate_tolerance)
    if receipt['rate']:
        receipt['rate']['rate_wall_source'] = w['rate_wall_source']
    if w['short_run']:
        receipt['status'] = 'too_short'
    elif receipt['rate'] and not receipt['rate']['matched']:
        receipt['status'] = 'rate_mismatch'
    else:
        receipt['status'] = 'accounted'
    return receipt, 0 if receipt['status'] == 'accounted' else 1


def parse_args(argv):
    if '--' not in argv:
        argv = argv + ['--']
    split = argv.index('--')
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--arm', required=True)
    payload = parser.add_mutually_exclusive_group(required=True)
    payload.add_argument('--payload-bytes', type=int)
    payload.add_argument('--payload-json-key')
    parser.add_argument('--elapsed-json-key',
                        help='harness JSON key of its timed span in seconds (rate)')
    parser.add_argument('--min-wall-s', type=float, default=10.0,
                        help='shorter runs are too_short (startup bias); 0 disables')
    parser.add_argument('--poller-cpus', default='')
    parser.add_argument('--kthread-comm', action='append', default=None,
                        help='comm regex of kthreads charged to the arm '
                             '(default %s)' % DEFAULT_KTHREAD_COMM)
    parser.add_argument('--kthread-interval', type=float, default=0.1)
    parser.add_argument('--uncore', action='store_true')
    parser.add_argument('--imc-event', action='append', default=None,
                        help='twice: the DRAM read event, then the write event')
    parser.add_argument('--imc-count-bytes', type=int, default=CAS_BYTES,
                        help='bytes per unitless IMC count')
    parser.add_argument('--pcie-event', action='append', default=[])
    parser.add_argument('--target-rate', type=float)
    parser.add_argument('--rate-flag')
    parser.add_argument('--rate-env')
    parser.add_argument('--rate-tolerance', type=float, default=0.05)
    parser.add_argument('--perf', default='perf')
    parser.add_argument('--host-root', default='/', help='filesystem root (tests)')
    parser.add_argument('--out')
    parser.add_argument('--harness-stdout')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv[:split])
    args.cmd = argv[split + 1:]
    if not args.cmd:
        parser.error('a harness command is required after --')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.arm):
        parser.error('--arm must be [A-Za-z0-9_.-]+')
    if (args.rate_flag or args.rate_env) and args.target_rate is None:
        parser.error('--rate-flag/--rate-env require --target-rate')
    if args.target_rate is not None and args.target_rate <= 0:
        parser.error('--target-rate must be positive')
    if args.payload_bytes is not None and args.payload_bytes <= 0:
        parser.error('--payload-bytes must be positive')
    if args.min_wall_s < 0 or args.kthread_interval <= 0 or args.imc_count_bytes <= 0:
        parser.error('--min-wall-s, --kthread-interval or --imc-count-bytes out of range')
    try:
        args.pollers = cpu_list(args.poller_cpus)
    except ValueError as e:
        parser.error(str(e))
    args.kthread_comm = args.kthread_comm or [DEFAULT_KTHREAD_COMM]
    for pattern in args.kthread_comm:
        try:
            re.compile(pattern)
        except re.error as e:
            parser.error('--kthread-comm %r: %s' % (pattern, e))
    if args.imc_event and (len(args.imc_event) != 2 or not args.uncore):
        parser.error('--imc-event is given twice with --uncore: the read event, '
                     'then the write event')
    args.imc = args.imc_event or IMC_EVENTS
    imc = args.imc if args.uncore else []
    args.uncore_events = (imc + args.pcie_event) if (args.uncore or args.pcie_event) else []
    args.perf_path = shutil.which(args.perf)
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.host_root)
    try:
        gate(args, root)
    except Refused as e:
        print('not_run: ' + str(e), file=sys.stderr)
        return 4
    if args.dry_run:
        work = Path(tempfile.gettempdir()) / ('xdev-cpu-account-%d' % os.getpid())
        print(json.dumps(plan(args, root, work), indent=1))
        return 0
    with tempfile.TemporaryDirectory(prefix='xdev-cpu-account-') as work:
        receipt, code = execute(args, root, plan(args, root, Path(work)))
    text = json.dumps(receipt, indent=1, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + '\n')
    print(text)
    return code


if __name__ == '__main__':
    sys.exit(main())

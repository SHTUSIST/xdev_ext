#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Parser and arithmetic of cpu_account.py against fixed perf/proc text.

No counter is opened and no workload runs: the fixtures are perf stat -x';'
outputs of the shapes cpu_account.py requests, and /proc/stat snapshots.
"""
import importlib.util
import io
import json
from pathlib import Path
import contextlib
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cpu_account', HERE / 'cpu_account.py')
ca = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ca)

CG = 'xdev_eval/arm-a'

# perf stat -a -A -x';' -e cycles,cycles:u,cycles:k,instructions,task-clock -G CG x5
CORE = f"""# started on Thu Oct 22 10:00:00 2026

CPU0;1000000000;;cycles;{CG};2000000000;100.00;;
CPU1;1000000000;;cycles;{CG};2000000000;100.00;;
CPU3;1000000000;;cycles;{CG};2000000000;100.00;;
CPU0;400000000;;cycles:u;{CG};2000000000;100.00;;
CPU1;400000000;;cycles:u;{CG};2000000000;100.00;;
CPU3;900000000;;cycles:u;{CG};2000000000;100.00;;
CPU0;600000000;;cycles:k;{CG};2000000000;100.00;;
CPU1;600000000;;cycles:k;{CG};2000000000;100.00;;
CPU3;100000000;;cycles:k;{CG};2000000000;100.00;;
CPU0;1500000000;;instructions;{CG};2000000000;100.00;1.50;insn per cycle
CPU1;1500000000;;instructions;{CG};2000000000;100.00;1.50;insn per cycle
CPU3;3000000000;;instructions;{CG};2000000000;100.00;3.00;insn per cycle
CPU0;500.00;msec;task-clock;{CG};500000000;100.00;0.250;CPUs utilized
CPU1;500.00;msec;task-clock;{CG};500000000;100.00;0.250;CPUs utilized
CPU3;1500.00;msec;task-clock;{CG};1500000000;100.00;0.750;CPUs utilized
CPU2;<not counted>;;cycles;{CG};0;0.00;;
"""

UNCORE = """1536.00;MiB;uncore_imc/cas_count_read/;2000000000;100.00;;
512.00;MiB;uncore_imc/cas_count_write/;2000000000;100.00;;
4096.00;MiB;uncore_iio_free_running_0/bw_in_port0/;2000000000;100.00;;
777;;uncore_iio_0/event=0x83,umask=0x4/;2000000000;100.00;;
"""

UNCORE_EVENTS = ['uncore_imc/cas_count_read/', 'uncore_imc/cas_count_write/',
                 'uncore_iio_free_running/bw_in_port0/', 'uncore_iio/event=0x83,umask=0x4/']

STAT_BEFORE = """cpu  100 0 200 10000 0 30 400 0 0 0
cpu0 25 0 50 2500 0 10 100 0 0 0
cpu1 25 0 50 2500 0 10 100 0 0 0
cpu2 25 0 50 2500 0 5 100 0 0 0
cpu3 25 0 50 2500 0 5 100 0 0 0
intr 1
softirq 9 0 0
"""
STAT_AFTER = """cpu  100 0 200 10400 0 30 600 0 0 0
cpu0 25 0 50 2600 0 10 200 0 0 0
cpu1 25 0 50 2600 0 60 150 0 0 0
cpu2 25 0 50 2600 0 5 150 0 0 0
cpu3 25 0 50 2600 0 5 100 0 0 0
intr 1
softirq 9 0 0
"""

# Outer perf stat -a -A -x';' -e cycles,cycles:k (no cgroup): the whole system.
SYSTEM = """CPU0;2000000000;;cycles;2000000000;100.00;;
CPU1;2000000000;;cycles;2000000000;100.00;;
CPU2;1000000000;;cycles;2000000000;100.00;;
CPU3;1000000000;;cycles;2000000000;100.00;;
CPU0;1500000000;;cycles:k;2000000000;100.00;;
CPU1;1500000000;;cycles:k;2000000000;100.00;;
CPU2;1000000000;;cycles:k;2000000000;100.00;;
CPU3;500000000;;cycles:k;2000000000;100.00;;
"""

PF_KTHREAD = 0x00200000


def proc_task(root, pid, comm, runtime_ns, start=100, cpus='0-3', cgroup='0::/',
              schedstat=True, ticks=(0, 0)):
    """A /proc/<pid> entry as fs/proc/base.c and fs/proc/array.c print it."""
    d = Path(root) / 'proc' / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    (d / 'comm').write_text(comm + '\n')
    rest = ['S', '2', '0', '0', '0', '-1', str(PF_KTHREAD), '0', '0', '0', '0',
            str(ticks[0]), str(ticks[1]), '0', '0', '20', '0', '1', '0', str(start)]
    (d / 'stat').write_text('%d (%s) %s 0 0\n' % (pid, comm, ' '.join(rest)))
    if schedstat:
        (d / 'schedstat').write_text('%d 0 0\n' % runtime_ns)
    elif (d / 'schedstat').exists():
        (d / 'schedstat').unlink()
    (d / 'status').write_text('Name:\t%s\nCpus_allowed_list:\t%s\n' % (comm, cpus))
    (d / 'cgroup').write_text(cgroup + '\n')
    return d


class Parse(unittest.TestCase):
    def test_steal_is_not_host_busy_time(self):
        before = ca.parse_proc_stat('cpu 0 0 0 0 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0 0\n')
        after = ca.parse_proc_stat('cpu 0 0 0 0 0 0 0 90 0 0\ncpu0 0 0 0 0 0 0 0 90 0 0\n')
        self.assertEqual(ca.proc_stat_seconds(before, after, 100)['busy']['total'], 0.0)

    def test_missing_cpu_is_not_silently_intersected(self):
        before = ca.parse_proc_stat(STAT_BEFORE)
        after = ca.parse_proc_stat(STAT_AFTER.replace('cpu3 25 0 50 2600 0 5 100 0 0 0\n', ''))
        with self.assertRaises(ValueError):
            ca.proc_stat_seconds(before, after, 100)

    def test_duplicate_cpu_and_unsigned_overflow_do_not_parse(self):
        for text in (STAT_BEFORE + 'cpu0 25 0 50 2500 0 10 100 0 0 0\n',
                     STAT_BEFORE.replace('cpu0 25 ', 'cpu0 18446744073709551616 ')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                ca.parse_proc_stat(text)

    def test_cpu_list(self):
        self.assertEqual(ca.cpu_list('0-2,5'), [0, 1, 2, 5])
        self.assertEqual(ca.cpu_list(''), [])
        for bad in ('2-1', 'x', '1,,2', '-1'):
            with self.assertRaises(ValueError):
                ca.cpu_list(bad)

    def test_core_rows_and_not_counted(self):
        rows = ca.parse_perf_csv(CORE, ca.CORE_EVENTS, cgroups=[CG])
        self.assertEqual(len(rows), 16)
        missing = [r for r in rows if r['value'] is None]
        self.assertEqual(len(missing), 1)
        self.assertEqual((missing[0]['cpu'], missing[0]['event']), (2, 'cycles'))
        agg = ca.aggregate(rows)
        self.assertEqual(agg['cycles']['total'], 3e9)
        self.assertEqual(agg['cycles']['per_cpu'], {0: 1e9, 1: 1e9, 3: 1e9})
        self.assertEqual(agg['task-clock']['total'], 2500.0)
        self.assertEqual(agg['cycles']['not_counted_cpus'], [2])

    def test_foreign_cgroup_and_unknown_event_are_refused(self):
        foreign = CORE.replace(CG, 'other/arm', 1)
        with self.assertRaises(ca.ParseError):
            ca.parse_perf_csv(foreign, ca.CORE_EVENTS, cgroups=[CG])
        with self.assertRaises(ca.ParseError):
            ca.parse_perf_csv('CPU0;5;;branch-misses;%s;1;100.00;;\n' % CG,
                              ca.CORE_EVENTS, cgroups=[CG])

    def test_uncore_units_and_pmu_instances(self):
        agg = ca.aggregate(ca.parse_perf_csv(UNCORE, UNCORE_EVENTS))
        self.assertEqual(ca.event_bytes(agg['uncore_imc/cas_count_read/']), 1536 * 2**20)
        self.assertEqual(ca.event_bytes(agg['uncore_imc/cas_count_write/']), 512 * 2**20)
        self.assertEqual(ca.event_bytes(agg['uncore_iio_free_running/bw_in_port0/']), 4096 * 2**20)
        # A raw count without a byte unit is reported, never converted by guess.
        self.assertIsNone(ca.event_bytes(agg['uncore_iio/event=0x83,umask=0x4/']))
        # A unitless CAS count is one 64-byte line per count.
        raw = ca.aggregate(ca.parse_perf_csv('10;;uncore_imc_0/cas_count_read/;1;100.00;;\n'
                                             '5;;uncore_imc_1/cas_count_read/;1;100.00;;\n',
                                             ['uncore_imc/cas_count_read/']))
        self.assertEqual(ca.event_bytes(raw['uncore_imc/cas_count_read/']), 15 * 64)

    def test_hardirq_softirq_and_busy_deltas(self):
        t = ca.proc_stat_seconds(ca.parse_proc_stat(STAT_BEFORE),
                                 ca.parse_proc_stat(STAT_AFTER), 100)
        self.assertEqual(t['softirq']['total'], 2.0)
        # /proc/stat field 5 (irq): 50 ticks on CPU1.
        self.assertEqual(t['irq']['total'], 0.5)
        self.assertEqual(t['irq']['per_cpu'], {0: 0.0, 1: 0.5, 2: 0.0, 3: 0.0})
        # busy = user+nice+system+irq+softirq+steal.
        self.assertEqual(t['busy']['total'], 2.5)

    def test_softirq_delta(self):
        hz = 100
        delta = ca.softirq_seconds(ca.parse_proc_stat(STAT_BEFORE),
                                   ca.parse_proc_stat(STAT_AFTER), hz)
        self.assertEqual(delta['total'], 2.0)
        self.assertEqual(delta['per_cpu'], {0: 1.0, 1: 0.5, 2: 0.5, 3: 0.0})
        with self.assertRaises(ca.ParseError):
            ca.parse_proc_stat('intr 1\n')


class Arithmetic(unittest.TestCase):
    def setUp(self):
        self.core = ca.aggregate(ca.parse_perf_csv(CORE, ca.CORE_EVENTS, cgroups=[CG]))
        self.uncore = ca.aggregate(ca.parse_perf_csv(UNCORE, UNCORE_EVENTS))
        self.soft = ca.proc_stat_seconds(ca.parse_proc_stat(STAT_BEFORE),
                                         ca.parse_proc_stat(STAT_AFTER), 100)
        self.system = ca.aggregate(ca.parse_perf_csv(SYSTEM, ca.SYSTEM_EVENTS))

    def test_system_totals_beside_the_cgroup(self):
        r = ca.account(self.core, None, self.soft, wall_s=2.0, payload_bytes=10**9,
                       poller_cpus=[], system=self.system)
        self.assertEqual(r['system_cycles'], 6e9)
        self.assertEqual(r['system_kernel_cycles'], 4.5e9)
        self.assertAlmostEqual(r['system_cycles_per_payload_byte'], 6.0)
        self.assertAlmostEqual(r['hardirq_cores_system'], 0.25)
        self.assertAlmostEqual(r['softirq_cores_system'], 1.0)
        self.assertAlmostEqual(r['system_busy_cores'], 1.25)
        # Busy time of neither the cgroup nor a named kthread.
        self.assertAlmostEqual(r['unattributed_busy_cores'], 0.0)
        self.assertIn('cgroup', r['attribution']['cycles'])

    def test_kthread_time_counts_toward_cores_charged(self):
        """The session worker kthread lives in the root cgroup: perf -G never
        sees it, so its runtime is added to the arm explicitly."""
        kt = dict(charged_s=1.0, on_poller_s=0.5, threads=[], exited_threads=0,
                  sample_interval_s=0.1, tail_bound_s=0.0)
        base = ca.account(self.core, None, self.soft, wall_s=2.0, payload_bytes=10**9,
                          poller_cpus=[3])
        r = ca.account(self.core, None, self.soft, wall_s=2.0, payload_bytes=10**9,
                       poller_cpus=[3], kthreads=kt)
        self.assertAlmostEqual(r['kthread_cores'], 0.5)
        # Time on a poller CPU is already inside that CPU's full core.
        self.assertAlmostEqual(r['cores_charged'], base['cores_charged'] + 0.5)
        self.assertAlmostEqual(r['core_seconds_charged_per_GB'], (1.5 + 0.5) * 2.0)
        self.assertIsNone(r['kthread_cycles'])

    def test_cycles_per_byte_and_poller_charged_as_full_core(self):
        r = ca.account(self.core, self.uncore, self.soft, wall_s=2.0,
                       payload_bytes=10**9, poller_cpus=[3])
        self.assertEqual(r['cycles'], 3e9)
        self.assertAlmostEqual(r['cycles_per_payload_byte'], 3.0)
        self.assertAlmostEqual(r['user_cycles_per_payload_byte'], 1.7)
        self.assertAlmostEqual(r['kernel_cycles_per_payload_byte'], 1.3)
        self.assertAlmostEqual(r['ipc'], 2.0)
        self.assertAlmostEqual(r['cores_measured'], 1.25)
        # CPUs 0 and 1 used 1.0 s over 2 s; the poller CPU counts as 1.0.
        self.assertAlmostEqual(r['cores_charged'], 1.5)
        self.assertEqual(r['poller_cores'], 1)
        self.assertAlmostEqual(r['core_seconds_charged_per_GB'], 3.0)
        self.assertAlmostEqual(r['softirq_cores_system'], 1.0)
        self.assertEqual(r['dram_read_bytes'], 1536 * 2**20)
        self.assertAlmostEqual(r['dram_bytes_per_payload_byte'], 2048 * 2**20 / 1e9)
        other = r['uncore_other']
        self.assertEqual(other['uncore_iio_free_running/bw_in_port0/']['bytes'], 4096 * 2**20)
        self.assertAlmostEqual(
            other['uncore_iio_free_running/bw_in_port0/']['bytes_per_payload_byte'],
            4096 * 2**20 / 1e9)
        self.assertEqual(other['uncore_iio/event=0x83,umask=0x4/']['value'], 777)
        self.assertIsNone(other['uncore_iio/event=0x83,umask=0x4/']['bytes'])

    def test_without_poller_and_without_uncore(self):
        r = ca.account(self.core, None, self.soft, wall_s=2.0,
                       payload_bytes=10**9, poller_cpus=[])
        self.assertAlmostEqual(r['cores_charged'], r['cores_measured'])
        self.assertIsNone(r['dram_bytes_per_payload_byte'])

    def test_poller_without_samples_still_charged(self):
        r = ca.account(self.core, None, self.soft, wall_s=2.0,
                       payload_bytes=10**9, poller_cpus=[3, 7])
        self.assertAlmostEqual(r['cores_charged'], 2.5)

    def test_rejects_zero_payload_or_wall(self):
        for wall, payload in ((0.0, 1), (1.0, 0)):
            with self.assertRaises(ValueError):
                ca.account(self.core, None, self.soft, wall_s=wall,
                           payload_bytes=payload, poller_cpus=[])

    def test_wall_sources(self):
        # The harness's own timed span is the rate denominator when it reports one.
        w = ca.walls(outer_wall_s=12.0, harness_elapsed_s=10.0, min_wall_s=10.0)
        self.assertEqual(w, dict(counting_wall_s=12.0, rate_wall_s=10.0,
                                 rate_wall_source='harness', short_run=False))
        w = ca.walls(outer_wall_s=12.0, harness_elapsed_s=None, min_wall_s=10.0)
        self.assertEqual((w['rate_wall_s'], w['rate_wall_source']), (12.0, 'outer'))
        # perf and shell startup dominate a short run: it is flagged.
        self.assertTrue(ca.walls(outer_wall_s=3.0, harness_elapsed_s=None,
                                 min_wall_s=10.0)['short_run'])
        out = 'x\n{"elapsed_s": 2.5, "result": {"payload_bytes": 7}}\n'
        self.assertEqual(ca.number_from_output(out, 'elapsed_s'), 2.5)
        with self.assertRaises(ca.ParseError):
            ca.number_from_output('{"elapsed_s": -1}\n', 'elapsed_s')

    def test_target_rate(self):
        self.assertEqual(ca.rate_check(10**9, 2.5, 4e8, 0.05),
                         dict(target_bytes_per_s=4e8, achieved_bytes_per_s=4e8,
                              relative_error=0.0, matched=True))
        self.assertFalse(ca.rate_check(10**9, 2.0, 4e8, 0.05)['matched'])
        self.assertIsNone(ca.rate_check(10**9, 2.0, None, 0.05))

    def test_payload_from_harness_json(self):
        out = 'log line\n{"result": {"payload_bytes": 4096}}\n'
        self.assertEqual(ca.payload_from_output(out, 'result.payload_bytes'), 4096)
        with self.assertRaises(ca.ParseError):
            ca.payload_from_output(out, 'result.bytes')
        with self.assertRaises(ca.ParseError):
            ca.payload_from_output('no json\n', 'result.payload_bytes')


def fake_root(base, hypervisor=False, cgroup=True, imc=False):
    root = Path(base)
    (root / 'proc').mkdir(parents=True)
    flags = 'fpu sse2 hypervisor' if hypervisor else 'fpu sse2'
    (root / 'proc/cpuinfo').write_text('processor\t: 0\nflags\t\t: %s\n' % flags)
    (root / 'proc/stat').write_text(STAT_BEFORE)
    if cgroup:
        (root / 'sys/fs/cgroup').mkdir(parents=True)
        (root / 'sys/fs/cgroup/cgroup.controllers').write_text('cpu memory\n')
    if imc:
        events = root / 'sys/bus/event_source/devices/uncore_imc_0/events'
        events.mkdir(parents=True)
        (events / 'cas_count_read').write_text('event=0x05,umask=0xcf\n')
        (events / 'cas_count_write').write_text('event=0x05,umask=0xf0\n')
        iio = root / 'sys/bus/event_source/devices/uncore_iio_free_running_0/events'
        iio.mkdir(parents=True)
        (iio / 'bw_in_port0').write_text('event=0xff,umask=0x20\n')
    return root


class Kthreads(unittest.TestCase):
    def test_scan_matches_comm_and_reads_runtime(self):
        with tempfile.TemporaryDirectory() as t:
            proc_task(t, 900, 'xdev_ext_mech/7', 2_500_000_000, start=500)
            proc_task(t, 950, 'kworker/u16:3', 9_000_000_000)
            # Without schedstat the stat utime+stime ticks are used.
            proc_task(t, 960, 'xdev_ext_mech/9', 0, schedstat=False, ticks=(3, 7))
            # A matching task inside the arm cgroup is already counted by perf -G.
            proc_task(t, 970, 'xdev_ext_mech/1', 1_000_000_000, cgroup='0::/' + CG)
            snap = ca.scan_threads(Path(t), [ca.DEFAULT_KTHREAD_COMM], CG, hz=100)
        self.assertEqual(sorted(k[0] for k in snap), [900, 960])
        a = snap[(900, 500)]
        self.assertEqual((a['comm'], a['runtime_ns'], a['source'], a['cpus']),
                         ('xdev_ext_mech/7', 2_500_000_000, 'schedstat', [0, 1, 2, 3]))
        b = snap[(960, 100)]
        self.assertEqual((b['runtime_ns'], b['source']), (100_000_000, 'stat_ticks'))

    def test_tracker_charges_deltas_and_skips_poller_threads(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            pat = [ca.DEFAULT_KTHREAD_COMM]
            proc_task(t, 901, 'xdev_ext_mech/8', 1_000_000_000, start=50, cpus='3')
            proc_task(t, 905, 'xdev_ext_mech/2', 4_000_000_000, start=60)
            tracker = ca.KthreadTracker(ca.scan_threads(root, pat, CG, 100), interval_s=0.1)
            # Born during the run: all of its runtime belongs to the run.
            proc_task(t, 900, 'xdev_ext_mech/7', 1_000_000_000, start=500)
            proc_task(t, 901, 'xdev_ext_mech/8', 1_200_000_000, start=50, cpus='3')
            proc_task(t, 905, 'xdev_ext_mech/2', 4_250_000_000, start=60)
            tracker.observe(ca.scan_threads(root, pat, CG, 100))
            proc_task(t, 900, 'xdev_ext_mech/7', 2_500_000_000, start=500)
            proc_task(t, 901, 'xdev_ext_mech/8', 1_500_000_000, start=50, cpus='3')
            # 905 exits before the last sample; its last observed delta stays.
            for f in (root / 'proc/905').iterdir():
                f.unlink()
            (root / 'proc/905').rmdir()
            tracker.observe(ca.scan_threads(root, pat, CG, 100))
            r = tracker.summary(pollers=[3])
        by_pid = {th['pid']: th for th in r['threads']}
        self.assertAlmostEqual(by_pid[900]['runtime_s'], 2.5)
        self.assertTrue(by_pid[900]['born_during_run'])
        self.assertAlmostEqual(by_pid[901]['runtime_s'], 0.5)
        self.assertTrue(by_pid[901]['on_poller'])
        self.assertAlmostEqual(by_pid[905]['runtime_s'], 0.25)
        self.assertTrue(by_pid[905]['exited'])
        self.assertAlmostEqual(r['charged_s'], 2.75)
        self.assertAlmostEqual(r['on_poller_s'], 0.5)
        self.assertEqual(r['exited_threads'], 1)
        # An exited thread may have run up to one interval after its last sample.
        self.assertAlmostEqual(r['tail_bound_s'], 0.1)


FAKE_PERF = r"""#!%s
# Fake perf for the end-to-end test: copies a fixture to -o, then runs the
# command after --.  With -G it is the inner per-cgroup count.
import os, subprocess, sys
argv = sys.argv[1:]
own = argv[:argv.index('--')]
out = own[own.index('-o') + 1]
if '-G' in own:
    cg = own[own.index('-G') + 1].split(',')[0]
    text = open(os.environ['FAKE_CORE']).read().replace('xdev_eval/arm-a', cg)
else:
    text = open(os.environ['FAKE_SYSTEM']).read()
open(out, 'w').write(text)
sys.exit(subprocess.run(argv[argv.index('--') + 1:]).returncode)
"""

HARNESS = r"""
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
def task(ns):
    d = root / 'proc/900'
    d.mkdir(parents=True, exist_ok=True)
    (d / 'comm').write_text('xdev_ext_mech/7\n')
    (d / 'stat').write_text('900 (xdev_ext_mech/7) S 2 0 0 0 -1 2097152 0 0 0 0 0 0 0 0 '
                            '20 0 1 0 500 0 0\n')
    (d / 'schedstat').write_text('%d 0 0\n' % ns)
    (d / 'status').write_text('Cpus_allowed_list:\t0-3\n')
    (d / 'cgroup').write_text('0::/\n')
# The session worker is created after the harness starts (session CREATE).
task(1000000000)
time.sleep(0.4)
task(2500000000)
(root / 'proc/stat').write_text(sys.argv[2])
print(json.dumps(dict(payload_bytes=10**9, elapsed_s=1.0)))
"""


class EndToEnd(unittest.TestCase):
    def test_kthread_runtime_reaches_the_receipt(self):
        import os
        import sys
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(Path(t) / 'root')
            perf = Path(t) / 'perf'
            perf.write_text(FAKE_PERF % sys.executable)
            perf.chmod(0o755)
            (Path(t) / 'core.csv').write_text(CORE)
            (Path(t) / 'system.csv').write_text(SYSTEM)
            (Path(t) / 'harness.py').write_text(HARNESS)
            env = dict(os.environ, FAKE_CORE=str(Path(t) / 'core.csv'),
                       FAKE_SYSTEM=str(Path(t) / 'system.csv'))
            p = subprocess.run([sys.executable, str(HERE / 'cpu_account.py'),
                                '--host-root', str(root), '--arm', 'e2e', '--perf', str(perf),
                                '--payload-json-key', 'payload_bytes',
                                '--elapsed-json-key', 'elapsed_s', '--min-wall-s', '0',
                                '--kthread-interval', '0.05',
                                '--target-rate', '1e9', '--rate-env', 'RATE',
                                '--', sys.executable, str(Path(t) / 'harness.py'), str(root),
                                STAT_AFTER], capture_output=True, text=True, env=env,
                               timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        receipt = json.loads(p.stdout)
        a = receipt['account']
        self.assertEqual(receipt['status'], 'accounted')
        self.assertAlmostEqual(a['kthread_s'], 2.5)
        self.assertEqual([th['comm'] for th in a['kthreads']['threads']], ['xdev_ext_mech/7'])
        wall = a['wall_s']
        # cgroup task-clock 2.5 s plus the worker kthread 2.5 s.
        self.assertAlmostEqual(a['cores_charged'], 5.0 / wall)
        self.assertEqual(a['system_cycles'], 6e9)
        hz = os.sysconf('SC_CLK_TCK')
        self.assertAlmostEqual(a['hardirq_s_system'], 50 / hz)
        self.assertEqual(receipt['rate']['rate_wall_source'], 'harness')
        self.assertTrue(receipt['rate']['matched'])


class Cli(unittest.TestCase):
    def run_main(self, argv):
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = ca.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_hypervisor_refused_with_exit4(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, hypervisor=True)
            code, _, err = self.run_main(['--host-root', str(root), '--arm', 'a',
                                          '--payload-bytes', '1', '--perf', '/bin/true',
                                          '--', 'true'])
        self.assertEqual(code, 4)
        self.assertIn('hypervisor', err)

    def test_missing_cgroup2_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, cgroup=False)
            code, _, err = self.run_main(['--host-root', str(root), '--arm', 'a',
                                          '--payload-bytes', '1', '--perf', '/bin/true',
                                          '--', 'true'])
        self.assertEqual(code, 4)
        self.assertIn('cgroup v2', err)

    def test_uncore_requires_observed_imc_events(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t)
            code, _, err = self.run_main(['--host-root', str(root), '--arm', 'a', '--uncore',
                                          '--payload-bytes', '1', '--perf', '/bin/true',
                                          '--dry-run', '--', 'true'])
        self.assertEqual(code, 4)
        self.assertIn('cas_count_read', err)

    def test_dry_run_plan_is_exact(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, imc=True)
            code, out, _ = self.run_main([
                '--host-root', str(root), '--arm', 'nvme-nic', '--uncore',
                '--pcie-event', 'uncore_iio_free_running/bw_in_port0/',
                '--poller-cpus', '3', '--payload-bytes', '4096', '--perf', '/usr/bin/perf',
                '--target-rate', '1000', '--rate-flag=--target-rate',
                '--dry-run', '--', 'harness', '--x', '1'])
        self.assertEqual(code, 0)
        plan = json.loads(out)
        cg = plan['cgroup']
        self.assertTrue(cg.startswith('xdev_eval/nvme-nic-'))
        inner = plan['argv'][plan['argv'].index('--', 1) + 1:]
        # The outer system-wide count always runs: core events without -G,
        # plus the uncore events.
        self.assertEqual(plan['argv'][:10], [
            '/usr/bin/perf', 'stat', '-a', '-A', '-x', ';', '-o', plan['system_output'], '-e',
            'cycles,cycles:k,uncore_imc/cas_count_read/,uncore_imc/cas_count_write/,'
            'uncore_iio_free_running/bw_in_port0/'])
        self.assertNotIn('-G', plan['argv'][:plan['argv'].index('--')])
        self.assertEqual(inner[:8], ['/usr/bin/perf', 'stat', '-a', '-A', '-x', ';', '-o',
                                     plan['core_output']])
        self.assertEqual(inner[8:12], ['-e', ','.join(ca.CORE_EVENTS),
                                       '-G', ','.join([cg] * len(ca.CORE_EVENTS))])
        self.assertEqual(plan['harness'], ['harness', '--x', '1', '--target-rate', '1000'])
        self.assertEqual(inner[-5:], plan['harness'])
        # The workload joins the arm cgroup itself before exec.
        self.assertEqual(inner[12:16], ['--', '/bin/sh', '-c', ca.JOIN_SCRIPT])
        self.assertEqual(plan['poller_cpus'], [3])
        self.assertEqual(plan['kthread_comm'], [ca.DEFAULT_KTHREAD_COMM])

    def test_system_count_without_uncore(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t)
            code, out, _ = self.run_main(['--host-root', str(root), '--arm', 'a',
                                          '--payload-bytes', '1', '--perf', '/usr/bin/perf',
                                          '--dry-run', '--', 'h'])
        self.assertEqual(code, 0)
        plan = json.loads(out)
        self.assertEqual(plan['argv'][:10], ['/usr/bin/perf', 'stat', '-a', '-A', '-x', ';',
                                             '-o', plan['system_output'], '-e',
                                             'cycles,cycles:k'])

    def test_imc_event_override_maps_read_and_write(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, imc=True)
            fr = root / 'sys/bus/event_source/devices/uncore_imc_free_running_0/events'
            fr.mkdir(parents=True)
            (fr / 'data_read').write_text('event=0xff,umask=0x10\n')
            (fr / 'data_write').write_text('event=0xff,umask=0x11\n')
            override = ['--imc-event', 'uncore_imc_free_running/data_read/',
                        '--imc-event', 'uncore_imc_free_running/data_write/']
            code, out, _ = self.run_main(['--host-root', str(root), '--arm', 'a', '--uncore',
                                          '--payload-bytes', '1', '--dry-run'] + override +
                                         ['--', 'h'])
            self.assertEqual(code, 0)
            plan = json.loads(out)
            self.assertEqual(plan['imc_events'], ['uncore_imc_free_running/data_read/',
                                                  'uncore_imc_free_running/data_write/'])
            self.assertIn('uncore_imc_free_running/data_read/', plan['argv'][9])
            # An override that names no sysfs event is refused, not guessed.
            code, _, err = self.run_main(['--host-root', str(root), '--arm', 'a', '--uncore',
                                          '--payload-bytes', '1', '--dry-run',
                                          '--imc-event', 'uncore_imc/rd/',
                                          '--imc-event', 'uncore_imc/wr/', '--', 'h'])
            self.assertEqual(code, 4)
            self.assertIn('uncore_imc/rd/', err)
            with self.assertRaises(SystemExit) as raised, \
                    contextlib.redirect_stderr(io.StringIO()):
                ca.main(['--host-root', str(root), '--arm', 'a', '--uncore', '--payload-bytes',
                         '1', '--dry-run', '--imc-event', 'uncore_imc/cas_count_read/',
                         '--', 'h'])
            self.assertEqual(raised.exception.code, 2)
        rows = ('2048.00;MiB;uncore_imc_free_running_0/data_read/;1;100.00;;\n'
                '1024.00;MiB;uncore_imc_free_running_0/data_write/;1;100.00;;\n')
        names = ['uncore_imc_free_running/data_read/', 'uncore_imc_free_running/data_write/']
        uncore = ca.aggregate(ca.parse_perf_csv(rows, names))
        core = ca.aggregate(ca.parse_perf_csv(CORE, ca.CORE_EVENTS, cgroups=[CG]))
        soft = ca.proc_stat_seconds(ca.parse_proc_stat(STAT_BEFORE),
                                    ca.parse_proc_stat(STAT_AFTER), 100)
        r = ca.account(core, uncore, soft, wall_s=2.0, payload_bytes=2**30, poller_cpus=[],
                       imc=names)
        self.assertEqual((r['dram_read_bytes'], r['dram_write_bytes']), (2**31, 2**30))
        self.assertAlmostEqual(r['dram_bytes_per_payload_byte'], 3.0)
        self.assertEqual(r['uncore_other'], {})

    def test_rate_flag_requires_target(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t)
            with self.assertRaises(SystemExit) as raised, \
                    contextlib.redirect_stderr(io.StringIO()):
                ca.main(['--host-root', str(root), '--arm', 'a', '--payload-bytes', '1',
                         '--rate-flag=--rate', '--dry-run', '--', 'true'])
        self.assertEqual(raised.exception.code, 2)



class SelectedOwnerAccounting(unittest.TestCase):
    """Inherited selected timer capture must not start the regex worker cadence."""
    def test_dry_run_discloses_selected_owner_artifacts_without_creating_them(self):
        from unittest.mock import patch
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp)/'root')
            output = Path(tmp)/'planned-cpu-output'
            online_text = Path('/sys/devices/system/cpu/online').read_text().strip()
            env = {k: v for k, v in os.environ.items() if not k.startswith('XDEV_EXT_EVAL_CPU_')}
            out, err = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    code = ca.main(['--host-root', str(root), '--arm', 'plan', '--perf', '/bin/true',
                                    '--payload-bytes', '1', '--cpu-set', online_text,
                                    '--cpu-output', str(output), '--dry-run', '--', 'true'])
                except SystemExit as error:
                    self.fail('common accounting wrapper lacks selected CPU dry-run API: ' + str(error))
            self.assertEqual(code, 0, err.getvalue())
            planned = json.loads(out.getvalue())['cpu_measurement_plan']
            self.assertEqual(planned['schema'], 1)
            self.assertEqual(planned['status'], 'planned')
            self.assertEqual(planned['selected_cpus'], ca.cpu_list(online_text))
            self.assertEqual(planned['clock'], 'CLOCK_MONOTONIC')
            self.assertEqual(planned['extra_clocks'], ['CLOCK_MONOTONIC_RAW'])
            self.assertEqual(planned['owner_mode'], 'create')
            self.assertTrue(planned['artifacts']['samples_path'])
            self.assertTrue(planned['artifacts']['journal_dir'])
            self.assertFalse(output.exists(), 'dry-run created CPU capture artifacts')

    def test_accounting_owner_supports_nested_raw_timer_with_one_actual_stream(self):
        import os
        import sys
        import threading
        from unittest.mock import patch
        timer_path = Path(ca.CPU_SAMPLING.__file__).parent/'timer_scope.py'
        spec = importlib.util.spec_from_file_location('accounting_raw_nested_scope', timer_path)
        timer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(timer)
        env = {k: v for k, v in os.environ.items() if not k.startswith('XDEV_EXT_EVAL_CPU_')}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, env, clear=True):
            output = Path(tmp)/'account-owner'
            args = ca.parse_args(['--arm', 'raw-chain', '--payload-bytes', '1',
                                  '--cpu-output', str(output), '--', sys.executable, '-c',
                                  "print('original-raw-result')"])
            with ca._timer(args, Path(tmp)) as owner:
                owner_env = owner.environment(dict(os.environ))
                config = json.loads(Path(owner_env['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                threads = [t for t in threading.enumerate() if t.name == 'native-cpu-sampler']
                self.assertEqual(len(threads), 1)
                with patch.dict(os.environ, owner_env, clear=True):
                    try:
                        with timer.TimerCpuRun(None, clock='CLOCK_MONOTONIC_RAW') as nested:
                            self.assertEqual(nested.environment({})['XDEV_EXT_EVAL_CPU_OWNER'],
                                             owner_env['XDEV_EXT_EVAL_CPU_OWNER'])
                            done = nested.run(args.cmd, capture_output=True, text=True, check=True)
                            self.assertEqual(done.stdout, 'original-raw-result\n')
                            self.assertEqual(done.returncode, 0)
                            self.assertEqual([t for t in threading.enumerate()
                                              if t.name == 'native-cpu-sampler'], threads)
                    except ValueError as error:
                        self.fail('accounting owner prevented existing RAW-timer workload: '+str(error))
            self.assertFalse(threads[0].is_alive())
            rows = [json.loads(line) for line in Path(config['samples_path']).read_text().splitlines()]
            self.assertGreaterEqual(len(rows), 2)
            self.assertTrue(all(row['clock'] == 'CLOCK_MONOTONIC' for row in rows))
            self.assertTrue(all('CLOCK_MONOTONIC_RAW' in row['clock_brackets'] for row in rows))

    def test_inherited_owner_disables_secondary_periodic_worker_sampler(self):
        import os
        import sys
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = fake_root(base / 'root')
            perf = base / 'perf'
            perf.write_text(FAKE_PERF % sys.executable)
            perf.chmod(0o755)
            (base / 'core.csv').write_text(CORE)
            (base / 'system.csv').write_text(SYSTEM)
            # This fixture describes an already active parent, not a second stream.
            owner = base / 'owner'
            owner.mkdir(mode=0o700)
            (owner / 'samples.jsonl').write_text('')
            (owner / 'journals').mkdir(mode=0o700)
            (owner / 'receipts').mkdir(mode=0o700)
            online = ca.CPU_SAMPLING.parse_cpu_set(None,
                        possible=tuple(ca.cpu_list(Path('/sys/devices/system/cpu/possible').read_text().strip())),
                        online=tuple(ca.cpu_list(Path('/sys/devices/system/cpu/online').read_text().strip())))
            possible = ca.cpu_list(Path('/sys/devices/system/cpu/possible').read_text().strip())
            cpu_scope = dict(schema=1, selected_cpus=list(online), online_cpus=list(online),
                             possible_cpus=possible,
                             boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                             clock='CLOCK_MONOTONIC', clock_domain='account-fixture',
                             selection='all-online', status='qualified', hold_reasons=[])
            config = dict(schema=1, token='fixture-owner-token', run_id='fixture-command',
                          cpu_scope=cpu_scope, measurement_cpu_count=len(online),
                          tick_hz=os.sysconf('SC_CLK_TCK'),
                          primary_clock='CLOCK_MONOTONIC', extra_clocks=[],
                          samples_path=str(owner/'samples.jsonl'), journal_dir=str(owner/'journals'),
                          receipts_dir=str(owner/'receipts'))
            config_path = owner/'owner.json'
            config_path.write_text(json.dumps(config))
            config_path.chmod(0o600)
            env = dict(FAKE_CORE=str(base/'core.csv'), FAKE_SYSTEM=str(base/'system.csv'),
                       XDEV_EXT_EVAL_CPU_OWNER=str(config_path),
                       XDEV_EXT_EVAL_CPU_JOURNAL_DIR=str(owner/'journals'),
                       XDEV_EXT_EVAL_CPU_TOKEN=config['token'],
                       XDEV_EXT_EVAL_CPU_RUN_ID=config['run_id'],
                       XDEV_EXT_EVAL_CPU_CLOCK_DOMAIN='account-fixture')
            args = ca.parse_args(['--host-root', str(root), '--arm', 'selected',
                                  '--perf', str(perf), '--payload-bytes', '1',
                                  '--min-wall-s', '0', '--', sys.executable, '-c',
                                  'print(1)'])
            p = ca.plan(args, root, base)
            def forbidden(*args, **kwargs):
                self.fail('selected owner started a second periodic regex-worker sampler')
            with patch.dict(os.environ, env), patch.object(ca, 'Sampler', side_effect=forbidden):
                receipt, code = ca.execute(args, root, p)
            self.assertEqual(code, 0)
            self.assertIn('separate-periodic-worker-sampler-disabled', json.dumps(receipt))
            self.assertEqual(config_path.read_text(), json.dumps(config))

if __name__ == '__main__':
    unittest.main()

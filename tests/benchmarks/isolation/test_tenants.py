#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""E8 multi-tenant runner: host contracts, no device and no timing claim.

Requirements (evaluation plan, RQ4/E8): N tenant processes share one NVMe
namespace, each in its own disjoint LBA window of one prepared region, for N
in {1, C/2, C, C+1, 1.5C, 2C, 3C, 4C}; every tenant is restricted to the same
C CPUs by affinity inside the running kernel (CPUs are never taken offline);
all tenants start together after every one is set up; the record per
repetition and N holds each tenant's numbers and the aggregate throughput
(verified bytes only) and the share of requests that took >= 1 ms. The same
runner shape drives the SPDK multi-process arm (spdk_nvme_perf per process)
and the xdev_ext session arm; an arm without per-request latency reports the
share as not measured, never as zero.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('tenants', HERE / 'tenants.py')
tn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tn)
KIB, MIB = 1 << 10, 1 << 20

FAKE_TENANT = textwrap.dedent('''
    import json, os, sys, time
    args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
    ready = time.monotonic_ns()
    print('TENANT_READY ' + json.dumps({'pid': os.getpid(), 'ready_ns': ready,
          'cpus': sorted(os.sched_getaffinity(0))}), flush=True)
    line = sys.stdin.readline()
    go = time.monotonic_ns()
    assert line.strip() == 'GO', line
    t = int(args['--tenant'])
    ops = 100 + t
    hist = [0] * 32
    hist[3] = ops - t
    hist[10] = t
    print('TENANT_RESULT ' + json.dumps({'ops': ops, 'bytes_ok': ops * 4096, 'errors': 0,
          'verify_fail': 0, 'measured_ns': 1000000000, 'go_ns': go, 'hist_log2_us': hist,
          'ge_1ms': t, 'args': args}), flush=True)
''')


def write_fake(tmp):
    p = Path(tmp) / 'fake_tenant.py'
    p.write_text(FAKE_TENANT)
    return [sys.executable, '-I', str(p), '--tenant', '{tenant}', '--offset', '{offset}',
            '--bytes', '{window_bytes}', '--depth', '{depth}', '--io-bytes', '{io_bytes}',
            '--seconds', '{seconds}', '--warmup', '{warmup}', '--seed', '{seed}']


class Plan(unittest.TestCase):
    def test_tenant_counts_follow_the_plan(self):
        self.assertEqual(tn.tenant_counts(6), [1, 3, 6, 7, 9, 12, 18, 24])
        self.assertEqual(tn.tenant_counts(1), [1, 2, 3, 4])

    def test_cpu_list(self):
        self.assertEqual(tn.parse_cpus('0-2,5'), [0, 1, 2, 5])
        for bad in ('', '3-1', 'x', '1,1'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                tn.parse_cpus(bad)

    def test_windows_are_disjoint_aligned_and_inside_the_region(self):
        w = tn.windows(1 * MIB, 64 * MIB, 7, 4096)
        self.assertEqual(len(w), 7)
        end = 1 * MIB
        for off, size in w:
            self.assertEqual(off, end, 'contiguous and disjoint')
            self.assertEqual((off % 4096, size % 4096), (0, 0))
            end = off + size
        self.assertLessEqual(end, 65 * MIB)
        self.assertEqual(len({s for _, s in w}), 1, 'equal windows')
        with self.assertRaises(ValueError):
            tn.windows(0, 4096 * 3, 4, 4096)

    def test_order_alternates_between_repetitions(self):
        self.assertEqual(tn.order([1, 3, 6], 0), [1, 3, 6])
        self.assertEqual(tn.order([1, 3, 6], 1), [6, 3, 1])


class Aggregate(unittest.TestCase):
    def test_sum_of_rates_and_share(self):
        res = [dict(ops=1000, bytes_ok=4096000, measured_ns=2 * 10**9, ge_1ms=10),
               dict(ops=3000, bytes_ok=4096 * 3000, measured_ns=10**9, ge_1ms=2)]
        a = tn.aggregate(res)
        self.assertAlmostEqual(a['bytes_per_s'], 4096000 / 2 + 4096 * 3000)
        self.assertAlmostEqual(a['gb_per_s'], a['bytes_per_s'] / 1e9)
        self.assertEqual(a['ops'], 4000)
        self.assertAlmostEqual(a['share_ge_1ms'], 12 / 4000)
        self.assertEqual(a['tenants'], 2)

    def test_share_not_measured_when_a_tenant_has_no_latency(self):
        res = [dict(ops=10, bytes_ok=40960, measured_ns=10**9, ge_1ms=0),
               dict(ops=10, bytes_ok=40960, measured_ns=10**9, ge_1ms=None)]
        self.assertIsNone(tn.aggregate(res)['share_ge_1ms'])

    def test_failed_tenant_makes_the_point_fail(self):
        res = [dict(ops=10, bytes_ok=40960, measured_ns=10**9, ge_1ms=0),
               dict(error='exit 1')]
        a = tn.aggregate(res)
        self.assertFalse(a['ok'])
        self.assertIsNone(a['bytes_per_s'])


SPDK_OUT = textwrap.dedent('''
    Initializing NVMe Controllers
    Attached to NVMe Controller at 0000:02:00.0 [144d:a80c]
    ========================================================
                                                                                 Latency(us)
    Device Information                                     :       IOPS      MiB/s    Average        min        max
    PCIE (0000:02:00.0) NSID 1 from core  2:  250000.00     976.56     127.90       8.20    2100.10
    ========================================================
    Total                                                  :  250000.00     976.56     127.90       8.20    2100.10

    Latency histogram for PCIE (0000:02:00.0) NSID 1                  from core 2:
    ==============================================================================
           Range in us     Cumulative    IO count
        8.192 -     8.250:    0.0004%  (       3)
      120.000 -   121.000:   99.0000%  (  742497)
      998.000 -  1003.000:   99.9000%  (    6750)
     1003.000 -  1010.000:   99.9600%  (     450)
     2097.152 -  2105.000:  100.0000%  (     300)
''')


class Spdk(unittest.TestCase):
    def test_perf_output(self):
        r = tn.parse_spdk_perf(SPDK_OUT, io_bytes=4096, seconds=3)
        self.assertEqual(r['ops'], 3 + 742497 + 6750 + 450 + 300)
        self.assertEqual(r['ge_1ms'], 450 + 300, 'buckets that start at or above 1000 us')
        self.assertEqual(r['straddle_1ms'], 6750, 'the bucket across 1 ms is kept apart')
        self.assertEqual(r['bytes_ok'], r['ops'] * 4096)
        self.assertEqual(r['measured_ns'], 3 * 10**9)
        self.assertAlmostEqual(r['reported_iops'], 250000.0)
        self.assertIsNone(tn.parse_spdk_perf('no histogram', 4096, 3).get('ge_1ms'))

    def test_one_core_per_process_and_a_shared_shm_group(self):
        cmds = tn.spdk_commands('spdk_nvme_perf', '0000:02:00.0', [2, 3, 4], 3, depth=8,
                                io_bytes=4096, seconds=30, warmup=5, shm_id=7)
        masks = [c[c.index('-c') + 1] for c in cmds]
        self.assertEqual(masks, ['0x4', '0x8', '0x10'])
        for c in cmds:
            self.assertEqual(c[c.index('-i') + 1], '7')
            self.assertIn('-LL', c)
            self.assertEqual(c[c.index('-w') + 1], 'randread')
            self.assertEqual(c[c.index('-a') + 1], '5')
        with self.assertRaises(SystemExit) as e:
            tn.spdk_commands('spdk_nvme_perf', '0000:02:00.0', [2, 3], 3, depth=8,
                             io_bytes=4096, seconds=30, warmup=5, shm_id=7)
        self.assertIn('share', str(e.exception), 'SPDK processes may not share cores')


class Session(unittest.TestCase):
    def test_session_record(self):
        line = json.dumps(dict(schema_version=1, arm='session', status='pass', io_bytes=8 * MIB,
                               verified_bytes=8 * MIB, operations=2048, io_ns=2 * 10**9))
        r = tn.parse_session(line + '\n')
        self.assertEqual((r['ops'], r['bytes_ok'], r['measured_ns']), (2048, 8 * MIB, 2 * 10**9))
        self.assertIsNone(r['ge_1ms'], 'no per-request latency: not measured')
        self.assertEqual(tn.parse_session('')['error'], 'no session record')


class Runs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='e8-')
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_barrier_affinity_windows_and_records(self):
        cpus = sorted(os.sched_getaffinity(0))[:2]
        out = self.dir / 'out'
        rc = tn.main(['run', '--arm', 'custom', '--tenant-cmd', json.dumps(write_fake(self.dir)),
                      '--cpus', ','.join(map(str, cpus)), '--tenants', '1,3',
                      '--region-offset', str(MIB), '--region-bytes', str(12 * MIB),
                      '--depth', '4', '--seconds', '1', '--warmup', '0',
                      '--repetitions', '2', '--output', str(out)])
        self.assertEqual(rc, 0)
        rows = [json.loads(l) for l in (out / 'results.jsonl').read_text().splitlines()]
        self.assertEqual([(r['rep'], r['n']) for r in rows], [(0, 1), (0, 3), (1, 3), (1, 1)])
        for r in rows:
            self.assertTrue(r['aggregate']['ok'], r)
            self.assertEqual(len(r['tenant_results']), r['n'])
            go = min(t['go_ns'] for t in r['tenant_results'])
            for t in r['tenant_results']:
                self.assertLess(t['ready']['ready_ns'], go, 'GO only after every READY')
                self.assertEqual(t['ready']['cpus'], cpus, 'every tenant on the same C CPUs')
            offs = [int(t['args']['--offset']) for t in r['tenant_results']]
            self.assertEqual(offs, sorted(set(offs)), 'disjoint windows')
            self.assertEqual(int(r['tenant_results'][0]['args']['--bytes']), 12 * MIB // r['n'])
        three = rows[1]['aggregate']
        self.assertEqual(three['ops'], 100 + 101 + 102)
        self.assertAlmostEqual(three['share_ge_1ms'], (0 + 1 + 2) / 303)
        meta = json.loads((out / 'run.json').read_text())
        self.assertEqual((meta['cores'], meta['cpus'], meta['performance_claim']),
                         (len(cpus), cpus, 'none'))
        self.assertEqual(meta['cpu_control'], 'affinity')
        s = tn.summarize([out])
        self.assertEqual([p['n'] for p in s['points']], [1, 3])
        self.assertEqual(s['points'][1]['repetitions'], 2)
        self.assertAlmostEqual(s['points'][1]['share_ge_1ms']['median'], 3 / 303)

    def test_refuses_cpus_outside_this_process(self):
        allowed = os.sched_getaffinity(0)
        missing = max(allowed) + 1
        with self.assertRaises(SystemExit) as e:
            tn.main(['run', '--arm', 'custom', '--tenant-cmd', json.dumps(['true']),
                     '--cpus', str(missing), '--tenants', '1', '--region-bytes', str(MIB),
                     '--output', str(self.dir / 'o')])
        self.assertIn('offline', str(e.exception))

    def test_dry_run_prints_commands(self):
        r = subprocess.run([sys.executable, '-I', str(HERE / 'tenants.py'), 'run', '--arm', 'uring',
                            '--device', '/dev/nvme0n1', '--cpus', '0', '--tenants', '2',
                            '--region-bytes', str(MIB), '--dry-run', '--output', 'x'],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        plan = json.loads(r.stdout)
        self.assertEqual(len(plan['points'][0]['commands']), 2)
        self.assertIn('--device', plan['points'][0]['commands'][0])


def build_tenant():
    if not shutil.which('make'):
        return None, None
    tmp = tempfile.TemporaryDirectory(prefix='uring-tenant-')
    r = subprocess.run(['make', '-s', '-C', str(HERE), f'BUILD={tmp.name}',
                        f'{tmp.name}/uring_tenant'], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)
    return Path(tmp.name) / 'uring_tenant', tmp


BIN, _BTMP = build_tenant()


def odirect_dir():
    """A directory whose file system accepts O_DIRECT (tmpfs does not)."""
    for d in (os.environ.get('E8_ODIRECT_DIR'), tempfile.gettempdir(), str(HERE)):
        if not d:
            continue
        try:
            fd, path = tempfile.mkstemp(dir=d)
            os.close(fd)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
            os.close(fd)
            os.unlink(path)
            return d
        except OSError:
            try:
                os.unlink(path)
            except OSError:
                pass
    return None


@unittest.skipUnless(BIN and odirect_dir() and hasattr(os, 'O_DIRECT'),
                     'needs make and an O_DIRECT-capable directory')
class UringTenant(unittest.TestCase):
    """The io_uring tenant: O_DIRECT 4 KiB random reads in its window, READ_FIXED
    into registered buffers, per-request latency histogram, payload check."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='e8-dev-', dir=odirect_dir())
        self.dev = Path(self.tmp.name) / 'disk.img'
        with open(self.dev, 'wb') as f:
            f.truncate(8 * MIB)

    def tearDown(self):
        self.tmp.cleanup()

    def prepare(self):
        r = subprocess.run([str(BIN), '--write-pattern', '--device', str(self.dev),
                            '--region-offset', str(MIB), '--bytes', str(4 * MIB), '--seed', '5'],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    def tenant(self, offset, nbytes, extra=()):
        p = subprocess.Popen([str(BIN), '--device', str(self.dev), '--region-offset', str(MIB),
                              '--offset', str(offset), '--bytes', str(nbytes), '--io-bytes', '4096',
                              '--depth', '4', '--seconds', '0.3', '--warmup', '0.1', '--seed', '5',
                              '--verify'] + list(extra),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        kind, ready = tn.parse_line(p.stdout.readline())
        self.assertEqual(kind, 'TENANT_READY')
        p.stdin.write('GO\n')
        p.stdin.flush()
        kind, res = tn.parse_line(p.stdout.readline())
        p.wait(timeout=30)
        p.stdin.close()
        p.stdout.close()
        self.assertEqual(kind, 'TENANT_RESULT')
        return p.returncode, ready, res

    def test_reads_verify_and_histogram(self):
        self.prepare()
        rc, ready, r = self.tenant(MIB + MIB, MIB)
        self.assertEqual(rc, 0, r)
        self.assertGreater(r['ops'], 0)
        self.assertEqual(r['verify_fail'], 0)
        self.assertEqual(r['bytes_ok'], r['ops'] * 4096)
        self.assertEqual(sum(r['hist_log2_us']), r['ops'], 'every request in the histogram')
        self.assertLessEqual(r['ge_1ms'], r['ops'])
        self.assertGreater(r['measured_ns'], 0.25e9)
        self.assertEqual((r['window_offset'], r['window_bytes']), (2 * MIB, MIB))

    def test_misplaced_payload_is_not_counted(self):
        self.prepare()
        with open(self.dev, 'r+b') as f:
            f.seek(2 * MIB)
            f.write(b'\0' * MIB)
        rc, _, r = self.tenant(2 * MIB, MIB)
        self.assertNotEqual(rc, 0)
        self.assertGreater(r['verify_fail'], 0)
        self.assertEqual(r['bytes_ok'], 0, 'only verified bytes count')

    def test_window_outside_the_region_is_refused(self):
        r = subprocess.run([str(BIN), '--device', str(self.dev), '--region-offset', str(MIB),
                            '--offset', str(MIB // 2), '--bytes', str(MIB), '--io-bytes', '4096',
                            '--depth', '4', '--seconds', '1', '--warmup', '0', '--seed', '5'],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)


if __name__ == '__main__':
    unittest.main()

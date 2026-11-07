#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host CPU core-seconds from /proc/stat, and the host-1 marker agent.

Requirement: the CPU cost of one restore on a host is the busy time of all
its CPUs (user, nice, system, irq, softirq, steal) between two markers,
because kernel workers, interrupts and every process of an arm count; guest
time is already inside user/nice and must not be added twice. The host-1
agent takes those markers on request so every arm is measured the same way.
"""
import importlib.util
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_cpu', HERE / 'kv_cpu.py')
kc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kc)

STAT = '''cpu  {u} 10 {s} 1000 50 {i} {si} {st} 999 777
cpu0 {u} 10 {s} 500 25 {i} {si} {st} 999 777
cpu1 0 0 0 500 25 0 0 0 0 0
intr 1 2 3
ctxt 99
btime 1700000000
'''


def stat(u, s, i=0, si=0, st=0):
    return STAT.format(u=u, s=s, i=i, si=si, st=st)


class Parse(unittest.TestCase):
    def test_busy_excludes_idle_iowait_and_double_counted_guest(self):
        snap = kc.parse_stat(stat(100, 40, 5, 6, 7))
        self.assertEqual(snap['busy_ticks'], 100 + 10 + 40 + 5 + 6 + 7)
        self.assertEqual(snap['idle_ticks'], 1000 + 50)
        self.assertEqual(snap['cpus'], 2)

    def test_delta_in_core_seconds(self):
        a = dict(kc.parse_stat(stat(100, 40)), mono_ns=1_000_000_000)
        b = dict(kc.parse_stat(stat(300, 140)), mono_ns=3_000_000_000)
        d = kc.delta(a, b, hz=100)
        self.assertAlmostEqual(d['busy_core_seconds'], 3.0)
        self.assertAlmostEqual(d['wall_seconds'], 2.0)
        self.assertEqual(d['cpus'], 2)

    def test_refusals(self):
        a = dict(kc.parse_stat(stat(300, 40)), mono_ns=2)
        b = dict(kc.parse_stat(stat(100, 40)), mono_ns=3)
        with self.assertRaises(kc.CpuError):
            kc.delta(a, b, hz=100)          # counter went backwards
        with self.assertRaises(kc.CpuError):
            kc.delta(dict(a, mono_ns=5), dict(a, mono_ns=4), hz=100)
        for bad in ('', 'intr 1\n', 'cpu  1 2 3\n'):
            with self.subTest(text=bad), self.assertRaises(kc.CpuError):
                kc.parse_stat(bad)


class Agent(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-cpu-')
        root = Path(self.tmp.name)
        (root / 'sys/vm').mkdir(parents=True)
        (root / 'stat').write_text(stat(100, 40))
        (root / 'sys/vm/drop_caches').write_text('')
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def serve(self, allow_drop):
        server = kc.AgentServer(('127.0.0.1', 0), token='t0k', proc_root=self.root,
                                allow_drop_caches=allow_drop)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        return kc.AgentClient(server.server_address, token='t0k', timeout=5)

    def test_markers_bracket_a_run(self):
        c = self.serve(False)
        self.assertEqual(c.ping()['ok'], True)
        c.begin('r1')
        (self.root / 'stat').write_text(stat(150, 90))
        d = c.end('r1')
        self.assertEqual(d['run'], 'r1')
        self.assertEqual(d['busy_ticks'], 100)
        self.assertGreater(d['busy_core_seconds'], 0)
        with self.assertRaises(kc.CpuError):
            c.end('r1')                     # no open marker any more

    def test_token_and_drop_caches_policy(self):
        c = self.serve(False)
        with self.assertRaises(kc.CpuError):
            c.drop_caches()
        bad = kc.AgentClient(c.address, token='wrong', timeout=5)
        with self.assertRaises(kc.CpuError):
            bad.ping()

    def test_drop_caches_when_allowed(self):
        c = self.serve(True)
        self.assertTrue(c.drop_caches()['ok'])
        self.assertEqual((self.root / 'sys/vm/drop_caches').read_text(), '3\n')


if __name__ == '__main__':
    unittest.main()

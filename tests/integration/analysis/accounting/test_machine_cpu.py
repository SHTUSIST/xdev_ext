#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""machine_cpu.py: machine-wide /proc/stat busy time minus an idle window.

The fixtures are fake /proc trees; the "harness" is a short Python program
that advances the fake counters.  No real workload is measured.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TOOL = HERE / 'machine_cpu.py'
spec = importlib.util.spec_from_file_location('machine_cpu', TOOL)
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)
kc = mc.KV_CPU


def stat(user, system, idle=1000, cpus=2):
    lines = [f'cpu  {user} 0 {system} {idle} 0 0 0 0 0 0']
    lines += [f'cpu{i} 1 0 1 1 0 0 0 0 0 0' for i in range(cpus)]
    return '\n'.join(lines + ['intr 1', '']) + '\n'


def snap(user, system, mono_s, cpus=2):
    return dict(kc.parse_stat(stat(user, system, cpus=cpus)), mono_ns=int(mono_s * 1e9))


# argv: TICKS EXIT ROOT... ; adds TICKS user ticks to every ROOT/stat.
ADVANCE = """
import sys
from pathlib import Path
ticks, code = int(sys.argv[1]), int(sys.argv[2])
for root in sys.argv[3:]:
    path = Path(root) / 'stat'
    lines = path.read_text().splitlines()
    first = lines[0].split()
    first[1] = str(int(first[1]) + ticks)
    lines[0] = ' '.join(first)
    path.write_text('\\n'.join(lines) + '\\n')
sys.exit(code)
"""


class Arithmetic(unittest.TestCase):
    def test_idle_rate_is_subtracted_over_the_run_wall_time(self):
        idle = kc.delta(snap(0, 0, 0), snap(30, 20, 5), hz=100)      # 0.5 core-s in 5 s
        run = kc.delta(snap(30, 20, 5), snap(230, 120, 7), hz=100)   # 3.0 core-s in 2 s
        net = mc.subtract_idle(idle, run)
        self.assertAlmostEqual(net['idle_cores'], 0.1)
        self.assertAlmostEqual(net['net_core_seconds'], 3.0 - 0.1 * 2)
        self.assertAlmostEqual(net['net_cores'], (3.0 - 0.2) / 2)
        self.assertAlmostEqual(net['raw_cores'], 1.5)
        self.assertFalse(net['below_idle'])

    def test_a_run_below_the_idle_rate_is_reported_not_clamped(self):
        idle = kc.delta(snap(0, 0, 0), snap(100, 0, 1), hz=100)      # 1 core idle
        run = kc.delta(snap(100, 0, 1), snap(150, 0, 2), hz=100)     # 0.5 core
        net = mc.subtract_idle(idle, run)
        self.assertAlmostEqual(net['net_cores'], -0.5)
        self.assertTrue(net['below_idle'])

    def test_idle_drift_between_the_two_windows(self):
        before = kc.delta(snap(0, 0, 0), snap(10, 0, 1), hz=100)     # 0.1 core
        after = kc.delta(snap(0, 0, 0), snap(40, 0, 1), hz=100)      # 0.4 core
        self.assertAlmostEqual(mc.idle_drift(before, after), 0.3)
        self.assertAlmostEqual(mc.idle_drift(before, before), 0.0)


class Runner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='machine-cpu-')
        self.base = Path(self.tmp.name)
        self.proc = self.base / 'proc'
        self.proc.mkdir()
        (self.proc / 'stat').write_text(stat(100, 40))
        self.host = self.base / 'host'
        (self.host / 'proc').mkdir(parents=True)
        (self.host / 'proc/cpuinfo').write_text('flags\t\t: fpu sse2\n')
        self.script = self.base / 'advance.py'
        self.script.write_text(ADVANCE)

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, *extra, ticks=500, code=0, roots=None):
        out = self.base / 'record.json'
        if out.exists():
            out.unlink()
        roots = [self.proc] if roots is None else roots
        argv = [sys.executable, str(TOOL), '--arm', 'fake-arm', '--idle-s', '0.05',
                '--proc-root', str(self.proc), '--host-root', str(self.host),
                '--out', str(out), *extra, '--', sys.executable, str(self.script),
                str(ticks), str(code), *map(str, roots)]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        record = json.loads(out.read_text()) if out.exists() else None
        return r, record

    def test_one_run_is_bracketed_and_the_idle_window_measured(self):
        r, rec = self.run_tool()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(rec['schema'], mc.SCHEMA)
        self.assertEqual(rec['verdict'], 'ok')
        self.assertEqual(rec['arm'], 'fake-arm')
        self.assertEqual(rec['harness']['exit'], 0)
        self.assertEqual(rec['local']['run']['busy_ticks'], 500)
        self.assertEqual(rec['local']['idle_before']['busy_ticks'], 0)
        self.assertEqual(rec['local']['net']['idle_cores'], 0)
        self.assertEqual(rec['busy_formula'], 'user+nice+system+irq+softirq+steal')
        self.assertIsNone(rec['remote'])
        self.assertEqual(rec['execution'], 'bare-metal')

    def test_harness_failure_is_recorded_and_exits_1(self):
        r, rec = self.run_tool(code=3)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(rec['verdict'], 'harness_failed')
        self.assertEqual(rec['harness']['exit'], 3)

    def test_idle_after_window_and_drift_gate(self):
        r, rec = self.run_tool('--idle-after', '--max-idle-drift-cores', '0.01')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(rec['local']['idle_after']['busy_ticks'], 0)
        self.assertEqual(rec['local']['idle_drift_cores'], 0)

    def test_drift_beyond_the_gate_rejects_the_run(self):
        # A background "tenant" adds ticks during the idle windows too.
        bg = self.base / 'bg.py'
        bg.write_text(ADVANCE)
        r, rec = self.run_tool('--idle-after', '--max-idle-drift-cores', '0.0001',
                               '--idle-after-hook', f'{sys.executable} {bg} 50 0 {self.proc}')
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(rec['verdict'], 'idle_drift')

    def test_virtual_machine_is_refused_unless_allowed(self):
        (self.host / 'proc/cpuinfo').write_text('flags\t\t: fpu hypervisor\n')
        r, rec = self.run_tool()
        self.assertEqual(r.returncode, 4)
        self.assertIsNone(rec)
        r, rec = self.run_tool('--allow-vm')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(rec['execution'], 'vm')
        self.assertEqual(rec['performance_claim'], 'none')

    def test_dry_run_runs_nothing(self):
        before = (self.proc / 'stat').read_text()
        r, rec = self.run_tool('--dry-run')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNone(rec)
        plan = json.loads(r.stdout)
        self.assertIs(plan['dry_run'], True)
        self.assertEqual(plan['harness'][1], str(self.script))
        self.assertEqual((self.proc / 'stat').read_text(), before)

    def test_remote_host_through_the_kv_cpu_agent(self):
        remote = self.base / 'remote-proc'
        remote.mkdir()
        (remote / 'stat').write_text(stat(7, 7))
        token = self.base / 'token'
        token.write_text('t0k\n')
        server = kc.AgentServer(('127.0.0.1', 0), token='t0k', proc_root=remote)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        addr = '%s:%d' % server.server_address
        r, rec = self.run_tool('--remote', addr, '--remote-token-file', str(token),
                               ticks=250, roots=[self.proc, remote])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(rec['remote']['address'], addr)
        self.assertEqual(rec['remote']['run']['busy_ticks'], 250)
        self.assertEqual(rec['remote']['idle_before']['busy_ticks'], 0)
        self.assertIn('net_cores', rec['remote']['net'])

    def test_irq_time_accounting_is_recorded(self):
        release = os.uname().release
        (self.host / 'boot').mkdir()
        (self.host / f'boot/config-{release}').write_text('CONFIG_IRQ_TIME_ACCOUNTING=y\n')
        r, rec = self.run_tool()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIs(rec['irq_time_accounting'], True)
        (self.host / f'boot/config-{release}').write_text('# CONFIG_IRQ_TIME_ACCOUNTING is not set\n')
        r, rec = self.run_tool()
        self.assertIs(rec['irq_time_accounting'], False)


if __name__ == '__main__':
    unittest.main()

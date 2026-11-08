#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""run.py (rank-local E4 runner) on one host with tcp_cuda --fake-gpu."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
RUN = HERE / 'run.py'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Runner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdg-run-')
        r = subprocess.run(['make', '-s', '-C', str(HERE), f'BUILD={cls.tmp.name}',
                            f'{cls.tmp.name}/tcp_cuda'], capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(r.stdout + r.stderr)
        cls.bindir = cls.tmp.name

    def test_dry_run_alternates_the_arm_order_per_pair(self):
        r = subprocess.run([sys.executable, str(RUN), '--rank', '0', '--addr', '127.0.0.1:9',
                            '--arms', 'tcp-cuda,xdev-ext', '--pairs', '2', '--bin-dir', 'B',
                            '--out', 'unused', '--dry-run', '--', '--sizes', '4096'],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        plan = json.loads(r.stdout)
        self.assertEqual([(s['pair'], s['arm']) for s in plan['steps']],
                         [(0, 'tcp-cuda'), (0, 'xdev-ext'), (1, 'xdev-ext'), (1, 'tcp-cuda')])
        first = plan['steps'][0]['argv']
        self.assertEqual(first[:5], ['B/tcp_cuda', '--rank', '0', '--peer', '127.0.0.1:9'])
        self.assertEqual(first[-2:], ['--sizes', '4096'])

    def test_stream_mode_records_nccl_as_not_run(self):
        r = subprocess.run([sys.executable, str(RUN), '--rank', '1', '--addr', '127.0.0.1:9',
                            '--arms', 'nccl', '--mode', 'stream', '--pairs', '1', '--bin-dir', 'B',
                            '--out', 'unused', '--dry-run'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        step = json.loads(r.stdout)['steps'][0]
        self.assertEqual(step['not_run'], 'nccl bandwidth comes from nccl_tests.py (sendrecv_perf)')

    def test_two_ranks_run_every_pair_and_keep_raw_output(self):
        port = free_port()
        base = Path(self.tmp.name)
        common = ['--addr', f'127.0.0.1:{port}', '--arms', 'tcp-cuda', '--pairs', '2',
                  '--bin-dir', self.bindir, '--', '--sizes', '64,4096', '--fake-gpu',
                  '--iters', '10', '--warmup', '2']
        r1 = subprocess.Popen([sys.executable, str(RUN), '--rank', '1', '--out',
                               str(base / 'r1'), *common], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
        r0 = subprocess.run([sys.executable, str(RUN), '--rank', '0', '--out', str(base / 'r0'),
                             *common], capture_output=True, text=True, timeout=120)
        out1, err1 = r1.communicate(timeout=120)
        self.assertEqual(r0.returncode, 0, r0.stderr)
        self.assertEqual(r1.returncode, 0, err1)
        summary = json.loads((base / 'r0/runs.json').read_text())
        self.assertEqual(summary['schema'], 'xdev-eval-e4-runs-v1')
        self.assertEqual(len(summary['steps']), 2)
        for step in summary['steps']:
            self.assertEqual(step['exit'], 0)
            recs = [json.loads(l) for l in (base / 'r0' / step['raw']).read_text().splitlines()]
            self.assertEqual([x['size'] for x in recs], [64, 4096])
            self.assertTrue(all(x['verified'] for x in recs))
        self.assertTrue((base / 'r1/runs.json').is_file())

    def test_a_failing_tool_fails_the_runner(self):
        r = subprocess.run([sys.executable, str(RUN), '--rank', '0', '--addr', '127.0.0.1:1',
                            '--arms', 'tcp-cuda', '--pairs', '1', '--bin-dir', self.bindir,
                            '--out', str(Path(self.tmp.name) / 'fail'), '--',
                            '--sizes', '4096', '--fake-gpu', '--timeout-s', '1'],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1)
        summary = json.loads((Path(self.tmp.name) / 'fail/runs.json').read_text())
        self.assertNotEqual(summary['steps'][0]['exit'], 0)


if __name__ == '__main__':
    unittest.main()

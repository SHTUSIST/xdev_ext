#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""nccl_tests.py (sendrecv_perf runner) against recorded-shape fake output."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TOOL = HERE / 'nccl_tests.py'
spec = importlib.util.spec_from_file_location('nccl_tests', TOOL)
nt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nt)

OUT = """# nThread 1 nGpus 1 minBytes 64 maxBytes 4194304 step: 2(factor) warmup iters: 5 iters: 20 agg iters: 1 validation: 1 graph: 0
#
host1:1234:1234 [0] NCCL INFO NCCL version 2.21.5+cuda12.4
host1:1234:1250 [0] NCCL INFO Channel 00/0 : 0[1000] -> 1[1000] [send] via NET/Socket/0
host1:1234:1250 [0] NCCL INFO Channel 00/0 : 1[1000] -> 0[1000] [receive] via NET/Socket/0
#
#                                                              out-of-place                       in-place
#       size         count      type   redop    root     time   algbw   busbw #wrong     time   algbw   busbw #wrong
#        (B)    (elements)                               (us)  (GB/s)  (GB/s)            (us)  (GB/s)  (GB/s)
          64            16     float     sum      -1    41.20    0.00    0.00      0    40.10    0.00    0.00      0
         128            32     float     sum      -1    41.90    0.00    0.00      0    41.00    0.00    0.00      0
     4194304       1048576     float     sum      -1   1500.0    2.80    2.80      0   1490.0    2.81    2.81      0
# Out of bounds values : 0 OK
# Avg bus bandwidth    : 1.2
"""


class Parse(unittest.TestCase):
    def test_rows_and_transport(self):
        p = nt.parse_output(OUT)
        self.assertEqual([r['size'] for r in p['rows']], [64, 128, 4194304])
        last = p['rows'][-1]
        self.assertEqual(last['out_of_place'], dict(time_us=1500.0, algbw_gbs=2.8, busbw_gbs=2.8,
                                                    wrong=0))
        self.assertEqual(last['in_place']['wrong'], 0)
        self.assertEqual(p['transports'], ['NET/Socket/0'])
        self.assertEqual(p['nccl_version'], '2.21.5+cuda12.4')
        self.assertEqual(nt.verdict(p), 'ok')

    def test_other_transport_or_wrong_data_rejects(self):
        self.assertEqual(nt.verdict(nt.parse_output(OUT.replace('NET/Socket/0', 'NET/IB/0'))),
                         'not_net_socket')
        bad = OUT.replace('2.80      0   1490.0', '2.80      3   1490.0')
        self.assertEqual(nt.verdict(nt.parse_output(bad)), 'wrong_data')
        self.assertEqual(nt.verdict(nt.parse_output('# nothing\n')), 'no_rows')


class Runner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='nccl-tests-')
        base = Path(self.tmp.name)
        self.fake = base / 'sendrecv_perf'
        self.fake.write_text('#!/bin/sh\necho "$@" > "%s/argv"\nenv | grep ^NCCL_ > "%s/env"\n'
                             'cat "%s/out.txt"\n' % (base, base, base))
        self.fake.chmod(0o755)
        (base / 'out.txt').write_text(OUT)
        self.base = base

    def tearDown(self):
        self.tmp.cleanup()

    def test_runs_the_plan_command_with_ordinary_settings(self):
        out = self.base / 'rec.json'
        r = subprocess.run([sys.executable, str(TOOL), '--binary', str(self.fake),
                            '--ifname', 'thunderbolt0', '--out', str(out)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = (self.base / 'argv').read_text().split()
        self.assertEqual(argv, ['-b', '64', '-e', '4M', '-f', '2', '-g', '1'])
        env = (self.base / 'env').read_text()
        self.assertIn('NCCL_SOCKET_IFNAME=thunderbolt0', env)
        self.assertIn('NCCL_DEBUG=INFO', env)
        rec = json.loads(out.read_text())
        self.assertEqual(rec['schema'], nt.SCHEMA)
        self.assertEqual(rec['verdict'], 'ok')
        self.assertEqual(rec['arm'], 'nccl-sendrecv')
        self.assertEqual(len(rec['rows']), 3)
        self.assertTrue((self.base / rec['raw_log']).is_file() or Path(rec['raw_log']).is_file())

    def test_a_launcher_prefixes_the_command(self):
        r = subprocess.run([sys.executable, str(TOOL), '--binary', str(self.fake), '--ifname',
                            'tb0', '--launcher', 'env FOO=1', '--dry-run'],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        plan = json.loads(r.stdout)
        self.assertEqual(plan['argv'][:2], ['env', 'FOO=1'])
        self.assertEqual(plan['env']['NCCL_SOCKET_IFNAME'], 'tb0')

    def test_wrong_transport_exits_1(self):
        (self.base / 'out.txt').write_text(OUT.replace('NET/Socket/0', 'P2P/IPC'))
        out = self.base / 'rec.json'
        r = subprocess.run([sys.executable, str(TOOL), '--binary', str(self.fake),
                            '--ifname', 'thunderbolt0', '--out', str(out)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(out.read_text())['verdict'], 'not_net_socket')


if __name__ == '__main__':
    unittest.main()

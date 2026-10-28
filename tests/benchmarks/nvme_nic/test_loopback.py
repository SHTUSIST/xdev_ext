#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Loopback correctness of the arms that run on an ordinary host (no timing emitted).

posix and splice forward, posix reverse, against the real C peer over
127.0.0.1 with a private temporary file as the window.  Fault injections must
fail the run.  The uring arm runs when the build and kernel support it, and
otherwise must refuse with exit 4 before any trial.  This certifies no NVMe,
NIC, DMA or performance property.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BUILD = Path(os.environ.get('NNB_BUILD_DIR', HERE / '.build'))


def loopback(*extra, timeout=600):
    with tempfile.TemporaryDirectory(prefix='nnb-test-', dir=BUILD) as tmp:
        return subprocess.run([sys.executable, str(HERE / 'run.py'), '--correctness-only', '--loopback',
                               '--build-dir', str(BUILD), '--directory', tmp, '--pairs', '1', *extra],
                              text=True, capture_output=True, timeout=timeout)


class Loopback(unittest.TestCase):
    def assert_clean(self, out, configs):
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = [json.loads(line) for line in out.stdout.splitlines()]
        self.assertEqual(len(lines), configs + 1)
        self.assertEqual(lines[-1], dict(status='ok', mode='correctness', configs=configs, admission=None))
        for config in lines[:-1]:
            self.assertEqual(config['mode'], 'correctness')
            self.assertTrue(all(config['integrity'].values()))
            self.assertNotIn('summary', config)
        self.assertNotIn('_ns', out.stdout)
        return lines

    def test_forward_posix_splice(self):
        out = loopback('--arms', 'posix,splice', '--sizes', '4096,65536,4194304', '--qd', '1,4')
        self.assert_clean(out, 6)

    def test_reverse_posix(self):
        out = loopback('--direction', 'rev', '--arms', 'posix', '--sizes', '4096,1048576', '--qd', '1,2')
        self.assert_clean(out, 4)

    def test_faults_fail(self):
        for direction, fault in (('fwd', 'skip-datagram'), ('fwd', 'duplicate-datagram'),
                                 ('fwd', 'corrupt-payload'), ('rev', 'skip-write')):
            out = loopback('--direction', direction, '--arms', 'posix', '--sizes', '65536', '--qd', '2',
                           '--fault', fault)
            self.assertEqual(out.returncode, 1, (fault, out.stdout, out.stderr))
            self.assertNotIn('"status": "ok", "mode"', out.stdout.splitlines()[-1] if out.stdout else '')

    def test_partial_thread_start_fails_cleanly(self):
        # pthread_create failing after some threads started must not hang the teardown,
        # and a failure that is not a missing capability exits 1, not 4.
        for qd in ('1', '4'):
            out = loopback('--arms', 'posix', '--sizes', '65536', '--qd', qd, '--fault', 'thread-create',
                           timeout=120)
            self.assertEqual(out.returncode, 1, (qd, out.stdout, out.stderr))
            self.assertIn('exit 1', out.stderr)

    def test_peer_coalesces_gso_runs(self):
        # UDP_GRO on the peer: one receive buffer carries a whole GSO run of datagrams.
        lines = self.assert_clean(loopback('--arms', 'posix', '--sizes', '4194304', '--qd', '1'), 1)
        buffers, datagrams = lines[0]['peer_buffers']['posix'], lines[0]['peer_datagrams']['posix']
        self.assertGreater(datagrams, 0)
        self.assertLess(buffers, datagrams)

    def test_uring_runs_or_refuses(self):
        features = json.loads(subprocess.run([str(BUILD / 'nnb_producer'), '--features'], text=True,
                                             capture_output=True, check=True).stdout)
        for direction in ('fwd', 'rev'):
            out = loopback('--direction', direction, '--arms', 'uring', '--sizes', '65536', '--qd', '2')
            if out.returncode == 0:
                self.assertTrue(features['uring'])
                self.assert_clean(out, 1)
                continue
            self.assertEqual(out.returncode, 4, out.stderr)
            self.assertEqual(out.stdout, '')
            status = json.loads(out.stderr.splitlines()[-1])
            self.assertEqual((status['status'], status['completed_configurations']), ('not_run_capability', 0))


if __name__ == '__main__':
    unittest.main()

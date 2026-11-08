#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The connector's client of the K-KV restore worker (kv_restore --dst ce-vmm).

The worker speaks the line protocol of tests/benchmarks/kv_restore
kv_protocol.py. A restore counts as good only when the worker says ok and its
KV_RESULT carries exactly the requested bytes into the CE VMM destination with
no CPU-copied payload; anything else is a failure, so the connector recomputes
instead of serving the staged bytes. A session whose restore failed after START
takes no more work (kv_restore README), so the client replaces the worker; a
refusal before START keeps it. Keys only grow on host 1, so ordinals never
repeat, also across connector restarts when a state file is given.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

import _paths
from xdev_kv_vllm import restore as kr

FAKE = Path(__file__).resolve().parent / 'fake_restore_worker.py'
POOL = 1 << 22


class Staging:
    made = []

    def __init__(self, ready, pid):
        self.ready, self.pid, self.released = ready, pid, False
        Staging.made.append(self)

    def release(self):
        self.released = True


class Base(unittest.TestCase):
    def setUp(self):
        Staging.made = []
        self.tmp = tempfile.TemporaryDirectory(prefix='kvconn-restore-')
        self.dir = Path(self.tmp.name)
        self.log = self.dir / 'go.log'
        self.source = self.dir / 'disk'
        self.stage = self.dir / 'stage'
        self.source.write_bytes(os.urandom(1 << 21))
        self.stage.write_bytes(b'\0' * POOL)

    def tearDown(self):
        self.tmp.cleanup()

    def service(self, mode='ok', fail_after=0, **overrides):
        argv = [sys.executable, '-B', str(FAKE), '--mode', mode, '--fail-after', str(fail_after),
                '--source', str(self.source), '--stage', str(self.stage), '--log', str(self.log),
                '--pool-bytes', str(POOL)]
        cfg = dict(argv=argv, group_bytes=131072, pool_bytes=POOL, ready_timeout=20.0,
                   go_timeout=20.0, max_restarts=1, worker_log=str(self.dir / 'worker.log'))
        cfg.update(overrides)
        svc = kr.RestoreService(kr.RestoreConfig(**cfg), staging_factory=Staging)
        self.addCleanup(svc.close)
        return svc

    def gos(self):
        return [dict(w.split('=', 1) for w in line.split()[1:])
                for line in self.log.read_text().splitlines() if line.startswith('GO ')]


class Protocol(Base):
    @unittest.skipIf(_paths.load_benchmark_module('kv_protocol') is None, 'no kv_protocol.py')
    def test_go_line_is_the_benchmark_protocol(self):
        kp = _paths.load_benchmark_module('kv_protocol')
        for args in (('xkv-1', 1, 2048, 131072, 0), ('a.b_c-9', 77, 0, 1 << 33, 4096)):
            self.assertEqual(kr.go_line(*args), kp.go_line(*args))

    def test_restore_copies_into_the_stage_and_keys_grow(self):
        svc = self.service()
        svc.start()
        self.assertEqual(len(Staging.made), 1)
        out = svc.restore(object_slba=256, nbytes=262144, staging_offset=8192)
        self.assertTrue(out.ok, out)
        self.assertGreaterEqual(out.latency_ns, 0)
        self.assertEqual(self.stage.read_bytes()[8192:8192 + 262144],
                         self.source.read_bytes()[256 * 512:256 * 512 + 262144])
        self.assertTrue(svc.restore(object_slba=0, nbytes=131072, staging_offset=0).ok)
        gos = self.gos()
        self.assertEqual([g['ordinal'] for g in gos], ['1', '2'])
        self.assertEqual([g['dst_frame0'] for g in gos], ['2', '0'])
        self.assertEqual({g['verify'] for g in gos}, {'0'})
        self.assertEqual(len({g['run'] for g in gos}), 2)

    def test_offset_must_be_whole_frames(self):
        svc = self.service()
        svc.start()
        with self.assertRaises(ValueError):
            svc.restore(object_slba=0, nbytes=131072, staging_offset=100)
        with self.assertRaises(ValueError):
            svc.restore(object_slba=0, nbytes=131072, staging_offset=POOL - 4096)

    def test_ordinals_continue_across_connectors(self):
        state = self.dir / 'ordinal.json'
        svc = self.service(ordinal_file=str(state), ordinal_base=10)
        svc.start()
        svc.restore(0, 131072, 0)
        svc.restore(0, 131072, 0)
        self.assertEqual(json.loads(state.read_text())['next_ordinal'], 12)
        svc.close()
        again = self.service(ordinal_file=str(state), ordinal_base=1)
        again.start()
        again.restore(0, 131072, 0)
        self.assertEqual([g['ordinal'] for g in self.gos()], ['10', '11', '12'])


class Failures(Base):
    def test_failure_after_start_replaces_the_worker(self):
        svc = self.service('fail-started', fail_after=1)
        svc.start()
        self.assertTrue(svc.restore(0, 131072, 0).ok)
        bad = svc.restore(0, 131072, 0)
        self.assertFalse(bad.ok)
        self.assertEqual(bad.error, -5)
        self.assertEqual(len(Staging.made), 2, 'a new worker and a new staging import')
        self.assertTrue(Staging.made[0].released)
        self.assertNotEqual(Staging.made[0].pid, Staging.made[1].pid)
        self.assertTrue(svc.restore(0, 131072, 0).ok)
        self.assertEqual([g['ordinal'] for g in self.gos()], ['1', '2', '3'])
        self.assertEqual(svc.stats['restarts'], 1)

    def test_refusal_before_start_keeps_the_worker(self):
        svc = self.service('refuse')
        svc.start()
        out = svc.restore(0, 131072, 0)
        self.assertFalse(out.ok)
        self.assertEqual(len(Staging.made), 1)
        self.assertFalse(svc.disabled)

    def test_untrusted_results_are_failures(self):
        for mode in ('short', 'wrong-dst'):
            with self.subTest(mode=mode):
                svc = self.service(mode)
                svc.start()
                out = svc.restore(0, 262144, 0)
                self.assertFalse(out.ok, out)
                self.assertIn('KV_RESULT', out.reason)
                svc.close()

    def test_timeout_kills_the_worker(self):
        svc = self.service('hang', go_timeout=1.0, max_restarts=0)
        svc.start()
        pid = Staging.made[0].pid
        t = time.monotonic()
        out = svc.restore(0, 131072, 0)
        self.assertFalse(out.ok)
        self.assertLess(time.monotonic() - t, 15)
        self.assertTrue(svc.disabled)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_worker_exit_is_a_failure(self):
        svc = self.service('exit-on-go')
        svc.start()
        self.assertFalse(svc.restore(0, 131072, 0).ok)
        self.assertEqual(svc.stats['restarts'], 1)

    def test_disabled_after_the_restart_budget(self):
        svc = self.service('fail-started', max_restarts=0)
        svc.start()
        self.assertFalse(svc.restore(0, 131072, 0).ok)
        self.assertTrue(svc.disabled)
        out = svc.restore(0, 131072, 0)
        self.assertFalse(out.ok)
        self.assertEqual(out.reason, 'disabled')
        self.assertEqual(len(self.gos()), 1, 'no GO once disabled')

    def test_setup_refusals(self):
        for mode, overrides in (('bad-ready', {}), ('error-ready', {}), ('ok', {'group_bytes': 65536}),
                                ('ok', {'pool_bytes': POOL * 2})):
            with self.subTest(mode=mode, overrides=overrides):
                svc = self.service(mode, **overrides)
                with self.assertRaises(kr.RestoreError):
                    svc.start()
                self.assertEqual(Staging.made, [])

    def test_retained_session_keeps_its_staging(self):
        svc = self.service('retained')
        svc.start()
        byes = svc.close()
        self.assertTrue(byes[-1]['retained'])
        self.assertFalse(Staging.made[0].released, 'DMA ownership unknown: keep the mapping')
        self.assertEqual(svc.stats['retained'], 1)


if __name__ == '__main__':
    unittest.main()

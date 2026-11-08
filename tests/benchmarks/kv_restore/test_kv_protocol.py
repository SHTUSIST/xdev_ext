#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Worker line protocol shared by the three restore arms.

A worker prints KV_READY after setup, answers each GO line with exactly one
KV_RESULT (or KV_ERROR), and QUIT with KV_BYE. The orchestrator must refuse
anything else rather than guess, and must not hang on a silent worker.
"""
import importlib.util
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_protocol', HERE / 'kv_protocol.py')
kp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kp)

FAKE = textwrap.dedent('''
    import json, sys, time
    mode = sys.argv[1]
    if mode == 'silent':
        time.sleep(30)
    if mode == 'setup-error':
        print('KV_ERROR {"where": "setup", "error": -19, "strerror": "No such device"}', flush=True)
        sys.exit(1)
    print('KV_READY {"role": "fake", "dry_run": true}', flush=True)
    for line in sys.stdin:
        if line.startswith('QUIT'):
            print('KV_BYE {"error": 0, "retained": false, "restores": 1}', flush=True)
            break
        fields = dict(f.split('=', 1) for f in line.split()[1:])
        if mode == 'garbage':
            print('hello', flush=True)
        elif mode == 'hang':
            time.sleep(30)
        else:
            print('noise on stdout is ignored only if it is a log line', file=sys.stderr, flush=True)
            print('KV_RESULT ' + json.dumps({'run': fields['run'], 'ok': True, 'error': 0,
                  'bytes': int(fields['bytes']), 't0_ns': 5, 't1_ns': 105, 'latency_ns': 100,
                  'verified': None}), flush=True)
''')


class Lines(unittest.TestCase):
    def test_go_line_is_key_value(self):
        line = kp.go_line(run='r-1', ordinal=3, object_slba=2048, bytes=1 << 20, dst_frame0=0,
                          seed=7, verify=True)
        self.assertEqual(line, 'GO run=r-1 ordinal=3 object_slba=2048 bytes=1048576 '
                               'dst_frame0=0 seed=7 verify=1\n')
        for bad in ('', 'a b', 'x' * 65, 'é', 'a=b'):
            with self.subTest(run=bad), self.assertRaises(kp.ProtocolError):
                kp.go_line(run=bad, ordinal=1, object_slba=0, bytes=1, dst_frame0=0)
        with self.assertRaises(kp.ProtocolError):
            kp.go_line(run='r', ordinal=0, object_slba=0, bytes=1, dst_frame0=0)

    def test_prefix_go_line(self):
        h = 'ab' * 32
        self.assertEqual(kp.prefix_go_line('r-2', 4, h, 7, verify=True),
                         f'GO run=r-2 ordinal=4 prefix={h} dst_frame0=7 seed=0 verify=1\n')
        for bad in ('AB' * 32, 'ab' * 31, 'xyz', None):
            with self.subTest(bad=bad), self.assertRaises(kp.ProtocolError):
                kp.prefix_go_line('r', 1, bad, 0)
        with self.assertRaises(kp.ProtocolError):
            kp.prefix_go_line('r', 0, h, 0)

    def test_parse_known_kinds_only(self):
        kind, body = kp.parse_line('KV_READY {"role": "restore"}')
        self.assertEqual((kind, body['role']), ('KV_READY', 'restore'))
        for bad in ('KV_RESULT', 'KV_RESULT [1]', 'KV_OTHER {}', 'KV_RESULT {"a": 1, "a": 2}',
                    'KV_RESULT {bad json}', 'random text'):
            with self.subTest(line=bad), self.assertRaises(kp.ProtocolError):
                kp.parse_line(bad)

    def test_result_schema(self):
        good = {'run': 'r', 'ok': True, 'error': 0, 'bytes': 4096, 't0_ns': 1, 't1_ns': 3,
                'latency_ns': 2, 'verified': True}
        self.assertEqual(kp.check_result(good, 'r'), good)
        for why, over in {'other run': {'run': 'x'}, 'ok not bool': {'ok': 1},
                          'negative bytes': {'bytes': -1},
                          'latency mismatch': {'latency_ns': 5},
                          'ok with error': {'error': -5}}.items():
            with self.subTest(why=why), self.assertRaises(kp.ProtocolError):
                kp.check_result(dict(good, **over), 'r')
        failed = dict(good, ok=False, error=-110, bytes=0, latency_ns=0, t0_ns=0, t1_ns=0)
        self.assertFalse(kp.check_result(failed, 'r')['ok'])


class WorkerProcess(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-proto-')
        self.fake = Path(self.tmp.name) / 'fake_worker.py'
        self.fake.write_text(FAKE)

    def tearDown(self):
        self.tmp.cleanup()

    def worker(self, mode, timeout=5.0):
        return kp.Worker([sys.executable, '-I', str(self.fake), mode], ready_timeout=timeout,
                         log=Path(self.tmp.name) / f'{mode}.log')

    def test_round_trip(self):
        w = self.worker('ok')
        self.assertEqual(w.ready['role'], 'fake')
        r = w.go(run='a1', ordinal=1, object_slba=0, bytes=8192, dst_frame0=0, timeout=5)
        self.assertTrue(r['ok'])
        self.assertEqual(r['bytes'], 8192)
        bye = w.quit(timeout=5)
        self.assertEqual(bye['error'], 0)
        self.assertEqual(w.returncode, 0)
        self.assertIn('noise on stdout', (Path(self.tmp.name) / 'ok.log').read_text())

    def test_setup_error_is_reported_not_ready(self):
        with self.assertRaises(kp.WorkerError) as e:
            self.worker('setup-error')
        self.assertIn('No such device', str(e.exception))

    def test_silent_worker_times_out_and_is_killed(self):
        with self.assertRaises(kp.WorkerError):
            self.worker('silent', timeout=0.5)

    def test_garbage_and_hang_fail_the_run(self):
        w = self.worker('garbage')
        with self.assertRaises(kp.ProtocolError):
            w.go(run='a1', ordinal=1, object_slba=0, bytes=1, dst_frame0=0, timeout=5)
        w.kill()
        w = self.worker('hang')
        with self.assertRaises(kp.WorkerError):
            w.go(run='a1', ordinal=1, object_slba=0, bytes=1, dst_frame0=0, timeout=0.5)
        w.kill()
        self.assertIsNotNone(w.returncode)



# A deliberately untrusted external worker. The production Worker object and
# subprocess/line protocol are real; only the peer result is controlled here.
TUPLE_WORKER = textwrap.dedent('''
    import json, sys
    print('KV_READY {"role":"restore"}', flush=True)
    for line in sys.stdin:
        if line.startswith('QUIT'):
            print('KV_BYE {"error":0}', flush=True)
            break
        f = dict(x.split('=', 1) for x in line.split()[1:])
        request_ordinal = int(f['ordinal'])
        reported_ordinal = 999 if sys.argv[1] == 'wrong' else request_ordinal
        host1 = 'DONE run=' + f['run'] + ' ok=1 err=0'
        if sys.argv[1] != 'legacy':
            host1 += ' ordinal=' + str(reported_ordinal) + ' first_seq=16 groups=1'
        body = dict(run=f['run'], ok=True, error=0, bytes=4096,
                    t0_ns=1, t1_ns=2, latency_ns=1, host1=host1,
                    ordinal=reported_ordinal, plan=dict(first_seq=16, groups=1, slots=16))
        print('KV_RESULT ' + json.dumps(body), flush=True)
''')


class SenderRequestContext(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-request-context-')
        self.addCleanup(self.tmp.cleanup)
        self.script = Path(self.tmp.name) / 'peer.py'
        self.script.write_text(TUPLE_WORKER)

    def worker(self, mode):
        worker = kp.Worker([sys.executable, self.script, mode], ready_timeout=3)
        self.addCleanup(worker.kill)
        return worker

    def body(self, ordinal):
        return dict(run='r', ok=True, error=0, bytes=4096, t0_ns=1, t1_ns=2,
                    latency_ns=1, ordinal=ordinal,
                    host1=f'DONE run=r ok=1 err=0 ordinal={ordinal} first_seq=16 groups=1',
                    plan=dict(first_seq=16, groups=1, slots=16))

    def test_tuple_without_request_context_is_refused(self):
        # Neither a response ordinal nor first_seq/slots is trusted context.
        with self.assertRaises(kp.ProtocolError):
            kp.check_result(self.body(999), 'r')

    def test_actual_go_rejects_wrong_sender_ordinal(self):
        worker = self.worker('wrong')
        with self.assertRaises(kp.ProtocolError):
            worker.go('r', 1, 2048, 4096, 0, timeout=3)

    def test_actual_prefix_go_rejects_wrong_sender_ordinal(self):
        worker = self.worker('wrong')
        with self.assertRaises(kp.ProtocolError):
            worker.go_prefix('r', 1, 'ab' * 32, 0, timeout=3)

    def test_actual_go_and_prefix_preserve_valid_tuple_and_legacy(self):
        for mode in ('valid', 'legacy'):
            with self.subTest(mode=mode):
                worker = self.worker(mode)
                self.assertTrue(worker.go('r', 1, 2048, 4096, 0, timeout=3)['ok'])
                self.assertTrue(worker.go_prefix('next', 2, 'ab' * 32, 0, timeout=3)['ok'])
                self.assertEqual(worker.quit(3)['error'], 0)

    def test_actual_collect_refuses_tuple_without_context(self):
        worker = self.worker('valid')
        worker.submit(kp.go_line('r', 1, 2048, 4096, 0))
        with self.assertRaises(kp.ProtocolError):
            worker.collect(3)

    def test_actual_collect_checks_explicit_request_context(self):
        for mode in ('valid', 'wrong'):
            with self.subTest(mode=mode):
                worker = self.worker(mode)
                worker.submit(kp.go_line('r', 1, 2048, 4096, 0))
                if mode == 'valid':
                    self.assertTrue(worker.collect(3, run='r', ordinal=1)['ok'])
                else:
                    with self.assertRaises(kp.ProtocolError):
                        worker.collect(3, run='r', ordinal=1)

    def test_actual_collect_legacy_remains_compatible(self):
        worker = self.worker('legacy')
        worker.submit(kp.go_line('r', 1, 2048, 4096, 0))
        self.assertTrue(worker.collect(3)['ok'])


if __name__ == '__main__':
    unittest.main()

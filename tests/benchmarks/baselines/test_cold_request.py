#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real owned HTTP children only; no vLLM, GPU, service deployment or benchmark."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.request
import urllib.error

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cold_request', HERE / 'cold_request.py')
cold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cold)

SERVER = r'''
import argparse, base64, http.server, json, os, pathlib, subprocess, sys, time
p=argparse.ArgumentParser();p.add_argument('serve',nargs='?');p.add_argument('model',nargs='?');p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int);p.add_argument('--log');p.add_argument('--ready');p.add_argument('--cached',type=int,default=0);p.add_argument('--error',action='store_true');p.add_argument('--delay',type=float,default=0);a=p.parse_args()
seen=set()
worker=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
pathlib.Path(a.log+'.pids').write_text(json.dumps([os.getpid(),worker.pid]))
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'healthy')
 def do_POST(self):
  body=self.rfile.read(int(self.headers['Content-Length']))
  with open(a.log,'ab') as f:f.write(base64.b64encode(body)+b'\n')
  cached=1 if body in seen else a.cached;seen.add(body)
  self.send_response(500 if a.error else 200);self.end_headers()
  self.wfile.write(json.dumps({'usage':{'prompt_tokens_details':{'cached_tokens':cached}},'text':'ok'}).encode())
time.sleep(a.delay)
server=http.server.HTTPServer(('127.0.0.1',a.port),Handler)
pathlib.Path(a.ready).write_text('ready')
server.serve_forever()
'''


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class ColdRequest(unittest.TestCase):
    def setUp(self):
        (HERE.parent.parent / 'build').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=HERE.parent.parent / 'build')
        self.base = Path(self.tmp.name)
        self.server = self.base / 'server.py'
        self.server.write_text(SERVER)
        self.log, self.ready = self.base / 'requests', self.base / 'ready'
        self.port = free_port()
        self.body = b'{ "model": "m", "prompt": "unchanged prefix", "max_tokens": 1 }\n'
        self.lock = mock.patch.object(cold, 'LOCK_ROOT', self.base / 'locks')
        self.lock.start()

    def tearDown(self):
        self.lock.stop()
        self.tmp.cleanup()

    def command(self, *extra):
        return [sys.executable, str(self.server), '--port', str(self.port),
                '--log', str(self.log), '--ready', str(self.ready), *extra]

    def request(self, *extra):
        return cold.run_request(self.command(*extra), self.body, self.port,
                                startup_timeout=5, request_timeout=2, cleanup_timeout=1)

    def test_two_identical_requests_use_distinct_fresh_processes(self):
        first = self.request()
        second = self.request()
        self.assertNotEqual(first['owned_pid'], second['owned_pid'])
        self.assertTrue(first['fresh_process'] and second['fresh_process'])
        self.assertEqual(first['reported_cached_tokens'], [0])
        self.assertEqual(second['reported_cached_tokens'], [0])
        self.assertEqual([base64.b64decode(x) for x in self.log.read_bytes().splitlines()],
                         [self.body, self.body])
        self.assertEqual(second['timing_scope'], 'http-full-response')
        self.assertTrue(second['owned_group_cleaned'])

    def test_persistent_fixture_would_cache_the_same_prefix(self):
        child = subprocess.Popen(self.command(), start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while not self.ready.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            values = []
            for _ in range(2):
                request = urllib.request.Request(f'http://127.0.0.1:{self.port}/v1/completions',
                                                 data=self.body)
                with http.open(request) as response:
                    values.append(json.loads(response.read())['usage']['prompt_tokens_details']['cached_tokens'])
            self.assertEqual(values, [0, 1])
        finally:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait(timeout=5)

    def test_startup_is_outside_the_request_timer(self):
        observed = []
        original = time.perf_counter_ns
        def clock():
            observed.append(self.ready.exists())
            return original()
        with mock.patch.object(cold.time, 'perf_counter_ns', clock):
            result = self.request('--delay', '0.2')
        self.assertEqual(observed, [True, True])
        self.assertGreater(result['elapsed_ns'], 0)

    def test_external_listener_is_not_replaced_or_killed(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', self.port)); listener.listen()
            with self.assertRaises(cold.OwnershipError):
                self.request()
            self.assertGreater(listener.fileno(), 0)
            self.assertFalse(Path(str(self.log) + '.pids').exists())

    def test_http_failure_cleans_the_owned_child_group(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('--error')
        self.assertEqual(error.exception.code, 500)
        self.assertTrue(self.log.exists())
        pids = json.loads(Path(str(self.log) + '.pids').read_text())
        for pid in pids:
            path = Path('/proc') / str(pid) / 'stat'
            self.assertTrue(not path.exists() or path.read_text().rsplit(')', 1)[1].split()[0] == 'Z')
        self.assertFalse(cold.listener_inodes(self.port))

    def test_nonzero_cached_tokens_is_rejected(self):
        with self.assertRaises(cold.ColdError):
            self.request('--cached', '1')
        self.assertFalse(cold.listener_inodes(self.port))

    def test_missing_ownership_evidence_refuses_before_launch(self):
        with mock.patch.object(cold, 'listener_inodes', side_effect=cold.OwnershipError('no proc')):
            with self.assertRaises(cold.OwnershipError):
                self.request()
        self.assertFalse(Path(str(self.log) + '.pids').exists())

    def test_unproven_new_listener_is_refused_before_inference(self):
        with mock.patch.object(cold, 'assert_owned_listener', side_effect=cold.OwnershipError('unproven')):
            with self.assertRaises(cold.OwnershipError):
                self.request()
        self.assertFalse(self.log.exists())
        self.assertFalse(cold.listener_inodes(self.port))

    def test_dry_run_does_not_start_a_child(self):
        body = self.base / 'body.json'; body.write_bytes(self.body)
        result = subprocess.run([sys.executable, str(HERE / 'cold_request.py'),
                                 '--port', str(self.port), '--request-file', str(body),
                                 '--server-argv-json', json.dumps(self.command())],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['dry_run'])
        self.assertFalse(Path(str(self.log) + '.pids').exists())

    def test_planner_wiring_executes_the_real_cold_helper(self):
        import shlex
        import test_baselines as t
        binaries = self.base / 'venv-recompute/bin'
        binaries.mkdir(parents=True)
        (binaries / 'python').symlink_to(sys.executable)
        fake_vllm = binaries / 'vllm'
        fake_vllm.write_text('#!/bin/sh\nexec ' + shlex.join([
            sys.executable, str(self.server), '--log', str(self.log), '--ready', str(self.ready)])
            + ' "$@"\n')
        fake_vllm.chmod(0o755)
        rig = t.bp.Rig(**dict(t.RIG, workdir=str(self.base)))
        plan = t.bp.build('recompute', rig, t.MODEL, cold_port=self.port)
        def executor(host, command, stdin=None):
            result = subprocess.run(['bash', '-c', command], input=stdin,
                                    capture_output=True, text=True, timeout=10)
            return result.returncode, result.stdout + result.stderr
        state = t.bp.execute(plan, ['up', 'check'], executor)
        self.assertTrue(state['cold_request']['fresh_process'])
        self.assertTrue(state['cold_request']['owned_group_cleaned'])
        self.assertFalse(state['qualifies_long_running_measurements'])
        self.assertEqual(state['pids'], {})
        sent = base64.b64decode(self.log.read_bytes().strip())
        self.assertEqual(sent, t.bp.smoke_body(t.MODEL).encode())


if __name__ == '__main__':
    (HERE.parent.parent / 'build').mkdir(exist_ok=True)
    unittest.main(verbosity=2)

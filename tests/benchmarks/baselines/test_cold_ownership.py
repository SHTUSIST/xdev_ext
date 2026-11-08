#!/usr/bin/env python3
"""Connection ownership and cancellation: real owned loopback/subprocesses only."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'cold_request.py'
spec = importlib.util.spec_from_file_location('review_cold', SOURCE)
cold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cold)

SERVER = r'''
import http.server,json,os,pathlib,signal,sys,time
port=int(sys.argv[1]);mode=sys.argv[2];base=pathlib.Path(sys.argv[3]);target=sys.argv[4]
base.joinpath('pid').write_text(str(os.getpid()))
if mode=='ignore-term':signal.signal(signal.SIGTERM,signal.SIG_IGN)
class H(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  if mode=='health-redirect':
   self.send_response(303);self.send_header('Location',target);self.end_headers();return
  self.send_response(200);self.end_headers();self.wfile.write(b'healthy')
 def do_POST(self):
  body=self.rfile.read(int(self.headers.get('Content-Length','0')))
  base.joinpath('body').write_bytes(body)
  if mode=='redirect':
   self.send_response(303);self.send_header('Location',target);self.end_headers();return
  self.send_response(200);self.end_headers();self.wfile.write(json.dumps({'origin':'owned','cached_tokens':0}).encode())
s=http.server.HTTPServer(('127.0.0.1',port),H)
base.joinpath('ready').write_text('ready')
if mode=='handoff':
 s.handle_request()
 while not base.joinpath('release').exists():time.sleep(.005)
 s.server_close();base.joinpath('released').write_text('released')
 while True:time.sleep(1)
else:s.serve_forever()
'''


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Foreign:
    """Foreign to helper, but created/owned by this review process only."""
    def __init__(self, port=0):
        self.requests = []
        outer = self
        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def reply(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                outer.requests.append((self.command, self.path, body))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"origin":"foreign","cached_tokens":0}')
            do_GET = do_POST = reply
        self.server = HTTPServer(('127.0.0.1', port), H)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class ConnectionOwnership(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.base = Path(self.tmp.name)
        self.server = self.base / 'server.py'
        self.server.write_text(SERVER)
        self.port = free_port()
        self.body = b'{ "prompt": "same bytes", "max_tokens": 1 }\n'
        self.lock = mock.patch.object(cold, 'LOCK_ROOT', self.base / 'locks')
        self.lock.start()
        self.foreign = None

    def tearDown(self):
        if self.foreign:
            self.foreign.close()
        self.lock.stop()
        self.tmp.cleanup()

    def run_cold(self, mode='normal', target=''):
        return cold.run_request([sys.executable, str(self.server), str(self.port), mode,
                                 str(self.base), target], self.body, self.port,
                                startup_timeout=3, request_timeout=2, cleanup_timeout=.2)

    def assert_child_stopped(self):
        pid = int((self.base / 'pid').read_text())
        self.assertFalse(Path('/proc', str(pid)).exists())
        self.assertFalse(cold.listener_inodes(self.port))

    def test_ignore_term_requires_kill_but_is_reaped(self):
        result = self.run_cold('ignore-term')
        self.assertTrue(result['owned_group_cleaned'])
        self.assert_child_stopped()

    def test_inherited_http_proxy_is_bypassed(self):
        env = {'http_proxy':'http://127.0.0.1:1', 'HTTP_PROXY':'http://127.0.0.1:1',
               'https_proxy':'http://127.0.0.1:1', 'ALL_PROXY':'http://127.0.0.1:1',
               'no_proxy':'', 'NO_PROXY':''}
        with mock.patch.dict(os.environ, env):
            result = self.run_cold()
        self.assertEqual(result['response']['origin'], 'owned')
        self.assertEqual((self.base / 'body').read_bytes(), self.body)
        self.assert_child_stopped()

    def test_early_child_exit_is_reaped(self):
        with self.assertRaises(cold.ColdError):
            cold.run_request([sys.executable, '-c', 'raise SystemExit(3)'], self.body,
                             self.port, startup_timeout=1, request_timeout=1, cleanup_timeout=.2)
        self.assertFalse(cold.listener_inodes(self.port))

    def test_helper_sigterm_must_not_leave_the_service_running(self):
        # Only signal actively created objects. Pin the owned server with pidfd
        # before stopping the helper; final cleanup never trusts a stale PID.
        launcher = self.base / 'helper.py'
        launcher.write_text('import importlib.util,sys\n'
                            + 's=importlib.util.spec_from_file_location("c",' + repr(str(SOURCE)) + ')\n'
                            + 'c=importlib.util.module_from_spec(s);s.loader.exec_module(c)\n'
                            + 'from pathlib import Path\nc.LOCK_ROOT=Path(' + repr(str(self.base / 'locks')) + ')\n'
                            + 'raise SystemExit(c.main(sys.argv[1:]))\n')
        # Never-ready service keeps the helper inside its finally-protected try.
        service = self.base / 'waiting.py'
        service.write_text('import os,pathlib,time\npathlib.Path(' + repr(str(self.base / 'pid'))
                           + ').write_text(str(os.getpid()))\ntime.sleep(30)\n')
        body = self.base / 'request.json'
        body.write_bytes(self.body)
        helper = subprocess.Popen([sys.executable, str(launcher), '--execute', '--port', str(self.port),
                                   '--request-file', str(body), '--server-argv-json',
                                   json.dumps([sys.executable, str(service)])],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        pidfd = None
        try:
            deadline = time.monotonic() + 3
            while not (self.base / 'pid').exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.005)
            pid = int((self.base / 'pid').read_text())
            pidfd = os.pidfd_open(pid)
            helper.terminate()
            helper.communicate(timeout=3)
            alive = True
            deadline = time.monotonic() + .5
            while time.monotonic() < deadline:
                p = Path('/proc', str(pid), 'stat')
                alive = p.exists() and p.read_text().rsplit(')', 1)[1].split()[0] != 'Z'
                if not alive:
                    break
                time.sleep(.01)
            print('HELPER_SIGTERM', json.dumps({'helper_exit':helper.returncode,
                                                'owned_service_alive':alive}), flush=True)
            self.assertFalse(alive, 'SIGTERM bypasses finally and leaves the owned service running')
            self.assertEqual(helper.returncode, 143)
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.communicate(timeout=3)
            if pidfd is not None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(pidfd)

    def test_redirect_must_not_qualify_foreign_response(self):
        self.foreign = Foreign()
        try:
            result = self.run_cold('redirect', f'http://127.0.0.1:{self.foreign.port}/foreign')
        except Exception:
            self.assertEqual(self.foreign.requests, [])
        else:
            print('REDIRECT_FALSE_QUALIFICATION', json.dumps(result),
                  'foreign_requests=', repr(self.foreign.requests), flush=True)
            self.fail('fresh_process accepted a redirected foreign response; POST changed to GET')
        self.assert_child_stopped()

    def test_health_redirect_sends_no_request_to_foreign_server(self):
        self.foreign = Foreign()
        with self.assertRaises(cold.ColdError):
            self.run_cold('health-redirect', f'http://127.0.0.1:{self.foreign.port}/health')
        self.assertEqual(self.foreign.requests, [])
        self.assertFalse((self.base / 'body').exists())
        self.assert_child_stopped()

    def test_missing_connected_peer_evidence_closes_socket_without_post(self):
        real_proof = cold.assert_owned_connection
        real_read = Path.read_text

        def unreadable(path, *args, **kwargs):
            if path == Path('/proc/net/tcp'):
                raise PermissionError('fixture: connected TCP evidence unreadable')
            return real_read(path, *args, **kwargs)

        def proof(child, sock, timeout):
            with mock.patch.object(Path, 'read_text', unreadable):
                return real_proof(child, sock, timeout)
        with mock.patch.object(cold, 'assert_owned_connection', proof):
            with self.assertRaises(cold.OwnershipError):
                self.run_cold()
        self.assertFalse((self.base / 'body').exists())
        self.assert_child_stopped()

    def run_signal_edge(self, edge):
        launcher = self.base / 'signal-edge.py'
        server = [sys.executable, str(self.server), str(self.port), 'normal', str(self.base), '']
        request = self.base / 'request.json'
        request.write_bytes(self.body)
        # Only signals this freshly launched helper and its held Popen object.
        launcher.write_text('import importlib.util,os,signal,sys,time\n'
                           'from pathlib import Path\n'
                           's=importlib.util.spec_from_file_location("c",' + repr(str(SOURCE)) + ')\n'
                           'c=importlib.util.module_from_spec(s);s.loader.exec_module(c)\n'
                           'c.LOCK_ROOT=Path(' + repr(str(self.base / 'locks')) + ')\n'
                           'edge=' + repr(edge) + '\n'
                           'real_spawn=c.subprocess.Popen\nreal_cleanup=c.cleanup\n'
                           'def await_pin():\n'
                           ' deadline=time.monotonic()+3\n'
                           ' while not Path(' + repr(str(self.base / 'pinned')) + ').exists():\n'
                           '  assert time.monotonic()<deadline;time.sleep(.005)\n'
                           'def spawn(*a,**kw):\n'
                           ' child=real_spawn(*a,**kw)\n'
                           ' if edge=="spawn":\n'
                           '  deadline=time.monotonic()+2\n'
                           '  while not Path(' + repr(str(self.base / 'pid')) + ').exists():\n'
                           '   assert time.monotonic()<deadline;time.sleep(.005)\n'
                           '  await_pin()\n'
                           '  os.kill(os.getpid(),signal.SIGTERM)\n'
                           ' return child\n'
                           'def cleanup(child,timeout):\n'
                           ' if edge=="cleanup":\n'
                           '  await_pin()\n'
                           '  os.kill(os.getpid(),signal.SIGTERM)\n'
                           '  os.kill(os.getpid(),signal.SIGTERM)\n'
                           ' return real_cleanup(child,timeout)\n'
                           'c.subprocess.Popen=spawn\nc.cleanup=cleanup\n'
                           'raise SystemExit(c.main(sys.argv[1:]))\n')
        helper = subprocess.Popen([sys.executable, str(launcher), '--execute', '--port',
                                   str(self.port), '--request-file', str(request),
                                   '--server-argv-json', json.dumps(server)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pidfd = None
        try:
            deadline = time.monotonic() + 3
            while not (self.base / 'pid').exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.005)
            # The held Popen stays unreaped behind await_pin until this handle
            # exists. Never acquire/signals a possibly reused PID after cleanup.
            pidfd = os.pidfd_open(int((self.base / 'pid').read_text()))
            (self.base / 'pinned').touch()
            out, err = helper.communicate(timeout=5)
            self.assertEqual(helper.returncode, 143, (out, err))
            self.assert_child_stopped()
        finally:
            if helper.poll() is None:
                helper.kill();helper.communicate(timeout=3)
            if pidfd is not None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(pidfd)

    def test_term_after_popen_returns_before_child_assignment(self):
        self.run_signal_edge('spawn')

    def test_term_during_normal_cleanup_cannot_interrupt_or_reenter_it(self):
        self.run_signal_edge('cleanup')

    def test_verified_connection_cannot_automatically_reconnect_before_post(self):
        request = cold.http.client.HTTPConnection.request

        def lose_connection(connection, method, *args, **kwargs):
            if method == 'POST':
                connection.close()
            return request(connection, method, *args, **kwargs)
        with mock.patch.object(cold.http.client.HTTPConnection, 'request', lose_connection):
            with self.assertRaises(cold.http.client.NotConnected):
                self.run_cold()
        self.assertFalse((self.base / 'body').exists())
        self.assert_child_stopped()

    def test_redirect_response_socket_closes_before_owned_group_cleanup(self):
        cleanup = cold.cleanup
        checked = []

        def inspect_then_cleanup(child, timeout):
            try:
                inodes = set()
                for fd in Path('/proc/self/fd').iterdir():
                    try:
                        target = os.readlink(fd)
                    except FileNotFoundError:
                        continue
                    if target.startswith('socket:['):
                        inodes.add(target[8:-1])
                leftovers = []
                for row in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                    fields = row.split()
                    if int(fields[2].rsplit(':', 1)[1], 16) == self.port and fields[9] in inodes:
                        leftovers.append(fields[3])
                checked.append(True)
                self.assertEqual(leftovers, [], 'HTTP response still holds a client socket FD')
            finally:
                cleanup(child, timeout)
            return True

        with mock.patch.object(cold, 'cleanup', inspect_then_cleanup):
            with self.assertRaises(cold.ColdError):
                self.run_cold('redirect', 'http://127.0.0.1:1/refused')
        self.assertEqual(checked, [True])
        self.assert_child_stopped()

    def test_last_ownership_snapshot_does_not_pin_request_peer(self):
        original = cold.assert_owned_listener
        calls = 0
        def interleave(child, port):
            nonlocal calls
            original(child, port)
            calls += 1
            if calls == 2:
                (self.base / 'release').touch()
                deadline = time.monotonic() + 2
                while not (self.base / 'released').exists():
                    if time.monotonic() > deadline:
                        raise RuntimeError('review fixture failed to release owned listener')
                    time.sleep(.005)
                self.foreign = Foreign(port)
        with mock.patch.object(cold, 'assert_owned_listener', interleave):
            try:
                result = self.run_cold('handoff')
            except cold.OwnershipError:
                self.assertEqual(self.foreign.requests, [])
            else:
                print('HANDOFF_FALSE_QUALIFICATION', json.dumps(result),
                      'foreign_requests=', repr(self.foreign.requests), flush=True)
                self.fail('fresh_process accepted an unowned request peer after final real /proc check')


if __name__ == '__main__':
    unittest.main(verbosity=2)

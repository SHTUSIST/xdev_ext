#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual C control plane with explicit session-only boundaries; no devices.

These tests catch accepting arbitrary sender text, per-byte timeout refresh,
blocking an accepted half line past QUIT, or treating malformed DONE as success.
"""
import errno
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

import kv_protocol as kp

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[2] / 'kernel'


class Control(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        given = os.environ.get('KV_CONTROL_BIN')
        if given:
            cls.binary = Path(given)
            cls.tmp = None
            return
        if not shutil.which('cc') or subprocess.run(
                ['pkg-config', '--atleast-version=1.0', 'libbpf'], capture_output=True).returncode:
            raise unittest.SkipTest('actual worker needs libbpf >= 1.0')
        cls.tmp = tempfile.TemporaryDirectory(prefix='kv-control-')
        lib = Path(cls.tmp.name) / 'lib'
        subprocess.run(['make', '-s', '-C', str(KERNEL / 'tools/xdev_ext_mech/lib'),
                        'BUILD_DIR=' + str(lib)], check=True)
        cls.binary = Path(cls.tmp.name) / 'worker-control'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                        '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', '-ffunction-sections', '-fdata-sections',
                        str(HERE / 'worker_control_boundary.c'), str(lib / 'libxdev_ext.a'),
                        '-Wl,--gc-sections', '-Wl,--wrap=send', '-Wl,--wrap=xdev_ext_session_start_frames',
                        '-Wl,--wrap=xdev_ext_session_wait', '-lbpf', '-lelf', '-lz', '-ldl',
                        '-pthread', '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        if cls.tmp:
            cls.tmp.cleanup()

    def go(self, reply, trickle=False):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            client = socket.create_connection(listener.getsockname())
            peer, _ = listener.accept()
        with peer, client:
            p = subprocess.Popen([str(self.binary), 'go', str(client.fileno())],
                                 pass_fds=(client.fileno(),), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
            try:
                peer.settimeout(1)
                self.assertTrue(peer.recv(2048).startswith(b'RESTORE token=5 run=r '))
                if trickle:
                    def slow():
                        try:
                            for b in reply:
                                peer.sendall(bytes([b]))
                                time.sleep(.035)
                        except OSError:
                            pass
                    thread = threading.Thread(target=slow, daemon=True)
                    thread.start()
                else:
                    peer.sendall(reply)
                try:
                    out, err = p.communicate(timeout=1.2)
                except subprocess.TimeoutExpired:
                    self.fail('actual handle_go did not bound the DONE read')
                if trickle:
                    thread.join(2)
                self.assertEqual(p.returncode, 0, out + err)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.communicate()
        rows = [json.loads(x[len('KV_RESULT '):]) for x in out.splitlines()
                if x.startswith('KV_RESULT ')]
        self.assertEqual(len(rows), 1, out)
        return rows[0], out

    def test_valid_legacy_and_correlated_sender(self):
        for line in (b'DONE run=r ok=1 err=0\n',
                     b'DONE run=r ok=1 err=0 ordinal=1 first_seq=16 groups=1 '
                     b'wait_ns=8 done=1 abort=0 sequestered=0 last_err=0\n'):
            with self.subTest(line=line):
                result, _ = self.go(line)
                self.assertTrue(result['ok'], result)
                self.assertEqual(result['bytes'], 4096)

    def test_sender_failure_mismatch_and_malformed_are_not_success(self):
        lines = [b'DONE run=r ok=0 err=-110\n', b'DONE run=other ok=1 err=0\n',
                 b'garbage\n', b'DONE\n', b'DONE run=r ok=1\n',
                 b'DONE run=r ok=1 err=0 err=-5\n', b'DONE run=r run=other ok=1 err=0\n',
                 b'DONE run=r ok=1 err=oops\n', b'DONE run=r ok=2 err=0\n',
                 b'DONE run=r ok=1 err=-5\n', b'DONE run=r ok=1 err=0 extra=x\n',
                 b'DONE run=r ok=1 err=0\x00ignored\n',
                 b'DONE run=r ok=1 err=0 ordinal=2 first_seq=16 groups=1\n',
                 b'DONE run=r ok=1 err=0 ordinal=1 first_seq=17 groups=1\n',
                 b'DONE run=r ok=1 err=0 ordinal=1 first_seq=16 groups=2\n',
                 b'DONE run=r ok=1 err=0 first_seq=16\n',
                 b'DONE run=r ok=1 err=0 wait_ns=18446744073709551616\n',
                 b'DONE run=r ok=1 err=2147483648\n', b'DONE=x run=r ok=1 err=0\n']
        for line in lines:
            with self.subTest(line=line):
                result, out = self.go(line)
                self.assertFalse(result['ok'], result)
                self.assertNotEqual(result['error'], 0)
                self.assertEqual(result['bytes'], 0)
                self.assertIn('CONTROL_STATE dirty=1', out)

    def test_slow_done_obeys_total_deadline(self):
        result, _ = self.go(b'DONE run=r ok=1 err=0\n', trickle=True)
        self.assertFalse(result['ok'], result)
        self.assertEqual(result['error'], -errno.ETIMEDOUT)

    def server(self, timeout_ms=180):
        p = subprocess.Popen([str(self.binary), 'serve', str(timeout_ms)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.finish, p)
        port = int(p.stdout.readline().split()[1])
        s = socket.create_connection(('127.0.0.1', port))
        self.addCleanup(s.close)
        s.settimeout(.8)
        return p, s

    @staticmethod
    def finish(p):
        if p.poll() is None:
            p.kill()
        p.communicate()

    def quit(self, p):
        try:
            out, err = p.communicate('QUIT\n', timeout=.8)
        except subprocess.TimeoutExpired:
            self.fail('serve did not process QUIT during a partial control line')
        self.assertEqual(p.returncode, 0, out + err)
        self.assertIn('CONTROL_RETURN 0', out)
        return out

    def test_quit_during_half_request(self):
        p, s = self.server(timeout_ms=3000)
        s.sendall(b'RESTORE token=5 run=r')
        # Give the old blocking recv loop a chance to consume the half line.
        time.sleep(.04)
        self.quit(p)

    def test_failed_done_send_is_not_reported_as_success(self):
        r = subprocess.run([str(self.binary), 'reply-failure'], capture_output=True,
                           text=True, timeout=1)
        self.assertEqual(r.returncode, 0, r.stderr)
        served = [json.loads(line[len('KV_SERVED '):]) for line in r.stdout.splitlines()
                  if line.startswith('KV_SERVED ')]
        self.assertEqual(len(served), 1)
        self.assertFalse(served[0]['ok'], served)
        self.assertEqual(served[0]['error'], -errno.EPIPE)
        self.assertIn('CONTROL_STATE dirty=1', r.stdout)

    def test_buffered_control_lines_do_not_hide_quit(self):
        p, _ = self.server()
        p.stdin.write('invalid\nQUIT\n')
        p.stdin.flush()
        try:
            p.wait(timeout=.8)
        except subprocess.TimeoutExpired:
            self.fail('buffered invalid control line hid the following QUIT')
        self.assertEqual(p.returncode, 0)

    def test_half_request_expires_and_server_accepts_again(self):
        p, s = self.server()
        address = s.getpeername()
        s.sendall(b'RESTORE token=5')
        try:
            data = s.recv(1)
        except TimeoutError:
            self.fail('accepted half line outlived its total deadline')
        self.assertEqual(data, b'', 'accepted half line must expire')
        with socket.create_connection(address) as another:
            another.settimeout(.8)
            another.sendall(b'RESTORE token=5 run=r ordinal=1 object_slba=2048 bytes=4096 '
                            b'first_seq=16 groups=1\n')
            self.assertTrue(another.recv(1024).startswith(b'DONE run=r ok=1 err=0 '))
        self.quit(p)

    def test_real_serve_request_emits_correlated_done(self):
        p, s = self.server()
        s.sendall(b'RESTORE token=5 run=r ordinal=1 object_slba=2048 bytes=4096 '
                  b'first_seq=16 groups=1\n')
        reply = bytearray()
        while not reply.endswith(b'\n'):
            reply.extend(s.recv(1024))
        fields = dict(x.split('=', 1) for x in reply.decode().split()[1:])
        self.assertEqual(fields['run'], 'r')
        self.assertEqual(fields['ok'], '1')
        self.assertEqual(fields.get('ordinal'), '1')
        self.assertEqual(fields.get('first_seq'), '16')
        self.assertEqual(fields.get('groups'), '1')
        self.quit(p)


class Downstream(unittest.TestCase):
    def body(self, text):
        return dict(run='r', role='restore', ok=True, error=0, bytes=4096,
                    t0_ns=1, t1_ns=2, latency_ns=1, host1=text)

    def test_good_sender_is_accepted(self):
        self.assertTrue(kp.check_result(self.body('DONE run=r ok=1 err=0'), 'r')['ok'])

    def test_original_negative_sender_results_are_rejected(self):
        for text in ('DONE run=r ok=0 err=-110', 'DONE run=other ok=1 err=0', 'garbage'):
            with self.subTest(text=text), self.assertRaises(kp.ProtocolError):
                kp.check_result(self.body(text), 'r')


if __name__ == '__main__':
    unittest.main(verbosity=2)

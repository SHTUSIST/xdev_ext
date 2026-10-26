#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent C2 action execution tests using actual harmless framed children."""
import copy
import importlib
import json
import os
import secrets
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
IDENTITY = dict(version=1, run_id="c2-action", sha="a" * 40, role="tx",
                case="cable-loss", direction="a-to-b", epoch=4, request_id=9)
# A controlled boundary executable, not a physical action emulator. It executes
# a harmless real primitive, then emits raw pipe receipts or deliberate errors.
HELPER = r'''
import json, os, pathlib, struct, subprocess, sys, time
mode, root, literal = sys.argv[1:]
root = pathlib.Path(root)
count = root / 'invocations'
count.write_text(str(int(count.read_text()) + 1) if count.exists() else '1')
(root / 'helper.pid').write_text(str(os.getpid()))
size = struct.unpack('!I', sys.stdin.buffer.read(4))[0]
c = json.loads(sys.stdin.buffer.read(size))
(root / 'challenge.json').write_text(json.dumps(c))
if mode == 'timeout':
    time.sleep(1)
    sys.exit(0)
if mode == 'oversized':
    sys.stdout.buffer.write(struct.pack('!I', 1024 * 1024 + 1))
    sys.stdout.buffer.flush()
    sys.exit(0)
started = time.monotonic_ns()
primitive_argv = [sys.executable, '-c', 'import sys; print(sys.argv[1])', literal]
p = subprocess.run(primitive_argv, capture_output=True)
(root / 'primitive.stdout').write_bytes(p.stdout)
(root / 'primitive.stderr').write_bytes(p.stderr)
(root / 'operator-event.raw').write_text(c['action_id'] + ': fixture operator acknowledgement')
r = dict(version=1, action_id=c['action_id'], identity=c['identity'], kind=c['kind'],
         target=c['target'], barrier=c['barrier'], attempted=True, completed=True,
         error=0, started_monotonic_ns=started, finished_monotonic_ns=time.monotonic_ns(),
         evidence=dict(argv=primitive_argv, returncode=p.returncode,
         stdout_path=str(root / 'primitive.stdout'), stderr_path=str(root / 'primitive.stderr'),
         operator_event=dict(action_id=c['action_id'], raw_path=str(root / 'operator-event.raw'),
                             observed_monotonic_ns=started)))
if mode == 'nonce': r['action_id'] = '0' * 64
if mode == 'role': r['identity'] = dict(r['identity'], role='rx')
if mode == 'epoch': r['identity'] = dict(r['identity'], epoch=99)
if mode == 'boot': r['target'] = dict(r['target'], boot_id='old-boot')
if mode == 'barrier': r['barrier'] = dict(r['barrier'], ticket=999)
if mode == 'deadline': r['finished_monotonic_ns'] = c['deadline_monotonic_ns'] + 1
if mode == 'error': r['error'] = -5
if mode == 'notattempted': r['attempted'] = False
if mode == 'notcompleted': r['completed'] = False
if mode == 'missingraw': r['evidence'] = {'operator_event': True}
b = json.dumps(r, separators=(',', ':')).encode()
f = struct.pack('!I', len(b)) + b
sys.stdout.buffer.write(f)
if mode == 'duplicate': sys.stdout.buffer.write(f)
if mode == 'trailing': sys.stdout.buffer.write(b'x')
sys.stdout.buffer.flush()
sys.stderr.write('actual-helper-stderr\n')
if mode == 'nonzero': sys.exit(7)
'''


class ActionProviderTests(unittest.TestCase):
    def setUp(self):
        try:
            self.module = importlib.import_module("action_provider")
        except ModuleNotFoundError:
            self.fail("C2 action_provider implementation is absent (frozen-API RED)")
        self.tmp = tempfile.TemporaryDirectory(prefix="c2-action-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.helper = self.root / "helper.py"
        self.helper.write_text(HELPER)
        now = time.monotonic_ns()
        self.challenge = dict(
            version=1, action_id=secrets.token_hex(32), identity=copy.deepcopy(IDENTITY),
            kind="cable-loss", target=dict(boot_id="current-boot",
            nhi_bdf="0000:04:00.0", link_token=71, local_inc=81, remote_inc=82,
            clock_domain="current-boot:CLOCK_MONOTONIC"),
            barrier=dict(native_accepted=True, inflight=1, session_id=101,
            batch_id=901, group=17, acceptance_seq=1, local_inc=81, remote_inc=82,
            identity=copy.deepcopy(IDENTITY), batch_key=40, stage=0, ticket=90,
            boot_id="current-boot", clock_domain="current-boot:CLOCK_MONOTONIC",
            accepted_monotonic_ns=now - 2000000, observed_monotonic_ns=now - 1000000,
            raw_path=str(self.root / "native.raw")), deadline_monotonic_ns=now + 2000000000)
        (self.root / "native.raw").write_text("fixture scoped native ledger\n")

    def invoke(self, mode="ok", timeout_ms=1000, literal="primitive-actually-ran"):
        if getattr(self, "calls", 0):
            self.challenge["action_id"] = secrets.token_hex(32)
        self.calls = getattr(self, "calls", 0) + 1
        provider = dict(argv=[sys.executable, str(self.helper), mode, str(self.root), literal],
                        timeout_ms=timeout_ms)
        return self.module.execute_action(self.challenge, provider, evidence_dir=str(self.root))

    def test_one_actual_framed_helper_receipt_and_primitive_raw_logs(self):
        result = self.invoke()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["execution"]["ack_count"], 1)
        self.assertEqual(result["execution"]["returncode"], 0)
        self.assertEqual(result["receipt"]["action_id"], self.challenge["action_id"])
        self.assertEqual((self.root / "primitive.stdout").read_bytes(), b"primitive-actually-ran\n")
        self.assertIn(b"actual-helper-stderr", Path(result["execution"]["stderr_path"]).read_bytes())
        wire = Path(result["execution"]["stdout_path"]).read_bytes()
        size = struct.unpack("!I", wire[:4])[0]
        self.assertEqual(size, len(wire) - 4)
        self.assertEqual(json.loads(wire[4:])["identity"], IDENTITY)
        self.assertNotIn("physical_execution", result)

    def test_shell_metacharacters_remain_literal_argv_data(self):
        forbidden = self.root / "shell-was-executed"
        literal = "; touch " + str(forbidden) + " $(echo expanded) `echo backtick`"
        result = self.invoke(literal=literal)
        self.assertEqual(result["status"], "complete")
        self.assertFalse(forbidden.exists())
        self.assertEqual((self.root / "primitive.stdout").read_text(), literal + "\n")
        self.assertEqual(result["execution"]["argv"][-1], literal)

    def test_duplicate_ack_is_not_accepted_as_one_action(self):
        self.assertEqual(self.invoke("duplicate")["status"], "incomplete")

    def test_trailing_unframed_bytes_reject_receipt(self):
        self.assertEqual(self.invoke("trailing")["status"], "incomplete")

    def test_action_nonce_role_epoch_boot_and_barrier_replay_rejected(self):
        for mode in ("nonce", "role", "epoch", "boot", "barrier"):
            with self.subTest(mode=mode):
                self.assertEqual(self.invoke(mode)["status"], "incomplete")

    def test_deadline_or_primitive_error_cannot_complete(self):
        for mode in ("deadline", "error", "notattempted", "notcompleted"):
            with self.subTest(mode=mode):
                self.assertEqual(self.invoke(mode)["status"], "incomplete")

    def test_successful_json_with_nonzero_real_process_exit_is_incomplete(self):
        result = self.invoke("nonzero")
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["execution"]["returncode"], 7)

    def test_provider_booleans_without_actual_argv_return_and_raw_logs_rejected(self):
        self.assertEqual(self.invoke("missingraw")["status"], "incomplete")

    def test_oversize_frame_is_rejected_without_waiting_for_body(self):
        start = time.monotonic()
        result = self.invoke("oversized")
        self.assertEqual(result["status"], "incomplete")
        self.assertLess(time.monotonic() - start, .8)

    def test_timeout_does_not_kill_or_reap_unknown_action_process(self):
        result = self.invoke("timeout", timeout_ms=250)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["execution"]["timed_out"])
        self.assertIsNone(result["execution"]["returncode"])
        pid = int((self.root / "helper.pid").read_text())
        self.assertTrue(Path("/proc/%d" % pid).exists(), "production killed timed-out helper")
        # Controlled helper exits by itself; no production or test owner is killed.
        time.sleep(1)

    def test_same_action_id_cannot_launch_executor_twice(self):
        self.assertEqual(self.invoke()["status"], "complete")
        provider = dict(argv=[sys.executable, str(self.helper), "ok", str(self.root), "again"],
                        timeout_ms=1000)
        try:
            result = self.module.execute_action(self.challenge, provider, evidence_dir=str(self.root))
        except ValueError:
            pass
        else:
            self.assertEqual(result["status"], "incomplete")
        self.assertEqual((self.root / "invocations").read_text(), "1")

    def test_invalid_provider_does_not_spawn(self):
        for provider in ({"argv": "sh -c true", "timeout_ms": 100},
                         {"argv": [], "timeout_ms": 100},
                         {"argv": [sys.executable], "timeout_ms": True},
                         {"argv": [sys.executable], "timeout_ms": 120001}):
            with self.subTest(provider=provider):
                with self.assertRaises(ValueError):
                    self.module.execute_action(self.challenge, provider, evidence_dir=str(self.root))
        self.assertFalse((self.root / "helper.pid").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)

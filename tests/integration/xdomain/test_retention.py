#!/usr/bin/env python3
"""Real subprocess/signal tests of production supervisor + production guard.

SIGKILL below is deliberately confined to a test-only owner that holds an
eventfd surrogate. It is never a coordinator cleanup path or release proof.
"""
import errno
import fcntl
import json
import os
import pathlib
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
# Shared test-only UAPI-shaped input, never a production expected-value helper.
from test_contract import terminal_stats  # noqa: E402
IDENTITY = dict(version=1, run_id="independent-c", sha="a" * 40,
                role="tx", case="functional-epochs", direction="a-to-b", epoch=3)


def wire(command, request_id=1, deadline=1500):
    payload = dict(mode="single-group", groups=1, first_seq=7, seed=9,
                   gpu_bdf="0000:01:00.0", nvidia_node="/dev/nvidia0",
                   link_token=901, channel=0,
                   geometry=dict(allocation_bytes=65536, group_bytes=4096,
                                 frame_size=65536, seg_len=4096, depth=1,
                                 native_elems=1), flags=0,
                   observer_object="observer.bpf.o", ptx_path="pattern.ptx")
    if command == "cancel":
        payload = {"reason": "test-cancel"}
    body = json.dumps(dict(identity=dict(IDENTITY, request_id=request_id),
                           command=command, deadline_ms=deadline, part_index=0,
                           part_count=1, payload=payload), separators=(",", ":")).encode()
    return struct.pack("!I", len(body)) + body


def verify_part(payload, index, count, deadline=3000, request_id=6, ident=None):
    body = json.dumps(dict(identity=dict(IDENTITY if ident is None else ident, request_id=request_id),
                           command="verify", deadline_ms=deadline, part_index=index,
                           part_count=count, payload=payload), separators=(",", ":")).encode()
    assert len(body) <= 1048576, "fixture frame itself must remain bounded"
    return struct.pack("!I", len(body)) + body


def stop_receipt(role):
    payload = terminal_stats(101 if role == "tx" else 202, 1, stopped=True)
    payload.update(stop_proved=True, first_error=0, stop_error=0)
    return dict(identity=dict(IDENTITY, role=role, request_id=5), command="stop",
                phase="DRAINED_SAFE", fate="SAFE", error=0, held=False,
                cleanup_permissions=1, evidence={}, part_index=0, part_count=1,
                payload=payload)


def eventually(predicate, seconds=4):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("bounded observation deadline expired")


class Retention(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="tb-retention-build-")
        cls.addClassCleanup(cls.build.cleanup)
        build = pathlib.Path(cls.build.name)
        sources = [HERE / "retention_test_owner.cc"]
        # Missing implementation is an honest initial link RED, not a fake guard.
        for name in ("check_contract.c", "agent_supervisor.cc"):
            if (HERE / name).exists():
                sources.append(HERE / name)
        objects = []
        for source in sources:
            obj = build / (source.name + ".o")
            compiler = "gcc" if source.suffix == ".c" else "g++"
            standard = "c11" if compiler == "gcc" else "c++17"
            cmd = [compiler, "-std=" + standard, "-Wall", "-Wextra", "-Werror",
                   "-pthread", "-I", str(HERE), "-c", str(source), "-o", str(obj)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode:
                raise AssertionError("compile RED: " + " ".join(cmd) + "\n" + result.stdout + result.stderr)
            objects.append(str(obj))
        cls.binary = build / "retention-owner"
        cmd = ["g++", "-pthread", *objects, "-o", str(cls.binary)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError("link RED (actual supervisor/guard required): " +
                                 " ".join(cmd) + "\n" + result.stdout + result.stderr)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="tb-retention-surrogate-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = pathlib.Path(self.tmp.name)
        os.chmod(self.directory, 0o700)
        self.ledger = self.directory / "owner-ledger"
        self.release_read, self.release_write = os.pipe()
        self.addCleanup(self._close_release_pipes)
        self.metadata = self._testMethodName.startswith("test_metadata_")
        self.exception = self._testMethodName.startswith("test_exception_")
        self.return_error = self._testMethodName.startswith("test_return_error_")
        self.return_error_new = self._testMethodName.startswith("test_return_error_new_")
        environment = dict(os.environ)
        if self.metadata:
            environment["TB_TEST_VERIFY_MODE"] = "1"
        if self.exception:
            environment["TB_TEST_EXCEPTION_MODE"] = "1"
        if self.return_error:
            environment["TB_TEST_RETURN_ERROR_MODE"] = "new" if self.return_error_new else "acquired"
        self.proc = subprocess.Popen([str(self.binary), str(self.directory),
                                      str(self.ledger), str(self.release_read)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, pass_fds=(self.release_read,), env=environment)
        self.addCleanup(self._cleanup_surrogate)
        os.close(self.release_read)
        self.release_read = -1
        if self.metadata:
            eventually(lambda: "verify_ready" in self.log())
        elif self.return_error:
            message = wire("prepare", deadline=120000)
            if self.return_error_new:
                record = json.loads(message[4:])
                record["command"] = "preflight"
                record["payload"] = {key: record["payload"][key] for key in
                    ("gpu_bdf", "nvidia_node", "link_token", "channel", "geometry", "flags")}
                body = json.dumps(record, separators=(",", ":")).encode()
                message = struct.pack("!I", len(body)) + body
            self.proc.stdin.write(message)
            self.proc.stdin.flush()
            eventually(lambda: "return_error_ready" in self.log())
        elif self.exception:
            # The exception must latch HELD itself, without a later watchdog,
            # disconnect or cancellation masking an unlatched shared guard.
            self.proc.stdin.write(wire("prepare", deadline=120000))
            self.proc.stdin.flush()
            eventually(lambda: "exception_thrown" in self.log())
        else:
            self.proc.stdin.write(wire("prepare"))
            self.proc.stdin.flush()
            eventually(lambda: "owner_blocked" in self.log())
        self.durable = pathlib.Path(next(line.removeprefix("durable=") for line in
                                        self.log().splitlines() if line.startswith("durable=")))

    def _cleanup_surrogate(self):
        # Explicit test harness teardown only. No real GPU/NHI/provider exists.
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=3)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream and not stream.closed:
                stream.close()

    def _close_release_pipes(self):
        for field in ("release_read", "release_write"):
            fd = getattr(self, field)
            if fd >= 0:
                os.close(fd)
                setattr(self, field, -1)

    def log(self):
        return self.ledger.read_text() if self.ledger.exists() else ""

    def terminal(self):
        if not self.durable.exists():
            return None
        rows = []
        for line in self.durable.read_text().splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("phase") == "HELD" or record.get("held") is True:
                rows.append(record)
        return rows[-1] if rows else None

    def assert_retained(self, reason):
        def matching_terminal():
            row = self.terminal()
            return row if row and row.get("hold_reasons", 0) & reason == reason else None
        record = eventually(matching_terminal)
        self.assertIsNone(self.proc.poll(), "HELD owner must remain alive")
        self.assertEqual(record["owner_pid"], self.proc.pid)
        self.assertEqual(record["recovery"], "manual")
        self.assertTrue(record["retained_resources"])
        self.assertEqual(record["hold_reasons"] & reason, reason)
        self.assertEqual(record["cleanup_permissions"], 0)
        self.assertEqual(record["identity"]["run_id"], IDENTITY["run_id"])
        self.assertEqual(record["identity"]["sha"], IDENTITY["sha"])
        self.assertGreater(record["proc_starttime"], 0)
        self.assertTrue(record["boot_id"])
        self.assertEqual(self.durable.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("SUPERVISOR_RETURNED", self.log())
        self.assertNotIn("OWNER_DESTRUCTOR_ENTERED", self.log())
        return record

    def release_late(self, reason):
        before = self.assert_retained(reason)
        os.write(self.release_write, b"R")
        eventually(lambda: "snapshot_permissions=" in self.log())
        log = self.log()
        self.assertIn("late_result=" + str(-errno.ECANCELED), log)
        for name in ("CREATE", "START", "REUSE", "GPU_CLOSE", "EPOCH_CLOSE"):
            self.assertIn("probe_" + name + "=" + str(-errno.EPERM), log)
        self.assertIn("delete=" + str(-errno.EPERM), log)
        self.assertIn("explicit_destructor_retained", log)
        self.assertIn("snapshot_held=1", log)
        self.assertIn("snapshot_permissions=0", log)
        resource_fd = int(next(line.rsplit("=", 1)[1] for line in log.splitlines()
                               if line.startswith("resource_acquired fd=")))
        self.assertTrue(pathlib.Path(f"/proc/{self.proc.pid}/fd/{resource_fd}").exists(),
                        "actual surrogate owner fd must survive refused destructor")
        self.assertNotIn("SIDE_EFFECT_", log)
        self.assertNotIn("\nFREE\n", log)
        self.assertNotIn("\nCONTEXT_DESTROY\n", log)
        after = self.assert_retained(reason)
        self.assertEqual(before["owner_pid"], after["owner_pid"])
        self.assertEqual(before["proc_starttime"], after["proc_starttime"])

    def test_sigterm_during_blocked_gpu_keeps_owner_and_resources(self):
        os.kill(self.proc.pid, signal.SIGTERM)
        self.release_late(1 << 1)

    def test_sighup_during_blocked_gpu_keeps_owner_and_resources(self):
        os.kill(self.proc.pid, signal.SIGHUP)
        self.release_late(1 << 1)

    def test_stdin_eof_without_owner_return_parks(self):
        self.proc.stdin.close()
        self.release_late(1 << 2)

    def test_stdout_closed_watchdog_durable_terminal_survives_epipe(self):
        self.proc.stdout.close()
        self.release_late(1 << 4)
        eventually(lambda: self.terminal()["hold_reasons"] & (1 << 3))
        self.assert_retained((1 << 4) | (1 << 3))

    def test_watchdog_then_late_success_cannot_create_start_reuse_or_destroy(self):
        self.release_late(1 << 4)

    def test_repeated_cancel_sticky_no_owner_dispatch_or_cleanup(self):
        for number in (2, 3):
            self.proc.stdin.write(wire("cancel", number))
            self.proc.stdin.flush()
        self.release_late(1)
        self.assertNotIn("command=cancel", self.log())

    def test_output_backpressure_does_not_block_signal_or_watchdog(self):
        # No protocol reads. Repeated cancels can fill bounded output buffers.
        fcntl.fcntl(self.proc.stdout.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        os.set_blocking(self.proc.stdin.fileno(), False)
        number = 2
        pending = b""
        until = time.monotonic() + 0.4
        while time.monotonic() < until:
            if not pending:
                pending = wire("cancel", number)
                number += 1
            try:
                count = os.write(self.proc.stdin.fileno(), pending)
                pending = pending[count:]
            except BlockingIOError:
                time.sleep(0.001)
        # We deliberately do not finish a pending write after sending signal.
        # Neither queue saturation nor a partial input may suppress signalfd.
        os.kill(self.proc.pid, signal.SIGHUP)
        self.release_late(1 << 1)

    def metadata_begin(self, count=20, extent_count=18000, deadline=3000):
        first = verify_part(dict(kind="begin", launch_cookie=42, extent_count=extent_count,
                                 stop_receipts=[stop_receipt("tx"), stop_receipt("rx")]),
                            0, count, deadline=deadline)
        self.proc.stdin.write(first)
        self.proc.stdin.flush()

    def metadata_extents(self, first=0, count=20, index=1, deadline=3000):
        return verify_part(dict(kind="extents", first_extent=first, extents=[
            dict(dst_off=i * 4096, src_off=i * 4096, len=4096,
                 seed=18446744073709551615, kind=1, reserved=0)
            for i in range(first, first + 1000)]), index, count, deadline=deadline)

    def test_metadata_over_one_mib_assembled_once_only_after_end(self):
        self.metadata_begin()
        total_bytes = 0
        for index in range(1, 19):
            part = self.metadata_extents(first=(index - 1) * 1000, index=index)
            total_bytes += len(part) - 4
            self.proc.stdin.write(part)
            self.proc.stdin.flush()
            self.assertNotIn("verify_executed", self.log())
        self.assertGreater(total_bytes, 1048576)
        self.proc.stdin.write(verify_part(dict(kind="end", extent_count=18000), 19, 20))
        self.proc.stdin.flush()
        eventually(lambda: "verify_executed" in self.log())
        self.assertEqual(self.log().count("verify_executed"), 1)
        length = int(next(line.split("=", 1)[1] for line in self.log().splitlines()
                          if line.startswith("verify_metadata_bytes=")))
        self.assertGreater(length, 1048576)

    def test_metadata_interpart_eof_does_not_dispatch_owner_or_verify(self):
        self.metadata_begin()
        self.proc.stdin.write(self.metadata_extents())
        self.proc.stdin.flush()
        self.proc.stdin.close()
        self.assert_retained(1 << 2)
        self.assertNotIn("command=verify", self.log())

    def test_metadata_duplicate_index_rejected_without_launch(self):
        self.metadata_begin()
        for _ in range(2):
            self.proc.stdin.write(self.metadata_extents())
            self.proc.stdin.flush()
        self.assert_retained(1 << 8)
        self.assertNotIn("command=verify", self.log())

    def test_metadata_no_end_never_launches_and_deadline_not_reset(self):
        started = time.monotonic()
        self.metadata_begin(deadline=1000)
        time.sleep(0.7)
        self.proc.stdin.write(self.metadata_extents(deadline=1000))
        self.proc.stdin.flush()
        eventually(self.terminal, seconds=0.6)
        self.assertLess(time.monotonic() - started, 1.35)
        self.assert_retained(1 << 4)
        self.assertNotIn("command=verify", self.log())

    def test_metadata_wrong_identity_part_cannot_complete_original_request(self):
        self.metadata_begin()
        changed = dict(IDENTITY, epoch=4)
        self.proc.stdin.write(verify_part(dict(kind="end", extent_count=18000),
                                          19, 20, ident=changed))
        self.proc.stdin.flush()
        self.assert_retained(1 << 8)
        self.assertNotIn("command=verify", self.log())

    def test_exception_after_actual_acquire_latches_guard_and_retains_authority(self):
        # Wait for the real supervisor's exception response, not an arbitrary
        # delay; no OwnerResult was returned by this execute invocation.
        ready, _, _ = select.select([self.proc.stdout], [], [], 3)
        self.assertTrue(ready, "supervisor must publish the failed owner result")
        prefix = os.read(self.proc.stdout.fileno(), 4)
        self.assertEqual(len(prefix), 4)
        length = struct.unpack("!I", prefix)[0]
        self.assertGreater(length, 0)
        self.assertLessEqual(length, 1048576)
        body = b""
        while len(body) < length:
            ready, _, _ = select.select([self.proc.stdout], [], [], 3)
            self.assertTrue(ready, "bounded exception response must complete")
            chunk = os.read(self.proc.stdout.fileno(), length - len(body))
            self.assertTrue(chunk)
            body += chunk
        response = json.loads(body)
        os.write(self.release_write, b"R")
        eventually(lambda: "exception_probe_complete" in self.log())
        log = self.log()
        self.assertIn("snapshot_held=1", log,
                      "wire HELD alone cannot retain actual guard authority")
        reasons = int(next(line.split("=", 1)[1] for line in log.splitlines()
                           if line.startswith("snapshot_reasons=")))
        self.assertEqual(reasons & (1 << 8), 1 << 8)
        self.assertIn("snapshot_permissions=0", log)
        for name in ("CREATE", "START", "REUSE", "GPU_CLOSE", "EPOCH_CLOSE", "CONTROL"):
            self.assertIn("probe_" + name + "=" + str(-errno.EPERM), log)
        self.assertNotIn("SIDE_EFFECT_", log)
        self.assertTrue(response["held"])
        self.assertEqual(response["phase"], "HELD")
        self.assertEqual(response["cleanup_permissions"], 0)
        self.assertNotEqual(response["error"], 0)
        record = self.assert_retained(1 << 8)
        resource_fd = int(next(line.rsplit("=", 1)[1] for line in log.splitlines()
                               if line.startswith("resource_acquired fd=")))
        target = pathlib.Path(f"/proc/{self.proc.pid}/fd/{resource_fd}")
        self.assertTrue(target.exists(), "acquired eventfd must survive execute exception")
        self.assertIn("eventfd", os.readlink(target))
        self.assertEqual(record["owner_pid"], self.proc.pid)
        self.proc.stdin.write(wire("prepare", request_id=2, deadline=120000))
        self.proc.stdin.flush()
        # Production supervisor must respond without dispatching execute again.
        ready, _, _ = select.select([self.proc.stdout], [], [], 3)
        self.assertTrue(ready, "HELD supervisor remains responsive to new commands")
        self.assertNotIn("OWNER_DESTRUCTOR_ENTERED", self.log())
        self.assertNotIn("destructor_entered", self.log())
        self.assertNotIn("\nFREE\n", self.log())
        self.assertNotIn("\nCONTEXT_DESTROY\n", self.log())
        self.assertEqual(self.log().count("command=prepare"), 1)
        self.assertNotIn("UNEXPECTED_OWNER_COMMAND", self.log())

    def returned_error_response(self):
        def bounded_read(size):
            data = b""
            until = time.monotonic() + 3
            while len(data) < size:
                remaining = until - time.monotonic()
                self.assertGreater(remaining, 0, "bounded owner error response deadline")
                ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
                self.assertTrue(ready, "owner error must yield a supervisor response")
                chunk = os.read(self.proc.stdout.fileno(), size - len(data))
                self.assertTrue(chunk)
                data += chunk
            return data
        length = struct.unpack("!I", bounded_read(4))[0]
        self.assertGreater(length, 0)
        self.assertLessEqual(length, 1048576)
        return json.loads(bounded_read(length))

    def test_return_error_acquired_cannot_claim_failed_safe_or_keep_authority(self):
        response = self.returned_error_response()
        os.write(self.release_write, b"R")
        eventually(lambda: "exception_probe_complete" in self.log())
        log = self.log()
        self.assertIn("snapshot_held=1", log,
                      "returned EIO after resource acquisition must hold actual guard")
        self.assertIn("snapshot_permissions=0", log)
        reason = int(next(line.split("=", 1)[1] for line in log.splitlines()
                          if line.startswith("snapshot_reasons=")))
        self.assertEqual(reason & (1 << 8), 1 << 8)
        for name in ("CREATE", "START", "REUSE", "GPU_CLOSE", "EPOCH_CLOSE", "CONTROL"):
            self.assertIn("probe_" + name + "=" + str(-errno.EPERM), log)
        self.assertNotIn("SIDE_EFFECT_", log)
        self.assertEqual(response["error"], -errno.EIO)
        self.assertTrue(response["held"])
        self.assertEqual(response["phase"], "HELD")
        self.assertEqual(response["cleanup_permissions"], 0)
        self.assert_retained(1 << 8)
        resource_fd = int(next(line.rsplit("=", 1)[1] for line in log.splitlines()
                               if line.startswith("resource_acquired fd=")))
        target = pathlib.Path(f"/proc/{self.proc.pid}/fd/{resource_fd}")
        self.assertTrue(target.exists())
        self.assertIn("eventfd", os.readlink(target))
        self.assertNotIn("OWNER_DESTRUCTOR_ENTERED", self.log())
        self.assertNotIn("destructor_entered", self.log())
        self.assertNotIn("\nFREE\n", self.log())
        self.assertNotIn("\nCONTEXT_DESTROY\n", self.log())
        self.assertEqual(log.count("command=prepare"), 1)

    def test_return_error_new_preflight_without_acquire_stays_new_nonheld(self):
        response = self.returned_error_response()
        os.write(self.release_write, b"R")
        eventually(lambda: "return_error_probe_complete" in self.log())
        log = self.log()
        self.assertEqual(response["error"], -errno.ENODEV)
        self.assertFalse(response["held"])
        self.assertEqual(response["phase"], "NEW")
        self.assertIn("snapshot_held=0", log)
        self.assertIn("snapshot_reasons=0", log)
        self.assertIn("snapshot_new=1", log)
        self.assertNotIn("resource_acquired", log)
        self.assertIsNone(self.terminal(), "pristine preflight failure is not retained HELD work")
        self.assertIsNone(self.proc.poll())
        self.assertEqual(log.count("command=preflight"), 1)


if __name__ == "__main__":
    unittest.main()

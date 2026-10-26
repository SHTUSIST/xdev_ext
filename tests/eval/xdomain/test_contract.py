#!/usr/bin/env python3
"""Independent wire/coordinator tests derived from closure SDD section 7.

The pipe peers below are protocol endpoints only. They supply no transport,
GPU, guard, parser, coordinator, or oracle implementation.
"""
import copy
import importlib
import json
import os
import pathlib
import signal
import struct
import sys
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
MAX_JSON = 1048576
U64 = (1 << 64) - 1


def identity(**changes):
    result = dict(version=1, run_id="independent-c", sha="a" * 40,
                  role="tx", case="functional-epochs", direction="a-to-b",
                  epoch=3, request_id=1)
    result.update(changes)
    return result


def request(command="start", payload=None, **changes):
    result = dict(identity=identity(), command=command, deadline_ms=1000,
                  part_index=0, part_count=1,
                  payload={"groups": 1, "first_seq": 7} if payload is None else payload)
    result.update(changes)
    return result


def frame(record):
    body = json.dumps(record, separators=(",", ":")).encode()
    return struct.pack("!I", len(body)) + body


class WireContract(unittest.TestCase):
    def setUp(self):
        self.protocol = importlib.import_module("check_protocol")

    def reject(self, record):
        with self.assertRaises(ValueError):
            self.protocol.decode_frame(frame(record))

    def test_exact_four_byte_length_and_roundtrip(self):
        record = request()
        self.assertEqual(self.protocol.decode_frame(frame(record)), record)
        encoded = self.protocol.encode_record(record)
        self.assertEqual(struct.unpack("!I", encoded[:4])[0], len(encoded) - 4)
        self.assertEqual(self.protocol.decode_frame(encoded), record)

    def test_prefix_zero_oversized_truncated_extra_and_invalid_utf8(self):
        for bad in (b"", b"\0\0\0", b"\0\0\0\0",
                    struct.pack("!I", MAX_JSON + 1) + b"{}",
                    b"\0\0\0\3{}", b"\0\0\0\2{}x", b"\0\0\0\1\xff"):
            with self.subTest(bad=bad[:8]), self.assertRaises(ValueError):
                self.protocol.decode_frame(bad)

    def test_duplicate_keys_rejected_at_every_level(self):
        good = json.dumps(request(), separators=(",", ":"))
        for text in (good.replace('"command":"start"', '"command":"start","command":"stop"'),
                     good.replace('"epoch":3', '"epoch":3,"epoch":3'),
                     good.replace('"groups":1', '"groups":1,"groups":1')):
            raw = text.encode()
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.protocol.decode_frame(struct.pack("!I", len(raw)) + raw)

    def test_nan_infinity_float_negative_bool_and_overflow_ids(self):
        for value in (float("nan"), float("inf"), -1, 1.0, True, U64 + 1):
            for field in ("epoch", "request_id"):
                record = request()
                record["identity"][field] = value
                with self.subTest(field=field, value=value):
                    self.reject(record)

    def test_unknown_fields_and_command_rejected(self):
        for target in ("top", "identity", "payload"):
            record = request()
            (record if target == "top" else record[target])["unexpected"] = 1
            with self.subTest(target=target):
                self.reject(record)
        self.reject(request(command="friendly-pass"))

    def test_exact_identity_enum_sha_and_string_bounds(self):
        for field, bad in (("role", "receiver"), ("direction", "both"),
                           ("sha", "A" * 40), ("sha", "a" * 39),
                           ("run_id", "x" * 129), ("run_id", "é" * 65),
                           ("case", "x" * 129), ("version", 2)):
            record = request()
            record["identity"][field] = bad
            with self.subTest(field=field, bad=bad):
                self.reject(record)
        for sha in ("a" * 40, "b" * 64):
            record = request()
            record["identity"]["sha"] = sha
            self.assertEqual(self.protocol.decode_frame(frame(record)), record)

    def test_deadline_and_nonstream_part_limits(self):
        for deadline in (0, 120001, -1, 1.0, True):
            self.reject(request(deadline_ms=deadline))
        for changes in ({"part_count": 0}, {"part_index": 1}, {"part_count": 2}):
            self.reject(request(**changes))

    def test_observe_requires_bounded_explicit_pagination(self):
        for limit in (1, 32):
            record = request("observe", {"first_ordinal": 9999, "limit": limit})
            self.assertEqual(self.protocol.decode_frame(frame(record)), record)
        for payload in ({}, {"first_ordinal": 0, "limit": 0},
                        {"first_ordinal": 0, "limit": 33},
                        {"first_ordinal": -1, "limit": 1}):
            self.reject(request("observe", payload))

    def test_verify_extent_part_bound_and_full_width_offsets(self):
        extent = dict(dst_off=U64 - 4095, src_off=4096, len=4096,
                      seed=U64, kind=1, reserved=0)
        record = request("verify", {"kind": "extents", "first_extent": 0,
                                    "extents": [extent]}, part_index=1, part_count=3)
        self.assertEqual(self.protocol.decode_frame(frame(record)), record)
        oversized = copy.deepcopy(record)
        oversized["payload"]["extents"] *= 1025
        self.reject(oversized)

    def test_response_matches_all_identity_command_and_phase_facts(self):
        expected = dict(identity=identity(), command="start", phase="SESSION_CREATED")
        response = dict(identity=identity(), command="start", phase="START_ACCEPTED",
                        fate="ACTIVE", error=0, held=False, cleanup_permissions=0,
                        evidence={}, payload=dict(start_accepted=True, arm_error=0,
                                                  start_error=0),
                        part_index=0, part_count=1)
        self.protocol.validate_record(response, expected)
        for field, bad in (("run_id", "other"), ("sha", "b" * 40), ("role", "rx"),
                           ("case", "bulk-static"), ("direction", "b-to-a"),
                           ("epoch", 2), ("request_id", 2)):
            mutated = copy.deepcopy(response)
            mutated["identity"][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.protocol.validate_record(mutated, expected)
        for changes in ({"phase": "VERIFIED"}, {"cleanup_permissions": 15},
                        {"error": -5}, {"held": True}, {"command": "wait"}):
            mutated = copy.deepcopy(response)
            mutated.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.protocol.validate_record(mutated, expected)


def coordinator_config(directory):
    return dict(identity={key: val for key, val in identity().items()
                          if key not in ("role", "request_id")},
                mode="single-group", groups=1, first_seq=7, seed=9,
                gpu_bdf={"tx": "0000:01:00.0", "rx": "0000:02:00.0"},
                nvidia_node={"tx": "/dev/nvidia0", "rx": "/dev/nvidia1"},
                link_token={"tx": 901, "rx": 1007}, channel=0,
                geometry=dict(allocation_bytes=65536, group_bytes=4096,
                              frame_size=65536, seg_len=4096, depth=1, native_elems=1),
                flags=0, observer_object="observer.bpf.o", ptx_path="pattern.ptx",
                deadline_ms=1000, evidence_dir=str(directory))


def read_exact(stream, length):
    data = b""
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def terminal_stats(session, groups, stopped=False):
    stats = dict(session_id=session, batches_done=groups, batches_abort=0, rejects=0,
                 recycled=groups, held=0, sequestered=0, timeouts=0, inflight=0,
                 native_publish=0, protocol_err=0, published=0, submitted=[groups, 0, 0, 0],
                 completed=[groups, 0, 0, 0], last_err=0, state=4 if stopped else 1)
    policy = dict(version=0, size=0, window=0, initial_credit=0, rto_ns=0, rto_max_ns=0,
                  backoff=0, max_attempts=0, ack_rule=0, ack_every=0, ack_delay_ns=0,
                  resend_order=0, flags=0, bad_field=0, rsvd0=0, rsvd=[0] * 6)
    transport = dict(v3=dict(v2=dict(v1=dict(size=216, version=4, session_id=session,
                         native_controls=0, pending_acks=0, uncertain_controls=0, rsvd=0),
                         retransmits=0, dup_suppressed=0, held_acks=0, held_unacked=0, rsvd2=0),
                         nic_copy_ops=0, nic_copy_bytes=0, nic_zc_ops=0, nic_zc_bytes=0),
                     rel_policy=policy)
    return dict(stats_valid=True, stats=stats, transport_valid=True, transport=transport)


def observed_record(role, ordinal, first_seq, epoch, group_bytes):
    key = first_seq + ordinal
    return dict(session_id=101 if role == "tx" else 202,
                batch_id=11 + ordinal * 7 if role == "tx" else 503 + ordinal * 11,
                key=key, epoch=epoch, generation=13 if role == "tx" else 37,
                local_inc=17 if role == "tx" else 29, remote_inc=29 if role == "tx" else 17,
                direction=1 if role == "tx" else 2, channel=0,
                build_attempts=1, cqe_seen=1, error_bits=0,
                spans=[dict(allocation_off=8192 if role == "tx" else 32768,
                            data_off=0, len=group_bytes)],
                tag=(key.to_bytes(8, "big") + bytes(16)).hex() if role == "tx" else bytes(24).hex(),
                completion=dict(status=0, outcome=0, remote=2 if role == "tx" else 0,
                    elems_done=group_bytes // 4096, group=key, bytes=group_bytes, crc_errors=0,
                    rsvd=0, tag=(key.to_bytes(8, "big") + bytes(16)).hex() if role == "rx" else bytes(24).hex()))


def pipe_agent(role, scenario, directory):
    """Contract endpoint; deliberately has no CUDA/native/resource behavior."""
    directory = pathlib.Path(directory)
    path = directory / (role + ".jsonl")
    signal.signal(signal.SIGTERM, lambda *_: path.open("a").write('{"signal":"TERM"}\n'))
    with path.open("a") as ledger:
        ledger.write(json.dumps({"pid": os.getpid(), "test_only_surrogate": True}) + "\n")
        ledger.flush()
    prepare = None
    verify_cookie = None
    unknown_owner_held = False
    success = scenario in ("success", "observe-gap", "observe-duplicate", "wrong-pair-stop", "bad-summary")
    while True:
        prefix = read_exact(sys.stdin.buffer, 4)
        if prefix is None:
            if prepare is None and not unknown_owner_held:
                return  # preflight-only endpoint never acquired a resource
            # Do not disappear on coordinator EOF after acquire/unknown work.
            while True:
                time.sleep(0.1)
        size = struct.unpack("!I", prefix)[0]
        body = read_exact(sys.stdin.buffer, size)
        if body is None:
            continue
        cmd = json.loads(body)
        with path.open("a") as ledger:
            ledger.write(json.dumps({"command": cmd, "at_ns": time.monotonic_ns()}) + "\n")
        name = cmd["command"]
        response = dict(identity=cmd["identity"], command=name, phase="NEW", fate="EMPTY",
                        error=0, held=False, cleanup_permissions=0, evidence={},
                        part_index=0, part_count=1, payload={})
        if name == "preflight":
            response["payload"] = dict(available=True, reason="",
                device_identity=dict(gpu_bdf=cmd["payload"]["gpu_bdf"],
                                     nvidia_node=cmd["payload"]["nvidia_node"], backing="gpu"),
                link_identity=dict(link_token=cmd["payload"]["link_token"], channel=0,
                                   local_inc=17 if role == "tx" else 29,
                                   remote_inc=29 if role == "tx" else 17),
                kernel_identity=dict(sha="a" * 40, config="CONFIG_XDEV_EXT=y"),
                visibility="NATIVE_OWNER", raw_evidence={"service_listing": ["xdev_ext_xdomain"]})
            if scenario == "wrong-sha":
                response["identity"]["sha"] = "b" * 40
            if scenario == "wrong-bdf":
                response["payload"]["device_identity"]["gpu_bdf"] = "0000:03:00.0"
        elif name == "prepare":
            prepare = cmd["payload"]
            if success:
                response.update(phase="SESSION_CREATED", fate="ACTIVE", payload=dict(
                    session_id=101 if role == "tx" else 202, registration_bytes=65536,
                    producer_sync_proved=role == "tx", guard_sync_proved=role == "rx",
                    create_error=0, stop_proved=False))
            else:
                response.update(phase="HELD", fate="HELD", error=-110, held=True,
                            evidence=dict(owner_pid=os.getpid(), durable_path=str(path),
                                          retained_resources=["test-only-eventfd"], recovery="manual"),
                            payload=dict(session_id=0, registration_bytes=65536,
                                         producer_sync_proved=False, guard_sync_proved=False,
                                         create_error=0, stop_proved=False))
                if scenario == "unknown-owner-prepare":
                    response["evidence"] = {}
        elif name == "start" and success:
            response.update(phase="START_ACCEPTED", fate="ACTIVE", payload=dict(
                start_accepted=True, arm_error=0, start_error=0))
        elif name in ("wait", "stop") and success:
            payload = terminal_stats(101 if role == "tx" else 202, prepare["groups"], name == "stop")
            if name == "stop":
                payload.update(stop_proved=True, first_error=0, stop_error=0)
            response.update(phase="DRAINED_SAFE" if name == "stop" else "TRANSPORT_DONE",
                            fate="SAFE" if name == "stop" else "ACTIVE",
                            cleanup_permissions=1 if name == "stop" else 0, payload=payload)
            if scenario == "wrong-pair-stop" and name == "stop" and role == "tx":
                response["identity"]["epoch"] += 1
        elif name == "observe" and success:
            first = cmd["payload"]["first_ordinal"]
            limit = cmd["payload"]["limit"]
            end = min(first + limit, prepare["groups"])
            rows = [dict(ordinal=i, record=observed_record(role, i, prepare["first_seq"],
                          cmd["identity"]["epoch"], prepare["geometry"]["group_bytes"]))
                    for i in range(first, end)]
            if rows and scenario == "observe-gap":
                rows.pop(0)
            if rows and scenario == "observe-duplicate":
                rows.append(copy.deepcopy(rows[0]))
            response.update(phase="DRAINED_SAFE", fate="SAFE", cleanup_permissions=1,
                            payload=dict(records=rows, next_ordinal=end if end < prepare["groups"] else None,
                                         total=prepare["groups"], error_bits=0))
        elif name == "verify" and success:
            if cmd["payload"]["kind"] == "begin":
                verify_cookie = cmd["payload"]["launch_cookie"]
                continue
            if cmd["payload"]["kind"] != "end":
                continue
            response.update(phase="VERIFIED", fate="SAFE", cleanup_permissions=15,
                            payload=dict(bytes=0 if scenario == "bad-summary" else 65536,
                                         mismatches=0, first_bad=U64,
                                         launch_cookie=verify_cookie,
                                         visibility="NATIVE_OWNER", visibility_error=0))
        elif name == "close" and success:
            response.update(phase="CLOSED", fate="SAFE", payload=dict(closed=True, retained_resources=[]))
        elif name == "cancel":
            owner_evidence = {}
            if scenario == "unknown-owner-prepare":
                unknown_owner_held = True
            else:
                owner_evidence = dict(owner_pid=os.getpid(), durable_path=str(path),
                                      retained_resources=["test-only-eventfd"], recovery="manual")
                # An actual same-process owner receipt, durably written before
                # advertising its PID/path; not a coordinator-side hint.
                with path.open("a") as durable:
                    durable.write(json.dumps(dict(identity=cmd["identity"], phase="HELD",
                                                   hold_reasons=1, **owner_evidence)) + "\n")
                    durable.flush()
                    os.fsync(durable.fileno())
            response.update(phase="HELD", fate="HELD", error=-1, held=True,
                            evidence=owner_evidence,
                            payload=dict(hold_reasons=1, retained_resources=["test-only-eventfd"]))
        else:
            # Any further owner operation after HELD is recorded and rejected.
            response.update(phase="HELD", fate="HELD", error=-1, held=True)
        sys.stdout.buffer.write(frame(response))
        sys.stdout.buffer.flush()
        if name == "close" and success:
            return


class CoordinatorProcesses(unittest.TestCase):
    def setUp(self):
        self.coordinator = importlib.import_module("two_host_check")
        self.tmp = tempfile.TemporaryDirectory(prefix="tb-coordinator-contract-")
        self.directory = pathlib.Path(self.tmp.name)

    def tearDown(self):
        # Only the pipe fixture above can appear here. Never production cleanup.
        for role in ("tx", "rx"):
            path = self.directory / (role + ".jsonl")
            if path.exists():
                first = json.loads(path.read_text().splitlines()[0])
                self.assertTrue(first["test_only_surrogate"])
                try:
                    os.kill(first["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(first["pid"], 0)
                except ChildProcessError:
                    pass
        self.tmp.cleanup()

    def run_case(self, scenario, groups=1):
        argv = lambda role: [sys.executable, "-I", str(__file__), "--pipe-agent", role,
                             scenario, str(self.directory)]
        config = coordinator_config(self.directory)
        if groups != 1:
            config.update(mode="bulk-static", groups=groups)
        return self.coordinator.run(config, {"tx": argv("tx"), "rx": argv("rx")})

    def commands(self, role):
        path = self.directory / (role + ".jsonl")
        return [row for row in map(json.loads, path.read_text().splitlines()) if "command" in row]

    def test_retained_peer_not_killed_reaped_or_advanced_after_failed_prepare(self):
        answer = self.run_case("held-prepare")
        self.assertIn(answer["status"], ("failed", "incomplete"))
        self.assertTrue(answer["retained_workers"])
        observed = set()
        for role in ("tx", "rx"):
            rows = [json.loads(line) for line in (self.directory / (role + ".jsonl")).read_text().splitlines()]
            pid = rows[0]["pid"]
            os.kill(pid, 0)
            self.assertFalse(any("signal" in row for row in rows), "coordinator must not terminate retained peers")
            names = [row["command"]["command"] for row in rows if "command" in row]
            self.assertFalse(set(names) & {"start", "wait", "stop", "observe", "verify", "close"})
            observed.add(pid)
        reported = {entry["owner_pid"] for entry in answer["retained_workers"]}
        self.assertTrue(reported <= observed)
        for worker in answer["retained_workers"]:
            for field in ("owner_pid", "durable_path", "identity", "phase", "hold_reasons"):
                self.assertIn(field, worker)
            self.assertTrue(worker["hold_reasons"])
            self.assertEqual(worker["phase"], "HELD")

    def test_unknown_owner_receipt_keeps_owner_fields_null_and_transport_separate(self):
        answer = self.run_case("unknown-owner-prepare")
        self.assertIn(answer["status"], ("failed", "incomplete"))
        self.assertTrue(answer["retained_workers"])
        observed = {}
        for role in ("tx", "rx"):
            rows = [json.loads(line) for line in (self.directory / (role + ".jsonl")).read_text().splitlines()]
            pid = rows[0]["pid"]
            os.kill(pid, 0)
            self.assertFalse(any("signal" in row for row in rows),
                             "unknown owner evidence cannot authorize terminating the transport")
            names = [row["command"]["command"] for row in rows if "command" in row]
            self.assertFalse(set(names) & {"start", "wait", "stop", "observe", "verify", "close"})
            observed[role] = pid
        for worker in answer["retained_workers"]:
            self.assertIsNone(worker["owner_pid"])
            self.assertIsNone(worker["durable_path"])
            self.assertTrue(worker["evidence_incomplete"])
            self.assertEqual(worker["transport_pid"], observed[worker["identity"]["role"]])
            self.assertTrue(pathlib.Path(worker["coordinator_log_path"]).is_file())

    def test_wrong_exact_sha_rejected_before_prepare(self):
        answer = self.run_case("wrong-sha")
        self.assertIn(answer["status"], ("failed", "incomplete"))
        for role in ("tx", "rx"):
            path = self.directory / (role + ".jsonl")
            if path.exists():
                self.assertNotIn('"command": "prepare"', path.read_text())

    def test_wrong_actual_bdf_rejected_before_prepare(self):
        answer = self.run_case("wrong-bdf")
        self.assertIn(answer["status"], ("failed", "incomplete"))
        for role in ("tx", "rx"):
            path = self.directory / (role + ".jsonl")
            if path.exists():
                self.assertNotIn('"command": "prepare"', path.read_text())

    def unsupported_without_action_provider(self, case):
        # The same peers can complete functional transport successfully. Case
        # dispatch, rather than a failed functional fixture, must close this gate.
        argv = lambda role: [sys.executable, "-I", str(__file__), "--pipe-agent", role,
                             "success", str(self.directory)]
        config = coordinator_config(self.directory)
        config["identity"]["case"] = case
        answer = self.coordinator.run(config, {"tx": argv("tx"), "rx": argv("rx")})
        for role in ("tx", "rx"):
            path = self.directory / (role + ".jsonl")
            if path.exists():
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                names = [row["command"]["command"] for row in rows if "command" in row]
                self.assertNotIn("prepare", names,
                                 case + " must fail closed before acquiring either owner")
                self.assertFalse(set(names) & {"start", "wait", "stop", "observe", "verify", "close"})
        self.assertEqual(answer["status"], "incomplete")
        self.assertTrue(answer["reason"])

    def test_fault_case_without_action_provider_is_incomplete_before_prepare(self):
        self.unsupported_without_action_provider("stop-inflight")

    def test_bringup_without_case_path_is_incomplete_before_prepare(self):
        self.unsupported_without_action_provider("bringup")

    def test_rx_first_pair_stop_then_observe_verify_then_close_real_coordinator(self):
        answer = self.run_case("success")
        self.assertEqual(answer["status"], "pass")
        self.assertEqual(answer["retained_workers"], [])
        self.assertEqual(len(answer["epochs"]), 1)
        commands = {role: self.commands(role) for role in ("tx", "rx")}
        starts = {role: next(row["at_ns"] for row in commands[role]
                             if row["command"]["command"] == "start") for role in commands}
        self.assertLess(starts["rx"], starts["tx"])
        stop_times = [row["at_ns"] for rows in commands.values() for row in rows
                      if row["command"]["command"] == "stop"]
        self.assertEqual(len(stop_times), 2)
        verify_times = []
        for rows in commands.values():
            for row in rows:
                cmd = row["command"]
                if cmd["command"] in ("observe", "verify"):
                    self.assertGreater(row["at_ns"], max(stop_times))
                if cmd["command"] == "verify":
                    verify_times.append(row["at_ns"])
                    if cmd["payload"]["kind"] == "begin":
                        receipts = cmd["payload"]["stop_receipts"]
                        self.assertEqual({r["identity"]["role"] for r in receipts}, {"tx", "rx"})
                        for receipt in receipts:
                            self.assertEqual(receipt["identity"]["sha"], "a" * 40)
                            self.assertEqual(receipt["identity"]["epoch"], 3)
                            self.assertTrue(receipt["payload"]["stop_proved"])
                            self.assertEqual(receipt["error"], 0)
        self.assertTrue(verify_times)
        for rows in commands.values():
            for row in rows:
                if row["command"]["command"] == "close":
                    self.assertGreater(row["at_ns"], max(verify_times))

    def test_ten_thousand_observer_records_are_exactly_covered_in_bounded_pages(self):
        answer = self.run_case("success", groups=10000)
        self.assertEqual(answer["status"], "pass")
        for role in ("tx", "rx"):
            pages = [row["command"]["payload"] for row in self.commands(role)
                     if row["command"]["command"] == "observe"]
            cursor = 0
            self.assertGreater(len(pages), 1)
            for page in pages:
                self.assertEqual(page["first_ordinal"], cursor)
                self.assertLessEqual(page["limit"], 32)
                self.assertGreaterEqual(page["limit"], 1)
                cursor += min(page["limit"], 10000 - cursor)
            self.assertEqual(cursor, 10000)

    def test_observer_gap_or_duplicate_prevents_positive_and_verify(self):
        for scenario in ("observe-gap", "observe-duplicate"):
            with self.subTest(scenario=scenario):
                # Each endpoint ledger must remain distinct between attempts.
                subdir = self.directory / scenario
                subdir.mkdir()
                original = self.directory
                self.directory = subdir
                try:
                    answer = self.run_case(scenario)
                    self.assertIn(answer["status"], ("failed", "incomplete"))
                    for role in ("tx", "rx"):
                        self.assertFalse(any(row["command"]["command"] == "verify"
                                             for row in self.commands(role)))
                finally:
                    # Add endpoint ledgers to teardown's test-only PID list.
                    for role in ("tx", "rx"):
                        path = subdir / (role + ".jsonl")
                        if path.exists():
                            pid = json.loads(path.read_text().splitlines()[0])["pid"]
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            try:
                                os.waitpid(pid, 0)
                            except ChildProcessError:
                                pass
                    self.directory = original

    def test_wrong_pair_stop_identity_blocks_verify_and_close(self):
        answer = self.run_case("wrong-pair-stop")
        self.assertIn(answer["status"], ("failed", "incomplete"))
        for role in ("tx", "rx"):
            self.assertFalse(any(row["command"]["command"] in ("verify", "close")
                                 for row in self.commands(role)))

    def test_zero_byte_fabricated_verify_summary_cannot_pass(self):
        answer = self.run_case("bad-summary")
        self.assertIn(answer["status"], ("failed", "incomplete"))

    def test_original_capacity_negative_requests_refused_before_prepare(self):
        for group_bytes, depth, elems in ((65536, 16, 16), (262144, 4, 64),
                                          (262144, 16, 64)):
            subdir = self.directory / (str(group_bytes) + "-" + str(depth))
            subdir.mkdir()
            config = coordinator_config(subdir)
            config["geometry"].update(group_bytes=group_bytes, depth=depth, native_elems=elems,
                                       seg_len=65536, allocation_bytes=16777216)
            argv = lambda role: [sys.executable, "-I", str(__file__), "--pipe-agent", role,
                                 "success", str(subdir)]
            with self.subTest(group_bytes=group_bytes, depth=depth):
                try:
                    answer = self.coordinator.run(config, {"tx": argv("tx"), "rx": argv("rx")})
                    self.assertIn(answer["status"], ("failed", "incomplete"))
                    for role in ("tx", "rx"):
                        path = subdir / (role + ".jsonl")
                        if path.exists():
                            commands = [row["command"] for row in map(json.loads, path.read_text().splitlines())
                                        if "command" in row]
                            self.assertFalse(any(cmd["command"] == "prepare" for cmd in commands))
                            for cmd in commands:
                                if cmd["command"] == "preflight":
                                    self.assertEqual(cmd["payload"]["geometry"], config["geometry"])
                finally:
                    for role in ("tx", "rx"):
                        path = subdir / (role + ".jsonl")
                        if path.exists():
                            pid = json.loads(path.read_text().splitlines()[0])["pid"]
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            try:
                                os.waitpid(pid, 0)
                            except ChildProcessError:
                                pass


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--pipe-agent":
        pipe_agent(*sys.argv[2:])
    else:
        unittest.main()

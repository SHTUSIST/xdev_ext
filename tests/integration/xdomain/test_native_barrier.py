#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent C2 tests derived from the root-frozen action/trace requirements.

No physical execution: literal trace records model the already accepted wire ABI.
"""
import copy
import importlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
IDENTITY = dict(version=1, run_id="c2-independent", sha="a" * 40, role="tx",
                case="cable-loss", direction="a-to-b", epoch=3, request_id=7)
# Model the actual declared tracepoint layout, including field widths. This is
# contract fixture data, not a claim to have read a running physical tracefs.
FORMAT = """name: native_event
ID: 900
format:
 field:unsigned short common_type; offset:0; size:2; signed:0;
 field:unsigned char common_flags; offset:2; size:1; signed:0;
 field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
 field:int common_pid; offset:4; size:4; signed:1;
 field:__data_loc char[] phase; offset:8; size:4; signed:1;
 field:__data_loc char[] origin; offset:12; size:4; signed:1;
 field:u64 session_id; offset:16; size:8; signed:0;
 field:u64 batch_id; offset:24; size:8; signed:0;
 field:u64 batch_key; offset:32; size:8; signed:0;
 field:u32 frame_id; offset:40; size:4; signed:0;
 field:u64 generation; offset:48; size:8; signed:0;
 field:u32 stage; offset:56; size:4; signed:0;
 field:u64 ticket; offset:64; size:8; signed:0;
 field:u32 class_id; offset:72; size:4; signed:0;
 field:int accepted; offset:76; size:4; signed:1;
 field:int status; offset:80; size:4; signed:1;
 field:u64 cookie; offset:88; size:8; signed:0;
 field:u64 address; offset:96; size:8; signed:0;
 field:u32 bytes; offset:104; size:4; signed:0;
 field:u64 aux; offset:112; size:8; signed:0;
 field:u64 sequence; offset:120; size:8; signed:0;
 field:u64 ts_ns; offset:128; size:8; signed:0;
 field:u32 origin_tgid; offset:136; size:4; signed:0;
 field:u64 process_start_ticks; offset:144; size:8; signed:0;
 field:u64 native_user_data; offset:152; size:8; signed:0;
 field:u32 frame_ordinal; offset:160; size:4; signed:0;
 field:u32 frame_offset; offset:164; size:4; signed:0;
 field:u32 frame_length; offset:168; size:4; signed:0;
print fmt: "abi=xdev-native-v1-nvme-xsk-batch phase=%s origin=%s"
"""


def row(ordinal, ts, phase="native_submit", **change):
    fields = dict(abi="xdev-native-v1-nvme-xsk-batch", phase=phase, origin="K",
                  session_id=101, batch_id=901, batch_key=40, frame_id=11 + ordinal,
                  generation=8 + ordinal, stage=0, ticket=90, class_id=11,
                  accepted=1, status=0, cookie=17, address=0, bytes=131072, aux=1,
                  sequence=0, ts_ns=ts, origin_tgid=0, process_start_ticks=0,
                  native_user_data=0, frame_ordinal=ordinal,
                  frame_offset=ordinal * 65536, frame_length=65536)
    fields.update(change)
    return "worker-23 [001] .... 1.000000: native_event: " + " ".join(
        "%s=%s" % (key, value) for key, value in fields.items()) + "\n"


def fixtures():
    expected = dict(identity=copy.deepcopy(IDENTITY), boot_id="boot-A",
                    kernel_build_id="1234abcd", source_commit="a" * 40,
                    clock_domain="boot-A:CLOCK_MONOTONIC", nhi_bdf="0000:04:00.0",
                    link_token=71, local_inc=81, remote_inc=82, session_id=101,
                    stage=0, batch_key=40, direction=1, group_bytes=131072,
                    max_age_ms=1000)
    receipt = dict(version=1, identity=copy.deepcopy(IDENTITY), boot_id="boot-A",
                   kernel_build_id="1234abcd", source_commit="a" * 40,
                   clock="CLOCK_MONOTONIC", clock_domain="boot-A:CLOCK_MONOTONIC",
                   nhi_bdf="0000:04:00.0", link_token=71, local_inc=81,
                   remote_inc=82, create_begin_ns=1010000000,
                   create_end_ns=1020000000, capture_begin_ns=1000000000,
                   capture_end_ns=1055000000, captured_monotonic_ns=1055000000,
                   trace_dropped=0, formats={"xdev_ext:native_event": FORMAT},
                   raw_path="/private/c2-native.raw")
    return row(0, 1040000000) + row(1, 1050000000), receipt, expected


class NativeBarrierTests(unittest.TestCase):
    def setUp(self):
        try:
            self.module = importlib.import_module("native_barrier")
        except ModuleNotFoundError:
            self.fail("C2 native_barrier implementation is absent (frozen-API RED)")
        self.raw, self.receipt, self.expected = fixtures()

    def qualify(self, *, action=None, now_ns=1055000000):
        return self.module.qualify_native_barrier(
            self.raw, self.receipt, self.expected, now_ns=now_ns, action=action)

    def assert_incomplete(self, result):
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["reason"])
        self.assertIsNone(result["barrier"])

    def test_full_native_group_is_provisional_ready_with_last_submit_time(self):
        result = self.qualify()
        self.assertEqual(result["status"], "ready")
        barrier = result["barrier"]
        self.assertEqual(barrier["accepted_monotonic_ns"], 1050000000)
        self.assertEqual(barrier["group"], 17)
        self.assertEqual(barrier["batch_id"], 901)
        self.assertEqual(barrier["session_id"], 101)
        self.assertEqual(barrier["acceptance_seq"], 1)
        self.assertEqual(barrier["identity"], IDENTITY)
        self.assertEqual(barrier["inflight"], 1)

    def test_zero_group_is_not_confused_with_missing_raw_acceptance_coordinate(self):
        self.raw = row(0, 1040000000, cookie=0) + row(1, 1050000000, cookie=0)
        result = self.qualify()
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["barrier"]["group"], 0)
        self.assertEqual(result["barrier"]["acceptance_seq"], 1)

    def test_submitted_statistics_or_build_without_native_acceptance_do_not_arm(self):
        self.raw = self.raw.replace("phase=native_submit", "phase=class_validate")
        self.assert_incomplete(self.qualify())

    def test_partial_frame_set_does_not_claim_full_acceptance(self):
        self.raw = row(0, 1040000000)
        self.assert_incomplete(self.qualify())

    def test_duplicate_frame_submission_is_ambiguous(self):
        self.raw += row(1, 1051000000)
        self.assert_incomplete(self.qualify())

    def test_wrong_bytes_offset_class_or_direction_are_not_acceptance(self):
        for field, value in (("bytes", 65536), ("address", 4096),
                             ("aux", 2), ("class_id", 6), ("accepted", 0),
                             ("frame_offset", 4096)):
            with self.subTest(field=field):
                self.raw = row(0, 1040000000) + row(1, 1050000000, **{field: value})
                self.assert_incomplete(self.qualify())

    def test_stale_boot_build_token_or_cross_epoch_cannot_bind(self):
        for field, value in (("boot_id", "boot-old"),
                             ("kernel_build_id", "wrong"), ("link_token", 72),
                             ("source_commit", "b" * 40),
                             ("clock_domain", "other:CLOCK_MONOTONIC")):
            with self.subTest(field=field):
                self.raw, self.receipt, self.expected = fixtures()
                self.receipt[field] = value
                self.assert_incomplete(self.qualify())
        self.raw, self.receipt, self.expected = fixtures()
        self.receipt["identity"]["epoch"] = 2
        self.assert_incomplete(self.qualify())

    def test_lost_trace_or_missing_format_cannot_prove_pending(self):
        for field, value in (("trace_dropped", 1), ("formats", {})):
            with self.subTest(field=field):
                self.raw, self.receipt, self.expected = fixtures()
                self.receipt[field] = value
                self.assert_incomplete(self.qualify())

    def test_future_or_old_sample_cannot_arm(self):
        self.assert_incomplete(self.qualify(now_ns=1054000000))
        self.assert_incomplete(self.qualify(now_ns=2056000000))

    def test_capture_must_start_before_create_and_cover_native_rows(self):
        self.receipt["capture_begin_ns"] = 1030000000
        self.assert_incomplete(self.qualify())
        self.raw, self.receipt, self.expected = fixtures()
        self.receipt["capture_end_ns"] = 1045000000
        self.assert_incomplete(self.qualify())

    def test_completed_even_on_another_cpu_read_order_is_not_pending(self):
        self.raw = row(0, 1052000000, "native_complete") + self.raw
        self.assert_incomplete(self.qualify())

    def test_multiple_batches_for_requested_key_are_not_guessed(self):
        self.raw += row(0, 1051000000, batch_id=902, cookie=18, ticket=91)
        self.raw += row(1, 1052000000, batch_id=902, cookie=18, ticket=91)
        self.assert_incomplete(self.qualify())

    def test_other_session_is_not_a_substitute_for_expected_session(self):
        self.raw = self.raw.replace("session_id=101", "session_id=102")
        self.assert_incomplete(self.qualify())

    def action_fixture(self):
        barrier = self.qualify()["barrier"]
        action = dict(version=1, action_id="b" * 64, identity=copy.deepcopy(IDENTITY),
                      kind="cable-loss", target=dict(boot_id="boot-A",
                      nhi_bdf="0000:04:00.0", link_token=71, local_inc=81,
                      remote_inc=82, clock_domain="boot-A:CLOCK_MONOTONIC"),
                      barrier=barrier, attempted=True, completed=True, error=0,
                      started_monotonic_ns=1060000000,
                      finished_monotonic_ns=1070000000, evidence={})
        self.receipt["capture_end_ns"] = 1090000000
        self.receipt["captured_monotonic_ns"] = 1090000000
        return action

    def test_continued_trace_qualifies_action_before_completion(self):
        action = self.action_fixture()
        self.raw += row(0, 1080000000, "native_complete")
        self.raw += row(1, 1080000001, "native_complete")
        self.assertEqual(self.qualify(action=action, now_ns=1090000000)["status"], "ready")

    def test_action_after_first_completion_is_incomplete_even_if_initially_pending(self):
        action = self.action_fixture()
        self.raw += row(0, 1059000000, "native_complete")
        self.raw += row(1, 1080000000, "native_complete")
        self.assert_incomplete(self.qualify(action=action, now_ns=1090000000))

    def test_action_before_full_submit_is_incomplete(self):
        action = self.action_fixture()
        action["started_monotonic_ns"] = 1045000000
        self.assert_incomplete(self.qualify(action=action, now_ns=1090000000))

    def test_action_wrong_boot_or_original_barrier_is_incomplete(self):
        for field, value in (("target", dict(boot_id="boot-old", nhi_bdf="0000:04:00.0",
                             link_token=71,local_inc=81,remote_inc=82,
                             clock_domain="boot-A:CLOCK_MONOTONIC")),
                             ("identity", dict(IDENTITY, role="rx"))):
            with self.subTest(field=field):
                self.raw, self.receipt, self.expected = fixtures()
                action = self.action_fixture()
                action[field] = value
                self.assert_incomplete(self.qualify(action=action, now_ns=1090000000))


if __name__ == "__main__":
    unittest.main(verbosity=2)

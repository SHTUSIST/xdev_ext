#!/usr/bin/env python3
"""Specification-derived mapping tests; no production mapper builds expectations.

Coordinates are allocation offsets, never GPU addresses. Fixtures deliberately
use different descriptor order/frame choices and nonconsecutive batch IDs.
"""
import copy
import importlib
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
U64 = (1 << 64) - 1
GUARD_XOR = 0xD6E8FEB86659FD93


def config(groups=1, group_bytes=8192):
    return dict(allocation_bytes=65536, group_bytes=group_bytes, groups=groups,
                first_seq=71, epoch=3, seed=9, tx_local_inc=17, rx_local_inc=29,
                link_token={"tx": 901, "rx": 1007},
                tx_session_id=101, rx_session_id=202)


def span(offset, length=4096, data_off=0):
    return dict(allocation_off=offset, data_off=data_off, len=length)


def record(role, ordinal, spans, *, batch=None):
    key = 71 + ordinal
    return dict(session_id=101 if role == "tx" else 202,
                batch_id=(11 if role == "tx" else 503) + ordinal * 7 if batch is None else batch,
                key=key, epoch=3, generation=13 if role == "tx" else 37,
                local_inc=17 if role == "tx" else 29,
                remote_inc=29 if role == "tx" else 17,
                direction=1 if role == "tx" else 2, channel=0,
                build_attempts=1, cqe_seen=1, error_bits=0, spans=spans,
                tag=(key.to_bytes(8, "big") + bytes(16)).hex() if role == "tx" else bytes(24).hex(),
                completion=dict(status=0, outcome=0, remote=2 if role == "tx" else 0,
                                elems_done=sum(item["len"] // 4096 for item in spans),
                                group=key, bytes=sum(item["len"] for item in spans),
                                crc_errors=0, rsvd=0,
                                tag=(key.to_bytes(8, "big") + bytes(16)).hex() if role == "rx" else bytes(24).hex()))


def extent(dst, src, length, kind=1, seed=9):
    return dict(dst_off=dst, src_off=src, len=length, seed=seed, kind=kind, reserved=0)


def guard(dst, length):
    return extent(dst, dst, length, 2, 9 ^ GUARD_XOR)


class MappingOracle(unittest.TestCase):
    def setUp(self):
        self.oracle = importlib.import_module("oracle")

    def base(self):
        return ([record("tx", 0, [span(8192), span(0)])],
                [record("rx", 0, [span(32768), span(16384)])], config())

    def reject(self, tx, rx, conf):
        with self.assertRaises(ValueError):
            self.oracle.build_expectations(tx, rx, conf)

    def test_pattern_golden_full_width_unsigned_wrap(self):
        vectors = ((0, 0, 0x00), (0, 1, 0xAF), (1, 0, 0xE5),
                   (9, 4095, 0x47), (9, 4096, 0x2C),
                   (U64, U64, 0x20), (0x123456789ABCDEF0, 65536, 0xFB),
                   (0x123456789ABCDEF0, 0x100000000, 0xB5))
        for seed, offset, want in vectors:
            with self.subTest(seed=seed, offset=offset):
                self.assertEqual(self.oracle.pattern_byte(seed, offset), want)

    def test_logical_stream_join_different_frames_complete_guards(self):
        tx, rx, conf = self.base()
        self.assertEqual(self.oracle.build_expectations(tx, rx, conf), [
            guard(0, 16384), extent(16384, 0, 4096), guard(20480, 12288),
            extent(32768, 8192, 4096), guard(36864, 28672)])

    def test_join_splits_at_stream_boundary_not_matching_span_positions(self):
        tx = [record("tx", 0, [span(8192, 8192)])]
        rx = [record("rx", 0, [span(32768), span(16384)])]
        self.assertEqual(self.oracle.build_expectations(tx, rx, config()), [
            guard(0, 16384), extent(16384, 12288, 4096), guard(20480, 12288),
            extent(32768, 8192, 4096), guard(36864, 28672)])

    def test_repeated_destination_last_writer_nonconsecutive_batch_ids(self):
        tx = [record("tx", 0, [span(8192), span(0)]),
              record("tx", 1, [span(24576), span(4096)])]
        rx = [record("rx", i, [span(32768), span(16384)])
              for i in range(2)]
        self.assertEqual(self.oracle.build_expectations(tx, rx, config(2)), [
            guard(0, 16384), extent(16384, 4096, 4096), guard(20480, 12288),
            extent(32768, 24576, 4096), guard(36864, 28672)])
        # Arrival order and the local batch ID ordering have no authority.
        tx[1]["batch_id"] = 2
        rx[1]["batch_id"] = 9
        self.assertEqual(self.oracle.build_expectations(tx[::-1], rx[::-1], config(2)),
                         self.oracle.build_expectations(tx, rx, config(2)))

    def test_successive_groups_partial_destination_overlap_is_legal(self):
        tx = [record("tx", 0, [span(0, 8192)]),
              record("tx", 1, [span(16384, 8192)])]
        rx = [record("rx", 0, [span(32768, 8192)]),
              record("rx", 1, [span(36864, 8192)])]
        self.assertEqual(self.oracle.build_expectations(tx, rx, config(2)), [
            guard(0, 32768), extent(32768, 0, 4096), extent(36864, 16384, 8192),
            guard(45056, 20480)])

    def test_within_group_duplicate_or_overlapping_spans_rejected(self):
        for host in ("tx", "rx"):
            tx, rx, conf = self.base()
            rows = tx if host == "tx" else rx
            rows[0]["spans"] = [span(8192), span(8192)]
            with self.subTest(host=host):
                self.reject(tx, rx, conf)

    def test_missing_duplicate_extra_or_out_of_range_ordinal_rejected(self):
        for mutation in ("missing", "duplicate", "extra", "before"):
            tx, rx, conf = self.base()
            if mutation == "missing":
                rx.clear()
            elif mutation == "duplicate":
                rx.append(copy.deepcopy(rx[0]))
            elif mutation == "extra":
                rx.append(record("rx", 1, [span(0, 8192)]))
            else:
                rx[0]["key"] = 70
            with self.subTest(mutation=mutation):
                self.reject(tx, rx, conf)

    def test_wrong_epoch_identity_native_completion_or_tag_rejected(self):
        mutations = (("epoch", 2), ("session_id", 999), ("cqe_seen", 0),
                     ("cqe_seen", 2), ("build_attempts", 0), ("error_bits", 1),
                     ("local_inc", 17), ("remote_inc", 29), ("direction", 1),
                     ("channel", 1), ("completion.tag", "00" * 24),
                     ("completion.bytes", 4096), ("completion.remote", 2),
                     ("completion.outcome", 2), ("completion.status", -5),
                     ("completion.crc_errors", 1), ("completion.rsvd", 1),
                     ("completion.elems_done", 1), ("completion.group", 72))
        for field, bad in mutations:
            tx, rx, conf = self.base()
            if "." in field:
                rx[0]["completion"][field.split(".")[1]] = bad
            else:
                rx[0][field] = bad
            with self.subTest(field=field, bad=bad):
                self.reject(tx, rx, conf)

    def test_reversed_transport_group_rejected_even_when_ids_and_counts_match(self):
        tx = [record("tx", i, [span(i * 8192, 8192)])
              for i in range(2)]
        rx = [record("rx", i, [span(32768, 8192)])
              for i in range(2)]
        for rows in (tx, rx):
            rows[0]["completion"]["group"] = 72
            rows[1]["completion"]["group"] = 71
        self.reject(tx, rx, config(2))

    def test_span_alignment_zero_out_of_range_and_checked_additions(self):
        for bad in (span(0, 0), span(0, 4095), span(1), span(65536),
                    span(U64 - 4095, 4096, 4096), span(0, 4096, U64)):
            tx, rx, conf = self.base()
            rx[0]["spans"][0] = bad
            with self.subTest(bad=bad):
                self.reject(tx, rx, conf)

    def test_summary_exact_full_allocation_cookie_and_first_bad_sentinel(self):
        extents = [guard(0, 16384), extent(16384, 0, 4096), guard(20480, 45056)]
        good = dict(bytes=65536, mismatches=0, first_bad=U64, launch_cookie=42)
        self.oracle.validate_summary(good, extents, 42)
        for changes in ({"bytes": 0}, {"bytes": 4096}, {"mismatches": U64},
                        {"mismatches": 1}, {"first_bad": 0}, {"launch_cookie": 0},
                        {"launch_cookie": 43}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.oracle.validate_summary(dict(good, **changes), extents, 42)
        for missing in good:
            bad = dict(good)
            del bad[missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                self.oracle.validate_summary(bad, extents, 42)


if __name__ == "__main__":
    unittest.main()

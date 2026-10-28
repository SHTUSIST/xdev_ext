#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Runner relay of the strict schema2 campaign record; no device or performance.

The runner relays the benchmark's single JSON line only when it is a complete
gds-campaign-v1 record for exactly the requested campaign. Schema1 correctness
records from the per-chunk variant are refused rather than promoted.
Run: python3 -B tests/eval/gds/test_campaign_result.py -v
"""
import argparse
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
SIZE, CHUNK, ITERATIONS, GUARD = 12288, 8192, 3, 4096
OPERATIONS = ((SIZE + CHUNK - 1) // CHUNK) * ITERATIONS


def runner():
    spec = importlib.util.spec_from_file_location("gds_result_runner", HERE / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(workload="llm-load"):
    """Independent expected benchmark record (schema2), not produced by the runner."""
    return dict(schema_version=2, measurement_policy="gds-campaign-v1", mode="cufile-direct",
                workload=workload, bytes=SIZE, chunk=CHUNK, iterations=ITERATIONS,
                io_bytes=SIZE * ITERATIONS, verified_bytes=SIZE * ITERATIONS, operations=OPERATIONS,
                native_operations=OPERATIONS, posix_operations=0, guards_ok=True, status="pass",
                execution="physical-cuda-cufile", path_evidence="cufile-l3-native-counters",
                compat_allowed=False, io_ns=5, input_id="deterministic-pattern-v1",
                source_window=[0, SIZE], output_residency="vram" if workload == "llm-load" else "file",
                queue_depth=1, direct_io=True, buffer_registration="once-reused", registration_count=1,
                campaign_complete=True, validation_phase="post-campaign", full_byte_compare=True,
                history_operations=OPERATIONS, history_bytes=OPERATIONS * (CHUNK + 2 * GUARD),
                manifest_count=1, capture_in_timing=True)


def args(workload="llm-load"):
    return argparse.Namespace(workload=workload, bytes=SIZE, chunk=CHUNK, iterations=ITERATIONS)


class CampaignResultRelayTests(unittest.TestCase):
    def relay(self, value, workload="llm-load"):
        return runner().checked_result(json.dumps(value) + "\n", args(workload))

    def test_complete_strict_record_is_relayed_for_both_workloads(self):
        for workload in ("llm-load", "checkpoint"):
            with self.subTest(workload=workload):
                self.assertEqual(self.relay(record(workload), workload), record(workload))

    def test_schema1_correctness_record_is_not_promoted(self):
        old = dict(schema_version=1, mode="cufile-direct", workload="llm-load", bytes=SIZE, chunk=CHUNK,
                   iterations=ITERATIONS, io_bytes=SIZE * ITERATIONS, verified_bytes=SIZE * ITERATIONS,
                   operations=OPERATIONS, native_operations=OPERATIONS, posix_operations=0,
                   guards_ok=True, status="pass", execution="physical-cuda-cufile",
                   path_evidence="cufile-l3-native-counters", compat_allowed=False, io_ns=5)
        with self.assertRaises(ValueError):
            self.relay(old)

    def test_requested_campaign_and_native_evidence_must_match(self):
        for key, value in (("workload", "checkpoint"), ("bytes", SIZE + GUARD), ("iterations", 2),
                           ("native_operations", OPERATIONS - 1), ("posix_operations", 1),
                           ("compat_allowed", True), ("output_residency", "file"),
                           ("source_window", [GUARD, SIZE + GUARD]), ("mode", "linux-pinned"),
                           ("validation_phase", "per-chunk"), ("history_bytes", OPERATIONS * CHUNK),
                           ("io_ns", 0), ("direct_io", False)):
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.relay(dict(record(), **{key: value}))

    def test_missing_extra_duplicate_and_non_finite_fields_are_refused(self):
        runner_module = runner()
        for key in record():
            value = record()
            del value[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.relay(value)
        with self.assertRaises(ValueError):
            self.relay(dict(record(), bandwidth=1))
        encoded = json.dumps(record())
        for output in (encoded, encoded[:-1] + ', "io_ns": 6}\n', encoded.replace('"io_ns": 5', '"io_ns": NaN') + "\n"):
            with self.subTest(output=output[-30:]), self.assertRaises(ValueError):
                runner_module.checked_result(output, args())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent strict GDS campaign contracts; no device or performance test.

GDS_CUDA_ROOT must point to official CUDA/cuFile SDK headers for the actual
C++ body observer. Its CUDA/cuFile calls are dependency substitutes, using
ordinary process memory and disposable regular files. Their counters and
logical clock are NOT hardware evidence; captured result JSON is never relayed
as a measurement. Existing test_gds.py separately owns the official build and
the unchanged native L3/no-fallback/source-MOVE/ABI contracts.

Run: GDS_CUDA_ROOT=/official/sdk python3 -B test_campaign_timing.py -v
Only the SDK boundary, clock and final-phase event observer are substituted.
The compiled unit directly includes the current bench_cufile.cc; no duplicate
benchmark loop, comparison code or device/provider model is implemented here.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SDK = Path(os.environ.get("GDS_CUDA_ROOT", "/usr/local/cuda"))
SIZE, CHUNK, ITERATIONS, GUARD = 12288, 8192, 3, 4096
OPERATIONS = ((SIZE + CHUNK - 1) // CHUNK) * ITERATIONS
HISTORY_BYTES = OPERATIONS * (CHUNK + 2 * GUARD)


def runner():
    spec = importlib.util.spec_from_file_location("gds_campaign_actual_runner", HERE / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def comparison_record(mode="cufile-direct"):
    """Independent admission fixture; this does not purport to be a run."""
    record = dict(schema_version=2, measurement_policy="gds-campaign-v1", mode=mode,
                workload="llm-load", bytes=SIZE, chunk=CHUNK, iterations=ITERATIONS,
                io_bytes=SIZE * ITERATIONS, verified_bytes=SIZE * ITERATIONS,
                operations=OPERATIONS, io_ns=1, status="pass", guards_ok=True,
                input_id="deterministic-pattern-v1", source_window=[0, SIZE],
                output_residency="vram", queue_depth=1, direct_io=True,
                buffer_registration="once-reused", registration_count=1,
                campaign_complete=True, validation_phase="post-campaign",
                full_byte_compare=True, history_operations=OPERATIONS,
                history_bytes=HISTORY_BYTES, manifest_count=1, capture_in_timing=True)
    if mode == "cufile-direct":
        record.update(native_operations=OPERATIONS, posix_operations=0,
                      execution="physical-cuda-cufile",
                      path_evidence="cufile-l3-native-counters", compat_allowed=False)
    return record


class ComparisonAdmissionTests(unittest.TestCase):
    def compare(self, left, right):
        function = getattr(runner(), "checked_comparison", None)
        self.assertTrue(callable(function),
                        "missing checked_comparison(left, right): old correctness JSON "
                        "does not establish fair post-campaign performance eligibility")
        return function(left, right)

    def test_same_input_window_residency_qd_direct_and_once_registered_is_admitted(self):
        self.compare(comparison_record("linux-pinned"), comparison_record())

    def test_missing_all_or_any_native_fields_is_rejected(self):
        native = ("native_operations", "posix_operations", "execution",
                  "path_evidence", "compat_allowed")
        left, right = comparison_record("linux-pinned"), comparison_record()
        with self.assertRaises(ValueError):
            self.compare(left, {k: v for k, v in right.items() if k not in native})
        for key in native:
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.compare(left, {k: v for k, v in right.items() if k != key})

    def test_unfair_input_window_residency_qd_direct_or_registration_is_rejected(self):
        mutations = dict(input_id="different-source", source_window=[4096, SIZE],
                         output_residency="host", queue_depth=2, direct_io=False,
                         buffer_registration="per-transfer", registration_count=OPERATIONS)
        for key, value in mutations.items():
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.compare(comparison_record("linux-pinned"),
                             dict(comparison_record(), **{key: value}))

    def test_success_and_ratios_require_full_campaign_final_byte_oracle(self):
        mutations = dict(campaign_complete=False, validation_phase="per-chunk",
                         full_byte_compare=False, guards_ok=False, status="pending",
                         verified_bytes=SIZE, history_operations=OPERATIONS - 1,
                         history_bytes=HISTORY_BYTES - 1, manifest_count=2,
                         capture_in_timing=False)
        for key, value in mutations.items():
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.compare(comparison_record("linux-pinned"),
                             dict(comparison_record(), **{key: value}))

    def test_missing_strict_evidence_is_rejected_including_old_correctness_records(self):
        strict = ("measurement_policy", "input_id", "source_window", "output_residency",
                  "queue_depth", "direct_io", "buffer_registration", "registration_count",
                  "campaign_complete", "validation_phase", "full_byte_compare",
                  "history_operations", "history_bytes", "manifest_count", "capture_in_timing")
        for key in strict:
            record = comparison_record()
            del record[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.compare(comparison_record("linux-pinned"), record)

    def test_evidence_types_are_not_coerced(self):
        for key, value in dict(direct_io=1, campaign_complete=1, manifest_count=True,
                               history_bytes=str(HISTORY_BYTES), queue_depth=True,
                               registration_count=1.0, source_window="0:12288").items():
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.compare(comparison_record("linux-pinned"),
                             dict(comparison_record(), **{key: value}))


@unittest.skipUnless((SDK / "include/cufile.h").is_file() and
                     (SDK / "include/cuda_runtime_api.h").is_file(),
                     "official SDK unavailable; set GDS_CUDA_ROOT for actual-body tests")
class ActualCampaignBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which(os.environ.get("CXX", "c++"))
        if not compiler:
            raise unittest.SkipTest("C++ compiler unavailable")
        (HERE / "build").mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="campaign-contract-", dir=HERE / "build")
        cls.root = Path(cls.temporary.name)
        cls.binary = cls.root / "actual-body"
        command = [compiler, "-std=c++17", "-O0", "-Wall", "-Wextra", "-Werror",
                   "-D_FILE_OFFSET_BITS=64", "-I" + str(SDK / "include"),
                   '-DGDS_BENCH_SOURCE="' + str(HERE / "bench_cufile.cc") + '"',
                   str(HERE / "_campaign_fixture.cc"), "-Wl,--wrap=printf", "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90,
                                env=dict(os.environ, TMPDIR=str(cls.root)))
        if result.returncode:
            cls.temporary.cleanup()
            raise AssertionError("actual-body observer failed to compile with official SDK:\n" + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def execute(self, workload="llm-load", fault="", capacity=None, check_input=False):
        with tempfile.TemporaryDirectory(prefix="run-", dir=self.root) as temporary:
            root = Path(temporary)
            directory = root / "data"
            directory.mkdir(mode=0o700)
            trace = root / "trace"
            source = root / "source"
            env = dict(os.environ, GDS_FIXTURE_TRACE=str(trace), GDS_FIXTURE_FAULT=fault,
                       GDS_FIXTURE_INPUT=str(source))
            if capacity is not None:
                env["GDS_FIXTURE_CAPACITY"] = str(capacity)
            result = subprocess.run([str(self.binary), workload, str(SIZE), str(CHUNK),
                                     str(ITERATIONS), str(directory)], env=env,
                                    capture_output=True, text=True, timeout=15)
            events = []
            for line in trace.read_text().splitlines():
                name, operation, size, offset = line.split()
                events.append(dict(name=name, operation=int(operation), size=int(size), offset=int(offset)))
            self.assertEqual(list(directory.iterdir()), [], "workload left temporary files")
            self.assertTrue(events, "dependency observer did not run")
            if check_input:
                expected = bytes((index * 37 + index // 251 + trial * 53) % 256
                                 for trial in range(ITERATIONS) for index in range(SIZE))
                self.assertEqual(source.read_bytes(), expected,
                                 "actual complete campaign input differs from independent source formula")
            return result, events

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(json.loads(result.stdout)["status"], "pass")

    def assert_failure_without_success(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "", "failure published success/performance output")

    def test_observer_executes_actual_both_workloads_tail_and_native_contract(self):
        for workload in ("llm-load", "checkpoint"):
            with self.subTest(workload=workload):
                result, events = self.execute(workload, check_input=True)
                self.assert_success(result)
                io = [e for e in events if e["name"] in ("read", "write")]
                self.assertEqual(len(io), OPERATIONS)
                self.assertEqual(sum(e["size"] for e in io), SIZE * ITERATIONS)
                self.assertEqual([e["size"] for e in io], [CHUNK, SIZE - CHUNK] * ITERATIONS)
                self.assertEqual(sum(e["name"] == "register" for e in events), 1)
                self.assertEqual(sum(e["name"] == "direct-handle" for e in events), 1)
                self.assertNotIn("compat-enabled", [e["name"] for e in events])
                self.assertIn("stats-retrieve", [e["name"] for e in events])

    def test_no_gpu_or_file_oracle_readback_until_every_campaign_operation_finishes(self):
        for workload in ("llm-load", "checkpoint"):
            with self.subTest(workload=workload):
                result, events = self.execute(workload)
                self.assert_success(result)
                observed = [e for e in events if e["name"] in ("readback", "file-readback")]
                self.assertTrue(observed)
                self.assertTrue(all(e["operation"] == OPERATIONS for e in observed),
                                "full oracle readback ran before campaign completion: " + repr(observed))

    def test_final_oracle_and_unique_manifest_have_observable_final_phase_order(self):
        result, events = self.execute()
        self.assert_success(result)
        names = [e["name"] for e in events]
        for phase in ("campaign-end", "oracle-begin", "oracle-end", "manifest"):
            self.assertEqual(names.count(phase), 1, "missing/repeated final-phase event " + phase)
        positions = [names.index(phase) for phase in
                     ("campaign-end", "oracle-begin", "oracle-end", "manifest", "publish", "returned")]
        self.assertEqual(positions, sorted(positions))
        for index, event in enumerate(events):
            if event["name"] in ("readback", "file-readback"):
                self.assertTrue(positions[1] < index < positions[2],
                                "complete readback must belong to the one final oracle")

    def test_history_capacity_is_admitted_before_first_submit(self):
        # One reusable old chunk fits. All six independent output+guard slots do not.
        result, events = self.execute(capacity=2 * (CHUNK + 2 * GUARD))
        self.assert_failure_without_success(result)
        self.assertFalse(any(e["name"] in ("read", "write") for e in events),
                         "campaign started despite insufficient complete raw-history capacity")

    def test_earliest_payload_and_all_guard_regions_are_retained_until_final_oracle(self):
        for workload in ("llm-load", "checkpoint"):
            for fault in ("payload-first", "prefix-first", "tail-first",
                          "prefix-edge-first", "suffix-edge-first",
                          "unused-tail-partial", "payload-early-trial"):
                with self.subTest(workload=workload, fault=fault):
                    result, events = self.execute(workload, fault)
                    self.assert_failure_without_success(result)
                    self.assertEqual(sum(e["name"] in ("read", "write") for e in events), OPERATIONS,
                                     "payload/guard oracle aborted an early chunk; it must run once after campaign")

    def test_checkpoint_first_trial_storage_error_survives_later_clean_overwrites(self):
        result, events = self.execute("checkpoint", "file-first")
        self.assert_failure_without_success(result)
        self.assertEqual(sum(e["name"] == "write" for e in events), OPERATIONS,
                         "checkpoint storage oracle ran between trials, not after campaign")

    def test_final_readback_covers_all_output_and_unused_tail_guard_history_bytes(self):
        for workload in ("llm-load", "checkpoint"):
            with self.subTest(workload=workload):
                result, events = self.execute(workload)
                self.assert_success(result)
                readbacks = [e for e in events if e["name"] == "readback" and e["operation"] == OPERATIONS]
                intervals = sorted((e["offset"], e["offset"] + e["size"]) for e in readbacks)
                unique_bytes, end = 0, 0
                for start, stop in intervals:
                    unique_bytes += max(0, stop - max(start, end))
                    end = max(end, stop)
                self.assertGreaterEqual(unique_bytes, HISTORY_BYTES,
                                        "only latest reusable GPU buffer was read back; raw history was lost")

    def test_submit_completion_and_any_raw_capture_cost_are_inside_timer(self):
        result, events = self.execute()
        self.assert_success(result)
        active, pending = False, False
        for event in events:
            name = event["name"]
            if name == "clock":
                if active:
                    self.assertFalse(pending, "timer stopped before native completion")
                active = not active
            elif name in ("read", "write"):
                self.assertTrue(active, "native submission excluded from timer")
                pending = True
            elif name == "complete":
                pending = False
            elif name == "capture":
                self.assertTrue(active, "required raw-history copy excluded from timer")
            elif name in ("readback", "file-readback"):
                self.assertFalse(active, "final readback included in performance timer")
        self.assertFalse(active, "unclosed timer interval")

    def test_exact_short_and_native_path_mismatches_still_refuse_success(self):
        for workload in ("llm-load", "checkpoint"):
            for fault in ("short", "posix", "native-count", "native-bytes", "dynamic-routing"):
                with self.subTest(workload=workload, fault=fault):
                    result, _ = self.execute(workload, fault)
                    self.assert_failure_without_success(result)


if __name__ == "__main__":
    unittest.main()

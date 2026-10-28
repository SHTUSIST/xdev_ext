#!/usr/bin/env python3
"""Independent CLI acceptance. Never executes real CUDA or performance code."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

DEFAULT_TARGET = Path(__file__).resolve().parent
TARGET = Path(os.environ.get("CUDA_HOST_COMPUTE_TARGET", DEFAULT_TARGET))
RUNNER = TARGET / "run.py"
BASE = ["--mode", "host-fixture", "--bytes", "24", "--frames", "3", "--rounds", "3"]


class Contract(unittest.TestCase):
    def invoke(self, args, expected=0, missing_nvcc=False):
        self.assertTrue(RUNNER.is_file(), "feature absent: cuda_host_compute/run.py missing")
        env = os.environ.copy()
        if missing_nvcc:
            env["NVCC"] = "/nonexistent-cuda-host-compute-test/nvcc"
        p = subprocess.run([sys.executable, str(RUNNER), *args], text=True,
                           capture_output=True, env=env, timeout=60)
        self.assertEqual(p.returncode, expected, (p.stdout, p.stderr))
        return p

    def record(self, args=BASE, expected=0, missing_nvcc=False):
        p = self.invoke(args, expected, missing_nvcc)
        lines = p.stdout.strip().splitlines()
        self.assertEqual(len(lines), 1, "exactly one final JSON record required")
        try:
            row = json.loads(lines[0])
        except ValueError as e:
            self.fail(f"final JSON required: {e}: {p.stdout!r}")
        self.assertEqual(row.get("schema"), "cuda-host-compute-v1")
        self.assertEqual(row.get("scope"), "correctness-only")
        self.assertIs(row.get("performance_measured"), False)
        self.no_performance(row)
        return row

    def no_performance(self, value):
        if isinstance(value, dict):
            for k, v in value.items():
                self.assertIsNone(re.search(r"(?:timing|throughput|latency|bandwidth|elapsed|duration|gbs|gbit|_ns$|_us$|_ms$)", k, re.I), k)
                self.no_performance(v)
        elif isinstance(value, list):
            for v in value:
                self.no_performance(v)

    def test_help_without_dependencies(self):
        p = self.invoke(["--help"])
        self.assertIn("host-fixture", p.stdout)
        self.assertIn("cuda-correctness", p.stdout)
        self.assertIn("correctness", p.stdout.lower())

    def test_all_routes_shapes_full_oracle_counts(self):
        row = self.record()
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["mode"], "host-fixture")
        self.assertEqual(row["backend"], "host-scalar-fixture")
        self.assertEqual(row["resource_semantics"], "simulated")
        self.assertEqual((row["bytes_per_frame"], row["frames"], row["rounds"]), (24, 3, 3))
        self.assertEqual(row["setup"], {"host_allocations": 2, "host_registrations": 2, "device_allocations": 1})
        self.assertEqual(row["steady"], {"host_allocations": 0, "host_registrations": 0, "device_allocations": 0})
        self.assertEqual(row["cleanup"], {"host_frees": 2, "host_unregistrations": 2, "device_frees": 1})
        cases = row["cases"]
        self.assertEqual(len(cases), 6)
        self.assertEqual({(x["route"], x["shape"]) for x in cases},
                         {(r, s) for r in ("mapped-host", "staged") for s in ("per-frame", "batch", "single-launch")})
        for x in cases:
            with self.subTest(route=x["route"], shape=x["shape"]):
                self.assertEqual(x["rounds_verified"], 3)
                self.assertEqual(x["payload_bytes_verified"], 216)
                self.assertEqual(x["guard_bytes_verified"], 384)
                self.assertEqual(x["kernel_launches"], 3 if x["shape"] == "single-launch" else 9)
                self.assertEqual(x["kernel_syncs"], 9 if x["shape"] == "per-frame" else 3)
                self.assertEqual(x["h2d_bytes"], 216 if x["route"] == "staged" else 0)
                self.assertEqual(x["d2h_bytes"], 216 if x["route"] == "staged" else 0)

    def test_non_power_of_two_and_single_word_frames(self):
        for b, f, r in ((8, 1, 1), (40, 5, 4), (4104, 3, 2)):
            with self.subTest(b=b, f=f, r=r):
                row = self.record(["--mode", "host-fixture", "--bytes", str(b), "--frames", str(f), "--rounds", str(r)])
                self.assertEqual(row["status"], "ok")
                self.assertTrue(all(x["payload_bytes_verified"] == b*f*r for x in row["cases"]))

    def test_shape_selection(self):
        for shape in ("per-frame", "batch", "single-launch"):
            with self.subTest(shape=shape):
                row = self.record(BASE + ["--shape", shape])
                self.assertEqual(len(row["cases"]), 2)
                self.assertEqual({x["shape"] for x in row["cases"]}, {shape})

    def test_corruption_last_payload_byte_later_round(self):
        self.assert_corruption_all_cases("payload-last")

    def test_corruption_prefix_later_round(self):
        self.assert_corruption_all_cases("prefix")

    def test_corruption_suffix_later_round(self):
        self.assert_corruption_all_cases("suffix")

    def assert_corruption_all_cases(self, fault):
        for route in ("mapped-host", "staged"):
            for shape in ("per-frame", "batch", "single-launch"):
                with self.subTest(fault=fault, route=route, shape=shape):
                    self.assert_failure(fault, 1, ["--fault-route", route, "--fault-shape", shape])

    def assert_failure(self, fault, code, extra=None):
        row = self.record(BASE + ["--inject", fault, "--fault-round", "2", *(extra or [])], code)
        self.assertEqual(row["status"], "unknown" if code == 3 else "error")
        self.assertEqual(row["cases"], [])
        self.assertTrue(row.get("reason"))
        return row

    def test_launch_error_is_failure(self):
        self.assert_failure("launch-error", 1)

    def test_copy_error_is_failure(self):
        self.assert_failure("copy-error", 1)

    def test_unknown_retains_all_owned_resources(self):
        row = self.assert_failure("sync-unknown", 3)
        self.assertEqual(row["cleanup"], {"host_frees": 0, "host_unregistrations": 0, "device_frees": 0})

    def test_cleanup_failure_blocks_success(self):
        self.assert_failure("cleanup-error", 1)

    def test_missing_nvcc_is_exit4_without_success(self):
        row = self.record(["--mode", "cuda-correctness", "--bytes", "24", "--frames", "3", "--rounds", "3"],
                          4, missing_nvcc=True)
        self.assertEqual(row["mode"], "cuda-correctness")
        self.assertEqual(row["status"], "unavailable")
        self.assertEqual(row["cases"], [])
        self.assertTrue(row.get("reason"))

    def test_bad_cli_rejected_before_dependencies(self):
        bad = (["--bytes", "0"], ["--bytes", "7"], ["--bytes", "-8"],
               ["--bytes", "8.0"], ["--bytes", "+8"], ["--bytes", "18446744073709551616"],
               ["--frames", "0"], ["--frames", "4097"], ["--rounds", "0"], ["--rounds", "1001"],
               ["--bytes", "67108864", "--frames", "2"], ["--shape", "bogus"],
               ["--performance"], ["junk"], ["--bytes", "24", "--bytes", "32"],
               ["--inject", "payload-last", "--fault-round", "3"],
               ["--inject", "payload-last", "--shape", "single-launch"])
        for suffix in bad:
            with self.subTest(suffix=suffix):
                p = self.invoke(["--mode", "host-fixture", *suffix], 2)
                self.assertNotIn('"status": "ok"', p.stdout)

    def test_cuda_fault_flags_rejected_without_cuda_execution(self):
        self.invoke(["--mode", "cuda-correctness", "--inject", "sync-unknown"], 2, missing_nvcc=True)

    def test_public_artifacts_no_private_paths_or_hardware_claim(self):
        self.assertTrue(TARGET.is_dir(), "feature absent: target directory missing")
        allowed = {".py", ".cpp", ".cc", ".h", ".hpp", ".cu", ".md", ".sh"}
        seen_cuda = False
        for p in TARGET.rglob("*"):
            if not p.is_file() or p.suffix not in allowed:
                continue
            body = p.read_text()
            seen_cuda |= p.suffix == ".cu"
            self.assertNotRegex(body, r"/ro" r"ot/|67" r"87p|RTX PRO " r"6000|0\.26 Gbit|gh[pousr]_[A-Za-z0-9]{20,}")
        self.assertTrue(seen_cuda, "migrated CUDA kernel source required; host model alone is not migration")


if __name__ == "__main__":
    unittest.main(verbosity=2)

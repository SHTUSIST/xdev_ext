#!/usr/bin/env python3
"""Independent SPDK-pipeline acceptance; no test executes a device or a VM.

The offline fixture exercises file→TCP bytes only. It is neither SPDK nor DMA.
Run: python3 tests/eval/spdk/test_contract.py -v
SPDK_PIPELINE_TARGET optionally selects an independent implementation directory.
"""
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
TARGET = Path(os.environ.get("SPDK_PIPELINE_TARGET", HERE)).resolve()
RUNNER = TARGET / "run.py"
MASK = (1 << 64) - 1


def slots(count, maximum):
    """Independent, explicitly unsigned transcription of the preserved trace."""
    result = []
    for i in range(count):
        x = (i + 1) & MASK
        x ^= x >> 12
        x ^= (x << 25) & MASK
        x ^= x >> 27
        result.append(((x * 2685821657736338717) & MASK) % maximum)
    return result


def strict_json(stdout):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out
    if not stdout.endswith("\n") or len(stdout.splitlines()) != 1:
        raise ValueError("exactly one JSON line required")
    return json.loads(stdout, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError("non-finite number")))


class Contract(unittest.TestCase):
    def setUp(self):
        # Keep all test data inside the project, including subprocess scratch.
        self.tmp = tempfile.TemporaryDirectory(prefix=".spdk-contract-", dir=HERE)
        self.root = Path(self.tmp.name)
        self.reference = self.root / "reference.bin"
        self.payload = random.Random(0x5344504B).randbytes(16384)
        self.reference.write_bytes(self.payload)
        self.reference.chmod(0o400)
        self.capture = self.root / "received.bin"
        self.sdk = self.root / "sdk-does-not-exist"
        self.env = os.environ.copy()
        self.env["TMPDIR"] = str(self.root)
        self.base = dict(mode="offline-check", traddr="0000:01:00.0", nsid="7",
                         sector_size="512", namespace_lbas="4096",
                         start_lba="101", window_lbas="32", block_bytes="1024",
                         iterations="7", warmup="2", calc_bytes="24",
                         deadline_ms="1000", reference=str(self.reference),
                         capture=str(self.capture))

    def tearDown(self):
        self.assertEqual(self.reference.read_bytes(), self.payload,
                         "reference source must remain unchanged")
        self.assertEqual(self.reference.stat().st_mode & 0o777, 0o400)
        self.tmp.cleanup()

    def args(self, changes=None):
        options = dict(self.base)
        options.update(changes or {})
        return [arg for key, value in options.items() if value is not None
                for arg in ("--" + key.replace("_", "-"), str(value))]

    def invoke(self, args, code=0):
        self.assertTrue(RUNNER.is_file(), "feature absent: spdk/run.py missing")
        p = subprocess.run([sys.executable, str(RUNNER), *args], env=self.env,
                           capture_output=True, text=True, timeout=20)
        self.assertEqual(p.returncode, code, (p.stdout, p.stderr))
        if code:
            self.assertEqual(p.stdout, "", "failure/refusal must emit no success row")
            self.assertTrue(p.stderr.strip(), "failure/refusal reason required")
        return p

    def row(self, changes=None, extra=()):
        p = self.invoke(self.args(changes) + list(extra))
        try:
            row = strict_json(p.stdout)
        except ValueError as error:
            self.fail(str(error))
        self.assertIs(type(row), dict)
        self.assertEqual(row.get("schema"), "spdk-pipeline-v1")
        self.assertIs(row.get("performance_measured"), False)
        self.assertIs(row.get("physical_execution"), False)
        for key in row:
            self.assertIsNone(re.search(r"(?:_ns$|_us$|_ms$|throughput|bandwidth|latency|speedup|elapsed)", key, re.I), key)
        return row

    def expected(self, iterations=7, warmup=2, block=1024):
        return b"".join(self.payload[s * block:(s + 1) * block]
                        for s in slots(iterations + warmup, len(self.payload) // block))

    def assert_offline(self, row, *, iterations=7, warmup=2, block=1024, calc=24):
        expected = self.expected(iterations, warmup, block)
        self.assertEqual(self.capture.read_bytes(), expected,
                         "independent full stream byte oracle, including warmup")
        self.assertEqual(row["mode"], "offline-check")
        self.assertEqual(row["execution"], "offline-host-file-tcp")
        self.assertEqual(row["status"], "pass")
        self.assertEqual(row["operations"], iterations + warmup)
        self.assertEqual(row["received_bytes"], len(expected))
        self.assertEqual(row["verified_bytes"], len(expected))
        self.assertIs(row["guards_ok"], True)
        self.assertEqual(row["payload_allocations"], 1)
        self.assertEqual(row["steady_payload_allocations"], 0)
        self.assertEqual(row["native_submissions"], 0)
        accumulator = 0
        for off in range(0, len(expected), block):
            accumulator ^= sum(int.from_bytes(expected[j:j + 8], "little")
                               for j in range(off, off + calc, 8)) & MASK
        self.assertEqual(row["calc_xor"], f"{accumulator:016x}")

    def test_help_is_dependency_free_and_safe(self):
        p = self.invoke(["--help"])
        for text in ("plan", "offline-check", "native-correctness", "native-performance"):
            self.assertIn(text, p.stdout)
        self.assertFalse(self.capture.exists())

    def test_no_default_mode_or_device(self):
        self.invoke([], 2)
        for key in ("mode", "traddr", "nsid", "start_lba", "window_lbas"):
            with self.subTest(missing=key):
                self.invoke(self.args({key: None}), 2)

    def test_plan_preserves_trace_and_explicit_read_only_geometry(self):
        row = self.row(dict(mode="plan", reference=None, capture=None))
        self.assertEqual(row["mode"], "plan")
        self.assertEqual(row["execution"], "metadata-only")
        self.assertEqual(row["traddr"], "0000:01:00.0")
        self.assertEqual(row["nsid"], 7)
        self.assertEqual(row["queue_depth"], 1)
        self.assertIs(row["read_only"], True)
        self.assertEqual(row["scheduled_lbas"], [101 + s * 2 for s in slots(9, 16)])
        self.assertEqual(row["stream_bytes"], 9216)
        self.assertFalse(self.capture.exists())

    def test_full_offline_stream_and_reused_buffer(self):
        self.assert_offline(self.row())

    def test_zero_warmup_and_zero_calculation(self):
        row = self.row(dict(warmup="0", calc_bytes="0"))
        self.assert_offline(row, warmup=0, calc=0)

    def test_non_power_of_two_block_and_max_calculation(self):
        # 1536-byte blocks deliberately leave an unused suffix in the window.
        row = self.row(dict(block_bytes="1536", calc_bytes="1536", iterations="3"))
        self.assert_offline(row, iterations=3, block=1536, calc=1536)

    def test_partial_tcp_io_and_eintr_preserve_all_bytes(self):
        self.assert_offline(self.row(extra=("--send-max", "3", "--recv-max", "7",
                                           "--inject", "send-eintr,recv-eintr")))

    def test_corruption_and_incomplete_receiver_are_failures(self):
        for fault in ("payload-first", "payload-middle", "payload-last",
                      "guard-head", "guard-tail", "receiver-early-eof",
                      "receiver-extra", "send-zero", "receiver-stall"):
            with self.subTest(fault=fault):
                self.capture.unlink(missing_ok=True)
                self.invoke(self.args() + ["--inject", fault], 1)

    def test_existing_capture_never_truncated(self):
        self.capture.write_bytes(b"owned-existing-output")
        self.invoke(self.args(), 2)
        self.assertEqual(self.capture.read_bytes(), b"owned-existing-output")

    def test_reference_geometry_and_file_kind_checked(self):
        short = self.root / "short.bin"
        short.write_bytes(self.payload[:-1])
        link = self.root / "link.bin"
        link.symlink_to(self.reference)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        for path in (short, link, fifo, self.root, self.root / "missing"):
            with self.subTest(path=path.name):
                self.invoke(self.args(dict(reference=path)), 2)
                self.assertFalse(self.capture.exists())

    def test_strict_numeric_and_geometry_validation(self):
        mutations = dict(iterations=("0", "-1", "1x", "1.5", "65537"),
                         warmup=("-1", "4097"), block_bytes=("0", "513", "1048577"),
                         calc_bytes=("-1", "7", "1032"), sector_size=("0", "511", "8192"),
                         namespace_lbas=("0", "100"), start_lba=("-1", "4080"),
                         window_lbas=("0", "1", "18446744073709551616"),
                         nsid=("0", "-1", "4294967295"),
                         deadline_ms=("0", "-1", "60001"),
                         traddr=("", "*", "01:00.0", "0000:01:00.8", "../device"))
        for key, values in mutations.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.invoke(self.args({key: value}), 2)
        # Overflow/total-stream cap and singleton duplicate rejection.
        self.invoke(self.args(dict(iterations="65536", block_bytes="1048576",
                                   window_lbas="2048", namespace_lbas="8192")), 2)
        self.invoke(self.args() + ["--iterations", "7"], 2)
        self.invoke(self.args() + ["--unknown-option"], 2)

    def test_native_requires_explicit_isolation_before_sdk_or_devices(self):
        self.invoke(self.args(dict(mode="native-correctness")) +
                    ["--spdk-root", str(self.sdk)], 2)
        self.assertFalse(self.capture.exists())

    def test_missing_official_sdk_refuses_without_success_or_capture(self):
        # The nonexistent SDK is checked before ANY native binary/device call.
        p = self.invoke(self.args(dict(mode="native-correctness")) +
                        ["--spdk-root", str(self.sdk), "--ack-isolated-read-only"], 4)
        self.assertRegex(p.stderr.lower(), r"spdk|sdk")
        self.assertFalse(self.capture.exists())

    def test_native_injection_forbidden_even_with_missing_sdk(self):
        self.invoke(self.args(dict(mode="native-correctness")) +
                    ["--spdk-root", str(self.sdk), "--ack-isolated-read-only",
                     "--inject", "send-eintr"], 2)

    def test_performance_requires_second_explicit_gate(self):
        self.invoke(self.args(dict(mode="native-performance")) +
                    ["--spdk-root", str(self.sdk), "--ack-isolated-read-only"], 2)
        self.assertFalse(self.capture.exists())

    def test_migrated_native_source_is_present(self):
        self.assertTrue((TARGET / "bench_nvme_pipeline.c").is_file(),
                        "feature absent: migrated native source missing")


class OracleSelfTests(unittest.TestCase):
    def test_trace_has_fixed_unsigned_64bit_known_answer(self):
        self.assertEqual(slots(5, 16), [13, 10, 7, 1, 4])

    def test_result_parser_rejects_duplicate_and_nonfinite_fields(self):
        self.assertEqual(strict_json('{"a":1}\n'), {"a": 1})
        for value in ('{"a":1,"a":2}\n', '{"a":NaN}\n', '{}', '{}\n\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                strict_json(value)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Independent GDS CLI contract tests; never substitute a simulated GPU.

Run with python3 tests/eval/gds/test_gds.py -v. GDS_CUDA_ROOT optionally
selects an official SDK for the build-only and physical-device absence checks.
No test invokes the benchmark on a host exposing an NVIDIA device.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ENTRY = HERE / "run.py"
REPO = HERE.parents[2]
SDK = Path(os.environ.get("GDS_CUDA_ROOT", "/usr/local/cuda"))


def validate_result(record, *, workload, size, chunk, iterations):
    """Independent exact schema/count oracle, not imported from implementation."""
    expected = {
        "schema_version": 1, "mode": "cufile-direct", "workload": workload,
        "bytes": size, "chunk": chunk, "iterations": iterations,
        "io_bytes": size * iterations, "verified_bytes": size * iterations,
        "operations": ((size + chunk - 1) // chunk) * iterations,
        "native_operations": ((size + chunk - 1) // chunk) * iterations,
        "posix_operations": 0, "guards_ok": True, "status": "pass",
        "execution": "physical-cuda-cufile",
        "path_evidence": "cufile-l3-native-counters", "compat_allowed": False,
    }
    if type(record) is not dict or set(record) != set(expected) | {"io_ns"}:
        raise ValueError("result fields differ from exact contract")
    for name, wanted in expected.items():
        if type(record[name]) is not type(wanted) or record[name] != wanted:
            raise ValueError("invalid field: " + name)
    if type(record["io_ns"]) is not int or record["io_ns"] <= 0:
        raise ValueError("io_ns must be a positive integer")


def parse_result(stdout, **geometry):
    if not stdout.endswith("\n") or len(stdout.splitlines()) != 1:
        raise ValueError("runtime result must be exactly one JSON line")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    record = json.loads(stdout, object_pairs_hook=unique_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(
                            ValueError("non-finite JSON number")))
    validate_result(record, **geometry)
    return record


def tree_snapshot(directory):
    """Detect changed bytes, modes, timestamps, inode, links or new entries."""
    snapshot = {}
    for item in sorted(directory.rglob("*")):
        info = item.lstat()
        digest = None
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256(item.read_bytes()).hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            digest = os.readlink(item)
        snapshot[str(item.relative_to(directory))] = (
            info.st_mode, info.st_ino, info.st_size, info.st_mtime_ns, digest)
    return snapshot


class ResultOracleTests(unittest.TestCase):
    def setUp(self):
        self.geometry = dict(workload="llm-load", size=12288,
                             chunk=8192, iterations=3)
        self.valid = dict(schema_version=1, mode="cufile-direct",
                          workload="llm-load", bytes=12288, chunk=8192,
                          iterations=3, io_bytes=36864, verified_bytes=36864,
                          operations=6, native_operations=6, posix_operations=0,
                          guards_ok=True, status="pass",
                          execution="physical-cuda-cufile",
                          path_evidence="cufile-l3-native-counters", io_ns=1,
                          compat_allowed=False)

    def test_valid_nondivisible_chunk_schedule_and_checkpoint(self):
        validate_result(self.valid, **self.geometry)
        record = dict(self.valid, workload="checkpoint")
        validate_result(record, **dict(self.geometry, workload="checkpoint"))

    def test_each_field_missing_or_extra_rejected(self):
        for key in self.valid:
            with self.subTest(missing=key):
                record = dict(self.valid)
                del record[key]
                with self.assertRaises(ValueError):
                    validate_result(record, **self.geometry)
        for key in ("speedup", "bandwidth", "gpu_emulated", "estimated"):
            with self.subTest(extra=key), self.assertRaises(ValueError):
                validate_result(dict(self.valid, **{key: 1}), **self.geometry)

    def test_mutated_types_counts_geometry_path_and_guard_proofs_rejected(self):
        for key, value in self.valid.items():
            replacements = [None, [], {}, str(value)]
            if type(value) is int:
                replacements += [True, False, float(value), value + 1, -1]
            elif type(value) is bool:
                replacements += [int(value), not value]
            else:
                replacements += ["posix", "cpu", "pass-without-proof"]
            for replacement in replacements:
                if type(value) is type(replacement) and value == replacement:
                    continue
                # Any positive integer timing satisfies the stated contract.
                if key == "io_ns" and type(replacement) is int and replacement > 0:
                    continue
                with self.subTest(field=key, value=replacement):
                    with self.assertRaises(ValueError):
                        validate_result(dict(self.valid, **{key: replacement}),
                                        **self.geometry)
        for key in ("io_ns", "native_operations", "verified_bytes"):
            with self.subTest(zero=key), self.assertRaises(ValueError):
                validate_result(dict(self.valid, **{key: 0}), **self.geometry)

    def test_no_hardware_or_performance_only_result_rejected(self):
        for record in ({"status": "skip", "io_ns": 1},
                       {"status": "pass", "bandwidth": 1},
                       dict(self.valid, execution="cpu-model"),
                       dict(self.valid, path_evidence="driver-open"),
                       dict(self.valid, path_evidence="nvidia-fs-present"),
                       dict(self.valid, compat_allowed=True),
                       dict(self.valid, posix_operations=6),
                       dict(self.valid, native_operations=0)):
            with self.subTest(record=record), self.assertRaises(ValueError):
                validate_result(record, **self.geometry)

    def test_exact_json_line_and_duplicate_fields(self):
        encoded = json.dumps(self.valid)
        parse_result(encoded + "\n", **self.geometry)
        for output in (encoded, encoded + "\n\n", "log\n" + encoded + "\n",
                       encoded + "\n" + encoded + "\n",
                       encoded[:-1] + ', "io_ns": 2}\n',
                       encoded.replace('"io_ns": 1', '"io_ns": NaN') + "\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                parse_result(output, **self.geometry)


class CLIContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gds-contract-")
        self.root = Path(self.temp.name)
        self.directory = self.root / "data"
        self.directory.mkdir(mode=0o700)
        self.sentinel = self.directory / "existing-user-file"
        self.sentinel.write_bytes(b"preserve-existing-user-data\x00" * 113)
        self.sentinel.chmod(0o640)
        (self.directory / "user-link").symlink_to(self.sentinel.name)
        self.missing_sdk = self.root / "missing-sdk"
        self.before = tree_snapshot(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def command(self, **changes):
        options = dict(mode="cufile-direct", workload="llm-load", bytes="12288",
                       chunk="8192", iterations="2", directory=str(self.directory),
                       cuda_root=str(self.missing_sdk))
        options.update(changes)
        args = []
        for key, value in options.items():
            if value is not None:
                args += ["--" + key.replace("_", "-"), str(value)]
        return [sys.executable, str(ENTRY)] + args

    def invoke(self, command, *, env=None, timeout=90):
        result = subprocess.run(command, cwd=REPO, env=env, text=True,
                                capture_output=True, timeout=timeout)
        self.assertTrue(ENTRY.is_file(),
                        "GDS CLI entrypoint is absent; actual subprocess exit="
                        + str(result.returncode) + "; stderr=" + result.stderr)
        self.assertEqual(tree_snapshot(self.root), self.before,
                         "CLI modified preexisting input or left temporary artifacts")
        return result

    def assert_exit(self, command, code, *, env=None):
        result = self.invoke(command, env=env)
        self.assertEqual(result.returncode, code,
                         f"command={command!r}\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertEqual(result.stdout, "", "non-runtime-success stdout must be empty")
        if code == 4:
            self.assertRegex(result.stderr, r"(?i)\bSKIP\b")
        return result

    def test_help_has_no_dependencies_or_file_access(self):
        result = self.invoke([sys.executable, str(ENTRY), "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cufile-direct", result.stdout)

    def test_missing_required_unknown_and_positional_arguments(self):
        self.assert_exit([sys.executable, str(ENTRY)], 2)
        for trailing in (["unexpected-file"], ["--output", str(self.sentinel)],
                         ["--input", str(self.sentinel)], ["--not-an-option"]):
            with self.subTest(trailing=trailing):
                self.assert_exit(self.command() + trailing, 2)

    def test_invalid_mode_and_workload_before_missing_sdk(self):
        for field, value in (("mode", "posix"), ("mode", "compat"),
                             ("mode", "cpu"), ("workload", "hft")):
            with self.subTest(field=field, value=value):
                self.assert_exit(self.command(**{field: value}), 2)

    def test_decimal_numeric_input_validation_before_missing_sdk(self):
        for field in ("bytes", "chunk", "iterations"):
            for value in ("0", "-1", "1.0", "1e4", "0x1000", "+4096",
                          " 4096", "4096 ", "٤٠٩٦", "True", ""):
                with self.subTest(field=field, value=value):
                    self.assert_exit(self.command(**{field: value}), 2)
        for changes in (dict(bytes="1"), dict(bytes="4097"),
                        dict(bytes=str(1024**3 + 4096)), dict(chunk="1"),
                        dict(chunk="4097"), dict(chunk=str(16*1024**2+4096)),
                        dict(bytes="4096", chunk="8192"),
                        dict(iterations="1001")):
            with self.subTest(changes=changes):
                self.assert_exit(self.command(**changes), 2)

    def test_invalid_directory_before_dependency_discovery_and_no_creation(self):
        for directory in (self.root / "does-not-exist", self.sentinel,
                          self.root / "does-not-exist" / "nested"):
            with self.subTest(directory=directory):
                self.assert_exit(self.command(directory=str(directory)), 2)

    def test_missing_sdk_runtime_and_build_only_are_explicit_unsupported(self):
        for workload in ("llm-load", "checkpoint"):
            for extra in ([], ["--build-only"]):
                with self.subTest(workload=workload, extra=extra):
                    self.assert_exit(self.command(workload=workload) + extra, 4)

    def test_incomplete_sdk_is_not_accepted(self):
        self.assert_exit(self.command(cuda_root=str(self.directory)), 4)

    def test_valid_boundaries_reach_dependency_error(self):
        for changes in (dict(bytes="4096", chunk="4096", iterations="1"),
                        dict(bytes=str(1024**3), chunk=str(16*1024**2),
                             iterations="1000"),
                        dict(bytes="12288", chunk="8192", iterations="2")):
            with self.subTest(changes=changes):
                self.assert_exit(self.command(**changes), 4)

    def test_missing_compiler_is_explicit_unsupported(self):
        empty_path = self.root / "empty-path"
        empty_path.mkdir()
        self.before = tree_snapshot(self.root)
        env = dict(os.environ, PATH=str(empty_path))
        self.assert_exit(self.command(cuda_root=str(SDK)) + ["--build-only"],
                         4, env=env)

    def test_official_sdk_build_only_has_no_result_json(self):
        if not (SDK / "include/cufile.h").is_file():
            self.skipTest("official cuFile SDK not installed; missing-SDK tests still run")
        if not (shutil.which("c++") or shutil.which("g++")):
            self.skipTest("no host compiler; compiler absence is tested separately")
        result = self.assert_exit(self.command(cuda_root=str(SDK)) + ["--build-only"], 0)
        self.assertTrue(result.stderr.strip(), "build-only must emit artifact path to stderr")

    def test_no_physical_gpu_is_skip_without_success_or_timing(self):
        if Path("/dev/nvidiactl").exists() or list(Path("/dev").glob("nvidia[0-9]*")):
            self.skipTest("physical device present: this host-only suite does not run hardware")
        if not (SDK / "include/cufile.h").is_file():
            self.skipTest("official SDK unavailable; missing-SDK paths run separately")
        for workload in ("llm-load", "checkpoint"):
            with self.subTest(workload=workload):
                result = self.assert_exit(self.command(cuda_root=str(SDK), workload=workload), 4)
                self.assertNotRegex(result.stderr, r'"(?:io_ns|status|bandwidth|speedup)"\s*:')


if __name__ == "__main__":
    unittest.main()

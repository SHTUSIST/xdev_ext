#!/usr/bin/env python3
"""Build and run the native cuFile storage/GPU workload on real hardware."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
_CPU_MODULES = HERE.parent / "native_trace"
if not _CPU_MODULES.is_dir():
    _CPU_MODULES = HERE.parents[1] / "support/evidence/native_trace"
sys.path.insert(0, str(_CPU_MODULES))
from timer_scope import TimerCpuRun, OptionalTimerCpuRun



def cpu_owner(args, clock="CLOCK_MONOTONIC", *, optional=False):
    import uuid
    output = args.cpu_output
    if output is None and not os.environ.get("XDEV_EXT_EVAL_CPU_OWNER"):
        parent = getattr(args, "build_dir", HERE / "build")
        output = Path(parent) / "cpu-measurements" / str(uuid.uuid4())
    elif output is not None:
        output = Path(output) / str(uuid.uuid4())
    capture = OptionalTimerCpuRun if optional else TimerCpuRun
    return capture(output, cpu_set=args.cpu_set, clock=clock)


def decimal(value):
    if not re.fullmatch(r"[0-9]+", value):
        raise argparse.ArgumentTypeError("expected an ASCII decimal integer")
    # Reject impractically long strings before Python's integer limit.
    if len(value) > 20:
        raise argparse.ArgumentTypeError("integer exceeds supported range")
    return int(value)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu-set")
    parser.add_argument("--cpu-output", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--mode", required=True, choices=["cufile-direct"])
    parser.add_argument("--workload", required=True, choices=["llm-load", "checkpoint"])
    parser.add_argument("--bytes", required=True, type=decimal)
    parser.add_argument("--chunk", required=True, type=decimal)
    parser.add_argument("--iterations", required=True, type=decimal)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--cuda-root", type=Path, default=Path("/usr/local/cuda"))
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    if not (0 < args.bytes <= 1024**3 and args.bytes % 4096 == 0 and
            0 < args.chunk <= min(args.bytes, 16*1024**2) and args.chunk % 4096 == 0 and
            1 <= args.iterations <= 1000):
        parser.error("bytes/chunk must be aligned, bounded and positive; iterations must be 1..1000")
    if not args.directory.is_dir():
        parser.error("--directory must name an existing directory")
    return args


def skip(reason):
    print("SKIP: " + reason, file=sys.stderr)
    return 4


def build(sdk):
    include = sdk / "include"
    if not all((include / h).is_file() for h in ("cuda.h", "cuda_runtime_api.h", "cufile.h")):
        return None, "official CUDA/cuFile development headers unavailable"
    compiler = shutil.which(os.environ.get("CXX", "c++"))
    if not compiler:
        return None, "C++ compiler unavailable"
    libraries = []
    for stem in ("libcufile.so", "libcudart.so"):
        matches = []
        for libdir in (sdk / "lib64", sdk / "lib", sdk / "targets/x86_64-linux/lib"):
            matches += sorted(p for p in libdir.glob(stem + "*") if p.is_file())
        if not matches:
            return None, "official " + stem + " unavailable"
        libraries.append(matches[0].resolve())
    destination = HERE / "build"
    destination.mkdir(exist_ok=True)
    # Atomic replacement: a failed rebuild never executes an older artifact.
    with tempfile.TemporaryDirectory(prefix="compile-", dir=destination) as temporary:
        binary = Path(temporary) / "bench_cufile"
        command = [compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-D_FILE_OFFSET_BITS=64", "-I" + str(include.resolve()),
                   str(HERE / "bench_cufile.cc"), "-o", str(binary)]
        command += [str(p) for p in libraries]
        command += ["-Wl,-rpath," + str(p.parent) for p in libraries]
        result = subprocess.run(command, text=True, capture_output=True, timeout=90)
        if result.returncode:
            print(result.stderr, file=sys.stderr, end="")
            return None, "SDK/compiler cannot build required official cuFile L3 statistics APIs"
        final = destination / "bench_cufile"
        os.replace(binary, final)
    return final, None


GUARD = 4096
POLICY = "gds-campaign-v1"
# Strict campaign evidence common to every compared mode (schema2).  Schema1
# records are correctness-only and never admitted for performance comparison.
CAMPAIGN_FIELDS = ("schema_version", "measurement_policy", "mode", "workload", "bytes", "chunk",
                   "iterations", "io_bytes", "verified_bytes", "operations", "io_ns", "status",
                   "guards_ok", "input_id", "source_window", "output_residency", "queue_depth",
                   "direct_io", "buffer_registration", "registration_count", "campaign_complete",
                   "validation_phase", "full_byte_compare", "history_operations", "history_bytes",
                   "manifest_count", "capture_in_timing")
# Additional native-path evidence that only the cuFile record carries.
CUFILE_FIELDS = ("native_operations", "posix_operations", "execution", "path_evidence", "compat_allowed")
# Fields that must be identical for a fair pair.
PAIRED_FIELDS = ("workload", "bytes", "chunk", "iterations", "io_bytes", "operations", "input_id",
                 "source_window", "output_residency", "queue_depth", "direct_io",
                 "buffer_registration", "registration_count", "history_operations", "history_bytes")
RESIDENCY = {"llm-load": "vram", "checkpoint": "file"}


def _integer(record, key, minimum=0):
    value = record[key]
    if type(value) is not int or value < minimum:
        raise ValueError("invalid integer evidence " + key)
    return value


def checked_campaign(record):
    """Exact strict-campaign record check; no physical truth is inferred from it."""
    if type(record) is not dict:
        raise ValueError("campaign record must be an object")
    mode = record.get("mode")
    allowed = set(CAMPAIGN_FIELDS) | (set(CUFILE_FIELDS) if mode == "cufile-direct" else set())
    if set(record) != allowed:
        raise ValueError("missing or unexpected strict campaign evidence")
    if record["schema_version"] != 2 or type(record["schema_version"]) is not int or \
            record["measurement_policy"] != POLICY or mode not in ("linux-pinned", "cufile-direct") or \
            record["workload"] not in RESIDENCY:
        raise ValueError("record is not a strict gds-campaign-v1 result")
    size, chunk = _integer(record, "bytes", 1), _integer(record, "chunk", 1)
    iterations = _integer(record, "iterations", 1)
    operations = ((size + chunk - 1) // chunk) * iterations
    if size % GUARD or chunk % GUARD or chunk > size:
        raise ValueError("invalid campaign geometry")
    for key, wanted in (("io_bytes", size * iterations), ("verified_bytes", size * iterations),
                        ("operations", operations), ("history_operations", operations),
                        ("history_bytes", operations * (chunk + 2 * GUARD)), ("queue_depth", 1),
                        ("registration_count", 1), ("manifest_count", 1)):
        if _integer(record, key) != wanted:
            raise ValueError("incomplete or inconsistent campaign evidence " + key)
    _integer(record, "io_ns", 1)
    for key, wanted in (("status", "pass"), ("validation_phase", "post-campaign"),
                        ("buffer_registration", "once-reused"),
                        ("output_residency", RESIDENCY[record["workload"]])):
        if type(record[key]) is not str or record[key] != wanted:
            raise ValueError("invalid campaign evidence " + key)
    for key in ("guards_ok", "campaign_complete", "full_byte_compare", "capture_in_timing", "direct_io"):
        if type(record[key]) is not bool or (key != "direct_io" and record[key] is not True):
            raise ValueError("invalid boolean evidence " + key)
    if type(record["input_id"]) is not str or not record["input_id"]:
        raise ValueError("invalid input identity")
    window = record["source_window"]
    if type(window) is not list or len(window) != 2 or any(type(v) is not int for v in window) or \
            window[0] < 0 or window[1] - window[0] != size:
        raise ValueError("invalid source window")
    if mode == "cufile-direct":
        for key, wanted in (("native_operations", operations), ("posix_operations", 0),
                            ("execution", "physical-cuda-cufile"),
                            ("path_evidence", "cufile-l3-native-counters"), ("compat_allowed", False)):
            if type(record[key]) is not type(wanted) or record[key] != wanted:
                raise ValueError("invalid native path evidence " + key)
    return record


def checked_comparison(left, right):
    """Admit a pair only with identical input, window, residency, depth, direct I/O and
    once-reused registration, both validated once after their complete campaigns."""
    left, right = checked_campaign(left), checked_campaign(right)
    for key in PAIRED_FIELDS:
        if type(left[key]) is not type(right[key]) or left[key] != right[key]:
            raise ValueError("unfair comparison: " + key + " differs")
    return dict(workload=left["workload"], left_mode=left["mode"], right_mode=right["mode"],
                left_io_ns=left["io_ns"], right_io_ns=right["io_ns"])


def checked_result(output, args):
    """Reject unexpected/partial output before relaying any measured result."""
    if not output.endswith("\n") or len(output.splitlines()) != 1:
        raise ValueError("expected one native result record")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate result key")
            result[key] = value
        return result
    record = json.loads(output, object_pairs_hook=pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    if type(record) is not dict or set(record) != set(CAMPAIGN_FIELDS) | set(CUFILE_FIELDS):
        raise ValueError("unexpected result schema")
    checked_campaign(record)
    if record["mode"] != "cufile-direct" or record["workload"] != args.workload or \
            record["bytes"] != args.bytes or record["chunk"] != args.chunk or \
            record["iterations"] != args.iterations or record["direct_io"] is not True or \
            record["input_id"] != "deterministic-pattern-v1" or record["source_window"] != [0, args.bytes]:
        raise ValueError("result does not match the requested campaign")
    return record


def checked_manifest(output, record):
    """Require actual observed-byte identity and final verification evidence.

    FNV-1a identifies the complete observed guard/payload image. It is not a
    cryptographic integrity claim and never substitutes for the C++ byte oracle.
    Reconstruct expected bytes outside measurement from the published formula.
    """
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate manifest field")
            result[key] = value
        return result
    rows = []
    lines = output.split("\n")
    for index, line in enumerate(lines):
        # stderr multiplexes LF-delimited JSON evidence and SDK diagnostics.
        # Only JSON whitespace may precede an object; a malformed object must
        # never fall back to the diagnostic path. Keep non-JSON [WARN] text.
        line = line.lstrip(" \t\r")
        if not line:
            continue
        if not line.startswith("{"):
            try:
                json.loads(line)
            except json.JSONDecodeError:
                continue
            raise ValueError("non-object JSON evidence on stderr")
        if index == len(lines) - 1:
            raise ValueError("unterminated campaign manifest")
        rows.append(json.loads(line, object_pairs_hook=pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite manifest number"))))
    if len(rows) != 1 or type(rows[0]) is not dict:
        raise ValueError("expected one actual campaign manifest")
    manifest = rows[0]
    size, chunk, iterations = record["bytes"], record["chunk"], record["iterations"]
    value = 14695981039346656037
    mask = (1 << 64) - 1
    # Keep reconstruction bounded to a single slot, never another full history.
    for iteration in range(iterations):
        for offset in range(0, size, chunk):
            part = min(chunk, size - offset)
            data = bytearray([0xa5]) * (chunk + 2 * GUARD)
            for j in range(part):
                index = offset + j
                data[GUARD + j] = (index * 37 + index // 251 + iteration * 53) % 256
            for byte in data:
                value = ((value ^ byte) * 1099511628211) & mask
    wanted = dict(kind="gds-campaign-manifest", schema_version=1, workload=record["workload"],
        input=dict(id="deterministic-pattern-v1", formula="(index*37+index/251+iteration*53)%256",
                   index_window=[0, size], iteration_window=[0, iterations]),
        geometry=dict(bytes=size, chunk=chunk, iterations=iterations, operations=record["operations"],
                      history_bytes=record["history_bytes"], guard_bytes=GUARD),
        verification=dict(phase="post-campaign", payload_bytes=record["io_bytes"],
                          device_history_bytes=record["history_bytes"],
                          file_bytes=record["io_bytes"] if record["workload"] == "checkpoint" else 0,
                          device_equal=True, file_equal=True, complete=True),
        observed_history_fnv1a64=f"{value:016x}")
    # JSON comparison preserves bool-vs-integer evidence types as well as keys.
    if json.dumps(manifest, sort_keys=True) != json.dumps(wanted, sort_keys=True):
        raise ValueError("manifest identity or verification differs from the requested campaign")
    return manifest


def main():
    args = arguments()
    if args.dry_run:
        print(json.dumps({"status": "planned", "mode": args.mode, "workload": args.workload,
                          "cpu_measurement_plan": cpu_owner(args).plan()}, sort_keys=True))
        return 0
    try:
        binary, reason = build(args.cuda_root)
        if reason:
            return skip(reason)
        if args.build_only:
            print("Built " + str(binary), file=sys.stderr)
            return 0
        if not Path("/dev/nvidiactl").exists():
            return skip("NVIDIA control device unavailable; no temporary workload files created")
        # TemporaryDirectory creates an exclusive mode0700 directory; the
        # executable only creates payload.bin below it using openat/O_EXCL.
        with tempfile.TemporaryDirectory(prefix="xdev-gds-", dir=args.directory.resolve()) as temporary:
            command = [str(binary), args.workload, str(args.bytes), str(args.chunk),
                       str(args.iterations), temporary]
            with cpu_owner(args, optional=True) as cpu:
                result = cpu.run(command, text=True, capture_output=True, timeout=300)
            print(result.stderr, file=sys.stderr, end="")
            if result.returncode:
                return result.returncode if result.returncode in (1, 2, 4) else 1
            record = checked_result(result.stdout, args)
            checked_manifest(result.stderr, record)
        rows = args.iterations * ((args.bytes + args.chunk - 1) // args.chunk + (args.workload == "checkpoint"))
        measurement = cpu.measurement([dict(arm="gds-direct", identity={"workload": args.workload},
            metric="io_ns", keys=list(range(rows)), expected_duration_ns=record["io_ns"],
            endpoint_semantics="chunk-completion-and-checkpoint-fsync", clock="CLOCK_MONOTONIC")])
        # Strict delegates receive precisely their existing record. Owner CPU output is retained separately.
        if measurement is not None:
            try:
                samples_path = measurement.get("artifacts", {}).get("samples_path")
                if samples_path:
                    Path(samples_path).with_name("cpu-measurement.json").write_text(
                        json.dumps(measurement, sort_keys=True) + "\n")
                else:
                    print("CPU measurement unavailable: " + measurement.get("reason", "capture setup refused"), file=sys.stderr)
            except (OSError, ValueError) as error:
                print("CPU measurement summary unavailable: " + str(error), file=sys.stderr)
        print(json.dumps(record, separators=(",", ":")))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("GDS execution failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

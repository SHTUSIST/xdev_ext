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


def decimal(value):
    if not re.fullmatch(r"[0-9]+", value):
        raise argparse.ArgumentTypeError("expected an ASCII decimal integer")
    # Reject impractically long strings before Python's integer limit.
    if len(value) > 20:
        raise argparse.ArgumentTypeError("integer exceeds supported range")
    return int(value)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
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
    record = json.loads(output, object_pairs_hook=pairs)
    operations = ((args.bytes + args.chunk - 1) // args.chunk) * args.iterations
    expected = dict(schema_version=1, mode="cufile-direct", workload=args.workload,
                    bytes=args.bytes, chunk=args.chunk, iterations=args.iterations,
                    io_bytes=args.bytes*args.iterations, verified_bytes=args.bytes*args.iterations,
                    operations=operations, native_operations=operations, posix_operations=0,
                    guards_ok=True, status="pass", execution="physical-cuda-cufile",
                    path_evidence="cufile-l3-native-counters", compat_allowed=False)
    if type(record) is not dict or set(record) != set(expected) | {"io_ns"}:
        raise ValueError("unexpected result schema")
    for key, value in expected.items():
        if type(record[key]) is not type(value) or record[key] != value:
            raise ValueError("invalid result field " + key)
    if type(record["io_ns"]) is not int or record["io_ns"] <= 0:
        raise ValueError("invalid I/O measurement")
    return record


def main():
    args = arguments()
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
            result = subprocess.run(command, text=True, capture_output=True, timeout=300)
            print(result.stderr, file=sys.stderr, end="")
            if result.returncode:
                return result.returncode if result.returncode in (1, 2, 4) else 1
            record = checked_result(result.stdout, args)
        print(json.dumps(record, separators=(",", ":")))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("GDS execution failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

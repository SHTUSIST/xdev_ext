#!/usr/bin/env python3
"""Compile and run a correctness-only scalar fixture or real CUDA workload."""
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
SHAPES = ("per-frame", "batch", "single-launch")
FAULTS = ("payload-last", "prefix", "suffix", "launch-error", "copy-error", "sync-unknown", "cleanup-error")


def positive(text):
    if not re.fullmatch(r"[0-9]+", text) or len(text) > 20:
        raise argparse.ArgumentTypeError("use bounded positive decimal integers")
    return int(text)


def parse(argv):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", choices=("host-fixture", "cuda-correctness"), required=True)
    parser.add_argument("--bytes", type=positive, default=4096)
    parser.add_argument("--frames", type=positive, default=3)
    parser.add_argument("--rounds", type=positive, default=3)
    parser.add_argument("--shape", choices=(*SHAPES, "all"), default="all")
    parser.add_argument("--inject", choices=FAULTS)
    parser.add_argument("--fault-round", type=positive)
    parser.add_argument("--fault-route", choices=("mapped-host", "staged"))
    parser.add_argument("--fault-shape", choices=SHAPES)
    seen = set()
    for arg in argv:
        if arg.startswith("--"):
            option = arg.split("=", 1)[0]
            if option in seen:
                parser.error("duplicate option: " + option)
            seen.add(option)
    args = parser.parse_args(argv)
    if (not args.bytes or args.bytes % 8 or not 1 <= args.frames <= 4096 or
            not 1 <= args.rounds <= 1000 or args.bytes * args.frames > 67108864):
        parser.error("require 8-byte frames, F<=4096, R<=1000, and B*F<=67108864")
    fault_options = any(x is not None for x in (args.fault_round, args.fault_route, args.fault_shape))
    if (args.inject or fault_options) and args.mode != "host-fixture":
        parser.error("fault injection is available only in the offline host fixture")
    if fault_options and not args.inject:
        parser.error("fault selectors require --inject")
    args.fault_round = 0 if args.fault_round is None else args.fault_round
    args.fault_route = args.fault_route or "staged"
    args.fault_shape = args.fault_shape or "batch"
    if args.inject and (args.fault_round >= args.rounds or
                        (args.shape != "all" and args.fault_shape != args.shape)):
        parser.error("fault case must be included in the selected rounds/shape")
    if args.inject == "copy-error" and args.fault_route != "staged":
        parser.error("copy-error requires the staged route")
    return args


def failure(args, status, reason):
    cuda = args.mode == "cuda-correctness"
    return {"schema": "cuda-host-compute-v1", "mode": args.mode,
            "backend": "cuda-runtime" if cuda else "host-scalar-fixture",
            "status": status, "scope": "correctness-only",
            "resource_semantics": "cuda-runtime" if cuda else "simulated",
            "performance_measured": False, "bytes_per_frame": args.bytes,
            "frames": args.frames, "rounds": args.rounds, "cases": [], "reason": reason}


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    cuda = args.mode == "cuda-correctness"
    compiler = os.environ.get("NVCC" if cuda else "CXX", "nvcc" if cuda else "c++")
    if not compiler or not shutil.which(compiler):
        print(json.dumps(failure(args, "unavailable", "requested compiler unavailable")))
        return 4
    architecture = os.environ.get("CUDA_ARCH", "sm_80")
    if cuda and not re.fullmatch(r"sm_[0-9]{2,3}[af]?", architecture):
        print(json.dumps(failure(args, "error", "invalid CUDA_ARCH")))
        return 1
    try:
        with tempfile.TemporaryDirectory(prefix=".build-", dir=HERE) as directory:
            binary = Path(directory) / "workload"
            source = HERE / ("bench_host_compute.cu" if cuda else "host_fixture.cpp")
            command = [compiler, "-std=c++17", "-O2"]
            if cuda:
                command += ["-arch=" + architecture, "--cudart=shared"]
            else:
                command += ["-Wall", "-Wextra", "-Werror"]
            command += [str(source), "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, check=False)
            if built.returncode:
                print(json.dumps(failure(args, "error", "requested compiler failed")))
                return 1
            command = [str(binary), str(args.bytes), str(args.frames), str(args.rounds),
                       args.shape, args.inject or "none", str(args.fault_round),
                       args.fault_route, args.fault_shape]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            try:
                row = json.loads(result.stdout)
                if not isinstance(row, dict) or row.get("schema") != "cuda-host-compute-v1":
                    raise ValueError("invalid worker record")
                if result.returncode not in (0, 1, 3, 4):
                    raise ValueError("unexpected worker status")
            except ValueError:
                print(json.dumps(failure(args, "error", "worker failed without a valid final record")))
                return 1
            print(json.dumps(row))
            return result.returncode
    except OSError:
        print(json.dumps(failure(args, "error", "compiler or worker could not be executed")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

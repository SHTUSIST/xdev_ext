#!/usr/bin/env python3
"""Compile the CUDA source with official nvcc; never execute the GPU workload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch", default=os.environ.get("CUDA_ARCH", "sm_80"))
    args = parser.parse_args()
    if not re.fullmatch(r"sm_[0-9]{2,3}[af]?", args.arch):
        parser.error("use an explicit supported sm architecture")
    compiler = os.environ.get("NVCC", "nvcc")
    if not compiler or not shutil.which(compiler):
        print(json.dumps({"status": "unavailable", "reason": "requested nvcc unavailable"}))
        return 4
    source = Path(__file__).resolve().parent / "bench_host_compute.cu"
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        built = subprocess.run([compiler, "-std=c++17", "-O2", "-arch=" + args.arch,
                                "--cudart=shared", str(source), "-o", str(args.output)],
                               capture_output=True, text=True, check=False)
        if built.returncode:
            # Compiler diagnostics stay on stderr, distinct from the final record.
            import sys
            sys.stderr.write(built.stdout + built.stderr)
            print(json.dumps({"status": "error", "reason": "nvcc compilation failed"}))
            return 1
        print(json.dumps({"status": "built", "execution": "not-run", "architecture": args.arch,
                          "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                          "binary_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}))
        return 0
    except OSError:
        print(json.dumps({"status": "error", "reason": "build could not be completed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

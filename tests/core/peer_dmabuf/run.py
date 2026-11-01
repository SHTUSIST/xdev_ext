#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile and execute the actual host/device shared admission policy.

An executable failure is a behavioral RED. Compile/setup failures use exit 2
and are never presented as successful tests or behavioral feature failures.
This does not instantiate a DMA-BUF, map a device, or measure performance.
"""
from pathlib import Path
import argparse
import json
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
from provenance import PRODUCTION_INPUTS, capture, capture_fixture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    root = args.source_root.resolve()
    here = Path(__file__).resolve().parent
    evidence = args.output.resolve() if args.output else None
    if evidence:
        evidence.mkdir(parents=True, exist_ok=True)
    record = {"environment": "local host GCC",
              "scope": "real shared admission pure rule; no importer/native DMA"}
    temporary_parent = evidence or root / "build"
    temporary_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dmabuf-host-admission-",
                                     dir=temporary_parent) as directory:
        snapshot_parent = evidence or Path(directory)
        record.update(capture(root, PRODUCTION_INPUTS, snapshot_parent / "source-snapshot"))
        compile_root = Path(record["compile_source_root"])
        compile_here, record["fixture_provenance"] = capture_fixture(
            here, snapshot_parent / "test-snapshot")
        source = compile_here / "host_admission_test.c"
        binary = Path(directory) / "host-admission"
        command = ["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                   "-fsanitize=undefined", "-I", str(compile_root / "src/core"),
                   str(source), "-o", str(binary)]
        compile_result = subprocess.run(command, text=True, capture_output=True)
        record["compile_command"] = command
        record["compile_exit"] = compile_result.returncode
        logs = compile_result.stdout + compile_result.stderr
        if compile_result.returncode:
            record["verdict"] = "SETUP_ERROR"
            code = 2
        else:
            result = subprocess.run([str(binary)], text=True, capture_output=True)
            logs += result.stdout + result.stderr
            record["execute_exit"] = result.returncode
            record["verdict"] = "PASS" if result.returncode == 0 else "FAIL"
            code = 0 if result.returncode == 0 else 1
        if evidence:
            (evidence / "output.log").write_text(logs)
            (evidence / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
        print(logs, end="")
        print(json.dumps(record, sort_keys=True))
        return code


if __name__ == "__main__":
    raise SystemExit(main())

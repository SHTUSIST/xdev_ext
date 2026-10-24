#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject compiler-runtime popcount calls in the real kernel lifecycle header.

Requires a prepared x86 kernel output tree and its matching full source tree.
Only an external Kbuild object is built: no modpost, Module.symvers, or module
load is needed. The output tree may receive ordinary Kbuild metadata, so use
an isolated copy when another build is using it. Kernel hweight helpers are
valid unresolved references at this stage; libgcc/compiler-rt helpers are not.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[4]


def run(command):
    print("COMMAND " + shlex.join(map(str, command)), flush=True)
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    print(result.stdout, end="", flush=True)
    result.check_returncode()
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-source", required=True, type=Path)
    parser.add_argument("--kernel-output", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--header", type=Path,
                        default=KERNEL / "io_uring/xdev_ext_mech_lifecycle.h")
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    parser.add_argument("--nm", default=os.environ.get("NM", "nm"))
    args = parser.parse_args()
    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    for name in ("Makefile", "probe.c"):
        shutil.copyfile(HERE / name, build / name)
    shutil.copyfile(args.header, build / "lifecycle.h")
    # A new header copy must never reuse a previously passing object.
    (build / "probe.o").unlink(missing_ok=True)
    run(["make", "-C", str(args.kernel_source.resolve()),
         "O=" + str(args.kernel_output.resolve()), "M=" + str(build),
         "CC=" + args.cc, "V=1", "probe.o"])
    undefined = run(shlex.split(args.nm) + ["-u", str(build / "probe.o")])
    (build / "undefined.txt").write_text(undefined)
    forbidden = re.findall(r"\b__(?:popcount|countones)[A-Za-z0-9_]*", undefined)
    if forbidden:
        print("FAIL: kernel lifecycle requires compiler runtime: " +
              ", ".join(sorted(set(forbidden))), flush=True)
        return 1
    print("PASS: kernel acquire/drop need no compiler-runtime popcount helper", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

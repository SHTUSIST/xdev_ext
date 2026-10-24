#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build and run lifecycle contracts; all failures remain failures, including absent APIs.

This entry does not boot guests or claim device/performance coverage.  The model
runner only reaches its seeded defects once the unmodified header passes.
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[3]
PROGRAMS = ("lifecycle_contract", "refs", "fanout_step", "cpu_xform", "ctl_chains")


def run(command, log):
    print("COMMAND " + shlex.join(map(str, command)), flush=True)
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=180)
        output, code = result.stdout, result.returncode
    except subprocess.TimeoutExpired as err:
        output = (err.stdout or b"")
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        output += "\nERROR: timeout after 180 seconds\n"
        code = 124
    log.write_text(output)
    print(output, end="", flush=True)
    print(f"EXIT {code}", flush=True)
    return code


def suite(build):
    build.mkdir(parents=True, exist_ok=True)
    failures = 0
    cc = shlex.split(os.environ.get("CC", "cc"))
    for name in PROGRAMS:
        binary = build / name
        command = cc + ["-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                        "-pthread", "-fsanitize=undefined", "-fno-sanitize-recover=all",
                        "-I" + str(KERNEL), "-I" + str(HERE / "model/shim"),
                        str(HERE / f"xdev_ext_mech_{name}_test.c"), "-o", str(binary)]
        if run(command, build / f"{name}.build.log"):
            failures += 1
            continue
        failures += bool(run([str(binary)], build / f"{name}.run.log"))
    failures += bool(run(["python3", str(HERE / "xdev_ext_mech_refs_source_test.py")],
                         build / "source.log"))
    failures += bool(run(["sh", str(HERE / "model/refs_run.sh")], build / "model.log"))
    print(f"LIFECYCLE_CONTRACTS={'FAIL' if failures else 'PASS'} failed_programs={failures}",
          flush=True)
    return bool(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    if args.build_dir:
        return suite(args.build_dir.resolve())
    with tempfile.TemporaryDirectory(prefix="xdev-ext-refs-") as name:
        return suite(Path(name))


if __name__ == "__main__":
    raise SystemExit(main())

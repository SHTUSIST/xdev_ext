#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production XDOMAIN login, registry and remove/suspend functions.

Thunderbolt XDomain, ring and workqueue operations are recording boundaries.
This proves local message arguments, epochs and teardown order, not a real
peer's acceptance, native DMA, physical path suitability or Phase H.
Activated after X2 acceptance. Only the explicitly named four test files
participate; declaration-only preflight aids never enter this runner.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
from xdomain_retention_fixture import retention_unit


def strip_includes(text):
    # Only environmental includes change. Every production declaration/body
    # remains byte-for-byte intact, including all branches and cleanup labels.
    return "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("#include")) + "\n"


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", type=Path, default=here.parents[4],
                        help="kernel tree (default: this test's kernel tree)")
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    production = kernel / "io_uring/xdomain"
    needed = [production / name for name in
              ("xdev_ext_xdomain_core.h", "xdev_ext_xdomain.h",
               "xdev_ext_xdomain_main.c")]
    absent = [str(path) for path in needed if not path.is_file()]
    if absent:
        print("TAP version 13\n1..1\nnot ok 1 - X3 preparation guard: production artifacts absent")
        print("# SETUP_MISSING; no behavioral RED/GREEN has run")
        for path in absent:
            print("# missing: " + path)
        return 2
    suffix = ".draft" if __file__.endswith(".draft") else ""
    # No globs/discovery: only explicitly named companions may be compiled.
    compat = (here / ("xdomain_login_compat.h" + suffix)).read_text()
    boundaries = (here / ("xdomain_login_boundaries.c" + suffix)).read_text()
    cases = (here / ("xdomain_login_cases.c" + suffix)).read_text()
    header = strip_includes(needed[1].read_text())
    source = strip_includes(needed[2].read_text())
    unit = (compat + "\nstatic unsigned long jiffies;\n#define time_before(a,b) ((long)((a)-(b))<0)\n#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))\n" + '\n#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n'
            + header + "\n" + boundaries + retention_unit(kernel) + "\n" + source + "\n" + cases)
    with tempfile.TemporaryDirectory(prefix="xdomain-login-") as directory:
        cfile, binary = Path(directory) / "login.c", Path(directory) / "login"
        cfile.write_text(unit)
        build = subprocess.run(["gcc", "-std=gnu11", "-O0", "-g", "-Wall",
                                "-Wextra", "-Wno-unused-parameter",
                                "-Wno-unused-variable", "-Wno-unused-function",
                                "-Werror=implicit-function-declaration", "-I", str(kernel),
                                str(cfile), "-o", str(binary)],
                               text=True, capture_output=True, timeout=60)
        if build.returncode:
            print("# SETUP_COMPILE_ERROR; not a behavioral RED", file=sys.stderr)
            print(build.stdout + build.stderr, file=sys.stderr)
            return 2
        count = int(subprocess.check_output([str(binary), "--count"], text=True, timeout=5))
        print("TAP version 13\n1.." + str(count), flush=True)
        failed = False
        for number in range(1, count + 1):
            result = subprocess.run([str(binary), str(number)], timeout=30)
            if result.returncode:
                failed = True
                if result.returncode < 0:
                    print(f"not ok {number} - fixture terminated by signal {-result.returncode}", flush=True)
        return int(failed)


if __name__ == "__main__":
    sys.exit(main())

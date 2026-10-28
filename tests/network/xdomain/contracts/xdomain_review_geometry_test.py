#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual-source short-tail and snapshot/apply WAIT regressions.

The case/oracle bytes are frozen independently of the production repair. The
existing class/family/reference-policy composition supplies environmental
boundaries only. No physical DMA, performance, or verifier claim.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

import xdomain_review_protocol_test as fixture

HERE = Path(__file__).resolve().parent
CASES = ("tail8192", "tail69632", "elapsed_wait", "invalid_wait", "hard_timeout")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=HERE.parents[4])
    parser.add_argument("--artifact-directory", "--out", dest="out", type=Path)
    parser.add_argument("--case", choices=CASES, action="append")
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    context = nullcontext(str(args.out.resolve())) if args.out else tempfile.TemporaryDirectory(prefix="xdomain-review-geometry-")
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
    with context as directory:
        out = Path(directory)
        source = fixture.source(kernel, HERE)
        before, token, after = source.rpartition("int main(int argc,char **argv)")
        if not token:
            raise ValueError("terminal main absent")
        source = (before + "int p0_unused_terminal_main(int argc,char **argv)" + after + "\n" +
                  (HERE / "xdomain_review_geometry_cases.c").read_text())
        src, binary = out / "geometry.c", out / "geometry"
        src.write_text(source)
        command = ["gcc", "-std=gnu11", "-O1", "-g", "-pthread", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-function", "-fsanitize=undefined", "-fno-sanitize-recover=all",
                   "-I" + str(kernel), str(src), "-o", str(binary)]
        print("COMMAND:", " ".join(command), flush=True)
        subprocess.run(command, check=True)
        failed = 0
        for case in args.case or CASES:
            run = subprocess.run([str(binary), case], timeout=20)
            print(f"{'not ok' if run.returncode else 'ok'} - {case}; exit={run.returncode}", flush=True)
            failed += bool(run.returncode)
        return bool(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print("GEOMETRY REVIEW SETUP FAILURE:", error, file=sys.stderr)
        sys.exit(2)

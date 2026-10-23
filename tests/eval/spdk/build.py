#!/usr/bin/env python3
"""Build the offline host fixture; native SDK compilation is not implemented."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--spdk-root", type=Path)
    a = p.parse_args()
    here = Path(__file__).resolve().parent
    env = os.environ.copy()
    if a.spdk_root:
        print("native SPDK build remains unimplemented/unqualified; offline build only", file=sys.stderr)
        return 4
    cc = shlex.split(os.environ.get("CC", "cc"))
    try:
        result = subprocess.run([*cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                                 "-pthread", str(here / "bench_nvme_pipeline.c"),
                                 "-o", str(a.output)], env=env,
                                capture_output=True, text=True)
    except FileNotFoundError:
        print("C compiler unavailable", file=sys.stderr)
        return 4
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

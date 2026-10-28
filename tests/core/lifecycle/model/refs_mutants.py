#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Show that refs_explore can fail: one seeded defect per new rule.

Each mutant builds refs_explore.c with one -D define that makes the
mechanism core's use of the lifecycle word behave like a defective
implementation (written against the frozen word layout of
io_uring/xdev_ext_mech_lifecycle.h), and requires a VIOLATION of an
expected invariant from the op search or, failing that, the access search.

Usage: refs_mutants.py <kernel dir> <build dir>
"""

import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent

# name, define, expected invariants
MUTANTS = [
    ("double_decrement", "REFS_MUTANT_DOUBLE_DECREMENT", {"INV_REFS"}),
    ("early_free_with_consumer_in_flight", "REFS_MUTANT_EARLY_FREE", {"INV_EARLY_REUSE"}),
    ("missed_generation_increment", "REFS_MUTANT_MISSED_GEN", {"INV_GEN"}),
    ("publish_without_completion_claim", "REFS_MUTANT_PUBLISH_WITHOUT_CLAIM",
     {"INV_STALE_MATCH"}),
    ("failed_consumer_keeps_references", "REFS_MUTANT_FAIL_KEEPS_REFS",
     {"INV_SUPPRESS", "INV_REFS"}),
]


def explore(binary, mode):
    return subprocess.run([str(binary), "--mode", mode], text=True,
                          capture_output=True, timeout=600)


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    kernel = Path(sys.argv[1]).resolve()
    build = Path(sys.argv[2]).resolve()
    cc = os.environ.get("CC", "cc")
    failures = 0

    print("TAP version 13")
    print(f"1..{len(MUTANTS)}")
    for n, (name, define, expected) in enumerate(MUTANTS, 1):
        build.mkdir(parents=True, exist_ok=True)
        binary = build / f"refs_explore.{name}"
        cmd = [cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
               "-I", str(HERE / "shim"), "-I", str(kernel), "-D" + define,
               str(HERE / "refs_explore.c"), "-o", str(binary)]
        built = subprocess.run(cmd, text=True, capture_output=True)
        if built.returncode:
            print(f"not ok {n} - {name}: build failed\n# " +
                  (built.stdout + built.stderr).strip().replace("\n", "\n# "))
            failures += 1
            continue
        run = explore(binary, "op")
        mode = "op"
        if run.returncode == 0:
            run = explore(binary, "access")
            mode = "access"
        found = re.search(r"^VIOLATION (\w+):.*$", run.stdout, re.M)
        if run.returncode != 1 or not found or found.group(1) not in expected:
            print(f"not ok {n} - {name}: exit {run.returncode}, "
                  f"wanted one of {sorted(expected)}\n# " +
                  run.stdout[-1500:].replace("\n", "\n# "))
            failures += 1
            continue
        print(f"ok {n} - {name} -> {found.group(0)} ({mode} search)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Show that life_explore can fail: one seeded defect per invariant.

Each mutant copies one live header (io_uring/xdev_ext_mech_lifecycle.h or
io_uring/xdev_ext_mech_core.h) into a private tree, changes one function body
there, compiles life_explore.c with that tree searched before the kernel tree
and requires a VIOLATION of an expected invariant.  Relative includes of the
copy are pointed back at the live tree.  Two
mutants change the model's own teardown glue through a define instead.

A pattern that no longer occurs exactly once in its function means the
header changed under this test: that is a failure, so the mutant is updated
with the header rather than silently skipped.

Usage: mutants.py <kernel dir> <build dir>
"""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
# Guards are disabled in place, so the mutant compiles under -Werror too.
OVERFLOW_GUARD = ("if ((old >> 3) == XDEV_EXT_MECH_L_GEN_MAX)", "if (0)")

# name, header, function, (old, new), expected invariants, define, op_must_miss
MUTANTS = [
    ("publish_ignores_generation", "lifecycle", "xdev_ext_mech_life_publish",
     ("(old >> 3) != token ||", ""),
     {"INV_STALE_MATCH", "INV_GEN_MONOTONE"}, None, False),
    ("produce_wraps_generation", "lifecycle", "xdev_ext_mech_life_begin_produce",
     OVERFLOW_GUARD, {"INV_GEN_MONOTONE"}, None, False),
    ("consume_wraps_generation", "lifecycle", "xdev_ext_mech_life_begin_consume",
     OVERFLOW_GUARD, {"INV_GEN_MONOTONE"}, None, False),
    ("completion_wraps_ticket", "lifecycle", "xdev_ext_mech_completion_begin",
     OVERFLOW_GUARD, {"INV_GEN_MONOTONE"}, None, False),
    ("cancel_after_claim", "lifecycle", "xdev_ext_mech_completion_cancel",
     ("!XDEV_EXT_L_CAS(&c->ctrl, &old, ticket << 3))",
      "(!XDEV_EXT_L_CAS(&c->ctrl, &old, ticket << 3) &&\n"
      "\t     (old = (ticket << 3) | XDEV_EXT_MECH_C_COMPLETING,\n"
      "\t      !XDEV_EXT_L_CAS(&c->ctrl, &old, ticket << 3))))"),
     {"INV_STALE_MATCH"}, None, False),
    ("release_while_consuming", "lifecycle", "xdev_ext_mech_life_release",
     ("if ((old & XDEV_EXT_MECH_L_MASK) != XDEV_EXT_MECH_L_READY)", "if (0)"),
     {"INV_EARLY_REUSE"}, None, False),
    ("complete_consume_any_generation", "lifecycle",
     "xdev_ext_mech_life_complete_consume",
     ("__u64 old = (token << 3) | XDEV_EXT_MECH_L_OUT_PENDING;",
      "__u64 old = XDEV_EXT_L_LOAD(&l->ctrl);"),
     {"INV_STALE_MATCH", "INV_GEN_MONOTONE"}, None, False),
    # Atomic at step granularity, wrong between its load and its store:
    # only the access-granularity search can see this one.
    ("release_plain_store", "lifecycle", "xdev_ext_mech_life_release",
     ("return XDEV_EXT_L_CAS(&l->ctrl, &old, token << 3) ? 0 : -ESTALE;",
      "XDEV_EXT_L_STORE(&l->ctrl, token << 3);\n\treturn 0;"),
     {"INV_GEN_MONOTONE", "INV_EARLY_REUSE", "INV_STALE_MATCH"}, None, True),
    ("admit_while_stopping", "core", "xdev_ext_mech_sess_admits",
     ("return s->state == XDEV_EXT_MECH_SESSION_ACTIVE;",
      "return s->state == XDEV_EXT_MECH_SESSION_ACTIVE ||\n"
      "\t       s->state == XDEV_EXT_MECH_SESSION_STOPPING;"),
     {"INV_STOP_ADMIT"}, None, False),
    ("drain_ignores_sequestered", "core", "xdev_ext_mech_sess_drain",
     ("if (!s->inflight && !s->sequestered)", "if (!s->inflight)"),
     {"INV_EARLY_REUSE", "INV_QUARANTINE"}, None, False),
    ("destroy_ignores_inflight", None, None, None,
     {"INV_EARLY_REUSE", "INV_TEARDOWN"}, "LIFE_MODEL_MUTANT_DESTROY_IGNORES_INFLIGHT",
     False),
    ("reap_releases_quarantined", None, None, None,
     {"INV_QUARANTINE"}, "LIFE_MODEL_MUTANT_REAP_RELEASES", False),
    ("late_release_ignores_quarantine", None, None, None,
     {"INV_EARLY_REUSE", "INV_QUARANTINE"}, "LIFE_MODEL_MUTANT_LATE_RELEASE_ALWAYS",
     False),
]

HEADERS = {
    "lifecycle": "io_uring/xdev_ext_mech_lifecycle.h",
    "core": "io_uring/xdev_ext_mech_core.h",
}


def function_span(text, name):
    """(start, end) of the braces-delimited body of static inline @name."""
    match = re.search(r"^static inline\b[^;{]*\b" + re.escape(name) + r"\s*\([^;{]*\)\s*\{",
                      text, re.M)
    if not match:
        return None
    depth = 0
    for pos in range(match.end() - 1, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return match.end() - 1, pos + 1
    return None


def mutate(text, function, old, new):
    span = function_span(text, function)
    if span is None:
        return None, f"function {function} not found"
    body = text[span[0]:span[1]]
    if body.count(old) != 1:
        return None, f"pattern occurs {body.count(old)} times in {function}"
    return text[:span[0]] + body.replace(old, new) + text[span[1]:], None


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
    for n, (name, header, function, change, expected, define, op_must_miss) in \
            enumerate(MUTANTS, 1):
        tree = build / "mutants" / name
        shutil.rmtree(tree, ignore_errors=True)
        tree.mkdir(parents=True)
        if header:
            rel = HEADERS[header]
            text, err = mutate((kernel / rel).read_text(), function, *change)
            if err:
                print(f"not ok {n} - {name}: {err} in the live {rel}")
                failures += 1
                continue
            live_dir = (kernel / rel).parent
            text = re.sub(r'^#include "(\.\./[^"]+)"',
                          lambda m: f'#include "{live_dir / m.group(1)}"', text,
                          flags=re.M)
            (tree / rel).parent.mkdir(parents=True)
            (tree / rel).write_text(text)
        binary = tree / "life_explore"
        cmd = [cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
               "-I", str(HERE / "shim"), "-I", str(tree), "-I", str(kernel)]
        if define:
            cmd.append("-D" + define)
        cmd += [str(HERE / "life_explore.c"), "-o", str(binary)]
        built = subprocess.run(cmd, text=True, capture_output=True)
        if built.returncode:
            print(f"not ok {n} - {name}: build failed\n# " +
                  (built.stdout + built.stderr).replace("\n", "\n# "))
            failures += 1
            continue
        # The exhaustive op search is cheap; the access search runs only when
        # the op search found nothing, as it must for op_must_miss mutants.
        detail = ""
        run = explore(binary, "op")
        if op_must_miss:
            if run.returncode != 0:
                print(f"not ok {n} - {name}: expected the op search to miss it, "
                      f"it exited {run.returncode}")
                failures += 1
                continue
            detail = " (op granularity misses it)"
        if run.returncode == 0:
            run = explore(binary, "access")
        found = re.search(r"^VIOLATION (\w+):.*$", run.stdout, re.M)
        if run.returncode != 1 or not found or found.group(1) not in expected:
            print(f"not ok {n} - {name}: exit {run.returncode}, "
                  f"wanted one of {sorted(expected)}\n# " +
                  run.stdout[-1500:].replace("\n", "\n# "))
            failures += 1
            continue
        print(f"ok {n} - {name} -> {found.group(0)}{detail}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

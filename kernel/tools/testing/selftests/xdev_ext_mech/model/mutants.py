#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Show that life_explore detects 13 retained defect classes plus four new ones.

Each mutant copies one live header (io_uring/xdev_ext_mech_lifecycle.h or
io_uring/xdev_ext_mech_core.h) into a private tree, changes one function body
there, compiles life_explore.c with that tree searched before the kernel tree
and requires a VIOLATION of an expected invariant.  Relative includes of the
copy are pointed back at the live tree.  Four
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
# The first thirteen entries preserve the old defect classes. Generation now
# advances at final release; the old consumer-claim wrap defect is mapped to
# an illegal generation increment on acquire. The tuples document each migrated production location; generation/claim
# exhaustion remain distinct from the added missing-final-increment defect.
# name, header, function, (old, new), expected invariants, define, op_must_miss
MUTANTS = [
    ("publish_ignores_generation", "lifecycle", "xdev_ext_mech_life_publish",
     ("!xdev_ext_mech_life_matches(old, claim)",
      "!xdev_ext_mech_life_matches(old, (old & ~((1ULL << 12) - 1)) | (claim & ((1ULL << 12) - 1)))"),
     {"INV_STALE_MATCH"}, None, False),
    ("produce_wraps_generation", "lifecycle", "xdev_ext_mech_life_claim",
     ("if (xdev_ext_mech_life_claim_gen(old) == XDEV_EXT_MECH_L_GEN_MAX)", "if (0)"),
     {"INV_GEN_MONOTONE"}, None, False),
    ("consume_wraps_generation", "lifecycle", "xdev_ext_mech_life_acquire",
     ("xdev_ext_mech_life_word(xdev_ext_mech_life_claim_gen(old),",
      "xdev_ext_mech_life_word(xdev_ext_mech_life_claim_gen(old) + 1,"),
     {"INV_GEN_MONOTONE"}, None, False),
    ("completion_wraps_ticket", "lifecycle", "xdev_ext_mech_completion_begin",
     ("if ((old >> 3) == XDEV_EXT_MECH_C_GEN_MAX)", "if (0)"),
     {"INV_GEN_MONOTONE"}, None, False),
    ("cancel_after_claim", "lifecycle", "xdev_ext_mech_completion_cancel",
     ("!XDEV_EXT_L_CAS(&c->ctrl, &old, ticket << 3))",
      "(!XDEV_EXT_L_CAS(&c->ctrl, &old, ticket << 3) &&\n"
      "\t     (old = (ticket << 3) | XDEV_EXT_MECH_C_COMPLETING,\n"
      "\t      !XDEV_EXT_L_CAS(&c->ctrl, &old, ticket << 3))))"),
     {"INV_STALE_MATCH"}, None, False),
    ("release_while_consuming", "lifecycle", "xdev_ext_mech_life_release",
     ("if (state != XDEV_EXT_MECH_L_READY)", "if (0)"),
     {"INV_EARLY_REUSE"}, None, False),
    ("complete_consume_any_generation", "lifecycle", "xdev_ext_mech_life_drop",
     ("!xdev_ext_mech_life_matches(old, claim)",
      "!xdev_ext_mech_life_matches(old, (old & ~((1ULL << 12) - 1)) | (claim & ((1ULL << 12) - 1)))"),
     {"INV_STALE_MATCH"}, None, False),
    # The load-to-store race requires preemption INSIDE the header call.
    ("release_plain_store", "lifecycle", "xdev_ext_mech_life_release",
     ("return XDEV_EXT_L_CAS(&l->ctrl, &old, (gen + 1) << XDEV_EXT_MECH_L_GEN_SHIFT) ? 0 : -ESTALE;",
      "XDEV_EXT_L_STORE(&l->ctrl, (gen + 1) << XDEV_EXT_MECH_L_GEN_SHIFT);\n\treturn 0;"),
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
     {"INV_EARLY_REUSE", "INV_TEARDOWN"}, "LIFE_MODEL_MUTANT_DESTROY_IGNORES_INFLIGHT", False),
    ("reap_releases_quarantined", None, None, None,
     {"INV_QUARANTINE"}, "LIFE_MODEL_MUTANT_REAP_RELEASES", False),
    ("late_release_ignores_quarantine", None, None, None,
     {"INV_EARLY_REUSE", "INV_QUARANTINE"}, "LIFE_MODEL_MUTANT_LATE_RELEASE_ALWAYS", False),
    ("double_decrement", "lifecycle", "xdev_ext_mech_life_drop",
     ("XDEV_EXT_MECH_L_REFS_SHIFT) - 1;", "XDEV_EXT_MECH_L_REFS_SHIFT) - 2;"),
     {"INV_REFS", "INV_EARLY_REUSE"}, None, False),
    ("early_free_with_consumer_active", "lifecycle", "xdev_ext_mech_life_drop",
     ("!refs ? XDEV_EXT_MECH_L_FREE : busy ? XDEV_EXT_MECH_L_OUT_PENDING : XDEV_EXT_MECH_L_READY,",
      "(!refs || busy) ? XDEV_EXT_MECH_L_FREE : XDEV_EXT_MECH_L_READY,"),
     {"INV_EARLY_REUSE"}, None, False),
    ("missed_generation_increment", "lifecycle", "xdev_ext_mech_life_drop",
     ("xdev_ext_mech_life_claim_gen(old) + !refs,", "xdev_ext_mech_life_claim_gen(old),"),
     {"INV_GEN_MONOTONE"}, None, False),
    ("publish_without_completion_claim", None, None, None,
     {"INV_COMPLETION_CLAIM"}, "LIFE_MODEL_MUTANT_PUBLISH_WITHOUT_CLAIM", False),
]

HEADERS = {
    "lifecycle": "io_uring/xdev_ext_mech_lifecycle.h",
    "core": "io_uring/xdev_ext_mech_core.h",
}


def function_span(text, name):
    """(start, end) of the braces-delimited body of static inline @name."""
    active = text
    legacy = re.search(r"#ifdef XDEV_EXT_MECH_LIFE_LEGACY\n.*?\n#else\n", text, re.S)
    if legacy:
        active = text[:legacy.start()] + " " * (legacy.end() - legacy.start()) + text[legacy.end():]
    match = re.search(r"^static inline\b[^;{]*\b" + re.escape(name) + r"\s*\([^;{]*\)\s*\{",
                      active, re.M)
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
        (tree / "command.txt").write_text(" ".join(cmd) + "\n")
        built = subprocess.run(cmd, text=True, capture_output=True)
        (tree / "build.log").write_text(built.stdout + built.stderr)
        if built.returncode:
            print(f"not ok {n} - {name}: build failed\n# " +
                  (built.stdout + built.stderr).replace("\n", "\n# "))
            failures += 1
            continue
        # The exhaustive op search is cheap; the access search runs only when
        # the op search found nothing, as it must for op_must_miss mutants.
        detail = ""
        run = explore(binary, "op")
        (tree / "op.log").write_text(run.stdout + run.stderr)
        if op_must_miss:
            if run.returncode != 0:
                print(f"not ok {n} - {name}: expected the op search to miss it, "
                      f"it exited {run.returncode}")
                failures += 1
                continue
            detail = " (op granularity misses it)"
        if run.returncode == 0:
            run = explore(binary, "access")
            (tree / "access.log").write_text(run.stdout + run.stderr)
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

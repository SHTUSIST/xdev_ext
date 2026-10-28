#!/usr/bin/env python3
"""Run real DMA adapter/core functions with OS and native-provider boundaries.

No provider/completion decision is reimplemented. Functions and ABI structures
are extracted verbatim. --ref fixes a Git snapshot; without it, test the tree.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

# Import the central path contract explicitly; isolated Python ignores PYTHONPATH.
import sys as _layout_sys
_LAYOUT = None
for _parent in (Path(__file__).resolve().parent, *Path(__file__).resolve().parents):
    if (_parent / "tools/layout.py").is_file():
        _layout_sys.path.insert(0, str(_parent / "tools"))
        import layout as _LAYOUT
        break
import re
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = next((p for p in HERE.parents if (p / "io_uring/xdev_ext_mech_dma.c").is_file()),
                    Path(str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
ROOT = Path(os.environ.get("KERNEL_SRC", DEFAULT_ROOT)).resolve()
REF = None


def source(path):
    if globals().get("_LAYOUT"):
        return _LAYOUT.read_native(ROOT if "KERNEL_SRC" in os.environ else HERE, "linux", path, REF).decode()
    if REF:
        return subprocess.check_output(["git", "show", f"{REF}:./{path}"],
                                       cwd=ROOT, text=True)
    return (ROOT / path).read_text()


def function(text, name):
    match = re.search(r"^\w[^;{}]*\b" + name + r"\([^;{}]*\)\n\{\n.*?^\}",
                      text, re.M | re.S)
    if not match:
        raise RuntimeError("missing production function: " + name)
    return match[0]


def structure(text, name):
    match = re.search(r"^struct " + name + r" \{\n.*?^\};", text, re.M | re.S)
    if not match:
        raise RuntimeError("missing production structure: " + name)
    return match[0]


def generate(mutation=None):
    core = source("io_uring/xdev_ext_mech.c")
    dma = source("io_uring/xdev_ext_mech_dma.c")
    abi = source("include/linux/xdev_ext_mech.h")
    ops = source("io_uring/xdev_ext_mech_ops.c")
    ce = source("io_uring/xdev_ext_mech_ce.c")
    if mutation == "ce_ticket":
        ce, n = re.subn(r"if \(xdev_ext_mech_batch_completion_claim\(ck->b, ticket\)\)\n\t\treturn;", "if (false) return;\n\t(void)xdev_ext_mech_batch_completion_claim(ck->b, ticket);", ce)
        assert n == 1
    if mutation == "ticket":
        dma, n = re.subn(r"if \(xdev_ext_mech_batch_completion_claim\(ck->b, ticket\)\)\n\t\treturn;",
                         "if (false) return;\n\t(void)xdev_ext_mech_batch_completion_claim(ck->b, ticket);", dma)
        assert n == 1
    elif mutation == "ambiguous_unbind":
        dma, n = re.subn(r"if \(atomic_read\(&cs->ambiguous\)\)\n\t\treturn;", "if (false) return;", dma)
        assert n == 1
    elif mutation == "duplicate_registry":
        dma, n = re.subn(r"if \(p->ops->fops == ops->fops\)", "if (false)", dma)
        assert n == 1
    template = (HERE / "provider_fault_fixture.c").read_text()
    template = template.replace("/* PRODUCTION_CLASS_FLAGS */",
                                re.search(r"^#define XDEV_EXT_MECH_CLASS_F_TRANSFORM .*", abi, re.M)[0])
    structs = [structure(abi, n) for n in (
        "xdev_ext_mech_frame", "xdev_ext_mech_stage", "xdev_ext_mech_class_ops",
        "xdev_ext_mech_pool_ops", "xdev_ext_mech_pool", "xdev_ext_dma_region",
        "xdev_ext_dma_xfer", "xdev_ext_dma_provider_ops", "xdev_ext_ce_region",
        "xdev_ext_ce_xfer", "xdev_ext_ce_backend_ops")]
    # The whole DMA adapter includes its family hook table in newer snapshots.
    # Extract the actual types only when that selected adapter requires them;
    # historical refs predate both the hook table and its contract header.
    if "struct xdev_ext_comp_hooks" in dma:
        structs.insert(0, structure(abi, "xdev_ext_family_hooks_hdr"))
        structs.append(structure(source("include/linux/xdev_ext_compfam.h"),
                                 "xdev_ext_comp_hooks"))
    if "static void xdev_ext_mech_start_queue_free(" in core:
        structs.append(structure(source("io_uring/xdev_ext_mech_start_queue.h"), "xdev_ext_mech_start_queue"))
    structs += [structure(core, n) for n in ("xdev_ext_mech_batch", "xdev_ext_mech_session")]
    # Preserve the adapter's own structs, registry storage, every function and
    # class table, stopping before its kernel initcall only.
    adapter = dma[dma.index("struct xdev_ext_dma_provider {"):dma.index("/* After every late_initcall")]
    before = ["xdev_ext_mech_notify_locked", "xdev_ext_mech_pool_frame_move",
              "xdev_ext_mech_pool_frame_state", "xdev_ext_mech_count", "xdev_ext_mech_frames_move",
              "xdev_ext_mech_session_pool", "xdev_ext_mech_session_layout",
              "xdev_ext_mech_settled", "xdev_ext_mech_settle_locked", "xdev_ext_mech_session_stop",
              "xdev_ext_mech_leave_locked", "xdev_ext_mech_batch_nr_frames",
              "xdev_ext_mech_batch_frame", "xdev_ext_mech_batch_frame_claim", "xdev_ext_mech_batch_priv", "xdev_ext_mech_batch_cookie",
              "xdev_ext_mech_batch_queue", "xdev_ext_mech_batch_ticket",
              "xdev_ext_mech_batch_completion_claim", "xdev_ext_mech_sync_for_cpu",
              "xdev_ext_mech_trim_produced", "xdev_ext_mech_batch_handoff",
              "xdev_ext_mech_life_undo", "xdev_ext_mech_batch_acquire",
              "xdev_ext_mech_batch_completion_publish"]
    after = ["xdev_ext_mech_transform_undo", "xdev_ext_mech_submit",
             "xdev_ext_mech_unbind_checked", "xdev_ext_mech_session_release", "xdev_ext_mech_quarantine",
             "xdev_ext_mech_session_destroy"]
    # Legacy NULL-report wrappers still execute the actual shared release and
    # destroy bodies. Extract their new dependencies rather than stub them.
    if "static int xdev_ext_mech_session_release_report(" in core:
        template = template.replace('#include "include/uapi/linux/xdev_ext_mech.h"',
            '#include "include/uapi/linux/xdev_ext_mech.h"\n#include "include/uapi/linux/xdev_ext_policy.h"')
        if "static int xdev_ext_mech_session_release_disposition(" in core:
            after.insert(after.index("xdev_ext_mech_session_release"),
                         "xdev_ext_mech_session_release_disposition")
        after.insert(after.index("xdev_ext_mech_session_release"),
                     "xdev_ext_mech_session_release_report")
        after.insert(after.index("xdev_ext_mech_session_destroy"),
                     "xdev_ext_mech_session_destroy_report")
        after[0:0] = ["xdev_ext_mech_stats_fill", "xdev_ext_mech_transport_stats_fill"]
    if "static void xdev_ext_mech_start_queue_free(" in core:
        after.insert(0, "xdev_ext_mech_start_queue_free")
    ce_adapter = "\n\n".join([structure(ce,n) for n in ("xdev_ext_ce_stage", "xdev_ext_ce_cookie", "xdev_ext_ce_batch")])
    ce_adapter += "\nXDEV_EXT_NATIVE_COOKIE_ASSERT(struct xdev_ext_ce_cookie);\n"
    # These native-cookie/provider fault cases have one uncontended CE owner.
    # Shared-window admission is exercised by independent_ce_lease.py using
    # the actual registry functions, including process and quarantine cases.
    # Keep that admission boundary explicit while preserving real submit and
    # completion decisions below (including stale-ticket mutation checks).
    ce_adapter += """
static int xdev_ext_ce_lease_get(struct xdev_ext_ce_stage *cs,
                               struct xdev_ext_mech_batch *b)
{
    (void)cs;
    (void)b;
    return 0; /* Fixture precondition: uncontended registered CE window. */
}
"""
    ce_adapter += "\n\n".join(function(ce,n) for n in ("xdev_ext_ce_stage_xfers", "xdev_ext_ce_submit", "xdev_ext_ce_complete"))
    blocks = {"CE_ADAPTER": ce_adapter,"STRUCTURES": "\n\n".join(structs),
              "OPS": "\n\n".join(function(ops, n) for n in
                                    ("xdev_ext_mech_class_put", "xdev_ext_mech_ops_put")),
              "CORE_BEFORE": "\n\n".join(function(core, n) for n in before),
              "ADAPTER": adapter,
              "CORE_AFTER": "\n\n".join(function(core, n) for n in after)}
    for key, value in blocks.items():
        marker = "/* PRODUCTION_" + key + " */"
        assert template.count(marker) == 1
        template = template.replace(marker, value)
    return template


CASES = [
    "registry", "bind_rollback", "directions_and_bounds", "preaccept_eagain",
    "inline", "duplicate", "stale_reuse", "stale_stage_reuse", "dma_to_ce_stale", "ce_to_dma_stale", "short", "excess", "ambiguous",
    "unsubmitted_zero", "accepted_pre_submit_error", "dead_before_submit",
    "callback_then_error", "stop_idle", "stop_pending", "stop_delayed",
    "stop_ambiguous", "ambiguous_unbind", "unregister_bound", "registry_capacity",
]


class ProviderFaults(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="xdev_ext-provider-faults-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.path = Path(cls.tmp.name)
        # Fixed-ref runs compile the exact portable headers too.
        if REF:
            for rel in ("include/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_binding.h",
                        "io_uring/xdev_ext_mech_core.h", "io_uring/xdev_ext_mech_lifecycle.h",
                        "io_uring/xdev_ext_mech_notify.h", "io_uring/xdev_ext_mech_produced.h", "io_uring/xdev_ext_mech_step.h",
                        "io_uring/xdev_ext_mech_dma_core.h", "io_uring/xdev_ext_mech_ce_core.h",
                        "io_uring/xdev_ext_mech_window_copy_core.h",
                        "io_uring/xdev_ext_mech_native_cookie.h", "io_uring/xdev_ext_mech_window.h"):
                p = cls.path / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(source(rel))
            # Report-aware refs need the selected public policy/report ABI;
            # pre-report refs do not borrow the current tree's new types.
            if "static int xdev_ext_mech_session_release_report(" in source("io_uring/xdev_ext_mech.c"):
                rel = "include/uapi/linux/xdev_ext_policy.h"
                (cls.path / rel).write_text(source(rel))
            # F1b core rules include the class table; keep fixed-ref copies
            # self-contained without adding new inputs to older snapshots.
            if 'xdev_ext_family_core.h' in (cls.path / "io_uring/xdev_ext_mech_core.h").read_text():
                rel = "include/linux/xdev_ext_family_core.h"
                (cls.path / rel).write_text(source(rel))
            # Follow CPU helper dependencies from the selected step snapshot.
            if '"xdev_ext_mech_cpu_core.h"' in (cls.path / "io_uring/xdev_ext_mech_step.h").read_text():
                rel = "io_uring/xdev_ext_mech_cpu_core.h"
                (cls.path / rel).write_text(source(rel))
            # F9a compute rules must come from that same fixed revision too.
            if 'xdev_ext_compfam_core.h' in (cls.path / "io_uring/xdev_ext_mech_step.h").read_text():
                rel = "include/linux/xdev_ext_compfam_core.h"
                (cls.path / rel).write_text(source(rel))
        cls.binary = cls.compile("production", generate())

    @classmethod
    def compile(cls, name, text):
        c = cls.path / (name + ".c")
        c.write_text(text)
        exe = cls.path / name
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-parameter",
            "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-pthread",
            "-I" + str(cls.path), "-I" + str(ROOT), str(c), "-o", str(exe)]
        built = subprocess.run(command, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError(" ".join(command) + "\n" + built.stdout + built.stderr)
        return exe

    def run_case(self, mode, binary=None):
        run = subprocess.run([str(binary or self.binary), mode], capture_output=True,
                             text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("PASS " + mode, run.stdout)

    def test_mutation_cookie_prefix_is_detected(self):
        text=generate().replace("struct xdev_ext_dma_cookie {", "struct xdev_ext_dma_cookie {\n u64 invalid_prefix;",1)
        with self.assertRaisesRegex(RuntimeError,"native cookie"):
            self.compile("mutant_cookie_prefix",text)
        print("MUTATION_RED cookie_prefix compilation rejected by layout assertions",flush=True)

    def test_mutation_crossclass_dma_ticket_is_detected(self):
        exe = self.compile("mutant_crossclass_dma_ticket", generate("ticket"))
        run = subprocess.run([str(exe), "dma_to_ce_stale"], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        print("MUTATION_RED crossclass_dma_ticket exit="+str(run.returncode), flush=True)

    def test_mutation_crossclass_ce_ticket_is_detected(self):
        exe = self.compile("mutant_ce_ticket", generate("ce_ticket"))
        run = subprocess.run([str(exe), "ce_to_dma_stale"], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        print("MUTATION_RED crossclass_ce_ticket exit="+str(run.returncode), flush=True)

    def test_mutation_duplicate_registry_is_detected(self):
        exe = self.compile("mutant_registry", generate("duplicate_registry"))
        run = subprocess.run([str(exe), "registry"], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("duplicate fops", run.stderr)
        print("MUTATION_RED duplicate_registry exit=" + str(run.returncode) + " " + run.stderr.strip(), flush=True)

    def test_mutation_stale_ticket_guard_is_detected(self):
        exe = self.compile("mutant_ticket", generate("ticket"))
        run = subprocess.run([str(exe), "stale_reuse"], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("stale callback", run.stderr)
        print("MUTATION_RED stale_ticket exit=" + str(run.returncode) + " " + run.stderr.strip(), flush=True)

    def test_mutation_ambiguous_unbind_guard_is_detected(self):
        exe = self.compile("mutant_unbind", generate("ambiguous_unbind"))
        run = subprocess.run([str(exe), "ambiguous_unbind"], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("ambiguous unbind", run.stderr)
        print("MUTATION_RED ambiguous_unbind exit=" + str(run.returncode) + " " + run.stderr.strip(), flush=True)


for case in CASES:
    def test(self, mode=case):
        self.run_case(mode)
    setattr(ProviderFaults, "test_" + case, test)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", help="extract this exact local Git commit")
    args, rest = parser.parse_known_args()
    REF = args.ref
    ref = (_LAYOUT.provenance(ROOT if "KERNEL_SRC" in os.environ else HERE, REF,
                              native="KERNEL_SRC" in os.environ)["revision"] if _LAYOUT else
           subprocess.check_output(["git", "rev-parse", REF or "HEAD"], cwd=ROOT,
                                   text=True).strip())
    inputs = ("io_uring/xdev_ext_mech.c", "io_uring/xdev_ext_mech_ops.c", "io_uring/xdev_ext_mech_dma.c",
              "include/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_mech.h",
              "include/uapi/linux/xdev_ext_binding.h", "io_uring/xdev_ext_mech_core.h",
              "io_uring/xdev_ext_mech_lifecycle.h", "io_uring/xdev_ext_mech_notify.h", "io_uring/xdev_ext_mech_produced.h",
              "io_uring/xdev_ext_mech_step.h", "io_uring/xdev_ext_mech_dma_core.h",
              "io_uring/xdev_ext_mech_ce.c", "io_uring/xdev_ext_mech_ce_core.h",
              "io_uring/xdev_ext_mech_window_copy_core.h",
              "io_uring/xdev_ext_mech_native_cookie.h", "io_uring/xdev_ext_mech_window.h")
    print(json.dumps({"source_root": str(ROOT), "ref": ref,
                      "working_tree": REF is None,
                      "source_sha256": {p: hashlib.sha256(source(p).encode()).hexdigest() for p in inputs}}), flush=True)
    unittest.main(argv=[__file__] + rest, verbosity=2)

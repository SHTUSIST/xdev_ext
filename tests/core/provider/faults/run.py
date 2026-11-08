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

import sys as _layout_sys
import re
import shlex
import subprocess
import tempfile
import unittest

try:
    HERE = Path(__file__).resolve().parent
    for _base in (HERE, *HERE.parents):
        if (_base / 'view.json').is_file() or (_base / 'source-layout.json').is_file():
            _shared = _base / 'tests/compute/transform_source.py'
            if not _shared.is_file():
                raise RuntimeError('missing owned transform source helper')
            _layout_sys.path.insert(0, str(_shared.parent))
            break
    else:
        raise RuntimeError('missing owned checkout/view')
    from transform_source import TransformSource, read_native, owned_dependency, source_root, verify_entry, compiler_headers, layout as _LAYOUT  # noqa: E402
    verify_entry(__file__, 'tests/core/provider/faults/run.py')
    ROOT = source_root(__file__, os.environ.get('KERNEL_SRC'))
except Exception as error:
    print("SETUP " + str(error), file=_layout_sys.stderr)
    raise SystemExit(2)
REF = None


def source(path):
    if globals().get("_LAYOUT"):
        if REF is None:
            return read_native(ROOT if "KERNEL_SRC" in os.environ else HERE, path)
        return _LAYOUT.read_native(ROOT if "KERNEL_SRC" in os.environ else HERE, "linux", path, REF).decode()
    if REF:
        return subprocess.check_output(["git", "show", f"{REF}:./{path}"],
                                       cwd=ROOT, text=True)
    return (ROOT / path).read_text()


def function(text, name):
    match = re.search(r"^\w[^;{}]*\b" + re.escape(name) + r"\([^;{}]*\)\n\{\n.*?^\}",
                      text, re.M | re.S)
    if not match:
        raise RuntimeError("missing production function: " + name)
    return match[0]



def structure(text, name):
    match = re.search(r"^struct " + name + r" \{\n.*?^\};", text, re.M | re.S)
    if not match:
        raise RuntimeError("missing production structure: " + name)
    return match[0]


def dma_scope_dependencies(text):
    """Only the selected production snapshot decides its scope dependencies."""
    return (("include/linux/xdev_ext_dma_scope_core.h",)
            if re.search(r"^struct xdev_ext_dma_scope \{", text, re.M) else ())


def shared_runtime_dependencies(*adapters):
    """Any shared-runtime marker requires the actual runtime, never old mode."""
    marker = r"\bxdev_ext_comp_copy_(?:member|registration|registry(?:_\w+)?|cookie|legacy_ops|stage(?:_\w+)?|collect|complete|mark_dead|poll|unbind)\b"
    return (("io_uring/xdev_ext_compfam_copy_runtime.h",
             "io_uring/xdev_ext_compfam_copy.c")
            if any(re.search(marker, text) or
                   "xdev_ext_compfam_copy_runtime.h" in text for text in adapters)
            else ())


def common_lease_dependencies(*adapters):
    return (("io_uring/xdev_ext_compfam_copy_lease.h", "io_uring/xdev_ext_compfam_copy_lease.c")
            if any('xdev_ext_compfam_copy_lease.h' in text for text in adapters) else ())


def copy_window_dependencies(text):
    """Follow the selected adapter's actual private or portable header edge."""
    return (("io_uring/xdev_ext_compfam_copy_core.h",)
            if '#include "xdev_ext_compfam_copy_core.h"' in text or
            shared_runtime_dependencies(text) else ())


def mutate_function(text, name, old, new):
    """A missing or changed mutation anchor is SETUP, not a behavioral kill."""
    body = function(text, name)
    if body.count(old) != 1:
        raise RuntimeError("SETUP mutation anchor: " + name)
    return text.replace(body, body.replace(old, new, 1), 1)


def shared_fixture_layout(template):
    """Relocate only fixture storage references; keep all comparisons literal."""
    for field in ("host", "window", "staged", "plan", "ambiguous"):
        template = re.sub(r"\bcs->" + field + r"\b", "cs->copy." + field, template)
    for field in ("ambiguous", "window"):
        template = template.replace(")->" + field, ")->copy." + field)
    template = template.replace("cs.ambiguous", "cs.copy.ambiguous")
    template = template.replace("sizeof(struct xdev_ext_dma_cookie)",
                                "sizeof(struct xdev_ext_comp_copy_cookie)")
    template = template.replace("struct xdev_ext_dma_cookie before;",
                                "struct xdev_ext_comp_copy_cookie before;")
    template = template.replace("((struct xdev_ext_dma_cookie *)b->cookie)",
                                "((struct xdev_ext_comp_copy_cookie *)b->cookie)")
    template = template.replace("xdev_ext_dma_providers", "xdev_ext_dma_registry.members")
    return template.replace("/* FIXTURE_CE_COPY_INIT */",
                            "cs.copy.ops = &xdev_ext_ce_copy_ops;")


def session_helpers(text, bodies, extractor):
    """Follow actual session-helper calls; a called missing definition is fatal."""
    helpers = ('xdev_ext_mech_session_stage_role', 'xdev_ext_mech_session_rows',
               'xdev_ext_mech_session_chain_refs', 'xdev_ext_mech_session_start_queue_check')
    bodies, selected = list(bodies), set()
    for _ in helpers:
        for name in helpers:
            if name not in selected and any(re.search(r'\b' + name + r'\s*\(', body) for body in bodies):
                bodies.append(extractor(text, name))
                selected.add(name)
    return [name for name in helpers if name in selected]


def generate(mutation=None):
    core = source("io_uring/xdev_ext_mech.c")
    selected = TransformSource(core, source, function)
    core = selected.text
    dma = source("io_uring/xdev_ext_mech_dma.c")
    abi = source("include/linux/xdev_ext_mech.h")
    ops = source("io_uring/xdev_ext_mech_ops.c")
    ce = source("io_uring/xdev_ext_mech_ce.c")
    runtime_dependencies = shared_runtime_dependencies(dma, ce)
    lease_dependencies = common_lease_dependencies(dma, ce)
    runtime = source("io_uring/xdev_ext_compfam_copy.c") if runtime_dependencies else ""
    if runtime_dependencies:
        # Both real adapters must require the runtime. A partly new snapshot
        # cannot quietly enter the historical fixture boundary.
        for text in (ce, dma):
            if not shared_runtime_dependencies(text):
                raise RuntimeError("SETUP partial shared-runtime snapshot")
        header = source("io_uring/xdev_ext_compfam_copy_runtime.h")
        for name in ("xdev_ext_comp_copy_member", "xdev_ext_comp_copy_registration",
                     "xdev_ext_comp_copy_registry", "xdev_ext_comp_copy_cookie",
                     "xdev_ext_comp_copy_legacy_ops", "xdev_ext_comp_copy_stage"):
            structure(header, name)
        for name in ("xdev_ext_comp_copy_registry_register", "xdev_ext_comp_copy_registry_unregister",
                     "xdev_ext_comp_copy_registry_get", "xdev_ext_comp_copy_collect",
                     "xdev_ext_comp_copy_stage_validate", "xdev_ext_comp_copy_claim",
                     "xdev_ext_comp_copy_stage_submit", "xdev_ext_comp_copy_complete",
                     "xdev_ext_comp_copy_mark_dead", "xdev_ext_comp_copy_poll", "xdev_ext_comp_copy_unbind"):
            function(runtime, name)
        if mutation in ("ce_ticket", "ticket"):
            runtime = mutate_function(runtime, "xdev_ext_comp_copy_complete",
                "if (xdev_ext_mech_batch_completion_claim(ck->b, ticket))\n\t\treturn;",
                "if (false) return;\n\t(void)xdev_ext_mech_batch_completion_claim(ck->b, ticket);")
        elif mutation == "ambiguous_unbind":
            runtime = mutate_function(runtime, "xdev_ext_comp_copy_unbind",
                "if (atomic_read(&cs->ambiguous))\n\t\treturn -EBUSY;", "if (false) return -EBUSY;")
            dma = mutate_function(dma, "xdev_ext_dma_copy_unbind_begin",
                "if (cs->lease.group && xdev_ext_comp_copy_lease_busy(&cs->lease))" if lease_dependencies else "if (cs->lease_group && xdev_ext_dma_lease_busy(cs))", "if (false)")
            dma = mutate_function(dma, "xdev_ext_dma_copy_unbind_end",
                "if (cs->lease.group &&\n\t    WARN_ON_ONCE(!xdev_ext_comp_copy_lease_unbind(&cs->lease, false)))" if lease_dependencies else "if (!xdev_ext_dma_lease_unbind(cs))", "if (false)")
        elif mutation == "lease_get":
            dma = mutate_function(dma, "xdev_ext_dma_copy_lease_get",
                "return xdev_ext_comp_copy_lease_get(&cs->lease,\n\t\txdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b));" if lease_dependencies else "return xdev_ext_dma_lease_get(cs, b);", "return 0;")
        elif mutation == "owner_guard":
            dma = mutate_function(dma, "xdev_ext_dma_copy_classify",
                "if (!xdev_ext_mech_batch_dma_owners_valid(b, ticket, cb->x, cb->n))", "if (false)")
        elif mutation == "duplicate_registry":
            runtime = mutate_function(runtime, "xdev_ext_comp_copy_registry_register",
                "if (p->member.fops == member->fops)", "if (false)")
    else:
        if mutation == "ce_ticket":
            ce, n = re.subn(r"if \(xdev_ext_mech_batch_completion_claim\(ck->b, ticket\)\)\n\t\treturn;", "if (false) return;\n\t(void)xdev_ext_mech_batch_completion_claim(ck->b, ticket);", ce)
            assert n == 1
        if mutation == "ticket":
            dma, n = re.subn(r"if \(xdev_ext_mech_batch_completion_claim\(ck->b, ticket\)\)\n\t\treturn;",
                             "if (false) return;\n\t(void)xdev_ext_mech_batch_completion_claim(ck->b, ticket);", dma)
            assert n == 1
        elif mutation == "ambiguous_unbind":
            dma, n = re.subn(r"if \(atomic_read\(&cs->ambiguous\)\)\n\s+return -EBUSY;", "if (false) return -EBUSY;", dma)
            assert n == 1
            # The new window lease is a second independent quarantine barrier.
            dma = dma.replace("if (cs->lease_group && xdev_ext_dma_lease_busy(cs))", "if (false)", 1)
            dma = dma.replace("if (!xdev_ext_dma_lease_unbind(cs))", "if (false)", 1)
        elif mutation == "lease_get":
            dma = dma.replace("err = xdev_ext_dma_lease_get(cs, b);", "err = 0;", 1)
        elif mutation == "owner_guard":
            dma = dma.replace("if (!xdev_ext_mech_batch_dma_owners_valid(ck->b, ticket, cb->x, cb->n))", "if (false)", 1)
        elif mutation == "duplicate_registry":
            dma, n = re.subn(r"if \(p->ops->fops == ops->fops\)", "if (false)", dma)
            assert n == 1
    template = owned_dependency(__file__, 'tests/core/provider/faults/provider_fault_fixture.c').read_text()
    if runtime_dependencies:
        template = shared_fixture_layout(template)
    if lease_dependencies:
        for field, target in (("lease_group", "lease.group"), ("cleanup_held", "lease.cleanup_held")):
            template = re.sub(r'(->|\.)'+field+r'\b', lambda m:m[1]+target, template)
        template = template.replace('xdev_ext_ce_lease_bind_ready(&cs);', 'xdev_ext_comp_copy_lease_hold(&cs.lease,false);')
        template = template.replace('xdev_ext_ce_lease_cleanup_begin(&cs)', 'xdev_ext_comp_copy_lease_cleanup_begin(&cs.lease)')
        template = template.replace('xdev_ext_ce_lease_unbind(&cs)', 'xdev_ext_comp_copy_lease_unbind(&cs.lease,true)')
        template = re.sub(r'xdev_ext_dma_lease_get\((cs),([^()]*)\)', r'xdev_ext_dma_copy_lease_get(&\1->copy,\2)', template)

    template = template.replace("/* PRODUCTION_CLASS_FLAGS */",
                                re.search(r"^#define XDEV_EXT_MECH_CLASS_F_TRANSFORM .*", abi, re.M)[0])
    # Historical void callbacks are adapted only at the fixture boundary so the
    # old implementation executes and fails ownership assertions, not compilation.
    if 'void (*unbind_region)(struct xdev_ext_dma_region *r)' in abi:
        template = template.replace('static int native_unbind_region(', 'static void native_unbind_region(')
        template = template.replace('if(region_unmap_error)return region_unmap_error;free(r->priv);r->priv=NULL;return 0;',
                                    'if(region_unmap_error)return;free(r->priv);r->priv=NULL;')
    # Initializer fields must match the selected historical class structure.
    if not re.search(r'\bdecl\s*;', structure(abi, "xdev_ext_mech_class_ops")):
        template = template.replace('.decl=&xdev_ext_mech_class_decls[XDEV_EXT_MECH_CLASS_CE],', '')
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
    if selected.split:
        structs.append(selected.types)
    structs += [structure(core, n) for n in ("xdev_ext_mech_batch", "xdev_ext_mech_session")]
    copy_dependencies = tuple(dict.fromkeys(copy_window_dependencies(dma) +
                                            copy_window_dependencies(ce)))
    if copy_dependencies:
        template = template.replace('#include "io_uring/xdev_ext_mech_window.h"',
            '#include "io_uring/xdev_ext_mech_window.h"\n' +
            '\n'.join('#include "' + rel + '"' for rel in copy_dependencies))
    scope_dependencies = dma_scope_dependencies(dma)
    if scope_dependencies:
        # Public declarations and the pure comparator are production inputs,
        # not substitutes for the scope implementation extracted below.
        structs += [structure(abi, n) for n in
                    ("xdev_ext_dma_scope_info", "xdev_ext_dma_scope_ops")]
        version = re.search(r"^#define XDEV_EXT_DMA_SCOPE_OPS_VERSION\s+.*", abi, re.M)
        if version is None:
            raise RuntimeError("missing production scope ops version")
        structs.insert(0, version[0])
        template = template.replace('#include "io_uring/xdev_ext_mech_dma_core.h"',
            '#include "include/linux/xdev_ext_dma_scope_core.h"\n#include "io_uring/xdev_ext_mech_dma_core.h"')
    # Preserve the adapter's own structs, registry storage, every function and
    # class table, including scope create/get/put when present, stopping before
    # its kernel initcall only. Historical refs start at the old registry.
    adapter_start = ("struct xdev_ext_dma_scope {" if scope_dependencies
                     else "struct xdev_ext_dma_provider {")
    adapter = dma[dma.index(adapter_start):dma.index("/* After every late_initcall")]
    before = ["xdev_ext_mech_notify_locked", "xdev_ext_mech_pool_frame_move",
              "xdev_ext_mech_pool_frame_state", "xdev_ext_mech_count", "xdev_ext_mech_frames_move",
              "xdev_ext_mech_session_pool", "xdev_ext_mech_session_layout",
              "xdev_ext_mech_settled", "xdev_ext_mech_settle_locked", "xdev_ext_mech_session_stop",
              "xdev_ext_mech_leave_locked", "xdev_ext_mech_batch_nr_frames",
              "xdev_ext_mech_batch_frame", "xdev_ext_mech_batch_frame_claim",
              "xdev_ext_mech_session_depth", "xdev_ext_mech_batch_id", "xdev_ext_mech_batch_slot",
              "xdev_ext_mech_batch_copy_owner_valid", "xdev_ext_mech_batch_dma_owners_valid", "xdev_ext_mech_batch_ce_owners_valid", "xdev_ext_mech_batch_priv", "xdev_ext_mech_batch_cookie",
              "xdev_ext_mech_batch_queue", "xdev_ext_mech_batch_ticket",
              "xdev_ext_mech_batch_completion_claim", "xdev_ext_mech_sync_for_cpu",
              "xdev_ext_mech_trim_produced", "xdev_ext_mech_batch_handoff",
              "xdev_ext_mech_life_undo", "xdev_ext_mech_batch_acquire",
              "xdev_ext_mech_batch_completion_publish"]
    after = ["xdev_ext_mech_transform_undo", "xdev_ext_mech_submit",
             "xdev_ext_mech_unbind_checked", "xdev_ext_mech_session_release", "xdev_ext_mech_quarantine",
             "xdev_ext_mech_session_destroy"]
    if selected.split:
        before.insert(before.index("xdev_ext_mech_batch_handoff"),
                      "xdev_ext_mech_transform_handoff")
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
    # A parked session's settle step kicks the evidence recovery queue; the
    # host boundary counts the kick and never runs the queue.
    if "static void xdev_ext_mech_quarantine_settled(" in core:
        after.insert(after.index("xdev_ext_mech_quarantine") + 1,
                     "xdev_ext_mech_quarantine_settled")
        anchor = "static DEFINE_MUTEX(xdev_ext_mech_quarantine_lock);"
        if template.count(anchor) != 1:
            raise RuntimeError("SETUP quarantine lock anchor")
        template = template.replace(anchor, anchor + "\nstatic unsigned recovery_kicks;\n"
            "static struct work_struct xdev_ext_mech_recovery_work;\n#define system_unbound_wq NULL\n"
            "static void queue_work(void *wq,struct work_struct *w){(void)wq;(void)w;recovery_kicks++;}")
        after[0:0] = ["xdev_ext_mech_stats_fill", "xdev_ext_mech_transport_stats_fill"]
    if "static void xdev_ext_mech_start_queue_free(" in core:
        after.insert(0, "xdev_ext_mech_start_queue_free")
    bodies = [function(core, name) for name in before + after]
    accessors = selected.helpers(bodies)
    before = session_helpers(core, bodies, function) + before
    ce_stage = structure(ce, "xdev_ext_ce_stage")
    # Only a wholly pre-repair source may use the historical uncontended
    # boundary. A partial new source still requires every actual new helper;
    # missing symbols are SETUP failures, never a fallback to success.
    configured_ce = bool(re.search(r"^\s*const struct xdev_ext_ce_backend_ops\s*\*ops\b", ce_stage, re.M)) or any(
        marker in ce_stage for marker in ("window_len;", "cleanup_held;")) or any(
        name in ce for name in ("xdev_ext_ce_lease_bind_ready", "xdev_ext_ce_lease_cleanup_begin"))
    if runtime_dependencies:
        if not configured_ce:
            raise RuntimeError("SETUP shared CE missing configured exclusion")
        ce_adapter = "#define FIXTURE_CE_CONFIGURED_EXCLUSION 1\n"
        ce_adapter += ce[ce.index("#define XDEV_EXT_CE_MAX_BACKENDS"):ce.index("/* After every late_initcall")]
    else:
        ce_adapter = "#define FIXTURE_CE_CONFIGURED_EXCLUSION " + str(int(configured_ce)) + "\n"
        if configured_ce:
            ce_adapter += structure(ce, "xdev_ext_ce_lease_group") + "\n"
        ce_adapter += "\n\n".join([structure(ce,n) for n in ("xdev_ext_ce_stage", "xdev_ext_ce_cookie", "xdev_ext_ce_batch")])
        ce_adapter += "\nXDEV_EXT_NATIVE_COOKIE_ASSERT(struct xdev_ext_ce_cookie);\n"
        if configured_ce:
            # These cases manually admit one CE window, but execute its real lease
            # admission and final release, including the repaired C-owned identity.
            ce_adapter += "\nstatic DEFINE_MUTEX(xdev_ext_ce_lease_lock);\n"
            ce_adapter += "static LIST_HEAD(xdev_ext_ce_lease_groups);\n"
            ce_adapter += "\n\n".join(function(ce, n) for n in (
                "xdev_ext_ce_lease_bind", "xdev_ext_ce_lease_bind_ready",
                "xdev_ext_ce_lease_get", "xdev_ext_ce_batch_release",
                "xdev_ext_ce_lease_cleanup_begin", "xdev_ext_ce_lease_unbind"))
        else:
            # Original historical fixture precondition: one uncontended CE owner.
            # Old refs only; repaired sources always execute the real helper above.
            ce_adapter += """
    static int xdev_ext_ce_lease_get(struct xdev_ext_ce_stage *cs,
                                   struct xdev_ext_mech_batch *b)
    {
        (void)cs;
        (void)b;
        return 0; /* Historical fixture's uncontended registered CE window. */
    }
    """
        # Keep the selected adapter's actual frame-claim callback, not a test
        # replacement. Older adapters have no typed transfer callback.
        if re.search(r"\bxdev_ext_ce_copy_claim\b", function(ce, "xdev_ext_ce_stage_xfers")):
            ce_adapter += "\n" + function(ce, "xdev_ext_ce_copy_claim") + "\n"
        ce_adapter += "\n\n".join(function(ce,n) for n in ("xdev_ext_ce_stage_xfers", "xdev_ext_ce_submit", "xdev_ext_ce_complete"))
    if "xdev_ext_mech_instance_put(" in core:
        # Default-only fixtures have no selected instance handle. Keep the
        # actual release call and fail closed if that precondition changes.
        template = template.replace("/* PRODUCTION_OPS */", """struct xdev_ext_mech_instance;
static void xdev_ext_mech_instance_put(struct xdev_ext_mech_instance *instance)
{
    if (instance)
        abort();
}
/* PRODUCTION_OPS */""")
    if lease_dependencies:
        runtime = re.sub(r'^#include[^\n]*\n', '', source(lease_dependencies[1]), flags=re.M) + '\n' + runtime
    blocks = {"COPY_DECLS": ('#include "io_uring/xdev_ext_compfam_copy_runtime.h"' if runtime_dependencies else "") + ('\n#include \"io_uring/xdev_ext_compfam_copy_lease.h\"' if lease_dependencies else ''),
              "COPY_RUNTIME": runtime,
              "CE_ADAPTER": ce_adapter,"STRUCTURES": "\n\n".join(structs),
              "OPS": "\n\n".join(function(ops, n) for n in
                                    ("xdev_ext_mech_class_put", "xdev_ext_mech_ops_put")),
              "CORE_BEFORE": "\n\n".join(accessors + [function(core, n) for n in before]),
              "ADAPTER": adapter,
              "CORE_AFTER": "\n\n".join(function(core, n) for n in after)}
    for key, value in blocks.items():
        marker = "/* PRODUCTION_" + key + " */"
        assert template.count(marker) == 1
        template = template.replace(marker, value)
    return template


CASES = [
    "overlapping_sessions", "stale_owner", "stale_generation", "saved_claims", "unmap_retry", "unmap_exclusion", "lease_depth", "lease_shifted", "partial_region_bind", "partial_host_bind", "region_reset", "cleanup_active_group", "host_unmap_retention", "region_unmap_retention",
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
        # Compile the exact selected portable headers in both fixed-ref and
        # canonical worktree runs; neither requires a materialized native view.
        for rel in ("include/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_binding.h",
                    "io_uring/xdev_ext_mech_core.h", "io_uring/xdev_ext_mech_lifecycle.h",
                    "io_uring/xdev_ext_mech_notify.h", "io_uring/xdev_ext_mech_produced.h", "io_uring/xdev_ext_mech_step.h",
                    "io_uring/xdev_ext_mech_dma_core.h", "io_uring/xdev_ext_mech_ce_core.h",
                    "io_uring/xdev_ext_mech_window_copy_core.h",
                    "io_uring/xdev_ext_mech_native_cookie.h", "io_uring/xdev_ext_mech_window.h", "io_uring/xdev_ext_mech_ce_lease.h"):
            p = cls.path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(source(rel))
        for rel in tuple(dict.fromkeys(
                dma_scope_dependencies(source("io_uring/xdev_ext_mech_dma.c")) +
                copy_window_dependencies(source("io_uring/xdev_ext_mech_dma.c")) +
                copy_window_dependencies(source("io_uring/xdev_ext_mech_ce.c")))):
            p = cls.path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(source(rel))
        if shared_runtime_dependencies(source("io_uring/xdev_ext_mech_dma.c"),
                                       source("io_uring/xdev_ext_mech_ce.c")):
            rel = "io_uring/xdev_ext_compfam_copy_runtime.h"
            (cls.path / rel).write_text(source(rel))
            for name in ("atomic", "fs", "list", "module", "mutex", "xdev_ext_mech", "slab"):
                p = cls.path / "linux" / (name + ".h")
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("/* OS boundary: definitions are supplied by the fixture. */\n")
        for rel in common_lease_dependencies(source("io_uring/xdev_ext_mech_dma.c"), source("io_uring/xdev_ext_mech_ce.c")):
            if rel.endswith('.h'):
                (cls.path / rel).write_text(source(rel))
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
        family_header = cls.path / "include/linux/xdev_ext_family_core.h"
        if family_header.is_file() and 'xdev_ext_binding_ctx.h' in family_header.read_text():
            rel = "include/linux/xdev_ext_binding_ctx.h"
            (cls.path / rel).write_text(source(rel))
        # Follow CPU helper dependencies from the selected step snapshot.
        if '"xdev_ext_mech_cpu_core.h"' in (cls.path / "io_uring/xdev_ext_mech_step.h").read_text():
            rel = "io_uring/xdev_ext_mech_cpu_core.h"
            (cls.path / rel).write_text(source(rel))
        # F9a compute rules must come from that same fixed revision too.
        if 'xdev_ext_compfam_core.h' in (cls.path / "io_uring/xdev_ext_mech_step.h").read_text():
            rel = "include/linux/xdev_ext_compfam_core.h"
            (cls.path / rel).write_text(source(rel))
        code = generate()
        cls.include_root = compiler_headers(ROOT, cls.path / 'qualified-include', code,
                                            reader=source, search=('', 'io_uring'))
        cls.binary = cls.compile("production", code)

    @classmethod
    def compile(cls, name, text):
        c = cls.path / (name + ".c")
        c.write_text(text)
        exe = cls.path / name
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-parameter",
            "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-pthread",
            "-I" + str(cls.path), "-I" + str(cls.include_root / "io_uring"), "-I" + str(cls.include_root), str(c), "-o", str(exe)]
        built = subprocess.run(command, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError(" ".join(command) + "\n" + built.stdout + built.stderr)
        return exe


    def test_dma_struct_ops_abi(self):
        ops = source("io_uring/xdev_ext_mech_ops.c")
        if os.environ.get("DMA_ABI_BASELINE"):
            repo = _LAYOUT.canonical_root(HERE)
            ops = subprocess.check_output(["git", "show", "HEAD:src/core/io_uring/xdev_ext_mech_ops.c"], cwd=repo, text=True)
        dma = "static bool xdev_ext_dma_mech_abi_valid(" in ops
        prefix = "xdev_ext_dma_mech" if dma else "xdev_ext_mech"
        def declaration(signature):
            start = ops.index(signature)
            return ops[start:ops.index("\n};", start)+3]
        code = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "include/linux/xdev_ext_family_core.h"
typedef __u32 u32;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
struct xdev_ext_dma_mech_ops { u32 abi_version,flags;void *prepare,*build,*complete; };
struct xdev_ext_nvme_mech_ops { u32 abi_version,flags;void *prepare,*build,*complete; };
"""
        code += re.search(r"^#define XDEV_EXT_MECH_OPS_KNOWN_FLAGS\s+.*", source("include/linux/xdev_ext_mech.h"), re.M)[0]+"\n"
        contract = source("io_uring/xdev_ext_ops_core.h")
        code += "\n".join(structure(contract, n) for n in (
            "xdev_ext_ops_u32_field", "xdev_ext_ops_member", "xdev_ext_ops_desc"))
        code += function(source("io_uring/xdev_ext_ops_core.c"), "xdev_ext_ops_validate")
        code += function(ops, "xdev_ext_mech_flags_known")
        name = prefix+"_abi_valid"
        code += function(ops[ops.index("static bool "+name+"("):], name)
        code += declaration("static const struct xdev_ext_ops_u32_field "+prefix+"_ops_fields[]")
        code += declaration("static const struct xdev_ext_ops_member xdev_ext_mech_ops_members[]")
        code += declaration("static const struct xdev_ext_ops_desc "+prefix+"_ops_desc")
        if "xdev_ext_mech_type_schema(" in function(ops, prefix+"_ops_validate"):
            # This fixture registers only DMA, using its actual production row
            # and complete schema lookup. BTF identity is an opaque boundary.
            code += "\nstruct bpf_struct_ops { int unused; };\n"
            code += "static const struct bpf_struct_ops bpf_xdev_ext_dma_mech_ops;\n"
            code += structure(ops, "xdev_ext_mech_type_decl") + "\n"
            macro = re.search(r"^#define XDEV_EXT_MECH_TYPE_ROW[^\n]*\\\n[^\n]*", ops, re.M)
            if macro is None:
                raise AssertionError("production type-row macro missing")
            row = re.search(r"^ XDEV_EXT_MECH_TYPE_ROW\(dma,[^\n]*", ops, re.M)
            if row is None:
                raise AssertionError("production DMA type row missing")
            code += macro[0] + "\nstatic const struct xdev_ext_mech_type_decl xdev_ext_mech_types[] = {\n" + row[0] + "\n};\n#undef XDEV_EXT_MECH_TYPE_ROW\n"
            code += function(ops, "xdev_ext_mech_type_schema")
        name = prefix+"_ops_validate"
        code += function(ops[ops.index("static int "+name+"("):], name)
        code += r"""
int main(void) {
 struct xdev_ext_dma_mech_ops ops={.abi_version=1,.build=(void *)1,.complete=(void *)1};
 if (VALIDATE(&ops) != -EINVAL) { fputs("FAIL old DMA ABI silently accepted\n",stderr);return 1; }
 ops.abi_version=2;assert(!VALIDATE(&ops));
 ops.abi_version=3;assert(VALIDATE(&ops)==-EINVAL);
 ops.abi_version=2;ops.flags=~0U;assert(VALIDATE(&ops)==-EINVAL);
 ops.flags=0;ops.complete=NULL;assert(VALIDATE(&ops)==-EINVAL);
 puts("PASS DMA struct_ops ABI: v2 accepted; v1/v3, unknown flags and missing completion refused");
 return 0;
}
""".replace("VALIDATE",prefix+"_ops_validate")
        code = code.replace("#include <stdint.h>", "#include <stdint.h>\n#include <stdio.h>")
        exe = self.compile("abi", code)
        run = subprocess.run([str(exe)],capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertIn("PASS DMA struct_ops ABI",run.stdout)
        if dma:
            registration = re.search(r"XDEV_EXT_MECH_STRUCT_OPS\(dma,.*?;",ops,re.S)[0]
            self.assertIn("xdev_ext_dma_mech_ops_init_member",registration)
            self.assertIn("xdev_ext_dma_mech_ops_validate",registration)

    def run_case(self, mode, binary=None):
        run = subprocess.run([str(binary or self.binary), mode], capture_output=True,
                             text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("PASS " + mode, run.stdout)

    def test_mutation_window_admission_is_detected(self):
        exe = self.compile("mutant_lease_get", generate("lease_get"))
        run = subprocess.run([str(exe), "overlapping_sessions"], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("second overlapping active window", run.stderr)

    def test_mutation_completion_owner_guard_is_detected(self):
        exe = self.compile("mutant_owner_guard", generate("owner_guard"))
        run = subprocess.run([str(exe), "stale_owner"], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("expired ownership cannot become success", run.stderr)

    def test_mutation_cookie_prefix_is_detected(self):
        text = generate()
        if shared_runtime_dependencies(source("io_uring/xdev_ext_mech_dma.c"), source("io_uring/xdev_ext_mech_ce.c")):
            header = source("io_uring/xdev_ext_compfam_copy_runtime.h")
            header = header.replace("struct xdev_ext_comp_copy_cookie {",
                                    "struct xdev_ext_comp_copy_cookie {\n u64 invalid_prefix;", 1)
            # Inline the actual header with precisely the old deliberate ABI break.
            header = re.sub(r'^#include [<"].*[>"]\n', '', header, flags=re.M)
            text = text.replace('#include "io_uring/xdev_ext_compfam_copy_runtime.h"', header, 1)
        else:
            text = text.replace("struct xdev_ext_dma_cookie {", "struct xdev_ext_dma_cookie {\n u64 invalid_prefix;", 1)
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


def main():
    global REF
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
    inputs += shared_runtime_dependencies(source("io_uring/xdev_ext_mech_dma.c"), source("io_uring/xdev_ext_mech_ce.c"))
    inputs += common_lease_dependencies(source("io_uring/xdev_ext_mech_dma.c"), source("io_uring/xdev_ext_mech_ce.c"))
    inputs += dma_scope_dependencies(source("io_uring/xdev_ext_mech_dma.c"))
    inputs += TransformSource.dependencies(source("io_uring/xdev_ext_mech.c"))
    inputs += tuple(dict.fromkeys(copy_window_dependencies(source("io_uring/xdev_ext_mech_dma.c")) +
                                 copy_window_dependencies(source("io_uring/xdev_ext_mech_ce.c"))))
    print(json.dumps({"source_root": str(ROOT), "ref": ref,
                      "working_tree": REF is None,
                      "source_sha256": {p: hashlib.sha256(source(p).encode()).hexdigest() for p in inputs}}), flush=True)
    suite = unittest.main(argv=[__file__] + rest, verbosity=2, exit=False)
    if suite.result.errors:
        print("SETUP provider fixture infrastructure error", file=_layout_sys.stderr)
        return 2
    return 0 if suite.result.wasSuccessful() else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print("SETUP " + str(error), file=_layout_sys.stderr)
        raise SystemExit(2)

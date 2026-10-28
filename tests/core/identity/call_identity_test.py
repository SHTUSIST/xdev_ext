#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production call identity checks without a built kernel.

The fixture only supplies kernel environment primitives. Structs, call_of,
invoke, its argument/member helpers, and all eight ctx kfuncs in mech_ops.c
are compiled verbatim from the selected checkout. A copied envelope retaining
the right magic must never authorize a helper or hide misuse from invoke.
"""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
KERNEL = Path(os.environ.get("KERNEL_SRC", HERE.parents[3])).resolve()


def definition(source, name, structure=False):
    pattern = (r"^struct " + re.escape(name) + r"\s*\{" if structure else
               r"^[A-Za-z_][^;{}]*?\b" + re.escape(name) + r"\([^;{}]*\)\s*\{")
    found = re.search(pattern, source, re.M)
    if found is None:
        raise AssertionError("production definition missing: " + name)
    end, depth = found.end(), 1
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise AssertionError("unterminated production definition: " + name)
    return source[found.start():end] + (";" if structure else "")


def production():
    header = (KERNEL / "include/linux/xdev_ext_mech.h").read_text()
    ops = (KERNEL / "io_uring/xdev_ext_mech_ops.c").read_text()
    internal = (KERNEL / "io_uring/xdev_ext_mech_internal.h").read_text()
    layout = re.search(r"^#define XDEV_EXT_MECH_OPS_TYPE\(name\).*?^}", header, re.M | re.S)
    if layout is None:
        raise AssertionError("production struct_ops layout missing")
    parts = [layout.group(), "XDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);"]
    parts.extend(definition(header, name, True) for name in (
        "xdev_ext_mech_frame", "xdev_ext_mech_call", "xdev_ext_mech_call_args"))
    parts.append(definition(internal, "xdev_ext_mech_target", True))
    magic = re.search(r"^#define XDEV_EXT_MECH_CALL_MAGIC\b.*$", header, re.M)
    if magic is None:
        raise AssertionError("production call seal missing")
    parts.append(magic.group())
    active = re.search(r"^(?:static\s+)?DEFINE_PER_CPU\([^;]*\bxdev_ext_mech_active_call\s*\);",
                       ops, re.M)
    if active:
        parts.append(active.group())
    if re.search(r"^struct xdev_ext_mech_prepare_call\s*\{", ops, re.M):
        parts.append(definition(ops, "xdev_ext_mech_prepare_call", True))
        parts.extend(re.findall(r"^(?:static\s+)?DEFINE_(?:HASHTABLE|(?:RAW_)?SPINLOCK)\([^;]*\);",
                                ops, re.M))
        parts.append(definition(ops, "xdev_ext_mech_prepare_current"))
    # The original inline is deliberately supported so the very same fixture
    # can demonstrate RED on an unmodified checkout, without a test algorithm.
    location = ops if re.search(r"\bxdev_ext_mech_call_of\([^;{}]*\)\s*\{", ops) else header
    parts.append(definition(location, "xdev_ext_mech_call_of"))
    parts.append("typedef __s32 (*xdev_ext_mech_cb_t)(const struct xdev_ext_mech_ctx *ctx);")
    parts.extend(definition(ops, name) for name in (
        "xdev_ext_mech_member_fn", "xdev_ext_mech_args_ok", "xdev_ext_mech_invoke",
        "xdev_ext_mech_frame_bytes", "xdev_ext_mech_compute_frame",
        "bpf_xdev_ext_info", "bpf_xdev_ext_desc", "bpf_xdev_ext_cqe",
        "bpf_xdev_ext_frame", "bpf_xdev_ext_frame_crc32c", "bpf_xdev_ext_frame_len",
        "bpf_xdev_ext_frame_rw", "bpf_xdev_ext_frame_set_len"))
    return "\n\n".join(parts)


class CallIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "gcc"))
        if not compiler or not shutil.which(compiler[0]):
            raise AssertionError("GCC unavailable")
        cls.directory = tempfile.TemporaryDirectory(prefix="xdev-ext-call-identity-")
        cls.addClassCleanup(cls.directory.cleanup)
        directory = Path(cls.directory.name)
        fixture = (HERE / "call_identity_fixture.c.in").read_text()
        (directory / "fixture.c").write_text(fixture.replace("/* PRODUCTION */", production()))
        cls.binary = directory / "probe"
        command = compiler + ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                              "-Wno-unused-function", "-Wno-unused-parameter", "-pthread",
                              "-I" + str(KERNEL), str(directory / "fixture.c"),
                              "-o", str(cls.binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if built.returncode:
            raise AssertionError("fixture compile failed:\n" + built.stdout + built.stderr)

    def run_case(self, name, *arguments):
        run = subprocess.run([str(self.binary), name, *arguments], capture_output=True,
                             text=True, timeout=15)
        self.assertEqual(run.returncode, 0, name + ":\n" + run.stdout + run.stderr)

    def test_no_callback_rejects_sealed_envelope(self):
        self.run_case("inactive")

    def test_copied_envelope_rejected_and_error_latched_on_real_call(self):
        self.run_case("copy", "identity")

    def test_each_ctx_kfunc_rejects_copy_and_latches_real_call(self):
        for helper in ("info", "desc", "cqe", "frame", "frame_crc32c",
                       "frame_len", "frame_rw", "frame_set_len"):
            with self.subTest(helper=helper):
                self.run_case("copy", helper)

    def test_legal_prepare_build_complete_compute(self):
        for member in ("prepare", "build", "complete", "compute"):
            with self.subTest(member=member):
                self.run_case("legal", member)

    def test_lone_ctx_copy_does_not_require_an_envelope(self):
        self.run_case("ctx-only")

    def test_noncurrent_pointer_is_not_read(self):
        self.run_case("unreadable")

    def test_null_ctx_is_rejected_and_latches_current_call(self):
        self.run_case("null")

    def test_no_callback_accepts_no_identity_even_for_null(self):
        self.run_case("inactive-null")

    def test_corrupted_real_seal_latches_protocol_error(self):
        self.run_case("unsealed")

    def test_callback_disables_preemption(self):
        self.run_case("preempt")

    def test_nested_invoke_restores_outer_identity(self):
        self.run_case("nested")

    def test_inner_wrong_outer_identity_only_poisons_inner_call(self):
        self.run_case("nested-misuse")

    def test_error_callback_restores_outer_identity(self):
        self.run_case("nested-error")

    def test_no_callback_identity_leaks_after_error_or_success(self):
        self.run_case("cleanup")

    def test_nested_validation_failure_preserves_outer(self):
        self.run_case("nested-validation")

    def test_simultaneous_cpus_keep_call_identity_independent(self):
        self.run_case("parallel")

    def test_sleeping_tasks_on_one_cpu_keep_prepare_identity_independent(self):
        self.run_case("prepare-parallel")

    def test_prepare_allows_scheduling_and_migration(self):
        self.run_case("prepare-migrate")

    def test_prepare_nested_prepare_and_compute_restore_outer(self):
        for inner in ("prepare", "compute"):
            with self.subTest(inner=inner):
                self.run_case("prepare-nested", inner)

    def test_interrupt_cannot_borrow_sleeping_task_prepare(self):
        self.run_case("prepare-interrupt")


if __name__ == "__main__":
    unittest.main(verbosity=2)

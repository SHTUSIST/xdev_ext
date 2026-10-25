#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract of the XDEV_EXT mechanism layer that classes code against."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HEADER = ROOT / "include/linux/xdev_ext_mech.h"

# Words that state where a declared function may run.
CONTEXT = re.compile(
    r"any context|process context|worker|softirq|rx_lock|initcall|"
    r"module (init|exit)|load time|CREATE", re.I)


def kconfig_block(text: str, symbol: str) -> str:
    match = re.search(rf"^config {symbol}\n(.*?)(?=^config |\Z)", text,
                      re.M | re.S)
    if not match:
        raise AssertionError(f"missing config {symbol}")
    return match.group(1)


def function_body(path: Path, signature: str) -> str:
    """Text of the function whose definition starts with @signature."""
    text = path.read_text(encoding="utf-8")
    # L11: checked-unbind introduces forward declarations; inspect definitions.
    start = text.index(signature)
    opening = text.index("{", start)
    while ";" in text[start:opening]:
        start = text.index(signature, start + len(signature))
        opening = text.index("{", start)
    depth = 0
    for offset, character in enumerate(text[opening:], opening):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[start:offset + 1]
    raise AssertionError(f"unterminated function {signature} in {path}")


def mech_sources():
    return sorted((ROOT / "io_uring").rglob("xdev_ext_mech*.c"))


def kernel_part(text: str) -> str:
    start = text.index("#ifdef __KERNEL__\n/*")
    return text[start:]


def prototypes(text: str):
    """(name, preceding text) of every out-of-line function declaration."""
    code = re.sub(r"static inline[\s\S]*?\n}\n", "", text)
    for match in re.finditer(
            r"^(?:const )?(?:struct \w+ \*|[a-z_0-9]+ \*?|u\d+ )\s*"
            r"(\w+)\(([^;{]*?)\);", code, re.M):
        yield match.group(1), code[:match.start()]


class UbrMechSourceTest(unittest.TestCase):
    def test_kconfig_symbols(self):
        text = (ROOT / "io_uring/Kconfig").read_text(encoding="utf-8")
        mech = kconfig_block(text, "XDEV_EXT_MECH")
        self.assertRegex(mech, r"^\tbool ", )
        self.assertIn("depends on IO_URING_XDEV_EXT_BPF_POLICY && XDP_SOCKETS",
                      mech)
        self.assertIn("select CRC32", mech)
        for symbol in ("XDEV_EXT_MECH_CE", "XDEV_EXT_MECH_C_REFERENCE",
                       "XDEV_EXT_MECH_KVM_BOUNCE"):
            block = kconfig_block(text, symbol)
            self.assertRegex(block, r"^\tbool ", symbol)
            self.assertIn("depends on XDEV_EXT_MECH" +
                          (" && !XDEV_EXT_MECH_ZEROCOPY" if symbol ==
                           "XDEV_EXT_MECH_KVM_BOUNCE" else "") + "\n", block, symbol)
            self.assertIn("default n", block, symbol)
        strict = kconfig_block(text, "XDEV_EXT_MECH_ZEROCOPY")
        self.assertIn("default y", strict)
        self.assertIn("depends on XDEV_EXT_MECH\n", strict)
        # IO_URING_XDEV_EXT_BPF_POLICY is what pulls in DEBUG_INFO_BTF: without it
        # a built-in struct_ops registration silently returns 0.
        self.assertIn("depends on DEBUG_INFO_BTF",
                      kconfig_block(text, "IO_URING_XDEV_EXT_BPF_POLICY"))

    def test_no_build_line_without_a_source(self):
        for makefile in ("io_uring/Makefile", "io_uring/iaa/Makefile", "net/xdp/Makefile",
                         "drivers/nvme/host/Makefile"):
            text = (ROOT / makefile).read_text(encoding="utf-8")
            for line in text.splitlines():
                if "XDEV_EXT_MECH" not in line:
                    continue
                for obj in re.findall(r"(\w+)\.o", line):
                    source = (ROOT / makefile).parent / f"{obj}.c"
                    self.assertTrue(source.is_file(), f"{makefile}: {obj}.o")

    def test_frame_states_are_shared_with_the_pure_core(self):
        text = HEADER.read_text(encoding="utf-8")
        user = text[:text.index("#ifdef __KERNEL__\n/*")]
        core = (ROOT / "io_uring/xdev_ext_mech_core.h").read_text(encoding="utf-8")

        self.assertIn("enum xdev_ext_mech_frame_state {", user)
        self.assertIn("struct xdev_ext_mech_hold_intent {", user)
        self.assertIn("enum xdev_ext_mech_counter {", user)
        self.assertNotIn("enum xdev_ext_mech_frame_state {", core)
        self.assertIn("#include <linux/xdev_ext_mech.h>", core)
        self.assertIn('#include "../include/linux/xdev_ext_mech.h"', core)

    def test_struct_ops_types(self):
        text = HEADER.read_text(encoding="utf-8")
        macro = re.search(r"#define XDEV_EXT_MECH_OPS_TYPE\(name\)(.*?)\n}\n",
                          text, re.S)
        self.assertIsNotNone(macro)
        members = re.findall(r"\(\*(\w+)\)\(const struct xdev_ext_mech_ctx \*ctx\)",
                             macro.group(1))
        # compute: CPU class only (Documentation/userspace-api/xdev_ext-compute.rst).
        self.assertEqual(members, ["prepare", "build", "complete", "compute"])
        self.assertLess(macro.group(1).index("__u32 abi_version;"),
                        macro.group(1).index("__u32 flags;"))
        for name in ("xdev_ext_nvme_mech_ops", "xdev_ext_afxdp_mech_ops",
                     "xdev_ext_ce_mech_ops"):
            self.assertIn(f"XDEV_EXT_MECH_OPS_TYPE({name});", text)

    def test_call_envelope(self):
        text = HEADER.read_text(encoding="utf-8")
        call = re.search(r"struct xdev_ext_mech_call {\n(.*?)\n};", text, re.S)
        self.assertIsNotNone(call)
        fields = re.findall(r"\s(\**\w+)(?:\[\w+\])?;", call.group(1))
        self.assertEqual(fields[0], "ctx")
        for field in ("magic", "member", "callsite", "hold_calls",
                      "protocol_error", "hold", "*s", "*st", "*b", "*frames",
                      "nr_frames", "frame_size", "hdr_room", "*info",
                      "info_size", "*scratch", "desc_size", "desc_cap",
                      "*cqe", "cqe_size", "cqe_cap", "batch_frames"):
            self.assertIn(field, fields)
        of = re.search(r"xdev_ext_mech_call_of\(const struct xdev_ext_mech_ctx \*ctx\)"
                       r"\n{(.*?)\n}", text, re.S)
        self.assertIsNotNone(of)
        self.assertIn("container_of(ctx, struct xdev_ext_mech_call, ctx)",
                      of.group(1))
        self.assertIn("READ_ONCE(c->magic) == XDEV_EXT_MECH_CALL_MAGIC",
                      of.group(1))
        # The mechanism layer must not use the per-CPU envelope: a sleepable
        # prepare can be preempted and overwritten on the same CPU.
        self.assertNotIn("DEFINE_PER_CPU", text)

    def test_hold_count_is_the_layout_frames_per_batch(self):
        # A kfunc takes at most five arguments, so bpf_xdev_ext_afxdp_hold()
        # has no count: C records the session layout's frames per batch,
        # carried in the envelope from the session or, without one, from
        # the caller of xdev_ext_mech_call_active().
        text = HEADER.read_text(encoding="utf-8")
        hold = re.search(r"^int bpf_xdev_ext_afxdp_hold\(([^;]*)\);", text, re.M)
        self.assertIsNotNone(hold)
        self.assertEqual([a.split()[-1] for a in hold.group(1).split(",")],
                         ["*ctx", "key", "pos", "span_off", "span_len"])
        args = re.search(r"struct xdev_ext_mech_call_args {\n(.*?)\n};", text,
                         re.S)
        self.assertRegex(args.group(1), r"\bu32 batch_frames;")
        call = function_body(ROOT / "io_uring/xdev_ext_mech.c",
                             "int xdev_ext_mech_call(")
        self.assertIn(".batch_frames = s->frames,", call)
        ops = ROOT / "io_uring/xdev_ext_mech_ops.c"
        active = function_body(ops, "int xdev_ext_mech_call_active(")
        self.assertIn("t.batch_frames = a->batch_frames;", active)
        invoke = function_body(ops, "int xdev_ext_mech_invoke(")
        self.assertIn("call.batch_frames = t->batch_frames;", invoke)
        self.assertRegex((ROOT / "io_uring/xdev_ext_mech_internal.h").read_text(
            encoding="utf-8"), r"\bu32 batch_frames;")

    def test_completion_status_convention_is_stated(self):
        # One status convention for every class; native acceptance can no
        # longer become a resend just because the program requests RETRY.
        text = HEADER.read_text(encoding="utf-8")
        doc = re.search(r"/\*\n \* Any context \(end_io,.*?\*/", text,
                        re.S).group(0)
        for words in ("negative errno", "positive", "native class status",
                      "Accepted commands are never resent", "preaccept queue refusal"):
            self.assertIn(words, doc)
        nvme = function_body(ROOT / "drivers/nvme/host/xdev_ext_mech_nvme.c",
                             "static enum rq_end_io_ret "
                             "nvme_xdev_ext_class_end_io(")
        self.assertIn("nvme_req(req)->status ?: blk_status_to_errno(err)",
                      nvme)
        self.assertLess(nvme.index("xdev_ext_mech_batch_completion_claim(b, ticket)"),
                        nvme.index("nvme_xdev_ext_mech_cqe("))
        self.assertIn("xdev_ext_mech_batch_completion_publish(b, ticket, status, uncertain);", nvme)
        self.assertIn("uncertain = blk_rq_bytes(req) != 0", nvme)
        self.assertNotIn("kfree(done)", nvme)
        ce = function_body(ROOT / "io_uring/xdev_ext_mech_ce.c",
                           "void xdev_ext_ce_complete(")
        self.assertIn("xdev_ext_mech_batch_completion_publish(ck->b, ticket, "
                      "err, false);", ce)

    def test_class_and_backend_tables(self):
        text = HEADER.read_text(encoding="utf-8")
        ops = re.search(r"struct xdev_ext_mech_class_ops {\n(.*?)\n};", text, re.S)
        self.assertIsNotNone(ops)
        for field in ("class_id", "desc_size", "desc_cap", "info_size",
                      "cqe_size", "cqe_cap", "batch_priv_size", "batch_cookie_size", "*owner",
                      "(*bind)", "(*unbind)", "(*fill_info)",
                      "(*default_build)", "(*validate)", "(*submit)",
                      "(*fill_cqe)", "(*mark_dead)"):
            self.assertIn(field, ops.group(1))
        backend = re.search(r"struct xdev_ext_ce_backend_ops {\n(.*?)\n};", text,
                            re.S)
        self.assertIsNotNone(backend)
        for field in ("*owner", "*fops", "(*bind_region)", "(*unbind_region)",
                      "(*bind_host)", "(*unbind_host)", "(*submit)"):
            self.assertIn(field, backend.group(1))
        self.assertRegex(
            text, r"void xdev_ext_ce_complete\(struct xdev_ext_ce_cookie \*ck, u64 ticket, int status,"
                  r"\s+bool hw_submitted, u64 bytes_done\);")

    def test_every_declaration_states_its_context(self):
        text = kernel_part(HEADER.read_text(encoding="utf-8"))
        names = []
        for name, before in prototypes(text):
            names.append(name)
            comment = before.rstrip()
            self.assertTrue(comment.endswith("*/"), name)
            self.assertRegex(comment[comment.rindex("/*"):], CONTEXT, name)
        for name in ("xdev_ext_mech_class_register", "xdev_ext_mech_class_unregister",
                     "xdev_ext_mech_call", "xdev_ext_mech_call_active",
                     "xdev_ext_mech_batch_complete", "xdev_ext_mech_batch_sequester",
                     "xdev_ext_mech_batch_frame", "xdev_ext_mech_batch_priv",
                     "xdev_ext_mech_batch_cookie", "xdev_ext_mech_batch_ticket",
                     "xdev_ext_mech_batch_completion_claim",
                     "xdev_ext_mech_batch_completion_publish",
                     "xdev_ext_mech_hold_commit", "xdev_ext_mech_frame_recycle",
                     "xdev_ext_mech_frame_publish", "xdev_ext_mech_pool_frame_move",
                     "xdev_ext_mech_count", "xdev_ext_mech_session_admits",
                     "xdev_ext_mech_stage_get_cmd", "xdev_ext_mech_stage_put",
                     "xdev_ext_mech_stage_dead", "xdev_ext_mech_class_kfunc_filter",
                     "xsk_xdev_ext_mech_pool_bind", "io_xdev_ext_umem_mech_pool_bind",
                     "xdev_ext_ce_backend_register", "xdev_ext_ce_backend_unregister",
                     "xdev_ext_ce_complete", "io_xdev_ext_mech_register",
                     "io_xdev_ext_mech_ring_exit"):
            self.assertIn(name, names)

    def test_struct_ops_types_register_then_self_check(self):
        path = ROOT / "io_uring/xdev_ext_mech_ops.c"
        init = " ".join(function_body(
            path, "static int __init xdev_ext_mech_ops_init(void)").split())
        regs = [init.index(f"register_bpf_struct_ops(&bpf_xdev_ext_{c}_mech_ops, "
                           f"xdev_ext_{c}_mech_ops)")
                for c in ("nvme", "afxdp", "ce")]
        check = init.index("xdev_ext_mech_types_findable()")
        ready = init.index("WRITE_ONCE(xdev_ext_mech_types_ready, true)")
        self.assertLess(init.index("register_btf_kfunc_id_set("), min(regs))
        # A built-in registration without vmlinux BTF returns 0 having
        # registered nothing, so readiness waits for the lookup.
        self.assertLess(max(regs), check)
        self.assertLess(check, ready)
        findable = function_body(
            path, "static bool __init xdev_ext_mech_types_findable(void)")
        self.assertIn("bpf_struct_ops_find(btf, id)", findable)
        self.assertIn("desc->st_ops != xdev_ext_mech_st_ops[i]", findable)
        self.assertIn("late_initcall(xdev_ext_mech_ops_init);",
                      path.read_text(encoding="utf-8"))

    def test_only_prepare_takes_a_sleepable_program(self):
        text = (ROOT / "io_uring/xdev_ext_mech_ops.c").read_text(encoding="utf-8")
        table = re.search(
            r"xdev_ext_mech_ops_members\[\] = {\n(.*?)\n};", text, re.S)
        self.assertIsNotNone(table)
        rows = dict(re.findall(r"offsetof\(struct xdev_ext_nvme_mech_ops, (\w+)\),"
                               r"\s*([^}]*)}", table.group(1)))
        self.assertEqual(sorted(rows), ["build", "complete", "prepare"])
        self.assertIn(".sleepable = true", rows["prepare"])
        self.assertNotIn(".required", rows["prepare"])
        for member in ("build", "complete"):
            self.assertNotIn("sleepable", rows[member])
            self.assertIn(".required = true", rows[member])
        check = function_body(
            ROOT / "io_uring/xdev_ext_mech_ops.c",
            "static int xdev_ext_mech_ops_check_member(")
        self.assertIn("xdev_ext_ops_check_member(&xdev_ext_mech_ops_desc,", check)
        # One instance per class: the struct_ops macro wires all three.
        for cls in ("nvme", "afxdp", "ce"):
            self.assertRegex(text, rf"XDEV_EXT_MECH_STRUCT_OPS\({cls}, "
                                   rf"XDEV_EXT_MECH_CLASS_{cls.upper()},\s*"
                                   rf"xdev_ext_(?:ce_)?mech_ops_init_member,\s*"
                                   rf"xdev_ext_(?:ce_)?mech_ops_validate\);")
        self.assertNotIn("priv_stack", text)

    def test_shared_kfunc_flags(self):
        text = (ROOT / "io_uring/xdev_ext_mech_ops.c").read_text(encoding="utf-8")
        ids = re.search(r"BTF_KFUNCS_START\(xdev_ext_mech_kfunc_ids\)\n(.*?)"
                        r"BTF_KFUNCS_END", text, re.S)
        self.assertIsNotNone(ids)
        flags = dict(re.findall(r"BTF_ID_FLAGS\(func, (\w+), ([^)]*)\)",
                                ids.group(1)))
        views = ("bpf_xdev_ext_info", "bpf_xdev_ext_desc", "bpf_xdev_ext_cqe",
                 "bpf_xdev_ext_frame")
        self.assertEqual(sorted(flags), sorted(views + (
            "bpf_xdev_ext_frame_crc32c", "bpf_xdev_ext_crc32c")))
        for name, value in flags.items():
            self.assertIn("KF_TRUSTED_ARGS", value, name)
            self.assertEqual("KF_RET_NULL" in value, name in views, name)
        sets = {name: set(re.findall(r"BTF_ID\(func, (\w+)\)", body))
                for name, body in re.findall(
                    r"BTF_SET_START\((xdev_ext_mech_\w+_kfuncs)\)\n(.*?)"
                    r"BTF_SET_END", text, re.S)}
        self.assertEqual(sets["xdev_ext_mech_prepare_kfuncs"],
                         {"bpf_xdev_ext_info", "bpf_xdev_ext_crc32c"})
        self.assertEqual(sets["xdev_ext_mech_build_kfuncs"],
                         {"bpf_xdev_ext_info", "bpf_xdev_ext_desc", "bpf_xdev_ext_frame",
                          "bpf_xdev_ext_frame_crc32c", "bpf_xdev_ext_crc32c"})
        self.assertEqual(sets["xdev_ext_mech_complete_kfuncs"],
                         {"bpf_xdev_ext_info", "bpf_xdev_ext_cqe", "bpf_xdev_ext_frame",
                          "bpf_xdev_ext_frame_crc32c", "bpf_xdev_ext_crc32c"})

    def test_kfunc_filters_ignore_kfuncs_outside_their_set(self):
        # Every filter on the STRUCT_OPS hook runs for every kfunc; a non-zero
        # answer hides the kfunc from sched_ext, HID and the policy layer too.
        core = function_body(ROOT / "io_uring/xdev_ext_ops_core.c",
                             "int xdev_ext_ops_kfunc_filter(")
        body = core[core.index("{"):]
        self.assertTrue(body[body.index("if ("):].startswith(
            "if (!btf_id_set8_contains(rule->ids, kfunc_id))\n\t\treturn 0;"))
        path = ROOT / "io_uring/xdev_ext_mech_ops.c"
        shared = function_body(path, "static int xdev_ext_mech_kfunc_filter(")
        self.assertIn("return xdev_ext_ops_kfunc_filter(&xdev_ext_mech_kfunc_rule, "
                      "prog, kfunc_id);", shared)
        cls = function_body(path, "int xdev_ext_mech_class_kfunc_filter(")
        self.assertIn("return xdev_ext_ops_kfunc_filter(&rule, prog, kfunc_id);",
                      cls)
        self.assertIn(".ids = ids,", cls)

    def test_call_envelope_is_on_the_callers_stack(self):
        for path in mech_sources():
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("DEFINE_PER_CPU", text, path)
            self.assertNotIn("this_cpu_", text, path)
            self.assertNotIn("preempt_disable", text, path)
        invoke = function_body(ROOT / "io_uring/xdev_ext_mech_ops.c",
                               "int xdev_ext_mech_invoke(")
        self.assertIn("struct xdev_ext_mech_call call;", invoke)
        seal = invoke.index("WRITE_ONCE(call.magic, XDEV_EXT_MECH_CALL_MAGIC);")
        run = invoke.index("*ret = fn(&call.ctx);")
        unseal = invoke.index("WRITE_ONCE(call.magic, 0);")
        self.assertLess(seal, run)
        self.assertLess(run, unseal)
        self.assertLess(unseal, invoke.index("call.protocol_error"))

    def test_iou_umem_pool_keeps_its_umem(self):
        path = ROOT / "io_uring/xdev_ext_umem.c"
        bind = function_body(path, "int io_xdev_ext_umem_mech_pool_bind(")
        # The session's own UMEM reference keeps pages and words alive after
        # IORING_UNREGISTER_XDEV_EXT_UMEM; the words live with the UMEM so every
        # session on it agrees on who owns a frame.
        self.assertLess(bind.index("umem = io_xdev_ext_umem_get_ctx(ctx);"),
                        bind.index(".state = state,"))
        self.assertIn("umem->mech_state = kvzalloc(", bind)
        self.assertIn("io_xdev_ext_umem_put(umem);", bind)
        release = function_body(path,
                                "static void io_xdev_ext_umem_mech_release(")
        self.assertLess(release.index("XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_USER"),
                        release.index("io_xdev_ext_umem_put(m->umem);"))
        free = function_body(path, "static void io_xdev_ext_umem_free(")
        self.assertIn("kvfree(umem->mech_state);", free)
        self.assertRegex((ROOT / "io_uring/xdev_ext_umem.h").read_text(
            encoding="utf-8"), r"\bu8\s+\*mech_state;")
        alloc = function_body(path, "static int io_xdev_ext_umem_mech_alloc(")
        self.assertIn("XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_HELD", alloc)
        self.assertIn("-ENOSPC", alloc)

    def test_batch_is_in_flight_before_submit(self):
        path = ROOT / "io_uring/xdev_ext_mech.c"
        submit = function_body(path, "static int xdev_ext_mech_submit(")
        call = submit.index("ret = st->cls->submit(st, b);")
        # blk_execute_rq_nowait() may complete before it returns, so the
        # batch, its frames and the generation ticket are set up first.
        for step in ("XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_INFLIGHT",
                     "xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_SUBMIT, 0);",
                     "xdev_ext_mech_completion_begin(&b->completion, &b->ticket)"):
            self.assertLess(submit.index(step), call, step)
        # The class area is zeroed when a step starts, so ->validate can
        # hand ->submit what it admitted; it stays intact from ->validate
        # through ->submit to ->fill_cqe.
        self.assertNotIn("b->priv", submit)
        build = function_body(path, "static int xdev_ext_mech_build(")
        zero = build.index("memset(b->priv, 0, s->priv_size);")
        for later in ("st->cls->default_build(st, b, s->scratch);",
                      "st->cls->validate(st, b, s->scratch, n);"):
            self.assertLess(zero, build.index(later), later)
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count("memset(b->priv, 0,"), 1)
        # A sequestered batch's object, and with it the class area a device
        # may still complete into, is never reused.
        put = function_body(path, "static bool xdev_ext_mech_batch_put_locked(")
        self.assertIn("if (!sequestered)\n\t\tlist_add(&b->node, &s->free);",
                      put)
        header = HEADER.read_text(encoding="utf-8")
        priv = header[:header.index("void *xdev_ext_mech_batch_priv(")]
        priv = priv[priv.rindex("/*"):]
        for words in ("->validate", "->submit", "->fill_cqe", "sequestered"):
            self.assertIn(words, priv)
        # Refusal can reclaim SUBMITTED only if no callback has claimed it.
        cancel = submit.index("xdev_ext_mech_completion_cancel(&b->completion, b->ticket)", call)
        self.assertLess(cancel, submit.index("atomic64_dec(&s->submitted[k]);", call))
        self.assertRegex(submit[call:], r"if \(xdev_ext_mech_completion_cancel\("
                         r"&b->completion, b->ticket\)\)\s+return 0;")
        claim = function_body(path, "int xdev_ext_mech_batch_completion_claim(")
        self.assertIn("xdev_ext_mech_completion_claim(&b->completion, ticket)", claim)
        for name, quarantine in (("xdev_ext_mech_batch_complete", "false"),
                                 ("xdev_ext_mech_batch_sequester", "true")):
            complete = function_body(path, f"void {name}(")
            self.assertIn("u64 ticket", complete)
            self.assertRegex(complete, r"if \(!xdev_ext_mech_batch_completion_claim\("
                             r"b, ticket\)\)\s+xdev_ext_mech_batch_completion_publish\(")
            self.assertIn(f"xdev_ext_mech_batch_completion_publish(b, ticket, err, {quarantine});",
                          complete)

    def test_completion_metadata_is_published_before_the_session_inbox(self):
        path = ROOT / "io_uring/xdev_ext_mech.c"
        publish = function_body(path, "void xdev_ext_mech_batch_completion_publish(")
        order = [publish.index(step) for step in (
            "xdev_ext_mech_completion_publish_begin(&b->completion, ticket)",
            "b->sequester = sequester;",
            "xdev_ext_mech_completion_publish_end(&b->completion, ticket, err);",
            "xdev_ext_mech_batch_queue(b);")]
        self.assertEqual(order, sorted(order))
        self.assertRegex(publish, r"if \(xdev_ext_mech_completion_publish_begin\("
                         r"&b->completion, ticket\)\)\s+return;")
        queue = function_body(path, "static void xdev_ext_mech_batch_queue(")
        order = [queue.index(step) for step in (
            "cmpxchg(&b->queued, 0, 1)",
            "llist_add(&b->inbox_node, &s->inbox)",
            "kthread_queue_work(worker, &s->drain_work);")]
        self.assertEqual(order, sorted(order))
        self.assertRegex(queue, r"if \(cmpxchg\(&b->queued, 0, 1\)\)\s+return;")
        # A publisher may be preempted after the worker consumes its last
        # reference; worker teardown must wait for that enqueue tail.
        self.assertLess(queue.index("rcu_read_lock();"), queue.index("llist_add("))
        self.assertLess(queue.index("kthread_queue_work("), queue.index("rcu_read_unlock();"))
        drain = function_body(path, "static void xdev_ext_mech_batch_drain(")
        order = [drain.index(step) for step in (
            "while ((head = llist_del_all(&s->inbox)))",
            "llist_reverse_order(head)", "llist_for_each_safe(node, next, head)",
            "smp_store_release(&b->queued, 0);",
            "xdev_ext_mech_completion_consume(", "xdev_ext_mech_batch_landed(s, b);")]
        self.assertEqual(order, sorted(order))
        # The detached node may be enqueued again by a synchronous next stage.
        self.assertIn("&b->completion, b->ticket, &b->status", drain)
        batch = re.search(r"struct xdev_ext_mech_batch {\n(.*?)\n};",
                          path.read_text(encoding="utf-8"), re.S).group(1)
        self.assertNotIn("struct kthread_work", batch)

    def test_worker_steps_follow_the_pure_rules(self):
        path = ROOT / "io_uring/xdev_ext_mech.c"
        build = function_body(path, "static int xdev_ext_mech_build(")
        order = [build.index(step) for step in (
            "xdev_ext_mech_fill_info(s, st, b);",
            "memset(s->scratch, 0, len);",
            "xdev_ext_mech_call(st, &a, &ret, NULL);",
            "xdev_ext_mech_ret_resolve(st->class_id, XDEV_EXT_MECH_MEMBER_BUILD,",
            "xdev_ext_mech_build_step(ret, st->cls->default_build, &err)",
            "xdev_ext_mech_slots_used(s->scratch,",
            "st->cls->validate(st, b, s->scratch, n);")]
        self.assertEqual(order, sorted(order))
        landed = function_body(path, "static void xdev_ext_mech_batch_landed(")
        order = [landed.index(step) for step in (
            "XDEV_EXT_MECH_F_INFLIGHT,",
            "cls->fill_cqe(st, b, s->cqe);",
            "xdev_ext_mech_call(st, &a, &ret, NULL)",
            "xdev_ext_mech_complete_step(st->class_id, ret, b->status,")]
        self.assertEqual(order, sorted(order))
        end = function_body(path, "static void xdev_ext_mech_end(")
        # Keep legacy finished-batch signals, but let the serialized notifier
        # suppress them after coarse notification is armed.
        notify = end.index("xdev_ext_mech_notify_locked(s, true);")
        self.assertLess(end.index("xdev_ext_mech_batch_put_locked("), notify)
        self.assertLess(notify, end.index("spin_unlock_irqrestore(&s->lock, flags);"))
        self.assertNotIn("eventfd_signal", end)
        notifier = function_body(path, "static void xdev_ext_mech_notify_locked(")
        self.assertIn("lockdep_assert_held(&s->lock);", notifier)
        self.assertIn("atomic64_read(&s->done) + atomic64_read(&s->aborted)", notifier)
        self.assertIn("atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_PUBLISHED])", notifier)
        self.assertRegex(notifier, r"if \(xdev_ext_mech_notify_signal\(&s->notify, finished,"
                         r"\s+atomic64_read\(&s->cnt\[XDEV_EXT_MECH_CNT_PUBLISHED\]\),"
                         r"\s+s->ss.state, s->last_err, legacy_event\) && s->evfd\)"
                         r"\s+eventfd_signal\(s->evfd\);")
        # Batches end in the worker; refilling START batches is queued, not
        # recursive, so a run of aborts cannot grow the stack.
        self.assertIn("kthread_queue_work(s->worker, &s->kick_work);", end)
        self.assertNotIn("xdev_ext_mech_start_more(s);", end)

    def test_teardown_order(self):
        path = ROOT / "io_uring/xdev_ext_mech.c"
        destroy = function_body(path, "static int xdev_ext_mech_session_destroy(")
        order = [destroy.index(step) for step in (
            "list_del_init(&s->all_node);",
            "xdev_ext_mech_session_stop(s, 0);",
            "timer_shutdown_sync(&s->group_timer);",
            "wait_event_timeout(s->drain_wq, xdev_ext_mech_settled(s),",
            "xdev_ext_mech_sess_drain(&s->ss, true);",
            "fate = xdev_ext_mech_sess_ref_fate(&s->ss);",
            "xdev_ext_mech_quarantine(s);",
            "xdev_ext_mech_session_release(s);")]
        self.assertEqual(order, sorted(order))
        park = destroy.index("xdev_ext_mech_quarantine(s);")
        self.assertLess(destroy.index("return -EBUSY;", park),
                        destroy.index("xdev_ext_mech_session_release(s);"))
        release = function_body(path, "static int xdev_ext_mech_session_release(")
        order = [release.index(step) for step in (
            "kthread_destroy_worker(s->worker);",
            "s->st[i].cls->unbind(&s->st[i]);",
            "s->pool.ops->release(&s->pool);",
            "fput(s->pool_file);",
            "xdev_ext_mech_class_put(st->cls);",
            "xdev_ext_mech_ops_put(s->ops[i], s->pinned[i], s->c_owner[i]);",
            "kfree(s);")]
        self.assertEqual(order, sorted(order))
        # Drains run without uring_lock (and never under xs->mutex).
        for sig in ("void io_xdev_ext_mech_ring_exit(",
                    "static int xdev_ext_mech_stop_op("):
            body = function_body(path, sig)
            self.assertLess(body.index("mutex_unlock(&ctx->uring_lock);"),
                            body.index("xdev_ext_mech_session_destroy(s);"), sig)
        self.assertNotIn("xs->mutex", path.read_text(encoding="utf-8"))
        # STOP runs in the task that runs its own uring_cmd completions as
        # task work: it stops admission and never waits for those.
        stop = function_body(path, "static int xdev_ext_mech_stop_op(")
        order = [stop.index(step) for step in (
            "xdev_ext_mech_session_stop(s, 0);",
            "if (READ_ONCE(s->cmd_refs))\n\t\treturn -EAGAIN;",
            "list_del_rcu(&s->ring_node);",
            "mutex_unlock(&ctx->uring_lock);")]
        self.assertEqual(order, sorted(order))
        get = function_body(path, "struct xdev_ext_mech_stage *xdev_ext_mech_stage_get_cmd(")
        self.assertIn("s->cmd_refs++;", get)
        put = function_body(path, "void xdev_ext_mech_stage_put(")
        self.assertIn("s->cmd_refs--;", put)
        exit_work = function_body(ROOT / "io_uring/io_uring.c",
                                  "static __cold void io_ring_exit_work(")
        hook = exit_work.index("io_xdev_ext_mech_ring_exit(ctx);")
        self.assertLess(exit_work.index("&ctx->ref_comp, interval)"), hook)
        self.assertLess(hook, exit_work.index("init_task_work(&exit.task_work"))

    def test_release_stops_queueing_before_the_worker_goes(self):
        # A stage still published while release runs (CREATE failed after
        # an AF_XDP bind) can call xdev_ext_mech_stage_dead() until its unbind
        # takes xs->mutex.  xdev_ext_mech_session_stop() queues on s->worker
        # unless worker_gone, so release sets it under s->lock before it
        # frees the worker, and the stages are unbound after that.
        path = ROOT / "io_uring/xdev_ext_mech.c"
        release = function_body(path, "static int xdev_ext_mech_session_release(")
        # L11: checked unbind can quarantine under an earlier lock; the worker
        # gate must be inside its own critical section before destruction.
        gone = release.index("s->worker_gone = true;")
        lock = release.rindex("spin_lock_irqsave(&s->lock, flags);", 0, gone)
        unlock = release.index("spin_unlock_irqrestore(&s->lock, flags);", gone)
        checked = release.index("xdev_ext_mech_unbind_checked(s)")
        quarantine = release.index("xdev_ext_mech_quarantine(s)")
        self.assertLess(checked, quarantine)
        self.assertLess(quarantine, release.index("return final_err;"))
        self.assertLess(release.index("return final_err;"), gone)
        destroy = release.index("kthread_destroy_worker(s->worker);")
        unbind = release.index("s->st[i].cls->unbind(&s->st[i]);")
        self.assertEqual([lock, gone, unlock, destroy, unbind],
                         sorted([lock, gone, unlock, destroy, unbind]))
        stop = function_body(path, "static void xdev_ext_mech_session_stop(")
        self.assertIn("if (!s->worker_gone)\n\t\tkthread_queue_work(s->worker, "
                      "&s->stop_work);", stop)

    def test_stop_and_stage_dead_never_block(self):
        path = ROOT / "io_uring/xdev_ext_mech.c"
        sleeping = ("mutex_lock", "wait_event", "wait_for_completion",
                    "flush", "synchronize_", "msleep", "schedule",
                    "kthread_destroy_worker", "timer_shutdown_sync",
                    "_sync(", "down_read", "down_write", "fget", "fput")
        for sig in ("void xdev_ext_mech_stage_dead(",
                    "static void xdev_ext_mech_session_stop(",
                    "int xdev_ext_mech_batch_completion_claim(",
                    "void xdev_ext_mech_batch_completion_publish(",
                    "void xdev_ext_mech_batch_complete(",
                    "void xdev_ext_mech_batch_sequester(",
                    "static void xdev_ext_mech_batch_queue(",
                    "void xdev_ext_mech_stage_put(",
                    "int xdev_ext_mech_hold_commit(",
                    "void xdev_ext_mech_frame_recycle(",
                    "int xdev_ext_mech_frame_publish(",
                    "static void xdev_ext_mech_group_timeout("):
            body = function_body(path, sig)
            for word in sleeping:
                self.assertNotIn(word, body, f"{sig} {word}")
        dead = function_body(path, "void xdev_ext_mech_stage_dead(")
        self.assertLess(dead.index("xdev_ext_mech_session_stop(st->s,"),
                        dead.index("st->cls->mark_dead(st);"))

    def test_generations_are_pinned_once_per_session(self):
        sources = {p.name: p.read_text(encoding="utf-8")
                   for p in mech_sources()}
        for name, text in sources.items():
            self.assertNotIn("bpf_struct_ops_get", text, name)
        self.assertEqual(sources["xdev_ext_mech_ops.c"].count("xdev_ext_ops_pin("), 1)
        self.assertEqual(sources["xdev_ext_mech.c"].count("xdev_ext_mech_ops_get("), 1)
        path = ROOT / "io_uring/xdev_ext_mech.c"
        bind = function_body(path, "static int xdev_ext_mech_session_bind(")
        self.assertIn("xdev_ext_mech_ops_get(st->class_id,", bind)
        call = function_body(path, "int xdev_ext_mech_call(")
        self.assertIn("xdev_ext_mech_invoke(s->ops[st->class_id], &t, a, ret, "
                      "hold);", call)
        unreg = function_body(ROOT / "io_uring/xdev_ext_mech_ops.c",
                              "static void xdev_ext_mech_unreg(")
        self.assertLess(unreg.index("xdev_ext_ops_retract("),
                        unreg.index("xdev_ext_mech_generation_gone(class_id, "
                                    "kdata);"))
        gone = function_body(path, "void xdev_ext_mech_generation_gone(")
        self.assertIn("xdev_ext_mech_session_stop(s, -ECANCELED);", gone)

    def test_c_reference_ops_hold_their_module(self):
        # CONFIG_XDEV_EXT_MECH_C_REFERENCE: a session (or one call) on the C
        # table keeps the table's module loaded until it lets go, and
        # clearing or replacing the table stops the sessions still on it,
        # like a retracted struct_ops generation (plan section 2.6).
        header = HEADER.read_text(encoding="utf-8")
        self.assertRegex(
            header,
            r"int __xdev_ext_mech_set_c_ops\(u32 class_id, "
            r"const struct xdev_ext_mech_c_ops \*ops,\s+struct module \*owner\);")
        self.assertRegex(
            header,
            r"#define xdev_ext_mech_set_c_ops\(class_id, ops\)\s*\\\s*"
            r"__xdev_ext_mech_set_c_ops\(class_id, ops, THIS_MODULE\)")
        ops_c = ROOT / "io_uring/xdev_ext_mech_ops.c"
        get = function_body(ops_c, "const void *xdev_ext_mech_ops_get(")
        self.assertIn("rcu_read_lock();", get)
        self.assertIn("smp_load_acquire(&xdev_ext_mech_c_table[class_id]);", get)
        self.assertIn("try_module_get(mod)", get)
        self.assertLess(get.index("try_module_get(mod)"),
                        get.index("rcu_read_unlock();"))
        # A table whose module is going fails closed, never falls to BPF.
        self.assertLess(get.index("if (c_set)\n\t\treturn ops;"),
                        get.index("xdev_ext_ops_pin("))
        put = function_body(ops_c, "void xdev_ext_mech_ops_put(")
        self.assertIn("module_put(owner);", put)
        current = function_body(ops_c, "bool xdev_ext_mech_ops_current(")
        self.assertNotIn("!pinned ||", current)
        self.assertIn("READ_ONCE(xdev_ext_mech_c_table[class_id]) == ops", current)
        cset = function_body(ops_c, "int __xdev_ext_mech_set_c_ops(")
        order = [cset.index(step) for step in (
            "mutex_lock(&xdev_ext_mech_class_lock);",
            "WRITE_ONCE(xdev_ext_mech_c_table[class_id], NULL);",
            "synchronize_rcu();",
            "WRITE_ONCE(xdev_ext_mech_c_owner[class_id], ops ? owner : NULL);",
            "smp_store_release(&xdev_ext_mech_c_table[class_id], ops);")]
        order += [cset.rindex("mutex_unlock(&xdev_ext_mech_class_lock);"),
                  cset.index("xdev_ext_mech_generation_gone(class_id, old);")]
        self.assertEqual(order, sorted(order))
        self.assertIn("EXPORT_SYMBOL_GPL(__xdev_ext_mech_set_c_ops);",
                      ops_c.read_text(encoding="utf-8"))
        active = function_body(ops_c, "int xdev_ext_mech_call_active(")
        self.assertIn("xdev_ext_mech_ops_get(class_id, &pinned, &owner);", active)
        self.assertIn("xdev_ext_mech_ops_put(ops, pinned, owner);", active)
        path = ROOT / "io_uring/xdev_ext_mech.c"
        bind = function_body(path, "static int xdev_ext_mech_session_bind(")
        self.assertIn("&s->c_owner[st->class_id]", bind)
        release = function_body(path, "static int xdev_ext_mech_session_release(")
        self.assertIn("xdev_ext_mech_ops_put(s->ops[i], s->pinned[i], "
                      "s->c_owner[i]);", release)
        # Sessions on a C table are stopped too, not only pinned ones.
        gone = function_body(path, "void xdev_ext_mech_generation_gone(")
        self.assertNotIn("s->pinned[class_id]", gone)

    def test_create_admits_nothing_until_bound(self):
        path = ROOT / "io_uring/xdev_ext_mech.c"
        create = function_body(path, "static int xdev_ext_mech_create(")
        ready = create.index("if (!xdev_ext_mech_ready())\n\t\treturn -EOPNOTSUPP;")
        self.assertLess(ready, create.index("kzalloc("))
        self.assertNotIn("s->ss.state = XDEV_EXT_MECH_SESSION_ACTIVE;", create)
        # A stage that died while CREATE was binding (state NONE) left its
        # stop recorded: activation fails, CREATE returns the stop reason
        # and releases, before the session is listed anywhere.
        order = [create.index(step) for step in (
            "xdev_ext_mech_session_bind(s, &c);",
            "spin_lock_irqsave(&s->lock, flags);",
            "ret = xdev_ext_mech_sess_activate(&s->ss);",
            "spin_unlock_irqrestore(&s->lock, flags);",
            "ret = xdev_ext_mech_stop_reason(s);",
            "list_add_tail_rcu(&s->ring_node, &ctx->xdev_ext_mech_sessions);")]
        self.assertEqual(order, sorted(order))
        refused = create[create.index("ret = xdev_ext_mech_stop_reason(s);"):
                         create.index("list_add_tail_rcu(&s->ring_node,")]
        self.assertIn("xdev_ext_mech_session_release(s);\n\t\treturn ret;",
                      refused)
        init = function_body(path, "static void xdev_ext_mech_session_init(")
        self.assertIn("s->ss.state = XDEV_EXT_MECH_SESSION_NONE;", init)
        # The reason of a stop is recorded whenever xdev_ext_mech_sess_stop()
        # takes it, NONE included (include/linux/xdev_ext_mech.h: stage_dead
        # "records @err, stops admission").
        stop = function_body(path, "static void xdev_ext_mech_session_stop(")
        taken = stop.index("xdev_ext_mech_sess_stop(&s->ss);")
        self.assertLess(taken, stop.index("WRITE_ONCE(s->stop_err, err);"))
        self.assertLess(stop.index("WRITE_ONCE(s->stop_err, err);"),
                        stop.index("xdev_ext_mech_settle_locked(s);"))
        self.assertNotIn("XDEV_EXT_MECH_SESSION_ACTIVE", stop)

    def test_quarantine_never_gives_references_back(self):
        path = ROOT / "io_uring/xdev_ext_mech.c"
        text = path.read_text(encoding="utf-8")
        park = function_body(path, "static void xdev_ext_mech_quarantine(")
        for word in ("fput", "module_put", "_put(", "->release", "->unbind",
                     "kfree", "kvfree", "list_del"):
            self.assertNotIn(word, park, word)
        self.assertIn("list_add_tail(&s->quarantine_node, "
                      "&xdev_ext_mech_quarantined);", park)
        # Nothing ever takes a session off the quarantine list.
        self.assertEqual(text.count("quarantine_node"), 2)
        destroy = function_body(path, "static int xdev_ext_mech_session_destroy(")
        self.assertIn("if (fate != XDEV_EXT_MECH_REFS_RELEASE || !last) {",
                      destroy)
        # A quarantined session's worker goes only after its last batch,
        # after its armed timers (retry, progress and stage polling); a
        # deferred STOP decides its fate there.
        reap = function_body(path, "static void xdev_ext_mech_reap(")
        self.assertEqual(re.findall(r"^\s*(\w+)\(", reap, re.M),
                         ["xdev_ext_mech_release_late",
                          "kthread_cancel_delayed_work_sync",
                          "kthread_cancel_delayed_work_sync",
                          "kthread_cancel_delayed_work_sync",
                          "synchronize_rcu", "kthread_destroy_worker"])
        self.assertIn("kthread_cancel_delayed_work_sync(&s->poll_work);", reap)
        self.assertIn("kthread_destroy_worker(s->worker);", reap)

    def test_batch_areas_are_u64_aligned(self):
        # Private areas and stable cookies each sit back to back in their
        # allocation; both need u64 alignment regardless of class sizes.
        path = ROOT / "io_uring/xdev_ext_mech.c"
        bufs = function_body(path, "static int xdev_ext_mech_session_buffers(")
        align = bufs.index("priv = ALIGN(priv, sizeof(u64));")
        self.assertLess(align, bufs.index("kvcalloc(s->depth * (XDEV_EXT_MECH_MAX_STAGES + 1), priv,"))
        self.assertLess(align, bufs.index("s->priv_size = priv;"))
        cookie_align = bufs.index("cookie = ALIGN(cookie, sizeof(u64));")
        # L11: each parent plus four preallocated stage branches needs its own area.
        self.assertLess(cookie_align, bufs.index("kvcalloc(s->depth * (XDEV_EXT_MECH_MAX_STAGES + 1), cookie,"))
        self.assertIn("s->fan_batches", bufs)

    def test_stats_from_any_ring_while_the_session_exists(self):
        # xdev_ext_mech_ctl reads STATS through a fresh ring after the owning
        # ring is gone: a session stays readable from CREATE until it is
        # freed (draining and ZOMBIE included), then -ENOENT.  Only its
        # creator's user can read it from another ring.
        path = ROOT / "io_uring/xdev_ext_mech.c"
        text = path.read_text(encoding="utf-8")
        stats = function_body(path, "static int xdev_ext_mech_stats(")
        own = stats.index("xdev_ext_mech_find(ctx, id)")
        live = stats.index("mutex_lock(&xdev_ext_mech_live_lock);")
        self.assertLess(own, live)
        self.assertLess(live, stats.index("xdev_ext_mech_find_live(id)"))
        self.assertLess(stats.index("xdev_ext_mech_stats_fill(s, &out);", live),
                        stats.index("mutex_unlock(&xdev_ext_mech_live_lock);"))
        self.assertIn("return -ENOENT;", stats)
        find = function_body(path, "static struct xdev_ext_mech_session "
                                   "*xdev_ext_mech_find_live(")
        self.assertIn("uid_eq(s->uid, current_euid())", find)
        create = function_body(path, "static int xdev_ext_mech_create(")
        self.assertLess(create.index("ret = xdev_ext_mech_sess_activate(&s->ss);"),
                        create.index("list_add_tail(&s->live_node, "
                                     "&xdev_ext_mech_live);"))
        release = function_body(path, "static int xdev_ext_mech_session_release(")
        gone = release.index("list_del_init(&s->live_node);")
        self.assertLess(gone, release.index("kthread_destroy_worker(s->worker);"))
        self.assertLess(gone, release.index("kfree(s);"))
        # A quarantined session is never released, so it stays readable.
        self.assertEqual(text.count("list_del_init(&s->live_node);"), 1)
        park = function_body(path, "static void xdev_ext_mech_quarantine(")
        self.assertNotIn("live_node", park)

    def test_register_and_ring_wiring(self):
        reg = (ROOT / "io_uring/register.c").read_text(encoding="utf-8")
        case = reg[reg.index("case IORING_REGISTER_XDEV_EXT_MECH:"):]
        case = case[:case.index("break;", case.index("io_xdev_ext_mech_register"))]
        self.assertIn("if (!arg || nr_args != 1)", case)
        self.assertIn("ret = io_xdev_ext_mech_register(ctx, arg, nr_args);", case)
        types = (ROOT / "include/linux/io_uring_types.h").read_text(
            encoding="utf-8")
        self.assertRegex(types, r"struct list_head\s+xdev_ext_mech_sessions;")
        alloc = function_body(
            ROOT / "io_uring/io_uring.c",
            "static __cold struct io_ring_ctx *io_ring_ctx_alloc(")
        self.assertIn("INIT_LIST_HEAD(&ctx->xdev_ext_mech_sessions);", alloc)
        make = (ROOT / "io_uring/Makefile").read_text(encoding="utf-8")
        self.assertIn("obj-$(CONFIG_XDEV_EXT_MECH) += xdev_ext_mech.o xdev_ext_mech_ops.o",
                      make)

    def test_contract_asserts_stay_in_the_core(self):
        text = (ROOT / "io_uring/xdev_ext_mech.c").read_text(encoding="utf-8")
        for line in (
                "static_assert(XDEV_EXT_MECH_NVME_STATUS_DNR == NVME_STATUS_DNR);",
                "static_assert(XDEV_EXT_MECH_NVME_SCT_SC_MASK == NVME_SCT_SC_MASK);",
                "static_assert(sizeof(struct xdp_desc) == 16);",
                "static_assert(sizeof(struct nvme_command) == "
                "XDEV_EXT_NVME_MECH_DESC_SIZE);",
                "static_assert(offsetof(struct xdev_ext_mech_call, ctx) == 0);",
                "typeof(&crc32c), xdev_ext_mech_crc32c_fn"):
            self.assertIn(line, text)

    def test_header_only_declares(self):
        text = kernel_part(HEADER.read_text(encoding="utf-8"))
        # Only trivial static inlines are defined here; the core goes in
        # io_uring/xdev_ext_mech.c.
        for body in re.findall(r"static inline [^;]*?\n{(.*?)\n}", text, re.S):
            self.assertLessEqual(body.count(";"), 8, body)


if __name__ == "__main__":
    unittest.main()

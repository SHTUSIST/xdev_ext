#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Source-order checks for the XDEV_EXT NVMe passthrough admission contracts."""

from pathlib import Path
import os
import re
import sys
import runpy
_CANONICAL = next(p for p in Path(__file__).resolve().parents if (p / "source-layout.json").is_file())
_HELPERS = runpy.run_path(str(_CANONICAL / "tests/integration/peer_graph/nvme_peer_async_test.py"))

def read_native(root, name):
    return _HELPERS["read_native"](root, name)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for offset in range(brace, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : offset]
    raise AssertionError(f"unterminated function: {signature}")


def in_order(body: str, *needles: str) -> bool:
    positions = []
    for needle in needles:
        if needle not in body:
            raise AssertionError(f"missing {needle!r}")
        positions.append(body.index(needle))
    return positions == sorted(positions)


def check_fixed_vector(source: str) -> str:
    body = function_body(source, "static int nvme_uring_cmd_io(")

    require("if (xdev_ext && vec)\n\t\t\treturn -EOPNOTSUPP;" not in body,
            "XDEV_EXT vectors are still rejected unconditionally")
    require("io_uring_cmd_import_fixed_vec" in body,
            "fixed-vector import is missing")
    require("iov_iter_count" in body,
            "effective vector byte length is not taken from the imported iterator")
    require("nvme_xdev_ext_effective_data_len" in body,
            "effective vector length is not validated")
    require("nvme_xdev_ext_capabilities_vec" in source,
            "vector dispatch does not advertise multibuffer capability")

    fixed_guard = body.index("IORING_URING_CMD_FIXED")
    import_vec = body.index("io_uring_cmd_import_fixed_vec")
    effective_len = body.index("nvme_xdev_ext_effective_data_len")
    initial_admit = body.index("nvme_xdev_ext_initial_admit")
    alloc_request = body.index("nvme_alloc_user_request")
    map_request = body.index("nvme_map_user_request")
    dispatch = body.index("nvme_xdev_ext_dispatch_admitted")
    final_admit = body.index("nvme_xdev_ext_final_admit")
    require(fixed_guard < import_vec,
            "XDEV_EXT vector import is not gated by IORING_URING_CMD_FIXED")
    require("io_uring_cmd_issue_blocking" not in body,
            "XDEV_EXT submission is requeued before the native IOPOLL request exists")
    # Allocation and mapping can return -EAGAIN under IO_URING_F_NONBLOCK
    # (no tag, or a bvec layout that would need a split).  They run before
    # the policy dispatch so io_uring may retry them from io-wq without
    # replaying policy; nothing after the dispatch returns -EAGAIN.
    require(import_vec < effective_len < initial_admit < alloc_request <
            map_request < dispatch < final_admit,
            "fixed-vector snapshot/admission/map/dispatch order is unsafe")
    require("if (!xdev_ext_sidecar->vector_imported)" in body and
            "xdev_ext_sidecar->vector_iter" in body,
            "fixed-vector retry can re-import mutable userspace iovecs")
    require("nvme_xdev_ext_issue_errno(&xdev_ext_sidecar->resources, ret)" in body,
            "a post-dispatch -EAGAIN can replay policy")
    require("if (xdev_ext && ret == -EAGAIN)" not in body,
            "a pre-dispatch -EAGAIN must stay retryable")

    completion = function_body(source, "static void nvme_uring_task_cb(")
    put_case = completion.split("case NVME_XDEV_EXT_CLEANUP_PUT_TOKEN:", 1)[1]
    put_case = put_case.split("break;", 1)[0]
    require("xdev_ext_binding_token_put" in put_case,
            "completion no longer releases the retained policy token")
    require("nvme_xdev_ext_policy_errors" not in put_case,
            "a successful token release is incorrectly counted as a policy error")
    return "XDEV_EXT fixed-vector snapshot and DMA mapping precede policy"


def check_build_order(source: str) -> str:
    """NVME_URING_CMD_F_XDEV_EXT_BUILD: plan section 2.5.1 (N1) and N2."""
    body = function_body(source, "static int nvme_uring_cmd_io(")

    require("nvme_xdev_ext_build_requested(xdev_ext_flags)" in body,
            "F_XDEV_EXT_BUILD is not decoded from rsvd2")
    # Stage lookup and identity-only admission come before any allocation;
    # the program builds only after the data is mapped; the command that
    # executes is re-decoded and finally admitted before execution.
    require(in_order(body, "nvme_xdev_ext_build_stage(ioucmd",
                     "nvme_xdev_ext_initial_admit(", "nvme_alloc_user_request(",
                     "nvme_map_user_request(", "nvme_xdev_ext_build(ioucmd",
                     "nvme_xdev_ext_final_admit(", "blk_execute_rq_nowait("),
            "F_XDEV_EXT_BUILD identity/alloc/map/build/final-admit/execute order")
    build_call = body.index("nvme_xdev_ext_build(ioucmd")
    branch = body[body.rindex("if (", 0, build_call):]
    require(branch.startswith("if (xdev_ext_build)") and
            "else\n\t\t\tret = nvme_xdev_ext_dispatch_admitted(" in branch,
            "a built command must not also run the frozen policy dispatch")
    final = body[body.index("nvme_xdev_ext_final_admit("):]
    require(final.index("nvme_req(req)->cmd") < final.index(";"),
            "final admission of a built command must read the request command")

    initial = function_body(source, "static int nvme_xdev_ext_initial_admit(")
    require(in_order(initial, "if (build)", "nvme_xdev_ext_build_user_check(",
                     "nvme_xdev_ext_admit_identity(", "nvme_xdev_ext_admit("),
            "a built command must get identity-only initial admission")

    stage = function_body(source, "static int nvme_xdev_ext_build_stage(")
    require("xdev_ext_mech_stage_get_cmd(ioucmd, XDEV_EXT_MECH_CLASS_NVME)" in stage,
            "the stage is not looked up through the mechanism core")
    require("XDEV_EXT_MECH_DIR_TO_DEVICE" in stage,
            "the stage direction is not matched against the command")

    # The CONFIG_XDEV_EXT_MECH definition, not the stub that follows it.
    build = function_body(source, "\nnvme_xdev_ext_build(struct io_uring_cmd")
    require(in_order(build, "nvme_xdev_ext_lifecycle_prepare(",
                     "xdev_ext_mech_call(st, &a, &prog, NULL)",
                     "xdev_ext_mech_ret_resolve(", "xdev_ext_mech_slots_used(",
                     "nvme_xdev_ext_build_errno(", "nvme_xdev_ext_mech_validate(",
                     "c->common.cdw10 =", "rq_cmd->common.cdw10 =",
                     "nvme_xdev_ext_build_redecode("),
            "build -> validate -> write -> re-decode order")
    for needle in ("XDEV_EXT_MECH_MEMBER_BUILD", "XDEV_EXT_MECH_SITE_URING_CMD",
                   ".desc_cap = 1", ".window_slba = info.window_slba",
                   ".window_nlb = info.window_nlb",
                   "XDEV_EXT_MECH_CNT_REJECTS"):
        require(needle in build, f"build is missing {needle}")
    require(in_order(build, "nvme_xdev_ext_mech_fill_info(st, NULL, &info)",
                     ".window_slba = info.window_slba", ".window_nlb = info.window_nlb",
                     "nvme_xdev_ext_mech_validate(sqe, &bounds, &validated)"),
            "build bounds must follow the immutable bound-window information")
    for needle in (".capacity_lbas = info.capacity_lbas", ".lba_shift = info.lba_shift"):
        require(needle in build, f"build is missing bound geometry {needle}")
    require("dispatch" not in build, "build must not run the policy dispatch")

    complete = function_body(source, "static void nvme_xdev_ext_build_complete(")
    require(in_order(complete, "nvme_xdev_ext_mech_cqe(pdu->status, pdu->result",
                     "XDEV_EXT_MECH_MEMBER_COMPLETE", "xdev_ext_mech_call(",
                     "xdev_ext_mech_ret_resolve("),
            "N2 completion copy and complete callback")
    require("XDEV_EXT_MECH_SITE_URING_CMD" in complete,
            "N2 runs at the uring_cmd callsite")
    require("normalize" not in complete,
            "N2 must hand the native status over unfolded")

    task = function_body(source, "static void nvme_uring_task_cb(")
    policy_case = task.split("case NVME_XDEV_EXT_CLEANUP_COMPLETE_POLICY:", 1)[1]
    policy_case = policy_case.split("break;", 1)[0]
    require(in_order(policy_case, "sidecar->mech_stage",
                     "nvme_xdev_ext_build_complete(", "nvme_xdev_ext_complete("),
            "a built command must complete through the program")
    done_case = task.split("case NVME_XDEV_EXT_CLEANUP_DONE:", 1)[1]
    require(in_order(done_case, "nvme_xdev_ext_build_put(sidecar)",
                     "io_uring_cmd_done("),
            "the stage reference is not dropped on completion")

    unwind = function_body(source, "static void nvme_xdev_ext_preaccept_unwind(")
    require("nvme_xdev_ext_build_put(sidecar)" in unwind,
            "the stage reference is not dropped on unwind")
    return "F_XDEV_EXT_BUILD identity admission, map, build, validate, final admit"


# Block-layer calls the NVMe class may make: all exported (or inline), so
# nvme-core still links as a module.  bio_iov_bvec_set() is not exported and
# blk_rq_map_user*() would bounce instead of failing closed.
CLASS_BLOCK_CALLS = {
    "bio_add_page", "bio_init", "bio_kmalloc", "bio_uninit",
    "blk_execute_rq_nowait", "blk_lim_dma_alignment_and_pad",
    "blk_mq_alloc_request", "blk_mq_free_request", "blk_rq_append_bio",
    "blk_status_to_errno", "blk_rq_bytes",
    # Stage polling (XDEV_EXT_MECH_STAGE_F_POLL): both exported by block/blk-mq.c.
    "blk_rq_is_poll", "blk_mq_poll_hw_queue",
}


def check_mech_class(source: str, root: Path) -> str:
    """The NVMe class of the mechanism layer: plan 2.5 W-NVME, 2.6, CHK.8."""
    host = root / "drivers/nvme/host"
    makefile = read_native(root, "drivers/nvme/host/Makefile")
    require(re.search(r"^nvme-core-\$\(CONFIG_XDEV_EXT_MECH\)\s*\+= xdev_ext_mech_nvme\.o$",
                      makefile, re.M) is not None,
            "xdev_ext_mech_nvme.o is not part of nvme-core under CONFIG_XDEV_EXT_MECH")
    core = read_native(root, "drivers/nvme/host/core.c")
    require(in_order(function_body(core, "static int __init nvme_core_init("),
                     "nvme_init_auth()", "nvme_xdev_ext_mech_init();", "return 0;"),
            "the class is not registered from nvme-core init")
    exit_body = function_body(core, "static void __exit nvme_core_exit(")
    require(exit_body.lstrip().startswith("nvme_xdev_ext_mech_exit();"),
            "the class is not unregistered first at nvme-core exit")
    if "\nint nvme_xdev_ext_capture_identity(" in source:
        require("static int nvme_xdev_ext_capture_identity(" not in source and
                "\nint nvme_xdev_ext_capture_identity(" in source,
                "nvme_xdev_ext_capture_identity is not shared inside nvme-core")
    else:
        nvme_header = read_native(root, "drivers/nvme/host/nvme.h")
        require(nvme_header.count("static inline int nvme_xdev_ext_capture_identity(") == 1 and
                "nvme_xdev_ext_capture_identity(" in source and
                '#include "nvme.h"' in source,
                "native identity capture must have one shared nvme.h definition and a real ioctl consumer")

    build = function_body(source, "\nnvme_xdev_ext_build(struct io_uring_cmd")
    require(in_order(build, "nvme_xdev_ext_mech_stage_matches(st, ns, id)",
                     "nvme_xdev_ext_mech_fill_info(st, NULL, &info)",
                     "xdev_ext_mech_call("),
            "a built uring_cmd must match the bound namespace before the program")
    complete = function_body(source, "static void nvme_xdev_ext_build_complete(")
    require("nvme_xdev_ext_mech_fill_info(st, NULL, &info)" in complete,
            "the completion callback gets no class information")

    mech = read_native(root, "drivers/nvme/host/xdev_ext_mech_nvme.c")
    for needle in (".class_id = XDEV_EXT_MECH_CLASS_NVME",
                   ".desc_size = NVME_XDEV_EXT_SQE_SIZE", ".desc_cap = 1",
                   ".info_size = sizeof(struct xdev_ext_nvme_mech_info)",
                   ".cqe_size = sizeof(struct xdev_ext_nvme_mech_cqe)",
                   ".owner = THIS_MODULE", ".bind = ", ".unbind = ",
                   ".fill_info = ", ".validate = ", ".submit = ",
                   ".fill_cqe = ", ".mark_dead = "):
        require(needle in mech, f"class ops miss {needle}")
    require("xdev_ext_mech_class_register(&nvme_xdev_ext_mech_class)" in mech and
            "xdev_ext_mech_class_unregister(&nvme_xdev_ext_mech_class)" in mech,
            "class registration is missing")

    family = "struct xdev_ext_stor_stage family;" in mech
    if family:
        runtime_block = read_native(root, "io_uring/family/xdev_ext_storfam_block.c")
        block_header = read_native(root, "include/linux/xdev_ext_storfam_block.h")
        adapter_bind = function_body(mech, "static int nvme_xdev_ext_class_bind(")
        native_bind = function_body(mech, "static int nvme_xdev_ext_member_bind(")
        common_bind = function_body(runtime_block, "int xdev_ext_storfam_bind(")
        identity = function_body(mech, "static int nvme_xdev_ext_member_identity(")
        require(in_order(native_bind, "FMODE_WRITE", "nvme_xdev_ext_mech_cmd_allowed(", "kzalloc("),
                "native fd/effects authorization must precede member allocation")
        require(in_order(adapter_bind, "xdev_ext_storfam_bind(st, u, &nvme_xdev_ext_member_ops)",
                         "if (ret)", "nvme_xdev_ext_class_resources_init(st)"),
                "class resources must follow successful common bind")
        require(in_order(common_bind, "dev->bind(st, u, &ss, &member)",
                         "dev->identity(member, false, &ss->geometry)", "xdev_ext_stor_window_bind(",
                         "dev->unbind(member)", "st->priv = member") and
                in_order(common_bind[common_bind.index("ret = dev->identity"):], "xdev_ext_stor_window_bind(",
                         "if (ret)", "dev->unbind(member)", "return ret;", "st->priv = member"),
                "identity/window admission must unwind before publication and resources")
        require(in_order(identity, "if (!final)", "nvme_xdev_ext_capture_identity(p->ns, &p->identity",
                         "nvme_xdev_ext_mech_bind_identity(&p->identity, p->write,"),
                "CREATE identity capture and native bind authority must precede common window construction")
        require("struct xdev_ext_stor_stage family;" in mech and
                "struct xdev_ext_stor_window window;" in block_header,
                "native stage must retain its typed immutable window through the embedded family stage")
        require(in_order(common_bind, "ss->geometry.capacity_lbas, ss->geometry.lba_shift",
                         "st->arg0, st->arg1", "xdev_ext_mech_session_layout(st->s)->group_bytes"),
                "common bind must construct typed window from identity geometry and both stage bounds")
        info = function_body(mech, "void nvme_xdev_ext_mech_fill_info(")
        for field, bound in (("window_slba", "slba"), ("window_nlb", "nlb"),
                             ("capacity_lbas", "capacity_lbas"), ("lba_shift", "lba_shift")):
            require(f"info->{field} = p->family.window.{bound};" in info,
                    f"class information must export typed window {bound}")
        validate = function_body(mech, "static int nvme_xdev_ext_class_validate(")
        common_validate = function_body(runtime_block, "int xdev_ext_storfam_validate(")
        decode = function_body(mech, "static int nvme_xdev_ext_member_decode(")
        require("xdev_ext_storfam_validate(&p->family, b, &bp->family, scratch, n)" in validate and
                in_order(common_validate, "sb->validated = false", "if (nr_slots != 1)",
                         "ss->dev->decode(", "sb->validated = true") and
                "nvme_xdev_ext_mech_validate(scratch, &bounds, &decoded)" in decode,
                "exactly one slot must consume the actual native schema/window decode before validation publishes")
        submit = function_body(mech, "static int nvme_xdev_ext_class_submit(")
        submit_check = function_body(runtime_block, "int xdev_ext_storfam_submit_check(")
        require(in_order(submit, "xdev_ext_storfam_submit_check(&p->family, b, &bp->family)",
                         "blk_mq_alloc_request(", "nvme_init_request(", "nvme_xdev_ext_class_map(",
                         "req->end_io = ", "req->end_io_data = done;", "blk_execute_rq_nowait(req, false);"),
                "submit: common recheck, request, bio, end_io, then execute")
        require(in_order(submit_check, "atomic_read(&ss->dead)", "!sb->validated",
                         "sb->batch_id != xdev_ext_mech_batch_id(batch)",
                         "ss->dev->identity(ss->member, true, &ss->geometry)"),
                "worker gate must preserve dead, validation/batch identity and native final identity order")
        tail = submit.split("blk_execute_rq_nowait(req, false);", 1)[1]
        require(tail.strip() == "return 0;", "nothing may touch the batch after blk_execute_rq_nowait()")
        require(in_order(identity, "nvme_xdev_ext_capture_identity(p->ns, &id", "head != p->head",
                         "disk != p->disk", "queue != p->queue", "nvme_xdev_ext_identity_equal(",
                         "xdev_ext_mech_stage_dead(p->family.st, ret)"),
                "worker native identity hook must retain pointer/value recheck and stage-dead error path")
        table = mech[mech.index("static const struct xdev_ext_stor_dev_ops nvme_xdev_ext_member_ops ="):]
        table = table[:table.index("};")]
        for hook in ("bind", "unbind", "identity", "requester", "queue", "decode", "poll"):
            require(f".{hook} = nvme_xdev_ext_member_{hook}," in table,
                    f"common runtime must consume real native {hook} hook")
    else:
        bind = function_body(mech, "static int nvme_xdev_ext_class_bind(")
        require(in_order(bind, "FMODE_WRITE", "nvme_xdev_ext_mech_cmd_allowed(",
                         "nvme_xdev_ext_capture_identity(", "nvme_xdev_ext_mech_bind_window(",
                         "nvme_xdev_ext_class_resources_init(st)"),
                "bind: write access, passthrough permission, identity, window")
        require(re.search(r"struct nvme_xdev_ext_mech_stage\s*\{[^}]*"
                          r"struct xdev_ext_stor_window window;", mech, re.S) is not None,
                "stage must retain the typed immutable storage window")
        require(re.search(r"nvme_xdev_ext_mech_bind_window\(&p->identity,\s*write,\s*"
                          r"st->arg0,\s*st->arg1,\s*l->group_bytes,\s*&p->window\)", bind) is not None,
                "bind must construct the typed window from identity and both stage bounds")
        window_tail = bind[bind.index("nvme_xdev_ext_mech_bind_window("):bind.index("st->priv = p;")]
        require(in_order(window_tail, "&p->window)", "if (ret)", "kfree(p);", "return ret;"),
                "window admission failure must unwind before resources are initialized")
        info = function_body(mech, "void nvme_xdev_ext_mech_fill_info(")
        for field, bound in (("window_slba", "slba"), ("window_nlb", "nlb"),
                             ("capacity_lbas", "capacity_lbas"), ("lba_shift", "lba_shift")):
            require(f"info->{field} = p->window.{bound};" in info,
                    f"class information must export typed window {bound}")
        validate = function_body(mech, "static int nvme_xdev_ext_class_validate(")
        require(in_order(validate, "if (n != 1)", "nvme_xdev_ext_mech_validate(",
                         "bp->validated = true"),
                "validate: exactly one slot through nvme_xdev_ext_mech_validate")

        submit = function_body(mech, "static int nvme_xdev_ext_class_submit(")
        require(in_order(submit, "bp->validated", "nvme_xdev_ext_class_recheck(st)",
                         "blk_mq_alloc_request(", "nvme_init_request(",
                         "nvme_xdev_ext_class_map(", "req->end_io = ",
                         "req->end_io_data = done;",
                         "blk_execute_rq_nowait(req, false);"),
                "submit: recheck, request, bio, end_io, then execute")
        tail = submit.split("blk_execute_rq_nowait(req, false);", 1)[1]
        require(tail.strip() == "return 0;",
                "nothing may touch the batch after blk_execute_rq_nowait()")
        recheck = function_body(mech, "static int nvme_xdev_ext_class_recheck(")
        require(in_order(recheck, "nvme_xdev_ext_capture_identity(",
                         "nvme_xdev_ext_identity_equal(", "xdev_ext_mech_stage_dead(st, ret)"),
                "the worker does not recheck the namespace identity")

    mapping = function_body(mech, "static int nvme_xdev_ext_class_map(")
    if "xdev_ext_stor_block_preflight(" in mapping:
        block = read_native(root, "io_uring/family/xdev_ext_storfam_block.c")
        require(in_order(mapping, "xdev_ext_stor_block_caps(", "xdev_ext_stor_block_preflight(",
                         "bio = bp->slot->bio;", "bio_init(", "xdev_ext_stor_block_append(",
                         "if (ret != -EREMOTEIO)", "nvme_xdev_ext_class_bounce("),
                "map: actual common precheck/append, fixture-owned bio, fail closed before bounce")
        preflight = function_body(block, "int xdev_ext_stor_block_preflight(")
        require(in_order(preflight, "xdev_ext_stor_seg_walk_init(", "xdev_ext_stor_block_walk(",
                         "xdev_ext_stor_seg_done("), "common payload preflight must consume the segment validator")
        walk = function_body(block, "static int xdev_ext_stor_block_walk(")
        require(in_order(walk, "xdev_ext_mech_batch_frame(", "xdev_ext_mech_frame_page(",
                         "bio_add_page(", "xdev_ext_stor_seg_add("),
                "common bio append must build page by page from actual batch frames")
        append = function_body(block, "int xdev_ext_stor_block_append(")
        require(in_order(append, "xdev_ext_stor_block_walk(", "blk_rq_append_bio("),
                "common append must hand the actual frame bio to block")
    else:
        require(in_order(mapping, "nvme_xdev_ext_seg_walk_init(",
                         "nvme_xdev_ext_seg_done(", "bio = bp->slot->bio;", "bio_init(",
                         "blk_rq_append_bio(", "if (ret != -EREMOTEIO)",
                         "nvme_xdev_ext_class_bounce("),
                "map: precheck, bio from frames, fail closed before any bounce")
        walk = function_body(mech, "static int nvme_xdev_ext_class_walk(")
        require(in_order(walk, "xdev_ext_mech_batch_frame(", "xdev_ext_mech_frame_page(",
                         "bio_add_page(", "nvme_xdev_ext_seg_add("),
                "the bio is not built page by page from the batch frames")

    resources = function_body(mech, "static int nvme_xdev_ext_class_resources_init(")
    require(in_order(resources, "xdev_ext_mech_session_depth(", "kcalloc(", "bio_kmalloc("),
            "CREATE must bound private bio/completion leases by session depth")
    for hot in (submit, mapping):
        require("GFP_KERNEL" not in hot and "bio_kmalloc(" not in hot and
                "kmalloc(" not in hot,
                "the session hot path must not allocate bio/completion metadata")
    end_io = function_body(mech, "static enum rq_end_io_ret nvme_xdev_ext_class_end_io(")
    runtime = read_native(root, "io_uring/family/xdev_ext_storfam.c")
    handoff = function_body(runtime, "void xdev_ext_stor_done(")
    complete = function_body(mech, "static int nvme_xdev_ext_class_complete(")
    require("xdev_ext_stor_done(req->end_io_data, blk_status_to_errno(err), req," in end_io,
            "end_io must dispatch the native completion to the family")
    require(in_order(handoff, "xdev_ext_mech_batch_completion_claim(b, done->ticket)",
                     "status = complete(", "xdev_ext_mech_trace_native_complete(",
                     "ready(b, status", "xdev_ext_mech_batch_completion_publish("),
            "family completion must claim before CQE, trace, ready and publish")
    require(in_order(complete, "NVME_REQ_CANCELLED", "blk_rq_bytes(req)",
                     "nvme_xdev_ext_mech_cqe("),
            "member must preserve host status and residual classification under claim")
    require(end_io.rstrip().endswith("return RQ_END_IO_FREE;"),
            "the block layer must retain native request destruction")
    require("kfree(done)" not in end_io, "a preallocated completion lease was freed")
    require("xdev_ext_mech_call" not in end_io, "end_io must not run a program")
    fill_cqe = function_body(mech, "static void nvme_xdev_ext_class_fill_cqe(")
    require(in_order(fill_cqe, "nvme_xdev_ext_class_bounce_release(",
                     "nvme_xdev_ext_class_slot_put(", "memcpy(cqe"),
            "the worker does not consume its completion lease before advancing")
    put = function_body(mech, "nvme_xdev_ext_class_slot_put(")
    require(in_order(put, "slot->done.uncertain", "bio_uninit(", "xdev_ext_stor_slot_put("),
            "an uncertain native lease must never rejoin the pool")
    require("kfree(" not in fill_cqe, "the per-group path frees a shared pool bio")
    dead = function_body(mech, "static void nvme_xdev_ext_class_mark_dead(")
    for word in ("mutex", "wait", "sleep", "synchronize", "flush", "lock"):
        require(word not in dead, f"mark_dead must not block ({word})")

    calls = set(re.findall(r"\b((?:__)?(?:blk|bio)_\w+)\s*\(", mech))
    require(calls <= CLASS_BLOCK_CALLS,
            f"unexported or bouncing block calls: {sorted(calls - CLASS_BLOCK_CALLS)}")
    blk_mq = read_native(root, "block/blk-mq.c")
    for name in ("blk_rq_is_poll", "blk_mq_poll_hw_queue"):
        require(f"EXPORT_SYMBOL_GPL({name});" in blk_mq,
                f"nvme-core calls {name}, which block/blk-mq.c must export")

    bounce = mech.split("#ifdef CONFIG_XDEV_EXT_MECH_KVM_BOUNCE", 1)
    require(len(bounce) == 2 and "module_param_cb(xdev_ext_mech_bounces" in
            bounce[1].split("#endif", 1)[0] and
            "atomic64_inc(&nvme_xdev_ext_mech_bounces)" in bounce[1],
            "the KVM bounce fallback is not confined to its option or not counted")
    return "NVMe mechanism class: bind, validate, submit, end_io, teardown"


def main() -> int:
    candidates = []
    if os.environ.get("NVME_XDEV_EXT_SOURCE_ROOT"):
        candidates.append(Path(os.environ["NVME_XDEV_EXT_SOURCE_ROOT"]))
    candidates.extend([Path.cwd(), *Path.cwd().parents])
    candidates.extend(Path(__file__).resolve().parents)
    root = next(
        (candidate for candidate in candidates
         if (candidate / "drivers/nvme/host/ioctl.c").is_file() or (candidate / "source-layout.json").is_file()),
        None,
    )
    if root is None:
        print("ok 1 - source tree unavailable # SKIP")
        return 4
    source = read_native(root, "drivers/nvme/host/ioctl.c")

    checks = (check_fixed_vector, check_build_order,
              lambda text: check_mech_class(text, root))
    failed = 0
    for number, check in enumerate(checks, 1):
        try:
            print(f"ok {number} - {check(source)}")
        except (AssertionError, OSError, ValueError) as error:
            print(f"not ok {number} - {error}", file=sys.stderr)
            failed += 1
    print(f"1..{len(checks)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Source-order checks for the XDEV_EXT NVMe passthrough admission contracts."""

from pathlib import Path
import os
import re
import sys


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
                   ".desc_cap = 1", "st->arg0", "st->arg1",
                   "XDEV_EXT_MECH_CNT_REJECTS"):
        require(needle in build, f"build is missing {needle}")
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
    makefile = (host / "Makefile").read_text()
    require(re.search(r"^nvme-core-\$\(CONFIG_XDEV_EXT_MECH\)\s*\+= xdev_ext_mech_nvme\.o$",
                      makefile, re.M) is not None,
            "xdev_ext_mech_nvme.o is not part of nvme-core under CONFIG_XDEV_EXT_MECH")
    core = (host / "core.c").read_text()
    require(in_order(function_body(core, "static int __init nvme_core_init("),
                     "nvme_init_auth()", "nvme_xdev_ext_mech_init();", "return 0;"),
            "the class is not registered from nvme-core init")
    exit_body = function_body(core, "static void __exit nvme_core_exit(")
    require(exit_body.lstrip().startswith("nvme_xdev_ext_mech_exit();"),
            "the class is not unregistered first at nvme-core exit")
    require("static int nvme_xdev_ext_capture_identity(" not in source and
            "\nint nvme_xdev_ext_capture_identity(" in source,
            "nvme_xdev_ext_capture_identity is not shared inside nvme-core")

    build = function_body(source, "\nnvme_xdev_ext_build(struct io_uring_cmd")
    require(in_order(build, "nvme_xdev_ext_mech_stage_matches(st, ns, id)",
                     "nvme_xdev_ext_mech_fill_info(st, NULL, &info)",
                     "xdev_ext_mech_call("),
            "a built uring_cmd must match the bound namespace before the program")
    complete = function_body(source, "static void nvme_xdev_ext_build_complete(")
    require("nvme_xdev_ext_mech_fill_info(st, NULL, &info)" in complete,
            "the completion callback gets no class information")

    mech = (host / "xdev_ext_mech_nvme.c").read_text()
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

    bind = function_body(mech, "static int nvme_xdev_ext_class_bind(")
    require(in_order(bind, "FMODE_WRITE", "nvme_xdev_ext_mech_cmd_allowed(",
                     "nvme_xdev_ext_capture_identity(", "nvme_xdev_ext_mech_bind_check(",
                     "nvme_xdev_ext_class_resources_init(st)"),
            "bind: write access, passthrough permission, identity, window")
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
    require(in_order(end_io, "xdev_ext_mech_batch_completion_claim(b, ticket)",
                     "NVME_REQ_CANCELLED", "blk_rq_bytes(req)", "nvme_xdev_ext_mech_cqe(",
                     "xdev_ext_mech_batch_completion_publish(b, ticket, status, uncertain)"),
            "end_io must claim its native ticket before publishing status/uncertainty")
    require(end_io.rstrip().endswith("return RQ_END_IO_FREE;"),
            "the block layer must retain native request destruction")
    require("kfree(done)" not in end_io, "a preallocated completion lease was freed")
    require("xdev_ext_mech_call" not in end_io, "end_io must not run a program")
    fill_cqe = function_body(mech, "static void nvme_xdev_ext_class_fill_cqe(")
    require(in_order(fill_cqe, "nvme_xdev_ext_class_bounce_release(",
                     "nvme_xdev_ext_class_slot_put(", "memcpy(cqe"),
            "the worker does not consume its completion lease before advancing")
    put = function_body(mech, "nvme_xdev_ext_class_slot_put(")
    require(in_order(put, "slot->done.uncertain", "bio_uninit(", "slot->busy = false"),
            "an uncertain native lease must never rejoin the pool")
    require("kfree(" not in fill_cqe, "the per-group path frees a shared pool bio")
    dead = function_body(mech, "static void nvme_xdev_ext_class_mark_dead(")
    for word in ("mutex", "wait", "sleep", "synchronize", "flush", "lock"):
        require(word not in dead, f"mark_dead must not block ({word})")

    calls = set(re.findall(r"\b((?:__)?(?:blk|bio)_\w+)\s*\(", mech))
    require(calls <= CLASS_BLOCK_CALLS,
            f"unexported or bouncing block calls: {sorted(calls - CLASS_BLOCK_CALLS)}")
    blk_mq = (root / "block/blk-mq.c").read_text()
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
         if (candidate / "drivers/nvme/host/ioctl.c").is_file()),
        None,
    )
    if root is None:
        print("ok 1 - source tree unavailable # SKIP")
        return 4
    source = (root / "drivers/nvme/host/ioctl.c").read_text()

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

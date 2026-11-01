// SPDX-License-Identifier: GPL-2.0
/* Logical block lookup; binding authority stays in the C admission path. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "nvme_blocktable.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct blocktable_key);
    __type(value, struct blocktable_value);
} blocks SEC(".maps");

SEC("struct_ops/blocktable_build")
__s32 BPF_PROG(blocktable_build, const struct xdev_ext_mech_ctx *mctx)
{
    const struct xdev_ext_nvme_mech_info *info;
    struct blocktable_key key = { mctx->session_id, mctx->base.src_offset };
    const struct blocktable_value *entry;
    __u64 offset, bytes, relative_lba, nlb;
    __u32 shift;
    __u8 *sqe;

    (void)ctx;
    info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
    if (!info || mctx->base.direction != XDEV_EXT_MP_DIR_FROM_DEVICE)
        return XDEV_EXT_MP_BUILD_ABORT;
    entry = bpf_map_lookup_elem(&blocks, &key);
    if (!entry)
        return XDEV_EXT_MP_BUILD_ABORT;
    offset = entry->byte_offset;
    bytes = entry->byte_length;
    shift = info->lba_shift;
    if (entry->reserved || shift < 9 || shift > 31 || !bytes ||
        bytes != mctx->base.length || bytes != info->l.group_bytes ||
        ((offset | bytes) & ((1ULL << shift) - 1)))
        return XDEV_EXT_MP_BUILD_ABORT;
    relative_lba = offset >> shift;
    nlb = bytes >> shift;
    /* Subtractions keep both map arithmetic and window arithmetic bounded. */
    if (!info->window_nlb || info->window_slba >= info->capacity_lbas ||
        info->window_nlb > info->capacity_lbas - info->window_slba ||
        relative_lba >= info->window_nlb ||
        nlb > info->window_nlb - relative_lba ||
        nlb > info->max_nlb || nlb > XDEV_EXT_MP_NVME_MAX_NLB)
        return XDEV_EXT_MP_BUILD_ABORT;
    sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
    if (!sqe || xdev_ext_mp_nvme_rw(sqe, mctx->base.direction,
                                  info->window_slba + relative_lba,
                                  (__u32)bytes, shift))
        return XDEV_EXT_MP_BUILD_ABORT;
    return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/blocktable_complete")
__s32 BPF_PROG(blocktable_complete, const struct xdev_ext_mech_ctx *mctx)
{
    const struct xdev_ext_nvme_mech_cqe *cqe;

    (void)ctx;
    cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
    if (!cqe)
        return XDEV_EXT_MP_ABORT;
    return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops blocktable_ops = {
    .abi_version = XDEV_EXT_MP_ABI_VERSION,
    .build = (void *)blocktable_build,
    .complete = (void *)blocktable_complete,
};
char LICENSE[] SEC("license") = "GPL";

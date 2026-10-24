// SPDX-License-Identifier: GPL-2.0
/* Fixed READ geometry; only the actual request ID selects one of eight slots.
 * Full class validation and native ownership remain in the existing C path. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

SEC("struct_ops/mv_nvme_build")
__s32 BPF_PROG(mv_nvme_build, const struct xdev_ext_mech_ctx *mctx)
{
    const struct xdev_ext_nvme_mech_info *info;
    __u32 x, slot;
    __u64 slba;
    __u8 *sqe;

    (void)ctx;
    info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
    if (!info || info->window_slba != 2048 || info->window_nlb != 64 ||
        info->lba_shift != 9 || info->l.group_bytes != 4096 ||
        mctx->base.length != 4096 ||
        mctx->base.direction != XDEV_EXT_MP_DIR_FROM_DEVICE)
        return XDEV_EXT_MP_BUILD_ABORT;
    sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
    if (!sqe)
        return XDEV_EXT_MP_BUILD_ABORT;
    x = mctx->base.request_id & 7U;
    slot = x ^ (x >> 1);
    slba = info->window_slba + ((__u64)slot << 3);
    if (xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba, 4096, 9))
        return XDEV_EXT_MP_BUILD_ABORT;
    return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/mv_nvme_complete")
__s32 BPF_PROG(mv_nvme_complete, const struct xdev_ext_mech_ctx *mctx)
{
    const struct xdev_ext_nvme_mech_cqe *cqe;

    (void)ctx;
    cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
    if (!cqe)
        return XDEV_EXT_MP_ABORT;
    return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops mv_nvme_ops = {
    .abi_version = XDEV_EXT_MP_ABI_VERSION,
    .build = (void *)mv_nvme_build,
    .complete = (void *)mv_nvme_complete,
};
char LICENSE[] SEC("license") = "GPL";

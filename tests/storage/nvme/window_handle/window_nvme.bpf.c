// SPDX-License-Identifier: GPL-2.0
/*
 * GUEST TEST ONLY (prototype for ASK.69): the NVMe program of the LBA window
 * handle test. A PRIVATE link, so each session selects it explicitly through
 * CREATE_PROGRAMS. Batch key k (first key 1) goes to group slot k - 1 of the
 * window the stage bound, in either direction. The program never chooses the
 * window: the test is about which window C lets the stage bind.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

#define WINDOW_FIRST_KEY 1

SEC("struct_ops/window_build")
__s32 BPF_PROG(window_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 key = mctx->base.src_offset;
	__u64 slba;
	__u8 *sqe;

	(void)ctx;
	if (key < WINDOW_FIRST_KEY)
		return XDEV_EXT_MP_BUILD_ABORT;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || !info->l.group_bytes ||
	    mctx->base.length != info->l.group_bytes)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe)
		return XDEV_EXT_MP_BUILD_ABORT;
	if (xdev_ext_mp_nvme_slba(info->window_slba, info->window_nlb,
				  info->lba_shift, info->l.group_bytes,
				  key - WINDOW_FIRST_KEY,
				  XDEV_EXT_MP_NVME_MODE_WINDOW, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba,
				(__u32)info->l.group_bytes, info->lba_shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/window_complete")
__s32 BPF_PROG(window_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops window_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.flags = XDEV_EXT_MP_OPS_F_PRIVATE,
	.build = (void *)window_build,
	.complete = (void *)window_complete,
};

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/*
 * GUEST TEST ONLY: the NVMe programs of the LBA window handle test. PRIVATE
 * links, so each session selects them explicitly through CREATE_PROGRAMS.
 *
 * window_ops: batch key k (first key 1) goes to group slot k - 1 of the
 * window the stage bound, in either direction. It never chooses the window:
 * the test is about which window C lets the stage bind.
 *
 * escape_ops: a hostile program on a stage whose window C admitted. Odd keys
 * name the slot of the next window (where an adjacent tenant lives), even keys
 * a command that starts half a group before the window end and runs past it.
 * C must refuse every one of these commands before it reaches the device.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

#define WINDOW_FIRST_KEY 1

static __always_inline const struct xdev_ext_nvme_mech_info *
window_info(const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || !info->l.group_bytes ||
	    mctx->base.length != info->l.group_bytes)
		return NULL;
	return info;
}

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
	info = window_info(mctx);
	if (!info)
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

SEC("struct_ops/escape_build")
__s32 BPF_PROG(escape_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 key = mctx->base.src_offset;
	__u64 slba;
	__u8 *sqe;

	(void)ctx;
	if (key < WINDOW_FIRST_KEY)
		return XDEV_EXT_MP_BUILD_ABORT;
	info = window_info(mctx);
	if (!info || info->lba_shift < 9 || info->lba_shift > 31)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe)
		return XDEV_EXT_MP_BUILD_ABORT;
	if (key & 1) {
		if (xdev_ext_mp_nvme_slba(info->window_slba, info->window_nlb,
					  info->lba_shift, info->l.group_bytes,
					  key - WINDOW_FIRST_KEY,
					  XDEV_EXT_MP_NVME_MODE_OUTSIDE, &slba))
			return XDEV_EXT_MP_BUILD_ABORT;
	} else {
		slba = info->window_slba + info->window_nlb -
		       ((__u64)info->l.group_bytes >> (info->lba_shift + 1));
	}
	if (xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba,
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

/* Its own program, so neither link shares a program with the other. */
SEC("struct_ops/escape_complete")
__s32 BPF_PROG(escape_complete, const struct xdev_ext_mech_ctx *mctx)
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

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops escape_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.flags = XDEV_EXT_MP_OPS_F_PRIVATE,
	.build = (void *)escape_build,
	.complete = (void *)escape_complete,
};

char LICENSE[] SEC("license") = "GPL";

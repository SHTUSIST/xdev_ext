// SPDX-License-Identifier: GPL-2.0
/* Ordinary BLOCK RW; the C member retains device and LBA authority. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

SEC("struct_ops/block_rw_build")
__s32 BPF_PROG(block_rw_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_block_mech_info *info;
	__u64 bytes = mctx->base.length, nlb, slots, slba;
	__u32 shift, i;
	__u8 *desc;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || (mctx->base.direction != XDEV_EXT_MP_DIR_TO_DEVICE &&
		      mctx->base.direction != XDEV_EXT_MP_DIR_FROM_DEVICE))
		return XDEV_EXT_MP_BUILD_ABORT;
	shift = info->lba_shift;
	if (shift < 9 || shift > 31 || !bytes || bytes > 0xffffffffULL ||
	    bytes != info->l.group_bytes || (bytes & ((1ULL << shift) - 1)))
		return XDEV_EXT_MP_BUILD_ABORT;
	nlb = bytes >> shift;
	if (!nlb || nlb > 65536U || nlb > info->max_nlb ||
	    !info->window_nlb || info->window_slba >= info->capacity_lbas ||
	    info->window_nlb > info->capacity_lbas - info->window_slba ||
	    nlb > info->window_nlb)
		return XDEV_EXT_MP_BUILD_ABORT;
	slots = info->window_nlb / nlb;
	if (!slots)
		return XDEV_EXT_MP_BUILD_ABORT;
	slba = info->window_slba + (mctx->base.request_id % slots) * nlb;
	desc = bpf_xdev_ext_desc(mctx, 0, sizeof(struct xdev_ext_block_rw_desc));
	if (!desc)
		return XDEV_EXT_MP_BUILD_ABORT;
	__builtin_memset(desc, 0, sizeof(struct xdev_ext_block_rw_desc));
	desc[0] = mctx->base.direction == XDEV_EXT_MP_DIR_TO_DEVICE ? 1 : 0;
#pragma unroll
	for (i = 0; i < 8; i++)
		desc[8 + i] = (__u8)(slba >> (8 * i));
#pragma unroll
	for (i = 0; i < 4; i++)
		desc[16 + i] = (__u8)(nlb >> (8 * i));
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/block_rw_complete")
__s32 BPF_PROG(block_rw_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_block_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!cqe || cqe->err || cqe->blk_status || cqe->residual_bytes ||
	    cqe->submitted_bytes != mctx->base.length)
		return XDEV_EXT_MP_ABORT;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_block_mech_ops block_rw_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)block_rw_build,
	.complete = (void *)block_rw_complete,
};

char LICENSE[] SEC("license") = "GPL";

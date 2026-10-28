// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>

/*
 * MK3 arm E: the S1 NVMe build, SLBA picked from the batch id inside the
 * window.  bpf_testmod_xdev_ext_mech_c_build() in bpf_testmod.c is its C arm,
 * line for line; keep the two in step.
 */
SEC("struct_ops/build")
__s32 BPF_PROG(mk3_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	struct xdev_ext_mech_nvme_rw *sqe;
	__u64 nlb, slots;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return XDEV_EXT_MECH_BUILD_ABORT;
	nlb = mctx->base.length >> info->lba_shift;
	if (!nlb || nlb > info->window_nlb)
		return XDEV_EXT_MECH_BUILD_ABORT;
	slots = info->window_nlb / nlb;
	sqe = (void *)bpf_xdev_ext_desc(mctx, 0, sizeof(*sqe));
	if (!sqe)
		return XDEV_EXT_MECH_BUILD_ABORT;
	sqe->opcode = mctx->base.direction == XDEV_EXT_MECH_DIR_TO_DEVICE ?
		      XDEV_EXT_MECH_NVME_OP_WRITE : XDEV_EXT_MECH_NVME_OP_READ;
	sqe->slba = info->window_slba + mctx->batch_id % slots * nlb;
	sqe->length = nlb - 1;
	return XDEV_EXT_MECH_BUILD_SUBMIT;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(mk3_complete, const struct xdev_ext_mech_ctx *mctx)
{
	return XDEV_EXT_MECH_DONE;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops mk3_nvme_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)mk3_build,
	.complete = (void *)mk3_complete,
};

char _license[] SEC("license") = "GPL";

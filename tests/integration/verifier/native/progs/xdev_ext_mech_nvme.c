// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

/* NVMe positive program: every kfunc each member may call. */
enum xdev_ext_mech_nvme_mode {
	XDEV_EXT_MECH_NVME_IN_WINDOW,	/* SLBA picked from the batch id */
	XDEV_EXT_MECH_NVME_PAST_WINDOW,	/* SLBA one past the window */
	XDEV_EXT_MECH_NVME_RESERVED,		/* cdw13 set */
};

__u32 nvme_mode;
__u32 prepare_calls;
__u32 prepare_lba_shift;
__u32 prepare_tag_crc;
struct xdev_ext_mech_obs build_obs;
struct xdev_ext_mech_obs complete_obs;
__u64 complete_result;
__u32 complete_status;
__s32 complete_err;

SEC("struct_ops.s/prepare")
__s32 BPF_PROG(nvme_prepare, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u8 tag[8] = { 'u', 'b', 'r', '-', 'm', 'e', 'c', 'h' };

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return -EINVAL;
	prepare_calls++;
	prepare_lba_shift = info->lba_shift;
	prepare_tag_crc = bpf_xdev_ext_crc32c(tag, sizeof(tag), ~0U);
	return 0;
}

SEC("struct_ops/build")
__s32 BPF_PROG(nvme_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	struct xdev_ext_mech_nvme_rw *sqe;
	__u64 nlb, slots, slba;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || !mctx->nr_frames)
		return XDEV_EXT_MECH_BUILD_ABORT;
	nlb = mctx->base.length >> info->lba_shift;
	if (!nlb || nlb > info->window_nlb)
		return XDEV_EXT_MECH_BUILD_ABORT;
	slots = info->window_nlb / nlb;
	slba = info->window_slba + mctx->batch_id % slots * nlb;
	if (nvme_mode == XDEV_EXT_MECH_NVME_PAST_WINDOW)
		slba = info->window_slba + info->window_nlb;

	sqe = (void *)bpf_xdev_ext_desc(mctx, 0, sizeof(*sqe));
	if (!sqe)
		return XDEV_EXT_MECH_BUILD_ABORT;
	sqe->opcode = mctx->base.direction == XDEV_EXT_MECH_DIR_TO_DEVICE ?
		      XDEV_EXT_MECH_NVME_OP_WRITE : XDEV_EXT_MECH_NVME_OP_READ;
	sqe->slba = slba;
	sqe->length = nlb - 1;
	if (nvme_mode == XDEV_EXT_MECH_NVME_RESERVED)
		sqe->dsmgmt = 1;
	xdev_ext_mech_observe(mctx, &info->f[0], &build_obs);
	return XDEV_EXT_MECH_BUILD_SUBMIT;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(nvme_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	const struct xdev_ext_nvme_mech_cqe *cqe;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!info || !cqe)
		return XDEV_EXT_MECH_ABORT;
	complete_result = cqe->result;
	complete_status = cqe->status;
	complete_err = cqe->err;
	xdev_ext_mech_observe(mctx, &info->f[0], &complete_obs);
	return !cqe->status && !cqe->err ? XDEV_EXT_MECH_DONE : XDEV_EXT_MECH_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops nvme_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.prepare = (void *)nvme_prepare,
	.build = (void *)nvme_build,
	.complete = (void *)nvme_complete,
};

char _license[] SEC("license") = "GPL";

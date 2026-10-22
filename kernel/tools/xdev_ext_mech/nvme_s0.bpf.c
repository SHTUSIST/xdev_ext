// SPDX-License-Identifier: GPL-2.0
/*
 * S0: the NVMe mechanism program at the uring_cmd callsite.  For a
 * passthrough command marked NVME_URING_CMD_F_XDEV_EXT_BUILD it writes the
 * opcode, SLBA and NLB into the scratch SQE; C validates them, fills the
 * rest and submits.  mode 0 picks a slot of the session window from the
 * request id; modes 1 and 2 build what C must refuse.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

#define S0_MODE_RESERVED	2U	/* in-window SLBA, nonzero cdw2 */

/* 0: in-window; 1: past the window (XDEV_EXT_MP_NVME_MODE_OUTSIDE); 2: reserved. */
__u32 mode;

SEC("struct_ops/nvme_s0_build")
__s32 BPF_PROG(nvme_s0_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u32 where = mode == XDEV_EXT_MP_NVME_MODE_OUTSIDE ?
		      XDEV_EXT_MP_NVME_MODE_OUTSIDE : XDEV_EXT_MP_NVME_MODE_WINDOW;
	__u64 bytes = mctx->base.length;
	__u64 slba;
	__u8 *sqe;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx,
					  sizeof(struct xdev_ext_nvme_mech_info));
	if (!info)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe || bytes > 0xffffffffULL)
		return XDEV_EXT_MP_BUILD_ABORT;
	if (xdev_ext_mp_nvme_s0_slba(info->window_slba, info->window_nlb,
				info->lba_shift, (__u32)bytes,
				mctx->base.request_id, where, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba, (__u32)bytes,
			   info->lba_shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	if (mode == S0_MODE_RESERVED)
		xdev_ext_mp_nvme_set_reserved(sqe);
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/nvme_s0_complete")
__s32 BPF_PROG(nvme_s0_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0,
					sizeof(struct xdev_ext_nvme_mech_cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops nvme_s0_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)nvme_s0_build,
	.complete = (void *)nvme_s0_complete,
};

char LICENSE[] SEC("license") = "GPL";

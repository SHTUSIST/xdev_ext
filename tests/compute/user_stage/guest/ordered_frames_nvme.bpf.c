// SPDX-License-Identifier: GPL-2.0
/* Test-only ordered USER sink: logical START keys 101..106 map to ordinal
 * groups 0..5. Production nvme_s0 deliberately uses a request-ID ring;
 * this policy follows the independent ordered-frame whole-image contract.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

SEC("struct_ops/ordered_frames_nvme_build")
__s32 BPF_PROG(ordered_frames_nvme_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 key = mctx->base.src_offset;
	__u64 slba;
	__u8 *sqe;

	(void)ctx;
	/* Check before subtracting: no underflow or wraparound into the window. */
	if (key < 101 || key > 106 || mctx->base.length != 6144 ||
	    mctx->base.direction != XDEV_EXT_MP_DIR_TO_DEVICE)
		return XDEV_EXT_MP_BUILD_ABORT;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || info->l.group_bytes != 6144 || info->lba_shift != 9 ||
	    info->window_nlb != 72)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe || xdev_ext_mp_nvme_slba(info->window_slba, info->window_nlb,
			info->lba_shift, 6144, key - 101,
			XDEV_EXT_MP_NVME_MODE_WINDOW, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba, 6144,
			       info->lba_shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/ordered_frames_nvme_complete")
__s32 BPF_PROG(ordered_frames_nvme_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops ordered_frames_nvme_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)ordered_frames_nvme_build,
	.complete = (void *)ordered_frames_nvme_complete,
};

char LICENSE[] SEC("license") = "GPL";

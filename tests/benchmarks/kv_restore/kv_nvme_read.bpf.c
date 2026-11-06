// SPDX-License-Identifier: GPL-2.0
/*
 * K-KV host 1 NVMe program: batch key k reads slot (k mod slots) of the
 * stage's LBA window as one READ of exactly one group.  The restore driver
 * chooses keys r * slots + slot0 + i, so key i reads group i of the KV object;
 * the key is the START sequence, which the core assigns in order and restores
 * when a frame allocation is retried, unlike the batch id.  C still admits
 * the SQE against the window, capacity and controller limit.  PRIVATE: a
 * session selects it per stage; it never replaces the NVMe class default.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

SEC("struct_ops/kv_nvme_build")
__s32 BPF_PROG(kv_nvme_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 bytes = mctx->base.length, slba;
	__u8 *sqe;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(struct xdev_ext_nvme_mech_info));
	if (!info || mctx->base.direction != XDEV_EXT_MP_DIR_FROM_DEVICE ||
	    bytes != info->l.group_bytes || bytes > 0xffffffffULL ||
	    info->lba_shift < 9 || info->lba_shift > 31 ||
	    (bytes >> info->lba_shift) > info->max_nlb)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe ||
	    xdev_ext_mp_nvme_s0_slba(info->window_slba, info->window_nlb, info->lba_shift,
				     (__u32)bytes, mctx->base.src_offset,
				     XDEV_EXT_MP_NVME_MODE_WINDOW, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_FROM_DEVICE, slba, (__u32)bytes,
				info->lba_shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/kv_nvme_complete")
__s32 BPF_PROG(kv_nvme_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(struct xdev_ext_nvme_mech_cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops kv_nvme_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.flags = XDEV_EXT_MP_OPS_F_PRIVATE,
	.build = (void *)kv_nvme_build,
	.complete = (void *)kv_nvme_complete,
};

char LICENSE[] SEC("license") = "GPL";

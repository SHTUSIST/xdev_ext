// SPDX-License-Identifier: GPL-2.0
/*
 * GUEST TEST ONLY: NVMe mechanism programs for the attacker/victim isolation
 * test. One object is compiled per role from compile-time ATK_MODE. Every
 * object is a PRIVATE link (flags = XDEV_EXT_MECH_OPS_F_PRIVATE), so a session
 * selects it explicitly through CREATE_PROGRAMS and two sessions can run
 * different programs over the same device at once.
 *
 * The CORRECT program places batch key k (first key ATK_FIRST_KEY) at group
 * slot k in the bound LBA window, exactly like the proven ordered-frames NVMe
 * build. Each malicious program keeps a valid topology but violates one
 * boundary the kernel enforces, so C refuses it:
 *   RESERVED  a valid in-window SQE with a nonzero reserved dword (cdw2)
 *   OUTSIDE   an SQE one window past the bound window (lands in a neighbour)
 *   FRAME     reads frame bytes past the frame, latching a protocol error
 *   VERDICT   returns an illegal build verdict
 * None of them can widen the window, clear the reserved mask, or turn an
 * out-of-bounds view into a legal one; those are C's decisions.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

#define ATK_CORRECT	0
#define ATK_RESERVED	1
#define ATK_OUTSIDE	2
#define ATK_FRAME	3
#define ATK_VERDICT	4

#ifndef ATK_MODE
#define ATK_MODE ATK_CORRECT
#endif
#ifndef ATK_FIRST_KEY
#define ATK_FIRST_KEY 1
#endif

/* Build a READ/WRITE for this batch's group slot. @mode is WINDOW for a valid
 * in-window SQE or OUTSIDE for one placed one window past the bound window
 * (which C must refuse). Shared by every program variant. */
static __always_inline __s32 attack_build_sqe(const struct xdev_ext_mech_ctx *mctx,
					      __u32 mode, __u8 **out_sqe)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 key = mctx->base.src_offset;
	__u64 slba;
	__u8 *sqe;

	*out_sqe = 0;
	if (key < ATK_FIRST_KEY)
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
				  key - ATK_FIRST_KEY, mode, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba,
				(__u32)info->l.group_bytes, info->lba_shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	*out_sqe = sqe;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/attack_build")
__s32 BPF_PROG(attack_build, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *sqe;
	__s32 ret;

	(void)ctx;
#if ATK_MODE == ATK_OUTSIDE
	/* One window past the bound window: C must refuse (-ERANGE). */
	ret = attack_build_sqe(mctx, XDEV_EXT_MP_NVME_MODE_OUTSIDE, &sqe);
	return ret;
#else
	ret = attack_build_sqe(mctx, XDEV_EXT_MP_NVME_MODE_WINDOW, &sqe);
#if ATK_MODE == ATK_FRAME
	/* A view one byte past the first frame latches a protocol error; the
	 * callback then fails regardless of this returned verdict. */
	(void)bpf_xdev_ext_frame_crc32c(mctx, 0, 1, (__u32)mctx->base.length, 0);
	return ret;
#elif ATK_MODE == ATK_VERDICT
	/* An out-of-range build verdict; C replaces it with ABORT. */
	if (ret != XDEV_EXT_MP_BUILD_SUBMIT)
		return ret;
	return 7;
#elif ATK_MODE == ATK_RESERVED
	/* Dirty one reserved dword of an otherwise valid SQE: C refuses it. */
	if (ret != XDEV_EXT_MP_BUILD_SUBMIT)
		return ret;
	xdev_ext_mp_nvme_set_reserved(sqe);
	return XDEV_EXT_MP_BUILD_SUBMIT;
#else
	return ret;
#endif
#endif
}

SEC("struct_ops/attack_complete")
__s32 BPF_PROG(attack_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops attack_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.flags = XDEV_EXT_MP_OPS_F_PRIVATE,
	.build = (void *)attack_build,
	.complete = (void *)attack_complete,
};

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe plan program of the random-read session arm (NVMe class).
 *
 * nvme_rand_ops:
 *   build at WORKER - one READ or WRITE of the batch's group, batch index
 *     k = key - key_base reading group xg_block(g, 0, k) of the window: the
 *     affine order of the NVMe<->GPU evaluation's rand pattern
 *     (tests/eval/nvme_gpu/nvme_gpu_core.h) for pass 0, with the arm's seed.
 *     A session longer than the window repeats that order.
 *   complete at WORKER - continue on success, abort otherwise.
 *
 * START numbers a session's batches first_seq, first_seq + 1, ..., so the
 * order cannot come from the keys; it is a plan choice.  nxp_mech.bpf.o's
 * nxp_nvme_ops keeps the linear order.  The kernel C validator still owns the
 * window and the command; this program only names a group inside it.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Open-coded iterator loops for the affine helpers (see xdev_ext_mech_prog.h). */
#define XDEV_EXT_MP_FOR(i, n)	bpf_for(i, 0, n)
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

/* Key of batch 0 (the eval arms START every pass at first_seq 1). */
__u64 key_base = 1;
/* The arm's --seed, set when the object is loaded (ctl attach --set). */
__u32 rand_seed = 1;
/*
 * (groups << 32) | multiplier of the last window seen under rand_seed.  One
 * 64-bit word, so a concurrent session reads a matching pair or recomputes its
 * own.
 */
__u64 rand_cache;

SEC("struct_ops/nvme_rand_build")
__s32 BPF_PROG(nvme_rand_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 key = mctx->base.src_offset;
	__u64 bytes = mctx->base.length;
	__u64 blocks, groups, cache, mul, group, slba;
	__u32 shift;
	__u8 *sqe;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx,
					  sizeof(struct xdev_ext_nvme_mech_info));
	if (!info)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe || key < key_base || bytes > 0xffffffffULL)
		return XDEV_EXT_MP_BUILD_ABORT;
	shift = info->lba_shift;
	if (shift < 9 || shift > 31)
		return XDEV_EXT_MP_BUILD_ABORT;
	/* The kernel's per-command limit (max_hw_sectors, NVMe 65536). */
	if ((bytes >> shift) > info->max_nlb)
		return XDEV_EXT_MP_BUILD_ABORT;
	blocks = info->l.group_bytes >> shift;
	if (!blocks)
		return XDEV_EXT_MP_BUILD_ABORT;
	groups = info->window_nlb / blocks;
	cache = rand_cache;
	if (groups && cache >> 32 == groups && (__u32)cache) {
		mul = (__u32)cache;
	} else {
		if (xdev_ext_mp_affine_mul(groups, rand_seed, &mul))
			return XDEV_EXT_MP_BUILD_ABORT;
		rand_cache = groups << 32 | mul;
	}
	if (xdev_ext_mp_affine_group(groups, mul,
				     xdev_ext_mp_affine_add(groups, rand_seed),
				     key - key_base, &group) ||
	    xdev_ext_mp_nvme_slba(info->window_slba, info->window_nlb, shift,
				  info->l.group_bytes, group,
				  XDEV_EXT_MP_NVME_MODE_WINDOW, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba, (__u32)bytes,
				shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/nvme_rand_complete")
__s32 BPF_PROG(nvme_rand_complete, const struct xdev_ext_mech_ctx *mctx)
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
struct xdev_ext_nvme_mech_ops nvme_rand_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)nvme_rand_build,
	.complete = (void *)nvme_rand_complete,
};

char LICENSE[] SEC("license") = "GPL";

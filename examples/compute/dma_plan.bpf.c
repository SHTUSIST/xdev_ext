// SPDX-License-Identifier: GPL-2.0
/* One provider-independent window <-> pool plan. C owns all native DMA. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

SEC("struct_ops/dma_plan_build")
__s32 BPF_PROG(dma_plan_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_dma_mech_info *info;
	struct xdev_ext_dma_copy_desc *d;
	__u64 device_off, slot_end;
	__u32 pos = 0, used = 0, nr;
	int slot;

	(void)ctx;
 if (mctx->mech_abi_version != XDEV_EXT_MP_DMA_ABI_VERSION)
  return XDEV_EXT_MP_BUILD_ABORT;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(struct xdev_ext_dma_mech_info));
	if (!info)
		return XDEV_EXT_MP_BUILD_ABORT;
	nr = info->nr_frames;
	if (!nr || nr > XDEV_EXT_MP_MAX_FRAMES || !info->lease_generation ||
     !info->window_depth || info->window_slot >= info->window_depth ||
     !info->l.group_bytes ||
     info->window_depth > info->window_len / info->l.group_bytes ||
	    (mctx->base.direction != XDEV_EXT_MP_DIR_TO_DEVICE &&
	     mctx->base.direction != XDEV_EXT_MP_DIR_FROM_DEVICE) ||
	    !(info->directions & (1U << mctx->base.direction)) ||
	    xdev_ext_mp_ce_base(info->window_slot, info->l.group_bytes,
			   info->window_len, &device_off))
		return XDEV_EXT_MP_BUILD_ABORT;
	slot_end = device_off + info->l.group_bytes;
	/*
	 * Split on provider segment and entry limits, bounded by scratch capacity.
	 * The iterator lets verifier states converge instead of expanding the
	 * combinations of frame and segment progress through a counted loop.
	 */
	bpf_for(slot, 0, 32) {
		const struct xdev_ext_mech_frame_info *f;
		__u32 len, off, segment_left;

		if (pos >= nr || pos >= XDEV_EXT_MP_MAX_FRAMES)
			break;
		f = &info->f[pos];
		if (used >= f->data_len)
			return XDEV_EXT_MP_BUILD_ABORT;
		len = f->data_len - used;
		off = f->data_off + used;
		if (len > info->max_entry_len)
			len = info->max_entry_len;
		if (info->segment_size) {
			segment_left = info->segment_size - device_off % info->segment_size;
			if (len > segment_left)
				len = segment_left;
		}
		if (!len || !info->alignment ||
		    ((off | device_off | len) & (info->alignment - 1)) ||
		    device_off > slot_end ||
		    len > slot_end - device_off)
			return XDEV_EXT_MP_BUILD_ABORT;
		d = (void *)bpf_xdev_ext_desc(mctx, slot, sizeof(struct xdev_ext_dma_copy_desc));
		if (!d)
			return XDEV_EXT_MP_BUILD_ABORT;
		d->frame_pos = pos;
		d->frame_off = off;
		d->device_off = device_off;
		d->len = len;
		used += len;
		device_off += len;
		if (used == f->data_len) {
			used = 0;
			pos++;
		}
		d->flags = pos == nr ? 1U : 0U;
	}
	return pos == nr ? XDEV_EXT_MP_BUILD_SUBMIT : XDEV_EXT_MP_BUILD_ABORT;
}

SEC("struct_ops/dma_plan_complete")
__s32 BPF_PROG(dma_plan_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_dma_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(struct xdev_ext_dma_mech_cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return cqe->outcome == 0 ? XDEV_EXT_MP_NEXT :
	       cqe->outcome == 1 ? XDEV_EXT_MP_RETRY : XDEV_EXT_MP_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_dma_mech_ops dma_plan_ops = {
	.abi_version = XDEV_EXT_MP_DMA_ABI_VERSION,
	.build = (void *)dma_plan_build,
	.complete = (void *)dma_plan_complete,
};
char LICENSE[] SEC("license") = "GPL";

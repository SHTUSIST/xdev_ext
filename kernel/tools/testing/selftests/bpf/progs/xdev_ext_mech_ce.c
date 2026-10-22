// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

/* Copy-engine positive program: every kfunc each member may call. */
__u32 prepare_calls;
__u64 prepare_window_len;
__u32 prepare_tag_crc;
struct xdev_ext_mech_obs build_obs;
struct xdev_ext_mech_obs complete_obs;
__u32 complete_outcome;
__u64 complete_bytes;
__u32 complete_entries;

SEC("struct_ops.s/prepare")
__s32 BPF_PROG(ce_prepare, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_info *info;
	__u8 tag[8] = { 'u', 'b', 'r', '-', 'm', 'e', 'c', 'h' };

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return -EINVAL;
	prepare_calls++;
	prepare_window_len = info->gpu_window_len;
	prepare_tag_crc = bpf_xdev_ext_crc32c(tag, sizeof(tag), ~0U);
	return 0;
}

/* One entry per frame, back to back in the window; the last one completes. */
SEC("struct_ops/build")
__s32 BPF_PROG(ce_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_info *info;
	__u64 gpu, slot_end;
	__u32 i, n;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	n = mctx->nr_frames;
	if (!info || !n || n > XDEV_EXT_MECH_MAX_FRAMES || n != info->nr_frames ||
	    !info->lease_generation || !info->window_depth ||
	    info->window_slot >= info->window_depth || !info->l.group_bytes ||
	    (__u64)info->window_depth * info->l.group_bytes > info->gpu_window_len)
		return XDEV_EXT_MECH_BUILD_ABORT;
	gpu = (__u64)info->window_slot * info->l.group_bytes;
	slot_end = gpu + info->l.group_bytes;
	for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++) {
		const struct xdev_ext_mech_frame_info *f = &info->f[i];
		struct xdev_ext_ce_copy_desc *d;

		if (i >= n)
			break;
		if (!f->data_len || f->data_len > slot_end - gpu ||
		    (info->max_entry_len && f->data_len > info->max_entry_len) ||
		    (info->gpu_seg_size &&
		     gpu / info->gpu_seg_size !=
		     (gpu + f->data_len - 1) / info->gpu_seg_size))
			return XDEV_EXT_MECH_BUILD_ABORT;
		d = (void *)bpf_xdev_ext_desc(mctx, i, sizeof(*d));
		if (!d)
			return XDEV_EXT_MECH_BUILD_ABORT;
		d->frame_pos = i;
		d->frame_off = f->data_off;
		d->gpu_off = gpu;
		d->len = f->data_len;
		d->flags = i + 1 == n ? XDEV_EXT_CE_F_COMPLETION_POINT : 0;
		gpu += f->data_len;
	}
	xdev_ext_mech_observe(mctx, &info->f[0], &build_obs);
	return XDEV_EXT_MECH_BUILD_SUBMIT;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(ce_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_info *info;
	const struct xdev_ext_ce_mech_cqe *cqe;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!info || !cqe)
		return XDEV_EXT_MECH_ABORT;
	complete_outcome = cqe->outcome;
	complete_bytes = cqe->bytes_done;
	complete_entries = cqe->entries_done;
	xdev_ext_mech_observe(mctx, &info->f[0], &complete_obs);
	switch (cqe->outcome) {
	case XDEV_EXT_CE_OK:
		return XDEV_EXT_MECH_NEXT;
	case XDEV_EXT_CE_PRE_SUBMIT_FAILED:
		return XDEV_EXT_MECH_RETRY;
	default:
		return XDEV_EXT_MECH_ABORT;
	}
}

SEC(".struct_ops.link")
struct xdev_ext_ce_mech_ops ce_ops = {
	.abi_version = XDEV_EXT_CE_MECH_ABI_VERSION,
	.prepare = (void *)ce_prepare,
	.build = (void *)ce_build,
	.complete = (void *)ce_complete,
};

char _license[] SEC("license") = "GPL";

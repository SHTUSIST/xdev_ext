// SPDX-License-Identifier: GPL-2.0
/*
 * TP host-frame copy-engine program (libxdev_ext_frame_endpoint.h), one
 * PRIVATE instance per CE stage of a TP endpoint:
 *
 *   send     CE FROM_DEVICE, slot mode: the group of batch slot s is read
 *            from window offset s * group_bytes into the batch's host frames
 *            (at depth 1 always offset 0, where the TP pack kernels wrote it).
 *   receive  CE TO_DEVICE with XDEV_EXT_CE_STAGE_F_TARGET_RANGE: the group
 *            keyed k, received by XDOMAIN into host frames, is written to
 *            window offset (k % (window_len / group_bytes)) * group_bytes,
 *            where the TP result kernels read it.
 *
 * Frames are the layout spans of one group in ring order; pieces split only
 * where a device segment or the largest entry ends (the cursor follows
 * tests/benchmarks/kv_restore/kv_ce_place.bpf.c). C still validates every
 * entry against the window, the frames and the lease. No map: both ends
 * derive the placement from the key and the window alone.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

#define TP_CE_RANGE_ENTRIES 64U	/* XDEV_EXT_CE_RANGE_MAX_ENTRIES */
#define TP_CE_SLOT_ENTRIES 32U	/* XDEV_EXT_CE_MAX_ENTRIES without a range target */

/* Entries a group can need at any device offset, at most @cap. */
static __always_inline int tp_ce_capacity(const struct xdev_ext_mech_layout *l,
					  __u64 window_len, __u32 seg_size,
					  __u32 max_entry_len, __u32 cap)
{
	__u32 frames, left, pos, len;
	__u32 max = max_entry_len ? max_entry_len : seg_size ? seg_size : 0xffffffffU;
	__u64 bound;

	if (!l->group_bytes || !l->seg_len || l->hdr_room >= l->frame_size ||
	    l->seg_len > l->frame_size - l->hdr_room || l->group_bytes > window_len)
		return -EINVAL;
	frames = 1 + (l->group_bytes - 1) / l->seg_len;
	if (frames > XDEV_EXT_MP_MAX_FRAMES)
		return -EMSGSIZE;
	bound = frames;
	if (seg_size)
		bound += ((__u64)l->group_bytes + seg_size - 2) / seg_size;
	if (bound > cap)
		return -EMSGSIZE;
	if (seg_size && max >= seg_size)
		return 0;
	left = l->group_bytes;
	for (pos = 0; pos < XDEV_EXT_MP_MAX_FRAMES; pos++) {
		if (pos >= frames)
			break;
		len = left < l->seg_len ? left : l->seg_len;
		bound += (len - 1) / max;
		if (bound > cap)
			return -EMSGSIZE;
		left -= len;
	}
	return 0;
}

SEC("struct_ops.s/tp_ce_prepare")
__s32 BPF_PROG(tp_ce_prepare, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_info *info;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return -EINVAL;
	return tp_ce_capacity(&info->l, info->gpu_window_len, info->gpu_seg_size,
			      info->max_entry_len, TP_CE_RANGE_ENTRIES);
}

struct tp_ce_cursor {
	__u64 gpu, window_len;
	__u32 pos, off, total, nr, group_bytes;
	__u32 seg_size, max_entry_len, data_off, data_len;
	struct xdev_ext_ce_copy_desc desc;
};

/* 0 continues; positive is the terminal BUILD verdict; negative: no piece. */
__attribute__((noinline))
int tp_ce_step(struct tp_ce_cursor *c)
{
	__u32 piece, remain, max;
	int err;

	if (!c || c->pos >= c->nr || c->pos >= XDEV_EXT_MP_MAX_FRAMES || c->off >= c->data_len)
		return -EINVAL;
	max = c->max_entry_len ? c->max_entry_len : c->seg_size ? c->seg_size : 0xffffffffU;
	piece = c->data_len - c->off;
	if (piece > max)
		piece = max;
	if (c->seg_size) {
		remain = c->seg_size - c->gpu % c->seg_size;
		if (piece > remain)
			piece = remain;
	}
	err = xdev_ext_mp_ce_piece(&c->desc, c->pos, c->total + piece == c->group_bytes,
				   c->data_off + c->off, piece, c->gpu, c->window_len,
				   c->seg_size, c->max_entry_len);
	if (err)
		return err;
	c->gpu += piece;
	c->total += piece;
	c->off += piece;
	if (c->off == c->data_len) {
		c->pos++;
		c->off = 0;
	}
	if (c->total == c->group_bytes)
		return c->pos == c->nr && !c->off ? XDEV_EXT_MP_BUILD_SUBMIT : XDEV_EXT_MP_BUILD_ABORT;
	return 0;
}

SEC("struct_ops/tp_ce_build")
__s32 BPF_PROG(tp_ce_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_info *info;
	const struct xdev_ext_mech_frame_info *f;
	struct xdev_ext_ce_copy_desc *d;
	struct tp_ce_cursor cursor;
	__u64 key = mctx->base.src_offset, slots, gpu;
	__u32 ordinal, nr, piece, remain, cap;
	bool send;
	int verdict;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || (mctx->base.direction != XDEV_EXT_MP_DIR_TO_DEVICE &&
		      mctx->base.direction != XDEV_EXT_MP_DIR_FROM_DEVICE) ||
	    !info->lease_generation || !info->window_depth ||
	    info->lease_generation != mctx->batch_id ||
	    mctx->base.request_id != mctx->batch_id ||
	    info->window_slot >= info->window_depth ||
	    mctx->base.length != info->l.group_bytes)
		return XDEV_EXT_MP_BUILD_ABORT;
	send = mctx->base.direction == XDEV_EXT_MP_DIR_FROM_DEVICE;
	cap = send ? TP_CE_SLOT_ENTRIES : TP_CE_RANGE_ENTRIES;
	/* A keyed receive group may start anywhere: bound it for any offset. The
	 * send slot offset is known, so the cursor below enforces its cap exactly. */
	if (tp_ce_capacity(&info->l, info->gpu_window_len, info->gpu_seg_size,
			   info->max_entry_len, send ? 0xffffffffU : cap))
		return XDEV_EXT_MP_BUILD_ABORT;
	slots = info->gpu_window_len / info->l.group_bytes;
	if (!slots || (send && info->window_depth > slots))
		return XDEV_EXT_MP_BUILD_ABORT;
	gpu = (send ? info->window_slot : key % slots) * (__u64)info->l.group_bytes;
	nr = info->nr_frames;
	if (!nr || nr > XDEV_EXT_MP_MAX_FRAMES || mctx->nr_frames != nr ||
	    nr != 1 + (info->l.group_bytes - 1) / info->l.seg_len)
		return XDEV_EXT_MP_BUILD_ABORT;
	/* Every frame carries its full share before any descriptor is written. */
	remain = info->l.group_bytes;
	for (ordinal = 0; ordinal < XDEV_EXT_MP_MAX_FRAMES; ordinal++) {
		if (ordinal >= nr)
			break;
		f = &info->f[ordinal];
		piece = remain < info->l.seg_len ? remain : info->l.seg_len;
		if (!f->data_len || f->data_len != piece || f->data_off > info->l.frame_size ||
		    f->data_len > info->l.frame_size - f->data_off)
			return XDEV_EXT_MP_BUILD_ABORT;
		remain -= piece;
	}
	if (remain)
		return XDEV_EXT_MP_BUILD_ABORT;
	__builtin_memset(&cursor, 0, sizeof(cursor));
	cursor.gpu = gpu;
	cursor.window_len = info->gpu_window_len;
	cursor.nr = nr;
	cursor.group_bytes = info->l.group_bytes;
	cursor.seg_size = info->gpu_seg_size;
	cursor.max_entry_len = info->max_entry_len;
	for (ordinal = 0; ordinal < TP_CE_RANGE_ENTRIES; ordinal++) {
		if (ordinal >= cap || cursor.pos >= nr || cursor.pos >= XDEV_EXT_MP_MAX_FRAMES ||
		    ordinal >= mctx->desc_cap)
			return XDEV_EXT_MP_BUILD_ABORT;
		f = &info->f[cursor.pos];
		if (cursor.off >= f->data_len)
			return XDEV_EXT_MP_BUILD_ABORT;
		cursor.data_off = f->data_off;
		cursor.data_len = f->data_len;
		d = (void *)bpf_xdev_ext_desc(mctx, ordinal, sizeof(*d));
		if (!d)
			return XDEV_EXT_MP_BUILD_ABORT;
		verdict = tp_ce_step(&cursor);
		if (verdict < 0)
			return XDEV_EXT_MP_BUILD_ABORT;
		*d = cursor.desc;
		if (verdict)
			return verdict == XDEV_EXT_MP_BUILD_SUBMIT ? XDEV_EXT_MP_BUILD_SUBMIT :
								     XDEV_EXT_MP_BUILD_ABORT;
	}
	return XDEV_EXT_MP_BUILD_ABORT;
}

SEC("struct_ops/tp_ce_complete")
__s32 BPF_PROG(tp_ce_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	return cqe ? xdev_ext_mp_ce_next(cqe->outcome) : XDEV_EXT_MP_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_ce_mech_ops tp_ce_ops = {
	.abi_version = XDEV_EXT_MP_CE_ABI_VERSION,
	.flags = XDEV_EXT_MP_OPS_F_PRIVATE,
	.prepare = (void *)tp_ce_prepare,
	.build = (void *)tp_ce_build,
	.complete = (void *)tp_ce_complete,
};

char LICENSE[] SEC("license") = "GPL";

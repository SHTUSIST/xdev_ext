// SPDX-License-Identifier: GPL-2.0
/* Opt-in two-stage NVMe<->CE requests. C owns admission, DMA and range leases.
 * Load one object, select its two PRIVATE links, then CREATE/fill/freeze/START.
 * CE stage must explicitly use XDEV_EXT_CE_STAGE_F_TARGET_RANGE; flags0 and
 * the existing default programs keep their original semantics. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "nvme_ce_request.h"

#define NVME_CE_REQUEST_ENTRIES 64U

/* Example-local all-offset bound. CREATE has no live batch fields.
 * A G-byte range has at most ceil((G-1)/S) segment cuts. Partitioning
 * one canonical host frame at these cuts cannot increase the sum of
 * floor((piece_len-1)/M) max-length cuts. M>=S needs no extra M cuts.
 * BUILD checks canonical lengths before using this proof. */
XDEV_EXT_MP_INLINE int request_ce_capacity(const struct xdev_ext_mech_layout *l,
				     __u64 window_len, __u32 seg_size,
				     __u32 max_entry_len, __u32 cap)
{
	__u32 frames, left, pos, len;
	__u32 max = max_entry_len ? max_entry_len :
		    seg_size ? seg_size : 0xffffffffU;
	__u64 bound;

	if (!l->group_bytes || !l->seg_len || l->hdr_room >= l->frame_size ||
	    l->seg_len > l->frame_size - l->hdr_room ||
	    l->group_bytes > window_len || !cap)
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, struct nvme_ce_request_key);
	__type(value, struct nvme_ce_request_value);
} request_map SEC(".maps");

/* No request lookup in CREATE: users receive session_id only after CREATE.
 * The actual C info already contains namespace/queue facts at this point. */
SEC("struct_ops.s/request_nvme_prepare")
__s32 BPF_PROG(request_nvme_prepare, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u32 shift, bytes;
	__u64 nlb;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return -EINVAL;
	shift = info->lba_shift;
	bytes = info->l.group_bytes;
	if (shift < 9 || shift > 31 || !bytes ||
	    bytes & ((1ULL << shift) - 1) || !info->window_nlb ||
	    info->window_slba >= info->capacity_lbas ||
	    info->window_nlb > info->capacity_lbas - info->window_slba)
		return -EINVAL;
	nlb = bytes >> shift;
	if (nlb > info->window_nlb || nlb > info->max_nlb ||
	    nlb > XDEV_EXT_MP_NVME_MAX_NLB)
		return -EMSGSIZE;
	return 0;
}

SEC("struct_ops.s/request_ce_prepare")
__s32 BPF_PROG(request_ce_prepare, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_info *info;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return -EINVAL;
	return request_ce_capacity(&info->l, info->gpu_window_len,
			info->gpu_seg_size, info->max_entry_len, NVME_CE_REQUEST_ENTRIES);
}

SEC("struct_ops/request_nvme_build")
__s32 BPF_PROG(request_nvme_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	struct nvme_ce_request_key key = { mctx->session_id, mctx->base.src_offset };
	const struct nvme_ce_request_value *entry;
	__u64 offset, bytes, relative_lba, nlb;
	__u32 shift;
	__u8 *sqe;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || (mctx->base.direction != XDEV_EXT_MP_DIR_FROM_DEVICE &&
		     mctx->base.direction != XDEV_EXT_MP_DIR_TO_DEVICE))
		return XDEV_EXT_MP_BUILD_ABORT;
	entry = bpf_map_lookup_elem(&request_map, &key);
	if (!entry)
		return XDEV_EXT_MP_BUILD_ABORT;
	offset = entry->nvme_byte_offset;
	bytes = entry->byte_length;
	shift = info->lba_shift;
	if (entry->reserved || shift < 9 || shift > 31 || !bytes ||
	    bytes != mctx->base.length || bytes != info->l.group_bytes ||
	    ((offset | bytes) & ((1ULL << shift) - 1)))
		return XDEV_EXT_MP_BUILD_ABORT;
	relative_lba = offset >> shift;
	nlb = bytes >> shift;
	if (!info->window_nlb || info->window_slba >= info->capacity_lbas ||
	    info->window_nlb > info->capacity_lbas - info->window_slba ||
	    relative_lba >= info->window_nlb || nlb > info->window_nlb - relative_lba ||
	    nlb > info->max_nlb || nlb > XDEV_EXT_MP_NVME_MAX_NLB)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe || xdev_ext_mp_nvme_rw(sqe, mctx->base.direction,
			info->window_slba + relative_lba, (__u32)bytes, shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

/* Only scalar data crosses this independently verified function boundary.
 * Keep the trusted callback ctx, readonly info and descriptor kfunc outside.
 * The ordinary stack object is writable; readonly kfunc memory is never
 * passed as a generic global-function memory argument. */
struct request_ce_cursor {
	__u64 gpu, window_len;
	__u32 pos, off, total, nr, group_bytes;
	__u32 seg_size, max_entry_len, data_off, data_len;
	struct xdev_ext_ce_copy_desc desc;
};

/* Zero continues; a positive value is the original terminal BUILD verdict.
 * A negative value means no descriptor was generated for this piece. */
__attribute__((noinline))
int request_ce_step(struct request_ce_cursor *c)
{
	__u32 piece, remain, max;
	int err;

	if (!c || c->pos >= c->nr || c->pos >= XDEV_EXT_MP_MAX_FRAMES ||
	    c->off >= c->data_len)
		return -EINVAL;
	max = c->max_entry_len ? c->max_entry_len :
		c->seg_size ? c->seg_size : 0xffffffffU;
	piece = c->data_len - c->off;
	if (piece > max)
		piece = max;
	if (c->seg_size) {
		remain = c->seg_size - c->gpu % c->seg_size;
		if (piece > remain)
			piece = remain;
	}
	err = xdev_ext_mp_ce_piece(&c->desc, c->pos,
		c->total + piece == c->group_bytes,
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
		return c->pos == c->nr && !c->off ?
			XDEV_EXT_MP_BUILD_SUBMIT : XDEV_EXT_MP_BUILD_ABORT;
	return 0;
}

SEC("struct_ops/request_ce_build")
__s32 BPF_PROG(request_ce_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_info *info;
	struct nvme_ce_request_key key = { mctx->session_id, mctx->base.src_offset };
	const struct nvme_ce_request_value *entry;
	const struct xdev_ext_mech_frame_info *f;
	struct xdev_ext_ce_copy_desc *d;
	struct request_ce_cursor cursor;
	__u32 ordinal, nr, piece, remain;
	int verdict;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || (mctx->base.direction != XDEV_EXT_MP_DIR_TO_DEVICE &&
		     mctx->base.direction != XDEV_EXT_MP_DIR_FROM_DEVICE) ||
	    !info->lease_generation || !info->window_depth ||
	    info->lease_generation != mctx->batch_id ||
	    mctx->base.request_id != mctx->batch_id ||
	    info->window_slot >= info->window_depth ||
	    request_ce_capacity(&info->l, info->gpu_window_len,
		info->gpu_seg_size, info->max_entry_len, NVME_CE_REQUEST_ENTRIES))
		return XDEV_EXT_MP_BUILD_ABORT;
	nr = info->nr_frames;
	if (!nr || nr > XDEV_EXT_MP_MAX_FRAMES || mctx->nr_frames != nr ||
	    nr != 1 + (info->l.group_bytes - 1) / info->l.seg_len)
		return XDEV_EXT_MP_BUILD_ABORT;
	entry = bpf_map_lookup_elem(&request_map, &key);
	if (!entry || entry->reserved || !entry->byte_length ||
	    entry->byte_length != mctx->base.length ||
	    entry->byte_length != info->l.group_bytes ||
	    entry->gpu_byte_offset > info->gpu_window_len ||
	    entry->byte_length > info->gpu_window_len - entry->gpu_byte_offset)
		return XDEV_EXT_MP_BUILD_ABORT;
	__builtin_memset(&cursor, 0, sizeof(cursor));
	cursor.gpu = entry->gpu_byte_offset;
	cursor.window_len = info->gpu_window_len;
	cursor.nr = nr;
	cursor.group_bytes = info->l.group_bytes;
	cursor.seg_size = info->gpu_seg_size;
	cursor.max_entry_len = info->max_entry_len;
	/* Validate all spans before writing a descriptor. The canonical lengths
	 * make CREATE's all-offset bound apply to the live BUILD frame list. */
	remain = info->l.group_bytes;
	for (ordinal = 0; ordinal < XDEV_EXT_MP_MAX_FRAMES; ordinal++) {
		if (ordinal >= nr)
			break;
		f = &info->f[ordinal];
		piece = remain < info->l.seg_len ? remain : info->l.seg_len;
		if (!f->data_len || f->data_len != piece ||
		    f->data_off > info->l.frame_size ||
		    f->data_len > info->l.frame_size - f->data_off)
			return XDEV_EXT_MP_BUILD_ABORT;
		remain -= piece;
	}
	if (remain)
		return XDEV_EXT_MP_BUILD_ABORT;
	for (ordinal = 0; ordinal < NVME_CE_REQUEST_ENTRIES; ordinal++) {
		if (cursor.pos >= nr || cursor.pos >= XDEV_EXT_MP_MAX_FRAMES ||
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
		verdict = request_ce_step(&cursor);
		if (verdict < 0)
			return XDEV_EXT_MP_BUILD_ABORT;
		*d = cursor.desc;
		if (verdict)
			return verdict == XDEV_EXT_MP_BUILD_SUBMIT ?
				XDEV_EXT_MP_BUILD_SUBMIT : XDEV_EXT_MP_BUILD_ABORT;
	}
	return XDEV_EXT_MP_BUILD_ABORT;
}

SEC("struct_ops/request_nvme_complete")
__s32 BPF_PROG(request_nvme_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC("struct_ops/request_ce_complete")
__s32 BPF_PROG(request_ce_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	return cqe ? xdev_ext_mp_ce_next(cqe->outcome) : XDEV_EXT_MP_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops request_nvme_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.flags = XDEV_EXT_MP_OPS_F_PRIVATE,
	.prepare = (void *)request_nvme_prepare,
	.build = (void *)request_nvme_build,
	.complete = (void *)request_nvme_complete,
};
SEC(".struct_ops.link")
struct xdev_ext_ce_mech_ops request_ce_ops = {
	.abi_version = XDEV_EXT_MP_CE_ABI_VERSION,
	.flags = XDEV_EXT_MP_OPS_F_PRIVATE,
	.prepare = (void *)request_ce_prepare,
	.build = (void *)request_ce_build,
	.complete = (void *)request_ce_complete,
};
char LICENSE[] SEC("license") = "GPL";

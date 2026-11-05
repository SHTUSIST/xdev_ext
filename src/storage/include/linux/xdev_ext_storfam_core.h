/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_STORFAM_CORE_H
#define _LINUX_XDEV_EXT_STORFAM_CORE_H

/* Pure rules shared by storage devices. */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <linux/types.h>
#endif

/* LBA authorization, separate from requester DMA extents and their pins. */
struct xdev_ext_stor_window {
	__u64 slba, nlb, capacity_lbas;
	__u8 lba_shift, write;
};

struct xdev_ext_stor_rw {
	__u64 slba, nlb, byte_offset, byte_length;
	__u8 write;
};

/* Queue limits a batch payload must meet to reach the device as it is. */
struct xdev_ext_stor_queue_caps {
	__u64 virt_boundary_mask;
	__u32 page_size;
	__u32 dma_align_mask;	/* dma_alignment | dma_pad_mask */
	__u32 max_segments;
	__u32 max_segment_size;
	__u32 max_bytes;	/* max_hw_sectors in bytes */
	__u32 lba_size;		/* a power of two */
};

/*
 * Walk of a batch payload, one page-local piece at a time in DMA order,
 * before a bio is built from it: the DMA alignment that blk_rq_append_bio()
 * does not check, and the virtual-boundary gaps and segment limit for which
 * it would have to split (it returns -EREMOTEIO instead).  A piece that
 * starts where the previous one ended in the same page merges with it, as
 * bio_add_page() does.
 */
struct xdev_ext_stor_seg_walk {
	struct xdev_ext_stor_queue_caps caps;
	__u32 segs;
	__u32 seg_len;		/* bytes of the current segment */
	__u32 bytes;
	__u32 end;		/* page offset where the last piece ended */
};

static inline void xdev_ext_stor_seg_walk_init(struct xdev_ext_stor_seg_walk *walk,
					  const struct xdev_ext_stor_queue_caps *caps)
{
	*walk = (struct xdev_ext_stor_seg_walk) { .caps = *caps };
}

/* -EREMOTEIO: the device cannot take the payload as it is. */
static inline int xdev_ext_stor_seg_add(struct xdev_ext_stor_seg_walk *walk,
				   __u32 page_off, __u32 len, int same_page)
{
	const struct xdev_ext_stor_queue_caps *caps = &walk->caps;

	if (!len || page_off >= caps->page_size ||
	    len > caps->page_size - page_off)
		return -EINVAL;
	if ((page_off | len) & caps->dma_align_mask)
		return -EREMOTEIO;
	if (len > caps->max_bytes - walk->bytes)
		return -EMSGSIZE;
	if (walk->segs && same_page && page_off == walk->end) {
		if (len > caps->max_segment_size - walk->seg_len)
			return -EREMOTEIO;
		walk->seg_len += len;
	} else {
		if (walk->segs && ((page_off | walk->end) &
				   caps->virt_boundary_mask))
			return -EREMOTEIO;
		if (walk->segs >= caps->max_segments ||
		    len > caps->max_segment_size)
			return -EREMOTEIO;
		walk->segs++;
		walk->seg_len = len;
	}
	walk->bytes += len;
	walk->end = page_off + len;
	return 0;
}

static inline int xdev_ext_stor_seg_done(const struct xdev_ext_stor_seg_walk *walk)
{
	if (!walk->segs)
		return -EINVAL;
	if (walk->bytes & (walk->caps.lba_size - 1))
		return -EMSGSIZE;
	return 0;
}

struct xdev_ext_stor_extent {
	__u64 addr;
	__u32 len;
};

/* Merge DMA-contiguous extents in payload order. Addresses and lengths
 * satisfy @align_mask; @out may be @seg. */
static inline int
xdev_ext_stor_coalesce(const struct xdev_ext_stor_extent *seg, __u32 nr,
		      struct xdev_ext_stor_extent *out, __u32 cap,
		      __u32 align_mask, __u32 *n)
{
	__u32 i, used = 0;

	if (!n)
		return -EINVAL;
	*n = 0;
	if (!seg || !out || !nr)
		return -EINVAL;
	for (i = 0; i < nr; i++) {
		if (!seg[i].len || ((seg[i].addr | seg[i].len) & align_mask))
			return -EINVAL;
		if (seg[i].addr + seg[i].len < seg[i].addr)
			return -EOVERFLOW;
		if (used && out[used - 1].addr + out[used - 1].len == seg[i].addr &&
		    seg[i].len <= (__u32)~0U - out[used - 1].len) {
			out[used - 1].len += seg[i].len;
		} else {
			if (used == cap)
				return -EREMOTEIO;
			out[used++] = seg[i];
		}
	}
	*n = used;
	return 0;
}

/* Require [slba, slba + nlb) to lie inside the bound window. */
static inline int xdev_ext_stor_window_check(__u64 window_slba,
					   __u64 window_nlb,
					   __u64 slba, __u64 nlb)
{
	__u64 offset;

	if (slba < window_slba)
		return -ERANGE;
	offset = slba - window_slba;
	if (offset >= window_nlb || nlb > window_nlb - offset)
		return -ERANGE;
	return 0;
}

/*
 * A delegated LBA range of one namespace (prototype for ASK.69).  A holder of
 * the namespace issues it; a stage presenting it binds a window only inside
 * the range and only in a granted direction.  Grants of one namespace that
 * share an LBA conflict unless both are read-only.
 */
#define XDEV_EXT_STOR_GRANT_READ	(1U << 0)
#define XDEV_EXT_STOR_GRANT_WRITE	(1U << 1)

struct xdev_ext_stor_grant {
	__u64 slba, nlb;
	__u32 access;
};

/* Issue: a nonempty range inside the namespace; publish only on success. */
static inline int xdev_ext_stor_grant_make(struct xdev_ext_stor_grant *out,
		__u64 capacity_lbas, __u64 slba, __u64 nlb, __u32 access)
{
	if (!out || !access ||
	    (access & ~(XDEV_EXT_STOR_GRANT_READ | XDEV_EXT_STOR_GRANT_WRITE)))
		return -EINVAL;
	if (!nlb)
		return -EINVAL;
	if (slba > capacity_lbas || nlb > capacity_lbas - slba)
		return -ERANGE;
	*out = (struct xdev_ext_stor_grant) {
		.slba = slba, .nlb = nlb, .access = access,
	};
	return 0;
}

/* CREATE: an ungranted direction (-EBADF) precedes the range (-EACCES). */
static inline int xdev_ext_stor_grant_admit(const struct xdev_ext_stor_grant *grant,
		bool write, __u64 slba, __u64 nlb)
{
	if (!grant)
		return -EINVAL;
	if (!(grant->access & (write ? XDEV_EXT_STOR_GRANT_WRITE :
				       XDEV_EXT_STOR_GRANT_READ)))
		return -EBADF;
	if (xdev_ext_stor_window_check(grant->slba, grant->nlb, slba, nlb))
		return -EACCES;
	return 0;
}

/* Two grants of one namespace: a shared LBA that either side may write. */
static inline bool xdev_ext_stor_grant_conflict(const struct xdev_ext_stor_grant *a,
		const struct xdev_ext_stor_grant *b)
{
	if (!((a->access | b->access) & XDEV_EXT_STOR_GRANT_WRITE))
		return false;
	if (a->slba >= b->slba)
		return a->slba - b->slba < b->nlb;
	return b->slba - a->slba < a->nlb;
}

/* Publish the immutable window only after every geometry check succeeds. */
static inline int xdev_ext_stor_window_bind(struct xdev_ext_stor_window *out,
		__u64 capacity_lbas, __u8 lba_shift, bool write,
		__u64 slba, __u64 nlb, __u32 group_bytes)
{
	if (!out)
		return -EINVAL;
	if (lba_shift < 9)
		return -EINVAL;
	if (lba_shift >= 32)
		return -EOVERFLOW;
	if (!group_bytes)
		return -EINVAL;
	if ((group_bytes & ((1U << lba_shift) - 1)) ||
	    (group_bytes >> lba_shift) > 65536U)
		return -EMSGSIZE;
	if (!nlb)
		return -EINVAL;
	if (slba > capacity_lbas || nlb > capacity_lbas - slba ||
	    (group_bytes >> lba_shift) > nlb)
		return -ERANGE;
	*out = (struct xdev_ext_stor_window) {
		.slba = slba, .nlb = nlb, .capacity_lbas = capacity_lbas,
		.lba_shift = lba_shift, .write = write,
	};
	return 0;
}

/* The caller supplies a successfully bound window (in particular its shift).
 * Window refusal precedes byte arithmetic, as at the native command boundary.
 */
static inline int xdev_ext_stor_window_admit(
		const struct xdev_ext_stor_window *window,
		__u64 slba, __u64 nlb, __u32 data_len,
		struct xdev_ext_stor_rw *out)
{
	__u64 bytes;
	int ret;

	if (!window || !out)
		return -EINVAL;
	*out = (struct xdev_ext_stor_rw) {};
	if (!nlb)
		return -EINVAL;
	ret = xdev_ext_stor_window_check(window->slba, window->nlb, slba, nlb);
	if (ret)
		return ret;
	if (nlb > (~(__u64)0 >> window->lba_shift))
		return -EOVERFLOW;
	bytes = nlb << window->lba_shift;
	if (!data_len)
		return -EINVAL;
	if (bytes > (__u64)~(__u32)0 || bytes != data_len)
		return -EMSGSIZE;
	if (slba > (~(__u64)0 >> window->lba_shift))
		return -EOVERFLOW;
	if (slba > window->capacity_lbas || nlb > window->capacity_lbas - slba)
		return -ERANGE;
	*out = (struct xdev_ext_stor_rw) {
		.slba = slba, .nlb = nlb,
		.byte_offset = slba << window->lba_shift, .byte_length = bytes,
		.write = window->write,
	};
	return 0;
}

#endif

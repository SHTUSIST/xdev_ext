/*
 * SPDX-FileCopyrightText: Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 *
 * Pure part of the copy-engine backend's DMA-API ownership transfer: which
 * mapped host segments one plan entry touches.  bind_host records every DMA
 * segment of the host mapping once, as its DMA API handle and the byte offset
 * just past it in the bound pages.  A request then syncs only the pieces of
 * the segments its entries cover, found by binary search, so the cost per
 * request does not grow with the number of segments in the pool.  No kernel
 * dependency, so tests/ runs it in user space.
 */
#ifndef _NV_XDEV_EXT_CE_SYNC_H_
#define _NV_XDEV_EXT_CE_SYNC_H_

#include "nv-xdev_ext-gpu-policy.h"

/* Segments are ordered and adjacent; the first starts at byte 0. */
struct nv_xdev_ext_ce_seg {
	nv_xdev_ext_gpu_u64 dma;	/* DMA API handle of the segment */
	nv_xdev_ext_gpu_u64 end;	/* byte offset just past it */
};

/* Bytes [seg_off, seg_off + len) of segment seg. */
struct nv_xdev_ext_ce_piece {
	nv_xdev_ext_gpu_u32 seg;
	nv_xdev_ext_gpu_u64 seg_off;
	nv_xdev_ext_gpu_u64 len;
};

/* First segment that ends after off; n when off is at or past the last end. */
static inline nv_xdev_ext_gpu_u32
nv_xdev_ext_ce_seg_first(const struct nv_xdev_ext_ce_seg *s, nv_xdev_ext_gpu_u32 n,
			 nv_xdev_ext_gpu_u64 off)
{
	nv_xdev_ext_gpu_u32 lo = 0, hi = n;

	while (lo < hi) {
		nv_xdev_ext_gpu_u32 mid = lo + (hi - lo) / 2;

		if (s[mid].end <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

/*
 * Next piece of [*off, stop): fills p, advances *off and *seg and returns 1;
 * returns 0 once *off reaches stop, the segments end, or *seg does not hold
 * *off.  Start with *seg = nv_xdev_ext_ce_seg_first(s, n, *off).
 */
static inline int
nv_xdev_ext_ce_seg_next(const struct nv_xdev_ext_ce_seg *s, nv_xdev_ext_gpu_u32 n,
			nv_xdev_ext_gpu_u32 *seg, nv_xdev_ext_gpu_u64 *off,
			nv_xdev_ext_gpu_u64 stop, struct nv_xdev_ext_ce_piece *p)
{
	nv_xdev_ext_gpu_u64 base, end;

	if (*off >= stop || *seg >= n)
		return 0;
	base = *seg ? s[*seg - 1].end : 0;
	if (*off < base || *off >= s[*seg].end)
		return 0;
	end = s[*seg].end < stop ? s[*seg].end : stop;
	p->seg = *seg;
	p->seg_off = *off - base;
	p->len = end - *off;
	*off = end;
	(*seg)++;
	return 1;
}

#endif /* _NV_XDEV_EXT_CE_SYNC_H_ */

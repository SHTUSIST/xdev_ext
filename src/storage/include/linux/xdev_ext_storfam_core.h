/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_STORFAM_CORE_H
#define _LINUX_XDEV_EXT_STORFAM_CORE_H

/* Pure rules shared by storage devices. */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <linux/types.h>
#endif

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

#endif

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

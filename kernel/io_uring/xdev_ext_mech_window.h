/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_WINDOW_H
#define IO_URING_XDEV_EXT_MECH_WINDOW_H

#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

/* Stable batch slots; no sequence arithmetic or per-copy allocation. */
static inline int xdev_ext_mech_window_offset(__u32 slot, __u32 depth,
                                         __u32 group_bytes, __u64 window_len,
                                         __u64 *offset)
{
	if (!offset || !depth || !group_bytes || slot >= depth)
		return -EINVAL;
	/* Both factors are u32: widening first makes the product exact. */
	if ((__u64)depth * group_bytes > window_len)
		return -ENOSPC;
	*offset = (__u64)slot * group_bytes;
	return 0;
}

#endif /* IO_URING_XDEV_EXT_MECH_WINDOW_H */

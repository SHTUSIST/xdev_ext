/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_REQUESTER_CORE_H
#define _LINUX_XDEV_EXT_REQUESTER_CORE_H

/* Pure rules every device-memory requester shares (any family). */
#include <linux/types.h>

#define XDEV_EXT_LEASE_MIN_SHIFT 12U

/*
 * After a provider refuses [off, off + len) with -ERANGE, retry the longest
 * proper prefix ending at a naturally aligned power-of-two page boundary.
 * The cursor starts at 31 and only falls; return 0 when no boundary of at
 * least 1 << min_shift remains.
 */
static inline __u32 xdev_ext_lease_shrink(__u64 off, __u32 len,
				       __u32 *shift, __u32 min_shift)
{
	while (*shift >= min_shift) {
		__u64 page = 1ULL << *shift;
		__u64 end = (off & ~(page - 1)) + page;

		if (end - off < len)
			return (__u32)(end - off);
		(*shift)--;
	}
	return 0;
}

#endif

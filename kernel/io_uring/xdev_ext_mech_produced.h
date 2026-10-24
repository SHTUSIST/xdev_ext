/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_PRODUCED_H
#define XDEV_EXT_MECH_PRODUCED_H
#include "xdev_ext_mech_core.h"

/* Validate all capacities before mutating the caller's lengths. */
static inline int xdev_ext_mech_produced_trim(__u32 *len, __u32 nr, __u32 produced)
{
	__u64 capacity = 0;
	__u32 i, left = produced, used = 0;

	if (!nr || nr > XDEV_EXT_MECH_MAX_FRAMES)
		return -EINVAL;
	for (i = 0; i < nr; i++) {
		if (!len[i])
			return -EINVAL;
		capacity += len[i];
	}
	if (!produced || produced > capacity)
		return -EOVERFLOW;
	for (i = 0; i < nr; i++) {
		len[i] = len[i] < left ? len[i] : left;
		left -= len[i];
		used += !!len[i];
	}
	return used;
}
#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_UNIFIED_OPS_CORE_H
#define IO_URING_UNIFIED_OPS_CORE_H

/* Pure compatibility rules shared by the kernel path and host selftest. */
#include "xdev_ext_mech_life_pool.h"

static inline bool xdev_ext_unified_write_force_dsync(__u32 opcode)
{
	return opcode == IO_UNIFIED_OP_WRITE;
}

static inline int
xdev_ext_unified_read_finish(struct xdev_ext_mech_life_pool *pool, __u32 frame, __u64 claim, long result,
			bool recycle_on_completion)
{
	if (result >= 0 && !recycle_on_completion)
		return xdev_ext_mech_life_publish(&pool->frames[frame], claim, 1, (__u32)result);
	return xdev_ext_mech_life_fail_produce(&pool->frames[frame], claim);
}

#endif /* IO_URING_UNIFIED_OPS_CORE_H */

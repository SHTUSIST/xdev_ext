/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_UNIFIED_OPS_CORE_H
#define IO_URING_UNIFIED_OPS_CORE_H

/* Pure compatibility rules shared by the kernel path and host selftest. */
#include "../xdev_ext_frame_sm.h"

static inline bool xdev_ext_unified_write_force_dsync(xdev_ext_sm_u32 opcode)
{
	return opcode == IO_UNIFIED_OP_WRITE;
}

static inline int
xdev_ext_unified_read_finish(struct xdev_ext_pool *pool, xdev_ext_sm_u32 frame, long result,
			bool recycle_on_completion)
{
	if (result >= 0 && !recycle_on_completion)
		return xdev_ext_frame_publish(pool, frame, (xdev_ext_sm_u32)result);
	return xdev_ext_frame_abort(pool, frame);
}

#endif /* IO_URING_UNIFIED_OPS_CORE_H */

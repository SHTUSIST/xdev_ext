/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_IAA_H
#define IO_URING_XDEV_EXT_IAA_H

#include <linux/compiler_types.h>
#include <linux/types.h>

#include "xdev_ext_iaa_core.h"

struct io_kiocb;
struct io_xdev_ext_umem;
struct io_uring_unified_shared;

struct io_xdev_ext_iaa_params {
	u32 opcode;
	u64 src_off;
	u64 dst_off;
	u32 src_len;
	u64 dst_cap;
};

typedef void (*io_xdev_ext_iaa_stats_fn)(struct io_uring_unified_shared __user *shared,
				    u64 result, bool error);

/*
 * Returns the produced byte count or a negative errno for synchronous
 * completion, and -EIOCBQUEUED once Crypto API owns an accepted request.
 * There is deliberately no cancellation entry point: accepted acomp work is
 * retained until its real terminal callback queues io_uring task work.
 */
int io_xdev_ext_iaa_issue(struct io_kiocb *req, struct io_xdev_ext_umem *umem,
		     struct io_uring_unified_shared __user *shared,
		     const struct io_xdev_ext_iaa_params *params,
		     io_xdev_ext_iaa_stats_fn update_stats);

#endif /* IO_URING_XDEV_EXT_IAA_H */

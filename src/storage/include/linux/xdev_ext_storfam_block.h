/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_STORFAM_BLOCK_H
#define _LINUX_XDEV_EXT_STORFAM_BLOCK_H

#include <linux/xdev_ext_storfam_core.h>

struct request_queue;
struct request;
struct bio;
struct xdev_ext_mech_pool;
struct xdev_ext_mech_batch;

/* Worker: snapshot the current queue limits for a validated LBA shift. */
struct xdev_ext_stor_queue_caps
xdev_ext_stor_block_caps(struct request_queue *queue, __u8 lba_shift);

/* Worker: return the positive page-piece count, or -errno, without mapping. */
int xdev_ext_stor_block_preflight(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch,
		const struct xdev_ext_stor_queue_caps *caps);

/* Worker, after preflight of the same exclusively owned batch: add its pages
 * to the caller-initialized bio and append it to request. All arguments are
 * borrowed synchronously; the caller retains bio init/uninit and ownership.
 */
int xdev_ext_stor_block_append(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch, struct request *request,
		struct bio *bio);

#endif

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

#ifdef CONFIG_BLOCK
#include <linux/blk_types.h>

struct xdev_ext_stor_completion;

/* CREATE: require an existing hardware poll queue, without IRQ fallback. */
bool xdev_ext_stor_block_poll_capable(const struct request_queue *queue);

static inline blk_opf_t xdev_ext_stor_block_poll_opf(bool poll, blk_opf_t opf)
{
	return poll ? opf | REQ_POLLED : opf;
}

/* Worker: check the allocated request before claiming or mapping a slot. */
int xdev_ext_stor_block_poll_check(bool poll, struct request *request);

/* Worker: arm after the completion context and end_io_data are ready. */
void xdev_ext_stor_block_poll_arm(bool poll, struct request *request,
		struct xdev_ext_stor_completion *done);

/* Borrowed slot array: first is the first embedded completion, stride is
 * sizeof the owning slot. Empty views may have first == NULL.
 */
struct xdev_ext_stor_poll_view {
	struct xdev_ext_stor_completion *first;
	size_t stride;
	__u32 count;
};

/* Worker: one queue-number pass over all views, without retaining requests. */
int xdev_ext_stor_block_poll(struct request_queue *queue,
		const struct xdev_ext_stor_poll_view *views, __u32 nr_views);
#endif

#endif

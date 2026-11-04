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
#include <linux/atomic.h>
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

struct pci_dev;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_stage_uapi;
struct xdev_ext_stor_stage;

struct xdev_ext_stor_geometry {
	__u64 capacity_lbas;
	__u8 lba_shift;
};

/* Native member boundaries consumed by the block family runtime. */
struct xdev_ext_stor_dev_ops {
	int (*bind)(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u,
		struct xdev_ext_stor_stage **family, void **member);
	void (*unbind)(void *member);
	int (*identity)(void *member, bool final,
		struct xdev_ext_stor_geometry *geometry);
	struct pci_dev *(*requester)(void *member);
	struct request_queue *(*queue)(void *member);
	int (*decode)(void *member, struct xdev_ext_mech_batch *batch,
		const __u8 sqe[64], const struct xdev_ext_stor_window *window,
		__u32 bytes, struct xdev_ext_stor_rw *rw);
	int (*poll)(void *member, const struct xdev_ext_stor_poll_view *views,
		__u32 nr_views);
};

/* Native container and stage file pin the member and borrowed slot arrays.
 * In 7A the member still owns those arrays and clears a view before freeing it.
 */
struct xdev_ext_stor_stage {
	struct xdev_ext_mech_stage *st;
	const struct xdev_ext_stor_dev_ops *dev;
	void *member;
	struct xdev_ext_stor_window window;
	struct xdev_ext_stor_geometry geometry;
	atomic_t dead;
	struct xdev_ext_stor_poll_view poll_views[2];
};

struct xdev_ext_stor_batch {
	__u8 sqe[64];
	struct xdev_ext_stor_rw rw;
	__u64 batch_id;
	bool validated;
};

/* CREATE: publish st->priv as the native member only after binding its window. */
int xdev_ext_storfam_bind(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u,
		const struct xdev_ext_stor_dev_ops *dev);
int xdev_ext_storfam_validate(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *batch, struct xdev_ext_stor_batch *sb,
		const __u8 scratch[64], __u32 nr_slots);
int xdev_ext_storfam_submit_check(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *batch, struct xdev_ext_stor_batch *sb);
int xdev_ext_storfam_poll(struct xdev_ext_stor_stage *ss);
void xdev_ext_storfam_mark_dead(struct xdev_ext_stor_stage *ss);

/* Worker: one queue-number pass over all views, without retaining requests. */
int xdev_ext_stor_block_poll(struct request_queue *queue,
		const struct xdev_ext_stor_poll_view *views, __u32 nr_views);
#endif

#endif

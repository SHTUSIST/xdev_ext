/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KV_RESTORE_USER_H
#define KV_RESTORE_USER_H
/*
 * User-space continuation of the E5 user modes (kv_restore --dst user-copy /
 * user-direct).  The session's USER stage hands each received group (one
 * batch of host frames of the ring's UMEM) to this loop, which copies it to
 * the GPU allocation at dst_base + (key - first_key) * group_bytes:
 *
 *   user-copy    memcpy of the frames into pinned staging slot s, the frames
 *                go back at once, then one asynchronous host-to-device copy
 *                of the slot; slot s is reused only after its copy completed.
 *   user-direct  asynchronous host-to-device copies straight from the frames
 *                (registered once with CUDA), one per physically contiguous
 *                run; the frames go back only after the copy completed.
 *
 * Up to depth groups are in flight, the session's own depth.  When no new
 * group is ready, or every slot is busy, the loop blocks on the oldest copy
 * instead of polling.  On any error it stops taking groups, waits for every
 * copy in flight, returns every held batch and reports the first error.
 * The operations are callbacks so the loop runs on the host without a GPU
 * (test_kv_user.c); kv_restore.c binds them to libxdev_ext and the CUDA driver.
 *
 * Include libxdev_ext.h before this header.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

struct kv_user_ops {
	/* 0 with *b filled, -EAGAIN (timeout 0: nothing ready), other -errno */
	int (*next)(void *ctx, int timeout_ms, struct xdev_ext_user_batch *b);
	int (*complete)(void *ctx, const struct xdev_ext_user_batch *b, int status);
	/* asynchronous copy on the stream, attributed to slot */
	int (*h2d)(void *ctx, uint32_t slot, uint64_t dst, const void *src, size_t len);
	int (*record)(void *ctx, uint32_t slot);	/* event after slot's copies */
	int (*query)(void *ctx, uint32_t slot);		/* 0 done, -EAGAIN pending */
	int (*wait)(void *ctx, uint32_t slot);		/* block until done */
};

struct kv_user_pipe {
	void *ctx;
	bool direct;
	uint32_t depth, group_bytes;
	uint8_t *staging;			/* user-copy: depth * group_bytes, pinned */
	struct xdev_ext_user_batch *held;	/* user-direct: depth entries */
	uint64_t dst_base, first_key, groups;
	int timeout_ms;
	/* results */
	uint64_t handed, retired, copied, copies;
};

/* The group is whole and its key belongs to this restore. */
static inline int kv_user_check(const struct kv_user_pipe *p, const struct xdev_ext_user_batch *b)
{
	uint64_t bytes = 0;

	if (!b->nr_frames || b->nr_frames > XDEV_EXT_MECH_MAX_FRAMES ||
	    b->key < p->first_key || b->key - p->first_key >= p->groups)
		return -EPROTO;
	for (uint32_t i = 0; i < b->nr_frames; i++) {
		if (!b->f[i].data_len || b->f[i].data_len > b->f[i].capacity)
			return -EPROTO;
		bytes += b->f[i].data_len;
	}
	return bytes == p->group_bytes ? 0 : -EPROTO;
}

/* Retire the oldest group: its copy completed; user-direct returns its frames. */
static inline int kv_user_retire(struct kv_user_pipe *p, const struct kv_user_ops *o, bool block)
{
	uint32_t s = (uint32_t)(p->retired % p->depth);
	int r = block ? o->wait(p->ctx, s) : o->query(p->ctx, s), c = 0;

	if (r == -EAGAIN && !block)
		return -EAGAIN;
	if (p->direct)
		c = o->complete(p->ctx, &p->held[s], r);
	p->retired++;
	return r ? r : c;
}

static inline int kv_user_issue(struct kv_user_pipe *p, const struct kv_user_ops *o,
				const struct xdev_ext_user_batch *b)
{
	uint32_t s = (uint32_t)(p->handed % p->depth);
	uint64_t dst;
	int r = kv_user_check(p, b);

	if (r) {
		o->complete(p->ctx, b, r);
		return r;
	}
	dst = p->dst_base + (b->key - p->first_key) * p->group_bytes;
	if (!p->direct) {
		uint8_t *slot = p->staging + (uint64_t)s * p->group_bytes;
		uint32_t off = 0;

		for (uint32_t i = 0; i < b->nr_frames; i++) {
			memcpy(slot + off, b->data[i], b->f[i].data_len);
			off += b->f[i].data_len;
		}
		p->copied += off;
		r = o->complete(p->ctx, b, 0);
		if (!r) {
			r = o->h2d(p->ctx, s, dst, slot, off);
			p->copies += !r;
		}
	} else {
		const uint8_t *run = b->data[0];
		size_t len = b->f[0].data_len;

		p->held[s] = *b;
		for (uint32_t i = 1; !r && i <= b->nr_frames; i++) {
			if (i < b->nr_frames && (const uint8_t *)b->data[i] == run + len) {
				len += b->f[i].data_len;
				continue;
			}
			r = o->h2d(p->ctx, s, dst, run, len);
			p->copies += !r;
			dst += len;
			if (i < b->nr_frames) {
				run = b->data[i];
				len = b->f[i].data_len;
			}
		}
	}
	if (!r)
		r = o->record(p->ctx, s);
	if (r) {
		/* Copies already queued for this slot finish before anything is reused. */
		o->record(p->ctx, s);
		o->wait(p->ctx, s);
		if (p->direct)
			o->complete(p->ctx, b, r);
		return r;
	}
	p->handed++;
	return 0;
}

static inline int kv_user_run(struct kv_user_pipe *p, const struct kv_user_ops *o)
{
	int err = 0;

	if (!p->depth || !p->group_bytes || (p->direct ? !p->held : !p->staging))
		return -EINVAL;
	p->handed = p->retired = p->copied = p->copies = 0;
	while (!err && p->retired < p->groups) {
		uint64_t inflight = p->handed - p->retired;

		if (p->handed < p->groups && inflight < p->depth) {
			struct xdev_ext_user_batch b;
			int r = o->next(p->ctx, inflight ? 0 : p->timeout_ms, &b);

			if (!r) {
				err = kv_user_issue(p, o, &b);
				/* Return what already finished, without waiting. */
				while (!err && p->retired < p->handed) {
					r = kv_user_retire(p, o, false);
					if (r == -EAGAIN)
						break;
					err = r;
				}
				continue;
			}
			if (r != -EAGAIN)
				err = r;
			else if (!inflight)
				err = -ETIMEDOUT;
			if (err)
				break;
		}
		/* Nothing new is ready, or every slot is busy: block on the oldest. */
		err = kv_user_retire(p, o, true);
	}
	while (p->retired < p->handed) {
		int r = kv_user_retire(p, o, true);

		if (!err)
			err = r;
	}
	return err;
}

#endif /* KV_RESTORE_USER_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_NETFAM_COUNT_H
#define _LINUX_XDEV_EXT_NETFAM_COUNT_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>
#endif

/* All cursors and entries are protected by the caller's lock; capacity is
 * a power of two. Native entries form a FIFO independent of DONE holes.
 * Descriptor storage, device custody and callbacks belong to the caller.
 */
enum xdev_ext_net_count_state {
	XDEV_EXT_NET_COUNT_PENDING = 0,
	XDEV_EXT_NET_COUNT_NATIVE = 1,
	XDEV_EXT_NET_COUNT_DONE = 2,
};

#define XDEV_EXT_NET_COUNT_NONE ((__u32)-1)
#define XDEV_EXT_NET_COUNT_BATCH_TRACKING 1

struct xdev_ext_net_count_batch {
	__u32 pending;
	int status;
	bool uncertain;
};

struct xdev_ext_net_count_entry {
	__s32 result;
	__u32 native_prev, native_next;
	__u8 state, tag;
};

struct xdev_ext_net_count_ring {
	__u32 prod, issued, cons, capacity;
	__u32 native_head, native_tail, native_count;
	int fatal;
};

/* Trusted, aligned metadata subobjects in one live caller-owned allocation.
 * first names entry zero; stride is the size of its enclosing slot.
 */
struct xdev_ext_net_count_view {
	void *first;
	size_t stride;
};

static inline struct xdev_ext_net_count_entry *
xdev_ext_net_count_entry(struct xdev_ext_net_count_view v, __u32 at)
{
	return (struct xdev_ext_net_count_entry *)
		((unsigned char *)v.first + (size_t)at * v.stride);
}

static inline void xdev_ext_net_count_fail(struct xdev_ext_net_count_ring *r,
					 int result)
{
	if (result && !r->fatal)
		r->fatal = result < 0 && result != -EAGAIN ? result : -EIO;
}

static inline int xdev_ext_net_count_reserve(struct xdev_ext_net_count_ring *r,
					   __u32 n, __u32 *start)
{
	if (r->fatal)
		return r->fatal;
	if (!n || n > r->capacity - (r->prod - r->cons))
		return -EAGAIN;
	*start = r->prod;
	r->prod += n;
	return 0;
}

/* Only before publication, under the uninterrupted reservation lock. */
static inline void xdev_ext_net_count_rollback(struct xdev_ext_net_count_ring *r,
					     __u32 start)
{
	r->prod = start;
}

static inline int xdev_ext_net_count_peek(struct xdev_ext_net_count_ring *r,
					struct xdev_ext_net_count_view v)
{
	struct xdev_ext_net_count_entry *e;
	__u32 at;

	if (r->fatal || r->issued == r->prod)
		return -ENOENT;
	at = r->issued++ & (r->capacity - 1);
	e = xdev_ext_net_count_entry(v, at);
	e->state = XDEV_EXT_NET_COUNT_NATIVE;
	e->native_prev = r->native_count ? r->native_tail : XDEV_EXT_NET_COUNT_NONE;
	e->native_next = XDEV_EXT_NET_COUNT_NONE;
	if (r->native_count)
		xdev_ext_net_count_entry(v, r->native_tail)->native_next = at;
	else
		r->native_head = at;
	r->native_tail = at;
	r->native_count++;
	return at;
}

/* Stop admission at the first error without retiring native ownership. */
static inline void xdev_ext_net_count_set_result(struct xdev_ext_net_count_ring *r,
					       struct xdev_ext_net_count_view v,
					       __u32 at, int result)
{
	struct xdev_ext_net_count_entry *e = xdev_ext_net_count_entry(v, at);

	if (e->state != XDEV_EXT_NET_COUNT_NATIVE)
		return;
	if (!e->result)
		e->result = result;
	xdev_ext_net_count_fail(r, result);
}

/* PENDING and repeated DONE transitions are no-ops. */
static inline void xdev_ext_net_count_mark_done(struct xdev_ext_net_count_ring *r,
					      struct xdev_ext_net_count_view v,
					      __u32 at)
{
	struct xdev_ext_net_count_entry *e = xdev_ext_net_count_entry(v, at);
	__u32 prev, next;

	if (e->state != XDEV_EXT_NET_COUNT_NATIVE)
		return;
	prev = e->native_prev;
	next = e->native_next;
	if (prev == XDEV_EXT_NET_COUNT_NONE)
		r->native_head = next;
	else
		xdev_ext_net_count_entry(v, prev)->native_next = next;
	if (next == XDEV_EXT_NET_COUNT_NONE)
		r->native_tail = prev;
	else
		xdev_ext_net_count_entry(v, next)->native_prev = prev;
	r->native_count--;
	e->state = XDEV_EXT_NET_COUNT_DONE;
	e->native_prev = e->native_next = XDEV_EXT_NET_COUNT_NONE;
}

static inline __u32
xdev_ext_net_count_native(const struct xdev_ext_net_count_ring *r)
{
	return r->native_count;
}

static inline int
xdev_ext_net_count_head(const struct xdev_ext_net_count_ring *r)
{
	return r->native_count ? (int)r->native_head : -ENOENT;
}

static inline int xdev_ext_net_count_tail(const struct xdev_ext_net_count_ring *r,
					struct xdev_ext_net_count_view v, __u32 n)
{
	__u32 at = r->native_tail;

	if (n >= r->native_count)
		return -ENOENT;
	while (n--)
		at = xdev_ext_net_count_entry(v, at)->native_prev;
	return at;
}

static inline void xdev_ext_net_count_reclaim(struct xdev_ext_net_count_ring *r,
					    struct xdev_ext_net_count_view v)
{
	while (r->cons != r->issued &&
	       xdev_ext_net_count_entry(v, r->cons & (r->capacity - 1))->state ==
			XDEV_EXT_NET_COUNT_DONE)
		r->cons++;
}

/* The caller has retired every never-issued entry before ending the suffix. */
static inline void xdev_ext_net_count_pending_end(struct xdev_ext_net_count_ring *r,
						struct xdev_ext_net_count_view v)
{
	r->issued = r->prod;
	xdev_ext_net_count_reclaim(r, v);
}

/* The caller has retired outstanding entries; UNKNOWN custody stays external. */
static inline void xdev_ext_net_count_stop_end(struct xdev_ext_net_count_ring *r)
{
	r->cons = r->issued = r->prod;
}

/* An accepted retry errno is terminal: the admitted bytes must not be replayed.
 * The caller owns uncertainty and dispatches only the last-entry completion.
 */
static inline bool
xdev_ext_net_count_retire_result(struct xdev_ext_net_count_batch *b,
				int result, __s32 *out)
{
	if (!b->pending)
		return false;
	if (result == -EAGAIN)
		result = -EIO;
	*out = result;
	if (result && !b->status)
		b->status = result;
	return !--b->pending;
}

#endif

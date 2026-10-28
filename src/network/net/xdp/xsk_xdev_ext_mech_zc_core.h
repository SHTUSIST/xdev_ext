/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XSK_XDEV_EXT_MECH_ZC_CORE_H
#define _XSK_XDEV_EXT_MECH_ZC_CORE_H
#include "xsk_xdev_ext_mech_tx_core.h"

/* Kernel descriptors have a separate producer and completion journal. All
 * cursors are protected by the provider lock; capacity is a power of two.
 * DONE holes from a rejected tail remain until earlier hardware completes.
 * NATIVE slots also form an intrusive doubly linked FIFO, independent of
 * those holes. Only peek and mark_done change FIFO membership.
 */
#define XSK_MECH_ZC_BATCH_TRACKING 1
struct xsk_mech_zc_batch {
	__u32 pending;
	int status;
	bool uncertain;
};
/* The batch can leave IN_FLIGHT exactly once, after its last frame. A retry
 * errno after acceptance becomes a permanent error: these bytes must never
 * be resent merely because the driver failed an accepted descriptor.
 */
static inline bool xsk_mech_zc_retire_result(struct xsk_mech_zc_batch *b,
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

enum xsk_mech_zc_state {
	XSK_MECH_ZC_PENDING,
	XSK_MECH_ZC_NATIVE,
	XSK_MECH_ZC_DONE,
};
enum xsk_mech_zc_owner { XSK_MECH_ZC_DATA, XSK_MECH_ZC_CONTROL };
struct xsk_mech_zc_slot {
	struct xdp_desc desc;
	void *batch;
	__u32 slot;
	__s32 result;
	__u32 native_prev, native_next;
	__u8 state, owner;
};
struct xsk_mech_zc_ring {
	__u32 prod, issued, cons, capacity;
	__u32 native_head, native_tail, native_count;
	int fatal;
};
#define XSK_MECH_ZC_NONE ((__u32)-1)
static inline void xsk_mech_zc_fail(struct xsk_mech_zc_ring *r, int result)
{
	if (result && !r->fatal)
		r->fatal = result < 0 && result != -EAGAIN ? result : -EIO;
}
/* A count completion can report one descriptor before its batch is done.
 * Stop admission at that first error, while retaining all native ownership. */
static inline void xsk_mech_zc_set_result(struct xsk_mech_zc_ring *r,
					struct xsk_mech_zc_slot *s,
					__u32 at, int result)
{
	if (s[at].state != XSK_MECH_ZC_NATIVE)
		return;
	if (!s[at].result)
		s[at].result = result;
	xsk_mech_zc_fail(r, result);
}
static inline int xsk_mech_zc_reserve(struct xsk_mech_zc_ring *r, __u32 n,
				    __u32 *start)
{
	if (r->fatal)
		return r->fatal;
	if (!n || n > r->capacity - (r->prod - r->cons))
		return -EAGAIN;
	*start = r->prod;
	r->prod += n;
	return 0;
}
static inline int xsk_mech_zc_peek(struct xsk_mech_zc_ring *r,
				 struct xsk_mech_zc_slot *s)
{
	__u32 at;

	if (r->fatal || r->issued == r->prod)
		return -ENOENT;
	at = r->issued++ & (r->capacity - 1);
	s[at].state = XSK_MECH_ZC_NATIVE;
	s[at].native_prev = r->native_count ? r->native_tail : XSK_MECH_ZC_NONE;
	s[at].native_next = XSK_MECH_ZC_NONE;
	if (r->native_count)
		s[r->native_tail].native_next = at;
	else
		r->native_head = at;
	r->native_tail = at;
	r->native_count++;
	return at;
}
/* Provider lock held. PENDING and repeated DONE transitions are no-ops. */
static inline void xsk_mech_zc_mark_done(struct xsk_mech_zc_ring *r,
				       struct xsk_mech_zc_slot *s, __u32 at)
{
	__u32 prev, next;

	if (s[at].state != XSK_MECH_ZC_NATIVE)
		return;
	prev = s[at].native_prev;
	next = s[at].native_next;
	if (prev == XSK_MECH_ZC_NONE)
		r->native_head = next;
	else
		s[prev].native_next = next;
	if (next == XSK_MECH_ZC_NONE)
		r->native_tail = prev;
	else
		s[next].native_prev = prev;
	r->native_count--;
	s[at].state = XSK_MECH_ZC_DONE;
	s[at].native_prev = s[at].native_next = XSK_MECH_ZC_NONE;
}
static inline __u32 xsk_mech_zc_native(const struct xsk_mech_zc_ring *r,
				      const struct xsk_mech_zc_slot *s)
{
	(void)s;
	return r->native_count;
}
static inline int xsk_mech_zc_tail(const struct xsk_mech_zc_ring *r,
				 const struct xsk_mech_zc_slot *s, __u32 n)
{
	__u32 at = r->native_tail;

	if (n >= r->native_count)
		return -ENOENT;
	while (n--)
		at = s[at].native_prev;
	return at;
}
static inline int xsk_mech_zc_complete(const struct xsk_mech_zc_ring *r,
				     const struct xsk_mech_zc_slot *s)
{
	(void)s;
	return r->native_count ? (int)r->native_head : -ENOENT;
}
static inline void xsk_mech_zc_reclaim(struct xsk_mech_zc_ring *r,
				      struct xsk_mech_zc_slot *s)
{
	while (r->cons != r->issued &&
	       s[r->cons & (r->capacity - 1)].state == XSK_MECH_ZC_DONE)
		r->cons++;
}
#endif

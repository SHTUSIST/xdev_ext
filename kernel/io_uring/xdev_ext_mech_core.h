/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_CORE_H
#define IO_URING_XDEV_EXT_MECH_CORE_H

/*
 * Pure rules of the XDEV_EXT mechanism layer: frame ownership words, the batch
 * state machine, descriptor slot and span checks, RX grouping, session
 * reference and teardown rules, callback return legality, RETRY limits and
 * the NXP CRC convention.  No locking and no allocation here; the kernel and
 * tools/testing/selftests/xdev_ext_mech compile the same code.
 */

#ifdef __KERNEL__
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/overflow.h>
#include <linux/types.h>
#include <linux/xdev_ext_mech.h>

#define XDEV_EXT_MECH_U32_MAX		U32_MAX
#define XDEV_EXT_MECH_U64_MAX		U64_MAX
#define XDEV_EXT_MECH_LOAD_U8(p)		READ_ONCE(*(p))
#define XDEV_EXT_MECH_CAS_U8(p, old, new)	try_cmpxchg(p, old, new)
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/types.h>
#include "../include/linux/xdev_ext_mech.h"

#ifndef check_add_overflow
#define check_add_overflow(a, b, d)	__builtin_add_overflow(a, b, d)
#endif
#define XDEV_EXT_MECH_U32_MAX		UINT32_MAX
#define XDEV_EXT_MECH_U64_MAX		UINT64_MAX
#define XDEV_EXT_MECH_LOAD_U8(p)		__atomic_load_n(p, __ATOMIC_RELAXED)
#define XDEV_EXT_MECH_CAS_U8(p, old, new)					\
	__atomic_compare_exchange_n(p, old, new, false, __ATOMIC_SEQ_CST, \
				    __ATOMIC_SEQ_CST)
#endif

#define XDEV_EXT_MECH_ERRNO_MAX		4095

/*
 * Frame ownership edges (enum xdev_ext_mech_frame_state, linux/xdev_ext_mech.h).  Every
 * change is a compare-and-exchange of a legal edge, so two owners can never
 * both win the same frame.
 */
static inline bool xdev_ext_mech_frame_edge_ok(__u32 from, __u32 to)
{
	if (to >= XDEV_EXT_MECH_F_NR)
		return false;
	switch (from) {
	case XDEV_EXT_MECH_F_USER:		/* START user frames, RX recycle; RX hold */
		return to == XDEV_EXT_MECH_F_K_FREE || to == XDEV_EXT_MECH_F_HELD ||
		       to == XDEV_EXT_MECH_F_NIC_RX;
	case XDEV_EXT_MECH_F_K_FREE:		/* source alloc or RX hold; RX publish */
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_USER ||
		       to == XDEV_EXT_MECH_F_NIC_RX;
	case XDEV_EXT_MECH_F_NIC_RX:		/* original ZC RX buffer */
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_K_FREE ||
		       to == XDEV_EXT_MECH_F_USER || to == XDEV_EXT_MECH_F_SEQUESTERED;
	case XDEV_EXT_MECH_F_HELD:		/* submit; release; failed ownership invariant */
		return to == XDEV_EXT_MECH_F_INFLIGHT || to == XDEV_EXT_MECH_F_K_FREE ||
		       to == XDEV_EXT_MECH_F_USER || to == XDEV_EXT_MECH_F_SEQUESTERED;
	case XDEV_EXT_MECH_F_INFLIGHT:	/* native completion; ambiguous or timed out */
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_SEQUESTERED;
	default:			/* SEQUESTERED has no way out */
		return false;
	}
}

/* Any context; ordering for an ownership change comes from the CAS. */
static inline __u8 xdev_ext_mech_frame_state(const __u8 *word)
{
	return XDEV_EXT_MECH_LOAD_U8(word);
}

/* Any context: 0, -EINVAL for an illegal edge, -EBUSY if @word is not @from. */
static inline int xdev_ext_mech_frame_move(__u8 *word, __u32 from, __u32 to)
{
	__u8 old = (__u8)from;

	if (!xdev_ext_mech_frame_edge_ok(from, to))
		return -EINVAL;
	return XDEV_EXT_MECH_CAS_U8(word, &old, (__u8)to) ? 0 : -EBUSY;
}

/*
 * Page bytes of frames, for proving once at CREATE that reserved output
 * frames share no byte with any other frame.  The caller owns the table;
 * @page is compared, never dereferenced.
 */
struct xdev_ext_mech_alias_seg {
	const void *page;
	__u32 off;
	__u32 len;
};

static inline bool xdev_ext_mech_alias_before(const struct xdev_ext_mech_alias_seg *a,
					 const struct xdev_ext_mech_alias_seg *b)
{
	if (a->page != b->page)
		return (uintptr_t)a->page < (uintptr_t)b->page;
	return a->off < b->off;
}

static inline void xdev_ext_mech_alias_sift(struct xdev_ext_mech_alias_seg *t,
				       size_t root, size_t n)
{
	for (;;) {
		struct xdev_ext_mech_alias_seg tmp;
		size_t child = 2 * root + 1;

		if (child >= n)
			return;
		if (child + 1 < n && xdev_ext_mech_alias_before(&t[child], &t[child + 1]))
			child++;
		if (!xdev_ext_mech_alias_before(&t[root], &t[child]))
			return;
		tmp = t[root];
		t[root] = t[child];
		t[child] = tmp;
		root = child;
	}
}

/* In place by (page, offset): O(n log n), bounded stack, no allocation. */
static inline void xdev_ext_mech_alias_sort(struct xdev_ext_mech_alias_seg *t, size_t n)
{
	struct xdev_ext_mech_alias_seg tmp;
	size_t i;

	if (n < 2)
		return;
	for (i = n / 2; i-- > 0;)
		xdev_ext_mech_alias_sift(t, i, n);
	for (i = n - 1; i > 0; i--) {
		tmp = t[0];
		t[0] = t[i];
		t[i] = tmp;
		xdev_ext_mech_alias_sift(t, 0, i);
	}
}

/* Sorted @t: true when two entries share a byte of one page. */
static inline bool xdev_ext_mech_alias_overlapping(const struct xdev_ext_mech_alias_seg *t,
					      size_t n)
{
	__u64 end = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		if (!i || t[i].page != t[i - 1].page)
			end = 0;
		else if (t[i].off < end)
			return true;
		if ((__u64)t[i].off + t[i].len > end)
			end = (__u64)t[i].off + t[i].len;
	}
	return false;
}

/*
 * Sorted @t without overlaps, so ends grow with offsets within a page:
 * true when bytes [@off, @off + @len) of @page meet an entry.
 */
static inline bool xdev_ext_mech_alias_hits(const struct xdev_ext_mech_alias_seg *t,
				       size_t n, const void *page, __u32 off,
				       __u32 len)
{
	size_t lo = 0, hi = n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if ((uintptr_t)t[mid].page < (uintptr_t)page ||
		    (t[mid].page == page && (__u64)t[mid].off + t[mid].len <= off))
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < n && t[lo].page == page && t[lo].off < (__u64)off + len;
}

/*
 * Batch: FREE -> OPEN (RX grouping) -> READY(k) -> IN_FLIGHT(k) ->
 * READY(k + 1) ... -> DONE, with ABORT from any live state and SEQUESTERED
 * from IN_FLIGHT.  A START batch goes FREE -> READY(0) directly.  At most
 * one stage is in flight at any time.  The owner serializes the steps.
 */
enum xdev_ext_mech_batch_state {
	XDEV_EXT_MECH_B_FREE		= 0,
	XDEV_EXT_MECH_B_OPEN,
	XDEV_EXT_MECH_B_READY,
	XDEV_EXT_MECH_B_IN_FLIGHT,
	XDEV_EXT_MECH_B_DONE,
	XDEV_EXT_MECH_B_ABORT,
	XDEV_EXT_MECH_B_SEQUESTERED,	/* terminal: frames stay sequestered */
	XDEV_EXT_MECH_B_NR,
};

enum xdev_ext_mech_batch_event {
	XDEV_EXT_MECH_EV_OPEN	= 0,	/* FREE -> OPEN */
	XDEV_EXT_MECH_EV_READY,		/* FREE or OPEN -> READY(arg) */
	XDEV_EXT_MECH_EV_SUBMIT,		/* READY(k) -> IN_FLIGHT(k) */
	XDEV_EXT_MECH_EV_NEXT,		/* IN_FLIGHT(k) -> READY(k + 1), or DONE after the last */
	XDEV_EXT_MECH_EV_RETRY,		/* IN_FLIGHT(k) -> READY(k) */
	XDEV_EXT_MECH_EV_DONE,		/* IN_FLIGHT -> DONE */
	XDEV_EXT_MECH_EV_ABORT,		/* OPEN, READY or IN_FLIGHT -> ABORT */
	XDEV_EXT_MECH_EV_SEQUESTER,		/* IN_FLIGHT -> SEQUESTERED */
	XDEV_EXT_MECH_EV_RELEASE,		/* DONE or ABORT -> FREE */
};

struct xdev_ext_mech_bstate {
	__u8 state;		/* enum xdev_ext_mech_batch_state */
	__u8 stage;		/* stage index while READY or IN_FLIGHT */
	__u8 nr_stages;
	__u8 retries;		/* RETRY edges taken at this stage */
};

static inline void xdev_ext_mech_bstate_init(struct xdev_ext_mech_bstate *b,
					__u32 nr_stages)
{
	b->state = XDEV_EXT_MECH_B_FREE;
	b->stage = 0;
	b->nr_stages = nr_stages > 255 ? 255 : (__u8)nr_stages;
	b->retries = 0;
}

/* Returns 0 after a legal step, -EINVAL and no change otherwise. */
static inline int xdev_ext_mech_batch_step(struct xdev_ext_mech_bstate *b, __u32 ev,
				      __u32 arg)
{
	if (!b->nr_stages || b->nr_stages > XDEV_EXT_MECH_MAX_STAGES)
		return -EINVAL;

	switch (ev) {
	case XDEV_EXT_MECH_EV_OPEN:
		if (b->state != XDEV_EXT_MECH_B_FREE)
			return -EINVAL;
		b->state = XDEV_EXT_MECH_B_OPEN;
		return 0;
	case XDEV_EXT_MECH_EV_READY:
		if ((b->state != XDEV_EXT_MECH_B_FREE && b->state != XDEV_EXT_MECH_B_OPEN) ||
		    arg >= b->nr_stages)
			return -EINVAL;
		b->state = XDEV_EXT_MECH_B_READY;
		b->stage = (__u8)arg;
		b->retries = 0;
		return 0;
	case XDEV_EXT_MECH_EV_SUBMIT:
		if (b->state != XDEV_EXT_MECH_B_READY)
			return -EINVAL;
		b->state = XDEV_EXT_MECH_B_IN_FLIGHT;
		return 0;
	case XDEV_EXT_MECH_EV_NEXT:
		if (b->state != XDEV_EXT_MECH_B_IN_FLIGHT)
			return -EINVAL;
		if (b->stage + 1 < b->nr_stages) {
			b->state = XDEV_EXT_MECH_B_READY;
			b->stage++;
			b->retries = 0;
		} else {
			b->state = XDEV_EXT_MECH_B_DONE;
		}
		return 0;
	case XDEV_EXT_MECH_EV_RETRY:
		if (b->state != XDEV_EXT_MECH_B_IN_FLIGHT)
			return -EINVAL;
		b->state = XDEV_EXT_MECH_B_READY;
		if (b->retries < 255)
			b->retries++;
		return 0;
	case XDEV_EXT_MECH_EV_DONE:
		if (b->state != XDEV_EXT_MECH_B_IN_FLIGHT)
			return -EINVAL;
		b->state = XDEV_EXT_MECH_B_DONE;
		return 0;
	case XDEV_EXT_MECH_EV_ABORT:
		if (b->state != XDEV_EXT_MECH_B_OPEN && b->state != XDEV_EXT_MECH_B_READY &&
		    b->state != XDEV_EXT_MECH_B_IN_FLIGHT)
			return -EINVAL;
		b->state = XDEV_EXT_MECH_B_ABORT;
		return 0;
	case XDEV_EXT_MECH_EV_SEQUESTER:
		if (b->state != XDEV_EXT_MECH_B_IN_FLIGHT)
			return -EINVAL;
		b->state = XDEV_EXT_MECH_B_SEQUESTERED;
		return 0;
	case XDEV_EXT_MECH_EV_RELEASE:
		if (b->state != XDEV_EXT_MECH_B_DONE && b->state != XDEV_EXT_MECH_B_ABORT)
			return -EINVAL;
		b->state = XDEV_EXT_MECH_B_FREE;
		b->stage = 0;
		b->retries = 0;
		return 0;
	default:
		return -EINVAL;
	}
}

/*
 * Scratch slots used by a callback: a slot is used when any of its bytes is
 * non-zero (C zeroes the scratch before the callback).  Used slots start at
 * slot 0 and are contiguous; a used slot after an unused one is -EPROTO.
 */
static inline int xdev_ext_mech_slots_used(const __u8 *scratch, __u32 desc_size,
				      __u32 desc_cap)
{
	__u32 slot, i;
	int used = 0;
	bool gap = false;

	if (!desc_size)
		return -EINVAL;
	for (slot = 0; slot < desc_cap; slot++) {
		const __u8 *d = scratch + (size_t)slot * desc_size;
		bool nonzero = false;

		for (i = 0; i < desc_size; i++)
			nonzero |= d[i] != 0;
		if (!nonzero) {
			gap = true;
			continue;
		}
		if (gap)
			return -EPROTO;
		used++;
	}
	return used;
}

/* [off, off + len) inside [0, cap), overflow-safe; an empty span may end at cap. */
static inline bool xdev_ext_mech_span_in(__u64 off, __u64 len, __u64 cap)
{
	__u64 end;

	return !check_add_overflow(off, len, &end) && end <= cap;
}

/* A non-empty [off, off + len) inside the window [base, base + size). */
static inline bool xdev_ext_mech_window_ok(__u64 off, __u64 len, __u64 base,
				      __u64 size)
{
	__u64 wend;

	if (!len || check_add_overflow(base, size, &wend) || off < base)
		return false;
	return xdev_ext_mech_span_in(off - base, len, size);
}

/* Two non-empty spans share a byte. */
static inline bool xdev_ext_mech_spans_overlap(__u64 a, __u64 alen, __u64 b,
					  __u64 blen)
{
	if (!alen || !blen)
		return false;
	return a < b ? b - a < alen : a - b < blen;
}

/* A non-empty span stays inside one @seg-aligned segment; @seg 0 is one segment. */
static inline bool xdev_ext_mech_span_one_segment(__u64 off, __u64 len, __u64 seg)
{
	__u64 last;

	if (!len || check_add_overflow(off, len - 1, &last))
		return false;
	return !seg || off / seg == last / seg;
}

/*
 * Exact, in-order coverage of a batch's data spans: each piece must start
 * where the previous one ended, in frame order, and stay in its frame's
 * span.  Covers frame-side entries of CE copy plans.
 */
struct xdev_ext_mech_cover {
	const struct xdev_ext_mech_frame_info *f;
	__u32 nr;
	__u32 pos;	/* frame being covered; nr once everything is covered */
	__u64 off;	/* next uncovered chunk offset in frame pos */
};

static inline void xdev_ext_mech_cover_skip(struct xdev_ext_mech_cover *c)
{
	while (c->pos < c->nr &&
	       c->off >= (__u64)c->f[c->pos].data_off + c->f[c->pos].data_len) {
		if (++c->pos < c->nr)
			c->off = c->f[c->pos].data_off;
	}
}

static inline void xdev_ext_mech_cover_init(struct xdev_ext_mech_cover *c,
				       const struct xdev_ext_mech_frame_info *f,
				       __u32 nr)
{
	c->f = f;
	c->nr = nr;
	c->pos = 0;
	c->off = nr ? f[0].data_off : 0;
	xdev_ext_mech_cover_skip(c);
}

/* 0, -EINVAL for a gap, overlap, wrong frame or empty piece, -ERANGE past the data. */
static inline int xdev_ext_mech_cover_take(struct xdev_ext_mech_cover *c, __u32 pos,
				      __u32 off, __u32 len)
{
	__u64 end = (__u64)off + len;

	if (c->pos >= c->nr)
		return -ERANGE;
	if (pos != c->pos || off != c->off || !len)
		return -EINVAL;
	if (end > (__u64)c->f[pos].data_off + c->f[pos].data_len)
		return -ERANGE;
	c->off = end;
	xdev_ext_mech_cover_skip(c);
	return 0;
}

static inline bool xdev_ext_mech_cover_done(const struct xdev_ext_mech_cover *c)
{
	return c->pos >= c->nr;
}

/*
 * Frames per batch for a session layout, or -EINVAL / -E2BIG.  Every frame
 * needs hdr_room + seg_len bytes of its chunk.
 */
static inline int xdev_ext_mech_layout_frames(const struct xdev_ext_mech_layout *l)
{
	__u32 need;

	if (!l->frame_size || !l->seg_len || !l->group_bytes ||
	    check_add_overflow(l->hdr_room, l->seg_len, &need) ||
	    need > l->frame_size)
		return -EINVAL;
	if ((l->group_bytes - 1) / l->seg_len + 1 > XDEV_EXT_MECH_MAX_FRAMES)
		return -E2BIG;
	return (int)((l->group_bytes - 1) / l->seg_len + 1);
}

/* Data span of frame @i of a source batch: after hdr_room, the last one short. */
static inline int xdev_ext_mech_layout_span(const struct xdev_ext_mech_layout *l,
				       __u32 i, __u32 *off, __u32 *len)
{
	int nr = xdev_ext_mech_layout_frames(l);

	if (nr < 0)
		return nr;
	if (i >= (__u32)nr)
		return -ERANGE;
	*off = l->hdr_room;
	*len = i + 1 < (__u32)nr ? l->seg_len :
				   l->group_bytes - (__u32)(nr - 1) * l->seg_len;
	return 0;
}

/*
 * AF_XDP RX hold intent against the received frame: frame pos of a batch of
 * count, payload [span_off, span_off + span_len) inside the packet bytes
 * [data_off, data_off + data_len) of its chunk.
 */
static inline int xdev_ext_mech_hold_check(__u32 pos, __u32 count, __u32 span_off,
				      __u32 span_len, __u32 data_off,
				      __u32 data_len)
{
	if (!count || count > XDEV_EXT_MECH_MAX_FRAMES || pos >= count || !span_len)
		return -EINVAL;
	if (span_off < data_off ||
	    (__u64)span_off + span_len > (__u64)data_off + data_len)
		return -ERANGE;
	return 0;
}

/* Frames held for one OPEN batch; the first hold fixes key and count. */
struct xdev_ext_mech_group {
	__u64 key;
	__u32 count;
	__u32 present;		/* bit pos set once that frame is held */
};

static inline void xdev_ext_mech_group_init(struct xdev_ext_mech_group *g, __u64 key,
				       __u32 count)
{
	g->key = key;
	g->count = count;
	g->present = 0;
}

/* 0, -EINVAL for another key, count or an out-of-range pos, -EEXIST for a duplicate. */
static inline int xdev_ext_mech_group_add(struct xdev_ext_mech_group *g, __u64 key,
				     __u32 pos, __u32 count)
{
	if (key != g->key || count != g->count ||
	    g->count > XDEV_EXT_MECH_MAX_FRAMES || pos >= g->count)
		return -EINVAL;
	if (g->present & (1U << pos))
		return -EEXIST;
	g->present |= 1U << pos;
	return 0;
}

static inline bool xdev_ext_mech_group_full(const struct xdev_ext_mech_group *g)
{
	if (!g->count || g->count > XDEV_EXT_MECH_MAX_FRAMES)
		return false;
	return g->present == (g->count == 32 ? ~0U : (1U << g->count) - 1);
}

/*
 * Session reference and teardown rules.  The creator holds one reference and
 * every batch in flight one more.  Only ACTIVE admits new batches.  A stop
 * never waits for the device under a lock: it moves to STOPPING, and drain
 * decides STOPPED (nothing in flight, nothing sequestered) or ZOMBIE (drain
 * timed out, or a batch was sequestered).  A ZOMBIE object lives until its
 * last batch completes, and its pool, region and module references are
 * parked in the quarantine instead of being released.
 */
struct xdev_ext_mech_sess {
	__u32 state;		/* enum xdev_ext_mech_session_state */
	__u32 refs;
	__u32 inflight;
	__u32 sequestered;	/* batches */
};

enum xdev_ext_mech_ref_fate {
	XDEV_EXT_MECH_REFS_KEEP	= 0,	/* still in use */
	XDEV_EXT_MECH_REFS_RELEASE	= 1,	/* drop pool, region and module references */
	XDEV_EXT_MECH_REFS_QUARANTINE = 2,	/* park them for good */
};

static inline void xdev_ext_mech_sess_init(struct xdev_ext_mech_sess *s)
{
	s->state = XDEV_EXT_MECH_SESSION_ACTIVE;
	s->refs = 1;
	s->inflight = 0;
	s->sequestered = 0;
}

static inline bool xdev_ext_mech_sess_admits(const struct xdev_ext_mech_sess *s)
{
	return s->state == XDEV_EXT_MECH_SESSION_ACTIVE;
}

static inline int xdev_ext_mech_sess_batch_begin(struct xdev_ext_mech_sess *s)
{
	if (!xdev_ext_mech_sess_admits(s))
		return -ESHUTDOWN;
	if (s->refs == XDEV_EXT_MECH_U32_MAX)
		return -EOVERFLOW;
	s->refs++;
	s->inflight++;
	return 0;
}

/* A batch left flight; true when that dropped the last reference. */
static inline bool xdev_ext_mech_sess_batch_end(struct xdev_ext_mech_sess *s,
					   bool sequestered)
{
	if (!s->inflight || !s->refs)
		return false;
	s->inflight--;
	if (sequestered) {
		s->sequestered++;
		if (s->state == XDEV_EXT_MECH_SESSION_ACTIVE)
			s->state = XDEV_EXT_MECH_SESSION_ERROR;
	}
	return --s->refs == 0;
}

/*
 * A stop in NONE (CREATE still binding) is kept too: the activation that
 * follows fails.
 */
static inline int xdev_ext_mech_sess_stop(struct xdev_ext_mech_sess *s)
{
	if (s->state != XDEV_EXT_MECH_SESSION_NONE &&
	    s->state != XDEV_EXT_MECH_SESSION_ACTIVE &&
	    s->state != XDEV_EXT_MECH_SESSION_ERROR)
		return -EALREADY;
	s->state = XDEV_EXT_MECH_SESSION_STOPPING;
	return 0;
}

/* End of CREATE: NONE -> ACTIVE, once. */
static inline int xdev_ext_mech_sess_activate(struct xdev_ext_mech_sess *s)
{
	if (s->state != XDEV_EXT_MECH_SESSION_NONE)
		return -ESHUTDOWN;
	s->state = XDEV_EXT_MECH_SESSION_ACTIVE;
	return 0;
}

/* STOPPING only: the state teardown moves to, or STOPPING to keep waiting. */
static inline int xdev_ext_mech_sess_drain(struct xdev_ext_mech_sess *s, bool timed_out)
{
	if (s->state != XDEV_EXT_MECH_SESSION_STOPPING)
		return -EINVAL;
	if (!s->inflight && !s->sequestered)
		s->state = XDEV_EXT_MECH_SESSION_STOPPED;
	else if (timed_out || !s->inflight)
		s->state = XDEV_EXT_MECH_SESSION_ZOMBIE;
	return (int)s->state;
}

static inline int xdev_ext_mech_sess_ref_fate(const struct xdev_ext_mech_sess *s)
{
	switch (s->state) {
	case XDEV_EXT_MECH_SESSION_STOPPED:
		return XDEV_EXT_MECH_REFS_RELEASE;
	case XDEV_EXT_MECH_SESSION_ZOMBIE:
		return XDEV_EXT_MECH_REFS_QUARANTINE;
	default:
		return XDEV_EXT_MECH_REFS_KEEP;
	}
}

/* Drop the creator reference; true when it was the last one. */
static inline bool xdev_ext_mech_sess_put(struct xdev_ext_mech_sess *s)
{
	if (!s->refs)
		return false;
	return --s->refs == 0;
}

/*
 * The quarantine only ever grows: there is deliberately no operation that
 * gives a parked reference or frame back.
 */
struct xdev_ext_mech_quarantine {
	__u64 objects;		/* pool, region and module references */
	__u64 frames;
};

static inline void xdev_ext_mech_quarantine_add(struct xdev_ext_mech_quarantine *q,
					   __u32 objects, __u32 frames)
{
	if (check_add_overflow(q->objects, (__u64)objects, &q->objects))
		q->objects = XDEV_EXT_MECH_U64_MAX;
	if (check_add_overflow(q->frames, (__u64)frames, &q->frames))
		q->frames = XDEV_EXT_MECH_U64_MAX;
}

/*
 * Legal callback returns per class, member and callsite:
 *   prepare  CREATE                      0 or -errno (fails the CREATE)
 *   build    WORKER, NVMe URING_CMD      DEFAULT, SUBMIT, ABORT
 *   complete WORKER                      NEXT, DONE, RETRY, ABORT
 *            NVMe URING_CMD              DONE, ABORT
 *            AF_XDP RX_GENERIC/NATIVE    HOLD, PUBLISH, RECYCLE
 *            AF_XDP RX_HOLD_RESULT       HOLD, PUBLISH, RECYCLE (advisory)
 */
static inline bool xdev_ext_mech_class_known(__u32 class_id)
{
	return class_id == XDEV_EXT_MECH_CLASS_AFXDP ||
	       class_id == XDEV_EXT_MECH_CLASS_NVME || class_id == XDEV_EXT_MECH_CLASS_CE ||
	       class_id == XDEV_EXT_MECH_CLASS_DMA || class_id == XDEV_EXT_MECH_CLASS_IAA ||
	       class_id == XDEV_EXT_MECH_CLASS_SOCKET || class_id == XDEV_EXT_MECH_CLASS_NET;
}

static inline bool xdev_ext_mech_ret_legal(__u32 class_id, __u32 member,
				      __u32 callsite, __s32 ret)
{
	if (!xdev_ext_mech_class_known(class_id))
		return false;
	switch (member) {
	case XDEV_EXT_MECH_MEMBER_PREPARE:
		return callsite == XDEV_EXT_MECH_SITE_CREATE && ret <= 0 &&
		       ret >= -XDEV_EXT_MECH_ERRNO_MAX;
	case XDEV_EXT_MECH_MEMBER_BUILD:
		if (callsite != XDEV_EXT_MECH_SITE_WORKER &&
		    !(callsite == XDEV_EXT_MECH_SITE_URING_CMD &&
		      class_id == XDEV_EXT_MECH_CLASS_NVME))
			return false;
		return ret >= XDEV_EXT_MECH_BUILD_DEFAULT &&
		       ret <= XDEV_EXT_MECH_BUILD_ABORT;
	case XDEV_EXT_MECH_MEMBER_COMPLETE:
		switch (callsite) {
		case XDEV_EXT_MECH_SITE_WORKER:
			return ret >= XDEV_EXT_MECH_NEXT && ret <= XDEV_EXT_MECH_ABORT;
		case XDEV_EXT_MECH_SITE_URING_CMD:
			return class_id == XDEV_EXT_MECH_CLASS_NVME &&
			       (ret == XDEV_EXT_MECH_DONE || ret == XDEV_EXT_MECH_ABORT);
		case XDEV_EXT_MECH_SITE_RX_GENERIC:
		case XDEV_EXT_MECH_SITE_RX_NATIVE:
		case XDEV_EXT_MECH_SITE_RX_HOLD_RESULT:
			return class_id == XDEV_EXT_MECH_CLASS_AFXDP &&
			       ret >= XDEV_EXT_MECH_HOLD && ret <= XDEV_EXT_MECH_RECYCLE;
		default:
			return false;
		}
	default:
		return false;
	}
}

/*
 * The return value C acts on: @ret when legal, otherwise the fail-closed
 * replacement (build/complete ABORT, RX PUBLISH, hold result RECYCLE,
 * prepare -EPROTO)
 * with *@illegal set so the caller counts a protocol error.
 */
static inline __s32 xdev_ext_mech_ret_resolve(__u32 class_id, __u32 member,
					 __u32 callsite, __s32 ret,
					 bool *illegal)
{
	*illegal = !xdev_ext_mech_ret_legal(class_id, member, callsite, ret);
	if (!*illegal)
		return ret;
	switch (member) {
	case XDEV_EXT_MECH_MEMBER_BUILD:
		return XDEV_EXT_MECH_BUILD_ABORT;
	case XDEV_EXT_MECH_MEMBER_COMPLETE:
		if (callsite == XDEV_EXT_MECH_SITE_RX_HOLD_RESULT)
			return XDEV_EXT_MECH_RECYCLE;
		return callsite == XDEV_EXT_MECH_SITE_RX_GENERIC ||
		       callsite == XDEV_EXT_MECH_SITE_RX_NATIVE ?
		       XDEV_EXT_MECH_PUBLISH : XDEV_EXT_MECH_ABORT;
	default:
		return -EPROTO;
	}
}

/*
 * Final AF_XDP RX disposition. Both serialized copy RX and native ZC RX
 * may hold the original frame with a valid intent. A recorded intent is
 * dropped unless the result is HOLD; count only actual native publications.
 */
static inline __s32 xdev_ext_mech_rx_resolve(__u32 callsite, __s32 ret,
					bool intent_ok, bool *protocol_err,
					bool *native_publish)
{
	*protocol_err = false;
	*native_publish = false;
	if (callsite == XDEV_EXT_MECH_SITE_RX_GENERIC ||
	    callsite == XDEV_EXT_MECH_SITE_RX_NATIVE) {
		if (ret == XDEV_EXT_MECH_PUBLISH || ret == XDEV_EXT_MECH_RECYCLE ||
		    (ret == XDEV_EXT_MECH_HOLD && intent_ok)) {
			*native_publish = callsite == XDEV_EXT_MECH_SITE_RX_NATIVE &&
					  ret == XDEV_EXT_MECH_PUBLISH;
			return ret;
		}
	}
	*native_publish = callsite == XDEV_EXT_MECH_SITE_RX_NATIVE;
	*protocol_err = true;
	return XDEV_EXT_MECH_PUBLISH;
}

/*
 * RETRY is honoured only for a failure the device did not consume, and only
 * a bounded number of times per stage.  @status is the NVMe status
 * (nvme_req(req)->status), the AF_XDP TX errno, or the CE outcome.
 */
#define XDEV_EXT_MECH_RETRY_MAX_NVME		3
#define XDEV_EXT_MECH_RETRY_MAX_AFXDP	4
#define XDEV_EXT_MECH_RETRY_MAX_CE		3
#define XDEV_EXT_MECH_RETRY_MAX_DMA		3
#define XDEV_EXT_MECH_NVME_SCT_SC_MASK	0x07ff	/* NVME_SCT_SC_MASK */
#define XDEV_EXT_MECH_NVME_STATUS_DNR	0x4000	/* NVME_STATUS_DNR */

static inline bool xdev_ext_mech_retry_ok(__u32 class_id, __u32 retries,
				     __s32 status)
{
	switch (class_id) {
	case XDEV_EXT_MECH_CLASS_NVME:
		return retries < XDEV_EXT_MECH_RETRY_MAX_NVME && status > 0 &&
		       (status & XDEV_EXT_MECH_NVME_SCT_SC_MASK) &&
		       !(status & XDEV_EXT_MECH_NVME_STATUS_DNR);
	case XDEV_EXT_MECH_CLASS_AFXDP:
		return retries < XDEV_EXT_MECH_RETRY_MAX_AFXDP && status == -EAGAIN;
	case XDEV_EXT_MECH_CLASS_DMA:
		return retries < XDEV_EXT_MECH_RETRY_MAX_DMA &&
		       status == XDEV_EXT_DMA_PRE_SUBMIT_FAILED;
	case XDEV_EXT_MECH_CLASS_CE:
		return retries < XDEV_EXT_MECH_RETRY_MAX_CE &&
		       status == XDEV_EXT_CE_PRE_SUBMIT_FAILED;
	default:
		return false;
	}
}

/*
 * NXP wire checksum: CRC32C seeded with ~0 over header bytes [0, 36), four
 * zero bytes in place of the checksum field, then the payload; the result is
 * inverted.  @update is a CRC32C step that neither pre- nor post-inverts,
 * as crc32c() in the kernel.  A program does the same with
 * bpf_xdev_ext_crc32c(hdr40 with bytes 36..39 cleared, 40, ~0) followed by
 * bpf_xdev_ext_frame_crc32c() over the payload and a final inversion.
 */
#define XDEV_EXT_MECH_NXP_HDR_LEN		40U
#define XDEV_EXT_MECH_NXP_CSUM_OFF		36U
#define XDEV_EXT_MECH_CRC32C_SEED		0xffffffffU

typedef __u32 (*xdev_ext_mech_crc32c_fn)(__u32 crc, const void *p, size_t len);

static inline __u32 xdev_ext_mech_nxp_csum(xdev_ext_mech_crc32c_fn update,
				      const __u8 *hdr, const void *payload,
				      __u32 len)
{
	const __u8 zero[4] = { 0 };
	__u32 crc = XDEV_EXT_MECH_CRC32C_SEED;

	crc = update(crc, hdr, XDEV_EXT_MECH_NXP_CSUM_OFF);
	crc = update(crc, zero, sizeof(zero));
	crc = update(crc, payload, len);
	return ~crc;
}

#endif /* IO_URING_XDEV_EXT_MECH_CORE_H */

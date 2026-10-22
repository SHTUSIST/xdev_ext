/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_CE_CORE_H
#define IO_URING_XDEV_EXT_MECH_CE_CORE_H

/*
 * Pure rules of the copy-engine class: window geometry, validation and
 * translation of a copy plan, the completion classifier and what C does with
 * each outcome, the cookie state word and the completion copy.  No locking
 * and no allocation; io_uring/xdev_ext_mech_ce.c and
 * tools/testing/selftests/xdev_ext_mech compile the same code.
 */

#include "xdev_ext_mech_core.h"
#include "xdev_ext_mech_window.h"

#define XDEV_EXT_CE_MAX_ENTRIES		32

/*
 * Geometry fixed at bind.  The device window is [0, window_len) of the bound
 * region, cut into seg_size-aligned device-contiguous segments (seg_size 0:
 * one segment).  Host offsets count from the first bind_host() page: chunk i
 * starts at first_page_off + i * frame_size.
 */
struct xdev_ext_ce_geom {
	__u64 window_len;
	__u64 host_bytes;
	__u32 seg_size;
	__u32 max_entry_len;		/* effective, never 0 */
	__u32 first_page_off;
	__u32 frame_size;
	__u32 nr_frames;
};

/* Largest entry: the backend's limit, else one segment, else any length. */
static inline __u32 xdev_ext_ce_max_entry_len(__u32 seg_size, __u32 max_entry_len)
{
	if (max_entry_len)
		return max_entry_len;
	return seg_size ? seg_size : XDEV_EXT_MECH_U32_MAX;
}

/*
 * The backend bound exactly the requested non-empty window, and every chunk
 * of the pool lies inside the host pages; -EINVAL otherwise.
 */
static inline int xdev_ext_ce_geom_init(struct xdev_ext_ce_geom *g, __u64 want_len,
				   __u64 window_len, __u32 seg_size,
				   __u32 max_entry_len, __u64 host_bytes,
				   __u32 first_page_off, __u32 frame_size,
				   __u32 nr_frames)
{
	if (!want_len || window_len != want_len || !frame_size || !nr_frames ||
	    !xdev_ext_mech_span_in(first_page_off, (__u64)nr_frames * frame_size,
			      host_bytes))
		return -EINVAL;
	g->window_len = window_len;
	g->host_bytes = host_bytes;
	g->seg_size = seg_size;
	g->max_entry_len = xdev_ext_ce_max_entry_len(seg_size, max_entry_len);
	g->first_page_off = first_page_off;
	g->frame_size = frame_size;
	g->nr_frames = nr_frames;
	return 0;
}

/* Host byte offset of [off, off + len) in chunk @index; -ERANGE outside it. */
static inline int xdev_ext_ce_host_off(const struct xdev_ext_ce_geom *g, __u32 index,
				  __u32 off, __u32 len, __u64 *host_off)
{
	__u64 at;

	if (index >= g->nr_frames || !xdev_ext_mech_span_in(off, len, g->frame_size))
		return -ERANGE;
	at = g->first_page_off + (__u64)index * g->frame_size + off;
	if (!xdev_ext_mech_span_in(at, len, g->host_bytes))
		return -ERANGE;
	*host_off = at;
	return 0;
}

/* A validated plan: host offsets of the entries, in entry order. */
struct xdev_ext_ce_plan {
	__u64 total;			/* bytes, = the batch payload */
	__u64 host_off[XDEV_EXT_CE_MAX_ENTRIES];
	__u32 n;
};

/*
 * Validate @n copy entries against the batch frames @f (data spans) with
 * pool chunk indices @index, and translate them into @plan.  Rejections:
 *   -EINVAL      no entry, more than XDEV_EXT_MECH_MAX_FRAMES frames, len 0, or a
 *                frame-side piece that is not the next one in frame order
 *                (gap, overlap, wrong frame)
 *   -E2BIG       more than XDEV_EXT_CE_MAX_ENTRIES entries
 *   -EOPNOTSUPP  a flag outside XDEV_EXT_CE_F_KNOWN_MASK
 *   -EMSGSIZE    longer than the largest entry
 *   -ERANGE      past a frame's data span, an entry after full coverage,
 *                device side outside the window, host side outside the chunk
 *   -EXDEV       device side crosses a contiguous segment
 *   -EEXIST      device side overlaps another entry
 *   -ENODATA     the entries end before the batch spans are covered
 * @plan is complete only on success.
 */
static inline int xdev_ext_ce_plan_check(const struct xdev_ext_ce_geom *g,
				    const struct xdev_ext_mech_frame_info *f,
				    const __u32 *index, __u32 nr_frames,
				    const struct xdev_ext_ce_copy_desc *d, __u32 n,
				    struct xdev_ext_ce_plan *plan)
{
	struct xdev_ext_mech_cover c;
	__u64 total = 0;
	__u32 i, j;
	int err;

	if (!n || nr_frames > XDEV_EXT_MECH_MAX_FRAMES)
		return -EINVAL;
	if (n > XDEV_EXT_CE_MAX_ENTRIES)
		return -E2BIG;
	xdev_ext_mech_cover_init(&c, f, nr_frames);
	for (i = 0; i < n; i++) {
		const struct xdev_ext_ce_copy_desc *e = &d[i];

		if (!e->len)
			return -EINVAL;
		if (e->flags & ~XDEV_EXT_CE_F_KNOWN_MASK)
			return -EOPNOTSUPP;
		if (e->len > g->max_entry_len)
			return -EMSGSIZE;
		err = xdev_ext_mech_cover_take(&c, e->frame_pos, e->frame_off,
					  e->len);
		if (err)
			return err;
		if (!xdev_ext_mech_span_in(e->gpu_off, e->len, g->window_len))
			return -ERANGE;
		if (!xdev_ext_mech_span_one_segment(e->gpu_off, e->len, g->seg_size))
			return -EXDEV;
		for (j = 0; j < i; j++)
			if (xdev_ext_mech_spans_overlap(d[j].gpu_off, d[j].len,
						   e->gpu_off, e->len))
				return -EEXIST;
		err = xdev_ext_ce_host_off(g, index[e->frame_pos], e->frame_off,
				      e->len, &plan->host_off[i]);
		if (err)
			return err;
		total += e->len;
	}
	if (!xdev_ext_mech_cover_done(&c))
		return -ENODATA;
	plan->total = total;
	plan->n = n;
	return 0;
}

/* Only an exact, hardware-submitted success may publish produced bytes. */
static inline int xdev_ext_ce_completion_status(int status, bool hw_submitted,
                                           __u64 bytes_done, __u64 expected)
{
	if (status)
		return status;
	return !hw_submitted || bytes_done != expected ? -EIO : 0;
}

/*
 * The backend reports status and whether GPPut or a doorbell was written;
 * C alone decides the outcome after xdev_ext_ce_completion_status() has
 * normalized any incomplete or unsubmitted success.
 */
static inline __u32 xdev_ext_ce_classify(int status, bool hw_submitted)
{
	if (!status)
		return XDEV_EXT_CE_OK;
	return hw_submitted ? XDEV_EXT_CE_AMBIGUOUS : XDEV_EXT_CE_PRE_SUBMIT_FAILED;
}

/*
 * What C does with a classified completion.  true: sequester the batch
 * before any program runs (AMBIGUOUS), *err an errno for the session record.
 * false: complete it with *err = the outcome, which is the status
 * xdev_ext_mech_retry_ok() reads for the CE class, so only PRE_SUBMIT_FAILED can
 * be retried and only within XDEV_EXT_MECH_RETRY_MAX_CE.
 */
static inline bool xdev_ext_ce_disposition(__u32 outcome, int status, int *err)
{
	if (outcome == XDEV_EXT_CE_AMBIGUOUS) {
		*err = status < 0 && status >= -XDEV_EXT_MECH_ERRNO_MAX ? status :
								      -EIO;
		return true;
	}
	*err = (int)outcome;
	return false;
}

/*
 * Cookie state word.  IDLE is zero so a zeroed batch area holds an idle
 * cookie.  The worker arms it before the backend sees it; exactly one
 * completion finishes it; a refused submit takes the arm back.
 */
enum xdev_ext_ce_cookie_state {
	XDEV_EXT_CE_CK_IDLE		= 0,
	XDEV_EXT_CE_CK_ARMED		= 1,
	XDEV_EXT_CE_CK_DONE		= 2,
};

/* Worker: IDLE or DONE (a RETRY) -> ARMED; false while still armed. */
static inline bool xdev_ext_ce_cookie_arm(__u8 *state)
{
	__u8 cur = XDEV_EXT_MECH_LOAD_U8(state);

	if (cur != XDEV_EXT_CE_CK_IDLE && cur != XDEV_EXT_CE_CK_DONE)
		return false;
	return XDEV_EXT_MECH_CAS_U8(state, &cur, XDEV_EXT_CE_CK_ARMED);
}

/* Any context: the one completion of an armed cookie. */
static inline bool xdev_ext_ce_cookie_finish(__u8 *state)
{
	__u8 old = XDEV_EXT_CE_CK_ARMED;

	return XDEV_EXT_MECH_CAS_U8(state, &old, XDEV_EXT_CE_CK_DONE);
}

/* Worker, after a refused submit: false if the backend completed it anyway. */
static inline bool xdev_ext_ce_cookie_disarm(__u8 *state)
{
	__u8 old = XDEV_EXT_CE_CK_ARMED;

	return XDEV_EXT_MECH_CAS_U8(state, &old, XDEV_EXT_CE_CK_IDLE);
}

/*
 * Completion copy for the program.  Without a finished cookie nothing reached
 * the device: PRE_SUBMIT_FAILED with no bytes.  bytes_done never exceeds the
 * plan; entries_done counts entries known complete, all of them only on OK.
 */
static inline void xdev_ext_ce_cqe_fill(struct xdev_ext_ce_mech_cqe *c, __u8 state,
				   __u32 outcome, int status, __u64 bytes_done,
				   __u64 total, __u32 n)
{
	bool done = state == XDEV_EXT_CE_CK_DONE;

	c->outcome = done ? outcome : XDEV_EXT_CE_PRE_SUBMIT_FAILED;
	c->backend_status = (__u32)status;
	c->bytes_done = !done ? 0 : bytes_done < total ? bytes_done : total;
	c->entries_done = done && outcome == XDEV_EXT_CE_OK ? n : 0;
	c->rsvd = 0;
}

/* Class information for the program; @f may be NULL when @nr is 0. */
static inline int xdev_ext_ce_info_fill(struct xdev_ext_ce_mech_info *info,
				   const struct xdev_ext_mech_layout *l,
				   const struct xdev_ext_ce_geom *g,
				   const struct xdev_ext_mech_frame_info *f,
				   __u32 nr)
{
	const struct xdev_ext_mech_frame_info none = { 0 };
	__u32 i;

	if (nr > XDEV_EXT_MECH_MAX_FRAMES)
		return -E2BIG;
	info->l = *l;
	info->gpu_window_len = g->window_len;
	info->gpu_seg_size = g->seg_size;
	info->max_entry_len = g->max_entry_len;
	info->nr_frames = nr;
	info->rsvd = 0;
	/* prepare has geometry but no lease; only C fill_info grants one. */
	info->window_slot = XDEV_EXT_MECH_U32_MAX;
	info->window_depth = 0;
	info->lease_generation = 0;
	for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++)
		info->f[i] = i < nr ? f[i] : none;
	return 0;
}

#endif /* IO_URING_XDEV_EXT_MECH_CE_CORE_H */

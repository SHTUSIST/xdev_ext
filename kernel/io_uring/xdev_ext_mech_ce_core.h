/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_CE_CORE_H
#define IO_URING_XDEV_EXT_MECH_CE_CORE_H

/*
 * Pure rules of the copy-engine class: window geometry, validation and
 * translation of a copy plan, the completion classifier and what C does with
 * each outcome, the cookie state word and the completion copy.  The rules
 * shared with the DMA provider class are in xdev_ext_mech_window_copy_core.h;
 * this header keeps the class names.  No locking and no allocation;
 * io_uring/xdev_ext_mech_ce.c and tools/testing/selftests/xdev_ext_mech
 * compile the same code.
 */

#include "xdev_ext_mech_window_copy_core.h"
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

/*
 * The shared window copy geometry of @g: no alignment, and either direction,
 * since the class admits only TO_DEVICE and FROM_DEVICE stages at bind.
 */
static inline struct xdev_ext_window_copy_geom
xdev_ext_ce_window_geom(const struct xdev_ext_ce_geom *g)
{
	return (struct xdev_ext_window_copy_geom){
		.window_len	= g->window_len,
		.host_bytes	= g->host_bytes,
		.seg_size	= g->seg_size,
		.max_entry_len	= g->max_entry_len,
		.first_page_off	= g->first_page_off,
		.frame_size	= g->frame_size,
		.nr_frames	= g->nr_frames,
		.alignment	= 1,
		.directions	= XDEV_EXT_WINDOW_COPY_DIRS,
	};
}

/* Largest entry: the backend's limit, else one segment, else any length. */
static inline __u32 xdev_ext_ce_max_entry_len(__u32 seg_size, __u32 max_entry_len)
{
	return xdev_ext_window_copy_max_entry_len(seg_size, max_entry_len);
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
	if (!xdev_ext_window_copy_geom_ok(want_len, window_len, host_bytes,
					  first_page_off, frame_size, nr_frames))
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
	const struct xdev_ext_window_copy_geom w = xdev_ext_ce_window_geom(g);

	return xdev_ext_window_copy_host_off(&w, index, off, len, host_off);
}

/* A validated plan: host offsets of the entries, in entry order. */
struct xdev_ext_ce_plan {
	__u64 total;			/* bytes, = the batch payload */
	__u64 host_off[XDEV_EXT_CE_MAX_ENTRIES];
	__u32 n;
};

/*
 * Validate @n copy entries against the batch frames @f (data spans) with
 * pool chunk indices @index, and translate them into @plan, by
 * xdev_ext_window_copy_plan_check() with no alignment and any direction: the
 * rejections and their order, and the rule that device ranges of one batch
 * may overlap, are there.  @plan is complete only on success.  The class
 * also confines a batch to its window slot (xdev_ext_ce_validate()).
 */
static inline int xdev_ext_ce_plan_check(const struct xdev_ext_ce_geom *g,
				    const struct xdev_ext_mech_frame_info *f,
				    const __u32 *index, __u32 nr_frames,
				    const struct xdev_ext_ce_copy_desc *d, __u32 n,
				    struct xdev_ext_ce_plan *plan)
{
	const struct xdev_ext_window_copy_geom w = xdev_ext_ce_window_geom(g);
	int err;

	err = xdev_ext_window_copy_plan_check(&w, f, index, nr_frames,
					      XDEV_EXT_MECH_DIR_TO_DEVICE, d, n,
					      XDEV_EXT_CE_MAX_ENTRIES,
					      XDEV_EXT_CE_F_KNOWN_MASK,
					      plan->host_off, &plan->total);
	if (err)
		return err;
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
	return xdev_ext_mech_classify(!status, hw_submitted);
}

/*
 * What C does with a classified completion: xdev_ext_window_copy_disposition().
 * For the CE class only PRE_SUBMIT_FAILED can be retried, within
 * XDEV_EXT_MECH_RETRY_MAX_CE.
 */
static inline bool xdev_ext_ce_disposition(__u32 outcome, int status, int *err)
{
	return xdev_ext_window_copy_disposition(outcome, status, err);
}

/* Cookie state word: the shared window copy cookie. */
enum xdev_ext_ce_cookie_state {
	XDEV_EXT_CE_CK_IDLE		= XDEV_EXT_WINDOW_COPY_CK_IDLE,
	XDEV_EXT_CE_CK_ARMED		= XDEV_EXT_WINDOW_COPY_CK_ARMED,
	XDEV_EXT_CE_CK_DONE		= XDEV_EXT_WINDOW_COPY_CK_DONE,
};

/* Worker: IDLE or DONE (a RETRY) -> ARMED; false while still armed. */
static inline bool xdev_ext_ce_cookie_arm(__u8 *state)
{
	return xdev_ext_window_copy_cookie_arm(state);
}

/* Any context: the one completion of an armed cookie. */
static inline bool xdev_ext_ce_cookie_finish(__u8 *state)
{
	return xdev_ext_window_copy_cookie_finish(state);
}

/* Worker, after a refused submit: false if the backend completed it anyway. */
static inline bool xdev_ext_ce_cookie_disarm(__u8 *state)
{
	return xdev_ext_window_copy_cookie_disarm(state);
}

/* Completion copy for the program: xdev_ext_window_copy_cqe(). */
static inline void xdev_ext_ce_cqe_fill(struct xdev_ext_ce_mech_cqe *c, __u8 state,
				   __u32 outcome, int status, __u64 bytes_done,
				   __u64 total, __u32 n)
{
	xdev_ext_window_copy_cqe(state, outcome, bytes_done, total, n,
				 &c->outcome, &c->bytes_done, &c->entries_done);
	c->backend_status = (__u32)status;
	c->rsvd = 0;
}

/* Class information for the program; @f may be NULL when @nr is 0. */
static inline int xdev_ext_ce_info_fill(struct xdev_ext_ce_mech_info *info,
				   const struct xdev_ext_mech_layout *l,
				   const struct xdev_ext_ce_geom *g,
				   const struct xdev_ext_mech_frame_info *f,
				   __u32 nr)
{
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
	xdev_ext_window_copy_frames(info->f, f, nr);
	return 0;
}

#endif /* IO_URING_XDEV_EXT_MECH_CE_CORE_H */

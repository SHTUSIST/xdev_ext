/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_DMA_CORE_H
#define IO_URING_XDEV_EXT_MECH_DMA_CORE_H

/*
 * Pure rules of the generic DMA provider class: window geometry, validation and
 * translation of a copy plan, the completion classifier and what C does with
 * each outcome, the cookie state word and the completion copy.  The rules
 * shared with the copy-engine class are in xdev_ext_mech_window_copy_core.h;
 * this header keeps the class names and adds alignment and directions.  No
 * locking and no allocation; io_uring/xdev_ext_mech_dma.c and
 * tools/testing/selftests/xdev_ext_mech compile the same code.
 */

#include "xdev_ext_mech_window_copy_core.h"

/*
 * Geometry fixed at bind.  The device window is [0, window_len) of the bound
 * region, cut into segment_size-aligned device-contiguous segments (segment_size 0:
 * one segment).  Host offsets count from the first bind_host() page: chunk i
 * starts at first_page_off + i * frame_size.
 */
struct xdev_ext_dma_geom {
	__u64 window_len;
	__u64 host_bytes;
	__u32 segment_size;
	__u32 max_entry_len;		/* effective, never 0 */
	__u32 first_page_off;
	__u32 frame_size;
	__u32 nr_frames;
	__u32 alignment, directions;
};

/* The shared window copy geometry of @g. */
static inline struct xdev_ext_window_copy_geom
xdev_ext_dma_window_geom(const struct xdev_ext_dma_geom *g)
{
	return (struct xdev_ext_window_copy_geom){
		.window_len	= g->window_len,
		.host_bytes	= g->host_bytes,
		.seg_size	= g->segment_size,
		.max_entry_len	= g->max_entry_len,
		.first_page_off	= g->first_page_off,
		.frame_size	= g->frame_size,
		.nr_frames	= g->nr_frames,
		.alignment	= g->alignment,
		.directions	= g->directions,
	};
}

/* Largest entry: the provider's limit, else one segment, else any length. */
static inline __u32 xdev_ext_dma_max_entry_len(__u32 segment_size, __u32 max_entry_len)
{
	return xdev_ext_window_copy_max_entry_len(segment_size, max_entry_len);
}

/*
 * The provider bound exactly the requested non-empty window, and every chunk
 * of the pool lies inside the host pages; -EINVAL otherwise.
 */
static inline int xdev_ext_dma_geom_init(struct xdev_ext_dma_geom *g, __u64 want_len,
				   __u64 window_len, __u32 segment_size,
				   __u32 max_entry_len, __u64 host_bytes,
				   __u32 first_page_off, __u32 frame_size,
				   __u32 nr_frames, __u32 alignment, __u32 directions)
{
	if (!alignment || (alignment & (alignment - 1)) || !directions ||
	    (directions & ~XDEV_EXT_DMA_DIR_KNOWN_MASK) ||
	    !xdev_ext_window_copy_geom_ok(want_len, window_len, host_bytes,
					  first_page_off, frame_size, nr_frames))
		return -EINVAL;
	g->window_len = window_len;
	g->host_bytes = host_bytes;
	g->segment_size = segment_size;
	g->max_entry_len = xdev_ext_dma_max_entry_len(segment_size, max_entry_len);
	g->first_page_off = first_page_off;
	g->frame_size = frame_size;
	g->nr_frames = nr_frames;
	g->alignment = alignment;
	g->directions = directions;
	return 0;
}

/* Host byte offset of [off, off + len) in chunk @index; -ERANGE outside it. */
static inline int xdev_ext_dma_host_off(const struct xdev_ext_dma_geom *g, __u32 index,
				  __u32 off, __u32 len, __u64 *host_off)
{
	const struct xdev_ext_window_copy_geom w = xdev_ext_dma_window_geom(g);

	return xdev_ext_window_copy_host_off(&w, index, off, len, host_off);
}

/* A validated plan: host offsets of the entries, in entry order. */
struct xdev_ext_dma_plan {
	__u64 total;			/* bytes, = the batch payload */
	__u64 host_off[XDEV_EXT_DMA_MAX_ENTRIES];
	__u32 n;
};

/*
 * Validate @n copy entries for direction @dir against the batch frames @f
 * (data spans) with pool chunk indices @index, and translate them into @plan,
 * by xdev_ext_window_copy_plan_check() with the provider's alignment and
 * directions: the rejections and their order, and the rule that device
 * ranges of one batch may overlap, are there.  Rejections leave every byte of
 * @plan unchanged.
 */
static inline int xdev_ext_dma_plan_check(const struct xdev_ext_dma_geom *g,
				    const struct xdev_ext_mech_frame_info *f,
				    const __u32 *index, __u32 nr_frames,
				    __u32 dir, const struct xdev_ext_dma_copy_desc *d, __u32 n,
				    struct xdev_ext_dma_plan *plan)
{
	const struct xdev_ext_window_copy_geom w = xdev_ext_dma_window_geom(g);
	struct xdev_ext_dma_plan tmp = { 0 };
	int err;

	err = xdev_ext_window_copy_plan_check(&w, f, index, nr_frames, dir, d, n,
					      XDEV_EXT_DMA_MAX_ENTRIES,
					      XDEV_EXT_DMA_F_KNOWN_MASK,
					      tmp.host_off, &tmp.total);
	if (err)
		return err;
	tmp.n = n;
	*plan = tmp;
	return 0;
}

/*
 * The provider reports status and whether a native queue or doorbell was written;
 * C alone decides the outcome. Only an exact submitted completion is OK.
 */
static inline __u32 xdev_ext_dma_classify(int status, bool hw_submitted,
				       __u64 bytes_done, __u64 total)
{
	return xdev_ext_mech_classify(!status && hw_submitted && bytes_done == total,
				      hw_submitted);
}

/*
 * What C does with a classified completion: xdev_ext_window_copy_disposition().
 * For the DMA class only PRE_SUBMIT_FAILED can be retried, within
 * XDEV_EXT_MECH_RETRY_MAX_DMA.
 */
static inline bool xdev_ext_dma_disposition(__u32 outcome, int status, int *err)
{
	return xdev_ext_window_copy_disposition(outcome, status, err);
}

/* Cookie state word: the shared window copy cookie. */
enum xdev_ext_dma_cookie_state {
	XDEV_EXT_DMA_CK_IDLE		= XDEV_EXT_WINDOW_COPY_CK_IDLE,
	XDEV_EXT_DMA_CK_ARMED		= XDEV_EXT_WINDOW_COPY_CK_ARMED,
	XDEV_EXT_DMA_CK_DONE		= XDEV_EXT_WINDOW_COPY_CK_DONE,
};

/* Worker: IDLE or DONE (a RETRY) -> ARMED; false while still armed. */
static inline bool xdev_ext_dma_cookie_arm(__u8 *state)
{
	return xdev_ext_window_copy_cookie_arm(state);
}

/* Any context: the one completion of an armed cookie. */
static inline bool xdev_ext_dma_cookie_finish(__u8 *state)
{
	return xdev_ext_window_copy_cookie_finish(state);
}

/* Worker, after a refused submit: false if the provider completed it anyway. */
static inline bool xdev_ext_dma_cookie_disarm(__u8 *state)
{
	return xdev_ext_window_copy_cookie_disarm(state);
}

/* Completion copy for the program: xdev_ext_window_copy_cqe(). */
static inline void xdev_ext_dma_cqe_fill(struct xdev_ext_dma_mech_cqe *c, __u8 state,
				   __u32 outcome, int status, __u64 bytes_done,
				   __u64 total, __u32 n)
{
	xdev_ext_window_copy_cqe(state, outcome, bytes_done, total, n,
				 &c->outcome, &c->bytes_done, &c->entries_done);
	c->provider_status = (__u32)status;
	c->rsvd = 0;
}

/* Class information for the program; @f may be NULL when @nr is 0. */
static inline int xdev_ext_dma_info_fill(struct xdev_ext_dma_mech_info *info,
				   const struct xdev_ext_mech_layout *l,
				   const struct xdev_ext_dma_geom *g,
				   const struct xdev_ext_mech_frame_info *f,
				   __u32 nr)
{
	if (nr > XDEV_EXT_MECH_MAX_FRAMES)
		return -E2BIG;
	info->l = *l;
	info->window_len = g->window_len;
	info->segment_size = g->segment_size;
	info->max_entry_len = g->max_entry_len;
	info->alignment = g->alignment;
	info->directions = g->directions;
	info->nr_frames = nr;
	info->rsvd = 0;
	xdev_ext_window_copy_frames(info->f, f, nr);
	return 0;
}

#endif /* IO_URING_XDEV_EXT_MECH_DMA_CORE_H */

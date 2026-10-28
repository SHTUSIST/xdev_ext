/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_WINDOW_COPY_CORE_H
#define IO_URING_XDEV_EXT_MECH_WINDOW_COPY_CORE_H

/*
 * Pure rules shared by the classes that copy between one bound device window
 * and the session host pool: the copy-engine class (xdev_ext_mech_ce_core.h)
 * and the registered DMA provider class (xdev_ext_mech_dma_core.h).  Window
 * geometry, validation and translation of a copy plan, what C does with each
 * classified outcome, the cookie state word and the completion copy.  The
 * class headers keep their own names and add what only they have: DMA's
 * alignment and directions, CE's window slot (checked in
 * io_uring/xdev_ext_mech_ce.c).  No locking and no allocation; the kernel
 * and tools/testing/selftests/xdev_ext_mech compile the same code.
 */

#include "xdev_ext_mech_core.h"

/*
 * Geometry fixed at bind.  The device window is [0, window_len) of the bound
 * region, cut into seg_size-aligned device-contiguous segments (seg_size 0:
 * one segment).  Host offsets count from the first bind_host() page: chunk i
 * starts at first_page_off + i * frame_size.  Every host offset, device
 * offset and length is a multiple of alignment (1: any), and a plan's
 * direction must be in directions (a mask of 1 << enum xdev_ext_mech_dir).
 */
struct xdev_ext_window_copy_geom {
	__u64 window_len;
	__u64 host_bytes;
	__u32 seg_size;
	__u32 max_entry_len;		/* effective, never 0 */
	__u32 first_page_off;
	__u32 frame_size;
	__u32 nr_frames;
	__u32 alignment;
	__u32 directions;
};

#define XDEV_EXT_WINDOW_COPY_DIRS					\
	((1U << XDEV_EXT_MECH_DIR_TO_DEVICE) |				\
	 (1U << XDEV_EXT_MECH_DIR_FROM_DEVICE))

/* Largest entry: the driver's limit, else one segment, else any length. */
static inline __u32 xdev_ext_window_copy_max_entry_len(__u32 seg_size,
						       __u32 max_entry_len)
{
	if (max_entry_len)
		return max_entry_len;
	return seg_size ? seg_size : XDEV_EXT_MECH_U32_MAX;
}

/*
 * The driver bound exactly the requested non-empty window, and every chunk
 * of the pool lies inside the host pages.
 */
static inline bool xdev_ext_window_copy_geom_ok(__u64 want_len, __u64 window_len,
						__u64 host_bytes,
						__u32 first_page_off,
						__u32 frame_size, __u32 nr_frames)
{
	return want_len && window_len == want_len && frame_size && nr_frames &&
	       xdev_ext_mech_span_in(first_page_off,
				     (__u64)nr_frames * frame_size, host_bytes);
}

/* Host byte offset of [off, off + len) in chunk @index; -ERANGE outside it. */
static inline int xdev_ext_window_copy_host_off(const struct xdev_ext_window_copy_geom *g,
						__u32 index, __u32 off, __u32 len,
						__u64 *host_off)
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

/*
 * One copy entry as C reads it from the scratch area.  struct
 * xdev_ext_ce_copy_desc and struct xdev_ext_dma_copy_desc carry exactly these
 * bytes; dev_off is their gpu_off and device_off.
 */
struct xdev_ext_window_copy_desc {
	__u32 frame_pos;
	__u32 frame_off;
	__u64 dev_off;
	__u32 len;
	__u32 flags;
};

#define XDEV_EXT_WINDOW_COPY_SAME_DESC(type, dev)				\
	_Static_assert(sizeof(type) == sizeof(struct xdev_ext_window_copy_desc) && \
		       __builtin_offsetof(type, frame_pos) ==			\
		       __builtin_offsetof(struct xdev_ext_window_copy_desc, frame_pos) && \
		       __builtin_offsetof(type, frame_off) ==			\
		       __builtin_offsetof(struct xdev_ext_window_copy_desc, frame_off) && \
		       __builtin_offsetof(type, dev) ==				\
		       __builtin_offsetof(struct xdev_ext_window_copy_desc, dev_off) && \
		       __builtin_offsetof(type, len) ==				\
		       __builtin_offsetof(struct xdev_ext_window_copy_desc, len) && \
		       __builtin_offsetof(type, flags) ==			\
		       __builtin_offsetof(struct xdev_ext_window_copy_desc, flags), \
		       #type " is not a window copy entry")
XDEV_EXT_WINDOW_COPY_SAME_DESC(struct xdev_ext_ce_copy_desc, gpu_off);
XDEV_EXT_WINDOW_COPY_SAME_DESC(struct xdev_ext_dma_copy_desc, device_off);

/*
 * Validate @n copy entries @descs (in the layout above) for direction @dir
 * against the batch frames @f (data spans) with pool chunk indices @index,
 * and translate them: @host_off[i] is the host offset of entry i, *total the
 * sum of entry lengths.  Rejections, in the order they are checked:
 *   -EINVAL      no entry or more than XDEV_EXT_MECH_MAX_FRAMES frames
 *   -E2BIG       more than @max_entries entries
 *   -EOPNOTSUPP  @dir is not a direction or not in g->directions
 * then for each entry in turn:
 *   -EINVAL      len 0
 *   -EOPNOTSUPP  a flag outside @known_flags
 *   -EMSGSIZE    longer than the largest entry
 *   -EINVAL      a frame-side piece that is not the next one in frame order
 *                (gap, overlap, wrong frame)
 *   -ERANGE      past a frame's data span or an entry after full coverage
 *   -ERANGE      device side outside the window
 *   -EXDEV       device side crosses a contiguous segment
 *   -ERANGE      host side outside the chunk
 *   -EINVAL      host offset, device offset or length not a multiple of
 *                g->alignment
 * and last:
 *   -ENODATA     the entries end before the batch spans are covered
 * @host_off[i] is written once entry i passes; *total only on success.
 *
 * Device ranges of one batch may overlap; keeping them apart is the caller's
 * responsibility.  FROM_DEVICE reads of an overlapped byte are well defined;
 * for TO_DEVICE its final content is unspecified.  *total is the sum of
 * entry lengths.  The window must behave like memory; a driver that needs
 * disjoint device ranges checks them in its own submit.
 */
static inline int xdev_ext_window_copy_plan_check(const struct xdev_ext_window_copy_geom *g,
						  const struct xdev_ext_mech_frame_info *f,
						  const __u32 *index, __u32 nr_frames,
						  __u32 dir, const void *descs, __u32 n,
						  __u32 max_entries, __u32 known_flags,
						  __u64 *host_off, __u64 *total)
{
	struct xdev_ext_mech_cover c;
	__u64 sum = 0, at;
	__u32 i;
	int err;

	if (!n || nr_frames > XDEV_EXT_MECH_MAX_FRAMES)
		return -EINVAL;
	if (n > max_entries)
		return -E2BIG;
	if ((dir != XDEV_EXT_MECH_DIR_TO_DEVICE &&
	     dir != XDEV_EXT_MECH_DIR_FROM_DEVICE) || !(g->directions & (1U << dir)))
		return -EOPNOTSUPP;
	xdev_ext_mech_cover_init(&c, f, nr_frames);
	for (i = 0; i < n; i++) {
		struct xdev_ext_window_copy_desc e;

		__builtin_memcpy(&e, (const __u8 *)descs + (size_t)i * sizeof(e),
				 sizeof(e));
		if (!e.len)
			return -EINVAL;
		if (e.flags & ~known_flags)
			return -EOPNOTSUPP;
		if (e.len > g->max_entry_len)
			return -EMSGSIZE;
		err = xdev_ext_mech_cover_take(&c, e.frame_pos, e.frame_off, e.len);
		if (err)
			return err;
		if (!xdev_ext_mech_span_in(e.dev_off, e.len, g->window_len))
			return -ERANGE;
		if (!xdev_ext_mech_span_one_segment(e.dev_off, e.len, g->seg_size))
			return -EXDEV;
		err = xdev_ext_window_copy_host_off(g, index[e.frame_pos], e.frame_off,
						    e.len, &at);
		if (err)
			return err;
		if ((at | e.dev_off | e.len) & (g->alignment - 1))
			return -EINVAL;
		host_off[i] = at;
		sum += e.len;
	}
	if (!xdev_ext_mech_cover_done(&c))
		return -ENODATA;
	*total = sum;
	return 0;
}

/*
 * The three outcomes use the values of enum xdev_ext_mech_outcome
 * (xdev_ext_mech_core.h); the class enums are the same numbers.
 */
_Static_assert((int)XDEV_EXT_CE_OK == (int)XDEV_EXT_MECH_OUTCOME_OK &&
	       (int)XDEV_EXT_CE_PRE_SUBMIT_FAILED ==
	       (int)XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED &&
	       (int)XDEV_EXT_CE_AMBIGUOUS == (int)XDEV_EXT_MECH_OUTCOME_AMBIGUOUS &&
	       (int)XDEV_EXT_DMA_OK == (int)XDEV_EXT_MECH_OUTCOME_OK &&
	       (int)XDEV_EXT_DMA_PRE_SUBMIT_FAILED ==
	       (int)XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED &&
	       (int)XDEV_EXT_DMA_AMBIGUOUS == (int)XDEV_EXT_MECH_OUTCOME_AMBIGUOUS,
	       "window copy outcomes are the shared outcome values");

/*
 * What C does with a classified completion.  true: sequester the batch
 * before any program runs (AMBIGUOUS), *err an errno for the session record.
 * false: complete it with *err = the outcome, which is the status
 * xdev_ext_mech_retry_ok() reads for the CE and DMA classes, so only
 * PRE_SUBMIT_FAILED can be retried and only within the class limit.
 */
static inline bool xdev_ext_window_copy_disposition(__u32 outcome, int status,
						    int *err)
{
	if (outcome == XDEV_EXT_MECH_OUTCOME_AMBIGUOUS) {
		*err = status < 0 && status >= -XDEV_EXT_MECH_ERRNO_MAX ? status :
								      -EIO;
		return true;
	}
	*err = (int)outcome;
	return false;
}

/*
 * Cookie state word.  IDLE is zero so a zeroed batch area holds an idle
 * cookie.  The worker arms it before the driver sees it; exactly one
 * completion finishes it; a refused submit takes the arm back.
 */
enum xdev_ext_window_copy_cookie_state {
	XDEV_EXT_WINDOW_COPY_CK_IDLE	= 0,
	XDEV_EXT_WINDOW_COPY_CK_ARMED	= 1,
	XDEV_EXT_WINDOW_COPY_CK_DONE	= 2,
};

/* Worker: IDLE or DONE (a RETRY) -> ARMED; false while still armed. */
static inline bool xdev_ext_window_copy_cookie_arm(__u8 *state)
{
	__u8 cur = XDEV_EXT_MECH_LOAD_U8(state);

	if (cur != XDEV_EXT_WINDOW_COPY_CK_IDLE && cur != XDEV_EXT_WINDOW_COPY_CK_DONE)
		return false;
	return XDEV_EXT_MECH_CAS_U8(state, &cur, XDEV_EXT_WINDOW_COPY_CK_ARMED);
}

/* Any context: the one completion of an armed cookie. */
static inline bool xdev_ext_window_copy_cookie_finish(__u8 *state)
{
	__u8 old = XDEV_EXT_WINDOW_COPY_CK_ARMED;

	return XDEV_EXT_MECH_CAS_U8(state, &old, XDEV_EXT_WINDOW_COPY_CK_DONE);
}

/* Worker, after a refused submit: false if the driver completed it anyway. */
static inline bool xdev_ext_window_copy_cookie_disarm(__u8 *state)
{
	__u8 old = XDEV_EXT_WINDOW_COPY_CK_ARMED;

	return XDEV_EXT_MECH_CAS_U8(state, &old, XDEV_EXT_WINDOW_COPY_CK_IDLE);
}

/*
 * Completion copy for the program.  Without a finished cookie nothing reached
 * the device: PRE_SUBMIT_FAILED with no bytes.  bytes_done never exceeds the
 * plan; entries_done counts entries known complete, all of them only on OK.
 */
static inline void xdev_ext_window_copy_cqe(__u8 state, __u32 outcome,
					    __u64 bytes_done, __u64 total, __u32 n,
					    __u32 *c_outcome, __u64 *c_bytes_done,
					    __u32 *c_entries_done)
{
	bool done = state == XDEV_EXT_WINDOW_COPY_CK_DONE;

	*c_outcome = done ? outcome : XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED;
	*c_bytes_done = !done ? 0 : bytes_done < total ? bytes_done : total;
	*c_entries_done = done && outcome == XDEV_EXT_MECH_OUTCOME_OK ? n : 0;
}

/* The program's frame table: @nr frames of @f, the rest zero; @f may be NULL when @nr is 0. */
static inline void xdev_ext_window_copy_frames(struct xdev_ext_mech_frame_info *out,
					       const struct xdev_ext_mech_frame_info *f,
					       __u32 nr)
{
	const struct xdev_ext_mech_frame_info none = { 0 };
	__u32 i;

	for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++)
		out[i] = i < nr ? f[i] : none;
}

#endif /* IO_URING_XDEV_EXT_MECH_WINDOW_COPY_CORE_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_IAA_CORE_H
#define IO_URING_XDEV_EXT_IAA_CORE_H

/*
 * Pure admission and ownership machinery for the io_uring IAA operation.
 * This header is dual-built by the kernel and the focused userspace tests.
 */
#ifdef __KERNEL__
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/types.h>
#define XDEV_EXT_IAA_PAGE_SIZE PAGE_SIZE
#else
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#define XDEV_EXT_IAA_PAGE_SIZE 4096U
#endif

#include "../xdev_ext_mech_life_pool.h"

#define XDEV_EXT_IAA_OP_COMPRESS	4U
#define XDEV_EXT_IAA_OP_DECOMPRESS	5U
#define XDEV_EXT_IAA_DST_MAX		131072U

struct xdev_ext_iaa_sqe_fields {
	__u64 src_off;
	__u64 dst_off;
	__u32 src_len;
	__u64 dst_cap;
};

static inline struct xdev_ext_iaa_sqe_fields
xdev_ext_iaa_sqe_fields_from_words(__u64 addr, __u64 off,
			      __u32 rw_flags, __u64 addr3)
{
	return (struct xdev_ext_iaa_sqe_fields) {
		.src_off = addr,
		.dst_off = off,
		.src_len = rw_flags,
		.dst_cap = addr3,
	};
}

struct xdev_ext_iaa_window_plan {
	__u64 src_off;
	__u64 dst_off;
	__u32 src_len;
	__u32 dst_cap;
	__u32 src_frame;
	__u32 dst_frame;
	__u32 src_frame_offset;
};

struct xdev_ext_iaa_sg_cursor {
	__u64 absolute_offset;
	__u64 remaining;
	__u32 nr_pages;
	__u32 nents;
};

struct xdev_ext_iaa_sg_segment {
	__u32 page_index;
	__u32 page_offset;
	__u32 length;
};

struct xdev_ext_iaa_phys_segment {
	__u64 page_id;
	__u32 page_offset;
	__u32 length;
};

struct xdev_ext_iaa_phys_extent {
	__u32 first;
	__u32 last;
};

static inline int
xdev_ext_iaa_phys_extent_init(struct xdev_ext_iaa_phys_extent *extent,
			 __u32 offset, __u32 length)
{
	if (!extent || !length)
		return -EINVAL;
	if (offset > ~(__u32)0 - length)
		return -EOVERFLOW;
	extent->first = offset;
	extent->last = offset + length;
	return 0;
}

/* Duplicate physical pages form a conservative hull, so gaps fail closed. */
static inline int
xdev_ext_iaa_phys_extent_merge(struct xdev_ext_iaa_phys_extent *extent,
			  __u32 offset, __u32 length)
{
	__u32 last;

	if (!extent || extent->first >= extent->last || !length)
		return -EINVAL;
	if (offset > ~(__u32)0 - length)
		return -EOVERFLOW;
	last = offset + length;
	if (offset < extent->first)
		extent->first = offset;
	if (last > extent->last)
		extent->last = last;
	return 0;
}

static inline bool
xdev_ext_iaa_phys_extent_overlaps(const struct xdev_ext_iaa_phys_extent *extent,
			     __u32 offset, __u32 length)
{
	__u64 last = (__u64)offset + length;

	return extent && extent->first < extent->last && length &&
	       extent->first < last && offset < extent->last;
}

static inline bool
xdev_ext_iaa_phys_segments_overlap(const struct xdev_ext_iaa_phys_segment *source,
			      const struct xdev_ext_iaa_phys_segment *destination)
{
	__u64 source_end;
	__u64 destination_end;

	if (!source || !destination || !source->length || !destination->length ||
	    source->page_id != destination->page_id)
		return false;
	source_end = (__u64)source->page_offset + source->length;
	destination_end = (__u64)destination->page_offset +
			  destination->length;
	return source->page_offset < destination_end &&
	       destination->page_offset < source_end;
}

static inline int
xdev_ext_iaa_sg_cursor_init(struct xdev_ext_iaa_sg_cursor *cursor,
		       __u32 umem_page_offset, __u32 nr_pages,
		       __u64 offset, __u32 length)
{
	__u64 absolute_offset, last_offset, nents;

	if (!cursor || !length || !nr_pages ||
	    umem_page_offset >= XDEV_EXT_IAA_PAGE_SIZE)
		return -EINVAL;
	if (offset > ~(__u64)0 - umem_page_offset)
		return -EOVERFLOW;
	absolute_offset = offset + umem_page_offset;
	if (length - 1 > ~(__u64)0 - absolute_offset)
		return -EOVERFLOW;
	last_offset = absolute_offset + length - 1;
	if (last_offset / XDEV_EXT_IAA_PAGE_SIZE >= nr_pages)
		return -ERANGE;
	nents = last_offset / XDEV_EXT_IAA_PAGE_SIZE -
		absolute_offset / XDEV_EXT_IAA_PAGE_SIZE + 1;
	if (!nents || nents > (__u64)~(__u32)0)
		return -EOVERFLOW;

	*cursor = (struct xdev_ext_iaa_sg_cursor) {
		.absolute_offset = absolute_offset,
		.remaining = length,
		.nr_pages = nr_pages,
		.nents = (__u32)nents,
	};
	return 0;
}

static inline int
xdev_ext_iaa_sg_cursor_next(struct xdev_ext_iaa_sg_cursor *cursor,
		       struct xdev_ext_iaa_sg_segment *segment)
{
	__u64 page_index;
	__u32 page_offset;
	__u32 length;

	if (!cursor || !segment)
		return -EINVAL;
	if (!cursor->remaining)
		return 0;
	page_index = cursor->absolute_offset / XDEV_EXT_IAA_PAGE_SIZE;
	if (page_index >= cursor->nr_pages ||
	    page_index > (__u64)~(__u32)0)
		return -ERANGE;
	page_offset = cursor->absolute_offset % XDEV_EXT_IAA_PAGE_SIZE;
	length = cursor->remaining < XDEV_EXT_IAA_PAGE_SIZE - page_offset ?
		 (__u32)cursor->remaining :
		 XDEV_EXT_IAA_PAGE_SIZE - page_offset;
	if (!length)
		return -EINVAL;
	*segment = (struct xdev_ext_iaa_sg_segment) {
		.page_index = (__u32)page_index,
		.page_offset = page_offset,
		.length = length,
	};
	cursor->absolute_offset += length;
	cursor->remaining -= length;
	return 1;
}

struct xdev_ext_iaa_phys_walk_ops {
	int (*source)(void *opaque, const struct xdev_ext_iaa_sg_segment *segment);
	int (*destination)(void *opaque,
			   const struct xdev_ext_iaa_sg_segment *segment);
};

/*
 * Walk the same logical windows used to build the provider SGs.  Backends
 * resolve each page index to its pinned-page identity and reject aliases.
 */
static inline int
xdev_ext_iaa_walk_physical_windows(__u32 umem_page_offset,
			      __u32 nr_pages,
			      const struct xdev_ext_iaa_window_plan *windows,
			      const struct xdev_ext_iaa_phys_walk_ops *ops,
			      void *opaque)
{
	struct xdev_ext_iaa_sg_segment segment;
	struct xdev_ext_iaa_sg_cursor cursor;
	int ret;

	if (!windows || !ops || !ops->source || !ops->destination)
		return -EINVAL;
	ret = xdev_ext_iaa_sg_cursor_init(&cursor, umem_page_offset, nr_pages,
				     windows->src_off, windows->src_len);
	if (ret)
		return ret;
	while ((ret = xdev_ext_iaa_sg_cursor_next(&cursor, &segment)) > 0) {
		ret = ops->source(opaque, &segment);
		if (ret)
			return ret;
	}
	if (ret < 0)
		return ret;

	ret = xdev_ext_iaa_sg_cursor_init(&cursor, umem_page_offset, nr_pages,
				     windows->dst_off, windows->dst_cap);
	if (ret)
		return ret;
	while ((ret = xdev_ext_iaa_sg_cursor_next(&cursor, &segment)) > 0) {
		ret = ops->destination(opaque, &segment);
		if (ret)
			return ret;
	}
	return ret < 0 ? ret : 0;
}

static inline bool xdev_ext_iaa_opcode_valid(__u32 opcode)
{
	return opcode == XDEV_EXT_IAA_OP_COMPRESS ||
	       opcode == XDEV_EXT_IAA_OP_DECOMPRESS;
}

static inline bool xdev_ext_iaa_is_decompress(__u32 opcode)
{
	return opcode == XDEV_EXT_IAA_OP_DECOMPRESS;
}

enum xdev_ext_unified_stats_source {
	XDEV_EXT_UNIFIED_STATS_NONE = 0,
	XDEV_EXT_UNIFIED_STATS_REGISTERED,
	XDEV_EXT_UNIFIED_STATS_SQE,
};

/*
 * Registered-UMEM operations must never reinterpret an operation-specific SQE
 * field as a statistics pointer.  In particular, READ/WRITE use off/addr2 as
 * a file offset, while IAA uses it as dst_off.  IAA alone may omit statistics.
 */
static inline int
xdev_ext_unified_stats_source(bool use_umem, bool iaa, bool registered_stats,
			 bool sqe_stats)
{
	if (use_umem) {
		if (registered_stats)
			return XDEV_EXT_UNIFIED_STATS_REGISTERED;
		return iaa ? XDEV_EXT_UNIFIED_STATS_NONE : -EFAULT;
	}
	if (iaa)
		return -EOPNOTSUPP;
	return sqe_stats ? XDEV_EXT_UNIFIED_STATS_SQE : -EFAULT;
}

/* IAA's addr2 is dst_off; only UMEM registration can supply statistics. */
static inline bool
xdev_ext_iaa_has_registered_stats(bool registered_stats,
			     __u64 sqe_destination_offset)
{
	(void)sqe_destination_offset;
	return registered_stats;
}

/*
 * Legacy UMEM operations share the same frame_pool with IAA whenever the
 * lifecycle state machine is enabled.  Their windows therefore must never
 * bypass ownership.  READY and valid_len describe a prefix of one frame;
 * producers must start at that prefix's beginning.
 */
struct xdev_ext_lifecycle_window {
 __u64 claim;
	__u32 frame;
	__u32 frame_offset;
	__u32 length;
};

enum xdev_ext_lifecycle_source_mode {
	XDEV_EXT_LIFECYCLE_SOURCE_READY = 1,
	XDEV_EXT_LIFECYCLE_SOURCE_FREE = 2,
};

static inline int
xdev_ext_lifecycle_decode_window(__u64 offset, __u32 length,
			    __u64 umem_size, __u32 frame_size,
			    bool producer, struct xdev_ext_lifecycle_window *window)
{
	__u64 frame;
	__u32 frame_offset;

	if (!window)
		return -EINVAL;
	*window = (struct xdev_ext_lifecycle_window) {};
	if (!frame_size || (frame_size & (frame_size - 1)) || !length)
		return -EINVAL;
	if (offset >= umem_size || length > umem_size - offset)
		return -EINVAL;
	frame_offset = offset % frame_size;
	if (producer && frame_offset)
		return -EINVAL;
	if (length > frame_size - frame_offset)
		return -EMSGSIZE;
	frame = offset / frame_size;
	if (frame > (__u64)~(__u32)0)
		return -EOVERFLOW;

	*window = (struct xdev_ext_lifecycle_window) {
		.frame = (__u32)frame,
		.frame_offset = frame_offset,
		.length = length,
	};
	return 0;
}

static inline int
xdev_ext_lifecycle_restore_ready(struct xdev_ext_mech_life_pool *pool,
                                const struct xdev_ext_lifecycle_window *window)
{
 if (!pool || !window || !pool->frames || window->frame >= pool->nr_frames)
  return -EINVAL;
 return xdev_ext_mech_life_rollback(&pool->frames[window->frame], window->claim);
}

static inline int
xdev_ext_lifecycle_consume_begin(struct xdev_ext_mech_life_pool *pool,
                                struct xdev_ext_lifecycle_window *window)
{
 struct xdev_ext_mech_life *life;
 __u64 input;
 bool supplied;
 int err;

 if (!pool || !window || !pool->frames || window->frame >= pool->nr_frames)
  return -EINVAL;
 life = &pool->frames[window->frame];
 supplied = xdev_ext_mech_life_phase(life) == XDEV_EXT_MECH_L_FREE;
 if (supplied) {
  /* Direct ABI supplies CPU-authored source bytes without a separate START.
   * Publish that input explicitly before taking its consumer reference. */
  err = xdev_ext_mech_life_claim(life, XDEV_EXT_MECH_L_OWNER_START, &input);
  if (err)
   return err;
  err = xdev_ext_mech_life_publish(life, input, 1, window->frame_offset + window->length);
  if (err)
   return err;
 }
 err = xdev_ext_mech_life_acquire(life, 0, 0, &window->claim);
 if (err)
  return err;
 if (window->frame_offset > life->valid_len ||
     window->length > life->valid_len - window->frame_offset) {
  err = xdev_ext_lifecycle_restore_ready(pool, window);
  return err ? err : -EMSGSIZE;
 }
 return supplied ? XDEV_EXT_LIFECYCLE_SOURCE_FREE : XDEV_EXT_LIFECYCLE_SOURCE_READY;
}

static inline int
xdev_ext_lifecycle_consume_end(struct xdev_ext_mech_life_pool *pool,
                              const struct xdev_ext_lifecycle_window *window, int mode)
{
 int err;

 if (!pool || !window || !pool->frames || window->frame >= pool->nr_frames ||
     (mode != XDEV_EXT_LIFECYCLE_SOURCE_READY && mode != XDEV_EXT_LIFECYCLE_SOURCE_FREE))
  return -EINVAL;
 err = xdev_ext_mech_life_put(&pool->frames[window->frame], window->claim);
 return err < 0 ? err : 0;
}

static inline int
xdev_ext_lifecycle_producer_begin(struct xdev_ext_mech_life_pool *pool,
                                 struct xdev_ext_lifecycle_window *window)
{
 if (!pool || !window || !pool->frames || window->frame >= pool->nr_frames)
  return -EINVAL;
 return xdev_ext_mech_life_claim(&pool->frames[window->frame], 0, &window->claim);
}

static inline int
xdev_ext_lifecycle_producer_abort(struct xdev_ext_mech_life_pool *pool,
                                 const struct xdev_ext_lifecycle_window *window)
{
 if (!pool || !window || !pool->frames || window->frame >= pool->nr_frames)
  return -EINVAL;
 return xdev_ext_mech_life_fail_produce(&pool->frames[window->frame], window->claim);
}

static inline int
xdev_ext_iaa_decode_windows(const struct xdev_ext_iaa_sqe_fields *fields,
		       __u64 umem_size, __u32 frame_size,
		       struct xdev_ext_iaa_window_plan *plan)
{
	__u64 src_end, dst_end, src_frame, dst_frame;

	if (!fields || !plan)
		return -EINVAL;
	*plan = (struct xdev_ext_iaa_window_plan) {};
	if (!frame_size || (frame_size & (frame_size - 1)))
		return -EINVAL;
	if (!fields->src_len || !fields->dst_cap)
		return -EINVAL;
	/* READY/valid_len and publish both describe prefixes of a frame. */
	if (fields->dst_off % frame_size)
		return -EINVAL;
	if (fields->dst_cap > XDEV_EXT_IAA_DST_MAX ||
	    fields->dst_cap > (__u64)~(__u32)0)
		return -E2BIG;
	if (fields->src_off >= umem_size ||
	    fields->src_len > umem_size - fields->src_off)
		return -EINVAL;
	if (fields->dst_off >= umem_size ||
	    fields->dst_cap > umem_size - fields->dst_off)
		return -EINVAL;

	/* The subtractive range checks above prove these additions cannot wrap. */
	src_end = fields->src_off + fields->src_len;
	dst_end = fields->dst_off + fields->dst_cap;
	if (fields->src_off < dst_end && fields->dst_off < src_end)
		return -EINVAL;

	src_frame = fields->src_off / frame_size;
	dst_frame = fields->dst_off / frame_size;
	if ((src_end - 1) / frame_size != src_frame ||
	    (dst_end - 1) / frame_size != dst_frame)
		return -EMSGSIZE;
	if (src_frame == dst_frame)
		return -EINVAL;
	if (src_frame > (__u64)~(__u32)0 ||
	    dst_frame > (__u64)~(__u32)0)
		return -EOVERFLOW;

	plan->src_off = fields->src_off;
	plan->dst_off = fields->dst_off;
	plan->src_len = fields->src_len;
	plan->dst_cap = (__u32)fields->dst_cap;
	plan->src_frame = (__u32)src_frame;
	plan->dst_frame = (__u32)dst_frame;
	plan->src_frame_offset = fields->src_off % frame_size;
	return 0;
}

enum xdev_ext_iaa_source_mode {
	XDEV_EXT_IAA_SOURCE_NONE,
	XDEV_EXT_IAA_SOURCE_READY,
	XDEV_EXT_IAA_SOURCE_FREE,
};

enum xdev_ext_iaa_claim_order {
	XDEV_EXT_IAA_CLAIM_SOURCE_FIRST,
	XDEV_EXT_IAA_CLAIM_DEST_FIRST,
};

struct xdev_ext_iaa_frame_claim {
 __u64 source_claim, destination_claim;
	struct xdev_ext_mech_life_pool *pool;
	struct xdev_ext_iaa_window_plan windows;
	enum xdev_ext_iaa_source_mode source_mode;
	bool source_owned;
	bool destination_owned;
	bool finished;
};

static inline int
xdev_ext_iaa_claim_source(struct xdev_ext_iaa_frame_claim *claim)
{
 struct xdev_ext_lifecycle_window window = {
  .frame = claim->windows.src_frame,
  .frame_offset = claim->windows.src_frame_offset,
  .length = claim->windows.src_len,
 };
 int mode = xdev_ext_lifecycle_consume_begin(claim->pool, &window);

 if (mode < 0)
  return mode;
 claim->source_claim = window.claim;
 claim->source_mode = mode == XDEV_EXT_LIFECYCLE_SOURCE_FREE ?
  XDEV_EXT_IAA_SOURCE_FREE : XDEV_EXT_IAA_SOURCE_READY;
 claim->source_owned = true;
 return 0;
}

/* Restore an unsubmitted consumer. A raw CPU source publication has completed
 * before this consumer, so closing that newly created publication recycles it. */
static inline int
xdev_ext_iaa_rollback_source(struct xdev_ext_iaa_frame_claim *claim)
{
 struct xdev_ext_mech_life *life = &claim->pool->frames[claim->windows.src_frame];
 int err;

 if (!claim->source_owned)
  return 0;
 err = xdev_ext_mech_life_rollback(life, claim->source_claim);
 if (!err && claim->source_mode == XDEV_EXT_IAA_SOURCE_FREE)
  err = xdev_ext_mech_life_release(life, xdev_ext_mech_life_claim_gen(claim->source_claim));
 if (!err)
  claim->source_owned = false;
 return err;
}

static inline int
xdev_ext_iaa_release_source(struct xdev_ext_iaa_frame_claim *claim)
{
 int err;

 if (!claim->source_owned)
  return 0;
 err = xdev_ext_mech_life_put(&claim->pool->frames[claim->windows.src_frame], claim->source_claim);
 if (err >= 0)
  claim->source_owned = false;
 return err < 0 ? err : 0;
}

static inline int
xdev_ext_iaa_claim_destination(struct xdev_ext_iaa_frame_claim *claim)
{
 int err = xdev_ext_mech_life_claim(&claim->pool->frames[claim->windows.dst_frame],
                                   1, &claim->destination_claim);
 if (!err)
  claim->destination_owned = true;
 return err;
}

static inline int
xdev_ext_iaa_frames_claim(struct xdev_ext_iaa_frame_claim *claim, struct xdev_ext_mech_life_pool *pool,
		     const struct xdev_ext_iaa_window_plan *windows,
		     enum xdev_ext_iaa_claim_order order)
{
	int ret;

	if (!claim || !pool || !windows)
		return -EINVAL;
	*claim = (struct xdev_ext_iaa_frame_claim) {
		.pool = pool,
		.windows = *windows,
	};
	if (windows->src_frame >= pool->nr_frames ||
	    windows->dst_frame >= pool->nr_frames)
		return -ERANGE;

	if (order == XDEV_EXT_IAA_CLAIM_SOURCE_FIRST) {
		ret = xdev_ext_iaa_claim_source(claim);
		if (ret) {
			if (claim->source_owned && xdev_ext_iaa_rollback_source(claim))
				return -EIO;
			return ret;
		}
		ret = xdev_ext_iaa_claim_destination(claim);
		if (ret && xdev_ext_iaa_rollback_source(claim))
			return -EIO;
		return ret;
	}
	if (order != XDEV_EXT_IAA_CLAIM_DEST_FIRST)
		return -EINVAL;

	ret = xdev_ext_iaa_claim_destination(claim);
	if (ret)
		return ret;
	ret = xdev_ext_iaa_claim_source(claim);
	if (ret) {
		if (xdev_ext_mech_life_rollback(&pool->frames[windows->dst_frame], claim->destination_claim))
			ret = -EIO;
		claim->destination_owned = false;
		if (claim->source_owned && xdev_ext_iaa_rollback_source(claim))
			ret = -EIO;
	}
	return ret;
}

/* Undo a fully prepared request before the provider is called. */
static inline int
xdev_ext_iaa_frames_rollback(struct xdev_ext_iaa_frame_claim *claim)
{
	int dst_ret = 0;
	int src_ret;

	if (!claim || !claim->pool)
		return -EINVAL;
	if (claim->finished)
		return -EALREADY;
	claim->finished = true;
	if (claim->destination_owned) {
		dst_ret = xdev_ext_mech_life_rollback(&claim->pool->frames[claim->windows.dst_frame],
     claim->destination_claim);
		claim->destination_owned = false;
	}
	src_ret = xdev_ext_iaa_rollback_source(claim);
	if (dst_ret || src_ret)
		return -EIO;
	return 0;
}

/*
 * Finish the destination before releasing the source.  native_result is the
 * acomp status (zero or a negative errno); success returns the byte count.
 */
static inline int
xdev_ext_iaa_frames_finish(struct xdev_ext_iaa_frame_claim *claim, int native_result,
		      __u32 produced)
{
	int result = native_result;
	int dst_ret;
	int src_ret;

	if (!claim || !claim->pool)
		return -EINVAL;
	if (claim->finished)
		return -EALREADY;
	claim->finished = true;
	if (!claim->source_owned || !claim->destination_owned)
		return -EINVAL;
	if (result > 0)
		result = -EPROTO;
	if (!result && produced > claim->windows.dst_cap)
		result = -EOVERFLOW;

	if (!result) {
		dst_ret = xdev_ext_mech_life_publish(&claim->pool->frames[claim->windows.dst_frame],
     claim->destination_claim, 1, produced);
		if (dst_ret)
			result = -EIO;
	} else {
		dst_ret = xdev_ext_mech_life_fail_produce(&claim->pool->frames[claim->windows.dst_frame],
     claim->destination_claim);
	}
	claim->destination_owned = false;
	src_ret = xdev_ext_iaa_release_source(claim);
	if (dst_ret || src_ret)
		result = -EIO;
	return result ? result : (int)produced;
}

enum xdev_ext_iaa_terminal_phase {
	XDEV_EXT_IAA_TERMINAL_SUBMITTING,
	XDEV_EXT_IAA_TERMINAL_ACCEPTED,
	XDEV_EXT_IAA_TERMINAL_EARLY,
	XDEV_EXT_IAA_TERMINAL_QUEUED,
	XDEV_EXT_IAA_TERMINAL_INLINE,
};

#ifdef __KERNEL__
struct xdev_ext_iaa_atomic {
	atomic_t value;
};

static inline void xdev_ext_iaa_atomic_set(struct xdev_ext_iaa_atomic *value, int next)
{
	atomic_set(&value->value, next);
}

static inline int xdev_ext_iaa_atomic_read(const struct xdev_ext_iaa_atomic *value)
{
	return atomic_read(&value->value);
}

static inline int
xdev_ext_iaa_atomic_cmpxchg(struct xdev_ext_iaa_atomic *value, int old, int next)
{
	return atomic_cmpxchg(&value->value, old, next);
}

static inline void xdev_ext_iaa_relax(void)
{
	cpu_relax();
}

#define xdev_ext_iaa_write_once(value, next)	WRITE_ONCE(value, next)
#define xdev_ext_iaa_read_once(value)	READ_ONCE(value)
#else
struct xdev_ext_iaa_atomic {
	int value;
};

static inline void xdev_ext_iaa_atomic_set(struct xdev_ext_iaa_atomic *value, int next)
{
	__atomic_store_n(&value->value, next, __ATOMIC_RELEASE);
}

static inline int xdev_ext_iaa_atomic_read(const struct xdev_ext_iaa_atomic *value)
{
	return __atomic_load_n(&value->value, __ATOMIC_ACQUIRE);
}

static inline int
xdev_ext_iaa_atomic_cmpxchg(struct xdev_ext_iaa_atomic *value, int old, int next)
{
	__atomic_compare_exchange_n(&value->value, &old, next, false,
				    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
	return old;
}

static inline void xdev_ext_iaa_relax(void)
{
	__asm__ __volatile__("" ::: "memory");
}

#define xdev_ext_iaa_write_once(value, next) \
	__atomic_store_n(&(value), (next), __ATOMIC_RELEASE)
#define xdev_ext_iaa_read_once(value)	__atomic_load_n(&(value), __ATOMIC_ACQUIRE)
#endif

struct xdev_ext_iaa_terminal {
	struct xdev_ext_iaa_atomic phase;
	struct xdev_ext_iaa_atomic claimed;
	int result;
	__u32 produced;
};

enum xdev_ext_iaa_callback_action {
	XDEV_EXT_IAA_CALLBACK_PROGRESS,
	XDEV_EXT_IAA_CALLBACK_DEFER,
	XDEV_EXT_IAA_CALLBACK_QUEUE,
	XDEV_EXT_IAA_CALLBACK_DUPLICATE,
};

enum xdev_ext_iaa_submit_action {
	XDEV_EXT_IAA_SUBMIT_WAIT,
	XDEV_EXT_IAA_SUBMIT_QUEUE_EARLY,
	XDEV_EXT_IAA_SUBMIT_FINISH_INLINE,
	XDEV_EXT_IAA_SUBMIT_INVALID,
};

static inline void xdev_ext_iaa_terminal_init(struct xdev_ext_iaa_terminal *terminal)
{
	xdev_ext_iaa_atomic_set(&terminal->phase, XDEV_EXT_IAA_TERMINAL_SUBMITTING);
	xdev_ext_iaa_atomic_set(&terminal->claimed, 0);
	xdev_ext_iaa_write_once(terminal->result, 0);
	xdev_ext_iaa_write_once(terminal->produced, 0);
}

static inline void
xdev_ext_iaa_terminal_record(struct xdev_ext_iaa_terminal *terminal, int result,
			__u32 produced)
{
	xdev_ext_iaa_write_once(terminal->result, result);
	xdev_ext_iaa_write_once(terminal->produced, result ? 0 : produced);
}

static inline enum xdev_ext_iaa_callback_action
xdev_ext_iaa_terminal_callback(struct xdev_ext_iaa_terminal *terminal, int error,
			  __u32 produced)
{
	int phase;

	if (error == -EINPROGRESS)
		return XDEV_EXT_IAA_CALLBACK_PROGRESS;
	if (xdev_ext_iaa_atomic_cmpxchg(&terminal->claimed, 0, 1))
		return XDEV_EXT_IAA_CALLBACK_DUPLICATE;
	xdev_ext_iaa_terminal_record(terminal, error, produced);

	for (;;) {
		phase = xdev_ext_iaa_atomic_read(&terminal->phase);
		if (phase == XDEV_EXT_IAA_TERMINAL_SUBMITTING) {
			if (xdev_ext_iaa_atomic_cmpxchg(&terminal->phase, phase,
						   XDEV_EXT_IAA_TERMINAL_EARLY) == phase)
				return XDEV_EXT_IAA_CALLBACK_DEFER;
			continue;
		}
		if (phase == XDEV_EXT_IAA_TERMINAL_ACCEPTED) {
			if (xdev_ext_iaa_atomic_cmpxchg(&terminal->phase, phase,
						   XDEV_EXT_IAA_TERMINAL_QUEUED) == phase)
				return XDEV_EXT_IAA_CALLBACK_QUEUE;
			continue;
		}
		return XDEV_EXT_IAA_CALLBACK_DUPLICATE;
	}
}

static inline bool xdev_ext_iaa_submit_is_async(int submit_result)
{
	return submit_result == -EINPROGRESS || submit_result == -EBUSY;
}

static inline enum xdev_ext_iaa_submit_action
xdev_ext_iaa_submit_return(struct xdev_ext_iaa_terminal *terminal, int submit_result,
		      __u32 produced)
{
	int phase;

	if (xdev_ext_iaa_submit_is_async(submit_result)) {
		for (;;) {
			phase = xdev_ext_iaa_atomic_read(&terminal->phase);
			if (phase == XDEV_EXT_IAA_TERMINAL_SUBMITTING) {
				if (xdev_ext_iaa_atomic_cmpxchg(&terminal->phase, phase,
							   XDEV_EXT_IAA_TERMINAL_ACCEPTED) == phase)
					return XDEV_EXT_IAA_SUBMIT_WAIT;
				continue;
			}
			if (phase == XDEV_EXT_IAA_TERMINAL_EARLY) {
				if (xdev_ext_iaa_atomic_cmpxchg(&terminal->phase, phase,
							   XDEV_EXT_IAA_TERMINAL_QUEUED) == phase)
					return XDEV_EXT_IAA_SUBMIT_QUEUE_EARLY;
				continue;
			}
			return XDEV_EXT_IAA_SUBMIT_INVALID;
		}
	}

	if (!xdev_ext_iaa_atomic_cmpxchg(&terminal->claimed, 0, 1)) {
		xdev_ext_iaa_terminal_record(terminal, submit_result, produced);
		phase = XDEV_EXT_IAA_TERMINAL_SUBMITTING;
		if (xdev_ext_iaa_atomic_cmpxchg(&terminal->phase, phase,
					   XDEV_EXT_IAA_TERMINAL_INLINE) != phase)
			return XDEV_EXT_IAA_SUBMIT_INVALID;
		return XDEV_EXT_IAA_SUBMIT_FINISH_INLINE;
	}

	/* Defensive handling for a provider that called back before a sync return. */
	do {
		phase = xdev_ext_iaa_atomic_read(&terminal->phase);
		xdev_ext_iaa_relax();
	} while (phase == XDEV_EXT_IAA_TERMINAL_SUBMITTING);
	if (phase == XDEV_EXT_IAA_TERMINAL_EARLY &&
	    xdev_ext_iaa_atomic_cmpxchg(&terminal->phase, phase,
				   XDEV_EXT_IAA_TERMINAL_INLINE) == phase)
		return XDEV_EXT_IAA_SUBMIT_FINISH_INLINE;
	return XDEV_EXT_IAA_SUBMIT_INVALID;
}

static inline int
xdev_ext_iaa_terminal_result(const struct xdev_ext_iaa_terminal *terminal)
{
	return xdev_ext_iaa_read_once(terminal->result);
}

static inline __u32
xdev_ext_iaa_terminal_produced(const struct xdev_ext_iaa_terminal *terminal)
{
	return xdev_ext_iaa_read_once(terminal->produced);
}

/*
 * Production-used fake-provider seam.  It centralizes ownership edges while
 * leaving frame publication and concrete resource allocation in the caller.
 */
struct xdev_ext_iaa_runtime_ops {
	int (*dispatch)(void *opaque);
	int (*prepare_provider)(void *opaque);
	void (*token_put)(void *opaque);
	void (*umem_get)(void *opaque);
	void (*umem_put)(void *opaque);
	int (*complete)(void *opaque, int result);
	int (*submit)(void *opaque, bool decompress, __u32 *produced);
	void (*queue_task_work)(void *opaque);
};

struct xdev_ext_iaa_runtime {
	struct xdev_ext_iaa_terminal terminal;
	const struct xdev_ext_iaa_runtime_ops *ops;
	void *opaque;
	bool dispatch_attempted;
	bool dispatch_accepted;
	bool provider_attempted;
	bool provider_prepared;
	bool umem_ref;
	bool submit_entered;
	bool task_work_queued;
	bool completion_done;
};

static inline int
xdev_ext_iaa_runtime_init(struct xdev_ext_iaa_runtime *runtime,
		     const struct xdev_ext_iaa_runtime_ops *ops, void *opaque)
{
	if (!runtime || !ops || !ops->dispatch || !ops->prepare_provider ||
	    !ops->token_put || !ops->umem_get || !ops->umem_put ||
	    !ops->complete || !ops->submit || !ops->queue_task_work)
		return -EINVAL;
	*runtime = (struct xdev_ext_iaa_runtime) {
		.ops = ops,
		.opaque = opaque,
	};
	xdev_ext_iaa_terminal_init(&runtime->terminal);
	return 0;
}

static inline int xdev_ext_iaa_runtime_dispatch(struct xdev_ext_iaa_runtime *runtime)
{
	int ret;

	if (!runtime || !runtime->ops || runtime->dispatch_attempted)
		return -EALREADY;
	runtime->dispatch_attempted = true;
	ret = runtime->ops->dispatch(runtime->opaque);
	if (!ret)
		runtime->dispatch_accepted = true;
	return ret;
}

static inline int
xdev_ext_iaa_runtime_prepare_provider(struct xdev_ext_iaa_runtime *runtime)
{
	int ret;

	if (!runtime || !runtime->dispatch_accepted ||
	    runtime->provider_attempted)
		return -EALREADY;
	runtime->provider_attempted = true;
	ret = runtime->ops->prepare_provider(runtime->opaque);
	if (!ret)
		runtime->provider_prepared = true;
	return ret;
}

static inline int
xdev_ext_iaa_runtime_acquire_umem(struct xdev_ext_iaa_runtime *runtime)
{
	if (!runtime || !runtime->dispatch_accepted ||
	    !runtime->provider_prepared || runtime->umem_ref ||
	    xdev_ext_iaa_read_once(runtime->submit_entered))
		return -EALREADY;
	runtime->ops->umem_get(runtime->opaque);
	runtime->umem_ref = true;
	return 0;
}

static inline void xdev_ext_iaa_runtime_queue_once(struct xdev_ext_iaa_runtime *runtime)
{
	/* The terminal CAS elects one queue path; this guards contract failures. */
	if (xdev_ext_iaa_read_once(runtime->task_work_queued))
		return;
	xdev_ext_iaa_write_once(runtime->task_work_queued, true);
	runtime->ops->queue_task_work(runtime->opaque);
}

static inline enum xdev_ext_iaa_callback_action
xdev_ext_iaa_runtime_callback(struct xdev_ext_iaa_runtime *runtime, int error,
			 __u32 produced)
{
	enum xdev_ext_iaa_callback_action action;

	if (!runtime || !xdev_ext_iaa_read_once(runtime->submit_entered))
		return XDEV_EXT_IAA_CALLBACK_DUPLICATE;
	action = xdev_ext_iaa_terminal_callback(&runtime->terminal, error, produced);
	if (action == XDEV_EXT_IAA_CALLBACK_QUEUE)
		xdev_ext_iaa_runtime_queue_once(runtime);
	return action;
}

static inline enum xdev_ext_iaa_submit_action
xdev_ext_iaa_runtime_submit(struct xdev_ext_iaa_runtime *runtime, bool decompress)
{
	enum xdev_ext_iaa_submit_action action;
	__u32 produced = 0;
	int ret;

	if (!runtime || !runtime->dispatch_accepted ||
	    !runtime->provider_prepared || !runtime->umem_ref ||
	    xdev_ext_iaa_read_once(runtime->submit_entered))
		return XDEV_EXT_IAA_SUBMIT_INVALID;
	xdev_ext_iaa_write_once(runtime->submit_entered, true);
	ret = runtime->ops->submit(runtime->opaque, decompress, &produced);
	action = xdev_ext_iaa_submit_return(&runtime->terminal, ret, produced);
	if (action == XDEV_EXT_IAA_SUBMIT_QUEUE_EARLY)
		xdev_ext_iaa_runtime_queue_once(runtime);
	return action;
}

static inline int
xdev_ext_iaa_runtime_complete(struct xdev_ext_iaa_runtime *runtime, int result)
{
	if (!runtime || !runtime->dispatch_accepted || runtime->completion_done)
		return -EALREADY;
	runtime->completion_done = true;
	runtime->dispatch_accepted = false;
	return runtime->ops->complete(runtime->opaque, result);
}

static inline void xdev_ext_iaa_runtime_release(struct xdev_ext_iaa_runtime *runtime)
{
	if (!runtime || !runtime->ops)
		return;
	if (runtime->dispatch_accepted) {
		runtime->dispatch_accepted = false;
		runtime->ops->token_put(runtime->opaque);
	}
	if (runtime->umem_ref) {
		runtime->umem_ref = false;
		runtime->ops->umem_put(runtime->opaque);
	}
}

#endif /* IO_URING_XDEV_EXT_IAA_CORE_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_COMPFAM_COPY_CORE_H
#define IO_URING_XDEV_EXT_COMPFAM_COPY_CORE_H

/* Prepared windows and admitted plans shared by the typed CE/DMA adapters. */
#include "xdev_ext_mech_window_copy_core.h"
#include "xdev_ext_mech_window.h"
#ifdef __KERNEL__
#include <linux/xdev_ext_compfam_core.h>
#else
#include "../include/linux/xdev_ext_compfam_core.h"
#endif

/* Typed adapters pass their own admission cap; DMA and legacy CE stay at32. */
#define XDEV_EXT_COMP_COPY_MAX_ENTRIES XDEV_EXT_CE_RANGE_MAX_ENTRIES

struct xdev_ext_comp_copy_window {
	struct xdev_ext_window_copy_geom geom;
	__u32 direction, depth, group_bytes;
	bool target_range;
};

struct xdev_ext_comp_copy_entry {
	__u64 host_byte_off, device_off;
	__u32 frame_pos, len, flags;
};

struct xdev_ext_comp_copy_plan {
	__u64 batch_id, total;
	__u64 target_start, target_len;
	__u32 slot, n;
	bool target_range;
	struct xdev_ext_comp_copy_entry entry[XDEV_EXT_COMP_COPY_MAX_ENTRIES];
};

struct xdev_ext_comp_copy_transfer {
	__u64 owner, generation, host_byte_off, device_off;
	__u32 len, flags;
};

typedef int (*xdev_ext_comp_claim_fn)(void *batch, __u32 frame_pos,
				    __u64 *owner, __u64 *generation);

/* CREATE: geometry has already passed the class's native bind checks. */
static inline int xdev_ext_comp_copy_prepare_mode(struct xdev_ext_comp_copy_window *out,
	int kind, const struct xdev_ext_window_copy_geom *geom,
	__u32 direction, __u32 depth, __u32 group_bytes, bool target_range)
{
	__u64 offset;
	int err;

	if (kind != XDEV_EXT_COMP_COPY_WINDOW)
		return -EINVAL;
	if ((direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
	     direction != XDEV_EXT_MECH_DIR_FROM_DEVICE) ||
	    !(geom->directions & (1U << direction)))
		return -EOPNOTSUPP;
	if (target_range) {
		if (!depth || !group_bytes)
			return -EINVAL;
		if (!xdev_ext_mech_span_in(0, group_bytes, geom->window_len))
			return -ENOSPC;
	} else {
		err = xdev_ext_mech_window_offset(0, depth, group_bytes, geom->window_len,
						&offset);
		if (err)
			return err;
	}
	*out = (struct xdev_ext_comp_copy_window){
		.geom = *geom,
		.direction = direction,
		.depth = depth,
		.group_bytes = group_bytes,
		.target_range = target_range,
	};
	return 0;
}

/* Existing CE/DMA callers retain the original slot geometry. */
static inline int xdev_ext_comp_copy_prepare(struct xdev_ext_comp_copy_window *out,
	int kind, const struct xdev_ext_window_copy_geom *geom,
	__u32 direction, __u32 depth, __u32 group_bytes)
{
	return xdev_ext_comp_copy_prepare_mode(out, kind, geom, direction, depth,
		group_bytes, false);
}

/* Worker: rejection leaves every byte of the previously admitted plan intact. */
static inline int xdev_ext_comp_copy_validate(
	const struct xdev_ext_comp_copy_window *window,
	const struct xdev_ext_mech_frame_info *frames, const __u32 *indices,
	__u32 nr_frames, const void *descriptors, __u32 n,
	__u32 max_entries, __u32 known_flags, __u32 slot, __u64 batch_id,
	struct xdev_ext_comp_copy_plan *out)
{
	__u64 host_off[XDEV_EXT_COMP_COPY_MAX_ENTRIES], offset = 0, total;
	__u64 target_start = 0, cursor = 0;
	__u32 i;
	int err;

	if (max_entries > XDEV_EXT_COMP_COPY_MAX_ENTRIES)
		return -EINVAL;
	if (n > XDEV_EXT_COMP_COPY_MAX_ENTRIES)
		return -E2BIG;
	err = xdev_ext_window_copy_plan_check(&window->geom, frames, indices,
		nr_frames, window->direction, descriptors, n, max_entries, known_flags,
		host_off, &total);
	if (err)
		return err;
	if (window->target_range) {
		if (!window->depth || slot >= window->depth || !window->group_bytes)
			return -EINVAL;
		if (total != window->group_bytes)
			return -EMSGSIZE;
	} else {
		err = xdev_ext_mech_window_offset(slot, window->depth, window->group_bytes,
						window->geom.window_len, &offset);
		if (err)
			return err;
	}
	for (i = 0; i < n; i++) {
		struct xdev_ext_window_copy_desc d;

		__builtin_memcpy(&d, (const __u8 *)descriptors + (size_t)i * sizeof(d),
				 sizeof(d));
		if (window->target_range) {
			if (!i)
				target_start = d.dev_off;
			if (d.dev_off < target_start || d.dev_off - target_start != cursor)
				return -EINVAL;
			if (cursor > total || d.len > total - cursor)
				return -ERANGE;
			cursor += d.len;
		} else if (d.dev_off < offset ||
			   !xdev_ext_mech_span_in(d.dev_off - offset, d.len, window->group_bytes)) {
			return -ERANGE;
		}
	}
	if (window->target_range &&
	    (!xdev_ext_mech_span_in(target_start, total, window->geom.window_len) || cursor != total))
		return -ERANGE;
	/* The descriptors are stable, worker-owned scratch. All fallible checks
	 * precede this commit; a rejected plan never changes the previous output.
	 * Read the entries again instead of keeping a full plan on the stack.
	 */
	__builtin_memset(out, 0, sizeof(*out));
	for (i = 0; i < n; i++) {
		struct xdev_ext_window_copy_desc d;

		__builtin_memcpy(&d, (const __u8 *)descriptors + (size_t)i * sizeof(d),
				 sizeof(d));
		out->entry[i] = (struct xdev_ext_comp_copy_entry){
			.host_byte_off = host_off[i],
			.device_off = d.dev_off,
			.frame_pos = d.frame_pos,
			.len = d.len,
			.flags = d.flags,
		};
	}
	out->batch_id = batch_id;
	out->total = total;
	out->target_range = window->target_range;
	if (window->target_range) {
		out->target_start = target_start;
		out->target_len = total;
	}
	out->slot = slot;
	out->n = n;
	return 0;
}

/* Worker: collect all current claims before changing any transfer output. */
static inline int xdev_ext_comp_copy_transfer(const struct xdev_ext_comp_copy_plan *plan,
	__u64 batch_id, __u32 slot, void *batch, xdev_ext_comp_claim_fn claim,
	struct xdev_ext_comp_copy_transfer *out)
{
	__u64 owner[XDEV_EXT_COMP_COPY_MAX_ENTRIES], generation[XDEV_EXT_COMP_COPY_MAX_ENTRIES];
	__u32 i;

	if (plan->batch_id != batch_id || plan->slot != slot)
		return -EPROTO;
	if (plan->n > XDEV_EXT_COMP_COPY_MAX_ENTRIES)
		return -E2BIG;
	for (i = 0; i < plan->n; i++)
		if (claim(batch, plan->entry[i].frame_pos, &owner[i], &generation[i]))
			return -ESTALE;
	for (i = 0; i < plan->n; i++)
		out[i] = (struct xdev_ext_comp_copy_transfer){
			.owner = owner[i],
			.generation = generation[i],
			.host_byte_off = plan->entry[i].host_byte_off,
			.device_off = plan->entry[i].device_off,
			.len = plan->entry[i].len,
			.flags = plan->entry[i].flags,
		};
	return 0;
}

#endif /* IO_URING_XDEV_EXT_COMPFAM_COPY_CORE_H */

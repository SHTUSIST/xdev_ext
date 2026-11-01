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

struct xdev_ext_comp_copy_window {
	struct xdev_ext_window_copy_geom geom;
	__u32 direction, depth, group_bytes;
};

struct xdev_ext_comp_copy_entry {
	__u64 host_byte_off, device_off;
	__u32 frame_pos, len, flags;
};

struct xdev_ext_comp_copy_plan {
	__u64 batch_id, total;
	__u32 slot, n;
	struct xdev_ext_comp_copy_entry entry[XDEV_EXT_DMA_MAX_ENTRIES];
};

struct xdev_ext_comp_copy_transfer {
	__u64 owner, generation, host_byte_off, device_off;
	__u32 len, flags;
};

typedef int (*xdev_ext_comp_claim_fn)(void *batch, __u32 frame_pos,
				    __u64 *owner, __u64 *generation);

/* CREATE: geometry has already passed the class's native bind checks. */
static inline int xdev_ext_comp_copy_prepare(struct xdev_ext_comp_copy_window *out,
	int kind, const struct xdev_ext_window_copy_geom *geom,
	__u32 direction, __u32 depth, __u32 group_bytes)
{
	__u64 offset;
	int err;

	if (kind != XDEV_EXT_COMP_COPY_WINDOW)
		return -EINVAL;
	if ((direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
	     direction != XDEV_EXT_MECH_DIR_FROM_DEVICE) ||
	    !(geom->directions & (1U << direction)))
		return -EOPNOTSUPP;
	err = xdev_ext_mech_window_offset(0, depth, group_bytes, geom->window_len,
					&offset);
	if (err)
		return err;
	*out = (struct xdev_ext_comp_copy_window){
		.geom = *geom,
		.direction = direction,
		.depth = depth,
		.group_bytes = group_bytes,
	};
	return 0;
}

/* Worker: rejection leaves every byte of the previously admitted plan intact. */
static inline int xdev_ext_comp_copy_validate(
	const struct xdev_ext_comp_copy_window *window,
	const struct xdev_ext_mech_frame_info *frames, const __u32 *indices,
	__u32 nr_frames, const void *descriptors, __u32 n,
	__u32 max_entries, __u32 known_flags, __u32 slot, __u64 batch_id,
	struct xdev_ext_comp_copy_plan *out)
{
	struct xdev_ext_comp_copy_plan plan = { 0 };
	__u64 host_off[XDEV_EXT_DMA_MAX_ENTRIES], offset;
	__u32 i;
	int err;

	if (max_entries > XDEV_EXT_DMA_MAX_ENTRIES)
		return -EINVAL;
	if (n > XDEV_EXT_DMA_MAX_ENTRIES)
		return -E2BIG;
	err = xdev_ext_window_copy_plan_check(&window->geom, frames, indices,
		nr_frames, window->direction, descriptors, n, max_entries, known_flags,
		host_off, &plan.total);
	if (err)
		return err;
	err = xdev_ext_mech_window_offset(slot, window->depth, window->group_bytes,
					window->geom.window_len, &offset);
	if (err)
		return err;
	for (i = 0; i < n; i++) {
		struct xdev_ext_window_copy_desc d;

		__builtin_memcpy(&d, (const __u8 *)descriptors + (size_t)i * sizeof(d),
				 sizeof(d));
		if (d.dev_off < offset ||
		    !xdev_ext_mech_span_in(d.dev_off - offset, d.len, window->group_bytes))
			return -ERANGE;
		plan.entry[i] = (struct xdev_ext_comp_copy_entry){
			.host_byte_off = host_off[i],
			.device_off = d.dev_off,
			.frame_pos = d.frame_pos,
			.len = d.len,
			.flags = d.flags,
		};
	}
	plan.batch_id = batch_id;
	plan.slot = slot;
	plan.n = n;
	*out = plan;
	return 0;
}

/* Worker: collect all current claims before changing any transfer output. */
static inline int xdev_ext_comp_copy_transfer(const struct xdev_ext_comp_copy_plan *plan,
	__u64 batch_id, __u32 slot, void *batch, xdev_ext_comp_claim_fn claim,
	struct xdev_ext_comp_copy_transfer *out)
{
	__u64 owner[XDEV_EXT_DMA_MAX_ENTRIES], generation[XDEV_EXT_DMA_MAX_ENTRIES];
	__u32 i;

	if (plan->batch_id != batch_id || plan->slot != slot)
		return -EPROTO;
	if (plan->n > XDEV_EXT_DMA_MAX_ENTRIES)
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

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_CE_LEASE_H
#define IO_URING_XDEV_EXT_MECH_CE_LEASE_H

#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <stdbool.h>
#include <errno.h>
#endif

/* Caller serializes all group/range checks and these transitions together.
 * A generation is the stable batch id, never the per-native-submit ticket.
 */
struct xdev_ext_ce_lease_slot {
	__u64 generation;
	bool active;
};

struct xdev_ext_ce_lease_state {
	__u32 active_batches;
	bool quarantined;
};

static inline bool xdev_ext_ce_lease_overlap(const void *backend_a,
		__u64 start_a, __u64 len_a, const void *backend_b,
		__u64 start_b, __u64 len_b)
{
	if (backend_a != backend_b)
		return false;
	/* Invalid geometry cannot authorize sharing. Bind rejects it too. */
	if (!len_a || !len_b || start_a > ~(__u64)0 - len_a ||
	    start_b > ~(__u64)0 - len_b)
		return true;
	return start_a < start_b + len_b && start_b < start_a + len_a;
}

static inline int xdev_ext_ce_lease_acquire(struct xdev_ext_ce_lease_state *state,
		struct xdev_ext_ce_lease_slot *slot, __u64 generation, bool conflict)
{
	if (!generation)
		return -EINVAL;
	if (state->quarantined)
		return -EBUSY;
	if (slot->active)
		return slot->generation == generation ? 0 : -EBUSY;
	if (!state->active_batches && conflict)
		return -EAGAIN;
	if (state->active_batches == ~(__u32)0)
		return -EOVERFLOW;
	slot->generation = generation;
	slot->active = true;
	state->active_batches++;
	return 0;
}

static inline int xdev_ext_ce_lease_finish(struct xdev_ext_ce_lease_state *state,
		struct xdev_ext_ce_lease_slot *slot, __u64 generation, bool sequestered)
{
	if (!slot->active)
		return 0;
	if (slot->generation != generation)
		return -ESTALE;
	if (sequestered)
		state->quarantined = true;
	if (state->quarantined)
		return -EBUSY;
	if (!state->active_batches)
		return -EPROTO;
	slot->active = false;
	state->active_batches--;
	return 0;
}

#endif /* IO_URING_XDEV_EXT_MECH_CE_LEASE_H */

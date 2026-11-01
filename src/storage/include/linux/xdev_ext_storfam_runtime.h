/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_STORFAM_RUNTIME_H
#define _LINUX_XDEV_EXT_STORFAM_RUNTIME_H

#include <linux/types.h>
#ifndef __KERNEL__
#include <stdbool.h>
#endif

struct xdev_ext_mech_batch;

/* Embedded in member-owned native resources; only the session worker links it. */
struct xdev_ext_stor_slot {
	struct xdev_ext_stor_slot *next;
	bool busy;
};

struct xdev_ext_stor_pool {
	struct xdev_ext_stor_slot *free;
};

/* Captured before native submission; never reload a reused batch's ticket. */
struct xdev_ext_stor_completion {
	struct xdev_ext_mech_batch *b;
	__u64 ticket;
	bool uncertain;
	/* Worker observes only queue identity, never a native request pointer.
	 * A stale live observation permits one extra safe queue poll. */
	bool poll_live;
	__u32 poll_queue;
};

void xdev_ext_stor_slot_add(struct xdev_ext_stor_pool *pool,
			  struct xdev_ext_stor_slot *slot);
struct xdev_ext_stor_slot *
xdev_ext_stor_slot_get(struct xdev_ext_stor_pool *pool, bool occupied);
void xdev_ext_stor_slot_put(struct xdev_ext_stor_pool *pool,
			  struct xdev_ext_stor_slot *slot, bool uncertain);

/* complete classifies native status and writes the member CQE under claim.
 * ready optionally makes compatibility bytes visible before publication.
 * Neither callback may release a slot or provider lease. */
void xdev_ext_stor_done(struct xdev_ext_stor_completion *done,
		       int transport_status, void *native,
		       int (*complete)(struct xdev_ext_mech_batch *, void *, int, bool *),
		       void (*ready)(struct xdev_ext_mech_batch *, int, bool));

#endif

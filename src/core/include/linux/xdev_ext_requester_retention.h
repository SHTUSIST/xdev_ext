/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_REQUESTER_RETENTION_H
#define _LINUX_XDEV_EXT_REQUESTER_RETENTION_H

#include <linux/types.h>

struct pci_dev;
struct xdev_ext_requester_retention;
struct xdev_ext_requester_retention_stats {
	u32 generations, retained_generations;
	u64 reserved_bytes, retained_bytes;
	u64 global_reserved_bytes, global_retained_bytes, global_limit;
};

/* Reserve before allocating a generation's DMA backing.  The generation
 * limit comes from the requester's native queue/hop capacity; worst_bytes
 * includes every descriptor and control allocation the generation can own.
 */
struct xdev_ext_requester_retention *
xdev_ext_requester_retention_reserve(struct pci_dev *pdev, u32 generation_limit,
				   u64 worst_bytes);
/* After all software callback barriers, transfer accounting to the built-in
 * inert ledger.  actual_bytes must describe exactly the UNKNOWN DMA backing
 * retained from this generation and must not exceed the reservation.
 * This is irreversible: release cannot reclaim a retained record.
 */
void xdev_ext_requester_retention_retain(struct xdev_ext_requester_retention *r,
				       u64 actual_bytes);
/* Only after the caller has actually freed all non-retained DMA backing. */
void xdev_ext_requester_retention_release(struct xdev_ext_requester_retention *r);
void xdev_ext_requester_retention_snapshot(struct pci_dev *pdev,
			struct xdev_ext_requester_retention_stats *stats);
#endif

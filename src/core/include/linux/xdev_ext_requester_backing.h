/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_REQUESTER_BACKING_H
#define _LINUX_XDEV_EXT_REQUESTER_BACKING_H

#include <linux/gfp_types.h>
#include <linux/types.h>

struct pci_dev;
struct xdev_ext_requester_backing;

struct xdev_ext_requester_backing_view {
	void *cpu;
	dma_addr_t dma;
	size_t bytes;
};

/* NULL on allocation failure. The caller owns admission and budget accounting. */
struct xdev_ext_requester_backing *xdev_ext_requester_backing_alloc(
		struct pci_dev *pdev, size_t bytes, gfp_t gfp);
/* The view is borrowed until retirement; the caller serializes both operations. */
void xdev_ext_requester_backing_view(struct xdev_ext_requester_backing *b,
		struct xdev_ext_requester_backing_view *view);
/* After the native callback barrier, consume *bp without allocating. The caller
 * proves known storage is safe to free. UNKNOWN storage stays inert in core;
 * return its full byte count for the caller's existing retention ledger.
 * An empty handle returns zero.
 */
u64 xdev_ext_requester_backing_retire(struct xdev_ext_requester_backing **bp,
		bool unknown);

#endif

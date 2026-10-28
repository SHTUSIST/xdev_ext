// SPDX-License-Identifier: GPL-2.0
/* Built-in requester DMA budget.  Retained records contain no subclass
 * module pointer, destructor or executable callback, and survive its unload.
 */
#include <linux/err.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/xdev_ext_requester_retention.h>

#define XDEV_EXT_REQUESTER_RETENTION_LIMIT (64ULL * 1024 * 1024)

struct xdev_ext_requester_retention {
	struct list_head node;
	struct pci_dev *pdev;
	u64 reserved, retained;
	bool unknown;
};
static LIST_HEAD(xdev_ext_requester_retention_records);
static DEFINE_SPINLOCK(xdev_ext_requester_retention_lock);
static u64 xdev_ext_requester_reserved, xdev_ext_requester_retained;

struct xdev_ext_requester_retention *
xdev_ext_requester_retention_reserve(struct pci_dev *pdev, u32 generation_limit,
				   u64 worst_bytes)
{
	struct xdev_ext_requester_retention *r, *p;
	unsigned long flags;
	u32 count = 0;

	if (!generation_limit || !worst_bytes)
		return ERR_PTR(-EINVAL);
	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);
	r->pdev = pci_dev_get(pdev);
	r->reserved = worst_bytes;
	spin_lock_irqsave(&xdev_ext_requester_retention_lock, flags);
	list_for_each_entry(p, &xdev_ext_requester_retention_records, node)
		if (p->pdev == pdev)
			count++;
	if (count >= generation_limit ||
	    worst_bytes > XDEV_EXT_REQUESTER_RETENTION_LIMIT - xdev_ext_requester_reserved) {
		spin_unlock_irqrestore(&xdev_ext_requester_retention_lock, flags);
		pci_dev_put(r->pdev);
		kfree(r);
		return ERR_PTR(-ENOSPC);
	}
	list_add_tail(&r->node, &xdev_ext_requester_retention_records);
	xdev_ext_requester_reserved += worst_bytes;
	spin_unlock_irqrestore(&xdev_ext_requester_retention_lock, flags);
	return r;
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_retention_reserve);

void xdev_ext_requester_retention_retain(struct xdev_ext_requester_retention *r,
				       u64 actual_bytes)
{
	unsigned long flags;

	spin_lock_irqsave(&xdev_ext_requester_retention_lock, flags);
	if (!r->unknown) {
		/* Exclusive generation owner calls once after the callback barrier.
		 * A repeated retain cannot add the same backing a second time.
		 */
		WARN_ON_ONCE(!actual_bytes || actual_bytes > r->reserved);
		r->unknown = true;
		r->retained = actual_bytes;
		xdev_ext_requester_retained += actual_bytes;
	}
	spin_unlock_irqrestore(&xdev_ext_requester_retention_lock, flags);
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_retention_retain);

void xdev_ext_requester_retention_release(struct xdev_ext_requester_retention *r)
{
	unsigned long flags;

	if (!r)
		return;
	spin_lock_irqsave(&xdev_ext_requester_retention_lock, flags);
	if (r->unknown) {
		spin_unlock_irqrestore(&xdev_ext_requester_retention_lock, flags);
		return;
	}
	list_del(&r->node);
	xdev_ext_requester_reserved -= r->reserved;
	spin_unlock_irqrestore(&xdev_ext_requester_retention_lock, flags);
	pci_dev_put(r->pdev);
	kfree(r);
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_retention_release);

void xdev_ext_requester_retention_snapshot(struct pci_dev *pdev,
			struct xdev_ext_requester_retention_stats *stats)
{
	struct xdev_ext_requester_retention *r;
	unsigned long flags;

	*stats = (struct xdev_ext_requester_retention_stats) {};
	spin_lock_irqsave(&xdev_ext_requester_retention_lock, flags);
	stats->global_reserved_bytes = xdev_ext_requester_reserved;
	stats->global_retained_bytes = xdev_ext_requester_retained;
	stats->global_limit = XDEV_EXT_REQUESTER_RETENTION_LIMIT;
	list_for_each_entry(r, &xdev_ext_requester_retention_records, node) {
		if (r->pdev != pdev)
			continue;
		stats->generations++;
		stats->reserved_bytes += r->reserved;
		stats->retained_bytes += r->retained;
		if (r->unknown)
			stats->retained_generations++;
	}
	spin_unlock_irqrestore(&xdev_ext_requester_retention_lock, flags);
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_retention_snapshot);

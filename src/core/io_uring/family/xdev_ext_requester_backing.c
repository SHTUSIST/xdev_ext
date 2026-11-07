// SPDX-License-Identifier: GPL-2.0
/* Built-in coherent storage owner. Retained records have no executable pointer
 * or reference to a device module's live state.
 */
#include <linux/dma-mapping.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/xdev_ext_requester_backing.h>

struct xdev_ext_requester_backing {
	struct list_head node;
	struct pci_dev *pdev;
	void *cpu;
	dma_addr_t dma;
	size_t bytes;
};

static LIST_HEAD(xdev_ext_requester_backing_retained);
static DEFINE_SPINLOCK(xdev_ext_requester_backing_lock);

struct xdev_ext_requester_backing *xdev_ext_requester_backing_alloc(
		struct pci_dev *pdev, size_t bytes, gfp_t gfp)
{
	struct xdev_ext_requester_backing *b;

	b = kzalloc(sizeof(*b), gfp);
	if (!b)
		return NULL;
	INIT_LIST_HEAD(&b->node);
	b->pdev = pci_dev_get(pdev);
	b->bytes = bytes;
	b->cpu = dma_alloc_coherent(&b->pdev->dev, bytes, &b->dma, gfp);
	if (!b->cpu) {
		pci_dev_put(b->pdev);
		kfree(b);
		return NULL;
	}
	return b;
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_backing_alloc);

void xdev_ext_requester_backing_view(struct xdev_ext_requester_backing *b,
		struct xdev_ext_requester_backing_view *view)
{
	*view = (struct xdev_ext_requester_backing_view) {
		.cpu = b->cpu, .dma = b->dma, .bytes = b->bytes,
	};
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_backing_view);

u64 xdev_ext_requester_backing_retire(struct xdev_ext_requester_backing **bp,
		bool unknown)
{
	struct xdev_ext_requester_backing *b = *bp;
	unsigned long flags;
	u64 retained;

	if (!b)
		return 0;
	*bp = NULL;
	if (unknown) {
		retained = b->bytes;
		spin_lock_irqsave(&xdev_ext_requester_backing_lock, flags);
		list_add_tail(&b->node, &xdev_ext_requester_backing_retained);
		spin_unlock_irqrestore(&xdev_ext_requester_backing_lock, flags);
		return retained;
	}
	dma_free_coherent(&b->pdev->dev, b->bytes, b->cpu, b->dma);
	pci_dev_put(b->pdev);
	kfree(b);
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_backing_retire);

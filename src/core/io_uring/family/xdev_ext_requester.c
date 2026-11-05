// SPDX-License-Identifier: GPL-2.0
/* Requester base below every device family: leases and bind-time admission. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/iommu-dma.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/pci-p2pdma.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/swiotlb.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_requester.h>

/* The ring's IOU_UMEM pool mapped page by page for one requester, with the
 * stage's direction. A record with an outstanding or unknown lease is never
 * unmapped; it keeps its device reference and has no module pointer. */
struct xdev_ext_requester_host {
	struct list_head node;
	struct pci_dev *pdev;
	dma_addr_t *dma;		/* nr_pages entries; NULL once retained */
	u64 bytes;
	u32 nr_pages, frame_size;
	enum dma_data_direction dir;
	atomic_t active;		/* leases granted and not yet released */
	bool need_sync, unknown;
};

static LIST_HEAD(xdev_ext_requester_host_retained);
static DEFINE_SPINLOCK(xdev_ext_requester_host_lock);

static void xdev_ext_requester_host_unmap(struct xdev_ext_requester_host *h, u32 nr)
{
	while (nr--)
		dma_unmap_page_attrs(&h->pdev->dev, h->dma[nr], PAGE_SIZE, h->dir,
				     DMA_ATTR_SKIP_CPU_SYNC);
}

/*
 * An outstanding lease or an unknown end: the device may still use pages.
 * Lockless, so the lease count is read first, with acquire semantics, pairing
 * with smp_mb__before_atomic() in xdev_ext_requester_host_release(): a release
 * whose decrement is seen here has its unknown mark seen by the read after
 * it. Reading the mark first could miss both the mark and the lease of a
 * release that ends between the two reads.
 */
static bool xdev_ext_requester_host_busy(const struct xdev_ext_requester_host *h)
{
	return atomic_read_acquire(&h->active) || READ_ONCE(h->unknown);
}

static void xdev_ext_requester_host_free(struct xdev_ext_requester_host *h)
{
	pci_dev_put(h->pdev);
	kvfree(h->dma);
	kfree(h);
}

/*
 * CREATE: map every page of the IOU_UMEM pool whole for @pdev. A device that
 * is not coherent, or bounced, gets explicit syncs per lease. An NHI element
 * is one contiguous DMA segment of at most 4 KiB, so the pool must start on a
 * page boundary (else every element spans two pages) and end on one (else
 * the device would see bytes outside the pool).
 */
int xdev_ext_requester_bind_host(struct xdev_ext_requester *rq,
		struct xdev_ext_mech_stage *st, struct pci_dev *pdev)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	struct xdev_ext_requester_host *h;
	u32 i;

	if (pool->kind != XDEV_EXT_MECH_POOL_IOU_UMEM || !pdev || rq->pdev)
		return -EINVAL;
	if (!pool->pages || !pool->nr_pages || !pool->frame_size ||
	    (pool->frame_size & (pool->frame_size - 1)) || pool->first_page_off ||
	    pool->size != (u64)pool->nr_pages << PAGE_SHIFT)
		return -EINVAL;
	if (st->create_reporting) {
		st->create_requester = pci_dev_get(pdev);
		st->create_requester_id = (struct xdev_ext_mech_requester_id) {
			.domain = pci_domain_nr(pdev->bus), .bus = pdev->bus->number,
			.devfn = pdev->devfn,
		};
		st->create_valid |= XDEV_EXT_MECH_CREATE_VALID_REQUESTER |
				    XDEV_EXT_MECH_CREATE_VALID_DECIDED;
		st->create_phase = XDEV_EXT_MECH_CREATE_REQUESTER_PREMAP;
	}
	rq->adm = (struct xdev_ext_admission) {
		.reachability = XDEV_EXT_CAP_UNKNOWN, .distance = -1,
		.backing = XDEV_EXT_PEER_BACKING_HOST_SYSTEM | XDEV_EXT_PEER_BACKING_STRUCT_PAGE,
	};
	st->caps.p2p_distance = -1;
	st->caps.backing = rq->adm.backing;
	st->caps.refused = 0;
	h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return -ENOMEM;
	h->dma = kvcalloc(pool->nr_pages, sizeof(*h->dma), GFP_KERNEL);
	if (!h->dma) {
		kfree(h);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&h->node);
	h->pdev = pci_dev_get(pdev);
	h->bytes = pool->size;
	h->nr_pages = pool->nr_pages;
	h->frame_size = pool->frame_size;
	h->dir = st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE ? DMA_FROM_DEVICE : DMA_TO_DEVICE;
	for (i = 0; i < h->nr_pages; i++) {
		h->dma[i] = dma_map_page_attrs(&pdev->dev, pool->pages[i], 0, PAGE_SIZE,
					       h->dir, DMA_ATTR_SKIP_CPU_SYNC);
		if (dma_mapping_error(&pdev->dev, h->dma[i])) {
			xdev_ext_requester_host_unmap(h, i);
			xdev_ext_requester_host_free(h);
			return -ENOMEM;
		}
		h->need_sync |= dma_need_sync(&pdev->dev, h->dma[i]);
	}
	rq->adm.reachability = XDEV_EXT_CAP_HOST_DMA_MAPPED;
	st->caps.reachability = XDEV_EXT_CAP_HOST_DMA_MAPPED;
	st->caps.requester_mapping = XDEV_EXT_CAP_ESTABLISHED;
	rq->host = h;
	rq->pdev = pci_dev_get(pdev);
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_bind_host);

void xdev_ext_requester_unbind_host(struct xdev_ext_requester *rq)
{
	struct xdev_ext_requester_host *h = rq->host;
	unsigned long flags;

	rq->host = NULL;
	/*
	 * Not reached with a busy mapping: the core calls the class unbind only
	 * after xdev_ext_requester_host_settled() returned 0, and otherwise
	 * quarantines the session with its pool, whose UMEM reference keeps every
	 * page pinned (xdev_ext_mech_session_release_disposition()); a failed
	 * class bind unbinds before any lease. A busy mapping here means a caller
	 * skipped that check. The device may still access these pages: the
	 * mapping and its device ref are kept for good, but the pages stay pinned
	 * only while the caller keeps the pool.
	 */
	if (h && WARN_ON_ONCE(xdev_ext_requester_host_busy(h))) {
		kvfree(h->dma);
		h->dma = NULL;
		spin_lock_irqsave(&xdev_ext_requester_host_lock, flags);
		list_add_tail(&h->node, &xdev_ext_requester_host_retained);
		spin_unlock_irqrestore(&xdev_ext_requester_host_lock, flags);
	} else if (h) {
		xdev_ext_requester_host_unmap(h, h->nr_pages);
		xdev_ext_requester_host_free(h);
	}
	xdev_ext_requester_unbind(rq);
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_unbind_host);

int xdev_ext_requester_host_lease(struct xdev_ext_requester *rq, u64 off, u32 len,
				  enum dma_data_direction dir, u64 *dma)
{
	struct xdev_ext_requester_host *h = rq->host;
	u64 frame_mask, page_off;
	dma_addr_t addr;

	if (!h)
		return -EINVAL;
	if (READ_ONCE(h->unknown))
		return -ESTALE;
	if (dir != h->dir)
		return -EACCES;
	frame_mask = ~(u64)(h->frame_size - 1);
	page_off = off & ~PAGE_MASK;
	if (!len || off >= h->bytes || len > h->bytes - off || len > PAGE_SIZE - page_off ||
	    (off & frame_mask) != ((off + len - 1) & frame_mask))
		return -ERANGE;
	addr = h->dma[off >> PAGE_SHIFT] + page_off;
	if (h->need_sync)
		dma_sync_single_for_device(&h->pdev->dev, addr, len, h->dir);
	atomic_inc(&h->active);
	*dma = addr;
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_host_lease);

void xdev_ext_requester_host_release(struct xdev_ext_requester *rq, u64 dma,
				     u32 len, bool quiesced)
{
	struct xdev_ext_requester_host *h = rq->host;

	if (WARN_ON_ONCE(!h))
		return;
	if (!quiesced)
		WRITE_ONCE(h->unknown, true);
	else if (h->need_sync && h->dir == DMA_FROM_DEVICE)
		dma_sync_single_for_cpu(&h->pdev->dev, dma, len, DMA_FROM_DEVICE);
	/* The mark is visible before the count drops; pairs with the acquire
	 * read in xdev_ext_requester_host_busy(). */
	smp_mb__before_atomic();
	atomic_dec(&h->active);
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_host_release);

int xdev_ext_requester_host_settled(const struct xdev_ext_requester *rq)
{
	const struct xdev_ext_requester_host *h = rq->host;

	return h && xdev_ext_requester_host_busy(h) ? -EIO : 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_host_settled);

int xdev_ext_peer_lease_split(struct file *authority, struct pci_dev *requester,
			    u64 generation, u64 off, u32 left,
			    enum dma_data_direction dir,
			    struct xdev_ext_peer_fd_lease *l)
{
	u32 shift = 31, len = left;
	int ret;

	for (;;) {
		ret = xdev_ext_peer_file_acquire(authority, requester, generation,
					       off, len, dir, l);
		if (ret != -ERANGE)
			return ret;
		len = xdev_ext_lease_shrink(off, len, &shift,
					  XDEV_EXT_LEASE_MIN_SHIFT);
		if (!len)
			return ret;
	}
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_lease_split);

int xdev_ext_requester_bind(struct xdev_ext_requester *rq, struct xdev_ext_mech_stage *st,
			  struct pci_dev *pdev, u32 admit_flags)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	struct xdev_ext_peer_backing back;
	struct xdev_ext_admit_facts f = { .distance = -1 };
	int ret;

	if (pool->kind != XDEV_EXT_MECH_POOL_PEER || !pdev || rq->pdev)
		return -EINVAL;
 if (st->create_reporting) {
  st->create_requester = pci_dev_get(pdev);
  st->create_requester_id = (struct xdev_ext_mech_requester_id) {
   .domain = pci_domain_nr(pdev->bus), .bus = pdev->bus->number,
   .devfn = pdev->devfn,
  };
  st->create_valid |= XDEV_EXT_MECH_CREATE_VALID_REQUESTER;
  st->create_phase = XDEV_EXT_MECH_CREATE_REQUESTER_DESCRIBE;
 }
	rq->authority = xdev_ext_peer_mech_pool_file(pool);
	rq->generation = xdev_ext_peer_mech_pool_generation(pool);
	ret = xdev_ext_peer_file_describe(rq->authority, pdev, &back);
	if (ret && ret != -EOPNOTSUPP)
		return ret;
 if (st->create_reporting) {
  if (!ret)
   st->create_valid |= XDEV_EXT_MECH_CREATE_VALID_DESCRIBED;
  st->create_phase = XDEV_EXT_MECH_CREATE_REQUESTER_DECIDE;
 }
	f.backing = ret ? 0 : back.flags;
	f.owner_known = !ret && back.owner;
	if (f.owner_known)
		f.distance = pci_p2pdma_distance(back.owner, &pdev->dev, true);
	f.untrusted = pdev->untrusted;
	f.swiotlb_force = is_swiotlb_force_bounce(&pdev->dev);
	f.dma_iommu = use_dma_iommu(&pdev->dev);
	f.dma_ops = get_dma_ops(&pdev->dev) != NULL;
	f.admin = capable(CAP_SYS_ADMIN);
	ret = xdev_ext_admit_decide(&f, admit_flags, &rq->adm);
 if (st->create_reporting)
  st->create_valid |= XDEV_EXT_MECH_CREATE_VALID_DECIDED;
	st->caps.reachability = rq->adm.reachability;
	st->caps.p2p_distance = rq->adm.distance;
	st->caps.backing = rq->adm.backing;
	st->caps.refused = rq->adm.refused;
	if (ret)
		return ret;
 if (st->create_reporting)
  st->create_phase = XDEV_EXT_MECH_CREATE_REQUESTER_PREMAP;
	ret = xdev_ext_peer_file_premap(rq->authority, pdev);
	if (ret)
		return ret;
	if (rq->adm.backing & XDEV_EXT_PEER_BACKING_HOST_SYSTEM) {
		rq->adm.reachability = XDEV_EXT_CAP_HOST_DMA_MAPPED;
		st->caps.reachability = XDEV_EXT_CAP_HOST_DMA_MAPPED;
	}
	st->caps.requester_mapping = XDEV_EXT_CAP_ESTABLISHED;
	rq->pdev = pci_dev_get(pdev);
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_bind);

void xdev_ext_requester_unbind(struct xdev_ext_requester *rq)
{
	pci_dev_put(rq->pdev);
	rq->pdev = NULL;
}
EXPORT_SYMBOL_GPL(xdev_ext_requester_unbind);

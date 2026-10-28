// SPDX-License-Identifier: GPL-2.0
/* Requester base below every device family: leases and bind-time admission. */
#include <linux/capability.h>
#include <linux/dma-map-ops.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/iommu-dma.h>
#include <linux/pci.h>
#include <linux/pci-p2pdma.h>
#include <linux/swiotlb.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_requester.h>

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

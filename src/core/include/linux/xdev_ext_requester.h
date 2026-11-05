/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_REQUESTER_H
#define _LINUX_XDEV_EXT_REQUESTER_H

#include <linux/dma-direction.h>
#include <linux/types.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_requester_core.h>

struct file;
struct pci_dev;
struct xdev_ext_mech_stage;
struct xdev_ext_requester_host;

struct xdev_ext_requester {
	struct pci_dev *pdev;	/* pci_dev_get() while bound */
	struct file *authority;	/* borrowed from the session pool */
	u64 generation;
	struct xdev_ext_admission adm;
	/* IOU_UMEM pool: its pages mapped for pdev; NULL on a PEER pool */
	struct xdev_ext_requester_host *host;
};

/* CREATE, process context: judge reachability before creating the mapping.
 * On the ring's IOU_UMEM pool, map every pool page for @pdev instead; the
 * pool must start and end on page boundaries (-EINVAL). */
int xdev_ext_requester_bind(struct xdev_ext_requester *rq,
			  struct xdev_ext_mech_stage *st, struct pci_dev *pdev,
			  u32 admit_flags);
/* Process context, after device use has ended: release the requester ref.
 * A host mapping with an outstanding or unknown lease is kept, never unmapped. */
void xdev_ext_requester_unbind(struct xdev_ext_requester *rq);

/* Worker, host mapping: the requester's DMA address of pool bytes
 * [off, off + len), synchronized for the device. The span must lie in one
 * page and one frame (-ERANGE) and follow the mapping direction (-EACCES);
 * -ESTALE once a lease ended with unknown device access; -EINVAL without a
 * host mapping. */
int xdev_ext_requester_host_lease(struct xdev_ext_requester *rq, u64 off, u32 len,
				  enum dma_data_direction dir, dma_addr_t *dma);
/* Any context, once per granted lease: a quiesced receive buffer is
 * synchronized for the CPU; an unquiesced end keeps the whole mapping. */
void xdev_ext_requester_host_release(struct xdev_ext_requester *rq, dma_addr_t dma,
				     u32 len, bool quiesced);
/* Process context: 0 when unbind may unmap the host mapping (or there is
 * none); -EIO with an outstanding lease or after unknown device access. */
int xdev_ext_requester_host_settled(const struct xdev_ext_requester *rq);

/* Worker: lease [off, off + left) or its longest prefix inside one provider
 * page; l->lease.len is what was leased. -ERANGE when the provider refuses
 * even the last candidate at a 4 KiB page boundary.
 */
int xdev_ext_peer_lease_split(struct file *authority, struct pci_dev *requester,
			    u64 generation, u64 off, u32 left,
			    enum dma_data_direction dir,
			    struct xdev_ext_peer_fd_lease *l);

#endif

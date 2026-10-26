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

struct xdev_ext_requester {
	struct pci_dev *pdev;	/* pci_dev_get() while bound */
	struct file *authority;	/* borrowed from the session pool */
	u64 generation;
	struct xdev_ext_admission adm;
};

/* CREATE, process context: judge reachability before creating the mapping. */
int xdev_ext_requester_bind(struct xdev_ext_requester *rq,
			  struct xdev_ext_mech_stage *st, struct pci_dev *pdev,
			  u32 admit_flags);
/* Process context, after device use has ended: release the requester ref. */
void xdev_ext_requester_unbind(struct xdev_ext_requester *rq);

/* Worker: lease [off, off + left) or its longest prefix inside one provider
 * page; l->lease.len is what was leased. -ERANGE when the provider refuses
 * even the last candidate at a 4 KiB page boundary.
 */
int xdev_ext_peer_lease_split(struct file *authority, struct pci_dev *requester,
			    u64 generation, u64 off, u32 left,
			    enum dma_data_direction dir,
			    struct xdev_ext_peer_fd_lease *l);

#endif

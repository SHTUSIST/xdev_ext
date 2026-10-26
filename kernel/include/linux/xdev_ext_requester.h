/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_REQUESTER_H
#define _LINUX_XDEV_EXT_REQUESTER_H

#include <linux/dma-direction.h>
#include <linux/types.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_requester_core.h>

struct file;
struct pci_dev;

/* Worker: lease [off, off + left) or its longest prefix inside one provider
 * page; l->lease.len is what was leased. -ERANGE when the provider refuses
 * even the last candidate at a 4 KiB page boundary.
 */
int xdev_ext_peer_lease_split(struct file *authority, struct pci_dev *requester,
			    u64 generation, u64 off, u32 left,
			    enum dma_data_direction dir,
			    struct xdev_ext_peer_fd_lease *l);

#endif

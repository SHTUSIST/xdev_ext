// SPDX-License-Identifier: GPL-2.0
/* Requester base below every device family: device-memory lease split. */
#include <linux/errno.h>
#include <linux/export.h>
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

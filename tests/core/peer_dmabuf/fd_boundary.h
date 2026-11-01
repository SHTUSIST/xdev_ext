/* SPDX-License-Identifier: GPL-2.0 */
/* The existing allocation/authority fd adapter's private shape, frozen from
 * 56e before the importer implementation. Only actual close functions are
 * compiled into the companion TU; no substitute close algorithm is supplied. */
struct xdev_ext_peer_authority;
struct xdev_ext_peer_fd {
	struct mutex lock;
	struct xdev_ext_peer_region *region;
	struct list_head maps;
	struct xdev_ext_peer_authority *claimed;
};
struct xdev_ext_peer_authority {
	struct file *original;
	struct xdev_ext_peer_fd *parent;
};
struct xdev_ext_peer_fd_map {
	struct list_head node;
	struct pci_dev *peer;
	struct xdev_ext_peer_mapping *mapping;
};
struct test_authority_handle;
struct test_authority_handle *test_authority_setup(struct xdev_ext_peer_region *,
					struct xdev_ext_peer_mapping *, struct pci_dev *);
bool test_authority_close(struct test_authority_handle *);
void test_authority_destroy_closed(struct test_authority_handle *);

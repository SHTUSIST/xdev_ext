/* SPDX-License-Identifier: GPL-2.0 */
/* Frozen public interfaces only. Used to compile the independent test fixture
 * before production is available; it supplies no importer implementation. */
#ifndef _TEST_DMABUF_CONTRACT_H
#define _TEST_DMABUF_CONTRACT_H
#include "include/linux/xdev_ext_peer.h"
#define XDEV_EXT_PEER_BACKING_MMIO_BAR (1U << 0)
#define XDEV_EXT_PEER_BACKING_STRUCT_PAGE (1U << 1)
#define XDEV_EXT_PEER_BACKING_COHERENT_C2C (1U << 2)
#define XDEV_EXT_PEER_BACKING_EXTERNAL (1U << 3)
#define XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR (1U << 4)
#define XDEV_EXT_PEER_BACKING_HOST_SYSTEM (1U << 5)
/* Prototype for ASK.70: opt-in import of an exporter without a descriptor. */
#define XDEV_EXT_PEER_BACKING_UNDESCRIBED (1U << 6)
#define XDEV_EXT_PEER_DMABUF_IMPORT_UNDESCRIBED (1U << 0)
struct xdev_ext_peer_dmabuf_desc_ops {
	struct module *owner;
	const struct dma_buf_ops *ops;
	int (*describe)(struct dma_buf *, struct pci_dev *, struct xdev_ext_peer_backing *);
};
int xdev_ext_peer_dmabuf_desc_register(const struct xdev_ext_peer_dmabuf_desc_ops *);
int xdev_ext_peer_dmabuf_desc_unregister(const struct xdev_ext_peer_dmabuf_desc_ops *);
int xdev_ext_peer_dmabuf_import(struct dma_buf *, u64, struct xdev_ext_peer_region **);
int xdev_ext_peer_dmabuf_import_flags(struct dma_buf *, u64, u32, struct xdev_ext_peer_region **);
int xdev_ext_peer_dmabuf_geometry(const struct sg_table *, u64, u64 **, u32 *);
int xdev_ext_peer_drainable(struct xdev_ext_peer_region *);
#endif

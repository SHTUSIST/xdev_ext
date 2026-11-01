/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_PEER_DMABUF_H
#define _LINUX_XDEV_EXT_PEER_DMABUF_H

#include <linux/errno.h>
#include <linux/types.h>

struct module;
struct dma_buf;
struct dma_buf_ops;
struct sg_table;
struct pci_dev;
struct xdev_ext_peer_backing;
struct xdev_ext_peer_region;

/* Only the exporter which owns this exact ops object can describe its backing.
 * The callback runs in process context without the descriptor registry lock.
 */
struct xdev_ext_peer_dmabuf_desc_ops {
 struct module *owner;
 const struct dma_buf_ops *ops;
 int (*describe)(struct dma_buf *, struct pci_dev *,
                 struct xdev_ext_peer_backing *);
};

#if IS_ENABLED(CONFIG_XDEV_EXT_PEER_DMABUF)
int xdev_ext_peer_dmabuf_desc_register(const struct xdev_ext_peer_dmabuf_desc_ops *);
int xdev_ext_peer_dmabuf_desc_unregister(const struct xdev_ext_peer_dmabuf_desc_ops *);
/* Success consumes one buf reference; failure consumes none. */
int xdev_ext_peer_dmabuf_import(struct dma_buf *, u64 len,
                               struct xdev_ext_peer_region **);
int xdev_ext_peer_dmabuf_geometry(const struct sg_table *, u64 len,
                                 u64 **addresses, u32 *entries);
#else
static inline int xdev_ext_peer_dmabuf_desc_register(
 const struct xdev_ext_peer_dmabuf_desc_ops *ops)
{ return -EOPNOTSUPP; }
static inline int xdev_ext_peer_dmabuf_desc_unregister(
 const struct xdev_ext_peer_dmabuf_desc_ops *ops)
{ return -EOPNOTSUPP; }
static inline int xdev_ext_peer_dmabuf_import(struct dma_buf *buf, u64 len,
                                             struct xdev_ext_peer_region **out)
{
 if (out) *out = NULL;
 return -EOPNOTSUPP;
}
#endif
#endif

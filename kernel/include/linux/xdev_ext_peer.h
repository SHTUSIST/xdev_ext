/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_PEER_H
#define _LINUX_XDEV_EXT_PEER_H
#ifndef XDEV_EXT_PEER_HOST_TEST
#include <linux/types.h>
#include <linux/dma-direction.h>
#endif
struct file;
struct file_operations;
struct module;
struct pci_dev;
struct xdev_ext_peer_region;
struct xdev_ext_peer_mapping;
/* Provider-private addresses, never exposed to BPF or userspace. */
struct xdev_ext_peer_dma {
 void *private;
 const u64 *addresses;
 u32 entries;
 u8 page_shift;
};
struct xdev_ext_peer_provider_ops {
 struct module *owner;
 const struct file_operations *fops;
 /* Caller context: validate the file's GPU and pin the caller's allocation. */
 int (*pin)(struct file *, u64 gpu_va, u64 len, void **allocation);
 int (*unpin)(void *allocation);
 int (*map)(void *allocation, struct pci_dev *, struct xdev_ext_peer_dma *);
 int (*unmap)(void *allocation, struct pci_dev *, struct xdev_ext_peer_dma *);
};
/* A lease is owned by one native request. Do not copy or reuse until release.
 * The peer device may use only dma_address..+len; no CPU struct page exists.
 */
struct xdev_ext_peer_lease {
 struct xdev_ext_peer_mapping *mapping;
 struct xdev_ext_peer_lease *next;
 u64 ticket;
 u64 dma_address;
 u32 len;
};
/* Native TX ownership: negative submit means no callback/DMA. Zero means
 * exactly one complete(), possibly synchronous, and no command resubmission.
 * Completion is any context; common code defers sleepable lease release.
 */
struct xdev_ext_peer_tx {
 u64 dma_address;
 u32 len;
 u16 header_len;
 const u8 *header;
 void (*complete)(struct xdev_ext_peer_tx *, int status, bool quiesced);
};
struct xdev_ext_peer_fd_lease {
 struct xdev_ext_peer_lease lease;
 struct file *file;
};
int xdev_ext_peer_file_acquire(struct file *, struct pci_dev *, u64 generation, u64 offset,
                              u32 len, enum dma_data_direction, struct xdev_ext_peer_fd_lease *);
int xdev_ext_peer_fd_acquire(int fd, struct pci_dev *, u64 generation, u64 offset,
                            u32 len, enum dma_data_direction, struct xdev_ext_peer_fd_lease *);
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *, bool quiesced);
long xdev_ext_peer_net_ioctl(unsigned long arg);
int xdev_ext_peer_provider_register(const struct xdev_ext_peer_provider_ops *);
int xdev_ext_peer_provider_unregister(const struct xdev_ext_peer_provider_ops *);
int xdev_ext_peer_pin(struct file *, u64 gpu_va, u64 len, struct xdev_ext_peer_region **);
u64 xdev_ext_peer_generation(struct xdev_ext_peer_region *);
int xdev_ext_peer_map(struct xdev_ext_peer_region *, struct pci_dev *, enum dma_data_direction,
                     struct xdev_ext_peer_mapping **);
int xdev_ext_peer_acquire(struct xdev_ext_peer_mapping *, u64 generation, u64 offset,
                         u32 len, enum dma_data_direction, struct xdev_ext_peer_lease *);
/* quiesced means the driver proved this native request can no longer DMA.
 * false permanently retains allocation, DMA map, file, PCI and module refs.
 */
int xdev_ext_peer_release(struct xdev_ext_peer_lease *, u64 ticket, bool quiesced);
void xdev_ext_peer_invalidate(struct xdev_ext_peer_region *);
int xdev_ext_peer_unmap(struct xdev_ext_peer_mapping *);
int xdev_ext_peer_unpin(struct xdev_ext_peer_region *);
#endif

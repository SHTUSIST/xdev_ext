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
struct xdev_ext_peer_backing;
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
 /* Optional, process context: backing as this requester would reach it. */
 int (*describe)(void *allocation, struct pci_dev *requester,
                 struct xdev_ext_peer_backing *out);
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
 * A false quiesced always forbids reuse, including with a zero status.
 */
#define XDEV_EXT_PEER_RX_CONTRACT 1
/* Chains contain at most 16 elements. The ndo posts all or none, with one
 * doorbell. A negative return forbids both DMA and callbacks. */
struct xdev_ext_peer_tx {
 u64 dma_address;
 u32 len;
 u16 header_len;
 const u8 *header;
 void (*complete)(struct xdev_ext_peer_tx *, int status, bool quiesced);
 struct xdev_ext_peer_tx *next;
};
/* Header bytes land in the host slot; remaining packet bytes start at the
 * peer address. Completion is exactly once, including flush/cancellation. */
struct xdev_ext_peer_rx {
 struct xdev_ext_peer_rx *next;
 u64 dma_address;
 u32 len;
 u16 header_room;
 u8 *header;
 void (*complete)(struct xdev_ext_peer_rx *, int status, u32 header_len,
                  u32 payload_len, bool quiesced);
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
struct xdev_ext_peer_net_endpoint;
struct xdev_ext_peer_net_desc;
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_dir(u32, u32, bool,
                                                            void (*)(void *), void *);
struct pci_dev *xdev_ext_peer_net_peer(struct xdev_ext_peer_net_endpoint *);
int xdev_ext_peer_net_post_tx(struct xdev_ext_peer_net_endpoint *, struct xdev_ext_peer_tx *);
int xdev_ext_peer_net_post_rx(struct xdev_ext_peer_net_endpoint *, struct xdev_ext_peer_rx *);
int xdev_ext_peer_net_rx_flush(struct xdev_ext_peer_net_endpoint *);
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind(u32 ifindex, u32 queue);
void xdev_ext_peer_net_unbind(struct xdev_ext_peer_net_endpoint *);
u32 xdev_ext_peer_net_mtu(struct xdev_ext_peer_net_endpoint *);
int xdev_ext_peer_net_send(struct xdev_ext_peer_net_endpoint *, struct file *, u64 generation,
                           const struct xdev_ext_peer_net_desc *, bool *accepted);
long xdev_ext_peer_net_ioctl(unsigned long arg);
struct file *xdev_ext_peer_file_claim(struct file *, u64 *len, u64 *generation);
int xdev_ext_peer_file_info(struct file *, u64 *len, u64 *generation);
bool xdev_ext_peer_control_file(struct file *);
int xdev_ext_peer_info(struct xdev_ext_peer_region *, u64 *len, u64 *generation, bool idle);
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

struct xdev_ext_peer_backing {
 struct pci_dev *owner; /* PCI function whose BAR backs the allocation; borrowed */
 u32 flags; /* XDEV_EXT_PEER_BACKING_* in uapi/linux/xdev_ext_mech.h */
};
/* Process context: -EOPNOTSUPP when the provider has no describe(). */
int xdev_ext_peer_describe(struct xdev_ext_peer_region *, struct pci_dev *requester,
                          struct xdev_ext_peer_backing *);
int xdev_ext_peer_file_describe(struct file *authority, struct pci_dev *requester,
                               struct xdev_ext_peer_backing *);
/* CREATE, process context: cache the requester mapping before its first lease. */
int xdev_ext_peer_file_premap(struct file *authority, struct pci_dev *requester);
#endif

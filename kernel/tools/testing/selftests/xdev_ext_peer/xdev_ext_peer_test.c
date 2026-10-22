// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#if !__has_include("../../../../include/linux/xdev_ext_peer.h")
int main(void) { puts("not ok 1 - GPU allocation provider cannot register or admit a bounded peer lease"); return 1; }
#else
#include "xdev_ext_peer_test_shim.h"
#define XDEV_EXT_PEER_HOST_TEST
#include "../../../../io_uring/xdev_ext_peer.c"
#include <assert.h>
static int pins, maps, unmaps, unpins, fail_unmap;
static int pin(struct file *f, u64 va, u64 len, void **p) { (void)f; (void)va; (void)len; pins++; *p = &pins; return 0; }
static int unpin(void *p) { (void)p; unpins++; return 0; }
static u64 addresses[] = { 0x100000, 0x700000 };
static int map(void *p, struct pci_dev *peer, struct xdev_ext_peer_dma *d) { (void)p; (void)peer; maps++; *d = (struct xdev_ext_peer_dma){ .private = &maps, .addresses = addresses, .entries = 2, .page_shift = 16 }; return 0; }
static int unmap(void *p, struct pci_dev *peer, struct xdev_ext_peer_dma *d) { (void)p; (void)peer; (void)d; unmaps++; return fail_unmap ? -EIO : 0; }
int main(void)
{
 static struct file_operations fops;
 struct file f = { .f_op = &fops };
 struct pci_dev pci = {0};
 struct xdev_ext_peer_provider_ops ops = { .fops = &fops, .pin = pin, .unpin = unpin, .map = map, .unmap = unmap };
 struct xdev_ext_peer_region *r;
 struct xdev_ext_peer_mapping *m, *same;
 struct xdev_ext_peer_lease lease = {0}, other = {0};
 u64 generation;
 assert(xdev_ext_peer_provider_register(&ops) == 0);
 assert(xdev_ext_peer_pin(&f, 0x20000, 0x20000, &r) == 0 && pins == 1);
 generation = xdev_ext_peer_generation(r);
 assert(generation != 0);
 assert(xdev_ext_peer_map(r, &pci, DMA_BIDIRECTIONAL, &m) == 0 && maps == 1);
 assert(xdev_ext_peer_map(r, &pci, DMA_BIDIRECTIONAL, &same) == 0 && same == m && maps == 1);
 assert(xdev_ext_peer_acquire(m, generation, 65520, 32, DMA_TO_DEVICE, &lease) == -ERANGE);
 assert(xdev_ext_peer_acquire(m, generation, 131072, 1, DMA_TO_DEVICE, &lease) == -ERANGE);
 assert(xdev_ext_peer_acquire(m, generation + 1, 0, 32, DMA_TO_DEVICE, &lease) == -ESTALE);
 assert(xdev_ext_peer_acquire(m, generation, 65536 + 17, 32, DMA_TO_DEVICE, &lease) == 0);
 assert(lease.dma_address == addresses[1] + 17 && lease.len == 32);
 assert(xdev_ext_peer_unmap(m) == -EBUSY && unmaps == 0);
 other = lease;
 assert(xdev_ext_peer_release(&other, lease.ticket, true) == -ESTALE);
 other = (struct xdev_ext_peer_lease){0};
 assert(xdev_ext_peer_release(&lease, lease.ticket + 1, true) == -ESTALE);
 assert(xdev_ext_peer_provider_unregister(&ops) == -EBUSY);
 xdev_ext_peer_invalidate(r);
 assert(xdev_ext_peer_acquire(m, generation, 0, 32, DMA_TO_DEVICE, &other) == -ESTALE);
 assert(xdev_ext_peer_release(&lease, lease.ticket, true) == 0);
 assert(xdev_ext_peer_release(&lease, lease.ticket, true) == -EINVAL);
 assert(xdev_ext_peer_unmap(m) == 0 && unmaps == 0);
 assert(xdev_ext_peer_unmap(same) == 0 && unmaps == 1);
 assert(xdev_ext_peer_unpin(r) == 0 && unpins == 1);
 puts("ok 1 - persistent allocation maps once per peer, generation and bounded spans");
 assert(xdev_ext_peer_pin(&f, 0x20000, 0x20000, &r) == 0);
 assert(xdev_ext_peer_map(r, &pci, DMA_TO_DEVICE, &m) == 0);
 assert(xdev_ext_peer_acquire(m, xdev_ext_peer_generation(r), 0, 64, DMA_FROM_DEVICE, &lease) == -EACCES);
 assert(xdev_ext_peer_acquire(m, xdev_ext_peer_generation(r), 0, 64, DMA_TO_DEVICE, &lease) == 0);
 assert(xdev_ext_peer_release(&lease, lease.ticket, false) == 0);
 assert(xdev_ext_peer_unmap(m) == -EIO && unmaps == 1);
 assert(xdev_ext_peer_unpin(r) == -EIO && unpins == 1);
 puts("ok 2 - unknown DMA outcome quarantines mapping and allocation");
 assert(xdev_ext_peer_pin(&f, 0x20000, 0x20000, &r) == 0);
 assert(xdev_ext_peer_map(r, &pci, DMA_TO_DEVICE, &m) == 0);
 fail_unmap = 1;
 assert(xdev_ext_peer_unmap(m) == -EIO);
 assert(xdev_ext_peer_unpin(r) == -EIO && unpins == 1);
 puts("ok 3 - failed native unmap cannot free allocation");
 return 0;
}
#endif

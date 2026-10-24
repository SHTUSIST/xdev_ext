// SPDX-License-Identifier: GPL-2.0
/* Compile contract of the native peer RX/TX-chain hooks and the generic
 * endpoint API (requirements P3/P4) in include/linux/xdev_ext_peer.h.
 */
#include <stdio.h>
#include "xdev_ext_peer_test_shim.h"
#define XDEV_EXT_PEER_HOST_TEST
#include "../../../../include/linux/xdev_ext_peer.h"
#ifndef XDEV_EXT_PEER_RX_CONTRACT
int main(void)
{
 puts("not ok 1 - struct xdev_ext_peer_rx, TX chain (tx->next) and endpoint post/flush API missing");
 return 1;
}
#else
#define SAME(a, b) __builtin_types_compatible_p(__typeof__(a), b)
_Static_assert(SAME(((struct xdev_ext_peer_tx *)0)->next, struct xdev_ext_peer_tx *), "tx chain");
_Static_assert(SAME(((struct xdev_ext_peer_rx *)0)->next, struct xdev_ext_peer_rx *), "rx chain");
_Static_assert(SAME(((struct xdev_ext_peer_rx *)0)->dma_address, u64), "rx peer frame address");
_Static_assert(SAME(((struct xdev_ext_peer_rx *)0)->len, u32), "rx frame room");
_Static_assert(SAME(((struct xdev_ext_peer_rx *)0)->header_room, u16), "rx header slot size");
_Static_assert(SAME(((struct xdev_ext_peer_rx *)0)->header, u8 *), "rx host header slot");
_Static_assert(SAME(((struct xdev_ext_peer_rx *)0)->complete,
                    void (*)(struct xdev_ext_peer_rx *, int, u32, u32, bool)), "rx completion reports header/payload length and quiescence");
_Static_assert(SAME(&xdev_ext_peer_net_bind_dir,
                    struct xdev_ext_peer_net_endpoint *(*)(u32, u32, bool, void (*)(void *), void *)), "bind by direction");
_Static_assert(SAME(&xdev_ext_peer_net_peer, struct pci_dev *(*)(struct xdev_ext_peer_net_endpoint *)), "endpoint peer function");
_Static_assert(SAME(&xdev_ext_peer_net_post_tx, int (*)(struct xdev_ext_peer_net_endpoint *, struct xdev_ext_peer_tx *)), "non-waiting TX post");
_Static_assert(SAME(&xdev_ext_peer_net_post_rx, int (*)(struct xdev_ext_peer_net_endpoint *, struct xdev_ext_peer_rx *)), "non-waiting RX post");
_Static_assert(SAME(&xdev_ext_peer_net_rx_flush, int (*)(struct xdev_ext_peer_net_endpoint *)), "RX flush");
int main(void)
{
 puts("ok 1 - peer RX descriptor, TX/RX chains and non-waiting endpoint API have the contract types");
 return 0;
}
#endif

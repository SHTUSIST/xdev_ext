/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef XDEV_EXT_PEER_SW_UAPI_H
#define XDEV_EXT_PEER_SW_UAPI_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define PEER_SW_BYTES 65536U
#define PEER_SW_VA 0x10000ULL
struct peer_sw_stats {
	__u64 opens, closes, pins, unpins, maps, unmaps;
	__u64 live_pins, live_maps;
};
#define PEER_SW_STATS _IOR('s', 0x10, struct peer_sw_stats)
/* Per-open map refusal, used before that allocation has any DMA mapping. */
#define PEER_SW_REJECT_MAP _IO('s', 0x11)
#endif

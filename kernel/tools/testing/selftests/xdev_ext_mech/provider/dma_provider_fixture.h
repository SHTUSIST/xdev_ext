/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef DMA_PROVIDER_FIXTURE_H
#define DMA_PROVIDER_FIXTURE_H
#include <linux/ioctl.h>
#include <linux/types.h>
/* CPU simulation only. One mmap configures disjoint input and output windows. */
#define DMA_FIXTURE_UNIT (2U * 1024U * 1024U)
#define DMA_FIXTURE_MAP_BYTES (4U * DMA_FIXTURE_UNIT)
#define DMA_FIXTURE_INPUT_OFF DMA_FIXTURE_UNIT
#define DMA_FIXTURE_OUTPUT_OFF (3U * DMA_FIXTURE_UNIT)
#define DMA_FIXTURE_WINDOW_BYTES DMA_FIXTURE_UNIT
struct dma_fixture_stats {
 __u64 region_binds, region_unbinds, host_binds, host_unbinds;
 __u64 accepted, completed, from_device, to_device, bytes;
 __u64 pending, peak_pending, stale_callbacks;
 /* Polled regions: ->poll calls, and completions delivered from them. */
 __u64 polls, polled_completed;
};
#define DMA_FIXTURE_STATS _IOR('D', 0x71, struct dma_fixture_stats)
#endif

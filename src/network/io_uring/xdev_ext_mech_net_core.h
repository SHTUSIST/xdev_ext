/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_NET_CORE_H
#define IO_URING_XDEV_EXT_MECH_NET_CORE_H
#include "xdev_ext_mech_core.h"
#include "xdev_ext_peer_net_core.h"
#ifdef __KERNEL__
#include <linux/xdev_ext_netfam_core.h>
#else
#include "../include/linux/xdev_ext_netfam_core.h"
#endif
/* Ordered exact coverage means the BPF plan cannot duplicate, omit or read
 * beyond its current C-owned GPU payload span. CPU headers are separate.
 * A batch of several frames is covered frame after frame, in batch order.
 */
#define XDEV_EXT_NET_PLAN_FRAMES 1
struct xdev_ext_net_plan_ctx {
	const struct xdev_ext_net_mech_info *info;
	const struct xdev_ext_net_send_desc *d;
};

static inline void xdev_ext_net_plan_span(const void *ctx, __u32 i,
					struct xdev_ext_net_span *out)
{
	const struct xdev_ext_net_plan_ctx *c = ctx;

	*out = (struct xdev_ext_net_span){
		.frame_pos = c->d[i].frame_pos,
		.frame_off = c->d[i].frame_off,
		.len = c->d[i].len,
		.bad = c->d[i].flags | c->d[i].reserved,
	};
}

static inline int xdev_ext_net_plan_entry(const void *ctx, __u32 i)
{
	const struct xdev_ext_net_plan_ctx *c = ctx;

	return xdev_ext_peer_net_check(c->info->mtu, c->d[i].header_len,
				     c->d[i].len, 0);
}

static inline int xdev_ext_net_plan_check(const struct xdev_ext_net_mech_info *info,
					const struct xdev_ext_net_send_desc *d, __u32 nr)
{
	const struct xdev_ext_net_plan_ctx c = { .info = info, .d = d };

	if (!info || !d)
		return -EINVAL;
	return xdev_ext_net_cover_check(info->f, info->nr_frames, nr,
		XDEV_EXT_NET_MAX_ENTRIES, xdev_ext_net_plan_span,
		xdev_ext_net_plan_entry, &c);
}
#endif

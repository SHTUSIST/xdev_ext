/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XDP_XSK_XDEV_EXT_RX_CORE_H
#define _NET_XDP_XSK_XDEV_EXT_RX_CORE_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>

typedef u32 xsk_xdev_ext_rx_u32;
typedef u64 xsk_xdev_ext_rx_u64;
#else
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

typedef uint32_t xsk_xdev_ext_rx_u32;
typedef uint64_t xsk_xdev_ext_rx_u64;
#endif

/*
 * One instance follows one complete RX packet.  AF_XDP owns synchronization;
 * this core only makes the dispatch/reserve/publish/complete order testable.
 */
enum xsk_xdev_ext_rx_state {
	XSK_XDEV_EXT_RX_IDLE = 0,
	XSK_XDEV_EXT_RX_DISPATCHED,
	XSK_XDEV_EXT_RX_RESERVED,
	XSK_XDEV_EXT_RX_PUBLISHED,
};

struct xsk_xdev_ext_rx_core {
	xsk_xdev_ext_rx_u64 length;
	xsk_xdev_ext_rx_u32 nr_descs;
	xsk_xdev_ext_rx_u32 reserved_descs;
	enum xsk_xdev_ext_rx_state state;
	bool token_live;
};

static inline void xsk_xdev_ext_rx_core_init(struct xsk_xdev_ext_rx_core *core)
{
	if (!core)
		return;
	*core = (struct xsk_xdev_ext_rx_core) {};
}

static inline int xsk_xdev_ext_rx_core_begin(struct xsk_xdev_ext_rx_core *core,
					xsk_xdev_ext_rx_u64 length,
					xsk_xdev_ext_rx_u32 nr_descs,
					bool token_live)
{
	if (!core || !length || !nr_descs || !token_live)
		return -EINVAL;
	if (core->state != XSK_XDEV_EXT_RX_IDLE)
		return -EBUSY;
	core->length = length;
	core->nr_descs = nr_descs;
	core->token_live = true;
	core->state = XSK_XDEV_EXT_RX_DISPATCHED;
	return 0;
}

static inline int
xsk_xdev_ext_rx_core_note_reservation(struct xsk_xdev_ext_rx_core *core)
{
	if (!core || core->state != XSK_XDEV_EXT_RX_DISPATCHED)
		return -EPROTO;
	if (core->reserved_descs >= core->nr_descs)
		return -EOVERFLOW;
	core->reserved_descs++;
	return 0;
}

static inline int
xsk_xdev_ext_rx_core_reservations_complete(struct xsk_xdev_ext_rx_core *core)
{
	if (!core || core->state != XSK_XDEV_EXT_RX_DISPATCHED)
		return -EPROTO;
	if (core->reserved_descs != core->nr_descs)
		return -EINVAL;
	core->state = XSK_XDEV_EXT_RX_RESERVED;
	return 0;
}

static inline int xsk_xdev_ext_rx_core_published(struct xsk_xdev_ext_rx_core *core,
					    xsk_xdev_ext_rx_u64 bytes)
{
	if (!core || core->state != XSK_XDEV_EXT_RX_RESERVED)
		return -EPROTO;
	if (bytes != core->length)
		return -EINVAL;
	core->state = XSK_XDEV_EXT_RX_PUBLISHED;
	return 0;
}

/* Returns one when the caller must consume the pinned policy token. */
static inline int xsk_xdev_ext_rx_core_complete(struct xsk_xdev_ext_rx_core *core)
{
	bool token_live;

	if (!core || core->state != XSK_XDEV_EXT_RX_PUBLISHED)
		return -EPROTO;
	token_live = core->token_live;
	xsk_xdev_ext_rx_core_init(core);
	return token_live;
}

/* Abort is valid only before publication and is idempotent after cleanup. */
static inline int xsk_xdev_ext_rx_core_abort(struct xsk_xdev_ext_rx_core *core)
{
	bool token_live;

	if (!core)
		return -EINVAL;
	if (core->state == XSK_XDEV_EXT_RX_IDLE)
		return 0;
	if (core->state == XSK_XDEV_EXT_RX_PUBLISHED)
		return -EPROTO;
	token_live = core->token_live;
	xsk_xdev_ext_rx_core_init(core);
	return token_live;
}

#endif /* _NET_XDP_XSK_XDEV_EXT_RX_CORE_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XSK_XDEV_EXT_MECH_ZC_CORE_H
#define _XSK_XDEV_EXT_MECH_ZC_CORE_H
#include <linux/xdev_ext_netfam_count.h>
#include "xsk_xdev_ext_mech_tx_core.h"

/* Legacy names share the family metadata and rules, not a second journal. */
#define XSK_MECH_ZC_BATCH_TRACKING XDEV_EXT_NET_COUNT_BATCH_TRACKING
#define xsk_mech_zc_batch xdev_ext_net_count_batch
#define xsk_mech_zc_ring xdev_ext_net_count_ring
#define xsk_mech_zc_state xdev_ext_net_count_state
#define XSK_MECH_ZC_PENDING XDEV_EXT_NET_COUNT_PENDING
#define XSK_MECH_ZC_NATIVE XDEV_EXT_NET_COUNT_NATIVE
#define XSK_MECH_ZC_DONE XDEV_EXT_NET_COUNT_DONE
#define XSK_MECH_ZC_NONE XDEV_EXT_NET_COUNT_NONE

enum xsk_mech_zc_owner { XSK_MECH_ZC_DATA, XSK_MECH_ZC_CONTROL };
struct xsk_mech_zc_slot {
	struct xdp_desc desc;
	void *batch;
	__u32 slot;
	union {
		struct xdev_ext_net_count_entry count;
		struct {
			__s32 result;
			__u32 native_prev, native_next;
			__u8 state, owner;
		};
	};
};

static inline struct xdev_ext_net_count_view
xsk_mech_zc_view(struct xsk_mech_zc_slot *slots)
{
	return (struct xdev_ext_net_count_view) {
		.first = &slots[0].count,
		.stride = sizeof(*slots),
	};
}

static inline bool xsk_mech_zc_retire_result(struct xsk_mech_zc_batch *b,
					   int result, __s32 *out)
{
	return xdev_ext_net_count_retire_result(b, result, out);
}

static inline void xsk_mech_zc_fail(struct xsk_mech_zc_ring *r, int result)
{
	xdev_ext_net_count_fail(r, result);
}

static inline void xsk_mech_zc_set_result(struct xsk_mech_zc_ring *r,
					struct xsk_mech_zc_slot *s,
					__u32 at, int result)
{
	xdev_ext_net_count_set_result(r, xsk_mech_zc_view(s), at, result);
}

static inline int xsk_mech_zc_reserve(struct xsk_mech_zc_ring *r, __u32 n,
				    __u32 *start)
{
	return xdev_ext_net_count_reserve(r, n, start);
}

static inline int xsk_mech_zc_peek(struct xsk_mech_zc_ring *r,
				 struct xsk_mech_zc_slot *s)
{
	return xdev_ext_net_count_peek(r, xsk_mech_zc_view(s));
}

static inline void xsk_mech_zc_mark_done(struct xsk_mech_zc_ring *r,
				       struct xsk_mech_zc_slot *s, __u32 at)
{
	xdev_ext_net_count_mark_done(r, xsk_mech_zc_view(s), at);
}

static inline __u32 xsk_mech_zc_native(const struct xsk_mech_zc_ring *r,
				      const struct xsk_mech_zc_slot *s)
{
	(void)s;
	return xdev_ext_net_count_native(r);
}

static inline int xsk_mech_zc_tail(const struct xsk_mech_zc_ring *r,
				 const struct xsk_mech_zc_slot *s, __u32 n)
{
	return xdev_ext_net_count_tail(r,
			xsk_mech_zc_view((struct xsk_mech_zc_slot *)s), n);
}

static inline int xsk_mech_zc_complete(const struct xsk_mech_zc_ring *r,
				     const struct xsk_mech_zc_slot *s)
{
	(void)s;
	return xdev_ext_net_count_head(r);
}

static inline void xsk_mech_zc_reclaim(struct xsk_mech_zc_ring *r,
				      struct xsk_mech_zc_slot *s)
{
	xdev_ext_net_count_reclaim(r, xsk_mech_zc_view(s));
}
#endif

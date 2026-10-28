/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_NETFAM_CORE_H
#define _LINUX_XDEV_EXT_NETFAM_CORE_H

/* Allocation-free network-family rules. Callers serialize reliable state.
 * Rendezvous helpers check BPF-selected actions; they select no runtime policy.
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/xdev_ext_mech.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>
#include "../uapi/linux/xdev_ext_mech.h"
#endif
#include "xdev_ext_mech_reliable_core.h"

struct xdev_ext_net_span {
	__u32 frame_pos, frame_off, len;
	__u32 bad; /* Nonzero descriptor flags or reserved fields. */
};
typedef void (*xdev_ext_net_span_fn)(const void *ctx, __u32 i,
				   struct xdev_ext_net_span *out);
typedef int (*xdev_ext_net_entry_fn)(const void *ctx, __u32 i);

/* Cover each frame exactly, in batch order. Keep range/error precedence equal
 * to xdev_ext_net_plan_check(), with the per-device rule supplied by @entry.
 */
static inline int xdev_ext_net_cover_check(const struct xdev_ext_mech_frame_info *f,
		__u32 nr_frames, __u32 nr, __u32 max_nr, xdev_ext_net_span_fn span,
		xdev_ext_net_entry_fn entry, const void *ctx)
{
	struct xdev_ext_net_span s;
	__u32 i, cur = 0, bytes = 0;
	int ret;

	if (!f || !span || !nr_frames || nr_frames > XDEV_EXT_MECH_MAX_FRAMES ||
	    !nr || nr > max_nr)
		return -EINVAL;
	for (i = 0; i < nr; i++) {
		span(ctx, i, &s);
		if (s.frame_pos >= nr_frames || s.frame_pos < cur || s.bad)
			return -EINVAL;
		if (s.frame_pos != cur) {
			if (bytes != f[cur].data_len || s.frame_pos != cur + 1)
				return -EMSGSIZE;
			cur++;
			bytes = 0;
		}
		if ((__u64)f[cur].data_off + bytes != s.frame_off ||
		    bytes > f[cur].data_len || s.len > f[cur].data_len - bytes)
			return -ERANGE;
		if (entry) {
			ret = entry(ctx, i);
			if (ret)
				return ret;
		}
		bytes += s.len;
	}
	return cur + 1 == nr_frames && bytes == f[cur].data_len ? 0 : -EMSGSIZE;
}

/* A nonempty span starts on @align and is cut into at most @max-byte pieces. */
static inline __u32 xdev_ext_net_segments(__u32 off, __u32 len, __u32 max,
					__u32 align)
{
	if (!len || !max || !align || off % align)
		return 0;
	return (len - 1) / max + 1;
}

/* @k is less than the count returned by xdev_ext_net_segments(). */
static inline void xdev_ext_net_segment(__u32 off, __u32 len, __u32 max, __u32 k,
				      __u32 *eoff, __u32 *elen)
{
	__u32 left = len - k * max;

	*eoff = off + k * max;
	*elen = left < max ? left : max;
}

/* RX posts a full device buffer even for the final partial payload piece. */
static inline bool xdev_ext_net_rx_room_ok(__u32 off, __u32 len, __u32 max,
					 __u32 frame_size)
{
	__u32 n = xdev_ext_net_segments(off, len, max, 1);

	return n && (__u64)off + (__u64)n * max <= frame_size;
}

/* Local DMA facts determine custody; remote delivery determines success. */
static inline int xdev_ext_net_outcome(int local_status, bool local_quiesced,
				     __u32 remote, bool *sequester)
{
	*sequester = !local_quiesced;
	if (!local_quiesced)
		return local_status ? local_status : -EIO;
	if (local_status)
		return local_status;
	switch (remote) {
	case XDEV_EXT_NET_REMOTE_ACKED:
		return 0;
	case XDEV_EXT_NET_REMOTE_FAILED:
		return -EREMOTEIO;
	case XDEV_EXT_NET_REMOTE_LOST:
		return -ENOLINK;
	default:
		return -EINPROGRESS;
	}
}

enum xdev_ext_net_rdv {
	XDEV_EXT_RDV_IDLE = 0,
	XDEV_EXT_RDV_ARMED = 1,
	XDEV_EXT_RDV_ANNOUNCED = 2,
	XDEV_EXT_RDV_POSTED = 3,
	XDEV_EXT_RDV_LOCAL_DONE = 4,
	XDEV_EXT_RDV_FINAL = 5,
};

enum xdev_ext_net_rdv_event {
	XDEV_EXT_RDV_EV_SUBMIT = 1,
	XDEV_EXT_RDV_EV_RTS = 2,
	XDEV_EXT_RDV_EV_CTS = 3,
	XDEV_EXT_RDV_EV_LOCAL = 4,
	XDEV_EXT_RDV_EV_REMOTE = 5,
	XDEV_EXT_RDV_EV_CANCEL = 6,
};

static inline int xdev_ext_net_rdv_next(__u32 state, __u32 event, bool rx)
{
	if (event == XDEV_EXT_RDV_EV_CANCEL)
		return state == XDEV_EXT_RDV_ARMED || state == XDEV_EXT_RDV_ANNOUNCED ?
		       XDEV_EXT_RDV_FINAL : -EPROTO;
	switch (state) {
	case XDEV_EXT_RDV_IDLE:
		return event == XDEV_EXT_RDV_EV_SUBMIT ?
		       (rx ? XDEV_EXT_RDV_ARMED : XDEV_EXT_RDV_ANNOUNCED) : -EPROTO;
	case XDEV_EXT_RDV_ARMED:
		return rx && event == XDEV_EXT_RDV_EV_RTS ? XDEV_EXT_RDV_POSTED : -EPROTO;
	case XDEV_EXT_RDV_ANNOUNCED:
		if (rx)
			return -EPROTO;
		if (event == XDEV_EXT_RDV_EV_CTS)
			return XDEV_EXT_RDV_POSTED;
		return event == XDEV_EXT_RDV_EV_REMOTE ? XDEV_EXT_RDV_FINAL : -EPROTO;
	case XDEV_EXT_RDV_POSTED:
		if (event == XDEV_EXT_RDV_EV_LOCAL)
			return rx ? XDEV_EXT_RDV_FINAL : XDEV_EXT_RDV_LOCAL_DONE;
		return !rx && event == XDEV_EXT_RDV_EV_REMOTE ? XDEV_EXT_RDV_POSTED : -EPROTO;
	case XDEV_EXT_RDV_LOCAL_DONE:
		return !rx && event == XDEV_EXT_RDV_EV_REMOTE ? XDEV_EXT_RDV_FINAL : -EPROTO;
	default:
		return -EPROTO;
	}
}

/* Validate an RTS before recording acceptance of its group. */
static inline int xdev_ext_net_rts_check(const struct xdev_ext_rel_rx *r,
		__u64 stream, __u64 group, __u32 total_len, __u32 count,
		__u32 want_total, __u32 want_count)
{
	const struct xdev_ext_rel_rx_entry *e;

	if (stream != r->cfg.session)
		return -ESTALE;
	if (!group || group < r->base_group || group >= r->credit ||
	    group > ~(__u64)0 - r->cfg.window)
		return -ERANGE;
	if (total_len != want_total || count != want_count)
		return -EMSGSIZE;
	e = &r->entry[group % r->cfg.window];
	if (e->group == group && e->state)
		return -EEXIST;
	return 0;
}

/* The reliable instance is initialized and rts_check() has returned zero. */
static inline void xdev_ext_net_rts_accept(struct xdev_ext_rel_rx *r, __u64 group)
{
	r->entry[group % r->cfg.window] = (struct xdev_ext_rel_rx_entry){
		.group = group,
		.total_len = r->cfg.group_bytes,
		.count = (__u16)((r->cfg.group_bytes - 1) / r->cfg.seg_len + 1),
		.state = XDEV_EXT_REL_RX_COLLECT,
	};
}

/* Apply a bounded credit selected from a received CTS or acknowledgement. */
static inline int xdev_ext_net_credit_update(struct xdev_ext_rel_tx *t, __u64 credit)
{
	__u64 floor = t->cfg.first_group + (t->cfg.initial_credit ?
					 t->cfg.initial_credit : t->cfg.window);

	if (credit < floor || t->next_group > ~(__u64)0 - t->cfg.window ||
	    credit > t->next_group + t->cfg.window)
		return -ERANGE;
	if (credit > t->credit)
		t->credit = credit;
	return 0;
}

/* No abort may retire a group while its device may still access the payload. */
static inline int xdev_ext_net_tx_abort(struct xdev_ext_rel_tx *t, __u64 group)
{
	struct xdev_ext_rel_tx_entry *e = xdev_ext_rel_tx_find(t, group);

	if (!e)
		return -ENOENT;
	if (e->native_pending)
		return -EBUSY;
	if (!e->terminal)
		e->terminal = XDEV_EXT_REL_UNKNOWN;
	return 0;
}

/* No-retransmission RX: close an accepted failed/withdrawn group, then release
 * it and any following DONE groups from the window. Configuration was checked
 * by xdev_ext_rel_rx_init(); closing never permits credit to wrap.
 */
static inline int xdev_ext_net_rx_close(struct xdev_ext_rel_rx *r, __u64 group)
{
	struct xdev_ext_rel_rx_entry *e;
	unsigned int i;

	if (r->cfg.max_attempts != 1 || group < r->base_group || group >= r->credit)
		return -ENOENT;
	e = &r->entry[group % r->cfg.window];
	if (e->group != group || !e->state)
		return -ENOENT;
	e->state = XDEV_EXT_REL_RX_DONE;
	for (i = 0; i < XDEV_EXT_REL_MAX_WINDOW; i++) {
		e = &r->entry[r->base_group % r->cfg.window];
		if (e->group != r->base_group || e->state != XDEV_EXT_REL_RX_DONE ||
		    r->base_group >= ~(__u64)0 - r->cfg.window)
			break;
		r->base_group++;
	}
	r->credit = r->base_group + r->cfg.window;
	return 0;
}

#endif /* _LINUX_XDEV_EXT_NETFAM_CORE_H */

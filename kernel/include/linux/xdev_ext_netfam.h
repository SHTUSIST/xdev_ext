/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_NETFAM_H
#define _LINUX_XDEV_EXT_NETFAM_H

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_peer_net_track.h>
#include <linux/xdev_ext_requester.h>
#include <linux/xdev_ext_netfam_core.h>
#include <uapi/linux/xdev_ext_policy.h>

enum xdev_ext_net_hdr_policy {
	XDEV_EXT_NET_HDR_SPLIT = 1,	/* host header bytes + device payload per element (mlx5, ice) */
	XDEV_EXT_NET_HDR_CHANNEL = 2,	/* payload-only elements; headers on a host control ring (XDomain) */
	XDEV_EXT_NET_HDR_INBAND = 3,	/* header and payload in one host frame (AF_XDP, SOCKET) */
};
#define XDEV_EXT_NET_DEV_AREA	64U
#define XDEV_EXT_NETFAM_MAX_ELEMS	64U
struct xdev_ext_net_slot;
struct xdev_ext_netfam_stage;
struct xdev_ext_net_elem {
	struct xdev_ext_peer_fd_lease lease;	/* payload lease for dev->requester() */
	struct xdev_ext_net_slot *slot;
	u32 len;			/* payload bytes this element carries */
	u32 buf_len;			/* bytes the device may write: TX len, RX full device frame */
	u32 done_len;			/* bytes the device reported */
	u16 hdr_len;			/* SPLIT only */
	u16 dev_flags;			/* subclass bits, e.g. last element of a group */
	u8 hdr[XDEV_EXT_NET_HEADER_MAX];
	union { u64 align; u8 bytes[XDEV_EXT_NET_DEV_AREA]; } dev;	/* subclass native object */
};
struct xdev_ext_net_dev_ops {
	struct module *owner;
	u32 hdr_policy;			/* SPLIT or CHANNEL */
	u32 max_elems;			/* elements per batch, <= XDEV_EXT_NETFAM_MAX_ELEMS */
	/* CREATE, may sleep: bind @u to a device endpoint; dead(arg) once when it goes away */
	void *(*bind)(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_stage_uapi *u,
		      void (*dead)(void *arg), void *arg);	/* endpoint or ERR_PTR */
	/* after drain, may sleep; never with an element outstanding */
	void (*unbind)(void *lk);
	/* any context: the PCI function that performs payload DMA */
	struct pci_dev *(*requester)(void *lk);
	/* any context: largest element payload; 0 once the device is gone */
	u32 (*max_payload)(void *lk);
	/* worker: all or none of @n elements, one doorbell; negative: no DMA, no callback */
	int (*post_tx)(void *lk, struct xdev_ext_net_elem *e, u32 n);
	int (*post_rx)(void *lk, struct xdev_ext_net_elem *e, u32 n);
	/* optional, may sleep: cancel posted RX elements; each completes exactly once */
	int (*rx_flush)(void *lk);
	/* CHANNEL only, any context but hardirq: send one control message */
	int (*ctl_send)(void *lk, const u8 *msg, u32 len);
};
struct xdev_ext_net_slot {
	struct xdev_ext_peer_net_track track;
	struct xdev_ext_netfam_stage *ns;
	struct xdev_ext_net_elem *elem;		/* max_elems entries, owned by ns->elems */
	struct xdev_ext_mech_batch *batch;
	u64 ticket, posted_ms, group;
	u64 withdraw_ms;			/* CHANNEL TX: when the withdrawal was sent */
	u32 nr, state, remote;			/* elements; enum xdev_ext_net_rdv; XDEV_EXT_NET_REMOTE_* */
	int local_status;
	bool busy, local_known, local_quiesced, sequestered;
	bool withdrawn;				/* CHANNEL TX: announced group withdrawn, answer pending */
};
struct xdev_ext_net_member {
	const struct xdev_ext_net_dev_ops *dev;
	bool admit;				/* run xdev_ext_requester_bind() in attach */
	/* any context, tracker or protocol winner only: write the class CQE */
	void (*result)(struct xdev_ext_netfam_stage *ns, struct xdev_ext_mech_batch *b,
		       const struct xdev_ext_net_slot *slot, int status, bool sequester);
	/* CHANNEL only, ns->lock held: record local DMA facts and kick; never run BPF or select protocol progress here */
	void (*local)(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot);
	/* CHANNEL TX only, ns->lock held: checked apply primitive for BPF-selected withdrawal; 0 when sent */
	int (*withdraw)(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot);
	/* CHANNEL only, ns->lock held, never blocks: the device ring may hold buffers that
	 * later data would fill, so the device's link incarnation must end (section 4.8) */
	void (*link_fail)(struct xdev_ext_netfam_stage *ns, int err);
};
struct xdev_ext_netfam_stage {
	struct xdev_ext_mech_stage *st;
	const struct xdev_ext_net_member *m;
	void *lk;				/* device subclass endpoint, opaque to the family */
	struct xdev_ext_requester rq;
	struct xdev_ext_net_slot *slots;
	struct xdev_ext_net_elem *elems;
	u32 depth, max_elems, header_room;
	u64 stop_ms;
	bool rx, dead, flushed, admitted;
	spinlock_t lock;			/* CHANNEL: slot state/remote, tx, rx_rel, events */
	struct xdev_ext_rel_tx tx;		/* CHANNEL TX window and credit */
	struct xdev_ext_rel_rx rx_rel;		/* CHANNEL RX window and credit */
	bool rx_rel_ready;
};
struct xdev_ext_net_rel_view {
	const struct xdev_ext_rel_tx *tx;	/* NULL when the stage only receives */
	const struct xdev_ext_rel_rx *rx;	/* NULL when the stage only sends */
	const u64 *ack_pending;			/* XDEV_EXT_REL_MAX_WINDOW entries or NULL */
	const struct xdev_ext_rel_policy *policy;	/* or NULL */
	spinlock_t *lock;			/* serializes everything above */
};
struct xdev_ext_net_hooks {
	struct xdev_ext_family_hooks_hdr hdr;	/* family = XDEV_EXT_FAMILY_NETWORK */
	u32 hdr_policy;				/* enum xdev_ext_net_hdr_policy */
	/* any context: the stage's reliable state; false when it has none */
	bool (*rel)(struct xdev_ext_mech_stage *st, struct xdev_ext_net_rel_view *out);
};
/* family runtime library, io_uring/family/xdev_ext_netfam.c */
int  xdev_ext_netfam_init(struct xdev_ext_netfam_stage *ns, struct xdev_ext_mech_stage *st,
			  const struct xdev_ext_net_member *m, bool rx, u32 header_room);
int  xdev_ext_netfam_attach(struct xdev_ext_netfam_stage *ns, const struct xdev_ext_mech_stage_uapi *u,
			    u32 admit_flags);	/* dev->bind, then admission when m->admit */
void xdev_ext_netfam_fini(struct xdev_ext_netfam_stage *ns);
struct xdev_ext_net_slot *xdev_ext_netfam_slot_get(struct xdev_ext_netfam_stage *ns,
						   struct xdev_ext_mech_batch *b);
int  xdev_ext_netfam_lease(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot,
			   u32 i, u64 off, u32 len, u32 buf_len);
int  xdev_ext_netfam_post(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot);
void xdev_ext_netfam_release(struct xdev_ext_net_slot *slot, bool quiesced);
void xdev_ext_netfam_fill_cqe(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot **slotp);
unsigned long xdev_ext_netfam_progress(struct xdev_ext_netfam_stage *ns);
void xdev_ext_netfam_mark_dead(struct xdev_ext_netfam_stage *ns);
void xdev_ext_net_elem_done(struct xdev_ext_net_elem *e, int status, u32 done_len,
			    u32 hdr_len, bool quiesced);	/* device callback, any context, once */
/* CHANNEL checked apply primitives (Task X5), ns->lock held; BPF selected the action */
void xdev_ext_netfam_remote_locked(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot,
				   u32 remote);			/* XDEV_EXT_NET_REMOTE_ACKED/FAILED/LOST */
void xdev_ext_netfam_cancel_locked(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot,
				   int err);			/* ARMED or ANNOUNCED: nothing posted */
void xdev_ext_netfam_publish_locked(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot,
				    int status, bool sequester);

#endif

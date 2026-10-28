// SPDX-License-Identifier: GPL-2.0
/* Network device family runtime: slots, element leases, one completion per
 * element, tracker hand-off, release and deadlines, shared by every network
 * subclass that implements struct xdev_ext_net_dev_ops (NET over netdev,
 * XDOMAIN over a Thunderbolt NHI).  Moved from the completion-driven part of
 * io_uring/xdev_ext_mech_net.c (main 42e7832, lines 186-475). */
#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_netfam.h>

/* xdev_ext_netfam runtime begin */
static void xdev_ext_netfam_link_dead(void *arg)
{
	xdev_ext_mech_stage_dead(arg, -ENXIO);
}

int xdev_ext_netfam_init(struct xdev_ext_netfam_stage *ns, struct xdev_ext_mech_stage *st,
			 const struct xdev_ext_net_member *m, bool rx, u32 header_room)
{
	u32 i;

	if (!m || !m->dev || !m->result || !m->dev->max_elems ||
	    m->dev->max_elems > XDEV_EXT_NETFAM_MAX_ELEMS)
		return -EINVAL;
	/* A CHANNEL subclass must say what its device does when a result is
	 * known, how it withdraws an announcement and how it ends its link. */
	if (m->dev->hdr_policy == XDEV_EXT_NET_HDR_CHANNEL &&
	    (!m->local || !m->withdraw || !m->link_fail))
		return -EINVAL;
	ns->st = st;
	ns->m = m;
	ns->rx = rx;
	ns->header_room = header_room;
	ns->depth = xdev_ext_mech_session_depth(st->s);
	ns->max_elems = m->dev->max_elems;
	spin_lock_init(&ns->lock);
	ns->slots = kvcalloc(ns->depth, sizeof(*ns->slots), GFP_KERNEL);
	ns->elems = kvcalloc((size_t)ns->depth * ns->max_elems, sizeof(*ns->elems), GFP_KERNEL);
	if (!ns->slots || !ns->elems) {
		kvfree(ns->elems);
		kvfree(ns->slots);
		ns->elems = NULL;
		ns->slots = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < ns->depth; i++)
		ns->slots[i].elem = &ns->elems[(size_t)i * ns->max_elems];
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_init);

int xdev_ext_netfam_attach(struct xdev_ext_netfam_stage *ns,
			   const struct xdev_ext_mech_stage_uapi *u, u32 admit_flags)
{
	void *lk = ns->m->dev->bind(ns->st, u, xdev_ext_netfam_link_dead, ns->st);
	int ret;

	if (IS_ERR(lk))
		return PTR_ERR(lk);
	ns->lk = lk;
	if (!ns->m->admit)
		return 0;
	ret = xdev_ext_requester_bind(&ns->rq, ns->st, ns->m->dev->requester(lk), admit_flags);
	ns->admitted = !ret;
	return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_attach);

/* After drain, or on a failed bind; never with a busy slot. */
void xdev_ext_netfam_fini(struct xdev_ext_netfam_stage *ns)
{
	if (ns->admitted)
		xdev_ext_requester_unbind(&ns->rq);
	ns->admitted = false;
	if (ns->lk)
		ns->m->dev->unbind(ns->lk);
	ns->lk = NULL;
	kvfree(ns->elems);
	kvfree(ns->slots);
	ns->elems = NULL;
	ns->slots = NULL;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_fini);

/* Worker: a free slot for @b, or NULL (pre-accept backpressure). */
struct xdev_ext_net_slot *xdev_ext_netfam_slot_get(struct xdev_ext_netfam_stage *ns,
						   struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_net_slot *slot = NULL;
	struct xdev_ext_net_elem *elem;
	unsigned long flags;
	u32 i;

	spin_lock_irqsave(&ns->lock, flags);
	for (i = 0; i < ns->depth; i++)
		if (!ns->slots[i].busy) {
			slot = &ns->slots[i];
			break;
		}
	if (slot) {
		elem = slot->elem;
		memset(elem, 0, ns->max_elems * sizeof(*elem));
		memset(slot, 0, sizeof(*slot));
		slot->elem = elem;
		slot->ns = ns;
		slot->busy = true;
		slot->batch = b;
		slot->ticket = xdev_ext_mech_batch_ticket(b);
		slot->posted_ms = ktime_get_boottime_ns() / NSEC_PER_MSEC;
	}
	spin_unlock_irqrestore(&ns->lock, flags);
	return slot;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_slot_get);

/* Worker: lease element @i; @buf_len >= @len is what the device may write. */
int xdev_ext_netfam_lease(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot,
			  u32 i, u64 off, u32 len, u32 buf_len)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(ns->st->s);
	struct xdev_ext_net_elem *e;
	int ret;

	if (i >= ns->max_elems || !len || buf_len < len)
		return -EPROTO;
	e = &slot->elem[i];
	ret = xdev_ext_peer_file_acquire(xdev_ext_peer_mech_pool_file(pool),
					 ns->m->dev->requester(ns->lk),
					 xdev_ext_peer_mech_pool_generation(pool), off, buf_len,
					 ns->rx ? DMA_FROM_DEVICE : DMA_TO_DEVICE, &e->lease);
	if (ret)
		return ret;
	e->slot = slot;
	e->len = len;
	e->buf_len = buf_len;
	if (i + 1 > slot->nr)
		slot->nr = i + 1;
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_lease);

void xdev_ext_netfam_release(struct xdev_ext_net_slot *slot, bool quiesced)
{
	u32 i;

	for (i = 0; i < slot->nr; i++)
		xdev_ext_peer_fd_release(&slot->elem[i].lease, quiesced);
	if (quiesced)
		slot->busy = false;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_release);

/* Worker: post @slot's elements.  The caller records @slot in its batch area
 * first: completion may run before this returns.  On error nothing reached
 * the device and every lease is released. */
int xdev_ext_netfam_post(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot)
{
	int ret = xdev_ext_peer_net_track_init_max(&slot->track, slot->nr, ns->max_elems);

	if (!ret)
		ret = ns->rx ? ns->m->dev->post_rx(ns->lk, slot->elem, slot->nr) :
			       ns->m->dev->post_tx(ns->lk, slot->elem, slot->nr);
	if (ret)
		xdev_ext_netfam_release(slot, true);
	return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_post);

/* Only the tracker winner touches batch state, using its immutable ticket. */
static void xdev_ext_netfam_handoff(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot)
{
	struct xdev_ext_mech_batch *b = slot->batch;
	bool sequester;
	int status = xdev_ext_peer_net_track_result(&slot->track, &sequester);

	if (xdev_ext_mech_batch_completion_claim(b, slot->ticket))
		return;
	slot->sequestered = sequester;
	ns->m->result(ns, b, slot, status, sequester);
	xdev_ext_mech_batch_completion_publish(b, slot->ticket, status, sequester);
}

/* Device callback, any context, exactly once per posted element.  @done_len
 * and @hdr_len are recorded as given; the subclass decides what they are on
 * failure. */
void xdev_ext_net_elem_done(struct xdev_ext_net_elem *e, int status, u32 done_len,
			    u32 hdr_len, bool quiesced)
{
	struct xdev_ext_net_slot *slot = e->slot;

	e->done_len = done_len;
	e->hdr_len = hdr_len;
	if (xdev_ext_peer_net_track_complete(&slot->track, status, quiesced) ==
	    XDEV_EXT_PEER_NET_TRACK_HANDOFF) {
		if (slot->ns->m->dev->hdr_policy == XDEV_EXT_NET_HDR_CHANNEL) {
			unsigned long flags;

			spin_lock_irqsave(&slot->ns->lock, flags);
			slot->local_status = xdev_ext_peer_net_track_result(&slot->track,
								      &slot->sequestered);
			slot->local_known = true;
			slot->local_quiesced = !slot->sequestered;
			slot->ns->m->local(slot->ns, slot);
			spin_unlock_irqrestore(&slot->ns->lock, flags);
		} else {
			xdev_ext_netfam_handoff(slot->ns, slot);
		}
	}
}
EXPORT_SYMBOL_GPL(xdev_ext_net_elem_done);

/* CHANNEL primitives: callers hold ns->lock; none selects protocol policy. */
void xdev_ext_netfam_remote_locked(struct xdev_ext_netfam_stage *ns,
		struct xdev_ext_net_slot *slot, u32 remote)
{
	(void)ns;
	slot->remote = remote;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_remote_locked);

void xdev_ext_netfam_cancel_locked(struct xdev_ext_netfam_stage *ns,
		struct xdev_ext_net_slot *slot, int err)
{
	(void)ns;
	slot->local_known = true;
	slot->local_quiesced = true;
	slot->local_status = err;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_cancel_locked);

void xdev_ext_netfam_publish_locked(struct xdev_ext_netfam_stage *ns,
		struct xdev_ext_net_slot *slot, int status, bool sequester)
{
	if (xdev_ext_mech_batch_completion_claim(slot->batch, slot->ticket))
		return;
	slot->sequestered = sequester;
	ns->m->result(ns, slot->batch, slot, status, sequester);
	xdev_ext_mech_batch_completion_publish(slot->batch, slot->ticket, status, sequester);
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_publish_locked);

/* Worker, the class fill_cqe: release the batch's leases by its final custody. */
void xdev_ext_netfam_fill_cqe(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot **slotp)
{
	(void)ns;
	if (!*slotp)
		return;
	xdev_ext_netfam_release(*slotp, !(*slotp)->sequestered);
	*slotp = NULL;
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_fill_cqe);

void xdev_ext_netfam_mark_dead(struct xdev_ext_netfam_stage *ns)
{
	WRITE_ONCE(ns->dead, true);
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_mark_dead);

unsigned long xdev_ext_netfam_progress(struct xdev_ext_netfam_stage *ns)
{
	u64 now = ktime_get_boottime_ns() / NSEC_PER_MSEC;
	bool stopping = READ_ONCE(ns->dead) || !xdev_ext_mech_session_admits(ns->st->s);
	u32 i;

	if (ns->m->dev->hdr_policy == XDEV_EXT_NET_HDR_CHANNEL)
		return msecs_to_jiffies(20);
	if (stopping && !ns->stop_ms)
		ns->stop_ms = now ? now : 1;
	if (ns->rx && !ns->flushed && ns->m->dev->rx_flush) {
		bool flush = stopping;

		for (i = 0; i < ns->depth && !flush; i++)
			flush = ns->slots[i].busy &&
				xdev_ext_peer_net_track_expired(now, ns->slots[i].posted_ms, ns->stop_ms);
		if (flush) {
			ns->m->dev->rx_flush(ns->lk);
			ns->flushed = true;
		}
	}
	for (i = 0; i < ns->depth; i++) {
		struct xdev_ext_net_slot *slot = &ns->slots[i];

		if (!slot->busy || !xdev_ext_peer_net_track_expired(now, slot->posted_ms, ns->stop_ms))
			continue;
		if (xdev_ext_peer_net_track_abandon(&slot->track, stopping ? -ECANCELED : -ETIMEDOUT))
			xdev_ext_netfam_handoff(ns, slot);
	}
	return msecs_to_jiffies(20);
}
EXPORT_SYMBOL_GPL(xdev_ext_netfam_progress);
/* xdev_ext_netfam runtime end */

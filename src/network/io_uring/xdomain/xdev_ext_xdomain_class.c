// SPDX-License-Identifier: GPL-2.0
/* XDOMAIN bounded protocol events. BPF chooses; C owns custody and effects. */
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xdev_ext_binding.h>
#include "xdev_ext_xdomain.h"
#include "../xdev_ext_mech_core.h"

#define XDEV_EXT_XD_FRAME XDEV_EXT_XDOMAIN_MAX_FRAME
#define XD_EVENTS (4U * XDEV_EXT_REL_MAX_WINDOW)
#define XD_REPLIES (2U * XDEV_EXT_REL_MAX_WINDOW)
#define XD_PHASE_NS (30000ULL * NSEC_PER_MSEC)
#define XD_WITHDRAW_NS (15000ULL * NSEC_PER_MSEC)
#define XD_STOP_NS (1000ULL * NSEC_PER_MSEC)
#define XD_TICK_NS (20ULL * NSEC_PER_MSEC)

struct xdev_ext_xd_reply {
	u64 group, stream, advertised, deadline;
	u64 wake, wait_epoch;
	int chain_status, local_status;
	bool used, admission, chain_done, sequestered, cts, final, closed, native_posted;
	u8 tag[XDEV_EXT_XDOMAIN_TAG_LEN];
};
struct xdev_ext_xd_fact {
	u64 epoch, wake, born, posted, local_done, withdrawal, arm_order;
	u64 wait_epoch;
	u32 event;
	bool reserved, accepted, traced, complete_traced, published, retired, cts_received;
	struct xdev_ext_xd_reply *reply;
};
struct xdev_ext_xd_rts {
	struct xdev_ext_xd_msg msg;
	u64 wake, wait_epoch;
	bool canceled, consumed, admission;
	int status;
};
struct xdev_ext_xd_cookie_entry { u64 group; int status; bool ended, released; };
struct xdev_ext_xd_cookie { struct xdev_ext_xd_cookie_entry st[XDEV_EXT_MECH_MAX_STAGES]; };
struct xdev_ext_xd_batch {
	struct xdev_ext_xdomain_desc desc[XDEV_EXT_MECH_MAX_FRAMES];
	struct xdev_ext_xdomain_mech_cqe cqe;
	struct xdev_ext_net_slot *slot;
	u32 nr, elems;
};
/* Shared policy facts, independent of the authority epoch. Unrelated group
 * publications change authority but do not make a waiting candidate runnable. */
struct xdev_ext_xd_wait_facts {
	u64 credit, base, next, posted, consumed, room, local, remote, pool, admits, stop;
};
struct xdev_ext_xd_stage {
	struct xdev_ext_netfam_stage ns;
	struct xdev_ext_xd_fact *facts;
	struct xdev_ext_xd_rts rts[XDEV_EXT_REL_MAX_WINDOW];
	struct xdev_ext_xd_msg ctl[XD_EVENTS];
	struct xdev_ext_xd_reply replies[XD_REPLIES];
	u32 rts_count, ctl_count, posted_groups, channel, cursor;
	u64 stream, epoch, event_id, order, local_inc, remote_inc, stop_ns, next_wake;
	u64 ctl_wake[XD_EVENTS], ctl_wait_epoch[XD_EVENTS];
	u64 wait_generation;
	struct xdev_ext_xd_wait_facts wait_facts;
	bool stop_latched, down_latched, overflow, failed;
	int stage_error;
	/* Worker-only current authority; callbacks change epoch, never this token. */
	struct { u64 id, epoch, ticket; u32 event; struct xdev_ext_net_slot *slot;
		struct xdev_ext_xd_reply *reply; bool rts, ctl; } worker_event;
};

static struct xdev_ext_xd_ep *xdev_ext_xd_ep_of(struct xdev_ext_xd_stage *xs)
{ return xs->ns.lk; }
static struct xdev_ext_xd_fact *xd_fact(struct xdev_ext_xd_stage *xs, struct xdev_ext_net_slot *slot)
{ return &xs->facts[slot - xs->ns.slots]; }
static void xd_changed(struct xdev_ext_xd_stage *xs)
{ xs->epoch++; xdev_ext_mech_stage_kick(xs->ns.st); }
static bool xd_waiting(struct xdev_ext_xd_stage *xs, u64 wake, u64 epoch, u64 now)
{ return wake > now && epoch == xs->wait_generation; }
/* ns lock held, with the same ns -> xl nesting as a protocol snapshot. */
static void xd_refresh_waits(struct xdev_ext_xd_stage *xs)
{
	struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
	struct xdev_ext_xd_wait_facts current = {
		.credit = xs->ns.rx ? (xs->ns.rx_rel_ready ? xs->ns.rx_rel.credit : 0) : xs->ns.tx.credit,
		.base = xs->ns.rx ? xs->ns.rx_rel.base_group : xs->ns.tx.base_group,
		.next = xs->ns.rx ? 0 : xs->ns.tx.next_group,
		.posted = xs->posted_groups,
		.pool = xdev_ext_peer_mech_pool_generation(xdev_ext_mech_session_pool(xs->ns.st->s)),
		.admits = xdev_ext_mech_session_admits(xs->ns.st->s),
		.stop = xs->stop_latched,
	};
	spin_lock(&ep->xl->lock);
	current.consumed = ep->xl->chan[ep->chan].consumed;
	current.room = !bitmap_empty(ep->xl->ctl_tx_free, XDEV_EXT_XD_CTL_RING);
	current.local = ep->xl->local_inc; current.remote = ep->xl->remote_inc;
	spin_unlock(&ep->xl->lock);
	if (memcmp(&current, &xs->wait_facts, sizeof(current))) {
		xs->wait_facts = current;
		xs->wait_generation++;
	}
}
static void xd_group_wake(struct xdev_ext_xd_stage *xs, struct xdev_ext_net_slot *s)
{
	struct xdev_ext_xd_fact *f = xd_fact(xs, s);
	u32 k;
	f->wake = 0;
	if (f->reply) f->reply->wake = 0;
	for (k = 0; k < xs->ctl_count; k++)
		if (xs->ctl[k].group == s->group) xs->ctl_wake[k] = 0;
}
static bool xd_remote_final(u32 remote)
{
	return remote == XDEV_EXT_NET_REMOTE_ACKED || remote == XDEV_EXT_NET_REMOTE_FAILED ||
	       remote == XDEV_EXT_NET_REMOTE_LOST;
}
static struct xdev_ext_net_slot *xd_group(struct xdev_ext_xd_stage *xs, u64 group)
{
	u32 i;
	for (i = 0; i < xs->ns.depth; i++)
		if (xs->ns.slots[i].busy && xs->ns.slots[i].group == group)
			return &xs->ns.slots[i];
	return NULL;
}
static struct xdev_ext_net_slot *xd_armed(struct xdev_ext_xd_stage *xs)
{
	struct xdev_ext_net_slot *best = NULL;
	u32 i;
	for (i = 0; i < xs->ns.depth; i++) {
		struct xdev_ext_net_slot *s = &xs->ns.slots[i];
		if (s->busy && s->state == XDEV_EXT_RDV_ARMED &&
		    (!best || xd_fact(xs, s)->arm_order < xd_fact(xs, best)->arm_order)) best = s;
	}
	return best;
}
static struct xdev_ext_xd_reply *xd_reply_group(struct xdev_ext_xd_stage *xs, u64 group)
{
	u32 i;
	for (i = 0; i < XD_REPLIES; i++)
		if (xs->replies[i].used && xs->replies[i].group == group) return &xs->replies[i];
	return NULL;
}
/* Same final status used by SEND_ACK/FAIL and observational diagnostics. */
static int xd_reply_status(const struct xdev_ext_xd_reply *r)
{
	return r->local_status ? r->local_status :
		(r->chain_status ? r->chain_status : r->sequestered ? -ENOLINK : 0);
}
static void xd_reply_put(struct xdev_ext_xd_stage *xs, struct xdev_ext_xd_reply *r)
{
	if (r && r->admission) {
		r->admission = false;
		xdev_ext_mech_stage_native_put(xs->ns.st);
	}
}
static int xd_send(struct xdev_ext_xd_stage *xs, struct xdev_ext_xd_msg *m)
{
	struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
	return xdev_ext_xd_msg_send(ep->xl, ep, ep->chan, m);
}
static void xd_fail_locked(struct xdev_ext_xd_stage *xs, int err)
{
	struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
	bool changed = !xs->failed || !xs->down_latched;

	if (!xs->failed) {
		xs->failed = true;
		xdev_ext_xd_link_fail(ep->xl, ep, err);
	}
	xs->down_latched = true;
	if (changed) xd_changed(xs);
}
static void xd_policy_error(struct xdev_ext_xd_stage *xs)
{
	unsigned long flags;
	xdev_ext_mech_count(xs->ns.st->s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
	spin_lock_irqsave(&xs->ns.lock, flags);
	xd_fail_locked(xs, -EPROTO);
	spin_unlock_irqrestore(&xs->ns.lock, flags);
	xdev_ext_mech_stage_dead(xs->ns.st, -EPROTO);
}
static void xd_local(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot)
{
	struct xdev_ext_xd_stage *xs = container_of(ns, struct xdev_ext_xd_stage, ns);
	struct xdev_ext_xd_fact *f = xd_fact(xs, slot);
	u32 i;
	/* Last callback has acquired every element's done_len/status. */
	for (i = 0; i < slot->nr; i++)
		if (!slot->local_status && slot->elem[i].done_len != slot->elem[i].len)
			slot->local_status = -EMSGSIZE;
	if (f->reply) {
		f->reply->local_status = slot->local_status;
		f->reply->sequestered |= !slot->local_quiesced;
		if (slot->local_status) f->reply->final = true;
	}
	if (ns->rx && f->accepted && slot->local_quiesced && xs->posted_groups) xs->posted_groups--;
	if (!slot->local_quiesced) xd_fail_locked(xs, -ENOLINK);
	f->local_done = ktime_get_boottime_ns();
	f->event = XDEV_EXT_XDP_EV_LOCAL;
	xd_group_wake(xs, slot);
	f->epoch++;
	xd_changed(xs);
}
static int xd_withdraw(struct xdev_ext_netfam_stage *ns, struct xdev_ext_net_slot *slot)
{
	struct xdev_ext_xd_stage *xs = container_of(ns, struct xdev_ext_xd_stage, ns);
	struct xdev_ext_xd_msg m = { .type = XDEV_EXT_XD_CANCEL, .stream = xs->stream, .group = slot->group };
	return xd_send(xs, &m);
}
static void xd_link_fail(struct xdev_ext_netfam_stage *ns, int err)
{ xd_fail_locked(container_of(ns, struct xdev_ext_xd_stage, ns), err); }
static void xd_result(struct xdev_ext_netfam_stage *ns, struct xdev_ext_mech_batch *b,
		const struct xdev_ext_net_slot *slot, int status, bool sequester)
{
	struct xdev_ext_xd_batch *bp = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_xd_stage *xs = container_of(ns, struct xdev_ext_xd_stage, ns);
	struct xdev_ext_xd_fact *f = xd_fact(xs, (struct xdev_ext_net_slot *)slot);
	u32 i;
	bp->cqe = (struct xdev_ext_xdomain_mech_cqe){ .status = status,
		.outcome = xdev_ext_mech_classify(!status, sequester), .remote = slot->remote, .group = slot->group };
	for (i = 0; i < slot->nr; i++) {
		bp->cqe.bytes += slot->elem[i].done_len;
		if (slot->elem[i].done_len) bp->cqe.elems_done++;
		if (slot->elem[i].dev_flags & XDEV_EXT_XD_DESC_CRC_ERROR) bp->cqe.crc_errors++;
	}
	if (ns->rx && f->reply) memcpy(bp->cqe.tag, f->reply->tag, sizeof(bp->cqe.tag));
	f->published = true;
}
static const struct xdev_ext_net_member xd_member = {
	.dev = &xdev_ext_xd_dev_ops, .admit = true, .result = xd_result,
	.local = xd_local, .withdraw = xd_withdraw, .link_fail = xd_link_fail,
};

static void xdev_ext_xd_class_fill_info(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, void *out)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
	struct xdev_ext_xdomain_mech_info *info = out;
	struct xdev_ext_mech_frame f;
	unsigned long flags;
	u32 i;
	*info = (struct xdev_ext_xdomain_mech_info){ .l = *xdev_ext_mech_session_layout(st->s),
		.generation = xdev_ext_peer_mech_pool_generation(xdev_ext_mech_session_pool(st->s)),
		.direction = st->direction, .channel = ep->chan, .max_frame = XDEV_EXT_XD_FRAME,
		.max_elems = XDEV_EXT_XDOMAIN_MAX_ELEMS };
	memcpy(info->remote_uuid, &ep->xl->remote_uuid, sizeof(info->remote_uuid));
	spin_lock_irqsave(&ep->xl->lock, flags);
	info->local_inc = ep->xl->local_inc; info->remote_inc = ep->xl->remote_inc;
	spin_unlock_irqrestore(&ep->xl->lock, flags);
	if (!xs->ns.rx) {
		spin_lock_irqsave(&xs->ns.lock, flags);
		info->next_group = xs->ns.tx.next_group; info->credit = xs->ns.tx.credit;
		spin_unlock_irqrestore(&xs->ns.lock, flags);
	}
	if (!b) return;
	info->nr_frames = xdev_ext_mech_batch_nr_frames(b);
	for (i = 0; i < info->nr_frames; i++) {
		if (xdev_ext_mech_batch_frame(b, i, &f)) { info->nr_frames = 0; return; }
		info->f[i] = (struct xdev_ext_mech_frame_info){ .umem_addr = f.umem_addr, .data_off = f.data_off, .data_len = f.data_len };
	}
}
static int xdev_ext_xd_class_default_build(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, u8 *scratch)
{
	struct xdev_ext_xdomain_desc *d = (void *)scratch;
	struct xdev_ext_xdomain_mech_info info;
	u32 i;
	xdev_ext_xd_class_fill_info(st, b, &info);
	if (!info.nr_frames) return -EPROTO;
	for (i = 0; i < info.nr_frames; i++) d[i] = (struct xdev_ext_xdomain_desc){ .frame_pos = i, .frame_off = info.f[i].data_off, .len = info.f[i].data_len };
	d[0].group = info.next_group;
	return 0;
}
struct xdev_ext_xd_cover { const struct xdev_ext_xdomain_desc *d; };
static void xdev_ext_xd_span(const void *ctx, u32 i, struct xdev_ext_net_span *s)
{
	const struct xdev_ext_xdomain_desc *d = &((const struct xdev_ext_xd_cover *)ctx)->d[i];
	u32 k, bad = d->flags;
	for (k = 0; k < sizeof(d->rsvd); k++) bad |= d->rsvd[k];
	if (i) { bad |= d->group != 0; for (k = 0; k < XDEV_EXT_XDOMAIN_TAG_LEN; k++) bad |= d->tag[k]; }
	*s = (struct xdev_ext_net_span){ d->frame_pos, d->frame_off, d->len, bad };
}
static int xdev_ext_xd_class_validate(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xd_batch *bp = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	const struct xdev_ext_xdomain_desc *d = (const void *)scratch;
	struct xdev_ext_xd_cover c = { .d = d };
	struct xdev_ext_xdomain_mech_info info;
	u32 i, k, segs, elems = 0;
	int ret;
	xdev_ext_xd_class_fill_info(st, b, &info);
	if (!info.nr_frames || !n || n > XDEV_EXT_MECH_MAX_FRAMES) return -EPROTO;
	for (i = 0; i < info.nr_frames; i++)
		if (info.f[i].umem_addr % pool->frame_size || !info.f[i].data_len) return -EPROTO;
	if (xs->ns.rx ? d[0].group != 0 : d[0].group != info.next_group) return -EINVAL;
	for (k = 0; xs->ns.rx && k < XDEV_EXT_XDOMAIN_TAG_LEN; k++) if (d[0].tag[k]) return -EINVAL;
	for (i = 0; i < n; i++)
		if (d[i].frame_off % XDEV_EXT_XD_FRAME) return -EINVAL;
	ret = xdev_ext_net_cover_check(info.f, info.nr_frames, n, XDEV_EXT_MECH_MAX_FRAMES, xdev_ext_xd_span, NULL, &c);
	if (ret) return ret;
	for (i = 0; i < n; i++) {
		segs = xdev_ext_net_segments(d[i].frame_off, d[i].len, XDEV_EXT_XD_FRAME, XDEV_EXT_XD_FRAME);
		if (!segs) return -EINVAL;
		if (xs->ns.rx && !xdev_ext_net_rx_room_ok(d[i].frame_off, d[i].len, XDEV_EXT_XD_FRAME, pool->frame_size)) return -ERANGE;
		elems += segs;
	}
	if (elems > XDEV_EXT_XDOMAIN_MAX_ELEMS) return -E2BIG;
	memcpy(bp->desc, d, n * sizeof(*d)); bp->nr = n; bp->elems = elems;
	return 0;
}
static int xdev_ext_xd_lease_all(struct xdev_ext_xd_stage *xs, struct xdev_ext_net_slot *slot, const struct xdev_ext_xd_batch *bp)
{
	struct xdev_ext_mech_frame f;
	u32 i, k, n = 0, eoff, elen, segs;
	int ret;
	for (i = 0; i < bp->nr; i++) {
		const struct xdev_ext_xdomain_desc *d = &bp->desc[i];
		ret = xdev_ext_mech_batch_frame(slot->batch, d->frame_pos, &f);
		if (ret) return ret;
		segs = xdev_ext_net_segments(d->frame_off, d->len, XDEV_EXT_XD_FRAME, XDEV_EXT_XD_FRAME);
		for (k = 0; k < segs; k++, n++) {
			xdev_ext_net_segment(d->frame_off, d->len, XDEV_EXT_XD_FRAME, k, &eoff, &elen);
			ret = xdev_ext_netfam_lease(&xs->ns, slot, n, f.umem_addr + eoff, elen, xs->ns.rx ? XDEV_EXT_XD_FRAME : elen);
			if (ret) return ret;
		}
	}
	return n == bp->elems ? 0 : -EPROTO;
}

static u64 xd_hard(struct xdev_ext_xd_stage *xs, struct xdev_ext_net_slot *s)
{
	struct xdev_ext_xd_fact *f = xd_fact(xs, s);
	u64 d = xdev_ext_rel_deadline(s->withdrawn && !f->accepted ? f->withdrawal :
		(!xs->ns.rx && s->local_known && f->accepted ? f->local_done :
		 (f->accepted ? f->posted : f->born)),
				    s->withdrawn && !f->accepted ? XD_STOP_NS : XD_PHASE_NS);
	if (xs->stop_latched && xdev_ext_rel_deadline(xs->stop_ns, XD_STOP_NS) < d)
		d = xdev_ext_rel_deadline(xs->stop_ns, XD_STOP_NS);
	return d;
}
/* Project a refusal without changing the live window. Only a fresh group in
 * this stream can return capacity; an accepted group keeps its commitment. */
static int xd_refusal_window(struct xdev_ext_xd_stage *xs,
		const struct xdev_ext_xd_msg *m, struct xdev_ext_rel_rx *proved)
{
	const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(xs->ns.st->s);
	int ret;

	if (xs->ns.rx_rel_ready) {
		*proved = xs->ns.rx_rel;
	} else {
		struct xdev_ext_rel_cfg cfg = { .session = m->stream, .first_group = m->group,
			.window = XDEV_EXT_REL_MAX_WINDOW, .max_attempts = 1, .timeout_ns = XD_PHASE_NS,
			.group_bytes = l->group_bytes, .seg_len = l->seg_len };
		ret = xdev_ext_rel_rx_init(proved, &cfg);
		if (ret) return ret;
	}
	ret = xdev_ext_net_rts_check(proved, m->stream, m->group,
		l->group_bytes, xdev_ext_xd_layout_count(l), l->group_bytes, xdev_ext_xd_layout_count(l));
	if (ret) return ret;
	xdev_ext_net_rts_accept(proved, m->group);
	return xdev_ext_net_rx_close(proved, m->group);
}
/* ns lock held. Link lock is nested only in the documented ns -> xl order. */
static void xd_snapshot(struct xdev_ext_xd_stage *xs, struct xdev_ext_net_slot *s,
		struct xdev_ext_xd_reply *r, u32 event, bool rts, bool ctl,
		struct xdev_ext_xdomain_proto_info *i)
{
	struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
	struct xdev_ext_xd_link *xl = ep->xl;
	struct xdev_ext_xd_fact *f = s ? xd_fact(xs, s) : NULL;
	const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(xs->ns.st->s);
	struct xdev_ext_xd_msg *m = rts ? &xs->rts[0].msg : ctl ? &xs->ctl[0] : NULL;
	bool admits = xdev_ext_mech_session_admits(xs->ns.st->s);
	*i = (struct xdev_ext_xdomain_proto_info){ .size = sizeof(*i), .version = XDEV_EXT_XDOMAIN_PROTO_VERSION,
		.event = event, .direction = xs->ns.st->direction, .event_id = xs->event_id == ~0ULL ? ~0ULL : ++xs->event_id,
		.epoch = xs->epoch, .pool_generation = xdev_ext_peer_mech_pool_generation(xdev_ext_mech_session_pool(xs->ns.st->s)),
		.stream = xs->stream, .now_ns = ktime_get_boottime_ns(), .want_len = l->group_bytes,
		.want_count = xdev_ext_xd_layout_count(l), .posted_groups = xs->posted_groups, .channel = ep->chan,
		.credit = xs->ns.rx ? (xs->ns.rx_rel_ready ? xs->ns.rx_rel.credit : 0) : xs->ns.tx.credit,
		.base_group = xs->ns.rx ? xs->ns.rx_rel.base_group : xs->ns.tx.base_group,
		.next_group = xs->ns.rx ? 0 : xs->ns.tx.next_group };
	if (admits) i->facts |= XDEV_EXT_XDP_F_ADMITS;
	else i->facts |= XDEV_EXT_XDP_F_STOPPING;
	if (xs->ns.dead) i->facts |= XDEV_EXT_XDP_F_STAGE_DEAD;
	spin_lock(&xl->lock);
	i->local_inc = xl->local_inc; i->remote_inc = xl->remote_inc;
	i->expected_seq = xl->chan[ep->chan].consumed;
	i->ctl_room = !bitmap_empty(xl->ctl_tx_free, XDEV_EXT_XD_CTL_RING);
	if (xl->up && !ep->detached && !xs->failed && i->local_inc == xs->local_inc && i->remote_inc == xs->remote_inc)
		i->facts |= XDEV_EXT_XDP_F_LINK_UP;
	spin_unlock(&xl->lock);
	if (s) {
		xs->cursor = (s - xs->ns.slots + 1) % xs->ns.depth;
		i->group = s->group; i->state = s->state; i->remote = s->remote; i->local_status = s->local_status;
		i->hard_deadline_ns = xd_hard(xs, s);
		if (!xs->ns.rx && s->state == XDEV_EXT_RDV_ANNOUNCED && !s->withdrawn)
			i->policy_deadline_ns = xdev_ext_rel_deadline(f->born, XD_WITHDRAW_NS);
		if (s->local_known) i->facts |= XDEV_EXT_XDP_F_LOCAL_KNOWN;
		if (s->local_quiesced) i->facts |= XDEV_EXT_XDP_F_LOCAL_QUIESCED;
		if (f->accepted) i->facts |= XDEV_EXT_XDP_F_NATIVE_POSTED;
		if (f->reserved || (f->accepted && !s->local_known)) i->facts |= XDEV_EXT_XDP_F_NATIVE_PENDING;
		if (s->withdrawn) i->facts |= XDEV_EXT_XDP_F_WITHDRAWN;
		if (f->cts_received) i->facts |= XDEV_EXT_XDP_F_CTS_RECEIVED;
		r = f->reply;
	}
	if (r) {
		i->group = r->group; i->stream = r->stream; i->chain_status = r->chain_status;
		if (!s) { i->local_status = r->local_status; i->hard_deadline_ns = r->deadline;
			if (xs->stop_latched && xdev_ext_rel_deadline(xs->stop_ns, XD_STOP_NS) < i->hard_deadline_ns)
				i->hard_deadline_ns = xdev_ext_rel_deadline(xs->stop_ns, XD_STOP_NS);
			if (r->native_posted) i->facts |= XDEV_EXT_XDP_F_NATIVE_POSTED; }
		if (r->cts) i->facts |= XDEV_EXT_XDP_F_CTS_OWED;
		if (r->final) i->facts |= XDEV_EXT_XDP_F_FINAL_OWED;
		if (r->chain_done) i->facts |= XDEV_EXT_XDP_F_CHAIN_DONE;
		if (r->sequestered) i->facts |= XDEV_EXT_XDP_F_CHAIN_SEQUESTERED;
		/* Final disposition proves capacity independently of whether BPF
		 * advertises it. Project the checked close without mutating the
		 * live window or promising credit before the selected reply. */
		if (xs->ns.rx && (r->chain_done || (!r->native_posted && r->local_status)) &&
		    !r->closed && !r->sequestered && xs->ns.rx_rel_ready) {
			struct xdev_ext_rel_rx proved = xs->ns.rx_rel;

			if (!xdev_ext_net_rx_close(&proved, r->group)) i->credit = proved.credit;
		}
		memcpy(i->tag, r->tag, sizeof(i->tag));
	}
	if (m) {
		i->group = m->group; i->stream = m->stream; i->msg_type = m->type;
		i->data_seq = m->data_seq; i->total_len = m->total_len; i->count = m->count;
		memcpy(i->tag, m->tag, sizeof(i->tag));
		if (!xs->ns.rx) {
			u64 cap = xs->ns.tx.next_group > ~0ULL - xs->ns.tx.cfg.window ? ~0ULL : xs->ns.tx.next_group + xs->ns.tx.cfg.window;
			i->msg_credit = m->type == XDEV_EXT_XD_HELD ? xs->ns.tx.credit : (m->credit < cap ? m->credit : cap);
		}
		if (rts) {
			struct xdev_ext_rel_rx proved;
			if (xs->rts[0].canceled) i->facts |= XDEV_EXT_XDP_F_RTS_CANCELED;
			if (!admits) i->local_status = -ESHUTDOWN;
			else if (xs->rts[0].canceled) i->local_status = -ECANCELED;
			else if (m->total_len != i->want_len || m->count != i->want_count || (xs->stream && m->stream != xs->stream)) i->local_status = -EPROTO;
			if (!xd_refusal_window(xs, m, &proved)) i->credit = proved.credit;
		}
	}
	xs->worker_event.id = i->event_id; xs->worker_event.epoch = i->epoch; xs->worker_event.event = event;
	xs->worker_event.slot = s; xs->worker_event.reply = r; xs->worker_event.rts = rts; xs->worker_event.ctl = ctl;
	xs->worker_event.ticket = s ? s->ticket : 0;
}
static int xdev_ext_xd_protocol_call(struct xdev_ext_xd_stage *xs,
		const struct xdev_ext_xdomain_proto_info *info, struct xdev_ext_xdomain_proto_result *result)
{
	struct xdev_ext_binding_ctx_v2 base = { .abi_version = XDEV_EXT_BINDING_ABI_VERSION,
		.ctx_size = sizeof(base), .backend = XDEV_EXT_BINDING_BACKEND_UNSPEC, .direction = xs->ns.st->direction };
	struct xdev_ext_mech_call_args a = { .member = XDEV_EXT_MECH_MEMBER_COMPLETE,
		.callsite = XDEV_EXT_MECH_SITE_WORKER_PROTOCOL, .base = &base,
		.info = info, .info_size = sizeof(*info), .xdomain = result };
	s32 ret = -1;
	int err;
	memset(result, 0, sizeof(*result));
	err = xdev_ext_mech_call(xs->ns.st, &a, &ret, NULL);
	return err || ret || result->calls != 1 ? -EPROTO : 0;
}
static void xd_drop_input(struct xdev_ext_xd_stage *xs)
{
	if (xs->worker_event.ctl && xs->ctl_count) {
		xs->ctl_count--; memmove(xs->ctl, xs->ctl + 1, xs->ctl_count * sizeof(xs->ctl[0]));
		memmove(xs->ctl_wake, xs->ctl_wake + 1, xs->ctl_count * sizeof(xs->ctl_wake[0]));
		memmove(xs->ctl_wait_epoch, xs->ctl_wait_epoch + 1, xs->ctl_count * sizeof(xs->ctl_wait_epoch[0]));
	}
	if (xs->worker_event.rts && xs->rts_count) {
		xs->rts_count--; memmove(xs->rts, xs->rts + 1, xs->rts_count * sizeof(xs->rts[0]));
	}
}
static void xd_trace_done(struct xdev_ext_xd_stage *xs, struct xdev_ext_net_slot *s)
{
	struct xdev_ext_xd_fact *f = xd_fact(xs, s);
	if (f->accepted && f->traced && s->local_known && !f->complete_traced &&
	    xdev_ext_net_read(&s->track.pending) == 0) {
		f->complete_traced = true;
		xdev_ext_mech_trace_native_complete(s->batch, s->ticket, s->local_status);
	}
}
/* Native reservation is immutable once accepted. Epoch changes from an early
 * completion are merged after post; they can never convert acceptance to retry. */
static int xd_post(struct xdev_ext_xd_stage *xs, struct xdev_ext_net_slot *s,
		const struct xdev_ext_xdomain_proto_info *i)
{
	struct xdev_ext_xd_fact *f = xd_fact(xs, s);
	struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
	struct xdev_ext_xd_batch *bp = xdev_ext_mech_batch_priv(s->batch);
	unsigned long flags;
	u64 ticket = s->ticket, epoch = f->epoch;
	u32 k, bytes = 0;
	bool family_called = false;
	int ret;
	ret = xdev_ext_xd_lease_all(xs, s, bp);
	spin_lock_irqsave(&xs->ns.lock, flags);
	if (!ret && (xs->ns.dead || xs->failed ||
	    (xs->ns.rx && !xdev_ext_mech_session_admits(xs->ns.st->s)) || s->ticket != ticket ||
	    xdev_ext_mech_batch_ticket(s->batch) != ticket || f->epoch != epoch ||
	    i->pool_generation != xdev_ext_peer_mech_pool_generation(xdev_ext_mech_session_pool(xs->ns.st->s)))) ret = -ESTALE;
	spin_lock(&ep->xl->lock);
	if (!ret && (!ep->xl->up || ep->detached || ep->xl->local_inc != i->local_inc || ep->xl->remote_inc != i->remote_inc)) ret = -ESTALE;
	spin_unlock(&ep->xl->lock);
	spin_unlock_irqrestore(&xs->ns.lock, flags);
	if (!ret) { family_called = true; ret = xdev_ext_netfam_post(&xs->ns, s); }
	spin_lock_irqsave(&xs->ns.lock, flags);
	f->reserved = false;
	xd_group_wake(xs, s);
	if (ret) {
		/* Vtable refuses all elements on error. No native owner exists. */
		if (!family_called) xdev_ext_netfam_release(s, true);
		s->busy = true;
		if (xs->ns.rx && xs->posted_groups) xs->posted_groups--;
		s->local_known = s->local_quiesced = true; s->local_status = ret;
		if (!xs->ns.rx) xdev_ext_rel_tx_native_done(&xs->ns.tx, s->group, 1, ret, false, i->now_ns);
		f->event = XDEV_EXT_XDP_EV_POST_RESULT;
		if (xs->ns.rx && f->reply) {
			f->reply->local_status = ret;
			f->reply->final = true;
		} else xd_fail_locked(xs, ret);
	} else {
		f->accepted = true; f->withdrawal = 0;
		s->state = XDEV_EXT_RDV_POSTED;
		f->posted = i->now_ns;
		for (k = 0; k < s->nr; k++) bytes += s->elem[k].len;
		xdev_ext_mech_trace_native_submit(s->batch, s->group, 0, bytes, xs->ns.st->direction);
		f->traced = true;
		/* Callback may have won on another CPU while post was returning. */
		if (s->local_known) {
			if (xs->ns.rx && s->local_quiesced && xs->posted_groups) xs->posted_groups--;
			f->event = XDEV_EXT_XDP_EV_LOCAL;
		} else f->event = XDEV_EXT_XDP_EV_POST_RESULT;
		if (xs->ns.rx && f->reply) { f->reply->cts = true; f->reply->native_posted = true; }
		xd_trace_done(xs, s);
	}
	xd_changed(xs);
	spin_unlock_irqrestore(&xs->ns.lock, flags);
	return 0;
}
static int xdev_ext_xd_apply(struct xdev_ext_xd_stage *xs,
		const struct xdev_ext_xdomain_proto_info *i, const struct xdev_ext_xdomain_proto_verdict *v)
{
	struct xdev_ext_netfam_stage *ns = &xs->ns;
	struct xdev_ext_net_slot *s;
	struct xdev_ext_xd_fact *f;
	struct xdev_ext_xd_reply *r;
	struct xdev_ext_xd_msg m = {};
	unsigned long flags;
	u64 now = ktime_get_boottime_ns();
	u32 act = v->action, k;
	bool sequester;
	int ret = 0, status;

	if (v->size != sizeof(*v) || v->version != XDEV_EXT_XDOMAIN_PROTO_VERSION ||
	    v->flags || v->reserved0 || v->reserved1 || v->event_id != i->event_id || v->epoch != i->epoch ||
	    act < XDEV_EXT_XDP_ACT_WAIT || act > XDEV_EXT_XDP_ACT_CANCEL_ARMED) return -EPROTO;
	if ((act != XDEV_EXT_XDP_ACT_WAIT && v->wake_ns) ||
	    ((act < XDEV_EXT_XDP_ACT_ACCEPT_HELD || act > XDEV_EXT_XDP_ACT_ACCEPT_FAIL) &&
	     (act < XDEV_EXT_XDP_ACT_SEND_CTS || act > XDEV_EXT_XDP_ACT_SEND_FAIL) && v->credit) ||
	    (act != XDEV_EXT_XDP_ACT_PUBLISH && act != XDEV_EXT_XDP_ACT_SEND_FAIL &&
	     act != XDEV_EXT_XDP_ACT_REJECT_RTS && act != XDEV_EXT_XDP_ACT_FAIL_LINK &&
	     act != XDEV_EXT_XDP_ACT_CANCEL_ARMED && v->status)) return -EPROTO;
	spin_lock_irqsave(&ns->lock, flags);
	s = xs->worker_event.slot; f = s ? xd_fact(xs, s) : NULL; r = xs->worker_event.reply;
	if (xs->event_id == ~0ULL || xs->worker_event.id != i->event_id || xs->worker_event.event != i->event) { ret = -EPROTO; goto out; }
	if (xs->epoch != i->epoch || (s && (!s->busy || s->ticket != xs->worker_event.ticket ||
	    xdev_ext_mech_batch_ticket(s->batch) != xs->worker_event.ticket)) ||
	    i->pool_generation != xdev_ext_peer_mech_pool_generation(xdev_ext_mech_session_pool(ns->st->s))) { ret = -ESTALE; goto out; }
	/* STOP may win without a class callback. Recheck before every side effect. */
	if (((i->facts & XDEV_EXT_XDP_F_ADMITS) && !xdev_ext_mech_session_admits(ns->st->s)) ||
	    (!!(i->facts & XDEV_EXT_XDP_F_STAGE_DEAD) != !!ns->dead)) { ret = -ESTALE; goto out; }
	{
		struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
		bool same;
		spin_lock(&ep->xl->lock);
		same = ep->xl->local_inc == i->local_inc && ep->xl->remote_inc == i->remote_inc &&
		       (!((i->facts & XDEV_EXT_XDP_F_LINK_UP)) || (ep->xl->up && !ep->detached));
		spin_unlock(&ep->xl->lock);
		if (!same) { ret = -ESTALE; goto out; }
	}
	if (i->hard_deadline_ns && now >= i->hard_deadline_ns &&
	    act != XDEV_EXT_XDP_ACT_WAIT &&
	    act != XDEV_EXT_XDP_ACT_FAIL_LINK && act != XDEV_EXT_XDP_ACT_CANCEL_ARMED &&
	    act != XDEV_EXT_XDP_ACT_PUBLISH && act != XDEV_EXT_XDP_ACT_WITHDRAW) { ret = -EPROTO; goto out; }
	m.stream = i->stream; m.group = i->group;
	switch (act) {
	case XDEV_EXT_XDP_ACT_WAIT:
		/* A verdict is legal against its snapshot. Scheduling delay is
		 * stale work, not a protocol violation by the BPF program.
		 */
		if (!v->wake_ns || v->wake_ns <= i->now_ns ||
		    v->wake_ns > xdev_ext_rel_deadline(i->now_ns, XD_TICK_NS) ||
		    (i->hard_deadline_ns && v->wake_ns > i->hard_deadline_ns) ||
		    (i->policy_deadline_ns && v->wake_ns > i->policy_deadline_ns) ||
		    (i->hard_deadline_ns && i->now_ns >= i->hard_deadline_ns) ||
		    (i->policy_deadline_ns && i->now_ns >= i->policy_deadline_ns)) { ret = -EPROTO; break; }
		if (v->wake_ns <= now ||
		    (i->hard_deadline_ns && now >= i->hard_deadline_ns) ||
		    (i->policy_deadline_ns && now >= i->policy_deadline_ns)) { ret = -ESTALE; break; }
		if (i->event == XDEV_EXT_XDP_EV_TX_SUBMIT || i->event == XDEV_EXT_XDP_EV_RX_SUBMIT) { ret = -EAGAIN; break; }
		if (xs->worker_event.rts) {
			xs->rts[0].wake = v->wake_ns; xs->rts[0].wait_epoch = xs->wait_generation;
		} else if (xs->worker_event.ctl) {
			xs->ctl_wake[0] = v->wake_ns; xs->ctl_wait_epoch[0] = xs->wait_generation;
		} else if (f) {
			f->wake = v->wake_ns; f->wait_epoch = xs->wait_generation;
		} else if (r) {
			r->wake = v->wake_ns; r->wait_epoch = xs->wait_generation;
		}
		if (!xs->next_wake || v->wake_ns < xs->next_wake) xs->next_wake = v->wake_ns;
		break;
	case XDEV_EXT_XDP_ACT_IGNORE:
		if (i->event != XDEV_EXT_XDP_EV_DUPLICATE || (r && (r->cts || r->final))) { ret = -EPROTO; break; }
		xd_drop_input(xs);
		break;
	case XDEV_EXT_XDP_ACT_TX_ANNOUNCE:
		if (ns->rx || !s || i->event != XDEV_EXT_XDP_EV_TX_SUBMIT || s->state != XDEV_EXT_RDV_IDLE ||
		    !(i->facts & XDEV_EXT_XDP_F_ADMITS) || !(i->facts & XDEV_EXT_XDP_F_LINK_UP)) { ret = -EPROTO; break; }
		{
			struct xdev_ext_xd_batch *bp = xdev_ext_mech_batch_priv(s->batch);
			u64 group = bp->desc[0].group;
			ret = xdev_ext_rel_tx_can_open(&ns->tx, group, i->want_len,
				(i->want_len - 1) / ns->tx.cfg.seg_len + 1);
			if (ret != XDEV_EXT_REL_SEND) { ret = ret == XDEV_EXT_REL_BACKPRESSURE ? -EAGAIN : -EPROTO; break; }
			m.type = XDEV_EXT_XD_RTS; m.group = group; m.total_len = i->want_len; m.count = bp->elems;
			memcpy(m.tag, bp->desc[0].tag, sizeof(m.tag));
			ret = xd_send(xs, &m);
			if (ret) break;
			xdev_ext_rel_tx_open(&ns->tx, group, i->want_len,
				(i->want_len - 1) / ns->tx.cfg.seg_len + 1);
			s->group = group; s->state = XDEV_EXT_RDV_ANNOUNCED; f->event = 0;
			((struct xdev_ext_xd_cookie *)xdev_ext_mech_batch_cookie(s->batch))->st[ns->st->index] =
				(struct xdev_ext_xd_cookie_entry){ .group = group };
		}
		break;
	case XDEV_EXT_XDP_ACT_RX_ARM:
		if (!ns->rx || !s || i->event != XDEV_EXT_XDP_EV_RX_SUBMIT || s->state != XDEV_EXT_RDV_IDLE ||
		    !(i->facts & XDEV_EXT_XDP_F_ADMITS) || !(i->facts & XDEV_EXT_XDP_F_LINK_UP)) { ret = -EPROTO; break; }
		for (k = 0; k < XD_REPLIES; k++) if (!xs->replies[k].used || (xs->replies[k].closed && xs->replies[k].chain_done &&
		    !xs->replies[k].admission && !xs->replies[k].cts && !xs->replies[k].final)) break;
		if (k == XD_REPLIES) { ret = -EAGAIN; break; }
		/* Worker native_get uses the core's existing ACTIVE/STOP admission. */
		ret = xdev_ext_mech_stage_native_get(ns->st);
		if (ret) { if (ret == -ESHUTDOWN) ret = -ESTALE; break; }
		r = &xs->replies[k]; *r = (struct xdev_ext_xd_reply){ .used = true, .admission = true, .deadline = xd_hard(xs, s) };
		f->reply = r; s->state = XDEV_EXT_RDV_ARMED; f->arm_order = ++xs->order; f->event = 0;
		for (k = 0; k < xs->rts_count; k++) xs->rts[k].wake = 0;
		break;
	case XDEV_EXT_XDP_ACT_RX_POST:
		if (!ns->rx || !s || !xs->worker_event.rts || i->event != XDEV_EXT_XDP_EV_RTS ||
		    s->state != XDEV_EXT_RDV_ARMED || xs->posted_groups || f->reserved || f->accepted ||
		    i->local_status || xs->rts[0].canceled || !(i->facts & XDEV_EXT_XDP_F_ADMITS)) { ret = -EPROTO; break; }
		if (!ns->rx_rel_ready) {
			struct xdev_ext_rel_cfg cfg = { .session = i->stream, .first_group = i->group,
				.window = XDEV_EXT_REL_MAX_WINDOW, .max_attempts = 1, .timeout_ns = XD_PHASE_NS,
				.group_bytes = i->want_len, .seg_len = xdev_ext_mech_session_layout(ns->st->s)->seg_len };
			ret = xdev_ext_rel_rx_init(&ns->rx_rel, &cfg); if (ret) break;
			xs->stream = i->stream; ns->rx_rel_ready = true;
		}
		ret = xdev_ext_net_rts_check(&ns->rx_rel, i->stream, i->group, i->total_len, i->count, i->want_len, i->want_count);
		if (ret) { ret = -EPROTO; break; }
		{
			struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
			ret = xdev_ext_xd_seq_consume(ep->xl, ep->chan, i->data_seq, i->count); if (ret) break;
		}
		xdev_ext_net_rts_accept(&ns->rx_rel, i->group);
		s->group = i->group;
		r = f->reply; r->group = i->group; r->stream = i->stream; memcpy(r->tag, i->tag, sizeof(r->tag));
		((struct xdev_ext_xd_cookie *)xdev_ext_mech_batch_cookie(s->batch))->st[ns->st->index] =
			(struct xdev_ext_xd_cookie_entry){ .group = i->group };
		xd_drop_input(xs); xs->posted_groups++; f->reserved = true;
		xd_changed(xs);
		spin_unlock_irqrestore(&ns->lock, flags);
		return xd_post(xs, s, i);
	case XDEV_EXT_XDP_ACT_TX_POST:
		if (ns->rx || !s || i->event != XDEV_EXT_XDP_EV_CTS || !xs->worker_event.ctl ||
		    s->state != XDEV_EXT_RDV_ANNOUNCED || f->reserved || f->accepted || ns->dead ||
		    s->local_known || s->remote != XDEV_EXT_NET_REMOTE_NONE ||
		    i->stream != xs->stream || !(i->facts & XDEV_EXT_XDP_F_LINK_UP)) { ret = -EPROTO; break; }
		ret = xdev_ext_net_credit_update(&ns->tx, i->msg_credit);
		if (ret) { ret = -EPROTO; break; }
		ret = xdev_ext_rel_tx_native_begin(&ns->tx, s->group, now);
		if (ret != XDEV_EXT_REL_SEND) { ret = -EPROTO; break; }
		f->cts_received = true; f->reserved = true; xd_drop_input(xs); xd_changed(xs);
		spin_unlock_irqrestore(&ns->lock, flags);
		return xd_post(xs, s, i);
	case XDEV_EXT_XDP_ACT_ACCEPT_HELD:
	case XDEV_EXT_XDP_ACT_ACCEPT_ACK:
	case XDEV_EXT_XDP_ACT_ACCEPT_FAIL:
		if (ns->rx || !s || f->published || xd_remote_final(s->remote) || !xs->worker_event.ctl || i->stream != xs->stream || v->credit != i->msg_credit ||
		    (act == XDEV_EXT_XDP_ACT_ACCEPT_HELD && i->event != XDEV_EXT_XDP_EV_HELD) ||
		    (act == XDEV_EXT_XDP_ACT_ACCEPT_ACK && i->event != XDEV_EXT_XDP_EV_ACK) ||
		    (act == XDEV_EXT_XDP_ACT_ACCEPT_FAIL && i->event != XDEV_EXT_XDP_EV_FAIL) ||
		    (act != XDEV_EXT_XDP_ACT_ACCEPT_FAIL && !f->accepted)) { ret = -EPROTO; break; }
		if (act != XDEV_EXT_XDP_ACT_ACCEPT_HELD && v->credit && xdev_ext_net_credit_update(&ns->tx, v->credit)) { ret = -EPROTO; break; }
		if (act == XDEV_EXT_XDP_ACT_ACCEPT_HELD) s->remote = XDEV_EXT_NET_REMOTE_HELD;
		else {
			xdev_ext_netfam_remote_locked(ns, s, act == XDEV_EXT_XDP_ACT_ACCEPT_ACK ? XDEV_EXT_NET_REMOTE_ACKED : XDEV_EXT_NET_REMOTE_FAILED);
			if (!f->accepted) xdev_ext_netfam_cancel_locked(ns, s, 0);
			if (act == XDEV_EXT_XDP_ACT_ACCEPT_ACK) {
				struct xdev_ext_rel_tx_entry *e = xdev_ext_rel_tx_find(&ns->tx, s->group);
				if (!e || !e->attempt) { ret = -EPROTO; break; }
				e->acked = 1; if (!e->native_pending) e->terminal = XDEV_EXT_REL_COMPLETE;
			}
			f->event = XDEV_EXT_XDP_EV_READY; f->wake = 0;
		}
		xd_drop_input(xs);
		break;
	case XDEV_EXT_XDP_ACT_PUBLISH:
		if (!s || f->published || (i->event != XDEV_EXT_XDP_EV_LOCAL && i->event != XDEV_EXT_XDP_EV_READY) ||
		    !s->local_known || f->reserved) { ret = -EPROTO; break; }
		if (!ns->rx && f->accepted && s->remote != XDEV_EXT_NET_REMOTE_ACKED &&
		    s->remote != XDEV_EXT_NET_REMOTE_FAILED && s->remote != XDEV_EXT_NET_REMOTE_LOST) { ret = -EPROTO; break; }
		status = ns->rx ? s->local_status : xdev_ext_net_outcome(s->local_status, s->local_quiesced, s->remote, &sequester);
		if (status == -EINPROGRESS || status != v->status || (!status && !s->local_quiesced)) { ret = -EPROTO; break; }
		if (!ns->rx && f->accepted) {
			struct xdev_ext_rel_tx_entry *e = xdev_ext_rel_tx_find(&ns->tx, s->group);
			if (e && e->native_pending && s->local_quiesced)
				xdev_ext_rel_tx_native_done(&ns->tx, s->group, 1, s->local_status, false, now);
		}
		xd_trace_done(xs, s);
		s->state = XDEV_EXT_RDV_FINAL;
		xdev_ext_netfam_publish_locked(ns, s, status, !s->local_quiesced);
		f->event = 0;
		break;
	case XDEV_EXT_XDP_ACT_SEND_CTS:
	case XDEV_EXT_XDP_ACT_SEND_ACK:
	case XDEV_EXT_XDP_ACT_SEND_FAIL:
		if (!ns->rx || !r || !r->used || !r->group || v->credit < r->advertised || v->credit > i->credit || !v->credit) { ret = -EPROTO; break; }
		if (act == XDEV_EXT_XDP_ACT_SEND_CTS) {
			if (!r->cts || (s && !f->accepted)) { ret = -EPROTO; break; }
			m.type = XDEV_EXT_XD_CTS;
		} else {
			status = xd_reply_status(r);
			if (!r->final || (act == XDEV_EXT_XDP_ACT_SEND_ACK && (!r->chain_done || status || r->sequestered)) ||
			    (act == XDEV_EXT_XDP_ACT_SEND_FAIL && (!status || status != v->status))) { ret = -EPROTO; break; }
			m.type = act == XDEV_EXT_XDP_ACT_SEND_ACK ? XDEV_EXT_XD_ACK : XDEV_EXT_XD_FAIL;
			m.status = status < 0 ? -status : 0;
		}
		m.credit = v->credit; ret = xd_send(xs, &m); if (ret) break;
		r->advertised = v->credit;
		r->wake = 0;
		if (act == XDEV_EXT_XDP_ACT_SEND_CTS) r->cts = false;
		else {
			r->final = false;
			if (!r->closed && ns->rx_rel_ready) { xdev_ext_net_rx_close(&ns->rx_rel, r->group); r->closed = true; }
			if (!r->sequestered) xd_reply_put(xs, r);
		}
		if (xs->worker_event.ctl || xs->worker_event.rts) xd_drop_input(xs);
		if (f) { f->event = s->local_known && !f->published ? XDEV_EXT_XDP_EV_READY : 0; f->wake = 0; }
		break;
	case XDEV_EXT_XDP_ACT_WITHDRAW:
		if (ns->rx || !s || s->state != XDEV_EXT_RDV_ANNOUNCED || s->withdrawn || f->reserved || f->accepted) { ret = -EPROTO; break; }
		ret = ns->m->withdraw(ns, s); if (ret) break;
		s->withdrawn = true; s->withdraw_ms = now / NSEC_PER_MSEC; f->withdrawal = now; f->event = 0; f->wake = 0;
		break;
	case XDEV_EXT_XDP_ACT_REJECT_RTS:
		if (!ns->rx || !xs->worker_event.rts || !xs->rts_count || (s && f->accepted) ||
		    v->status >= 0 || v->status != i->local_status) { ret = -EPROTO; break; }
		{
			struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
			struct xdev_ext_rel_rx proved;
			bool close = !xd_refusal_window(xs, &xs->rts[0].msg, &proved);
			/* A refusal is transactional with control admission. Duplicates,
			 * old streams and groups already posted cannot close capacity. */
			if (i->data_seq != i->expected_seq ||
			    (close && i->count > ~0ULL - i->expected_seq)) { ret = -EPROTO; break; }
			if ((!r || !r->admission) && !xs->rts[0].admission) {
				ret = xdev_ext_mech_stage_native_get(ns->st);
				if (ret) { xd_fail_locked(xs, -ENOLINK); ret = 0; break; }
				xs->rts[0].admission = true;
			}
			m.type = XDEV_EXT_XD_FAIL; m.status = -v->status;
			m.credit = close ? proved.credit : i->credit;
			ret = xd_send(xs, &m); if (ret) break;
			if (close) {
				ret = xdev_ext_xd_seq_consume(ep->xl, ep->chan, i->data_seq, i->count); if (ret) break;
				ns->rx_rel = proved; ns->rx_rel_ready = true; xs->stream = i->stream;
			}
			if (xs->rts[0].admission) {
				xs->rts[0].admission = false;
				xdev_ext_mech_stage_native_put(ns->st);
			}
			xd_drop_input(xs);
			if (v->status == -EPROTO) {
				xd_fail_locked(xs, -EPROTO); ns->dead = true; xs->stage_error = -EPROTO;
			}
		}
		break;
	case XDEV_EXT_XDP_ACT_FAIL_LINK:
		if (v->status >= 0 || v->status < -XDEV_EXT_MECH_ERRNO_MAX) { ret = -EPROTO; break; }
		xd_fail_locked(xs, v->status);
		break;
	case XDEV_EXT_XDP_ACT_CANCEL_ARMED:
		status = xdev_ext_mech_session_admits(ns->st->s) ? -ETIMEDOUT : -ECANCELED;
		if (!ns->rx || !s || s->state != XDEV_EXT_RDV_ARMED || f->accepted || f->reserved ||
		    v->status != status || (status == -ETIMEDOUT && now < xd_hard(xs, s))) { ret = -EPROTO; break; }
		xdev_ext_netfam_cancel_locked(ns, s, status); xd_reply_put(xs, f->reply);
		if (f->reply) f->reply->used = false;
		s->state = XDEV_EXT_RDV_FINAL;
		xdev_ext_netfam_publish_locked(ns, s, status, false); f->event = 0;
		break;
	default: ret = -EPROTO;
	}
	if (!ret && act != XDEV_EXT_XDP_ACT_WAIT) {
		if (s) xd_group_wake(xs, s);
		xd_changed(xs);
	}
 out:
	spin_unlock_irqrestore(&ns->lock, flags);
	return ret;
}

/* Safety terminalization never invents a completion, credit, or reusable owner. */
static void xd_terminal_locked(struct xdev_ext_xd_stage *xs, int err)
{
	u32 k;
	for (k = 0; k < xs->ns.depth; k++) {
		struct xdev_ext_net_slot *s = &xs->ns.slots[k];
		struct xdev_ext_xd_fact *f = xd_fact(xs, s);
		if (!s->busy || f->published || f->reserved) continue;
		if (!f->accepted) {
			xdev_ext_netfam_cancel_locked(&xs->ns, s, s->local_known ? s->local_status : 0);
		} else if (!s->local_known) {
			if (xdev_ext_peer_net_track_abandon(&s->track, err)) {
				s->local_known = true; s->local_quiesced = false; s->local_status = err;
			}
		}
		if (!s->local_known) continue;
		if (!xs->ns.rx) s->remote = XDEV_EXT_NET_REMOTE_LOST;
		if (!xs->ns.rx && s->local_quiesced && f->accepted)
			xdev_ext_rel_tx_native_done(&xs->ns.tx, s->group, 1, s->local_status, false, ktime_get_boottime_ns());
		xd_trace_done(xs, s);
		s->state = XDEV_EXT_RDV_FINAL;
		xdev_ext_netfam_publish_locked(&xs->ns, s, s->local_status ? s->local_status : -ENOLINK, !s->local_quiesced);
		if (f->reply && s->local_quiesced) { xd_reply_put(xs, f->reply); f->reply->final = f->reply->cts = false; }
		f->event = 0;
	}
	for (k = 0; k < xs->rts_count; k++)
		if (xs->rts[k].admission) {
			xs->rts[k].admission = false;
			xdev_ext_mech_stage_native_put(xs->ns.st);
		}
	/* Detached group replies have no native payload owner. */
	for (k = 0; k < XD_REPLIES; k++) {
		struct xdev_ext_xd_reply *r = &xs->replies[k];
		struct xdev_ext_net_slot *s = r->group ? xd_group(xs, r->group) : NULL;
		if (r->used && (!s || s->local_quiesced) && !r->sequestered) {
			xd_reply_put(xs, r); r->final = r->cts = false;
		}
	}
}
/* Device unbind holds ep_mutex after removing the endpoint. The worker is
 * stopped, so no ingress or progress can add/remove these records. Keep the
 * class storage and endpoint alive until X4 has settled each raw obligation;
 * native admissions, replies and slot custody remain the core drain's job. */
void xdev_ext_xd_class_detach(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xd_ep *ep = xdev_ext_xd_ep_of(xs);
	struct xdev_ext_xd_msg m;
	unsigned long flags;
	u32 k = 0;
	bool overflow;

	spin_lock_irqsave(&xs->ns.lock, flags);
	overflow = xs->overflow;
	spin_unlock_irqrestore(&xs->ns.lock, flags);
	/* An overflow may have omitted an RTS from the bounded queue. */
	if (overflow) xdev_ext_xd_link_fail(ep->xl, ep, -EPROTO);
	for (;;) {
		spin_lock_irqsave(&xs->ns.lock, flags);
		if (k == xs->rts_count) {
			spin_unlock_irqrestore(&xs->ns.lock, flags);
			break;
		}
		m = xs->rts[k++].msg;
		spin_unlock_irqrestore(&xs->ns.lock, flags);
		xdev_ext_xd_refuse_rts(ep->xl, &m);
	}
}
void xdev_ext_xd_class_ctl(struct xdev_ext_mech_stage *st, const struct xdev_ext_xd_msg *m)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	unsigned long flags;
	u32 k;
	if (!xs) return;
	spin_lock_irqsave(&xs->ns.lock, flags);
	/* dev.bind may have published the endpoint just before ns.lk is set.
	 * X4 already authenticated this wire record; retain its scalar facts,
	 * then compare incarnations on the worker after attachment finishes. */
	if (m->channel != xs->channel || xs->failed ||
	    (xs->local_inc && (m->src_inc != xs->remote_inc || m->dst_inc != xs->local_inc))) goto out;
	if (!xs->ns.rx && m->stream != xs->stream) goto out;
	if (xs->ns.rx && m->type == XDEV_EXT_XD_RTS) {
		for (k = 0; k < xs->rts_count; k++)
			if (xs->rts[k].msg.group == m->group && xs->rts[k].msg.stream == m->stream) goto out;
		if (xs->rts_count == XDEV_EXT_REL_MAX_WINDOW) { xs->overflow = true; xs->down_latched = true; goto changed; }
		xs->rts[xs->rts_count++] = (struct xdev_ext_xd_rts){ .msg = *m };
	} else if (xs->ns.rx && m->type == XDEV_EXT_XD_CANCEL) {
		for (k = 0; k < xs->rts_count; k++)
			if (xs->rts[k].msg.group == m->group && xs->rts[k].msg.stream == m->stream) {
				xs->rts[k].canceled = true; xs->rts[k].wake = 0; goto changed;
			}
		if (!xd_reply_group(xs, m->group) || xd_reply_group(xs, m->group)->stream != m->stream) goto out;
		if (xs->ctl_count == XD_EVENTS) { xs->overflow = true; xs->down_latched = true; goto changed; }
		xs->ctl_wake[xs->ctl_count] = xs->ctl_wait_epoch[xs->ctl_count] = 0;
		xs->ctl[xs->ctl_count++] = *m;
	} else if (!xs->ns.rx && m->type >= XDEV_EXT_XD_CTS && m->type <= XDEV_EXT_XD_FAIL) {
		for (k = 0; k < xs->ctl_count; k++)
			if (xs->ctl[k].type == m->type && xs->ctl[k].group == m->group &&
			    xs->ctl[k].credit == m->credit && xs->ctl[k].status == m->status) goto out;
		if (xs->ctl_count == XD_EVENTS) { xs->overflow = true; xs->down_latched = true; goto changed; }
		xs->ctl_wake[xs->ctl_count] = xs->ctl_wait_epoch[xs->ctl_count] = 0;
		xs->ctl[xs->ctl_count++] = *m;
	} else goto out;
 changed:
	{
		struct xdev_ext_net_slot *slot = xd_group(xs, m->group);
		if (slot) xd_group_wake(xs, slot);
	}
	xd_changed(xs);
 out:
	spin_unlock_irqrestore(&xs->ns.lock, flags);
}
static bool xd_next_locked(struct xdev_ext_xd_stage *xs, struct xdev_ext_xdomain_proto_info *i)
{
	struct xdev_ext_net_slot *s;
	struct xdev_ext_xd_reply *r;
	u64 now = ktime_get_boottime_ns();
	u32 k, ev;
	if (!xs->stop_latched && !xdev_ext_mech_session_admits(xs->ns.st->s)) {
		/* Registry retraction closes admission before generation_gone
		 * publishes STOP. Establish the core timestamp before latching it;
		 * zero is also a valid timestamp for an actual STOP at boot.
		 */
		xdev_ext_mech_stage_stop(xs->ns.st, 0);
		xs->stop_ns = xdev_ext_mech_session_stop_started_ns(xs->ns.st->s);
		xs->stop_latched = true;
		xs->epoch++;
	}
	if (xs->overflow) { xd_fail_locked(xs, -EPROTO); xd_terminal_locked(xs, -ENOLINK); return false; }
	if (xs->failed || xs->ns.dead || xs->down_latched) {
		xd_fail_locked(xs, -ENOLINK); xd_terminal_locked(xs, -ENOLINK); return false;
	}
	xd_refresh_waits(xs);
	/* A hard native/withdrawal deadline cannot depend on a cooperative policy. */
	for (k = 0; k < xs->ns.depth; k++) {
		s = &xs->ns.slots[k];
		if (s->busy && s->state != XDEV_EXT_RDV_FINAL && now >= xd_hard(xs, s) &&
		    (xd_fact(xs, s)->accepted || s->withdrawn)) {
			xd_fail_locked(xs, -ETIMEDOUT); xd_terminal_locked(xs, -ETIMEDOUT); return false;
		}
	}
	/* Deadline events precede persistent POST_RESULT/LOCAL facts. A policy
	 * WAIT on those facts must not hide withdrawal or an armed hard bound. */
	for (k = 0; k < xs->ns.depth; k++) {
		struct xdev_ext_xd_fact *f;
		s = &xs->ns.slots[(xs->cursor + k) % xs->ns.depth]; f = xd_fact(xs, s);
		if (!s->busy || f->published || f->reserved || s->local_known || s->state == XDEV_EXT_RDV_FINAL) continue;
		/* A queued refusal may borrow this ARMED slot's control admission
		 * after STOP. Do not return it before the RTS can be answered. */
		if (xs->ns.rx && xs->rts_count && now < xd_hard(xs, s)) continue;
		if (now >= xd_hard(xs, s) || xs->stop_latched ||
		    (!xs->ns.rx && s->state == XDEV_EXT_RDV_ANNOUNCED && !s->withdrawn &&
		     now >= xdev_ext_rel_deadline(f->born, XD_WITHDRAW_NS))) {
			if (now < xd_hard(xs, s) && xd_waiting(xs, f->wake, f->wait_epoch, now)) continue;
			xd_snapshot(xs, s, f->reply, xs->stop_latched ? XDEV_EXT_XDP_EV_STOP : XDEV_EXT_XDP_EV_TIMER,
				false, false, i); return true;
		}
	}
	for (k = 0; k < XD_REPLIES; k++) {
		r = &xs->replies[k];
		if (r->used && (r->cts || r->final) && r->deadline && now >= r->deadline) {
			xd_fail_locked(xs, -ETIMEDOUT); xd_terminal_locked(xs, -ETIMEDOUT); return false;
		}
	}
	while (xs->ctl_count && (xs->ctl[0].src_inc != xs->remote_inc || xs->ctl[0].dst_inc != xs->local_inc)) {
		xs->ctl_count--; memmove(xs->ctl, xs->ctl + 1, xs->ctl_count * sizeof(xs->ctl[0])); xs->epoch++;
	}
	while (xs->rts_count && (xs->rts[0].msg.src_inc != xs->remote_inc || xs->rts[0].msg.dst_inc != xs->local_inc)) {
		xs->rts_count--; memmove(xs->rts, xs->rts + 1, xs->rts_count * sizeof(xs->rts[0])); xs->epoch++;
	}
	/* Independent groups can pass a waiting control candidate. Keep the
	 * order of records for each group, and preserve the selected head token. */
	for (k = 0; k < xs->ctl_count; k++) {
		u32 n;
		bool blocked = false;
		if (xd_waiting(xs, xs->ctl_wake[k], xs->ctl_wait_epoch[k], now)) continue;
		for (n = 0; n < k; n++)
			if (xs->ctl[n].group == xs->ctl[k].group) { blocked = true; break; }
		if (blocked) continue;
		if (k) {
			struct xdev_ext_xd_msg selected = xs->ctl[k];
			u64 wake = xs->ctl_wake[k], epoch = xs->ctl_wait_epoch[k];
			memmove(xs->ctl + 1, xs->ctl, k * sizeof(xs->ctl[0]));
			memmove(xs->ctl_wake + 1, xs->ctl_wake, k * sizeof(xs->ctl_wake[0]));
			memmove(xs->ctl_wait_epoch + 1, xs->ctl_wait_epoch, k * sizeof(xs->ctl_wait_epoch[0]));
			xs->ctl[0] = selected; xs->ctl_wake[0] = wake; xs->ctl_wait_epoch[0] = epoch;
		}
		break;
	}
	if (k < xs->ctl_count) {
		struct xdev_ext_xd_msg *m = &xs->ctl[0];
		s = xd_group(xs, m->group); r = xd_reply_group(xs, m->group);
		switch (m->type) {
		case XDEV_EXT_XD_CTS: ev = s && xd_fact(xs, s)->accepted ? XDEV_EXT_XDP_EV_DUPLICATE : XDEV_EXT_XDP_EV_CTS; break;
		case XDEV_EXT_XD_ACK: ev = s && s->remote == XDEV_EXT_NET_REMOTE_ACKED ? XDEV_EXT_XDP_EV_DUPLICATE : XDEV_EXT_XDP_EV_ACK; break;
		case XDEV_EXT_XD_HELD: ev = s && xd_fact(xs, s)->published ? XDEV_EXT_XDP_EV_DUPLICATE : XDEV_EXT_XDP_EV_HELD; break;
		case XDEV_EXT_XD_FAIL: ev = s && (xd_fact(xs, s)->published || s->remote == XDEV_EXT_NET_REMOTE_FAILED) ? XDEV_EXT_XDP_EV_DUPLICATE : XDEV_EXT_XDP_EV_FAIL; break;
		case XDEV_EXT_XD_CANCEL:
			ev = r && r->native_posted ? XDEV_EXT_XDP_EV_CANCEL : XDEV_EXT_XDP_EV_DUPLICATE;
			if (r && r->native_posted) r->cts = true;
			break;
		default: ev = XDEV_EXT_XDP_EV_DUPLICATE;
		}
		/* A final remote disposition is immutable. Later CTS/HELD/ACK/FAIL
		 * records are informational; they cannot reopen its commitment. */
		if (s && !xs->ns.rx && xd_remote_final(s->remote)) ev = XDEV_EXT_XDP_EV_DUPLICATE;
		if (!s && !r) ev = XDEV_EXT_XDP_EV_DUPLICATE;
		xd_snapshot(xs, s, r, ev, false, true, i); return true;
	}
	for (k = 0; k < xs->ns.depth; k++) {
		struct xdev_ext_xd_fact *f;
		s = &xs->ns.slots[(xs->cursor + k) % xs->ns.depth]; f = xd_fact(xs, s);
		if (!s->busy || f->published || f->reserved || xd_waiting(xs, f->wake, f->wait_epoch, now)) continue;
		if (f->event) {
			xd_snapshot(xs, s, f->reply, f->event, false, false, i); return true;
		}
	}
	for (k = 0; k < XD_REPLIES; k++) {
		r = &xs->replies[k];
		if (r->used && (r->cts || r->final) && !xd_waiting(xs, r->wake, r->wait_epoch, now)) {
			if (r->deadline && now >= r->deadline) { xd_fail_locked(xs, -ETIMEDOUT); xd_terminal_locked(xs, -ETIMEDOUT); return false; }
			xd_snapshot(xs, NULL, r, r->chain_done ? XDEV_EXT_XDP_EV_CHAIN_END : XDEV_EXT_XDP_EV_REPLY_DUE, false, false, i); return true;
		}
	}
	if (xs->rts_count && !xd_waiting(xs, xs->rts[0].wake, xs->rts[0].wait_epoch, now)) {
		struct xdev_ext_xd_msg *m = &xs->rts[0].msg;
		r = xd_reply_group(xs, m->group);
		if (r && r->stream != m->stream) r = NULL;
		/* Retransmitted RTS is informational after acceptance or refusal;
		 * never pair it with a different ARMED slot. */
		if (r || (xs->ns.rx_rel_ready && m->stream == xs->stream &&
		    (m->group < xs->ns.rx_rel.base_group ||
		     (xs->ns.rx_rel.entry[m->group % xs->ns.rx_rel.cfg.window].group == m->group &&
		      xs->ns.rx_rel.entry[m->group % xs->ns.rx_rel.cfg.window].state)))) {
			if (r && r->native_posted && xs->rts[0].canceled) r->cts = true;
			s = r ? xd_group(xs, m->group) : NULL;
			xd_snapshot(xs, s, r, XDEV_EXT_XDP_EV_DUPLICATE, true, false, i); return true;
		}
		s = xd_armed(xs);
		xd_snapshot(xs, s, NULL, xs->rts[0].canceled ? XDEV_EXT_XDP_EV_CANCEL : XDEV_EXT_XDP_EV_RTS, true, false, i); return true;
	}
	for (k = 0; k < xs->ns.depth; k++) {
		s = &xs->ns.slots[(xs->cursor + k) % xs->ns.depth];
		if (!s->busy || s->state == XDEV_EXT_RDV_FINAL || xd_fact(xs, s)->reserved ||
		    xd_waiting(xs, xd_fact(xs, s)->wake, xd_fact(xs, s)->wait_epoch, now)) continue;
		xd_snapshot(xs, s, NULL, xs->stop_latched ? XDEV_EXT_XDP_EV_STOP : XDEV_EXT_XDP_EV_TIMER, false, false, i); return true;
	}
	return false;
}
static unsigned long xdev_ext_xd_class_progress(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xdomain_proto_info info;
	struct xdev_ext_xdomain_proto_result result;
	unsigned long flags;
	u32 budget = XD_EVENTS;
	int ret;
	while (budget--) {
		spin_lock_irqsave(&xs->ns.lock, flags);
		if (!xd_next_locked(xs, &info)) { spin_unlock_irqrestore(&xs->ns.lock, flags); break; }
		spin_unlock_irqrestore(&xs->ns.lock, flags);
		ret = xdev_ext_xd_protocol_call(xs, &info, &result);
		if (!ret) ret = xdev_ext_xd_apply(xs, &info, &result.verdict);
		if (xs->stage_error) {
			int err;
			spin_lock_irqsave(&xs->ns.lock, flags);
			err = xs->stage_error; xs->stage_error = 0;
			spin_unlock_irqrestore(&xs->ns.lock, flags);
			xdev_ext_mech_stage_dead(st, err);
		}
		if (ret == -ESTALE) continue;
		if (ret == -EAGAIN) {
			u64 wake = xdev_ext_rel_deadline(ktime_get_boottime_ns(), XD_TICK_NS);
			spin_lock_irqsave(&xs->ns.lock, flags);
			if (xs->worker_event.rts && xs->rts_count) {
				xs->rts[0].wake = wake; xs->rts[0].wait_epoch = xs->wait_generation;
			} else if (xs->worker_event.ctl && xs->ctl_count) {
				xs->ctl_wake[0] = wake; xs->ctl_wait_epoch[0] = xs->wait_generation;
			} else if (xs->worker_event.slot) {
				struct xdev_ext_xd_fact *f = xd_fact(xs, xs->worker_event.slot);
				f->wake = wake; f->wait_epoch = xs->wait_generation;
			} else if (xs->worker_event.reply) {
				xs->worker_event.reply->wake = wake; xs->worker_event.reply->wait_epoch = xs->wait_generation;
			}
			spin_unlock_irqrestore(&xs->ns.lock, flags);
			continue;
		}
		if (ret) { xd_policy_error(xs); break; }
	}
	{
		u64 now = ktime_get_boottime_ns(), due = xdev_ext_rel_deadline(now, XD_TICK_NS);
		u32 k;
		spin_lock_irqsave(&xs->ns.lock, flags);
		if (xs->next_wake && xs->next_wake <= now) xs->next_wake = 0;
		if (xs->next_wake && xs->next_wake < due) due = xs->next_wake;
		for (k = 0; k < xs->ns.depth; k++)
			if (xs->ns.slots[k].busy && xs->ns.slots[k].state != XDEV_EXT_RDV_FINAL &&
			    xd_hard(xs, &xs->ns.slots[k]) < due) due = xd_hard(xs, &xs->ns.slots[k]);
		spin_unlock_irqrestore(&xs->ns.lock, flags);
		return msecs_to_jiffies(due <= now ? 1 : (due - now + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC);
	}
}
static int xdev_ext_xd_class_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xd_batch *bp = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_net_slot *s;
	struct xdev_ext_xd_fact *f;
	struct xdev_ext_xdomain_proto_info info;
	struct xdev_ext_xdomain_proto_result result;
	unsigned long flags;
	int ret;
	if (xs->ns.dead || !xdev_ext_mech_session_admits(st->s)) return -ESHUTDOWN;
	s = xdev_ext_netfam_slot_get(&xs->ns, b); if (!s) return -EAGAIN;
	bp->slot = s;
	spin_lock_irqsave(&xs->ns.lock, flags);
	f = xd_fact(xs, s); *f = (struct xdev_ext_xd_fact){ .born = ktime_get_boottime_ns() };
	xd_changed(xs);
	xd_snapshot(xs, s, NULL, xs->ns.rx ? XDEV_EXT_XDP_EV_RX_SUBMIT : XDEV_EXT_XDP_EV_TX_SUBMIT, false, false, &info);
	spin_unlock_irqrestore(&xs->ns.lock, flags);
	ret = xdev_ext_xd_protocol_call(xs, &info, &result);
	if (!ret) ret = xdev_ext_xd_apply(xs, &info, &result.verdict);
	if (ret) {
		spin_lock_irqsave(&xs->ns.lock, flags);
		if (!s->group && !f->accepted && !f->reserved) { xd_reply_put(xs, f->reply); if (f->reply) f->reply->used = false; s->busy = false; bp->slot = NULL; }
		spin_unlock_irqrestore(&xs->ns.lock, flags);
		if (ret != -EAGAIN && ret != -ESTALE) xd_policy_error(xs);
		return ret == -ESTALE ? -EAGAIN : ret;
	}
	xdev_ext_mech_stage_kick(st);
	return 0;
}
static void xdev_ext_xd_class_fill_cqe(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, void *out)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xd_batch *bp = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_net_slot *s = bp->slot;
	unsigned long flags;
	*(struct xdev_ext_xdomain_mech_cqe *)out = bp->cqe;
	if (!s) return;
	spin_lock_irqsave(&xs->ns.lock, flags);
	if (!xs->ns.rx && !xd_fact(xs, s)->retired && s->local_known && s->local_quiesced) {
		struct xdev_ext_rel_tx_entry *e = xdev_ext_rel_tx_find(&xs->ns.tx, s->group);
		if (e && !e->native_pending && (s->remote == XDEV_EXT_NET_REMOTE_ACKED ||
		    s->remote == XDEV_EXT_NET_REMOTE_FAILED || s->remote == XDEV_EXT_NET_REMOTE_LOST)) {
			if (!e->terminal) xdev_ext_net_tx_abort(&xs->ns.tx, s->group);
			if (!xdev_ext_rel_tx_retire(&xs->ns.tx, s->group)) xd_fact(xs, s)->retired = true;
		}
	}
	xdev_ext_netfam_fill_cqe(&xs->ns, &bp->slot);
	xd_changed(xs);
	spin_unlock_irqrestore(&xs->ns.lock, flags);
}
static void xdev_ext_xd_class_batch_end(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, int err)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xd_cookie *ck = xdev_ext_mech_batch_cookie(b);
	unsigned long flags;
	if (!xs->ns.rx) return;
	spin_lock_irqsave(&xs->ns.lock, flags);
	if (!ck->st[st->index].ended) { ck->st[st->index].status = err; ck->st[st->index].ended = true; }
	spin_unlock_irqrestore(&xs->ns.lock, flags);
}
static void xdev_ext_xd_class_batch_release(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, bool sequestered)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xd_cookie *ck = xdev_ext_mech_batch_cookie(b);
	struct xdev_ext_xd_cookie_entry *ce = &ck->st[st->index];
	struct xdev_ext_xd_reply *r;
	unsigned long flags;
	if (!xs->ns.rx) return;
	spin_lock_irqsave(&xs->ns.lock, flags);
	if (ce->group && !ce->released && (r = xd_reply_group(xs, ce->group))) {
		ce->released = true; r->chain_done = true; r->sequestered |= sequestered;
		r->chain_status = ce->status ? ce->status : sequestered ? -ENOLINK : 0;
		r->final = r->admission || !r->closed; r->deadline = xdev_ext_rel_deadline(ktime_get_boottime_ns(), XD_PHASE_NS);
		r->wake = 0;
		xd_changed(xs);
	}
	spin_unlock_irqrestore(&xs->ns.lock, flags);
}
static void xdev_ext_xd_class_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	unsigned long flags;
	if (!xs) return;
	spin_lock_irqsave(&xs->ns.lock, flags);
	xs->ns.dead = true; xs->down_latched = true; xd_changed(xs);
	spin_unlock_irqrestore(&xs->ns.lock, flags);
}
static void xdev_ext_xd_class_transport_stats(struct xdev_ext_mech_stage *st, u32 *pending_acks, u32 *uncertain_controls)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	unsigned long flags;
	u32 k;
	*pending_acks = *uncertain_controls = 0;
	spin_lock_irqsave(&xs->ns.lock, flags);
	for (k = 0; k < xs->rts_count; k++)
		if (xs->rts[k].admission) (*pending_acks)++;
	for (k = 0; k < XD_REPLIES; k++) {
		if (xs->replies[k].admission) (*pending_acks)++;
		if (xs->replies[k].admission && xs->replies[k].sequestered) (*uncertain_controls)++;
	}
	spin_unlock_irqrestore(&xs->ns.lock, flags);
}
static int xdev_ext_xd_class_stage_diag(struct xdev_ext_mech_stage *st,
                                       struct xdev_ext_mech_stage_diag *out)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	struct xdev_ext_xd_ep *ep;
	struct xdev_ext_mech_stage_diag d = {
		.size = sizeof(d), .version = XDEV_EXT_MECH_STAGE_DIAG_VERSION,
		.session_id = xdev_ext_mech_session_id(st->s),
		.stage = st->index, .class_id = st->class_id,
	};
	unsigned long flags;
	u32 k;
	int ret;

	if (!xs || !xs->ns.lk)
		return -EOPNOTSUPP;
	ep = xdev_ext_xd_ep_of(xs);
	d.capture_begin_ns = ktime_get_boottime_ns();
	mutex_lock(&ep->xl->ctl_mutex);
	spin_lock_irqsave(&xs->ns.lock, flags);
	/* A failed attach has bound identity but no initialized protocol pair. */
	if (xs->local_inc != ep->bound_local_inc ||
	    xs->remote_inc != ep->bound_remote_inc) {
		spin_unlock_irqrestore(&xs->ns.lock, flags);
		ret = -ESTALE;
		goto unlock;
	}
	for (k = 0; k < XD_REPLIES; k++) {
		struct xdev_ext_xd_reply *r = &xs->replies[k];
		struct xdev_ext_net_slot *slot;

		if (!r->used)
			continue;
		if (r->cts)
			d.cts_owed++;
		if (r->final) {
			if (xd_reply_status(r))
				d.fail_owed++;
			else if (r->chain_done && !r->sequestered)
				d.ack_owed++;
			else
				d.final_waiting_chain++;
		}
		if (!xs->ns.rx || !r->native_posted || r->chain_done || r->sequestered)
			continue;
		slot = xd_group(xs, r->group);
		if (slot && slot->local_known && slot->local_quiesced)
			d.downstream_release_pending++;
	}
	for (k = 0; k < xs->rts_count; k++)
		if (xs->rts[k].admission)
			d.fail_owed++;
	d.valid |= XDEV_EXT_MECH_DIAG_PROTOCOL;
	spin_unlock_irqrestore(&xs->ns.lock, flags);
	d.pool_generation = xdev_ext_peer_mech_pool_generation(xdev_ext_mech_session_pool(st->s));
	ret = xdev_ext_xd_link_diag(ep, &d);
	if (!ret) {
		d.capture_end_ns = ktime_get_boottime_ns();
		*out = d;
	}
unlock:
	mutex_unlock(&ep->xl->ctl_mutex);
	return ret;
}
static bool xd_rel(struct xdev_ext_mech_stage *st, struct xdev_ext_net_rel_view *out)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	*out = (struct xdev_ext_net_rel_view){ .tx = xs->ns.rx ? NULL : &xs->ns.tx,
		.rx = xs->ns.rx && xs->ns.rx_rel_ready ? &xs->ns.rx_rel : NULL, .lock = &xs->ns.lock };
	return true;
}
static const struct xdev_ext_net_hooks xd_hooks = {
	.hdr = { .family = XDEV_EXT_FAMILY_NETWORK }, .hdr_policy = XDEV_EXT_NET_HDR_CHANNEL, .rel = xd_rel,
};
static int xdev_ext_xd_class_bind(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_stage_uapi *u)
{
	struct xdev_ext_xd_stage *xs;
	struct xdev_ext_xd_ep *ep;
	const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
	struct xdev_ext_rel_cfg cfg;
	u32 depth = xdev_ext_mech_session_depth(st->s), elems = xdev_ext_xd_layout_elems(l);
	unsigned long flags;
	int ret;
	if (xdev_ext_mech_session_pool(st->s)->kind != XDEV_EXT_MECH_POOL_PEER ||
	    (st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE && st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE)) return -EOPNOTSUPP;
	if (st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE && st->index) return -EOPNOTSUPP;
	if (!xdev_ext_peer_control_file(st->file) || !u->arg0 || u->arg1 >= XDEV_EXT_XD_CHANNELS_V1 ||
	    (u->flags & ~XDEV_EXT_XDOMAIN_KNOWN_FLAGS) || !xdev_ext_xd_budget_ok(depth, elems, XDEV_EXT_XD_DATA_RING)) return -EINVAL;
	xs = kzalloc(sizeof(*xs), GFP_KERNEL); if (!xs) return -ENOMEM;
	xs->channel = u->arg1;
	xs->stream = st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE ? 0 : xdev_ext_mech_session_id(st->s);
	xs->facts = kvcalloc(depth, sizeof(*xs->facts), GFP_KERNEL);
	if (!xs->facts) { kfree(xs); return -ENOMEM; }
	ret = xdev_ext_netfam_init(&xs->ns, st, &xd_member, st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE, 0);
	if (ret) goto free;
	st->priv = xs;
	ret = xdev_ext_netfam_attach(&xs->ns, u, u->flags & XDEV_EXT_XDOMAIN_F_ALLOW_UNVERIFIED ? XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED : 0);
	if (xs->ns.lk) {
		struct pci_dev *pdev = xs->ns.m->dev->requester(xs->ns.lk);
		dev_dbg(&pdev->dev, "XDEV_EXT_XDOMAIN_ADMIT session=%llu stage=%u requester=%s errno=%d reachability=%u distance=%d backing=0x%x refused=0x%x mapped=%u\n",
			(unsigned long long)xdev_ext_mech_session_id(st->s), st->index, pci_name(pdev), ret,
			xs->ns.rq.adm.reachability, xs->ns.rq.adm.distance, xs->ns.rq.adm.backing, xs->ns.rq.adm.refused, xs->ns.admitted);
	}
	if (xs->ns.lk) {
		ep = xdev_ext_xd_ep_of(xs);
		spin_lock_irqsave(&xs->ns.lock, flags);
		xs->local_inc = ep->bound_local_inc;
		xs->remote_inc = ep->bound_remote_inc;
		spin_unlock_irqrestore(&xs->ns.lock, flags);
	}
	if (ret) goto fini;
	cfg = (struct xdev_ext_rel_cfg){ .session = xs->stream ? xs->stream : 1, .first_group = 1,
		.window = XDEV_EXT_REL_MAX_WINDOW, .max_attempts = 1, .timeout_ns = XD_PHASE_NS,
		.group_bytes = l->group_bytes, .seg_len = l->seg_len };
	ret = xdev_ext_rel_tx_init(&xs->ns.tx, &cfg);
	if (ret) goto fini;
	return 0;
 fini:
	if (st->create_reporting && xs->ns.lk &&
	    !xdev_ext_xd_class_stage_diag(st, &st->create_observed)) {
		st->create_observed.session_id = 0;
		st->create_valid |= XDEV_EXT_MECH_CREATE_VALID_OBSERVED;
	}
	xdev_ext_netfam_fini(&xs->ns); st->priv = NULL;
 free:
	kvfree(xs->facts); kfree(xs); return ret;
}
static void xdev_ext_xd_class_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_xd_stage *xs = st->priv;
	xdev_ext_netfam_fini(&xs->ns); st->priv = NULL; kvfree(xs->facts); kfree(xs);
}
static const struct xdev_ext_mech_class_ops xdev_ext_xd_class = {
	.stage_diag = xdev_ext_xd_class_stage_diag,
	.class_id = XDEV_EXT_MECH_CLASS_XDOMAIN, .flags = XDEV_EXT_MECH_CLASS_F_ORDERED,
	.desc_size = sizeof(struct xdev_ext_xdomain_desc), .desc_cap = XDEV_EXT_MECH_MAX_FRAMES,
	.info_size = sizeof(struct xdev_ext_xdomain_mech_info), .cqe_size = sizeof(struct xdev_ext_xdomain_mech_cqe), .cqe_cap = 1,
	.batch_priv_size = sizeof(struct xdev_ext_xd_batch), .batch_cookie_size = sizeof(struct xdev_ext_xd_cookie), .owner = THIS_MODULE,
	.bind = xdev_ext_xd_class_bind, .unbind = xdev_ext_xd_class_unbind, .fill_info = xdev_ext_xd_class_fill_info,
	.default_build = xdev_ext_xd_class_default_build, .validate = xdev_ext_xd_class_validate, .submit = xdev_ext_xd_class_submit,
	.fill_cqe = xdev_ext_xd_class_fill_cqe, .mark_dead = xdev_ext_xd_class_mark_dead,
	.batch_end = xdev_ext_xd_class_batch_end, .batch_release = xdev_ext_xd_class_batch_release,
	.progress = xdev_ext_xd_class_progress, .transport_stats = xdev_ext_xd_class_transport_stats, .fam.net = &xd_hooks,
};
int xdev_ext_xd_class_register(void) { return xdev_ext_mech_class_register(&xdev_ext_xd_class); }
void xdev_ext_xd_class_unregister(void) { xdev_ext_mech_class_unregister(&xdev_ext_xd_class); }

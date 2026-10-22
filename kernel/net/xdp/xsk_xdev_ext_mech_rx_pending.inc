/* SPDX-License-Identifier: GPL-2.0 */
/* Legacy datagrams have no remote credit. Retain validated HOLD intents in
 * registered NIC_RX custody until an actual depth-bounded batch is available.
 * A FIFO reservation is admission, not READY publication or native execution.
 */
/* Before BPF parses/rejects a newly delivered packet, protect a previous
 * queue owner if a broken driver delivers the same native frame twice.
 */
static bool xsk_rx_pending_owned(struct xdev_ext_mech_stage *st, u32 index)
{
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	struct xsk_mech_rx_pending *q = &xst->pending;
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	unsigned long flags;
	bool owned;

	if (!q->entries || index >= pool->nr_frames)
		return false;
	spin_lock_irqsave(&q->lock, flags);
	owned = q->entries[index].queued;
	spin_unlock_irqrestore(&q->lock, flags);
	return owned;
}

static int xsk_rx_pending_add(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_hold_intent *hold,
		const struct xdev_ext_mech_frame *f)
{
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	struct xsk_mech_rx_pending *q = &xst->pending;
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	struct xsk_mech_rx_pending_entry *e;
	unsigned long flags;
	u32 state;
	int err = 0;

	spin_lock_irqsave(&q->lock, flags);
	if (!xdev_ext_mech_session_admits(st->s)) {
		err = -ESHUTDOWN;
		goto unlock;
	}
	if (f->index >= pool->nr_frames) {
		err = -ERANGE;
		goto unlock;
	}
	e = &q->entries[f->index];
	if (e->queued) {
		err = -EALREADY;
		goto unlock;
	}
	if (q->count == q->capacity) {
		err = -EOVERFLOW;
		goto unlock;
	}
	state = xdev_ext_mech_pool_frame_state(pool, f->index);
	if (state != XDEV_EXT_MECH_F_NIC_RX) {
		if ((state != XDEV_EXT_MECH_F_USER && state != XDEV_EXT_MECH_F_K_FREE) ||
		    xdev_ext_mech_pool_frame_move(pool, f->index, state,
					 XDEV_EXT_MECH_F_NIC_RX)) {
			err = -EPROTO;
			goto unlock;
		}
	}
	*e = (struct xsk_mech_rx_pending_entry) {
		.hold = *hold, .data_off = f->data_off, .data_len = f->data_len,
		.queued = true,
	};
	if (q->count)
		q->entries[q->tail].next = f->index;
	else
		q->head = f->index;
	q->tail = f->index;
	q->count++;
unlock:
	spin_unlock_irqrestore(&q->lock, flags);
	if (err == -EALREADY || err == -EPROTO || err == -EOVERFLOW)
		xdev_ext_mech_stage_dead(st, err == -EALREADY ? -EPROTO : err);
	if (!err)
		xdev_ext_mech_stage_kick(st);
	return err;
}

/* Worker, or final unbind after synchronize_net(). Keep native depth/CE slots
 * unchanged. Never save a temporary xdp_buff pointer in the pending queue.
 * The queue lock serializes the sole owner of each retained NIC_RX frame;
 * hold_commit serializes batches with s->lock and claims custody atomically.
 * resolve only reconstructs an address in the pinned pool (no allocator or
 * RX ring access). In particular this worker must not acquire pool->rx_lock:
 * receive may already hold that lock when it acquires the pending lock.
 */
static unsigned long xsk_rx_pending_drain(struct xdev_ext_mech_stage *st, bool stopping)
{
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	struct xsk_mech_rx_pending *q = &xst->pending;
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	unsigned long flags;
	u32 budget = 64;
	bool pending;

	if (!q->entries)
		return 0;
	while (stopping || budget--) {
		struct xsk_mech_rx_pending_entry *e;
		struct xdev_ext_mech_frame f;
		bool cancel;
		int err;

		spin_lock_irqsave(&q->lock, flags);
		if (!q->count) {
			spin_unlock_irqrestore(&q->lock, flags);
			break;
		}
		e = &q->entries[q->head];
		f = (struct xdev_ext_mech_frame) {
			.index = q->head, .data_off = e->data_off, .data_len = e->data_len,
		};
		cancel = stopping || !xdev_ext_mech_session_admits(st->s);
		err = xsk_xdev_ext_mech_pool_resolve(pool, &f);
		if (!err && xdev_ext_mech_pool_frame_state(pool, f.index) !=
		    XDEV_EXT_MECH_F_NIC_RX)
			err = -EPROTO;
		if (!err && !cancel)
			err = xdev_ext_mech_hold_commit(st, &e->hold, &f);
		/* STOP can win between the snapshot and core admission. No
		 * native request accepted this pending frame: cancel locally.
		 */
		if (err == -ESHUTDOWN && !xdev_ext_mech_session_admits(st->s)) {
			cancel = true;
			err = 0;
		}
		if (err == -EAGAIN || err == -ENOSPC) {
			spin_unlock_irqrestore(&q->lock, flags);
			break;
		}
		q->head = e->next;
		e->queued = false;
		q->count--;
		if ((cancel || err) &&
		    xdev_ext_mech_pool_frame_state(pool, f.index) == XDEV_EXT_MECH_F_NIC_RX)
			xdev_ext_mech_frame_recycle(st->s, &f);
		spin_unlock_irqrestore(&q->lock, flags);
		if (err)
			xdev_ext_mech_stage_dead(st, err);
	}
	spin_lock_irqsave(&q->lock, flags);
	pending = q->count != 0;
	spin_unlock_irqrestore(&q->lock, flags);
	return pending ? 1 : 0;
}

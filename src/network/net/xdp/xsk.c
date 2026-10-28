// SPDX-License-Identifier: GPL-2.0
/* XDP sockets
 *
 * AF_XDP sockets allows a channel between XDP programs and userspace
 * applications.
 * Copyright(c) 2018 Intel Corporation.
 *
 * Author(s): Björn Töpel <bjorn.topel@intel.com>
 *	      Magnus Karlsson <magnus.karlsson@intel.com>
 */

#define pr_fmt(fmt) "AF_XDP: %s: " fmt, __func__

#include <linux/if_xdp.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/vmalloc.h>
#include <net/xdp_sock_drv.h>
#include <net/busy_poll.h>
#include <net/netdev_lock.h>
#include <net/netdev_rx_queue.h>
#include <net/xdp.h>

#include "xsk_queue.h"
#include "xdp_umem.h"
#include "xsk.h"
#include "xsk_xdev_ext.h"
#include "xsk_xdev_ext_mech.h"

#define TX_BATCH_SIZE 32
#define MAX_PER_SOCKET_BUDGET (TX_BATCH_SIZE)

void xsk_set_rx_need_wakeup(struct xsk_buff_pool *pool)
{
	if (pool->cached_need_wakeup & XDP_WAKEUP_RX)
		return;

	pool->fq->ring->flags |= XDP_RING_NEED_WAKEUP;
	pool->cached_need_wakeup |= XDP_WAKEUP_RX;
}
EXPORT_SYMBOL(xsk_set_rx_need_wakeup);

void xsk_set_tx_need_wakeup(struct xsk_buff_pool *pool)
{
	struct xdp_sock *xs;

	if (pool->cached_need_wakeup & XDP_WAKEUP_TX)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		xs->tx->ring->flags |= XDP_RING_NEED_WAKEUP;
	}
	rcu_read_unlock();

	pool->cached_need_wakeup |= XDP_WAKEUP_TX;
}
EXPORT_SYMBOL(xsk_set_tx_need_wakeup);

void xsk_clear_rx_need_wakeup(struct xsk_buff_pool *pool)
{
	if (!(pool->cached_need_wakeup & XDP_WAKEUP_RX))
		return;

	pool->fq->ring->flags &= ~XDP_RING_NEED_WAKEUP;
	pool->cached_need_wakeup &= ~XDP_WAKEUP_RX;
}
EXPORT_SYMBOL(xsk_clear_rx_need_wakeup);

void xsk_clear_tx_need_wakeup(struct xsk_buff_pool *pool)
{
	struct xdp_sock *xs;

	if (!(pool->cached_need_wakeup & XDP_WAKEUP_TX))
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		xs->tx->ring->flags &= ~XDP_RING_NEED_WAKEUP;
	}
	rcu_read_unlock();

	pool->cached_need_wakeup &= ~XDP_WAKEUP_TX;
}
EXPORT_SYMBOL(xsk_clear_tx_need_wakeup);

bool xsk_uses_need_wakeup(struct xsk_buff_pool *pool)
{
	return pool->uses_need_wakeup;
}
EXPORT_SYMBOL(xsk_uses_need_wakeup);

struct xsk_buff_pool *xsk_get_pool_from_qid(struct net_device *dev,
					    u16 queue_id)
{
	if (queue_id < dev->real_num_rx_queues)
		return dev->_rx[queue_id].pool;
	if (queue_id < dev->real_num_tx_queues)
		return dev->_tx[queue_id].pool;

	return NULL;
}
EXPORT_SYMBOL(xsk_get_pool_from_qid);

void xsk_clear_pool_at_qid(struct net_device *dev, u16 queue_id)
{
	if (queue_id < dev->num_rx_queues)
		dev->_rx[queue_id].pool = NULL;
	if (queue_id < dev->num_tx_queues)
		dev->_tx[queue_id].pool = NULL;
}

/* The buffer pool is stored both in the _rx struct and the _tx struct as we do
 * not know if the device has more tx queues than rx, or the opposite.
 * This might also change during run time.
 */
int xsk_reg_pool_at_qid(struct net_device *dev, struct xsk_buff_pool *pool,
			u16 queue_id)
{
	if (queue_id >= max_t(unsigned int,
			      dev->real_num_rx_queues,
			      dev->real_num_tx_queues))
		return -EINVAL;

	if (queue_id < dev->real_num_rx_queues)
		dev->_rx[queue_id].pool = pool;
	if (queue_id < dev->real_num_tx_queues)
		dev->_tx[queue_id].pool = pool;

	return 0;
}

static int __xsk_rcv_zc_reserve(struct xdp_sock *xs,
				struct xdp_buff_xsk *xskb, u32 len,
				u32 flags)
{
	u64 addr;
	int err;

	addr = xp_get_handle(xskb, xskb->pool);
	err = xskq_prod_reserve_desc(xs->rx, addr, len, flags);
	if (err) {
		xs->rx_queue_full++;
		return err;
	}

	return 0;
}

static int xsk_rcv_zc(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len,
		      struct xsk_xdev_ext_rx_cookie *xdev_ext_cookie)
{
	struct xdp_buff_xsk *xskb = container_of(xdp, struct xdp_buff_xsk, xdp);
	u32 frags = xdp_buff_has_frags(xdp);
	struct xdp_buff_xsk *pos, *tmp;
	struct list_head *xskb_list;
	u32 reserved = 0;
	u32 contd = 0;
	int err;

	if (!frags && xsk_xdev_ext_mech_rx_session(xs)) {
		int disposition;

		/* Native ZC: NIC already DMA'd into this exact UMEM frame. */
		spin_lock_bh(&xs->pool->rx_lock);
		disposition = xsk_xdev_ext_mech_rx(xs, xskb, len, XDEV_EXT_MECH_SITE_RX_NATIVE);
		spin_unlock_bh(&xs->pool->rx_lock);
		if (disposition != XDEV_EXT_MECH_PUBLISH)
			return 0; /* HOLD/RECYCLE stays entirely in the kernel. */
	}
	if (frags)
		contd = XDP_PKT_CONTD;

	err = __xsk_rcv_zc_reserve(xs, xskb, len, contd);
	if (err)
		goto err;
	reserved++;
	if (xdev_ext_cookie) {
		err = xsk_xdev_ext_rx_core_note_reservation(&xdev_ext_cookie->core);
		if (err)
			goto err;
	}
	if (likely(!frags)) {
		if (xdev_ext_cookie) {
			err = xsk_xdev_ext_rx_core_reservations_complete(&xdev_ext_cookie->core);
			if (err)
				goto err;
		}
		xsk_xdev_ext_mech_rx_settle(xs, xskb, true);
		xp_release(xskb);
		return 0;
	}

	xskb_list = &xskb->pool->xskb_list;
	list_for_each_entry_safe(pos, tmp, xskb_list, list_node) {
		if (list_is_last(&pos->list_node, xskb_list))
			contd = 0;
		len = pos->xdp.data_end - pos->xdp.data;
		err = __xsk_rcv_zc_reserve(xs, pos, len, contd);
		if (err)
			goto err;
		reserved++;
		if (xdev_ext_cookie) {
			err = xsk_xdev_ext_rx_core_note_reservation(&xdev_ext_cookie->core);
			if (err)
				goto err;
		}
	}
	if (xdev_ext_cookie) {
		err = xsk_xdev_ext_rx_core_reservations_complete(&xdev_ext_cookie->core);
		if (err)
			goto err;
	}

	xsk_xdev_ext_mech_rx_settle(xs, xskb, true);
	xp_release(xskb);
	list_for_each_entry_safe(pos, tmp, xskb_list, list_node) {
		list_del(&pos->list_node);
		xsk_xdev_ext_mech_rx_settle(xs, pos, true);
		xp_release(pos);
	}
	return 0;
err:
	if (reserved)
		xskq_prod_cancel_n(xs->rx, reserved);
	xsk_buff_free(xdp);
	return err;
}

static void *xsk_copy_xdp_start(struct xdp_buff *from)
{
	if (unlikely(xdp_data_meta_unsupported(from)))
		return from->data;
	else
		return from->data_meta;
}

static u32 xsk_copy_xdp(void *to, void **from, u32 to_len,
			u32 *from_len, skb_frag_t **frag, u32 rem)
{
	u32 copied = 0;

	while (1) {
		u32 copy_len = min_t(u32, *from_len, to_len);

		memcpy(to, *from, copy_len);
		copied += copy_len;
		if (rem == copied)
			return copied;

		if (*from_len == copy_len) {
			*from = skb_frag_address(*frag);
			*from_len = skb_frag_size((*frag)++);
		} else {
			*from += copy_len;
			*from_len -= copy_len;
		}
		if (to_len == copy_len)
			return copied;

		to_len -= copy_len;
		to += copy_len;
	}
}

/*
 * @callsite is XDEV_EXT_MECH_SITE_RX_GENERIC (pool->rx_lock held) or
 * XDEV_EXT_MECH_SITE_RX_NATIVE (driver NAPI, no lock).
 */
static int __xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len,
		     struct xsk_xdev_ext_rx_cookie *xdev_ext_cookie, u32 callsite)
{
	u32 frame_size = xsk_pool_get_rx_frame_size(xs->pool);
	void *copy_from = xsk_copy_xdp_start(xdp), *copy_to;
	u32 from_len, meta_len, rem, num_desc;
	LIST_HEAD(allocated_xskbs);
	struct xdp_buff_xsk *pos, *tmp;
	struct xdp_buff_xsk *xskb;
	struct xdp_buff *xsk_xdp;
	skb_frag_t *frag;
	u32 reserved = 0;
	int err;

	from_len = xdp->data_end - copy_from;
	meta_len = xdp->data - copy_from;
	rem = len + meta_len;

	if (len <= frame_size && !xdp_buff_has_frags(xdp)) {
		xsk_xdp = xsk_buff_alloc(xs->pool);
		if (!xsk_xdp) {
			xs->rx_dropped++;
			return -ENOMEM;
		}
		memcpy(xsk_xdp->data - meta_len, copy_from, rem);
		xskb = container_of(xsk_xdp, struct xdp_buff_xsk, xdp);
		/* A mechanism session runs its AF_XDP complete on the frame: a
		 * held frame waits in a batch and a recycled one is back in the
		 * kernel partition; neither gets an RX descriptor.
		 */
		if (xsk_xdev_ext_mech_rx_session(xs) &&
		    xsk_xdev_ext_mech_rx(xs, xskb, len, callsite) != XDEV_EXT_MECH_PUBLISH)
			return 0;
		err = __xsk_rcv_zc_reserve(xs, xskb, len, 0);
		if (err) {
			xsk_xdev_ext_mech_rx_settle(xs, xskb, false);
			xsk_buff_free(xsk_xdp);
			return err;
		}
		if (xdev_ext_cookie) {
			err = xsk_xdev_ext_rx_core_note_reservation(&xdev_ext_cookie->core);
			if (!err)
				err = xsk_xdev_ext_rx_core_reservations_complete(&xdev_ext_cookie->core);
			if (err) {
				xskq_prod_cancel_n(xs->rx, 1);
				xsk_xdev_ext_mech_rx_settle(xs, xskb, false);
				xsk_buff_free(xsk_xdp);
				return err;
			}
		}
		xsk_xdev_ext_mech_rx_settle(xs, xskb, true);
		xp_release(xskb);

		return 0;
	}

	num_desc = (len - 1) / frame_size + 1;

	if (!xsk_buff_can_alloc(xs->pool, num_desc)) {
		xs->rx_dropped++;
		return -ENOMEM;
	}
	if (xskq_prod_nb_free(xs->rx, num_desc) < num_desc) {
		xs->rx_queue_full++;
		return -ENOBUFS;
	}

	if (xdp_buff_has_frags(xdp)) {
		struct skb_shared_info *sinfo;

		sinfo = xdp_get_shared_info_from_buff(xdp);
		frag =  &sinfo->frags[0];
	}

	do {
		u32 to_len = frame_size + meta_len;
		u32 copied;

		xsk_xdp = xsk_buff_alloc(xs->pool);
		if (unlikely(!xsk_xdp)) {
			xs->rx_dropped++;
			err = -ENOMEM;
			goto rollback;
		}
		xskb = container_of(xsk_xdp, struct xdp_buff_xsk, xdp);
		list_add_tail(&xskb->list_node, &allocated_xskbs);
		copy_to = xsk_xdp->data - meta_len;

		copied = xsk_copy_xdp(copy_to, &copy_from, to_len, &from_len, &frag, rem);
		rem -= copied;

		err = __xsk_rcv_zc_reserve(xs, xskb, copied - meta_len,
					   rem ? XDP_PKT_CONTD : 0);
		if (unlikely(err))
			goto rollback;
		reserved++;
		if (xdev_ext_cookie) {
			err = xsk_xdev_ext_rx_core_note_reservation(&xdev_ext_cookie->core);
			if (unlikely(err))
				goto rollback;
		}
		meta_len = 0;
	} while (rem);
	if (xdev_ext_cookie) {
		err = xsk_xdev_ext_rx_core_reservations_complete(&xdev_ext_cookie->core);
		if (unlikely(err))
			goto rollback;
	}
	list_for_each_entry_safe(pos, tmp, &allocated_xskbs, list_node) {
		list_del_init(&pos->list_node);
		xsk_xdev_ext_mech_rx_settle(xs, pos, true);
		xp_release(pos);
	}

	return 0;

rollback:
	if (reserved)
		xskq_prod_cancel_n(xs->rx, reserved);
	list_for_each_entry_safe(pos, tmp, &allocated_xskbs, list_node) {
		list_del_init(&pos->list_node);
		xsk_xdev_ext_mech_rx_settle(xs, pos, false);
		xp_free(pos);
	}
	return err;
}

static bool xsk_tx_writeable(struct xdp_sock *xs)
{
	if (xskq_cons_present_entries(xs->tx) > xs->tx->nentries / 2)
		return false;

	return true;
}

static bool xsk_is_bound(struct xdp_sock *xs)
{
	if (READ_ONCE(xs->state) == XSK_BOUND) {
		/* Matches smp_wmb() in bind(). */
		smp_rmb();
		return true;
	}
	return false;
}

static int xsk_rcv_check(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len)
{
	if (!xsk_is_bound(xs))
		return -ENXIO;

	if (xs->dev != xdp->rxq->dev || xs->queue_id != xdp->rxq->queue_index)
		return -EINVAL;

	if (len > xsk_pool_get_rx_frame_size(xs->pool) && !xs->sg) {
		xs->rx_dropped++;
		return -ENOSPC;
	}

	return 0;
}

/*
 * A mechanism session socket runs its AF_XDP complete in __xsk_rcv()
 * instead of the RX policy dispatch and publish hooks.
 */
static enum xsk_xdev_ext_rx_disposition
xsk_rx_dispatch(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len,
		u32 nr_descs, bool zero_copy, struct xsk_xdev_ext_rx_cookie *cookie)
{
	if (xsk_xdev_ext_mech_rx_session(xs)) {
		xsk_xdev_ext_rx_core_init(&cookie->core);
		return XSK_XDEV_EXT_RX_C_FALLBACK;
	}
	return xsk_xdev_ext_rx_dispatch(xs->pool, xs, xdp, len, nr_descs,
				   zero_copy, cookie);
}

static void xsk_flush(struct xdp_sock *xs)
{
	u32 published = xsk_xdev_ext_mech_rx_session(xs) ?
		xs->rx->cached_prod - READ_ONCE(xs->rx->ring->producer) : 0;

	xskq_prod_submit(xs->rx);
	/* The eventfd wake must follow the RX ring's release publication. */
	if (published)
		xsk_xdev_ext_mech_rx_published(xs, published);
	__xskq_cons_release(xs->pool->fq);
	sock_def_readable(&xs->sk);
}

int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	u32 len = xdp_get_buff_len(xdp);
	u32 frame_size, nr_descs;
	struct xsk_xdev_ext_rx_cookie xdev_ext_cookie;
	struct xsk_xdev_ext_rx_cookie *tracked_cookie;
	enum xsk_xdev_ext_rx_disposition disposition;
	int err;

	err = xsk_rcv_check(xs, xdp, len);
	if (!err) {
		frame_size = xsk_pool_get_rx_frame_size(xs->pool);
		nr_descs = DIV_ROUND_UP(len, frame_size);
		disposition = xsk_rx_dispatch(xs, xdp, len, nr_descs, false,
					      &xdev_ext_cookie);
		if (disposition == XSK_XDEV_EXT_RX_TERMINAL)
			return 0;
		tracked_cookie = disposition == XSK_XDEV_EXT_RX_TRACKED ?
				 &xdev_ext_cookie : NULL;
		spin_lock_bh(&xs->pool->rx_lock);
		err = __xsk_rcv(xs, xdp, len, tracked_cookie,
				XDEV_EXT_MECH_SITE_RX_GENERIC);
		if (err) {
			xsk_xdev_ext_rx_abort(&xdev_ext_cookie);
			xsk_flush(xs);
		} else if (disposition == XSK_XDEV_EXT_RX_TRACKED) {
			if (!xsk_xdev_ext_rx_publish(xs, &xdev_ext_cookie))
				xsk_flush(xs);
		} else {
			xsk_flush(xs);
		}
		spin_unlock_bh(&xs->pool->rx_lock);
	}

	return err;
}

static int xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp, bool *flushed)
{
	u32 len = xdp_get_buff_len(xdp);
	u32 nr_descs;
	struct xsk_xdev_ext_rx_cookie xdev_ext_cookie;
	struct xsk_xdev_ext_rx_cookie *tracked_cookie;
	enum xsk_xdev_ext_rx_disposition disposition;
	bool zero_copy;
	int err;

	*flushed = false;
	err = xsk_rcv_check(xs, xdp, len);
	if (err)
		return err;

	zero_copy = xdp->rxq->mem.type == MEM_TYPE_XSK_BUFF_POOL;
	if (zero_copy) {
		nr_descs = 1;
		if (xdp_buff_has_frags(xdp))
			nr_descs += xdp_get_shared_info_from_buff(xdp)->nr_frags;
	} else {
		nr_descs = DIV_ROUND_UP(len,
					xsk_pool_get_rx_frame_size(xs->pool));
	}
	disposition = xsk_rx_dispatch(xs, xdp, len, nr_descs, zero_copy,
				      &xdev_ext_cookie);
	if (disposition == XSK_XDEV_EXT_RX_TERMINAL) {
		if (zero_copy) {
			xsk_buff_free(xdp);
			__xskq_cons_release(xs->pool->fq);
		} else {
			xdp_return_buff(xdp);
		}
		*flushed = true;
		return 0;
	}
	tracked_cookie = disposition == XSK_XDEV_EXT_RX_TRACKED ? &xdev_ext_cookie : NULL;

	if (zero_copy) {
		u32 head_len = xdp->data_end - xdp->data;

		err = xsk_rcv_zc(xs, xdp, head_len, tracked_cookie);
	} else {
		spin_lock_bh(&xs->pool->rx_lock);
		err = __xsk_rcv(xs, xdp, len, tracked_cookie,
				XDEV_EXT_MECH_SITE_RX_NATIVE);
		spin_unlock_bh(&xs->pool->rx_lock);
		if (!err)
			xdp_return_buff(xdp);
	}

	if (err) {
		xsk_xdev_ext_rx_abort(&xdev_ext_cookie);
		return err;
	}
	if (disposition == XSK_XDEV_EXT_RX_TRACKED)
		*flushed = xsk_xdev_ext_rx_publish(xs, &xdev_ext_cookie);
	return err;
}

int __xsk_map_redirect(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	bool flushed;
	int err;

	err = xsk_rcv(xs, xdp, &flushed);
	if (err)
		return err;

	if (!flushed && !xs->flush_node.prev) {
		struct list_head *flush_list = bpf_net_ctx_get_xskmap_flush_list();

		list_add(&xs->flush_node, flush_list);
	}

	return 0;
}

void __xsk_map_flush(struct list_head *flush_list)
{
	struct xdp_sock *xs, *tmp;

	list_for_each_entry_safe(xs, tmp, flush_list, flush_node) {
		xsk_flush(xs);
		__list_del_clearprev(&xs->flush_node);
	}
}

static int xsk_cq_reserve_addr_locked(struct xsk_buff_pool *pool, u64 addr)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&pool->cq_lock, flags);
	ret = xsk_xdev_ext_mech_tx_active(pool) ? -ENOSPC :
		xskq_prod_reserve_addr(pool->cq, addr);
	spin_unlock_irqrestore(&pool->cq_lock, flags);

	return ret;
}

static void xsk_cq_submit_locked(struct xsk_buff_pool *pool, u32 n)
{
	unsigned long flags;

	spin_lock_irqsave(&pool->cq_lock, flags);
	xskq_prod_submit_n(pool->cq, n);
	spin_unlock_irqrestore(&pool->cq_lock, flags);
}

static void xsk_cq_cancel_locked(struct xsk_buff_pool *pool, u32 n)
{
	unsigned long flags;

	spin_lock_irqsave(&pool->cq_lock, flags);
	xskq_prod_cancel_n(pool->cq, n);
	spin_unlock_irqrestore(&pool->cq_lock, flags);
}

#ifdef CONFIG_XDEV_EXT_MECH
#include <trace/events/xdev_ext.h>
/* Lock gives descriptor events a per-pool total sequence, across all CPUs.
 * Fresh pools must be created with tracing enabled: an unobserved prefix
 * deliberately produces underflow and makes a capture unavailable.
 */
static void xsk_native_trace_event(struct xsk_buff_pool *pool, const char *phase,
				   struct xdev_ext_trace_entry *e, u32 n, int status)
{
	xdev_ext_native_event_emit(phase, xsk_xdev_ext_mech_tx_active(pool) ? "K" : "U",
		0, 0, 0, 0, 0, 0, 0, XDEV_EXT_MECH_CLASS_AFXDP,
		!status, status, (u64)(unsigned long)pool, e ? e->address : 0,
		e ? e->bytes : 0, n, e ? e->sequence : pool->native_trace.sequence, 0, 0, 0);
}

static void xsk_native_trace_submit(struct xsk_buff_pool *pool,
				    const struct xdp_desc *descs, u32 n)
{
	struct xdev_ext_trace_entry e;
	unsigned long flags;
	u32 i;
	int ret;

	if (!trace_native_event_enabled() || !n)
		return;
	spin_lock_irqsave(&pool->native_trace_lock, flags);
	for (i = 0; i < n; i++) {
		ret = xdev_ext_trace_push(&pool->native_trace,
				descs[i].addr, descs[i].len, &e);
		if (ret) {
			xsk_native_trace_event(pool, "trace_invalid", NULL, n, ret);
			break;
		}
		xsk_native_trace_event(pool, "native_submit", &e, n, 0);
	}
	spin_unlock_irqrestore(&pool->native_trace_lock, flags);
}

/* n counts descriptors, including multiple frames of one logical record. */
static void xsk_native_trace_complete(struct xsk_buff_pool *pool, u32 n)
{
	struct xdev_ext_trace_entry e;
	unsigned long flags;
	u32 i;

	if (!trace_native_event_enabled() || !n)
		return;
	spin_lock_irqsave(&pool->native_trace_lock, flags);
	if (n > pool->native_trace.count) {
		xsk_native_trace_event(pool, "trace_invalid", NULL, n, -ENODATA);
		goto out;
	}
	for (i = 0; i < n; i++) {
		xdev_ext_trace_pop(&pool->native_trace, &e);
		xsk_native_trace_event(pool, "native_complete", &e, n, e.status);
	}
out:
	spin_unlock_irqrestore(&pool->native_trace_lock, flags);
}

static void xsk_native_trace_tail(struct xsk_buff_pool *pool, u32 n,
				  int status, bool cancel)
{
	struct xdev_ext_trace_journal *j = &pool->native_trace;
	unsigned long flags;
	int ret;

	if (!trace_native_event_enabled() || !n)
		return;
	spin_lock_irqsave(&pool->native_trace_lock, flags);
	ret = xdev_ext_trace_tail(j, n, status ?: -ECANCELED);
	/* Native tail cancellation is not a successful completion. */
	xsk_native_trace_event(pool, "trace_invalid", NULL, n, ret ?: status ?: -ECANCELED);
	if (!ret && cancel)
		j->count -= n;
	spin_unlock_irqrestore(&pool->native_trace_lock, flags);
}
#else
static inline void xsk_native_trace_submit(struct xsk_buff_pool *pool,
					 const struct xdp_desc *descs, u32 n) {}
static inline void xsk_native_trace_complete(struct xsk_buff_pool *pool, u32 n) {}
static inline void xsk_native_trace_tail(struct xsk_buff_pool *pool, u32 n,
				       int status, bool cancel) {}
#endif

void xsk_tx_completed(struct xsk_buff_pool *pool, u32 nb_entries)
{
	int ret;

	xsk_native_trace_complete(pool, nb_entries);
	ret = xsk_xdev_ext_mech_tx_complete(pool, nb_entries, 0, false, false);

	if (ret != -EOPNOTSUPP)
		return;
	ret = xsk_xdev_ext_zc_tx_completed(pool, nb_entries);

	if (ret != -EOPNOTSUPP)
		return;
	xsk_cq_submit_locked(pool, nb_entries);
}
EXPORT_SYMBOL(xsk_tx_completed);

void xsk_tx_cancel_tail(struct xsk_buff_pool *pool, u32 nb_entries,
			int result)
{
	int ret;

	xsk_native_trace_tail(pool, nb_entries, result, true);
	ret = xsk_xdev_ext_mech_tx_complete(pool, nb_entries, result, true, false);

	if (ret != -EOPNOTSUPP)
		return;
	ret = xsk_xdev_ext_zc_tx_cancel_tail(pool, nb_entries, result);

	if (ret == -EOPNOTSUPP)
		xsk_cq_submit_locked(pool, nb_entries);
}
EXPORT_SYMBOL(xsk_tx_cancel_tail);

void xsk_tx_set_tail_result(struct xsk_buff_pool *pool, u32 nb_entries,
			    int result)
{
	xsk_native_trace_tail(pool, nb_entries, result, false);
	if (xsk_xdev_ext_mech_tx_complete(pool, nb_entries, result, true, true) == -EOPNOTSUPP)
		(void)xsk_xdev_ext_zc_tx_set_tail_result(pool, nb_entries, result);
}
EXPORT_SYMBOL(xsk_tx_set_tail_result);

void xsk_tx_release(struct xsk_buff_pool *pool)
{
	struct xdp_sock *xs;

	rcu_read_lock();
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		__xskq_cons_release(xs->tx);
		if (xsk_tx_writeable(xs))
			xs->sk.sk_write_space(&xs->sk);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(xsk_tx_release);

bool xsk_tx_peek_desc(struct xsk_buff_pool *pool, struct xdp_desc *desc)
{
	bool budget_exhausted = false;
	struct xdp_sock *xs;
	int ret;

	ret = xsk_xdev_ext_mech_tx_peek(pool, desc);
	if (ret != -EOPNOTSUPP) {
		if (ret > 0)
			xsk_native_trace_submit(pool, desc, 1);
		return ret > 0;
	}
	ret = xsk_xdev_ext_zc_tx_peek_desc(pool, desc);
	if (ret != -EOPNOTSUPP) {
		if (ret > 0)
			xsk_native_trace_submit(pool, desc, 1);
		return ret > 0;
	}

	rcu_read_lock();
again:
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		if (xs->tx_budget_spent >= MAX_PER_SOCKET_BUDGET) {
			budget_exhausted = true;
			continue;
		}

		if (!xskq_cons_peek_desc(xs->tx, desc, pool)) {
			if (xskq_has_descs(xs->tx))
				xskq_cons_release(xs->tx);
			continue;
		}

		xs->tx_budget_spent++;

		/* This is the backpressure mechanism for the Tx path.
		 * Reserve space in the completion queue and only proceed
		 * if there is space in it. This avoids having to implement
		 * any buffering in the Tx path.
		 */
		if (xsk_cq_reserve_addr_locked(pool, desc->addr))
			goto out;

		xskq_cons_release(xs->tx);
		rcu_read_unlock();
		xsk_native_trace_submit(pool, desc, 1);
		return true;
	}

	if (budget_exhausted) {
		list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list)
			xs->tx_budget_spent = 0;

		budget_exhausted = false;
		goto again;
	}

out:
	rcu_read_unlock();
	return false;
}
EXPORT_SYMBOL(xsk_tx_peek_desc);

static u32 xsk_tx_peek_release_fallback(struct xsk_buff_pool *pool, u32 max_entries)
{
	struct xdp_desc *descs = pool->tx_descs;
	u32 nb_pkts = 0;

	while (nb_pkts < max_entries && xsk_tx_peek_desc(pool, &descs[nb_pkts]))
		nb_pkts++;

	xsk_tx_release(pool);
	return nb_pkts;
}

u32 xsk_tx_peek_release_desc_batch(struct xsk_buff_pool *pool, u32 nb_pkts)
{
	unsigned long flags;
	struct xdp_sock *xs;
	int ret;

	ret = xsk_xdev_ext_mech_tx_batch(pool, nb_pkts);
	if (ret != -EOPNOTSUPP) {
		if (ret > 0)
			xsk_native_trace_submit(pool, pool->tx_descs, ret);
		return ret < 0 ? 0 : ret;
	}
	ret = xsk_xdev_ext_zc_tx_peek_release_desc_batch(pool, nb_pkts);
	if (ret != -EOPNOTSUPP) {
		if (ret > 0)
			xsk_native_trace_submit(pool, pool->tx_descs, ret);
		return ret < 0 ? 0 : ret;
	}

	rcu_read_lock();
	if (!list_is_singular(&pool->xsk_tx_list)) {
		/* Fallback to the non-batched version */
		rcu_read_unlock();
		return xsk_tx_peek_release_fallback(pool, nb_pkts);
	}

	xs = list_first_or_null_rcu(&pool->xsk_tx_list, struct xdp_sock, tx_list);
	if (!xs) {
		nb_pkts = 0;
		goto out;
	}

	nb_pkts = xskq_cons_nb_entries(xs->tx, nb_pkts);

	/* This is the backpressure mechanism for the Tx path. Try to
	 * reserve space in the completion queue for all packets, but
	 * if there are fewer slots available, just process that many
	 * packets. This avoids having to implement any buffering in
	 * the Tx path.
	 */
	spin_lock_irqsave(&pool->cq_lock, flags);
	if (xsk_xdev_ext_mech_tx_active(pool)) {
		nb_pkts = 0;
		goto out_unlock_cq;
	}
	nb_pkts = xskq_prod_nb_free(pool->cq, nb_pkts);
	if (!nb_pkts)
		goto out_unlock_cq;

	nb_pkts = xskq_cons_read_desc_batch(xs->tx, pool, nb_pkts);
	if (!nb_pkts) {
		xs->tx->queue_empty_descs++;
		goto out_unlock_cq;
	}

	__xskq_cons_release(xs->tx);
	xskq_prod_write_addr_batch(pool->cq, pool->tx_descs, nb_pkts);
	spin_unlock_irqrestore(&pool->cq_lock, flags);
	xs->sk.sk_write_space(&xs->sk);
	goto out;

out_unlock_cq:
	spin_unlock_irqrestore(&pool->cq_lock, flags);
out:
	rcu_read_unlock();
	xsk_native_trace_submit(pool, pool->tx_descs, nb_pkts);
	return nb_pkts;
}
EXPORT_SYMBOL(xsk_tx_peek_release_desc_batch);

static int xsk_wakeup(struct xdp_sock *xs, u8 flags)
{
	struct net_device *dev = xs->dev;

	return dev->netdev_ops->ndo_xsk_wakeup(dev, xs->queue_id, flags);
}

static u32 xsk_get_num_desc(struct sk_buff *skb)
{
	return skb ? (long)skb_shinfo(skb)->destructor_arg : 0;
}

static void xsk_destruct_skb(struct sk_buff *skb)
{
	struct xsk_tx_metadata_compl *compl = &skb_shinfo(skb)->xsk_meta;

	if (compl->tx_timestamp) {
		/* sw completion timestamp, not a real one */
		*compl->tx_timestamp = ktime_get_tai_fast_ns();
	}

	xsk_cq_submit_locked(xdp_sk(skb->sk)->pool, xsk_get_num_desc(skb));
	sock_wfree(skb);
}

static void xsk_xdev_ext_destruct_skb(struct sk_buff *skb)
{
	struct xsk_tx_metadata_compl *compl = &skb_shinfo(skb)->xsk_meta;
	struct xsk_xdev_ext_copy_cookie *cookie = skb_shinfo(skb)->destructor_arg;

	if (compl->tx_timestamp) {
		/* sw completion timestamp, not a real one */
		*compl->tx_timestamp = ktime_get_tai_fast_ns();
	}

	/* The exact record must observe retirement before releasing the socket
	 * accounting that keeps the pool and its journal alive.
	 */
	xsk_xdev_ext_copy_retired(cookie);
	sock_wfree(skb);
}

static void xsk_set_destructor_arg(struct sk_buff *skb)
{
	long num = xsk_get_num_desc(xdp_sk(skb->sk)->skb) + 1;

	skb_shinfo(skb)->destructor_arg = (void *)num;
}

static void xsk_consume_skb(struct sk_buff *skb)
{
	struct xdp_sock *xs = xdp_sk(skb->sk);

	skb->destructor = sock_wfree;
	xsk_cq_cancel_locked(xs->pool, xsk_get_num_desc(skb));
	/* Free skb without triggering the perf drop trace */
	consume_skb(skb);
	xs->skb = NULL;
}

static void xsk_drop_skb(struct sk_buff *skb)
{
	xdp_sk(skb->sk)->tx->invalid_descs += xsk_get_num_desc(skb);
	xsk_consume_skb(skb);
}

static int xsk_build_skb_zerocopy(struct xdp_sock *xs,
				  struct xdp_desc *desc,
				  struct sk_buff **skb_out)
{
	struct xsk_buff_pool *pool = xs->pool;
	u32 hr, len, ts, offset, copy, copied;
	struct sk_buff *skb = *skb_out;
	struct page *page;
	void *buffer;
	int err, i;
	u64 addr;

	if (!skb) {
		hr = max(NET_SKB_PAD, L1_CACHE_ALIGN(xs->dev->needed_headroom));

		skb = sock_alloc_send_skb(&xs->sk, hr, 1, &err);
		if (unlikely(!skb))
			return err;

		skb_reserve(skb, hr);
	}

	addr = desc->addr;
	len = desc->len;
	ts = pool->unaligned ? len : pool->chunk_size;

	buffer = xsk_buff_raw_get_data(pool, addr);
	offset = offset_in_page(buffer);
	addr = buffer - pool->addrs;

	for (copied = 0, i = skb_shinfo(skb)->nr_frags; copied < len; i++) {
		if (unlikely(i >= MAX_SKB_FRAGS)) {
			*skb_out = skb;
			return -EOVERFLOW;
		}

		page = pool->umem->pgs[addr >> PAGE_SHIFT];
		get_page(page);

		copy = min_t(u32, PAGE_SIZE - offset, len - copied);
		skb_fill_page_desc(skb, i, page, offset, copy);

		copied += copy;
		addr += copy;
		offset = 0;
	}

	skb->len += len;
	skb->data_len += len;
	skb->truesize += ts;

	refcount_add(ts, &xs->sk.sk_wmem_alloc);

	*skb_out = skb;
	return 0;
}

static struct sk_buff *xsk_build_skb(struct xdp_sock *xs,
				     struct xdp_desc *desc)
{
	struct xsk_tx_metadata *meta = NULL;
	struct net_device *dev = xs->dev;
	struct sk_buff *skb = xs->skb;
	struct sk_buff *drop_skb;
	bool first_frag = !skb;
	int err;

	if (dev->priv_flags & IFF_TX_SKB_NO_LINEAR) {
		err = xsk_build_skb_zerocopy(xs, desc, &skb);
		if (err)
			goto free_err;
	} else {
		u32 hr, tr, len;
		void *buffer;

		buffer = xsk_buff_raw_get_data(xs->pool, desc->addr);
		len = desc->len;

		if (!skb) {
			hr = max(NET_SKB_PAD, L1_CACHE_ALIGN(dev->needed_headroom));
			tr = dev->needed_tailroom;
			skb = sock_alloc_send_skb(&xs->sk, hr + len + tr, 1, &err);
			if (unlikely(!skb))
				goto free_err;

			skb_reserve(skb, hr);
			skb_put(skb, len);

			err = skb_store_bits(skb, 0, buffer, len);
			if (unlikely(err))
				goto free_err;
		} else {
			int nr_frags = skb_shinfo(skb)->nr_frags;
			struct page *page;
			u8 *vaddr;

			if (unlikely(nr_frags == (MAX_SKB_FRAGS - 1) && xp_mb_desc(desc))) {
				err = -EOVERFLOW;
				goto free_err;
			}

			page = alloc_page(xs->sk.sk_allocation);
			if (unlikely(!page)) {
				err = -EAGAIN;
				goto free_err;
			}

			vaddr = kmap_local_page(page);
			memcpy(vaddr, buffer, len);
			kunmap_local(vaddr);

			skb_add_rx_frag(skb, nr_frags, page, 0, len, PAGE_SIZE);
			refcount_add(PAGE_SIZE, &xs->sk.sk_wmem_alloc);
		}

		if (first_frag && desc->options & XDP_TX_METADATA) {
			if (unlikely(xs->pool->tx_metadata_len == 0)) {
				err = -EINVAL;
				goto free_err;
			}

			meta = buffer - xs->pool->tx_metadata_len;
			if (unlikely(!xsk_buff_valid_tx_metadata(meta))) {
				err = -EINVAL;
				goto free_err;
			}

			if (meta->flags & XDP_TXMD_FLAGS_CHECKSUM) {
				if (unlikely(meta->request.csum_start +
					     meta->request.csum_offset +
					     sizeof(__sum16) > len)) {
					err = -EINVAL;
					goto free_err;
				}

				skb->csum_start = hr + meta->request.csum_start;
				skb->csum_offset = meta->request.csum_offset;
				skb->ip_summed = CHECKSUM_PARTIAL;

				if (unlikely(xs->pool->tx_sw_csum)) {
					err = skb_checksum_help(skb);
					if (err)
						goto free_err;
				}
			}

			if (meta->flags & XDP_TXMD_FLAGS_LAUNCH_TIME)
				skb->skb_mstamp_ns = meta->request.launch_time;
		}
	}

	skb->dev = dev;
	skb->priority = READ_ONCE(xs->sk.sk_priority);
	skb->mark = READ_ONCE(xs->sk.sk_mark);
	skb->destructor = xsk_destruct_skb;
	xsk_tx_metadata_to_compl(meta, &skb_shinfo(skb)->xsk_meta);
	xsk_set_destructor_arg(skb);

	return skb;

free_err:
	if (err == -EOVERFLOW) {
		/* Drop the packet */
		xs->tx_copy_discard_until_eop = xp_mb_desc(desc);
		drop_skb = xs->skb ?: skb;
		if (drop_skb) {
			xsk_set_destructor_arg(drop_skb);
			xsk_drop_skb(drop_skb);
		} else {
			WARN_ON_ONCE(1);
			xsk_cq_cancel_locked(xs->pool, 1);
			xs->tx->invalid_descs++;
		}
		xskq_cons_release(xs->tx);
	} else {
		/* Let application retry */
		if (first_frag && skb)
			kfree_skb(skb);
		xsk_cq_cancel_locked(xs->pool, 1);
	}

	return ERR_PTR(err);
}

static int
xsk_xdev_ext_consume_terminal_skb(struct xdp_sock *xs, struct sk_buff *skb,
			     struct xsk_xdev_ext_copy_cookie *cookie, int result)
{
	int ret;

	/* Release copied/page-backed skb state before making the terminal
	 * record visible to the CQ drainer.
	 */
	skb->destructor = sock_wfree;
	consume_skb(skb);
	xs->skb = NULL;
	__xskq_cons_release(xs->tx);
	ret = xsk_xdev_ext_copy_set_result(cookie, result, 0);
	return ret ?: result;
}

static bool xsk_copy_has_descs(struct xdp_sock *xs, bool xdev_ext_copy)
{
	struct xsk_queue *tx = xs->tx;

	/* Generic refresh publishes cached_cons. XDEV_EXT COPY keeps a partial packet
	 * private so that BUSY can roll the whole packet back on a later call.
	 */
	if (tx->cached_prod == tx->cached_cons) {
		if (xdev_ext_copy || xs->tx_copy_discard_until_eop)
			__xskq_cons_peek(tx);
		else
			xskq_cons_get_entries(tx);
	}
	return xskq_has_descs(tx);
}

static bool xsk_copy_peek_desc(struct xdp_sock *xs, struct xdp_desc *desc,
			       bool xdev_ext_copy, bool *valid)
{
	struct xsk_queue *tx = xs->tx;
	struct xdp_rxtx_ring *ring;

	if (!xsk_copy_has_descs(xs, xdev_ext_copy))
		return false;

	/* The rest of an already rejected packet is untrusted framing rather
	 * than a new descriptor to validate or admit. Read only its continuation
	 * bit and consume it below.
	 */
	if (xs->tx_copy_discard_until_eop) {
		ring = (struct xdp_rxtx_ring *)tx->ring;
		*desc = ring->desc[tx->cached_cons & tx->ring_mask];
		*valid = false;
		return true;
	}

	*valid = xskq_cons_read_desc(tx, desc, xs->pool);
	return true;
}

static void xsk_copy_discard_desc(struct xdp_sock *xs,
				  const struct xdp_desc *desc)
{
	if (!xp_mb_desc(desc))
		xs->tx_copy_discard_until_eop = false;
	xs->tx->invalid_descs++;
	xskq_cons_release(xs->tx);
	__xskq_cons_release(xs->tx);
}

static int __xsk_generic_xmit(struct sock *sk)
{
	struct xdp_sock *xs = xdp_sk(sk);
	u32 max_batch = TX_BATCH_SIZE;
	bool sent_frame = false;
	bool xdev_ext_copy = false;
	struct xdp_desc desc;
	struct sk_buff *skb;
	bool valid_desc;
	int err = 0;

	mutex_lock(&xs->mutex);

	/* Since we dropped the RCU read lock, the socket state might have changed. */
	if (unlikely(!xsk_is_bound(xs))) {
		err = -ENXIO;
		goto out;
	}

	if (xs->queue_id >= xs->dev->real_num_tx_queues)
		goto out;

	err = xsk_xdev_ext_copy_enter(xs->pool, xs);
	if (!err)
		xdev_ext_copy = true;
	else if (err == -EOPNOTSUPP)
		err = 0;
	else
		goto out;

	while (max_batch) {
		bool first_desc;

		if (!xsk_copy_peek_desc(xs, &desc, xdev_ext_copy, &valid_desc))
			break;
		max_batch--;
		first_desc = !xs->skb;
		if (xs->tx_copy_discard_until_eop) {
			xsk_copy_discard_desc(xs, &desc);
			continue;
		}
		if (!valid_desc) {
			if (xs->skb)
				xsk_drop_skb(xs->skb);
			xs->tx_copy_discard_until_eop = xp_mb_desc(&desc);
			xskq_cons_release(xs->tx);
			__xskq_cons_release(xs->tx);
			continue;
		}

		/* This is the backpressure mechanism for the Tx path.
		 * Reserve space in the completion queue and only proceed
		 * if there is space in it. This avoids having to implement
		 * any buffering in the Tx path.
		 */
		err = xsk_cq_reserve_addr_locked(xs->pool, desc.addr);
		if (err) {
			err = -EAGAIN;
			goto out;
		}

		skb = xsk_build_skb(xs, &desc);
		if (IS_ERR(skb)) {
			err = PTR_ERR(skb);
			if (err != -EOVERFLOW)
				goto out;
			__xskq_cons_release(xs->tx);
			err = 0;
			continue;
		}

		if (xdev_ext_copy && first_desc)
			xsk_xdev_ext_copy_note_first(xs->pool, xs, desc.addr);
		xskq_cons_release(xs->tx);

		if (xp_mb_desc(&desc)) {
			xs->skb = skb;
			continue;
		}

		if (xdev_ext_copy) {
			struct xsk_xdev_ext_copy_cookie *cookie;
			u32 nr_descs = xsk_get_num_desc(skb);
			u64 length = skb->len;
			int terminal_result;
			int disposition;
			int state_err;

			disposition =
				xsk_xdev_ext_copy_dispatch(xs->pool, xs, length,
						      nr_descs, &cookie,
						      &terminal_result);
			if (unlikely(disposition < 0)) {
				/* Nothing crossed the native boundary. Restore both
				 * producer transactions and let userspace retry.
				 */
				xskq_cons_cancel_n(xs->tx, nr_descs);
				xsk_cq_cancel_locked(xs->pool, nr_descs);
				skb->destructor = sock_wfree;
				consume_skb(skb);
				xs->skb = NULL;
				err = -EAGAIN;
				goto out;
			}

			if (disposition == XSK_XDEV_EXT_COPY_TERMINAL) {
				err = xsk_xdev_ext_consume_terminal_skb(xs, skb, cookie,
								   terminal_result);
				goto out;
			}

			skb_shinfo(skb)->destructor_arg = cookie;
			skb->destructor = xsk_xdev_ext_destruct_skb;

			err = __dev_direct_xmit(skb, xs->queue_id);
			if (err == NETDEV_TX_BUSY) {
				state_err = xsk_xdev_ext_copy_cancel_busy(cookie);
				if (!state_err)
					state_err = xsk_xdev_ext_copy_set_result(cookie, -EAGAIN, 0);
				xskq_cons_cancel_n(xs->tx, nr_descs);
				/* BUSY leaves ownership with us. The exact destructor
				 * supplies the second completion gate while CQ slots
				 * remain canceled for the retried descriptors.
				 */
				consume_skb(skb);
				xs->skb = NULL;
				err = state_err ?: -EAGAIN;
				goto out;
			}

			/* A synchronous destructor can retire first, but cannot
			 * publish until this native result supplies the other gate.
			 */
			if (err == NET_XMIT_DROP) {
				terminal_result = -EBUSY;
				length = 0;
			} else if (err < 0) {
				terminal_result = err;
				length = 0;
			} else {
				terminal_result = 0;
			}
			/* BUSY is the only return for which cached_cons is rolled
			 * back. Publish successful/drop consumption before the CQ.
			 */
			__xskq_cons_release(xs->tx);
			state_err = xsk_xdev_ext_copy_set_result(cookie,
							    terminal_result,
							    length);
			if (unlikely(state_err)) {
				err = state_err;
				xs->skb = NULL;
				goto out;
			}
			if (err == NET_XMIT_DROP) {
				err = -EBUSY;
				xs->skb = NULL;
				goto out;
			}

			sent_frame = true;
			xs->skb = NULL;
			continue;
		}

		err = __dev_direct_xmit(skb, xs->queue_id);
		if  (err == NETDEV_TX_BUSY) {
			/* Tell user-space to retry the send */
			xskq_cons_cancel_n(xs->tx, xsk_get_num_desc(skb));
			xsk_consume_skb(skb);
			err = -EAGAIN;
			goto out;
		}

		/* Ignore NET_XMIT_CN as packet might have been sent */
		if (err == NET_XMIT_DROP) {
			/* SKB completed but not sent */
			err = -EBUSY;
			xs->skb = NULL;
			goto out;
		}

		sent_frame = true;
		xs->skb = NULL;
	}
	if (!max_batch && xsk_copy_has_descs(xs, xdev_ext_copy)) {
		err = -EAGAIN;
		goto out;
	}

	if (xskq_has_descs(xs->tx)) {
		if (xs->skb)
			xsk_drop_skb(xs->skb);
		xskq_cons_release(xs->tx);
		if (xdev_ext_copy)
			__xskq_cons_release(xs->tx);
	}

out:
	if (xdev_ext_copy)
		xsk_xdev_ext_copy_exit(xs->pool, xs, !!xs->skb);
	if (sent_frame)
		if (xsk_tx_writeable(xs))
			sk->sk_write_space(sk);

	mutex_unlock(&xs->mutex);
	return err;
}

static int xsk_generic_xmit(struct sock *sk)
{
	int ret;

	/* Drop the RCU lock since the SKB path might sleep. */
	rcu_read_unlock();
	ret = __xsk_generic_xmit(sk);
	/* Reaquire RCU lock before going into common code. */
	rcu_read_lock();

	return ret;
}

static bool xsk_no_wakeup(struct sock *sk)
{
#ifdef CONFIG_NET_RX_BUSY_POLL
	/* Prefer busy-polling, skip the wakeup. */
	return READ_ONCE(sk->sk_prefer_busy_poll) && READ_ONCE(sk->sk_ll_usec) &&
		napi_id_valid(READ_ONCE(sk->sk_napi_id));
#else
	return false;
#endif
}

static int xsk_check_common(struct xdp_sock *xs)
{
	if (unlikely(!xsk_is_bound(xs)))
		return -ENXIO;
	if (unlikely(!(xs->dev->flags & IFF_UP)))
		return -ENETDOWN;

	return 0;
}

/**
 * xsk_kernel_tx_capable - is @sock a bound, TX-capable AF_XDP socket?
 * @sock: socket to test (may be any family).
 *
 * Lockless fast probe used by kernel callers (e.g. io_uring) to decide
 * whether the in-kernel copy-send path (xsk_kernel_xmit) applies. Returns
 * true only for a PF_XDP socket that is bound and has a TX ring and a pool.
 * This is advisory: xsk_kernel_xmit() re-checks all state under xs->mutex.
 */
bool xsk_kernel_tx_capable(struct socket *sock)
{
	struct xsk_buff_pool *pool;
	struct xsk_queue *tx;
	struct xdp_sock *xs;

	if (!sock || !sock->sk || sock->sk->sk_family != PF_XDP)
		return false;

	xs = xdp_sk(sock->sk);
	if (!xsk_is_bound(xs))
		return false;

	/* This lockless probe is advisory.  Pair the bound-state observation
	 * above with single-copy pointer reads; xsk_kernel_xmit() takes xs->mutex
	 * and validates the live state again before dereferencing either pointer.
	 */
	tx = READ_ONCE(xs->tx);
	pool = READ_ONCE(xs->pool);
	return tx && pool;
}
EXPORT_SYMBOL_GPL(xsk_kernel_tx_capable);

/**
 * xsk_kernel_xmit - portable COPY-mode AF_XDP send of one UMEM frame
 * @sock:    a bound, TX-capable PF_XDP socket (see xsk_kernel_tx_capable).
 * @addr:    UMEM byte offset of the frame to send.
 * @len:     frame length in bytes (single contiguous frame).
 * @options: xdp_desc options; XDP_PKT_CONTD (multi-buffer) is rejected.
 *
 * Builds ONE linear skb directly from the UMEM frame and hands it to the
 * device via __dev_direct_xmit(). It deliberately never touches xs->tx, so
 * there is no producer/consumer co-ownership with the driver's NAPI consumer
 * and no completion-queue round-trip. A ZC-capable socket simply gets a copy
 * here. Mechanism sessions use xsk_xdev_ext_mech's separate kernel-owned descriptor
 * source for ZERO-COPY TX; they never produce into xs->tx or race its cached
 * consumer cursors.
 *
 * Locking: holds xs->mutex for the whole call, which pins xs->dev / xs->pool /
 * xs->queue_id against xsk_unbind_dev(). The caller must NOT hold the RCU read
 * lock or otherwise be in a non-sleepable context because mutex_lock() may
 * sleep.
 *
 * Return: @len on success (frame handed to the device), or a negative errno.
 * -EAGAIN is retryable (device busy); -EBUSY means the frame was dropped.
 */
int xsk_kernel_xmit(struct socket *sock, u64 addr, u32 len, u32 options)
{
	struct xdp_desc desc = { .addr = addr, .len = len, .options = options };
	struct net_device *dev;
	struct sock *sk;
	struct xdp_sock *xs;
	struct sk_buff *skb;
	void *buffer;
	u32 hr, tr;
	int err;

	if (!sock || !sock->sk || sock->sk->sk_family != PF_XDP)
		return -EOPNOTSUPP;
	sk = sock->sk;
	xs = xdp_sk(sk);

	mutex_lock(&xs->mutex);

	err = xsk_check_common(xs);		/* bound + IFF_UP -> -ENXIO/-ENETDOWN */
	if (err)
		goto out;
	if (!xs->tx) {
		err = -ENOBUFS;
		goto out;
	}
	if (!xp_validate_desc(xs->pool, &desc)) {	/* OOB / bad-options guard */
		err = -EINVAL;
		goto out;
	}
	if (desc.options & XDP_PKT_CONTD) {		/* single frame only */
		err = -EINVAL;
		goto out;
	}

	dev = xs->dev;
	if (xs->queue_id >= dev->real_num_tx_queues) {
		err = -ENXIO;
		goto out;
	}

	/*
	 * Portable COPY-mode build, mirroring xsk_build_skb()'s linear path:
	 * xsk_buff_raw_get_data() returns the kernel VA of the frame (applying
	 * the unaligned-chunk fix-up). The frame already holds the full L2
	 * header, so we do NOT call eth_type_trans() (an RX helper that pulls
	 * L2) and we leave skb->protocol unset, exactly like xsk_build_skb().
	 */
	buffer = xsk_buff_raw_get_data(xs->pool, addr);

	hr = max(NET_SKB_PAD, L1_CACHE_ALIGN(dev->needed_headroom));
	tr = dev->needed_tailroom;

	skb = sock_alloc_send_skb(sk, hr + len + tr, 1, &err);
	if (unlikely(!skb))
		goto out;			/* err set by sock_alloc_send_skb */

	skb_reserve(skb, hr);
	skb_put(skb, len);
	err = skb_store_bits(skb, 0, buffer, len);
	if (unlikely(err)) {
		kfree_skb(skb);
		goto out;
	}
	/*
	 * __dev_direct_xmit() does not reset the MAC header the way
	 * __dev_queue_xmit() does, and drivers such as ice read
	 * skb_mac_header() on every send; the frame starts at skb->data.
	 */
	skb_reset_mac_header(skb);

	skb->dev = dev;
	skb->priority = READ_ONCE(sk->sk_priority);
	skb->mark = READ_ONCE(sk->sk_mark);
	skb_set_queue_mapping(skb, xs->queue_id);
	/*
	 * Do NOT set skb->destructor = xsk_destruct_skb here: that destructor
	 * submits a completion-queue slot we never reserved. sock_alloc_send_skb
	 * already wired the plain sock_wfree destructor via skb_set_owner_w,
	 * which is what we want.
	 */

	/*
	 * Ownership contract (see dev_xmit_complete()): __dev_direct_xmit()
	 * consumes the skb on success, on NET_XMIT_CN and on its drop paths,
	 * but on NETDEV_TX_BUSY (frozen/stopped queue, or the driver returning
	 * busy) the skb is returned to the caller and must be freed here --
	 * exactly as __xsk_generic_xmit() and dev_direct_xmit() do on the
	 * same return. Freeing also releases the sk_wmem_alloc charge taken
	 * by sock_alloc_send_skb() (via sock_wfree).
	 */
	err = __dev_direct_xmit(skb, xs->queue_id);
	if (err == NETDEV_TX_BUSY) {
		kfree_skb(skb);
		err = -EAGAIN;			/* retryable */
	} else if (err == NET_XMIT_DROP) {
		err = -EBUSY;			/* dropped, not sent */
	}
	/* NET_XMIT_SUCCESS(0)/NET_XMIT_CN: sent. */

out:
	mutex_unlock(&xs->mutex);
	return err < 0 ? err : (int)len;
}
EXPORT_SYMBOL_GPL(xsk_kernel_xmit);

static int __xsk_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	bool need_wait = !(m->msg_flags & MSG_DONTWAIT);
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct xsk_buff_pool *pool;
	int err;

	err = xsk_check_common(xs);
	if (err)
		return err;
	if (unlikely(need_wait))
		return -EOPNOTSUPP;
	if (unlikely(!xs->tx))
		return -ENOBUFS;

	if (sk_can_busy_loop(sk))
		sk_busy_loop(sk, 1); /* only support non-blocking sockets */

	if (xs->zc && xsk_no_wakeup(sk))
		return 0;

	pool = xs->pool;
	if (pool->cached_need_wakeup & XDP_WAKEUP_TX) {
		if (xs->zc)
			return xsk_wakeup(xs, XDP_WAKEUP_TX);
		return xsk_generic_xmit(sk);
	}
	return 0;
}

static int xsk_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	int ret;

	rcu_read_lock();
	ret = __xsk_sendmsg(sock, m, total_len);
	rcu_read_unlock();

	return ret;
}

static int __xsk_recvmsg(struct socket *sock, struct msghdr *m, size_t len, int flags)
{
	bool need_wait = !(flags & MSG_DONTWAIT);
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	int err;

	err = xsk_check_common(xs);
	if (err)
		return err;
	if (unlikely(!xs->rx))
		return -ENOBUFS;
	if (unlikely(need_wait))
		return -EOPNOTSUPP;

	if (sk_can_busy_loop(sk))
		sk_busy_loop(sk, 1); /* only support non-blocking sockets */

	if (xsk_no_wakeup(sk))
		return 0;

	if (xs->pool->cached_need_wakeup & XDP_WAKEUP_RX && xs->zc)
		return xsk_wakeup(xs, XDP_WAKEUP_RX);
	return 0;
}

static int xsk_recvmsg(struct socket *sock, struct msghdr *m, size_t len, int flags)
{
	int ret;

	rcu_read_lock();
	ret = __xsk_recvmsg(sock, m, len, flags);
	rcu_read_unlock();

	return ret;
}

static __poll_t xsk_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait)
{
	__poll_t mask = 0;
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct xsk_buff_pool *pool;

	sock_poll_wait(file, sock, wait);

	rcu_read_lock();
	if (xsk_check_common(xs))
		goto out;

	pool = xs->pool;

	if (pool->cached_need_wakeup) {
		if (xs->zc)
			xsk_wakeup(xs, pool->cached_need_wakeup);
		else if (xs->tx)
			/* Poll needs to drive Tx also in copy mode */
			xsk_generic_xmit(sk);
	}

	if (xs->rx && !xskq_prod_is_empty(xs->rx))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (xs->tx && xsk_tx_writeable(xs))
		mask |= EPOLLOUT | EPOLLWRNORM;
out:
	rcu_read_unlock();
	return mask;
}

static int xsk_init_queue(u32 entries, struct xsk_queue **queue,
			  bool umem_queue)
{
	struct xsk_queue *q;

	if (entries == 0 || *queue || !is_power_of_2(entries))
		return -EINVAL;

	q = xskq_create(entries, umem_queue);
	if (!q)
		return -ENOMEM;

	/* Make sure queue is ready before it can be seen by others */
	smp_wmb();
	WRITE_ONCE(*queue, q);
	return 0;
}

static void xsk_unbind_dev(struct xdp_sock *xs)
{
	struct net_device *dev = xs->dev;

	if (xs->state != XSK_BOUND)
		return;
	WRITE_ONCE(xs->state, XSK_UNBOUND);
	/* Mechanism stages on this socket: mark them dead, never wait. */
	xsk_xdev_ext_mech_unbind_dev(xs);

	/* Wait for driver to stop using the xdp socket. */
	xp_del_xsk(xs->pool, xs);
	synchronize_net();
	if (xs->tx)
		xsk_xdev_ext_del_tx_socket(xs->pool);
	dev_put(dev);
}

static struct xsk_map *xsk_get_map_list_entry(struct xdp_sock *xs,
					      struct xdp_sock __rcu ***map_entry)
{
	struct xsk_map *map = NULL;
	struct xsk_map_node *node;

	*map_entry = NULL;

	spin_lock_bh(&xs->map_list_lock);
	node = list_first_entry_or_null(&xs->map_list, struct xsk_map_node,
					node);
	if (node) {
		bpf_map_inc(&node->map->map);
		map = node->map;
		*map_entry = node->map_entry;
	}
	spin_unlock_bh(&xs->map_list_lock);
	return map;
}

static void xsk_delete_from_maps(struct xdp_sock *xs)
{
	/* This function removes the current XDP socket from all the
	 * maps it resides in. We need to take extra care here, due to
	 * the two locks involved. Each map has a lock synchronizing
	 * updates to the entries, and each socket has a lock that
	 * synchronizes access to the list of maps (map_list). For
	 * deadlock avoidance the locks need to be taken in the order
	 * "map lock"->"socket map list lock". We start off by
	 * accessing the socket map list, and take a reference to the
	 * map to guarantee existence between the
	 * xsk_get_map_list_entry() and xsk_map_try_sock_delete()
	 * calls. Then we ask the map to remove the socket, which
	 * tries to remove the socket from the map. Note that there
	 * might be updates to the map between
	 * xsk_get_map_list_entry() and xsk_map_try_sock_delete().
	 */
	struct xdp_sock __rcu **map_entry = NULL;
	struct xsk_map *map;

	while ((map = xsk_get_map_list_entry(xs, &map_entry))) {
		xsk_map_try_sock_delete(map, xs, map_entry);
		bpf_map_put(&map->map);
	}
}

static int xsk_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct net *net;
	int copy_entered;

	if (!sk)
		return 0;

	net = sock_net(sk);

	mutex_lock(&xs->mutex);
	if (xs->skb) {
		copy_entered = xsk_xdev_ext_copy_enter(xs->pool, xs);
		if (WARN_ON_ONCE(copy_entered &&
				 copy_entered != -EOPNOTSUPP)) {
			/* The socket owns every partial skb, so no shared-UMEM
			 * peer can legitimately block this cleanup.
			 */
		} else {
			xsk_drop_skb(xs->skb);
			if (!copy_entered)
				xsk_xdev_ext_copy_exit(xs->pool, xs, false);
		}
	}
	mutex_unlock(&xs->mutex);

	mutex_lock(&net->xdp.lock);
	sk_del_node_init_rcu(sk);
	mutex_unlock(&net->xdp.lock);

	sock_prot_inuse_add(net, sk->sk_prot, -1);

	xsk_delete_from_maps(xs);
	mutex_lock(&xs->mutex);
	xsk_unbind_dev(xs);
	mutex_unlock(&xs->mutex);

	xskq_destroy(xs->rx);
	xskq_destroy(xs->tx);
	xskq_destroy(xs->fq_tmp);
	xskq_destroy(xs->cq_tmp);

	sock_orphan(sk);
	sock->sk = NULL;

	sock_put(sk);

	return 0;
}

static struct socket *xsk_lookup_xsk_from_fd(int fd)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return ERR_PTR(-ENOTSOCK);

	if (sock->sk->sk_family != PF_XDP) {
		sockfd_put(sock);
		return ERR_PTR(-ENOPROTOOPT);
	}

	return sock;
}

static bool xsk_validate_queues(struct xdp_sock *xs)
{
	return xs->fq_tmp && xs->cq_tmp;
}

static int xsk_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_xdp *sxdp = (struct sockaddr_xdp *)addr;
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct net_device *dev;
	int bound_dev_if;
	u32 flags, qid;
	int err = 0;

	if (addr_len < sizeof(struct sockaddr_xdp))
		return -EINVAL;
	if (sxdp->sxdp_family != AF_XDP)
		return -EINVAL;

	flags = sxdp->sxdp_flags;
	if (flags & ~(XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY |
		      XDP_USE_NEED_WAKEUP | XDP_USE_SG))
		return -EINVAL;

	bound_dev_if = READ_ONCE(sk->sk_bound_dev_if);
	if (bound_dev_if && bound_dev_if != sxdp->sxdp_ifindex)
		return -EINVAL;

	rtnl_lock();
	mutex_lock(&xs->mutex);
	if (xs->state != XSK_READY) {
		err = -EBUSY;
		goto out_release;
	}

	dev = dev_get_by_index(sock_net(sk), sxdp->sxdp_ifindex);
	if (!dev) {
		err = -ENODEV;
		goto out_release;
	}

	netdev_lock_ops(dev);

	if (!xs->rx && !xs->tx) {
		err = -EINVAL;
		goto out_unlock;
	}

	qid = sxdp->sxdp_queue_id;

	if (flags & XDP_SHARED_UMEM) {
		struct xdp_sock *umem_xs;
		struct socket *sock;

		if ((flags & XDP_COPY) || (flags & XDP_ZEROCOPY) ||
		    (flags & XDP_USE_NEED_WAKEUP) || (flags & XDP_USE_SG)) {
			/* Cannot specify flags for shared sockets. */
			err = -EINVAL;
			goto out_unlock;
		}

		if (xs->umem) {
			/* We have already our own. */
			err = -EINVAL;
			goto out_unlock;
		}

		sock = xsk_lookup_xsk_from_fd(sxdp->sxdp_shared_umem_fd);
		if (IS_ERR(sock)) {
			err = PTR_ERR(sock);
			goto out_unlock;
		}

		umem_xs = xdp_sk(sock->sk);
		if (!xsk_is_bound(umem_xs)) {
			err = -EBADF;
			sockfd_put(sock);
			goto out_unlock;
		}

		/* A mechanism session owns every frame state of its UMEM. */
		err = xsk_xdev_ext_mech_share_begin(umem_xs);
		if (err) {
			sockfd_put(sock);
			goto out_unlock;
		}

		if (umem_xs->queue_id != qid || umem_xs->dev != dev) {
			/* Share the umem with another socket on another qid
			 * and/or device.
			 */
			xs->pool = xp_create_and_assign_umem(xs,
							     umem_xs->umem);
			if (!xs->pool) {
				err = -ENOMEM;
				xsk_xdev_ext_mech_share_end(umem_xs);
				sockfd_put(sock);
				goto out_unlock;
			}

			err = xp_assign_dev_shared(xs->pool, umem_xs, dev,
						   qid);
			if (err) {
				xp_destroy(xs->pool);
				xs->pool = NULL;
				xsk_xdev_ext_mech_share_end(umem_xs);
				sockfd_put(sock);
				goto out_unlock;
			}
		} else {
			/* Share the buffer pool with the other socket. */
			if (xs->fq_tmp || xs->cq_tmp) {
				/* Do not allow setting your own fq or cq. */
				err = -EINVAL;
				xsk_xdev_ext_mech_share_end(umem_xs);
				sockfd_put(sock);
				goto out_unlock;
			}

			xp_get_pool(umem_xs->pool);
			xs->pool = umem_xs->pool;

			/* If underlying shared umem was created without Tx
			 * ring, allocate Tx descs array that Tx batching API
			 * utilizes
			 */
			if (xs->tx && !xs->pool->tx_descs) {
				err = xp_alloc_tx_descs(xs->pool, xs);
				if (err) {
					xp_put_pool(xs->pool);
					xs->pool = NULL;
					xsk_xdev_ext_mech_share_end(umem_xs);
					sockfd_put(sock);
					goto out_unlock;
				}
			}
		}

		xdp_get_umem(umem_xs->umem);
		WRITE_ONCE(xs->umem, umem_xs->umem);
		xsk_xdev_ext_mech_share_end(umem_xs);
		sockfd_put(sock);
	} else if (!xs->umem || !xsk_validate_queues(xs)) {
		err = -EINVAL;
		goto out_unlock;
	} else {
		/* This xsk has its own umem. */
		xs->pool = xp_create_and_assign_umem(xs, xs->umem);
		if (!xs->pool) {
			err = -ENOMEM;
			goto out_unlock;
		}

		err = xp_assign_dev(xs->pool, dev, qid, flags);
		if (err) {
			xp_destroy(xs->pool);
			xs->pool = NULL;
			goto out_unlock;
		}
	}

	/* FQ and CQ are now owned by the buffer pool and cleaned up with it. */
	xs->fq_tmp = NULL;
	xs->cq_tmp = NULL;

	xs->dev = dev;
	xs->zc = xs->umem->zc;
	xs->sg = !!(xs->umem->flags & XDP_UMEM_SG_FLAG);
	xs->queue_id = qid;
	xp_add_xsk(xs->pool, xs);

	if (qid < dev->real_num_rx_queues) {
		struct netdev_rx_queue *rxq;

		rxq = __netif_get_rx_queue(dev, qid);
		if (rxq->napi)
			__sk_mark_napi_id_once(sk, rxq->napi->napi_id);
	}

out_unlock:
	if (err) {
		dev_put(dev);
	} else {
		/* Matches smp_rmb() in bind() for shared umem
		 * sockets, and xsk_is_bound().
		 */
		smp_wmb();
		WRITE_ONCE(xs->state, XSK_BOUND);
	}
	netdev_unlock_ops(dev);
out_release:
	mutex_unlock(&xs->mutex);
	rtnl_unlock();
	return err;
}

struct xdp_umem_reg_v1 {
	__u64 addr; /* Start of packet data area */
	__u64 len; /* Length of packet data area */
	__u32 chunk_size;
	__u32 headroom;
};

static int xsk_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	int err;

	if (level != SOL_XDP)
		return -ENOPROTOOPT;

	switch (optname) {
	case XDP_RX_RING:
	case XDP_TX_RING:
	{
		struct xsk_queue **q;
		int entries;

		if (optlen < sizeof(entries))
			return -EINVAL;
		if (copy_from_sockptr(&entries, optval, sizeof(entries)))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		if (xs->state != XSK_READY) {
			mutex_unlock(&xs->mutex);
			return -EBUSY;
		}
		q = (optname == XDP_TX_RING) ? &xs->tx : &xs->rx;
		err = xsk_init_queue(entries, q, false);
		if (!err && optname == XDP_TX_RING)
			/* Tx needs to be explicitly woken up the first time */
			xs->tx->ring->flags |= XDP_RING_NEED_WAKEUP;
		mutex_unlock(&xs->mutex);
		return err;
	}
	case XDP_UMEM_REG:
	{
		size_t mr_size = sizeof(struct xdp_umem_reg);
		struct xdp_umem_reg mr = {};
		struct xdp_umem *umem;

		if (optlen < sizeof(struct xdp_umem_reg_v1))
			return -EINVAL;
		else if (optlen < sizeof(mr))
			mr_size = sizeof(struct xdp_umem_reg_v1);

		BUILD_BUG_ON(sizeof(struct xdp_umem_reg_v1) >= sizeof(struct xdp_umem_reg));

		/* Make sure the last field of the struct doesn't have
		 * uninitialized padding. All padding has to be explicit
		 * and has to be set to zero by the userspace to make
		 * struct xdp_umem_reg extensible in the future.
		 */
		BUILD_BUG_ON(offsetof(struct xdp_umem_reg, tx_metadata_len) +
			     sizeof_field(struct xdp_umem_reg, tx_metadata_len) !=
			     sizeof(struct xdp_umem_reg));

		if (copy_from_sockptr(&mr, optval, mr_size))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		if (xs->state != XSK_READY || xs->umem) {
			mutex_unlock(&xs->mutex);
			return -EBUSY;
		}

		umem = xdp_umem_create(&mr);
		if (IS_ERR(umem)) {
			mutex_unlock(&xs->mutex);
			return PTR_ERR(umem);
		}

		/* Make sure umem is ready before it can be seen by others */
		smp_wmb();
		WRITE_ONCE(xs->umem, umem);
		mutex_unlock(&xs->mutex);
		return 0;
	}
	case XDP_UMEM_FILL_RING:
	case XDP_UMEM_COMPLETION_RING:
	{
		struct xsk_queue **q;
		int entries;

		if (optlen < sizeof(entries))
			return -EINVAL;
		if (copy_from_sockptr(&entries, optval, sizeof(entries)))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		if (xs->state != XSK_READY) {
			mutex_unlock(&xs->mutex);
			return -EBUSY;
		}

		q = (optname == XDP_UMEM_FILL_RING) ? &xs->fq_tmp :
			&xs->cq_tmp;
		err = xsk_init_queue(entries, q, true);
		mutex_unlock(&xs->mutex);
		return err;
	}
	default:
		break;
	}

	return -ENOPROTOOPT;
}

static void xsk_enter_rxtx_offsets(struct xdp_ring_offset_v1 *ring)
{
	ring->producer = offsetof(struct xdp_rxtx_ring, ptrs.producer);
	ring->consumer = offsetof(struct xdp_rxtx_ring, ptrs.consumer);
	ring->desc = offsetof(struct xdp_rxtx_ring, desc);
}

static void xsk_enter_umem_offsets(struct xdp_ring_offset_v1 *ring)
{
	ring->producer = offsetof(struct xdp_umem_ring, ptrs.producer);
	ring->consumer = offsetof(struct xdp_umem_ring, ptrs.consumer);
	ring->desc = offsetof(struct xdp_umem_ring, desc);
}

struct xdp_statistics_v1 {
	__u64 rx_dropped;
	__u64 rx_invalid_descs;
	__u64 tx_invalid_descs;
};

static int xsk_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	int len;

	if (level != SOL_XDP)
		return -ENOPROTOOPT;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case XDP_STATISTICS:
	{
		struct xdp_statistics stats = {};
		bool extra_stats = true;
		size_t stats_size;

		if (len < sizeof(struct xdp_statistics_v1)) {
			return -EINVAL;
		} else if (len < sizeof(stats)) {
			extra_stats = false;
			stats_size = sizeof(struct xdp_statistics_v1);
		} else {
			stats_size = sizeof(stats);
		}

		mutex_lock(&xs->mutex);
		stats.rx_dropped = xs->rx_dropped;
		if (extra_stats) {
			stats.rx_ring_full = xs->rx_queue_full;
			stats.rx_fill_ring_empty_descs =
				xs->pool ? xskq_nb_queue_empty_descs(xs->pool->fq) : 0;
			stats.tx_ring_empty_descs = xskq_nb_queue_empty_descs(xs->tx);
		} else {
			stats.rx_dropped += xs->rx_queue_full;
		}
		stats.rx_invalid_descs = xskq_nb_invalid_descs(xs->rx);
		stats.tx_invalid_descs = xskq_nb_invalid_descs(xs->tx);
		mutex_unlock(&xs->mutex);

		if (copy_to_user(optval, &stats, stats_size))
			return -EFAULT;
		if (put_user(stats_size, optlen))
			return -EFAULT;

		return 0;
	}
	case XDP_MMAP_OFFSETS:
	{
		struct xdp_mmap_offsets off;
		struct xdp_mmap_offsets_v1 off_v1;
		bool flags_supported = true;
		void *to_copy;

		if (len < sizeof(off_v1))
			return -EINVAL;
		else if (len < sizeof(off))
			flags_supported = false;

		if (flags_supported) {
			/* xdp_ring_offset is identical to xdp_ring_offset_v1
			 * except for the flags field added to the end.
			 */
			xsk_enter_rxtx_offsets((struct xdp_ring_offset_v1 *)
					       &off.rx);
			xsk_enter_rxtx_offsets((struct xdp_ring_offset_v1 *)
					       &off.tx);
			xsk_enter_umem_offsets((struct xdp_ring_offset_v1 *)
					       &off.fr);
			xsk_enter_umem_offsets((struct xdp_ring_offset_v1 *)
					       &off.cr);
			off.rx.flags = offsetof(struct xdp_rxtx_ring,
						ptrs.flags);
			off.tx.flags = offsetof(struct xdp_rxtx_ring,
						ptrs.flags);
			off.fr.flags = offsetof(struct xdp_umem_ring,
						ptrs.flags);
			off.cr.flags = offsetof(struct xdp_umem_ring,
						ptrs.flags);

			len = sizeof(off);
			to_copy = &off;
		} else {
			xsk_enter_rxtx_offsets(&off_v1.rx);
			xsk_enter_rxtx_offsets(&off_v1.tx);
			xsk_enter_umem_offsets(&off_v1.fr);
			xsk_enter_umem_offsets(&off_v1.cr);

			len = sizeof(off_v1);
			to_copy = &off_v1;
		}

		if (copy_to_user(optval, to_copy, len))
			return -EFAULT;
		if (put_user(len, optlen))
			return -EFAULT;

		return 0;
	}
	case XDP_OPTIONS:
	{
		struct xdp_options opts = {};

		if (len < sizeof(opts))
			return -EINVAL;

		mutex_lock(&xs->mutex);
		if (xs->zc)
			opts.flags |= XDP_OPTIONS_ZEROCOPY;
		mutex_unlock(&xs->mutex);

		len = sizeof(opts);
		if (copy_to_user(optval, &opts, len))
			return -EFAULT;
		if (put_user(len, optlen))
			return -EFAULT;

		return 0;
	}
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static int xsk_mmap(struct file *file, struct socket *sock,
		    struct vm_area_struct *vma)
{
	loff_t offset = (loff_t)vma->vm_pgoff << PAGE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	struct xdp_sock *xs = xdp_sk(sock->sk);
	int state = READ_ONCE(xs->state);
	struct xsk_queue *q = NULL;

	if (state != XSK_READY && state != XSK_BOUND)
		return -EBUSY;

	if (offset == XDP_PGOFF_RX_RING) {
		q = READ_ONCE(xs->rx);
	} else if (offset == XDP_PGOFF_TX_RING) {
		q = READ_ONCE(xs->tx);
	} else {
		/* Matches the smp_wmb() in XDP_UMEM_REG */
		smp_rmb();
		if (offset == XDP_UMEM_PGOFF_FILL_RING)
			q = state == XSK_READY ? READ_ONCE(xs->fq_tmp) :
						 READ_ONCE(xs->pool->fq);
		else if (offset == XDP_UMEM_PGOFF_COMPLETION_RING)
			q = state == XSK_READY ? READ_ONCE(xs->cq_tmp) :
						 READ_ONCE(xs->pool->cq);
	}

	if (!q)
		return -EINVAL;

	/* Matches the smp_wmb() in xsk_init_queue */
	smp_rmb();
	if (size > q->ring_vmalloc_size)
		return -EINVAL;

	return remap_vmalloc_range(vma, q->ring, 0);
}

static int xsk_notifier(struct notifier_block *this,
			unsigned long msg, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct net *net = dev_net(dev);
	struct sock *sk;

	switch (msg) {
	case NETDEV_UNREGISTER:
		mutex_lock(&net->xdp.lock);
		sk_for_each(sk, &net->xdp.list) {
			struct xdp_sock *xs = xdp_sk(sk);

			mutex_lock(&xs->mutex);
			if (xs->dev == dev) {
				sk->sk_err = ENETDOWN;
				if (!sock_flag(sk, SOCK_DEAD))
					sk_error_report(sk);

				xsk_unbind_dev(xs);

				/* Clear device references. */
				xp_clear_dev(xs->pool);
			}
			mutex_unlock(&xs->mutex);
		}
		mutex_unlock(&net->xdp.lock);
		break;
	}
	return NOTIFY_DONE;
}

static struct proto xsk_proto = {
	.name =		"XDP",
	.owner =	THIS_MODULE,
	.obj_size =	sizeof(struct xdp_sock),
};

static const struct proto_ops xsk_proto_ops = {
	.family		= PF_XDP,
	.owner		= THIS_MODULE,
	.release	= xsk_release,
	.bind		= xsk_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= xsk_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= xsk_setsockopt,
	.getsockopt	= xsk_getsockopt,
	.sendmsg	= xsk_sendmsg,
	.recvmsg	= xsk_recvmsg,
	.mmap		= xsk_mmap,
};

static void xsk_destruct(struct sock *sk)
{
	struct xdp_sock *xs = xdp_sk(sk);

	if (!sock_flag(sk, SOCK_DEAD))
		return;

	if (!xp_put_pool(xs->pool))
		xdp_put_umem(xs->umem, !xs->pool);
}

static int xsk_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	struct xdp_sock *xs;
	struct sock *sk;

	if (!ns_capable(net->user_ns, CAP_NET_RAW))
		return -EPERM;
	if (sock->type != SOCK_RAW)
		return -ESOCKTNOSUPPORT;

	if (protocol)
		return -EPROTONOSUPPORT;

	sock->state = SS_UNCONNECTED;

	sk = sk_alloc(net, PF_XDP, GFP_KERNEL, &xsk_proto, kern);
	if (!sk)
		return -ENOBUFS;

	sock->ops = &xsk_proto_ops;

	sock_init_data(sock, sk);

	sk->sk_family = PF_XDP;

	sk->sk_destruct = xsk_destruct;

	sock_set_flag(sk, SOCK_RCU_FREE);

	xs = xdp_sk(sk);
	xs->state = XSK_READY;
	mutex_init(&xs->mutex);

	INIT_LIST_HEAD(&xs->map_list);
	spin_lock_init(&xs->map_list_lock);

	mutex_lock(&net->xdp.lock);
	sk_add_node_rcu(sk, &net->xdp.list);
	mutex_unlock(&net->xdp.lock);

	sock_prot_inuse_add(net, &xsk_proto, 1);

	return 0;
}

static const struct net_proto_family xsk_family_ops = {
	.family = PF_XDP,
	.create = xsk_create,
	.owner	= THIS_MODULE,
};

static struct notifier_block xsk_netdev_notifier = {
	.notifier_call	= xsk_notifier,
};

static int __net_init xsk_net_init(struct net *net)
{
	mutex_init(&net->xdp.lock);
	INIT_HLIST_HEAD(&net->xdp.list);
	return 0;
}

static void __net_exit xsk_net_exit(struct net *net)
{
	WARN_ON_ONCE(!hlist_empty(&net->xdp.list));
}

static struct pernet_operations xsk_net_ops = {
	.init = xsk_net_init,
	.exit = xsk_net_exit,
};

static int __init xsk_init(void)
{
	int err;

	err = proto_register(&xsk_proto, 0 /* no slab */);
	if (err)
		goto out;

	err = sock_register(&xsk_family_ops);
	if (err)
		goto out_proto;

	err = register_pernet_subsys(&xsk_net_ops);
	if (err)
		goto out_sk;

	err = register_netdevice_notifier(&xsk_netdev_notifier);
	if (err)
		goto out_pernet;

	return 0;

out_pernet:
	unregister_pernet_subsys(&xsk_net_ops);
out_sk:
	sock_unregister(PF_XDP);
out_proto:
	proto_unregister(&xsk_proto);
out:
	return err;
}

fs_initcall(xsk_init);

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XDP_XSK_XDEV_EXT_MECH_H
#define _NET_XDP_XSK_XDEV_EXT_MECH_H

#include <linux/llist.h>
#include <net/xdp_sock.h>
#include <net/xsk_buff_pool.h>

#include "xsk_xdev_ext_mech_core.h"

#ifdef CONFIG_XDEV_EXT_MECH
/* Any context: NULL unless a mechanism session uses @pool's UMEM. */
static inline const u8 *xp_xdev_ext_mech_state(const struct xsk_buff_pool *pool)
{
	return READ_ONCE(pool->umem->xdev_ext_mech_state);
}

/*
 * Allocator only.  A session gives frames back from any context through the
 * pool's recycle llist; they rejoin free_list here, inside the allocator's
 * own serialization (pool->rx_lock, NAPI, or the session worker of a pool
 * without an RX ring) and never from the recycling context.
 */
static inline void xp_xdev_ext_mech_splice(struct xsk_buff_pool *pool)
{
	struct xdp_buff_xsk *xskb, *tmp;
	struct llist_node *first;

	if (likely(llist_empty(&pool->xdev_ext_mech_recycle)))
		return;
	first = llist_del_all(&pool->xdev_ext_mech_recycle);
	llist_for_each_entry_safe(xskb, tmp, first, xdev_ext_mech_node) {
		if (!list_empty(&xskb->list_node))
			continue;
		pool->free_list_cnt++;
		list_add(&xskb->list_node, &pool->free_list);
	}
}

static inline void xp_xdev_ext_mech_alloc_lock(struct xsk_buff_pool *pool)
{
	spin_lock_bh(&pool->xdev_ext_mech_alloc_lock);
}
static inline void xp_xdev_ext_mech_alloc_unlock(struct xsk_buff_pool *pool)
{
	spin_unlock_bh(&pool->xdev_ext_mech_alloc_lock);
}
static inline void xp_xdev_ext_mech_reuse(struct xdp_buff_xsk *xskb)
{
	u8 *state = READ_ONCE(xskb->pool->umem->xdev_ext_mech_state);
	u32 idx = xskb - xskb->pool->heads;

	if (state && xskb->pool->umem->zc)
		WARN_ON_ONCE(xdev_ext_mech_frame_move(&state[idx], XDEV_EXT_MECH_F_K_FREE,
					     XDEV_EXT_MECH_F_NIC_RX));
}
static inline bool xp_xdev_ext_mech_return(struct xdp_buff_xsk *xskb)
{
	u8 *state = READ_ONCE(xskb->pool->umem->xdev_ext_mech_state);
	u32 idx = xskb - xskb->pool->heads;

	if (!state || !xskb->pool->umem->zc)
		return true;
	if (xdev_ext_mech_frame_state(&state[idx]) == XDEV_EXT_MECH_F_K_FREE)
		return true;
	return !WARN_ON_ONCE(xdev_ext_mech_frame_move(&state[idx],
			XDEV_EXT_MECH_F_NIC_RX, XDEV_EXT_MECH_F_K_FREE));
}
int xsk_xdev_ext_mech_tx_peek(struct xsk_buff_pool *pool, struct xdp_desc *desc);
int xsk_xdev_ext_mech_tx_batch(struct xsk_buff_pool *pool, u32 n);
int xsk_xdev_ext_mech_tx_complete(struct xsk_buff_pool *pool, u32 n, int result,
			    bool tail, bool set_only);

static inline bool xsk_xdev_ext_mech_tx_active(const struct xsk_buff_pool *pool)
{
	return rcu_access_pointer(pool->xdev_ext_mech_tx);
}
void xsk_xdev_ext_mech_pool_dead(struct xsk_buff_pool *pool);

/* xsk_bind(), XDP_SHARED_UMEM: process context, may sleep. */
int xsk_xdev_ext_mech_share_begin(struct xdp_sock *umem_xs);
void xsk_xdev_ext_mech_share_end(struct xdp_sock *umem_xs);

/*
 * xsk_unbind_dev(), xs->mutex held, never waits: the mechanism stages on
 * @xs lost their device.
 */
void xsk_xdev_ext_mech_unbind_dev(struct xdp_sock *xs);

/* RX, under RCU: @xs is the AF_XDP RX stage of a mechanism session. */
static inline bool xsk_xdev_ext_mech_rx_session(const struct xdp_sock *xs)
{
	struct xdev_ext_mech_stage *tx = READ_ONCE(xs->xdev_ext_mech_tx);
 return READ_ONCE(xs->xdev_ext_mech_rx) ||
        (tx && (READ_ONCE(tx->flags) & XDEV_EXT_AFXDP_F_RELIABLE));
}

/* __xsk_rcv(): XDEV_EXT_MECH_HOLD, XDEV_EXT_MECH_RECYCLE or XDEV_EXT_MECH_PUBLISH. */
int xsk_xdev_ext_mech_rx(struct xdp_sock *xs, struct xdp_buff_xsk *xskb, u32 len,
		    u32 callsite);
void __xsk_xdev_ext_mech_rx_settle(struct xdp_sock *xs, struct xdp_buff_xsk *xskb,
			      u8 *state, bool to_user);
void xsk_xdev_ext_mech_rx_published(struct xdp_sock *xs, u32 nr);

/*
 * RX allocator context: a frame received on a session UMEM leaves the RX
 * path, published (@to_user) or back on free_list.
 */
static inline void xsk_xdev_ext_mech_rx_settle(struct xdp_sock *xs,
					  struct xdp_buff_xsk *xskb,
					  bool to_user)
{
	u8 *state = READ_ONCE(xs->umem->xdev_ext_mech_state);

	if (unlikely(state))
		__xsk_xdev_ext_mech_rx_settle(xs, xskb, state, to_user);
}
#else
static inline const u8 *xp_xdev_ext_mech_state(const struct xsk_buff_pool *pool)
{
	return NULL;
}

static inline void xp_xdev_ext_mech_splice(struct xsk_buff_pool *pool)
{
}

static inline bool xsk_xdev_ext_mech_tx_active(const struct xsk_buff_pool *pool)
{ return false; }
static inline void xsk_xdev_ext_mech_pool_dead(struct xsk_buff_pool *pool) {}
static inline void xp_xdev_ext_mech_alloc_lock(struct xsk_buff_pool *pool) {}
static inline void xp_xdev_ext_mech_alloc_unlock(struct xsk_buff_pool *pool) {}
static inline void xp_xdev_ext_mech_reuse(struct xdp_buff_xsk *xskb) {}
static inline bool xp_xdev_ext_mech_return(struct xdp_buff_xsk *xskb) { return true; }
static inline int xsk_xdev_ext_mech_tx_peek(struct xsk_buff_pool *pool,
				      struct xdp_desc *desc) { return -EOPNOTSUPP; }
static inline int xsk_xdev_ext_mech_tx_batch(struct xsk_buff_pool *pool, u32 n)
{ return -EOPNOTSUPP; }
static inline int xsk_xdev_ext_mech_tx_complete(struct xsk_buff_pool *pool, u32 n,
		int result, bool tail, bool set_only) { return -EOPNOTSUPP; }

static inline int xsk_xdev_ext_mech_share_begin(struct xdp_sock *umem_xs)
{
	return 0;
}

static inline void xsk_xdev_ext_mech_share_end(struct xdp_sock *umem_xs)
{
}

static inline void xsk_xdev_ext_mech_unbind_dev(struct xdp_sock *xs)
{
}

static inline bool xsk_xdev_ext_mech_rx_session(const struct xdp_sock *xs)
{
	return false;
}

static inline int xsk_xdev_ext_mech_rx(struct xdp_sock *xs,
				  struct xdp_buff_xsk *xskb, u32 len,
				  u32 callsite)
{
	return XDEV_EXT_MECH_PUBLISH;
}

static inline void xsk_xdev_ext_mech_rx_settle(struct xdp_sock *xs,
					  struct xdp_buff_xsk *xskb,
					  bool to_user)
{
}

static inline void xsk_xdev_ext_mech_rx_published(struct xdp_sock *xs, u32 nr)
{
}
#endif /* CONFIG_XDEV_EXT_MECH */

/* A fill-ring address of a frame the session owns is not the user's to give. */
static inline bool xp_xdev_ext_mech_fq_ok(const struct xsk_buff_pool *pool,
				     const u8 *state, u64 addr)
{
	u32 idx = addr >> pool->chunk_shift;

	if (!xsk_xdev_ext_mech_fq_ok(state, pool->heads_cnt, idx))
		return false;
	if (state && pool->umem->zc)
		return !xdev_ext_mech_frame_move((u8 *)&state[idx], XDEV_EXT_MECH_F_USER,
					   XDEV_EXT_MECH_F_NIC_RX);
	return true;
}

#endif /* _NET_XDP_XSK_XDEV_EXT_MECH_H */

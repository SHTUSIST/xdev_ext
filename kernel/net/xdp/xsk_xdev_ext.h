/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XDP_XSK_XDEV_EXT_H
#define _NET_XDP_XSK_XDEV_EXT_H

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/xdev_ext_binding.h>

#include "xsk_xdev_ext_rx_core.h"

struct xdp_desc;
struct xdp_buff;
struct xdp_sock;
struct xsk_buff_pool;
struct xsk_xdev_ext_copy_cookie;

struct xsk_xdev_ext_rx_cookie {
	struct xsk_xdev_ext_rx_core core;
	struct xdev_ext_binding_ctx_v2 ctx;
	struct xdev_ext_binding_token token;
};

enum xsk_xdev_ext_copy_disposition {
	XSK_XDEV_EXT_COPY_NATIVE = 0,
	XSK_XDEV_EXT_COPY_TERMINAL = 1,
};

enum xsk_xdev_ext_rx_disposition {
	XSK_XDEV_EXT_RX_C_FALLBACK = 0,
	XSK_XDEV_EXT_RX_TRACKED = 1,
	XSK_XDEV_EXT_RX_TERMINAL = 2,
};

#ifdef CONFIG_XDP_SOCKETS_XDEV_EXT_POLICY
int xsk_xdev_ext_pool_init(struct xsk_buff_pool *pool, u32 capacity);
void xsk_xdev_ext_pool_destroy(struct xsk_buff_pool *pool);
void xsk_xdev_ext_add_tx_socket(struct xsk_buff_pool *pool);
void xsk_xdev_ext_del_tx_socket(struct xsk_buff_pool *pool);

int xsk_xdev_ext_zc_tx_completed(struct xsk_buff_pool *pool, u32 nr_descs);
int xsk_xdev_ext_zc_tx_cancel_tail(struct xsk_buff_pool *pool, u32 nr_descs,
			      int result);
int xsk_xdev_ext_zc_tx_set_tail_result(struct xsk_buff_pool *pool, u32 nr_descs,
				  int result);
int xsk_xdev_ext_zc_tx_peek_desc(struct xsk_buff_pool *pool,
			    struct xdp_desc *desc);
int xsk_xdev_ext_zc_tx_peek_release_desc_batch(struct xsk_buff_pool *pool,
					  u32 max_descs);

void xsk_xdev_ext_zc_teardown_begin(struct xsk_buff_pool *pool);
void xsk_xdev_ext_zc_teardown_finish(struct xsk_buff_pool *pool);

/*
 * Generic COPY transactions hold a per-pool sleepable lock from enter() to
 * exit().  A partial multi-buffer packet keeps @xs as the logical owner after
 * the lock is dropped, preventing a shared-UMEM peer from interleaving CQ
 * reservations with that packet on its next invocation.
 */
int xsk_xdev_ext_copy_enter(struct xsk_buff_pool *pool, struct xdp_sock *xs);
void xsk_xdev_ext_copy_note_first(struct xsk_buff_pool *pool,
			     struct xdp_sock *xs, u64 addr);
void xsk_xdev_ext_copy_exit(struct xsk_buff_pool *pool, struct xdp_sock *xs,
		       bool partial);
int xsk_xdev_ext_copy_dispatch(struct xsk_buff_pool *pool, struct xdp_sock *xs,
			  u64 length, u32 nr_descs,
			  struct xsk_xdev_ext_copy_cookie **cookie,
			  int *terminal_result);
int xsk_xdev_ext_copy_set_result(struct xsk_xdev_ext_copy_cookie *cookie, int result,
			    u64 bytes_done);
int xsk_xdev_ext_copy_cancel_busy(struct xsk_xdev_ext_copy_cookie *cookie);
void xsk_xdev_ext_copy_retired(struct xsk_xdev_ext_copy_cookie *cookie);

enum xsk_xdev_ext_rx_disposition
xsk_xdev_ext_rx_dispatch(struct xsk_buff_pool *pool, struct xdp_sock *xs,
		    struct xdp_buff *xdp, u64 length, u32 nr_descs,
		    bool zero_copy, struct xsk_xdev_ext_rx_cookie *cookie);
void xsk_xdev_ext_rx_abort(struct xsk_xdev_ext_rx_cookie *cookie);
bool xsk_xdev_ext_rx_publish(struct xdp_sock *xs,
			struct xsk_xdev_ext_rx_cookie *cookie);
#else
static inline int xsk_xdev_ext_pool_init(struct xsk_buff_pool *pool, u32 capacity)
{
	return 0;
}

static inline void xsk_xdev_ext_pool_destroy(struct xsk_buff_pool *pool)
{
}

static inline void xsk_xdev_ext_add_tx_socket(struct xsk_buff_pool *pool)
{
}

static inline void xsk_xdev_ext_del_tx_socket(struct xsk_buff_pool *pool)
{
}

static inline int
xsk_xdev_ext_zc_tx_completed(struct xsk_buff_pool *pool, u32 nr_descs)
{
	return -EOPNOTSUPP;
}

static inline int
xsk_xdev_ext_zc_tx_cancel_tail(struct xsk_buff_pool *pool, u32 nr_descs,
			  int result)
{
	return -EOPNOTSUPP;
}

static inline int
xsk_xdev_ext_zc_tx_set_tail_result(struct xsk_buff_pool *pool, u32 nr_descs,
			      int result)
{
	return -EOPNOTSUPP;
}

static inline int
xsk_xdev_ext_zc_tx_peek_desc(struct xsk_buff_pool *pool, struct xdp_desc *desc)
{
	return -EOPNOTSUPP;
}

static inline int
xsk_xdev_ext_zc_tx_peek_release_desc_batch(struct xsk_buff_pool *pool,
				      u32 max_descs)
{
	return -EOPNOTSUPP;
}

static inline void xsk_xdev_ext_zc_teardown_begin(struct xsk_buff_pool *pool)
{
}

static inline void xsk_xdev_ext_zc_teardown_finish(struct xsk_buff_pool *pool)
{
}

static inline int xsk_xdev_ext_copy_enter(struct xsk_buff_pool *pool,
				     struct xdp_sock *xs)
{
	return -EOPNOTSUPP;
}

static inline void xsk_xdev_ext_copy_note_first(struct xsk_buff_pool *pool,
					   struct xdp_sock *xs, u64 addr)
{
}

static inline void xsk_xdev_ext_copy_exit(struct xsk_buff_pool *pool,
				     struct xdp_sock *xs, bool partial)
{
}

static inline int
xsk_xdev_ext_copy_dispatch(struct xsk_buff_pool *pool, struct xdp_sock *xs,
		      u64 length, u32 nr_descs,
		      struct xsk_xdev_ext_copy_cookie **cookie,
		      int *terminal_result)
{
	return -EOPNOTSUPP;
}

static inline int
xsk_xdev_ext_copy_set_result(struct xsk_xdev_ext_copy_cookie *cookie, int result,
			u64 bytes_done)
{
	return -EOPNOTSUPP;
}

static inline int
xsk_xdev_ext_copy_cancel_busy(struct xsk_xdev_ext_copy_cookie *cookie)
{
	return -EOPNOTSUPP;
}

static inline void
xsk_xdev_ext_copy_retired(struct xsk_xdev_ext_copy_cookie *cookie)
{
}

static inline enum xsk_xdev_ext_rx_disposition
xsk_xdev_ext_rx_dispatch(struct xsk_buff_pool *pool, struct xdp_sock *xs,
		    struct xdp_buff *xdp, u64 length, u32 nr_descs,
		    bool zero_copy, struct xsk_xdev_ext_rx_cookie *cookie)
{
	xsk_xdev_ext_rx_core_init(&cookie->core);
	cookie->token.private = NULL;
	return XSK_XDEV_EXT_RX_C_FALLBACK;
}

static inline void xsk_xdev_ext_rx_abort(struct xsk_xdev_ext_rx_cookie *cookie)
{
}

static inline bool xsk_xdev_ext_rx_publish(struct xdp_sock *xs,
				      struct xsk_xdev_ext_rx_cookie *cookie)
{
	return false;
}
#endif /* CONFIG_XDP_SOCKETS_XDEV_EXT_POLICY */

#endif /* _NET_XDP_XSK_XDEV_EXT_H */

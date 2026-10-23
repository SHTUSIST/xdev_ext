// SPDX-License-Identifier: GPL-2.0
/* Ordinary UDP compatibility sink over the common mechanism stage contract.
 * kernel_sendmsg copies from the original mapped pool spans into socket-owned
 * skb storage. No private payload bounce, MSG_ZEROCOPY or MSG_SPLICE_PAGES.
 * Its return is the local native lifetime boundary, never a remote ACK.
 */
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/udp.h>
#include <linux/xdev_ext_mech.h>
#include <net/sock.h>
#include <net/tcp_states.h>

struct xdev_ext_socket_request {
	struct kvec vec[XDEV_EXT_MECH_MAX_FRAMES];
	u32 nr, bytes;
};
struct xdev_ext_socket_stage {
	struct socket *sock; /* st->file owns the original socket until unbind */
	struct xdev_ext_socket_request *request;
	const struct cred *cred;	/* CREATE caller, retained until worker drain */
	u32 depth;
	bool dead;
	struct xdev_ext_socket_rx *rx;
};

static int xdev_ext_socket_ready(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk || sock->type != SOCK_DGRAM ||
	    (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sk->sk_protocol != IPPROTO_UDP)
		return -EPROTONOSUPPORT;
	if (READ_ONCE(sk->sk_shutdown) & SEND_SHUTDOWN)
		return -ESHUTDOWN;
	if (READ_ONCE(sk->sk_state) != TCP_ESTABLISHED)
		return -ENOTCONN;
	/* One group must remain one datagram. The caller lends configuration;
	 * it must not race reconnect/cork/segment changes with this session.
	 */
	if (udp_test_bit(CORK, sk) || READ_ONCE(udp_sk(sk)->pending) ||
	    READ_ONCE(udp_sk(sk)->gso_size))
		return -EOPNOTSUPP;
	return 0;
}

static int xdev_ext_socket_bind(struct xdev_ext_mech_stage *st,
			       const struct xdev_ext_mech_stage_uapi *u)
{
	struct xdev_ext_socket_stage *ss;
	struct socket *sock;
	int err;

	if (st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE ||
	    u->flags || u->arg0 || u->arg1)
		return -EINVAL;
	sock = sock_from_file(st->file);
	if (!sock)
		return -ENOTSOCK;
	err = xdev_ext_socket_ready(sock);
	if (err)
		return err;
	ss = kzalloc(sizeof(*ss), GFP_KERNEL);
	if (!ss)
		return -ENOMEM;
	ss->depth = xdev_ext_mech_session_depth(st->s);
	ss->request = kvcalloc(ss->depth, sizeof(*ss->request), GFP_KERNEL);
	if (!ss->request) {
		kfree(ss);
		return -ENOMEM;
	}
	ss->sock = sock;
	ss->cred = get_current_cred();
	st->priv = ss;
	return 0;
}

static void xdev_ext_socket_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_socket_stage *ss = st->priv;

	/* Common core drains the worker before dropping st->file. No deferred
	 * socket callback or skb can retain these original pool spans.
	 */
	kvfree(ss->request);
	put_cred(ss->cred);
	kfree(ss);
	st->priv = NULL;
}

static void xdev_ext_socket_fill_info(struct xdev_ext_mech_stage *st,
				    struct xdev_ext_mech_batch *b, void *info)
{
	struct xdev_ext_socket_mech_info *out = info;
	struct xdev_ext_mech_frame f;
	u32 i;

	*out = (struct xdev_ext_socket_mech_info) {
		.l = *xdev_ext_mech_session_layout(st->s),
		.nr_frames = b ? xdev_ext_mech_batch_nr_frames(b) : 0,
		.max_datagram = XDEV_EXT_SOCKET_MAX_DATAGRAM,
	};
	for (i = 0; i < out->nr_frames; i++) {
		if (xdev_ext_mech_batch_frame(b, i, &f)) {
			out->nr_frames = 0;
			break;
		}
		out->f[i] = (struct xdev_ext_mech_frame_info) {
			.umem_addr = f.umem_addr, .data_off = f.data_off,
			.data_len = f.data_len,
		};
	}
}

static int xdev_ext_socket_validate(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
	struct xdev_ext_socket_stage *ss = st->priv;
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	const struct xdev_ext_socket_send_desc *d = (const void *)scratch;
	struct xdev_ext_socket_request *r;
	struct xdev_ext_mech_frame f;
	u32 i, bytes = 0, slot = xdev_ext_mech_batch_slot(b);

	if (!xdev_ext_mech_batch_bytes(b) ||
	    xdev_ext_mech_batch_bytes(b) > XDEV_EXT_SOCKET_MAX_DATAGRAM)
		return -EMSGSIZE;
	if (slot >= ss->depth || !n || n > XDEV_EXT_MECH_MAX_FRAMES ||
	    n != xdev_ext_mech_batch_nr_frames(b))
		return -EINVAL;
	r = &ss->request[slot];
	for (i = 0; i < n; i++) {
		if (xdev_ext_mech_batch_frame(b, i, &f) || !f.kaddr ||
		    f.index >= pool->nr_frames || !f.data_len ||
		    f.data_off > pool->frame_size ||
		    f.data_len > pool->frame_size - f.data_off ||
		    d[i].flags || d[i].frame_pos != i ||
		    d[i].frame_off != f.data_off || d[i].len != f.data_len ||
		    f.data_len > XDEV_EXT_SOCKET_MAX_DATAGRAM - bytes)
			return -EINVAL;
		r->vec[i] = (struct kvec) {
			.iov_base = (u8 *)f.kaddr + f.data_off,
			.iov_len = f.data_len,
		};
		bytes += f.data_len;
	}
	if (bytes != xdev_ext_mech_batch_bytes(b))
		return -EINVAL;
	r->nr = n;
	r->bytes = bytes;
	return 0;
}

static int xdev_ext_socket_submit(struct xdev_ext_mech_stage *st,
				struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_socket_stage *ss = st->priv;
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	struct xdev_ext_socket_request *r;
	struct xdev_ext_mech_frame f;
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	const struct cred *old_cred;
	u32 i, slot = xdev_ext_mech_batch_slot(b);
	u64 ticket = xdev_ext_mech_batch_ticket(b);
	int err;

	if (READ_ONCE(ss->dead))
		return -ENODEV;
	if (!xdev_ext_mech_session_admits(st->s))
		return -ESHUTDOWN;
	if (slot >= ss->depth)
		return -EINVAL;
	err = xdev_ext_socket_ready(ss->sock);
	if (err)
		return err;
	r = &ss->request[slot];
	for (i = 0; i < r->nr; i++)
		if (xdev_ext_mech_batch_frame(b, i, &f) ||
		    xdev_ext_mech_pool_frame_state(pool, f.index) != XDEV_EXT_MECH_F_INFLIGHT)
			return -EBUSY;
	/* Native socket LSM checks must see the session's bound caller, not
	 * the shared kernel worker's credentials. Restore before every exit,
	 * including preaccept EAGAIN and native errors.
	 */
	old_cred = override_creds(ss->cred);
	err = kernel_sendmsg(ss->sock, &msg, r->vec, r->nr, r->bytes);
	revert_creds(old_cred);
	/* UDP EAGAIN guarantees no datagram was accepted. Common core restores
	 * HELD and schedules preaccept backpressure; native RETRY is forbidden.
	 */
	if (err == -EAGAIN)
		return err;
	if (err >= 0)
		err = (u32)err == r->bytes ? 0 : -EIO;
	if (!err) {
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_NIC_COPY_OPS, 1);
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_NIC_COPY_BYTES, r->bytes);
	}
	xdev_ext_mech_batch_complete(b, ticket, err);
	return 0;
}

static void xdev_ext_socket_fill_cqe(struct xdev_ext_mech_stage *st,
				   struct xdev_ext_mech_batch *b, void *out)
{
	int status = xdev_ext_mech_batch_status(b);

	(void)st;
	*(struct xdev_ext_socket_mech_cqe *)out = (struct xdev_ext_socket_mech_cqe) {
		.status = status,
		.bytes_sent = status ? 0 : xdev_ext_mech_batch_bytes(b),
	};
}

static void xdev_ext_socket_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_socket_stage *ss = st->priv;

	WRITE_ONCE(ss->dead, true);
}

/* All mutable queue state belongs to the session worker. The callback only
 * borrows st under sk_callback_lock and queues work; it never touches a slot. */
struct xdev_ext_socket_rx_slot {
	struct xdev_ext_mech_batch *batch;
	u64 ticket;
	u32 flags;
};
struct xdev_ext_socket_rx {
	struct xdev_ext_mech_stage *stage;
	void (*saved_ready)(struct sock *sk);
	struct xdev_ext_socket_rx_slot *slot;
	u32 *fifo;
	u32 head, count;
};

static void xdev_ext_socket_data_ready(struct sock *sk)
{
	struct xdev_ext_socket_rx *rx;

	/* A delayed invocation may enter after unbind restored the callback. */
	read_lock_bh(&sk->sk_callback_lock);
	rx = sk->sk_user_data;
	if (rx)
		xdev_ext_mech_stage_kick(rx->stage);
	read_unlock_bh(&sk->sk_callback_lock);
}

static int xdev_ext_socket_class_bind(struct xdev_ext_mech_stage *st,
				     const struct xdev_ext_mech_stage_uapi *u)
{
	struct xdev_ext_socket_stage *ss;
	struct xdev_ext_socket_rx *rx;
	struct socket *sock;
	struct sock *sk;
	int err = -ENOMEM;

	if (st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE)
		return xdev_ext_socket_bind(st, u);
	if (st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE ||
	    u->flags || u->arg0 || u->arg1)
		return -EINVAL;
	sock = sock_from_file(st->file);
	if (!sock)
		return -ENOTSOCK;
	sk = sock->sk;
	if (!sk || sock->type != SOCK_DGRAM ||
	    (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sk->sk_protocol != IPPROTO_UDP)
		return -EPROTONOSUPPORT;
	if (READ_ONCE(sk->sk_shutdown) & RCV_SHUTDOWN)
		return -ESHUTDOWN;
	if (udp_test_bit(GRO_ENABLED, sk) || udp_test_bit(ENCAP_ENABLED, sk))
		return -EOPNOTSUPP;
	if (READ_ONCE(sk->sk_user_data))
		return -EBUSY;
	ss = kzalloc(sizeof(*ss), GFP_KERNEL);
	if (!ss)
		return -ENOMEM;
	ss->depth = xdev_ext_mech_session_depth(st->s);
	ss->sock = sock;
	ss->request = kvcalloc(ss->depth, sizeof(*ss->request), GFP_KERNEL);
	ss->rx = kzalloc(sizeof(*ss->rx), GFP_KERNEL);
	rx = ss->rx;
	if (!ss->request || !rx)
		goto free;
	rx->slot = kvcalloc(ss->depth, sizeof(*rx->slot), GFP_KERNEL);
	rx->fifo = kvcalloc(ss->depth, sizeof(*rx->fifo), GFP_KERNEL);
	if (!rx->slot || !rx->fifo)
		goto free;
	rx->stage = st;
	ss->cred = get_current_cred();
	write_lock_bh(&sk->sk_callback_lock);
	/* Serialize two CREATEs lending the same socket. */
	if (sk->sk_user_data) {
		write_unlock_bh(&sk->sk_callback_lock);
		put_cred(ss->cred);
		err = -EBUSY;
		goto free;
	}
	rx->saved_ready = sk->sk_data_ready;
	st->priv = ss;
	sk->sk_user_data = rx;
	sk->sk_data_ready = xdev_ext_socket_data_ready;
	write_unlock_bh(&sk->sk_callback_lock);
	return 0;
free:
	if (rx) {
		kvfree(rx->fifo);
		kvfree(rx->slot);
		kfree(rx);
	}
	kvfree(ss->request);
	kfree(ss);
	return err;
}

static void xdev_ext_socket_class_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_socket_stage *ss = st->priv;
	struct xdev_ext_socket_rx *rx = ss->rx;

	if (rx) {
		struct sock *sk = ss->sock->sk;

		/* The core has drained all armed requests before this point. */
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_data_ready = rx->saved_ready;
		sk->sk_user_data = NULL;
		write_unlock_bh(&sk->sk_callback_lock);
		kvfree(rx->fifo);
		kvfree(rx->slot);
		kfree(rx);
	}
	xdev_ext_socket_unbind(st);
}

static int xdev_ext_socket_class_submit(struct xdev_ext_mech_stage *st,
				       struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_socket_stage *ss = st->priv;
	struct xdev_ext_socket_rx *rx = ss->rx;
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	struct xdev_ext_mech_frame f;
	u32 slot = xdev_ext_mech_batch_slot(b), i;

	if (!rx)
		return xdev_ext_socket_submit(st, b);
	if (READ_ONCE(ss->dead))
		return -ENODEV;
	if (!xdev_ext_mech_session_admits(st->s))
		return -ESHUTDOWN;
	if (slot >= ss->depth)
		return -EINVAL;
	if (rx->slot[slot].batch)
		return -EBUSY;
	if (READ_ONCE(ss->sock->sk->sk_shutdown) & RCV_SHUTDOWN)
		return -ESHUTDOWN;
	for (i = 0; i < ss->request[slot].nr; i++)
		if (xdev_ext_mech_batch_frame(b, i, &f) ||
		    xdev_ext_mech_pool_frame_state(pool, f.index) != XDEV_EXT_MECH_F_INFLIGHT)
			return -EBUSY;
	rx->slot[slot] = (struct xdev_ext_socket_rx_slot) {
		.batch = b, .ticket = xdev_ext_mech_batch_ticket(b),
	};
	rx->fifo[(rx->head + rx->count) % ss->depth] = slot;
	rx->count++;
	/* Covers datagrams queued before the first request was armed. */
	xdev_ext_mech_stage_kick(st);
	return 0;
}

static unsigned long xdev_ext_socket_progress(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_socket_stage *ss = st->priv;
	struct xdev_ext_socket_rx *rx = ss->rx;

	if (!rx)
		return 0;
	while (rx->count) {
		u32 index = rx->fifo[rx->head];
		struct xdev_ext_socket_rx_slot *slot = &rx->slot[index];
		struct xdev_ext_socket_request *r = &ss->request[index];
		struct msghdr msg = {};
		const struct cred *old_cred;
		int err = READ_ONCE(ss->dead) ? -ENODEV :
			  !xdev_ext_mech_session_admits(st->s) ? -ESHUTDOWN : 0;

		if (err) {
			xdev_ext_mech_batch_complete_cancelled(slot->batch, slot->ticket, err);
		} else {
			old_cred = override_creds(ss->cred);
			err = kernel_recvmsg(ss->sock, &msg, r->vec, r->nr,
					     r->bytes, MSG_DONTWAIT);
			revert_creds(old_cred);
			if (err == -EAGAIN)
				break;
			if (err >= 0 && (msg.msg_flags & MSG_TRUNC)) {
				slot->flags = XDEV_EXT_SOCKET_CQE_F_TRUNC;
				err = -EMSGSIZE;
			} else if (!err) {
				err = -ENODATA;
			}
			if (err > 0) {
				xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_NIC_COPY_OPS, 1);
				xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_NIC_COPY_BYTES, err);
			}
			xdev_ext_mech_batch_complete_produced(slot->batch, slot->ticket,
						      err < 0 ? err : 0, err > 0 ? err : 0);
		}
		slot->batch = NULL;
		rx->head = (rx->head + 1) % ss->depth;
		rx->count--;
	}
	return 0;
}

static void xdev_ext_socket_class_fill_cqe(struct xdev_ext_mech_stage *st,
					 struct xdev_ext_mech_batch *b, void *out)
{
	struct xdev_ext_socket_stage *ss = st->priv;
	int status = xdev_ext_mech_batch_status(b);

	if (!ss->rx) {
		xdev_ext_socket_fill_cqe(st, b, out);
		return;
	}
	*(struct xdev_ext_socket_mech_cqe *)out = (struct xdev_ext_socket_mech_cqe) {
		.status = status,
		.bytes_received = status ? 0 : xdev_ext_mech_batch_produced(b),
		.flags = ss->rx->slot[xdev_ext_mech_batch_slot(b)].flags,
	};
}

static void xdev_ext_socket_class_mark_dead(struct xdev_ext_mech_stage *st)
{
	xdev_ext_socket_mark_dead(st);
	xdev_ext_mech_stage_kick(st);
}

static const struct xdev_ext_mech_class_ops xdev_ext_socket_class = {
	.class_id = XDEV_EXT_MECH_CLASS_SOCKET,
	.flags = XDEV_EXT_MECH_CLASS_F_ORDERED | XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE,
	.desc_size = sizeof(struct xdev_ext_socket_send_desc),
	.desc_cap = XDEV_EXT_MECH_MAX_FRAMES,
	.info_size = sizeof(struct xdev_ext_socket_mech_info),
	.cqe_size = sizeof(struct xdev_ext_socket_mech_cqe), .cqe_cap = 1,
	.owner = THIS_MODULE,
	.progress = xdev_ext_socket_progress,
	.bind = xdev_ext_socket_class_bind, .unbind = xdev_ext_socket_class_unbind,
	.fill_info = xdev_ext_socket_fill_info, .validate = xdev_ext_socket_validate,
	.submit = xdev_ext_socket_class_submit, .fill_cqe = xdev_ext_socket_class_fill_cqe,
	.mark_dead = xdev_ext_socket_class_mark_dead,
};

static int __init xdev_ext_mech_socket_init(void)
{
	return xdev_ext_mech_class_register(&xdev_ext_socket_class);
}
late_initcall_sync(xdev_ext_mech_socket_init);

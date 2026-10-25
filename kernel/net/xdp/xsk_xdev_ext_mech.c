// SPDX-License-Identifier: GPL-2.0
/*
 * AF_XDP class of the XDEV_EXT mechanism layer.
 *
 * The xsk pool provider lends a session the frames of one aligned
 * UMEM. Zero-copy sockets use a kernel descriptor source and hardware
 * completion journal; copy-mode sockets retain the compatible skb path.
 * Ownership is one word per chunk, kept with the UMEM so
 * every path that hands out a chunk sees it; a frame the session gives back
 * travels on a lock-free llist and rejoins the pool's free list only inside
 * the allocator.  The class ops bind an AF_XDP socket as the RX source of a
 * session; its complete runs on every single-buffer frame the socket
 * receives, under pool->rx_lock in generic and native receive paths. C acts on
 * the program's HOLD, PUBLISH or RECYCLE only after it returns.  The same
 * socket may be a TX stage: its build fills one struct xdp_desc per batch
 * frame and the frame headers, C validates every field, writes the IPv4
 * checksum and submits descriptors to the driver on zero-copy sockets.
 * The two class kfuncs give an AF_XDP TX build a write
 * window on the header room and let an RX complete record one hold intent.
 */

#include <linux/bpf.h>
#include <linux/crc32c.h>
#include <linux/uaccess.h>
#include <linux/xdev_ext_mech_reliable_core.h>
#include "../../io_uring/xdev_ext_policy.h"
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/log2.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/xdev_ext_binding.h>
#include <linux/xdev_ext_mech.h>
#include <net/busy_poll.h>
#include <net/netdev_rx_queue.h>
#include <net/xdp_sock.h>
#include <net/xsk_buff_pool.h>

#include "xsk.h"
#include "xsk_queue.h"
#include "xsk_xdev_ext_mech.h"
#include "xsk_xdev_ext_mech_tx_core.h"
#include "xsk_xdev_ext_mech_zc_core.h"

/* One xsk pool lent to a session; the file pins the socket, pool and UMEM. */
struct xsk_xdev_ext_mech_provider {
	struct file *file;
	struct xdp_sock *xs;
	struct xsk_buff_pool *xp;
	bool has_rx;
	bool zc;
	bool stopped;
	u32 source_first, source_next;
	spinlock_t tx_lock;
	struct xsk_mech_zc_ring ring;
	struct xsk_mech_zc_slot *slots;
};

/* Pending RX holds own registered chunk identities, never a transient xdp_buff.
 * Entries are indexed by pool frame and linked in packet admission order.
 */
struct xsk_mech_rx_pending_entry {
	struct xdev_ext_mech_hold_intent hold;
	u32 next;
	u32 data_off, data_len;
	bool queued;
};

struct xsk_mech_rx_pending {
	spinlock_t lock;
	struct xsk_mech_rx_pending_entry *entries;
	u32 head, tail, count, capacity;
};

/* An AF_XDP stage: the RX source or a TX stage of a session. */
struct xsk_mech_reliable;
struct xsk_xdev_ext_mech_stage {
	struct xsk_mech_rx_pending pending;
 struct xsk_mech_reliable *rel;
	/* RX lock serializes this stage-owned, zeroed protocol state. */
	__u64 bpf_state[XDEV_EXT_AFXDP_MECH_STATE_SIZE / sizeof(__u64)];
	struct xdp_sock *xs;
	struct socket *sock;		/* pinned by the stage file */
	bool dead;
	u32 mtu;
	/* RX complete info; f[0] is rewritten per frame under pool->rx_lock */
	struct xdev_ext_afxdp_reliable_info rx_info;
	/* TX: per chunk, the id of the last batch that sent it */
	u64 *tx_sent;
	u32 tx_nr_sent;
	/*
	 * TX, session worker only: what ->validate accepted, for ->submit of
	 * the same batch right after it.
	 */
	struct xdev_ext_mech_batch *tx_staged;
	u64 tx_staged_id;
	u32 tx_n;
	struct xdp_desc tx_desc[XDEV_EXT_MECH_MAX_FRAMES];
	u8 *tx_pkt[XDEV_EXT_MECH_MAX_FRAMES];
	u64 *tx_tag[XDEV_EXT_MECH_MAX_FRAMES];
	struct xdev_ext_mech_frame_info tx_fi[XDEV_EXT_MECH_MAX_FRAMES];
	u8 *tx_kaddr[XDEV_EXT_MECH_MAX_FRAMES];
	/* Polled stage: NAPI ids the session worker busy-polls, fixed at bind. */
	unsigned int poll_napi[2];
	u32 nr_poll_napi;
};

/* xdev_ext_mech_batch_priv() of a TX batch: the last attempt, per frame. */
struct xsk_xdev_ext_mech_tx_batch {
 struct xdev_ext_mech_stage *reliable_stage;
 u32 attempt;
 bool control;
 bool cancelled_before_native;
 int native_error;
	struct list_head done;
	struct xdev_ext_mech_batch *batch;
	u64 ticket;
	struct xsk_mech_zc_batch completion;
	u32 n;
	s32 err[XDEV_EXT_MECH_MAX_FRAMES];
};

static const struct xdev_ext_mech_pool_ops xsk_xdev_ext_mech_pool_ops;
static int xsk_xdev_ext_mech_pool_resolve(struct xdev_ext_mech_pool *pool,
				     struct xdev_ext_mech_frame *f);

static int xsk_rel_bind(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_stage_uapi *u);
static void xsk_rel_unbind(struct xdev_ext_mech_stage *st);
static void xsk_rel_info(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
                         struct xdev_ext_afxdp_reliable_info *info);
static int xsk_rel_rx(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_frame *f,
                      struct xdev_ext_rel_msg *msg);
#ifdef XDEV_EXT_REL_C_GLUE
static int xsk_rel_hold_commit(struct xdev_ext_mech_stage *st, const struct xdev_ext_rel_msg *m,
 const struct xdev_ext_mech_hold_intent *hold, const struct xdev_ext_mech_frame *f);
#else
static int xsk_rel_hold_commit(struct xdev_ext_mech_stage *st,
 const struct xdev_ext_mech_hold_intent *hold, const struct xdev_ext_mech_frame *f);
#endif
static int xsk_rel_validate_initial(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b);
static int xsk_rel_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b);
static void xsk_rel_native_done(struct xsk_xdev_ext_mech_tx_batch *tb);
static void xsk_rel_dead(struct xdev_ext_mech_stage *st);
static unsigned long xsk_rx_pending_drain(struct xdev_ext_mech_stage *st, bool stopping);

/* The chunk behind @xskb, with its data at the buffer's data pointer. */
static void xsk_xdev_ext_mech_frame(struct xsk_buff_pool *xp,
			       struct xdp_buff_xsk *xskb,
			       struct xdev_ext_mech_frame *f)
{
	u64 handle = xp_get_handle(xskb, xp);
	u64 base = handle & xp->chunk_mask;

	*f = (struct xdev_ext_mech_frame) {
		.kaddr = xp->addrs + base,
		.umem_addr = base,
		.index = base >> xp->chunk_shift,
		.data_off = handle - base,
		.pool_priv = xskb,
	};
}

static void xsk_xdev_ext_mech_sock_facts(struct xdp_sock *xs,
				    struct xsk_xdev_ext_mech_sock_facts *f)
{
	struct xsk_queue *fq;

	*f = (struct xsk_xdev_ext_mech_sock_facts) {};
	f->bound = READ_ONCE(xs->state) == XSK_BOUND;
	if (!f->bound)
		return;
	fq = xs->pool->fq;
	f->zero_copy = xs->zc;
	f->unaligned = xs->pool->unaligned;
	f->owned = READ_ONCE(xs->umem->xdev_ext_mech_state);
	f->pool_users = refcount_read(&xs->pool->users);
	f->umem_users = refcount_read(&xs->umem->users);
	f->fq_entries = fq ? xskq_cons_present_entries(fq) : 0;
	f->fq_used = xs->pool->xdev_ext_mech_fq_used;
	if (xs->tx)
		f->tx_entries = READ_ONCE(xs->tx->ring->producer) -
				READ_ONCE(xs->tx->cached_cons);
	if (xs->pool->cq)
		f->cq_entries = READ_ONCE(xs->pool->cq->cached_prod) -
				READ_ONCE(xs->pool->cq->ring->consumer);
	if (xs->rx)
		f->rx_entries = READ_ONCE(xs->rx->cached_prod) -
				READ_ONCE(xs->rx->ring->consumer);
	f->chunk_size = xs->umem->chunk_size;
	f->chunks = xs->umem->chunks;
}

/* ZC means NIC DMA reaches the registered UMEM pages themselves. A valid
 * AF_XDP map may still hide SWIOTLB, so certify every permanent page map.
 */
static bool xsk_xdev_ext_mech_dma_unbounced(struct xsk_buff_pool *xp)
{
	u32 i;

	if (!xp->dev || !xp->dma_pages || xp->dma_pages_cnt != xp->umem->npgs)
		return false;
	for (i = 0; i < xp->dma_pages_cnt; i++)
		if (!dma_single_page_is_unbounced(xp->dev, xp->umem->pgs[i],
				xp->dma_pages[i] & ~XSK_NEXT_PG_CONTIG_MASK))
			return false;
	return true;
}

/*
 * CREATE, process context.  The admission and the publication of the words
 * happen under xs->mutex, which XDP_SHARED_UMEM also takes on this socket
 * (xsk_xdev_ext_mech_share_begin()), so a share either counts as a user here or
 * sees the words and fails.
 */
int xsk_xdev_ext_mech_pool_bind(struct xdev_ext_mech_pool *pool, struct file *file,
			   const struct xdev_ext_mech_layout *l)
{
	struct xsk_xdev_ext_mech_sock_facts facts;
	struct xsk_xdev_ext_mech_provider *p;
	struct socket *sock;
	struct xdp_sock *xs;
	u8 *state;
	int err;

	sock = sock_from_file(file);
	if (!sock || !sock->sk || sock->sk->sk_family != PF_XDP)
		return -ENOTSOCK;
	xs = xdp_sk(sock->sk);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	mutex_lock(&xs->mutex);
	xsk_xdev_ext_mech_sock_facts(xs, &facts);
	err = xsk_xdev_ext_mech_pool_admit(&facts, l);
	if (err)
		goto out_unlock;
	if (xs->zc && !xsk_xdev_ext_mech_dma_unbounced(xs->pool)) {
		err = -EREMOTEIO;
		goto out_unlock;
	}
	state = kvzalloc(facts.chunks, GFP_KERNEL_ACCOUNT);
	if (!state) {
		err = -ENOMEM;
		goto out_unlock;
	}

	spin_lock_init(&p->tx_lock);
	p->zc = xs->zc;
	if (p->zc) {
		p->source_first = facts.chunks / 2;
		p->source_next = p->source_first;
		if (facts.chunks - p->source_first < xdev_ext_mech_layout_frames(l)) {
			err = -ENOSPC;
			goto out_state;
		}
		p->ring.capacity = roundup_pow_of_two(facts.chunks);
		p->slots = kvcalloc(p->ring.capacity, sizeof(*p->slots), GFP_KERNEL);
		if (!p->slots) {
			err = -ENOMEM;
			goto out_state;
		}
		memset(state + p->source_first, XDEV_EXT_MECH_F_K_FREE,
		       facts.chunks - p->source_first);
	}
	/* Allocators and the legacy CQ reservation see admission atomically. */
	xp_xdev_ext_mech_alloc_lock(xs->pool);
	spin_lock(&xs->pool->cq_lock);
	xsk_xdev_ext_mech_sock_facts(xs, &facts);
	err = xsk_xdev_ext_mech_pool_admit(&facts, l);
	if (err) {
		spin_unlock(&xs->pool->cq_lock);
		xp_xdev_ext_mech_alloc_unlock(xs->pool);
		goto out_state;
	}
	p->file = get_file(file);
	p->xs = xs;
	p->xp = xs->pool;
	p->has_rx = !!xs->rx;
	*pool = (struct xdev_ext_mech_pool) {
		.ops = &xsk_xdev_ext_mech_pool_ops,
		.priv = p,
		.state = state,
		.pages = xs->umem->pgs,
		.vaddr = xs->umem->addrs,
		.size = xs->umem->size,
		.kind = XDEV_EXT_MECH_POOL_XSK,
		.capabilities = p->zc ? XDEV_EXT_BINDING_CAP_ZERO_COPY |
				       XDEV_EXT_BINDING_CAP_ASYNC : 0,
		.frame_size = xs->umem->chunk_size,
		.nr_frames = xs->umem->chunks,
		.nr_pages = xs->umem->npgs,
	};
	/* From here the fill-ring check and XDP_SHARED_UMEM see the session. */
	smp_store_release(&xs->umem->xdev_ext_mech_state, state);
	if (p->zc)
		rcu_assign_pointer(xs->pool->xdev_ext_mech_tx, p);
	spin_unlock(&xs->pool->cq_lock);
	xp_xdev_ext_mech_alloc_unlock(xs->pool);
	mutex_unlock(&xs->mutex);
	return 0;

out_state:
	kvfree(p->slots);
	kvfree(state);
out_unlock:
	mutex_unlock(&xs->mutex);
	kfree(p);
	return err;
}

/*
 * Session worker.  Only a pool without an RX path backs source batches, so
 * the worker is its only allocator: xp_alloc() splices recycled frames, then
 * takes free_list and fill-ring frames, refusing any the session owns.
 * Either all @nr frames move to HELD or none does.
 */
static int xsk_xdev_ext_mech_pool_alloc(struct xdev_ext_mech_pool *pool,
				   struct xdev_ext_mech_frame *f, u32 nr)
{
	struct xsk_xdev_ext_mech_provider *p = pool->priv;
	struct xsk_buff_pool *xp = p->xp;
	u32 i;
	int err;

	if (p->zc) {
		u32 scanned = 0, at = p->source_next;

		for (i = 0; i < nr; ) {
			if (scanned++ == pool->nr_frames - p->source_first)
				break;
			if (!xdev_ext_mech_frame_move(&pool->state[at],
					XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_HELD)) {
				f[i] = (struct xdev_ext_mech_frame) { .index = at };
				xsk_xdev_ext_mech_pool_resolve(pool, &f[i++]);
			}
			if (++at == pool->nr_frames)
				at = p->source_first;
		}
		p->source_next = at;
		if (i == nr)
			return 0;
		while (i--)
			xdev_ext_mech_frame_move(&pool->state[f[i].index],
					    XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE);
		return -ENOSPC;
	}
	err = xsk_xdev_ext_mech_source_ok(p->has_rx);
	if (err)
		return err;
	for (i = 0; i < nr; i++) {
		struct xdp_buff *xdp = xp_alloc(xp);
		u8 *word;

		if (!xdp) {
			err = -ENOSPC;
			break;
		}
		xsk_xdev_ext_mech_frame(xp, container_of(xdp, struct xdp_buff_xsk,
						    xdp), &f[i]);
		f[i].data_off = 0;
		/* free_list frames are K_FREE, fill-ring frames USER */
		word = &pool->state[f[i].index];
		err = xdev_ext_mech_frame_move(word, xdev_ext_mech_frame_state(word),
					  XDEV_EXT_MECH_F_HELD);
		if (WARN_ON_ONCE(err))
			break;	/* someone owns frame i: leave it alone */
	}
	__xskq_cons_release(xp->fq);
	if (!err)
		return 0;
	while (i--) {
		WARN_ON_ONCE(xdev_ext_mech_frame_move(&pool->state[f[i].index],
						 XDEV_EXT_MECH_F_HELD,
						 XDEV_EXT_MECH_F_K_FREE));
		xp_free(f[i].pool_priv);
	}
	return err;
}

/* Session worker. */
static int xsk_xdev_ext_mech_pool_resolve(struct xdev_ext_mech_pool *pool,
				     struct xdev_ext_mech_frame *f)
{
	struct xsk_xdev_ext_mech_provider *p = pool->priv;

	if (f->index >= pool->nr_frames)
		return -ERANGE;
	f->umem_addr = (u64)f->index * pool->frame_size;
	f->kaddr = pool->vaddr + f->umem_addr;
	f->pool_priv = &p->xp->heads[f->index];
	return 0;
}

/*
 * Any context, never sleeps and never takes pool->rx_lock: an RX complete
 * may recycle under that lock, and the native receive path holds none.
 */
static void xsk_xdev_ext_mech_pool_recycle(struct xdev_ext_mech_pool *pool,
				      struct xdev_ext_mech_frame *f)
{
	struct xsk_xdev_ext_mech_provider *p = pool->priv;

	if (WARN_ON_ONCE(f->index >= pool->nr_frames))
		return;
	if (p->zc && f->index >= p->source_first)
		return; /* the source partition has its own allocator */
	llist_add(&p->xp->heads[f->index].xdev_ext_mech_node,
		  &p->xp->xdev_ext_mech_recycle);
}

/*
 * Process context, after drain; never for a quarantined pool.  Recycled
 * frames still on the llist rejoin free_list at the next allocation.
 */
static void xsk_xdev_ext_mech_pool_release(struct xdev_ext_mech_pool *pool)
{
	struct xsk_xdev_ext_mech_provider *p = pool->priv;
	struct xdp_sock *xs = p->xs;

	mutex_lock(&xs->mutex);
	xp_xdev_ext_mech_alloc_lock(p->xp);
	rcu_assign_pointer(p->xp->xdev_ext_mech_tx, NULL);
	WRITE_ONCE(xs->umem->xdev_ext_mech_state, NULL);
	xp_xdev_ext_mech_alloc_unlock(p->xp);
	mutex_unlock(&xs->mutex);
	/* RX and the fill-ring check read the words under RCU. */
	synchronize_net();
	kvfree(pool->state);
	pool->state = NULL;
	kvfree(p->slots);
	fput(p->file);
	kfree(p);
	pool->priv = NULL;
}

/* Permanent NIC mapping: return ownership to CPU before CPU or NVMe access.
 * NVMe maps these same pages independently for its own device.
 */
static void xsk_xdev_ext_mech_sync_for_cpu_batch(struct xdev_ext_mech_pool *pool,
					  const struct xdev_ext_mech_frame *f,
					  u32 nr)
{
	struct xsk_xdev_ext_mech_provider *p = pool->priv;
	unsigned long flags;
	u32 i;

	if (!p->zc || !nr)
		return;
	spin_lock_irqsave(&p->tx_lock, flags);
	/* pool_dead serializes here before xp_dma_unmap frees dma_pages. */
	if (!p->stopped && p->xp->dev && p->xp->dma_pages) {
		for (i = 0; i < nr; i++)
			dma_sync_single_for_cpu(p->xp->dev,
				xp_raw_get_dma(p->xp, f[i].umem_addr),
				pool->frame_size, DMA_BIDIRECTIONAL);
	}
	spin_unlock_irqrestore(&p->tx_lock, flags);
}

static void xsk_xdev_ext_mech_sync_for_cpu(struct xdev_ext_mech_pool *pool,
				    const struct xdev_ext_mech_frame *f)
{
	xsk_xdev_ext_mech_sync_for_cpu_batch(pool, f, 1);
}

static const struct xdev_ext_mech_pool_ops xsk_xdev_ext_mech_pool_ops = {
	.sync_for_cpu = xsk_xdev_ext_mech_sync_for_cpu,
	.sync_for_cpu_batch = xsk_xdev_ext_mech_sync_for_cpu_batch,
	.alloc = xsk_xdev_ext_mech_pool_alloc,
	.resolve = xsk_xdev_ext_mech_pool_resolve,
	.recycle = xsk_xdev_ext_mech_pool_recycle,
	.release = xsk_xdev_ext_mech_pool_release,
};

/*
 * xsk_bind(), XDP_SHARED_UMEM onto @umem_xs, process context: hold
 * @umem_xs->mutex until the share is counted, so it serializes with
 * xsk_xdev_ext_mech_pool_bind() on the same socket.
 */
int xsk_xdev_ext_mech_share_begin(struct xdp_sock *umem_xs)
{
	int err;

	mutex_lock_nested(&umem_xs->mutex, SINGLE_DEPTH_NESTING);
	err = xsk_xdev_ext_mech_share_check(READ_ONCE(umem_xs->umem->xdev_ext_mech_state));
	if (err)
		mutex_unlock(&umem_xs->mutex);
	return err;
}

void xsk_xdev_ext_mech_share_end(struct xdp_sock *umem_xs)
{
	mutex_unlock(&umem_xs->mutex);
}

/* RX_GENERIC/RX_NATIVE, pool->rx_lock held: the stage's rx_info is ours to rewrite. */
static int xsk_xdev_ext_mech_rx_call(struct xdev_ext_mech_stage *st,
				struct xsk_xdev_ext_mech_stage *xst,
				const struct xdev_ext_mech_frame *f, u32 callsite,
				s32 *ret, struct xdev_ext_mech_hold_intent *hold,
				const struct xdev_ext_afxdp_rx_hold_cqe *result)
{
	struct xdp_desc desc = {
		.addr = f->umem_addr + f->data_off,
		.len = f->data_len,
	};
	struct xdev_ext_binding_ctx_v2 base =
		xdev_ext_binding_make_afxdp_rx_ctx(desc.addr, desc.len,
			xst->xs->zc ? XDEV_EXT_BINDING_CAP_ZERO_COPY : 0);
	struct xdev_ext_mech_call_args a = {
		.member = XDEV_EXT_MECH_MEMBER_COMPLETE,
		.callsite = callsite,
		.base = &base,
		.frames = result ? NULL : f,
		.nr_frames = result ? 0 : 1,
		.info_size = sizeof(xst->rx_info),
		.info = &xst->rx_info,
		.cqe = result ? (const void *)result : &desc,
		.cqe_size = result ? sizeof(*result) : sizeof(desc),
		.cqe_cap = 1,
	};

	base.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	base.chain_id = xdev_ext_mech_session_id(st->s);
	xst->rx_info.base.nr_frames = result ? 0 : 1;
	xst->rx_info.base.f[0] = (struct xdev_ext_mech_frame_info) {};
	if (result) {
		base.src_offset = 0;
		base.length = 0;
	} else {
		xst->rx_info.base.f[0].umem_addr = f->umem_addr;
		xst->rx_info.base.f[0].data_off = f->data_off;
		xst->rx_info.base.f[0].data_len = f->data_len;
	}
	return xdev_ext_mech_call(st, &a, ret, hold);
}

#include "xsk_xdev_ext_mech_rx_pending.inc"

/*
 * __xsk_rcv() or xsk_rcv_zc(), single-buffer branch, before
 * any RX reservation.  HOLD: the frame went into the session's OPEN batch
 * and gets no RX descriptor; RECYCLE: it went back to the kernel partition
 * through the recycle llist; PUBLISH: the caller reserves it as usual.
 * Pending legacy holds use their own short ownership lock; no free_list access.
 */
int xsk_xdev_ext_mech_rx(struct xdp_sock *xs, struct xdp_buff_xsk *xskb, u32 len,
		    u32 callsite)
{
	struct xdev_ext_mech_stage *st = smp_load_acquire(&xs->xdev_ext_mech_rx);
	struct xdev_ext_mech_hold_intent hold = {};
	struct xsk_xdev_ext_mech_stage *xst;
	s32 ret = XDEV_EXT_MECH_PUBLISH;
	struct xdev_ext_mech_frame f;
 struct xdev_ext_rel_msg reliable_msg = {};
 int reliable_action = 0;
	bool perr, npub, ran;
	int disp, err = 0;

	if (!st) {
  st = smp_load_acquire(&xs->xdev_ext_mech_tx);
  if (!st || !((struct xsk_xdev_ext_mech_stage *)st->priv)->rel)
   return XDEV_EXT_MECH_PUBLISH;
 }
	xst = st->priv;
	xsk_xdev_ext_mech_frame(xs->pool, xskb, &f);
	if (xsk_rx_pending_owned(st, f.index)) {
		xdev_ext_mech_stage_dead(st, -EPROTO);
		return XDEV_EXT_MECH_HOLD;
	}
	f.data_len = len;
 if (xst->rel) {
  reliable_action = xsk_rel_rx(st, &f, &reliable_msg);
  if (reliable_action != XDEV_EXT_REL_HOLD) {
   xdev_ext_mech_frame_recycle(st->s, &f);
   return XDEV_EXT_MECH_RECYCLE;
  }
 }
	ran = xsk_xdev_ext_mech_rx_runs(callsite, !READ_ONCE(xst->dead) &&
				   xdev_ext_mech_session_admits(st->s), xs->zc);
	if (ran)
		err = xsk_xdev_ext_mech_rx_call(st, xst, &f, callsite, &ret, &hold, NULL);
	disp = xsk_xdev_ext_mech_rx_verdict(callsite, ran, err, ret, &hold,
				       f.data_off, f.data_len, &perr, &npub);
	if (disp == XDEV_EXT_MECH_HOLD) {
		struct xdev_ext_afxdp_rx_hold_cqe result = {
			.key = hold.key,
			.pos = hold.pos,
		};

#ifdef XDEV_EXT_REL_C_GLUE
		if (xst->rel && (hold.key != reliable_msg.group ||
      hold.pos != reliable_msg.index || hold.count != reliable_msg.count ||
      hold.span_off != f.data_off + 106 || hold.span_len != reliable_msg.payload_len))
   result.err = -EPROTO;
  else if (xst->rel)
   result.err = xsk_rel_hold_commit(st, &reliable_msg, &hold, &f);
#else
  if (xst->rel) result.err=xsk_rel_hold_commit(st,&hold,&f);
#endif
  else
   result.err = xst->pending.entries ? xsk_rx_pending_add(st, &hold, &f) :
       xdev_ext_mech_hold_commit(st, &hold, &f);
		if (!result.err && (xst->rel || !xst->pending.entries)) {
			xdev_ext_mech_count(st->s, xdev_ext_mech_nic_ops_counter(xs->zc), 1);
			xdev_ext_mech_count(st->s, xdev_ext_mech_nic_bytes_counter(xs->zc), hold.span_len);
		}
		/* Still under the RX lock: no other packet can replace the candidate. */
		ret = XDEV_EXT_MECH_ABORT;
		err = xsk_xdev_ext_mech_rx_call(st, xst, &f,
					   XDEV_EXT_MECH_SITE_RX_HOLD_RESULT,
					   &ret, NULL, &result);
		disp = xsk_xdev_ext_mech_rx_hold_result(result.err, err, ret, &perr);
		/* A duplicate RX identity cannot free its earlier pending owner. */
		if (result.err == -EALREADY)
			disp = XDEV_EXT_MECH_HOLD;
		if (perr)
			xdev_ext_mech_stage_dead(st, -EPROTO);
	}
	if (npub)
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_NATIVE_PUBLISH, 1);
	if (perr)
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
	if (disp == XDEV_EXT_MECH_RECYCLE)
		xdev_ext_mech_frame_recycle(st->s, &f);
	return disp;
}

void __xsk_xdev_ext_mech_rx_settle(struct xdp_sock *xs, struct xdp_buff_xsk *xskb,
			      u8 *state, bool to_user)
{
	struct xdev_ext_mech_frame f;
	u32 from, to;
	int edge;

	xsk_xdev_ext_mech_frame(xs->pool, xskb, &f);
	edge = xsk_xdev_ext_mech_settle_edge(xdev_ext_mech_frame_state(&state[f.index]),
					to_user, &from, &to);
	if (edge > 0)
		edge = xdev_ext_mech_frame_move(&state[f.index], from, to);
	WARN_ON_ONCE(edge < 0);
}

/* RX/flush context under RCU, after the descriptors become user-visible. */
void xsk_xdev_ext_mech_rx_published(struct xdp_sock *xs, u32 nr)
{
	struct xdev_ext_mech_stage *st = smp_load_acquire(&xs->xdev_ext_mech_rx);

	if (st && nr)
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_PUBLISHED, nr);
}

/* Worker, or CREATE with @b NULL; never sleeps. */
static void xsk_xdev_ext_mech_fill_info(struct xdev_ext_mech_stage *st,
				   struct xdev_ext_mech_batch *b, void *info)
{
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	struct xdev_ext_afxdp_mech_info *in = info;
	u32 i, nr = b ? xdev_ext_mech_batch_nr_frames(b) : 0;
	struct xdev_ext_mech_frame f;

	memset(info, 0, sizeof(struct xdev_ext_afxdp_reliable_info));
	in->l = *xdev_ext_mech_session_layout(st->s);
	in->mtu = xst->mtu;
	in->peer = *xdev_ext_mech_session_peer(st->s);
	for (i = 0; i < nr && i < XDEV_EXT_MECH_MAX_FRAMES; i++) {
		if (xdev_ext_mech_batch_frame(b, i, &f))
			break;
		in->f[i].umem_addr = f.umem_addr;
		in->f[i].data_off = f.data_off;
		in->f[i].data_len = f.data_len;
	}
	in->nr_frames = i;
 if (xst->rel) xsk_rel_info(st, b, info);
}

/*
 * CREATE, polled stage: NAPI can keep the device interrupt masked while the
 * session worker keeps busy-polling, which needs napi_defer_hard_irqs and
 * gro_flush_timeout on the instance (Documentation/networking/napi.rst,
 * "Busy polling").  Without them interrupts would still deliver.
 */
static bool xsk_mech_poll_napi_ok(const struct napi_struct *napi)
{
	return napi && napi_id_valid(napi->napi_id) &&
	       READ_ONCE(napi->defer_hard_irqs) && READ_ONCE(napi->gro_flush_timeout);
}

/*
 * CREATE, polled stage, before xs->mutex (RTNL comes first, as in
 * xsk_bind()): the NAPI instances of the socket's queue, receive first.  A
 * zero-copy transmit stage completes in the NAPI the driver registered for
 * its transmit queue: that instance must be known and either the receive one
 * or busy-pollable itself.  A transmit-only instance (netif_napi_add_tx(),
 * NAPI_STATE_NO_BUSY_POLL, e.g. virtio-net) has no NAPI id and is refused.
 * A copy-mode transmit stage without the reliable protocol completes inside
 * ->submit, so it has nothing to poll; a reliable one waits for ACKs that the
 * receive NAPI delivers.  -EOPNOTSUPP refuses; nothing is changed then.
 */
static int xsk_mech_poll_bind(struct xsk_xdev_ext_mech_stage *xst, struct xdp_sock *xs,
			      bool tx, bool reliable)
{
#ifdef CONFIG_NET_RX_BUSY_POLL
	struct napi_struct *rx = NULL, *txn = NULL;
	bool zc_tx = tx && xs->zc;
	struct net_device *dev;
	int err = -EOPNOTSUPP;
	u32 qid;

	if (tx && !xs->zc && !reliable)
		return -EOPNOTSUPP;
	rtnl_lock();
	dev = READ_ONCE(xs->state) == XSK_BOUND ? xs->dev : NULL;
	qid = xs->queue_id;
	if (dev && qid < dev->real_num_rx_queues)
		rx = __netif_get_rx_queue(dev, qid)->napi;
	if (dev && zc_tx && qid < dev->real_num_tx_queues)
		txn = netdev_get_tx_queue(dev, qid)->napi;
	if (xsk_mech_poll_napi_ok(rx) &&
	    (!zc_tx || txn == rx || xsk_mech_poll_napi_ok(txn))) {
		xst->poll_napi[0] = rx->napi_id;
		xst->nr_poll_napi = 1;
		if (zc_tx && txn != rx)
			xst->poll_napi[xst->nr_poll_napi++] = txn->napi_id;
		err = 0;
	}
	rtnl_unlock();
	return err;
#else
	return -EOPNOTSUPP;
#endif
}

/*
 * Session worker, polled stage: one preferred busy-poll pass of each NAPI
 * instance.  Received frames and transmit completions are processed here,
 * through the same RX and completion paths an interrupt-driven NAPI runs.
 */
static int xsk_mech_poll(struct xdev_ext_mech_stage *st)
{
#ifdef CONFIG_NET_RX_BUSY_POLL
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	u32 i;

	for (i = 0; i < xst->nr_poll_napi; i++)
		napi_busy_loop(xst->poll_napi[i], NULL, NULL, true, BUSY_POLL_BUDGET);
#endif
	return 0;
}

/*
 * CREATE, process context.  Both directions sit on the very socket whose
 * UMEM backs the session's xsk pool: the RX stage is the session's source,
 * stage 0; a TX stage uses the kernel source for zero-copy and
 * xsk_kernel_xmit() for copy compatibility. A TX ring selects a driver TX
 * queue, but the zero-copy mechanism never produces into that shared ring.
 */
static int xsk_xdev_ext_mech_bind(struct xdev_ext_mech_stage *st,
			     const struct xdev_ext_mech_stage_uapi *u)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	bool tx = st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE;
	struct xsk_xdev_ext_mech_provider *p;
	struct xsk_xdev_ext_mech_stage *xst;
	struct socket *sock;
	struct xdp_sock *xs;
	int err;

	if ((u->flags & ~(XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) ||
	    ((u->flags & (XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) &&
	     !(u->flags & XDEV_EXT_AFXDP_F_RELIABLE)))
		return -EINVAL;
	sock = sock_from_file(st->file);
	if (!sock || !sock->sk || sock->sk->sk_family != PF_XDP)
		return -ENOTSOCK;
	xs = xdp_sk(sock->sk);
	if (!pool || pool->ops != &xsk_xdev_ext_mech_pool_ops)
		return -EINVAL;
	p = pool->priv;
	if (p->xs != xs)
		return -EINVAL;

	xst = kzalloc(sizeof(*xst), GFP_KERNEL);
	if (!xst)
		return -ENOMEM;
	xst->xs = xs;
	xst->sock = sock;
	spin_lock_init(&xst->pending.lock);
	if (!tx && !(u->flags & XDEV_EXT_AFXDP_F_RELIABLE)) {
		u32 rx_frames = p->zc ? p->source_first : pool->nr_frames;
		u64 reserved = (u64)xdev_ext_mech_session_depth(st->s) *
			xdev_ext_mech_layout_frames(xdev_ext_mech_session_layout(st->s));

		/* Reserve the active window and one RX frame. Exhaustion is
		 * observed while a native buffer is still available to fail-stop.
		 * Capacity depends on the registered pool, never campaign length.
		 */
		if (rx_frames <= reserved + 1) {
			kfree(xst);
			return -ENOSPC;
		}
		xst->pending.capacity = rx_frames - reserved - 1;
		xst->pending.entries = kvcalloc(pool->nr_frames,
					sizeof(*xst->pending.entries), GFP_KERNEL);
		if (!xst->pending.entries) {
			kfree(xst);
			return -ENOMEM;
		}
	}
	if (tx) {
		xst->tx_nr_sent = pool->nr_frames;
		xst->tx_sent = kvcalloc(pool->nr_frames, sizeof(*xst->tx_sent),
					GFP_KERNEL);
		if (!xst->tx_sent) {
			kfree(xst);
			return -ENOMEM;
		}
	}
	if (st->poll) {
		err = xsk_mech_poll_bind(xst, xs, tx, u->flags & XDEV_EXT_AFXDP_F_RELIABLE);
		if (err) {
			kvfree(xst->pending.entries);
			kvfree(xst->tx_sent);
			kfree(xst);
			return err;
		}
	}

	mutex_lock(&xs->mutex);
	err = xsk_xdev_ext_mech_stage_check(st->direction, st->index,
				       READ_ONCE(xs->state) == XSK_BOUND,
				       tx ? xs->tx : xs->rx,
				       tx ? xs->xdev_ext_mech_tx : xs->xdev_ext_mech_rx);
	if (!err) {
		xst->mtu = READ_ONCE(xs->dev->mtu);
		st->priv = xst;
  if (u->flags & XDEV_EXT_AFXDP_F_RELIABLE) {
   err = xsk_rel_bind(st, u);
   if (err) { st->priv = NULL; goto bind_unlock; }
  }
		/* Reliable TX receives control packets through the RX callback too. */
		xsk_xdev_ext_mech_fill_info(st, NULL, &xst->rx_info);
		xst->rx_info.base.nr_frames = 1;
		if (tx) {
			smp_store_release(&xs->xdev_ext_mech_tx, st);
		} else {
			/* RX dereferences st->priv after it sees the stage. */
			smp_store_release(&xs->xdev_ext_mech_rx, st);
		}
	}
bind_unlock:
	mutex_unlock(&xs->mutex);
	if (err) {
		kvfree(xst->pending.entries);
		kvfree(xst->tx_sent);
		kfree(xst);
	}
	return err;
}

/* After drain, process context. */
static void xsk_xdev_ext_mech_unbind(struct xdev_ext_mech_stage *st)
{
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	struct xdp_sock *xs = xst->xs;

	mutex_lock(&xs->mutex);
	if (xs->xdev_ext_mech_rx == st)
		WRITE_ONCE(xs->xdev_ext_mech_rx, NULL);
	if (xs->xdev_ext_mech_tx == st)
		WRITE_ONCE(xs->xdev_ext_mech_tx, NULL);
	mutex_unlock(&xs->mutex);
	/* RX reads its stage under RCU. */
	synchronize_net();
	xsk_rx_pending_drain(st, true);
	kvfree(xst->pending.entries);
	xsk_rel_unbind(st);
	st->priv = NULL;
	kvfree(xst->tx_sent);
	kfree(xst);
}

/*
 * Session worker: a TX build's descriptors against the batch frames and the
 * session peer (xsk_xdev_ext_mech_tx_validate()).  An accepted batch is staged
 * for the ->submit that follows in the same worker.
 */
static int xsk_xdev_ext_mech_validate(struct xdev_ext_mech_stage *st,
				 struct xdev_ext_mech_batch *b, const u8 *scratch,
				 u32 n)
{
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	u32 i, nr = xdev_ext_mech_batch_nr_frames(b);
	struct xsk_xdev_ext_mech_tx_bounds bd;
	struct xdev_ext_mech_frame f;
	int err;

	xst->tx_staged = NULL;
	if (st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE)
		return -EOPNOTSUPP;
	if (nr > XDEV_EXT_MECH_MAX_FRAMES)
		return -E2BIG;
	for (i = 0; i < nr; i++) {
		err = xdev_ext_mech_batch_frame(b, i, &f);
		if (err)
			return err;
		if (f.index >= xst->tx_nr_sent)
			return -ERANGE;
		xst->tx_fi[i] = (struct xdev_ext_mech_frame_info) {
			.umem_addr = f.umem_addr,
			.data_off = f.data_off,
			.data_len = f.data_len,
		};
		xst->tx_kaddr[i] = f.kaddr;
		xst->tx_tag[i] = &xst->tx_sent[f.index];
	}
	bd = (struct xsk_xdev_ext_mech_tx_bounds) {
		.hdr_room = xdev_ext_mech_session_layout(st->s)->hdr_room,
		.mtu = xst->mtu,
		.peer = *xdev_ext_mech_session_peer(st->s),
	};
	err = xsk_xdev_ext_mech_tx_validate(scratch, n, xst->tx_fi,
				       (const u8 *const *)xst->tx_kaddr, nr,
				       &bd, xst->tx_desc);
	if (err)
		return err;
	for (i = 0; i < n; i++)
		xst->tx_pkt[i] = xst->tx_kaddr[i] +
				 (xst->tx_desc[i].addr - xst->tx_fi[i].umem_addr);
	xst->tx_n = n;
 if (xst->rel) {
  err=xsk_rel_validate_initial(st,b);
  if (err) return err;
 }
	xst->tx_staged_id = xdev_ext_mech_batch_id(b);
	xst->tx_staged = b;
	return 0;
}

/* Session worker, one frame: the header fields only C writes, then the send. */
static int xsk_xdev_ext_mech_tx_xmit(void *arg, u32 slot)
{
	struct xsk_xdev_ext_mech_stage *xst = arg;
	const struct xdp_desc *d = &xst->tx_desc[slot];
	struct xdev_ext_mech_stage *st = READ_ONCE(xst->xs->xdev_ext_mech_tx);
	int err;

	/* After mark_dead nothing more goes to the device. */
	if (READ_ONCE(xst->dead))
		return -ENXIO;
	xsk_xdev_ext_mech_tx_finish(xst->tx_pkt[slot]);
	/* xsk_kernel_xmit() returns the frame length once the device has it. */
	err = xsk_kernel_xmit(xst->sock, d->addr, d->len, d->options);
	if (err < 0)
		return err;
	if (st) {
		xdev_ext_mech_count(st->s, xdev_ext_mech_nic_ops_counter(xst->xs->zc), 1);
		xdev_ext_mech_count(st->s, xdev_ext_mech_nic_bytes_counter(xst->xs->zc),
				    xst->tx_fi[slot].data_len);
	}
	return 0;
}

/* A completion owns the batch until it has left this local list. */
static void xsk_mech_zc_done(struct list_head *done)
{
	struct xsk_xdev_ext_mech_tx_batch *tb, *next;

	list_for_each_entry_safe(tb, next, done, done) {
		struct xdev_ext_mech_batch *b = tb->batch;
		u64 ticket = tb->ticket;
		int status = tb->native_error ?: tb->completion.status;
		bool uncertain = tb->completion.uncertain;

		list_del_init(&tb->done);
  if (tb->reliable_stage) {
   xsk_rel_native_done(tb);
   continue;
  }
		if (uncertain)
			xdev_ext_mech_batch_sequester(b, ticket, status ?: -ENXIO);
		else if (tb->cancelled_before_native && !tb->native_error)
			xdev_ext_mech_batch_complete_cancelled(b, ticket, status);
		else
			xdev_ext_mech_batch_complete(b, ticket, status);
	}
}

/* tx_lock held. No batch callback runs with this lock held. */
static void xsk_mech_zc_retire(struct xsk_xdev_ext_mech_provider *p, u32 at,
			     int result, struct list_head *done)
{
	struct xsk_mech_zc_slot *slot = &p->slots[at];
	struct xsk_xdev_ext_mech_tx_batch *tb = slot->batch;

	if (slot->state == XSK_MECH_ZC_DONE)
		return;
	if (slot->state == XSK_MECH_ZC_NATIVE && !result &&
	    slot->owner == XSK_MECH_ZC_DATA && tb->batch) {
		struct xdev_ext_mech_frame f;

		if (!xdev_ext_mech_batch_frame(tb->batch, slot->slot, &f)) {
			struct xdev_ext_mech_session *s = xdev_ext_mech_batch_session(tb->batch);

			xdev_ext_mech_count(s, xdev_ext_mech_nic_ops_counter(p->zc), 1);
			xdev_ext_mech_count(s, xdev_ext_mech_nic_bytes_counter(p->zc), f.data_len);
		}
	}
	if (slot->state == XSK_MECH_ZC_NATIVE)
		xsk_mech_zc_mark_done(&p->ring, p->slots, at);
	else
		slot->state = XSK_MECH_ZC_DONE;
	if (xsk_mech_zc_retire_result(&tb->completion, result,
				    &tb->err[slot->slot]))
		list_add_tail(&tb->done, done);
}

/* A failed wakeup guarantees nothing about already-issued descriptors. Cancel
 * only the never-issued suffix; the caller must retain or quarantine the
 * accepted prefix until hardware ownership is resolved.
 */
static void xsk_mech_zc_cancel_pending(struct xsk_xdev_ext_mech_provider *p, int result)
{
	LIST_HEAD(done);
	unsigned long flags;
	u32 i;

	spin_lock_irqsave(&p->tx_lock, flags);
	/* Latch before callbacks or another worker can admit more descriptors. */
	p->stopped = true;
	for (i = p->ring.issued; i != p->ring.prod; i++) {
		struct xsk_mech_zc_slot *slot = &p->slots[i & (p->ring.capacity - 1)];
		struct xsk_xdev_ext_mech_tx_batch *tb = slot->batch;
		/* Mark every never-issued suffix, DATA included. A genuine result
		 * from an accepted prefix is retained separately in native_error,
		 * so even native ECANCELED cannot be mistaken for this cancellation. */
		tb->cancelled_before_native = true;

		if (p->xp->dev && p->xp->dma_pages)
			dma_sync_single_for_cpu(p->xp->dev,
				xp_raw_get_dma(p->xp, slot->desc.addr), slot->desc.len,
				DMA_BIDIRECTIONAL);
		xsk_mech_zc_retire(p, i & (p->ring.capacity - 1), result, &done);
	}
	p->ring.issued = p->ring.prod;
	xsk_mech_zc_reclaim(&p->ring, p->slots);
	spin_unlock_irqrestore(&p->tx_lock, flags);
	xsk_mech_zc_done(&done);
}

/* Detach is not proof of DMA completion. Pin any accepted frame forever;
 * descriptors which never left the kernel source can safely be cancelled.
 */
static void xsk_mech_zc_stop(struct xsk_xdev_ext_mech_provider *p, int result)
{
	LIST_HEAD(done);
	unsigned long flags;
	u32 i;

	spin_lock_irqsave(&p->tx_lock, flags);
	p->stopped = true;
	xsk_mech_zc_fail(&p->ring, result);
	for (i = p->ring.cons; i != p->ring.prod; i++) {
		struct xsk_mech_zc_slot *slot = &p->slots[i & (p->ring.capacity - 1)];
		struct xsk_xdev_ext_mech_tx_batch *tb = slot->batch;

		if (slot->state == XSK_MECH_ZC_NATIVE)
			tb->completion.uncertain = true;
	}
	for (i = p->ring.cons; i != p->ring.prod; i++) {
		struct xsk_mech_zc_slot *slot = &p->slots[i & (p->ring.capacity - 1)];

		if (slot->state == XSK_MECH_ZC_PENDING && p->xp->dev && p->xp->dma_pages)
			dma_sync_single_for_cpu(p->xp->dev,
				xp_raw_get_dma(p->xp, slot->desc.addr), slot->desc.len,
				DMA_BIDIRECTIONAL);
		if (slot->state != XSK_MECH_ZC_DONE)
			xsk_mech_zc_retire(p, i & (p->ring.capacity - 1), result, &done);
	}
	p->ring.cons = p->ring.issued = p->ring.prod;
	spin_unlock_irqrestore(&p->tx_lock, flags);
	xsk_mech_zc_done(&done);
}

void xsk_xdev_ext_mech_pool_dead(struct xsk_buff_pool *pool)
{
	struct xsk_xdev_ext_mech_provider *p;

	rcu_read_lock();
	p = rcu_dereference(pool->xdev_ext_mech_tx);
	if (p)
		xsk_mech_zc_stop(p, -ENXIO);
	rcu_read_unlock();
}

int xsk_xdev_ext_mech_tx_peek(struct xsk_buff_pool *pool, struct xdp_desc *desc)
{
	struct xsk_xdev_ext_mech_provider *p;
	unsigned long flags;
	int at, ret = -EOPNOTSUPP;

	rcu_read_lock();
	p = rcu_dereference(pool->xdev_ext_mech_tx);
	if (p) {
		spin_lock_irqsave(&p->tx_lock, flags);
		at = p->stopped ? -ENOENT : xsk_mech_zc_peek(&p->ring, p->slots);
		if (at >= 0)
			*desc = p->slots[at].desc;
		ret = at >= 0;
		spin_unlock_irqrestore(&p->tx_lock, flags);
	}
	rcu_read_unlock();
	return ret;
}

int xsk_xdev_ext_mech_tx_batch(struct xsk_buff_pool *pool, u32 n)
{
	struct xsk_xdev_ext_mech_provider *p;
	unsigned long flags;
	int at, ret = -EOPNOTSUPP;

	rcu_read_lock();
	p = rcu_dereference(pool->xdev_ext_mech_tx);
	if (p) {
		spin_lock_irqsave(&p->tx_lock, flags);
		n = min(n, pool->tx_descs_capacity);
		ret = 0;
		while (!p->stopped && ret < n) {
			at = xsk_mech_zc_peek(&p->ring, p->slots);
			if (at < 0)
				break;
			pool->tx_descs[ret++] = p->slots[at].desc;
		}
		spin_unlock_irqrestore(&p->tx_lock, flags);
	}
	rcu_read_unlock();
	return ret;
}

/* Driver counts are native descriptors, never user CQ reservations. */
int xsk_xdev_ext_mech_tx_complete(struct xsk_buff_pool *pool, u32 n, int result,
			    bool tail, bool set_only)
{
	struct xsk_xdev_ext_mech_provider *p;
	struct xdev_ext_mech_stage *failed_stage = NULL;
	LIST_HEAD(done);
	unsigned long flags;
	int at, ret = -EOPNOTSUPP;
	int fatal = 0;
	u32 i;

	rcu_read_lock();
	p = rcu_dereference(pool->xdev_ext_mech_tx);
	if (!p)
		goto out;
	spin_lock_irqsave(&p->tx_lock, flags);
	if (n > xsk_mech_zc_native(&p->ring, p->slots)) {
		/* An unmatched hardware count is ambiguous: do not recycle. */
		p->stopped = true;
		at = xsk_mech_zc_complete(&p->ring, p->slots);
		if (at >= 0) {
			struct xsk_xdev_ext_mech_tx_batch *tb = p->slots[at].batch;

			failed_stage = tb->reliable_stage;
		}
		if (!failed_stage)
			failed_stage = READ_ONCE(p->xs->xdev_ext_mech_rx);
		if (!failed_stage)
			failed_stage = READ_ONCE(p->xs->xdev_ext_mech_tx);
		spin_unlock_irqrestore(&p->tx_lock, flags);
		xsk_mech_zc_stop(p, -EPROTO);
		if (failed_stage)
			xdev_ext_mech_stage_dead(failed_stage, -EPROTO);
		ret = -EPROTO;
		goto out;
	}
	at = tail ? xsk_mech_zc_tail(&p->ring, p->slots, 0) :
		    xsk_mech_zc_complete(&p->ring, p->slots);
	for (i = 0; i < n; i++) {
		struct xsk_mech_zc_slot *slot;
		struct xsk_xdev_ext_mech_tx_batch *tb;
		u32 next;

		slot = &p->slots[at];
		tb = slot->batch;
		if (tb->reliable_stage)
			failed_stage = tb->reliable_stage;
		next = tail ? slot->native_prev : slot->native_next;
		if (!tb->native_error && (result || slot->result))
			tb->native_error = result ?: slot->result;
		xsk_mech_zc_set_result(&p->ring, p->slots, at, result);
		if (!set_only)
			xsk_mech_zc_retire(p, at, result ?: slot->result, &done);
		at = next;
	}
	if (!set_only)
		xsk_mech_zc_reclaim(&p->ring, p->slots);
	if (p->ring.fatal) {
		fatal = p->ring.fatal;
		p->stopped = true;
		if (!failed_stage)
			failed_stage = READ_ONCE(p->xs->xdev_ext_mech_rx);
		if (!failed_stage)
			failed_stage = READ_ONCE(p->xs->xdev_ext_mech_tx);
	}
	spin_unlock_irqrestore(&p->tx_lock, flags);
	/* mark_dead takes tx_lock: propagate only after dropping it.  The
	 * synchronous latch above prevents enqueue/peek before core stop runs. */
	if (fatal && failed_stage)
		xdev_ext_mech_stage_dead(failed_stage, fatal);
	xsk_mech_zc_done(&done);
	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

static int xsk_xdev_ext_mech_zc_submit(struct xdev_ext_mech_stage *st,
				struct xdev_ext_mech_batch *b)
{
	struct xsk_xdev_ext_mech_provider *p = xdev_ext_mech_session_pool(st->s)->priv;
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	struct xsk_xdev_ext_mech_tx_batch *tb = xdev_ext_mech_batch_priv(b);
	struct xdp_sock *xs = xst->xs;
	unsigned long flags;
	u32 start, i, nr = 0, out = 0;
	int err;

	for (i = 0; i < xst->tx_n; i++)
		if (*xst->tx_tag[i] != xdev_ext_mech_batch_id(b))
			nr++;
	if (!nr) {
		xdev_ext_mech_batch_complete(b, tb->ticket, 0);
		return 0;
	}
	INIT_LIST_HEAD(&tb->done);
	tb->batch = b;
	tb->completion.pending = nr;
	tb->completion.status = 0;
	tb->completion.uncertain = false;
	tb->native_error = 0;
	tb->cancelled_before_native = false;
	mutex_lock(&xs->mutex);
	spin_lock_irqsave(&p->tx_lock, flags);
	if (p->stopped || READ_ONCE(xst->dead) || xs->state != XSK_BOUND) {
		err = -ENXIO;
		goto unlock;
	}
	err = xsk_mech_zc_reserve(&p->ring, nr, &start);
	if (err)
		goto unlock;
	for (i = 0; i < xst->tx_n; i++) {
		const struct xdp_desc *d = &xst->tx_desc[i];
		struct xsk_mech_zc_slot *slot;

		tb->err[i] = 0;
		if (*xst->tx_tag[i] == xdev_ext_mech_batch_id(b))
			continue;
		xsk_xdev_ext_mech_tx_finish(xst->tx_pkt[i]);
		xp_dma_sync_for_device(p->xp, xp_raw_get_dma(p->xp, d->addr), d->len);
		slot = &p->slots[(start + out++) & (p->ring.capacity - 1)];
		*slot = (struct xsk_mech_zc_slot) {
			.desc = *d, .batch = tb, .slot = i,
			.state = XSK_MECH_ZC_PENDING,
		};
		xdev_ext_mech_trace_descriptor_bind(b, i, (u64)(unsigned long)p->xp,
					     d->addr, d->len);
		*xst->tx_tag[i] = xdev_ext_mech_batch_id(b);
	}
	spin_unlock_irqrestore(&p->tx_lock, flags);
	/* The kernel ring is visible before the driver's NAPI wakeup. */
	err = xs->dev->netdev_ops->ndo_xsk_wakeup(xs->dev, xs->queue_id,
						XDP_WAKEUP_TX);
	if (err) {
		spin_lock_irqsave(&p->tx_lock, flags);
		p->stopped = true;
		spin_unlock_irqrestore(&p->tx_lock, flags);
	}
	mutex_unlock(&xs->mutex);
	if (err) {
		xsk_mech_zc_cancel_pending(p, err);
		/* Acceptance does not prove DMA quiescence: quarantine the prefix. */
		xdev_ext_mech_stage_dead(st, err);
	}
	return 0;
unlock:
	spin_unlock_irqrestore(&p->tx_lock, flags);
	mutex_unlock(&xs->mutex);
	/* No descriptor reached the source; the core may retry this batch. */
	return err;
}

/*
 * Session worker: submit the staged descriptors. ZC completes asynchronously
 * through the driver journal. Compatibility COPY uses xsk_kernel_xmit(),
 * whose skb owns its bytes on return, and completes synchronously here;
 * a COPY retry skips frames already sent.
 */
static int xsk_xdev_ext_mech_submit(struct xdev_ext_mech_stage *st,
			       struct xdev_ext_mech_batch *b)
{
	struct xsk_xdev_ext_mech_tx_batch *tb = xdev_ext_mech_batch_priv(b);
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	u64 ticket = xdev_ext_mech_batch_ticket(b);
	int status;

	if (xst->tx_staged != b || xst->tx_staged_id != xdev_ext_mech_batch_id(b)) {
		xst->tx_staged = NULL;
		return -EPROTO;
	}
	xst->tx_staged = NULL;
	tb->n = xst->tx_n;
	tb->ticket = ticket;
 if (xst->rel) return xsk_rel_submit(st, b);
	if (xst->xs->zc)
		return xsk_xdev_ext_mech_zc_submit(st, b);
	status = xsk_xdev_ext_mech_tx_run(xdev_ext_mech_batch_id(b), xst->tx_n,
				     xst->tx_tag, tb->err,
				     xsk_xdev_ext_mech_tx_xmit, xst);
	xdev_ext_mech_batch_complete(b, ticket, status);
	return 0;
}

/* Session worker, after an attempt: each frame's send result. */
static void xsk_xdev_ext_mech_fill_cqe(struct xdev_ext_mech_stage *st,
				  struct xdev_ext_mech_batch *b, void *cqe)
{
	const struct xsk_xdev_ext_mech_tx_batch *tb = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_afxdp_tx_cqe *c = cqe;
	u32 i;

	for (i = 0; i < tb->n && i < XDEV_EXT_MECH_MAX_FRAMES; i++)
		c[i].err = tb->err[i];
}

/* Any context, never blocks, also with xs->mutex held: hold nothing more. */
static void xsk_xdev_ext_mech_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xsk_xdev_ext_mech_stage *xst = st->priv;

	if (xst) {
		struct xsk_xdev_ext_mech_provider *p = xdev_ext_mech_session_pool(st->s)->priv;

		WRITE_ONCE(xst->dead, true);
		if (p->zc)
			xsk_mech_zc_stop(p, -ENXIO);
  xsk_rel_dead(st);
	}
}

/*
 * xsk_unbind_dev(), from release or NETDEV_UNREGISTER, with xs->mutex held.
 * The session worker's xsk_kernel_xmit() takes that mutex, so waiting here
 * for a TX batch would deadlock.  Only mark the stages dead: the session
 * stops admitting, RX stops holding, a TX batch stops before its next frame
 * or gets -ENXIO from xsk_kernel_xmit() once the socket is unbound, and the
 * session drains later outside xs->mutex.  ->unbind clears both pointers
 * under the same mutex, so the stages are alive here.
 */
void xsk_xdev_ext_mech_unbind_dev(struct xdp_sock *xs)
{
	lockdep_assert_held(&xs->mutex);
	if (xs->xdev_ext_mech_rx)
		xdev_ext_mech_stage_dead(xs->xdev_ext_mech_rx, -ENXIO);
	if (xs->xdev_ext_mech_tx)
		xdev_ext_mech_stage_dead(xs->xdev_ext_mech_tx, -ENXIO);
}

#include "xsk_xdev_ext_mech_reliable.inc"

static unsigned long xsk_mech_progress(struct xdev_ext_mech_stage *st)
{
	unsigned long pending = xsk_rx_pending_drain(st, false);
	unsigned long reliable = xsk_rel_progress(st);

	return pending && reliable ? min(pending, reliable) : pending ?: reliable;
}

static const struct xdev_ext_mech_class_ops xsk_xdev_ext_mech_class_ops = {
	.class_id = XDEV_EXT_MECH_CLASS_AFXDP,
	/* The NXP receiver takes generations only in order. */
	.flags = XDEV_EXT_MECH_CLASS_F_ORDERED | XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE,
	.desc_size = sizeof(struct xdp_desc),
	.desc_cap = XDEV_EXT_MECH_MAX_FRAMES,
	.info_size = sizeof(struct xdev_ext_afxdp_reliable_info),
	.cqe_size = sizeof(struct xdev_ext_afxdp_tx_cqe),
	.cqe_cap = XDEV_EXT_MECH_MAX_FRAMES,
	.batch_priv_size = sizeof(struct xsk_xdev_ext_mech_tx_batch),
	.owner = THIS_MODULE,
	.transport_stats = xsk_rel_transport_stats,
	.transport_counters = xsk_rel_transport_counters,
 .transport_policy = xsk_rel_transport_policy,
	.bind = xsk_xdev_ext_mech_bind,
	.unbind = xsk_xdev_ext_mech_unbind,
	.fill_info = xsk_xdev_ext_mech_fill_info,
	.validate = xsk_xdev_ext_mech_validate,
	.submit = xsk_xdev_ext_mech_submit,
	.fill_cqe = xsk_xdev_ext_mech_fill_cqe,
	.mark_dead = xsk_xdev_ext_mech_mark_dead,
 .batch_end = xsk_rel_batch_end,
 .progress = xsk_mech_progress,
	.poll = xsk_mech_poll,
};

__bpf_kfunc_start_defs();

/*
 * AF_XDP TX build: a writable view of [off, off + rdwr_buf_size) inside the
 * header room of batch frame @pos, NULL otherwise.  The data span stays out
 * of reach, so a program writes headers only.
 */
__bpf_kfunc __u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
				    __u32 off, const size_t rdwr_buf_size)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);

	if (!c || !c->frames ||
	    !xsk_xdev_ext_mech_hdr_ok(c->ctx.class_id, c->member, c->callsite, pos,
				 c->nr_frames, off, rdwr_buf_size,
				 c->hdr_room))
		return NULL;
	return (__u8 *)c->frames[pos].kaddr + off;
}

/* Stage-private RX state; no worker or other class can obtain this view. */
__bpf_kfunc __u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *ctx,
                                      const size_t rdwr_buf_size)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);
	struct xsk_xdev_ext_mech_stage *xst;

	if (!c || !c->st || c->ctx.class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
	    c->member != XDEV_EXT_MECH_MEMBER_COMPLETE || !rdwr_buf_size ||
	    rdwr_buf_size > XDEV_EXT_AFXDP_MECH_STATE_SIZE ||
	    (c->callsite != XDEV_EXT_MECH_SITE_RX_GENERIC &&
	     c->callsite != XDEV_EXT_MECH_SITE_RX_NATIVE &&
	     c->callsite != XDEV_EXT_MECH_SITE_RX_HOLD_RESULT))
		return NULL;
	xst = c->st->priv;
	return xst ? (__u8 *)xst->bpf_state : NULL;
}

/*
 * AF_XDP RX_GENERIC/RX_NATIVE complete: record one hold intent. Nothing
 * else changes; C checks the intent against the received frame and commits
 * it only if the callback returns XDEV_EXT_MECH_HOLD.  The count is the session
 * layout's frames per batch, not a program argument (a kfunc takes at most
 * five). A second call, or a call outside RX_GENERIC/RX_NATIVE, latches a
 * protocol error.
 */
__bpf_kfunc int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *ctx, __u64 key,
				   __u32 pos, __u32 span_off, __u32 span_len)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);
	int err;

	if (!c)
		return -EINVAL;
	err = xsk_xdev_ext_mech_hold_record(c->ctx.class_id, c->member,
				       c->callsite, &c->hold_calls);
	if (err) {
		c->protocol_error = 1;
		return err;
	}
	c->hold = (struct xdev_ext_mech_hold_intent) {
		.key = key,
		.pos = pos,
		.count = c->batch_frames,
		.span_off = span_off,
		.span_len = span_len,
	};
	return 0;
}

/* A sealed callback grants only the reliable instance of its own stage. */
static struct xsk_mech_reliable *xsk_rel_call_state(struct xdev_ext_mech_call *c)
{
 struct xsk_xdev_ext_mech_stage *xst;
 if (!c || !c->st || c->ctx.class_id!=XDEV_EXT_MECH_CLASS_AFXDP) return NULL;
 xst=c->st->priv;
 return xst ? xst->rel : NULL;
}
static bool xsk_rel_call_rx(const struct xdev_ext_mech_call *c)
{
 return c->member==XDEV_EXT_MECH_MEMBER_COMPLETE &&
        (c->callsite==XDEV_EXT_MECH_SITE_RX_GENERIC || c->callsite==XDEV_EXT_MECH_SITE_RX_NATIVE);
}
__bpf_kfunc int bpf_xdev_ext_rel_rx_view(const struct xdev_ext_mech_ctx *ctx, u64 group,
                                       void *view, u32 view__sz)
{
 struct xdev_ext_mech_call *c=xdev_ext_mech_call_of(ctx);
 struct xsk_mech_reliable *r=xsk_rel_call_state(c);
 struct xdev_ext_rel_rx_view *v=view;
 struct xsk_xdev_ext_mech_provider *p;
 unsigned long flags;
 u32 i,slot;
 bool build;
 if (!c) return -EINVAL;
 build=c->member==XDEV_EXT_MECH_MEMBER_BUILD && c->callsite==XDEV_EXT_MECH_SITE_WORKER;
 if (!r || (!build && !xsk_rel_call_rx(c))) return -EOPNOTSUPP;
 if (view__sz!=sizeof(*v)) return -EINVAL;
 if (!group || group<r->rx.cfg.first_group || group>~0ULL-r->rx.cfg.window) return -ERANGE;
 slot=group % r->rx.cfg.window;
 if (build) {
  p=xdev_ext_mech_session_pool(c->st->s)->priv;
  spin_lock_irqsave(&p->tx_lock,flags);
  xdev_ext_rel_rx_view_fill(&r->rx,r->ack_pending[slot],group,v);
  for(i=0;i<r->rx.cfg.window;i++)
   if (r->ack_pending[i] && r->rx.entry[i].reply!=XDEV_EXT_REL_HELD) v->owed_count++;
  v->must_emit=r->build_must;
  spin_unlock_irqrestore(&p->tx_lock,flags);
 } else {
  /* Advisory RX snapshot only. Every decision is rechecked under tx_lock. */
  data_race(({ xdev_ext_rel_rx_view_fill(&r->rx,r->ack_pending[slot],group,v); 0; }));
 }
 return 0;
}
__bpf_kfunc int bpf_xdev_ext_rel_rx_data(const struct xdev_ext_mech_ctx *ctx,u64 group,
                                       u32 index,u32 attempt,u32 verdict)
{
 struct xdev_ext_mech_call *c=xdev_ext_mech_call_of(ctx);
 struct xsk_mech_reliable *r=xsk_rel_call_state(c);
 struct xsk_xdev_ext_mech_provider *p;
 unsigned long flags;
 u32 slot;
 u64 owed;
 int err;
 bool kick=false;
 if (!c) return -EINVAL;
 if (!r || !xsk_rel_call_rx(c) || c->st->direction!=XDEV_EXT_MECH_DIR_FROM_DEVICE) return -EOPNOTSUPP;
 p=xdev_ext_mech_session_pool(c->st->s)->priv;
 spin_lock_irqsave(&p->tx_lock,flags);
 if (r->rx_intent.calls) { c->protocol_error=1; err=-EALREADY; goto out; }
 r->rx_intent.calls=1;
 if (index>0xffff) { err=-EINVAL; goto out; }
 if (r->nr_groups && (group<r->rx.cfg.first_group || group-r->rx.cfg.first_group>=r->nr_groups)) {
  err=-ERANGE; goto out;
 }
 slot=group % r->rx.cfg.window;
 /* Use a local owed value so first-owed timestamp is set before publication. */
 owed=r->ack_pending[slot];
 err=xdev_ext_rel_rx_verdict(&r->rx,&owed,group,index,attempt,verdict);
 if (!err && verdict==XDEV_EXT_REL_HOLD) {
  r->rx_intent.group=group; r->rx_intent.index=index; r->rx_intent.attempt=attempt; r->rx_intent.valid=1;
 } else if (err==1) { xsk_rel_owe(r,group,true,ktime_get_ns()); kick=true; err=0; }
out:
 spin_unlock_irqrestore(&p->tx_lock,flags);
 if (kick) xdev_ext_mech_stage_kick(c->st);
 return err;
}
__bpf_kfunc int bpf_xdev_ext_rel_rx_control(const struct xdev_ext_mech_ctx *ctx,u64 group,
                                          u32 attempt,u64 credit,u32 type)
{
 struct xdev_ext_mech_call *c=xdev_ext_mech_call_of(ctx);
 struct xsk_mech_reliable *r=xsk_rel_call_state(c);
 struct xsk_xdev_ext_mech_provider *p;
 unsigned long flags;
 int err;
 if (!c) return -EINVAL;
 if (!r || !xsk_rel_call_rx(c)) return -EOPNOTSUPP;
 p=xdev_ext_mech_session_pool(c->st->s)->priv;
 spin_lock_irqsave(&p->tx_lock,flags);
 if (r->rx_intent.calls) { c->protocol_error=1; err=-EALREADY; }
 else {
  r->rx_intent.calls=1;
  err=type>0xff ? -EINVAL : xdev_ext_rel_tx_control(&r->tx,group,attempt,credit,type);
 }
 spin_unlock_irqrestore(&p->tx_lock,flags);
 if (err>=0 && (type==XDEV_EXT_REL_ACK || type==XDEV_EXT_REL_ACK_CUM)) xdev_ext_mech_stage_kick(c->st);
 return err<0 ? err : 0;
}
__bpf_kfunc int bpf_xdev_ext_rel_policy(const struct xdev_ext_mech_ctx *ctx,void *policy,u32 policy__sz)
{
 struct xdev_ext_mech_call *c=xdev_ext_mech_call_of(ctx);
 struct xsk_mech_reliable *r=xsk_rel_call_state(c);
 if (!c) return -EINVAL;
 if (!r || (c->callsite!=XDEV_EXT_MECH_SITE_WORKER &&
     c->callsite!=XDEV_EXT_MECH_SITE_WORKER_SELECT && !xsk_rel_call_rx(c))) return -EOPNOTSUPP;
 if (policy__sz!=sizeof(r->policy)) return -EINVAL;
 memcpy(policy,&r->policy,sizeof(r->policy));
 return 0;
}
/* rdonly_buf_size is the verifier's PTR_TO_MEM read-only size annotation. */
__bpf_kfunc __u8 *bpf_xdev_ext_rel_tx_view(const struct xdev_ext_mech_ctx *ctx,
                                         const size_t rdonly_buf_size)
{
 struct xdev_ext_mech_call *c=xdev_ext_mech_call_of(ctx);
 struct xsk_mech_reliable *r=xsk_rel_call_state(c);
 if (!r || c->member!=XDEV_EXT_MECH_MEMBER_BUILD ||
     c->callsite!=XDEV_EXT_MECH_SITE_WORKER_SELECT ||
     c->b || c->frames || c->nr_frames || c->scratch || c->cqe ||
     rdonly_buf_size!=sizeof(r->select_view) || c->info!=&r->select_view) return NULL;
 return (__u8 *)&r->select_view;
}

__bpf_kfunc_end_defs();

EXPORT_SYMBOL_GPL(bpf_xdev_ext_afxdp_state);

BTF_KFUNCS_START(xsk_xdev_ext_mech_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdev_ext_afxdp_hdr, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdev_ext_afxdp_hold, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_afxdp_state, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdev_ext_rel_rx_view, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_rel_rx_data, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_rel_rx_control, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_rel_policy, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_rel_tx_view, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_KFUNCS_END(xsk_xdev_ext_mech_kfunc_ids)

BTF_SET_START(xsk_xdev_ext_mech_build_kfuncs)
BTF_ID(func, bpf_xdev_ext_afxdp_hdr)
BTF_ID(func, bpf_xdev_ext_rel_rx_view)
BTF_ID(func, bpf_xdev_ext_rel_policy)
BTF_ID(func, bpf_xdev_ext_rel_tx_view)
BTF_SET_END(xsk_xdev_ext_mech_build_kfuncs)

BTF_SET_START(xsk_xdev_ext_mech_complete_kfuncs)
BTF_ID(func, bpf_xdev_ext_afxdp_hold)
BTF_ID(func, bpf_xdev_ext_afxdp_state)
BTF_ID(func, bpf_xdev_ext_rel_rx_view)
BTF_ID(func, bpf_xdev_ext_rel_policy)
BTF_ID(func, bpf_xdev_ext_rel_rx_data)
BTF_ID(func, bpf_xdev_ext_rel_rx_control)
BTF_SET_END(xsk_xdev_ext_mech_complete_kfuncs)

static int xsk_xdev_ext_mech_kfunc_filter(const struct bpf_prog *prog,
				     u32 kfunc_id)
{
	return xdev_ext_mech_class_kfunc_filter(XDEV_EXT_MECH_CLASS_AFXDP, prog, kfunc_id,
					   &xsk_xdev_ext_mech_kfunc_ids,
					   &xsk_xdev_ext_mech_build_kfuncs,
					   &xsk_xdev_ext_mech_complete_kfuncs);
}

static const struct btf_kfunc_id_set xsk_xdev_ext_mech_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &xsk_xdev_ext_mech_kfunc_ids,
	.filter = xsk_xdev_ext_mech_kfunc_filter,
};

static int __init xsk_xdev_ext_mech_init(void)
{
	int err;

 BTF_TYPE_EMIT(struct xdev_ext_rel_rx_view);
 BTF_TYPE_EMIT(struct xdev_ext_rel_policy);
 BTF_TYPE_EMIT(struct xdev_ext_rel_tx_view);
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&xsk_xdev_ext_mech_kfunc_set);
	if (err)
		return err;
	return xdev_ext_mech_class_register(&xsk_xdev_ext_mech_class_ops);
}
late_initcall(xsk_xdev_ext_mech_init);

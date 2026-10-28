// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/xdev_ext_binding.h>
#include <linux/wait.h>
#include <net/xdp_sock.h>
#include <net/xsk_buff_pool.h>

#include "xsk.h"
#include "xsk_queue.h"
#include "xsk_xdev_ext.h"
#include "xsk_xdev_ext_core.h"

#define XSK_XDEV_EXT_TERMINAL_RESULT (-EPERM)
#define XSK_XDEV_EXT_MAX_PER_SOCKET_BUDGET 32

struct xsk_xdev_ext_copy_cookie {
	struct xsk_buff_pool *pool;
	u64 sequence;
};

struct xsk_xdev_ext_record {
	struct xdev_ext_binding_ctx_v2 ctx;
	struct xdev_ext_binding_token token;
	struct xsk_xdev_ext_copy_cookie copy;
};

struct xsk_xdev_ext_journal {
	/* Serializes journal, CQ reservations, and TX consumer admission. */
	spinlock_t lock;
	/* Serializes sleepable generic COPY packet construction per pool. */
	struct mutex copy_mutex;
	wait_queue_head_t waitq;
	struct xsk_xdev_ext_journal_core core;
	struct xsk_xdev_ext_record_core *core_records;
	struct xsk_xdev_ext_record *records;
	u64 pool_id;
	u32 tx_sockets;
	struct xdp_sock *copy_owner;
	u64 copy_first_offset;
	bool copy_first_valid;
	bool admission_busy;
	bool draining;
	bool stopping;
	atomic64_t dispatch_errors;
	atomic64_t completion_errors;
};

struct xsk_xdev_ext_packet {
	struct xdp_sock *xs;
	u64 first_offset;
	u64 length;
	u32 nr_descs;
	u32 invalid_descs;
	bool invalid;
	bool complete;
	bool discard_until_eop;
};

static atomic64_t xsk_xdev_ext_next_pool_id = ATOMIC64_INIT(0);
static atomic64_t xsk_xdev_ext_next_request_id = ATOMIC64_INIT(0);

static bool xsk_xdev_ext_start_drain(struct xsk_xdev_ext_journal *journal);
static void xsk_xdev_ext_drain(struct xsk_buff_pool *pool);

static u32 xsk_xdev_ext_tx_budget_left(const struct xdp_sock *xs)
{
	return XSK_XDEV_EXT_MAX_PER_SOCKET_BUDGET - xs->tx_budget_spent;
}

static u64 xsk_xdev_ext_next_nonzero_id(atomic64_t *counter)
{
	u64 id = atomic64_inc_return(counter);

	/* Zero is valid in the ABI, but reserving it keeps these IDs distinct. */
	if (unlikely(!id))
		id = atomic64_inc_return(counter);
	return id;
}

static struct xsk_xdev_ext_record *
xsk_xdev_ext_record(struct xsk_xdev_ext_journal *journal, u64 sequence)
{
	return &journal->records[sequence & journal->core.mask];
}

static u64 xsk_xdev_ext_desc_offset(const struct xsk_buff_pool *pool,
			       const struct xdp_desc *desc)
{
	return pool->unaligned ? xp_unaligned_add_offset_to_addr(desc->addr) :
				 desc->addr;
}

/* Caller holds journal->lock and an RCU read-side critical section. */
static void xsk_xdev_ext_scan_packet(struct xsk_buff_pool *pool,
				struct xdp_sock *xs,
				struct xsk_xdev_ext_packet *packet,
				struct xdp_desc *snapshot,
				u32 snapshot_capacity)
{
	struct xsk_queue *tx = xs->tx;
	struct xdp_rxtx_ring *ring;
	u32 available, i;

	*packet = (struct xsk_xdev_ext_packet) {
		.xs = xs,
	};
	available = xskq_cons_nb_entries(tx, tx->nentries);
	if (!available)
		return;

	ring = (struct xdp_rxtx_ring *)tx->ring;
	for (i = 0; i < available; i++) {
		struct xdp_desc desc;

		if (snapshot && i >= snapshot_capacity)
			return;
		desc = ring->desc[(tx->cached_cons + i) & tx->ring_mask];

		if (snapshot)
			snapshot[i] = desc;
		if (!i)
			packet->first_offset = xsk_xdev_ext_desc_offset(pool, &desc);
		packet->nr_descs++;
		if (!xp_validate_desc(pool, &desc)) {
			packet->invalid_descs++;
			packet->invalid = true;
		} else if (check_add_overflow(packet->length, (u64)desc.len,
					      &packet->length)) {
			packet->invalid_descs++;
			packet->invalid = true;
		}
		if (packet->nr_descs >= pool->xdp_zc_max_segs &&
		    xp_mb_desc(&desc)) {
			if (!packet->invalid)
				packet->invalid_descs++;
			packet->invalid = true;
			packet->complete = true;
			packet->discard_until_eop = true;
			return;
		}
		if (snapshot && packet->nr_descs == snapshot_capacity &&
		    xp_mb_desc(&desc))
			return;
		if (!xp_mb_desc(&desc)) {
			packet->complete = true;
			return;
		}
	}
}

static bool xsk_xdev_ext_packet_matches(const struct xsk_xdev_ext_packet *left,
				   const struct xsk_xdev_ext_packet *right)
{
	return left->xs == right->xs &&
	       left->first_offset == right->first_offset &&
	       left->length == right->length &&
	       left->nr_descs == right->nr_descs &&
	       left->complete == right->complete &&
	       left->invalid == right->invalid &&
	       left->discard_until_eop == right->discard_until_eop;
}

static u32 xsk_xdev_ext_discard_packet_tail(struct xdp_sock *xs, u32 max_descs);

/* Caller holds journal->lock. */
static u32 xsk_xdev_ext_drop_invalid_packet(struct xsk_buff_pool *pool,
				       struct xsk_xdev_ext_packet *expected,
				       bool single_only, u32 max_descs)
{
	struct xsk_xdev_ext_packet packet;

	xsk_xdev_ext_scan_packet(pool, expected->xs, &packet, NULL, 0);
	if (!xsk_xdev_ext_packet_matches(expected, &packet) || !packet.complete ||
	    (!packet.invalid && (!single_only || packet.nr_descs == 1)))
		return 0;

	packet.xs->tx_xdev_ext_discard_until_eop = true;
	return xsk_xdev_ext_discard_packet_tail(packet.xs, max_descs);
}

/* Caller holds journal->lock and an RCU read-side critical section. */
static u32 xsk_xdev_ext_discard_packet_tail(struct xdp_sock *xs, u32 max_descs)
{
	struct xsk_queue *tx = xs->tx;
	struct xdp_rxtx_ring *ring;
	u32 available, discarded;

	if (!xs->tx_xdev_ext_discard_until_eop || !max_descs)
		return 0;
	available = xskq_cons_nb_entries(tx, max_descs);
	if (!available)
		return 0;

	ring = (struct xdp_rxtx_ring *)tx->ring;
	for (discarded = 0; discarded < available; discarded++) {
		struct xdp_desc desc;

		desc = ring->desc[(tx->cached_cons + discarded) & tx->ring_mask];
		if (!xp_mb_desc(&desc)) {
			discarded++;
			xs->tx_xdev_ext_discard_until_eop = false;
			break;
		}
	}

	tx->invalid_descs += discarded;
	xskq_cons_release_n(tx, discarded);
	__xskq_cons_release(tx);
	return discarded;
}

static struct xdev_ext_binding_ctx_v2
xsk_xdev_ext_make_ctx(struct xsk_buff_pool *pool, struct xsk_xdev_ext_packet *packet,
		 u64 request_id, u32 tx_sockets)
{
	u32 capabilities = XDEV_EXT_BINDING_CAP_ASYNC | XDEV_EXT_BINDING_CAP_ZERO_COPY;
	struct xdev_ext_binding_ctx_v2 ctx;

	if (packet->nr_descs > 1)
		capabilities |= XDEV_EXT_BINDING_CAP_MULTIBUFFER;
	if (tx_sockets > 1)
		capabilities |= XDEV_EXT_BINDING_CAP_SHARED_UMEM;

	ctx = xdev_ext_binding_make_afxdp_native_tx_ctx(packet->first_offset,
						   packet->length,
						   capabilities);
	ctx.request_id = request_id;
	ctx.src_buffer_id = pool->xdev_ext_journal->pool_id;
	return ctx;
}

static bool xsk_xdev_ext_cq_has_space(struct xsk_buff_pool *pool, u32 nr_descs)
{
	unsigned long flags;
	bool available;

	spin_lock_irqsave(&pool->cq_lock, flags);
	available = xskq_prod_nb_free(pool->cq, nr_descs) >= nr_descs;
	spin_unlock_irqrestore(&pool->cq_lock, flags);
	return available;
}

static int xsk_xdev_ext_cq_reserve_snapshot(struct xsk_buff_pool *pool,
				       const struct xdp_desc *snapshot,
				       u32 nr_descs)
{
	unsigned long flags;
	u32 i;
	int ret = 0;

	spin_lock_irqsave(&pool->cq_lock, flags);
	if (xskq_prod_nb_free(pool->cq, nr_descs) < nr_descs) {
		ret = -ENOSPC;
		goto out;
	}
	for (i = 0; i < nr_descs; i++) {
		ret = xskq_prod_reserve_addr(pool->cq, snapshot[i].addr);
		if (unlikely(ret)) {
			xskq_prod_cancel_n(pool->cq, i);
			break;
		}
	}
out:
	spin_unlock_irqrestore(&pool->cq_lock, flags);
	return ret;
}

static void xsk_xdev_ext_cq_cancel(struct xsk_buff_pool *pool, u32 nr_descs)
{
	unsigned long flags;

	spin_lock_irqsave(&pool->cq_lock, flags);
	xskq_prod_cancel_n(pool->cq, nr_descs);
	spin_unlock_irqrestore(&pool->cq_lock, flags);
}

static struct xdev_ext_binding_ctx_v2
xsk_xdev_ext_make_copy_ctx(struct xsk_buff_pool *pool, u64 first_offset,
		      u64 length, u32 nr_descs, u64 request_id,
		      u32 tx_sockets)
{
	u32 capabilities = XDEV_EXT_BINDING_CAP_ASYNC;
	struct xdev_ext_binding_ctx_v2 ctx;

	if (nr_descs > 1)
		capabilities |= XDEV_EXT_BINDING_CAP_MULTIBUFFER;
	if (tx_sockets > 1)
		capabilities |= XDEV_EXT_BINDING_CAP_SHARED_UMEM;

	ctx = xdev_ext_binding_make_afxdp_native_tx_ctx(first_offset, length,
						   capabilities);
	ctx.request_id = request_id;
	ctx.src_buffer_id = pool->xdev_ext_journal->pool_id;
	return ctx;
}

/*
 * The caller owns the single admission slot.  The BPF callback deliberately
 * runs without journal->lock; the TX descriptor stays owned by userspace until
 * this function later advances the cached consumer under the lock.
 */
static int xsk_xdev_ext_dispatch_packet(struct xsk_buff_pool *pool,
				   struct xsk_xdev_ext_packet *packet,
				   u32 output)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	struct xdev_ext_binding_token token = {};
	struct xdev_ext_binding_plan plan;
	struct xdev_ext_binding_ctx_v2 ctx;
	struct xsk_xdev_ext_record *record;
	struct xsk_xdev_ext_packet snapshot_packet;
	struct xdp_desc *snapshot;
	unsigned long flags;
	u64 request_id, sequence;
	int reserve_ret, ret;
	bool native;
	bool drain = false;
	bool cq_reserved = false;

	spin_lock_irqsave(&journal->lock, flags);
	if (journal->stopping || journal->admission_busy ||
	    journal->copy_owner ||
	    journal->core.tail - journal->core.head == journal->core.capacity) {
		spin_unlock_irqrestore(&journal->lock, flags);
		return 0;
	}
	if (output >= pool->tx_descs_capacity ||
	    packet->nr_descs > pool->tx_descs_capacity - output) {
		spin_unlock_irqrestore(&journal->lock, flags);
		return 0;
	}
	snapshot = &pool->tx_descs[output];
	xsk_xdev_ext_scan_packet(pool, packet->xs, &snapshot_packet, snapshot,
			    packet->nr_descs);
	if (!xsk_xdev_ext_packet_matches(packet, &snapshot_packet) ||
	    !snapshot_packet.complete || snapshot_packet.invalid ||
	    !xsk_xdev_ext_cq_has_space(pool, snapshot_packet.nr_descs)) {
		spin_unlock_irqrestore(&journal->lock, flags);
		return 0;
	}
	*packet = snapshot_packet;
	journal->admission_busy = true;
	request_id = xsk_xdev_ext_next_nonzero_id(&xsk_xdev_ext_next_request_id);
	ctx = xsk_xdev_ext_make_ctx(pool, packet, request_id, journal->tx_sockets);
	spin_unlock_irqrestore(&journal->lock, flags);

	ret = xdev_ext_binding_dispatch(&ctx, &token, &plan);
	if (unlikely(ret > 0))
		ret = -EPROTO;
	if (unlikely(ret)) {
		atomic64_inc(&journal->dispatch_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT dispatch failed: %d\n", ret);
	}
	native = !ret && plan.action != XDEV_EXT_BINDING_ACTION_TERMINAL;

	spin_lock_irqsave(&journal->lock, flags);
	if (unlikely(journal->stopping)) {
		journal->admission_busy = false;
		wake_up_all(&journal->waitq);
		spin_unlock_irqrestore(&journal->lock, flags);
		xdev_ext_binding_token_put(&token);
		return 0;
	}

	reserve_ret = xsk_xdev_ext_core_reserve(&journal->core, packet->nr_descs,
					   packet->length, &sequence);
	if (unlikely(reserve_ret)) {
		journal->admission_busy = false;
		wake_up_all(&journal->waitq);
		spin_unlock_irqrestore(&journal->lock, flags);
		xdev_ext_binding_token_put(&token);
		atomic64_inc(&journal->dispatch_errors);
		return 0;
	}

	record = xsk_xdev_ext_record(journal, sequence);
	record->ctx = ctx;
	record->token = token;
	reserve_ret = xsk_xdev_ext_cq_reserve_snapshot(pool, snapshot,
						  packet->nr_descs);
	if (unlikely(reserve_ret))
		goto rollback;
	cq_reserved = true;

	if (native)
		ret = xsk_xdev_ext_core_set_native(&journal->core, sequence);
	else
		ret = xsk_xdev_ext_core_set_ready(&journal->core, sequence,
					     ret ?: XSK_XDEV_EXT_TERMINAL_RESULT, 0);
	if (unlikely(ret))
		goto rollback;

	xskq_cons_release_n(packet->xs->tx, packet->nr_descs);
	__xskq_cons_release(packet->xs->tx);

	if (!native)
		drain = xsk_xdev_ext_start_drain(journal);
	journal->admission_busy = false;
	wake_up_all(&journal->waitq);
	spin_unlock_irqrestore(&journal->lock, flags);
	if (drain)
		xsk_xdev_ext_drain(pool);
	return native ? packet->nr_descs : -EACCES;

rollback:
	if (cq_reserved)
		xsk_xdev_ext_cq_cancel(pool, packet->nr_descs);
	(void)xsk_xdev_ext_core_rollback_tail(&journal->core, sequence);
	*record = (struct xsk_xdev_ext_record) {};
	journal->admission_busy = false;
	wake_up_all(&journal->waitq);
	spin_unlock_irqrestore(&journal->lock, flags);
	xdev_ext_binding_token_put(&token);
	atomic64_inc(&journal->dispatch_errors);
	return 0;
}

static bool xsk_xdev_ext_start_drain(struct xsk_xdev_ext_journal *journal)
{
	if (journal->draining)
		return false;
	journal->draining = true;
	return true;
}

static void xsk_xdev_ext_drain(struct xsk_buff_pool *pool)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;

	for (;;) {
		struct xdev_ext_binding_ctx_v2 ctx;
		struct xdev_ext_binding_token token;
		struct xdev_ext_binding_plan plan;
		struct xsk_xdev_ext_record_core *core_record;
		struct xsk_xdev_ext_record *record;
		u64 sequence;
		int cq_descs, ret;

		spin_lock_irqsave(&journal->lock, flags);
		core_record = (struct xsk_xdev_ext_record_core *)
			xsk_xdev_ext_core_front(&journal->core);
		if (!core_record) {
			journal->draining = false;
			wake_up_all(&journal->waitq);
			spin_unlock_irqrestore(&journal->lock, flags);
			return;
		}

		sequence = core_record->sequence;
		record = xsk_xdev_ext_record(journal, sequence);
		ctx = record->ctx;
		token = record->token;
		record->token = (struct xdev_ext_binding_token) {};
		ctx.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
		ctx.result = core_record->result;
		ctx.bytes_done = core_record->bytes_done;
		spin_unlock_irqrestore(&journal->lock, flags);

		ret = xdev_ext_binding_complete(&ctx, &token, &plan);
		if (unlikely(ret)) {
			atomic64_inc(&journal->completion_errors);
			pr_warn_ratelimited("AF_XDP XDEV_EXT completion failed: %d\n",
					    ret);
		}

		spin_lock_irqsave(&journal->lock, flags);
		core_record = (struct xsk_xdev_ext_record_core *)
			xsk_xdev_ext_core_front(&journal->core);
		if (WARN_ON_ONCE(!core_record ||
				 core_record->sequence != sequence)) {
			journal->draining = false;
			wake_up_all(&journal->waitq);
			spin_unlock_irqrestore(&journal->lock, flags);
			return;
		}
		cq_descs = xsk_xdev_ext_core_pop(&journal->core);
		if (WARN_ON_ONCE(cq_descs < 0)) {
			journal->draining = false;
			wake_up_all(&journal->waitq);
			spin_unlock_irqrestore(&journal->lock, flags);
			return;
		}
		*record = (struct xsk_xdev_ext_record) {};
		if (cq_descs) {
			unsigned long cq_flags;

			spin_lock_irqsave(&pool->cq_lock, cq_flags);
			xskq_prod_submit_n(pool->cq, cq_descs);
			spin_unlock_irqrestore(&pool->cq_lock, cq_flags);
		}
		spin_unlock_irqrestore(&journal->lock, flags);
	}
}

int xsk_xdev_ext_pool_init(struct xsk_buff_pool *pool, u32 capacity)
{
	struct xsk_xdev_ext_journal *journal;
	int ret = -ENOMEM;

	if (!pool || !capacity || !is_power_of_2(capacity) || capacity > INT_MAX)
		return -EINVAL;

	journal = kvzalloc(sizeof(*journal), GFP_KERNEL);
	if (!journal)
		return -ENOMEM;
	journal->core_records = kvcalloc(capacity,
					 sizeof(*journal->core_records), GFP_KERNEL);
	if (!journal->core_records)
		goto err_free_journal;
	journal->records = kvcalloc(capacity, sizeof(*journal->records),
				    GFP_KERNEL);
	if (!journal->records)
		goto err_free_core;

	spin_lock_init(&journal->lock);
	mutex_init(&journal->copy_mutex);
	init_waitqueue_head(&journal->waitq);
	atomic64_set(&journal->dispatch_errors, 0);
	atomic64_set(&journal->completion_errors, 0);
	journal->pool_id = xsk_xdev_ext_next_nonzero_id(&xsk_xdev_ext_next_pool_id);
	ret = xsk_xdev_ext_core_init(&journal->core, journal->core_records, capacity);
	if (ret)
		goto err_free_records;
	pool->xdev_ext_journal = journal;
	return 0;

err_free_records:
	kvfree(journal->records);
err_free_core:
	kvfree(journal->core_records);
err_free_journal:
	kvfree(journal);
	return ret ?: -ENOMEM;
}

void xsk_xdev_ext_pool_destroy(struct xsk_buff_pool *pool)
{
	struct xsk_xdev_ext_journal *journal;
	u64 sequence;

	if (!pool || !pool->xdev_ext_journal)
		return;
	journal = pool->xdev_ext_journal;
	WARN_ON_ONCE(journal->core.head != journal->core.tail ||
		     journal->admission_busy || journal->draining ||
		     journal->copy_owner);
	for (sequence = journal->core.head; sequence < journal->core.tail;
	     sequence++)
		xdev_ext_binding_token_put(&xsk_xdev_ext_record(journal, sequence)->token);
	pool->xdev_ext_journal = NULL;
	kvfree(journal->records);
	kvfree(journal->core_records);
	kvfree(journal);
}

void xsk_xdev_ext_add_tx_socket(struct xsk_buff_pool *pool)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;

	spin_lock_irqsave(&journal->lock, flags);
	journal->tx_sockets++;
	spin_unlock_irqrestore(&journal->lock, flags);
}

void xsk_xdev_ext_del_tx_socket(struct xsk_buff_pool *pool)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;

	spin_lock_irqsave(&journal->lock, flags);
	if (WARN_ON_ONCE(!journal->tx_sockets)) {
		spin_unlock_irqrestore(&journal->lock, flags);
		return;
	}
	journal->tx_sockets--;
	spin_unlock_irqrestore(&journal->lock, flags);
}

int xsk_xdev_ext_zc_tx_completed(struct xsk_buff_pool *pool, u32 nr_descs)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;
	bool drain;
	int ret;

	spin_lock_irqsave(&journal->lock, flags);
	ret = xsk_xdev_ext_core_complete_descs_result(&journal->core, nr_descs,
						 journal->stopping ?
						 -ECANCELED : 0);
	if (unlikely(ret)) {
		atomic64_inc(&journal->completion_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT retirement count rejected: %d\n",
				    ret);
	}
	drain = !ret && xsk_xdev_ext_start_drain(journal);
	spin_unlock_irqrestore(&journal->lock, flags);
	if (drain)
		xsk_xdev_ext_drain(pool);
	return ret;
}

int xsk_xdev_ext_zc_tx_cancel_tail(struct xsk_buff_pool *pool, u32 nr_descs,
			      int result)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;
	bool drain = false;
	int ret;

	spin_lock_irqsave(&journal->lock, flags);
	ret = xsk_xdev_ext_core_cancel_native_tail(&journal->core, nr_descs,
					      result);
	if (!ret && xsk_xdev_ext_core_ready(&journal->core))
		drain = xsk_xdev_ext_start_drain(journal);
	spin_unlock_irqrestore(&journal->lock, flags);
	if (unlikely(ret)) {
		atomic64_inc(&journal->completion_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT tail cancel rejected: %d\n",
				    ret);
	}
	if (drain)
		xsk_xdev_ext_drain(pool);
	return ret;
}

int xsk_xdev_ext_zc_tx_set_tail_result(struct xsk_buff_pool *pool, u32 nr_descs,
				  int result)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&journal->lock, flags);
	ret = xsk_xdev_ext_core_set_native_tail_result(&journal->core, nr_descs,
						  result);
	spin_unlock_irqrestore(&journal->lock, flags);
	if (unlikely(ret)) {
		atomic64_inc(&journal->completion_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT tail result rejected: %d\n",
				    ret);
	}
	return ret;
}

int xsk_xdev_ext_zc_tx_peek_desc(struct xsk_buff_pool *pool,
			    struct xdp_desc *desc)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	bool budget_exhausted = false;
	struct xdp_sock *xs;
	unsigned long flags;

	rcu_read_lock();
again:
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		struct xsk_xdev_ext_packet packet;
		u32 discard_budget;
		u32 discarded;
		int ret;

		if (xs->tx_budget_spent >= XSK_XDEV_EXT_MAX_PER_SOCKET_BUDGET) {
			budget_exhausted = true;
			continue;
		}

		spin_lock_irqsave(&journal->lock, flags);
		if (journal->stopping || journal->admission_busy) {
			spin_unlock_irqrestore(&journal->lock, flags);
			goto out;
		}
		if (journal->copy_owner) {
			spin_unlock_irqrestore(&journal->lock, flags);
			goto out;
		}
		discard_budget = xsk_xdev_ext_tx_budget_left(xs);
		discarded = xsk_xdev_ext_discard_packet_tail(xs, discard_budget);
		if (discarded) {
			xs->tx_budget_spent += discarded;
			spin_unlock_irqrestore(&journal->lock, flags);
			continue;
		}
		xsk_xdev_ext_scan_packet(pool, xs, &packet, NULL, 0);
		spin_unlock_irqrestore(&journal->lock, flags);
		if (!packet.nr_descs)
			continue;
		if (!packet.complete)
			continue;
		if (packet.invalid || packet.nr_descs != 1) {
			spin_lock_irqsave(&journal->lock, flags);
			if (!journal->admission_busy && !journal->stopping &&
			    !journal->copy_owner) {
				discard_budget = xsk_xdev_ext_tx_budget_left(xs);
				discarded = xsk_xdev_ext_drop_invalid_packet(pool, &packet,
									true, discard_budget);
				xs->tx_budget_spent += discarded;
			}
			spin_unlock_irqrestore(&journal->lock, flags);
			continue;
		}

		ret = xsk_xdev_ext_dispatch_packet(pool, &packet, 0);
		if (!ret)
			goto out;
		xs->tx_budget_spent += packet.nr_descs;
		if (ret < 0)
			continue;
		*desc = pool->tx_descs[0];
		rcu_read_unlock();
		return 1;
	}

	if (budget_exhausted) {
		list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list)
			xs->tx_budget_spent = 0;
		budget_exhausted = false;
		goto again;
	}
out:
	rcu_read_unlock();
	return 0;
}

int xsk_xdev_ext_zc_tx_peek_release_desc_batch(struct xsk_buff_pool *pool,
					  u32 max_descs)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	bool budget_exhausted = false;
	struct xdp_sock *xs;
	u32 output = 0;
	u32 work_descs = 0;

	if (!max_descs || !pool->tx_descs_capacity)
		return 0;
	max_descs = min(max_descs, pool->tx_descs_capacity);

	rcu_read_lock();
again:
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		while (work_descs < max_descs) {
			struct xsk_xdev_ext_packet packet;
			unsigned long flags;
			u32 discard_budget;
			u32 discarded;
			int ret;

			if (xs->tx_budget_spent >=
			    XSK_XDEV_EXT_MAX_PER_SOCKET_BUDGET) {
				budget_exhausted = true;
				break;
			}
			spin_lock_irqsave(&journal->lock, flags);
			if (journal->stopping || journal->admission_busy ||
			    journal->copy_owner) {
				spin_unlock_irqrestore(&journal->lock, flags);
				goto out;
			}
			discard_budget = min(max_descs - work_descs,
					     xsk_xdev_ext_tx_budget_left(xs));
			discarded = xsk_xdev_ext_discard_packet_tail(xs, discard_budget);
			if (discarded) {
				work_descs += discarded;
				xs->tx_budget_spent += discarded;
				spin_unlock_irqrestore(&journal->lock, flags);
				continue;
			}
			xsk_xdev_ext_scan_packet(pool, xs, &packet, NULL, 0);
			spin_unlock_irqrestore(&journal->lock, flags);
			if (!packet.nr_descs || !packet.complete)
				break;
			if (packet.invalid) {
				spin_lock_irqsave(&journal->lock, flags);
				if (journal->admission_busy || journal->stopping ||
				    journal->copy_owner) {
					spin_unlock_irqrestore(&journal->lock,
							       flags);
					goto out;
				}
				discard_budget = min(max_descs - work_descs,
						     xsk_xdev_ext_tx_budget_left(xs));
				discarded = xsk_xdev_ext_drop_invalid_packet(pool, &packet,
									false, discard_budget);
				if (!discarded) {
					spin_unlock_irqrestore(&journal->lock,
							       flags);
					goto out;
				}
				spin_unlock_irqrestore(&journal->lock, flags);
				work_descs += discarded;
				xs->tx_budget_spent += discarded;
				continue;
			}
			if (packet.nr_descs > max_descs - work_descs)
				break;

			ret = xsk_xdev_ext_dispatch_packet(pool, &packet, output);
			if (!ret)
				goto out;
			work_descs += packet.nr_descs;
			xs->tx_budget_spent += packet.nr_descs;
			if (ret > 0)
				output += ret;
		}
		__xskq_cons_release(xs->tx);
		xs->sk.sk_write_space(&xs->sk);
	}
	if (budget_exhausted && work_descs < max_descs) {
		list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list)
			xs->tx_budget_spent = 0;
		budget_exhausted = false;
		goto again;
	}
out:
	rcu_read_unlock();
	return output;
}

int xsk_xdev_ext_copy_enter(struct xsk_buff_pool *pool, struct xdp_sock *xs)
{
	struct xsk_xdev_ext_journal *journal;
	unsigned long flags;
	int ret = 0;

	if (WARN_ON_ONCE(!pool || !xs || !pool->xdev_ext_journal))
		return -EINVAL;
	journal = pool->xdev_ext_journal;

	mutex_lock(&journal->copy_mutex);
	spin_lock_irqsave(&journal->lock, flags);
	if (journal->copy_owner && journal->copy_owner != xs) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	/* The current partial owner must always be able to unwind on close,
	 * including after teardown has stopped new admission.
	 */
	if (unlikely(READ_ONCE(journal->stopping)) && !journal->copy_owner) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	if (journal->admission_busy && !journal->copy_owner) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	if (!journal->copy_owner) {
		journal->copy_owner = xs;
		journal->copy_first_valid = false;
	}
	spin_unlock_irqrestore(&journal->lock, flags);
	return 0;

out_unlock:
	spin_unlock_irqrestore(&journal->lock, flags);
	mutex_unlock(&journal->copy_mutex);
	return ret;
}

void xsk_xdev_ext_copy_note_first(struct xsk_buff_pool *pool,
			     struct xdp_sock *xs, u64 addr)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;

	if (WARN_ON_ONCE(journal->copy_owner != xs))
		return;
	journal->copy_first_offset = pool->unaligned ?
		xp_unaligned_add_offset_to_addr(addr) : addr;
	journal->copy_first_valid = true;
}

void xsk_xdev_ext_copy_exit(struct xsk_buff_pool *pool, struct xdp_sock *xs,
		       bool partial)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;

	spin_lock_irqsave(&journal->lock, flags);
	if (WARN_ON_ONCE(journal->copy_owner != xs)) {
		spin_unlock_irqrestore(&journal->lock, flags);
		mutex_unlock(&journal->copy_mutex);
		return;
	}
	if (!partial) {
		journal->copy_owner = NULL;
		journal->copy_first_valid = false;
	}
	spin_unlock_irqrestore(&journal->lock, flags);
	mutex_unlock(&journal->copy_mutex);
}

int xsk_xdev_ext_copy_dispatch(struct xsk_buff_pool *pool, struct xdp_sock *xs,
			  u64 length, u32 nr_descs,
			  struct xsk_xdev_ext_copy_cookie **cookie,
			  int *terminal_result)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	struct xdev_ext_binding_token token = {};
	struct xdev_ext_binding_plan plan;
	struct xdev_ext_binding_ctx_v2 ctx;
	struct xsk_xdev_ext_record *record;
	unsigned long flags;
	u64 request_id, sequence;
	int ret;
	bool native;

	if (!cookie || !terminal_result || !length || !nr_descs)
		return -EINVAL;
	*cookie = NULL;
	*terminal_result = 0;
	if (WARN_ON_ONCE(journal->copy_owner != xs) ||
	    WARN_ON_ONCE(!journal->copy_first_valid))
		return -EINVAL;

	/* Reserve the FIFO position before invoking a callback with the lock
	 * dropped. admission_busy keeps ZC and COPY reservations ordered while
	 * this record is temporarily in RESERVED state.
	 */
	spin_lock_irqsave(&journal->lock, flags);
	if (journal->stopping || journal->admission_busy) {
		spin_unlock_irqrestore(&journal->lock, flags);
		return -EAGAIN;
	}
	journal->admission_busy = true;
	ret = xsk_xdev_ext_core_reserve(&journal->core, nr_descs, length,
				   &sequence);
	if (ret) {
		journal->admission_busy = false;
		wake_up_all(&journal->waitq);
		spin_unlock_irqrestore(&journal->lock, flags);
		return ret == -ENOSPC ? -EAGAIN : ret;
	}
	request_id = xsk_xdev_ext_next_nonzero_id(&xsk_xdev_ext_next_request_id);
	ctx = xsk_xdev_ext_make_copy_ctx(pool, journal->copy_first_offset, length,
				    nr_descs, request_id,
				    journal->tx_sockets);
	spin_unlock_irqrestore(&journal->lock, flags);

	ret = xdev_ext_binding_dispatch(&ctx, &token, &plan);
	if (unlikely(ret > 0))
		ret = -EPROTO;
	if (unlikely(ret)) {
		atomic64_inc(&journal->dispatch_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT COPY dispatch failed: %d\n",
				    ret);
	}
	native = !ret && plan.action != XDEV_EXT_BINDING_ACTION_TERMINAL;

	spin_lock_irqsave(&journal->lock, flags);
	if (unlikely(journal->stopping)) {
		ret = -ESHUTDOWN;
		goto rollback;
	}
	record = xsk_xdev_ext_record(journal, sequence);
	if (native) {
		int state_ret;

		state_ret = xsk_xdev_ext_core_set_native_exact(&journal->core,
							  sequence);
		if (unlikely(state_ret)) {
			ret = state_ret;
			goto rollback;
		}
	}
	record->ctx = ctx;
	record->token = token;
	record->copy.pool = pool;
	record->copy.sequence = sequence;
	*cookie = &record->copy;
	*terminal_result = ret ?: XSK_XDEV_EXT_TERMINAL_RESULT;
	spin_unlock_irqrestore(&journal->lock, flags);
	return native ? XSK_XDEV_EXT_COPY_NATIVE : XSK_XDEV_EXT_COPY_TERMINAL;

rollback:
	if (WARN_ON_ONCE(xsk_xdev_ext_core_rollback_tail(&journal->core,
						    sequence) < 0))
		atomic64_inc(&journal->dispatch_errors);
	record = xsk_xdev_ext_record(journal, sequence);
	*record = (struct xsk_xdev_ext_record) {};
	journal->admission_busy = false;
	wake_up_all(&journal->waitq);
	spin_unlock_irqrestore(&journal->lock, flags);
	xdev_ext_binding_token_put(&token);
	return ret;
}

static int
xsk_xdev_ext_copy_lookup_locked(struct xsk_xdev_ext_copy_cookie *cookie,
			   struct xsk_xdev_ext_journal **journal_out,
			   struct xsk_xdev_ext_record_core **core_record_out)
{
	struct xsk_xdev_ext_journal *journal;
	struct xsk_xdev_ext_record_core *core_record;
	struct xsk_xdev_ext_record *record;
	int ret;

	if (!cookie || !cookie->pool || !cookie->pool->xdev_ext_journal)
		return -EINVAL;
	journal = cookie->pool->xdev_ext_journal;
	ret = xsk_xdev_ext_core_lookup(&journal->core, cookie->sequence,
				  &core_record);
	if (ret)
		return ret;
	record = xsk_xdev_ext_record(journal, cookie->sequence);
	if (&record->copy != cookie || record->copy.pool != cookie->pool ||
	    record->copy.sequence != cookie->sequence)
		return -ESTALE;
	*journal_out = journal;
	*core_record_out = core_record;
	return 0;
}

int xsk_xdev_ext_copy_set_result(struct xsk_xdev_ext_copy_cookie *cookie, int result,
			    u64 bytes_done)
{
	struct xsk_xdev_ext_record_core *core_record;
	struct xsk_xdev_ext_journal *journal;
	struct xsk_buff_pool *pool;
	unsigned long flags;
	bool drain = false;
	int ret;

	if (!cookie || !cookie->pool)
		return -EINVAL;
	pool = cookie->pool;
	journal = pool->xdev_ext_journal;
	spin_lock_irqsave(&journal->lock, flags);
	ret = xsk_xdev_ext_copy_lookup_locked(cookie, &journal, &core_record);
	if (!ret) {
		if (core_record->state == XSK_XDEV_EXT_RECORD_RESERVED)
			ret = xsk_xdev_ext_core_set_ready(&journal->core,
						     cookie->sequence,
						     result, bytes_done);
		else
			ret = xsk_xdev_ext_core_set_result(&journal->core,
						      cookie->sequence,
						      result, bytes_done);
		if (!ret && xsk_xdev_ext_core_ready(&journal->core))
			drain = xsk_xdev_ext_start_drain(journal);
	}
	if (WARN_ON_ONCE(!journal->admission_busy) && !ret)
		ret = -EPROTO;
	journal->admission_busy = false;
	wake_up_all(&journal->waitq);
	spin_unlock_irqrestore(&journal->lock, flags);
	if (unlikely(ret)) {
		atomic64_inc(&journal->completion_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT COPY result rejected: %d\n",
				    ret);
	}
	if (drain)
		xsk_xdev_ext_drain(pool);
	return ret;
}

int xsk_xdev_ext_copy_cancel_busy(struct xsk_xdev_ext_copy_cookie *cookie)
{
	struct xsk_xdev_ext_record_core *core_record;
	struct xsk_xdev_ext_journal *journal;
	struct xsk_buff_pool *pool;
	unsigned long flags;
	int cq_descs, ret;

	if (!cookie || !cookie->pool)
		return -EINVAL;
	pool = cookie->pool;
	journal = pool->xdev_ext_journal;
	spin_lock_irqsave(&journal->lock, flags);
	ret = xsk_xdev_ext_copy_lookup_locked(cookie, &journal, &core_record);
	if (!ret) {
		(void)core_record;
		cq_descs = xsk_xdev_ext_core_cancel_tail_cq(&journal->core,
						       cookie->sequence);
		ret = cq_descs < 0 ? cq_descs : 0;
	} else {
		cq_descs = 0;
	}
	spin_unlock_irqrestore(&journal->lock, flags);
	if (unlikely(ret)) {
		atomic64_inc(&journal->completion_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT COPY busy cancel failed: %d\n",
				    ret);
		return ret;
	}
	if (cq_descs) {
		spin_lock_irqsave(&pool->cq_lock, flags);
		xskq_prod_cancel_n(pool->cq, cq_descs);
		spin_unlock_irqrestore(&pool->cq_lock, flags);
	}
	return 0;
}

void xsk_xdev_ext_copy_retired(struct xsk_xdev_ext_copy_cookie *cookie)
{
	struct xsk_xdev_ext_record_core *core_record;
	struct xsk_xdev_ext_journal *journal;
	struct xsk_buff_pool *pool;
	unsigned long flags;
	bool drain = false;
	int ret;

	if (WARN_ON_ONCE(!cookie || !cookie->pool))
		return;
	pool = cookie->pool;
	journal = pool->xdev_ext_journal;
	spin_lock_irqsave(&journal->lock, flags);
	ret = xsk_xdev_ext_copy_lookup_locked(cookie, &journal, &core_record);
	if (!ret) {
		(void)core_record;
		ret = xsk_xdev_ext_core_complete_exact(&journal->core,
						  cookie->sequence);
		if (!ret && xsk_xdev_ext_core_ready(&journal->core))
			drain = xsk_xdev_ext_start_drain(journal);
	}
	spin_unlock_irqrestore(&journal->lock, flags);
	if (unlikely(ret)) {
		atomic64_inc(&journal->completion_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT COPY retirement rejected: %d\n",
				    ret);
	}
	if (drain)
		xsk_xdev_ext_drain(pool);
}

void xsk_xdev_ext_zc_teardown_begin(struct xsk_buff_pool *pool)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;

	spin_lock_irqsave(&journal->lock, flags);
	journal->stopping = true;
	spin_unlock_irqrestore(&journal->lock, flags);
	wait_event(journal->waitq, !READ_ONCE(journal->admission_busy));
}

void xsk_xdev_ext_zc_teardown_finish(struct xsk_buff_pool *pool)
{
	struct xsk_xdev_ext_journal *journal = pool->xdev_ext_journal;
	unsigned long flags;
	bool drain;
	int ret;

	wait_event(journal->waitq,
		   !READ_ONCE(journal->admission_busy) &&
		   !READ_ONCE(journal->draining));
	spin_lock_irqsave(&journal->lock, flags);
	ret = xsk_xdev_ext_core_stop(&journal->core, -ECANCELED);
	if (unlikely(ret < 0)) {
		atomic64_inc(&journal->completion_errors);
		pr_warn_ratelimited("AF_XDP XDEV_EXT teardown failed: %d\n", ret);
	}
	drain = ret >= 0 && xsk_xdev_ext_start_drain(journal);
	spin_unlock_irqrestore(&journal->lock, flags);
	if (drain)
		xsk_xdev_ext_drain(pool);
	wait_event(journal->waitq, !READ_ONCE(journal->draining));
}

enum xsk_xdev_ext_rx_disposition
xsk_xdev_ext_rx_dispatch(struct xsk_buff_pool *pool, struct xdp_sock *xs,
		    struct xdp_buff *xdp, u64 length, u32 nr_descs,
		    bool zero_copy, struct xsk_xdev_ext_rx_cookie *cookie)
{
	struct xdev_ext_binding_plan plan;
	u32 capabilities = 0;
	u64 dst_offset = 0;
	u64 request_id;
	int ret;

	if (WARN_ON_ONCE(!cookie))
		return XSK_XDEV_EXT_RX_C_FALLBACK;
	*cookie = (struct xsk_xdev_ext_rx_cookie) {};
	if (!pool || !xs || !xdp || !xs->rx || !length || !nr_descs ||
	    !xdev_ext_binding_policy_active())
		return XSK_XDEV_EXT_RX_C_FALLBACK;

	if (zero_copy) {
		struct xdp_buff_xsk *xskb =
			container_of(xdp, struct xdp_buff_xsk, xdp);
		u64 handle = xp_get_handle(xskb, pool);

		dst_offset = pool->unaligned ?
			xp_unaligned_add_offset_to_addr(handle) : handle;
		capabilities |= XDEV_EXT_BINDING_CAP_ZERO_COPY;
	}
	if (nr_descs > 1)
		capabilities |= XDEV_EXT_BINDING_CAP_MULTIBUFFER;
	if (refcount_read(&pool->users) > 1)
		capabilities |= XDEV_EXT_BINDING_CAP_SHARED_UMEM;

	request_id = xsk_xdev_ext_next_nonzero_id(&xsk_xdev_ext_next_request_id);
	cookie->ctx = xdev_ext_binding_make_afxdp_rx_ctx(dst_offset, length,
						    capabilities);
	cookie->ctx.request_id = request_id;
	if (pool->xdev_ext_journal)
		cookie->ctx.dst_buffer_id = pool->xdev_ext_journal->pool_id;

	ret = xdev_ext_binding_dispatch(&cookie->ctx, &cookie->token, &plan);
	if (unlikely(ret > 0))
		ret = -EPROTO;
	if (unlikely(ret)) {
		pr_warn_ratelimited("AF_XDP XDEV_EXT RX dispatch failed: %d\n", ret);
		return XSK_XDEV_EXT_RX_TERMINAL;
	}
	if (plan.action == XDEV_EXT_BINDING_ACTION_TERMINAL)
		return XSK_XDEV_EXT_RX_TERMINAL;
	/* No token means no plugin, or a flags=0 AF_XDP plugin skipped by C. */
	if (!cookie->token.private)
		return XSK_XDEV_EXT_RX_C_FALLBACK;

	ret = xsk_xdev_ext_rx_core_begin(&cookie->core, length, nr_descs, true);
	if (WARN_ON_ONCE(ret)) {
		xdev_ext_binding_token_put(&cookie->token);
		xsk_xdev_ext_rx_core_init(&cookie->core);
		return XSK_XDEV_EXT_RX_C_FALLBACK;
	}
	return XSK_XDEV_EXT_RX_TRACKED;
}

void xsk_xdev_ext_rx_abort(struct xsk_xdev_ext_rx_cookie *cookie)
{
	int ret;

	if (!cookie)
		return;
	ret = xsk_xdev_ext_rx_core_abort(&cookie->core);
	if (ret > 0) {
		xdev_ext_binding_token_put(&cookie->token);
	} else if (WARN_ON_ONCE(ret < 0)) {
		/* Fail closed on an internal ordering bug: never leak the pin. */
		xdev_ext_binding_token_put(&cookie->token);
		xsk_xdev_ext_rx_core_init(&cookie->core);
	}
}

bool xsk_xdev_ext_rx_publish(struct xdp_sock *xs,
			struct xsk_xdev_ext_rx_cookie *cookie)
{
	struct xdev_ext_binding_plan plan;
	int core_ret, ret;

	if (!xs || !cookie || cookie->core.state == XSK_XDEV_EXT_RX_IDLE)
		return false;
	if (WARN_ON_ONCE(cookie->core.state != XSK_XDEV_EXT_RX_RESERVED)) {
		xsk_xdev_ext_rx_abort(cookie);
		return false;
	}

	/* This release-store is the RX ownership handoff to userspace. */
	xskq_prod_submit(xs->rx);
	core_ret = xsk_xdev_ext_rx_core_published(&cookie->core,
					     cookie->ctx.length);
	if (WARN_ON_ONCE(core_ret)) {
		cookie->ctx.result = -EIO;
		cookie->ctx.bytes_done = 0;
	} else {
		cookie->ctx.result = 0;
		cookie->ctx.bytes_done = cookie->ctx.length;
	}
	cookie->ctx.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	ret = xdev_ext_binding_complete(&cookie->ctx, &cookie->token, &plan);
	if (unlikely(ret))
		pr_warn_ratelimited("AF_XDP XDEV_EXT RX completion failed: %d\n", ret);

	if (core_ret || WARN_ON_ONCE(xsk_xdev_ext_rx_core_complete(&cookie->core) != 1))
		xsk_xdev_ext_rx_core_init(&cookie->core);

	__xskq_cons_release(xs->pool->fq);
	sock_def_readable(&xs->sk);
	return true;
}

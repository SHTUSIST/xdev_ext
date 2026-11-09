// SPDX-License-Identifier: GPL-2.0-only
/* Legacy RX completion wake scheduling boundary.
 * Production RX, pending FIFO, core terminal release/progress and stage kick
 * bodies are injected verbatim. The OS delayed-work/list/ref/lifecycle and
 * hold-commit seams below are deterministic controls, not kernel execution or
 * a simulated NIC. The RX program/order seam follows the existing backlog
 * fixture; its actual protocol order helper is injected too.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t __u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t s32;
typedef int spinlock_t;
#define XDEV_EXT_MP_HOLD 4
#define XDEV_EXT_MP_RECYCLE 6
#define XDEV_EXT_MP_GROUP_TIMEOUT_NS 1000000000ULL
#define XDEV_EXT_MECH_HOLD 4
#define XDEV_EXT_MECH_PUBLISH 5
#define XDEV_EXT_MECH_RECYCLE 6
#define XDEV_EXT_MECH_ABORT 3
#define XDEV_EXT_MECH_SITE_RX_NATIVE 2
#define XDEV_EXT_MECH_SITE_RX_HOLD_RESULT 5
#define XDEV_EXT_REL_HOLD 1
#define XDEV_EXT_MECH_CNT_NATIVE_PUBLISH 0
#define XDEV_EXT_MECH_CNT_PROTOCOL_ERR 1
#define XDEV_EXT_MECH_F_USER 0
#define XDEV_EXT_MECH_F_K_FREE 1
#define XDEV_EXT_MECH_F_HELD 2
#define XDEV_EXT_MECH_F_NIC_RX 5
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))
#define spin_lock_irqsave(p, f)                                                                    \
	do {                                                                                       \
		(f) = 0;                                                                           \
		if ((*(p))++)                                                                      \
			abort();                                                                   \
	} while (0)
#define spin_unlock_irqrestore(p, f)                                                               \
	do {                                                                                       \
		(void)(f);                                                                         \
		if (--(*(p)))                                                                      \
			abort();                                                                   \
	} while (0)
struct xdev_ext_mech_hold_intent {
	u64 key;
	u32 pos, count, span_off, span_len;
};
struct xdev_ext_mech_frame {
	void *kaddr, *pool_priv;
	u64 umem_addr;
	u32 index, data_off, data_len;
};
/* ACTUAL_xsk_mech_rx_pending_entry */
/* ACTUAL_xsk_mech_rx_pending */
/* ACTUAL_xdev_ext_mp_segment */
/* ACTUAL_xdev_ext_mp_rx_order */
/* ACTUAL_RX_ORDER */

struct xdp_sock;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_batch;
struct fake_bs {
	int native_sequester, state, stage;
};
struct fake_ss {
	int state, q;
};
struct fake_rel {
	struct {
		struct {
			u32 window;
		} cfg;
		struct {
			int reply;
		} entry[2];
	} rx;
};
struct xsk_xdev_ext_mech_provider {
	spinlock_t tx_lock;
};
struct kthread_work {
	int unused;
};
struct kthread_delayed_work {
	struct kthread_work work;
	bool pending;
	unsigned long due;
};
struct fake_ops {
	unsigned long (*progress)(struct xdev_ext_mech_stage *);
	void (*batch_end)(struct xdev_ext_mech_stage *, struct xdev_ext_mech_batch *, int);
	void (*batch_release)(struct xdev_ext_mech_stage *, struct xdev_ext_mech_batch *, bool);
};
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define XDEV_EXT_MECH_END_DONE 0
#define XDEV_EXT_MECH_END_ABORT 1
#define XDEV_EXT_MECH_END_SEQUESTER 2
#define XDEV_EXT_MECH_B_SEQUESTERED 3
#define XDEV_EXT_MECH_SESSION_ACTIVE 1
#define XDEV_EXT_MECH_SESSION_STOPPING 2
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 1
#define XDEV_EXT_MECH_CNT_SEQUESTERED 5
#define XDEV_EXT_REL_REPLAY_ACK 5
#define XDEV_EXT_REL_ACK 2
#define XDEV_EXT_REL_NONE 0
#define min(a, b) ((a) < (b) ? (a) : (b))
#define atomic64_inc(p) (++*(p))
static unsigned long tick;
static unsigned progress_runs, other_work, mod_calls, finish_calls, owe_calls;
static int finish_action;
static int system_unbound_wq;
static bool kthread_queue_delayed_work(void *worker, struct kthread_delayed_work *work,
				       unsigned long delay)
{
	(void)worker;
	if (work->pending)
		return false;
	work->pending = true;
	work->due = tick + delay;
	return true;
}
static bool kthread_mod_delayed_work(void *worker, struct kthread_delayed_work *work,
				     unsigned long delay)
{
	mod_calls++;
	(void)worker;
	work->pending = true;
	work->due = tick + delay;
	return true;
}
static void kthread_queue_work(void *worker, struct kthread_work *work)
{
	(void)worker;
	(void)work;
	other_work++;
}
static void queue_work(int worker, struct kthread_work *work)
{
	(void)worker;
	(void)work;
	other_work++;
}

struct xsk_xdev_ext_mech_stage {
	struct xdp_sock *xs;
	struct fake_rel *rel;
	bool dead;
	struct xsk_mech_rx_pending pending;
};
struct xdev_ext_mech_pool {
	u32 nr_frames;
	u8 state[4096];
	void *priv;
};
struct list_head {
	int boundary;
};
struct xdev_ext_mech_batch {
	struct list_head node;
	struct fake_bs bs;
	bool ordered_loan;
	u64 ticket;
	u64 id, key, bytes;
	int abort_err, status;
	u32 present, nr_frames, life_active;
	bool sequester, to_user, fifo_accepted;
};
struct xdev_ext_mech_session {
	bool admits;
	struct xdev_ext_mech_pool *pool;
	struct list_head free, retry, ordered;
	struct fake_ss ss;
	u32 nr_stages;
	spinlock_t lock;
	struct xdev_ext_mech_stage *st;
	bool progress_ready, worker_gone, order_kicking, start_recycle, start_return_pending;
	u32 start_left;
	void *worker;
	struct kthread_delayed_work progress_work, retry_work;
	struct kthread_work kick_work, reap_work;
	u64 done, aborted;
	u64 next_batch_id;
};
struct xdev_ext_mech_stage {
	struct xsk_xdev_ext_mech_stage *priv;
	struct xdev_ext_mech_session *s;
	struct fake_ops *cls;
	u32 direction, order_window;
};
struct xdp_sock {
	struct xdev_ext_mech_stage *xdev_ext_mech_rx, *xdev_ext_mech_tx;
	bool zc;
	struct xdev_ext_mech_pool *pool;
};
struct xdp_buff_xsk {
	u32 index, data_off;
};
struct xdev_ext_rel_msg {
	u64 group;
	u32 index, count, payload_len;
};
struct xdev_ext_afxdp_rx_hold_cqe {
	u64 key;
	u32 pos;
	int err;
};
static struct xdev_ext_mp_rx_order order, candidate;
static u32 held, completed, recycled, kicks, busy, expected_key = 1, expected_pos;
static u32 owned[4096], owned_count;
static int last_err;
static bool stop_during_commit;
static int begin_error;
static struct xdev_ext_mech_batch free_batch;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{
	return s->pool;
}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s)
{
	return s->admits;
}
static u32 xdev_ext_mech_pool_frame_state(struct xdev_ext_mech_pool *p, u32 i)
{
	return i < p->nr_frames ? p->state[i] : 99;
}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p, u32 i, u32 from, u32 to)
{
	if (i >= p->nr_frames || p->state[i] != from)
		return -EBUSY;
	p->state[i] = to;
	return 0;
}
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st, int err)
{
	if (!last_err)
		last_err = err;
	st->s->admits = false;
	st->priv->dead = true;
}
/* ACTUAL_xdev_ext_mech_stage_kick */
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s, int counter, u64 n)
{
	(void)s;
	(void)counter;
	(void)n;
}
/* Real header maps the socket mode to separate NIC zero-copy/copy counters. */
enum { NIC_COPY_OPS, NIC_COPY_BYTES, NIC_ZC_OPS, NIC_ZC_BYTES };
static int xdev_ext_mech_nic_ops_counter(bool zc)
{
	return zc ? NIC_ZC_OPS : NIC_COPY_OPS;
}
static int xdev_ext_mech_nic_bytes_counter(bool zc)
{
	return zc ? NIC_ZC_BYTES : NIC_COPY_BYTES;
}
static void xdev_ext_mech_frame_recycle(struct xdev_ext_mech_session *s,
					struct xdev_ext_mech_frame *f)
{
	if (s->pool->state[f->index] != XDEV_EXT_MECH_F_NIC_RX)
		abort();
	s->pool->state[f->index] = XDEV_EXT_MECH_F_K_FREE;
	recycled++;
}
static int xsk_xdev_ext_mech_pool_resolve(struct xdev_ext_mech_pool *p,
					  struct xdev_ext_mech_frame *f)
{
	if (f->index >= p->nr_frames)
		return -ERANGE;
	f->kaddr = (void *)(uintptr_t)(f->index + 1);
	return 0;
}
static void xsk_xdev_ext_mech_frame(struct xdev_ext_mech_pool *p, struct xdp_buff_xsk *b,
				    struct xdev_ext_mech_frame *f)
{
	(void)p;
	*f = (struct xdev_ext_mech_frame){.index = b->index, .data_off = b->data_off};
}
static int xsk_rel_rx(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_frame *f,
		      struct xdev_ext_rel_msg *m)
{
	(void)st;
	(void)f;
	(void)m;
	abort();
}
static int xsk_rel_hold_commit(struct xdev_ext_mech_stage *st,
			       const struct xdev_ext_mech_hold_intent *h,
			       const struct xdev_ext_mech_frame *f)
{
	(void)st;
	(void)h;
	(void)f;
	abort();
}
static bool xsk_xdev_ext_mech_rx_runs(u32 site, bool active, bool zc)
{
	(void)site;
	(void)zc;
	return active;
}
static int xsk_xdev_ext_mech_rx_call(struct xdev_ext_mech_stage *st,
				     struct xsk_xdev_ext_mech_stage *xst,
				     const struct xdev_ext_mech_frame *f, u32 site, s32 *ret,
				     struct xdev_ext_mech_hold_intent *h,
				     const struct xdev_ext_afxdp_rx_hold_cqe *cqe)
{
	(void)st;
	(void)xst;
	if (site == XDEV_EXT_MECH_SITE_RX_HOLD_RESULT) {
		if (!cqe->err)
			order = candidate;
		*ret = cqe->err ? XDEV_EXT_MECH_RECYCLE : XDEV_EXT_MECH_HOLD;
		return 0;
	}
	struct xdev_ext_mp_segment seg = {.generation = f->index / 6 + 1,
					  .index = f->index % 6,
					  .count = 6,
					  .relative_offset = (f->index % 6) * 100,
					  .payload_len = 100,
					  .total_len = 600};
	candidate = order;
	*ret = xdev_ext_mp_rx_order(&candidate, &seg, 1);
	if (*ret == XDEV_EXT_MECH_HOLD)
		*h = (struct xdev_ext_mech_hold_intent){.key = seg.generation,
							.pos = seg.index,
							.count = 6,
							.span_off = f->data_off,
							.span_len = 100};
	return 0;
}
static int xsk_xdev_ext_mech_rx_verdict(u32 site, bool ran, int err, s32 ret,
					const struct xdev_ext_mech_hold_intent *h, u32 off, u32 len,
					bool *perr, bool *npub)
{
	(void)site;
	(void)h;
	(void)off;
	(void)len;
	*perr = false;
	*npub = false;
	return ran && !err ? ret : XDEV_EXT_MECH_PUBLISH;
}
static int xsk_xdev_ext_mech_rx_hold_result(int admission, int err, s32 ret, bool *perr)
{
	(void)ret;
	*perr = !!err;
	return admission ? XDEV_EXT_MECH_RECYCLE : XDEV_EXT_MECH_HOLD;
}
/* Native list availability and lifecycle initialization are scheduling seams.
 * The exact production core function decides the errno for an empty free list.
 */
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define list_first_entry_or_null(head, type, member)                                               \
	((head)->boundary == 1 && busy < 1 ? &free_batch : NULL)
static void list_del_init(struct list_head *node)
{
	(void)node;
}
static int xdev_ext_mech_sess_batch_begin(struct fake_ss *ss)
{
	(void)ss;
	return begin_error;
}
static void xdev_ext_mech_bstate_init(struct fake_bs *bs, int stages)
{
	bs->stage = stages;
}
/* ACTUAL_xdev_ext_mech_batch_get_locked */
/* Hold/frame admission remains a controlled external core boundary. */
static int xdev_ext_mech_hold_commit(struct xdev_ext_mech_stage *st,
				     const struct xdev_ext_mech_hold_intent *h,
				     const struct xdev_ext_mech_frame *f)
{
	if (stop_during_commit) {
		st->s->admits = false;
		return -ESHUTDOWN;
	}
	if (!st->s->admits)
		return -ESHUTDOWN;
	if (!h->pos) {
		struct xdev_ext_mech_batch *b = xdev_ext_mech_batch_get_locked(st->s);
		if (IS_ERR(b))
			return PTR_ERR(b);
	}
	if (h->key != expected_key || h->pos != expected_pos)
		return -EPROTO;
	if (st->s->pool->state[f->index] != XDEV_EXT_MECH_F_NIC_RX)
		return -EBUSY;
	st->s->pool->state[f->index] = XDEV_EXT_MECH_F_HELD;
	owned[owned_count++] = f->index;
	held++;
	if (!h->pos)
		busy++;
	if (++expected_pos == 6) {
		expected_pos = 0;
		expected_key++;
	}
	return 0;
}
/* ACTUAL_PENDING */
/* ACTUAL_xsk_xdev_ext_mech_rx */
static u32 pending_count(struct xdp_sock *xs)
{
	(void)xs;
	return xs->xdev_ext_mech_rx->priv->pending.count;
}
static void progress(struct xdp_sock *xs, bool stop)
{
	struct xdev_ext_mech_stage st = *xs->xdev_ext_mech_rx;
	(void)st;
	xsk_rx_pending_drain(&st, stop);
}
#define CHECK(x)                                                                                   \
	do {                                                                                       \
		if (!(x)) {                                                                        \
			fprintf(stderr,                                                            \
				"FAIL line=%d expression=%s held=%u completed=%u recycled=%u "     \
				"pending=%u last_err=%d\n",                                        \
				__LINE__, #x, held, completed, recycled, pending_count(&xs),       \
				last_err);                                                         \
			return 1;                                                                  \
		}                                                                                  \
	} while (0)
static void retire(struct xdp_sock *xs)
{
	for (u32 i = 0; i < owned_count; i++) {
		if (xs->pool->state[owned[i]] != XDEV_EXT_MECH_F_HELD)
			abort();
		xs->pool->state[owned[i]] = XDEV_EXT_MECH_F_K_FREE;
	}
	owned_count = 0;
	completed += busy;
	busy = 0;
}

/* Empty retry/order lists and no START are explicit test preconditions. */
static bool list_empty(struct list_head *h)
{
	return h->boundary == 0;
}
static void list_add(struct list_head *node, struct list_head *head)
{
	(void)node;
	if (head->boundary != 1 || busy != 1)
		abort();
	busy--;
}
static void xdev_ext_mech_settle_locked(struct xdev_ext_mech_session *s)
{
	(void)s;
}
static void xdev_ext_mech_notify_locked(struct xdev_ext_mech_session *s, bool event)
{
	(void)s;
	(void)event;
}
static bool xdev_ext_mech_sess_batch_end(struct fake_ss *s, bool sequestered)
{
	if (s->state != XDEV_EXT_MECH_SESSION_ACTIVE || sequestered)
		abort();
	return false;
}
static void xdev_ext_mech_batch_run(struct xdev_ext_mech_session *s, struct xdev_ext_mech_batch *b)
{
	(void)s;
	(void)b;
	abort();
}
static bool xdev_ext_mech_order_blocked(struct xdev_ext_mech_session *s,
					struct xdev_ext_mech_batch *b)
{
	(void)s;
	(void)b;
	abort();
}
static void xdev_ext_mech_session_stop(struct xdev_ext_mech_session *s, int err)
{
	(void)err;
	s->admits = false;
	s->ss.state = XDEV_EXT_MECH_SESSION_STOPPING;
}
static void xdev_ext_mech_qrecovery_note(int *q, bool native, int stage)
{
	(void)q;
	(void)native;
	(void)stage;
	abort();
}
static void xdev_ext_mech_trace_batch(struct xdev_ext_mech_batch *b, const char *phase, u64 ticket,
				      int err)
{
	(void)b;
	(void)phase;
	(void)ticket;
	(void)err;
}
static void xdev_ext_mech_set_err_locked(struct xdev_ext_mech_session *s, int err)
{
	(void)s;
	if (err)
		abort();
}
static int xdev_ext_mech_start_queue_release(struct xdev_ext_mech_session *s,
					     struct xdev_ext_mech_batch *b, bool ok)
{
	(void)s;
	(void)b;
	(void)ok;
	abort();
}
static void xdev_ext_mech_return_idle(struct xdev_ext_mech_session *s, bool stopping)
{
	if (stopping || s->start_return_pending)
		abort();
}
static int xdev_ext_mech_frames_release(struct xdev_ext_mech_session *s,
					struct xdev_ext_mech_batch *b)
{
	(void)b;
	for (u32 i = 0; i < owned_count; i++) {
		if (s->pool->state[owned[i]] != XDEV_EXT_MECH_F_HELD)
			abort();
		s->pool->state[owned[i]] = XDEV_EXT_MECH_F_K_FREE;
	}
	owned_count = 0;
	completed++;
	return 0;
}
static u64 xdev_ext_mech_batch_key(struct xdev_ext_mech_batch *b)
{
	return b->key;
}
static struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(struct xdev_ext_mech_batch *b)
{
	(void)b;
	abort();
}
static int xdev_ext_rel_rx_finish(void *r, u64 group, int err)
{
	(void)r;
	(void)group;
	(void)err;
	finish_calls++;
	return finish_action;
}
static void xsk_rel_owe(void *r, u64 group, bool nack, u64 now)
{
	(void)r;
	(void)group;
	(void)nack;
	(void)now;
	owe_calls++;
}
static u64 ktime_get_ns(void)
{
	return 0;
}
static void xsk_mech_zc_rewake(struct xdev_ext_mech_stage *st)
{
	if (st->priv->rel)
		abort();
}
static unsigned long xsk_rel_progress(struct xdev_ext_mech_stage *st)
{
	if (st->priv->rel)
		abort();
	return 0;
}

/* ACTUAL_xdev_ext_mech_leave_locked */

/* ACTUAL_xdev_ext_mech_batch_put_locked */

/* ACTUAL_xdev_ext_mech_retry_kick */

/* ACTUAL_xdev_ext_mech_order_kick */

/* ACTUAL_xsk_rel_batch_end */

/* ACTUAL_xsk_mech_progress */

/* ACTUAL_xdev_ext_mech_end */

/* ACTUAL_xdev_ext_mech_progress_work */

static void run_due(struct xdev_ext_mech_session *s)
{
	if (s->progress_work.pending && s->progress_work.due <= tick) {
		s->progress_work.pending = false;
		progress_runs++;
		xdev_ext_mech_progress_work(&s->progress_work.work);
	}
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	bool empty = !strcmp(argv[1], "empty");
	struct xdev_ext_mech_pool pool = {.nr_frames = 4096};
	struct xdev_ext_mech_session session = {.admits = true,
						.pool = &pool,
						.free = {.boundary = 1},
						.ss = {.state = XDEV_EXT_MECH_SESSION_ACTIVE},
						.nr_stages = 1,
						.progress_ready = true};
	struct xsk_xdev_ext_mech_stage xst = {0};
	struct fake_ops ops = {.progress = xsk_mech_progress, .batch_end = xsk_rel_batch_end};
	struct xdev_ext_mech_stage st = {
	    .priv = &xst, .s = &session, .cls = &ops, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE};
	struct xdp_sock xs = {.xdev_ext_mech_rx = &st, .pool = &pool, .zc = true};
	session.st = &st;
	xst.xs = &xs;
	/* Reliable protocol transitions are a controlled boundary here; the existing
	 * reliable terminal regression separately executes the real protocol core. */
	if (!strcmp(argv[1], "reliable")) {
		struct fake_rel reliable = {.rx = {.cfg = {.window = 2}}};
		struct xsk_xdev_ext_mech_provider provider = {0};
		pool.priv = &provider;
		xst.rel = &reliable;
		xst.pending.count = 6;
		free_batch.key = 1;
		finish_action = XDEV_EXT_REL_REPLAY_ACK;
		xsk_rel_batch_end(&st, &free_batch, 0);
		CHECK(finish_calls == 1 && owe_calls == 1 && mod_calls == 1 &&
		      reliable.rx.entry[1].reply == XDEV_EXT_REL_ACK);
		session.progress_work.pending = false;
		finish_action = XDEV_EXT_REL_NONE;
		xsk_rel_batch_end(&st, &free_batch, 0);
		CHECK(finish_calls == 2 && owe_calls == 1 && mod_calls == 1 &&
		      !session.progress_work.pending);
		st.direction = 2;
		finish_action = XDEV_EXT_REL_REPLAY_ACK;
		xsk_rel_batch_end(&st, &free_batch, 0);
		CHECK(finish_calls == 2 && owe_calls == 1 && mod_calls == 1 && !busy && !held);
		printf("WAKE_REQUIRED mode=reliable ACK_kick=1 stale_no_kick=1 TX_no_kick=1\n");
		return 0;
	}
	xst.pending.entries = calloc(32, sizeof(*xst.pending.entries));
	CHECK(xst.pending.entries);
	xst.pending.capacity = 32;
	for (u32 i = 0; i < (empty ? 6U : 12U); i++) {
		struct xdp_buff_xsk f = {.index = i};
		pool.state[i] = XDEV_EXT_MECH_F_NIC_RX;
		CHECK(xsk_xdev_ext_mech_rx(&xs, &f, 100, 2) == XDEV_EXT_MECH_HOLD);
	}
	CHECK(session.progress_work.pending && session.progress_work.due == 0);
	run_due(&session);
	CHECK(busy == 1 && held == 6 && progress_runs == 1);
	unsigned before = mod_calls;
	if (empty) {
		CHECK(!pending_count(&xs) && !session.progress_work.pending);
		xdev_ext_mech_end(&session, &free_batch, XDEV_EXT_MECH_END_DONE, 0);
		CHECK(!busy && !session.progress_work.pending && mod_calls == before);
		printf("WAKE_REQUIRED mode=empty no_extra_kick=1 free=1\n");
	} else if (!strcmp(argv[1], "stop")) {
		CHECK(pending_count(&xs) == 6 && owned_count == 6);
		xdev_ext_mech_session_stop(&session, -ECANCELED);
		for (unsigned i = 0; i < 3; i++)
			xsk_rel_batch_end(&st, &free_batch, -ECANCELED);
		CHECK(session.progress_work.due == 0 && busy == 1 && owned_count == 6 && held == 6);
		run_due(&session);
		CHECK(!pending_count(&xs) && recycled == 6 && busy == 1 && owned_count == 6 &&
		      held == 6);
		for (unsigned i = 0; i < 6; i++)
			CHECK(pool.state[i] == XDEV_EXT_MECH_F_HELD);
		printf("WAKE_REQUIRED mode=stop pending_cancelled=6 prior_owner_retained=6 "
		       "new_admissions=0\n");
	} else if (!strcmp(argv[1], "worker-gone")) {
		session.worker_gone = true;
		xsk_rel_batch_end(&st, &free_batch, 0);
		CHECK(mod_calls == before && busy == 1 && held == 6 && pending_count(&xs) == 6);
		printf("WAKE_REQUIRED mode=worker-gone no_new_schedule=1 new_admissions=0\n");
	} else {
		CHECK(pending_count(&xs) == 6 && session.progress_work.pending &&
		      session.progress_work.due == 1);
		xdev_ext_mech_end(&session, &free_batch, XDEV_EXT_MECH_END_DONE, 0);
		CHECK(!busy && pending_count(&xs) == 6 && !other_work);
		if (!strcmp(argv[1], "new-packet")) {
			struct xdp_buff_xsk f = {.index = 12};
			pool.state[12] = XDEV_EXT_MECH_F_NIC_RX;
			CHECK(xsk_xdev_ext_mech_rx(&xs, &f, 100, 2) == XDEV_EXT_MECH_HOLD);
		} else if (!strcmp(argv[1], "repeat")) {
			for (unsigned i = 0; i < 4; i++)
				xsk_rel_batch_end(&st, &free_batch, 0);
			CHECK(!busy && !owned_count && held == 6 && pending_count(&xs) == 6);
		} else if (strcmp(argv[1], "tail"))
			return 2;
		/* Designated RED: completion must expedite old pending work without a packet. */
		CHECK(session.progress_work.due == 0);
		run_due(&session);
		CHECK(busy == 1 && progress_runs == 2 && held == 12);
		CHECK(pending_count(&xs) == (!strcmp(argv[1], "new-packet") ? 1U : 0U));
		printf("WAKE_REQUIRED mode=%s tick=%lu due_zero=1 old_pending_admitted=1 held=%u "
		       "busy=%u progress_runs=%u\n",
		       argv[1], tick, held, busy, progress_runs);
	}
	free(xst.pending.entries);
	return 0;
}

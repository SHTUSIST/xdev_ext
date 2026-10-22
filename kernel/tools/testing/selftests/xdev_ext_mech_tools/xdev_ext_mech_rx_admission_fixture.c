// SPDX-License-Identifier: GPL-2.0
/* Host-only fixture. Production definitions are inserted verbatim by the runner.
 * Reuse the established BPF host environment and valid-wire packet builder;
 * its differential tests are compiled but not invoked in this independent test.
 */
#define main existing_cref_test_main
#include "tools/testing/selftests/xdev_ext_mech/cref/xdev_ext_mech_cref_test.c"
#undef main
#include "io_uring/xdev_ext_mech_lifecycle.h"
#include "include/linux/xdev_ext_mech_reliable_core.h"

/* Keep every regression visible even though the reused differential harness
 * bounds its very large fuzz logs. */
#undef EXPECT
#define EXPECT(cond, ...) do { \
	checks++; \
	if (!(cond)) { \
		failures++; \
		fprintf(stderr, "FAIL %s:%d [%s] ", __FILE__, __LINE__, scenario); \
		fprintf(stderr, __VA_ARGS__); \
		fputc('\n', stderr); \
	} \
} while (0)

typedef __u64 u64;
typedef __u32 u32;
typedef __s32 s32;
typedef __u8 u8;
typedef int spinlock_t;
struct page;
struct xdev_ext_mech_pool;
/* PRODUCTION_FRAME */
/* PRODUCTION_POOL_OPS */
struct xdev_ext_mech_pool {
	const struct xdev_ext_mech_pool_ops *ops;
	void *priv;
	u32 nr_frames, frame_size;
	u8 *vaddr;
	u8 state[T_MAX];
};

/* Only the scheduler and mutual exclusion are inert in this single-threaded
 * fixture. Lists, allocation, state transitions and lifetime words are real.
 */
struct list_head { struct list_head *next, *prev; };
static void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
static void list_add_tail(struct list_head *n, struct list_head *h)
{
	n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n;
}
static void list_del_init(struct list_head *n)
{
	n->prev->next = n->next; n->next->prev = n->prev; INIT_LIST_HEAD(n);
}
#define entry(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))
#define list_first_entry_or_null(h, type, member) \
	((h)->next == (h) ? NULL : entry((h)->next, type, member))
#define list_for_each_entry(p, h, member) \
	for (p = entry((h)->next, __typeof__(*p), member); \
	     &p->member != (h); p = entry(p->member.next, __typeof__(*p), member))
#define BIT(n) (1U << (n))
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define spin_lock_irqsave(lock, flags) do { (void)(lock); (flags) = 0; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(lock); (void)(flags); } while (0)
#define WARN_ON_ONCE(c) ({ bool _bad = !!(c); if (_bad) abort(); _bad; })
static unsigned long jiffies = 1;
#define XDEV_EXT_MECH_GROUP_TIMEOUT 1000
static bool timer_pending(const int *t) { return *t; }
static void mod_timer(int *t, unsigned long expires) { *t = !!expires; }
static void atomic64_inc(u64 *p) { ++*p; }
struct xdev_ext_mech_batch {
	struct list_head node;
	struct xdev_ext_mech_group group;
	struct xdev_ext_mech_bstate bs;
	struct xdev_ext_mech_frame f[T_MAX];
	u64 id, key;
	u32 nr_frames, present, bytes, life_active;
	int abort_err, status;
	bool sequester, to_user, fifo_accepted;
	unsigned long opened;
};
struct xdev_ext_mech_session {
	struct xdev_ext_mech_pool pool;
	struct xdev_ext_mech_layout layout;
	struct xdev_ext_mech_life life[T_MAX];
	struct xdev_ext_mech_sess ss;
	struct list_head open, free;
	int lock, group_timer;
	u32 nr_stages;
	struct { u32 flags; } st[1];
	u64 next_batch_id, completed[4], counters[XDEV_EXT_MECH_CNT_NR];
};
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; u32 index, direction; void *priv; };
static u32 queued;
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s)
{ return xdev_ext_mech_sess_admits(&s->ss); }
static bool xdev_ext_mech_rx_first(struct xdev_ext_mech_session *s) { (void)s; return true; }
static u32 xdev_ext_mech_pool_frame_state(struct xdev_ext_mech_pool *p, u32 i)
{ return xdev_ext_mech_frame_state(&p->state[i]); }
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p, u32 i, u32 a, u32 b)
{ return xdev_ext_mech_frame_move(&p->state[i], a, b); }
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s, u32 n, u64 count)
{ s->counters[n] += count; }
static void xdev_ext_mech_batch_queue(struct xdev_ext_mech_batch *b) { (void)b; queued++; }
static bool xdev_ext_mech_batch_put_locked(struct xdev_ext_mech_session *s,
				     struct xdev_ext_mech_batch *b, bool quarantine)
{
	list_add_tail(&b->node, &s->free);
	return xdev_ext_mech_sess_batch_end(&s->ss, quarantine);
}
/* PRODUCTION_ALLOC */
/* PRODUCTION_FIND */
/* PRODUCTION_COMMIT */
/* PRODUCTION_SYNC */

static struct xdev_ext_mech_session sess;
static struct xdev_ext_mech_batch batch;
static struct xdev_ext_mech_stage stage = { .s = &sess };
static unsigned int commits, result_calls;
static int last_admission;
static unsigned int dead_calls;
static int dead_error, rx_result_error, rx_result_verdict;

static void reset_rx(void)
{
	memset(&sess, 0, sizeof(sess));
	memset(&batch, 0, sizeof(batch));
	memset(&w_e.rx.order, 0, sizeof(w_e.rx.order));
	xdev_ext_mech_sess_init(&sess.ss);
	INIT_LIST_HEAD(&sess.open);
	INIT_LIST_HEAD(&sess.free);
	INIT_LIST_HEAD(&batch.node);
	sess.nr_stages = 2;
	sess.pool.nr_frames = T_MAX;
	sess.pool.frame_size = T_FRAME_SIZE;
	sess.pool.vaddr = &w_e.mem[0][0];
	sess.layout = (struct xdev_ext_mech_layout) {
		.frame_size = T_FRAME_SIZE, .hdr_room = T_HDR_ROOM,
		.seg_len = T_SEG_LEN, .group_bytes = T_GROUP,
	};
	nxp_session = 0x1122334455667788ULL;
	queued = commits = result_calls = dead_calls = 0;
	dead_error = rx_result_error = 0;
	rx_result_verdict = -1;
	mock_now = 100;
	/* Session binding itself is permitted before any admission. */
	xdev_ext_mp_rx_order_session(&w_e.rx.order, 41);
}

static void add_free_batch(void) { list_add_tail(&batch.node, &sess.free); }

/* The result uses .complete, not a new struct_ops member. */
static int deliver_result(const struct xdev_ext_mech_hold_intent *h, int err)
{
#ifdef XDEV_EXT_MP_SITE_RX_HOLD_RESULT
	struct xdev_ext_afxdp_rx_hold_cqe cqe = { .key = h->key, .pos = h->pos, .err = err };
	struct mock_call *c = &w_e.call;
	c->ctx.callsite = XDEV_EXT_MP_SITE_RX_HOLD_RESULT;
	c->callsite = XDEV_EXT_MP_SITE_RX_HOLD_RESULT;
	c->frames = NULL;
	c->nr_frames = c->ctx.nr_frames = 0;
	c->cqe = &cqe;
	c->cqe_size = sizeof(cqe);
	c->cqe_cap = 1;
	result_calls++;
	return nxp_afxdp_complete(NULL, &c->ctx);
#else
	(void)h; (void)err;
	return XDEV_EXT_MP_PUBLISH; /* baseline has no result notification */
#endif
}

static int receive_segment(u32 site, u32 generation, __u16 index, u32 frame,
			   bool notify)
{
	struct xdev_ext_mech_frame f = { .index = frame, .data_off = T_DATA_OFF,
		.data_len = XDEV_EXT_MP_PKT_HDR_LEN + seg_payload(index) };
	struct xdev_ext_mech_hold_intent h;
	int verdict;

	rx_world(site, 41, nxp_session, generation, index);
	w_e.call.batch_frames = T_FRAMES;
	verdict = nxp_afxdp_complete(NULL, &w_e.call.ctx);
	if (verdict != XDEV_EXT_MP_HOLD)
		return verdict;
	h = w_e.call.hold;
	last_admission = xdev_ext_mech_hold_commit(&stage, &h, &f);
	if (!last_admission)
		commits++;
	if (notify)
		(void)deliver_result(&h, last_admission);
	return last_admission ? XDEV_EXT_MP_RECYCLE : XDEV_EXT_MP_HOLD;
}

/* Execute the actual RX entry, including its HOLD failure disposition. */
struct xdp_sock {
	struct xdev_ext_mech_stage *xdev_ext_mech_rx, *xdev_ext_mech_tx;
	bool zc;
	void *pool;
};
struct xdp_buff_xsk { struct xdev_ext_mech_frame frame; };
/* Only fields used by the extracted RX/commit bodies are required here. */
struct xsk_mech_reliable {
	struct xdev_ext_rel_tx tx;
	struct xdev_ext_rel_rx rx;
	u64 ack_pending[XDEV_EXT_REL_MAX_WINDOW];
	u64 nr_groups;
};
/* Stable native RX head identities/address mapping, not queue policy. */
struct fixture_xsk_pool { u8 heads[T_MAX]; };
struct xsk_xdev_ext_mech_provider { int tx_lock; struct fixture_xsk_pool *xp; };
/* PRODUCTION_PENDING_ENTRY */
/* PRODUCTION_PENDING_QUEUE */
struct xsk_xdev_ext_mech_stage {
	struct xsk_mech_rx_pending pending;
	bool dead;
	struct xdp_sock *xs;
	struct xsk_mech_reliable *rel;
};
#define smp_load_acquire(p) (*(p))
#define READ_ONCE(v) (v)
static void xsk_xdev_ext_mech_frame(void *pool, struct xdp_buff_xsk *xskb,
			      struct xdev_ext_mech_frame *f)
{ (void)pool; *f = xskb->frame; }
static int xsk_xdev_ext_mech_rx_call(struct xdev_ext_mech_stage *st,
			       struct xsk_xdev_ext_mech_stage *xst,
			       const struct xdev_ext_mech_frame *f, u32 site,
			       s32 *ret, struct xdev_ext_mech_hold_intent *hold,
			       const struct xdev_ext_afxdp_rx_hold_cqe *result)
{
	(void)st; (void)xst; (void)f;
	w_e.call.ctx.callsite = w_e.call.callsite = site;
	if (result) {
		w_e.call.frames = NULL;
		w_e.call.nr_frames = w_e.call.ctx.nr_frames = 0;
		_Static_assert(sizeof(*result) == 16, "result CQE must remain 16 bytes");
		w_e.call.cqe = result;
		w_e.call.cqe_size = sizeof(*result);
		w_e.call.cqe_cap = 1;
		result_calls++;
	}
	*ret = nxp_afxdp_complete(NULL, &w_e.call.ctx);
	if (hold)
		*hold = w_e.call.hold;
	if (result) {
		/* Inject return/call failures only after exercising the real BPF
		 * result callback and its exact production CQE envelope. */
		if (rx_result_verdict >= 0)
			*ret = rx_result_verdict;
		if (rx_result_error)
			return rx_result_error;
	}
	return w_e.call.protocol_error ? -EPROTO : 0;
}
static void xdev_ext_mech_frame_recycle(struct xdev_ext_mech_session *s,
				 const struct xdev_ext_mech_frame *f)
{
	EXPECT(xdev_ext_mech_frame_move(&s->pool.state[f->index],
		xdev_ext_mech_frame_state(&s->pool.state[f->index]), XDEV_EXT_MECH_F_K_FREE) == 0,
	       "recycling a frame owned by a batch");
	s->counters[XDEV_EXT_MECH_CNT_RECYCLED]++;
}
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st, int err)
{
	struct xsk_xdev_ext_mech_stage *xst = st->priv;
	dead_calls++;
	dead_error = err;
	xst->dead = true;
	st->s->ss.state = XDEV_EXT_MECH_SESSION_ERROR;
}
/* Decode is a wire-boundary shim, not a reliable admission implementation.
 * Legacy tests leave rel NULL. Reliable tests supply an already decoded
 * message, then execute the actual RX inspector and HOLD commit below. */
static struct xdev_ext_rel_msg decoded_message;
static int decode_error = XDEV_EXT_REL_BAD;
static unsigned int decode_calls, reliable_kicks;
static int xsk_rel_decode(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_frame *f,
			  struct xdev_ext_rel_msg *msg)
{
	(void)st; (void)f;
	decode_calls++;
	*msg = decoded_message;
	return decode_error;
}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{ return &s->pool; }
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st)
{ (void)st; reliable_kicks++; }
/* PRODUCTION_RESOLVE */
/* PRODUCTION_PENDING_OWNED */
/* PRODUCTION_PENDING_ADD */
/* PRODUCTION_PENDING_DRAIN */
/* PRODUCTION_REL_RX */
/* PRODUCTION_REL_COMMIT */
/* PRODUCTION_XSK_RX */

static void test_rx_entry_enospc(u32 site)
{
	struct xdp_sock xs = { .xdev_ext_mech_rx = &stage, .zc = site == XDEV_EXT_MP_SITE_RX_NATIVE };
	struct xsk_xdev_ext_mech_stage xst = { .xs = &xs };
	struct xdp_buff_xsk xskb = { .frame = { .index = 0, .data_off = T_DATA_OFF } };
	struct xdev_ext_mp_rx_order before;
	reset_rx();
	scenario = "actual XSK RX must recycle matched ENOSPC payload";
	stage.priv = &xst;
	rx_world(site, 41, nxp_session, 1, 0);
	w_e.call.batch_frames = T_FRAMES;
	before = w_e.rx.order;
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &xskb, XDEV_EXT_MP_PKT_HDR_LEN + T_SEG_LEN, site) == XDEV_EXT_MP_RECYCLE,
	       "actual XSK RX published matched payload after real HOLD ENOSPC");
	EXPECT(!memcmp(&w_e.rx.order, &before, sizeof(before)), "actual XSK RX consumed rejected order");
	EXPECT(sess.counters[XDEV_EXT_MECH_CNT_RECYCLED] == 1 &&
	       sess.counters[XDEV_EXT_MECH_CNT_NATIVE_PUBLISH] == 0,
	       "matched admission failure leaked to user RX ring");
	EXPECT(result_calls == 1 && dead_calls == 0,
	       "normal ENOSPC result must notify once without stopping session");
	add_free_batch();
	rx_world(site, 41, nxp_session, 1, 0);
	w_e.call.batch_frames = T_FRAMES;
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &xskb, XDEV_EXT_MP_PKT_HDR_LEN + T_SEG_LEN, site) == XDEV_EXT_MP_HOLD,
	       "actual XSK RX rejected same packet after restoring capacity");
	EXPECT(result_calls == 2 && w_e.rx.order.next == 1 && batch.group.present == 1 &&
	       sess.pool.state[0] == XDEV_EXT_MECH_F_HELD && !dead_calls,
	       "actual XSK success did not notify once and commit ownership/order");
	stage.priv = NULL;
}

/* Exercise the new class-private queue with the original real BPF callback,
 * core batch allocator/HOLD and lifecycle words; no admission errno seam.
 */
static void test_pending_real_core_admission(u32 site)
{
	struct xdp_sock xs = { .xdev_ext_mech_rx = &stage, .zc = site == XDEV_EXT_MP_SITE_RX_NATIVE };
	struct xsk_xdev_ext_mech_stage xst = { .xs = &xs };
	struct xsk_mech_rx_pending_entry pending[T_MAX] = {};
	struct fixture_xsk_pool xp = {};
	struct xsk_xdev_ext_mech_provider provider = { .xp = &xp };

	reset_rx();
	scenario = "actual queued RX preserves order and custody until real core capacity returns";
	stage.priv = &xst;
	sess.pool.priv = &provider;
	xst.pending.entries = pending;
	xst.pending.capacity = T_MAX;
	for (u32 i = 0; i < T_FRAMES; i++) {
		struct xdp_buff_xsk packet = { .frame = { .index = i, .data_off = T_DATA_OFF } };

		rx_world(site, 41, nxp_session, 1, i);
		w_e.call.batch_frames = T_FRAMES;
		EXPECT(xsk_xdev_ext_mech_rx(&xs, &packet,
			XDEV_EXT_MP_PKT_HDR_LEN + seg_payload(i), site) == XDEV_EXT_MP_HOLD,
			"pending RX rejected segment %u", i);
		EXPECT(xsk_rx_pending_owned(&stage, i) &&
		       sess.pool.state[i] == XDEV_EXT_MECH_F_NIC_RX &&
		       xdev_ext_mech_life_phase(&sess.life[i]) == XDEV_EXT_MECH_L_FREE,
		       "queue segment %u lost NIC custody or published READY early", i);
	}
	EXPECT(xst.pending.count == T_FRAMES && result_calls == T_FRAMES &&
	       w_e.rx.order.last_generation == 1 && !queued &&
	       !sess.counters[XDEV_EXT_MECH_CNT_HELD],
	       "queue admission changed actual core execution or canonical order");
	EXPECT(xsk_rx_pending_drain(&stage, false) == 1 &&
	       xst.pending.count == T_FRAMES && !queued && !dead_calls,
	       "real core ENOSPC must preserve every queued frame");
	add_free_batch();
	EXPECT(xsk_rx_pending_drain(&stage, false) == 0 && !xst.pending.count &&
	       queued == 1 && batch.group.present == BIT(T_FRAMES) - 1 &&
	       sess.counters[XDEV_EXT_MECH_CNT_HELD] == T_FRAMES,
	       "real core capacity did not dispatch the complete group exactly once");
	for (u32 i = 0; i < T_FRAMES; i++)
		EXPECT(!xsk_rx_pending_owned(&stage, i) &&
		       sess.pool.state[i] == XDEV_EXT_MECH_F_HELD &&
		       xdev_ext_mech_life_phase(&sess.life[i]) == XDEV_EXT_MECH_L_READY,
		       "committed segment %u lost actual batch/lifecycle ownership", i);
	EXPECT(!dead_calls && !sess.counters[XDEV_EXT_MECH_CNT_RECYCLED] &&
	       !sess.counters[XDEV_EXT_MECH_CNT_NATIVE_PUBLISH],
	       "pending drain falsely stopped, recycled or published frames");
	stage.priv = NULL;
}

static void test_pending_full_and_duplicate(u32 site, bool duplicate)
{
	struct xdp_sock xs = { .xdev_ext_mech_rx = &stage, .zc = site == XDEV_EXT_MP_SITE_RX_NATIVE };
	struct xsk_xdev_ext_mech_stage xst = { .xs = &xs };
	struct xsk_mech_rx_pending_entry pending[T_MAX] = {};
	struct fixture_xsk_pool xp = {};
	struct xsk_xdev_ext_mech_provider provider = { .xp = &xp };
	struct xdp_buff_xsk packet = { .frame = { .index = 0, .data_off = T_DATA_OFF } };
	struct xdev_ext_mp_rx_order before;

	reset_rx();
	scenario = "actual pending RX rejects overflow and protects a duplicate owner's frame";
	stage.priv = &xst;
	sess.pool.priv = &provider;
	xst.pending.entries = pending;
	xst.pending.capacity = 1;
	rx_world(site, 41, nxp_session, 1, 0);
	w_e.call.batch_frames = T_FRAMES;
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &packet, XDEV_EXT_MP_PKT_HDR_LEN + T_SEG_LEN, site) == XDEV_EXT_MP_HOLD,
	       "first pending admission rejected");
	before = w_e.rx.order;
	if (!duplicate) {
		packet.frame.index = 1;
		rx_world(site, 41, nxp_session, 1, 1);
		w_e.call.batch_frames = T_FRAMES;
	}
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &packet, XDEV_EXT_MP_PKT_HDR_LEN + T_SEG_LEN, site) ==
	       (duplicate ? XDEV_EXT_MP_HOLD : XDEV_EXT_MP_RECYCLE),
	       "duplicate/full result released the wrong custody");
	EXPECT(dead_calls == 1 && dead_error == (duplicate ? -EPROTO : -EOVERFLOW) &&
	       xsk_rx_pending_owned(&stage, 0) && xst.pending.count == 1 &&
	       sess.pool.state[0] == XDEV_EXT_MECH_F_NIC_RX &&
	       !memcmp(&w_e.rx.order, &before, sizeof(before)),
	       "failed pending admission changed earlier owner or committed order");
	EXPECT(!xsk_rx_pending_drain(&stage, true) && !xst.pending.count &&
	       sess.pool.state[0] == XDEV_EXT_MECH_F_K_FREE &&
	       sess.counters[XDEV_EXT_MECH_CNT_RECYCLED] == (duplicate ? 1 : 2) &&
	       !queued && !sess.counters[XDEV_EXT_MECH_CNT_HELD],
	       "STOP did not safely reclaim pending custody without executing a batch");
	stage.priv = NULL;
}

static void test_enospc_retry(u32 site)
{
	struct xdev_ext_mp_rx_order before;
	reset_rx();
	scenario = "real HOLD ENOSPC must not consume protocol order";
	before = w_e.rx.order;
	EXPECT(receive_segment(site, 1, 0, 0, true) == XDEV_EXT_MP_RECYCLE,
	       "capacity failure must recycle matched NXP payload");
	EXPECT(last_admission == -ENOSPC, "real HOLD commit returned %d, expected ENOSPC", last_admission);
	EXPECT(!memcmp(&w_e.rx.order, &before, sizeof(before)), "ENOSPC advanced BPF w_e.rx.order");
	EXPECT(commits == 0 && queued == 0 && sess.pool.state[0] == XDEV_EXT_MECH_F_USER,
	       "rejection acquired frame ownership or scheduled work");
	add_free_batch();
	EXPECT(receive_segment(site, 1, 0, 0, true) == XDEV_EXT_MP_HOLD,
	       "same packet was not accepted after capacity became available");
	EXPECT(commits == 1 && w_e.rx.order.next == 1 && batch.group.present == 1,
	       "accepted retry must advance exactly once");
	EXPECT(result_calls == 2, "both success and failure need a result notification");
}

static void test_only_result_commits(void)
{
	struct xdev_ext_mp_rx_order before;
	struct xdev_ext_mech_hold_intent h;
	reset_rx(); add_free_batch();
	scenario = "successful admission order is committed by result exactly once";
	before = w_e.rx.order;
	EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_GENERIC, 1, 0, 0, false) == XDEV_EXT_MP_HOLD,
	       "first segment admission failed");
	h = w_e.call.hold;
	EXPECT(!memcmp(&w_e.rx.order, &before, sizeof(before)), "pre-result callback changed canonical order");
	(void)deliver_result(&h, 0);
	EXPECT(w_e.rx.order.next == 1 && w_e.rx.order.received_len == T_SEG_LEN,
	       "success result did not advance order once");
	before = w_e.rx.order;
	(void)deliver_result(&h, 0);
	EXPECT(!memcmp(&w_e.rx.order, &before, sizeof(before)), "duplicate result advanced order twice");
	h.pos++;
	(void)deliver_result(&h, 0);
	EXPECT(!memcmp(&w_e.rx.order, &before, sizeof(before)), "unmatched result advanced order");
}

static void test_duplicate_gap_and_once(void)
{
	reset_rx(); add_free_batch();
	scenario = "duplicate and gap cannot reexecute or admit later generation";
	EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_NATIVE, 1, 0, 0, true) == XDEV_EXT_MP_HOLD,
	       "first segment rejected");
	EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_NATIVE, 1, 0, 6, true) == XDEV_EXT_MP_RECYCLE,
	       "duplicate accepted");
	EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_NATIVE, 1, 2, 7, true) == XDEV_EXT_MP_RECYCLE,
	       "out-of-order segment accepted");
	EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_NATIVE, 2, 0, 8, true) == XDEV_EXT_MP_RECYCLE,
	       "later generation crossed a missing middle segment");
	EXPECT(commits == 1 && queued == 0 && w_e.rx.order.last_generation == 0,
	       "incomplete group executed a downstream batch");
	for (__u16 i = 1; i < T_FRAMES; i++)
		EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_NATIVE, 1, i, i, true) == XDEV_EXT_MP_HOLD,
		       "in-order segment %u rejected", i);
	EXPECT(commits == T_FRAMES && queued == 1 && w_e.rx.order.last_generation == 1,
	       "complete group must queue exactly once");
	EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_NATIVE, 1, T_FRAMES - 1, 9, true) == XDEV_EXT_MP_RECYCLE,
	       "completed group replay accepted");
	EXPECT(commits == T_FRAMES && queued == 1, "replay reexecuted completed group");
}

/* Contract adapter: baseline intentionally exhibits its publish-on-error
 * behavior. A production feature macro selects the future pure result rule.
 */
static int result_disposition(int admission_err, int callback_err, s32 ret, bool *perr)
{
#ifdef XSK_XDEV_EXT_MECH_RX_HOLD_RESULT
	return xsk_xdev_ext_mech_rx_hold_result(admission_err, callback_err, ret, perr);
#else
	bool npub;
	struct xdev_ext_mech_hold_intent hold = {};
	(void)admission_err;
	return xsk_xdev_ext_mech_rx_verdict(5, true, callback_err, ret, &hold,
				     T_DATA_OFF, 100, perr, &npub);
#endif
}

static void test_post_admission_failure(void)
{
	bool perr;
	reset_rx(); add_free_batch();
	scenario = "post-admission failure cannot publish batch-owned frame";
	EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_GENERIC, 1, 0, 0, true) == XDEV_EXT_MP_HOLD,
	       "admission failed");
	EXPECT(result_disposition(0, -EIO, XDEV_EXT_MP_PUBLISH, &perr) == XDEV_EXT_MP_HOLD && perr,
	       "callback failure must retain admitted frame and signal fail-stop");
	EXPECT(sess.pool.state[0] == XDEV_EXT_MECH_F_HELD && batch.group.present == 1,
	       "successful HOLD ownership was undone");
	EXPECT(result_disposition(0, 0, XDEV_EXT_MP_PUBLISH, &perr) == XDEV_EXT_MP_HOLD && !perr,
	       "compatibility PUBLISH no-op must retain admission without protocol error");
	EXPECT(result_disposition(0, 0, XDEV_EXT_MP_RECYCLE + 100, &perr) == XDEV_EXT_MP_HOLD && perr,
	       "out-of-range result verdict must retain admission and flag protocol error");
	EXPECT(result_disposition(-ENOSPC, -EIO, XDEV_EXT_MP_PUBLISH, &perr) == XDEV_EXT_MP_RECYCLE && perr,
	       "failed admission callback must recycle matched frame");
	EXPECT(result_disposition(0, 0, XDEV_EXT_MP_HOLD, &perr) == XDEV_EXT_MP_HOLD && !perr,
	       "normal success result must keep HOLD without protocol error");
	EXPECT(result_disposition(-ENOSPC, 0, XDEV_EXT_MP_RECYCLE, &perr) == XDEV_EXT_MP_RECYCLE && !perr,
	       "normal failure result must recycle without protocol error");
}

/* Exercise actual RX fail-stop wiring, in addition to the pure disposition
 * rule above. PUBLISH is a compatibility no-op; it never releases ownership. */
static void test_rx_entry_result_outcome(u32 site, int callback_err, s32 verdict,
					 bool expect_failstop)
{
	struct xdp_sock xs = { .xdev_ext_mech_rx = &stage, .zc = site == XDEV_EXT_MP_SITE_RX_NATIVE };
	struct xsk_xdev_ext_mech_stage xst = { .xs = &xs };
	struct xdp_buff_xsk xskb = { .frame = { .index = 0, .data_off = T_DATA_OFF } };
	reset_rx(); add_free_batch();
	scenario = "actual XSK post-admission result preserves custody and enforces fail-stop";
	stage.priv = &xst;
	rx_result_error = callback_err;
	rx_result_verdict = verdict;
	rx_world(site, 41, nxp_session, 1, 0);
	w_e.call.batch_frames = T_FRAMES;
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &xskb, XDEV_EXT_MP_PKT_HDR_LEN + T_SEG_LEN, site) == XDEV_EXT_MP_HOLD,
	       "post-admission result released batch-owned frame");
	EXPECT(result_calls == 1 && sess.pool.state[0] == XDEV_EXT_MECH_F_HELD &&
	       batch.group.present == 1 && !sess.counters[XDEV_EXT_MECH_CNT_RECYCLED] &&
	       !sess.counters[XDEV_EXT_MECH_CNT_NATIVE_PUBLISH],
	       "result path recycled/published frame or skipped actual result callback");
	EXPECT(dead_calls == (unsigned int)expect_failstop && xst.dead == expect_failstop &&
	       sess.counters[XDEV_EXT_MECH_CNT_PROTOCOL_ERR] == (unsigned int)expect_failstop,
	       "result path fail-stop/protocol error does not match callback outcome");
	if (expect_failstop)
		EXPECT(dead_error == -EPROTO && !xdev_ext_mech_session_admits(&sess),
		       "callback failure did not close future session admission");
	stage.priv = NULL;
}

static u32 frame_calls, batch_calls, seen_mask;
static void sync_one(struct xdev_ext_mech_pool *p, const struct xdev_ext_mech_frame *f)
{ (void)p; frame_calls++; seen_mask |= BIT(f->index); }
#ifdef XDEV_EXT_MECH_POOL_CPU_BATCH
static void sync_batch(struct xdev_ext_mech_pool *p, const struct xdev_ext_mech_frame *f, u32 nr)
{
	(void)p; batch_calls++;
	EXPECT(nr == 3, "batch callback got %u frames, expected actual count 3", nr);
	for (u32 i = 0; i < nr; i++) seen_mask |= BIT(f[i].index);
}
#endif
static void test_cpu_sync_dispatch(void)
{
	struct xdev_ext_mech_pool_ops ops = { .sync_for_cpu = sync_one };
	reset_rx();
	scenario = "batch CPU sync covers actual frames once; legacy provider falls back";
	batch.nr_frames = 3;
	batch.f[0].index = 1; batch.f[1].index = 5; batch.f[2].index = 9;
	sess.pool.ops = &ops;
	frame_calls = batch_calls = seen_mask = 0;
	xdev_ext_mech_sync_for_cpu(&sess, &batch);
	EXPECT(frame_calls == 3 && !batch_calls && seen_mask == (BIT(1) | BIT(5) | BIT(9)),
	       "old provider no longer synchronizes every actual frame");
#ifdef XDEV_EXT_MECH_POOL_CPU_BATCH
	ops.sync_for_cpu_batch = sync_batch;
#endif
	frame_calls = batch_calls = seen_mask = 0;
	xdev_ext_mech_sync_for_cpu(&sess, &batch);
	EXPECT(batch_calls == 1 && !frame_calls && seen_mask == (BIT(1) | BIT(5) | BIT(9)),
	       "batch provider needs one callback covering all actual frames (batch=%u frame=%u mask=%x)",
	       batch_calls, frame_calls, seen_mask);
	ops.sync_for_cpu = NULL;
	frame_calls = batch_calls = seen_mask = 0;
	xdev_ext_mech_sync_for_cpu(&sess, &batch);
	EXPECT(batch_calls == 1 && !frame_calls && seen_mask == (BIT(1) | BIT(5) | BIT(9)),
	       "batch-only provider was skipped");
	memset(&ops, 0, sizeof(ops));
	xdev_ext_mech_sync_for_cpu(&sess, &batch); /* no optional sync callbacks is legal */
}

/* The reliable flag changes the legacy partial-group timer, not HOLD custody. */
static void test_partial_group_timer_modes(void)
{
	for (u32 reliable = 0; reliable < 2; reliable++) {
		reset_rx(); add_free_batch();
		scenario = "actual HOLD timer is explicit for legacy and reliable modes";
		sess.st[0].flags = reliable ? XDEV_EXT_AFXDP_F_RELIABLE : 0;
		EXPECT(receive_segment(XDEV_EXT_MP_SITE_RX_NATIVE, 1, 0, 0, true) == XDEV_EXT_MP_HOLD,
		       "mode %u failed ordinary HOLD custody", reliable);
		EXPECT(sess.group_timer == !reliable && batch.group.present == 1 &&
		       sess.pool.state[0] == XDEV_EXT_MECH_F_HELD,
		       "mode %u changed custody or armed the wrong partial-group timer", reliable);
	}
}

static void reliable_fixture(struct xsk_xdev_ext_mech_stage *xst,
			      struct xsk_mech_reliable *rel,
			      struct xsk_xdev_ext_mech_provider *provider)
{
	struct xdev_ext_rel_cfg cfg = {
		.session = nxp_session, .first_group = 1, .timeout_ns = 1000,
		.window = 2, .max_attempts = 3, .group_bytes = T_GROUP,
		.seg_len = 1408, /* v3 at MTU 1500: 20+8+64 protocol bytes */
	};

	memset(rel, 0, sizeof(*rel));
	memset(provider, 0, sizeof(*provider));
	EXPECT(!xdev_ext_rel_rx_init(&rel->rx, &cfg) && !xdev_ext_rel_tx_init(&rel->tx, &cfg),
	       "reliable fixture configuration rejected");
	xst->rel = rel;
	stage.priv = xst;
	stage.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	sess.st[0].flags = XDEV_EXT_AFXDP_F_RELIABLE;
	sess.layout.hdr_room = T_DATA_OFF + 106;
	sess.layout.seg_len = cfg.seg_len;
	sess.pool.priv = provider;
	decoded_message = (struct xdev_ext_rel_msg) {
		.session = cfg.session, .group = 1, .attempt = 1,
		.total_len = cfg.group_bytes, .payload_len = cfg.seg_len,
		.index = 0, .count = 6, .type = XDEV_EXT_REL_DATA,
	};
	decode_error = 0;
	decode_calls = reliable_kicks = 0;
}

/* Use the actual reliable inspector/commit adapter and the actual core HOLD.
 * A decoded message is the only injected boundary; no wire/CRC claim is made. */
static void test_reliable_hold_capacity_and_replay(void)
{
	struct xsk_xdev_ext_mech_stage xst = {};
	struct xsk_mech_reliable rel;
	struct xsk_xdev_ext_mech_provider provider;
	struct xdev_ext_mech_frame f = { .index = 0, .data_off = T_DATA_OFF,
		.data_len = 106 + 1408 };
	struct xdev_ext_mech_hold_intent hold = { .key = 1, .pos = 0, .count = 6,
		.span_off = T_DATA_OFF + 106, .span_len = 1408 };
	struct xdev_ext_rel_rx before;
	struct xdev_ext_rel_msg message;

	reset_rx();
	scenario = "real reliable HOLD commits protocol state only after core admission";
	reliable_fixture(&xst, &rel, &provider);
	before = rel.rx;
	EXPECT(xsk_rel_rx(&stage, &f, &message) == XDEV_EXT_REL_HOLD,
	       "valid decoded message was not inspected as HOLD");
	EXPECT(xsk_rel_hold_commit(&stage, &message, &hold, &f) == -ENOSPC,
	       "missing batch capacity did not reject real core HOLD");
	EXPECT(!memcmp(&before, &rel.rx, sizeof(before)) &&
	       sess.pool.state[0] == XDEV_EXT_MECH_F_USER && !queued,
	       "ENOSPC consumed reliable order/credit or native custody");
	add_free_batch();
	EXPECT(!xsk_rel_hold_commit(&stage, &message, &hold, &f),
	       "same decoded message failed after capacity became available");
	EXPECT(rel.rx.entry[1].present == 1 && batch.group.present == 1 &&
	       sess.pool.state[0] == XDEV_EXT_MECH_F_HELD && !sess.group_timer,
	       "successful reliable HOLD did not commit both views or disabled legacy timer");
	EXPECT(xsk_rel_rx(&stage, &f, &message) == XDEV_EXT_REL_RECYCLE && !queued &&
	       sess.counters[XDEV_EXT_MECH_CNT_HELD] == 1,
	       "duplicate decoded DATA was held or submitted twice");
	/* Deliberately deliver segment 2 before segment 1. */
	const u32 order[] = { 2, 1, 3, 4, 5 };
	for (u32 i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
		u32 pos = order[i], len = pos == 5 ? T_GROUP - 5 * 1408 : 1408;

		decoded_message.index = pos;
		decoded_message.relative_offset = pos * 1408;
		decoded_message.payload_len = len;
		f.index = pos; f.data_len = 106 + len;
		hold.pos = pos; hold.span_len = len;
		EXPECT(xsk_rel_rx(&stage, &f, &message) == XDEV_EXT_REL_HOLD &&
		       !xsk_rel_hold_commit(&stage, &message, &hold, &f),
		       "out-of-order reliable segment %u failed actual HOLD", pos);
		EXPECT(queued == (pos == 5), "partial group queued early or full group not queued");
	}
	EXPECT(rel.rx.entry[1].state == XDEV_EXT_REL_RX_SUBMITTED && queued == 1 &&
	       sess.counters[XDEV_EXT_MECH_CNT_HELD] == 6,
	       "complete reliable group did not submit exactly once");
	EXPECT(xdev_ext_rel_rx_finish(&rel.rx, 1, 0) == XDEV_EXT_REL_REPLAY_ACK,
	       "explicit downstream-complete fixture record rejected");
	EXPECT(xsk_rel_rx(&stage, &f, &message) == XDEV_EXT_REL_REPLAY_ACK &&
	       rel.ack_pending[1] == 1 && reliable_kicks == 1 && queued == 1,
	       "completed replay did not only schedule another ACK");
	stage.priv = NULL;
}

static void test_reliable_rx_early_recycle_and_tx_fallback(void)
{
	struct xdp_sock xs = { .xdev_ext_mech_rx = &stage, .zc = true };
	struct xsk_xdev_ext_mech_stage xst = { .xs = &xs };
	struct xsk_mech_reliable rel;
	struct xsk_xdev_ext_mech_provider provider;
	struct xdp_buff_xsk xskb = { .frame = { .index = 0, .data_off = T_DATA_OFF } };

	reset_rx();
	scenario = "real reliable RX recycles bad/credit-blocked/control packets before legacy BPF";
	reliable_fixture(&xst, &rel, &provider);
	decode_error = XDEV_EXT_REL_BAD;
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &xskb, 106 + 1408, XDEV_EXT_MP_SITE_RX_NATIVE) == XDEV_EXT_MP_RECYCLE &&
	       decode_calls == 1 && result_calls == 0 && !queued &&
	       sess.counters[XDEV_EXT_MECH_CNT_NATIVE_PUBLISH] == 0,
	       "bad reliable decode reached BPF admission or user publication");
	decode_error = 0;
	decoded_message.group = rel.rx.credit;
	xskb.frame.index = 1;
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &xskb, 106 + 1408, XDEV_EXT_MP_SITE_RX_NATIVE) == XDEV_EXT_MP_RECYCLE &&
	       !rel.rx.entry[1].present && !queued && !result_calls,
	       "credit-blocked DATA acquired custody or reached legacy BPF");
	xs.xdev_ext_mech_rx = NULL; xs.xdev_ext_mech_tx = &stage;
	stage.direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
	decoded_message = (struct xdev_ext_rel_msg) { .session = nxp_session,
		.group = 1, .attempt = 1, .credit = rel.tx.credit, .type = XDEV_EXT_REL_ACK };
	xskb.frame.index = 2;
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &xskb, 106, XDEV_EXT_MP_SITE_RX_NATIVE) == XDEV_EXT_MP_RECYCLE &&
	       reliable_kicks == 1 && !result_calls && !queued,
	       "TX-only reliable socket did not consume ACK through actual RX fallback");
	xst.rel = NULL;
	xskb.frame.index = 3;
	EXPECT(xsk_xdev_ext_mech_rx(&xs, &xskb, 106, XDEV_EXT_MP_SITE_RX_NATIVE) == XDEV_EXT_MP_PUBLISH &&
	       sess.pool.state[3] == XDEV_EXT_MECH_F_USER,
	       "legacy TX-only socket incorrectly intercepted RX");
	stage.priv = NULL;
}

int main(void)
{
	test_rx_entry_enospc(XDEV_EXT_MP_SITE_RX_GENERIC);
	test_rx_entry_enospc(XDEV_EXT_MP_SITE_RX_NATIVE);
	test_enospc_retry(XDEV_EXT_MP_SITE_RX_GENERIC);
	test_enospc_retry(XDEV_EXT_MP_SITE_RX_NATIVE);
	test_only_result_commits();
	test_duplicate_gap_and_once();
	test_post_admission_failure();
	for (u32 site = XDEV_EXT_MP_SITE_RX_GENERIC; site <= XDEV_EXT_MP_SITE_RX_NATIVE; site++) {
		test_rx_entry_result_outcome(site, -EIO, XDEV_EXT_MP_HOLD, true);
		test_rx_entry_result_outcome(site, 0, XDEV_EXT_MP_RECYCLE + 100, true);
		test_rx_entry_result_outcome(site, 0, XDEV_EXT_MP_PUBLISH, false);
	}
	for (u32 site = XDEV_EXT_MP_SITE_RX_GENERIC; site <= XDEV_EXT_MP_SITE_RX_NATIVE; site++) {
		test_pending_real_core_admission(site);
		test_pending_full_and_duplicate(site, false);
		test_pending_full_and_duplicate(site, true);
	}
	test_cpu_sync_dispatch();
	test_partial_group_timer_modes();
	test_reliable_hold_capacity_and_replay();
	test_reliable_rx_early_recycle_and_tx_fallback();
	printf("RX admission / CPU sync: %lu checks, %lu failures\n", checks, failures);
	return failures ? 1 : 0;
}

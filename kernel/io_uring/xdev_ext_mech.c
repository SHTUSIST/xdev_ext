// SPDX-License-Identifier: GPL-2.0
/*
 * XDEV_EXT mechanism layer, session side.  IORING_REGISTER_XDEV_EXT_MECH creates a
 * session: a chain of up to four stages (NVMe, AF_XDP, copy engine) over one
 * frame pool, with one kthread_worker that runs every batch step.  eBPF
 * fills native descriptors in a scratch area and interprets completions; C
 * here owns admission, batches, frame ownership words, generation pinning,
 * the bounded drain and the quarantine of anything a device may still use.
 */

#include <linux/align.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/crc32.h>
#include <linux/err.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nvme.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/xdev_ext_binding.h>
#include <linux/xdev_ext_mech.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <uapi/linux/if_xdp.h>

#include "xdev_ext_mech_core.h"
#include "xdev_ext_mech_lifecycle.h"
#include "xdev_ext_mech_internal.h"
#include "xdev_ext_policy.h"
#include "xdev_ext_mech_notify.h"
#include "xdev_ext_mech_step.h"
#include "xdev_ext_mech_produced.h"

/* What the contract headers mirror from kernel definitions. */
static_assert(XDEV_EXT_MECH_NVME_STATUS_DNR == NVME_STATUS_DNR);
static_assert(XDEV_EXT_MECH_NVME_SCT_SC_MASK == NVME_SCT_SC_MASK);
static_assert(sizeof(struct xdp_desc) == 16);
static_assert(sizeof(struct nvme_command) == XDEV_EXT_NVME_MECH_DESC_SIZE);
static_assert(offsetof(struct xdev_ext_mech_call, ctx) == 0);
static_assert(__builtin_types_compatible_p(typeof(&crc32c), xdev_ext_mech_crc32c_fn));

#define XDEV_EXT_MECH_GROUP_TIMEOUT	HZ		/* RX group, as user space waits */
#define XDEV_EXT_MECH_DRAIN_TIMEOUT	(5 * HZ)

enum xdev_ext_mech_end {
	XDEV_EXT_MECH_END_DONE,
	XDEV_EXT_MECH_END_ABORT,
	XDEV_EXT_MECH_END_SEQUESTER,
};

struct xdev_ext_mech_batch {
	struct xdev_ext_mech_session *s;
 struct xdev_ext_mech_batch *parent;
 u32 fan_first, fan_end, fan_pending;
 int fan_error;
 bool fan_sequester;
	struct llist_node inbox_node;
	u32 queued;
	struct xdev_ext_mech_completion completion;
	u64 ticket;
	struct list_head node;		/* s->free or s->open, under s->lock */
	struct xdev_ext_mech_bstate bs;	/* s->lock while OPEN, else the worker */
	struct xdev_ext_mech_group group;	/* RX holds, under s->lock */
	u64 id;
	u64 key;			/* RX hold key or START sequence */
	unsigned long opened;		/* jiffies of the first RX hold */
	int abort_err;			/* an OPEN batch queued for abort */
	int status;			/* what the native command completed with */
	u32 life_active;		/* lifecycle acquisitions for this step */
	u64 life_token[XDEV_EXT_MECH_MAX_FRAMES];
	u32 life_previous[XDEV_EXT_MECH_MAX_FRAMES]; /* legacy evidence only */
	bool producing;
 bool produced_set;
 u32 produced, produced_used;
	bool fifo_accepted;
	u32 present;			/* frames held, one bit per position */
	u32 nr_frames;
	u32 bytes;
	bool sequester;			/* the completion was a sequester */
	bool locally_cancelled;		/* explicit non-native cancellation origin */
	bool to_user;			/* frames go back to user space at the end */
	void *priv;			/* class area of s->priv_size bytes */
	void *cookie;			/* stable native callback identity */
 struct {
  struct xdev_ext_mech_frame dst[XDEV_EXT_MECH_MAX_FRAMES];
  u64 token[XDEV_EXT_MECH_MAX_FRAMES];
  u32 nr, produced;
  bool active;
 } transform;
	struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
};

struct xdev_ext_mech_session {
	struct list_head ring_node;	/* ctx->xdev_ext_mech_sessions: uring_lock, RCU readers */
	struct list_head all_node;	/* xdev_ext_mech_all, xdev_ext_mech_all_lock */
	struct list_head quarantine_node;
	struct list_head live_node;	/* xdev_ext_mech_live, xdev_ext_mech_live_lock */
	struct io_ring_ctx *ctx;
	u64 id;
	kuid_t uid;			/* creator, for STATS from another ring */

	spinlock_t lock;		/* the fields up to last_err */
	struct xdev_ext_mech_sess ss;
	struct xdev_ext_mech_notify_state notify; /* and target counters, under lock */
	struct list_head open;		/* OPEN RX batches */
	struct list_head free;		/* unused batch objects */
	struct list_head ordered;	/* READY, waiting for their turn; worker */
	struct list_head retry;		/* preaccept backpressure; worker */
	u64 next_batch_id;
	u64 start_left;			/* START batches not yet taken */
	u64 start_seq;
	bool start_to_user;
	bool start_recycle;		/* explicit bounded USER_FRAMES START */
	u32 start_user_len;		/* USER_SPANS actual bytes; zero: legacy capacity */
	bool start_preparing;		/* CPU START copy/custody handoff in progress */
	u32 start_legacy_events;	/* prior batches finishing during the handoff */
	bool start_return_pending;	/* queued loans must precede terminal wake */
	bool worker_gone;
	bool release_deferred;		/* drain bound passed; the last batch decides */
	u32 cmd_refs;			/* uring_cmd stage references */
	int stop_err;			/* first reason the session stopped */
	int last_err;

	struct xdev_ext_mech_layout layout;
	struct xdev_ext_mech_peer peer;
	u32 depth;
	u32 frames;			/* frames per batch */
	u32 nr_stages;
	u32 nr_bound;			/* stages whose ->bind succeeded */
	struct xdev_ext_mech_stage st[XDEV_EXT_MECH_MAX_STAGES];
 struct xdev_ext_mech_stage_uapi plan[XDEV_EXT_MECH_MAX_STAGES];
	const void *ops[XDEV_EXT_MECH_CLASS_MAX];	/* per class, for life */
	bool pinned[XDEV_EXT_MECH_CLASS_MAX];
	struct module *c_owner[XDEV_EXT_MECH_CLASS_MAX];	/* C reference ops */
	struct xdev_ext_mech_pool pool;
	/* Authoritative lifecycle only while provider custody admits a frame. */
	struct xdev_ext_mech_life *life;
 bool owns_life;
 u8 *transform_owner; /* stage index + 1; reserved output custody */
	struct file *pool_file;

	struct kthread_worker *worker;
	bool order_kicking;		/* the worker drains s->ordered */
	struct llist_head inbox;
	struct kthread_work drain_work;
	struct kthread_delayed_work retry_work;
	struct kthread_work stop_work;
	struct kthread_work kick_work;
 struct kthread_delayed_work progress_work;
 atomic_t native_controls;
	struct work_struct reap_work;
	struct timer_list group_timer;
	wait_queue_head_t drain_wq;
	struct eventfd_ctx *evfd;

	/* Used by one batch step at a time: CREATE, then the worker. */
	u8 *info;
	u8 *scratch;
	u8 *cqe;
	u32 priv_size;
	struct xdev_ext_mech_batch *batches;
 struct xdev_ext_mech_batch *fan_batches;
	u8 *privs;
	u8 *cookies;

	atomic64_t cnt[XDEV_EXT_MECH_CNT_NR];
	atomic64_t done;
	atomic64_t aborted;
	atomic64_t submitted[XDEV_EXT_MECH_MAX_STAGES];
	atomic64_t completed[XDEV_EXT_MECH_MAX_STAGES];
};

static atomic64_t xdev_ext_mech_next_id;
static LIST_HEAD(xdev_ext_mech_all);
static DEFINE_SPINLOCK(xdev_ext_mech_all_lock);

/*
 * Every session from CREATE until it is freed, quarantined ones for good:
 * what STATS finds through a ring that does not own the session.
 */
static LIST_HEAD(xdev_ext_mech_live);
static DEFINE_MUTEX(xdev_ext_mech_live_lock);

/* Sessions whose references are parked for good; nothing leaves the list. */
static LIST_HEAD(xdev_ext_mech_quarantined);
static DEFINE_MUTEX(xdev_ext_mech_quarantine_lock);
static struct xdev_ext_mech_quarantine xdev_ext_mech_parked;

/*
 * s->lock serializes arm, target counters, terminal state and the decision.
 * Signal under that lock so rearm cannot overtake the previous arm's wake.
 * Results and custody updates precede this wake; it is not a DMA fence.
 */
static void xdev_ext_mech_notify_locked(struct xdev_ext_mech_session *s, bool legacy_event)
{
	u64 finished;

	lockdep_assert_held(&s->lock);
	if (s->start_preparing) {
		if (legacy_event && !s->notify.coarse && s->evfd)
			s->start_legacy_events++;
		return;
	}
	if (s->start_return_pending)
		return;
	/* Only the at most depth (64) prior batches can finish while preparing:
	 * START requires start_left == 0 and start_more is gated throughout.
	 * Keep the legacy ABI of one eventfd count per finished batch.
	 */
	while (s->start_legacy_events) {
		s->start_legacy_events--;
		eventfd_signal(s->evfd);
	}
	finished = atomic64_read(&s->done) + atomic64_read(&s->aborted);
	if (xdev_ext_mech_notify_signal(&s->notify, finished,
			atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_PUBLISHED]),
			s->ss.state, s->last_err, legacy_event) && s->evfd)
		eventfd_signal(s->evfd);
}

static bool xdev_ext_mech_rx_first(const struct xdev_ext_mech_session *s)
{
	return s->st[0].class_id == XDEV_EXT_MECH_CLASS_AFXDP &&
	       s->st[0].direction == XDEV_EXT_MECH_DIR_FROM_DEVICE;
}

static struct xdev_ext_binding_ctx_v2 xdev_ext_mech_base(const struct xdev_ext_mech_stage *st,
					       u64 bytes)
{
	bool to_dev = st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE;
	u32 caps = st->s->pool.capabilities;

	switch (st->class_id) {
	case XDEV_EXT_MECH_CLASS_NVME:
		return xdev_ext_binding_make_nvme_ctx(to_dev, 0, bytes);
	case XDEV_EXT_MECH_CLASS_AFXDP:
		if (caps & XDEV_EXT_BINDING_CAP_ZERO_COPY)
			return to_dev ? xdev_ext_binding_make_afxdp_native_tx_ctx(0, bytes, caps) :
					xdev_ext_binding_make_afxdp_rx_ctx(0, bytes, caps);
		return to_dev ? xdev_ext_binding_make_afxdp_tx_ctx(bytes) :
				xdev_ext_binding_make_afxdp_rx_ctx(0, bytes, 0);
	case XDEV_EXT_MECH_CLASS_CPU:
	case XDEV_EXT_MECH_CLASS_IAA:
	case XDEV_EXT_MECH_CLASS_SOCKET:
	case XDEV_EXT_MECH_CLASS_NET:
	case XDEV_EXT_MECH_CLASS_DMA:
		/* Common metadata only; DMA never enters the legacy policy validator. */
		return (struct xdev_ext_binding_ctx_v2) {
			.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
			.ctx_size = sizeof(struct xdev_ext_binding_ctx_v2),
			.backend = XDEV_EXT_BINDING_BACKEND_UNSPEC,
			.direction = st->direction,
			.length = bytes,
		};
	default:
		return xdev_ext_binding_make_gpu_ctx(st->direction, 0, 0, bytes);
	}
}

int xdev_ext_mech_call(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_call_args *a,
		  s32 *ret, struct xdev_ext_mech_hold_intent *hold)
{
	struct xdev_ext_mech_session *s;
	struct xdev_ext_mech_target t;

	if (!st || !st->s || !a)
		return -EINVAL;
	s = st->s;
	if (!s->ops[st->class_id])
		return -ENOENT;
	t = (struct xdev_ext_mech_target) {
		.s = s,
		.st = st,
		.session_id = s->id,
		.batch_id = a->batch_id,
		.class_id = st->class_id,
		.frame_size = s->layout.frame_size,
		.hdr_room = s->layout.hdr_room,
		.batch_frames = s->frames,
	};
	if (a->b) {
		t.batch = true;
		t.batch_id = a->b->id;
		t.key = a->b->key;
		t.bytes = a->b->bytes;
	}
	return xdev_ext_mech_invoke(s->ops[st->class_id], &t, a, ret, hold);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_call);

/* Frame ownership words and session counters. */

int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *pool, u32 index, u32 from,
			     u32 to)
{
	if (!pool->state || index >= pool->nr_frames)
		return -ERANGE;
	return xdev_ext_mech_frame_move(&pool->state[index], from, to);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_pool_frame_move);

u32 xdev_ext_mech_pool_frame_state(const struct xdev_ext_mech_pool *pool, u32 index)
{
	if (!pool->state || index >= pool->nr_frames)
		return XDEV_EXT_MECH_F_NR;
	return xdev_ext_mech_frame_state(&pool->state[index]);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_pool_frame_state);

void xdev_ext_mech_count(struct xdev_ext_mech_session *s, enum xdev_ext_mech_counter c, u64 n)
{
	unsigned long flags;

	if ((u32)c >= XDEV_EXT_MECH_CNT_NR)
		return;
	/* Published callers do not already hold s->lock. */
	if (c == XDEV_EXT_MECH_CNT_PUBLISHED) {
		spin_lock_irqsave(&s->lock, flags);
		atomic64_add(n, &s->cnt[c]);
		xdev_ext_mech_notify_locked(s, false);
		spin_unlock_irqrestore(&s->lock, flags);
	} else {
		atomic64_add(n, &s->cnt[c]);
	}
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_count);

void xdev_ext_mech_frame_recycle(struct xdev_ext_mech_session *s,
			    struct xdev_ext_mech_frame *f)
{
	u32 state = xdev_ext_mech_pool_frame_state(&s->pool, f->index);

	if ((state == XDEV_EXT_MECH_F_USER || state == XDEV_EXT_MECH_F_NIC_RX) &&
	    !xdev_ext_mech_pool_frame_move(&s->pool, f->index, state,
				      XDEV_EXT_MECH_F_K_FREE))
		state = XDEV_EXT_MECH_F_K_FREE;
	if (state != XDEV_EXT_MECH_F_K_FREE) {
		/* A frame inside a batch is not the caller's to recycle. */
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
		return;
	}
	s->pool.ops->recycle(&s->pool, f);
	xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_RECYCLED, 1);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_frame_recycle);

int xdev_ext_mech_frame_publish(struct xdev_ext_mech_session *s,
			   const struct xdev_ext_mech_frame *f)
{
	u32 state = xdev_ext_mech_pool_frame_state(&s->pool, f->index);

	if (state == XDEV_EXT_MECH_F_K_FREE &&
	    !xdev_ext_mech_pool_frame_move(&s->pool, f->index, XDEV_EXT_MECH_F_K_FREE,
				      XDEV_EXT_MECH_F_USER))
		state = XDEV_EXT_MECH_F_USER;
	if (state != XDEV_EXT_MECH_F_USER)
		return -EBUSY;
	xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PUBLISHED, 1);
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_frame_publish);

/* Every frame present in @b moves @from -> @to, or none does. */
static int xdev_ext_mech_frames_move(struct xdev_ext_mech_session *s,
				struct xdev_ext_mech_batch *b, u32 from, u32 to)
{
	u32 pos, moved = 0;
	int ret = 0;

	for (pos = 0; pos < b->nr_frames; pos++) {
		if (!(b->present & BIT(pos)))
			continue;
		ret = xdev_ext_mech_pool_frame_move(&s->pool, b->f[pos].index, from,
					       to);
		if (ret)
			break;
		moved |= BIT(pos);
	}
	if (ret)
		for (pos = 0; pos < b->nr_frames; pos++)
			if (moved & BIT(pos))
				xdev_ext_mech_pool_frame_move(&s->pool,
							 b->f[pos].index, to,
							 from);
	return ret;
}

/* A finished batch's HELD frames go back to user space or to the pool. */
static int xdev_ext_mech_frames_release(struct xdev_ext_mech_session *s,
				    struct xdev_ext_mech_batch *b)
{
	bool recycle = b->to_user && s->start_recycle &&
		READ_ONCE(s->start_left) && xdev_ext_mech_session_admits(s);
	u32 to = b->to_user && !recycle ? XDEV_EXT_MECH_F_USER : XDEV_EXT_MECH_F_K_FREE;
	u32 pos, done = 0, parked = 0;

	/* Validate the whole batch before returning any provider custody. */
	for (pos = 0; pos < b->nr_frames; pos++) {
		u32 phase;

		if (!(b->present & BIT(pos)))
			continue;
		phase = xdev_ext_mech_life_phase(&s->life[b->f[pos].index]);
		if (WARN_ON_ONCE((phase != XDEV_EXT_MECH_L_FREE &&
				 phase != XDEV_EXT_MECH_L_READY) ||
			xdev_ext_mech_pool_frame_state(&s->pool, b->f[pos].index) !=
			XDEV_EXT_MECH_F_HELD))
			goto quarantine;
	}
	for (pos = 0; pos < b->nr_frames; pos++) {
		struct xdev_ext_mech_frame *f = &b->f[pos];

		if (!(b->present & BIT(pos)))
			continue;
  if (s->transform_owner[f->index]) {
   if (xdev_ext_mech_life_phase(&s->life[f->index]) != XDEV_EXT_MECH_L_FREE &&
       xdev_ext_mech_life_release(&s->life[f->index],
                                xdev_ext_mech_life_gen(&s->life[f->index])))
    goto quarantine;
   done |= BIT(pos);
   continue; /* stage lease remains HELD until unbind */
  }
		/* FREE includes a failed producer or a not-yet-started batch. */
		/* Even a terminal transform's READY output closes this publication.
		 * A later RECYCLE loan installs new consumers over its valid span. */
		if (xdev_ext_mech_life_phase(&s->life[f->index]) != XDEV_EXT_MECH_L_FREE &&
		    WARN_ON_ONCE(xdev_ext_mech_life_release(&s->life[f->index],
				xdev_ext_mech_life_gen(&s->life[f->index]))))
			goto quarantine;
		if (WARN_ON_ONCE(xdev_ext_mech_pool_frame_move(&s->pool, f->index,
							  XDEV_EXT_MECH_F_HELD, to)))
			goto quarantine;
		done |= BIT(pos);
		if (to == XDEV_EXT_MECH_F_USER) {
			xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PUBLISHED, 1);
		} else {
			s->pool.ops->recycle(&s->pool, f);
			xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_RECYCLED, 1);
		}
	}
	return 0;
quarantine:
	/* Never return an active/unknown lifecycle to the allocator.  Frames
	 * already returned are user space's or the pool's again; park the
	 * HELD rest one by one and count exactly those.
	 */
	for (pos = 0; pos < b->nr_frames; pos++)
		if ((b->present & ~done & BIT(pos)) &&
		    !xdev_ext_mech_pool_frame_move(&s->pool, b->f[pos].index,
					      XDEV_EXT_MECH_F_HELD,
					      XDEV_EXT_MECH_F_SEQUESTERED))
			parked++;
	xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_SEQUESTERED, parked);
	return -EIO;
}

static bool xdev_ext_mech_transform_alias(struct xdev_ext_mech_pool *p,
                    const struct xdev_ext_mech_frame *a,
                    const struct xdev_ext_mech_frame *b);

/*
 * CREATE: a table of the page bytes of reserved frames [@first, @first + @nr),
 * sorted, then one walk of every other frame: O((pool + table) log table).
 */
static int xdev_ext_mech_transform_alias_free(struct xdev_ext_mech_session *s,
                        u32 first, u32 nr)
{
 struct xdev_ext_mech_alias_seg *table;
 u32 i, j, off, po, len, fs = s->pool.frame_size;
 size_t n = 0, cap = 0;
 struct page *page;
 int err = 0;
 for (i = 0; i < nr; i++) {
  struct xdev_ext_mech_frame out = { .index = first + i };
  for (off = 0; off < fs; off += len) {
   if (!xdev_ext_mech_frame_page(&s->pool, &out, off, &po, &len))
    return -EINVAL;
   len = min(len, fs - off);
   cap++;
  }
 }
 table = kvmalloc_array(cap, sizeof(*table), GFP_KERNEL);
 if (!table)
  return -ENOMEM;
 for (i = 0; i < nr; i++) {
  struct xdev_ext_mech_frame out = { .index = first + i };
  for (off = 0; off < fs && n < cap; off += len, n++) {
   page = xdev_ext_mech_frame_page(&s->pool, &out, off, &po, &len);
   len = min(len, fs - off);
   table[n] = (struct xdev_ext_mech_alias_seg){ .page = page, .off = po, .len = len };
  }
 }
 xdev_ext_mech_alias_sort(table, n);
 /* Two reserved outputs, or two pages of one, share bytes. */
 if (xdev_ext_mech_alias_overlapping(table, n))
  err = -EINVAL;
 for (j = 0; !err && j < s->pool.nr_frames; j++) {
  struct xdev_ext_mech_frame other = { .index = j };
  if (j >= first && j - first < nr)
   continue;
  for (off = 0; off < fs; off += len) {
   page = xdev_ext_mech_frame_page(&s->pool, &other, off, &po, &len);
   if (!page) { err = -EINVAL; break; }
   len = min(len, fs - off);
   if (xdev_ext_mech_alias_hits(table, n, page, po, len)) { err = -EINVAL; break; }
  }
  cond_resched(); /* uring_lock is a mutex; a 1 GiB pool is many frames */
 }
 kvfree(table);
 return err;
}

/*
 * CREATE owns these output frames until unbind; START cannot lend them.
 * The pool's pages are pinned at registration and fixed while the session
 * holds it, so this one proof covers every later batch: a reserved output
 * shares no page byte with any other frame, START sources included.
 */
int xdev_ext_mech_transform_reserve(struct xdev_ext_mech_stage *st, u32 first, u32 nr)
{
 struct xdev_ext_mech_session *s = st->s;
 u32 i;
 int err;
 if (s->pool.kind != XDEV_EXT_MECH_POOL_IOU_UMEM || !nr ||
     first >= s->pool.nr_frames || nr > s->pool.nr_frames - first)
  return -EINVAL;
 err = xdev_ext_mech_transform_alias_free(s, first, nr);
 if (err)
  return err;
 for (i = 0; i < nr; i++) {
  if (s->transform_owner[first + i]) { err = -EBUSY; goto undo; }
  err = xdev_ext_mech_pool_frame_move(&s->pool, first + i,
                         XDEV_EXT_MECH_F_USER, XDEV_EXT_MECH_F_HELD);
  if (err) goto undo;
  s->transform_owner[first + i] = st->index + 1;
 }
 return 0;
undo:
 while (i--) {
  s->transform_owner[first + i] = 0;
  xdev_ext_mech_pool_frame_move(&s->pool, first + i,
                         XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_USER);
 }
 return err;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_transform_reserve);

void xdev_ext_mech_transform_unreserve(struct xdev_ext_mech_stage *st, u32 first, u32 nr)
{
 struct xdev_ext_mech_session *s = st->s;
 u32 i;
 for (i = 0; i < nr; i++) {
  u32 idx = first + i;
  if (WARN_ON_ONCE(idx >= s->pool.nr_frames ||
      s->transform_owner[idx] != st->index + 1 ||
      xdev_ext_mech_life_phase(&s->life[idx]) != XDEV_EXT_MECH_L_FREE ||
      xdev_ext_mech_pool_frame_state(&s->pool, idx) != XDEV_EXT_MECH_F_HELD))
   continue;
  if (!xdev_ext_mech_pool_frame_move(&s->pool, idx,
                       XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_USER))
   s->transform_owner[idx] = 0;
 }
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_transform_unreserve);

/* Compare real page intervals, including distinct indices aliasing one page. */
static bool xdev_ext_mech_transform_alias(struct xdev_ext_mech_pool *p,
                    const struct xdev_ext_mech_frame *a,
                    const struct xdev_ext_mech_frame *b)
{
 u32 ai = 0, bi, ao, bo, al, bl;
 struct page *ap, *bp;
 while (ai < a->data_len) {
  ap = xdev_ext_mech_frame_page(p, a, a->data_off + ai, &ao, &al);
  if (!ap) return true;
  al = min(al, a->data_len - ai);
  bi = 0;
  while (bi < b->data_len) {
   bp = xdev_ext_mech_frame_page(p, b, b->data_off + bi, &bo, &bl);
   if (!bp) return true;
   bl = min(bl, b->data_len - bi);
   if (ap == bp && ao < bo + bl && bo < ao + al) return true;
   bi += bl;
  }
  ai += al;
 }
 return false;
}

int xdev_ext_mech_batch_transform_begin(struct xdev_ext_mech_batch *b,
                        const struct xdev_ext_mech_frame *dst, u32 nr)
{
 struct xdev_ext_mech_session *s = b->s;
 struct xdev_ext_mech_stage *st = &s->st[b->bs.stage];
 u32 i, j, begun = 0, moved = 0;
 int err = -EINVAL;
 if (!(st->cls->flags & XDEV_EXT_MECH_CLASS_F_TRANSFORM) ||
     b->transform.active || !nr || nr > XDEV_EXT_MECH_MAX_FRAMES)
  return -EINVAL;
 for (i = 0; i < b->nr_frames; i++) {
  const struct xdev_ext_mech_frame *f = &b->f[i];
  if (xdev_ext_mech_life_phase(&s->life[f->index]) != XDEV_EXT_MECH_L_OUT_PENDING ||
      s->life[f->index].valid_len < f->data_len)
   return -ENODATA;
 }
 for (i = 0; i < nr; i++) {
  if (dst[i].index >= s->pool.nr_frames || !dst[i].data_len ||
      dst[i].data_off >= s->pool.frame_size ||
      dst[i].data_len > s->pool.frame_size - dst[i].data_off ||
      s->transform_owner[dst[i].index] != st->index + 1 ||
      xdev_ext_mech_pool_frame_state(&s->pool, dst[i].index) != XDEV_EXT_MECH_F_HELD)
   return -EINVAL;
  for (j = 0; j < b->nr_frames; j++)
   if (xdev_ext_mech_transform_alias(&s->pool, &dst[i], &b->f[j])) return -EINVAL;
  /* Reserved windows of other slots/stages are independent leases too;
   * reserve proved at CREATE that no two reserved chunks share a page
   * byte, so only the index, owner and state checks above run per batch.
   */
  for (j = 0; j < i; j++)
   if (dst[i].index == dst[j].index ||
       xdev_ext_mech_transform_alias(&s->pool, &dst[i], &dst[j])) return -EINVAL;
 }
 for (i = 0; i < nr; i++) {
  b->transform.dst[i] = dst[i];
  err = s->pool.ops->resolve(&s->pool, &b->transform.dst[i]);
  if (err) goto undo;
  err = xdev_ext_mech_life_claim(&s->life[dst[i].index], st->index,
                                        &b->transform.token[i]);
  if (err) goto undo;
  begun++;
  err = xdev_ext_mech_pool_frame_move(&s->pool, dst[i].index,
                        XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_INFLIGHT);
  if (err) goto undo;
  moved++;
 }
 b->transform.nr = nr;
 b->transform.produced = 0;
 b->transform.active = true;
 return 0;
undo:
 for (i = 0; i < moved; i++)
  xdev_ext_mech_pool_frame_move(&s->pool, dst[i].index,
                        XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD);
 for (i = 0; i < begun; i++)
  WARN_ON_ONCE(xdev_ext_mech_life_rollback(&s->life[dst[i].index],
                        b->transform.token[i]));
 return err;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_transform_begin);

void xdev_ext_mech_batch_transform_complete(struct xdev_ext_mech_batch *b, u64 ticket,
                                          int err, u32 produced, bool sequester)
{
 u64 cap = 0;
 u32 i;
 if (xdev_ext_mech_batch_completion_claim(b, ticket)) return;
 if (!b->transform.active) { err = -EPROTO; sequester = true; }
 for (i = 0; i < b->transform.nr; i++) cap += b->transform.dst[i].data_len;
 if (!err && (!produced || produced > cap)) err = -EOVERFLOW;
 b->transform.produced = err ? 0 : produced;
 xdev_ext_mech_batch_completion_publish(b, ticket, err, sequester);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_transform_complete);

u32 xdev_ext_mech_batch_transform_produced(const struct xdev_ext_mech_batch *b)
{
 return b->transform.produced;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_transform_produced);

int xdev_ext_mech_batch_status(const struct xdev_ext_mech_batch *b)
{
 return b->status;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_status);

/* Submit refusal has proven no native owner; restore the entire dst lease. */
static void xdev_ext_mech_transform_undo(struct xdev_ext_mech_session *s,
                                       struct xdev_ext_mech_batch *b)
{
 u32 i;
 if (!b->transform.active) return;
 for (i = 0; i < b->transform.nr; i++) {
  struct xdev_ext_mech_frame *f = &b->transform.dst[i];
  WARN_ON_ONCE(xdev_ext_mech_life_rollback(&s->life[f->index],
                    b->transform.token[i]));
  WARN_ON_ONCE(xdev_ext_mech_pool_frame_move(&s->pool, f->index,
                    XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD));
 }
 b->transform.active = false;
}

/* Worker only, after source consume is complete. Unknown retains both leases. */
static bool xdev_ext_mech_transform_landed(struct xdev_ext_mech_session *s,
                                         struct xdev_ext_mech_batch *b, bool seq)
{
 u32 i, left = b->transform.produced, used = 0;
 for (i = 0; i < b->transform.nr; i++) {
  struct xdev_ext_mech_frame *f = &b->transform.dst[i];
  if (xdev_ext_mech_pool_frame_move(&s->pool, f->index, XDEV_EXT_MECH_F_INFLIGHT,
                    seq ? XDEV_EXT_MECH_F_SEQUESTERED : XDEV_EXT_MECH_F_HELD))
   seq = true;
  if (seq) {
   xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_SEQUESTERED, 1);
   continue;
  }
  if (!b->status && left) {
   left -= f->data_len;
   used++;
  }
 }
 if (seq) {
quarantine:
  /* A partial ownership failure cannot authorize either lease's reuse. */
  for (i = 0; i < b->transform.nr; i++)
   xdev_ext_mech_pool_frame_move(&s->pool, b->transform.dst[i].index,
                    XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_SEQUESTERED);
  xdev_ext_mech_frames_move(s, b, XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_SEQUESTERED);
  return true;
 }
 if (!b->status) {
  if (WARN_ON_ONCE(left || !used) || xdev_ext_mech_frames_release(s, b))
   goto quarantine;
  memcpy(b->f, b->transform.dst, used * sizeof(b->f[0]));
  b->nr_frames = used;
  b->present = (u32)GENMASK_ULL(used - 1, 0);
  b->bytes = b->transform.produced;
 }
 b->transform.active = false;
 return false;
}

/* Session state, admission and accessors. */

u64 xdev_ext_mech_session_id(const struct xdev_ext_mech_session *s)
{
	return s->id;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_session_id);

const struct xdev_ext_mech_layout *
xdev_ext_mech_session_layout(const struct xdev_ext_mech_session *s)
{
	return &s->layout;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_session_layout);

const struct xdev_ext_mech_peer *
xdev_ext_mech_session_peer(const struct xdev_ext_mech_session *s)
{
	return &s->peer;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_session_peer);

struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{
	return &s->pool;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_session_pool);

u32 xdev_ext_mech_session_depth(const struct xdev_ext_mech_session *s)
{
	return s->depth;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_session_depth);

u32 xdev_ext_mech_session_state(const struct xdev_ext_mech_session *s)
{
	return READ_ONCE(s->ss.state);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_session_state);

bool xdev_ext_mech_session_admits(const struct xdev_ext_mech_session *s)
{
	u32 i;

	if (READ_ONCE(s->ss.state) != XDEV_EXT_MECH_SESSION_ACTIVE)
		return false;
	for (i = 0; i < XDEV_EXT_MECH_CLASS_MAX; i++)
		if (s->ops[i] &&
		    !xdev_ext_mech_ops_current(i, s->ops[i], s->pinned[i]))
			return false;
	return true;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_session_admits);

static bool xdev_ext_mech_settled(struct xdev_ext_mech_session *s)
{
	return READ_ONCE(s->ss.state) != XDEV_EXT_MECH_SESSION_STOPPING &&
	       !READ_ONCE(s->start_preparing) &&
	       !READ_ONCE(s->start_return_pending) &&
	       !atomic_read(&s->native_controls);
}

/* Under s->lock: a stopping session with nothing left in flight settles. */
static void xdev_ext_mech_settle_locked(struct xdev_ext_mech_session *s)
{
	if (s->ss.state != XDEV_EXT_MECH_SESSION_STOPPING || s->ss.inflight ||
	    s->start_preparing || s->start_return_pending ||
	    atomic_read(&s->native_controls))
		return;
	xdev_ext_mech_sess_drain(&s->ss, false);
	wake_up(&s->drain_wq);
}

static void xdev_ext_mech_set_err_locked(struct xdev_ext_mech_session *s, int err)
{
	/* Worker aborts after STOP carry a cancellation reason, not a newly
	 * observed native failure. Native errors use session_stop explicitly. */
	if (err && !s->stop_err && !s->last_err &&
	    s->ss.state == XDEV_EXT_MECH_SESSION_ACTIVE)
		s->last_err = err;
}

static int xdev_ext_mech_stop_reason(struct xdev_ext_mech_session *s)
{
	int err = READ_ONCE(s->stop_err);

	return err ? err : -ESHUTDOWN;
}

/*
 * Any context, never blocks: stop admitting, record @err as the reason,
 * and let the worker abort what has not reached a device.
 */
static void xdev_ext_mech_session_stop(struct xdev_ext_mech_session *s, int err)
{
	unsigned long flags;

	spin_lock_irqsave(&s->lock, flags);
	/* STOP(0) closes admission but cannot seal the native-error latch.
	 * Keep the first nonzero reason, including a late callback during drain
	 * or the provider's final synchronization in unbind. */
	xdev_ext_mech_sess_stop(&s->ss);
	if (err && !s->stop_err) {
		err = s->last_err ?: err;
		s->last_err = err;
		WRITE_ONCE(s->stop_err, err);
	}
	s->start_left = 0;
	if (s->start_recycle)
		s->start_return_pending = true;
	xdev_ext_mech_settle_locked(s);
	xdev_ext_mech_notify_locked(s, false);
	if (!s->worker_gone)
		kthread_queue_work(s->worker, &s->stop_work);
	spin_unlock_irqrestore(&s->lock, flags);
}

static void xdev_ext_mech_release_late(struct xdev_ext_mech_session *s);

/*
 * The last reference of a session that STOP did not release.  One whose
 * drain bound passed with only accepted commands outstanding decides its
 * fate now; of a quarantined one only the worker goes.  worker_gone is set,
 * so only timers armed before it remain, and kthread_destroy_worker()
 * flushes queued work but not armed timers.
 */
static void xdev_ext_mech_reap(struct work_struct *work)
{
	struct xdev_ext_mech_session *s = container_of(work, struct xdev_ext_mech_session,
						  reap_work);

	if (READ_ONCE(s->release_deferred)) {
		xdev_ext_mech_release_late(s);
		return;
	}
	kthread_cancel_delayed_work_sync(&s->retry_work);
	kthread_cancel_delayed_work_sync(&s->progress_work);
	synchronize_rcu();
	kthread_destroy_worker(s->worker);
}

/* Under s->lock; true when that was the last reference. */
static bool xdev_ext_mech_leave_locked(struct xdev_ext_mech_session *s,
				  bool sequestered)
{
	bool last = xdev_ext_mech_sess_batch_end(&s->ss, sequestered);

	xdev_ext_mech_settle_locked(s);
	if (last)
		s->worker_gone = true;
	xdev_ext_mech_notify_locked(s, false);
	return last;
}

/* Stages and uring_cmd. */

struct xdev_ext_mech_stage *xdev_ext_mech_stage_get_cmd(struct io_uring_cmd *ioucmd,
					      u32 class_id)
{
	struct xdev_ext_mech_stage *found = ERR_PTR(-EOPNOTSUPP);
	struct io_ring_ctx *ctx = io_uring_cmd_ctx_handle(ioucmd);
	struct xdev_ext_mech_session *s;
	unsigned long flags;
	u32 i;
	int ret;

	/*
	 * Only the issuing ring's sessions, per command and possibly from
	 * io-wq without uring_lock: uring_lock orders the list writers, and a
	 * session is freed only after a grace period that follows its removal.
	 */
	rcu_read_lock();
	list_for_each_entry_rcu(s, &ctx->xdev_ext_mech_sessions, ring_node) {
		for (i = 0; i < s->nr_stages; i++) {
			struct xdev_ext_mech_stage *st = &s->st[i];

			if (st->class_id != class_id ||
			    st->file != ioucmd->file)
				continue;
			spin_lock_irqsave(&s->lock, flags);
			ret = xdev_ext_mech_session_admits(s) ?
			      xdev_ext_mech_sess_batch_begin(&s->ss) : -ESHUTDOWN;
			if (!ret)
				s->cmd_refs++;
			spin_unlock_irqrestore(&s->lock, flags);
			found = ret ? ERR_PTR(ret) : st;
			goto out;
		}
	}
out:
	rcu_read_unlock();
	return found;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_stage_get_cmd);

void xdev_ext_mech_stage_put(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_mech_session *s = st->s;
	unsigned long flags;
	bool last;

	spin_lock_irqsave(&s->lock, flags);
	if (!WARN_ON_ONCE(!s->cmd_refs))
		s->cmd_refs--;
	last = xdev_ext_mech_leave_locked(s, false);
	spin_unlock_irqrestore(&s->lock, flags);
	if (last)
		queue_work(system_unbound_wq, &s->reap_work);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_stage_put);

void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st, int err)
{
	xdev_ext_mech_session_stop(st->s, err ? err : -ENXIO);
	if (st->cls->mark_dead)
		st->cls->mark_dead(st);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_stage_dead);

/* Batches. */

u64 xdev_ext_mech_batch_id(const struct xdev_ext_mech_batch *b)
{
	return b->id;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_id);

u64 xdev_ext_mech_batch_key(const struct xdev_ext_mech_batch *b)
{
	return b->key;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_key);

u32 xdev_ext_mech_batch_slot(const struct xdev_ext_mech_batch *b)
{
	return (b->parent ? b->parent : b) - b->s->batches;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_slot);

u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch *b)
{
	return b->nr_frames;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_nr_frames);

u32 xdev_ext_mech_batch_bytes(const struct xdev_ext_mech_batch *b)
{
	return b->bytes;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_bytes);

struct xdev_ext_mech_session *xdev_ext_mech_batch_session(const struct xdev_ext_mech_batch *b)
{
	return b->s;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_session);

struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(const struct xdev_ext_mech_batch *b)
{
	return &b->s->st[b->bs.stage];
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_stage);

int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch *b, u32 pos,
			 struct xdev_ext_mech_frame *f)
{
	if (pos >= b->nr_frames)
		return -ERANGE;
	*f = b->f[pos];
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_frame);

int xdev_ext_mech_batch_cpu_length(struct xdev_ext_mech_batch *b, u32 pos, u32 len)
{
 struct xdev_ext_mech_frame *f;
 u64 claim;

 if (pos >= b->nr_frames || !(b->life_active & BIT(pos)))
  return -EINVAL;
 f = &b->f[pos];
 claim = b->life_token[pos];
 if ((claim & XDEV_EXT_MECH_L_STATE_MASK) != XDEV_EXT_MECH_L_CLAIM_EXCLUSIVE ||
     !xdev_ext_mech_life_matches(smp_load_acquire(&b->s->life[f->index].ctrl), claim))
  return -ESTALE;
 if (len > b->s->pool.frame_size - f->data_off)
  return -EMSGSIZE;
 b->bytes = b->bytes - f->data_len + len;
 f->data_len = len;
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_cpu_length);

int xdev_ext_mech_batch_frame_claim(const struct xdev_ext_mech_batch *b,
                                   u32 pos, u64 *owner, u64 *generation)
{
 u64 claim;

 if (pos >= b->nr_frames || !(b->life_active & BIT(pos)))
  return -ESTALE;
 claim = b->life_token[pos];
 *owner = xdev_ext_mech_life_claim_owner(claim);
 *generation = xdev_ext_mech_life_claim_gen(claim);
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_frame_claim);

/* Read-only admission: never steal the native callback's completion claim.
 * The cookie's batch pointer is immutable. Check its ticket before reading any
 * reusable batch metadata, and again after the bounded snapshot validation.
 */
bool xdev_ext_mech_batch_ce_owners_valid(const struct xdev_ext_mech_batch *b,
                                       u64 ticket, const struct xdev_ext_ce_xfer *x, u32 n)
{
 const struct xdev_ext_mech_session *s;
 u64 expected = (ticket << 3) | XDEV_EXT_MECH_C_SUBMITTED;
 u32 i, j;

 if (!ticket || !n || n > XDEV_EXT_MECH_MAX_FRAMES ||
     smp_load_acquire(&b->completion.ctrl) != expected)
  return false;
 s = b->s;
 for (i = 0; i < n; i++) {
  bool found = false;

  for (j = 0; j < b->nr_frames; j++) {
   const struct xdev_ext_mech_frame *f = &b->f[j];
   struct xdev_ext_mech_frame_rec rec;
   u64 start = s->pool.first_page_off + (u64)f->index * s->pool.frame_size + f->data_off;
   u64 claim = b->life_token[j], word;

   if (x[i].host_byte_off < start || x[i].host_byte_off - start > f->data_len ||
       !x[i].len || x[i].len > f->data_len - (x[i].host_byte_off - start))
    continue;
   if (!(b->life_active & BIT(j)) || x[i].owner != xdev_ext_mech_life_claim_owner(claim) ||
       x[i].generation != xdev_ext_mech_life_claim_gen(claim))
    return false;
   xdev_ext_mech_frame_rec_fill(&rec, &s->life[f->index], f->index, s->pool.frame_size,
     s->pool.first_page_off, PAGE_SHIFT, s->pool.capabilities,
     s->pool.ops->sync_for_cpu != NULL, READ_ONCE(s->ss.state) == XDEV_EXT_MECH_SESSION_ZOMBIE);
   word = smp_load_acquire(&s->life[f->index].ctrl);
   if (rec.gen != x[i].generation || rec.closing || !xdev_ext_mech_life_matches(word, claim))
    return false;
   if ((claim & XDEV_EXT_MECH_L_STATE_MASK) != XDEV_EXT_MECH_L_CLAIM_PRODUCE && !rec.refs)
    return false;
   found = true;
   break;
  }
  if (!found)
   return false;
 }
 return smp_load_acquire(&b->completion.ctrl) == expected;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_ce_owners_valid);

void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b)
{
	return b->priv;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_priv);

void *xdev_ext_mech_batch_cookie(struct xdev_ext_mech_batch *b)
{
	return b->cookie;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_cookie);

/*
 * A batch has at most one inbox record. Detached nodes are cleared before
 * processing, so a synchronous next-stage callback can enqueue the same batch.
 * Only empty -> nonempty queues drain_work. An executing drain detaches whole
 * lists and loops until empty; a producer racing its final empty check sees
 * empty and queues it again. kthread_work removes work->node before invoking
 * the function, so running work can be requeued. False means already pending.
 *
 * A running drain can consume this record before queue_work returns. RCU
 * protects that final publisher tail against last-reference worker teardown;
 * every destroy path synchronizes RCU before destroying the worker.
 */
static void xdev_ext_mech_batch_queue(struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_mech_session *s = b->s;
	struct kthread_worker *worker = s->worker;

	if (cmpxchg(&b->queued, 0, 1))
		return;
	rcu_read_lock();
	if (llist_add(&b->inbox_node, &s->inbox))
		kthread_queue_work(worker, &s->drain_work);
	rcu_read_unlock();
}

u64 xdev_ext_mech_batch_ticket(const struct xdev_ext_mech_batch *b)
{
	return READ_ONCE(b->ticket);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_ticket);

int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b, u64 ticket)
{
	return xdev_ext_mech_completion_claim(&b->completion, ticket);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_completion_claim);

static void xdev_ext_mech_sync_for_cpu(struct xdev_ext_mech_session *s,
                                      struct xdev_ext_mech_batch *b);

/* Ticket winner only. Empty tails never publish READY or acquire consumer
 * references. Retain INFLIGHT provider custody until the worker can recycle;
 * lifecycle invalidation itself still happens in this native completion. */
static int xdev_ext_mech_trim_produced(struct xdev_ext_mech_session *s,
                                     struct xdev_ext_mech_batch *b)
{
 u32 len[XDEV_EXT_MECH_MAX_FRAMES], i;
 int used, err;

 if (!b->producing)
  return -EINVAL;
 for (i = 0; i < b->nr_frames; i++)
  len[i] = b->f[i].data_len;
 used = xdev_ext_mech_produced_trim(len, b->nr_frames, b->produced);
 if (used < 0)
  return used;
 for (i = used; i < b->nr_frames; i++) {
  err = xdev_ext_mech_life_fail_produce(&s->life[b->f[i].index], b->life_token[i]);
  if (err)
   return err;
  b->life_active &= ~BIT(i);
 }
 for (i = 0; i < b->nr_frames; i++)
  b->f[i].data_len = len[i];
 b->produced_used = used;
 b->bytes = b->produced;
 return 0;
}

/* Native callback, after completion_publish_begin won. Provider sync hooks are
 * IRQ-safe (XSK uses its existing mapping lifetime lock); no new lifecycle lock.
 * Unknown DMA retains every claim and the pool's permanent quarantine custody.
 * Destination custody transfer and descriptor construction remain in the worker.
 */
static int xdev_ext_mech_batch_handoff(struct xdev_ext_mech_batch *b,
                                      int err, bool *sequester)
{
 struct xdev_ext_mech_session *s = b->s;
 u32 i, refs = xdev_ext_mech_chain_refs(s->plan, s->nr_stages, b->bs.stage + 1);
 u32 left = b->transform.produced;
 int rc;

 if (*sequester || READ_ONCE(s->ss.state) == XDEV_EXT_MECH_SESSION_ZOMBIE) {
  *sequester = true;
  return err;
 }
 if (!err && b->produced_set && xdev_ext_mech_trim_produced(s, b)) {
  *sequester = true;
  return -EIO;
 }
 xdev_ext_mech_sync_for_cpu(s, b);
 for (i = 0; i < b->nr_frames; i++) {
  struct xdev_ext_mech_life *l = &s->life[b->f[i].index];
  u64 claim = b->life_token[i];

  if (!(b->life_active & BIT(i)))
   continue;
  if (b->producing)
   rc = err ? xdev_ext_mech_life_fail_produce(l, claim) :
    xdev_ext_mech_life_publish(l, claim, refs, b->f[i].data_len);
  else if (!err && xdev_ext_mech_stage_role(&s->plan[b->bs.stage]) == XDEV_EXT_MECH_ROLE_INPLACE)
   rc = xdev_ext_mech_life_republish(l, claim, refs, b->f[i].data_len);
  else
   rc = err ? xdev_ext_mech_life_fail_put(l, claim) : xdev_ext_mech_life_put(l, claim);
  if (rc < 0) {
   *sequester = true;
   return -EIO;
  }
 }
 b->life_active = 0;
 if (!b->transform.active)
  return err;
 for (i = 0; i < b->transform.nr; i++) {
  struct xdev_ext_mech_frame *f = &b->transform.dst[i];
  struct xdev_ext_mech_life *l = &s->life[f->index];

  if (err || !left) {
   rc = xdev_ext_mech_life_fail_produce(l, b->transform.token[i]);
   f->data_len = 0;
  } else {
   f->data_len = min(f->data_len, left);
   left -= f->data_len;
   if (s->pool.ops->sync_for_cpu)
    s->pool.ops->sync_for_cpu(&s->pool, f);
   rc = xdev_ext_mech_life_publish(l, b->transform.token[i], refs, f->data_len);
  }
  if (rc < 0) {
   *sequester = true;
   return -EIO;
  }
 }
 return err;
}

/* Only the matching claim winner may call this and write class metadata. */
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b, u64 ticket,
				      int err, bool sequester)
{
	unsigned long flags;

	if (xdev_ext_mech_completion_publish_begin(&b->completion, ticket))
		return;
	/* Publish native errors under the same lock as STOP, regardless of state:
	 * the worker may not land this completion until after a clean STOP wins.
	 * Local never-issued cancellations use their separate entry point. */
	if (err && !b->locally_cancelled) {
		spin_lock_irqsave(&b->s->lock, flags);
		if (!b->s->last_err)
			b->s->last_err = xdev_ext_mech_status_errno(err);
		spin_unlock_irqrestore(&b->s->lock, flags);
	}
	err = xdev_ext_mech_batch_handoff(b, err, &sequester);
	b->sequester = sequester;
	xdev_ext_mech_completion_publish_end(&b->completion, ticket, err);
	xdev_ext_mech_batch_queue(b);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_completion_publish);

void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b, u64 ticket, int err)
{
	if (!xdev_ext_mech_batch_completion_claim(b, ticket))
		xdev_ext_mech_batch_completion_publish(b, ticket, err, false);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_complete);

void xdev_ext_mech_batch_complete_produced(struct xdev_ext_mech_batch *b,
                                         u64 ticket, int err, u32 produced)
{
 if (xdev_ext_mech_batch_completion_claim(b, ticket))
  return;
 if (!err && (!produced || produced > b->bytes))
  err = -EOVERFLOW;
 b->produced = err ? 0 : produced;
 b->produced_set = true;
 xdev_ext_mech_batch_completion_publish(b, ticket, err, false);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_complete_produced);

u32 xdev_ext_mech_batch_produced(const struct xdev_ext_mech_batch *b)
{
 return b->produced;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_produced);

void xdev_ext_mech_batch_complete_cancelled(struct xdev_ext_mech_batch *b,
					 u64 ticket, int err)
{
	if (!xdev_ext_mech_batch_completion_claim(b, ticket)) {
		b->locally_cancelled = true;
		xdev_ext_mech_batch_completion_publish(b, ticket, err, false);
	}
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_complete_cancelled);

void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch *b, u64 ticket, int err)
{
	if (!xdev_ext_mech_batch_completion_claim(b, ticket))
		xdev_ext_mech_batch_completion_publish(b, ticket, err, true);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_sequester);

/* Under s->lock: a free batch object with a session reference. */
static struct xdev_ext_mech_batch *
xdev_ext_mech_batch_get_locked(struct xdev_ext_mech_session *s)
{
	struct xdev_ext_mech_batch *b;
	int ret;

	if (!xdev_ext_mech_session_admits(s))
		return ERR_PTR(-ESHUTDOWN);
	b = list_first_entry_or_null(&s->free, struct xdev_ext_mech_batch, node);
	if (!b)
		return ERR_PTR(-ENOSPC);
	ret = xdev_ext_mech_sess_batch_begin(&s->ss);
	if (ret)
		return ERR_PTR(ret);
	list_del_init(&b->node);
	xdev_ext_mech_bstate_init(&b->bs, s->nr_stages);
	b->id = ++s->next_batch_id;
	b->key = 0;
	b->abort_err = 0;
	b->status = 0;
	b->present = 0;
	b->nr_frames = 0;
	b->bytes = 0;
	b->sequester = false;
	b->to_user = false;
	b->fifo_accepted = false;
	b->life_active = 0;
	return b;
}

/*
 * Under s->lock: the session reference goes back.  A sequestered batch's
 * object stays off the free list for good: a device may still complete
 * into its class area.
 */
static bool xdev_ext_mech_batch_put_locked(struct xdev_ext_mech_session *s,
				      struct xdev_ext_mech_batch *b,
				      bool sequestered)
{
	if (!sequestered)
		list_add(&b->node, &s->free);
	return xdev_ext_mech_leave_locked(s, sequestered);
}

static void xdev_ext_mech_order_kick(struct xdev_ext_mech_session *s);
static void xdev_ext_mech_retry_kick(struct xdev_ext_mech_session *s);

/*
 * Worker only: give back queued RECYCLE loans as soon as no future batch can
 * use them. The IOU allocator removes only K_FREE queue entries, never a
 * frame held by an in-flight or sequestered batch. STOP waits until stop_work
 * has aborted its safe retry/open/ordered batches before lifting the wake gate.
 */
static void xdev_ext_mech_return_idle(struct xdev_ext_mech_session *s, bool stopping)
{
	struct xdev_ext_mech_frame f;
	unsigned long flags;
	u32 phase;
	int err;

	/* Pair the handoff gate with START under the same lock. Once this
	 * snapshot admits reclamation, pending remains set until the loop ends;
	 * another START therefore cannot join the queue we are draining.
	 */
	spin_lock_irqsave(&s->lock, flags);
	if (s->start_preparing || !s->start_return_pending ||
	    (s->start_left && xdev_ext_mech_session_admits(s)) ||
	    (!stopping && !xdev_ext_mech_session_admits(s))) {
		spin_unlock_irqrestore(&s->lock, flags);
		return;
	}
	spin_unlock_irqrestore(&s->lock, flags);
	while (!(err = s->pool.ops->alloc(&s->pool, &f, 1))) {
		phase = xdev_ext_mech_life_phase(&s->life[f.index]);
		if ((phase != XDEV_EXT_MECH_L_FREE && phase != XDEV_EXT_MECH_L_READY) ||
		    (phase == XDEV_EXT_MECH_L_READY &&
		     xdev_ext_mech_life_release(&s->life[f.index],
			xdev_ext_mech_life_gen(&s->life[f.index]))) ||
		    xdev_ext_mech_pool_frame_move(&s->pool, f.index,
					XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_USER)) {
			xdev_ext_mech_pool_frame_move(&s->pool, f.index,
				XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_SEQUESTERED);
			xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_SEQUESTERED, 1);
			err = -EIO;
			break;
		}
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PUBLISHED, 1);
	}
	if (WARN_ON_ONCE(err != -ENOSPC)) {
		/* A broken queue/custody invariant cannot authorize unmapping. */
		spin_lock_irqsave(&s->lock, flags);
		s->ss.sequestered++;
		if (s->ss.state == XDEV_EXT_MECH_SESSION_STOPPED)
			s->ss.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
		spin_unlock_irqrestore(&s->lock, flags);
		xdev_ext_mech_session_stop(s, err);
	}
	spin_lock_irqsave(&s->lock, flags);
	s->start_return_pending = false;
	xdev_ext_mech_settle_locked(s);
	xdev_ext_mech_notify_locked(s, false);
	spin_unlock_irqrestore(&s->lock, flags);
}

/* Worker: the batch is finished; its frames and reference are released. */
static void xdev_ext_mech_end(struct xdev_ext_mech_session *s, struct xdev_ext_mech_batch *b,
			 int how, int err)
{
	unsigned long flags;
	bool last, kick;
	u32 i;

 if (s->st[0].cls->batch_end)
  s->st[0].cls->batch_end(&s->st[0], b,
                        how == XDEV_EXT_MECH_END_DONE ? 0 : (err ?: -EIO));
	xdev_ext_mech_retry_kick(s);
	/* @b no longer holds back a later key at an ordered stage. */
	xdev_ext_mech_order_kick(s);
	if (how != XDEV_EXT_MECH_END_SEQUESTER && xdev_ext_mech_frames_release(s, b)) {
		how = XDEV_EXT_MECH_END_SEQUESTER;
		err = -EIO;
		b->bs.state = XDEV_EXT_MECH_B_SEQUESTERED;
		xdev_ext_mech_session_stop(s, err);
	}
	/* Frame release can itself discover uncertainty. Resource leases may
	 * become reusable only after that final disposition is known.
	 */
	for (i = 0; i < s->nr_stages; i++)
		if (s->st[i].cls->batch_release)
			s->st[i].cls->batch_release(&s->st[i], b,
				how == XDEV_EXT_MECH_END_SEQUESTER);
	if (how != XDEV_EXT_MECH_END_DONE && s->start_recycle &&
	    xdev_ext_mech_session_admits(s))
		xdev_ext_mech_session_stop(s, err ?: -EIO);
	xdev_ext_mech_return_idle(s, false);
	spin_lock_irqsave(&s->lock, flags);
	atomic64_inc(how == XDEV_EXT_MECH_END_DONE ? &s->done : &s->aborted);
	xdev_ext_mech_set_err_locked(s, err);
	last = xdev_ext_mech_batch_put_locked(s, b, how == XDEV_EXT_MECH_END_SEQUESTER);
	kick = s->start_left && s->ss.state == XDEV_EXT_MECH_SESSION_ACTIVE;
	xdev_ext_mech_notify_locked(s, true);
	spin_unlock_irqrestore(&s->lock, flags);

	if (last)
		queue_work(system_unbound_wq, &s->reap_work);
	else if (kick)
		kthread_queue_work(s->worker, &s->kick_work);
}

static void xdev_ext_mech_fanout_landed(struct xdev_ext_mech_session *s,
                                      struct xdev_ext_mech_batch *b, int err, bool sequester);

static void xdev_ext_mech_abort(struct xdev_ext_mech_session *s, struct xdev_ext_mech_batch *b,
			   int err)
{
	u32 i;

 if (b->parent) {
  xdev_ext_mech_fanout_landed(s, b, err, false);
  return;
 }
	/* No wire skip protocol: stop before a later generation can overtake. */
	for (i = b->bs.stage; i < s->nr_stages; i++)
		if ((s->st[i].cls->flags & XDEV_EXT_MECH_CLASS_F_ORDERED) &&
		    xdev_ext_mech_session_admits(s)) {
			xdev_ext_mech_session_stop(s, err ?: -EIO);
			break;
		}
	xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_ABORT, 0);
	xdev_ext_mech_end(s, b, XDEV_EXT_MECH_END_ABORT, err);
}

static void xdev_ext_mech_fill_info(struct xdev_ext_mech_session *s,
			       struct xdev_ext_mech_stage *st,
			       struct xdev_ext_mech_batch *b)
{
	if (!st->cls->info_size)
		return;
	memset(s->info, 0, st->cls->info_size);
	st->cls->fill_info(st, b, s->info);
}

static void xdev_ext_mech_worker_args(struct xdev_ext_mech_session *s,
				 struct xdev_ext_mech_stage *st,
				 struct xdev_ext_mech_batch *b, u32 member,
				 const struct xdev_ext_binding_ctx_v2 *base,
				 struct xdev_ext_mech_call_args *a)
{
	const struct xdev_ext_mech_class_ops *cls = st->cls;

	*a = (struct xdev_ext_mech_call_args) {
		.member = member,
		.callsite = XDEV_EXT_MECH_SITE_WORKER,
		.base = base,
		.b = b,
		.frames = b->f,
		.nr_frames = b->nr_frames,
		.info_size = cls->info_size,
		.info = cls->info_size ? s->info : NULL,
	};
	if (member == XDEV_EXT_MECH_MEMBER_BUILD) {
		a->scratch = s->scratch;
		a->desc_size = cls->desc_size;
		a->desc_cap = cls->desc_cap;
	} else if (cls->cqe_size) {
		a->cqe = s->cqe;
		a->cqe_size = cls->cqe_size;
		a->cqe_cap = cls->cqe_cap;
	}
}

/*
 * Worker: program build (or the class default), slot rule, validate.  The
 * class area starts each step zeroed; what ->validate admits there stays
 * for ->submit and ->fill_cqe of the same step.
 */
static void xdev_ext_mech_sync_for_cpu(struct xdev_ext_mech_session *s,
				  struct xdev_ext_mech_batch *b)
{
	u32 i;

	if (s->pool.ops->sync_for_cpu_batch) {
		s->pool.ops->sync_for_cpu_batch(&s->pool, b->f, b->nr_frames);
		return;
	}
	if (!s->pool.ops->sync_for_cpu)
		return;
	for (i = 0; i < b->nr_frames; i++)
		s->pool.ops->sync_for_cpu(&s->pool, &b->f[i]);
}

static int xdev_ext_mech_build(struct xdev_ext_mech_session *s, struct xdev_ext_mech_stage *st,
			  struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_binding_ctx_v2 base = xdev_ext_mech_base(st, b->bytes);
	u32 len = st->cls->desc_size * st->cls->desc_cap;
	struct xdev_ext_mech_call_args a;
	s32 ret = XDEV_EXT_MECH_BUILD_ABORT;
	bool illegal;
	int err, n;

	xdev_ext_mech_sync_for_cpu(s, b);
	if (s->priv_size)
		memset(b->priv, 0, s->priv_size);
	xdev_ext_mech_fill_info(s, st, b);
	memset(s->scratch, 0, len);
	xdev_ext_mech_worker_args(s, st, b, XDEV_EXT_MECH_MEMBER_BUILD, &base, &a);
	err = xdev_ext_mech_call(st, &a, &ret, NULL);
	if (err) {
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
		return err;
	}
	ret = xdev_ext_mech_ret_resolve(st->class_id, XDEV_EXT_MECH_MEMBER_BUILD,
				   XDEV_EXT_MECH_SITE_WORKER, ret, &illegal);
	if (illegal)
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
	switch (xdev_ext_mech_build_step(ret, st->cls->default_build, &err)) {
	case XDEV_EXT_MECH_STEP_SUBMIT:
		break;
	case XDEV_EXT_MECH_STEP_DEFAULT:
		memset(s->scratch, 0, len);
		err = st->cls->default_build(st, b, s->scratch);
		if (err)
			return err;
		break;
	default:
		return err;
	}

	n = xdev_ext_mech_slots_used(s->scratch, st->cls->desc_size,
				st->cls->desc_cap);
	if (n > 0)
		err = st->cls->validate(st, b, s->scratch, n);
	else
		err = n ? n : -EPROTO;
	if (err)
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_REJECTS, 1);
	return err;
}

/* Acquire frame lifecycle only after provider custody made this batch HELD. */
static void xdev_ext_mech_life_undo(struct xdev_ext_mech_session *s,
			       struct xdev_ext_mech_batch *b)
{
	u32 i;

	for (i = 0; i < b->nr_frames; i++)
		if (b->life_active & BIT(i))
			WARN_ON_ONCE(xdev_ext_mech_life_rollback(&s->life[b->f[i].index],
				b->life_token[i]));
	b->life_active = 0;
}

static int xdev_ext_mech_batch_acquire(struct xdev_ext_mech_session *s,
				 struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_mech_stage *st = &s->st[b->bs.stage];
	u32 i;
	int ret;

	b->producing = !(st->cls->flags & XDEV_EXT_MECH_CLASS_F_TRANSFORM) &&
		st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE;
	b->fifo_accepted = false;
	for (i = 0; i < b->nr_frames; i++) {
		struct xdev_ext_mech_life *l = &s->life[b->f[i].index];
		u32 phase = xdev_ext_mech_life_phase(l);

		b->life_previous[i] = phase;
		if (b->producing)
			ret = xdev_ext_mech_life_claim(l, st->index, &b->life_token[i]);
		else
			ret = xdev_ext_mech_life_acquire(l, st->index,
    xdev_ext_mech_stage_role(&s->plan[st->index]) == XDEV_EXT_MECH_ROLE_INPLACE ?
    XDEV_EXT_MECH_L_ACQ_EXCLUSIVE :
    ((s->plan[st->index].flags & XDEV_EXT_MECH_STAGE_F_FANOUT) ||
     xdev_ext_mech_stage_group_end(s->plan, s->nr_stages, st->index) > st->index + 1) ?
    XDEV_EXT_MECH_L_ACQ_FANOUT : 0, &b->life_token[i]);
		if (ret) {
			xdev_ext_mech_life_undo(s, b);
			return ret;
		}
		b->life_active |= BIT(i);
		/* valid_len is read only after the winning READY acquire. */
		if (!b->producing && l->valid_len < b->f[i].data_len) {
			xdev_ext_mech_life_undo(s, b);
			return -ENODATA;
		}
	}
	return 0;
}

/* Worker: the batch is IN_FLIGHT before the class hands it to a device. */
static int xdev_ext_mech_submit(struct xdev_ext_mech_session *s, struct xdev_ext_mech_stage *st,
			   struct xdev_ext_mech_batch *b)
{
	u32 k = b->bs.stage;
	int ret;

	ret = b->parent ? 0 : xdev_ext_mech_frames_move(s, b, XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_INFLIGHT);
	if (ret)
		return ret;
	ret = xdev_ext_mech_completion_begin(&b->completion, &b->ticket);
	if (ret) {
		if (!b->parent)
			xdev_ext_mech_frames_move(s, b, XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD);
		return ret;
	}
	xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_SUBMIT, 0);
	b->status = 0;
	b->sequester = false;
	b->locally_cancelled = false;
 b->produced_set = false;
 b->produced = 0;
 b->produced_used = 0;
	atomic64_inc(&s->submitted[k]);

	ret = st->cls->submit(st, b);
	if (!ret) {
		b->fifo_accepted = (st->cls->flags & XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE) &&
			((s->pool.capabilities & XDEV_EXT_BINDING_CAP_ZERO_COPY) ||
    (st->class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
     st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE)) &&
			!READ_ONCE(b->sequester);
		return 0;
	}
	/* A callback that claimed ownership wins even before submit returns. */
	if (xdev_ext_mech_completion_cancel(&b->completion, b->ticket))
		return 0;
	atomic64_dec(&s->submitted[k]);
 xdev_ext_mech_transform_undo(s, b);
	if (!b->parent)
		xdev_ext_mech_frames_move(s, b, XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD);
	/* Preaccept refusal is scheduling backpressure, not a native RETRY. */
	b->bs.state = XDEV_EXT_MECH_B_READY;
	return ret;
}

/*
 * Worker: a stage whose class has XDEV_EXT_MECH_CLASS_F_ORDERED submits @b only
 * after every live batch with a smaller key was submitted there.  A session
 * that no longer admits lets every batch through to its abort.
 */
static bool xdev_ext_mech_order_blocked(struct xdev_ext_mech_session *s,
				   const struct xdev_ext_mech_batch *b)
{
	const struct xdev_ext_mech_stage *st = &s->st[b->bs.stage];
	unsigned long flags;
	bool blocked = false;
	u32 i;

	if (!(st->cls->flags & XDEV_EXT_MECH_CLASS_F_ORDERED) ||
	    !xdev_ext_mech_session_admits(s))
		return false;
	/* OPEN batches change under s->lock; the others belong to the worker. */
	spin_lock_irqsave(&s->lock, flags);
	for (i = 0; i < s->depth && !blocked; i++) {
		const struct xdev_ext_mech_batch *o = &s->batches[i];

		blocked = o != b && o != b->parent && xdev_ext_mech_order_holds_ex(b->key, b->bs.stage,
							    o->key, &o->bs, o->fifo_accepted);
	}
	spin_unlock_irqrestore(&s->lock, flags);
	return blocked;
}

/* Worker: wait in key order for the turn of @b at its ordered stage. */
static void xdev_ext_mech_order_park(struct xdev_ext_mech_session *s,
				struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_mech_batch *o;

	list_for_each_entry(o, &s->ordered, node)
		if (o->key > b->key)
			break;
	list_add_tail(&b->node, &o->node);
}

static void xdev_ext_mech_batch_run(struct xdev_ext_mech_session *s,
                                  struct xdev_ext_mech_batch *b);

/* Per-stage callback identity and storage are allocated once at CREATE, never
 * copied from the parent: a late native ticket cannot match a sibling/reuse. */
static void xdev_ext_mech_fanout_prepare(struct xdev_ext_mech_session *s,
                                       struct xdev_ext_mech_batch *root,
                                       struct xdev_ext_mech_batch *b, u32 stage)
{
 b->parent = root;
 b->id = root->id;
 b->key = root->key;
 b->nr_frames = root->nr_frames;
 b->present = root->present;
 b->bytes = root->bytes;
 b->life_active = 0;
 b->status = 0;
 b->sequester = false;
 b->fifo_accepted = false;
 b->to_user = false;
 memcpy(b->f, root->f, sizeof(b->f));
 xdev_ext_mech_bstate_init(&b->bs, s->nr_stages);
 xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_READY, stage);
}

static void xdev_ext_mech_fanout_run(struct xdev_ext_mech_session *s,
                                   struct xdev_ext_mech_batch *root)
{
 u32 i, slot = root - s->batches;
 int err;

 root->fan_first = root->bs.stage;
 root->fan_end = xdev_ext_mech_stage_group_end(s->plan, s->nr_stages, root->fan_first);
 root->fan_error = 0;
 root->fan_sequester = false;
 root->fan_pending = 0;
 err = xdev_ext_mech_frames_move(s, root, XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_INFLIGHT);
 if (err) {
  xdev_ext_mech_abort(s, root, err);
  return;
 }
 /* Install the whole barrier before any inline native completion can queue. */
 for (i = root->fan_first; i < root->fan_end; i++) {
  struct xdev_ext_mech_batch *b = &s->fan_batches[slot * XDEV_EXT_MECH_MAX_STAGES + i];

  xdev_ext_mech_fanout_prepare(s, root, b, i);
  root->fan_pending |= BIT(i);
 }
 root->bs.state = XDEV_EXT_MECH_B_IN_FLIGHT;
 for (i = root->fan_first; i < root->fan_end; i++)
  xdev_ext_mech_batch_run(s, &s->fan_batches[slot * XDEV_EXT_MECH_MAX_STAGES + i]);
}

/* Worker barrier; native callbacks have already released their own references.
 * Accepted peers drain even after failure/STOP. No dependent stage receives the
 * publication until every member is terminal; unknown DMA retains group custody.
 */
static void xdev_ext_mech_fanout_landed(struct xdev_ext_mech_session *s,
                                      struct xdev_ext_mech_batch *b, int err, bool sequester)
{
 struct xdev_ext_mech_batch *root = b->parent;
 u32 stage = b->bs.stage;

 if (!(root->fan_pending & BIT(stage)))
  return;
 if (err && !root->fan_error)
  root->fan_error = err;
 root->fan_sequester |= sequester;
 root->fan_pending &= ~BIT(stage);
 b->bs.state = sequester ? XDEV_EXT_MECH_B_SEQUESTERED : XDEV_EXT_MECH_B_DONE;
 if (root->fan_pending)
  return;
 root->sequester = root->fan_sequester;
 root->status = root->fan_error;
 if (xdev_ext_mech_frames_move(s, root, XDEV_EXT_MECH_F_INFLIGHT,
     root->fan_sequester ? XDEV_EXT_MECH_F_SEQUESTERED : XDEV_EXT_MECH_F_HELD)) {
  root->fan_sequester = true;
  root->fan_error = -EIO;
 }
 if (root->fan_sequester) {
  xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_SEQUESTERED, hweight32(root->present));
  xdev_ext_mech_batch_step(&root->bs, XDEV_EXT_MECH_EV_SEQUESTER, 0);
  xdev_ext_mech_end(s, root, XDEV_EXT_MECH_END_SEQUESTER, root->fan_error ?: -EIO);
 } else if (root->fan_error || !xdev_ext_mech_session_admits(s)) {
  xdev_ext_mech_abort(s, root, root->fan_error ?: xdev_ext_mech_stop_reason(s));
 } else {
  root->bs.stage = root->fan_end - 1;
  xdev_ext_mech_batch_step(&root->bs, XDEV_EXT_MECH_EV_NEXT, 0);
  if (root->bs.state == XDEV_EXT_MECH_B_DONE)
   xdev_ext_mech_end(s, root, XDEV_EXT_MECH_END_DONE, 0);
  else
   xdev_ext_mech_batch_run(s, root);
 }
}

/* Worker: a READY batch at its current stage. */
static void xdev_ext_mech_batch_run(struct xdev_ext_mech_session *s,
			       struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_mech_stage *st = &s->st[b->bs.stage];
	int err;

	if (!xdev_ext_mech_session_admits(s) || (b->parent && b->parent->fan_error)) {
  if (b->parent) {
   xdev_ext_mech_fanout_landed(s, b, b->parent->fan_error ?: xdev_ext_mech_stop_reason(s), false);
   return;
  }
		xdev_ext_mech_abort(s, b, xdev_ext_mech_stop_reason(s));
		return;
	}
 /* NVMe LBA placement and the current NXP wire format describe fixed
  * groups. A preceding transform must restore that group before entering
  * either class; its capacity is never interpreted as valid payload.
  */
 if ((st->class_id == XDEV_EXT_MECH_CLASS_NVME ||
      st->class_id == XDEV_EXT_MECH_CLASS_AFXDP) &&
     b->bytes != s->layout.group_bytes) {
  if (b->parent)
   xdev_ext_mech_fanout_landed(s, b, -EOPNOTSUPP, false);
  else
   xdev_ext_mech_abort(s, b, -EOPNOTSUPP);
  return;
 }
	if (xdev_ext_mech_order_blocked(s, b)) {
		xdev_ext_mech_order_park(s, b);
		return;
	}
 if (!b->parent && xdev_ext_mech_stage_group_end(s->plan, s->nr_stages, b->bs.stage) > (u32)b->bs.stage + 1) {
  xdev_ext_mech_fanout_run(s, b);
  return;
 }
	err = xdev_ext_mech_batch_acquire(s, b);
	if (!err)
		err = xdev_ext_mech_build(s, st, b);
	if (!err)
		err = xdev_ext_mech_submit(s, st, b);
	if (err) {
		xdev_ext_mech_life_undo(s, b);
		if ((err == -EAGAIN || err == -ENOSPC) && xdev_ext_mech_session_admits(s)) {
			list_add_tail(&b->node, &s->retry);
			/* No busy polling: capacity completion can expedite this timer. */
			kthread_mod_delayed_work(s->worker, &s->retry_work, 1);
		} else {
			if (b->parent)
    xdev_ext_mech_fanout_landed(s, b, err, false);
   else
    xdev_ext_mech_abort(s, b, err);
		}
	} else if (st->cls->flags & XDEV_EXT_MECH_CLASS_F_ORDERED)
		xdev_ext_mech_order_kick(s);
}

static void xdev_ext_mech_retry_kick(struct xdev_ext_mech_session *s)
{
	if (xdev_ext_mech_session_admits(s) && !list_empty(&s->retry))
		kthread_mod_delayed_work(s->worker, &s->retry_work, 0);
}

static void xdev_ext_mech_retry_work(struct kthread_work *work)
{
	struct xdev_ext_mech_session *s = container_of(work, struct xdev_ext_mech_session,
						 retry_work.work);
	struct xdev_ext_mech_batch *b, *next;
	LIST_HEAD(retry);

	/* Refused submissions rejoin the session list for a later timer tick. */
	list_splice_init(&s->retry, &retry);
	list_for_each_entry_safe(b, next, &retry, node) {
		list_del_init(&b->node);
		xdev_ext_mech_batch_run(s, b);
	}
}

/*
 * Worker: run the parked batches whose turn has come, smallest key first.
 * A batch run from here can end or submit and kick again; the outer loop
 * picks that up.
 */
static void xdev_ext_mech_order_kick(struct xdev_ext_mech_session *s)
{
	struct xdev_ext_mech_batch *b;

	if (s->order_kicking)
		return;
	s->order_kicking = true;
	while ((b = list_first_entry_or_null(&s->ordered,
					     struct xdev_ext_mech_batch, node)) &&
	       !xdev_ext_mech_order_blocked(s, b)) {
		list_del_init(&b->node);
		xdev_ext_mech_batch_run(s, b);
	}
	s->order_kicking = false;
}

/* Callback already ended each tail producer lease. Provider queue operations
 * are worker-only; no callback publishes or returns an unproduced empty tail. */
static int xdev_ext_mech_recycle_produced_tail(struct xdev_ext_mech_session *s,
                                            struct xdev_ext_mech_batch *b)
{
 u32 i;

 if (!b->produced_set || b->status || !b->produced_used)
  return 0;
 for (i = b->produced_used; i < b->nr_frames; i++) {
  struct xdev_ext_mech_frame *f = &b->f[i];
  u32 to = b->to_user && !s->start_recycle ? XDEV_EXT_MECH_F_USER : XDEV_EXT_MECH_F_K_FREE;

  if (s->transform_owner[f->index]) {
   b->present &= ~BIT(i);
   continue;
  }
  if (xdev_ext_mech_pool_frame_move(&s->pool, f->index, XDEV_EXT_MECH_F_HELD, to))
   return -EIO;
  b->present &= ~BIT(i);
  if (to == XDEV_EXT_MECH_F_USER) {
   xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PUBLISHED, 1);
  } else {
   s->pool.ops->recycle(&s->pool, f);
   xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_RECYCLED, 1);
  }
 }
 b->nr_frames = b->produced_used;
 return 0;
}

/* Worker: the native command of an IN_FLIGHT batch came back. */
static void xdev_ext_mech_batch_landed(struct xdev_ext_mech_session *s,
				  struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_mech_stage *st = &s->st[b->bs.stage];
	const struct xdev_ext_mech_class_ops *cls = st->cls;
	bool zombie = READ_ONCE(s->ss.state) == XDEV_EXT_MECH_SESSION_ZOMBIE;
	bool seq = b->sequester || zombie;
	struct xdev_ext_binding_ctx_v2 base;
	struct xdev_ext_mech_call_args a;
	s32 ret = XDEV_EXT_MECH_ABORT;
	bool illegal;
	int err;

	atomic64_inc(&s->completed[b->bs.stage]);
	if (!b->parent)
	WARN_ON_ONCE(xdev_ext_mech_frames_move(s, b, XDEV_EXT_MECH_F_INFLIGHT,
					  seq ? XDEV_EXT_MECH_F_SEQUESTERED :
						XDEV_EXT_MECH_F_HELD));
	if (seq && !b->parent)
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_SEQUESTERED,
			       hweight32(b->present));
 if (!seq && xdev_ext_mech_recycle_produced_tail(s, b)) {
  seq = true;
  b->sequester = true;
  b->status = -EIO;
  xdev_ext_mech_frames_move(s, b, XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_SEQUESTERED);
  xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_SEQUESTERED, hweight32(b->present));
 }
	if (cls->cqe_size) {
		memset(s->cqe, 0, cls->cqe_size * cls->cqe_cap);
		cls->fill_cqe(st, b, s->cqe);
	}
#ifdef XDEV_EXT_MECH_HANDOFF_LEGACY
	/* Complete compatibility payload fixups and DMA CPU synchronization
	 * before release-publishing READY. Acquire/release is not a DMA fence.
	 */
	if (!seq)
		xdev_ext_mech_sync_for_cpu(s, b);
	if (!seq) {
		u32 i;

		for (i = 0; i < b->nr_frames; i++) {
			struct xdev_ext_mech_life *l = &s->life[b->f[i].index];
			u64 token = b->life_token[i];
			int rc;

			if (b->producing)
				rc = b->status ? xdev_ext_mech_life_fail_produce(l, token) :
					xdev_ext_mech_life_publish(l, token, b->f[i].data_len);
			else
				rc = xdev_ext_mech_life_complete_consume(l, token);
			if (WARN_ON_ONCE(rc)) {
				seq = true;
				b->sequester = true;
				b->status = -EIO;
				xdev_ext_mech_frames_move(s, b, XDEV_EXT_MECH_F_HELD,
						     XDEV_EXT_MECH_F_SEQUESTERED);
				xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_SEQUESTERED,
						 hweight32(b->present));
				break;
			}
		}
		b->life_active = 0;
	}
#endif

 if (b->transform.active && xdev_ext_mech_transform_landed(s, b, seq)) {
  seq = true;
  b->sequester = true;
  b->status = -EIO;
 }
	/* After the drain timed out no program runs: C default only. */
	if (!zombie) {
		base = xdev_ext_mech_base(st, b->bytes);
		xdev_ext_mech_fill_info(s, st, b);
		xdev_ext_mech_worker_args(s, st, b, XDEV_EXT_MECH_MEMBER_COMPLETE, &base,
				     &a);
		if (seq) {
			/* Record the outcome without exposing pages still under DMA. */
			a.frames = NULL;
			a.nr_frames = 0;
		}
		if (xdev_ext_mech_call(st, &a, &ret, NULL)) {
			xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
			ret = XDEV_EXT_MECH_ABORT;
		} else {
			ret = xdev_ext_mech_ret_resolve(st->class_id,
						   XDEV_EXT_MECH_MEMBER_COMPLETE,
						   XDEV_EXT_MECH_SITE_WORKER, ret,
						   &illegal);
			if (illegal)
				xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
		}
	}

 if (b->parent) {
  int step = xdev_ext_mech_complete_step(st->class_id, ret, b->status,
     b->sequester, zombie, b->bs.retries, &err);

  xdev_ext_mech_fanout_landed(s, b,
    step == XDEV_EXT_MECH_STEP_NEXT || step == XDEV_EXT_MECH_STEP_DONE ? 0 : (err ?: -EIO),
    step == XDEV_EXT_MECH_STEP_SEQUESTER);
  return;
 }
	switch (xdev_ext_mech_complete_step(st->class_id, ret, b->status,
				       b->sequester, zombie, b->bs.retries,
				       &err)) {
	case XDEV_EXT_MECH_STEP_NEXT:
		xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_NEXT, 0);
		if (b->bs.state == XDEV_EXT_MECH_B_DONE)
			xdev_ext_mech_end(s, b, XDEV_EXT_MECH_END_DONE, 0);
		else
			xdev_ext_mech_batch_run(s, b);
		break;
	case XDEV_EXT_MECH_STEP_DONE:
		xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_DONE, 0);
		xdev_ext_mech_end(s, b, XDEV_EXT_MECH_END_DONE, 0);
		break;
	case XDEV_EXT_MECH_STEP_RETRY:
		/* Accepted ownership is never resent, even on a safe native error. */
		xdev_ext_mech_abort(s, b, b->status ?: -EIO);
		break;
	case XDEV_EXT_MECH_STEP_SEQUESTER:
		xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_SEQUESTER, 0);
		xdev_ext_mech_end(s, b, XDEV_EXT_MECH_END_SEQUESTER, err);
		break;
	default:
		xdev_ext_mech_abort(s, b, err);
		break;
	}
}

static void xdev_ext_mech_batch_drain(struct kthread_work *work)
{
	struct xdev_ext_mech_session *s = container_of(work, struct xdev_ext_mech_session,
						 drain_work);
	struct llist_node *head, *node, *next;

	while ((head = llist_del_all(&s->inbox))) {
		head = llist_reverse_order(head);
		llist_for_each_safe(node, next, head) {
			struct xdev_ext_mech_batch *b = llist_entry(node,
					struct xdev_ext_mech_batch, inbox_node);

			/* Save next above before the node can be reused by a callback. */
			smp_store_release(&b->queued, 0);
			switch (b->bs.state) {
			case XDEV_EXT_MECH_B_OPEN:
				xdev_ext_mech_abort(s, b, b->abort_err);
				break;
			case XDEV_EXT_MECH_B_READY:
				xdev_ext_mech_batch_run(s, b);
				break;
			case XDEV_EXT_MECH_B_IN_FLIGHT:
				if (!WARN_ON_ONCE(xdev_ext_mech_completion_consume(
					&b->completion, b->ticket, &b->status)))
					xdev_ext_mech_batch_landed(s, b);
				break;
			default:
				WARN_ON_ONCE(1);
				break;
			}
		}
	}
}

/* RECYCLE lends the CPU-authored input again after its prior final put.
 * The allocator has returned HELD custody before this helper runs; publishing
 * existing registered bytes is a new CPU START operation, not a producer
 * overwriting READY. No payload copy or user continuation is introduced. */
static int xdev_ext_mech_start_publication(struct xdev_ext_mech_session *s,
                                         struct xdev_ext_mech_batch *b)
{
 u32 i, refs, bytes = 0;

 if (!s->start_recycle || xdev_ext_mech_stage_role(&s->plan[0]) == XDEV_EXT_MECH_ROLE_PRODUCER)
  return 0;
 refs = xdev_ext_mech_chain_refs(s->plan, s->nr_stages, 0);
 for (i = 0; i < b->nr_frames; i++) {
  struct xdev_ext_mech_life *life = &s->life[b->f[i].index];
  u64 claim;
  int err;

  if (xdev_ext_mech_life_phase(life) == XDEV_EXT_MECH_L_READY) {
   bytes += b->f[i].data_len;
   continue; /* Initial user loan was already CPU-published by START. */
  }
  /* Reuse the preceding output, not the CREATE capacity reconstructed by
   * start_more: an in-place stage may have changed the valid byte length. */
  if (!life->valid_len || b->f[i].data_off > s->pool.frame_size ||
      life->valid_len > s->pool.frame_size - b->f[i].data_off)
   return -EINVAL;
  b->f[i].data_len = life->valid_len;
  err = xdev_ext_mech_life_claim(life, XDEV_EXT_MECH_L_OWNER_START, &claim);
  if (err)
   return err;
  err = xdev_ext_mech_life_publish(life, claim, refs, b->f[i].data_len);
  if (err) {
   xdev_ext_mech_life_rollback(life, claim);
   return err;
  }
  bytes += b->f[i].data_len;
 }
 b->bytes = bytes;
 return 0;
}

/* Worker: START batches while depth and frames allow. */
static void xdev_ext_mech_start_more(struct xdev_ext_mech_session *s)
{
	struct xdev_ext_mech_batch *b;
	unsigned long flags;
	bool last, idle;
	u32 i;
	int ret;

	for (;;) {
		spin_lock_irqsave(&s->lock, flags);
		b = !s->start_preparing && s->start_left ?
			xdev_ext_mech_batch_get_locked(s) : NULL;
		if (IS_ERR_OR_NULL(b)) {
			spin_unlock_irqrestore(&s->lock, flags);
			return;
		}
		b->key = s->start_seq++;
		b->to_user = s->start_to_user;
		s->start_left--;
		spin_unlock_irqrestore(&s->lock, flags);

		ret = s->pool.ops->alloc(&s->pool, b->f, s->frames);
		if (ret) {
			spin_lock_irqsave(&s->lock, flags);
			last = xdev_ext_mech_batch_put_locked(s, b, false);
			/*
			 * Out of frames: a finished batch kicks again.  With
			 * nothing in flight none will, so give the START up.
			 */
			idle = ret != -ENOSPC || !s->ss.inflight;
			if (idle) {
				s->start_left = 0;
				xdev_ext_mech_set_err_locked(s, ret);
			} else {
				s->start_left++;
				s->start_seq--;
			}
			xdev_ext_mech_notify_locked(s, idle);
			spin_unlock_irqrestore(&s->lock, flags);
			if (idle)
				xdev_ext_mech_return_idle(s, false);
			WARN_ON_ONCE(last);
			return;
		}
		b->nr_frames = s->frames;
		b->present = (u32)GENMASK_ULL(s->frames - 1, 0);
		b->bytes = s->layout.group_bytes;
		for (i = 0; i < s->frames && !ret; i++) {
			ret = s->pool.ops->resolve(&s->pool, &b->f[i]);
			if (!ret)
				ret = xdev_ext_mech_layout_span(&s->layout, i,
							   &b->f[i].data_off,
							   &b->f[i].data_len);
			if (!ret && s->start_user_len)
				b->f[i].data_len = s->start_user_len;
		}
		if (s->start_user_len)
			b->bytes = s->start_user_len;
		if (!ret)
			ret = xdev_ext_mech_start_publication(s, b);
		xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_READY, 0);
		if (ret)
			xdev_ext_mech_abort(s, b, ret);
		else
			xdev_ext_mech_batch_run(s, b);
	}
}

int xdev_ext_mech_stage_native_get(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_mech_session *s = st->s;
 unsigned long flags;
 int ret = -ESHUTDOWN;

 /* Admission and the control reference must be one operation relative to
  * STOP and its final release decision. The caller has not enqueued yet. */
 spin_lock_irqsave(&s->lock, flags);
 if (!s->worker_gone && xdev_ext_mech_session_admits(s)) {
  atomic_inc(&s->native_controls);
  ret = 0;
 }
 spin_unlock_irqrestore(&s->lock, flags);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_stage_native_get);
void xdev_ext_mech_stage_native_put(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_mech_session *s = st->s;
 unsigned long flags;
 atomic_dec(&s->native_controls);
 spin_lock_irqsave(&s->lock, flags);
 xdev_ext_mech_settle_locked(s);
 spin_unlock_irqrestore(&s->lock, flags);
 wake_up(&s->drain_wq);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_stage_native_put);

void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_mech_session *s = st->s;
 unsigned long flags;
 spin_lock_irqsave(&s->lock, flags);
 if (!s->worker_gone && (s->ss.state == XDEV_EXT_MECH_SESSION_ACTIVE ||
                         s->ss.state == XDEV_EXT_MECH_SESSION_STOPPING))
  kthread_mod_delayed_work(s->worker, &s->progress_work, 0);
 spin_unlock_irqrestore(&s->lock, flags);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_stage_kick);

static void xdev_ext_mech_progress_work(struct kthread_work *work)
{
 struct xdev_ext_mech_session *s = container_of(work, struct xdev_ext_mech_session,
                                         progress_work.work);
 unsigned long delay = 0;
 u32 i;
 if (READ_ONCE(s->worker_gone)) return;
 for (i = 0; i < s->nr_stages; i++) {
  unsigned long next;
  if (!s->st[i].cls->progress) continue;
  next = s->st[i].cls->progress(&s->st[i]);
  if (next && (!delay || next < delay)) delay = next;
 }
 if (delay && !READ_ONCE(s->worker_gone))
  kthread_mod_delayed_work(s->worker, &s->progress_work, delay);
}

static void xdev_ext_mech_kick_work(struct kthread_work *work)
{
	xdev_ext_mech_start_more(container_of(work, struct xdev_ext_mech_session,
					 kick_work));
}

/* Worker: abort the partial RX groups of a stopping session. */
static void xdev_ext_mech_stop_work(struct kthread_work *work)
{
	struct xdev_ext_mech_session *s = container_of(work, struct xdev_ext_mech_session,
						  stop_work);
	struct xdev_ext_mech_batch *b, *n;
	unsigned long flags;
	LIST_HEAD(open);

	spin_lock_irqsave(&s->lock, flags);
	list_splice_init(&s->open, &open);
	spin_unlock_irqrestore(&s->lock, flags);

	list_for_each_entry_safe(b, n, &open, node) {
		list_del_init(&b->node);
		xdev_ext_mech_abort(s, b, xdev_ext_mech_stop_reason(s));
	}
	/* No native ownership lives on retry; retire every reference on STOP. */
	kthread_cancel_delayed_work_sync(&s->retry_work);
 kthread_cancel_delayed_work_sync(&s->progress_work);
	list_for_each_entry_safe(b, n, &s->retry, node) {
		list_del_init(&b->node);
		xdev_ext_mech_abort(s, b, xdev_ext_mech_stop_reason(s));
	}
	/* Batches waiting at an ordered stage run into their abort. */
	xdev_ext_mech_order_kick(s);
 {
  u32 i;
  for (i = 0; i < s->nr_stages; i++)
   if (s->st[i].cls->progress) {
    unsigned long delay = s->st[i].cls->progress(&s->st[i]);
    /* This may run in the flush of kthread_destroy_worker(); a timer
     * armed after worker_gone would outlive the worker. */
    spin_lock_irqsave(&s->lock, flags);
    if (delay && !s->worker_gone)
     kthread_mod_delayed_work(s->worker, &s->progress_work, delay);
    spin_unlock_irqrestore(&s->lock, flags);
   }
 }
	xdev_ext_mech_return_idle(s, true);
}

/* AF_XDP RX holds. */

static struct xdev_ext_mech_batch *
xdev_ext_mech_open_find_locked(struct xdev_ext_mech_session *s, u64 key)
{
	struct xdev_ext_mech_batch *b;

	list_for_each_entry(b, &s->open, node)
		if (b->key == key)
			return b;
	return NULL;
}

int xdev_ext_mech_hold_commit(struct xdev_ext_mech_stage *st,
			 const struct xdev_ext_mech_hold_intent *hold,
			 const struct xdev_ext_mech_frame *f)
{
	struct xdev_ext_mech_session *s = st->s;
	struct xdev_ext_mech_batch *b;
	unsigned long flags;
	bool fresh = false;
	u32 from, pos;
	int ret;

	if (st->index || !xdev_ext_mech_rx_first(s))
		return -EINVAL;
	ret = xdev_ext_mech_hold_check(hold->pos, hold->count, hold->span_off,
				  hold->span_len, f->data_off, f->data_len);
	if (ret)
		return ret;
	if (!xdev_ext_mech_span_in(hold->span_off, hold->span_len,
			      s->layout.frame_size))
		return -ERANGE;
	pos = hold->pos;

	spin_lock_irqsave(&s->lock, flags);
	if (!xdev_ext_mech_session_admits(s)) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	b = xdev_ext_mech_open_find_locked(s, hold->key);
	if (!b) {
		b = xdev_ext_mech_batch_get_locked(s);
		if (IS_ERR(b)) {
			ret = PTR_ERR(b);
			goto unlock;
		}
		fresh = true;
		b->key = hold->key;
		b->nr_frames = hold->count;
		xdev_ext_mech_group_init(&b->group, hold->key, hold->count);
		xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_OPEN, 0);
	}
	ret = xdev_ext_mech_group_add(&b->group, hold->key, pos, hold->count);
	if (!ret) {
		from = xdev_ext_mech_pool_frame_state(&s->pool, f->index);
		ret = from == XDEV_EXT_MECH_F_USER || from == XDEV_EXT_MECH_F_K_FREE ||
		      from == XDEV_EXT_MECH_F_NIC_RX ?
		      xdev_ext_mech_pool_frame_move(&s->pool, f->index, from,
					       XDEV_EXT_MECH_F_HELD) : -EBUSY;
		if (ret)
			b->group.present &= ~BIT(pos);
	}
	if (ret) {
		if (fresh)
			WARN_ON_ONCE(xdev_ext_mech_batch_put_locked(s, b, false));
		goto unlock;
	}

	/*
	 * Admission is here, after native RX completed under NIC_RX custody.
	 * The session does not govern the earlier external NIC posting. Claim
	 * and publish the already-produced payload only after custody is HELD.
	 */
	{
		u64 token;

		ret = xdev_ext_mech_life_claim(&s->life[f->index], 0, &token);
		if (!ret)
			ret = xdev_ext_mech_life_publish(&s->life[f->index], token,
       xdev_ext_mech_chain_refs(s->plan, s->nr_stages, 1), hold->span_len);
		if (ret) {
			xdev_ext_mech_pool_frame_move(&s->pool, f->index, XDEV_EXT_MECH_F_HELD, from);
			b->group.present &= ~BIT(pos);
			if (fresh)
				WARN_ON_ONCE(xdev_ext_mech_batch_put_locked(s, b, false));
			goto unlock;
		}
	}

	b->f[pos] = *f;
	b->f[pos].data_off = hold->span_off;
	b->f[pos].data_len = hold->span_len;
	b->present |= BIT(pos);
	b->bytes += hold->span_len;
	xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_HELD, 1);
	if (fresh) {
		b->opened = jiffies;
		list_add_tail(&b->node, &s->open);
		if (!(s->st[0].flags & XDEV_EXT_AFXDP_F_RELIABLE) &&
      !timer_pending(&s->group_timer))
			mod_timer(&s->group_timer,
				  b->opened + XDEV_EXT_MECH_GROUP_TIMEOUT);
	}
	if (xdev_ext_mech_group_full(&b->group)) {
		/* Stage 0 completed by holding; the chain goes on at 1. */
		list_del_init(&b->node);
		xdev_ext_mech_batch_step(&b->bs, XDEV_EXT_MECH_EV_READY, 1);
		atomic64_inc(&s->completed[0]);
		xdev_ext_mech_batch_queue(b);
	}
unlock:
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_hold_commit);

/* Timer softirq: partial groups older than the timeout are aborted. */
static void xdev_ext_mech_group_timeout(struct timer_list *t)
{
	struct xdev_ext_mech_session *s = timer_container_of(s, t, group_timer);
	struct xdev_ext_mech_batch *b, *n;
	unsigned long flags, next = 0;
	bool rearm = false;

	spin_lock_irqsave(&s->lock, flags);
	list_for_each_entry_safe(b, n, &s->open, node) {
		unsigned long due = b->opened + XDEV_EXT_MECH_GROUP_TIMEOUT;

		if (time_before(jiffies, due)) {
			if (!rearm || time_before(due, next))
				next = due;
			rearm = true;
			continue;
		}
		list_del_init(&b->node);
		b->abort_err = -ETIMEDOUT;
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_TIMEOUTS, 1);
		xdev_ext_mech_batch_queue(b);
	}
	if (rearm)
		mod_timer(&s->group_timer, next);
	spin_unlock_irqrestore(&s->lock, flags);
}

/* Session life. */

static void xdev_ext_mech_session_init(struct xdev_ext_mech_session *s,
				  struct io_ring_ctx *ctx,
				  const struct xdev_ext_mech_create *c, u32 frames)
{
	INIT_LIST_HEAD(&s->ring_node);
	INIT_LIST_HEAD(&s->all_node);
	INIT_LIST_HEAD(&s->live_node);
	INIT_LIST_HEAD(&s->open);
	INIT_LIST_HEAD(&s->free);
	INIT_LIST_HEAD(&s->ordered);
	INIT_LIST_HEAD(&s->retry);
	spin_lock_init(&s->lock);
	xdev_ext_mech_sess_init(&s->ss);
	xdev_ext_mech_notify_init(&s->notify);
	/* Nothing is admitted until CREATE has bound everything. */
	s->ss.state = XDEV_EXT_MECH_SESSION_NONE;
	s->ctx = ctx;
	s->id = atomic64_inc_return(&xdev_ext_mech_next_id);
	s->uid = current_euid();
	s->layout = c->layout;
	s->peer = c->peer;
	s->depth = c->depth;
	s->frames = frames;
	s->nr_stages = c->nr_stages;
 memcpy(s->plan, c->st, sizeof(s->plan));
	init_llist_head(&s->inbox);
	kthread_init_work(&s->drain_work, xdev_ext_mech_batch_drain);
	kthread_init_delayed_work(&s->retry_work, xdev_ext_mech_retry_work);
	kthread_init_work(&s->stop_work, xdev_ext_mech_stop_work);
	kthread_init_work(&s->kick_work, xdev_ext_mech_kick_work);
 kthread_init_delayed_work(&s->progress_work, xdev_ext_mech_progress_work);
	INIT_WORK(&s->reap_work, xdev_ext_mech_reap);
	timer_setup(&s->group_timer, xdev_ext_mech_group_timeout, 0);
	init_waitqueue_head(&s->drain_wq);
}

/* Worker buffers and batch objects, sized for the session's classes. */
static int xdev_ext_mech_session_buffers(struct xdev_ext_mech_session *s)
{
	u32 info = 0, scratch = 0, cqe = 0, priv = 0, cookie = 0, i;

	for (i = 0; i < s->nr_stages; i++) {
		const struct xdev_ext_mech_class_ops *cls = s->st[i].cls;

		info = max(info, cls->info_size);
		scratch = max(scratch, cls->desc_size * cls->desc_cap);
		cqe = max(cqe, cls->cqe_size * cls->cqe_cap);
		priv = max(priv, cls->batch_priv_size);
		if (cls->batch_cookie_size > XDEV_EXT_MECH_CLASS_SIZE_MAX)
			return -E2BIG;
		cookie = max(cookie, cls->batch_cookie_size);
	}
	if (info) {
		s->info = kzalloc(info, GFP_KERNEL);
		if (!s->info)
			return -ENOMEM;
	}
	if (cqe) {
		s->cqe = kzalloc(cqe, GFP_KERNEL);
		if (!s->cqe)
			return -ENOMEM;
	}
	s->scratch = kzalloc(scratch, GFP_KERNEL);
	s->batches = kvcalloc(s->depth, sizeof(*s->batches), GFP_KERNEL);
 s->fan_batches = kvcalloc(s->depth * XDEV_EXT_MECH_MAX_STAGES, sizeof(*s->fan_batches), GFP_KERNEL);
	if (!s->scratch || !s->batches || !s->fan_batches)
		return -ENOMEM;
	/* Areas sit back to back: keep each one u64 aligned. */
	priv = ALIGN(priv, sizeof(u64));
	if (priv) {
		s->privs = kvcalloc(s->depth * (XDEV_EXT_MECH_MAX_STAGES + 1), priv, GFP_KERNEL);
		if (!s->privs)
			return -ENOMEM;
	}
	cookie = ALIGN(cookie, sizeof(u64));
	if (cookie) {
		s->cookies = kvcalloc(s->depth * (XDEV_EXT_MECH_MAX_STAGES + 1), cookie, GFP_KERNEL);
		if (!s->cookies)
			return -ENOMEM;
	}
	s->priv_size = priv;
	for (i = 0; i < s->depth; i++) {
		struct xdev_ext_mech_batch *b = &s->batches[i];

		b->s = s;
		xdev_ext_mech_completion_init(&b->completion);
		b->priv = priv ? s->privs + (size_t)i * priv : NULL;
		b->cookie = cookie ? s->cookies + (size_t)i * cookie : NULL;
		list_add_tail(&b->node, &s->free);
  {
   u32 j;

   for (j = 0; j < XDEV_EXT_MECH_MAX_STAGES; j++) {
    u32 offset = s->depth + i * XDEV_EXT_MECH_MAX_STAGES + j;
    struct xdev_ext_mech_batch *child = &s->fan_batches[i * XDEV_EXT_MECH_MAX_STAGES + j];

    child->s = s;
    child->priv = priv ? s->privs + (size_t)offset * priv : NULL;
    child->cookie = cookie ? s->cookies + (size_t)offset * cookie : NULL;
    xdev_ext_mech_completion_init(&child->completion);
    INIT_LIST_HEAD(&child->node);
   }
  }
	}
	return 0;
}

static int xdev_ext_mech_pool_bind(struct xdev_ext_mech_session *s,
			      const struct xdev_ext_mech_create *c)
{
	int ret;

	if (c->pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM) {
		ret = io_xdev_ext_umem_mech_pool_bind(&s->pool, s->ctx, &s->layout);
	} else {
		s->pool_file = fget(c->pool_fd);
		if (!s->pool_file)
			return -EBADF;
  if (c->pool_kind == XDEV_EXT_MECH_POOL_PEER)
   ret = xdev_ext_peer_mech_pool_bind(&s->pool, s->pool_file, &s->layout);
  else
		ret = xsk_xdev_ext_mech_pool_bind(&s->pool, s->pool_file,
					     &s->layout);
	}
	if (ret) {
		memset(&s->pool, 0, sizeof(s->pool));
		return ret;
	}
	if (s->pool.frame_size != s->layout.frame_size || !s->pool.state ||
	    !s->pool.nr_frames) {
		s->pool.ops->release(&s->pool);
		memset(&s->pool, 0, sizeof(s->pool));
		return -EINVAL;
	}
	s->life = s->pool.life;
 if (!s->life) {
  s->life = kvcalloc(s->pool.nr_frames, sizeof(*s->life), GFP_KERNEL);
  s->owns_life = true;
 }
	s->transform_owner = kvcalloc(s->pool.nr_frames, 1, GFP_KERNEL);
	if (!s->life || !s->transform_owner)
		return -ENOMEM;
	/* Fresh table starts FREE; provider still controls partition admission. */
	return 0;
}

/* CREATE, process context: run the stage's optional prepare program. */
static int xdev_ext_mech_prepare(struct xdev_ext_mech_session *s,
			    struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_binding_ctx_v2 base = xdev_ext_mech_base(st, 0);
	struct xdev_ext_mech_call_args a = {
		.member = XDEV_EXT_MECH_MEMBER_PREPARE,
		.callsite = XDEV_EXT_MECH_SITE_CREATE,
		.base = &base,
		.info_size = st->cls->info_size,
		.info = st->cls->info_size ? s->info : NULL,
	};
	bool illegal;
	s32 ret;
	int err;

	if (st->cls->info_size) {
		memset(s->info, 0, st->cls->info_size);
		st->cls->fill_info(st, NULL, s->info);
	}
	err = xdev_ext_mech_call(st, &a, &ret, NULL);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;
	return xdev_ext_mech_ret_resolve(st->class_id, XDEV_EXT_MECH_MEMBER_PREPARE,
				    XDEV_EXT_MECH_SITE_CREATE, ret, &illegal);
}

/*
 * CREATE, process context: classes and one callback generation per class,
 * buffers, eventfd, worker, pool, stage files and binds, then prepare.
 * On error the caller releases whatever was taken.
 */
static int xdev_ext_mech_session_bind(struct xdev_ext_mech_session *s,
				 const struct xdev_ext_mech_create *c)
{
	struct xdev_ext_mech_stage *st;
	u32 i;
	int ret;

	for (i = 0; i < s->nr_stages; i++) {
		st = &s->st[i];
		*st = (struct xdev_ext_mech_stage) {
			.s = s,
			.arg0 = c->st[i].arg0,
			.arg1 = c->st[i].arg1,
			.class_id = c->st[i].class_id,
			.direction = c->st[i].direction,
			.flags = c->st[i].flags,
			.index = i,
		};
		st->cls = xdev_ext_mech_class_get(st->class_id);
		if (!st->cls)
			return -EOPNOTSUPP;
		if (s->ops[st->class_id])
			continue;
		/* No program for the class: no silent C path either. */
		s->ops[st->class_id] = xdev_ext_mech_ops_get(st->class_id,
							&s->pinned[st->class_id],
							&s->c_owner[st->class_id]);
		if (!s->ops[st->class_id])
			return -EOPNOTSUPP;
	}
	ret = xdev_ext_mech_session_buffers(s);
	if (ret)
		return ret;
	if (c->eventfd >= 0) {
		s->evfd = eventfd_ctx_fdget(c->eventfd);
		if (IS_ERR(s->evfd)) {
			ret = PTR_ERR(s->evfd);
			s->evfd = NULL;
			return ret;
		}
	}
	s->worker = kthread_run_worker(0, "xdev_ext_mech/%llu", s->id);
	if (IS_ERR(s->worker)) {
		ret = PTR_ERR(s->worker);
		s->worker = NULL;
		return ret;
	}
	ret = xdev_ext_mech_pool_bind(s, c);
	if (ret)
		return ret;
	for (i = 0; i < s->nr_stages; i++) {
		st = &s->st[i];
		if (st->class_id != XDEV_EXT_MECH_CLASS_CPU) {
			st->file = fget(c->st[i].fd);
			if (!st->file)
				return -EBADF;
		}
		ret = st->cls->bind(st, &c->st[i]);
  if (ret) {
   /* Checked classes publish any residual mapping in priv on failure. */
   if (st->cls->unbind_checked && st->priv)
    s->nr_bound++;
   return ret;
  }
		s->nr_bound++;
	}
	for (i = 0; i < s->nr_stages; i++) {
		ret = xdev_ext_mech_prepare(s, &s->st[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static void xdev_ext_mech_quarantine(struct xdev_ext_mech_session *s);

/* Both failed CREATE and normal DESTROY arrive here before pool release. */
static int xdev_ext_mech_unbind_checked(struct xdev_ext_mech_session *s)
{
 u32 i;
 int err;

 for (i = s->nr_bound; i-- > 0;) {
  struct xdev_ext_mech_stage *st = &s->st[i];

  if (!st->cls->unbind_checked)
   continue;
  err = st->cls->unbind_checked(st);
  if (err)
   return err;
 }
 return 0;
}

/* Process context, nothing in flight: give every reference back. */
static int xdev_ext_mech_session_release(struct xdev_ext_mech_session *s)
{
	struct xdev_ext_mech_stage *st;
	unsigned long flags;
	u32 i;
	int final_err;

 final_err = xdev_ext_mech_unbind_checked(s);
 if (final_err) {
  /* Unmap failure is uncertainty, not permission to put the UMEM's original
   * FOLL_PIN refs. Keep pool, files, callback storage and module refs intact. */
  spin_lock_irqsave(&s->lock, flags);
  s->ss.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
  s->ss.sequestered++;
  if (!s->last_err)
   s->last_err = final_err;
  spin_unlock_irqrestore(&s->lock, flags);
  atomic64_add(s->pool.nr_frames, &s->cnt[XDEV_EXT_MECH_CNT_SEQUESTERED]);
  xdev_ext_mech_quarantine(s);
  return final_err;
 }

	/* STATS from another ring finds it no more. */
	mutex_lock(&xdev_ext_mech_live_lock);
	list_del_init(&s->live_node);
	mutex_unlock(&xdev_ext_mech_live_lock);
	/*
	 * A stage stays published until its unbind below; a stop it reports
	 * meanwhile (T-UNBIND after a failed CREATE) must not queue on the
	 * worker freed here.
	 */
	spin_lock_irqsave(&s->lock, flags);
	s->worker_gone = true;
	spin_unlock_irqrestore(&s->lock, flags);
	if (s->worker) {
		kthread_cancel_delayed_work_sync(&s->retry_work);
 kthread_cancel_delayed_work_sync(&s->progress_work);
		synchronize_rcu();
		kthread_destroy_worker(s->worker);
	}
	timer_shutdown_sync(&s->group_timer);
	for (i = s->nr_bound; i-- > 0;)
		if (s->st[i].cls->unbind)
			s->st[i].cls->unbind(&s->st[i]);
	if (s->pool.ops)
		s->pool.ops->release(&s->pool);
	/* All published native callbacks have now been detached/synchronized.
	 * Capture the result before freeing s; a pre-unbind snapshot can miss
	 * the last error even when all native reference counts reached zero. */
	spin_lock_irqsave(&s->lock, flags);
	final_err = s->last_err;
	spin_unlock_irqrestore(&s->lock, flags);
	if (s->pool_file)
		fput(s->pool_file);
	for (i = 0; i < s->nr_stages; i++) {
		st = &s->st[i];
		if (st->file)
			fput(st->file);
		if (st->cls)
			xdev_ext_mech_class_put(st->cls);
	}
	if (s->evfd)
		eventfd_ctx_put(s->evfd);
	for (i = 0; i < XDEV_EXT_MECH_CLASS_MAX; i++)
		if (s->ops[i])
			xdev_ext_mech_ops_put(s->ops[i], s->pinned[i], s->c_owner[i]);
	kvfree(s->cookies);
	kvfree(s->transform_owner);
	if (s->owns_life)
		kvfree(s->life);
	kvfree(s->privs);
	kvfree(s->fan_batches);
	kvfree(s->batches);
	kfree(s->cqe);
	kfree(s->scratch);
	kfree(s->info);
	kfree(s);
	return final_err;
}

/*
 * Process context: a device may still use frames of @s (a sequestered batch,
 * or the drain timed out).  The session object, its pool and pool file, its
 * stages (never unbound) with their files, class modules and backend
 * regions, its callback generations and its eventfd stay referenced for
 * good; late completions still run in its worker with C defaults only.
 */
static void xdev_ext_mech_quarantine(struct xdev_ext_mech_session *s)
{
	u64 frames = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_SEQUESTERED]);
	struct xdev_ext_mech_quarantine total;

	mutex_lock(&xdev_ext_mech_quarantine_lock);
	list_add_tail(&s->quarantine_node, &xdev_ext_mech_quarantined);
	xdev_ext_mech_quarantine_add(&xdev_ext_mech_parked, 1 + s->nr_stages,
				min_t(u64, frames, U32_MAX));
	total = xdev_ext_mech_parked;
	mutex_unlock(&xdev_ext_mech_quarantine_lock);
	pr_warn("xdev_ext_mech: session %llu quarantined, inflight=%u sequestered=%u; %llu references and %llu frames parked in all\n",
		s->id, READ_ONCE(s->ss.inflight), READ_ONCE(s->ss.sequestered),
		total.objects, total.frames);
}

/*
 * Process context, without uring_lock or an AF_XDP socket mutex; @s is off
 * its ring's list.  Stop, bounded drain, then release, or quarantine when a device may
 * still use the frames. Returns the synchronized final error, or -EBUSY
 * when quarantined or when the release waits for accepted commands.
 *
 * The drain bound is shorter than provider deadlines (CE and NET wait 30 s,
 * NVMe its io_timeout).  A command still in flight at the bound is accepted,
 * not known to be lost: if nothing is sequestered and no native control
 * reference is held, the session stays STOPPING and the batch that drops
 * the last reference makes the release decision (xdev_ext_mech_release_late).
 * Nothing is reissued; any ambiguous outcome still quarantines.
 */
static int xdev_ext_mech_session_destroy(struct xdev_ext_mech_session *s)
{
	unsigned long flags;
	u32 inflight = 0;
	bool last;
	int fate;

	spin_lock(&xdev_ext_mech_all_lock);
	list_del_init(&s->all_node);
	spin_unlock(&xdev_ext_mech_all_lock);

	xdev_ext_mech_session_stop(s, 0);
	timer_shutdown_sync(&s->group_timer);
	wait_event_timeout(s->drain_wq, xdev_ext_mech_settled(s),
			   XDEV_EXT_MECH_DRAIN_TIMEOUT);

	spin_lock_irqsave(&s->lock, flags);
	if (s->ss.state == XDEV_EXT_MECH_SESSION_STOPPING && s->ss.inflight &&
	    !s->ss.sequestered && !atomic_read(&s->native_controls) &&
	    !s->start_preparing && !s->start_return_pending) {
		/* Only accepted commands remain: their completion decides. */
		s->release_deferred = true;
		inflight = s->ss.inflight;
	} else if (s->ss.state == XDEV_EXT_MECH_SESSION_STOPPING) {
		xdev_ext_mech_sess_drain(&s->ss, true);
	}
	xdev_ext_mech_notify_locked(s, false);
	fate = xdev_ext_mech_sess_ref_fate(&s->ss);
 if (atomic_read(&s->native_controls)) {
  s->ss.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
  fate = XDEV_EXT_MECH_REFS_QUARANTINE;
 }
	last = xdev_ext_mech_sess_put(&s->ss);
	if (last)
		s->worker_gone = true;
	spin_unlock_irqrestore(&s->lock, flags);

	if (inflight) {
		/* In flight, so not last; @s may be gone once the lock is dropped. */
		pr_warn("xdev_ext_mech: drain bound passed with %u batches in flight; release waits for their completion\n",
			inflight);
		return -EBUSY;
	}
	if (fate != XDEV_EXT_MECH_REFS_RELEASE || !last) {
		xdev_ext_mech_quarantine(s);
		if (last) {
			kthread_cancel_delayed_work_sync(&s->retry_work);
			kthread_cancel_delayed_work_sync(&s->progress_work);
			synchronize_rcu();
			kthread_destroy_worker(s->worker);
		}
		return -EBUSY;
	}
	return xdev_ext_mech_session_release(s);
}

/*
 * System workqueue: the last batch of a session whose STOP passed the drain
 * bound has ended.  Release only when every outcome was definite (nothing
 * sequestered, no native control reference); otherwise quarantine as STOP
 * would have.  A settle that could not run leaves STOPPING: fail closed.
 */
static void xdev_ext_mech_release_late(struct xdev_ext_mech_session *s)
{
	unsigned long flags;
	int fate;

	spin_lock_irqsave(&s->lock, flags);
	if (s->ss.state == XDEV_EXT_MECH_SESSION_STOPPING || s->ss.inflight ||
	    atomic_read(&s->native_controls))
		s->ss.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
	fate = xdev_ext_mech_sess_ref_fate(&s->ss);
	xdev_ext_mech_notify_locked(s, false);
	spin_unlock_irqrestore(&s->lock, flags);

	if (fate == XDEV_EXT_MECH_REFS_RELEASE) {
		xdev_ext_mech_session_release(s);
		return;
	}
	xdev_ext_mech_quarantine(s);
	kthread_cancel_delayed_work_sync(&s->retry_work);
	kthread_cancel_delayed_work_sync(&s->progress_work);
	synchronize_rcu();
	kthread_destroy_worker(s->worker);
}

void xdev_ext_mech_generation_gone(u32 class_id, const void *ops)
{
	struct xdev_ext_mech_session *s;

	spin_lock(&xdev_ext_mech_all_lock);
	list_for_each_entry(s, &xdev_ext_mech_all, all_node)
		if (s->ops[class_id] == ops)
			xdev_ext_mech_session_stop(s, -ECANCELED);
	spin_unlock(&xdev_ext_mech_all_lock);
}

/* Control plane, uring_lock held. */

static struct xdev_ext_mech_session *xdev_ext_mech_find(struct io_ring_ctx *ctx, u64 id)
{
	struct xdev_ext_mech_session *s;

	list_for_each_entry(s, &ctx->xdev_ext_mech_sessions, ring_node)
		if (s->id == id)
			return s;
	return NULL;
}

/* Owning ring only, as START/STOP; uring_lock pins the session here. */
static int xdev_ext_mech_notify_arm_op(struct io_ring_ctx *ctx, void __user *uarg)
{
	struct xdev_ext_mech_notify_arm arm;
	struct xdev_ext_mech_session *s;
	unsigned long flags;
	int ret;

	if (copy_from_user(&arm, uarg, sizeof(arm)))
		return -EFAULT;
	ret = xdev_ext_mech_notify_validate(&arm);
	if (ret)
		return ret;
	s = xdev_ext_mech_find(ctx, arm.session_id);
	if (!s)
		return -ENOENT;
	spin_lock_irqsave(&s->lock, flags);
	ret = xdev_ext_mech_notify_arm(&s->notify, &arm);
	if (!ret)
		xdev_ext_mech_notify_locked(s, false);
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
}

static int xdev_ext_mech_create(struct io_ring_ctx *ctx, void __user *uarg)
{
	struct xdev_ext_mech_create __user *ucreate = uarg;
	struct xdev_ext_mech_session *s;
	struct xdev_ext_mech_create c;
	unsigned long flags;
	u32 frames;
	int ret;

	if (!xdev_ext_mech_ready())
		return -EOPNOTSUPP;
	if (copy_from_user(&c, ucreate, sizeof(c)))
		return -EFAULT;
	ret = xdev_ext_mech_create_check(&c, &frames);
	if (ret)
		return ret;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	xdev_ext_mech_session_init(s, ctx, &c, frames);
	ret = xdev_ext_mech_session_bind(s, &c);
	if (!ret && put_user(s->id, &ucreate->session_id))
		ret = -EFAULT;
	if (ret) {
		xdev_ext_mech_session_release(s);
		return ret;
	}

	spin_lock_irqsave(&s->lock, flags);
	ret = xdev_ext_mech_sess_activate(&s->ss);
	spin_unlock_irqrestore(&s->lock, flags);
	if (ret) {
		/* A stage's device went away while CREATE was binding. */
		ret = xdev_ext_mech_stop_reason(s);
		xdev_ext_mech_session_release(s);
		return ret;
	}
	list_add_tail_rcu(&s->ring_node, &ctx->xdev_ext_mech_sessions);
	spin_lock(&xdev_ext_mech_all_lock);
	list_add_tail(&s->all_node, &xdev_ext_mech_all);
	spin_unlock(&xdev_ext_mech_all_lock);
	mutex_lock(&xdev_ext_mech_live_lock);
	list_add_tail(&s->live_node, &xdev_ext_mech_live);
	mutex_unlock(&xdev_ext_mech_live_lock);
	/* A generation retracted before the session was listed. */
	if (!xdev_ext_mech_session_admits(s))
		xdev_ext_mech_session_stop(s, -ECANCELED);
	return 0;
}

/* Process context, START preparing: lend USER frames, then queue them.
 * uring_lock pins the session; preparing excludes the worker from this queue.
 * No pool-sized loop may hold s->lock or keep interrupts disabled.
 */
static int xdev_ext_mech_take_user_frames(struct xdev_ext_mech_session *s,
				     const u32 *idx, u32 nr)
{
	struct xdev_ext_mech_frame f = {};
	u32 i;
	int ret = 0;

	for (i = 0; i < nr; i++) {
		cond_resched();
		ret = xdev_ext_mech_pool_frame_move(&s->pool, idx[i],
					       XDEV_EXT_MECH_F_USER,
					       XDEV_EXT_MECH_F_K_FREE);
		if (ret)
			break;
	}
	if (ret) {
		while (i--) {
			cond_resched();
			xdev_ext_mech_pool_frame_move(&s->pool, idx[i],
						 XDEV_EXT_MECH_F_K_FREE,
						 XDEV_EXT_MECH_F_USER);
		}
		return ret == -ERANGE ? -EINVAL : -EBUSY;
	}
	/* User-selected IOU source bytes become READY only after all custody
	 * transfers succeeded; a pure producer starts from FREE instead.
	 */
	if (s->st[0].direction == XDEV_EXT_MECH_DIR_TO_DEVICE ||
     (s->st[0].cls->flags & XDEV_EXT_MECH_CLASS_F_TRANSFORM)) {
		for (i = 0; i < nr; i++) {
			u32 off, len;
			u64 token;

			cond_resched();
			ret = xdev_ext_mech_layout_span(&s->layout, i % s->frames, &off, &len);
			if (!ret && s->start_user_len)
				len = s->start_user_len;
			if (!ret)
				ret = xdev_ext_mech_life_claim(&s->life[idx[i]], XDEV_EXT_MECH_L_OWNER_START, &token);
			if (!ret)
				ret = xdev_ext_mech_life_publish(&s->life[idx[i]], token,
       xdev_ext_mech_chain_refs(s->plan, s->nr_stages, 0), len);
			if (ret)
				break;
		}
		if (ret) {
			u32 j;

			for (j = 0; j < i; j++) {
				cond_resched();
				xdev_ext_mech_life_release(&s->life[idx[j]],
					xdev_ext_mech_life_gen(&s->life[idx[j]]));
			}
			for (j = 0; j < nr; j++) {
				cond_resched();
				xdev_ext_mech_pool_frame_move(&s->pool, idx[j],
					XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_USER);
			}
			return ret;
		}
	}
	for (i = 0; i < nr; i++) {
		cond_resched();
		f.index = idx[i];
		s->pool.ops->recycle(&s->pool, &f);
	}
	return 0;
}

static int xdev_ext_mech_start(struct io_ring_ctx *ctx, void __user *uarg)
{
	struct xdev_ext_mech_session *s;
	struct xdev_ext_mech_start req;
	struct xdev_ext_mech_user_span span;
	unsigned long flags;
	u32 *idx = NULL;
	u32 user_len = 0;
	int ret;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;
	s = xdev_ext_mech_find(ctx, req.session_id);
	if (!s)
		return -ENOENT;
	ret = xdev_ext_mech_start_check(&req, s->pool.kind, xdev_ext_mech_rx_first(s),
				   s->frames, s->pool.nr_frames);
	if (ret)
		return ret;
	if (req.flags & XDEV_EXT_MECH_START_F_USER_SPANS) {
		u32 off, capacity;

		if (s->st[0].direction != XDEV_EXT_MECH_DIR_TO_DEVICE ||
		    copy_from_user(&span, u64_to_user_ptr(req.user_frames), sizeof(span)))
			return s->st[0].direction != XDEV_EXT_MECH_DIR_TO_DEVICE ? -EINVAL : -EFAULT;
		ret = xdev_ext_mech_layout_span(&s->layout, 0, &off, &capacity);
		if (ret || !span.len || span.len > capacity || span.index >= s->pool.nr_frames)
			return -EINVAL;
		user_len = span.len;
	}
	if ((req.flags & XDEV_EXT_MECH_START_F_RECYCLE) &&
	    req.nr_user_frames != min_t(u64, req.nr_batches, s->depth) * s->frames)
		return -EINVAL;

	/* io_uring_register holds uring_lock throughout START. STOP removes the
	 * session from that ring under the same mutex before dropping it to
	 * destroy; ring_exit also takes it before splicing the session list.
	 * Thus the session/root reference and worker outlive this CPU handoff.
	 */
	spin_lock_irqsave(&s->lock, flags);
	if (!xdev_ext_mech_session_admits(s))
		ret = -ESHUTDOWN;
	else if (s->start_preparing || s->start_return_pending || s->start_left ||
		 ((s->start_user_len || user_len) && s->ss.inflight) ||
		 ((s->start_recycle || (req.flags & XDEV_EXT_MECH_START_F_RECYCLE)) &&
		  s->ss.inflight))
		ret = -EBUSY;
	else {
		s->start_preparing = true;
		s->start_user_len = user_len;
	}
	spin_unlock_irqrestore(&s->lock, flags);
	if (ret)
		return ret;

	if (req.flags & XDEV_EXT_MECH_START_F_USER_FRAMES) {
		if (user_len)
			idx = kmemdup(&span.index, sizeof(*idx), GFP_KERNEL);
		else
			idx = memdup_array_user(u64_to_user_ptr(req.user_frames),
					req.nr_user_frames, sizeof(*idx));
		if (IS_ERR_OR_NULL(idx)) {
			ret = idx ? PTR_ERR(idx) : -ENOMEM;
			idx = NULL;
			goto finish;
		}
		/* Avoid lending at all if STOP won during a faulting user copy. */
		if (!xdev_ext_mech_session_admits(s))
			ret = -ESHUTDOWN;
		else
			ret = xdev_ext_mech_take_user_frames(s, idx, req.nr_user_frames);
	}
finish:
	spin_lock_irqsave(&s->lock, flags);
	if (!ret && xdev_ext_mech_session_admits(s)) {
		s->start_left = req.nr_batches;
		s->start_seq = req.first_seq;
		s->start_to_user = req.flags & XDEV_EXT_MECH_START_F_USER_FRAMES;
		s->start_recycle = req.flags & XDEV_EXT_MECH_START_F_RECYCLE;
		s->start_return_pending = s->start_recycle;
	} else if (!ret) {
		/* STOP can run even while take_user_frames is publishing its queue.
		 * The worker could already have tried to drain it; requeue below
		 * after the complete loan set is visible, including legacy USER.
		 */
		s->start_return_pending = idx != NULL;
		ret = -ESHUTDOWN;
	}
	s->start_preparing = false;
	xdev_ext_mech_settle_locked(s);
	xdev_ext_mech_notify_locked(s, false);
	if (!s->worker_gone) {
		if (!xdev_ext_mech_session_admits(s))
			kthread_queue_work(s->worker, &s->stop_work);
		else if (!ret)
			kthread_queue_work(s->worker, &s->kick_work);
	}
	spin_unlock_irqrestore(&s->lock, flags);
	kfree(idx);
	return ret;
}

static int xdev_ext_mech_stop_op(struct io_ring_ctx *ctx, u64 id)
	__must_hold(&ctx->uring_lock)
{
	struct xdev_ext_mech_session *s = xdev_ext_mech_find(ctx, id);
	int ret;

	if (!s)
		return -ENOENT;
	/*
	 * This task runs the completions of its own uring_cmds as task work,
	 * so it must not wait for them: stop admitting and let it come back.
	 */
	xdev_ext_mech_session_stop(s, 0);
	if (READ_ONCE(s->cmd_refs))
		return -EAGAIN;
	/* An io-wq uring_cmd lookup may still be walking past this node. */
	list_del_rcu(&s->ring_node);
	/* The drain may wait for completions; never under uring_lock. */
	mutex_unlock(&ctx->uring_lock);
	ret = xdev_ext_mech_session_destroy(s);
	mutex_lock(&ctx->uring_lock);
	return ret;
}

/*
 * xdev_ext_mech_live_lock held: a session of another ring, while it exists, if
 * the caller is its creator's user.
 */
static struct xdev_ext_mech_session *xdev_ext_mech_find_live(u64 id)
{
	struct xdev_ext_mech_session *s;

	lockdep_assert_held(&xdev_ext_mech_live_lock);
	list_for_each_entry(s, &xdev_ext_mech_live, live_node)
		if (s->id == id)
			return uid_eq(s->uid, current_euid()) ? s : NULL;
	return NULL;
}

static void xdev_ext_mech_stats_fill(struct xdev_ext_mech_session *s,
				struct xdev_ext_mech_stats *out)
{
	unsigned long flags;
	u32 i;

	memset(out, 0, sizeof(*out));
	out->session_id = s->id;
	out->rejects = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_REJECTS]);
	out->recycled = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_RECYCLED]);
	out->held = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_HELD]);
	out->sequestered = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_SEQUESTERED]);
	out->timeouts = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_TIMEOUTS]);
	out->native_publish = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_NATIVE_PUBLISH]);
	out->protocol_err = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_PROTOCOL_ERR]);
	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++) {
		out->submitted[i] = atomic64_read(&s->submitted[i]);
		out->completed[i] = atomic64_read(&s->completed[i]);
	}
	spin_lock_irqsave(&s->lock, flags);
	out->batches_done = atomic64_read(&s->done);
	out->batches_abort = atomic64_read(&s->aborted);
	out->published = atomic64_read(&s->cnt[XDEV_EXT_MECH_CNT_PUBLISHED]);
	out->inflight = s->ss.inflight;
	out->last_err = s->last_err;
	out->state = s->ss.state;
	spin_unlock_irqrestore(&s->lock, flags);
}

/*
 * The owning ring, or any ring of the creator's user while the session
 * exists (a draining or quarantined one included); -ENOENT once freed.
 */
static int xdev_ext_mech_stats(struct io_ring_ctx *ctx, void __user *uarg)
{
	struct xdev_ext_mech_session *s;
	struct xdev_ext_mech_stats out;
	u64 id;

	if (copy_from_user(&id, uarg, sizeof(id)))
		return -EFAULT;
	s = xdev_ext_mech_find(ctx, id);
	if (s) {
		xdev_ext_mech_stats_fill(s, &out);
	} else {
		mutex_lock(&xdev_ext_mech_live_lock);
		s = xdev_ext_mech_find_live(id);
		if (s)
			xdev_ext_mech_stats_fill(s, &out);
		mutex_unlock(&xdev_ext_mech_live_lock);
		if (!s)
			return -ENOENT;
	}
	return copy_to_user(uarg, &out, sizeof(out)) ? -EFAULT : 0;
}

/* A full v4 snapshot; older callers copy only their exact versioned prefix. */
static void xdev_ext_mech_transport_stats_fill(struct xdev_ext_mech_session *s,
				struct xdev_ext_mech_transport_stats_v4 *full, u32 version)
{
	struct xdev_ext_mech_transport_stats_v2 *out=&full->v3.v2;
	u32 i;
	u64 pending = 0, uncertain = 0;

	memset(full, 0, sizeof(*full));
	out->v1.size = version == XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4 ? sizeof(*full) :
                   version == XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3 ? sizeof(full->v3) :
                   version == XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_2 ?
		       sizeof(*out) : sizeof(out->v1);
	out->v1.version = version;
	out->v1.session_id = s->id;
	out->v1.native_controls = atomic_read(&s->native_controls);
	/* No session lock while acquiring a provider lock: RX admission uses
	 * the opposite order. The synchronous STOP remains the final barrier. */
	for (i = 0; i < s->nr_stages; i++) {
		u32 p = 0, u = 0;

		if (s->st[i].cls->transport_stats)
			s->st[i].cls->transport_stats(&s->st[i], &p, &u);
		if (version >= XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_2 &&
		    s->st[i].cls->transport_counters)
			s->st[i].cls->transport_counters(&s->st[i], out);
  if (version==XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4 && !full->rel_policy.version &&
      s->st[i].cls->transport_policy)
   s->st[i].cls->transport_policy(&s->st[i],&full->rel_policy);
		pending += p;
		uncertain += u;
	}
	out->v1.pending_acks = min_t(u64, pending, U32_MAX);
	out->v1.uncertain_controls = min_t(u64, uncertain, U32_MAX);
}

static int xdev_ext_mech_transport_stats(struct io_ring_ctx *ctx, void __user *uarg)
{
	struct xdev_ext_mech_transport_stats_v4 out = {};
	struct xdev_ext_mech_session *s;
	u32 size;

	if (copy_from_user(&out.v3.v2.v1, uarg, sizeof(out.v3.v2.v1)))
		return -EFAULT;
	size = out.v3.v2.v1.version == XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4 ? sizeof(out) :
        out.v3.v2.v1.version == XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3 ? sizeof(out.v3) :
        out.v3.v2.v1.version == XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_2 ? sizeof(out.v3.v2) : sizeof(out.v3.v2.v1);
	if ((out.v3.v2.v1.version != XDEV_EXT_MECH_TRANSPORT_STATS_VERSION &&
	     out.v3.v2.v1.version != XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_2 &&
      out.v3.v2.v1.version != XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3 &&
      out.v3.v2.v1.version != XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4) ||
	    out.v3.v2.v1.size != size)
		return -EINVAL;
	if (size > sizeof(out.v3.v2.v1) && copy_from_user(&out, uarg, size))
		return -EFAULT;
	if (out.v3.v2.v1.native_controls || out.v3.v2.v1.pending_acks || out.v3.v2.v1.uncertain_controls ||
	    out.v3.v2.v1.rsvd || out.v3.v2.retransmits || out.v3.v2.dup_suppressed || out.v3.v2.held_acks ||
	    out.v3.v2.held_unacked || out.v3.v2.rsvd2 ||
     out.v3.nic_copy_ops || out.v3.nic_copy_bytes || out.v3.nic_zc_ops || out.v3.nic_zc_bytes ||
     memchr_inv(&out.rel_policy,0,sizeof(out.rel_policy)))
		return -EINVAL;
	s = xdev_ext_mech_find(ctx, out.v3.v2.v1.session_id);
	if (s) {
		xdev_ext_mech_transport_stats_fill(s, &out, out.v3.v2.v1.version);
	} else {
		mutex_lock(&xdev_ext_mech_live_lock);
		s = xdev_ext_mech_find_live(out.v3.v2.v1.session_id);
		if (s)
			xdev_ext_mech_transport_stats_fill(s, &out, out.v3.v2.v1.version);
		mutex_unlock(&xdev_ext_mech_live_lock);
		if (!s)
			return -ENOENT;
	}
	return copy_to_user(uarg, &out, size) ? -EFAULT : 0;
}

int io_xdev_ext_mech_register(struct io_ring_ctx *ctx, void __user *arg,
			 unsigned int nr_args)
{
	struct io_uring_xdev_ext_mech req;

	if (nr_args != 1)
		return -EINVAL;
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;
	if (req.rsvd)
		return -EINVAL;

	switch (req.op) {
	case XDEV_EXT_MECH_OP_CREATE:
		return xdev_ext_mech_create(ctx, u64_to_user_ptr(req.arg));
	case XDEV_EXT_MECH_OP_START:
		return xdev_ext_mech_start(ctx, u64_to_user_ptr(req.arg));
	case XDEV_EXT_MECH_OP_STOP:
		return xdev_ext_mech_stop_op(ctx, req.arg);
	case XDEV_EXT_MECH_OP_STATS:
		return xdev_ext_mech_stats(ctx, u64_to_user_ptr(req.arg));
	case XDEV_EXT_MECH_OP_NOTIFY_ARM:
		return xdev_ext_mech_notify_arm_op(ctx, u64_to_user_ptr(req.arg));
	case XDEV_EXT_MECH_OP_TRANSPORT_STATS:
		return xdev_ext_mech_transport_stats(ctx, u64_to_user_ptr(req.arg));
	default:
		return -EINVAL;
	}
}

/*
 * io_ring_exit_work, after the ring's requests are gone (so no uring_cmd
 * holds a stage) and without uring_lock: stop every session, then drain
 * and release or quarantine each.
 */
void io_xdev_ext_mech_ring_exit(struct io_ring_ctx *ctx)
{
	struct xdev_ext_mech_session *s, *n;
	LIST_HEAD(list);

	/* No uring_cmd of this ring is left to walk the list (ref_comp). */
	mutex_lock(&ctx->uring_lock);
	list_splice_init(&ctx->xdev_ext_mech_sessions, &list);
	mutex_unlock(&ctx->uring_lock);

	/* Stop them all first so their drains overlap. */
	list_for_each_entry(s, &list, ring_node)
		xdev_ext_mech_session_stop(s, 0);
	list_for_each_entry_safe(s, n, &list, ring_node) {
		list_del_init(&s->ring_node);
		xdev_ext_mech_session_destroy(s);
	}
}

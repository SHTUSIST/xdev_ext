// SPDX-License-Identifier: GPL-2.0
/*
 * Bounded interleaving check of the LIVE lifecycle/completion/core headers.
 * The kernel atomic shim yields before each acquire load, release store and CAS.
 * op explores all whole-call interleavings; access explores every schedule within
 * the configured preemption bound (not a weak-memory/LKMM proof).
 *
 * Migration reason: four states now carry consumer refs/busy tags; generation
 * advances on final release, producer publication occurs inside the completion
 * claim, and an exclusive CPU consumer republishes the same frame. No duplicate
 * implementation of those transitions appears here: all edges call production.
 * Independent ghosts check generation, reference conservation, device access,
 * metadata visibility, exactly-once callbacks, STOP admission and quarantine.
 *
 * Producer, two fan-out consumers, CPU transform, stale/duplicate/late callback,
 * and STOP actors are combined in bounded scenarios. Custody/session actors are
 * reduced call sequences, not execution of the complete io_uring worker/provider.
 * The CPU actor tests lifecycle and valid-length publication, not transform bytes.
 * See mutants.py for the preserved 13 defect classes and four added defects.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include "io_uring/xdev_ext_mech_core.h"
/* The lifecycle header is the kernel build of it, over shim/linux/atomic.h. */
#define __KERNEL__
#include "io_uring/xdev_ext_mech_lifecycle.h"
#undef __KERNEL__

#define MAX_ACTORS 4
#define MAX_TRACE 512
#define MAX_DECISIONS 4096
#define STACK_BYTES (256 * 1024)
#define HIST_LEN 7U

enum actor_kind { A_PRODUCER, A_CONSUMER, A_TRANSFORM, A_STALE, A_TEARDOWN };

enum effect { E_NONE, E_CLAIM, E_ACQUIRE, E_PUBLISH, E_PUT, E_FAIL_PUT,
	E_FAIL_PRODUCE, E_ROLLBACK, E_REPUBLISH, E_RELEASE };

enum fault {
	F_NONE,		/* the device lands the data */
	F_FAIL,		/* a definite native error: fail_produce */
	F_REFUSE,	/* submit refuses after the callback may have claimed */
	F_AMBIG,	/* an ambiguous result: the batch is sequestered */
	F_NR,
};

static const char *const fault_names[F_NR] = {
	"none", "native-error", "refused-submit", "ambiguous",
};

/* Native producer/consumer and CPU actors share the leave/late tail. */
enum {
	B_ADMIT, B_CUSTODY, B_ACQUIRE, B_SUBMIT, B_REFUSE, B_CALLBACK,
	B_PUBLISH_CQE, B_LAND, B_RELEASE, B_LEAVE, B_LATE,
};
static const char *const producer_ops[] = {
	"P.admit", "P.custody", "P.life_acquire", "P.submit",
	"P.refused_submit_cancel", "P.callback_claim", "P.callback_publish",
	"P.worker_land", "P.frame_release", "P.leave", "P.release_late",
};
static const char *const consumer_ops[] = {
	"C.admit", "C.custody", "C.life_acquire", "C.submit", "C.unused",
	"C.callback_claim", "C.callback_publish", "C.worker_land", "C.frame_release",
	"C.leave", "C.release_late",
};

enum {
	S_STALE_LIFE, S_STALE_COMPLETION, S_UNCLAIMED_PUBLISH, S_DUP_CLAIM, S_DUP_PUBLISH,
	S_LATE_CALLBACK, S_RACE_RELEASE, S_END,
};
static const char *const stale_ops[] = {
	"S.stale_life_edges", "S.stale_completion_edges", "S.publish_without_claim",
	"S.duplicate_callback_claim", "S.duplicate_callback_publish",
	"S.late_callback", "S.racing_release", "S.end",
};

enum { T_STOP, T_DECIDE, T_ACT };
static const char *const teardown_ops[] = {
	"T.stop", "T.decide_after_drain_bound", "T.release_or_quarantine",
};

/* All fields are fixed width and the structs are compared bytewise. */
struct actor {
	__u64 token;
	__u64 ticket;
	__u32 prev_phase;
	__u8 kind;
	__u8 pc;
	__u8 done;
	__u8 round;
	__u8 seq;
	__u8 deferred;
	__u8 fate;
	__u8 last;
	__u8 effect;
	__u8 completion;
	__u8 pad[2];
};

struct world {
	struct xdev_ext_mech_life life;
	struct xdev_ext_mech_completion comp[MAX_ACTORS];	/* one ticket per native stage */
	struct xdev_ext_mech_sess ss;
	struct xdev_ext_mech_quarantine q;
	__u64 last_word[MAX_ACTORS + 1]; /* previous atomic write, independent oracle */
	__u64 q_seen_objects;
	__u64 q_seen_frames;
	__u64 announced;		/* the producer's live ticket, if any */
	__u64 hist_life[4];		/* generations of a finished cycle */
	__u64 hist_ticket;		/* ticket of a finished completion */
	__u32 data_len;			/* ghost: what the last publish wrote */
	__s32 result[MAX_ACTORS];		/* ghost: what each callback published */
	__u8 fw;			/* frame custody word */
	__u8 writer;			/* ghost: actor+1 whose device may write */
	__u8 reader;			/* ghost: mask of active native consumers */
	__u8 owners;			/* winners of the live producer ticket */
	__u8 stop_called;
	__u8 release_deferred;
	__u8 released;
	__u8 quarantined;
	__u8 fw_sequestered;
	__u8 stale_op;			/* actor+1 running a stale edge */
	__u8 transformed;
	__u8 suppressed;
	__u8 pad[4];
};

struct state {
	struct world w;
	struct actor a[MAX_ACTORS];
};

struct config {
	const char *name;
	__u8 kinds[MAX_ACTORS];
	__u8 nr;
	bool custody;
	__u8 prefill; /* 0: FREE, 1: READY fan-out, 2: READY CPU input */
	enum fault fault;
	__u8 rounds;
	__u64 seed;
};

static struct state S;
static struct config cfg;
static bool access_mode;
static bool hooks_on;
static int running = -1;
static unsigned long long checks;

/*
 * Event coverage.  A run of every scenario in both modes must reach each of
 * these, or the invariants above were checked over a model that never got
 * to the case they guard.
 */
enum cov {
	COV_ADMIT_REFUSED, COV_ACQUIRE_REFUSED, COV_GEN_EXHAUSTED,
	COV_TICKET_EXHAUSTED, COV_FANOUT_OVERLAP, COV_PUBLISHED,
	COV_FAIL_PRODUCE, COV_CONSUMED, COV_SEQUESTERED, COV_CANCEL_WON,
	COV_CALLBACK_WON_CANCEL, COV_DUPLICATE_WON, COV_DUPLICATE_LOST,
	COV_RACING_RELEASE, COV_DEFERRED, COV_LATE_RELEASE, COV_RELEASED,
	COV_QUARANTINED, COV_RESUMED_INSIDE_STEP, COV_TRANSFORM,
	COV_FAIL_CONSUME, COV_DUPLICATE_PUT, COV_UNCLAIMED_REJECTED, COV_NR,
};
static const char *const cov_names[COV_NR] = {
	"admission_refused", "life_acquire_refused", "generation_exhausted",
	"ticket_exhausted", "fanout_overlap", "published", "fail_produce",
	"consumed", "sequestered", "cancel_won", "callback_won_over_cancel",
	"duplicate_callback_won", "duplicate_callback_lost", "racing_release",
	"teardown_deferred", "late_release", "released", "quarantined",
	"resumed_inside_step", "transform_republish", "failed_consumer",
	"duplicate_put_rejected", "unclaimed_publish_rejected",
};
static unsigned long long cov[COV_NR];
#define COV(e) (cov[COV_##e]++)

/* Trace of the current path, printed with a violation. */
struct trace_entry {
	__u8 actor;
	__u8 pc;
	__u8 resumed;
};
static struct trace_entry trace[MAX_TRACE];
static unsigned int trace_len;

static const char *op_name(__u8 kind, __u8 pc)
{
	switch (kind) {
	case A_PRODUCER:
		return producer_ops[pc];
	case A_CONSUMER:
	case A_TRANSFORM:
		return consumer_ops[pc];
	case A_STALE:
		return stale_ops[pc];
	default:
		return teardown_ops[pc];
	}
}

static void trace_push(int i, bool resumed)
{
	if (trace_len < MAX_TRACE) {
		trace[trace_len].actor = (__u8)i;
		trace[trace_len].pc = S.a[i].pc;
		trace[trace_len].resumed = resumed;
	}
	trace_len++;
}

static void __attribute__((noreturn, format(printf, 2, 3)))
violation(const char *inv, const char *fmt, ...)
{
	va_list ap;
	unsigned int i;

	printf("VIOLATION %s: ", inv);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n# config %s fault=%s custody=%d rounds=%u seed=%s%llu mode=%s\n",
	       cfg.name, fault_names[cfg.fault], cfg.custody, cfg.rounds,
	       cfg.seed ? "GEN_MAX-" : "",
	       (unsigned long long)(cfg.seed ? XDEV_EXT_MECH_L_GEN_MAX - cfg.seed : 0),
	       access_mode ? "access" : "op");
	printf("# trace (actor: step):\n");
	for (i = 0; i < trace_len && i < MAX_TRACE; i++)
		printf("#   %u %s%s\n", trace[i].actor,
		       op_name(S.a[trace[i].actor].kind, trace[i].pc),
		       trace[i].resumed ? " (resumed inside the step)" : "");
	printf("#   %d %s <- violation here\n", running,
	       running >= 0 ? op_name(S.a[running].kind, S.a[running].pc) : "-");
	fflush(stdout);
	exit(1);
}

#define CHECK(cond, inv, ...) do {					\
	checks++;							\
	if (!(cond))							\
		violation(inv, __VA_ARGS__);				\
} while (0)

/* ---- hooks called by shim/linux/atomic.h ---- */

static void access_yield(void);

static int watched(const volatile void *p)
{
	unsigned int i;

	if (p == &S.w.life.ctrl)
		return 0;
	for (i = 0; i < MAX_ACTORS; i++)
		if (p == &S.w.comp[i].ctrl)
			return (int)i + 1;
	return -1;
}

void life_model_before(const volatile void *p, int kind)
{
	(void)p;
	(void)kind;
	if (hooks_on && access_mode && running >= 0)
		access_yield();
}

void life_model_after(const volatile void *p, int kind, bool wrote)
{
	int idx = watched(p);
	__u64 v, old, gen, prev;
	__u32 phase, oldphase, refs, busy, owner, oldrefs;
	struct actor *a;

	(void)kind;
	if (!hooks_on || !wrote || idx < 0)
		return;
	v = __atomic_load_n((const __u64 *)p, __ATOMIC_RELAXED);
	old = S.w.last_word[idx];
	gen = v >> (idx ? 3 : XDEV_EXT_MECH_L_GEN_SHIFT);
	prev = old >> (idx ? 3 : XDEV_EXT_MECH_L_GEN_SHIFT);
	phase = v & (idx ? 7 : XDEV_EXT_MECH_L_STATE_MASK);
	CHECK(gen >= prev, "INV_GEN_MONOTONE", "word %d generation decreased", idx);
	CHECK(S.w.stale_op != running + 1, "INV_STALE_MATCH",
	      "a stale claim/ticket wrote word %d", idx);
	S.w.last_word[idx] = v;
	if (idx) {
		CHECK(phase <= XDEV_EXT_MECH_C_PUBLISHING, "INV_PHASE",
		      "completion word holds undefined phase %u", phase);
		return;
	}
	a = &S.a[running];
	oldphase = old & XDEV_EXT_MECH_L_STATE_MASK;
	refs = (v & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT;
	busy = (v & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT;
	owner = (v & XDEV_EXT_MECH_L_OWNER_MASK) >> XDEV_EXT_MECH_L_OWNER_SHIFT;
	oldrefs = (old & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT;
	CHECK(refs <= 4 && (__u32)__builtin_popcount(busy) <= refs, "INV_REFS",
	      "refs=%u busy=%u", refs, busy);
	CHECK(phase != XDEV_EXT_MECH_L_FREE || (!refs && !busy && !owner),
	      "INV_EARLY_REUSE", "FREE retains references/busy/owner");
	CHECK(phase != XDEV_EXT_MECH_L_READY || (!busy && !owner), "INV_PHASE",
	      "READY retains busy/owner");
	CHECK(phase != XDEV_EXT_MECH_L_IO_PENDING || (!busy && !refs && owner),
	      "INV_PHASE", "IO_PENDING lacks exclusive producer");
	CHECK(phase != XDEV_EXT_MECH_L_OUT_PENDING || busy, "INV_PHASE",
	      "OUT_PENDING has no active consumer");
	CHECK(phase != XDEV_EXT_MECH_L_FREE || (!S.w.writer && !S.w.reader),
	      "INV_EARLY_REUSE", "FREE while a native actor may access payload");
	if (a->effect == E_ROLLBACK) {
		CHECK(gen == prev, "INV_GEN_MONOTONE", "rollback advanced generation");
	} else if (phase == XDEV_EXT_MECH_L_FREE) {
		CHECK(oldphase != XDEV_EXT_MECH_L_FREE && gen == prev + 1,
		      "INV_GEN_MONOTONE", "final release did not increment generation");
	} else {
		CHECK(gen == prev, "INV_GEN_MONOTONE", "non-recycle changed generation");
	}
	CHECK(a->effect != E_CLAIM || prev != XDEV_EXT_MECH_L_GEN_MAX,
	      "INV_GEN_MONOTONE", "producer claimed exhausted generation");
	if (a->effect == E_PUT)
		CHECK(refs + 1 == oldrefs, "INV_REFS", "completion did not drop exactly one reference");
	if (a->effect == E_FAIL_PUT)
		CHECK(refs == (__u32)__builtin_popcount(busy), "INV_REFS",
		      "failed consumer retained dependent references");
	if (a->effect == E_PUBLISH || a->effect == E_REPUBLISH) {
		__u64 c = __atomic_load_n(&S.w.comp[a->completion].ctrl, __ATOMIC_RELAXED);

		CHECK((c & 7) == XDEV_EXT_MECH_C_PUBLISHING, "INV_COMPLETION_CLAIM",
		      "metadata published without winning completion publication claim");
	}
	if (__builtin_popcount(busy) == 2)
		COV(FANOUT_OVERLAP);
}

/* ---- the code under test, as io_uring/xdev_ext_mech.c drives it ---- */

static __u64 raw_ctrl(const __u64 *ctrl)
{
	return __atomic_load_n(ctrl, __ATOMIC_ACQUIRE);
}

static __u32 round_len(__u8 round)
{
	return 100U + 17U * round;
}

static void custody(__u8 from, __u8 to, const char *what)
{
	if (!cfg.custody)
		return;
	CHECK(!xdev_ext_mech_frame_move(&S.w.fw, from, to), "INV_CUSTODY",
	      "%s: custody %u -> %u failed (word %u)", what, from, to, S.w.fw);
}

/* xdev_ext_mech_settle_locked: a stopping session with nothing in flight. */
static void settle(void)
{
	if (S.w.ss.state == XDEV_EXT_MECH_SESSION_STOPPING && !S.w.ss.inflight)
		xdev_ext_mech_sess_drain(&S.w.ss, false);
}

static void do_release(void)
{
	CHECK(!S.w.quarantined, "INV_QUARANTINE",
	      "a quarantined session was released");
	CHECK(!S.w.writer && !S.w.reader, "INV_EARLY_REUSE",
	      "pool released while the device of actor %d may still access the frame",
	      (S.w.writer ? S.w.writer : S.w.reader) - 1);
	CHECK(!cfg.custody || (S.w.fw != XDEV_EXT_MECH_F_INFLIGHT &&
			       S.w.fw != XDEV_EXT_MECH_F_SEQUESTERED),
	      "INV_EARLY_REUSE", "pool released with frame custody %u", S.w.fw);
	CHECK(!S.w.released, "INV_TEARDOWN", "the session was released twice");
	S.w.released = 1;
	COV(RELEASED);
}

static void do_quarantine(void)
{
	CHECK(!S.w.released, "INV_TEARDOWN",
	      "a released session was quarantined too");
	xdev_ext_mech_quarantine_add(&S.w.q, 1, S.w.fw_sequestered);
	S.w.quarantined = 1;
	COV(QUARANTINED);
}

/* xdev_ext_mech_release_late, run by the batch that dropped the last ref. */
static void release_late(void)
{
	COV(LATE_RELEASE);
	if (S.w.ss.state == XDEV_EXT_MECH_SESSION_STOPPING || S.w.ss.inflight)
		S.w.ss.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
#ifdef LIFE_MODEL_MUTANT_LATE_RELEASE_ALWAYS
	do_release();
	return;
#endif
	if (xdev_ext_mech_sess_ref_fate(&S.w.ss) == XDEV_EXT_MECH_REFS_RELEASE)
		do_release();
	else
		do_quarantine();
}

static void batch_done(struct actor *a)
{
	if (a->kind == A_PRODUCER && ++a->round < cfg.rounds) {
		a->pc = B_ADMIT;
		a->seq = 0;
		return;
	}
	a->done = 1;
}

/* Callback handoff follows production split publication: only its winner can
 * mutate lifecycle or valid_len, before making LANDED visible to the worker. */
static int callback_publish(int callback, int stage, __u64 ticket, bool unclaimed)
{
	struct world *w = &S.w;
	struct actor *a = &S.a[stage], *cb = &S.a[callback];
	bool producer = a->kind == A_PRODUCER, transform = a->kind == A_TRANSFORM;
	int res = cfg.fault == F_FAIL ? -EIO : cfg.fault == F_AMBIG ? -ETIMEDOUT : 0;
	int rc;

#ifndef LIFE_MODEL_MUTANT_PUBLISH_WITHOUT_CLAIM
	(void)unclaimed;
	rc = xdev_ext_mech_completion_publish_begin(&w->comp[stage], ticket);
#else
	rc = unclaimed ? 0 : xdev_ext_mech_completion_publish_begin(&w->comp[stage], ticket);
#endif
	if (rc)
		return rc;
	cb->completion = (__u8)stage;
	if (res != -ETIMEDOUT) {
		if (producer) {
			w->writer = 0;
			cb->effect = res ? E_FAIL_PRODUCE : E_PUBLISH;
			if (!res)
				w->data_len = round_len(a->round);
			rc = res ? xdev_ext_mech_life_fail_produce(&w->life, a->token) :
				xdev_ext_mech_life_publish(&w->life, a->token, 1, w->data_len);
			CHECK(!rc, "INV_STALE_MATCH", "native producer handoff lost claim (%d)", rc);
			if (res)
				COV(FAIL_PRODUCE);
			else
				COV(PUBLISHED);
		} else {
			w->reader &= ~((__u8)1 << stage);
			cb->effect = res ? E_FAIL_PUT : transform ? E_REPUBLISH : E_PUT;
			if (res) {
				rc = xdev_ext_mech_life_fail_put(&w->life, a->token);
				w->suppressed = 1;
				COV(FAIL_CONSUME);
			} else if (transform) {
				w->data_len += 4;
				rc = xdev_ext_mech_life_republish(&w->life, a->token, 1, w->data_len);
				w->transformed = 1;
				COV(TRANSFORM);
			} else {
				rc = xdev_ext_mech_life_put(&w->life, a->token);
			}
			CHECK(rc >= 0, "INV_STALE_MATCH", "native consumer handoff lost claim (%d)", rc);
			COV(CONSUMED);
		}
		cb->effect = E_NONE;
	}
	w->result[stage] = res;
	xdev_ext_mech_completion_publish_end(&w->comp[stage], ticket, res);
	return 0;
}

static void batch_step(int i)
{
	struct actor *a = &S.a[i];
	struct world *w = &S.w;
	bool producer = a->kind == A_PRODUCER;
	bool transform = a->kind == A_TRANSFORM;
	__s32 res;
	int rc;

	switch (a->pc) {
	case B_ADMIT:
		if (xdev_ext_mech_sess_batch_begin(&w->ss)) {
			COV(ADMIT_REFUSED);
			a->done = 1;
			return;
		}
		CHECK(!w->stop_called, "INV_STOP_ADMIT", "a batch was admitted after STOP");
		a->pc = B_CUSTODY;
		return;
	case B_CUSTODY:
		CHECK(!w->released, "INV_EARLY_REUSE", "batch used released pool");
		if (cfg.custody && xdev_ext_mech_frame_move(&w->fw, XDEV_EXT_MECH_F_K_FREE,
							   XDEV_EXT_MECH_F_HELD)) {
			a->pc = B_LEAVE;
			return;
		}
		a->pc = B_ACQUIRE;
		return;
	case B_ACQUIRE:
		a->effect = producer ? E_CLAIM : E_ACQUIRE;
		if (producer)
			rc = xdev_ext_mech_life_claim(&w->life, (__u32)i, &a->token);
		else if (cfg.prefill == 2 && !transform && !w->transformed)
			rc = -EBUSY; /* descriptor dependency: CPU has not returned */
		else
			rc = xdev_ext_mech_life_acquire(&w->life, (__u32)i,
				transform ? XDEV_EXT_MECH_L_ACQ_EXCLUSIVE :
				cfg.prefill == 1 ? XDEV_EXT_MECH_L_ACQ_FANOUT : 0, &a->token);
		a->effect = E_NONE;
		if (rc) {
			CHECK(rc == -EBUSY || rc == -EOVERFLOW || rc == -ENOENT,
			      "INV_PHASE", "life acquire returned %d", rc);
			if (rc == -EOVERFLOW)
				COV(GEN_EXHAUSTED);
			else
				COV(ACQUIRE_REFUSED);
			custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE, "refused acquire");
			a->pc = B_LEAVE;
			return;
		}
		CHECK(!w->writer && (!(producer || transform) || !w->reader),
		      "INV_EARLY_REUSE", "exclusive actor acquired active payload");
		if (producer)
			w->writer = (__u8)(i + 1);
		else {
			CHECK(!w->suppressed, "INV_REFS", "dependent consumer admitted after failure");
			w->reader |= (__u8)1 << i;
			CHECK(w->life.valid_len == w->data_len, "INV_STALE_MATCH",
			      "consumer metadata %u differs from published %u", w->life.valid_len, w->data_len);
		}
		a->pc = B_SUBMIT;
		return;
	case B_SUBMIT:
		custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_INFLIGHT, "submit");
		rc = xdev_ext_mech_completion_begin(&w->comp[i], &a->ticket);
		if (rc) {
			CHECK(rc == -EOVERFLOW, "INV_PHASE", "completion_begin returned %d", rc);
			COV(TICKET_EXHAUSTED);
			if (producer)
				w->writer = 0;
			else
				w->reader &= ~((__u8)1 << i);
			a->effect = E_ROLLBACK;
			CHECK(!xdev_ext_mech_life_rollback(&w->life, a->token),
			      "INV_STALE_MATCH", "own rollback failed");
			a->effect = E_NONE;
			custody(XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD, "undo submit");
			custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE, "undo submit");
			a->pc = B_LEAVE;
			return;
		}
		if (producer) {
			w->announced = a->ticket;
			w->owners = 0;
		}
		a->pc = producer && cfg.fault == F_REFUSE ? B_REFUSE : B_CALLBACK;
		return;
	case B_REFUSE:
		if (xdev_ext_mech_completion_cancel(&w->comp[i], a->ticket)) {
			COV(CALLBACK_WON_CANCEL);
			a->pc = B_LAND;
			return;
		}
		COV(CANCEL_WON);
		CHECK(++w->owners == 1, "INV_STALE_MATCH", "ticket both claimed and cancelled");
		w->writer = 0;
		a->effect = E_ROLLBACK;
		CHECK(!xdev_ext_mech_life_rollback(&w->life, a->token),
		      "INV_STALE_MATCH", "rollback after refused submit failed");
		a->effect = E_NONE;
		w->announced = 0;
		custody(XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD, "refused submit");
		custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE, "refused submit");
		a->pc = B_LEAVE;
		return;
	case B_CALLBACK:
		if (xdev_ext_mech_completion_claim(&w->comp[i], a->ticket)) {
			CHECK(producer, "INV_STALE_MATCH", "only callback lost claim");
			a->pc = B_LAND;
			return;
		}
		if (producer)
			CHECK(++w->owners == 1, "INV_STALE_MATCH", "ticket claimed twice");
		a->pc = B_PUBLISH_CQE;
		return;
	case B_PUBLISH_CQE:
		CHECK(!callback_publish(i, i, a->ticket, false), "INV_STALE_MATCH",
		      "callback could not publish claimed completion");
		a->pc = B_LAND;
		return;
	case B_LAND:
		res = 1;
		CHECK(!xdev_ext_mech_completion_consume(&w->comp[i], a->ticket, &res),
		      "INV_STALE_MATCH", "worker could not consume landed ticket");
		CHECK(res == w->result[i], "INV_STALE_MATCH", "worker read unpublished result");
		if (producer)
			w->announced = 0;
		if (res == -ETIMEDOUT) {
			custody(XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_SEQUESTERED, "sequester");
			w->fw_sequestered = 1;
			a->seq = 1;
			COV(SEQUESTERED);
			a->pc = B_LEAVE;
			return;
		}
		custody(XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD, "landing");
		/* The worker never publishes/releases a native completion's lifecycle. */
		a->pc = B_RELEASE;
		return;
	case B_RELEASE:
		if (!producer && !transform) {
			w->stale_op = (__u8)(i + 1);
			CHECK(xdev_ext_mech_life_put(&w->life, a->token) == -ESTALE,
			      "INV_STALE_MATCH", "duplicate consumer decrement accepted");
			w->stale_op = 0;
			COV(DUPLICATE_PUT);
		}
		if (producer && cfg.custody &&
		    xdev_ext_mech_life_phase(&w->life) == XDEV_EXT_MECH_L_READY) {
			/* Unused READY publication at batch end; no reader owns it. */
			a->effect = E_RELEASE;
			CHECK(!xdev_ext_mech_life_release(&w->life, xdev_ext_mech_life_gen(&w->life)),
			      "INV_STALE_MATCH", "unused publication release failed");
			a->effect = E_NONE;
		}
		custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE, "release");
		a->pc = B_LEAVE;
		return;
	case B_LEAVE: {
		bool last = xdev_ext_mech_sess_batch_end(&w->ss, a->seq);

		settle();
#ifdef LIFE_MODEL_MUTANT_REAP_RELEASES
		if (last && w->quarantined)
			do_release();
#endif
		if (last && w->release_deferred) {
			a->pc = B_LATE;
			return;
		}
		batch_done(a);
		return;
	}
	case B_LATE:
		release_late();
		a->done = 1;
		return;
	}
}

static void stale_step(int i)
{
	struct actor *a = &S.a[i];
	struct world *w = &S.w;
	__u64 k = w->hist_ticket;
	__u32 len = w->life.valid_len;
	unsigned int j;
	int r = 0;

	switch (a->pc) {
	case S_STALE_LIFE:
		w->stale_op = (__u8)(i + 1);
		for (j = 0; j < 4; j++) {
			__u64 t = w->hist_life[j];

			CHECK(xdev_ext_mech_life_publish(&w->life, t, 1, 999) &&
			      xdev_ext_mech_life_republish(&w->life, t, 1, 999) &&
			      xdev_ext_mech_life_fail_produce(&w->life, t) &&
			      xdev_ext_mech_life_put(&w->life, t) < 0 &&
			      xdev_ext_mech_life_fail_put(&w->life, t) < 0 &&
			      xdev_ext_mech_life_rollback(&w->life, t) &&
			      xdev_ext_mech_life_release(&w->life, xdev_ext_mech_life_claim_gen(t)),
			      "INV_STALE_MATCH", "old claim won lifecycle edge");
		}
		CHECK(access_mode || w->life.valid_len == len, "INV_STALE_MATCH", "stale metadata write");
		w->stale_op = 0;
		a->pc = S_STALE_COMPLETION;
		return;
	case S_STALE_COMPLETION:
		w->stale_op = (__u8)(i + 1);
		CHECK(xdev_ext_mech_completion_claim(&w->comp[0], k) &&
		      xdev_ext_mech_completion_publish(&w->comp[0], k, -EIO) &&
		      xdev_ext_mech_completion_consume(&w->comp[0], k, &r) &&
		      xdev_ext_mech_completion_cancel(&w->comp[0], k),
		      "INV_STALE_MATCH", "old completion ticket won edge");
		w->stale_op = 0;
		a->pc = S_UNCLAIMED_PUBLISH;
		return;
	case S_UNCLAIMED_PUBLISH:
		/* This deliberately invalid caller is checked only at op granularity:
		 * if preempted, a legitimate callback could claim the same ticket
		 * before publish_begin, so the probe would steal its publication. */
		k = w->announced;
		if (!access_mode && k &&
		    (raw_ctrl(&w->comp[0].ctrl) & 7) == XDEV_EXT_MECH_C_SUBMITTED) {
			CHECK(callback_publish(i, 0, k, true), "INV_COMPLETION_CLAIM",
			      "publication succeeded without callback claim");
			COV(UNCLAIMED_REJECTED);
		}
		a->pc = S_DUP_CLAIM;
		return;
	case S_DUP_CLAIM:
		a->ticket = w->announced;
		if (a->ticket && !xdev_ext_mech_completion_claim(&w->comp[0], a->ticket)) {
			CHECK(++w->owners == 1, "INV_STALE_MATCH", "ticket owned twice");
			COV(DUPLICATE_WON);
			a->pc = S_DUP_PUBLISH;
			return;
		}
		if (a->ticket)
			COV(DUPLICATE_LOST);
		a->pc = S_LATE_CALLBACK;
		return;
	case S_DUP_PUBLISH:
		CHECK(!callback_publish(i, 0, a->ticket, false), "INV_STALE_MATCH",
		      "winning duplicate failed to publish");
		a->pc = S_LATE_CALLBACK;
		return;
	case S_LATE_CALLBACK:
		if (a->ticket) {
			w->stale_op = (__u8)(i + 1);
			CHECK(xdev_ext_mech_completion_claim(&w->comp[0], a->ticket),
			      "INV_STALE_MATCH", "late callback claimed ticket twice");
			w->stale_op = 0;
		}
		a->pc = cfg.custody ? S_END : S_RACE_RELEASE;
		if (a->pc == S_END)
			a->done = 1;
		return;
	case S_RACE_RELEASE:
		a->effect = E_RELEASE;
		if (!xdev_ext_mech_life_release(&w->life, xdev_ext_mech_life_gen(&w->life))) {
			CHECK(!w->writer && !w->reader, "INV_EARLY_REUSE", "release raced native access");
			COV(RACING_RELEASE);
		}
		a->effect = E_NONE;
		a->pc = S_END;
		a->done = 1;
		return;
	}
}

static void teardown_step(int i)
{
	struct actor *a = &S.a[i];
	struct world *w = &S.w;

	switch (a->pc) {
	case T_STOP:
		/* xdev_ext_mech_session_stop */
		xdev_ext_mech_sess_stop(&w->ss);
		w->stop_called = 1;
		settle();
		a->pc = T_DECIDE;
		return;
	case T_DECIDE:
		/* xdev_ext_mech_session_destroy after wait_event_timeout */
		if (w->ss.state == XDEV_EXT_MECH_SESSION_STOPPING && w->ss.inflight &&
		    !w->ss.sequestered) {
			w->release_deferred = 1;
			COV(DEFERRED);
			a->deferred = 1;
		} else if (w->ss.state == XDEV_EXT_MECH_SESSION_STOPPING) {
			xdev_ext_mech_sess_drain(&w->ss, true);
		}
		a->fate = (__u8)xdev_ext_mech_sess_ref_fate(&w->ss);
		a->last = xdev_ext_mech_sess_put(&w->ss);
		a->pc = T_ACT;
		return;
	case T_ACT:
#ifdef LIFE_MODEL_MUTANT_DESTROY_IGNORES_INFLIGHT
		if (a->fate != XDEV_EXT_MECH_REFS_QUARANTINE)
			do_release();
		else
			do_quarantine();
#else
		if (!a->deferred) {
			if (a->fate != XDEV_EXT_MECH_REFS_RELEASE || !a->last)
				do_quarantine();
			else
				do_release();
		}
#endif
		a->done = 1;
		return;
	}
}

static bool enabled(int i)
{
	const struct actor *a = &S.a[i];
	int c;

	if (a->done)
		return false;
	if ((a->kind == A_PRODUCER || a->kind == A_CONSUMER ||
	     a->kind == A_TRANSFORM) && a->pc == B_LAND) {
		c = i;
		return (raw_ctrl(&S.w.comp[c].ctrl) & 7) == XDEV_EXT_MECH_C_LANDED;
	}
	return true;
}

static void step(int i)
{
	if (i < 0 || i >= MAX_ACTORS)
		abort();
	switch (S.a[i].kind) {
	case A_PRODUCER:
	case A_CONSUMER:
	case A_TRANSFORM:
		batch_step(i);
		break;
	case A_STALE:
		stale_step(i);
		break;
	default:
		teardown_step(i);
		break;
	}
}

/* Checked in every state of every path. */
static void check_state(void)
{
	const struct world *w = &S.w;

	CHECK(w->q.objects >= w->q_seen_objects && w->q.frames >= w->q_seen_frames,
	      "INV_QUARANTINE", "a quarantine counter decreased");
	S.w.q_seen_objects = w->q.objects;
	S.w.q_seen_frames = w->q.frames;
	CHECK(!(w->quarantined && w->released), "INV_QUARANTINE",
	      "a quarantined session was reclaimed");
	CHECK(!cfg.custody || !w->fw_sequestered || w->fw == XDEV_EXT_MECH_F_SEQUESTERED,
	      "INV_QUARANTINE", "a sequestered frame left SEQUESTERED (word %u)", w->fw);
	CHECK(!w->stop_called || w->ss.state != XDEV_EXT_MECH_SESSION_ACTIVE,
	      "INV_STOP_ADMIT", "the session admits again after STOP");
}

static bool has_kind(__u8 kind)
{
	unsigned int i;

	for (i = 0; i < cfg.nr; i++)
		if (cfg.kinds[i] == kind)
			return true;
	return false;
}

/* Checked once in every final state. */
static void check_final(void)
{
	const struct world *w = &S.w;

	if (has_kind(A_TEARDOWN)) {
		CHECK(w->released + w->quarantined == 1, "INV_TEARDOWN",
		      "teardown ended with released=%u quarantined=%u (state %u, refs %u, inflight %u)",
		      w->released, w->quarantined, w->ss.state, w->ss.refs,
		      w->ss.inflight);
		CHECK(!(w->fw_sequestered || w->writer || w->reader) || w->quarantined,
		      "INV_QUARANTINE",
		      "a frame a device may still access was not quarantined");
	} else {
		CHECK(!w->ss.inflight && w->ss.refs == 1, "INV_TEARDOWN",
		      "batches left inflight=%u refs=%u", w->ss.inflight, w->ss.refs);
	}
}

/* Independent initial fixtures model an already recycled historical version. */
static void init_state(void)
{
	struct world *w = &S.w;
	__u64 ticket;
	int res = 1;
	unsigned int i;

	memset(&S, 0, sizeof(S));
	hooks_on = false;
	xdev_ext_mech_life_init(&w->life);
	/* Fixture starts immediately after one completed generation. Historical
	 * tokens are independently encoded from the public layout, not obtained
	 * through a possibly mutated edge during uninstrumented initialization. */
	w->life.ctrl = (cfg.seed + 1) << XDEV_EXT_MECH_L_GEN_SHIFT;
	w->hist_life[0] = (cfg.seed << 12) | (1ULL << 9) | 1;
	w->hist_life[1] = (cfg.seed << 12) | (1ULL << 9) | 3;
	w->hist_life[2] = (cfg.seed << 12) | (1ULL << 9) | 2;
	w->hist_life[3] = (cfg.seed << 12) | (2ULL << 9) | 2;
	if (cfg.prefill) {
		/* A published input fixture for the fan-out/CPU actors; publication
		 * itself is checked in the producer scenarios with hooks enabled. */
		w->life.ctrl |= XDEV_EXT_MECH_L_READY |
			((__u64)(cfg.prefill == 1 ? 2 : 1) << XDEV_EXT_MECH_L_REFS_SHIFT);
		w->life.valid_len = HIST_LEN;
	}
	w->data_len = HIST_LEN;
	for (i = 0; i < MAX_ACTORS; i++) {
		xdev_ext_mech_completion_init(&w->comp[i]);
		/* Completion tickets have their own 61-bit exhaustion boundary. */
		ticket = cfg.seed ? XDEV_EXT_MECH_C_GEN_MAX -
			(XDEV_EXT_MECH_L_GEN_MAX - cfg.seed) : 0;
		w->comp[i].ctrl = ticket << 3;
		if (xdev_ext_mech_completion_begin(&w->comp[i], &ticket) ||
		    xdev_ext_mech_completion_claim(&w->comp[i], ticket) ||
		    xdev_ext_mech_completion_publish(&w->comp[i], ticket, 0) ||
		    xdev_ext_mech_completion_consume(&w->comp[i], ticket, &res))
			abort();
		if (!i)
			w->hist_ticket = ticket;
		w->last_word[i + 1] = w->comp[i].ctrl;
	}
	w->last_word[0] = w->life.ctrl;
	xdev_ext_mech_sess_init(&w->ss);
	w->fw = XDEV_EXT_MECH_F_K_FREE;
	for (i = 0; i < cfg.nr; i++)
		S.a[i].kind = cfg.kinds[i];
	hooks_on = true;
}

/* ---- op granularity: exhaustive stateful search ---- */

struct visited {
	struct state *slot;
	unsigned char *used;
	size_t cap;
	size_t n;
};
static struct visited seen;

static uint64_t state_hash(const struct state *s)
{
	const unsigned char *p = (const unsigned char *)s;
	uint64_t h = 1469598103934665603ULL;
	size_t i;

	for (i = 0; i < sizeof(*s); i++)
		h = (h ^ p[i]) * 1099511628211ULL;
	return h;
}

static bool visit(const struct state *s);

static void seen_grow(void)
{
	struct visited old = seen;
	size_t i;

	seen.cap = old.cap ? old.cap * 2 : 1U << 14;
	seen.n = 0;
	seen.slot = calloc(seen.cap, sizeof(*seen.slot));
	seen.used = calloc(seen.cap, 1);
	if (!seen.slot || !seen.used) {
		fprintf(stderr, "out of memory for %zu states\n", seen.cap);
		exit(2);
	}
	for (i = 0; i < old.cap; i++)
		if (old.used[i])
			visit(&old.slot[i]);
	free(old.slot);
	free(old.used);
}

/* True when @s is new. */
static bool visit(const struct state *s)
{
	size_t idx;

	if ((seen.n + 1) * 2 > seen.cap)
		seen_grow();
	idx = state_hash(s) & (seen.cap - 1);
	while (seen.used[idx]) {
		if (!memcmp(&seen.slot[idx], s, sizeof(*s)))
			return false;
		idx = (idx + 1) & (seen.cap - 1);
	}
	memcpy(&seen.slot[idx], s, sizeof(*s));
	seen.used[idx] = 1;
	seen.n++;
	return true;
}

static unsigned long long transitions, finals;

static void dfs(unsigned int depth)
{
	struct state save;
	bool moved = false, all_done = true;
	int i;

	if (!visit(&S))
		return;
	check_state();
	for (i = 0; i < cfg.nr; i++) {
		if (!S.a[i].done)
			all_done = false;
		if (!enabled(i))
			continue;
		memcpy(&save, &S, sizeof(save));
		trace_len = depth;
		trace_push(i, false);
		running = i;
		step(i);
		running = -1;
		transitions++;
		moved = true;
		dfs(depth + 1);
		memcpy(&S, &save, sizeof(S));
	}
	trace_len = depth;
	if (!moved) {
		CHECK(all_done, "INV_DEADLOCK", "no actor can move");
		finals++;
		check_final();
	}
}

/* ---- access granularity: bounded-preemption stateless search ---- */

struct decision {
	__u8 n;
	__u8 chosen;
	__u8 cur_first;
	__u8 preempt_before;
};

static ucontext_t sched_uc, actor_uc[MAX_ACTORS];
static char *stacks[MAX_ACTORS];
static __u8 in_step[MAX_ACTORS];
static __u8 started[MAX_ACTORS];
static struct decision dec[MAX_DECISIONS];
static __u8 prefix[MAX_DECISIONS];
static unsigned int prefix_len, ndec;
static unsigned int preempt_bound = 2;
static unsigned long long runs;

static void access_yield(void)
{
	int i = running;

	in_step[i] = 1;
	swapcontext(&actor_uc[i], &sched_uc);
	in_step[i] = 0;
}

static void actor_main(int i)
{
	for (;;) {
		trace_push(i, false);
		step(i);
		check_state();
		if (S.a[i].done)
			break;
		/* A step boundary is a scheduling point too. */
		swapcontext(&actor_uc[i], &sched_uc);
	}
	running = -1;
}

static void actor_entry(unsigned int i)
{
	actor_main((int)i);
}

/* Replays prefix[], then always takes the first candidate (no preemption). */
static void run_once(void)
{
	/* Static: swapcontext returns here like setjmp does. */
	static int current, cand[MAX_ACTORS];
	static unsigned int preempt, n, c, i;

	current = -1;
	preempt = 0;
	init_state();
	trace_len = 0;
	ndec = 0;
	memset(in_step, 0, sizeof(in_step));
	memset(started, 0, sizeof(started));
	for (;;) {
		n = 0;
		if (current >= 0 && !S.a[current].done &&
		    (in_step[current] || enabled(current)))
			cand[n++] = current;
		for (i = 0; i < cfg.nr; i++)
			if ((int)i != current && !S.a[i].done && (in_step[i] || enabled((int)i)))
				cand[n++] = (int)i;
		if (!n) {
			bool all_done = true;

			for (i = 0; i < cfg.nr; i++)
				if (!S.a[i].done)
					all_done = false;
			running = -1;
			CHECK(all_done, "INV_DEADLOCK", "no actor can move");
			check_final();
			finals++;
			return;
		}
		if (ndec >= MAX_DECISIONS) {
			fprintf(stderr, "schedule longer than %u decisions\n", MAX_DECISIONS);
			exit(2);
		}
		c = ndec < prefix_len ? prefix[ndec] : 0;
		dec[ndec].n = (__u8)n;
		dec[ndec].chosen = (__u8)c;
		dec[ndec].cur_first = cand[0] == current;
		dec[ndec].preempt_before = (__u8)preempt;
		ndec++;
		if (dec[ndec - 1].cur_first && c)
			preempt++;
		i = (unsigned int)cand[c];
		if ((int)i != current && in_step[i]) {
			trace_push((int)i, true);
			COV(RESUMED_INSIDE_STEP);
		}
		current = (int)i;
		if (!started[i]) {
			started[i] = 1;
			getcontext(&actor_uc[i]);
			actor_uc[i].uc_stack.ss_sp = stacks[i];
			actor_uc[i].uc_stack.ss_size = STACK_BYTES;
			actor_uc[i].uc_link = &sched_uc;
			makecontext(&actor_uc[i], (void (*)(void))actor_entry, 1, i);
		}
		running = current;
		swapcontext(&sched_uc, &actor_uc[i]);
		running = -1;
	}
}

static bool next_prefix(void)
{
	int d;

	for (d = (int)ndec - 1; d >= 0; d--) {
		unsigned int alt = dec[d].chosen + 1U;
		unsigned int cost = dec[d].preempt_before + (dec[d].cur_first ? 1U : 0U);

		if (alt >= dec[d].n || cost > preempt_bound)
			continue;
		for (unsigned int k = 0; k < (unsigned int)d; k++)
			prefix[k] = dec[k].chosen;
		prefix[d] = (__u8)alt;
		prefix_len = (unsigned int)d + 1;
		return true;
	}
	return false;
}

/* ---- driver ---- */

struct scenario {
	const char *name;
	__u8 kinds[MAX_ACTORS];
	__u8 nr;
	__u8 prefill;
	bool custody;
	unsigned int faults;	/* bit per enum fault */
};

#define FB(f) (1U << (f))
static const struct scenario scenarios[] = {
	{ "producer+consumer", { A_PRODUCER, A_CONSUMER }, 2, 0, true,
	  FB(F_NONE) | FB(F_FAIL) },
	{ "producer+stale", { A_PRODUCER, A_STALE }, 2, 0, true,
	  FB(F_NONE) | FB(F_FAIL) | FB(F_REFUSE) | FB(F_AMBIG) },
	{ "producer+teardown", { A_PRODUCER, A_TEARDOWN }, 2, 0, true,
	  FB(F_NONE) | FB(F_FAIL) | FB(F_REFUSE) | FB(F_AMBIG) },
	{ "producer+consumer+stale", { A_PRODUCER, A_CONSUMER, A_STALE }, 3, 0, true,
	  FB(F_NONE) | FB(F_REFUSE) | FB(F_AMBIG) },
	{ "producer+consumer+teardown", { A_PRODUCER, A_CONSUMER, A_TEARDOWN }, 3, 0, true,
	  FB(F_NONE) | FB(F_FAIL) | FB(F_AMBIG) },
	{ "producer+stale+teardown", { A_PRODUCER, A_STALE, A_TEARDOWN }, 3, 0, true,
	  FB(F_NONE) | FB(F_REFUSE) | FB(F_AMBIG) },
	{ "lifecycle-only producer+consumer+stale", { A_PRODUCER, A_CONSUMER, A_STALE },
	  3, 0, false, FB(F_NONE) | FB(F_FAIL) },
	{ "fanout+stale", { A_CONSUMER, A_CONSUMER, A_STALE }, 3, 1, false,
	  FB(F_NONE) | FB(F_FAIL) },
	{ "fanout+teardown", { A_CONSUMER, A_CONSUMER, A_TEARDOWN }, 3, 1, false,
	  FB(F_NONE) | FB(F_FAIL) | FB(F_AMBIG) },
	{ "transform+consumer+stale", { A_TRANSFORM, A_CONSUMER, A_STALE }, 3, 2, false,
	  FB(F_NONE) | FB(F_FAIL) },
	{ "transform+stale+teardown", { A_TRANSFORM, A_STALE, A_TEARDOWN }, 3, 2, false,
	  FB(F_NONE) | FB(F_FAIL) | FB(F_AMBIG) },
};

/* Separate lifecycle (52-bit) and completion (61-bit) maximum seeds. */
static const __u64 seed_gap[] = { 0, 4, 3, 2 };

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [--mode op|access|both] [--preemptions N] [--rounds N]\n"
		"          [--access-rounds N] [--scenario SUBSTRING]\n", prog);
	exit(2);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "mode", required_argument, NULL, 'm' },
		{ "preemptions", required_argument, NULL, 'p' },
		{ "rounds", required_argument, NULL, 'r' },
		{ "access-rounds", required_argument, NULL, 'a' },
		{ "scenario", required_argument, NULL, 's' },
		{ NULL, 0, NULL, 0 },
	};
	bool do_op = true, do_access = true;
	unsigned int op_rounds = 2, access_rounds = 1, sc, f, sd, i, n = 0;
	unsigned long long op_states = 0, op_trans = 0, op_finals = 0;
	unsigned long long ac_runs = 0, ac_finals = 0;
	const char *filter = NULL;
	int opt;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (opt) {
		case 'm':
			do_op = !strcmp(optarg, "op") || !strcmp(optarg, "both");
			do_access = !strcmp(optarg, "access") || !strcmp(optarg, "both");
			if (!do_op && !do_access)
				usage(argv[0]);
			break;
		case 'p':
			preempt_bound = (unsigned int)strtoul(optarg, NULL, 0);
			break;
		case 'r':
			op_rounds = (unsigned int)strtoul(optarg, NULL, 0);
			break;
		case 'a':
			access_rounds = (unsigned int)strtoul(optarg, NULL, 0);
			break;
		case 's':
			filter = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}
	if (!op_rounds || op_rounds > 8 || !access_rounds || access_rounds > 8)
		usage(argv[0]);
	for (i = 0; i < MAX_ACTORS; i++) {
		stacks[i] = malloc(STACK_BYTES);
		if (!stacks[i])
			return 2;
	}

	printf("TAP version 13\n");
	for (sc = 0; sc < sizeof(scenarios) / sizeof(scenarios[0]); sc++) {
		const struct scenario *s = &scenarios[sc];

		if (filter && !strstr(s->name, filter))
			continue;
		for (f = 0; f < F_NR; f++) {
			if (!(s->faults & FB(f)))
				continue;
			for (sd = 0; sd < sizeof(seed_gap) / sizeof(seed_gap[0]); sd++) {
				unsigned long long st = 0, tr = 0, fi = 0, ru = 0, af = 0;

				cfg.name = s->name;
				memcpy(cfg.kinds, s->kinds, sizeof(cfg.kinds));
				cfg.nr = s->nr;
				cfg.custody = s->custody;
				cfg.prefill = s->prefill;
				cfg.fault = (enum fault)f;
				cfg.seed = seed_gap[sd] ? XDEV_EXT_MECH_L_GEN_MAX - seed_gap[sd] : 0;
				if (do_op) {
					access_mode = false;
					cfg.rounds = (__u8)op_rounds;
					free(seen.slot);
					free(seen.used);
					memset(&seen, 0, sizeof(seen));
					transitions = finals = 0;
					init_state();
					trace_len = 0;
					dfs(0);
					st = seen.n;
					tr = transitions;
					fi = finals;
				}
				/* Every selected seed is explored in both granularities. */
				if (do_access) {
					access_mode = true;
					cfg.rounds = (__u8)access_rounds;
					runs = finals = 0;
					prefix_len = 0;
					do {
						run_once();
						runs++;
					} while (next_prefix());
					ru = runs;
					af = finals;
					access_mode = false;
				}
				op_states += st;
				op_trans += tr;
				op_finals += fi;
				ac_runs += ru;
				ac_finals += af;
				printf("ok %u - %s fault=%s seed=%s%llu op_states=%llu op_transitions=%llu op_final_states=%llu access_runs=%llu access_final_states=%llu\n",
				       ++n, s->name, fault_names[f],
				       seed_gap[sd] ? "GEN_MAX-" : "",
				       (unsigned long long)seed_gap[sd], st, tr, fi, ru, af);
			}
		}
	}
	if (!n) {
		fprintf(stderr, "no scenario matches\n");
		return 2;
	}
	printf("1..%u\n", n);
	printf("# explored: op states %llu, op transitions %llu, op final states %llu; access runs %llu (preemption bound %u), access final states %llu\n",
	       op_states, op_trans, op_finals, ac_runs, preempt_bound, ac_finals);
	printf("# invariant checks %llu, violations 0\n", checks);
	printf("# coverage:");
	for (i = 0; i < COV_NR; i++)
		printf(" %s=%llu", cov_names[i], cov[i]);
	printf("\n");
	/* The full set must reach every event; a filtered run need not. */
	if (!filter && do_op && do_access) {
		for (i = 0; i < COV_NR; i++)
			if (!cov[i]) {
				printf("VACUOUS %s: no explored path reached this event\n",
				       cov_names[i]);
				return 1;
			}
	}
	return 0;
}

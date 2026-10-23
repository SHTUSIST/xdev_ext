// SPDX-License-Identifier: GPL-2.0
/*
 * Bounded model checker for one frame's lifecycle word, its batches' native
 * completion words and the session's STOP, drain and quarantine rules.
 *
 * The code under test is compiled in, not restated: the frame lifecycle and
 * completion words come from io_uring/xdev_ext_mech_lifecycle.h, built with
 * its __KERNEL__ primitives (smp_load_acquire, smp_store_release,
 * try_cmpxchg) supplied by shim/linux/atomic.h; frame custody, session
 * admission, drain, reference fate and the quarantine counters come from
 * io_uring/xdev_ext_mech_core.h.  The actors below are the call sequences of
 * io_uring/xdev_ext_mech.c that drive those words, one header call (or one
 * section the kernel runs under s->lock) per step:
 *
 *   producer   admission, custody, life acquire (xdev_ext_mech_life_acquire),
 *              submit (completion_begin, optionally a refused submit that
 *              races the callback through completion_cancel), the native
 *              callback (claim, publish), the worker landing
 *              (completion_consume, life publish or fail_produce, or
 *              sequester on an ambiguous result), frame release and the
 *              session leave/settle, plus xdev_ext_mech_release_late when it
 *              drops the last reference of a deferred teardown;
 *   consumer   the same for a batch that reads the READY frame
 *              (begin_consume / complete_consume / release);
 *   stale      old generations and old tickets replayed against every
 *              lifecycle and completion edge, a duplicate callback for the
 *              live ticket, a late callback after it landed, and (lifecycle
 *              only) a racing release of the READY frame;
 *   teardown   xdev_ext_mech_session_destroy: STOP, then the decision after
 *              the drain bound (defer to the last batch, drain, or keep
 *              waiting), then release or quarantine.
 *
 * Two explorations run per configuration:
 *
 *   op      every interleaving of whole steps, exhaustively, as a depth-first
 *           search over complete states (frame words, session, ghosts and
 *           every actor's program counter and locals) with a visited set;
 *   access  every interleaving that preempts at most --preemptions times at
 *           any atomic access inside the header functions (each actor runs on
 *           its own ucontext stack; the shims yield before every access), as
 *           a stateless search that replays schedule prefixes.
 *
 * Invariants (a violation prints VIOLATION <name> and a trace, exit 1):
 *
 *   INV_EARLY_REUSE   a frame is acquired while another batch's device may
 *                     still write or read it, or the pool is released while a
 *                     device may still access it, or a batch touches a frame
 *                     of a released pool;
 *   INV_STALE_MATCH   an old generation or ticket changes a word or wins an
 *                     edge, a ticket is owned twice (claim/claim or
 *                     claim/cancel), or a batch reads metadata or a result
 *                     that was not published for what it acquired;
 *   INV_GEN_MONOTONE  a generation or ticket field decreases on any write,
 *                     which is how a wrap past XDEV_EXT_MECH_L_GEN_MAX shows;
 *   INV_PHASE         a word holds a phase its header does not define;
 *   INV_QUARANTINE    a quarantine counter decreases, a quarantined session
 *                     is released, or a sequestered frame leaves SEQUESTERED;
 *   INV_STOP_ADMIT    a batch is admitted after STOP;
 *   INV_TEARDOWN      at the end of a teardown run the session was neither
 *                     released nor quarantined, or was both;
 *   INV_CUSTODY       a custody edge the protocol needs fails;
 *   INV_DEADLOCK      no actor can move while some have not finished.
 *
 * Generation seeds start every word at 0 or a few generations below
 * XDEV_EXT_MECH_L_GEN_MAX, so acquisition refusal at the last generation,
 * and the absence of a wrap, are explored together with the races.
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

#define MAX_ACTORS 3
#define MAX_TRACE 512
#define MAX_DECISIONS 4096
#define STACK_BYTES (256 * 1024)
#define HIST_LEN 7U

enum actor_kind { A_PRODUCER, A_CONSUMER, A_STALE, A_TEARDOWN };

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

/* Producer and consumer program counters share the leave/late tail. */
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
	"C.callback", "C.unused", "C.worker_land", "C.frame_release",
	"C.leave", "C.release_late",
};

enum {
	S_STALE_LIFE, S_STALE_COMPLETION, S_DUP_CLAIM, S_DUP_PUBLISH,
	S_LATE_CALLBACK, S_RACE_RELEASE, S_END,
};
static const char *const stale_ops[] = {
	"S.stale_life_edges", "S.stale_completion_edges",
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
	__u8 pad[4];
};

struct world {
	struct xdev_ext_mech_life life;
	struct xdev_ext_mech_completion comp[2];	/* producer, consumer */
	struct xdev_ext_mech_sess ss;
	struct xdev_ext_mech_quarantine q;
	__u64 last_gen[3];		/* life, comp[0], comp[1] */
	__u64 q_seen_objects;
	__u64 q_seen_frames;
	__u64 announced;		/* the producer's live ticket, if any */
	__u64 hist_life[2];		/* generations of a finished cycle */
	__u64 hist_ticket;		/* ticket of a finished completion */
	__u32 data_len;			/* ghost: what the last publish wrote */
	__s32 result[2];		/* ghost: what each callback published */
	__u8 fw;			/* frame custody word */
	__u8 writer;			/* ghost: actor+1 whose device may write */
	__u8 reader;			/* ghost: actor+1 whose device may read */
	__u8 owners;			/* winners of the live producer ticket */
	__u8 stop_called;
	__u8 release_deferred;
	__u8 released;
	__u8 quarantined;
	__u8 fw_sequestered;
	__u8 stale_op;			/* actor+1 running a stale edge */
	__u8 pad[6];
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
	COV_TICKET_EXHAUSTED, COV_OVERWRITE_READY, COV_PUBLISHED,
	COV_FAIL_PRODUCE, COV_CONSUMED, COV_SEQUESTERED, COV_CANCEL_WON,
	COV_CALLBACK_WON_CANCEL, COV_DUPLICATE_WON, COV_DUPLICATE_LOST,
	COV_RACING_RELEASE, COV_DEFERRED, COV_LATE_RELEASE, COV_RELEASED,
	COV_QUARANTINED, COV_RESUMED_INSIDE_STEP, COV_NR,
};
static const char *const cov_names[COV_NR] = {
	"admission_refused", "life_acquire_refused", "generation_exhausted",
	"ticket_exhausted", "overwrite_ready", "published", "fail_produce",
	"consumed", "sequestered", "cancel_won", "callback_won_over_cancel",
	"duplicate_callback_won", "duplicate_callback_lost", "racing_release",
	"teardown_deferred", "late_release", "released", "quarantined",
	"resumed_inside_step",
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
	if (p == &S.w.life.ctrl)
		return 0;
	if (p == &S.w.comp[0].ctrl)
		return 1;
	if (p == &S.w.comp[1].ctrl)
		return 2;
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
	static const char *const word[] = { "life", "producer completion",
					    "consumer completion" };
	int idx = watched(p);
	__u64 v, gen;
	__u32 phase;

	(void)kind;
	if (!hooks_on || !wrote || idx < 0)
		return;
	v = __atomic_load_n((const __u64 *)p, __ATOMIC_RELAXED);
	gen = v >> 3;
	phase = v & 7;
	CHECK(gen >= S.w.last_gen[idx], "INV_GEN_MONOTONE",
	      "%s generation went from %llu to %llu", word[idx],
	      (unsigned long long)S.w.last_gen[idx], (unsigned long long)gen);
	S.w.last_gen[idx] = gen;
	CHECK(idx ? phase <= XDEV_EXT_MECH_C_PUBLISHING :
		    phase != 4 && phase != 7, "INV_PHASE",
	      "%s word holds undefined phase %u", word[idx], phase);
	CHECK(S.w.stale_op != running + 1, "INV_STALE_MATCH",
	      "a stale generation or ticket wrote the %s word", word[idx]);
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

static void batch_step(int i)
{
	struct actor *a = &S.a[i];
	struct world *w = &S.w;
	bool producer = a->kind == A_PRODUCER;
	int c = producer ? 0 : 1;
	__u32 phase;
	__s32 res;
	int rc;

	switch (a->pc) {
	case B_ADMIT:
		if (xdev_ext_mech_sess_batch_begin(&w->ss)) {
			COV(ADMIT_REFUSED);
			a->done = 1;
			return;
		}
		CHECK(!w->stop_called, "INV_STOP_ADMIT",
		      "a batch was admitted after STOP (state %u)", w->ss.state);
		a->pc = B_CUSTODY;
		return;
	case B_CUSTODY:
		CHECK(!w->released, "INV_EARLY_REUSE",
		      "a batch used a frame of a released pool");
		if (cfg.custody && xdev_ext_mech_frame_move(&w->fw, XDEV_EXT_MECH_F_K_FREE,
							   XDEV_EXT_MECH_F_HELD)) {
			a->pc = B_LEAVE;
			return;
		}
		a->pc = B_ACQUIRE;
		return;
	case B_ACQUIRE:
		phase = xdev_ext_mech_life_phase(&w->life);
		a->prev_phase = producer ? phase : XDEV_EXT_MECH_L_READY;
		rc = producer ?
			xdev_ext_mech_life_begin_produce(&w->life,
				phase == XDEV_EXT_MECH_L_READY, &a->token) :
			xdev_ext_mech_life_begin_consume(&w->life, &a->token);
		if (rc) {
			CHECK(rc == -EBUSY || rc == -EOVERFLOW, "INV_PHASE",
			      "life acquire returned %d", rc);
			if (rc == -EOVERFLOW)
				COV(GEN_EXHAUSTED);
			else
				COV(ACQUIRE_REFUSED);
			custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE,
				"refused acquire");
			a->pc = B_LEAVE;
			return;
		}
		CHECK(!w->writer && !w->reader, "INV_EARLY_REUSE",
		      "actor %d acquired the frame while the device of actor %d may still access it",
		      i, (w->writer ? w->writer : w->reader) - 1);
		if (producer) {
			w->writer = (__u8)(i + 1);
			if (phase == XDEV_EXT_MECH_L_READY)
				COV(OVERWRITE_READY);
		} else {
			w->reader = (__u8)(i + 1);
			/* valid_len is read only after the winning READY acquire. */
			CHECK(w->life.valid_len == w->data_len, "INV_STALE_MATCH",
			      "consumer read valid_len %u, the READY generation published %u",
			      w->life.valid_len, w->data_len);
		}
		a->pc = B_SUBMIT;
		return;
	case B_SUBMIT:
		custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_INFLIGHT, "submit");
		rc = xdev_ext_mech_completion_begin(&w->comp[c], &a->ticket);
		if (rc) {
			/* Preaccept failure: undo the life edge and custody. */
			CHECK(rc == -EOVERFLOW, "INV_PHASE",
			      "completion_begin on an idle word returned %d", rc);
			COV(TICKET_EXHAUSTED);
			CHECK(!xdev_ext_mech_life_rollback(&w->life, a->token, a->prev_phase),
			      "INV_STALE_MATCH", "rollback of the batch's own edge failed");
			if (producer)
				w->writer = 0;
			else
				w->reader = 0;
			custody(XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD, "undo submit");
			custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE, "undo submit");
			a->pc = B_LEAVE;
			return;
		}
		if (producer) {
			w->announced = a->ticket;
			w->owners = 0;
			a->pc = cfg.fault == F_REFUSE ? B_REFUSE : B_CALLBACK;
		} else {
			a->pc = B_CALLBACK;
		}
		return;
	case B_REFUSE:
		/* A callback that claimed ownership wins even before submit returns. */
		if (xdev_ext_mech_completion_cancel(&w->comp[0], a->ticket)) {
			COV(CALLBACK_WON_CANCEL);
			a->pc = B_LAND;
			return;
		}
		COV(CANCEL_WON);
		CHECK(++w->owners == 1, "INV_STALE_MATCH",
		      "ticket %llu was both claimed and cancelled",
		      (unsigned long long)a->ticket);
		CHECK(!xdev_ext_mech_life_rollback(&w->life, a->token, a->prev_phase),
		      "INV_STALE_MATCH", "rollback after a refused submit failed");
		w->writer = 0;
		w->announced = 0;
		custody(XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD, "refused submit");
		custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE, "refused submit");
		a->pc = B_LEAVE;
		return;
	case B_CALLBACK:
		if (xdev_ext_mech_completion_claim(&w->comp[c], a->ticket)) {
			CHECK(producer, "INV_STALE_MATCH",
			      "the consumer's only callback lost its claim");
			a->pc = B_LAND;
			return;
		}
		if (producer) {
			CHECK(++w->owners == 1, "INV_STALE_MATCH",
			      "ticket %llu was claimed twice",
			      (unsigned long long)a->ticket);
			a->pc = B_PUBLISH_CQE;
			return;
		}
		CHECK(!xdev_ext_mech_completion_publish(&w->comp[1], a->ticket, 0),
		      "INV_STALE_MATCH", "consumer callback could not publish its claim");
		w->result[1] = 0;
		a->pc = B_LAND;
		return;
	case B_PUBLISH_CQE:
		res = cfg.fault == F_FAIL ? -EIO : cfg.fault == F_AMBIG ? -ETIMEDOUT : 0;
		CHECK(!xdev_ext_mech_completion_publish(&w->comp[0], a->ticket, res),
		      "INV_STALE_MATCH", "callback could not publish its claim");
		w->result[0] = res;
		a->pc = B_LAND;
		return;
	case B_LAND:
		res = 1;
		CHECK(!xdev_ext_mech_completion_consume(&w->comp[c], a->ticket, &res),
		      "INV_STALE_MATCH", "the worker could not consume its landed ticket");
		CHECK(res == w->result[c], "INV_STALE_MATCH",
		      "the worker read result %d, its callback published %d",
		      res, w->result[c]);
		if (producer)
			w->announced = 0;
		if (producer && res == -ETIMEDOUT) {
			/* The device may still write: the frame never comes back. */
			custody(XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_SEQUESTERED,
				"sequester");
			w->fw_sequestered = 1;
			a->seq = 1;
			COV(SEQUESTERED);
			a->pc = B_LEAVE;
			return;
		}
		custody(XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD, "landing");
		if (!producer)
			rc = xdev_ext_mech_life_complete_consume(&w->life, a->token);
		else if (res)
			rc = xdev_ext_mech_life_fail_produce(&w->life, a->token);
		else
			rc = xdev_ext_mech_life_publish(&w->life, a->token,
						   round_len(a->round));
		CHECK(!rc, "INV_STALE_MATCH",
		      "the landing batch lost its own generation (%d)", rc);
		if (producer) {
			if (!res)
				w->data_len = round_len(a->round);
			w->writer = 0;
			if (res)
				COV(FAIL_PRODUCE);
			else
				COV(PUBLISHED);
		} else {
			w->reader = 0;
			COV(CONSUMED);
		}
		a->pc = B_RELEASE;
		return;
	case B_RELEASE:
		/*
		 * xdev_ext_mech_frames_release: a producer keeps READY for a later
		 * reader; a reader releases the generation it finds, as the kernel
		 * does, and a refused release quarantines the frame.
		 */
		if (!producer && cfg.custody &&
		    xdev_ext_mech_life_phase(&w->life) != XDEV_EXT_MECH_L_FREE &&
		    xdev_ext_mech_life_release(&w->life, xdev_ext_mech_life_token(&w->life))) {
			custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_SEQUESTERED,
				"refused release");
			w->fw_sequestered = 1;
			a->seq = 1;
		} else {
			custody(XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE, "release");
		}
		a->pc = B_LEAVE;
		return;
	case B_LEAVE: {
		/* xdev_ext_mech_leave_locked, then xdev_ext_mech_reap on the last ref */
		bool last = xdev_ext_mech_sess_batch_end(&w->ss, a->seq);

		settle();
#ifdef LIFE_MODEL_MUTANT_REAP_RELEASES
		/* Seeded defect: the reap of a quarantined session frees the pool. */
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
	__u64 t0 = w->hist_life[0], t1 = w->hist_life[1], k = w->hist_ticket;
	__u32 len = w->life.valid_len;
	int r = 0;

	switch (a->pc) {
	case S_STALE_LIFE:
		w->stale_op = (__u8)(i + 1);
		CHECK(xdev_ext_mech_life_publish(&w->life, t0, 999) &&
		      xdev_ext_mech_life_publish(&w->life, t1, 999) &&
		      xdev_ext_mech_life_fail_produce(&w->life, t0) &&
		      xdev_ext_mech_life_fail_produce(&w->life, t1) &&
		      xdev_ext_mech_life_complete_consume(&w->life, t0) &&
		      xdev_ext_mech_life_complete_consume(&w->life, t1) &&
		      xdev_ext_mech_life_rollback(&w->life, t0, XDEV_EXT_MECH_L_FREE) &&
		      xdev_ext_mech_life_rollback(&w->life, t0, XDEV_EXT_MECH_L_READY) &&
		      xdev_ext_mech_life_rollback(&w->life, t1, XDEV_EXT_MECH_L_READY) &&
		      xdev_ext_mech_life_release(&w->life, t0),
		      "INV_STALE_MATCH", "an old generation won a lifecycle edge");
		CHECK(access_mode || w->life.valid_len == len, "INV_STALE_MATCH",
		      "an old generation changed valid_len");
		w->stale_op = 0;
		a->pc = S_STALE_COMPLETION;
		return;
	case S_STALE_COMPLETION:
		w->stale_op = (__u8)(i + 1);
		CHECK(xdev_ext_mech_completion_claim(&w->comp[0], k) &&
		      xdev_ext_mech_completion_publish(&w->comp[0], k, -EIO) &&
		      xdev_ext_mech_completion_consume(&w->comp[0], k, &r) &&
		      xdev_ext_mech_completion_cancel(&w->comp[0], k),
		      "INV_STALE_MATCH", "an old ticket won a completion edge");
		w->stale_op = 0;
		a->pc = S_DUP_CLAIM;
		return;
	case S_DUP_CLAIM:
		/* A duplicate native callback for whatever ticket is live now. */
		a->ticket = w->announced;
		if (a->ticket && !xdev_ext_mech_completion_claim(&w->comp[0], a->ticket)) {
			CHECK(++w->owners == 1, "INV_STALE_MATCH",
			      "ticket %llu was owned twice", (unsigned long long)a->ticket);
			COV(DUPLICATE_WON);
			a->pc = S_DUP_PUBLISH;
			return;
		}
		if (a->ticket)
			COV(DUPLICATE_LOST);
		a->pc = S_LATE_CALLBACK;
		return;
	case S_DUP_PUBLISH:
		r = cfg.fault == F_FAIL ? -EIO : cfg.fault == F_AMBIG ? -ETIMEDOUT : 0;
		CHECK(!xdev_ext_mech_completion_publish(&w->comp[0], a->ticket, r),
		      "INV_STALE_MATCH", "the winning duplicate could not publish");
		w->result[0] = r;
		a->pc = S_LATE_CALLBACK;
		return;
	case S_LATE_CALLBACK:
		/* The same callback again: its ticket has an owner already. */
		if (a->ticket) {
			w->stale_op = (__u8)(i + 1);
			CHECK(xdev_ext_mech_completion_claim(&w->comp[0], a->ticket),
			      "INV_STALE_MATCH", "ticket %llu was claimed again",
			      (unsigned long long)a->ticket);
			w->stale_op = 0;
		}
		a->pc = cfg.custody ? S_END : S_RACE_RELEASE;
		if (a->pc == S_END)
			a->done = 1;
		return;
	case S_RACE_RELEASE:
		/* Lifecycle only: another owner gives a READY frame back. */
		if (xdev_ext_mech_life_phase(&w->life) != XDEV_EXT_MECH_L_FREE &&
		    !xdev_ext_mech_life_release(&w->life, xdev_ext_mech_life_token(&w->life))) {
			CHECK(!w->writer && !w->reader, "INV_EARLY_REUSE",
			      "the frame was released while the device of actor %d may still access it",
			      (w->writer ? w->writer : w->reader) - 1);
			COV(RACING_RELEASE);
		}
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
	if ((a->kind == A_PRODUCER || a->kind == A_CONSUMER) && a->pc == B_LAND) {
		c = a->kind == A_PRODUCER ? 0 : 1;
		return (raw_ctrl(&S.w.comp[c].ctrl) & 7) == XDEV_EXT_MECH_C_LANDED;
	}
	return true;
}

static void step(int i)
{
	switch (S.a[i].kind) {
	case A_PRODUCER:
	case A_CONSUMER:
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

/* One finished cycle before the actors start, so stale values exist. */
static void init_state(void)
{
	struct world *w = &S.w;
	__u64 tok, ticket;
	int res = 1;
	unsigned int i;

	memset(&S, 0, sizeof(S));
	hooks_on = false;
	xdev_ext_mech_life_init(&w->life);
	xdev_ext_mech_completion_init(&w->comp[0]);
	xdev_ext_mech_completion_init(&w->comp[1]);
	/* Tickets run two generations ahead so they can run out first too. */
	ticket = cfg.seed ? cfg.seed + 2 : 0;
	if (ticket >= XDEV_EXT_MECH_L_GEN_MAX)
		ticket = XDEV_EXT_MECH_L_GEN_MAX - 1;
	w->life.ctrl = cfg.seed << 3;
	w->comp[0].ctrl = ticket << 3;
	w->comp[1].ctrl = ticket << 3;
	if (xdev_ext_mech_life_begin_produce(&w->life, false, &tok) ||
	    xdev_ext_mech_life_publish(&w->life, tok, HIST_LEN))
		abort();
	w->hist_life[0] = tok;
	if (xdev_ext_mech_life_begin_consume(&w->life, &tok) ||
	    xdev_ext_mech_life_complete_consume(&w->life, tok) ||
	    xdev_ext_mech_life_release(&w->life, tok))
		abort();
	w->hist_life[1] = tok;
	w->data_len = HIST_LEN;
	if (xdev_ext_mech_completion_begin(&w->comp[0], &ticket) ||
	    xdev_ext_mech_completion_claim(&w->comp[0], ticket) ||
	    xdev_ext_mech_completion_publish(&w->comp[0], ticket, 0) ||
	    xdev_ext_mech_completion_consume(&w->comp[0], ticket, &res) ||
	    xdev_ext_mech_completion_claim(&w->comp[0], ticket) != -ESTALE)
		abort();
	w->hist_ticket = ticket;
	w->last_gen[0] = w->life.ctrl >> 3;
	w->last_gen[1] = w->comp[0].ctrl >> 3;
	w->last_gen[2] = w->comp[1].ctrl >> 3;
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
	bool custody;
	unsigned int faults;	/* bit per enum fault */
};

#define FB(f) (1U << (f))
static const struct scenario scenarios[] = {
	{ "producer+consumer", { A_PRODUCER, A_CONSUMER }, 2, true,
	  FB(F_NONE) | FB(F_FAIL) },
	{ "producer+stale", { A_PRODUCER, A_STALE }, 2, true,
	  FB(F_NONE) | FB(F_FAIL) | FB(F_REFUSE) | FB(F_AMBIG) },
	{ "producer+teardown", { A_PRODUCER, A_TEARDOWN }, 2, true,
	  FB(F_NONE) | FB(F_FAIL) | FB(F_REFUSE) | FB(F_AMBIG) },
	{ "producer+consumer+stale", { A_PRODUCER, A_CONSUMER, A_STALE }, 3, true,
	  FB(F_NONE) | FB(F_REFUSE) | FB(F_AMBIG) },
	{ "producer+consumer+teardown", { A_PRODUCER, A_CONSUMER, A_TEARDOWN }, 3,
	  true, FB(F_NONE) | FB(F_FAIL) | FB(F_AMBIG) },
	{ "producer+stale+teardown", { A_PRODUCER, A_STALE, A_TEARDOWN }, 3, true,
	  FB(F_NONE) | FB(F_REFUSE) | FB(F_AMBIG) },
	{ "lifecycle-only producer+consumer+stale",
	  { A_PRODUCER, A_CONSUMER, A_STALE }, 3, false, FB(F_NONE) | FB(F_FAIL) },
};

/* Fresh words, and words a few generations below the last one. */
static const __u64 seed_gap[] = { 0, 5, 4, 3, 2 };

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
				/*
				 * With one round per actor no word seeded at
				 * GEN_MAX-5 reaches the last generation, so the
				 * access search would repeat the seed 0 one;
				 * GEN_MAX-4 uses the last generation as a token.
				 */
				if (do_access && (access_rounds > 1 || seed_gap[sd] != 5)) {
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

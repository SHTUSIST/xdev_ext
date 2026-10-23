// SPDX-License-Identifier: GPL-2.0
/*
 * Bounded model checker for the reference-counted frame lifecycle: one
 * frame word, a producer, concurrent fan-out consumers, a dependent
 * consumer, an in-frame (exclusive) transform, duplicate native callbacks
 * and stale claims.  It complements life_explore.c, which covers custody,
 * session STOP, drain and quarantine.
 *
 * The code under test is compiled in: the lifecycle and completion words of
 * io_uring/xdev_ext_mech_lifecycle.h in their __KERNEL__ form over
 * shim/linux/atomic.h.  Each actor is the call sequence the mechanism core
 * runs for one stage of a batch:
 *
 *   producer   claim (FREE -> IO_PENDING), submit (completion_begin), the
 *              native callback (completion_claim, then the lifecycle
 *              hand-off in the callback: publish with the chain's reference
 *              count, or fail_produce), the completion record, and the
 *              worker landing (completion_consume) that lets the worker
 *              build the next stage; or a refused submit that cancels and
 *              rolls back;
 *   consumer   acquire once the worker may build its descriptor (shared,
 *              fan-out or exclusive), submit, callback (claim, hand-off by
 *              put or fail_put; an exclusive transform republishes), record,
 *              landing;
 *   dupcb      a second native callback for the producer's live ticket;
 *   stale      claims of an earlier cycle against every edge, and a late
 *              duplicate completion of a consumer that already handed off.
 *
 * Two explorations per configuration, as in life_explore.c: "op" (every
 * interleaving of whole steps, exhaustive, with a visited set) and "access"
 * (every interleaving with at most --preemptions preemptions at the atomic
 * accesses inside the header functions).
 *
 * Invariants (VIOLATION <name> and a trace, exit 1):
 *   INV_PHASE        a word that is not one of the four states with the
 *                    busy/refs/owner rules of that state;
 *   INV_GEN          the generation changes other than by +1 on entering FREE
 *                    (or 0 on a rollback of a claim no device saw);
 *   INV_EARLY_REUSE  the frame becomes FREE or is claimed while a consumer's
 *                    device may still read it or a producer's may write it;
 *   INV_REFS         references or in-flight consumers in the word differ
 *                    from what the publication installed minus completions;
 *   INV_SUPPRESS     a stage after a failed consumer acquires the frame;
 *   INV_STALE_MATCH  a stale claim writes the word, a duplicate completion
 *                    is accepted, or a consumer reads a valid length that the
 *                    winning publication did not write;
 *   INV_FINAL        a finished run leaves the frame anywhere but FREE, or
 *                    recycles it other than once per publication;
 *   INV_DEADLOCK     no actor can move while some have not finished.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#define __KERNEL__
#include "io_uring/xdev_ext_mech_lifecycle.h"
#undef __KERNEL__

#ifndef XDEV_EXT_MECH_LIFE_REFS
#error "reference-counted lifecycle API (XDEV_EXT_MECH_LIFE_REFS) is missing"
#else

#define MAX_ACTORS 5
#define MAX_TRACE 512
#define MAX_DECISIONS 4096
#define STACK_BYTES (256 * 1024)

#define ST(w) ((__u32)((w) & XDEV_EXT_MECH_L_STATE_MASK))
#define BUSY(w) ((__u32)(((w) & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT))
#define REFS(w) ((__u32)(((w) & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT))
#define OWN(w) ((__u32)(((w) & XDEV_EXT_MECH_L_OWNER_MASK) >> XDEV_EXT_MECH_L_OWNER_SHIFT))
#define GEN(w) ((w) >> XDEV_EXT_MECH_L_GEN_SHIFT)

enum kind { K_PRODUCER, K_CONSUMER, K_DUPCB, K_STALE };

/* Consumer roles: stage index and acquire flags. */
enum role { R_LEAD, R_FAN, R_DEP, R_EXCL, R_AFTER };
static const __u8 role_stage[] = { 1, 2, 3, 1, 2 };

enum fault { F_NONE, F_FAIL_LEAD, F_FAIL_FAN, F_FAIL_PRODUCE, F_REFUSE, F_FAIL_EXCL, F_NR };
static const char *const fault_names[F_NR] = {
	"none", "lead-consumer-fails", "fanout-consumer-fails", "producer-fails",
	"refused-submit", "transform-fails",
};

enum { P_CLAIM, P_SUBMIT, P_REFUSE, P_CB_CLAIM, P_HANDOFF, P_CB_PUBLISH, P_LAND, P_END };
static const char *const p_ops[] = {
	"P.claim", "P.submit", "P.refused_submit_cancel_rollback", "P.callback_claim",
	"P.callback_handoff", "P.callback_record", "P.worker_land", "P.end",
};
enum { C_ACQUIRE, C_SUBMIT, C_CB_CLAIM, C_HANDOFF, C_CB_PUBLISH, C_LAND, C_END };
static const char *const c_ops[] = {
	"C.acquire", "C.submit", "C.callback_claim", "C.callback_handoff", "C.callback_record",
	"C.worker_land", "C.end",
};
enum { U_CLAIM, U_HANDOFF, U_PUBLISH, U_END };
static const char *const u_ops[] = {
	"U.duplicate_claim", "U.duplicate_handoff", "U.duplicate_record", "U.end",
};
enum { S_OLD, S_LATE, S_END };
static const char *const s_ops[] = { "S.old_cycle_claims", "S.late_duplicate_put", "S.end" };

struct actor {
	__u64 claim;
	__u64 ticket;
	__u8 kind;
	__u8 role;
	__u8 pc;
	__u8 done;
	__u8 round;
	__u8 won;		/* this callback owns the completion ticket */
	__u8 pad[2];
};

struct world {
	struct xdev_ext_mech_life life;
	struct xdev_ext_mech_completion comp[MAX_ACTORS];
	__u64 last_ctrl;	/* the word before the latest write */
	__u64 gen0;		/* generation of the first publication */
	__u64 hist_p, hist_c;	/* claims of an earlier, finished cycle */
	__u64 late;		/* a consumer claim after its hand-off */
	__u64 p_ticket;		/* the producer's live ticket */
	__u32 data_len;		/* ghost: the winning publication's length */
	__u32 g_refs;		/* ghost: references owed */
	__u32 g_busy;		/* ghost: stage mask acquired, not handed off */
	__u32 recycles;		/* transitions into FREE that end a version */
	__u32 claims;		/* successful producer claims */
	__u32 rollbacks;	/* claims undone before any device saw them */
	__u8 readers;		/* ghost: actor mask whose device may read */
	__u8 writer;		/* ghost: actor+1 whose device may write */
	__u8 failed;		/* a consumer of this publication failed */
	__u8 p_landed;		/* worker saw the producer: consumers may build */
	__u8 p_gone;		/* producer ended without a publication */
	__u8 landed;		/* actor mask: consumer completions consumed */
	__u8 handed;		/* actor mask: consumer hand-offs done */
	__u8 republished;
	__u8 rollback_op;	/* actor+1 inside a rollback */
	__u8 stale_op;		/* actor+1 replaying a stale claim */
	__u8 owners;		/* completion-claim winners of p_ticket */
	__u8 round;		/* producer round in progress */
	__u8 exhausted;		/* the producer met the last generation */
};

struct state {
	struct world w;
	struct actor a[MAX_ACTORS];
};

struct config {
	const char *name;
	__u8 kinds[MAX_ACTORS];
	__u8 roles[MAX_ACTORS];
	__u8 nr;
	__u8 refs;		/* references the producer installs */
	__u8 rounds;
	enum fault fault;
	__u64 seed;
};

static struct state S;
static struct config cfg;
static bool access_mode, hooks_on;
static int running = -1;
static unsigned long long checks;

enum cov {
	COV_PUBLISHED, COV_BOTH_OUT, COV_READY_AGAIN, COV_FREED, COV_SUPPRESSED,
	COV_FAIL_PUT, COV_FAIL_PRODUCE, COV_ROLLBACK, COV_DUP_WON, COV_DUP_LOST,
	COV_STALE_REJECTED, COV_LATE_REJECTED, COV_REPUBLISHED, COV_EXHAUSTED,
	COV_RESUMED_INSIDE_STEP, COV_NR,
};
static const char *const cov_names[COV_NR] = {
	"published", "fanout_both_in_flight", "ready_again_for_dependent", "freed",
	"dependent_suppressed", "failed_consumer", "failed_producer", "rollback",
	"duplicate_callback_won", "duplicate_callback_lost", "stale_rejected",
	"late_duplicate_rejected", "republished", "generation_exhausted",
	"resumed_inside_step",
};
static unsigned long long cov[COV_NR];
#define COV(e) (cov[COV_##e]++)

struct trace_entry { __u8 actor, pc, resumed; };
static struct trace_entry trace[MAX_TRACE];
static unsigned int trace_len;

static const char *op_name(__u8 kind, __u8 pc)
{
	switch (kind) {
	case K_PRODUCER: return p_ops[pc];
	case K_CONSUMER: return c_ops[pc];
	case K_DUPCB: return u_ops[pc];
	default: return s_ops[pc];
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
	printf("\n# config %s fault=%s refs=%u rounds=%u seed=%s%llu mode=%s\n", cfg.name,
	       fault_names[cfg.fault], cfg.refs, cfg.rounds, cfg.seed ? "GEN_MAX-" : "",
	       (unsigned long long)(cfg.seed ? XDEV_EXT_MECH_L_GEN_MAX - cfg.seed : 0),
	       access_mode ? "access" : "op");
	printf("# trace (actor: step):\n");
	for (i = 0; i < trace_len && i < MAX_TRACE; i++)
		printf("#   %u %s%s\n", trace[i].actor, op_name(S.a[trace[i].actor].kind, trace[i].pc),
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

/* ---- hooks of shim/linux/atomic.h ---- */

static void access_yield(void);
static __u8 in_step[MAX_ACTORS];

void life_model_before(const volatile void *p, int kind)
{
	(void)p;
	(void)kind;
	if (hooks_on && access_mode && running >= 0)
		access_yield();
}

static bool word_ok(__u64 w)
{
	__u32 st = ST(w), busy = BUSY(w), refs = REFS(w), own = OWN(w);

	if (refs > XDEV_EXT_MECH_L_REFS_MAX || own > XDEV_EXT_MECH_L_OWNER_MAX + 1)
		return false;
	switch (st) {
	case XDEV_EXT_MECH_L_FREE:
		return !busy && !refs && !own;
	case XDEV_EXT_MECH_L_IO_PENDING:
		return !busy && !refs && own;
	case XDEV_EXT_MECH_L_READY:
		return !busy && !own;
	default:
		return busy && (__u32)__builtin_popcount(busy) <= refs &&
		       (!own || busy == 1U << (own - 1));
	}
}

void life_model_after(const volatile void *p, int kind, bool wrote)
{
	__u64 old, w;

	(void)kind;
	if (!hooks_on || !wrote || p != &S.w.life.ctrl)
		return;
	w = __atomic_load_n(&S.w.life.ctrl, __ATOMIC_RELAXED);
	old = S.w.last_ctrl;
	S.w.last_ctrl = w;
	CHECK(S.w.stale_op != running + 1, "INV_STALE_MATCH",
	      "a stale or duplicate claim wrote the word (%#llx -> %#llx)",
	      (unsigned long long)old, (unsigned long long)w);
	CHECK(word_ok(w), "INV_PHASE", "ill-formed word %#llx", (unsigned long long)w);
	if (ST(w) == XDEV_EXT_MECH_L_FREE && ST(old) != XDEV_EXT_MECH_L_FREE) {
		bool rollback = S.w.rollback_op == running + 1 &&
				ST(old) == XDEV_EXT_MECH_L_IO_PENDING;

		CHECK(GEN(w) == GEN(old) + (rollback ? 0 : 1), "INV_GEN",
		      "entering FREE moved the generation %llu -> %llu%s",
		      (unsigned long long)GEN(old), (unsigned long long)GEN(w),
		      rollback ? " on a rollback" : "");
		CHECK(!S.w.readers && !S.w.writer, "INV_EARLY_REUSE",
		      "FREE while devices may still access the frame (readers %#x writer %u)",
		      S.w.readers, S.w.writer);
		if (!rollback)
			S.w.recycles++;
	} else {
		CHECK(GEN(w) == GEN(old), "INV_GEN", "generation %llu -> %llu without a recycle",
		      (unsigned long long)GEN(old), (unsigned long long)GEN(w));
	}
	if (ST(w) == XDEV_EXT_MECH_L_IO_PENDING && ST(old) == XDEV_EXT_MECH_L_FREE)
		CHECK(!S.w.readers && !S.w.writer, "INV_EARLY_REUSE",
		      "claimed while devices may still access the frame (readers %#x)",
		      S.w.readers);
}

/* ---- defects the mutant runner plants in the core's use of the word ---- */

static __u64 raw(void)
{
	return __atomic_load_n(&S.w.life.ctrl, __ATOMIC_ACQUIRE);
}

/* A CAS of the whole word on behalf of a defective implementation. */
static void __attribute__((unused)) raw_set(__u64 old, __u64 next)
{
	if (__atomic_compare_exchange_n(&S.w.life.ctrl, &old, next, false,
					__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		life_model_after(&S.w.life.ctrl, 2, true);
}

static int m_put(__u64 claim)
{
#ifdef REFS_MUTANT_MISSED_GEN
	{
		/* The final reference recycles without a generation increment. */
		__u64 w = raw();
		__u32 bit = 1U << (((claim >> XDEV_EXT_MECH_L_OWNER_SHIFT) & 7) - 1);

		if (ST(w) == XDEV_EXT_MECH_L_OUT_PENDING && REFS(w) == 1 && BUSY(w) == bit &&
		    GEN(w) == claim >> XDEV_EXT_MECH_L_GEN_SHIFT) {
			raw_set(w, w & ~((1ULL << XDEV_EXT_MECH_L_GEN_SHIFT) - 1));
			return XDEV_EXT_MECH_L_FREED;
		}
	}
#endif
	int ret = xdev_ext_mech_life_put(&S.w.life, claim);

#ifdef REFS_MUTANT_DOUBLE_DECREMENT
	if (ret == XDEV_EXT_MECH_L_KEPT) {
		__u64 w = raw();

		if (REFS(w) > (__u32)__builtin_popcount(BUSY(w)))
			raw_set(w, w - (1ULL << XDEV_EXT_MECH_L_REFS_SHIFT));
	}
#endif
#ifdef REFS_MUTANT_EARLY_FREE
	if (ret == XDEV_EXT_MECH_L_KEPT) {
		__u64 w = raw();

		if (BUSY(w))
			raw_set(w, (GEN(w) + 1) << XDEV_EXT_MECH_L_GEN_SHIFT);
	}
#endif
	return ret;
}

static int m_fail_put(__u64 claim)
{
#ifdef REFS_MUTANT_FAIL_KEEPS_REFS
	return xdev_ext_mech_life_put(&S.w.life, claim);
#else
	return xdev_ext_mech_life_fail_put(&S.w.life, claim);
#endif
}

/* ---- actors ---- */

static __u32 pub_len(const struct actor *a)
{
	return 100U + 17U * a->round + (a->kind == K_DUPCB ? 50U : 0U);
}

static bool consumer_fails(const struct actor *a)
{
	return (cfg.fault == F_FAIL_LEAD && a->role == R_LEAD) ||
	       (cfg.fault == F_FAIL_FAN && a->role == R_FAN) ||
	       (cfg.fault == F_FAIL_EXCL && a->role == R_EXCL);
}

static __u8 consumer_mask(__u8 role_lo, __u8 role_hi)
{
	__u8 m = 0;
	unsigned int i;

	for (i = 0; i < cfg.nr; i++)
		if (cfg.kinds[i] == K_CONSUMER && cfg.roles[i] >= role_lo && cfg.roles[i] <= role_hi)
			m |= (__u8)(1U << i);
	return m;
}

/* The worker builds a consumer's descriptor only after its predecessors landed. */
static bool consumer_may_start(const struct actor *a)
{
	const struct world *w = &S.w;

	if (a->round != w->round)
		return false;
	if (w->p_gone)
		return true;
	if (!w->p_landed)
		return false;
	switch (a->role) {
	case R_LEAD:
	case R_FAN:
	case R_EXCL:
		return true;
	case R_DEP:
		return (w->landed & consumer_mask(R_LEAD, R_FAN)) == consumer_mask(R_LEAD, R_FAN);
	default:
		return (w->landed & consumer_mask(R_EXCL, R_EXCL)) == consumer_mask(R_EXCL, R_EXCL);
	}
}

/* A producer's next round waits until the batch gave the frame back. */
static bool round_over(void)
{
	return (S.w.p_gone || (S.w.landed & consumer_mask(R_LEAD, R_AFTER)) ==
		consumer_mask(R_LEAD, R_AFTER)) && !S.w.readers;
}

static void producer_handoff(struct actor *a, bool dup)
{
	struct world *w = &S.w;
	int rc;

	if (cfg.fault == F_FAIL_PRODUCE) {
		/* The device finished writing (with an error) before the callback. */
		w->writer = 0;
		rc = xdev_ext_mech_life_fail_produce(&w->life, a->claim);
		CHECK(!rc, "INV_STALE_MATCH", "the callback owner could not fail its claim (%d)", rc);
		w->p_gone = 1;
		COV(FAIL_PRODUCE);
		return;
	}
	w->writer = 0;
	rc = xdev_ext_mech_life_publish(&w->life, a->claim, cfg.refs, pub_len(a));
	if (!rc) {
		w->data_len = pub_len(a);
		w->g_refs = cfg.refs;
		w->g_busy = 0;
		COV(PUBLISHED);
		if (dup)
			COV(DUP_WON);
	} else {
		/* Only a protocol without the ticket guard has a losing publisher. */
		CHECK(!a->won, "INV_STALE_MATCH", "the completion owner's publish failed (%d)", rc);
	}
}

static void producer_step(int i)
{
	struct actor *a = &S.a[i];
	struct world *w = &S.w;
	int rc, res = 1;

	switch (a->pc) {
	case P_CLAIM:
		rc = xdev_ext_mech_life_claim(&w->life, 0, &a->claim);
		if (rc == -EOVERFLOW) {
			COV(EXHAUSTED);
			w->p_gone = 1;
			w->exhausted = 1;
			a->pc = P_END;
			a->done = 1;
			return;
		}
		CHECK(!rc, "INV_EARLY_REUSE", "the batch could not claim its own free frame (%d)", rc);
		w->writer = (__u8)(i + 1);
		w->claims++;
		a->pc = P_SUBMIT;
		return;
	case P_SUBMIT:
		CHECK(!xdev_ext_mech_completion_begin(&w->comp[i], &a->ticket), "INV_PHASE",
		      "completion_begin failed");
		w->p_ticket = a->ticket;
		w->owners = 0;
		a->pc = cfg.fault == F_REFUSE ? P_REFUSE : P_CB_CLAIM;
		return;
	case P_REFUSE:
		/* Submit refused before any device saw it: undo, no recycle. */
		if (xdev_ext_mech_completion_cancel(&w->comp[i], a->ticket)) {
			/* A duplicate callback claimed first: it owns the outcome. */
			a->pc = P_LAND;
			return;
		}
		CHECK(++w->owners == 1, "INV_STALE_MATCH", "ticket owned twice");
		w->writer = 0;
		w->rollback_op = (__u8)(i + 1);
		rc = xdev_ext_mech_life_rollback(&w->life, a->claim);
		w->rollback_op = 0;
		CHECK(!rc, "INV_STALE_MATCH", "rollback of the batch's own claim failed (%d)", rc);
		w->rollbacks++;
		w->p_gone = 1;
		COV(ROLLBACK);
		a->pc = P_END;
		a->done = 1;
		return;
	case P_CB_CLAIM:
#ifndef REFS_MUTANT_PUBLISH_WITHOUT_CLAIM
		if (xdev_ext_mech_completion_claim(&w->comp[i], a->ticket)) {
			a->pc = P_LAND;
			return;
		}
		CHECK(++w->owners == 1, "INV_STALE_MATCH", "ticket claimed twice");
		a->won = 1;
#endif
		a->pc = P_HANDOFF;
		return;
	case P_HANDOFF:
		/* The lifecycle hand-off runs in the native callback (L6). */
		producer_handoff(a, false);
		a->pc = P_CB_PUBLISH;
		return;
	case P_CB_PUBLISH:
#ifdef REFS_MUTANT_PUBLISH_WITHOUT_CLAIM
		if (xdev_ext_mech_completion_claim(&w->comp[i], a->ticket)) {
			a->pc = P_LAND;
			return;
		}
#endif
		CHECK(!xdev_ext_mech_completion_publish(&w->comp[i], a->ticket, 0), "INV_PHASE",
		      "callback could not record its claim");
		a->pc = P_LAND;
		return;
	case P_LAND:
		CHECK(!xdev_ext_mech_completion_consume(&w->comp[i], a->ticket, &res),
		      "INV_STALE_MATCH", "worker could not consume the landed ticket");
		if (!w->p_gone) {
			CHECK(xdev_ext_mech_life_phase(&w->life) != XDEV_EXT_MECH_L_IO_PENDING,
			      "INV_PHASE", "worker landed a completion whose hand-off did not run");
			w->p_landed = 1;
		}
		a->pc = P_END;
		return;
	case P_END:
		if (++a->round < cfg.rounds) {
			/* Next batch over the recycled frame. */
			w->round = a->round;
			w->p_landed = 0;
			w->p_gone = 0;
			w->landed = 0;
			w->handed = 0;
			w->failed = 0;
			w->republished = 0;
			a->pc = P_CLAIM;
			return;
		}
		a->done = 1;
		return;
	}
}

static void consumer_step(int i)
{
	struct actor *a = &S.a[i];
	struct world *w = &S.w;
	__u32 stage = role_stage[a->role], bit = 1U << stage, flags;
	int rc, res = 1;

	switch (a->pc) {
	case C_ACQUIRE:
		/* Every member of a fan-out group joins with FANOUT, the head too. */
		flags = (a->role == R_FAN || a->role == R_LEAD) && consumer_mask(R_FAN, R_FAN) ?
			XDEV_EXT_MECH_L_ACQ_FANOUT :
			a->role == R_EXCL ? XDEV_EXT_MECH_L_ACQ_EXCLUSIVE : 0;
		rc = xdev_ext_mech_life_acquire(&w->life, stage, flags, &a->claim);
		if (rc) {
			CHECK(rc == -EBUSY || rc == -ENOENT, "INV_PHASE", "acquire returned %d", rc);
			/* Refused only when the publication was suppressed or never made. */
			CHECK(w->failed || w->p_gone, "INV_REFS",
			      "stage %u refused (%d) with references owed %u", stage, rc, w->g_refs);
			if (w->failed)
				COV(SUPPRESSED);
			w->landed |= (__u8)(1U << i);
			a->pc = C_END;
			return;
		}
		CHECK(!w->failed && !w->p_gone, "INV_SUPPRESS",
		      "stage %u acquired a frame whose publication was suppressed", stage);
		CHECK(w->life.valid_len == w->data_len, "INV_STALE_MATCH",
		      "consumer read valid_len %u, the publication wrote %u",
		      w->life.valid_len, w->data_len);
		w->readers |= (__u8)(1U << i);
		w->g_busy |= bit;
		if (__builtin_popcount(w->g_busy) == 2)
			COV(BOTH_OUT);
		a->pc = C_SUBMIT;
		return;
	case C_SUBMIT:
		CHECK(!xdev_ext_mech_completion_begin(&w->comp[i], &a->ticket), "INV_PHASE",
		      "completion_begin failed");
		a->pc = C_CB_CLAIM;
		return;
	case C_CB_CLAIM:
		CHECK(!xdev_ext_mech_completion_claim(&w->comp[i], a->ticket), "INV_STALE_MATCH",
		      "the consumer's only callback lost its claim");
		a->pc = C_HANDOFF;
		return;
	case C_HANDOFF:
		/* The device finished reading; the callback releases the reference. */
		w->readers &= (__u8)~(1U << i);
		w->g_busy &= ~bit;
		if (consumer_fails(a)) {
			rc = m_fail_put(a->claim);
			/* No access between the CAS and here: the ghost follows it. */
			w->failed = 1;
			w->g_refs = (__u32)__builtin_popcount(w->g_busy);
			COV(FAIL_PUT);
		} else if (a->role == R_EXCL) {
			/* In-frame transform: same frame, new length, next consumer. */
			w->data_len = 900;
			rc = xdev_ext_mech_life_republish(&w->life, a->claim, 1, 900);
			w->g_refs = 1;
			w->republished = 1;
			COV(REPUBLISHED);
		} else {
			rc = m_put(a->claim);
			w->g_refs--;
		}
		CHECK(rc >= 0, "INV_STALE_MATCH", "hand-off of a live claim failed (%d)", rc);
		if (rc == XDEV_EXT_MECH_L_FREED)
			COV(FREED);
		else if (ST(raw()) == XDEV_EXT_MECH_L_READY && REFS(raw()))
			COV(READY_AGAIN);
		w->handed |= (__u8)(1U << i);
		w->late = a->claim;
		a->pc = C_CB_PUBLISH;
		return;
	case C_CB_PUBLISH:
		CHECK(!xdev_ext_mech_completion_publish(&w->comp[i], a->ticket,
							consumer_fails(a) ? -EIO : 0),
		      "INV_PHASE", "callback could not record its claim");
		a->pc = C_LAND;
		return;
	case C_LAND:
		CHECK(!xdev_ext_mech_completion_consume(&w->comp[i], a->ticket, &res),
		      "INV_STALE_MATCH", "worker could not consume the landed ticket");
		w->landed |= (__u8)(1U << i);
		a->pc = C_END;
		return;
	case C_END:
		if (++a->round < cfg.rounds && !w->exhausted) {
			a->pc = C_ACQUIRE;
			return;
		}
		a->done = 1;
		return;
	}
}

/* A second native callback for the producer's live ticket. */
static void dupcb_step(int i)
{
	struct actor *a = &S.a[i];
	struct world *w = &S.w;
	int p = 0;

	switch (a->pc) {
	case U_CLAIM:
		/* Possibly late: the ticket may have landed or been cancelled. */
		a->ticket = w->p_ticket;
		if (!a->ticket) {
			a->pc = U_END;
			a->done = 1;
			return;
		}
#ifdef REFS_MUTANT_PUBLISH_WITHOUT_CLAIM
		a->claim = S.a[p].claim;
		a->pc = U_HANDOFF;
		return;
#else
		if (xdev_ext_mech_completion_claim(&w->comp[p], a->ticket)) {
			COV(DUP_LOST);
			a->pc = U_END;
			a->done = 1;
			return;
		}
		CHECK(++w->owners == 1, "INV_STALE_MATCH", "ticket owned twice");
		a->won = 1;
		a->claim = S.a[p].claim;
		a->pc = U_HANDOFF;
		return;
#endif
	case U_HANDOFF:
		producer_handoff(a, true);
		a->pc = U_PUBLISH;
		return;
	case U_PUBLISH:
#ifdef REFS_MUTANT_PUBLISH_WITHOUT_CLAIM
		if (xdev_ext_mech_completion_claim(&w->comp[p], a->ticket)) {
			a->pc = U_END;
			a->done = 1;
			return;
		}
#endif
		CHECK(!xdev_ext_mech_completion_publish(&w->comp[p], a->ticket, 0), "INV_PHASE",
		      "duplicate owner could not record");
		a->pc = U_END;
		a->done = 1;
		return;
	}
}

static void stale_step(int i)
{
	struct actor *a = &S.a[i];
	struct world *w = &S.w;
	__u64 hp = w->hist_p, hc = w->hist_c;
	__u32 len = w->life.valid_len;

	switch (a->pc) {
	case S_OLD:
		w->stale_op = (__u8)(i + 1);
		CHECK(xdev_ext_mech_life_publish(&w->life, hp, 1, 999) < 0 &&
		      xdev_ext_mech_life_fail_produce(&w->life, hp) < 0 &&
		      xdev_ext_mech_life_rollback(&w->life, hp) < 0 &&
		      xdev_ext_mech_life_put(&w->life, hc) < 0 &&
		      xdev_ext_mech_life_fail_put(&w->life, hc) < 0 &&
		      xdev_ext_mech_life_rollback(&w->life, hc) < 0 &&
		      xdev_ext_mech_life_republish(&w->life, hc, 1, 999) < 0,
		      "INV_STALE_MATCH", "a claim of an earlier cycle won an edge");
		CHECK(access_mode || w->life.valid_len == len, "INV_STALE_MATCH",
		      "a stale claim changed valid_len");
		w->stale_op = 0;
		COV(STALE_REJECTED);
		a->pc = S_LATE;
		return;
	case S_LATE:
		/* Enabled once some consumer handed off: its completion again. */
		if (!w->late) {
			a->pc = S_END;
			a->done = 1;
			return;
		}
		w->stale_op = (__u8)(i + 1);
		CHECK(xdev_ext_mech_life_put(&w->life, w->late) < 0 &&
		      xdev_ext_mech_life_fail_put(&w->life, w->late) < 0,
		      "INV_STALE_MATCH", "a duplicate consumer completion was accepted");
		w->stale_op = 0;
		COV(LATE_REJECTED);
		a->pc = S_END;
		a->done = 1;
		return;
	}
}

static bool all_consumers_done(void)
{
	unsigned int i;

	for (i = 0; i < cfg.nr; i++)
		if (cfg.kinds[i] == K_CONSUMER && !S.a[i].done)
			return false;
	return true;
}

static bool enabled(int i)
{
	const struct actor *a = &S.a[i];
	const struct world *w = &S.w;

	if (a->done)
		return false;
	switch (a->kind) {
	case K_PRODUCER:
		if (a->pc == P_END && a->round + 1 < cfg.rounds)
			return round_over();
		if (a->pc == P_LAND)
			return (__atomic_load_n(&w->comp[i].ctrl, __ATOMIC_ACQUIRE) & 7) ==
			       XDEV_EXT_MECH_C_LANDED;
		return true;
	case K_CONSUMER:
		if (a->pc == C_ACQUIRE)
			return consumer_may_start(a);
		return true;
	case K_DUPCB:
		return a->pc != U_CLAIM || w->p_ticket || S.a[0].done;
	default:
		return a->pc != S_LATE || w->late || all_consumers_done();
	}
}

static void step(int i)
{
	switch (S.a[i].kind) {
	case K_PRODUCER: producer_step(i); break;
	case K_CONSUMER: consumer_step(i); break;
	case K_DUPCB: dupcb_step(i); break;
	default: stale_step(i); break;
	}
}

/* Between steps: the word against the ghost bookkeeping. */
static void check_state(void)
{
	const struct world *w = &S.w;
	__u64 v = raw();
	unsigned int j;

	/* Ghosts are updated next to each call: judge only between whole steps. */
	for (j = 0; access_mode && j < cfg.nr; j++)
		if (in_step[j])
			return;

	if (ST(v) == XDEV_EXT_MECH_L_READY || ST(v) == XDEV_EXT_MECH_L_OUT_PENDING) {
		CHECK(REFS(v) == w->g_refs, "INV_REFS", "word owes %u references, the chain %u",
		      REFS(v), w->g_refs);
		CHECK(BUSY(v) == w->g_busy, "INV_REFS", "word has stages %#x in flight, ghost %#x",
		      BUSY(v), w->g_busy);
	}
	if (ST(v) == XDEV_EXT_MECH_L_FREE)
		CHECK(!w->readers && !w->writer, "INV_EARLY_REUSE",
		      "FREE with devices active (readers %#x writer %u)", w->readers, w->writer);
}

static void check_final(void)
{
	const struct world *w = &S.w;
	__u64 v = raw();
	__u32 expect = w->claims - w->rollbacks;

	CHECK(ST(v) == XDEV_EXT_MECH_L_FREE, "INV_FINAL", "the run ended with the frame in state %u",
	      ST(v));
	CHECK(!w->readers && !w->writer, "INV_FINAL", "a device still accesses the frame");
	/* Exactly one recycle per claim a device saw; none for a rollback. */
	CHECK(w->recycles == expect && GEN(v) == w->gen0 + expect, "INV_FINAL",
	      "%u recycles to generation %llu from %llu, expected %u", w->recycles,
	      (unsigned long long)GEN(v), (unsigned long long)w->gen0, expect);
}

/* One finished cycle before the actors start, so stale claims exist. */
static void init_state(void)
{
	struct world *w = &S.w;
	__u64 p, c;
	unsigned int i;

	memset(&S, 0, sizeof(S));
	hooks_on = false;
	xdev_ext_mech_life_init(&w->life);
	for (i = 0; i < MAX_ACTORS; i++)
		xdev_ext_mech_completion_init(&w->comp[i]);
	w->life.ctrl = (cfg.seed ? cfg.seed - 1 : 0) << XDEV_EXT_MECH_L_GEN_SHIFT;
	if (xdev_ext_mech_life_claim(&w->life, 0, &p) ||
	    xdev_ext_mech_life_publish(&w->life, p, 1, 7) ||
	    xdev_ext_mech_life_acquire(&w->life, 1, 0, &c) ||
	    xdev_ext_mech_life_put(&w->life, c) != XDEV_EXT_MECH_L_FREED)
		abort();
	w->hist_p = p;
	w->hist_c = c;
	w->last_ctrl = w->life.ctrl;
	w->gen0 = GEN(w->life.ctrl);
	w->data_len = 7;
	for (i = 0; i < cfg.nr; i++) {
		S.a[i].kind = cfg.kinds[i];
		S.a[i].role = cfg.roles[i];
	}
	hooks_on = true;
}

/* ---- op granularity: exhaustive stateful search ---- */

struct visited {
	struct state *slot;
	unsigned char *used;
	size_t cap, n;
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

struct decision { __u8 n, chosen, cur_first, preempt_before; };

static ucontext_t sched_uc, actor_uc[MAX_ACTORS];
static char *stacks[MAX_ACTORS];
static __u8 started[MAX_ACTORS];
static struct decision dec[MAX_DECISIONS];
static __u8 prefix[MAX_DECISIONS];
static unsigned int prefix_len, ndec, preempt_bound = 2;
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
		swapcontext(&actor_uc[i], &sched_uc);
	}
	running = -1;
}

static void actor_entry(unsigned int i)
{
	actor_main((int)i);
}

static void run_once(void)
{
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
		if (current >= 0 && !S.a[current].done && (in_step[current] || enabled(current)))
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
	__u8 roles[MAX_ACTORS];
	__u8 nr, refs, rounds;
	unsigned int faults;
	bool access;		/* also run the access-granularity search */
};

#define FB(f) (1U << (f))
#define P K_PRODUCER
#define C K_CONSUMER
static const struct scenario scenarios[] = {
	/* NVMe READ -> {NVMe WRITE, AF_XDP TX} -> dependent stage. */
	{ "fanout+dependent", { P, C, C, C }, { 0, R_LEAD, R_FAN, R_DEP }, 4, 3, 1,
	  FB(F_NONE) | FB(F_FAIL_LEAD) | FB(F_FAIL_FAN) | FB(F_FAIL_PRODUCE) | FB(F_REFUSE), true },
	{ "fanout+stale", { P, C, C, K_STALE }, { 0, R_LEAD, R_FAN, 0 }, 4, 2, 1,
	  FB(F_NONE) | FB(F_FAIL_FAN), true },
	{ "producer+duplicate-callback+consumer", { P, K_DUPCB, C }, { 0, 0, R_LEAD }, 3, 1, 1,
	  FB(F_NONE) | FB(F_FAIL_PRODUCE) | FB(F_REFUSE), true },
	/* NVMe READ -> CPU in-frame transform -> next native stage. */
	{ "transform+after", { P, C, C }, { 0, R_EXCL, R_AFTER }, 3, 1, 1,
	  FB(F_NONE) | FB(F_FAIL_EXCL), true },
	/* The batch reuses the recycled frame: exhaustion near the last generation. */
	{ "recycle", { P, C, K_STALE }, { 0, R_LEAD, 0 }, 3, 1, 2, FB(F_NONE), true },
};
#undef P
#undef C

static const __u64 seed_gap[] = { 0, 2, 1 };

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s [--mode op|access|both] [--preemptions N] [--scenario SUBSTRING]\n",
		prog);
	exit(2);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "mode", required_argument, NULL, 'm' },
		{ "preemptions", required_argument, NULL, 'p' },
		{ "scenario", required_argument, NULL, 's' },
		{ NULL, 0, NULL, 0 },
	};
	bool do_op = true, do_access = true;
	unsigned int sc, f, sd, i, n = 0;
	unsigned long long op_states = 0, op_trans = 0, op_finals = 0, ac_runs = 0, ac_finals = 0;
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
		case 's':
			filter = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}
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
				memcpy(cfg.roles, s->roles, sizeof(cfg.roles));
				cfg.nr = s->nr;
				cfg.refs = s->refs;
				cfg.rounds = s->rounds;
				cfg.fault = (enum fault)f;
				/* seed: generation of the actors' first claim, GEN_MAX - gap */
				cfg.seed = seed_gap[sd] ? XDEV_EXT_MECH_L_GEN_MAX - seed_gap[sd] + 1 : 0;
				if (do_op) {
					access_mode = false;
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
				if (do_access && s->access) {
					access_mode = true;
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
				printf("ok %u - %s fault=%s first_claim_gen=%s%llu op_states=%llu op_transitions=%llu op_final_states=%llu access_runs=%llu access_final_states=%llu\n",
				       ++n, s->name, fault_names[f], seed_gap[sd] ? "GEN_MAX-" : "",
				       (unsigned long long)(seed_gap[sd] ? seed_gap[sd] - 1 : 1),
				       st, tr, fi, ru, af);
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
	if (!filter && do_op && do_access) {
		for (i = 0; i < COV_NR; i++)
			if (!cov[i]) {
				printf("VACUOUS %s: no explored path reached this event\n", cov_names[i]);
				return 1;
			}
	}
	return 0;
}

#endif /* XDEV_EXT_MECH_LIFE_REFS */

// SPDX-License-Identifier: GPL-2.0
/*
 * Host tests of the frame lifecycle word as the design specifies it: four
 * data-plane states, consumer reference counts installed at publication,
 * concurrent fan-out consumers, a failed consumer suppressing later stages,
 * owner and generation on every claim, the generation advancing only when the
 * final reference recycles the frame, the in-frame transform's exclusive claim
 * and republication, and one write of the word per hand-off.
 *
 * The lifecycle header is compiled in its __KERNEL__ form over the model
 * shim (selftests/xdev_ext_mech/model/shim/linux/atomic.h), whose hooks let
 * this test count the atomic accesses of each call.  Build with
 * -I <kernel tree> -I model/shim -pthread.
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define __KERNEL__
#include "io_uring/xdev_ext_mech_lifecycle.h"
#undef __KERNEL__

#define CHECK(expr) do {                                                     \
	if (!(expr)) {                                                        \
		fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr);        \
		return false;                                                  \
	}                                                                     \
} while (0)

/* ---- hooks of shim/linux/atomic.h: per-thread access counters ---- */

static __thread const volatile void *watch;
static __thread unsigned int word_loads, word_writes, word_cas, other_writes;

void life_model_before(const volatile void *p, int kind)
{
	if (!watch)
		return;
	if (p == watch && kind == LIFE_MODEL_LOAD)
		word_loads++;
	if (p == watch && kind == LIFE_MODEL_CAS)
		word_cas++;
}

void life_model_after(const volatile void *p, int kind, bool wrote)
{
	(void)kind;
	if (!watch || !wrote)
		return;
	if (p == watch)
		word_writes++;
	else
		other_writes++;
}

#ifdef XDEV_EXT_MECH_LIFE_REFS

static void count_start(const struct xdev_ext_mech_life *l)
{
	watch = &l->ctrl;
	word_loads = word_writes = word_cas = other_writes = 0;
}

static void count_stop(void)
{
	watch = NULL;
}

#define STAGE_BIT(s) (1U << (s))

static __u64 raw(const struct xdev_ext_mech_life *l)
{
	return __atomic_load_n(&l->ctrl, __ATOMIC_ACQUIRE);
}

static bool unchanged(const struct xdev_ext_mech_life *l, __u64 ctrl, __u32 len)
{
	return raw(l) == ctrl && l->valid_len == len;
}

/* Packed state, busy mask, references, owner and generation fields. */
static __u64 word(__u64 gen, __u32 owner_tag1, __u32 refs, __u32 busy, __u32 state)
{
	return gen << XDEV_EXT_MECH_L_GEN_SHIFT |
	       (__u64)owner_tag1 << XDEV_EXT_MECH_L_OWNER_SHIFT |
	       (__u64)refs << XDEV_EXT_MECH_L_REFS_SHIFT |
	       (__u64)busy << XDEV_EXT_MECH_L_BUSY_SHIFT | state;
}

static bool well_formed(const struct xdev_ext_mech_life *l)
{
	__u64 w = raw(l);
	__u32 state = w & XDEV_EXT_MECH_L_STATE_MASK;
	__u32 busy = (w & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT;
	__u32 refs = (w & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT;
	__u32 owner = (w & XDEV_EXT_MECH_L_OWNER_MASK) >> XDEV_EXT_MECH_L_OWNER_SHIFT;

	if (refs > XDEV_EXT_MECH_L_REFS_MAX || owner > XDEV_EXT_MECH_L_OWNER_MAX + 1)
		return false;
	switch (state) {
	case XDEV_EXT_MECH_L_FREE:
		return !busy && !refs && !owner;
	case XDEV_EXT_MECH_L_IO_PENDING:
		return !busy && !refs && owner;
	case XDEV_EXT_MECH_L_READY:
		return !busy && !owner;
	default:
		return busy && (__u32)__builtin_popcount(busy) <= refs;
	}
}

/* A READY publication at the frame's current generation. */
static bool ready(struct xdev_ext_mech_life *l, __u32 refs, __u32 len, __u64 *claim)
{
	return !xdev_ext_mech_life_claim(l, 0, claim) &&
	       !xdev_ext_mech_life_publish(l, *claim, refs, len) &&
	       xdev_ext_mech_life_phase(l) == XDEV_EXT_MECH_L_READY;
}

static bool test_four_states_only(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, c;

	CHECK(XDEV_EXT_MECH_L_FREE == 0 && XDEV_EXT_MECH_L_IO_PENDING == 1 &&
	      XDEV_EXT_MECH_L_READY == 2 && XDEV_EXT_MECH_L_OUT_PENDING == 3);
	CHECK(XDEV_EXT_MECH_L_STATE_MASK == 3);
	CHECK(XDEV_EXT_MECH_L_GEN_SHIFT == 12);
	CHECK(XDEV_EXT_MECH_L_GEN_MAX == (~(__u64)0) >> 12);
	CHECK(XDEV_EXT_MECH_L_REFS_MAX == 4);
	xdev_ext_mech_life_init(&l);
	CHECK(raw(&l) == 0 && l.valid_len == 0);
	CHECK(xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_FREE);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_IO_PENDING);
	CHECK((raw(&l) & XDEV_EXT_MECH_L_STATE_MASK) == XDEV_EXT_MECH_L_IO_PENDING);
	CHECK(well_formed(&l));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 1, 64));
	CHECK(xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_READY);
	CHECK(well_formed(&l));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &c));
	CHECK(xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_OUT_PENDING);
	CHECK((raw(&l) & XDEV_EXT_MECH_L_STATE_MASK) == XDEV_EXT_MECH_L_OUT_PENDING);
	CHECK(well_formed(&l));
	CHECK(xdev_ext_mech_life_put(&l, c) == XDEV_EXT_MECH_L_FREED);
	CHECK(xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_FREE);
	CHECK(well_formed(&l));
	return true;
}

static bool test_claim_records_owner_and_generation(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, other, w;

	xdev_ext_mech_life_init(&l);
	l.ctrl = word(41, 0, 0, 0, XDEV_EXT_MECH_L_FREE);
	CHECK(xdev_ext_mech_life_claim(&l, XDEV_EXT_MECH_L_OWNER_MAX + 1, &p) == -EINVAL);
	CHECK(unchanged(&l, word(41, 0, 0, 0, 0), 0));
	CHECK(!xdev_ext_mech_life_claim(&l, 2, &p));
	CHECK(p != 0);
	/* The claim names its owner; the generation does not move at a claim. */
	CHECK(xdev_ext_mech_life_gen(&l) == 41);
	CHECK(xdev_ext_mech_life_owner(&l) == 2);
	CHECK(xdev_ext_mech_life_claim_gen(p) == 41);
	CHECK(xdev_ext_mech_life_claim_owner(p) == 2);
	CHECK(raw(&l) == word(41, 3, 0, 0, XDEV_EXT_MECH_L_IO_PENDING));
	CHECK(p == (41ULL << 12 | 3ULL << 9 | XDEV_EXT_MECH_L_CLAIM_PRODUCE));
	w = raw(&l);
	CHECK(xdev_ext_mech_life_claim(&l, 2, &other) == -EBUSY);
	CHECK(xdev_ext_mech_life_claim(&l, 0, &other) == -EBUSY);
	CHECK(unchanged(&l, w, 0));
	/* A START publication has its own owner tag. */
	xdev_ext_mech_life_init(&l);
	CHECK(!xdev_ext_mech_life_claim(&l, XDEV_EXT_MECH_L_OWNER_START, &p));
	CHECK(xdev_ext_mech_life_owner(&l) == XDEV_EXT_MECH_L_OWNER_START);
	CHECK(xdev_ext_mech_life_claim_owner(p) == XDEV_EXT_MECH_L_OWNER_START);
	CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 9));
	CHECK(xdev_ext_mech_life_owner(&l) == XDEV_EXT_MECH_L_NO_OWNER);
	return true;
}

static bool test_publish_installs_references(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, w;

	xdev_ext_mech_life_init(&l);
	l.ctrl = word(7, 0, 0, 0, 0);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	w = raw(&l);
	CHECK(xdev_ext_mech_life_publish(&l, p, XDEV_EXT_MECH_L_REFS_MAX + 1, 5) == -EINVAL);
	CHECK(unchanged(&l, w, 0));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 4093));
	CHECK(raw(&l) == word(7, 0, 2, 0, XDEV_EXT_MECH_L_READY));
	CHECK(l.valid_len == 4093);
	CHECK(xdev_ext_mech_life_refs(&l) == 2);
	CHECK(xdev_ext_mech_life_busy(&l) == 0);
	CHECK(xdev_ext_mech_life_gen(&l) == 7);
	/* A duplicate publication of the same claim changes nothing. */
	w = raw(&l);
	CHECK(xdev_ext_mech_life_publish(&l, p, 1, 1) == -ESTALE);
	CHECK(unchanged(&l, w, 4093));
	/* refs 0: end of chain, no consumer can take it, release recycles it. */
	xdev_ext_mech_life_init(&l);
	CHECK(ready(&l, 0, 10, &p));
	CHECK(xdev_ext_mech_life_refs(&l) == 0);
	CHECK(xdev_ext_mech_life_acquire(&l, 1, 0, &w) == -ENOENT);
	CHECK(xdev_ext_mech_life_acquire(&l, 1, XDEV_EXT_MECH_L_ACQ_FANOUT, &w) == -ENOENT);
	CHECK(raw(&l) == word(0, 0, 0, 0, XDEV_EXT_MECH_L_READY));
	return true;
}

static bool test_fanout_two_consumers(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, a, b, c;

	xdev_ext_mech_life_init(&l);
	l.ctrl = word(3, 0, 0, 0, 0);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 8192));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	CHECK(raw(&l) == word(3, 0, 2, STAGE_BIT(1), XDEV_EXT_MECH_L_OUT_PENDING));
	/* Joining a publication that is already out needs the fan-out flag. */
	CHECK(xdev_ext_mech_life_acquire(&l, 2, 0, &b) == -EBUSY);
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &b));
	CHECK(raw(&l) == word(3, 0, 2, STAGE_BIT(1) | STAGE_BIT(2),
			     XDEV_EXT_MECH_L_OUT_PENDING));
	CHECK(xdev_ext_mech_life_claim_owner(a) == 1 && xdev_ext_mech_life_claim_owner(b) == 2);
	CHECK(xdev_ext_mech_life_claim_gen(a) == 3 && xdev_ext_mech_life_claim_gen(b) == 3);
	/* Both references are taken: a third consumer has none left. */
	CHECK(xdev_ext_mech_life_acquire(&l, 3, XDEV_EXT_MECH_L_ACQ_FANOUT, &c) == -ENOENT);
	CHECK(xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &c) == -EALREADY);
	CHECK(l.valid_len == 8192);
	/* The second completion to arrive drops the final reference, either order. */
	CHECK(xdev_ext_mech_life_put(&l, b) == XDEV_EXT_MECH_L_KEPT);
	CHECK(raw(&l) == word(3, 0, 1, STAGE_BIT(1), XDEV_EXT_MECH_L_OUT_PENDING));
	CHECK(xdev_ext_mech_life_put(&l, a) == XDEV_EXT_MECH_L_FREED);
	CHECK(raw(&l) == word(4, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	return true;
}

static bool test_dependent_consumer_after_fanout(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, a, b, c, w;

	xdev_ext_mech_life_init(&l);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 3, 700));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &b));
	w = raw(&l);
	/* A later, dependent stage waits while the fan-out group is out. */
	CHECK(xdev_ext_mech_life_acquire(&l, 3, 0, &c) == -EBUSY);
	CHECK(unchanged(&l, w, 700));
	CHECK(xdev_ext_mech_life_put(&l, a) == XDEV_EXT_MECH_L_KEPT);
	CHECK(xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_OUT_PENDING);
	CHECK(xdev_ext_mech_life_put(&l, b) == XDEV_EXT_MECH_L_KEPT);
	/* References remain and nobody is in flight: READY again. */
	CHECK(raw(&l) == word(0, 0, 1, 0, XDEV_EXT_MECH_L_READY));
	CHECK(!xdev_ext_mech_life_acquire(&l, 3, 0, &c));
	CHECK(l.valid_len == 700);
	CHECK(xdev_ext_mech_life_put(&l, c) == XDEV_EXT_MECH_L_FREED);
	CHECK(raw(&l) == word(1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	return true;
}

static bool test_failed_consumer_suppresses_dependents(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, a, b, c, w;

	/* Failure while the sibling is still out: it finishes, nothing follows. */
	xdev_ext_mech_life_init(&l);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 3, 64));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &b));
	CHECK(xdev_ext_mech_life_fail_put(&l, a) == XDEV_EXT_MECH_L_KEPT);
	CHECK(raw(&l) == word(0, 0, 1, STAGE_BIT(2), XDEV_EXT_MECH_L_OUT_PENDING));
	CHECK(xdev_ext_mech_life_fail_put(&l, a) == -ESTALE);
	CHECK(xdev_ext_mech_life_put(&l, b) == XDEV_EXT_MECH_L_FREED);
	CHECK(raw(&l) == word(1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	CHECK(xdev_ext_mech_life_acquire(&l, 3, 0, &c) == -EBUSY);
	CHECK(xdev_ext_mech_life_acquire(&l, 3, XDEV_EXT_MECH_L_ACQ_FANOUT, &c) == -EBUSY);

	/* Failure before the sibling acquired: the whole publication ends. */
	xdev_ext_mech_life_init(&l);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 3, 64));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	CHECK(xdev_ext_mech_life_fail_put(&l, a) == XDEV_EXT_MECH_L_FREED);
	CHECK(raw(&l) == word(1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	CHECK(xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &b) == -EBUSY);

	/* Failure of a sibling while a third reference remains not yet taken. */
	xdev_ext_mech_life_init(&l);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 3, 64));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &b));
	CHECK(xdev_ext_mech_life_put(&l, b) == XDEV_EXT_MECH_L_KEPT);
	CHECK(xdev_ext_mech_life_fail_put(&l, a) == XDEV_EXT_MECH_L_FREED);
	w = raw(&l);
	CHECK(w == word(1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	CHECK(xdev_ext_mech_life_acquire(&l, 3, 0, &c) == -EBUSY);
	CHECK(unchanged(&l, w, 64));
	return true;
}

static bool test_generation_moves_only_at_final_release(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, a, b;

	xdev_ext_mech_life_init(&l);
	l.ctrl = word(100, 0, 0, 0, 0);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(xdev_ext_mech_life_gen(&l) == 100);
	CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 1));
	CHECK(xdev_ext_mech_life_gen(&l) == 100);
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	CHECK(xdev_ext_mech_life_gen(&l) == 100);
	CHECK(xdev_ext_mech_life_put(&l, a) == XDEV_EXT_MECH_L_KEPT);
	CHECK(xdev_ext_mech_life_gen(&l) == 100);
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, 0, &b));
	CHECK(xdev_ext_mech_life_gen(&l) == 100);
	CHECK(xdev_ext_mech_life_put(&l, b) == XDEV_EXT_MECH_L_FREED);
	CHECK(xdev_ext_mech_life_gen(&l) == 101);
	/* An accepted producer failure ends the claim: +1. */
	CHECK(!xdev_ext_mech_life_claim(&l, 1, &p));
	CHECK(!xdev_ext_mech_life_fail_produce(&l, p));
	CHECK(raw(&l) == word(102, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	CHECK(xdev_ext_mech_life_fail_produce(&l, p) == -ESTALE);
	/* A refusal no device saw restores the word exactly: no increment. */
	CHECK(!xdev_ext_mech_life_claim(&l, 1, &p));
	CHECK(!xdev_ext_mech_life_rollback(&l, p));
	CHECK(raw(&l) == word(102, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	/* release of an unconsumed publication: +1. */
	CHECK(ready(&l, 2, 5, &p));
	CHECK(!xdev_ext_mech_life_release(&l, 102));
	CHECK(raw(&l) == word(103, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	return true;
}

static bool test_stale_owner_and_generation_rejected(void)
{
	struct xdev_ext_mech_life l;
	__u64 p0, a0, p1, a1, forged, w;

	xdev_ext_mech_life_init(&l);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p0));
	CHECK(!xdev_ext_mech_life_publish(&l, p0, 1, 111));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a0));
	CHECK(xdev_ext_mech_life_put(&l, a0) == XDEV_EXT_MECH_L_FREED);
	/* The same stages claim the recycled frame for the next operation. */
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p1));
	CHECK(xdev_ext_mech_life_claim_owner(p1) == xdev_ext_mech_life_claim_owner(p0));
	CHECK(xdev_ext_mech_life_claim_gen(p1) == xdev_ext_mech_life_claim_gen(p0) + 1);
	w = raw(&l);
	CHECK(xdev_ext_mech_life_publish(&l, p0, 1, 999) == -ESTALE);
	CHECK(xdev_ext_mech_life_fail_produce(&l, p0) == -ESTALE);
	CHECK(xdev_ext_mech_life_rollback(&l, p0) == -ESTALE);
	CHECK(xdev_ext_mech_life_put(&l, a0) == -ESTALE);
	CHECK(xdev_ext_mech_life_fail_put(&l, a0) == -ESTALE);
	/* Right generation, wrong owner. */
	forged = (p1 & ~(__u64)XDEV_EXT_MECH_L_OWNER_MASK) | 2ULL << XDEV_EXT_MECH_L_OWNER_SHIFT;
	CHECK(xdev_ext_mech_life_publish(&l, forged, 1, 999) == -ESTALE);
	CHECK(xdev_ext_mech_life_fail_produce(&l, forged) == -ESTALE);
	/* Right generation and owner, wrong kind. */
	forged = (p1 & ~(__u64)3) | XDEV_EXT_MECH_L_CLAIM_SHARED;
	CHECK(xdev_ext_mech_life_publish(&l, forged, 1, 999) == -ESTALE);
	CHECK(xdev_ext_mech_life_publish(&l, 0, 1, 999) == -ESTALE);
	CHECK(unchanged(&l, w, 111));
	CHECK(!xdev_ext_mech_life_publish(&l, p1, 1, 222));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a1));
	w = raw(&l);
	/* An old consumer claim of the same stage, and a wrong-stage claim. */
	CHECK(xdev_ext_mech_life_put(&l, a0) == -ESTALE);
	forged = (a1 & ~(__u64)XDEV_EXT_MECH_L_OWNER_MASK) | 3ULL << XDEV_EXT_MECH_L_OWNER_SHIFT;
	CHECK(xdev_ext_mech_life_put(&l, forged) == -ESTALE);
	CHECK(xdev_ext_mech_life_fail_put(&l, forged) == -ESTALE);
	CHECK(xdev_ext_mech_life_rollback(&l, forged) == -ESTALE);
	CHECK(xdev_ext_mech_life_republish(&l, a1, 1, 5) == -ESTALE);
	CHECK(xdev_ext_mech_life_put(&l, 0) == -ESTALE);
	CHECK(xdev_ext_mech_life_release(&l, xdev_ext_mech_life_gen(&l)) == -EBUSY);
	CHECK(unchanged(&l, w, 222));
	CHECK(xdev_ext_mech_life_put(&l, a1) == XDEV_EXT_MECH_L_FREED);
	CHECK(xdev_ext_mech_life_put(&l, a1) == -ESTALE);
	return true;
}

static bool test_no_ready_to_io_pending_edge(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, h2d, d2h, w;

	/* Chain a: NVMe READ -> CE H2D -> CE D2H -> NVMe WRITE on one frame. */
	xdev_ext_mech_life_init(&l);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 1, 8192));
	w = raw(&l);
	/* A producer never overwrites a published frame. */
	CHECK(xdev_ext_mech_life_claim(&l, 2, &d2h) == -EBUSY);
	CHECK(unchanged(&l, w, 8192));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &h2d));
	w = raw(&l);
	CHECK(xdev_ext_mech_life_claim(&l, 2, &d2h) == -EBUSY);
	CHECK(unchanged(&l, w, 8192));
	CHECK(xdev_ext_mech_life_put(&l, h2d) == XDEV_EXT_MECH_L_FREED);
	/* Only after the last reference dropped: FREE -> IO_PENDING. */
	CHECK(!xdev_ext_mech_life_claim(&l, 2, &d2h));
	CHECK(raw(&l) == word(1, 3, 0, 0, XDEV_EXT_MECH_L_IO_PENDING));
	CHECK(!xdev_ext_mech_life_publish(&l, d2h, 1, 4096));
	CHECK(raw(&l) == word(1, 0, 1, 0, XDEV_EXT_MECH_L_READY));
	CHECK(l.valid_len == 4096);
	return true;
}

static bool test_rollback_is_exact_inverse(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, a, b, x, before;

	xdev_ext_mech_life_init(&l);
	l.ctrl = word(9, 0, 0, 0, 0);
	before = raw(&l);
	CHECK(!xdev_ext_mech_life_claim(&l, 1, &p));
	CHECK(!xdev_ext_mech_life_rollback(&l, p));
	CHECK(raw(&l) == before);
	CHECK(xdev_ext_mech_life_rollback(&l, p) == -ESTALE);
	CHECK(!xdev_ext_mech_life_claim(&l, 1, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 32));
	before = raw(&l);
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, 0, &a));
	CHECK(!xdev_ext_mech_life_rollback(&l, a));
	CHECK(unchanged(&l, before, 32));
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, 0, &a));
	before = raw(&l);
	CHECK(!xdev_ext_mech_life_acquire(&l, 3, XDEV_EXT_MECH_L_ACQ_FANOUT, &b));
	CHECK(!xdev_ext_mech_life_rollback(&l, b));
	CHECK(unchanged(&l, before, 32));
	CHECK(!xdev_ext_mech_life_rollback(&l, a));
	CHECK(raw(&l) == word(9, 0, 2, 0, XDEV_EXT_MECH_L_READY));
	/* Exclusive needs the last reference. */
	CHECK(xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_EXCLUSIVE, &x) == -EBUSY);
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, 0, &a));
	CHECK(xdev_ext_mech_life_put(&l, a) == XDEV_EXT_MECH_L_KEPT);
	before = raw(&l);
	CHECK(!xdev_ext_mech_life_acquire(&l, 3, XDEV_EXT_MECH_L_ACQ_EXCLUSIVE, &x));
	CHECK(!xdev_ext_mech_life_rollback(&l, x));
	CHECK(unchanged(&l, before, 32));
	return true;
}

static bool test_exclusive_transform_republishes_same_frame(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, x, s, d, w;

	xdev_ext_mech_life_init(&l);
	l.ctrl = word(20, 0, 0, 0, 0);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 1, 100));
	CHECK(xdev_ext_mech_life_acquire(&l, 1, XDEV_EXT_MECH_L_ACQ_EXCLUSIVE |
					 XDEV_EXT_MECH_L_ACQ_FANOUT, &x) == -EINVAL);
	CHECK(xdev_ext_mech_life_acquire(&l, 4, XDEV_EXT_MECH_L_ACQ_EXCLUSIVE, &x) == -EINVAL);
	CHECK(xdev_ext_mech_life_acquire(&l, 1, 1U << 7, &x) == -EINVAL);
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, XDEV_EXT_MECH_L_ACQ_EXCLUSIVE, &x));
	CHECK(raw(&l) == word(20, 2, 1, STAGE_BIT(1), XDEV_EXT_MECH_L_OUT_PENDING));
	CHECK(xdev_ext_mech_life_owner(&l) == 1);
	CHECK(xdev_ext_mech_life_claim_owner(x) == 1);
	CHECK((x & 3) == XDEV_EXT_MECH_L_CLAIM_EXCLUSIVE);
	/* Nobody joins an exclusive claim. */
	CHECK(xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &s) == -ENOENT);
	CHECK(xdev_ext_mech_life_acquire(&l, 2, 0, &s) == -EBUSY);
	w = raw(&l);
	CHECK(xdev_ext_mech_life_republish(&l, x, XDEV_EXT_MECH_L_REFS_MAX + 1, 104) == -EINVAL);
	CHECK(unchanged(&l, w, 100));
	/* Same frame, new valid length, next consumer: generation unchanged. */
	CHECK(!xdev_ext_mech_life_republish(&l, x, 2, 104));
	CHECK(raw(&l) == word(20, 0, 2, 0, XDEV_EXT_MECH_L_READY));
	CHECK(l.valid_len == 104);
	CHECK(xdev_ext_mech_life_republish(&l, x, 1, 108) == -ESTALE);
	CHECK(l.valid_len == 104);
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, 0, &d));
	CHECK(xdev_ext_mech_life_republish(&l, d, 1, 1) == -ESTALE);
	CHECK(xdev_ext_mech_life_put(&l, d) == XDEV_EXT_MECH_L_KEPT);
	CHECK(!xdev_ext_mech_life_acquire(&l, 3, 0, &d));
	CHECK(xdev_ext_mech_life_put(&l, d) == XDEV_EXT_MECH_L_FREED);
	CHECK(raw(&l) == word(21, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	/* A transform that fails releases its exclusive reference like a consumer. */
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 50));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &s));
	CHECK(xdev_ext_mech_life_put(&l, s) == XDEV_EXT_MECH_L_KEPT);
	CHECK(!xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_EXCLUSIVE, &x));
	CHECK(xdev_ext_mech_life_fail_put(&l, x) == XDEV_EXT_MECH_L_FREED);
	CHECK(raw(&l) == word(22, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	return true;
}

static bool test_destination_frame_is_a_producer(void)
{
	struct xdev_ext_mech_life src, dst;
	__u64 p, s, d, other;

	/* A variable-output transform: source consumed, destination produced. */
	xdev_ext_mech_life_init(&src);
	xdev_ext_mech_life_init(&dst);
	CHECK(!xdev_ext_mech_life_claim(&src, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&src, p, 1, 4096));
	CHECK(!xdev_ext_mech_life_acquire(&src, 1, 0, &s));
	CHECK(!xdev_ext_mech_life_claim(&dst, 1, &d));
	CHECK(xdev_ext_mech_life_claim(&dst, 1, &other) == -EBUSY);
	CHECK(!xdev_ext_mech_life_publish(&dst, d, 1, 1234));
	CHECK(xdev_ext_mech_life_put(&src, s) == XDEV_EXT_MECH_L_FREED);
	CHECK(raw(&dst) == word(0, 0, 1, 0, XDEV_EXT_MECH_L_READY));
	CHECK(dst.valid_len == 1234);
	/* Output that does not fit fails the destination producer, never READY. */
	CHECK(!xdev_ext_mech_life_claim(&src, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&src, p, 1, 4096));
	CHECK(!xdev_ext_mech_life_acquire(&src, 1, 0, &s));
	xdev_ext_mech_life_init(&dst);
	CHECK(!xdev_ext_mech_life_claim(&dst, 1, &d));
	CHECK(!xdev_ext_mech_life_fail_produce(&dst, d));
	CHECK(xdev_ext_mech_life_fail_put(&src, s) == XDEV_EXT_MECH_L_FREED);
	CHECK(raw(&dst) == word(1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	return true;
}

static bool test_release_rules(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, a, w;

	xdev_ext_mech_life_init(&l);
	CHECK(xdev_ext_mech_life_release(&l, 0) == -ENOENT);
	CHECK(raw(&l) == 0);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	w = raw(&l);
	CHECK(xdev_ext_mech_life_release(&l, 0) == -EBUSY);
	CHECK(unchanged(&l, w, 0));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 3));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	w = raw(&l);
	CHECK(xdev_ext_mech_life_release(&l, 0) == -EBUSY);
	CHECK(unchanged(&l, w, 3));
	CHECK(xdev_ext_mech_life_put(&l, a) == XDEV_EXT_MECH_L_KEPT);
	w = raw(&l);
	CHECK(xdev_ext_mech_life_release(&l, 1) == -ESTALE);
	CHECK(unchanged(&l, w, 3));
	/* Abort with a reference still owed and nobody in flight. */
	CHECK(!xdev_ext_mech_life_release(&l, 0));
	CHECK(raw(&l) == word(1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	/* The state is checked first: FREE is -ENOENT for any generation. */
	CHECK(xdev_ext_mech_life_release(&l, 0) == -ENOENT);
	CHECK(xdev_ext_mech_life_release(&l, 1) == -ENOENT);
	CHECK(raw(&l) == word(1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	return true;
}

static bool test_generation_exhaustion(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, a, w;

	xdev_ext_mech_life_init(&l);
	l.ctrl = word(XDEV_EXT_MECH_L_GEN_MAX - 1, 0, 0, 0, 0);
	l.valid_len = 91;
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 1, 92));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	CHECK(xdev_ext_mech_life_put(&l, a) == XDEV_EXT_MECH_L_FREED);
	CHECK(xdev_ext_mech_life_gen(&l) == XDEV_EXT_MECH_L_GEN_MAX);
	w = raw(&l);
	CHECK(w == word(XDEV_EXT_MECH_L_GEN_MAX, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	/* The last generation is never claimed: no wrap to a matching old claim. */
	CHECK(xdev_ext_mech_life_claim(&l, 0, &p) == -EOVERFLOW);
	CHECK(unchanged(&l, w, 92));
	xdev_ext_mech_life_init(&l);
	l.ctrl = word(XDEV_EXT_MECH_L_GEN_MAX - 1, 0, 0, 0, 0);
	CHECK(!xdev_ext_mech_life_claim(&l, 3, &p));
	CHECK(!xdev_ext_mech_life_fail_produce(&l, p));
	CHECK(xdev_ext_mech_life_claim(&l, 3, &p) == -EOVERFLOW);
	return true;
}

static bool test_frame_record(void)
{
	struct xdev_ext_mech_life l;
	struct xdev_ext_mech_frame_rec r;
	__u64 p, a;

	xdev_ext_mech_life_init(&l);
	l.ctrl = word(77, 0, 0, 0, 0);
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 1500));
	CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
	memset(&r, 0xa5, sizeof(r));
	xdev_ext_mech_frame_rec_fill(&r, &l, 5, 4096, 256, 12, 0x13, 0x2, true);
	CHECK(r.pool_off == 5 * 4096);
	CHECK(r.page_pos == (256 + 5 * 4096) >> 12);
	CHECK(r.frame_size == 4096);
	CHECK(r.valid_len == 1500);
	CHECK(r.state == XDEV_EXT_MECH_L_OUT_PENDING);
	CHECK(r.refs == 2 && r.busy == STAGE_BIT(1));
	CHECK(r.owner == XDEV_EXT_MECH_L_NO_OWNER);
	CHECK(r.gen == 77);
	CHECK(r.binding == 0x13 && r.dma == 0x2 && r.closing == 1);
	xdev_ext_mech_frame_rec_fill(&r, &l, 0, 65536, 0, 12, 0, 0, false);
	CHECK(r.pool_off == 0 && r.page_pos == 0 && r.closing == 0);
	return true;
}

/* Each successful hand-off is one write of the word, by one CAS. */
static bool cost(const struct xdev_ext_mech_life *l, int ret, int want,
		 unsigned int writes)
{
	unsigned int w = word_writes, c = word_cas, o = other_writes;

	count_stop();
	if (ret != want || w != writes || c != writes || o) {
		fprintf(stderr, "ret %d (want %d) word writes %u cas %u other atomic writes %u (want %u)\n",
			ret, want, w, c, o, writes);
		return false;
	}
	(void)l;
	return true;
}

static bool test_one_atomic_update_per_handoff(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, a, b, x;

	xdev_ext_mech_life_init(&l);
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_claim(&l, 0, &p), 0, 1));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_publish(&l, p, 2, 512), 0, 1));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_acquire(&l, 1, 0, &a), 0, 1));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &b), 0, 1));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_put(&l, a), XDEV_EXT_MECH_L_KEPT, 1));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_put(&l, b), XDEV_EXT_MECH_L_FREED, 1));
	/* Refusals write nothing. */
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_put(&l, b), -ESTALE, 0));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_publish(&l, p, 1, 1), -ESTALE, 0));
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_acquire(&l, 1, 0, &a), -EBUSY, 0));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_fail_produce(&l, p), 0, 1));
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_rollback(&l, p), 0, 1));
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 1, 64));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_acquire(&l, 1, XDEV_EXT_MECH_L_ACQ_EXCLUSIVE, &x), 0, 1));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_republish(&l, x, 1, 68), 0, 1));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_acquire(&l, 2, 0, &a), 0, 1));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_fail_put(&l, a), XDEV_EXT_MECH_L_FREED, 1));
	CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
	CHECK(!xdev_ext_mech_life_publish(&l, p, 0, 64));
	count_start(&l);
	CHECK(cost(&l, xdev_ext_mech_life_release(&l, xdev_ext_mech_life_gen(&l)), 0, 1));
	/* An accessor is a single acquire load and no write. */
	count_start(&l);
	(void)xdev_ext_mech_life_refs(&l);
	CHECK(word_loads == 1 && !word_writes && !word_cas);
	count_stop();
	return true;
}

/* ---- concurrent hand-offs ---- */

#define RACE_ROUNDS 2000
#define DUP_RACERS 8

struct fan_racer {
	pthread_barrier_t *start, *mid;
	struct xdev_ext_mech_life *l;
	__u32 stage;
	__u64 claim;
	int acq, put;
};

static void *fan_race(void *arg)
{
	struct fan_racer *r = arg;

	pthread_barrier_wait(r->start);
	r->acq = xdev_ext_mech_life_acquire(r->l, r->stage, XDEV_EXT_MECH_L_ACQ_FANOUT,
					    &r->claim);
	pthread_barrier_wait(r->mid);
	r->put = r->acq ? -1 : xdev_ext_mech_life_put(r->l, r->claim);
	return NULL;
}

static bool test_race_fanout_final_decrement_once(void)
{
	struct xdev_ext_mech_life l;
	pthread_barrier_t start, mid;
	struct fan_racer r[2];
	pthread_t t[2];
	unsigned int round, i, freed;
	__u64 p, gen;

	CHECK(!pthread_barrier_init(&start, NULL, 2));
	CHECK(!pthread_barrier_init(&mid, NULL, 2));
	xdev_ext_mech_life_init(&l);
	for (round = 0; round < RACE_ROUNDS; round++) {
		gen = xdev_ext_mech_life_gen(&l);
		CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
		CHECK(!xdev_ext_mech_life_publish(&l, p, 2, round + 1));
		for (i = 0; i < 2; i++) {
			r[i] = (struct fan_racer){ &start, &mid, &l, i + 1, 0, 0, 0 };
			CHECK(!pthread_create(&t[i], NULL, fan_race, &r[i]));
		}
		freed = 0;
		for (i = 0; i < 2; i++) {
			CHECK(!pthread_join(t[i], NULL));
			CHECK(r[i].acq == 0);
			CHECK(r[i].put == XDEV_EXT_MECH_L_KEPT || r[i].put == XDEV_EXT_MECH_L_FREED);
			freed += r[i].put == XDEV_EXT_MECH_L_FREED;
		}
		CHECK(freed == 1);
		CHECK(raw(&l) == word(gen + 1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	}
	CHECK(!pthread_barrier_destroy(&start));
	CHECK(!pthread_barrier_destroy(&mid));
	return true;
}

struct dup_racer {
	pthread_barrier_t *start;
	struct xdev_ext_mech_life *l;
	__u64 claim;
	int ret;
};

static void *dup_race(void *arg)
{
	struct dup_racer *r = arg;

	pthread_barrier_wait(r->start);
	r->ret = xdev_ext_mech_life_put(r->l, r->claim);
	return NULL;
}

/* Duplicate completions of one consumer: one decrement, never two. */
static bool test_race_duplicate_put(void)
{
	struct xdev_ext_mech_life l;
	pthread_barrier_t start;
	struct dup_racer r[DUP_RACERS];
	pthread_t t[DUP_RACERS];
	unsigned int round, i, wins;
	__u64 p, a, b;

	CHECK(!pthread_barrier_init(&start, NULL, DUP_RACERS));
	for (round = 0; round < RACE_ROUNDS / 8; round++) {
		xdev_ext_mech_life_init(&l);
		CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
		CHECK(!xdev_ext_mech_life_publish(&l, p, 2, 1));
		CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
		CHECK(!xdev_ext_mech_life_acquire(&l, 2, XDEV_EXT_MECH_L_ACQ_FANOUT, &b));
		for (i = 0; i < DUP_RACERS; i++) {
			r[i] = (struct dup_racer){ &start, &l, a, 1 };
			CHECK(!pthread_create(&t[i], NULL, dup_race, &r[i]));
		}
		wins = 0;
		for (i = 0; i < DUP_RACERS; i++) {
			CHECK(!pthread_join(t[i], NULL));
			if (r[i].ret == XDEV_EXT_MECH_L_KEPT)
				wins++;
			else
				CHECK(r[i].ret == -ESTALE);
		}
		CHECK(wins == 1);
		CHECK(raw(&l) == word(0, 0, 1, STAGE_BIT(2), XDEV_EXT_MECH_L_OUT_PENDING));
	}
	CHECK(!pthread_barrier_destroy(&start));
	return true;
}

/*
 * Native callbacks race on the batch completion ticket; only the winner
 * writes valid_len and publishes, and the consumer observes that length.
 */
struct cb_racer {
	pthread_barrier_t *start;
	struct xdev_ext_mech_completion *c;
	struct xdev_ext_mech_life *l;
	__u64 ticket, claim;
	__u32 len;
	int won;
};

static void *cb_race(void *arg)
{
	struct cb_racer *r = arg;

	pthread_barrier_wait(r->start);
	r->won = !xdev_ext_mech_completion_claim(r->c, r->ticket);
	if (r->won) {
		if (xdev_ext_mech_life_publish(r->l, r->claim, 1, r->len))
			r->won = -1;
		else
			xdev_ext_mech_completion_publish(r->c, r->ticket, 0);
	}
	return NULL;
}

static bool test_race_completion_winner_publishes(void)
{
	struct xdev_ext_mech_completion c;
	struct xdev_ext_mech_life l;
	pthread_barrier_t start;
	struct cb_racer r[DUP_RACERS];
	pthread_t t[DUP_RACERS];
	unsigned int round, i, winner = 0, wins;
	__u64 p, ticket, a;
	int result;

	CHECK(!pthread_barrier_init(&start, NULL, DUP_RACERS));
	for (round = 0; round < RACE_ROUNDS / 8; round++) {
		xdev_ext_mech_life_init(&l);
		xdev_ext_mech_completion_init(&c);
		CHECK(!xdev_ext_mech_life_claim(&l, 0, &p));
		CHECK(!xdev_ext_mech_completion_begin(&c, &ticket));
		for (i = 0; i < DUP_RACERS; i++) {
			r[i] = (struct cb_racer){ &start, &c, &l, ticket, p, 1000 + i, 0 };
			CHECK(!pthread_create(&t[i], NULL, cb_race, &r[i]));
		}
		wins = 0;
		for (i = 0; i < DUP_RACERS; i++) {
			CHECK(!pthread_join(t[i], NULL));
			CHECK(r[i].won >= 0);
			if (r[i].won) {
				wins++;
				winner = i;
			}
		}
		CHECK(wins == 1);
		/* The worker sees the frame READY when it consumes the completion. */
		CHECK(!xdev_ext_mech_completion_consume(&c, ticket, &result));
		CHECK(result == 0);
		CHECK(xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_READY);
		CHECK(!xdev_ext_mech_life_acquire(&l, 1, 0, &a));
		CHECK(l.valid_len == 1000 + winner);
	}
	CHECK(!pthread_barrier_destroy(&start));
	return true;
}

#define PUBLICATIONS 4096

struct publication {
	struct xdev_ext_mech_life life;
	__u64 claim;
	__u64 payload[4];
};

struct publication_run {
	struct publication *slots;
	bool ok;
};

static bool deadline_passed(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec - start->tv_sec >= 15;
}

/* Two fan-out readers per publication, the last one recycles the frame. */
static void *read_publications(void *arg)
{
	struct publication_run *run = arg;
	struct timespec start;
	unsigned int i, j, spins = 0;
	__u64 claim;
	int ret;

	run->ok = false;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < PUBLICATIONS; i++) {
		struct publication *slot = &run->slots[i];

		while (xdev_ext_mech_life_acquire(&slot->life, 2, XDEV_EXT_MECH_L_ACQ_FANOUT,
						  &claim)) {
			if (!(++spins % 1024)) {
				if (deadline_passed(&start))
					return NULL;
				sched_yield();
			}
		}
		if (slot->life.valid_len != i + 1)
			return NULL;
		for (j = 0; j < 4; j++)
			if (slot->payload[j] != ((__u64)i << 32 | (j + 1)))
				return NULL;
		ret = xdev_ext_mech_life_put(&slot->life, claim);
		if (ret != XDEV_EXT_MECH_L_KEPT && ret != XDEV_EXT_MECH_L_FREED)
			return NULL;
	}
	run->ok = true;
	return NULL;
}

static bool test_consumer_acquires_payload_and_length(void)
{
	struct publication_run run;
	pthread_t reader;
	unsigned int i, j;
	bool published = true;
	__u64 claim;
	int ret;

	run.slots = calloc(PUBLICATIONS, sizeof(*run.slots));
	CHECK(run.slots != NULL);
	for (i = 0; i < PUBLICATIONS; i++) {
		xdev_ext_mech_life_init(&run.slots[i].life);
		CHECK(!xdev_ext_mech_life_claim(&run.slots[i].life, 0, &run.slots[i].claim));
	}
	CHECK(!pthread_create(&reader, NULL, read_publications, &run));
	for (i = 0; i < PUBLICATIONS; i++) {
		struct publication *slot = &run.slots[i];

		for (j = 0; j < 4; j++)
			slot->payload[j] = ((__u64)i << 32) | (j + 1);
		if (xdev_ext_mech_life_publish(&slot->life, slot->claim, 2, i + 1)) {
			published = false;
			break;
		}
		/* The other fan-out reader, on this thread. */
		while (xdev_ext_mech_life_acquire(&slot->life, 1, XDEV_EXT_MECH_L_ACQ_FANOUT,
						  &claim))
			sched_yield();
		ret = xdev_ext_mech_life_put(&slot->life, claim);
		if (ret != XDEV_EXT_MECH_L_KEPT && ret != XDEV_EXT_MECH_L_FREED) {
			published = false;
			break;
		}
	}
	CHECK(!pthread_join(reader, NULL));
	for (i = 0; published && i < PUBLICATIONS; i++)
		CHECK(raw(&run.slots[i].life) == word(1, 0, 0, 0, XDEV_EXT_MECH_L_FREE));
	free(run.slots);
	CHECK(published);
	CHECK(run.ok);
	return true;
}

#define FN(f) f
#else
#define FN(f) NULL
#endif /* XDEV_EXT_MECH_LIFE_REFS */

int main(void)
{
	static const struct {
		const char *name;
		bool (*run)(void);
	} tests[] = {
		{ "L1 exactly four data-plane states", FN(test_four_states_only) },
		{ "L5 claim records owner and generation", FN(test_claim_records_owner_and_generation) },
		{ "L2 publication installs consumer references", FN(test_publish_installs_references) },
		{ "L2 two fan-out consumers, final decrement recycles", FN(test_fanout_two_consumers) },
		{ "L2 READY again for the dependent consumer", FN(test_dependent_consumer_after_fanout) },
		{ "L2 failed consumer suppresses later stages", FN(test_failed_consumer_suppresses_dependents) },
		{ "L5 generation moves only at the final release", FN(test_generation_moves_only_at_final_release) },
		{ "L5 stale owner or generation is rejected", FN(test_stale_owner_and_generation_rejected) },
		{ "L4 no READY to IO_PENDING edge", FN(test_no_ready_to_io_pending_edge) },
		{ "L1 rollback restores the word exactly", FN(test_rollback_is_exact_inverse) },
		{ "L7 exclusive transform republishes the same frame", FN(test_exclusive_transform_republishes_same_frame) },
		{ "L7 destination frame is a producer case", FN(test_destination_frame_is_a_producer) },
		{ "L2 release of an unconsumed publication", FN(test_release_rules) },
		{ "L5 generation exhaustion refuses a new claim", FN(test_generation_exhaustion) },
		{ "L9 per-frame record fields", FN(test_frame_record) },
		{ "L2 one atomic update per hand-off", FN(test_one_atomic_update_per_handoff) },
		{ "L2 racing fan-out completions free exactly once", FN(test_race_fanout_final_decrement_once) },
		{ "L5 racing duplicate completion decrements once", FN(test_race_duplicate_put) },
		{ "L1 completion-ticket winner alone writes valid_len", FN(test_race_completion_winner_publishes) },
		{ "L2 fan-out readers acquire payload and length", FN(test_consumer_acquires_payload_and_length) },
	};
	unsigned int i, failed = 0;

	printf("TAP version 13\n1..%zu\n", sizeof(tests) / sizeof(tests[0]));
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		bool ok = tests[i].run && tests[i].run();

		printf("%s %u - %s%s\n", ok ? "ok" : "not ok", i + 1, tests[i].name,
		       tests[i].run ? "" :
		       " # missing API: XDEV_EXT_MECH_LIFE_REFS (reference-counted lifecycle contract)");
		failed += !ok;
	}
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

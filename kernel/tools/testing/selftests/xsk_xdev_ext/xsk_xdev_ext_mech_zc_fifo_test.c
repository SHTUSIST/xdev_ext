// SPDX-License-Identifier: GPL-2.0
/* Native journal contract. This tests behavior, not the FIFO representation
 * or its complexity; O(1) access still needs production-code review.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../../net/xdp/xsk_xdev_ext_mech_zc_core.h"

#define CAP 8U
#define CHECK(expr) do {                                                   \
	if (!(expr)) {                                                     \
		fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr);  \
		return 1;                                                 \
	}                                                                  \
} while (0)

struct journal {
	struct xsk_mech_zc_ring ring;
	struct xsk_mech_zc_slot slots[CAP];
	/* An independent logical journal, never native FIFO links/count. */
	unsigned char state[CAP];
	uint32_t prod, issued, cons;
};

static void init(struct journal *j, uint32_t cursor)
{
	memset(j, 0, sizeof(*j));
	j->ring.capacity = CAP;
	j->ring.prod = j->ring.issued = j->ring.cons = cursor;
	j->prod = j->issued = j->cons = cursor;
}

static int invariants(struct journal *j)
{
	uint32_t i, count = 0, order[CAP];

	CHECK(j->ring.prod == j->prod);
	CHECK(j->ring.issued == j->issued);
	CHECK(j->ring.cons == j->cons);
	CHECK(j->prod - j->cons <= CAP);
	for (i = j->cons; i != j->prod; i++)
		CHECK(j->slots[i & (CAP - 1)].state == j->state[i & (CAP - 1)]);
	for (i = j->cons; i != j->issued; i++)
		if (j->state[i & (CAP - 1)] == XSK_MECH_ZC_NATIVE)
			order[count++] = i & (CAP - 1);
	CHECK(xsk_mech_zc_native(&j->ring, j->slots) == count);
	CHECK(xsk_mech_zc_complete(&j->ring, j->slots) ==
	      (count ? (int)order[0] : -ENOENT));
	for (i = 0; i < count; i++)
		CHECK(xsk_mech_zc_tail(&j->ring, j->slots, i) ==
		      (int)order[count - 1 - i]);
	CHECK(xsk_mech_zc_tail(&j->ring, j->slots, count) == -ENOENT);
	CHECK(xsk_mech_zc_tail(&j->ring, j->slots, UINT32_MAX) == -ENOENT);
	return 0;
}

static int reserve(struct journal *j, uint32_t n)
{
	uint32_t at = 0xdeadbeefU, i;
	bool fits = n && n <= CAP - (j->prod - j->cons);

	CHECK(xsk_mech_zc_reserve(&j->ring, n, &at) == (fits ? 0 : -EAGAIN));
	if (fits) {
		CHECK(at == j->prod);
		for (i = 0; i < n; i++) {
			uint32_t pos = (at + i) & (CAP - 1);

			j->state[pos] = XSK_MECH_ZC_PENDING;
			j->slots[pos] = (struct xsk_mech_zc_slot) {
				.state = XSK_MECH_ZC_PENDING,
				.slot = at + i,
			};
		}
		j->prod += n;
	} else {
		CHECK(at == 0xdeadbeefU);
	}
	return invariants(j);
}

static int issue(struct journal *j)
{
	bool available = j->issued != j->prod;
	uint32_t at = j->issued & (CAP - 1);

	CHECK(xsk_mech_zc_peek(&j->ring, j->slots) ==
	      (available ? (int)at : -ENOENT));
	if (available) {
		CHECK(j->state[at] == XSK_MECH_ZC_PENDING);
		CHECK(j->slots[at].slot == j->issued);
		j->state[at] = XSK_MECH_ZC_NATIVE;
		j->issued++;
	}
	return invariants(j);
}

static int retire(struct journal *j, uint32_t at)
{
	CHECK(at < CAP);
	CHECK(j->state[at] == XSK_MECH_ZC_NATIVE ||
	      j->state[at] == XSK_MECH_ZC_DONE);
	xsk_mech_zc_mark_done(&j->ring, j->slots, at);
	j->state[at] = XSK_MECH_ZC_DONE;
	return invariants(j);
}

static int reclaim(struct journal *j)
{
	while (j->cons != j->issued &&
	       j->state[j->cons & (CAP - 1)] == XSK_MECH_ZC_DONE)
		j->cons++;
	xsk_mech_zc_reclaim(&j->ring, j->slots);
	return invariants(j);
}

static int done_holes_hold_capacity_until_the_accepted_prefix_completes(void)
{
	struct journal j;
	unsigned int i;

	init(&j, 0);
	CHECK(!invariants(&j));
	CHECK(!reserve(&j, CAP));
	for (i = 0; i < CAP; i++)
		CHECK(!issue(&j));
	/* Native accepted 0..4; 5..7 were rejected after being peeked. */
	CHECK(!retire(&j, 7));
	CHECK(!retire(&j, 6));
	CHECK(!retire(&j, 5));
	CHECK(!reclaim(&j));
	CHECK(j.cons == 0);
	CHECK(xsk_mech_zc_native(&j.ring, j.slots) == 5);
	CHECK(!reserve(&j, 1)); /* full: DONE holes cannot be reused yet */
	CHECK(j.prod == CAP);
	CHECK(!retire(&j, 0));
	CHECK(!reclaim(&j));
	CHECK(!reserve(&j, 1)); /* now index 0 is reusable */
	CHECK(!issue(&j));
	CHECK(xsk_mech_zc_complete(&j.ring, j.slots) == 1);
	CHECK(xsk_mech_zc_tail(&j.ring, j.slots, 0) == 0);
	for (i = 1; i < 5; i++) {
		CHECK(!retire(&j, i));
		CHECK(!reclaim(&j));
	}
	CHECK(j.cons == CAP); /* reclaim skipped the three DONE holes */
	CHECK(xsk_mech_zc_complete(&j.ring, j.slots) == 0);
	CHECK(!retire(&j, 0));
	CHECK(!reclaim(&j));
	CHECK(j.cons == j.prod);
	return 0;
}

static int partial_issue_and_counter_wrap_preserve_fifo(void)
{
	struct journal j;
	unsigned int i;

	init(&j, UINT32_MAX - 2);
	CHECK(!reserve(&j, 6));
	CHECK(!issue(&j));
	CHECK(!issue(&j));
	CHECK(xsk_mech_zc_native(&j.ring, j.slots) == 2);
	CHECK(!retire(&j, (UINT32_MAX - 1) & (CAP - 1)));
	CHECK(!reclaim(&j)); /* rejected tail is behind the accepted head */
	CHECK(j.cons == UINT32_MAX - 2);
	for (i = 0; i < 4; i++)
		CHECK(!issue(&j));
	CHECK(!issue(&j)); /* exhaustion does not resend accepted entries */
	CHECK(j.issued == 3);
	CHECK(!retire(&j, (UINT32_MAX - 2) & (CAP - 1)));
	CHECK(!reclaim(&j));
	CHECK(j.cons == UINT32_MAX);
	CHECK(xsk_mech_zc_complete(&j.ring, j.slots) == (int)(UINT32_MAX & (CAP - 1)));
	while (xsk_mech_zc_native(&j.ring, j.slots)) {
		int head = xsk_mech_zc_complete(&j.ring, j.slots);

		CHECK(!retire(&j, head));
		CHECK(!retire(&j, head)); /* duplicate DONE cannot underflow count */
		CHECK(!reclaim(&j));
	}
	CHECK(j.cons == j.prod);
	return 0;
}

static int rejected_suffix_does_not_reissue_an_accepted_descriptor(void)
{
	struct journal j;
	struct xsk_mech_zc_batch b = { .pending = 4 };
	__s32 result;
	unsigned int i;

	init(&j, 0);
	CHECK(!reserve(&j, 4));
	for (i = 0; i < 4; i++)
		CHECK(!issue(&j));
	/* Driver accepted only 0..1. Failed enqueue leaves no native retry. */
	for (i = 4; i-- > 2;) {
		CHECK(!retire(&j, i));
		CHECK(!xsk_mech_zc_retire_result(&b, -EAGAIN, &result));
		CHECK(result == -EIO);
	}
	CHECK(b.pending == 2 && b.status == -EIO);
	CHECK(!xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP, 0, b.status));
	CHECK(!issue(&j));
	CHECK(j.issued == 4);
	CHECK(xsk_mech_zc_complete(&j.ring, j.slots) == 0);
	CHECK(!retire(&j, 0));
	CHECK(!xsk_mech_zc_retire_result(&b, 0, &result));
	CHECK(!retire(&j, 1));
	CHECK(xsk_mech_zc_retire_result(&b, 0, &result));
	CHECK(b.pending == 0 && b.status == -EIO);
	CHECK(!xsk_mech_zc_retire_result(&b, 0, &result));
	CHECK(!reclaim(&j));
	CHECK(j.cons == 4);
	CHECK(!issue(&j));
	CHECK(j.issued == 4);
	return 0;
}

static uint32_t random_step(uint32_t *seed)
{
	*seed = *seed * 1664525U + 1013904223U;
	return *seed;
}

static int mixed_head_tail_retirement_matches_logical_journal(void)
{
	struct journal j;
	uint32_t seed = 0x853c49e6U, k;

	init(&j, UINT32_MAX - 31);
	for (k = 0; k < 20000; k++) {
		uint32_t choice = random_step(&seed);
		int at;

		switch ((choice >> 16) % 5) {
		case 0:
			CHECK(!reserve(&j, (choice >> 8) % (CAP + 2)));
			break;
		case 1:
			CHECK(!issue(&j));
			break;
		case 2:
			at = xsk_mech_zc_complete(&j.ring, j.slots);
			if (at >= 0)
				CHECK(!retire(&j, at));
			break;
		case 3:
			at = xsk_mech_zc_tail(&j.ring, j.slots,
					     (choice >> 8) % CAP);
			if (at >= 0) {
				CHECK(!retire(&j, at));
				CHECK(!retire(&j, at));
			}
			break;
		case 4:
			CHECK(!reclaim(&j));
			break;
		}
		CHECK(!invariants(&j));
	}
	while (j.issued != j.prod)
		CHECK(!issue(&j));
	while (xsk_mech_zc_native(&j.ring, j.slots))
		CHECK(!retire(&j, xsk_mech_zc_complete(&j.ring, j.slots)));
	CHECK(!reclaim(&j));
	CHECK(j.cons == j.prod);
	return 0;
}

static int first_native_error_stops_new_admission_before_batch_completion(void)
{
	struct xsk_mech_zc_ring r = { .capacity = CAP };
	struct xsk_mech_zc_slot s[CAP] = {};
	__u32 start, prod;
	int first;

	CHECK(!xsk_mech_zc_reserve(&r, 3, &start));
	CHECK(xsk_mech_zc_peek(&r, s) == 0);
	CHECK(xsk_mech_zc_peek(&r, s) == 1);
	/* A failed descriptor need not be the last descriptor of its batch.
	 * A third descriptor is still PENDING when the first error is observed. */
	first = xsk_mech_zc_complete(&r, s);
	CHECK(first == 0);
	xsk_mech_zc_set_result(&r, s, first, -EIO);
	CHECK(xsk_mech_zc_native(&r, s) == 2);
	prod = r.prod;
	CHECK(xsk_mech_zc_reserve(&r, 1, &start) < 0);
	CHECK(r.prod == prod);
	CHECK(xsk_mech_zc_peek(&r, s) == -ENOENT);
	/* Detection stops admission, but never fabricates DMA quiescence. */
	CHECK(xsk_mech_zc_complete(&r, s) == first);
	xsk_mech_zc_mark_done(&r, s, first);
	CHECK(xsk_mech_zc_native(&r, s) == 1);
	CHECK(xsk_mech_zc_complete(&r, s) == 1);
	return 0;
}

int main(void)
{
	CHECK(!done_holes_hold_capacity_until_the_accepted_prefix_completes());
	CHECK(!partial_issue_and_counter_wrap_preserve_fifo());
	CHECK(!rejected_suffix_does_not_reissue_an_accepted_descriptor());
	CHECK(!mixed_head_tail_retirement_matches_logical_journal());
	CHECK(!first_native_error_stops_new_admission_before_batch_completion());
	puts("PASS: native ZC FIFO head/tail, DONE holes, wrap, counts and accepted ownership");
	return 0;
}

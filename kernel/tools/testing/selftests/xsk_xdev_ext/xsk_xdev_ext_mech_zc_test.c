// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#if __has_include("../../../../net/xdp/xsk_xdev_ext_mech_zc_core.h")
#include "../../../../net/xdp/xsk_xdev_ext_mech_zc_core.h"
#define CHECK(e) do { if (!(e)) { fprintf(stderr, "%d: %s\n", __LINE__, #e); return 1; } } while (0)
int main(void)
{
	struct xsk_mech_zc_ring r = { .capacity = 4 };
	struct xsk_mech_zc_slot slots[4] = {};
	unsigned int p;
	/* Reservation is atomic: a whole batch fits, or nothing changes. */
	CHECK(xsk_mech_zc_reserve(&r, 3, &p) == 0 && p == 0);
	CHECK(xsk_mech_zc_reserve(&r, 2, &p) == -EAGAIN && r.prod == 3);
	for (p = 0; p < 3; p++) slots[p].state = XSK_MECH_ZC_PENDING;
	CHECK(xsk_mech_zc_peek(&r, slots) == 0);
	CHECK(xsk_mech_zc_peek(&r, slots) == 1);
	CHECK(xsk_mech_zc_native(&r, slots) == 2);
	/* Tail cancellation must never retire the earlier hardware frame. */
	CHECK(xsk_mech_zc_tail(&r, slots, 0) == 1);
	xsk_mech_zc_mark_done(&r, slots, 1);
	CHECK(xsk_mech_zc_complete(&r, slots) == 0);
	xsk_mech_zc_mark_done(&r, slots, 0);
	xsk_mech_zc_reclaim(&r, slots);
	CHECK(r.cons == 2);
	CHECK(xsk_mech_zc_peek(&r, slots) == 2);
	CHECK(xsk_mech_zc_peek(&r, slots) == -ENOENT);
	CHECK(xsk_mech_zc_complete(&r, slots) == 2);
	xsk_mech_zc_mark_done(&r, slots, 2);
	xsk_mech_zc_reclaim(&r, slots);
	CHECK(r.cons == r.prod);
	/* Wraparound and mixed cancellation/completion preserve FIFO. */
	r.cons = r.issued = r.prod = UINT32_MAX - 1;
	CHECK(xsk_mech_zc_reserve(&r, 4, &p) == 0);
	for (unsigned int i = 0; i < 4; i++) slots[(p + i) % 4].state = XSK_MECH_ZC_PENDING;
	for (unsigned int i = 0; i < 4; i++) CHECK(xsk_mech_zc_peek(&r, slots) >= 0);
	CHECK(xsk_mech_zc_native(&r, slots) == 4);
	CHECK(xsk_mech_zc_tail(&r, slots, 4) == -ENOENT);
	for (unsigned int i = 0; i < 4; i++) {
		int at = xsk_mech_zc_complete(&r, slots);
		CHECK(at >= 0);
		xsk_mech_zc_mark_done(&r, slots, at);
		xsk_mech_zc_reclaim(&r, slots);
	}
	CHECK(r.cons == r.prod);
#ifdef XSK_MECH_ZC_BATCH_TRACKING
	{
		struct xsk_mech_zc_batch b = { .pending = 3 };
		__s32 result;

		CHECK(!xsk_mech_zc_retire_result(&b, 0, &result));
		CHECK(result == 0 && b.pending == 2 && b.status == 0);
		CHECK(!xsk_mech_zc_retire_result(&b, -EAGAIN, &result));
		CHECK(result == -EIO && b.pending == 1 && b.status == -EIO);
		CHECK(xsk_mech_zc_retire_result(&b, -ENXIO, &result));
		CHECK(result == -ENXIO && b.pending == 0 && b.status == -EIO);
		CHECK(!xsk_mech_zc_retire_result(&b, 0, &result));
		CHECK(b.pending == 0); /* duplicate completion cannot underflow */
	}
#else
	CHECK(!"batch must wait for every hardware frame and forbid EAGAIN resend");
#endif
	puts("PASS: kernel TX ring capacity, FIFO, cancellation and wraparound");
	return 0;
}
#else
int main(void) { fputs("FAIL: kernel-owned AF_XDP TX ring missing\n", stderr); return 1; }
#endif

// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../../net/xdp/xsk_xdev_ext_rx_core.h"
#include "../../../../net/xdp/xsk_xdev_ext_mech_core.h"

static unsigned int tests_run;
static unsigned int tests_failed;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	tests_run++;                                                        \
	if (actual_ != expected_) {                                         \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__FILE__, __LINE__, #actual_expr, actual_, expected_); \
		tests_failed++;                                               \
	}                                                                   \
} while (0)

enum fake_rx_mode {
	FAKE_RX_COPY,
	FAKE_RX_ZERO_COPY,
};

enum fake_rx_action {
	FAKE_RX_FALLBACK,
	FAKE_RX_USE_PLAN,
	FAKE_RX_TERMINAL,
};

enum fake_rx_event {
	FAKE_RX_EVENT_DMA = 1,
	FAKE_RX_EVENT_DISPATCH,
	FAKE_RX_EVENT_COPY,
	FAKE_RX_EVENT_RESERVE,
	FAKE_RX_EVENT_PUBLISH,
	FAKE_RX_EVENT_COMPLETE,
	FAKE_RX_EVENT_TOKEN_PUT,
};

struct fake_rx_driver {
	struct xsk_xdev_ext_rx_core core;
	enum fake_rx_event events[16];
	unsigned int nr_events;
	unsigned int dispatches;
	unsigned int completions;
	unsigned int token_puts;
	unsigned int ring_reserved;
	unsigned int ring_cancelled;
	unsigned int buffers_allocated;
	unsigned int buffers_released;
	uint64_t completed_bytes;
	bool rx_aware;
};

static void fake_event(struct fake_rx_driver *driver, enum fake_rx_event event)
{
	driver->events[driver->nr_events++] = event;
}

static void fake_driver_init(struct fake_rx_driver *driver, bool rx_aware)
{
	memset(driver, 0, sizeof(*driver));
	xsk_xdev_ext_rx_core_init(&driver->core);
	driver->rx_aware = rx_aware;
}

static int fake_receive(struct fake_rx_driver *driver, enum fake_rx_mode mode,
			enum fake_rx_action action, uint64_t length,
			uint32_t nr_descs, int reserve_failure_after,
			bool publish_fails)
{
	bool tracked;
	uint32_t i;
	int ret;

	if (mode == FAKE_RX_ZERO_COPY)
		fake_event(driver, FAKE_RX_EVENT_DMA);

	/* A flags=0 policy is intentionally outside the RX callback domain. */
	if (!driver->rx_aware) {
		if (mode == FAKE_RX_COPY)
			fake_event(driver, FAKE_RX_EVENT_COPY);
		fake_event(driver, FAKE_RX_EVENT_RESERVE);
		driver->ring_reserved = nr_descs;
		fake_event(driver, FAKE_RX_EVENT_PUBLISH);
		return 0;
	}

	fake_event(driver, FAKE_RX_EVENT_DISPATCH);
	driver->dispatches++;
	if (action == FAKE_RX_TERMINAL)
		return -EPERM;

	tracked = true;
	ret = xsk_xdev_ext_rx_core_begin(&driver->core, length, nr_descs, tracked);
	if (ret)
		return ret;

	if (mode == FAKE_RX_COPY)
		fake_event(driver, FAKE_RX_EVENT_COPY);

	fake_event(driver, FAKE_RX_EVENT_RESERVE);
	for (i = 0; i < nr_descs; i++) {
		driver->buffers_allocated++;
		if (reserve_failure_after >= 0 &&
		    i == (uint32_t)reserve_failure_after) {
			ret = -ENOBUFS;
			goto abort;
		}
		driver->ring_reserved++;
		ret = xsk_xdev_ext_rx_core_note_reservation(&driver->core);
		if (ret)
			goto abort;
	}
	ret = xsk_xdev_ext_rx_core_reservations_complete(&driver->core);
	if (ret)
		goto abort;
	driver->buffers_released = driver->buffers_allocated;
	if (publish_fails)
		goto abort;

	fake_event(driver, FAKE_RX_EVENT_PUBLISH);
	ret = xsk_xdev_ext_rx_core_published(&driver->core, length);
	if (ret)
		goto abort;

	fake_event(driver, FAKE_RX_EVENT_COMPLETE);
	driver->completions++;
	driver->completed_bytes = length;
	EXPECT_EQ(xsk_xdev_ext_rx_core_complete(&driver->core), 1);
	return 0;

abort:
	driver->ring_cancelled = driver->ring_reserved;
	driver->buffers_released = driver->buffers_allocated;
	if (xsk_xdev_ext_rx_core_abort(&driver->core)) {
		fake_event(driver, FAKE_RX_EVENT_TOKEN_PUT);
		driver->token_puts++;
	}
	return -ENOBUFS;
}

static void test_copy_single_and_multibuffer_order(void)
{
	struct fake_rx_driver driver;

	fake_driver_init(&driver, true);
	EXPECT_EQ(fake_receive(&driver, FAKE_RX_COPY, FAKE_RX_FALLBACK,
			       1500, 1, -1, false), 0);
	EXPECT_EQ(driver.dispatches, 1);
	EXPECT_EQ(driver.completions, 1);
	EXPECT_EQ(driver.completed_bytes, 1500);
	EXPECT_EQ(driver.nr_events, 5);
	EXPECT_EQ(driver.events[0], FAKE_RX_EVENT_DISPATCH);
	EXPECT_EQ(driver.events[1], FAKE_RX_EVENT_COPY);
	EXPECT_EQ(driver.events[2], FAKE_RX_EVENT_RESERVE);
	EXPECT_EQ(driver.events[3], FAKE_RX_EVENT_PUBLISH);
	EXPECT_EQ(driver.events[4], FAKE_RX_EVENT_COMPLETE);

	fake_driver_init(&driver, true);
	EXPECT_EQ(fake_receive(&driver, FAKE_RX_COPY, FAKE_RX_USE_PLAN,
			       12288, 3, -1, false), 0);
	EXPECT_EQ(driver.dispatches, 1);
	EXPECT_EQ(driver.completions, 1);
	EXPECT_EQ(driver.completed_bytes, 12288);
}

static void test_zero_copy_dispatches_after_dma(void)
{
	struct fake_rx_driver driver;

	fake_driver_init(&driver, true);
	EXPECT_EQ(fake_receive(&driver, FAKE_RX_ZERO_COPY, FAKE_RX_FALLBACK,
			       8192, 2, -1, false), 0);
	EXPECT_EQ(driver.dispatches, 1);
	EXPECT_EQ(driver.completions, 1);
	EXPECT_EQ(driver.nr_events, 5);
	EXPECT_EQ(driver.events[0], FAKE_RX_EVENT_DMA);
	EXPECT_EQ(driver.events[1], FAKE_RX_EVENT_DISPATCH);
	EXPECT_EQ(driver.events[2], FAKE_RX_EVENT_RESERVE);
	EXPECT_EQ(driver.events[3], FAKE_RX_EVENT_PUBLISH);
	EXPECT_EQ(driver.events[4], FAKE_RX_EVENT_COMPLETE);
}

static void test_terminal_never_copies_publishes_or_completes(void)
{
	struct fake_rx_driver driver;

	fake_driver_init(&driver, true);
	EXPECT_EQ(fake_receive(&driver, FAKE_RX_COPY, FAKE_RX_TERMINAL,
			       4096, 1, -1, false), -EPERM);
	EXPECT_EQ(driver.dispatches, 1);
	EXPECT_EQ(driver.completions, 0);
	EXPECT_EQ(driver.token_puts, 0);
	EXPECT_EQ(driver.nr_events, 1);
	EXPECT_EQ(driver.events[0], FAKE_RX_EVENT_DISPATCH);
	EXPECT_EQ(driver.core.state, XSK_XDEV_EXT_RX_IDLE);
}

static void test_reserve_and_prepublication_failure_unwind(void)
{
	struct fake_rx_driver driver;

	fake_driver_init(&driver, true);
	EXPECT_EQ(fake_receive(&driver, FAKE_RX_COPY, FAKE_RX_FALLBACK,
			       4096, 1, 0, false), -ENOBUFS);
	EXPECT_EQ(driver.dispatches, 1);
	EXPECT_EQ(driver.completions, 0);
	EXPECT_EQ(driver.token_puts, 1);
	EXPECT_EQ(driver.ring_cancelled, 0);
	EXPECT_EQ(driver.buffers_allocated, 1);
	EXPECT_EQ(driver.buffers_released, 1);
	EXPECT_EQ(driver.core.state, XSK_XDEV_EXT_RX_IDLE);

	fake_driver_init(&driver, true);
	EXPECT_EQ(fake_receive(&driver, FAKE_RX_ZERO_COPY, FAKE_RX_USE_PLAN,
			       8192, 2, -1, true), -ENOBUFS);
	EXPECT_EQ(driver.dispatches, 1);
	EXPECT_EQ(driver.completions, 0);
	EXPECT_EQ(driver.token_puts, 1);
	EXPECT_EQ(driver.ring_cancelled, 2);
	EXPECT_EQ(driver.core.state, XSK_XDEV_EXT_RX_IDLE);

	/* A mid-packet COPY failure must never publish a partial CONTD chain. */
	fake_driver_init(&driver, true);
	EXPECT_EQ(fake_receive(&driver, FAKE_RX_COPY, FAKE_RX_FALLBACK,
			       12288, 3, 1, false), -ENOBUFS);
	EXPECT_EQ(driver.ring_reserved, 1);
	EXPECT_EQ(driver.ring_cancelled, 1);
	EXPECT_EQ(driver.buffers_allocated, 2);
	EXPECT_EQ(driver.buffers_released, 2);
	EXPECT_EQ(driver.completions, 0);
	EXPECT_EQ(driver.token_puts, 1);
	EXPECT_EQ(driver.core.state, XSK_XDEV_EXT_RX_IDLE);
}

static void test_legacy_policy_is_c_fallback_without_callback(void)
{
	struct fake_rx_driver driver;

	fake_driver_init(&driver, false);
	EXPECT_EQ(fake_receive(&driver, FAKE_RX_COPY, FAKE_RX_TERMINAL,
			       2048, 1, -1, false), 0);
	EXPECT_EQ(driver.dispatches, 0);
	EXPECT_EQ(driver.completions, 0);
	EXPECT_EQ(driver.events[0], FAKE_RX_EVENT_COPY);
	EXPECT_EQ(driver.events[1], FAKE_RX_EVENT_RESERVE);
	EXPECT_EQ(driver.events[2], FAKE_RX_EVENT_PUBLISH);
}

static void test_teardown_unwinds_unpublished_token_once(void)
{
	struct fake_rx_driver driver;

	fake_driver_init(&driver, true);
	EXPECT_EQ(xsk_xdev_ext_rx_core_begin(&driver.core, 1024, 1, true), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_note_reservation(&driver.core), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_reservations_complete(&driver.core), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_abort(&driver.core), 1);
	EXPECT_EQ(xsk_xdev_ext_rx_core_abort(&driver.core), 0);
	EXPECT_EQ(driver.core.state, XSK_XDEV_EXT_RX_IDLE);
}

static void test_core_rejects_wrong_order_and_inexact_publication(void)
{
	struct xsk_xdev_ext_rx_core core;

	xsk_xdev_ext_rx_core_init(&core);
	EXPECT_EQ(xsk_xdev_ext_rx_core_note_reservation(&core), -EPROTO);
	EXPECT_EQ(xsk_xdev_ext_rx_core_reservations_complete(&core), -EPROTO);
	EXPECT_EQ(xsk_xdev_ext_rx_core_begin(&core, 4096, 2, true), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_begin(&core, 4096, 2, true), -EBUSY);
	EXPECT_EQ(xsk_xdev_ext_rx_core_note_reservation(&core), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_reservations_complete(&core), -EINVAL);
	EXPECT_EQ(core.reserved_descs, 1);
	EXPECT_EQ(xsk_xdev_ext_rx_core_abort(&core), 1);
	EXPECT_EQ(core.state, XSK_XDEV_EXT_RX_IDLE);

	EXPECT_EQ(xsk_xdev_ext_rx_core_begin(&core, 4096, 2, true), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_note_reservation(&core), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_note_reservation(&core), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_note_reservation(&core), -EOVERFLOW);
	EXPECT_EQ(xsk_xdev_ext_rx_core_reservations_complete(&core), 0);
	EXPECT_EQ(xsk_xdev_ext_rx_core_published(&core, 4095), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_rx_core_complete(&core), -EPROTO);
	EXPECT_EQ(xsk_xdev_ext_rx_core_abort(&core), 1);
}

/*
 * Fake copy-mode pool of an AF_XDP mechanism session.  The allocator entry
 * points mirror xp_alloc(), xp_alloc_batch() and xp_can_alloc(); the
 * decisions come from net/xdp/xsk_xdev_ext_mech_core.h and
 * io_uring/xdev_ext_mech_core.h exactly as the kernel takes them.
 */
#define MECH_CHUNK_SHIFT	11
#define MECH_CHUNK_SIZE		(1U << MECH_CHUNK_SHIFT)
#define MECH_CHUNKS		16U
#define MECH_RING		64U

struct mech_pool {
	uint8_t state[MECH_CHUNKS];	/* ownership words of the UMEM */
	bool session;			/* words published by the pool bind */
	uint32_t free_list[MECH_CHUNKS];
	uint32_t free_cnt;
	uint32_t recycle[MECH_CHUNKS];	/* the pool's recycle llist */
	uint32_t recycle_cnt;
	uint64_t fq[MECH_RING];
	uint32_t fq_prod;
	uint32_t fq_cons;
	uint64_t invalid_descs;
	uint32_t splices;
	uint32_t recycled;
};

static void mech_pool_init(struct mech_pool *p, bool session)
{
	memset(p, 0, sizeof(*p));
	p->session = session;
}

static const uint8_t *mech_words(const struct mech_pool *p)
{
	return p->session ? p->state : NULL;
}

static void mech_fq_put(struct mech_pool *p, uint32_t idx)
{
	p->fq[p->fq_prod++ % MECH_RING] = (uint64_t)idx << MECH_CHUNK_SHIFT;
}

/* xp_xdev_ext_mech_splice(): only the allocator drains the recycle llist. */
static void mech_splice(struct mech_pool *p)
{
	if (!p->recycle_cnt)
		return;
	p->splices++;
	while (p->recycle_cnt)
		p->free_list[p->free_cnt++] = p->recycle[--p->recycle_cnt];
}

/* __xp_alloc() and xp_alloc_new_from_fq(): aligned check, then the words. */
static bool mech_fq_take(struct mech_pool *p, uint32_t *idx)
{
	while (p->fq_cons != p->fq_prod) {
		uint64_t addr = p->fq[p->fq_cons++ % MECH_RING];
		uint64_t i = addr >> MECH_CHUNK_SHIFT;

		if (i >= MECH_CHUNKS ||
		    !xsk_xdev_ext_mech_fq_ok(mech_words(p), MECH_CHUNKS, i)) {
			p->invalid_descs++;
			continue;
		}
		*idx = (uint32_t)i;
		return true;
	}
	return false;
}

static bool mech_xp_alloc(struct mech_pool *p, uint32_t *idx)
{
	mech_splice(p);
	if (p->free_cnt) {
		*idx = p->free_list[--p->free_cnt];
		return true;
	}
	return mech_fq_take(p, idx);
}

static uint32_t mech_xp_alloc_batch(struct mech_pool *p, uint32_t *idx,
				    uint32_t max)
{
	uint32_t n = 0;

	mech_splice(p);
	while (n < max && p->free_cnt)
		idx[n++] = p->free_list[--p->free_cnt];
	while (n < max && mech_fq_take(p, &idx[n]))
		n++;
	return n;
}

static bool mech_xp_can_alloc(struct mech_pool *p, uint32_t count)
{
	mech_splice(p);
	return p->free_cnt + (p->fq_prod - p->fq_cons) >= count;
}

/* xdev_ext_mech_frame_recycle() plus the provider's ->recycle: word, then llist. */
static void mech_recycle(struct mech_pool *p, uint32_t idx)
{
	uint8_t cur = xdev_ext_mech_frame_state(&p->state[idx]);

	if (cur != XDEV_EXT_MECH_F_K_FREE)
		EXPECT_EQ(xdev_ext_mech_frame_move(&p->state[idx], cur,
					      XDEV_EXT_MECH_F_K_FREE), 0);
	p->recycle[p->recycle_cnt++] = idx;
	p->recycled++;
}

static struct xsk_xdev_ext_mech_sock_facts mech_good_socket(void)
{
	return (struct xsk_xdev_ext_mech_sock_facts) {
		.bound = true,
		.pool_users = 1,
		.umem_users = 1,
		.chunk_size = MECH_CHUNK_SIZE,
		.chunks = MECH_CHUNKS,
	};
}

static void test_mech_pool_admission(void)
{
	struct xdev_ext_mech_layout l = {
		.frame_size = MECH_CHUNK_SIZE,
		.hdr_room = 360,
		.seg_len = 1432,
		.group_bytes = 8192,
	};
	struct xdev_ext_mech_layout bad = l;
	struct xsk_xdev_ext_mech_sock_facts f;

	f = mech_good_socket();
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), 0);
	f.bound = false;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -ENXIO);
	f = mech_good_socket();
	f.zero_copy = true;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), 0);
	f.fq_used = true;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EBUSY);
	f = mech_good_socket();
	f.tx_entries = 1;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EBUSY);
	f = mech_good_socket();
	f.cq_entries = 1;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EBUSY);
	f = mech_good_socket();
	f.unaligned = true;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EOPNOTSUPP);
	f = mech_good_socket();
	f.pool_users = 2;	/* XDP_SHARED_UMEM on the same queue */
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EBUSY);
	f = mech_good_socket();
	f.umem_users = 2;	/* XDP_SHARED_UMEM on another queue */
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EBUSY);
	f = mech_good_socket();
	f.owned = true;		/* another session uses the UMEM */
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EBUSY);
	f = mech_good_socket();
	f.fq_entries = 1;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EBUSY);
	f = mech_good_socket();
	f.rx_entries = 1;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EBUSY);

	f = mech_good_socket();
	bad.frame_size = MECH_CHUNK_SIZE / 2;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &bad), -EINVAL);
	bad = l;
	bad.hdr_room = MECH_CHUNK_SIZE;	/* no room for a segment */
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &bad), -EINVAL);
	bad = l;
	bad.group_bytes = 33 * bad.seg_len;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &bad), -E2BIG);
	f.chunks = 0;
	EXPECT_EQ(xsk_xdev_ext_mech_pool_admit(&f, &l), -EINVAL);
}

static void test_mech_shared_umem_bind_busy(void)
{
	EXPECT_EQ(xsk_xdev_ext_mech_share_check(true), -EBUSY);
	EXPECT_EQ(xsk_xdev_ext_mech_share_check(false), 0);
}

static void test_mech_fill_ring_refuses_session_frames(void)
{
	static const uint8_t owned[] = {
		XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_INFLIGHT,
		XDEV_EXT_MECH_F_SEQUESTERED, XDEV_EXT_MECH_F_NIC_RX,
	};
	struct mech_pool p;
	uint32_t got[4], idx, i;

	/* No session on the UMEM: every in-range address is the user's. */
	EXPECT_EQ(xsk_xdev_ext_mech_fq_ok(NULL, MECH_CHUNKS, 3), true);
	EXPECT_EQ(xsk_xdev_ext_mech_fq_ok(NULL, MECH_CHUNKS, MECH_CHUNKS), true);

	for (i = 0; i < sizeof(owned); i++) {
		/* xp_alloc() -> __xp_alloc() */
		mech_pool_init(&p, true);
		p.state[5] = owned[i];
		mech_fq_put(&p, 5);
		mech_fq_put(&p, 6);
		EXPECT_EQ(mech_xp_alloc(&p, &idx), true);
		EXPECT_EQ(idx, 6);
		EXPECT_EQ(p.invalid_descs, 1);
		EXPECT_EQ(p.state[5], owned[i]);

		/* xp_alloc_batch() -> xp_alloc_new_from_fq() */
		mech_pool_init(&p, true);
		p.state[5] = owned[i];
		mech_fq_put(&p, 4);
		mech_fq_put(&p, 5);
		mech_fq_put(&p, 7);
		EXPECT_EQ(mech_xp_alloc_batch(&p, got, 3), 2);
		EXPECT_EQ(got[0], 4);
		EXPECT_EQ(got[1], 7);
		EXPECT_EQ(p.invalid_descs, 1);
	}

	/* A word table never reads past its UMEM. */
	mech_pool_init(&p, true);
	EXPECT_EQ(xsk_xdev_ext_mech_fq_ok(p.state, MECH_CHUNKS, MECH_CHUNKS), false);
	EXPECT_EQ(xsk_xdev_ext_mech_fq_ok(p.state, MECH_CHUNKS, MECH_CHUNKS - 1),
		  true);
}

static void test_mech_recycle_rejoins_free_list_at_allocator(void)
{
	struct mech_pool p;
	uint32_t got[4], idx;

	/* xp_can_alloc() */
	mech_pool_init(&p, true);
	mech_recycle(&p, 2);
	mech_recycle(&p, 3);
	EXPECT_EQ(p.free_cnt, 0);	/* the recycling context never touches it */
	EXPECT_EQ(p.recycle_cnt, 2);
	EXPECT_EQ(p.state[2], XDEV_EXT_MECH_F_K_FREE);
	EXPECT_EQ(mech_xp_can_alloc(&p, 2), true);
	EXPECT_EQ(p.splices, 1);
	EXPECT_EQ(p.free_cnt, 2);
	EXPECT_EQ(p.recycle_cnt, 0);

	/* xp_alloc() */
	mech_pool_init(&p, true);
	mech_recycle(&p, 9);
	EXPECT_EQ(mech_xp_alloc(&p, &idx), true);
	EXPECT_EQ(idx, 9);
	EXPECT_EQ(p.splices, 1);
	EXPECT_EQ(p.fq_cons, 0);	/* free_list before the fill ring */

	/* xp_alloc_batch() */
	mech_pool_init(&p, true);
	mech_recycle(&p, 1);
	mech_fq_put(&p, 8);
	EXPECT_EQ(mech_xp_alloc_batch(&p, got, 2), 2);
	EXPECT_EQ(got[0], 1);
	EXPECT_EQ(got[1], 8);
	EXPECT_EQ(p.splices, 1);

	/* A recycled frame stays K_FREE: the user cannot give it back. */
	mech_pool_init(&p, true);
	mech_recycle(&p, 4);
	mech_fq_put(&p, 4);
	EXPECT_EQ(mech_xp_alloc_batch(&p, got, 2), 1);
	EXPECT_EQ(got[0], 4);
	EXPECT_EQ(p.invalid_descs, 1);
}

static void test_mech_source_alloc_needs_no_rx_ring(void)
{
	EXPECT_EQ(xsk_xdev_ext_mech_source_ok(false), 0);
	EXPECT_EQ(xsk_xdev_ext_mech_source_ok(true), -EOPNOTSUPP);
}

static void test_mech_afxdp_kfunc_bounds(void)
{
	uint8_t calls = 0;

	/* bpf_xdev_ext_afxdp_hdr(): header room of a batch frame, TX build only. */
	EXPECT_EQ(xsk_xdev_ext_mech_hdr_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_SITE_WORKER, 5, 6, 278, 82,
				      360), true);
	EXPECT_EQ(xsk_xdev_ext_mech_hdr_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_SITE_WORKER, 0, 6, 278, 83,
				      360), false);	/* reaches the data span */
	EXPECT_EQ(xsk_xdev_ext_mech_hdr_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_SITE_WORKER, 6, 6, 0, 14, 360),
		  false);	/* past the batch */
	EXPECT_EQ(xsk_xdev_ext_mech_hdr_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_SITE_WORKER, 0, 6, 0, 0, 360),
		  false);
	EXPECT_EQ(xsk_xdev_ext_mech_hdr_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_SITE_WORKER, 0, 6, UINT32_MAX,
				      2, 360), false);
	EXPECT_EQ(xsk_xdev_ext_mech_hdr_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_COMPLETE,
				      XDEV_EXT_MECH_SITE_WORKER, 0, 6, 0, 14, 360),
		  false);
	EXPECT_EQ(xsk_xdev_ext_mech_hdr_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_SITE_RX_GENERIC, 0, 6, 0, 14,
				      360), false);
	EXPECT_EQ(xsk_xdev_ext_mech_hdr_ok(XDEV_EXT_MECH_CLASS_NVME,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_SITE_WORKER, 0, 6, 0, 14, 360),
		  false);

	/* bpf_xdev_ext_afxdp_hold(): RX complete, at most once per callback. */
	EXPECT_EQ(xsk_xdev_ext_mech_hold_record(XDEV_EXT_MECH_CLASS_AFXDP,
					   XDEV_EXT_MECH_MEMBER_COMPLETE,
					   XDEV_EXT_MECH_SITE_RX_GENERIC, &calls), 0);
	EXPECT_EQ(calls, 1);
	EXPECT_EQ(xsk_xdev_ext_mech_hold_record(XDEV_EXT_MECH_CLASS_AFXDP,
					   XDEV_EXT_MECH_MEMBER_COMPLETE,
					   XDEV_EXT_MECH_SITE_RX_GENERIC, &calls),
		  -EALREADY);
	calls = 0;
	EXPECT_EQ(xsk_xdev_ext_mech_hold_record(XDEV_EXT_MECH_CLASS_AFXDP,
					   XDEV_EXT_MECH_MEMBER_COMPLETE,
					   XDEV_EXT_MECH_SITE_RX_NATIVE, &calls), 0);
	calls = 0;
	EXPECT_EQ(xsk_xdev_ext_mech_hold_record(XDEV_EXT_MECH_CLASS_AFXDP,
					   XDEV_EXT_MECH_MEMBER_COMPLETE,
					   XDEV_EXT_MECH_SITE_WORKER, &calls),
		  -EINVAL);	/* TX complete */
	EXPECT_EQ(xsk_xdev_ext_mech_hold_record(XDEV_EXT_MECH_CLASS_AFXDP,
					   XDEV_EXT_MECH_MEMBER_BUILD,
					   XDEV_EXT_MECH_SITE_RX_GENERIC, &calls),
		  -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_mech_hold_record(XDEV_EXT_MECH_CLASS_NVME,
					   XDEV_EXT_MECH_MEMBER_COMPLETE,
					   XDEV_EXT_MECH_SITE_RX_GENERIC, &calls),
		  -EINVAL);
	EXPECT_EQ(calls, 0);
	calls = 255;
	EXPECT_EQ(xsk_xdev_ext_mech_hold_record(XDEV_EXT_MECH_CLASS_AFXDP,
					   XDEV_EXT_MECH_MEMBER_COMPLETE,
					   XDEV_EXT_MECH_SITE_RX_GENERIC, &calls),
		  -EALREADY);
	EXPECT_EQ(calls, 255);
}

/*
 * Fake session socket on that pool: __xsk_rcv() with the AF_XDP complete
 * hook, the core's OPEN batch (xdev_ext_mech_hold_commit()) and the RX ring.
 */
#define MECH_DATA_OFF		256U	/* XDP_PACKET_HEADROOM, no UMEM headroom */
#define MECH_PKT_LEN		1514U
#define MECH_PAYLOAD_OFF	(MECH_DATA_OFF + 82U)
#define MECH_PAYLOAD_LEN	1432U

struct mech_rx {
	struct mech_pool pool;
	uint64_t ring[MECH_RING];
	uint32_t rx_prod;		/* RX descriptors reserved */
	uint32_t rx_cap;		/* RX ring entries free */
	bool live;			/* session admits and the stage is alive */
	bool zero_copy;
	struct xdev_ext_mech_group group;	/* the OPEN batch */
	uint32_t group_frames[XDEV_EXT_MECH_MAX_FRAMES];
	uint32_t last;			/* chunk of the last received frame */
	uint32_t held;
	uint32_t published;
	uint32_t native_publish;
	uint32_t protocol_err;
	uint32_t program_runs;
};

/* What the AF_XDP complete program does with one frame. */
struct mech_prog {
	int32_t ret;
	uint32_t hold_calls;
	struct xdev_ext_mech_hold_intent intent;
};

/* The fields of struct xdev_ext_mech_call the kfunc touches. */
struct mech_call {
	uint32_t class_id;
	uint32_t member;
	uint32_t callsite;
	uint8_t hold_calls;
	uint8_t protocol_error;
	struct xdev_ext_mech_hold_intent hold;
};

static void mech_rx_init(struct mech_rx *r)
{
	memset(r, 0, sizeof(*r));
	mech_pool_init(&r->pool, true);
	r->rx_cap = MECH_RING;
	r->live = true;
}

static struct mech_prog mech_hold_prog(uint64_t key, uint32_t pos,
				       uint32_t count)
{
	return (struct mech_prog) {
		.ret = XDEV_EXT_MECH_HOLD,
		.hold_calls = 1,
		.intent = {
			.key = key,
			.pos = pos,
			.count = count,
			.span_off = MECH_PAYLOAD_OFF,
			.span_len = MECH_PAYLOAD_LEN,
		},
	};
}

/* bpf_xdev_ext_afxdp_hold() */
static void mech_kfunc_hold(struct mech_call *c,
			    const struct xdev_ext_mech_hold_intent *in)
{
	if (xsk_xdev_ext_mech_hold_record(c->class_id, c->member, c->callsite,
				     &c->hold_calls)) {
		c->protocol_error = 1;
		return;
	}
	c->hold = *in;
}

/* xdev_ext_mech_hold_commit(): frame into the OPEN batch, word to HELD. */
static int mech_hold_commit(struct mech_rx *r,
			    const struct xdev_ext_mech_hold_intent *h, uint32_t idx)
{
	uint8_t *word = &r->pool.state[idx];
	int err;

	if (!r->group.count)
		xdev_ext_mech_group_init(&r->group, h->key, h->count);
	err = xdev_ext_mech_group_add(&r->group, h->key, h->pos, h->count);
	if (err)
		return err;
	err = xdev_ext_mech_frame_move(word, xdev_ext_mech_frame_state(word),
				  XDEV_EXT_MECH_F_HELD);
	if (err) {
		r->group.present &= ~(1U << h->pos);
		return err;
	}
	r->group_frames[h->pos] = idx;
	r->held++;
	return 0;
}

/* xsk_xdev_ext_mech_rx_settle() */
static void mech_settle(struct mech_rx *r, uint32_t idx, bool to_user)
{
	uint8_t *word = &r->pool.state[idx];
	uint32_t from = 0, to = 0;
	int edge;

	if (!r->pool.session)
		return;
	edge = xsk_xdev_ext_mech_settle_edge(xdev_ext_mech_frame_state(word), to_user,
					&from, &to);
	if (edge > 0)
		edge = xdev_ext_mech_frame_move(word, from, to);
	EXPECT_EQ(edge, 0);
	if (to_user)
		r->published++;
}

/* __xsk_rcv() of a session socket.  -ENOMEM: no frame; -ENOBUFS: RX full. */
static int32_t mech_receive(struct mech_rx *r, const struct mech_prog *prog,
			    uint32_t callsite, uint32_t len, uint32_t nr_bufs)
{
	struct mech_call c = {
		.class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.member = XDEV_EXT_MECH_MEMBER_COMPLETE,
		.callsite = callsite,
	};
	uint32_t got[XDEV_EXT_MECH_MAX_FRAMES], idx, i;
	int32_t ret = XDEV_EXT_MECH_PUBLISH, disp;
	bool perr, npub, ran;
	int err = 0;

	if (nr_bufs > 1) {	/* multi-buffer: no hook, every piece published */
		if (!mech_xp_can_alloc(&r->pool, nr_bufs))
			return -ENOMEM;
		for (i = 0; i < nr_bufs; i++) {
			EXPECT_EQ(mech_xp_alloc(&r->pool, &got[i]), true);
			r->ring[r->rx_prod++ % MECH_RING] =
				(uint64_t)got[i] << MECH_CHUNK_SHIFT;
		}
		for (i = 0; i < nr_bufs; i++)
			mech_settle(r, got[i], true);
		return XDEV_EXT_MECH_PUBLISH;
	}

	if (!mech_xp_alloc(&r->pool, &idx))
		return -ENOMEM;
	r->last = idx;
	ran = xsk_xdev_ext_mech_rx_runs(callsite, r->live, r->zero_copy);
	if (ran) {
		r->program_runs++;
		for (i = 0; i < prog->hold_calls; i++)
			mech_kfunc_hold(&c, &prog->intent);
		err = c.protocol_error ? -EPROTO : 0;
		ret = prog->ret;
	}
	disp = xsk_xdev_ext_mech_rx_verdict(callsite, ran, err, ret, &c.hold,
				       MECH_DATA_OFF, len, &perr, &npub);
	if (disp == XDEV_EXT_MECH_HOLD && mech_hold_commit(r, &c.hold, idx)) {
		perr = true;
		disp = XDEV_EXT_MECH_PUBLISH;
	}
	r->native_publish += npub;
	r->protocol_err += perr;
	if (disp == XDEV_EXT_MECH_HOLD)
		return disp;	/* no reservation, the head stays with the frame */
	if (disp == XDEV_EXT_MECH_RECYCLE) {
		mech_recycle(&r->pool, idx);
		return disp;
	}
	if (!r->rx_cap) {	/* xsk_buff_free(): back on free_list */
		mech_settle(r, idx, false);
		r->pool.free_list[r->pool.free_cnt++] = idx;
		return -ENOBUFS;
	}
	r->rx_cap--;
	r->ring[r->rx_prod++ % MECH_RING] =
		((uint64_t)idx << MECH_CHUNK_SHIFT) + MECH_DATA_OFF;
	mech_settle(r, idx, true);
	return disp;
}

/* The core's group timeout: every held frame of the OPEN batch recycles. */
static void mech_group_timeout(struct mech_rx *r)
{
	uint32_t pos;

	for (pos = 0; pos < r->group.count; pos++)
		if (r->group.present & (1U << pos))
			mech_recycle(&r->pool, r->group_frames[pos]);
	xdev_ext_mech_group_init(&r->group, 0, 0);
}

static void test_mech_rx_runs_at_serialized_sites_while_live(void)
{
	EXPECT_EQ(xsk_xdev_ext_mech_rx_runs(XDEV_EXT_MECH_SITE_RX_GENERIC, true, false), true);
	EXPECT_EQ(xsk_xdev_ext_mech_rx_runs(XDEV_EXT_MECH_SITE_RX_GENERIC, false, false), false);
	EXPECT_EQ(xsk_xdev_ext_mech_rx_runs(XDEV_EXT_MECH_SITE_RX_NATIVE, true, false), false);
	EXPECT_EQ(xsk_xdev_ext_mech_rx_runs(XDEV_EXT_MECH_SITE_RX_NATIVE, true, true), true);
	EXPECT_EQ(xsk_xdev_ext_mech_rx_runs(XDEV_EXT_MECH_SITE_RX_NATIVE, false, true), false);
	EXPECT_EQ(xsk_xdev_ext_mech_rx_runs(XDEV_EXT_MECH_SITE_WORKER, true, true), false);
}

static void test_mech_rx_hold_reserves_nothing(void)
{
	struct mech_prog prog;
	struct mech_rx r;
	uint32_t pos;

	mech_rx_init(&r);
	for (pos = 0; pos < 6; pos++)
		mech_fq_put(&r.pool, pos + 2);
	for (pos = 0; pos < 6; pos++) {
		prog = mech_hold_prog(41, pos, 6);
		EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
				       MECH_PKT_LEN, 1), XDEV_EXT_MECH_HOLD);
		EXPECT_EQ(r.pool.state[r.last], XDEV_EXT_MECH_F_HELD);
		EXPECT_EQ(r.group_frames[pos], r.last);
	}
	EXPECT_EQ(r.rx_prod, 0);	/* the RX producer never moved */
	EXPECT_EQ(r.rx_cap, MECH_RING);
	EXPECT_EQ(r.held, 6);
	EXPECT_EQ(r.published, 0);
	EXPECT_EQ(r.protocol_err, 0);
	EXPECT_EQ(r.pool.free_cnt, 0);
	EXPECT_EQ(r.pool.recycle_cnt, 0);
	EXPECT_EQ(xdev_ext_mech_group_full(&r.group), true);
}

static void test_mech_rx_intent_commits_only_on_hold(void)
{
	struct mech_prog prog;
	struct mech_rx r;

	mech_rx_init(&r);
	mech_fq_put(&r.pool, 3);
	prog = mech_hold_prog(7, 0, 6);
	prog.ret = XDEV_EXT_MECH_PUBLISH;	/* recorded, then published */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(r.group.present, 0);
	EXPECT_EQ(r.held, 0);
	EXPECT_EQ(r.rx_prod, 1);
	EXPECT_EQ(r.pool.state[3], XDEV_EXT_MECH_F_USER);
	EXPECT_EQ(r.protocol_err, 0);

	mech_fq_put(&r.pool, 4);
	prog.ret = XDEV_EXT_MECH_RECYCLE;	/* recorded, then recycled */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_RECYCLE);
	EXPECT_EQ(r.group.present, 0);
	EXPECT_EQ(r.held, 0);
	EXPECT_EQ(r.rx_prod, 1);
	EXPECT_EQ(r.protocol_err, 0);
}

static void test_mech_rx_publish_hands_kernel_frame_to_user(void)
{
	struct mech_prog prog = { .ret = XDEV_EXT_MECH_PUBLISH };
	struct mech_rx r;

	mech_rx_init(&r);
	mech_recycle(&r.pool, 9);	/* kernel partition, on the llist */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(r.last, 9);
	EXPECT_EQ(r.pool.splices, 1);
	EXPECT_EQ(r.pool.state[9], XDEV_EXT_MECH_F_USER);
	EXPECT_EQ(r.published, 1);
	/* The user owns it now and may fill it again. */
	EXPECT_EQ(xsk_xdev_ext_mech_fq_ok(r.pool.state, MECH_CHUNKS, 9), true);
}

static void test_mech_rx_recycle_goes_through_the_llist(void)
{
	struct mech_prog prog = { .ret = XDEV_EXT_MECH_RECYCLE };
	struct mech_rx r;

	mech_rx_init(&r);
	mech_fq_put(&r.pool, 5);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_RECYCLE);
	EXPECT_EQ(r.pool.state[5], XDEV_EXT_MECH_F_K_FREE);
	EXPECT_EQ(r.pool.recycle_cnt, 1);
	EXPECT_EQ(r.pool.free_cnt, 0);	/* the complete never touches free_list */
	EXPECT_EQ(r.rx_prod, 0);
	EXPECT_EQ(r.published, 0);

	prog.ret = XDEV_EXT_MECH_PUBLISH;
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(r.last, 5);		/* spliced back by the allocator */
	EXPECT_EQ(r.pool.splices, 1);
}

static void test_mech_rx_native_zc_holds_while_live(void)
{
	struct mech_prog prog = mech_hold_prog(1, 0, 6);
	struct mech_rx r;

	mech_rx_init(&r);
	r.zero_copy = true;
	mech_fq_put(&r.pool, 2);
	mech_fq_put(&r.pool, 3);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_NATIVE,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_HOLD);
	r.live = false;
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_NATIVE,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(r.program_runs, 1);
	EXPECT_EQ(r.native_publish, 1);
	EXPECT_EQ(r.held, 1);
	EXPECT_EQ(r.rx_prod, 1);
	EXPECT_EQ(r.protocol_err, 0);
}

static void test_mech_rx_native_copy_publishes(void)
{
	struct mech_prog prog = mech_hold_prog(1, 0, 6);
	struct mech_rx r;

	mech_rx_init(&r);
	mech_fq_put(&r.pool, 2);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_NATIVE,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(r.program_runs, 0);
	EXPECT_EQ(r.native_publish, 1);
	EXPECT_EQ(r.held, 0);
	EXPECT_EQ(r.rx_prod, 1);
	EXPECT_EQ(r.protocol_err, 0);
}

static void test_mech_rx_multibuffer_publishes(void)
{
	struct mech_prog prog = mech_hold_prog(1, 0, 6);
	struct mech_rx r;

	mech_rx_init(&r);
	mech_recycle(&r.pool, 6);
	mech_fq_put(&r.pool, 7);
	mech_fq_put(&r.pool, 8);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       3 * MECH_CHUNK_SIZE, 3), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(r.program_runs, 0);
	EXPECT_EQ(r.held, 0);
	EXPECT_EQ(r.rx_prod, 3);
	EXPECT_EQ(r.published, 3);
	EXPECT_EQ(r.pool.state[6], XDEV_EXT_MECH_F_USER);
	EXPECT_EQ(r.pool.state[7], XDEV_EXT_MECH_F_USER);
}

static void test_mech_rx_bad_intent_or_return_publishes(void)
{
	static const int32_t illegal[] = {
		XDEV_EXT_MECH_NEXT, XDEV_EXT_MECH_DONE, XDEV_EXT_MECH_RETRY, XDEV_EXT_MECH_ABORT,
		99, -1,
	};
	struct xdev_ext_mech_hold_intent hold;
	struct mech_prog prog;
	struct mech_rx r;
	bool perr, npub;
	uint32_t i, n = 0;

	mech_rx_init(&r);
	for (i = 0; i < MECH_CHUNKS; i++)
		mech_fq_put(&r.pool, i);

	prog = mech_hold_prog(1, 0, 6);
	prog.hold_calls = 0;		/* HOLD with nothing recorded */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	n++;
	prog = mech_hold_prog(1, 0, 0);	/* count 0 */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	n++;
	prog = mech_hold_prog(1, 6, 6);	/* pos past count */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	n++;
	prog = mech_hold_prog(1, 0, 6);
	prog.intent.span_off = MECH_DATA_OFF - 1;	/* before the packet */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	n++;
	prog = mech_hold_prog(1, 0, 6);
	prog.intent.span_len = MECH_PKT_LEN;	/* past the packet end */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	n++;
	prog = mech_hold_prog(1, 0, 6);
	prog.intent.span_len = 0;
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	n++;
	prog = mech_hold_prog(1, 0, 6);
	prog.hold_calls = 2;		/* the second call latches misuse */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	n++;
	for (i = 0; i < sizeof(illegal) / sizeof(illegal[0]); i++) {
		prog = mech_hold_prog(1, 0, 6);
		prog.ret = illegal[i];
		EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
				       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
		n++;
	}
	EXPECT_EQ(r.protocol_err, n);
	EXPECT_EQ(r.held, 0);
	EXPECT_EQ(r.rx_prod, n);
	EXPECT_EQ(r.published, n);

	/* A failed callback publishes whatever it returned or recorded. */
	hold = mech_hold_prog(1, 0, 6).intent;
	EXPECT_EQ(xsk_xdev_ext_mech_rx_verdict(XDEV_EXT_MECH_SITE_RX_GENERIC, true,
					  -EPROTO, XDEV_EXT_MECH_HOLD, &hold,
					  MECH_DATA_OFF, MECH_PKT_LEN, &perr,
					  &npub), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(perr, true);
	EXPECT_EQ(npub, false);
	EXPECT_EQ(xsk_xdev_ext_mech_rx_verdict(XDEV_EXT_MECH_SITE_RX_GENERIC, true,
					  -ENOENT, XDEV_EXT_MECH_RECYCLE, &hold,
					  MECH_DATA_OFF, MECH_PKT_LEN, &perr,
					  &npub), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(perr, true);
}

static void test_mech_rx_stopping_session_publishes(void)
{
	struct mech_prog prog = mech_hold_prog(1, 0, 6);
	struct mech_rx r;
	bool perr, npub;

	mech_rx_init(&r);
	r.live = false;			/* STOPPING, generation gone, or dead */
	mech_fq_put(&r.pool, 2);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(r.program_runs, 0);
	EXPECT_EQ(r.held, 0);
	EXPECT_EQ(r.protocol_err, 0);
	EXPECT_EQ(r.native_publish, 0);
	EXPECT_EQ(r.rx_prod, 1);

	/* Whatever ret and the intent say when nothing ran, it publishes. */
	EXPECT_EQ(xsk_xdev_ext_mech_rx_verdict(XDEV_EXT_MECH_SITE_RX_GENERIC, false, 0,
					  XDEV_EXT_MECH_HOLD, &prog.intent,
					  MECH_DATA_OFF, MECH_PKT_LEN, &perr,
					  &npub), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(perr, false);
	EXPECT_EQ(npub, false);
}

static void test_mech_rx_failed_commit_publishes(void)
{
	struct mech_prog prog = mech_hold_prog(3, 1, 6);
	struct mech_rx r;

	mech_rx_init(&r);
	mech_fq_put(&r.pool, 2);
	mech_fq_put(&r.pool, 4);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_HOLD);
	/* Same position again: the core refuses, the frame is untouched. */
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_PUBLISH);
	EXPECT_EQ(r.last, 4);
	EXPECT_EQ(r.pool.state[4], XDEV_EXT_MECH_F_USER);
	EXPECT_EQ(r.pool.state[2], XDEV_EXT_MECH_F_HELD);
	EXPECT_EQ(r.held, 1);
	EXPECT_EQ(r.protocol_err, 1);
	EXPECT_EQ(r.rx_prod, 1);
}

static void test_mech_rx_full_ring_keeps_frame_in_kernel(void)
{
	struct mech_prog prog = { .ret = XDEV_EXT_MECH_PUBLISH };
	struct mech_rx r;
	uint32_t idx;

	mech_rx_init(&r);
	r.rx_cap = 0;
	mech_fq_put(&r.pool, 6);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), -ENOBUFS);
	EXPECT_EQ(r.pool.state[6], XDEV_EXT_MECH_F_K_FREE);
	EXPECT_EQ(r.published, 0);
	/* The kernel reuses it; the user cannot hand it in a second time. */
	mech_fq_put(&r.pool, 6);
	EXPECT_EQ(mech_xp_alloc(&r.pool, &idx), true);
	EXPECT_EQ(idx, 6);
	EXPECT_EQ(mech_xp_alloc(&r.pool, &idx), false);
	EXPECT_EQ(r.pool.invalid_descs, 1);
}

static void test_mech_rx_group_timeout_recycles_every_frame(void)
{
	struct mech_prog prog;
	struct mech_rx r;
	uint32_t pos, got[8];

	mech_rx_init(&r);
	for (pos = 0; pos < 4; pos++) {
		mech_fq_put(&r.pool, pos + 8);
		prog = mech_hold_prog(9, pos, 6);
		EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
				       MECH_PKT_LEN, 1), XDEV_EXT_MECH_HOLD);
	}
	mech_group_timeout(&r);
	EXPECT_EQ(r.pool.recycled, 4);
	EXPECT_EQ(r.pool.recycle_cnt, 4);
	EXPECT_EQ(r.rx_prod, 0);	/* nothing published */
	EXPECT_EQ(r.published, 0);
	for (pos = 0; pos < 4; pos++)
		EXPECT_EQ(r.pool.state[pos + 8], XDEV_EXT_MECH_F_K_FREE);
	EXPECT_EQ(mech_xp_alloc_batch(&r.pool, got, 8), 4);
	EXPECT_EQ(r.pool.splices, 1);
}

static void test_mech_rx_held_frame_refused_in_fill_ring(void)
{
	struct mech_prog prog = mech_hold_prog(2, 0, 6);
	struct mech_rx r;

	mech_rx_init(&r);
	mech_fq_put(&r.pool, 3);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_HOLD);
	mech_fq_put(&r.pool, 3);	/* the user hands in the held frame */
	mech_fq_put(&r.pool, 4);
	prog = mech_hold_prog(2, 1, 6);
	EXPECT_EQ(mech_receive(&r, &prog, XDEV_EXT_MECH_SITE_RX_GENERIC,
			       MECH_PKT_LEN, 1), XDEV_EXT_MECH_HOLD);
	EXPECT_EQ(r.last, 4);
	EXPECT_EQ(r.pool.invalid_descs, 1);
	EXPECT_EQ(r.group_frames[0], 3);
	EXPECT_EQ(r.group_frames[1], 4);
	EXPECT_EQ(r.pool.state[3], XDEV_EXT_MECH_F_HELD);
}

static void test_mech_settle_edges(void)
{
	uint32_t from = 0, to = 0;

	EXPECT_EQ(xsk_xdev_ext_mech_settle_edge(XDEV_EXT_MECH_F_USER, true, &from, &to), 0);
	EXPECT_EQ(xsk_xdev_ext_mech_settle_edge(XDEV_EXT_MECH_F_K_FREE, false, &from,
					   &to), 0);
	EXPECT_EQ(xsk_xdev_ext_mech_settle_edge(XDEV_EXT_MECH_F_K_FREE, true, &from, &to),
		  1);
	EXPECT_EQ(from, XDEV_EXT_MECH_F_K_FREE);
	EXPECT_EQ(to, XDEV_EXT_MECH_F_USER);
	EXPECT_EQ(xsk_xdev_ext_mech_settle_edge(XDEV_EXT_MECH_F_USER, false, &from, &to),
		  1);
	EXPECT_EQ(from, XDEV_EXT_MECH_F_USER);
	EXPECT_EQ(to, XDEV_EXT_MECH_F_K_FREE);
	EXPECT_EQ(xsk_xdev_ext_mech_settle_edge(XDEV_EXT_MECH_F_HELD, true, &from, &to),
		  -EPROTO);
	EXPECT_EQ(xsk_xdev_ext_mech_settle_edge(XDEV_EXT_MECH_F_INFLIGHT, false, &from,
					   &to), -EPROTO);
	EXPECT_EQ(xsk_xdev_ext_mech_settle_edge(XDEV_EXT_MECH_F_SEQUESTERED, true, &from,
					   &to), -EPROTO);
}

int main(void)
{
	test_copy_single_and_multibuffer_order();
	test_zero_copy_dispatches_after_dma();
	test_terminal_never_copies_publishes_or_completes();
	test_reserve_and_prepublication_failure_unwind();
	test_legacy_policy_is_c_fallback_without_callback();
	test_teardown_unwinds_unpublished_token_once();
	test_core_rejects_wrong_order_and_inexact_publication();
	test_mech_pool_admission();
	test_mech_shared_umem_bind_busy();
	test_mech_fill_ring_refuses_session_frames();
	test_mech_recycle_rejoins_free_list_at_allocator();
	test_mech_source_alloc_needs_no_rx_ring();
	test_mech_afxdp_kfunc_bounds();
	test_mech_rx_runs_at_serialized_sites_while_live();
	test_mech_rx_hold_reserves_nothing();
	test_mech_rx_intent_commits_only_on_hold();
	test_mech_rx_publish_hands_kernel_frame_to_user();
	test_mech_rx_recycle_goes_through_the_llist();
	test_mech_rx_native_zc_holds_while_live();
	test_mech_rx_native_copy_publishes();
	test_mech_rx_multibuffer_publishes();
	test_mech_rx_bad_intent_or_return_publishes();
	test_mech_rx_stopping_session_publishes();
	test_mech_rx_failed_commit_publishes();
	test_mech_rx_full_ring_keeps_frame_in_kernel();
	test_mech_rx_group_timeout_recycles_every_frame();
	test_mech_rx_held_frame_refused_in_fill_ring();
	test_mech_settle_edges();

	if (tests_failed) {
		fprintf(stderr, "FAIL: %u of %u checks failed\n",
			tests_failed, tests_run);
		return 1;
	}
	printf("PASS: %u AF_XDP RX policy checks\n", tests_run);
	return 0;
}

/* SPDX-License-Identifier: MIT */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#if __has_include("../kernel-open/nvidia/nv-xdev_ext-ce-async.h")
#include "../kernel-open/nvidia/nv-xdev_ext-ce-async.h"
#define HAVE_PRODUCTION_ASYNC_HELPER 1
#else
#include "nv_xdev_ext_ce_async_contract.h"
#endif

static unsigned int checks, failures;

#define CHECK(condition) do { \
	checks++; \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d FAIL: %s\n", __func__, __LINE__, #condition); \
		failures++; \
	} \
} while (0)

#define REQUIRE(condition) do { \
	checks++; \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d FAIL: %s\n", __func__, __LINE__, #condition); \
		failures++; return; \
	} \
} while (0)

#define EQ64(expected, actual) do { \
	uint64_t e_ = (uint64_t)(expected), a_ = (uint64_t)(actual); \
	checks++; \
	if (e_ != a_) { \
		fprintf(stderr, "%s:%d FAIL: expected 0x%" PRIx64 \
			" got 0x%" PRIx64 "\n", __func__, __LINE__, e_, a_); \
		failures++; \
	} \
} while (0)

#define HIGH_TOKEN (UINT64_C(1) << 40)
#define HIGH_TICKET ((UINT64_C(1) << 60) | 5)

static void bounded_preallocated_slots(void)
{
	struct {
		uint64_t before;
		struct nv_xdev_ext_ce_async_slot slots[2];
		uint64_t after;
	} storage = { .before = UINT64_C(0x0123456789abcdef),
		      .after = UINT64_C(0xfedcba9876543210) };
	struct nv_xdev_ext_ce_async_pool p;
	struct nv_xdev_ext_ce_async_slot *a = NULL, *b = NULL, *extra = NULL;
	int cookies[3];

	REQUIRE(nv_xdev_ext_ce_async_init(&p, storage.slots, 2) == 0);
	CHECK(p.slots == storage.slots && p.capacity == 2);
	CHECK(nv_xdev_ext_ce_async_can_release(&p));
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 1, &cookies[0], 4096, &a) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 2, &cookies[1], 8192, &b) == 0);
	CHECK(a != b);
	CHECK((a == &storage.slots[0] || a == &storage.slots[1]) &&
	      (b == &storage.slots[0] || b == &storage.slots[1]));
	CHECK(a->state == NV_XDEV_EXT_CE_ASYNC_RESERVED);
	CHECK(!nv_xdev_ext_ce_async_can_release(&p));
	CHECK(nv_xdev_ext_ce_async_reserve(&p, 3, &cookies[2], 1, &extra) == -EAGAIN);
	EQ64(1, a->ticket);
	EQ64(2, b->ticket);
	EQ64(UINT64_C(0x0123456789abcdef), storage.before);
	EQ64(UINT64_C(0xfedcba9876543210), storage.after);
}

static void pending_waits_for_full_width_token(void)
{
	struct nv_xdev_ext_ce_async_slot slots[1], *s = NULL;
	struct nv_xdev_ext_ce_async_pool p;
	struct nv_xdev_ext_ce_async_completion c = {0};
	int cookie;
	const uint64_t token = HIGH_TOKEN + 19;

	REQUIRE(nv_xdev_ext_ce_async_init(&p, slots, 1) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, HIGH_TICKET, &cookie, 16384, &s) == 0);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, s, 0, 1, token) == NV_XDEV_EXT_CE_OK);
	CHECK(s->state == NV_XDEV_EXT_CE_ASYNC_PENDING);
	EQ64(token, s->token);
	CHECK(!nv_xdev_ext_ce_async_can_release(&p));
	CHECK(nv_xdev_ext_ce_async_ready(&p, s, (uint32_t)token, &c) == 0);
	CHECK(nv_xdev_ext_ce_async_ready(&p, s, token - 1, &c) == 0);
	CHECK(s->state == NV_XDEV_EXT_CE_ASYNC_PENDING);
	EQ64(HIGH_TICKET, s->ticket);
	CHECK(s->cookie == &cookie);
	EQ64(16384, s->bytes);
	REQUIRE(nv_xdev_ext_ce_async_ready(&p, s, token, &c) == 1);
	EQ64(HIGH_TICKET, c.ticket);
	EQ64(token, c.token);
	EQ64(16384, c.bytes);
	CHECK(c.cookie == &cookie);
	CHECK(nv_xdev_ext_ce_async_ready(&p, s, token, &c) == 0);
	CHECK(nv_xdev_ext_ce_async_ready(&p, s, UINT64_MAX, &c) == 0);
	CHECK(nv_xdev_ext_ce_async_can_release(&p));
}

static void watermark_completes_only_covered_requests(void)
{
	struct nv_xdev_ext_ce_async_slot slots[2], *a = NULL, *b = NULL;
	struct nv_xdev_ext_ce_async_pool p;
	struct nv_xdev_ext_ce_async_completion c;
	int cookies[2];

	REQUIRE(nv_xdev_ext_ce_async_init(&p, slots, 2) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 41, &cookies[0], 100, &a) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 42, &cookies[1], 200, &b) == 0);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, a, 0, 1, HIGH_TOKEN + 5) == NV_XDEV_EXT_CE_OK);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, b, 0, 1, HIGH_TOKEN + 8) == NV_XDEV_EXT_CE_OK);
	CHECK(nv_xdev_ext_ce_async_ready(&p, b, HIGH_TOKEN + 5, &c) == 0);
	REQUIRE(nv_xdev_ext_ce_async_ready(&p, a, HIGH_TOKEN + 5, &c) == 1);
	EQ64(41, c.ticket);
	CHECK(!nv_xdev_ext_ce_async_can_release(&p));
	REQUIRE(nv_xdev_ext_ce_async_ready(&p, b, HIGH_TOKEN + 9, &c) == 1);
	EQ64(42, c.ticket);
	CHECK(c.cookie == &cookies[1]);
	CHECK(nv_xdev_ext_ce_async_can_release(&p));
}

static void reused_slot_rejects_stale_completion(void)
{
	struct nv_xdev_ext_ce_async_slot slots[1], *s = NULL, *new_s = NULL;
	struct nv_xdev_ext_ce_async_pool p;
	struct nv_xdev_ext_ce_async_completion c;
	int cookies[2];
	const uint64_t old_token = HIGH_TOKEN + 7;
	/* Deliberately identical low 32 bits in successive tokens. */
	const uint64_t new_token = old_token + (UINT64_C(1) << 32);

	REQUIRE(nv_xdev_ext_ce_async_init(&p, slots, 1) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, HIGH_TICKET, &cookies[0], 64, &s) == 0);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, s, 0, 1, old_token) == NV_XDEV_EXT_CE_OK);
	REQUIRE(nv_xdev_ext_ce_async_ready(&p, s, old_token, &c) == 1);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, HIGH_TICKET + 8, &cookies[1], 128, &new_s) == 0);
	CHECK(new_s == s);
	CHECK(nv_xdev_ext_ce_async_ready(&p, new_s, UINT64_MAX, &c) == 0);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, new_s, 0, 1, new_token) == NV_XDEV_EXT_CE_OK);
	CHECK(nv_xdev_ext_ce_async_ready(&p, new_s, old_token, &c) == 0);
	EQ64(HIGH_TICKET + 8, new_s->ticket);
	EQ64(new_token, new_s->token);
	CHECK(new_s->cookie == &cookies[1]);
	REQUIRE(nv_xdev_ext_ce_async_ready(&p, new_s, new_token, &c) == 1);
	EQ64(HIGH_TICKET + 8, c.ticket);
	EQ64(128, c.bytes);
	CHECK(c.cookie == &cookies[1]);
}

static void no_submit_failure_releases_only_its_slot(void)
{
	struct nv_xdev_ext_ce_async_slot slots[2], *a = NULL, *b = NULL, *reused = NULL;
	struct nv_xdev_ext_ce_async_pool p;
	struct nv_xdev_ext_ce_async_completion c;
	int cookies[3];

	REQUIRE(nv_xdev_ext_ce_async_init(&p, slots, 2) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 1, &cookies[0], 64, &a) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 2, &cookies[1], 128, &b) == 0);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, a, 0, 1, HIGH_TOKEN + 1) == NV_XDEV_EXT_CE_OK);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, b, -ENOMEM, 0, 0) == NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED);
	CHECK(b->state == NV_XDEV_EXT_CE_ASYNC_FREE);
	CHECK(nv_xdev_ext_ce_async_ready(&p, b, UINT64_MAX, &c) == 0);
	CHECK(!p.quarantined);
	CHECK(!nv_xdev_ext_ce_async_can_release(&p));
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 3, &cookies[2], 256, &reused) == 0);
	CHECK(reused == b);
	EQ64(HIGH_TOKEN + 1, a->token);
	CHECK(a->state == NV_XDEV_EXT_CE_ASYNC_PENDING);
}

static void partial_submit_failure_is_permanent_quarantine(void)
{
	struct nv_xdev_ext_ce_async_slot slots[2], *a = NULL, *b = NULL, *extra = NULL;
	struct nv_xdev_ext_ce_async_pool p;
	struct nv_xdev_ext_ce_async_completion c;
	int cookies[3];

	REQUIRE(nv_xdev_ext_ce_async_init(&p, slots, 2) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 1, &cookies[0], 1024, &a) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, HIGH_TICKET, &cookies[1], 4096, &b) == 0);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, a, 0, 1, HIGH_TOKEN + 1) == NV_XDEV_EXT_CE_OK);
	/* A chunk was issued, then a later submission failed: no safe rollback. */
	CHECK(nv_xdev_ext_ce_async_submitted(&p, b, -EIO, 1, HIGH_TOKEN + 2) == NV_XDEV_EXT_CE_AMBIGUOUS);
	CHECK(b->state == NV_XDEV_EXT_CE_ASYNC_QUARANTINED);
	CHECK(p.quarantined);
	EQ64(HIGH_TICKET, b->ticket);
	CHECK(b->cookie == &cookies[1]);
	EQ64(4096, b->bytes);
	CHECK(nv_xdev_ext_ce_async_ready(&p, b, UINT64_MAX, &c) == 0);
	CHECK(nv_xdev_ext_ce_async_reserve(&p, 3, &cookies[2], 1, &extra) == -ESHUTDOWN);
	CHECK(!nv_xdev_ext_ce_async_can_release(&p));
	nv_xdev_ext_ce_async_stop(&p);
	REQUIRE(nv_xdev_ext_ce_async_ready(&p, a, HIGH_TOKEN + 1, &c) == 1);
	CHECK(!nv_xdev_ext_ce_async_can_release(&p));
	CHECK(b->state == NV_XDEV_EXT_CE_ASYNC_QUARANTINED);
	CHECK(nv_xdev_ext_ce_async_ready(&p, b, UINT64_MAX, &c) == 0);
}

static void teardown_requires_drain_and_never_completes_reserved(void)
{
	struct nv_xdev_ext_ce_async_slot slots[2], *a = NULL, *b = NULL, *extra = NULL;
	struct nv_xdev_ext_ce_async_pool p;
	struct nv_xdev_ext_ce_async_completion c;
	int cookies[3];

	REQUIRE(nv_xdev_ext_ce_async_init(&p, slots, 2) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 1, &cookies[0], 64, &a) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, 2, &cookies[1], 128, &b) == 0);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, a, 0, 1, HIGH_TOKEN + 10) == NV_XDEV_EXT_CE_OK);
	nv_xdev_ext_ce_async_stop(&p);
	nv_xdev_ext_ce_async_stop(&p);
	CHECK(nv_xdev_ext_ce_async_reserve(&p, 3, &cookies[2], 1, &extra) == -ESHUTDOWN);
	CHECK(!nv_xdev_ext_ce_async_can_release(&p));
	CHECK(nv_xdev_ext_ce_async_ready(&p, b, UINT64_MAX, &c) == 0);
	CHECK(b->state == NV_XDEV_EXT_CE_ASYNC_RESERVED);
	CHECK(nv_xdev_ext_ce_async_ready(&p, a, HIGH_TOKEN + 9, &c) == 0);
	REQUIRE(nv_xdev_ext_ce_async_ready(&p, a, HIGH_TOKEN + 10, &c) == 1);
	CHECK(!nv_xdev_ext_ce_async_can_release(&p));
	CHECK(nv_xdev_ext_ce_async_submitted(&p, b, -ECANCELED, 0, 0) == NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED);
	CHECK(nv_xdev_ext_ce_async_can_release(&p));
	CHECK(nv_xdev_ext_ce_async_reserve(&p, 3, &cookies[2], 1, &extra) == -ESHUTDOWN);
}

static void token_comparison_near_u64_limit(void)
{
	struct nv_xdev_ext_ce_async_slot slots[1], *s = NULL;
	struct nv_xdev_ext_ce_async_pool p;
	struct nv_xdev_ext_ce_async_completion c;
	int cookie;

	REQUIRE(nv_xdev_ext_ce_async_init(&p, slots, 1) == 0);
	REQUIRE(nv_xdev_ext_ce_async_reserve(&p, HIGH_TICKET, &cookie, 64, &s) == 0);
	CHECK(nv_xdev_ext_ce_async_submitted(&p, s, 0, 1, UINT64_MAX) == NV_XDEV_EXT_CE_OK);
	CHECK(nv_xdev_ext_ce_async_ready(&p, s, UINT64_MAX - 1, &c) == 0);
	CHECK(nv_xdev_ext_ce_async_ready(&p, s, 0, &c) == 0);
	REQUIRE(nv_xdev_ext_ce_async_ready(&p, s, UINT64_MAX, &c) == 1);
	EQ64(UINT64_MAX, c.token);
}

int main(void)
{
#ifndef HAVE_PRODUCTION_ASYNC_HELPER
	if (!nv_xdev_ext_ce_async_init || !nv_xdev_ext_ce_async_reserve ||
	    !nv_xdev_ext_ce_async_submitted || !nv_xdev_ext_ce_async_ready ||
	    !nv_xdev_ext_ce_async_stop || !nv_xdev_ext_ce_async_can_release) {
		fprintf(stderr, "FAIL: production nv-xdev_ext-ce-async.h lifecycle helper is missing; "
			"native async slot behavior cannot run (API contract compiles and links).\n");
		return 1;
	}
#endif
	bounded_preallocated_slots();
	pending_waits_for_full_width_token();
	watermark_completes_only_covered_requests();
	reused_slot_rejects_stale_completion();
	no_submit_failure_releases_only_its_slot();
	partial_submit_failure_is_permanent_quarantine();
	teardown_requires_drain_and_never_completes_reserved();
	token_comparison_near_u64_limit();
	printf("nv_xdev_ext_ce_async_test: %u checks, %u failures\n", checks, failures);
	return failures != 0;
}

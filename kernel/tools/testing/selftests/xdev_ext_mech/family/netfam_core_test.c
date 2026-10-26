// SPDX-License-Identifier: GPL-2.0
/* Requirement: exact ordered payload coverage; bounded segmentation; local
 * evidence owns custody, remote evidence owns delivery; no-retry failures
 * must not block receive credit. Derived from plan 4.3/4.8/4.11 and F4.
 * Breaks caught: omitted/overlapping spans, early ACK success, UNKNOWN reuse,
 * invalid rendezvous transitions, accepted RTS replay and stranded windows.
 * Compile with -I <kernel tree>. This does not simulate a device. */
#include <stdio.h>
#if !__has_include("include/linux/xdev_ext_netfam_core.h")
int main(void)
{
	puts("not ok 1 - no network family rules");
	return 1;
}
#else
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_core.h"
#include "include/linux/xdev_ext_mech_reliable_core.h"
#include "include/linux/xdev_ext_netfam_core.h"

static unsigned int checks, failures;
#define EQ(actual, expected) do { \
	long long got_ = (long long)(actual), want_ = (long long)(expected); \
	checks++; \
	if (got_ != want_) { \
		fprintf(stderr, "line %d: %s got %lld expected %lld\n", \
			__LINE__, #actual, got_, want_); \
		failures++; \
	} \
} while (0)

struct cover_ctx {
	struct xdev_ext_net_span s[4];
	unsigned int visits, seen;
	int fail_at, err;
};

static void span_at(const void *arg, __u32 i, struct xdev_ext_net_span *out)
{
	const struct cover_ctx *c = arg;
	*out = c->s[i];
}

static int entry_at(const void *arg, __u32 i)
{
	struct cover_ctx *c = (struct cover_ctx *)arg;
	c->visits++;
	c->seen |= 1U << i;
	return (int)i == c->fail_at ? c->err : 0;
}

static void coverage(void)
{
	struct xdev_ext_mech_frame_info f[3] = {
		{.data_off = 0, .data_len = 2048},
		{.data_off = 4096, .data_len = 100},
		{.data_off = 8192, .data_len = 100},
	};
	struct cover_ctx c = {.s = {{0, 0, 1024, 0}, {0, 1024, 1024, 0}}, .fail_at = -1};
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, NULL, &c), 0);
	c.s[1].frame_off = 1023;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, NULL, &c), -ERANGE);
	c.s[1].frame_off = 1025;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, NULL, &c), -ERANGE);
	c.s[1].frame_off = 1024; c.s[1].len = 1023;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, NULL, &c), -EMSGSIZE);
	c.s[1].len = 1025;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, NULL, &c), -ERANGE);
	c.s[1].len = 1024; c.s[1].frame_pos = 1;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, NULL, &c), -EINVAL);
	c.s[1].frame_pos = 0; c.s[1].bad = 1;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, NULL, &c), -EINVAL);
	c.s[1].bad = 0;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 1, span_at, NULL, &c), -EINVAL);
	EQ(xdev_ext_net_cover_check(f, 1, 0, 4, span_at, NULL, &c), -EINVAL);
	EQ(xdev_ext_net_cover_check(NULL, 1, 2, 4, span_at, NULL, &c), -EINVAL);
	EQ(xdev_ext_net_cover_check(f, 0, 2, 4, span_at, NULL, &c), -EINVAL);
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, NULL, NULL, &c), -EINVAL);
	EQ(xdev_ext_net_cover_check(f, XDEV_EXT_MECH_MAX_FRAMES + 1, 2, 4, span_at, NULL, &c), -EINVAL);
	/* Entry validation must run after the span's range check and stop at
	 * its first error, preserving the callback errno. */
	c.fail_at = 1; c.err = -EACCES;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, entry_at, &c), -EACCES);
	EQ(c.visits, 2); EQ(c.seen, 3);
	c.visits = c.seen = 0; c.fail_at = 0; c.err = -EOPNOTSUPP;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, entry_at, &c), -EOPNOTSUPP);
	EQ(c.visits, 1); EQ(c.seen, 1);
	c.visits = c.seen = 0; c.s[0].frame_off = 1;
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, entry_at, &c), -ERANGE);
	EQ(c.visits, 0); EQ(c.seen, 0);
	c.s[0] = (struct xdev_ext_net_span){0, 0, 2048, 0};
	c.s[1] = (struct xdev_ext_net_span){1, 4096, 100, 0};
	EQ(xdev_ext_net_cover_check(f, 2, 2, 4, span_at, NULL, &c), 0);
	c.s[0].len = 2047;
	EQ(xdev_ext_net_cover_check(f, 2, 2, 4, span_at, NULL, &c), -EMSGSIZE);
	c.s[0].len = 2048; c.s[1].frame_pos = 2; c.s[1].frame_off = 8192;
	EQ(xdev_ext_net_cover_check(f, 3, 2, 4, span_at, NULL, &c), -EMSGSIZE);
	c.s[1] = (struct xdev_ext_net_span){1, 4096, 100, 0};
	c.s[2] = (struct xdev_ext_net_span){0, 0, 1, 0};
	EQ(xdev_ext_net_cover_check(f, 2, 3, 4, span_at, NULL, &c), -EINVAL);
	/* Addition in a wider type must reject a wrapped descriptor offset. */
	f[0].data_off = UINT32_MAX - 1023; c.s[0].frame_off = UINT32_MAX - 1023;
	c.s[0].len = 1024; c.s[1] = (struct xdev_ext_net_span){0, 0, 1024, 0};
	EQ(xdev_ext_net_cover_check(f, 1, 2, 4, span_at, NULL, &c), -ERANGE);
}

static void segmentation(void)
{
	__u32 o = 123, l = 456;
	EQ(xdev_ext_net_segments(0, 8192, 4096, 4096), 2);
	EQ(xdev_ext_net_segments(0, 4097, 4096, 4096), 2);
	EQ(xdev_ext_net_segments(0, 1, 4096, 4096), 1);
	EQ(xdev_ext_net_segments(512, 100, 4096, 4096), 0);
	EQ(xdev_ext_net_segments(0, 0, 4096, 4096), 0);
	EQ(xdev_ext_net_segments(0, 100, 0, 4096), 0);
	EQ(xdev_ext_net_segments(0, 100, 4096, 0), 0);
	EQ(xdev_ext_net_segments(0, UINT32_MAX, 4096, 4096), 1048576);
	xdev_ext_net_segment(4096, 5000, 4096, 0, &o, &l);
	EQ(o, 4096); EQ(l, 4096);
	xdev_ext_net_segment(4096, 5000, 4096, 1, &o, &l);
	EQ(o, 8192); EQ(l, 904);
	EQ(xdev_ext_net_rx_room_ok(0, 1000, 4096, 4096), true);
	EQ(xdev_ext_net_rx_room_ok(4096, 1000, 4096, 8192), true);
	EQ(xdev_ext_net_rx_room_ok(4096, 4097, 4096, 8192), false);
	EQ(xdev_ext_net_rx_room_ok(0, 4096, 4096, 4095), false);
	EQ(xdev_ext_net_rx_room_ok(0, 0, 4096, 4096), false);
	EQ(xdev_ext_net_rx_room_ok(0, 100, 0, 4096), false);
	EQ(xdev_ext_net_rx_room_ok(UINT32_MAX - 1023, 100, 4096, UINT32_MAX), false);
}

static void outcomes(void)
{
	/* Columns: NONE, HELD, ACKED, FAILED, LOST. Literal expected results
	 * independently encode local-error priority and remote-only success. */
	static const int status[3] = {0, -EBADMSG, -ECANCELED};
	static const __u32 remote[5] = {XDEV_EXT_NET_REMOTE_NONE, XDEV_EXT_NET_REMOTE_HELD,
		XDEV_EXT_NET_REMOTE_ACKED, XDEV_EXT_NET_REMOTE_FAILED, XDEV_EXT_NET_REMOTE_LOST};
	static const int expected[2][3][5] = {
		{{-EIO, -EIO, -EIO, -EIO, -EIO},
		 {-EBADMSG, -EBADMSG, -EBADMSG, -EBADMSG, -EBADMSG},
		 {-ECANCELED, -ECANCELED, -ECANCELED, -ECANCELED, -ECANCELED}},
		{{-EINPROGRESS, -EINPROGRESS, 0, -EREMOTEIO, -ENOLINK},
		 {-EBADMSG, -EBADMSG, -EBADMSG, -EBADMSG, -EBADMSG},
		 {-ECANCELED, -ECANCELED, -ECANCELED, -ECANCELED, -ECANCELED}},
	};
	unsigned int q, s, r;
	for (q = 0; q < 2; q++) for (s = 0; s < 3; s++) for (r = 0; r < 5; r++) {
		bool sequester = q; /* opposite of the required output */
		EQ(xdev_ext_net_outcome(status[s], q, remote[r], &sequester), expected[q][s][r]);
		EQ(sequester, !q);
	}
}

static void rendezvous(void)
{
	/* Columns: SUBMIT RTS CTS LOCAL REMOTE CANCEL; rows IDLE ARMED
	 * ANNOUNCED POSTED LOCAL_DONE FINAL. CANCEL from either pre-post
	 * state is permitted in both directions by the frozen helper contract. */
#define P (-EPROTO)
	static const int expected[2][6][6] = {
		{{2, P, P, P, P, P}, {P, P, P, P, P, 5}, {P, P, 3, P, 5, 5},
		 {P, P, P, 4, 3, P}, {P, P, P, P, 5, P}, {P, P, P, P, P, P}},
		{{1, P, P, P, P, P}, {P, 3, P, P, P, 5}, {P, P, P, P, P, 5},
		 {P, P, P, 5, P, P}, {P, P, P, P, P, P}, {P, P, P, P, P, P}},
	};
#undef P
	static const __u32 state[] = {XDEV_EXT_RDV_IDLE, XDEV_EXT_RDV_ARMED,
		XDEV_EXT_RDV_ANNOUNCED, XDEV_EXT_RDV_POSTED, XDEV_EXT_RDV_LOCAL_DONE, XDEV_EXT_RDV_FINAL};
	static const __u32 event[] = {XDEV_EXT_RDV_EV_SUBMIT, XDEV_EXT_RDV_EV_RTS,
		XDEV_EXT_RDV_EV_CTS, XDEV_EXT_RDV_EV_LOCAL, XDEV_EXT_RDV_EV_REMOTE, XDEV_EXT_RDV_EV_CANCEL};
	unsigned int rx, s, e;
	for (rx = 0; rx < 2; rx++) {
		for (s = 0; s < 6; s++) {
			for (e = 0; e < 6; e++)
				EQ(xdev_ext_net_rdv_next(state[s], event[e], rx), expected[rx][s][e]);
			EQ(xdev_ext_net_rdv_next(state[s], 0, rx), -EPROTO);
			EQ(xdev_ext_net_rdv_next(state[s], UINT32_MAX, rx), -EPROTO);
		}
		for (e = 0; e < 6; e++) {
			EQ(xdev_ext_net_rdv_next(6, event[e], rx), -EPROTO);
			EQ(xdev_ext_net_rdv_next(UINT32_MAX, event[e], rx), -EPROTO);
		}
	}
}

static struct xdev_ext_rel_cfg config(void)
{
	return (struct xdev_ext_rel_cfg){.session = 91, .first_group = 10,
		.timeout_ns = 1000, .window = 4, .max_attempts = 1,
		.group_bytes = 8192, .seg_len = 4096, .initial_credit = 2};
}

static void rts_credit_abort(void)
{
	struct xdev_ext_rel_cfg cfg = config();
	struct xdev_ext_rel_rx r, before;
	struct xdev_ext_rel_tx t, tx_before;
	struct xdev_ext_rel_tx_entry *e;
	EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
	before = r;
	EQ(xdev_ext_net_rts_check(&r, 92, 10, 8192, 2, 8192, 2), -ESTALE);
	EQ(xdev_ext_net_rts_check(&r, 91, 0, 8192, 2, 8192, 2), -ERANGE);
	EQ(xdev_ext_net_rts_check(&r, 91, 9, 8192, 2, 8192, 2), -ERANGE);
	EQ(xdev_ext_net_rts_check(&r, 91, 12, 8192, 2, 8192, 2), -ERANGE);
	EQ(xdev_ext_net_rts_check(&r, 91, 13, 8192, 2, 8192, 2), -ERANGE);
	EQ(xdev_ext_net_rts_check(&r, 91, 10, 8191, 2, 8192, 2), -EMSGSIZE);
	EQ(xdev_ext_net_rts_check(&r, 91, 10, 8192, 1, 8192, 2), -EMSGSIZE);
	EQ(xdev_ext_net_rts_check(&r, 91, 10, 8192, 2, 8192, 2), 0);
	EQ(memcmp(&r, &before, sizeof(r)), 0); /* checking is not accepting */
	r.entry[10 % 4] = (struct xdev_ext_rel_rx_entry){.group = 6, .present = ~0U,
		.latest_attempt = 9, .state = XDEV_EXT_REL_RX_DONE, .reply = XDEV_EXT_REL_ACK};
	EQ(xdev_ext_net_rts_check(&r, 91, 10, 8192, 2, 8192, 2), 0);
	xdev_ext_net_rts_accept(&r, 10);
	EQ(r.entry[2].group, 10); EQ(r.entry[2].state, XDEV_EXT_REL_RX_COLLECT);
	EQ(r.entry[2].present, 0); EQ(r.entry[2].total_len, 8192); EQ(r.entry[2].count, 2);
	EQ(r.entry[2].latest_attempt, 0); EQ(r.entry[2].reply, 0);
	EQ(xdev_ext_net_rts_check(&r, 91, 10, 8192, 2, 8192, 2), -EEXIST);
	EQ(r.base_group, 10); EQ(r.credit, 12);
	EQ(xdev_ext_rel_tx_init(&t, &cfg), 0);
	tx_before = t;
	EQ(xdev_ext_net_credit_update(&t, 11), -ERANGE);
	EQ(xdev_ext_net_credit_update(&t, 15), -ERANGE);
	EQ(memcmp(&t, &tx_before, sizeof(t)), 0);
	EQ(xdev_ext_net_credit_update(&t, 14), 0); EQ(t.credit, 14);
	EQ(xdev_ext_net_credit_update(&t, 12), 0); EQ(t.credit, 14);
	EQ(xdev_ext_net_credit_update(&t, 13), 0); EQ(t.credit, 14);
	cfg.initial_credit = 0;
	EQ(xdev_ext_rel_tx_init(&t, &cfg), 0);
	EQ(xdev_ext_net_credit_update(&t, 13), -ERANGE); EQ(t.credit, 14);
	EQ(xdev_ext_net_tx_abort(&t, 10), -ENOENT);
	EQ(xdev_ext_rel_tx_open(&t, 10, 8192, 2), XDEV_EXT_REL_SEND);
	EQ(xdev_ext_net_tx_abort(&t, 14), -ENOENT); /* colliding slot is another identity */
	e = xdev_ext_rel_tx_find(&t, 10);
	EQ(e != NULL, true);
	EQ(e->attempt, 0);
	EQ(xdev_ext_net_tx_abort(&t, 10), 0);
	EQ(e->terminal, XDEV_EXT_REL_UNKNOWN); EQ(e->native_pending, 0);
	EQ(xdev_ext_rel_tx_retire(&t, 10), 0); EQ(t.base_group, 11); EQ(e->live, 0);
	EQ(xdev_ext_rel_tx_open(&t, 11, 8192, 2), XDEV_EXT_REL_SEND);
	EQ(xdev_ext_rel_tx_native_begin(&t, 11, 0), XDEV_EXT_REL_SEND);
	tx_before = t;
	EQ(xdev_ext_net_tx_abort(&t, 11), -EBUSY);
	EQ(memcmp(&t, &tx_before, sizeof(t)), 0);
	EQ(xdev_ext_rel_tx_retire(&t, 11), -EBUSY);
	/* Valid near-limit state: advancing credit may not wrap. */
	cfg.first_group = UINT64_MAX - 4;
	EQ(xdev_ext_rel_tx_init(&t, &cfg), 0);
	EQ(xdev_ext_rel_tx_open(&t, UINT64_MAX - 4, 8192, 2), XDEV_EXT_REL_SEND);
	tx_before = t;
	EQ(xdev_ext_net_credit_update(&t, UINT64_MAX), -ERANGE);
	EQ(memcmp(&t, &tx_before, sizeof(t)), 0);
}

static void window_close(void)
{
	struct xdev_ext_rel_cfg cfg = config();
	struct xdev_ext_rel_rx r, before;
	unsigned int i;
	cfg.initial_credit = 0;
	EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
	xdev_ext_net_rts_accept(&r, 10); r.entry[2].state = XDEV_EXT_REL_RX_FAILED;
	xdev_ext_net_rts_accept(&r, 11); r.entry[3].state = XDEV_EXT_REL_RX_DONE;
	xdev_ext_net_rts_accept(&r, 12); r.entry[0].state = XDEV_EXT_REL_RX_DONE;
	EQ(xdev_ext_net_rx_close(&r, 10), 0); EQ(r.base_group, 13); EQ(r.credit, 17);
	before = r;
	EQ(xdev_ext_net_rx_close(&r, 14), -ENOENT);
	EQ(xdev_ext_net_rx_close(&r, 18), -ENOENT);
	EQ(memcmp(&r, &before, sizeof(r)), 0);
	EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
	/* Closing a later failure cannot skip the earlier group. */
	xdev_ext_net_rts_accept(&r, 10); r.entry[2].state = XDEV_EXT_REL_RX_FAILED;
	xdev_ext_net_rts_accept(&r, 11); r.entry[3].state = XDEV_EXT_REL_RX_FAILED;
	EQ(xdev_ext_net_rx_close(&r, 11), 0); EQ(r.base_group, 10); EQ(r.credit, 14);
	EQ(xdev_ext_net_rx_close(&r, 10), 0); EQ(r.base_group, 12); EQ(r.credit, 16);
	cfg.max_attempts = 2;
	EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
	xdev_ext_net_rts_accept(&r, 10); r.entry[2].state = XDEV_EXT_REL_RX_FAILED;
	before = r;
	EQ(xdev_ext_net_rx_close(&r, 10), -ENOENT); EQ(memcmp(&r, &before, sizeof(r)), 0);
	cfg.max_attempts = 1;
	EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
	/* More than one complete modulo window proves that closed entries do
	 * not strand credit or poison a later group with the same slot. */
	for (i = 0; i < 12; i++) {
		__u64 group = 10 + i;
		EQ(xdev_ext_net_rts_check(&r, 91, group, 8192, 2, 8192, 2), 0);
		xdev_ext_net_rts_accept(&r, group);
		r.entry[group % 4].state = XDEV_EXT_REL_RX_FAILED;
		EQ(xdev_ext_net_rx_close(&r, group), 0);
		EQ(r.base_group, group + 1); EQ(r.credit, group + 5);
	}
	EQ(xdev_ext_net_rts_check(&r, 91, 22, 8192, 2, 8192, 2), 0);
	/* Closing the final admitted identity must never wrap credit. */
	cfg.first_group = UINT64_MAX - 4;
	EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
	xdev_ext_net_rts_accept(&r, UINT64_MAX - 4);
	r.entry[(UINT64_MAX - 4) % 4].state = XDEV_EXT_REL_RX_FAILED;
	EQ(xdev_ext_net_rx_close(&r, UINT64_MAX - 4), 0);
	EQ(r.base_group == UINT64_MAX - 4, true); EQ(r.credit == UINT64_MAX, true);
}

int main(void)
{
	coverage(); segmentation(); outcomes(); rendezvous(); rts_credit_abort(); window_close();
	printf("%s 1 - network family pure rules: %u checks, %u failures\n",
		failures ? "not ok" : "ok", checks, failures);
	return failures ? 1 : 0;
}
#endif

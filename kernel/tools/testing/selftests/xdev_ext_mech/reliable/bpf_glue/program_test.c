// SPDX-License-Identifier: GPL-2.0
/*
 * The production tools/xdev_ext_mech/nxp_reliable.bpf.c compiled as host C
 * (bpf_glue/host + cref host stand-ins for vmlinux.h and libbpf). Kfuncs are
 * recording mocks, so this checks only the program's own protocol
 * decisions: how it classifies a received segment from the C-supplied view,
 * which reply it owes, how it interprets ACK/HELD, whether it emits an owed
 * reply now or defers it under the session policy, and what it writes into a
 * control frame. Wire bytes use an independent network-byte-order oracle (not the production encoder).
 * PROGRAM is the absolute path of the program source.
 */
#include <errno.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmlinux.h"

static struct {
	struct xdev_ext_mech_ctx ctx;
	const void *info;
	size_t info_size;
	__u8 *frames[32];
	__u32 frame_size;
	struct xdp_desc *desc;
	__u32 desc_cap;
	const void *cqe;
	size_t cqe_size;
} M;

/* What the program asked C for, per callback. */
static struct {
	unsigned crc, hold, view, data, control, policy;
	__u64 hold_key; __u32 hold_pos, hold_off, hold_len;
	__u64 view_group;
	__u64 data_group; __u32 data_index, data_attempt, data_verdict;
	__u64 ctl_group, ctl_credit; __u32 ctl_attempt, ctl_type;
} K;
static int view_rc, data_rc, control_rc;

static const void *TX_VIEW;
__u8 *bpf_xdev_ext_rel_tx_view(const struct xdev_ext_mech_ctx *c,const size_t n)
{ (void)c; return n==528 ? (__u8 *)TX_VIEW : NULL; }
#include PROGRAM

static struct xdev_ext_rel_rx_view VIEW;
static struct xdev_ext_rel_policy POLICY;

static __u32 sw_crc32c(__u32 crc, const void *buf, size_t len)
{
	const __u8 *p = buf;
	int k;

	while (len--) {
		crc ^= *p++;
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1)));
	}
	return crc;
}

__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c, const size_t n)
{ (void)c; return n == M.info_size ? (__u8 *)M.info : NULL; }
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c, __u32 slot, const size_t n)
{ (void)c; return n == sizeof(struct xdp_desc) && slot < M.desc_cap ? (__u8 *)&M.desc[slot] : NULL; }
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c, __u32 slot, const size_t n)
{ (void)c; return !slot && n == M.cqe_size ? (__u8 *)M.cqe : NULL; }
__u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, const size_t n)
{ (void)c; return pos < 32 && M.frames[pos] && off + n <= M.frame_size ? M.frames[pos] + off : NULL; }
__u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, __u32 len, __u32 seed)
{ (void)c; K.crc++; return sw_crc32c(seed, M.frames[pos] + off, len); }
__u32 bpf_xdev_ext_crc32c(const void *buf, __u32 n, __u32 seed) { K.crc++; return sw_crc32c(seed, buf, n); }
__u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *c, const size_t n) { (void)c; (void)n; return NULL; }
__u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, const size_t n)
{ (void)c; return pos < 32 && M.frames[pos] && off + n <= M.frame_size ? M.frames[pos] + off : NULL; }
int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *c, __u64 key, __u32 pos, __u32 off, __u32 len)
{ (void)c; K.hold++; K.hold_key = key; K.hold_pos = pos; K.hold_off = off; K.hold_len = len; return 0; }
int bpf_xdev_ext_rel_rx_view(const struct xdev_ext_mech_ctx *c, __u64 group, void *view, __u32 view__sz)
{
	(void)c;
	K.view++;
	K.view_group = group;
	if (view_rc)
		return view_rc;
	if (view__sz != sizeof(VIEW))
		return -EINVAL;
	VIEW.group = group;
	memcpy(view, &VIEW, sizeof(VIEW));
	return 0;
}
int bpf_xdev_ext_rel_rx_data(const struct xdev_ext_mech_ctx *c, __u64 group, __u32 index,
			     __u32 attempt, __u32 verdict)
{
	(void)c;
	K.data++;
	K.data_group = group; K.data_index = index; K.data_attempt = attempt; K.data_verdict = verdict;
	return data_rc;
}
int bpf_xdev_ext_rel_rx_control(const struct xdev_ext_mech_ctx *c, __u64 group, __u32 attempt,
				__u64 credit, __u32 type)
{
	(void)c;
	K.control++;
	K.ctl_group = group; K.ctl_attempt = attempt; K.ctl_credit = credit; K.ctl_type = type;
	return control_rc;
}
int bpf_xdev_ext_rel_policy(const struct xdev_ext_mech_ctx *c, void *policy, __u32 policy__sz)
{
	(void)c;
	K.policy++;
	if (policy__sz != sizeof(POLICY))
		return -EINVAL;
	memcpy(policy, &POLICY, sizeof(POLICY));
	return 0;
}

static unsigned checks, failures;
#define EXPECT_EQ(expr, expected) do { \
	long long actual_ = (long long)(expr); \
	long long expected_ = (long long)(expected); \
	checks++; \
	if (actual_ != expected_) { \
		fprintf(stderr, "FAIL %s:%d %s: %lld != %lld\n", \
			__func__, __LINE__, #expr, actual_, expected_); \
		failures++; \
	} \
} while (0)
#define EXPECT(c) EXPECT_EQ(!!(c), 1)

#define SESSION 9ULL
#define HDR_ROOM 384U
#define RX_OFF 278U	/* packet start in the chunk of a received frame */
static const struct xdev_ext_mech_layout layout = {
	.frame_size = 4096, .hdr_room = HDR_ROOM, .seg_len = 1408, .group_bytes = 8192,
};
static const struct xdev_ext_mech_peer peer = {
	.local_mac = { 2, 0, 0, 0, 0, 1 }, .peer_mac = { 2, 0, 0, 0, 0, 2 },
	.local_ip = 0x0100000aU, .peer_ip = 0x0200000aU,
	.local_port = 0x3412, .peer_port = 0x7856,
};
static __u8 chunk[32][4096];
static struct xdp_desc desc[32];
static struct xdev_ext_afxdp_reliable_info info;

static void policy_defaults(void)
{
	memset(&POLICY, 0, sizeof(POLICY));
	POLICY.version = 1;
	POLICY.size = sizeof(POLICY);
	POLICY.window = 4;
	POLICY.initial_credit = 4;
	POLICY.rto_ns = 100000000ULL;
	POLICY.max_attempts = 8;
	POLICY.ack_rule = XDEV_EXT_REL_ACK_EACH;
	POLICY.ack_every = 1;
	POLICY.resend_order = XDEV_EXT_REL_RESEND_SLOT;
}

static void reset(void)
{
	memset(&K, 0, sizeof(K));
	memset(&M, 0, sizeof(M));
	memset(&info, 0, sizeof(info));
	memset(desc, 0, sizeof(desc));
	view_rc = data_rc = control_rc = 0;
	policy_defaults();
	info.base.l = layout;
	info.base.mtu = 1500;
	info.base.peer = peer;
	info.wire_session = SESSION;
	M.info = &info;
	M.info_size = sizeof(info);
	M.frame_size = 4096;
	M.desc = desc;
	M.desc_cap = 32;
}

static struct xdev_ext_rel_msg data_msg(__u64 g, __u16 i, __u32 attempt)
{
	return (struct xdev_ext_rel_msg){
		.session = SESSION, .group = g, .attempt = attempt, .type = XDEV_EXT_REL_DATA,
		.total_len = 8192, .index = i, .count = 6, .relative_offset = i * 1408u,
		.payload_len = i == 5 ? 1152 : 1408,
	};
}

static struct xdev_ext_rel_msg ctl_msg(__u8 type, __u64 g, __u32 attempt, __u64 credit)
{
	return (struct xdev_ext_rel_msg){
		.session = SESSION, .group = g, .attempt = attempt, .type = type, .credit = credit,
	};
}

/* A received frame as C hands it to the program: envelope and CRC already
 * verified by C, so they are written correctly here. */
static void receive(const struct xdev_ext_rel_msg *m, __u32 mutate_off, __u8 mutate)
{
	__u8 *pkt = chunk[0] + RX_OFF;
	__u32 i, crc;

	memset(chunk[0], 0, sizeof(chunk[0]));
	pkt[12] = 8;
	for (i = 0; i < m->payload_len; i++)
		pkt[106 + i] = (__u8)(i * 7 + m->index);
	if (xdev_ext_rel_wire_encode(pkt + 42, m)) {
		fprintf(stderr, "bad test message\n");
		exit(2);
	}
	if (mutate_off)
		pkt[mutate_off] = mutate;
	crc = sw_crc32c(sw_crc32c(~0U, pkt + 42, 64), pkt + 106, m->payload_len);
	xdev_ext_rel_put(pkt + 98, crc ^ ~0U, 4);
	info.base.nr_frames = 1;
	info.base.f[0] = (struct xdev_ext_mech_frame_info){
		.umem_addr = 0, .data_off = RX_OFF, .data_len = 106 + m->payload_len,
	};
	M.frames[0] = chunk[0];
	M.ctx.member = XDEV_EXT_MECH_MEMBER_COMPLETE;
	M.ctx.callsite = XDEV_EXT_MECH_SITE_RX_NATIVE;
	M.ctx.class_id = XDEV_EXT_MECH_CLASS_AFXDP;
	M.ctx.nr_frames = 1;
}

static void view_set(__u64 slot_group, __u8 state, __u32 present, __u64 base, __u64 credit,
		     __u64 owed)
{
	memset(&VIEW, 0, sizeof(VIEW));
	VIEW.slot_group = slot_group;
	VIEW.state = state;
	VIEW.present = present;
	VIEW.base_group = base;
	VIEW.credit = credit;
	VIEW.owed = owed;
	if (state) {
		VIEW.total_len = 8192;
		VIEW.count = 6;
		VIEW.latest_attempt = 1;
	}
}

static __s32 rx_complete(void)
{
	return rel_afxdp_complete(NULL, &M.ctx);
}

/* ------------------------------------------------------------- RX DATA */

static void new_segment_is_held_with_one_decision(void)
{
	struct xdev_ext_rel_msg m = data_msg(2, 5, 1);

	reset();
	view_set(0, XDEV_EXT_REL_RX_EMPTY, 0, 1, 5, 0);
	receive(&m, 0, 0);
	EXPECT_EQ(rx_complete(), XDEV_EXT_MP_HOLD);
	EXPECT_EQ(K.view, 1);
	EXPECT_EQ(K.view_group, 2);
	EXPECT_EQ(K.data, 1);
	EXPECT_EQ(K.data_group, 2);
	EXPECT_EQ(K.data_index, 5);
	EXPECT_EQ(K.data_attempt, 1);
	EXPECT_EQ(K.data_verdict, XDEV_EXT_REL_HOLD);
	EXPECT_EQ(K.hold, 1);
	EXPECT_EQ(K.hold_key, 2);
	EXPECT_EQ(K.hold_pos, 5);
	EXPECT_EQ(K.hold_off, RX_OFF + 106);
	EXPECT_EQ(K.hold_len, 1152);
	EXPECT_EQ(K.control, 0);
	EXPECT_EQ(K.crc, 0);
	EXPECT_EQ(K.policy, 0);		/* no policy read on the per-packet path */

	/* Next segment of a collecting group: still one view and one decision. */
	reset();
	m = data_msg(2, 1, 2);
	view_set(2, XDEV_EXT_REL_RX_COLLECT, 1U << 5, 1, 5, 0);
	receive(&m, 0, 0);
	EXPECT_EQ(rx_complete(), XDEV_EXT_MP_HOLD);
	EXPECT_EQ(K.view, 1);
	EXPECT_EQ(K.data, 1);
	EXPECT_EQ(K.data_verdict, XDEV_EXT_REL_HOLD);
	EXPECT_EQ(K.data_attempt, 2);
	EXPECT_EQ(K.hold, 1);
	EXPECT_EQ(K.hold_len, 1408);
	EXPECT_EQ(K.crc, 0);
}

static void refused_claim_is_not_held(void)
{
	struct xdev_ext_rel_msg m = data_msg(2, 0, 1);
	static const int refusals[] = { -EEXIST, -ERANGE, -EINVAL, -EOPNOTSUPP };
	unsigned i;

	for (i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++) {
		reset();
		view_set(0, XDEV_EXT_REL_RX_EMPTY, 0, 1, 5, 0);
		data_rc = refusals[i];
		receive(&m, 0, 0);
		EXPECT_EQ(rx_complete(), XDEV_EXT_MP_RECYCLE);
		EXPECT_EQ(K.data, 1);
		EXPECT_EQ(K.hold, 0);
	}
}

struct classify_case {
	const char *name;
	__u64 group;
	__u16 index;
	__u64 slot_group;
	__u8 state;
	__u32 present;
	__u64 base, credit, owed;
	__u32 verdict;
};

/* Exactly the decisions of the old xdev_ext_rel_rx_inspect(), on the view. */
static void duplicates_are_classified_from_the_view(void)
{
	static const struct classify_case cases[] = {
		{ "present index", 2, 3, 2, XDEV_EXT_REL_RX_COLLECT, 1U << 3, 1, 5, 0, XDEV_EXT_REL_RECYCLE },
		{ "other index", 2, 4, 2, XDEV_EXT_REL_RX_COLLECT, 1U << 3, 1, 5, 0, XDEV_EXT_REL_HOLD },
		{ "finished", 2, 0, 2, XDEV_EXT_REL_RX_DONE, 0x3f, 1, 5, 0, XDEV_EXT_REL_REPLAY_ACK },
		{ "finished, reply owed", 2, 0, 2, XDEV_EXT_REL_RX_DONE, 0x3f, 1, 5, 2, XDEV_EXT_REL_REPLAY_ACK },
		{ "chain running", 2, 1, 2, XDEV_EXT_REL_RX_SUBMITTED, 0x3f, 1, 5, 0, XDEV_EXT_REL_REPLAY_HELD },
		{ "chain running, reply owed", 2, 1, 2, XDEV_EXT_REL_RX_SUBMITTED, 0x3f, 1, 5, 6, XDEV_EXT_REL_RECYCLE },
		{ "failed", 2, 1, 2, XDEV_EXT_REL_RX_FAILED, 0x3f, 1, 5, 0, XDEV_EXT_REL_RECYCLE },
		{ "retired, slot reused", 2, 1, 6, XDEV_EXT_REL_RX_COLLECT, 1, 3, 7, 0, XDEV_EXT_REL_STALE },
		{ "beyond credit", 6, 0, 2, XDEV_EXT_REL_RX_COLLECT, 1, 1, 5, 0, XDEV_EXT_REL_BACKPRESSURE },
		{ "new in window", 4, 0, 0, XDEV_EXT_REL_RX_EMPTY, 0, 1, 5, 0, XDEV_EXT_REL_HOLD },
		{ "slot of a retired group", 5, 2, 1, XDEV_EXT_REL_RX_DONE, 0x3f, 2, 6, 0, XDEV_EXT_REL_HOLD },
	};
	unsigned i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct classify_case *c = &cases[i];
		struct xdev_ext_rel_msg m = data_msg(c->group, c->index, 2);
		__s32 ret;

		reset();
		view_set(c->slot_group, c->state, c->present, c->base, c->credit, c->owed);
		receive(&m, 0, 0);
		ret = rx_complete();
		if (K.data != 1 || K.data_verdict != c->verdict)
			fprintf(stderr, "case '%s'\n", c->name);
		EXPECT_EQ(K.view, 1);
		EXPECT_EQ(K.data, 1);
		EXPECT_EQ(K.data_verdict, c->verdict);
		EXPECT_EQ(K.data_group, c->group);
		EXPECT_EQ(K.data_index, c->index);
		EXPECT_EQ(K.data_attempt, 2);
		EXPECT_EQ(ret, c->verdict == XDEV_EXT_REL_HOLD ? XDEV_EXT_MP_HOLD : XDEV_EXT_MP_RECYCLE);
		EXPECT_EQ(K.hold, c->verdict == XDEV_EXT_REL_HOLD);
		EXPECT_EQ(K.crc, 0);
	}
}

static void unusable_view_holds_nothing(void)
{
	struct xdev_ext_rel_msg m = data_msg(2, 0, 1);

	reset();
	view_rc = -ERANGE;
	receive(&m, 0, 0);
	EXPECT_EQ(rx_complete(), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(K.view, 1);
	EXPECT_EQ(K.data, 0);
	EXPECT_EQ(K.hold, 0);
}

static void undecodable_frames_ask_nothing(void)
{
	struct xdev_ext_rel_msg m = data_msg(2, 0, 1);

	reset();
	view_set(0, 0, 0, 1, 5, 0);
	info.wire_session = SESSION + 1;	/* foreign session */
	receive(&m, 0, 0);
	EXPECT_EQ(rx_complete(), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(K.view + K.data + K.control + K.hold, 0);

	reset();
	view_set(0, 0, 0, 1, 5, 0);
	receive(&m, 42 + 7, 1);			/* reserved header byte */
	EXPECT_EQ(rx_complete(), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(K.view + K.data + K.control + K.hold, 0);

	reset();
	view_set(0, 0, 0, 1, 5, 0);
	/* Construct a malformed wire offset after the encoder accepts the valid message. */
	receive(&m, 42 + 39, 1);		/* index 0 must start at 0 */
	EXPECT_EQ(chunk[0][RX_OFF + 42 + 39], 1);
	EXPECT_EQ(rx_complete(), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(K.view + K.data + K.control + K.hold, 0);
	EXPECT_EQ(K.crc, 0);
}

/* --------------------------------------------------------- RX control */

static void ack_and_held_are_interpreted_by_the_program(void)
{
	struct xdev_ext_rel_msg m = ctl_msg(XDEV_EXT_REL_ACK, 3, 2, 7);
	static const __u8 types[] = { XDEV_EXT_REL_ACK, XDEV_EXT_REL_HELD, XDEV_EXT_REL_ACK_CUM };
	unsigned i;

	for (i = 0; i < 3; i++) {
		reset();
		m = ctl_msg(types[i], 3 + i, 2 + i, 7 - i);
		receive(&m, 0, 0);
		EXPECT_EQ(rx_complete(), XDEV_EXT_MP_RECYCLE);
		EXPECT_EQ(K.control, 1);
		EXPECT_EQ(K.ctl_group, 3 + i);
		EXPECT_EQ(K.ctl_attempt, 2 + i);
		EXPECT_EQ(K.ctl_credit, 7 - i);
		EXPECT_EQ(K.ctl_type, types[i]);
		EXPECT_EQ(K.view + K.data + K.hold + K.crc, 0);
	}

	/* C refusing the ACK (beyond window, stale) does not change the verdict. */
	reset();
	control_rc = -ERANGE;
	m = ctl_msg(XDEV_EXT_REL_ACK, 3, 1, 900);
	receive(&m, 0, 0);
	EXPECT_EQ(rx_complete(), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(K.control, 1);
	EXPECT_EQ(K.ctl_credit, 900);
	EXPECT_EQ(K.hold, 0);

	reset();
	info.wire_session = SESSION + 1;
	m = ctl_msg(XDEV_EXT_REL_ACK, 3, 1, 6);
	receive(&m, 0, 0);
	EXPECT_EQ(rx_complete(), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(K.control, 0);
}

/* ----------------------------------------------------------------- TX */

static void expect_envelope(const __u8 *pkt, __u32 payload)
{
	unsigned i;

	for (i = 0; i < 6; i++) {
		EXPECT_EQ(pkt[i], peer.peer_mac[i]);
		EXPECT_EQ(pkt[6 + i], peer.local_mac[i]);
	}
	EXPECT_EQ(xdev_ext_rel_be(pkt + 12, 2), 0x800);
	EXPECT_EQ(pkt[14], 0x45);
	EXPECT_EQ(xdev_ext_rel_be(pkt + 16, 2), 92 + payload);
	EXPECT_EQ(pkt[22], 64);
	EXPECT_EQ(pkt[23], 17);
	EXPECT(!memcmp(pkt + 26, &peer.local_ip, 4));
	EXPECT(!memcmp(pkt + 30, &peer.peer_ip, 4));
	EXPECT(!memcmp(pkt + 34, &peer.local_port, 2));
	EXPECT(!memcmp(pkt + 36, &peer.peer_port, 2));
	EXPECT_EQ(xdev_ext_rel_be(pkt + 38, 2), 72 + payload);
	EXPECT_EQ(pkt[40] | pkt[41], 0);
}

static void prepare_build(__u32 nr, __u64 group, __u32 attempt, __u32 type)
{
	unsigned i;

	reset();
	for (i = 0; i < nr; i++) {
		memset(chunk[i], 0x5a, sizeof(chunk[i]));
		M.frames[i] = chunk[i];
		info.base.f[i] = (struct xdev_ext_mech_frame_info){
			.umem_addr = 4096ULL * i, .data_off = HDR_ROOM,
			.data_len = type == XDEV_EXT_REL_DATA ? (i == 5 ? 1152 : 1408) : 0,
		};
	}
	info.base.nr_frames = nr;
	info.wire_group = group;
	info.wire_attempt = attempt;
	info.wire_type = type;
	info.wire_credit = 0;
	M.ctx.member = XDEV_EXT_MECH_MEMBER_BUILD;
	M.ctx.callsite = XDEV_EXT_MECH_SITE_WORKER;
	M.ctx.class_id = XDEV_EXT_MECH_CLASS_AFXDP;
	M.ctx.nr_frames = nr;
}

/* Independent wire oracle: protocol constants/offsets from the v3 contract,
 * libc network byte order, never the production encoder/put helpers. */
static void oracle_u32(__u8 *p, __u32 n) { n=htonl(n); memcpy(p,&n,4); }
static void oracle_u16(__u8 *p, __u16 n) { n=htons(n); memcpy(p,&n,2); }
static void oracle_u64(__u8 *p, __u64 n) { oracle_u32(p,n>>32); oracle_u32(p+4,n); }
static void expect_header(const __u8 *pkt, const struct xdev_ext_rel_msg *want)
{
 __u8 hdr[64] = {0x4e,0x58,0x50,0x33,3,64};
 hdr[6]=want->type;
 oracle_u64(hdr+8,want->session); oracle_u64(hdr+16,want->group);
 oracle_u32(hdr+24,want->attempt); oracle_u32(hdr+28,want->total_len);
 oracle_u16(hdr+32,want->index); oracle_u16(hdr+34,want->count);
 oracle_u32(hdr+36,want->relative_offset); oracle_u32(hdr+40,want->payload_len);
 oracle_u64(hdr+48,want->credit);
 EXPECT(!memcmp(pkt+42,hdr,64)); /* CRC reserved for C; must remain zero. */
}

struct reply_case {
	const char *name;
	__u32 rule, every;
	__u64 group, slot_group, base;
	__u8 state, reply;
	__u32 latest, owed_count;
	__u8 must;
	__u64 credit;
	int emit;	/* 0: the program defers (BUILD_DEFAULT) */
	__u8 type;
	__u64 wire_group;
};

static void reply_build_follows_policy(void)
{
	static const struct reply_case cases[] = {
		/* EACH (75b51c2): always emitted, even when C would allow a deferral. */
		{ "each: chain running, HELD owed", XDEV_EXT_REL_ACK_EACH, 1, 3, 3, 1,
		  XDEV_EXT_REL_RX_SUBMITTED, XDEV_EXT_REL_HELD, 2, 0, 1, 7, 1, XDEV_EXT_REL_HELD, 3 },
		{ "each: finished", XDEV_EXT_REL_ACK_EACH, 1, 3, 3, 4,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_ACK, 3, 1, 1, 8, 1, XDEV_EXT_REL_ACK, 3 },
		{ "each: not urgent is still emitted", XDEV_EXT_REL_ACK_EACH, 1, 3, 3, 4,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_ACK, 3, 1, 0, 8, 1, XDEV_EXT_REL_ACK, 3 },
		{ "each: finished after HELD", XDEV_EXT_REL_ACK_EACH, 1, 3, 3, 4,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_HELD, 1, 1, 1, 8, 1, XDEV_EXT_REL_ACK, 3 },
		{ "each: chain running, ACK recorded", XDEV_EXT_REL_ACK_EACH, 1, 3, 3, 1,
		  XDEV_EXT_REL_RX_SUBMITTED, XDEV_EXT_REL_ACK, 2, 1, 1, 7, 1, XDEV_EXT_REL_ACK, 3 },
		{ "each: retired, slot reused", XDEV_EXT_REL_ACK_EACH, 1, 3, 7, 5,
		  XDEV_EXT_REL_RX_COLLECT, 0, 4, 1, 1, 9, 1, XDEV_EXT_REL_ACK, 3 },
		/* EVERY_N: defer below N owed ACKs unless C says the reply is due. */
		{ "every 3: two owed", XDEV_EXT_REL_ACK_EVERY_N, 3, 2, 2, 4,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_ACK, 1, 2, 0, 8, 0, 0, 0 },
		{ "every 3: three owed, cumulative", XDEV_EXT_REL_ACK_EVERY_N, 3, 2, 2, 4,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_ACK, 1, 3, 0, 8, 1, XDEV_EXT_REL_ACK_CUM, 3 },
		{ "every 3: flush due", XDEV_EXT_REL_ACK_EVERY_N, 3, 2, 2, 4,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_ACK, 1, 1, 1, 8, 1, XDEV_EXT_REL_ACK_CUM, 3 },
		{ "every 3: finished above a gap", XDEV_EXT_REL_ACK_EVERY_N, 3, 5, 5, 3,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_ACK, 2, 3, 0, 7, 1, XDEV_EXT_REL_ACK, 5 },
		{ "every 3: HELD for a retransmission", XDEV_EXT_REL_ACK_EVERY_N, 3, 3, 3, 1,
		  XDEV_EXT_REL_RX_SUBMITTED, XDEV_EXT_REL_HELD, 2, 0, 1, 7, 1, XDEV_EXT_REL_HELD, 3 },
		/* DELAYED: only when due. */
		{ "delayed: many owed, not due", XDEV_EXT_REL_ACK_DELAYED, 0, 2, 2, 6,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_ACK, 1, 4, 0, 10, 0, 0, 0 },
		{ "delayed: due", XDEV_EXT_REL_ACK_DELAYED, 0, 2, 2, 6,
		  XDEV_EXT_REL_RX_DONE, XDEV_EXT_REL_ACK, 1, 4, 1, 10, 1, XDEV_EXT_REL_ACK_CUM, 5 },
	};
	unsigned i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct reply_case *c = &cases[i];
		const __u8 *pkt = chunk[0] + HDR_ROOM - 106;
		__s32 ret;

		prepare_build(1, c->group, 0, 0);
		POLICY.ack_rule = c->rule;
		POLICY.ack_every = c->every;
		POLICY.ack_delay_ns = c->rule == XDEV_EXT_REL_ACK_EACH ? 0 : 1000;
		memset(&VIEW, 0, sizeof(VIEW));
		VIEW.slot_group = c->slot_group;
		VIEW.state = c->state;
		VIEW.reply = c->reply;
		VIEW.latest_attempt = c->latest;
		VIEW.credit = c->credit;
		VIEW.base_group = c->base;
		VIEW.owed = c->group;
		VIEW.owed_count = c->owed_count;
		VIEW.must_emit = c->must;
		ret = rel_afxdp_build(NULL, &M.ctx);
		if (ret != (c->emit ? XDEV_EXT_MP_BUILD_SUBMIT : XDEV_EXT_MP_BUILD_DEFAULT) ||
		    (c->emit && pkt[42 + 6] != c->type))
			fprintf(stderr, "case '%s'\n", c->name);
		EXPECT_EQ(ret, c->emit ? XDEV_EXT_MP_BUILD_SUBMIT : XDEV_EXT_MP_BUILD_DEFAULT);
		EXPECT_EQ(K.view, 1);
		EXPECT_EQ(K.view_group, c->group);
		EXPECT_EQ(K.policy, 1);
		EXPECT_EQ(K.data + K.control + K.hold + K.crc, 0);
		if (c->emit) {
			struct xdev_ext_rel_msg want = ctl_msg(c->type, c->wire_group, c->latest, c->credit);

			expect_envelope(pkt, 0);
			expect_header(pkt, &want);
			EXPECT_EQ(desc[0].addr, HDR_ROOM - 106);
			EXPECT_EQ(desc[0].len, 106);
		} else {
			EXPECT_EQ(desc[0].len, 0);	/* nothing staged for C to send */
		}
		EXPECT_EQ(desc[1].len, 0);
	}

	prepare_build(1, 3, 0, 0);
	view_rc = -ERANGE;
	EXPECT_EQ(rel_afxdp_build(NULL, &M.ctx), XDEV_EXT_MP_BUILD_ABORT);
}

static void data_bytes_are_unchanged(void)
{
	static const __u32 attempts[] = { 1, 2, 3 };
	unsigned a, i;

	for (a = 0; a < 3; a++) {
		prepare_build(6, 5, attempts[a], XDEV_EXT_REL_DATA);
		EXPECT_EQ(rel_afxdp_build(NULL, &M.ctx), XDEV_EXT_MP_BUILD_SUBMIT);
		EXPECT_EQ(K.view + K.data + K.control + K.hold + K.crc, 0);
		for (i = 0; i < 6; i++) {
			struct xdev_ext_rel_msg want = data_msg(5, i, attempts[a]);
			const __u8 *pkt = chunk[i] + HDR_ROOM - 106;

			expect_envelope(pkt, want.payload_len);
			expect_header(pkt, &want);
			EXPECT_EQ(desc[i].addr, 4096ULL * i + HDR_ROOM - 106);
			EXPECT_EQ(desc[i].len, 106 + want.payload_len);
			EXPECT_EQ(chunk[i][HDR_ROOM], 0x5a);	/* payload untouched */
		}
	}
}

/* C supplies unordered eligible candidates; the production BPF chooses. */
static void resend_selection_is_bpf_and_wrap_aware(void)
{
 struct xdev_ext_rel_tx_view v = {.count=4,.window=4,.rr_next=2,
  .candidate={{.group=5,.slot=1,.attempt=2},{.group=7,.slot=3,.attempt=3},
              {.group=4,.slot=0,.attempt=2},{.group=6,.slot=2,.attempt=2}}};
 struct xdev_ext_rel_tx_view before=v;
 struct xdev_ext_rel_policy p;
 policy_defaults(); p=POLICY;
 /* Slots are deliberately unsorted; old slot order must choose slot 0. */
 p.resend_order=XDEV_EXT_REL_RESEND_SLOT; EXPECT_EQ(rel_choose_resend(&v,&p),4);
 p.resend_order=XDEV_EXT_REL_RESEND_ROUND_ROBIN; EXPECT_EQ(rel_choose_resend(&v,&p),6);
 v.rr_next=3; EXPECT_EQ(rel_choose_resend(&v,&p),7);
 v.rr_next=0; p.resend_order=XDEV_EXT_REL_RESEND_OLDEST;
 EXPECT_EQ(rel_choose_resend(&v,&p),4);
 /* Move active groups across the slot wrap: SLOT=8, OLDEST=5. */
 v.candidate[2].group=8;
 EXPECT_EQ(rel_choose_resend(&v,&p),5);
 p.resend_order=XDEV_EXT_REL_RESEND_SLOT; EXPECT_EQ(rel_choose_resend(&v,&p),8);
 v=before; EXPECT_EQ(rel_choose_resend(&v,&p),4);
 EXPECT(!memcmp(&v,&before,sizeof(v)));
 v.count=0; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.count=33; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.window=0; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.window=33; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.rr_next=4; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.candidate[0].group=0; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.candidate[0].attempt=0; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.candidate[0].slot=4; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.candidate[0].slot=2; EXPECT_EQ(rel_choose_resend(&v,&p),0);
 v=before; v.candidate[1]=v.candidate[0]; EXPECT_EQ(rel_choose_resend(&v,&p),0);
}

static void select_callback_uses_readonly_snapshot(void)
{
 struct xdev_ext_rel_tx_view v={.count=2,.window=4,.rr_next=1,
  .candidate={{.group=8,.slot=0,.attempt=2},{.group=5,.slot=1,.attempt=2}}};
 reset();TX_VIEW=&v;M.ctx.callsite=XDEV_EXT_MP_SITE_WORKER_SELECT;
 EXPECT_EQ(rel_afxdp_build(NULL,&M.ctx),1); /* default SLOT */
 POLICY.resend_order=XDEV_EXT_REL_RESEND_OLDEST;
 EXPECT_EQ(rel_afxdp_build(NULL,&M.ctx),2);
 POLICY.resend_order=XDEV_EXT_REL_RESEND_ROUND_ROBIN;
 EXPECT_EQ(rel_afxdp_build(NULL,&M.ctx),2);
 EXPECT_EQ(K.hold+K.data+K.control+K.view+K.crc,0);
 EXPECT_EQ(desc[0].addr|desc[0].len,0);
 TX_VIEW=NULL;EXPECT_EQ(rel_afxdp_build(NULL,&M.ctx),-EINVAL);
}
int main(void)
{
 select_callback_uses_readonly_snapshot();
	resend_selection_is_bpf_and_wrap_aware();
	new_segment_is_held_with_one_decision();
	refused_claim_is_not_held();
	duplicates_are_classified_from_the_view();
	unusable_view_holds_nothing();
	undecodable_frames_ask_nothing();
	ack_and_held_are_interpreted_by_the_program();
	reply_build_follows_policy();
	data_bytes_are_unchanged();
	printf("reliable program decisions: %u checks, %u failures\n", checks, failures);
	return failures != 0;
}

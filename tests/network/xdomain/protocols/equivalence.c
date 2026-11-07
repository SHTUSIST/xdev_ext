/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Decision equivalence of the two independent protocol programs.
 *
 * The reference program chooses its protocol from the stage's mode fact. Each
 * new program must take exactly the reference decision for its own protocol:
 *   - RTS/CTS program == reference with mode 0, for every version-1 event;
 *     on PAIR_DUE and HELLO it declines (IGNORE); it refuses other events;
 *   - early program == reference with mode 1, for every event.
 * Fact records are drawn from a fixed-seed generator that concentrates on
 * the values the rules test (deadline edges, status signs, facts bits,
 * states). Both programs must also leave the shared fact record unchanged.
 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define xdomain_peer_prepare ref_prepare
#define xdomain_peer_build ref_build
#define xdomain_peer_complete ref_complete
#define xdomain_peer_ops ref_ops
#define LICENSE ref_license
#include "xdomain_peer.bpf.c"
#undef xdomain_peer_prepare
#undef xdomain_peer_build
#undef xdomain_peer_complete
#undef xdomain_peer_ops
#undef LICENSE
#define xdomain_peer_prepare rts_prepare
#define xdomain_peer_build rts_build
#define xdomain_peer_complete rts_complete
#define xdomain_peer_ops rts_ops
#define LICENSE rts_license
#include "xdomain_rts_cts.bpf.c"
#undef xdomain_peer_prepare
#undef xdomain_peer_build
#undef xdomain_peer_complete
#undef xdomain_peer_ops
#undef LICENSE
#define xdomain_peer_prepare early_prepare
#define xdomain_peer_build early_build
#define xdomain_peer_complete early_complete
#define xdomain_peer_ops early_ops
#define LICENSE early_license
#include "xdomain_early.bpf.c"

/* The programs are only called through their pure decision functions. */
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c, const size_t s) { (void)c; (void)s; return NULL; }
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c, __u32 i, const size_t s) { (void)c; (void)i; (void)s; return NULL; }
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c, __u32 i, const size_t s) { (void)c; (void)i; (void)s; return NULL; }
int bpf_xdev_ext_xdomain_info_v2(const struct xdev_ext_mech_ctx *c, void *o, __u32 s) { (void)c; (void)o; (void)s; return -1; }
int bpf_xdev_ext_xdomain_verdict_v2(const struct xdev_ext_mech_ctx *c, const void *v, __u32 s) { (void)c; (void)v; (void)s; return -1; }

static unsigned long long state = 0x9e3779b97f4a7c15ULL, checks, failures;
static __u64 next(void)
{
	state ^= state << 13; state ^= state >> 7; state ^= state << 17;
	return state;
}
static __u64 pick(const __u64 *v, unsigned n) { return v[next() % n]; }
#define PICK(a) pick(a, sizeof(a) / sizeof(a[0]))
#define EXPECT(c, why) do { checks++; if (!(c)) { failures++; if (failures < 20) \
	fprintf(stderr, "PROTOCOL_EQUIVALENCE_FAIL %s event=%u dir=%u mode=%u state=%u facts=0x%x\n", \
		why, in.base.event, in.base.direction, in.mode, in.base.state, in.base.facts); } } while (0)

static void draw(struct xdev_ext_xdomain_proto_info_v2 *in)
{
	static const __u64 nows[] = {0, 1, 5000000000ULL, 1ULL << 62, ~0ULL - 20000000ULL,
		~0ULL - 19999999ULL, ~0ULL - 1, ~0ULL};
	static const __s64 offsets[] = {0, -1, 0, 1, 19999999, 20000000, 20000001, 30000000000LL};
	static const __u64 status[] = {0, (__u64)-5LL, (__u64)-71LL, (__u64)-110LL, (__u64)-125LL, 3};
	__u64 now = PICK(nows);
	unsigned i;

	memset(in, 0, sizeof(*in));
	for (i = 0; i < sizeof(*in); i++)
		((__u8 *)in)[i] = (__u8)next();
	in->base.size = sizeof(*in);
	in->base.version = XDEV_EXT_XDOMAIN_PROTO_V2_VERSION;
	in->base.event = next() % 26;
	in->base.direction = next() % 4;
	in->base.now_ns = now;
	in->base.hard_deadline_ns = next() % 3 ? 0 : now + (__u64)offsets[next() % 8];
	in->base.policy_deadline_ns = next() % 3 ? 0 : now + (__u64)offsets[next() % 8];
	in->base.facts = (__u32)(next() & (next() % 4 ? 0x7fffU : 0xffffffffU));
	in->base.state = next() % 6;
	in->base.remote = next() % 6;
	in->base.local_status = (__s32)PICK(status);
	in->base.chain_status = (__s32)PICK(status);
	in->base.ctl_room = next() % 3;
	in->base.posted_groups = next() % 3;
	in->base.next_group = next() % 5;
	in->base.credit = next() % 5;
	in->early_facts = (__u32)(next() & 0x7f);
}

/* Actions that bind a group by RTS/CTS, and actions of pairing and grants. */
static int rts_cts_action(__u32 a)
{
	return a == XDEV_EXT_XDP_ACT_TX_ANNOUNCE || a == XDEV_EXT_XDP_ACT_RX_POST ||
	       a == XDEV_EXT_XDP_ACT_TX_POST || a == XDEV_EXT_XDP_ACT_WITHDRAW;
}
static int early_action(__u32 a)
{
	return a >= XDEV_EXT_XDP_ACT_SEND_HELLO && a <= XDEV_EXT_XDP_ACT_TX_POST_EARLY;
}

int main(void)
{
	struct xdev_ext_xdomain_proto_info_v2 in, a, b, c;
	struct xdev_ext_xdomain_proto_verdict va, vb, vc;
	unsigned long n;
	int ra, rb, rc, tx;

	for (n = 0; n < 4000000UL; n++) {
		draw(&in);
		tx = in.base.direction == XDEV_EXT_MP_DIR_TO_DEVICE;
		/* RTS/CTS program against the reference in mode 0. */
		in.mode = XDEV_EXT_XDP_MODE_NORMAL;
		a = in; b = in;
		memset(&va, 0xa5, sizeof(va)); memset(&vb, 0x5a, sizeof(vb));
		ra = xdomain_peer_choose_v2(&a, &va);
		rb = xd_rts_cts_choose(&b, &vb);
		EXPECT(!memcmp(&b, &in, sizeof(in)), "RTS/CTS program leaves the facts unchanged");
		EXPECT(rb || !early_action(vb.action), "RTS/CTS program never selects a pairing or grant action");
		if (in.base.event == XDEV_EXT_XDP_EV_PAIR_DUE || in.base.event == XDEV_EXT_XDP_EV_HELLO) {
			EXPECT(!rb && vb.action == XDEV_EXT_XDP_ACT_IGNORE && vb.size == sizeof(vb) &&
			       vb.version == XDEV_EXT_XDOMAIN_PROTO_V2_VERSION && !vb.credit && !vb.status &&
			       !vb.wake_ns && vb.event_id == in.base.event_id && vb.epoch == in.base.epoch,
			       "RTS/CTS program declines pairing");
		} else if (in.base.event >= XDEV_EXT_XDP_EV_TX_SUBMIT &&
			   in.base.event <= XDEV_EXT_XDP_EV_DUPLICATE) {
			EXPECT(ra == rb, "RTS/CTS program returns the reference mode-0 result");
			if (!ra && !rb)
				EXPECT(!memcmp(&va, &vb, sizeof(va)), "RTS/CTS program takes the reference mode-0 verdict");
		} else {
			EXPECT(rb != 0, "RTS/CTS program refuses events outside its protocol");
		}
		c = in; c.mode = (__u32)next();
		rc = xd_rts_cts_choose(&c, &vc);
		EXPECT(rc == rb && (rc || !memcmp(&vc, &vb, sizeof(vb))), "RTS/CTS program ignores the mode fact");
		/* Early-grant program against the reference in mode 1. */
		in.mode = XDEV_EXT_XDP_MODE_EARLY;
		a = in; b = in;
		memset(&va, 0xa5, sizeof(va)); memset(&vb, 0x5a, sizeof(vb));
		ra = xdomain_peer_choose_v2(&a, &va);
		rb = xd_early_choose(&b, &vb);
		EXPECT(!memcmp(&b, &in, sizeof(in)), "early program leaves the facts unchanged");
		EXPECT(rb || !rts_cts_action(vb.action), "early program never selects an RTS/CTS binding action");
		if (tx && in.base.event == XDEV_EXT_XDP_EV_CTS &&
		    (in.base.facts & XDEV_EXT_XDP_F_LINK_UP) && !(in.base.facts & XDEV_EXT_XDP_F_STAGE_DEAD) &&
		    !(in.base.hard_deadline_ns && in.base.now_ns >= in.base.hard_deadline_ns)) {
			/* Link up, stage alive, hard deadline not missed: no shared rule
			 * decides a sender's CTS, and the early program refuses it. */
			EXPECT(rb == -XD_POLICY_EPROTO, "early program refuses a version-1 CTS");
		} else if (!(tx && in.base.state == XDEV_EXT_MP_RDV_ANNOUNCED)) {
			/* Only TX_ANNOUNCE creates an announced sender slot. */
			EXPECT(ra == rb, "early program returns the reference mode-1 result");
			if (!ra && !rb)
				EXPECT(!memcmp(&va, &vb, sizeof(va)), "early program takes the reference mode-1 verdict");
		}
		c = in; c.mode = (__u32)next();
		rc = xd_early_choose(&c, &vc);
		EXPECT(rc == rb && (rc || !memcmp(&vc, &vb, sizeof(vb))), "early program ignores the mode fact");
	}
	printf("PROTOCOL_EQUIVALENCE checks=%llu failures=%llu\n", checks, failures);
	return failures ? 1 : 0;
}

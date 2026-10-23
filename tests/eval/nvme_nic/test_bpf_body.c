/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Controlled user-space dependencies for the checked-in nnb_bench.bpf.c body,
 * compiled as host C like tests/eval/hft/test_benchmark_bpf_body.c.  This is
 * not a device/provider model, a BPF verifier run or a performance test.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "nnb_bench.bpf.c"
#include "nnb_wire.h"

static struct xdev_ext_afxdp_mech_info af;
static struct xdev_ext_nvme_mech_info nv;
static struct xdev_ext_afxdp_tx_cqe tx[NNB_MAX_FRAMES];
static struct xdev_ext_afxdp_rx_hold_cqe hold_cqe;
static struct xdev_ext_nvme_mech_cqe nc;
static struct xdp_desc desc[NNB_MAX_FRAMES];
static unsigned char umem[NNB_MAX_FRAMES][4096], sqe[64], state[sizeof(struct xdev_ext_mp_rx_state)];
static int nvme_view, tx_cqes = NNB_MAX_FRAMES, crc_calls;
static struct { __u64 key; __u32 pos, off, len; int calls; } hold;
static __u64 clock_ns = 1000;

__u64 bpf_ktime_get_ns(void) { return clock_ns; }
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c, const size_t n)
{
	(void)c;
	if (nvme_view)
		return n == sizeof(nv) ? (void *)&nv : NULL;
	return n == sizeof(af) ? (void *)&af : NULL;
}
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c, __u32 slot, const size_t n)
{
	(void)c;
	if (n == 64 && !slot)
		return sqe;
	return slot < NNB_MAX_FRAMES && n == sizeof(desc[0]) ? (void *)&desc[slot] : NULL;
}
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c, __u32 slot, const size_t n)
{
	/* The NVMe and hold copies have the same size: select by callsite/class. */
	if (n == sizeof(nc) && !slot && nvme_view)
		return (void *)&nc;
	if (n == sizeof(hold_cqe) && !slot && c && c->callsite == XDEV_EXT_MP_SITE_RX_HOLD_RESULT)
		return (void *)&hold_cqe;
	return (int)slot < tx_cqes && n == sizeof(tx[0]) ? (void *)&tx[slot] : NULL;
}
__u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, const size_t n)
{
	(void)c;
	return pos >= NNB_MAX_FRAMES || off > 4096 || n > 4096 - off ? NULL : umem[pos] + off;
}
__u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, const size_t n)
{
	(void)c;
	return pos >= NNB_MAX_FRAMES || off + n > NNB_HDR_ROOM ? NULL : umem[pos] + off;
}
__u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *c, const size_t n)
{
	(void)c;
	return n == sizeof(state) ? state : NULL;
}
int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *c, __u64 key, __u32 pos, __u32 off, __u32 len)
{
	(void)c;
	hold.key = key, hold.pos = pos, hold.off = off, hold.len = len, hold.calls++;
	return 0;
}
/* The policy must never call the checksum kfuncs. */
__u32 bpf_xdev_ext_crc32c(const void *b, __u32 n, __u32 seed) { (void)b; (void)n; crc_calls++; return seed; }
__u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *c, __u32 p, __u32 o, __u32 l, __u32 s)
{ (void)c; (void)p; (void)o; (void)l; crc_calls++; return s; }

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "test_bpf_body: line %d: %s\n", __LINE__, #c); \
	return 1; } } while (0)

static void peer_init(struct xdev_ext_mech_peer *p, int receiving)
{
	static const __u8 a[6] = { 2, 0, 0, 0, 0, 1 }, b[6] = { 2, 0, 0, 0, 0, 2 };

	memcpy(p->local_mac, receiving ? b : a, 6);
	memcpy(p->peer_mac, receiving ? a : b, 6);
	p->local_ip = receiving ? 0x0200000aU : 0x0100000aU;
	p->peer_ip = receiving ? 0x0100000aU : 0x0200000aU;
	p->local_port = receiving ? 0x3412 : 0x7856;
	p->peer_port = receiving ? 0x7856 : 0x3412;
}

static int check_tx(const struct nnb_geom *g)
{
	struct xdev_ext_mech_ctx c = { .callsite = XDEV_EXT_MP_SITE_WORKER, .nr_frames = g->dgrams };
	unsigned char want[NNB_HDR_LEN];

	nvme_view = 0;
	memset(&af, 0, sizeof(af));
	af.l = (struct xdev_ext_mech_layout){ 4096, NNB_HDR_ROOM, g->seg, g->group };
	af.nr_frames = g->dgrams;
	af.mtu = g->mtu;
	peer_init(&af.peer, 0);
	for (__u32 i = 0; i < g->dgrams; i++) {
		__u32 rel, len;

		nnb_dgram(g, i, &rel, &len);
		af.f[i] = (struct xdev_ext_mech_frame_info){ .umem_addr = 8192 + i * 4096,
			.data_off = NNB_HDR_ROOM, .data_len = len };
		memset(umem[i], 0xa5, NNB_HDR_ROOM);
		memset(umem[i] + NNB_HDR_ROOM, 0x6d, 4096 - NNB_HDR_ROOM);
	}
	nnb_session = 0x1122334455667788ULL;
	c.base.src_offset = 9;
	CHECK(nnb_afxdp_build(NULL, &c) == XDEV_EXT_MP_BUILD_SUBMIT);
	for (__u32 i = 0; i < g->dgrams; i++) {
		nnb_hdr_encode(want, g, nnb_session, 9, i);
		CHECK(!memcmp(umem[i] + NNB_HDR_ROOM - NNB_HDR_LEN, want, NNB_HDR_LEN));
		CHECK(desc[i].addr == 8192 + i * 4096 + NNB_HDR_ROOM - NNB_PKT_HDR_LEN);
		CHECK(desc[i].len == NNB_PKT_HDR_LEN + af.f[i].data_len && !desc[i].options);
		CHECK(umem[i][NNB_HDR_ROOM] == 0x6d && umem[i][4095] == 0x6d);	/* payload untouched */
		CHECK(umem[i][0] == 0xa5 && umem[i][NNB_HDR_ROOM - NNB_PKT_HDR_LEN - 1] == 0xa5);
	}
	CHECK(!crc_calls);
	c.base.src_offset = 0;
	CHECK(nnb_afxdp_build(NULL, &c) == XDEV_EXT_MP_BUILD_ABORT);
	c.base.src_offset = 1ULL << 32;
	CHECK(nnb_afxdp_build(NULL, &c) == XDEV_EXT_MP_BUILD_ABORT);
	c.base.src_offset = 9;
	af.f[0].data_off = 40;
	CHECK(nnb_afxdp_build(NULL, &c) == XDEV_EXT_MP_BUILD_ABORT);
	af.f[0].data_off = NNB_HDR_ROOM;
	nnb_session = 0;
	CHECK(nnb_afxdp_build(NULL, &c) == XDEV_EXT_MP_BUILD_ABORT);
	nnb_session = 0x1122334455667788ULL;

	memset(tx, 0, sizeof(tx));
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_NEXT);
	tx[1].err = -11;
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_RETRY);
	tx[1].err = -5;
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_ABORT);
	tx[1].err = 0;
	tx_cqes = 0;
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_ABORT);
	tx_cqes = NNB_MAX_FRAMES;
	return 0;
}

/* One received datagram of generation @gen, segment @j, at chunk offset 278. */
static void rx_frame(const struct nnb_geom *g, __u32 gen, __u32 j)
{
	struct xdev_ext_mech_peer sender;
	struct xdev_ext_mp_tx_seg ts;
	__u32 rel, len;
	__u8 *pkt = umem[0] + NNB_HDR_ROOM - NNB_PKT_HDR_LEN;
	__u16 csum;

	peer_init(&sender, 0);
	nnb_dgram(g, j, &rel, &len);
	ts = (struct xdev_ext_mp_tx_seg){ .session_id = nnb_session, .generation = gen,
		.total_len = g->group, .relative_offset = rel, .payload_len = len,
		.index = (__u16)j, .count = (__u16)g->dgrams };
	xdev_ext_mp_tx_encode(pkt, &sender, &ts);
	csum = xdev_ext_mp_ip_csum(pkt + 14);
	xdev_ext_mp_put_be16(pkt + 24, csum);
	nnb_gen_fill(3, rel, pkt + NNB_PKT_HDR_LEN, len);
	af.f[0] = (struct xdev_ext_mech_frame_info){ .umem_addr = 0,
		.data_off = NNB_HDR_ROOM - NNB_PKT_HDR_LEN, .data_len = NNB_PKT_HDR_LEN + len };
}

static int check_rx(const struct nnb_geom *g)
{
	struct xdev_ext_mech_ctx c = { .callsite = XDEV_EXT_MP_SITE_RX_NATIVE, .nr_frames = 1,
		.session_id = 41 };
	struct xdev_ext_mech_ctx r = { .callsite = XDEV_EXT_MP_SITE_RX_HOLD_RESULT, .session_id = 41 };

	nvme_view = 0;
	memset(&af, 0, sizeof(af));
	memset(state, 0, sizeof(state));
	af.l = (struct xdev_ext_mech_layout){ 4096, NNB_HDR_ROOM, g->seg, g->group };
	af.mtu = g->mtu;
	af.nr_frames = 1;
	peer_init(&af.peer, 1);
	nnb_session = 0x1122334455667788ULL;
	for (__u32 j = 0; j < g->dgrams; j++) {
		rx_frame(g, 1, j);
		CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_HOLD);
		CHECK(hold.key == 1 && hold.pos == j && hold.off == NNB_HDR_ROOM);
		CHECK(hold.len == af.f[0].data_len - NNB_PKT_HDR_LEN);
		hold_cqe = (struct xdev_ext_afxdp_rx_hold_cqe){ .key = 1, .pos = j };
		CHECK(nnb_afxdp_complete(NULL, &r) == XDEV_EXT_MP_HOLD);
	}
	CHECK(!crc_calls);	/* a zero NXP2 checksum is accepted without computing one */
	hold.calls = 0;
	rx_frame(g, 3, 0);	/* generation 2 is missing: strict order recycles */
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_RECYCLE && !hold.calls);
	rx_frame(g, 2, 1);	/* not the first segment of the next group */
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_RECYCLE && !hold.calls);
	rx_frame(g, 2, 0);
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_HOLD && hold.key == 2);
	hold_cqe = (struct xdev_ext_afxdp_rx_hold_cqe){ .key = 2, .pos = 0, .err = -12 };
	CHECK(nnb_afxdp_complete(NULL, &r) == XDEV_EXT_MP_RECYCLE);	/* rejected admission */
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_HOLD);	/* same segment again */
	hold_cqe = (struct xdev_ext_afxdp_rx_hold_cqe){ .key = 2, .pos = 0 };
	CHECK(nnb_afxdp_complete(NULL, &r) == XDEV_EXT_MP_HOLD);
	rx_frame(g, 2, 1);
	umem[0][NNB_HDR_ROOM - NNB_PKT_HDR_LEN + 42 + 36] = 1;	/* nonzero checksum field */
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_RECYCLE);
	rx_frame(g, 2, 1);
	umem[0][NNB_HDR_ROOM - NNB_PKT_HDR_LEN + 42] = 0;	/* not NXP2: user space */
	CHECK(nnb_afxdp_complete(NULL, &c) == XDEV_EXT_MP_PUBLISH);
	return 0;
}

static int check_nvme(const struct nnb_geom *g)
{
	struct xdev_ext_mech_ctx c = { .callsite = XDEV_EXT_MP_SITE_WORKER };
	__u64 blocks = g->group >> 9, slba;

	nvme_view = 1;
	memset(&nv, 0, sizeof(nv));
	nv.l = (struct xdev_ext_mech_layout){ 4096, NNB_HDR_ROOM, g->seg, g->group };
	nv.lba_shift = 9;
	nv.window_slba = 1000;
	nv.window_nlb = 4 * blocks;
	c.base.length = g->group;
	c.base.direction = XDEV_EXT_MP_DIR_FROM_DEVICE;
	c.base.src_offset = 4 + 3;	/* fourth slot again after one wrap */
	memset(sqe, 0, sizeof(sqe));
	CHECK(nnb_nvme_build(NULL, &c) == XDEV_EXT_MP_BUILD_SUBMIT && sqe[0] == XDEV_EXT_MP_NVME_OP_READ);
	slba = 0;
	for (int i = 7; i >= 0; i--)
		slba = slba << 8 | sqe[40 + i];
	CHECK(slba == 1000 + 2 * blocks);
	c.base.direction = XDEV_EXT_MP_DIR_TO_DEVICE;
	c.base.src_offset = 1;
	memset(sqe, 0, sizeof(sqe));
	CHECK(nnb_nvme_build(NULL, &c) == XDEV_EXT_MP_BUILD_SUBMIT && sqe[0] == XDEV_EXT_MP_NVME_OP_WRITE);
	CHECK(sqe[40] == (1000 & 0xff) && sqe[41] == (1000 >> 8));
	c.base.length = g->group / 2;	/* a partial group is never a unit's group */
	CHECK(nnb_nvme_build(NULL, &c) == XDEV_EXT_MP_BUILD_ABORT);
	c.base.length = g->group;
	c.base.src_offset = 0;
	CHECK(nnb_nvme_build(NULL, &c) == XDEV_EXT_MP_BUILD_ABORT);
	c.base.src_offset = 1;
	nv.window_nlb = blocks - 1;	/* no whole slot */
	CHECK(nnb_nvme_build(NULL, &c) == XDEV_EXT_MP_BUILD_ABORT);
	nc.status = 0;
	CHECK(nnb_nvme_complete(NULL, &c) == XDEV_EXT_MP_NEXT);
	nc.status = 1;
	CHECK(nnb_nvme_complete(NULL, &c) == XDEV_EXT_MP_ABORT);
	return 0;
}

int main(void)
{
	static const __u32 mtus[] = { 1500, 9000 };

	for (unsigned i = 0; i < 2; i++) {
		struct nnb_geom g;

		if (nnb_geom_init(&g, mtus[i], 1U << 20, 64ULL << 20) || check_tx(&g) ||
		    check_rx(&g) || check_nvme(&g))
			return 1;
	}
	puts("nnb_bench BPF body: NXP2 headers without checksum, descriptors, payload untouched, "
	     "strict RX order, hold admission, NVMe window slots PASS");
	return 0;
}

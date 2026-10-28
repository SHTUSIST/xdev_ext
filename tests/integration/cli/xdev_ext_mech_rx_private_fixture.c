// SPDX-License-Identifier: GPL-2.0
/* Independent host driver of the production NXP callbacks. Host packet/envelope
 * support follows the existing cref fixture; reference callbacks are not used. */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmlinux.h"
#include "include/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_core.h"
#include "net/xdp/xsk_xdev_ext_mech_core.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"

/* --- mock call envelope and kfuncs ------------------------------------- */

#define MOCK_MAGIC	0x55424d43U

struct mock_frame {
	void *kaddr;
};

/* The fields of struct xdev_ext_mech_call the kfuncs read, under its names. */
struct mock_call {
	struct xdev_ext_mech_ctx ctx;
	__u32 magic;
	__u32 member;
	__u32 callsite;
	__u8 hold_calls;
	__u8 protocol_error;
	struct xdev_ext_mech_hold_intent hold;
	const struct mock_frame *frames;
	__u32 nr_frames;
	__u32 frame_size;
	__u32 hdr_room;
	__u32 batch_frames;
	__u32 info_size;
	const void *info;
	__u8 *scratch;
	__u32 desc_size;
	__u32 desc_cap;
	const void *cqe;
	__u32 cqe_size;
	__u32 cqe_cap;
};

static __u64 mock_now;

static struct mock_call *mock_call_of(const struct xdev_ext_mech_ctx *ctx)
{
	struct mock_call *c = (struct mock_call *)((char *)ctx -
						   offsetof(struct mock_call, ctx));

	return c->magic == MOCK_MAGIC ? c : NULL;
}

/* lib/crc32: crc32c() without pre- or post-inversion. */
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

/* xdev_ext_mech_frame_bytes() */
static __u8 *mock_frame_bytes(struct mock_call *c, __u32 pos, __u32 off,
			      __u64 len)
{
	const struct mock_frame *f;

	if ((c->member != XDEV_EXT_MECH_MEMBER_BUILD &&
	     c->member != XDEV_EXT_MECH_MEMBER_COMPLETE) ||
	    pos >= c->nr_frames || !len)
		return NULL;
	f = &c->frames[pos];
	if (!f->kaddr || !xdev_ext_mech_span_in(off, len, c->frame_size))
		return NULL;
	return (__u8 *)f->kaddr + off;
}

__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, const size_t rdonly_buf_size)
{
	struct mock_call *c = mock_call_of(ctx);

	if (!c || !c->info || rdonly_buf_size != c->info_size)
		return NULL;
	return (__u8 *)c->info;
}

__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
		   const size_t rdwr_buf_size)
{
	struct mock_call *c = mock_call_of(ctx);

	if (!c || c->member != XDEV_EXT_MECH_MEMBER_BUILD || !c->scratch ||
	    rdwr_buf_size != c->desc_size || slot >= c->desc_cap)
		return NULL;
	return c->scratch + (size_t)slot * c->desc_size;
}

__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
		  const size_t rdonly_buf_size)
{
	struct mock_call *c = mock_call_of(ctx);

	if (!c || c->member != XDEV_EXT_MECH_MEMBER_COMPLETE || !c->cqe ||
	    rdonly_buf_size != c->cqe_size || slot >= c->cqe_cap)
		return NULL;
	return (__u8 *)c->cqe + (size_t)slot * c->cqe_size;
}

__u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *ctx, __u32 pos, __u32 off,
		    const size_t rdonly_buf_size)
{
	struct mock_call *c = mock_call_of(ctx);

	return c ? mock_frame_bytes(c, pos, off, rdonly_buf_size) : NULL;
}

__u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
			   __u32 off, __u32 len, __u32 seed)
{
	struct mock_call *c = mock_call_of(ctx);
	const __u8 *p;

	if (!c)
		return 0;
	if (!len)
		return seed;
	p = mock_frame_bytes(c, pos, off, len);
	if (!p) {
		c->protocol_error = 1;
		return 0;
	}
	return sw_crc32c(seed, p, len);
}

__u32 bpf_xdev_ext_crc32c(const void *buf, __u32 buf__sz, __u32 seed)
{
	return sw_crc32c(seed, buf, buf__sz);
}

/* net/xdp/xsk_xdev_ext_mech.c, for the program. */
__u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
			__u32 off, const size_t rdwr_buf_size)
{
	struct mock_call *c = mock_call_of(ctx);

	if (!c || !c->frames ||
	    !xsk_xdev_ext_mech_hdr_ok(c->ctx.class_id, c->member, c->callsite, pos,
				 c->nr_frames, off, rdwr_buf_size,
				 c->hdr_room))
		return NULL;
	return (__u8 *)c->frames[pos].kaddr + off;
}

int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *ctx, __u64 key, __u32 pos,
		       __u32 span_off, __u32 span_len)
{
	struct mock_call *c = mock_call_of(ctx);
	int err;

	if (!c)
		return -EINVAL;
	err = xsk_xdev_ext_mech_hold_record(c->ctx.class_id, c->member,
				       c->callsite, &c->hold_calls);
	if (err) {
		c->protocol_error = 1;
		return err;
	}
	c->hold = (struct xdev_ext_mech_hold_intent) {
		.key = key,
		.pos = pos,
		.count = c->batch_frames,
		.span_off = span_off,
		.span_len = span_len,
	};
	return 0;
}

__u64 bpf_ktime_get_ns(void)
{
	return mock_now;
}


/* The host supplies only stage storage. No order, candidate, admission, or
 * site-gating decisions are implemented in this adapter. The production
 * kfunc's gate/registration are checked independently by the Python runner.
 */
static _Alignas(256) __u8 pool_state[2][256];
static unsigned int active_pool, state_reads;
__u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *ctx, const size_t size)
{
 (void)ctx;
 state_reads++;
 if (!size || size > sizeof(pool_state[0])) return NULL;
 return pool_state[active_pool];
}
#include "tools/xdev_ext_mech/nxp_mech.bpf.c"
#define T_FRAME_SIZE	4096U
#define T_HDR_ROOM	360U	/* xdev_ext_mech_ctl's layout: payload at 360 */
#define T_DATA_OFF	(T_HDR_ROOM - XDEV_EXT_MP_PKT_HDR_LEN)
#define T_MTU		1500U
#define T_SEG_LEN	1432U
#define T_GROUP		8192U
#define T_FRAMES	6U
#define T_MAX		XDEV_EXT_MECH_MAX_FRAMES
#define T_SCRATCH	(T_MAX * 64U)
#define T_CQES		(T_MAX * 16U)

union t_info {
	struct xdev_ext_afxdp_mech_info afxdp;
	struct xdev_ext_nvme_mech_info nvme;
};

struct world {
	struct mock_call call;
	struct mock_frame frames[T_MAX];
	union t_info info;
	__u8 scratch[T_SCRATCH];
	__u8 cqe[T_CQES];
	__u32 nmem;			/* frames in use, compared */
	__u8 mem[T_MAX][T_FRAME_SIZE];
};

static struct world w_e;
static unsigned long checks, failures;
#define EXPECT(c, msg) do { checks++; if (!(c)) { failures++; \
 fprintf(stderr, "FAIL: %s\n", msg); } } while (0)
static __u32 rnd_below(__u32 n) { (void)n; return 1; }
/* A fresh world: a sealed envelope over its own frames, info and buffers. */
static void world_reset(struct world *w, __u32 class_id, __u32 member,
			__u32 callsite)
{
	__u32 i;

	memset(&w->call, 0, sizeof(w->call));
	memset(&w->info, 0, sizeof(w->info));
	memset(w->scratch, 0, sizeof(w->scratch));
	memset(w->cqe, 0, sizeof(w->cqe));
	w->nmem = 0;
	for (i = 0; i < T_MAX; i++)
		w->frames[i].kaddr = w->mem[i];
	w->call.magic = MOCK_MAGIC;
	w->call.member = member;
	w->call.callsite = callsite;
	w->call.ctx.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION;
	w->call.ctx.member = member;
	w->call.ctx.class_id = class_id;
	w->call.ctx.callsite = callsite;
	w->call.frames = w->frames;
	w->call.frame_size = T_FRAME_SIZE;
	w->call.hdr_room = T_HDR_ROOM;
	w->call.batch_frames = T_FRAMES;
	w->call.info = &w->info;
}

static const struct xdev_ext_mech_peer rx_peer = {
	.local_mac = { 0x02, 0, 0, 0, 0, 0x02 },
	.peer_mac = { 0x02, 0, 0, 0, 0, 0x01 },
	.local_ip = 0x020200c0U,	/* 192.0.2.2, network order */
	.peer_ip = 0x010200c0U,		/* 192.0.2.1 */
	.local_port = 0x3930,		/* 12345 */
	.peer_port = 0x31d4,		/* 54321 */
};

/* The sender's view of the same pair. */
static struct xdev_ext_mech_peer tx_peer(const struct xdev_ext_mech_peer *rx)
{
	struct xdev_ext_mech_peer tx;

	memcpy(tx.local_mac, rx->peer_mac, 6);
	memcpy(tx.peer_mac, rx->local_mac, 6);
	tx.local_ip = rx->peer_ip;
	tx.peer_ip = rx->local_ip;
	tx.local_port = rx->peer_port;
	tx.peer_port = rx->local_port;
	return tx;
}

static __u32 seg_payload(__u16 index)
{
	__u32 off = index * T_SEG_LEN;

	return T_GROUP - off < T_SEG_LEN ? T_GROUP - off : T_SEG_LEN;
}

/*
 * Arm E's world: RX complete at @callsite of one received frame, segment
 * @index of generation @gen of NXP session @session, with valid IPv4 and
 * NXP checksums.
 */
static void rx_world(__u32 callsite, __u64 mech_session, __u64 session,
		     __u32 gen, __u16 index)
{
	struct xdev_ext_mech_peer tx = tx_peer(&rx_peer);
	struct xdev_ext_afxdp_mech_info *info = &w_e.info.afxdp;
	struct xdev_ext_mp_tx_seg s = {
		.session_id = session,
		.generation = gen,
		.total_len = T_GROUP,
		.relative_offset = index * T_SEG_LEN,
		.payload_len = seg_payload(index),
		.index = index,
		.count = T_FRAMES,
	};
	__u8 *pkt = w_e.mem[0] + T_DATA_OFF, hdr[XDEV_EXT_MP_NXP_LEN];
	__u32 i, crc;
	__u16 csum;

	world_reset(&w_e, XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_MEMBER_COMPLETE,
		    callsite);
	w_e.nmem = 1;
	/* The session layout's frames per batch, which a hold records. */
	if (!rnd_below(4))
		w_e.call.batch_frames = 1 + rnd_below(T_MAX);
	w_e.call.ctx.session_id = mech_session;
	w_e.call.ctx.nr_frames = 1;
	w_e.call.nr_frames = 1;
	w_e.call.info_size = sizeof(*info);
	info->l = (struct xdev_ext_mech_layout) {
		.frame_size = T_FRAME_SIZE, .hdr_room = T_HDR_ROOM,
		.seg_len = T_SEG_LEN, .group_bytes = T_GROUP,
	};
	info->mtu = T_MTU;
	info->nr_frames = 1;
	info->peer = rx_peer;
	info->f[0].umem_addr = 7 * T_FRAME_SIZE;
	info->f[0].data_off = T_DATA_OFF;
	info->f[0].data_len = XDEV_EXT_MP_PKT_HDR_LEN + s.payload_len;
	for (i = 0; i < T_FRAME_SIZE; i++)
		w_e.mem[0][i] = (__u8)(i * 31 + gen * 7 + index);
	if (xdev_ext_mp_tx_encode(pkt, &tx, &s)) {
		fprintf(stderr, "test bug: cannot encode segment %u/%u\n", gen,
			index);
		exit(2);
	}
	csum = xdev_ext_mp_ip_csum(pkt + XDEV_EXT_MP_ETH_LEN);
	xdev_ext_mp_put_be16(pkt + XDEV_EXT_MP_ETH_LEN + 10, csum);
	xdev_ext_mp_nxp_crc_prep(hdr, pkt + XDEV_EXT_MP_NXP_OFF);
	crc = sw_crc32c(XDEV_EXT_MP_CRC32C_SEED, hdr, sizeof(hdr));
	crc = sw_crc32c(crc, pkt + XDEV_EXT_MP_PKT_HDR_LEN, s.payload_len);
	xdev_ext_mp_nxp_crc_store(pkt + XDEV_EXT_MP_NXP_OFF, crc);
}


static int candidate(unsigned int pool, __u64 session, __u32 site, __u16 index)
{
 active_pool = pool;
 rx_world(site, session, nxp_session, 1, index);
 w_e.call.batch_frames = T_FRAMES;
 return nxp_afxdp_complete(NULL, &w_e.call.ctx);
}
static int result(unsigned int pool, __u64 session, __u32 pos, int err)
{
 struct xdev_ext_afxdp_rx_hold_cqe q = { .key=1, .pos=pos, .err=err };
 active_pool = pool;
 world_reset(&w_e, XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_MEMBER_COMPLETE,
             XDEV_EXT_MP_SITE_RX_HOLD_RESULT);
 w_e.call.ctx.session_id=session;
 w_e.call.ctx.nr_frames=w_e.call.nr_frames=0;
 w_e.call.frames=NULL;
 w_e.call.cqe=&q; w_e.call.cqe_size=sizeof(q); w_e.call.cqe_cap=1;
 return nxp_afxdp_complete(NULL, &w_e.call.ctx);
}
static void test_interleaved_pools(__u32 site_a, __u32 site_b)
{
 /* Both pool locks may be held independently. This schedule requires no
  * threads and cannot be repaired with process-wide callback serialization. */
 memset(pool_state, 0, sizeof(pool_state));
 nxp_session=0x1122334455667788ULL; mock_now=100;
 EXPECT(candidate(0,41,site_a,0)==XDEV_EXT_MP_HOLD, "A candidate must HOLD");
 EXPECT(candidate(1,42,site_b,0)==XDEV_EXT_MP_HOLD, "B candidate must HOLD");
 EXPECT(result(1,42,0,0)==XDEV_EXT_MP_HOLD, "B admitted result must HOLD");
 EXPECT(result(0,41,0,0)==XDEV_EXT_MP_HOLD, "A candidate survives B candidate/result");
 /* The frozen state representation starts with canonical order. Inspect
  * that view, never a separate test model or a BPF global snapshot. */
 const struct xdev_ext_mp_rx_order *a=(const void *)pool_state[0];
 const struct xdev_ext_mp_rx_order *b=(const void *)pool_state[1];
 EXPECT(a->session_id==41 && a->next==1, "A private canonical order must be session41/next1");
 EXPECT(b->session_id==42 && b->next==1, "B private canonical order must be session42/next1");
 EXPECT(result(0,41,0,0)==XDEV_EXT_MP_ABORT, "A duplicate result cannot commit twice");
 EXPECT(candidate(0,41,site_a,0)==XDEV_EXT_MP_RECYCLE, "A duplicate segment0 must recycle");
 EXPECT(candidate(1,42,site_b,0)==XDEV_EXT_MP_RECYCLE, "B duplicate segment0 must recycle");
 EXPECT(candidate(0,41,site_a,1)==XDEV_EXT_MP_HOLD, "A accepts its own next segment");
 EXPECT(result(0,41,1,-ENOSPC)==XDEV_EXT_MP_RECYCLE, "A admission rejection recycles");
 EXPECT(a->next==1 && b->next==1, "rejected A leaves both canonical orders at next1");
 EXPECT(candidate(1,42,site_b,1)==XDEV_EXT_MP_HOLD, "B remains independently admissible");
 EXPECT(result(1,42,1,0)==XDEV_EXT_MP_HOLD, "B advances while A is rejected");
 EXPECT(a->next==1 && b->next==2, "only B advances after its admission");
}
int main(void)
{
 test_interleaved_pools(XDEV_EXT_MP_SITE_RX_GENERIC, XDEV_EXT_MP_SITE_RX_GENERIC);
 test_interleaved_pools(XDEV_EXT_MP_SITE_RX_NATIVE, XDEV_EXT_MP_SITE_RX_NATIVE);
 test_interleaved_pools(XDEV_EXT_MP_SITE_RX_GENERIC, XDEV_EXT_MP_SITE_RX_NATIVE);
 EXPECT(state_reads>0, "NXP must read per-stage state rather than globals");
 printf("private-pool RX: %lu checks, %lu failures\n", checks, failures);
 return !!failures;
}

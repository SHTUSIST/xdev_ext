// SPDX-License-Identifier: GPL-2.0
/*
 * Arm C against arm E without a kernel: the C reference callbacks of
 * xdev_ext_mech_cref.h and the BPF programs of tools/xdev_ext_mech/nxp_mech.bpf.c,
 * compiled here as host C, run on two identical copies of every call
 * (envelope, frames, class info, scratch, completion copies, program
 * state).  Return value, scratch bytes, frame bytes, recorded hold intent,
 * misuse latch and group order must come out identical.
 *
 * The program sees the kfuncs as this file mocks them, after
 * io_uring/xdev_ext_mech_ops.c and net/xdp/xsk_xdev_ext_mech.c.  The C reference uses
 * the same six shared kfuncs (exported by the kernel) but its own copies of
 * the two AF_XDP ones, written on the call envelope; those copies run here
 * on a mock envelope with the kernel's field names, so a difference between
 * them and the kfuncs shows as a difference in output.
 */
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
	struct xdev_ext_mp_rx_state *st;
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
	    c->callsite == XDEV_EXT_MECH_SITE_RX_HOLD_RESULT || !c->frames ||
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

__u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *ctx,
                           const size_t rdwr_buf_size)
{
	struct mock_call *c = mock_call_of(ctx);

	if (!c || !c->st || c->ctx.class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
	    c->member != XDEV_EXT_MECH_MEMBER_COMPLETE || !rdwr_buf_size ||
	    rdwr_buf_size > XDEV_EXT_AFXDP_MECH_STATE_SIZE ||
	    (c->callsite != XDEV_EXT_MECH_SITE_RX_GENERIC &&
	     c->callsite != XDEV_EXT_MECH_SITE_RX_NATIVE &&
	     c->callsite != XDEV_EXT_MECH_SITE_RX_HOLD_RESULT))
		return NULL;
	return (__u8 *)c->st;
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

/* --- the two implementations ------------------------------------------- */

/* Arm E: the BPF programs, as host C. */
#include "tools/xdev_ext_mech/nxp_mech.bpf.c"

/* Arm C: the reference callbacks on the mock envelope. */
#define XDEV_EXT_MECH_CREF_CALL_OF(ctx)	mock_call_of(ctx)

static __u64 xdev_ext_mech_cref_now_ns(void)
{
	return mock_now;
}

#include "xdev_ext_mech_cref.h"

/* --- test worlds --------------------------------------------------------- */

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
	struct xdev_ext_mp_rx_state rx;
	struct mock_call call;
	struct mock_frame frames[T_MAX];
	union t_info info;
	__u8 scratch[T_SCRATCH];
	__u8 cqe[T_CQES];
	__u32 nmem;			/* frames in use, compared */
	__u8 mem[T_MAX][T_FRAME_SIZE];
};

/* Program state of both arms; each arm keeps its own copy. */
struct t_state {
	__u64 nxp_session;
	__u64 key_base;
	__u32 nvme_mode;
	struct xdev_ext_mp_rx_order rx_order;
};

static struct world w_e, w_c;		/* arm E, arm C */
static struct xdev_ext_mech_cref_state cref;
static unsigned long checks, failures;
static const char *scenario = "";

#define EXPECT(cond, ...)						\
	do {								\
		checks++;						\
		if (!(cond)) {						\
			failures++;					\
			if (failures <= 20) {				\
				fprintf(stderr, "FAIL %s:%d [%s] ",	\
					__FILE__, __LINE__, scenario);	\
				fprintf(stderr, __VA_ARGS__);		\
				fputc('\n', stderr);			\
			}						\
		}							\
	} while (0)

static __u64 lcg_state = 0x9e3779b97f4a7c15ULL;

static __u32 rnd(void)
{
	lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
	return (__u32)(lcg_state >> 33);
}

static __u32 rnd_below(__u32 n)
{
	return n ? rnd() % n : 0;
}

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
	w->call.st = &w->rx;
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

/* Arm C's world becomes a copy of arm E's, with its own pointers. */
static void world_mirror(void)
{
	struct world *src = &w_e, *dst = &w_c;
	__u32 i;

	memcpy(dst, src, offsetof(struct world, mem));
	for (i = 0; i < src->nmem; i++)
		memcpy(dst->mem[i], src->mem[i], T_FRAME_SIZE);
	for (i = 0; i < T_MAX; i++)
		dst->frames[i].kaddr = src->frames[i].kaddr ?
			dst->mem[i] : NULL;
	dst->call.st = src->call.st ? &dst->rx : NULL;
	dst->call.frames = src->call.frames ? dst->frames : NULL;
	dst->call.info = src->call.info ? (const void *)&dst->info : NULL;
	dst->call.scratch = src->call.scratch ? dst->scratch : NULL;
	dst->call.cqe = src->call.cqe ? (const void *)dst->cqe : NULL;
}

static void state_load(const struct t_state *s)
{
	nxp_session = s->nxp_session;
	key_base = s->key_base;
	nvme_mode = s->nvme_mode;
	memset(&w_e.rx, 0, sizeof(w_e.rx));
	memset(&w_c.rx, 0, sizeof(w_c.rx));
	w_e.rx.order = s->rx_order;
	w_c.rx.order = s->rx_order;
	cref.nxp_session = s->nxp_session;
	cref.key_base = s->key_base;
	cref.nvme_mode = s->nvme_mode;
}

enum t_cb { CB_AFXDP_BUILD, CB_AFXDP_COMPLETE, CB_NVME_BUILD, CB_NVME_COMPLETE };

static const char *const cb_name[] = {
	"afxdp_build", "afxdp_complete", "nvme_build", "nvme_complete",
};

/* Outcome tallies of arm C, so no scenario family passes vacuously. */
static unsigned long seen[4][8];

/*
 * Run callback @cb in both worlds and compare everything either arm could
 * have touched.  Returns the common verdict.
 */
static __s32 run_both_call(enum t_cb cb)
{
	const struct xdev_ext_mech_ctx *ce = &w_e.call.ctx, *cc = &w_c.call.ctx;
	__s32 re = -100, rc = -100;
	__u32 i;

	switch (cb) {
	case CB_AFXDP_BUILD:
		re = nxp_afxdp_build(NULL, ce);
		rc = xdev_ext_mech_cref_afxdp_build(&cref, cc);
		break;
	case CB_AFXDP_COMPLETE:
		re = nxp_afxdp_complete(NULL, ce);
		rc = xdev_ext_mech_cref_afxdp_complete(&cref, cc);
		break;
	case CB_NVME_BUILD:
		re = nxp_nvme_build(NULL, ce);
		rc = xdev_ext_mech_cref_nvme_build(&cref, cc);
		break;
	case CB_NVME_COMPLETE:
		re = nxp_nvme_complete(NULL, ce);
		rc = xdev_ext_mech_cref_nvme_complete(cc);
		break;
	}
	EXPECT(re == rc, "%s: E returned %d, C returned %d", cb_name[cb], re, rc);
	EXPECT(!memcmp(w_e.scratch, w_c.scratch, sizeof(w_e.scratch)),
	       "%s: scratch differs", cb_name[cb]);
	for (i = 0; i < w_e.nmem; i++)
		EXPECT(!memcmp(w_e.mem[i], w_c.mem[i], T_FRAME_SIZE),
		       "%s: frame %u bytes differ", cb_name[cb], i);
	EXPECT(!memcmp(&w_e.call.hold, &w_c.call.hold, sizeof(w_e.call.hold)),
	       "%s: hold intent differs (E key=%llu pos=%u count=%u off=%u len=%u, C key=%llu pos=%u count=%u off=%u len=%u)",
	       cb_name[cb], (unsigned long long)w_e.call.hold.key,
	       w_e.call.hold.pos, w_e.call.hold.count, w_e.call.hold.span_off,
	       w_e.call.hold.span_len, (unsigned long long)w_c.call.hold.key,
	       w_c.call.hold.pos, w_c.call.hold.count, w_c.call.hold.span_off,
	       w_c.call.hold.span_len);
	EXPECT(w_e.call.hold_calls == w_c.call.hold_calls,
	       "%s: hold calls %u vs %u", cb_name[cb], w_e.call.hold_calls,
	       w_c.call.hold_calls);
	EXPECT(w_e.call.protocol_error == w_c.call.protocol_error,
	       "%s: misuse latch %u vs %u", cb_name[cb],
	       w_e.call.protocol_error, w_c.call.protocol_error);
	EXPECT(!memcmp(&w_e.rx, &w_c.rx, sizeof(w_e.rx)),
	       "%s: group order differs", cb_name[cb]);
	EXPECT(nxp_session == cref.nxp_session && key_base == cref.key_base &&
	       nvme_mode == cref.nvme_mode, "%s: globals changed", cb_name[cb]);
	if (rc >= 0 && rc < 8)
		seen[cb][rc]++;
	return rc;
}

/* Complete admission separately: RESULT has neither frame nor payload views. */
static __s32 run_result_both(int admission_err)
{
	struct mock_call saved_e = w_e.call, saved_c = w_c.call;
	struct xdev_ext_afxdp_rx_hold_cqe cqe = {
		.key = saved_e.hold.key, .pos = saved_e.hold.pos,
		.err = admission_err,
	};
	__s32 ret;
	struct world *worlds[] = { &w_e, &w_c };
	unsigned int i;

	for (i = 0; i < 2; i++) {
		struct mock_call *c = &worlds[i]->call;
		c->callsite = c->ctx.callsite = XDEV_EXT_MP_SITE_RX_HOLD_RESULT;
		c->nr_frames = c->ctx.nr_frames = 0;
		c->frames = NULL;
		c->cqe = &cqe;
		c->cqe_size = sizeof(cqe);
		c->cqe_cap = 1;
	}
	ret = run_both_call(CB_AFXDP_COMPLETE);
	w_e.call = saved_e;
	w_c.call = saved_c;
	return ret;
}

static __s32 run_both(enum t_cb cb)
{
	__s32 ret = run_both_call(cb);

	if (cb == CB_AFXDP_COMPLETE && ret == XDEV_EXT_MP_HOLD &&
	    (w_e.call.callsite == XDEV_EXT_MP_SITE_RX_GENERIC ||
	     w_e.call.callsite == XDEV_EXT_MP_SITE_RX_NATIVE))
		EXPECT(run_result_both(0) == XDEV_EXT_MP_HOLD,
		       "accepted admission did not commit candidate");
	return ret;
}

/* --- AF_XDP RX complete ------------------------------------------------- */

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

/* Candidate parsing is speculative in both implementations. Only C's
 * successful admission notification may advance canonical protocol order. */
static __s32 run_rx_admission_result(__u64 session, __u64 key, __u32 pos,
                                    int admission_err)
{
 struct xdev_ext_afxdp_rx_hold_cqe *q = (void *)w_e.cqe;
 world_reset(&w_e, XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_MEMBER_COMPLETE,
             XDEV_EXT_MECH_SITE_RX_HOLD_RESULT);
 w_e.call.ctx.session_id = session;
 w_e.call.ctx.nr_frames = w_e.call.nr_frames = 0;
 w_e.call.frames = NULL;
 *q = (struct xdev_ext_afxdp_rx_hold_cqe) {
  .key = key, .pos = pos, .err = admission_err,
 };
 w_e.call.cqe = q;
 w_e.call.cqe_size = sizeof(*q);
 w_e.call.cqe_cap = 1;
 world_mirror();
 return run_both(CB_AFXDP_COMPLETE);
}

static void test_rx_admission_transaction(void)
{
 const __u32 sites[] = { XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_SITE_RX_NATIVE };
 for (unsigned int i = 0; i < sizeof(sites) / sizeof(sites[0]); i++) {
  struct t_state st = { .nxp_session = 1000000011, .key_base = 1 };
  xdev_ext_mp_rx_order_session(&st.rx_order, 41);
  state_load(&st);
  scenario = "RX candidate/admission-result transaction";
  rx_world(sites[i], 41, st.nxp_session, 1, 0);
  world_mirror();
  EXPECT(run_both_call(CB_AFXDP_COMPLETE) == XDEV_EXT_MECH_HOLD,
         "valid candidate must HOLD before C admission");
  EXPECT(w_e.rx.order.next == 0 && w_c.rx.order.next == 0,
         "neither implementation may commit order during candidate parsing");
  EXPECT(run_rx_admission_result(41, 1, 0, -ENOSPC) == XDEV_EXT_MECH_RECYCLE,
         "rejected admission must recycle in both implementations");
  EXPECT(w_e.rx.order.next == 0 && w_c.rx.order.next == 0,
         "rejected admission must preserve canonical order in both arms");
  rx_world(sites[i], 41, st.nxp_session, 1, 0);
  world_mirror();
  EXPECT(run_both_call(CB_AFXDP_COMPLETE) == XDEV_EXT_MECH_HOLD,
         "same candidate must retry after rejected admission");
  EXPECT(w_e.rx.order.next == 0 && w_c.rx.order.next == 0,
         "retry remains speculative until success result");
  EXPECT(run_rx_admission_result(41, 1, 0, 0) == XDEV_EXT_MECH_HOLD,
         "admitted result must HOLD in both implementations");
  EXPECT(w_e.rx.order.next == 1 && w_c.rx.order.next == 1,
         "success result advances both canonical orders exactly once");
  EXPECT(run_rx_admission_result(41, 1, 0, 0) == XDEV_EXT_MECH_ABORT,
         "duplicate admission result must reject in both implementations");
  EXPECT(w_e.rx.order.next == 1 && w_c.rx.order.next == 1,
         "duplicate result cannot advance order again");
 }
}

/* The world as built is a segment both arms accept. */
static void test_rx_valid_group(void)
{
	struct t_state st = { .nxp_session = 1000000011, .key_base = 1 };
	__u16 index;

	scenario = "rx valid group";
	state_load(&st);
	for (index = 0; index < T_FRAMES; index++) {
		rx_world(XDEV_EXT_MECH_SITE_RX_GENERIC, 41, st.nxp_session, 1, index);
		world_mirror();
		EXPECT(run_both(CB_AFXDP_COMPLETE) == XDEV_EXT_MECH_HOLD,
		       "segment %u not held", index);
		EXPECT(w_c.call.hold.key == 1 && w_c.call.hold.pos == index &&
		       w_c.call.hold.count == w_c.call.batch_frames &&
		       w_c.call.hold.span_off == T_HDR_ROOM &&
		       w_c.call.hold.span_len == seg_payload(index),
		       "segment %u: wrong intent", index);
	}
	EXPECT(w_c.rx.order.last_generation == 1 && !w_c.rx.order.active,
	       "group 1 not committed");
}

/* Admission rejection, duplicate result and mismatched result never commit. */
static void test_rx_result_rejection(void)
{
	struct t_state st = { .nxp_session = 1000000011, .key_base = 1 };
	struct xdev_ext_mp_rx_order before;

	scenario = "rx result rejection";
	state_load(&st);
	rx_world(XDEV_EXT_MECH_SITE_RX_GENERIC, 41, st.nxp_session, 1, 0);
	world_mirror();
	EXPECT(run_both_call(CB_AFXDP_COMPLETE) == XDEV_EXT_MP_HOLD,
	       "valid segment not proposed");
	before = w_e.rx.order;
	EXPECT(!before.next, "proposal advanced order before admission");
	EXPECT(run_result_both(-ENOSPC) == XDEV_EXT_MP_RECYCLE,
	       "rejected admission not recycled");
	EXPECT(!memcmp(&before, &w_e.rx.order, sizeof(before)),
	       "rejected admission committed order");
	EXPECT(!w_e.rx.candidate_valid && !w_c.rx.candidate_valid,
	       "rejected candidate remained live");
	EXPECT(run_result_both(0) == XDEV_EXT_MP_ABORT,
	       "duplicate result accepted");
	EXPECT(!memcmp(&before, &w_e.rx.order, sizeof(before)),
	       "duplicate result committed order");
	rx_world(XDEV_EXT_MECH_SITE_RX_NATIVE, 41, st.nxp_session, 1, 0);
	world_mirror();
	EXPECT(run_both_call(CB_AFXDP_COMPLETE) == XDEV_EXT_MP_HOLD,
	       "rejected segment could not retry");
	w_e.call.hold.pos++;
	w_c.call.hold.pos++;
	EXPECT(run_result_both(0) == XDEV_EXT_MP_ABORT,
	       "mismatched result accepted");
	EXPECT(!memcmp(&before, &w_e.rx.order, sizeof(before)),
	       "mismatched result committed order");
}

/* Ways a received frame can go wrong, each against an ordered stream. */
enum rx_mut {
	RX_OK, RX_SESSION, RX_CRC, RX_PAYLOAD, RX_IPCSUM, RX_MAC, RX_PORT,
	RX_ETHERTYPE, RX_PROTO, RX_MAGIC, RX_SHORT, RX_LONG, RX_OFF_EARLY,
	RX_OFF_LATE, RX_DIR, RX_VERSION, RX_INFO_SIZE, RX_NO_INFO,
	RX_CLASS, RX_NATIVE, RX_WORKER, RX_CREATE, RX_FRAG, RX_TOTAL,
	RX_NR,
};

static void rx_mutate(enum rx_mut m)
{
	struct xdev_ext_afxdp_mech_info *info = &w_e.info.afxdp;
	__u8 *pkt = w_e.mem[0] + T_DATA_OFF;

	switch (m) {
	case RX_OK:
		break;
	case RX_SESSION:	/* NXP session field, CRC left stale */
		pkt[XDEV_EXT_MP_NXP_OFF + 15] ^= 1;
		break;
	case RX_CRC:
		pkt[XDEV_EXT_MP_NXP_OFF + XDEV_EXT_MP_NXP_CSUM_OFF] ^= 0x80;
		break;
	case RX_PAYLOAD:
		pkt[XDEV_EXT_MP_PKT_HDR_LEN + rnd_below(1000)] ^= 0x10;
		break;
	case RX_IPCSUM:
		pkt[XDEV_EXT_MP_ETH_LEN + 11] ^= 1;
		break;
	case RX_MAC:
		pkt[5] ^= 1;
		break;
	case RX_PORT:
		pkt[XDEV_EXT_MP_ETH_LEN + XDEV_EXT_MP_IP_LEN + 3] ^= 1;
		break;
	case RX_ETHERTYPE:
		pkt[12] = 0x86;
		pkt[13] = 0xdd;
		break;
	case RX_PROTO:
		pkt[XDEV_EXT_MP_ETH_LEN + 9] = 6;
		break;
	case RX_MAGIC:
		pkt[XDEV_EXT_MP_NXP_OFF] ^= 0x20;
		break;
	case RX_SHORT:
		info->f[0].data_len = XDEV_EXT_MP_PKT_HDR_LEN - 1 - rnd_below(20);
		break;
	case RX_LONG:
		info->f[0].data_len += 1 + rnd_below(8);
		break;
	case RX_OFF_EARLY:
		info->f[0].data_off -= 8;
		break;
	case RX_OFF_LATE:
		info->f[0].data_off = T_FRAME_SIZE - 40;
		break;
	case RX_DIR:
		pkt[XDEV_EXT_MP_NXP_OFF + 6] = XDEV_EXT_MP_NXP_DIR_READ;
		break;
	case RX_VERSION:
		pkt[XDEV_EXT_MP_NXP_OFF + 4] = 3;
		break;
	case RX_INFO_SIZE:
		w_e.call.info_size -= 8;
		break;
	case RX_NO_INFO:
		w_e.call.info = NULL;
		break;
	case RX_CLASS:	/* the hold kfunc refuses: misuse latched */
		w_e.call.ctx.class_id = XDEV_EXT_MECH_CLASS_NVME;
		break;
	case RX_NATIVE:
		w_e.call.ctx.callsite = XDEV_EXT_MECH_SITE_RX_NATIVE;
		w_e.call.callsite = XDEV_EXT_MECH_SITE_RX_NATIVE;
		break;
	case RX_WORKER:	/* the TX complete branch on an RX world */
		w_e.call.ctx.callsite = XDEV_EXT_MECH_SITE_WORKER;
		w_e.call.callsite = XDEV_EXT_MECH_SITE_WORKER;
		break;
	case RX_CREATE:
		w_e.call.ctx.callsite = XDEV_EXT_MECH_SITE_CREATE;
		w_e.call.callsite = XDEV_EXT_MECH_SITE_CREATE;
		break;
	case RX_FRAG:
		pkt[XDEV_EXT_MP_ETH_LEN + 6] |= 0x20;
		break;
	case RX_TOTAL:
		pkt[XDEV_EXT_MP_NXP_OFF + 27] ^= 8;
		break;
	case RX_NR:
		break;
	}
}

/*
 * A sender's stream of groups, with a mutation, a duplicate, a skipped or
 * reordered segment, a clock jump past the group timeout or a session
 * change mixed in at random.  Both arms keep their own group order.
 */
static void test_rx_stream(void)
{
	struct t_state st = { .nxp_session = 1000000011, .key_base = 1 };
	__u32 gen = 1, step;
	__u16 index = 0;
	__u64 mech_session = 7;

	scenario = "rx stream";
	state_load(&st);
	mock_now = 1000;
	for (step = 0; step < 40000; step++) {
		__u32 r = rnd_below(100);
		__u32 g = gen;
		__u16 i = index;
		enum rx_mut m = RX_OK;

		if (r < 8)
			m = (enum rx_mut)(1 + rnd_below(RX_NR - 1));
		else if (r < 10 && index)
			i = index - 1;			/* duplicate */
		else if (r < 12)
			i = (index + 1) % T_FRAMES;	/* skip ahead */
		else if (r < 13)
			g = gen + 1;			/* next group early */
		else if (r < 14)
			mock_now += XDEV_EXT_MP_GROUP_TIMEOUT_NS;	/* timeout */
		else if (r < 15)
			mech_session++;			/* new session */
		mock_now += 1 + rnd_below(5000);
		rx_world(XDEV_EXT_MECH_SITE_RX_GENERIC, mech_session,
			 st.nxp_session, g, i);
		rx_mutate(m);
		world_mirror();
		run_both(CB_AFXDP_COMPLETE);
		/* The sender goes on with what the receiver expects next. */
		gen = w_c.rx.order.active ? w_c.rx.order.generation :
			w_c.rx.order.last_generation + 1;
		index = w_c.rx.order.active ? w_c.rx.order.next : 0;
	}
}

/* Random byte flips over the whole header and the start of the payload. */
static void test_rx_fuzz(void)
{
	struct t_state st = { .nxp_session = 1000000011, .key_base = 1 };
	__u32 n, k;

	scenario = "rx fuzz";
	for (n = 0; n < 30000; n++) {
		memset(&st.rx_order, 0, sizeof(st.rx_order));
		if (rnd_below(2)) {	/* sometimes mid-group */
			st.rx_order.session_id = 9;
			st.rx_order.active = 1;
			st.rx_order.generation = 3;
			st.rx_order.total_len = T_GROUP;
			st.rx_order.count = T_FRAMES;
			st.rx_order.next = 2;
			st.rx_order.received_len = 2 * T_SEG_LEN;
			st.rx_order.last_generation = 2;
			st.rx_order.started_ns = 500;
		}
		state_load(&st);
		mock_now = 1000 + rnd_below(3) * XDEV_EXT_MP_GROUP_TIMEOUT_NS;
		rx_world(XDEV_EXT_MECH_SITE_RX_GENERIC, 9, st.nxp_session,
			 rnd_below(2) ? 3 : 1 + rnd_below(4),
			 (__u16)rnd_below(T_FRAMES));
		for (k = 0; k < 1 + rnd_below(3); k++)
			w_e.mem[0][T_DATA_OFF + rnd_below(XDEV_EXT_MP_PKT_HDR_LEN + 64)] ^=
				(__u8)(1 + rnd_below(255));
		if (!rnd_below(8))
			w_e.info.afxdp.f[0].data_len = rnd_below(2000);
		if (!rnd_below(16))
			w_e.info.afxdp.f[0].data_off = rnd_below(T_FRAME_SIZE);
		if (!rnd_below(16))
			w_e.info.afxdp.mtu = rnd_below(2) ? 0 : rnd_below(9000);
		if (!rnd_below(16))
			w_e.info.afxdp.l.seg_len = 1424;
		world_mirror();
		run_both(CB_AFXDP_COMPLETE);
	}
}

/* --- AF_XDP TX build and complete ---------------------------------------- */

static void tx_build_world(__u32 nr, __u64 key)
{
	struct xdev_ext_afxdp_mech_info *info = &w_e.info.afxdp;
	__u32 i, j;

	world_reset(&w_e, XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_MEMBER_BUILD,
		    XDEV_EXT_MECH_SITE_WORKER);
	w_e.nmem = nr < T_MAX ? nr : T_MAX;
	w_e.call.ctx.base.src_offset = key;
	w_e.call.ctx.nr_frames = nr < T_MAX ? nr : T_MAX;
	w_e.call.nr_frames = nr < T_MAX ? nr : T_MAX;
	w_e.call.info_size = sizeof(*info);
	w_e.call.scratch = w_e.scratch;
	w_e.call.desc_size = sizeof(struct xdp_desc);
	w_e.call.desc_cap = T_MAX;
	w_e.call.ctx.desc_cap = T_MAX;
	info->l = (struct xdev_ext_mech_layout) {
		.frame_size = T_FRAME_SIZE, .hdr_room = T_HDR_ROOM,
		.seg_len = T_SEG_LEN, .group_bytes = nr * T_SEG_LEN,
	};
	info->mtu = T_MTU;
	info->nr_frames = nr;
	info->peer = tx_peer(&rx_peer);
	for (i = 0; i < T_MAX; i++) {
		info->f[i].umem_addr = (__u64)(i + 3) * T_FRAME_SIZE;
		info->f[i].data_off = T_HDR_ROOM;
		info->f[i].data_len = T_SEG_LEN;
		if (i >= w_e.nmem)
			continue;
		memset(w_e.mem[i], (int)(rnd() & 0xff), T_FRAME_SIZE);
		for (j = 0; j < 16; j++)
			w_e.mem[i][rnd_below(T_FRAME_SIZE)] = (__u8)rnd();
	}
}

static void test_tx_build(void)
{
	struct t_state st = { .nxp_session = 1000000012, .key_base = 1 };
	__u32 n;

	scenario = "tx build valid";
	state_load(&st);
	tx_build_world(T_FRAMES, 1);
	world_mirror();
	EXPECT(run_both(CB_AFXDP_BUILD) == XDEV_EXT_MECH_BUILD_SUBMIT,
	       "a valid TX build did not submit");

	scenario = "tx build random";
	for (n = 0; n < 8000; n++) {
		__u32 nr = rnd_below(4) ? 1 + rnd_below(T_MAX) : rnd_below(40);
		__u32 r = rnd_below(24), p;

		st.key_base = rnd_below(3) ? 1 : rnd_below(10);
		st.nxp_session = rnd_below(8) ? 1000000012 : rnd_below(2);
		state_load(&st);
		tx_build_world(nr, st.key_base + rnd_below(100));
		p = rnd_below(nr ? (nr < T_MAX ? nr : T_MAX) : 1);
		switch (r) {
		case 0:
			w_e.call.ctx.base.src_offset = st.key_base ?
				st.key_base - 1 : 0;
			break;
		case 1:
			w_e.call.ctx.base.src_offset = st.key_base + 0xffffffffULL;
			break;
		case 2:
			w_e.info.afxdp.f[p].data_off = XDEV_EXT_MP_PKT_HDR_LEN - 1;
			break;
		case 3:
			w_e.call.hdr_room = 100;
			break;
		case 4:
			w_e.info.afxdp.f[p].data_off = T_FRAME_SIZE;
			break;
		case 5:
			w_e.info.afxdp.f[p].data_len = 0;
			break;
		case 6:
			w_e.info.afxdp.f[p].data_len = T_FRAME_SIZE;
			break;
		case 7:
			w_e.call.desc_size = 15;
			break;
		case 8:
			w_e.call.desc_cap = p;
			break;
		case 9:
			w_e.call.info_size = 0;
			break;
		case 10:
			w_e.call.nr_frames = p;
			break;
		case 11:
			w_e.call.ctx.callsite = XDEV_EXT_MECH_SITE_RX_GENERIC;
			w_e.call.callsite = XDEV_EXT_MECH_SITE_RX_GENERIC;
			break;
		case 12:
			w_e.info.afxdp.l.group_bytes += 1 + rnd_below(3000);
			break;
		case 13:
			w_e.info.afxdp.f[p].data_len = 1 + rnd_below(T_SEG_LEN);
			break;
		case 14:
			w_e.info.afxdp.f[p].data_off = XDEV_EXT_MP_PKT_HDR_LEN +
						       rnd_below(400);
			break;
		case 15:
			w_e.call.ctx.class_id = XDEV_EXT_MECH_CLASS_NVME;
			break;
		default:
			break;
		}
		world_mirror();
		run_both(CB_AFXDP_BUILD);
	}
}

static void test_tx_complete(void)
{
	static const int errs[] = { 0, 1, 1432, -EAGAIN, -ECANCELED, -EIO,
				    -ENOBUFS, -ENXIO };
	struct t_state st = { .key_base = 1 };
	__u32 n, i;

	scenario = "tx complete";
	state_load(&st);
	for (n = 0; n < 20000; n++) {
		__u32 nr = rnd_below(T_MAX + 3);
		struct xdev_ext_afxdp_tx_cqe *cqe = (void *)w_e.cqe;

		world_reset(&w_e, XDEV_EXT_MECH_CLASS_AFXDP,
			    XDEV_EXT_MECH_MEMBER_COMPLETE, XDEV_EXT_MECH_SITE_WORKER);
		w_e.call.ctx.nr_frames = nr;
		w_e.call.nr_frames = nr < T_MAX ? nr : T_MAX;
		w_e.call.cqe = w_e.cqe;
		w_e.call.cqe_size = rnd_below(10) ? sizeof(*cqe) : 4;
		w_e.call.cqe_cap = rnd_below(4) ? (nr < T_MAX ? nr : T_MAX) :
				   rnd_below(T_MAX + 1);
		if (!rnd_below(20))
			w_e.call.cqe = NULL;
		for (i = 0; i < T_MAX; i++)
			cqe[i].err = rnd_below(3) ? 0 :
				     errs[rnd_below(sizeof(errs) / sizeof(errs[0]))];
		world_mirror();
		run_both(CB_AFXDP_COMPLETE);
	}
}

/* --- NVMe build and complete ---------------------------------------------- */

static void test_nvme_build(void)
{
	static const __u32 shifts[] = { 9, 12, 9, 12, 8, 31, 32 };
	static const __u32 groups[] = { 8192, 8192, 4096, 65536, 1000, 0,
					1U << 31 };
	struct t_state st = { .key_base = 1 };
	__u32 n;

	for (n = 0; n < 30000; n++) {
		struct xdev_ext_nvme_mech_info *info = &w_e.info.nvme;
		__u32 shift = shifts[rnd_below(sizeof(shifts) / sizeof(shifts[0]))];

		scenario = "nvme build";
		st.key_base = rnd_below(4) ? 1 : rnd_below(5);
		st.nvme_mode = rnd_below(4) ? 0 : rnd_below(4);
		state_load(&st);
		world_reset(&w_e, XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_MEMBER_BUILD,
			    XDEV_EXT_MECH_SITE_WORKER);
		w_e.call.info_size = rnd_below(30) ? sizeof(*info) : 64;
		w_e.call.scratch = w_e.scratch;
		w_e.call.desc_size = rnd_below(30) ? XDEV_EXT_NVME_MECH_DESC_SIZE : 32;
		w_e.call.desc_cap = rnd_below(30) ? 1 : 0;
		w_e.call.ctx.desc_cap = 1;
		w_e.call.ctx.base.direction = rnd_below(8) ?
			1 + rnd_below(2) : rnd_below(5);
		w_e.call.ctx.base.src_offset = st.key_base + rnd_below(2048) -
					      (rnd_below(16) ? 0 : 1);
		info->l.group_bytes = groups[rnd_below(sizeof(groups) / sizeof(groups[0]))];
		w_e.call.ctx.base.length = rnd_below(8) ? info->l.group_bytes :
			rnd() | (rnd_below(4) ? 0 : 1ULL << 32);
		info->lba_shift = shift;
		info->max_nlb = 65536;
		info->window_slba = rnd_below(4) ? 32768 :
			((__u64)rnd() << 32 | rnd());
		info->window_nlb = rnd_below(4) ? 1024 :
			((__u64)rnd() << rnd_below(33));
		info->capacity_lbas = 524288;
		world_mirror();
		run_both(CB_NVME_BUILD);
	}
}

static void test_nvme_complete(void)
{
	static const __u32 sites[] = { XDEV_EXT_MECH_SITE_WORKER,
				       XDEV_EXT_MECH_SITE_URING_CMD,
				       XDEV_EXT_MECH_SITE_RX_GENERIC };
	struct t_state st = { .key_base = 1 };
	__u32 n;

	scenario = "nvme complete";
	state_load(&st);
	for (n = 0; n < 10000; n++) {
		struct xdev_ext_nvme_mech_cqe *cqe = (void *)w_e.cqe;
		__u32 site = sites[rnd_below(3)];

		world_reset(&w_e, XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_MEMBER_COMPLETE,
			    site);
		w_e.call.cqe = w_e.cqe;
		w_e.call.cqe_size = rnd_below(10) ? sizeof(*cqe) : 8;
		w_e.call.cqe_cap = rnd_below(10) ? 1 : 0;
		cqe->status = rnd_below(3) ? 0 : (__u16)rnd();
		cqe->err = rnd_below(3) ? 0 : -(int)rnd_below(200);
		cqe->result = rnd();
		world_mirror();
		run_both(CB_NVME_COMPLETE);
	}
}

int main(void)
{
	test_rx_admission_transaction();
	test_rx_valid_group();
	test_rx_result_rejection();
	test_rx_stream();
	test_rx_fuzz();
	test_tx_build();
	test_tx_complete();
	test_nvme_build();
	test_nvme_complete();

	/* Every family reached its interesting verdicts, in arm C. */
	scenario = "coverage";
	EXPECT(seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_HOLD] >= 1000,
	       "RX held %lu", seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_HOLD]);
	EXPECT(seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_RECYCLE] >= 1000,
	       "RX recycled %lu", seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_RECYCLE]);
	EXPECT(seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_PUBLISH] >= 1000,
	       "RX published %lu", seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_PUBLISH]);
	EXPECT(seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_NEXT] >= 1000 &&
	       seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_RETRY] >= 100 &&
	       seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_ABORT] >= 100,
	       "TX complete verdicts %lu/%lu/%lu",
	       seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_NEXT],
	       seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_RETRY],
	       seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_ABORT]);
	EXPECT(seen[CB_AFXDP_BUILD][XDEV_EXT_MECH_BUILD_SUBMIT] >= 1000 &&
	       seen[CB_AFXDP_BUILD][XDEV_EXT_MECH_BUILD_ABORT] >= 1000,
	       "TX build verdicts %lu/%lu",
	       seen[CB_AFXDP_BUILD][XDEV_EXT_MECH_BUILD_SUBMIT],
	       seen[CB_AFXDP_BUILD][XDEV_EXT_MECH_BUILD_ABORT]);
	EXPECT(seen[CB_NVME_BUILD][XDEV_EXT_MECH_BUILD_SUBMIT] >= 1000 &&
	       seen[CB_NVME_BUILD][XDEV_EXT_MECH_BUILD_ABORT] >= 1000,
	       "NVMe build verdicts %lu/%lu",
	       seen[CB_NVME_BUILD][XDEV_EXT_MECH_BUILD_SUBMIT],
	       seen[CB_NVME_BUILD][XDEV_EXT_MECH_BUILD_ABORT]);
	EXPECT(seen[CB_NVME_COMPLETE][XDEV_EXT_MECH_NEXT] >= 100 &&
	       seen[CB_NVME_COMPLETE][XDEV_EXT_MECH_DONE] >= 100 &&
	       seen[CB_NVME_COMPLETE][XDEV_EXT_MECH_ABORT] >= 100,
	       "NVMe complete verdicts %lu/%lu/%lu",
	       seen[CB_NVME_COMPLETE][XDEV_EXT_MECH_NEXT],
	       seen[CB_NVME_COMPLETE][XDEV_EXT_MECH_DONE],
	       seen[CB_NVME_COMPLETE][XDEV_EXT_MECH_ABORT]);

	printf("COVERAGE rx_hold=%lu rx_recycle=%lu rx_publish=%lu tx_submit=%lu tx_abort=%lu nvme_submit=%lu nvme_abort=%lu\n",
	       seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_HOLD],
	       seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_RECYCLE],
	       seen[CB_AFXDP_COMPLETE][XDEV_EXT_MECH_PUBLISH],
	       seen[CB_AFXDP_BUILD][XDEV_EXT_MECH_BUILD_SUBMIT],
	       seen[CB_AFXDP_BUILD][XDEV_EXT_MECH_BUILD_ABORT],
	       seen[CB_NVME_BUILD][XDEV_EXT_MECH_BUILD_SUBMIT],
	       seen[CB_NVME_BUILD][XDEV_EXT_MECH_BUILD_ABORT]);
	if (failures) {
		printf("FAIL: %lu/%lu XDEV_EXT mechanism C reference checks failed\n",
		       failures, checks);
		return 1;
	}
	printf("PASS: %lu XDEV_EXT mechanism C reference checks\n", checks);
	return 0;
}

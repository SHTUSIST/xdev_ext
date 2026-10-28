/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_GPU_NIC_CORE_H
#define XDEV_EVAL_GPU_NIC_CORE_H

/*
 * Pure host logic of the GPU<->NIC eval arms (session_gpu_nic.c,
 * afxdp_cuda.cu, udp_pinned_cuda.cu, nxp_peer.c): the message and group
 * plan, the NXP wire every arm speaks, its CRC32C, and the oracles.
 *
 * Every arm moves the same NXP2 WRITE groups the session's nxp_afxdp_ops
 * program sends and accepts (kernel/tools/xdev_ext_mech/xdev_ext_mech_prog.h,
 * included here unchanged): Ethernet, option-less IPv4, UDP, a 40-byte NXP
 * header, CRC32C over the header (checksum field zero) and the payload.  A
 * baseline therefore does the same per-packet protocol work as the session
 * and can face the same peer.
 *
 * A message of `size` bytes travels as size/group_bytes groups.  group_bytes
 * is the largest power of two that is at most the message and at most the 32
 * frames of the session layout xdev_ext_mech_ctl gives the link MTU.  Group
 * g (generation g + 1) carries block g mod window_groups of the
 * nvme_gpu_core.h payload, so a group names itself.  On the GPU side every
 * arm places group g in device slot g mod depth, as the session's
 * ce_plan_ops places a batch in its batch slot: the slot oracle accepts any
 * whole, distinct group image per slot.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <linux/if_xdp.h>
#include <linux/types.h>

#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
#include "../nvme_gpu/nvme_gpu_core.h"

#include <arpa/inet.h>

#if defined(__SSE4_2__)
#include <nmmintrin.h>
#endif

#define GN_MIN_SIZE		64ULL
#define GN_MAX_SIZE		(4ULL << 20)
#define GN_MAX_DEPTH		64ULL		/* XDEV_EXT_MECH_MAX_DEPTH */
#define GN_MAX_MESSAGES		(1ULL << 24)
#define GN_PORT_BYTES		2

/*
 * Scenario message shapes (microbenchmarks shaped like the services, not the
 * services): ingest is one LoRA microbatch of 8 x 4096 int32 token ids with
 * its attention mask and labels; egress is one 4 MiB response group.
 */
#define GN_INGEST_MESSAGE	(8ULL * 4096 * 4 * 3)
#define GN_EGRESS_MESSAGE	(4ULL << 20)

struct gn_plan {
	uint64_t size;			/* message bytes */
	uint64_t messages;		/* messages in the campaign */
	uint32_t mtu;
	uint32_t depth;			/* device slots and groups in flight */
	struct xdev_ext_mech_layout l;	/* the session layout of one group */
	uint32_t frames;		/* frames (segments) per group */
	uint64_t groups;		/* messages * size / group_bytes */
	uint64_t window_groups;		/* distinct group payloads */
};

static inline uint64_t gn_pow2_floor(uint64_t v)
{
	uint64_t p = 1;

	while (v / 2 >= p)
		p <<= 1;
	return v ? p : 0;
}

/*
 * The plan for @size-byte messages on an @mtu link.  0, -EINVAL for an
 * unsupported size/MTU/depth, -ERANGE when the message is not whole groups.
 */
static inline int gn_plan_init(struct gn_plan *p, uint64_t size, uint64_t messages,
			       uint32_t mtu, uint32_t depth, uint64_t window_groups)
{
	struct xdev_ext_mech_layout l;
	uint64_t cap, group;
	int ret;

	memset(p, 0, sizeof(*p));
	if (size < GN_MIN_SIZE || size > GN_MAX_SIZE || size % 8 || !messages ||
	    messages > GN_MAX_MESSAGES || !depth || depth > GN_MAX_DEPTH ||
	    !window_groups || window_groups > GN_MAX_MESSAGES)
		return -EINVAL;
	/* seg_len of this MTU: a one-frame probe of the ctl layout. */
	ret = xdev_ext_mech_ctl_layout(mtu, 8, &l);
	if (ret)
		return -EINVAL;
	cap = (uint64_t)l.seg_len * XDEV_EXT_MECH_MAX_FRAMES;
	group = gn_pow2_floor(size < cap ? size : cap);
	if (size % group)
		return -ERANGE;
	ret = xdev_ext_mech_ctl_layout(mtu, (uint32_t)group, &l);
	if (ret)
		return -EINVAL;
	p->size = size;
	p->messages = messages;
	p->mtu = mtu;
	p->depth = depth;
	p->l = l;
	p->frames = (uint32_t)xdev_ext_mech_layout_frames(&l);
	p->groups = messages * (size / group);
	p->window_groups = window_groups;
	return 0;
}

/* Segment @i of a group: payload [off, off + len) of the group. */
static inline void gn_segment(const struct gn_plan *p, uint32_t i, uint32_t *off,
			      uint32_t *len)
{
	uint32_t seg = p->l.seg_len, total = p->l.group_bytes;

	*off = i * seg;
	*len = total - *off < seg ? total - *off : seg;
}

/*
 * CUDA copies of one group between its device slot and host memory where
 * segment i starts at host + i*pitch: one 2D copy of the full-length
 * segments (rows of seg_len bytes) and one copy of a shorter last segment.
 * calls is 1 or 2, whatever the number of segments.
 */
struct gn_group_copy {
	uint32_t rows, width, tail, calls;
};

static inline struct gn_group_copy gn_group_copy(const struct gn_plan *p)
{
	struct gn_group_copy c;

	c.width = p->l.seg_len;
	c.rows = p->l.group_bytes / c.width;
	c.tail = p->l.group_bytes % c.width;
	c.calls = (c.rows ? 1 : 0) + (c.tail ? 1 : 0);
	return c;
}

/* Whether @n payload addresses sit at one fixed @pitch (a 2D copy reaches them). */
static inline bool gn_chunks_strided(const uint64_t *addr, uint32_t n, uint64_t pitch)
{
	uint32_t i;

	if (!n)
		return false;
	for (i = 1; i < n; i++)
		if (addr[i] != addr[0] + (uint64_t)i * pitch)
			return false;
	return true;
}

/* Byte offset of group @g's payload in the shared window payload. */
static inline uint64_t gn_group_offset(const struct gn_plan *p, uint64_t g)
{
	return (g % p->window_groups) * p->l.group_bytes;
}

/* --- endpoint options shared by every arm and the peer ------------------ */

/* Dotted IPv4 into network byte order. */
static inline int gn_parse_ip(const char *text, __be32 *ip)
{
	return inet_pton(AF_INET, text, ip) == 1 ? 0 : -EINVAL;
}

/* Decimal port 1..65535 into network byte order. */
static inline int gn_parse_port(const char *text, __be16 *port)
{
	uint64_t v;

	if (xg_parse_u64(text, 65535, &v) || !v)
		return -EINVAL;
	*port = htons((uint16_t)v);
	return 0;
}

/* --- CRC32C (Castagnoli, reflected 0x82f63b78), as crc32c() in the kernel - */

static inline uint32_t gn_crc32c_sw(uint32_t crc, const unsigned char *p, size_t n)
{
	static uint32_t table[256];
	static bool ready;
	size_t i;

	if (!ready) {
		for (i = 0; i < 256; i++) {
			uint32_t c = (uint32_t)i;
			int k;

			for (k = 0; k < 8; k++)
				c = c & 1 ? (c >> 1) ^ 0x82f63b78U : c >> 1;
			table[i] = c;
		}
		ready = true;
	}
	for (i = 0; i < n; i++)
		crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
	return crc;
}

/* No pre- or post-inversion, like the kernel's crc32c() step. */
static inline uint32_t gn_crc32c(uint32_t crc, const unsigned char *p, size_t n)
{
#if defined(__SSE4_2__)
	uint64_t c = crc;

	for (; n >= 8; n -= 8, p += 8) {
		uint64_t v;

		memcpy(&v, p, 8);
		c = _mm_crc32_u64(c, v);
	}
	crc = (uint32_t)c;
	for (; n; n--, p++)
		crc = _mm_crc32_u8(crc, *p);
	return crc;
#else
	return gn_crc32c_sw(crc, p, n);
#endif
}

/* The NXP checksum field value of a header @nxp (40 bytes) and its payload. */
static inline uint32_t gn_nxp_crc(const unsigned char *nxp, const unsigned char *payload,
				  size_t len)
{
	unsigned char hdr[XDEV_EXT_MP_NXP_LEN];
	uint32_t crc;

	xdev_ext_mp_nxp_crc_prep(hdr, nxp);
	crc = gn_crc32c(XDEV_EXT_MP_CRC32C_SEED, hdr, sizeof(hdr));
	crc = gn_crc32c(crc, payload, len);
	return ~crc;
}

/*
 * NXP header (40 bytes, no Ethernet/IP/UDP) of segment @i of group @g, as
 * the session's TX program writes it: generation g + 1, checksum zero.
 */
static inline int gn_nxp_header(unsigned char *nxp, const struct gn_plan *p,
				uint64_t wire_session, uint64_t g, uint32_t i)
{
	unsigned char pkt[XDEV_EXT_MP_PKT_HDR_LEN];
	struct xdev_ext_mech_peer peer;
	struct xdev_ext_mp_tx_seg s;
	uint32_t off, len;
	int ret;

	if (g >= 0xffffffffULL || i >= p->frames)
		return -EINVAL;
	gn_segment(p, i, &off, &len);
	memset(&peer, 0, sizeof(peer));
	s = (struct xdev_ext_mp_tx_seg) {
		.session_id = wire_session, .generation = (__u32)(g + 1),
		.total_len = p->l.group_bytes, .relative_offset = off,
		.payload_len = len, .index = (__u16)i, .count = (__u16)p->frames,
	};
	ret = xdev_ext_mp_tx_encode(pkt, &peer, &s);
	if (ret)
		return ret;
	memcpy(nxp, pkt + XDEV_EXT_MP_NXP_OFF, XDEV_EXT_MP_NXP_LEN);
	return 0;
}

/* A received NXP header (UDP payload start) of this plan; fields in @s. */
static inline int gn_nxp_parse(const unsigned char *nxp, size_t udp_payload_len,
			       const struct gn_plan *p, uint64_t wire_session,
			       struct xdev_ext_mp_segment *s)
{
	uint32_t off, len;

	if (udp_payload_len < XDEV_EXT_MP_NXP_LEN ||
	    xdev_ext_mp_get_be32(nxp) != XDEV_EXT_MP_NXP_MAGIC ||
	    nxp[4] != XDEV_EXT_MP_NXP_VERSION || nxp[5] != XDEV_EXT_MP_NXP_LEN ||
	    nxp[6] != XDEV_EXT_MP_NXP_DIR_WRITE || nxp[7])
		return -EPROTO;
	memset(s, 0, sizeof(*s));
	s->session_id = xdev_ext_mp_get_be64(nxp + 8);
	s->generation = xdev_ext_mp_get_be32(nxp + 16);
	s->index = xdev_ext_mp_get_be16(nxp + 20);
	s->count = xdev_ext_mp_get_be16(nxp + 22);
	s->total_len = xdev_ext_mp_get_be32(nxp + 24);
	s->relative_offset = xdev_ext_mp_get_be32(nxp + 28);
	s->payload_len = xdev_ext_mp_get_be32(nxp + 32);
	if (s->session_id != wire_session || !s->generation ||
	    s->total_len != p->l.group_bytes || s->count != p->frames ||
	    s->index >= s->count)
		return -EPROTO;
	gn_segment(p, s->index, &off, &len);
	if (s->relative_offset != off || s->payload_len != len ||
	    udp_payload_len != XDEV_EXT_MP_NXP_LEN + (size_t)len)
		return -EPROTO;
	return 0;
}

/*
 * Payload identity from the protocol CRC, for a receiver that must not scan
 * a payload twice.  Without pre/post inversion a CRC32C step is linear over
 * GF(2): crc(H, P) = crc(H, zeros(len)) ^ crc(0, P).  The receiver computes
 * c = crc(crc(SEED, header), payload) for the protocol check anyway; with the
 * 32 columns of the zeros(len) shift precomputed per segment length,
 * c ^ shift(crc(SEED, header)) is crc(0, payload), compared against a table
 * of the expected payload blocks built before the campaign.
 */
struct gn_crc_shift {
	uint32_t len;
	uint32_t column[32];
};

static inline void gn_crc_shift_init(struct gn_crc_shift *m, uint32_t len,
				     unsigned char *zeros)
{
	int j;

	memset(zeros, 0, len);
	m->len = len;
	for (j = 0; j < 32; j++)
		m->column[j] = gn_crc32c(1U << j, zeros, len);
}

static inline uint32_t gn_crc_shift(const struct gn_crc_shift *m, uint32_t state)
{
	uint32_t out = 0;
	int j;

	for (j = 0; j < 32; j++)
		if (state & (1U << j))
			out ^= m->column[j];
	return out;
}

/* crc(0, payload) of segment @i of a group carrying payload block @block. */
static inline uint32_t gn_payload_crc(const struct gn_plan *p, uint64_t block,
				      uint32_t i, uint32_t pattern_seed,
				      unsigned char *scratch)
{
	uint32_t off, len;

	gn_segment(p, i, &off, &len);
	xg_fill(scratch, block * p->l.group_bytes + off, len, pattern_seed);
	return gn_crc32c(0, scratch, len);
}

/*
 * One received segment: the protocol check (the header's checksum field) and
 * crc(0, payload) in *@payload_crc, from a single pass over the payload.
 */
static inline bool gn_segment_check(const unsigned char *nxp, const unsigned char *payload,
				    const struct gn_crc_shift *m, uint32_t *payload_crc)
{
	unsigned char hdr[XDEV_EXT_MP_NXP_LEN];
	uint32_t h, c;

	xdev_ext_mp_nxp_crc_prep(hdr, nxp);
	h = gn_crc32c(XDEV_EXT_MP_CRC32C_SEED, hdr, sizeof(hdr));
	c = gn_crc32c(h, payload, m->len);
	*payload_crc = c ^ gn_crc_shift(m, h);
	return xdev_ext_mp_nxp_crc_ok(nxp, c);
}

/*
 * Slot oracle of the GPU side: @slots device slots of one group each.  Every
 * slot holds a whole image of a distinct group block, or (when fewer groups
 * than slots ran) still its sentinel.  0, -EEXIST for a duplicate,
 * -EBADMSG for a torn or foreign slot, -ENODATA for too few images.
 */
static inline int gn_check_slots(const unsigned char *slots, const struct gn_plan *p,
				 uint32_t seed, unsigned char *seen, uint64_t *used)
{
	uint64_t s, g = p->l.group_bytes, nblocks = p->window_groups;
	uint64_t want = p->groups < p->depth ? p->groups : p->depth;

	memset(seen, 0, nblocks);
	*used = 0;
	for (s = 0; s < p->depth; s++) {
		uint64_t block;
		int ret = xg_identify(slots + s * g, g, nblocks, seed, &block);

		if (!ret) {
			if (seen[block]++)
				return -EEXIST;
			(*used)++;
			continue;
		}
		if (xg_compare(slots + s * g, s * g, g, ~seed) >= 0)
			return -EBADMSG;
	}
	return *used == want ? 0 : -ENODATA;
}

#endif /* XDEV_EVAL_GPU_NIC_CORE_H */

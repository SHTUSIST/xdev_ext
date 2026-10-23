/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NVMe<->NIC eval (reviewer E3): geometry, wire header, payload generator and
 * control messages shared by the producer, the C peer and the host tests.
 *
 * Every arm moves the same logical units of `size` bytes.  A unit is split into
 * groups of `group` bytes (the session's batch), a group into datagrams of at
 * most `seg` payload bytes.  Each datagram carries the 40-byte NXP2 header of
 * kernel/tools/xdev_ext_mech/xdev_ext_mech_prog.h (xdev_ext_mp_tx_encode), with
 * the checksum field left zero: no arm and no receiver computes a per-datagram
 * checksum.  Payload bytes are a pure function of (seed, window offset), so
 * every arm and every trial reads or writes identical bytes.
 */
#ifndef NNB_WIRE_H
#define NNB_WIRE_H

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define NNB_HDR_LEN		40U	/* NXP2 header, the UDP payload prefix */
#define NNB_PKT_HDR_LEN		82U	/* Ethernet + IPv4 + UDP + NXP2 */
#define NNB_FRAME_SIZE		4096U	/* session UMEM chunk */
#define NNB_HDR_ROOM		360U	/* XDP headroom 256 + 22 + 82, as the ctl tool */
#define NNB_MAX_FRAMES		32U	/* XDEV_EXT_MECH_MAX_FRAMES */
#define NNB_MAGIC		0x4e585032U	/* "NXP2" */
#define NNB_VERSION		2U
#define NNB_DIR_WRITE		2U	/* every NXP2 segment is a WRITE segment */
#define NNB_MIN_SIZE		4096U
#define NNB_MAX_SIZE		(4U << 20)
#define NNB_GSO_BYTES		61440U	/* one GSO send stays below the IPv4 limit */
#define NNB_GSO_MAX_SEGS	64U

struct nnb_geom {
	uint32_t mtu, seg, size, group, dgrams, groups_per_unit;
	uint32_t gso_dgrams;		/* datagrams per GSO send call */
	uint32_t dgrams_per_unit;
	uint64_t window_bytes, window_groups, window_units;
};

static inline uint32_t nnb_seg_limit(uint32_t mtu)
{
	uint32_t mtu_data, frame_data = NNB_FRAME_SIZE - NNB_HDR_ROOM;

	/* xdev_ext_mp_seg_limit(mtu, 4096, 360): IPv4 + UDP + NXP2 off the MTU. */
	if (mtu <= 20U + 8U + NNB_HDR_LEN)
		return 0;
	mtu_data = mtu - 20U - 8U - NNB_HDR_LEN;
	return (mtu_data < frame_data ? mtu_data : frame_data) & ~7U;
}

/*
 * Group = the largest power of two that is at most @size and at most
 * NNB_MAX_FRAMES segments; at least 4096 so every group is whole LBAs of a
 * 512 B or 4 KiB namespace.  @size must be a power of two in [4 KiB, 4 MiB];
 * @window_bytes a positive multiple of NNB_MAX_SIZE so the group slots are the
 * same for every size of one campaign.
 */
static inline int nnb_geom_init(struct nnb_geom *g, uint32_t mtu, uint32_t size,
				uint64_t window_bytes)
{
	uint32_t group = NNB_MAX_SIZE, per;

	memset(g, 0, sizeof(*g));
	g->seg = nnb_seg_limit(mtu);
	if (!g->seg || size < NNB_MIN_SIZE || size > NNB_MAX_SIZE ||
	    (size & (size - 1)) || !window_bytes || window_bytes % NNB_MAX_SIZE)
		return -EINVAL;
	while (group > size || group > NNB_MAX_FRAMES * g->seg)
		group >>= 1;
	if (group < 4096U)
		return -EMSGSIZE;
	per = NNB_GSO_BYTES / (NNB_HDR_LEN + g->seg);
	g->mtu = mtu;
	g->size = size;
	g->group = group;
	g->dgrams = (group - 1) / g->seg + 1;
	g->groups_per_unit = size / group;
	g->dgrams_per_unit = g->dgrams * g->groups_per_unit;
	g->gso_dgrams = per < NNB_GSO_MAX_SEGS ? (per ? per : 1) : NNB_GSO_MAX_SEGS;
	g->window_bytes = window_bytes;
	g->window_units = window_bytes / size;
	g->window_groups = window_bytes / group;
	return 0;
}

/* Span of datagram @j of a group, as xdev_ext_mech_layout_span(). */
static inline void nnb_dgram(const struct nnb_geom *g, uint32_t j, uint32_t *rel,
			     uint32_t *len)
{
	*rel = j * g->seg;
	*len = j + 1 < g->dgrams ? g->seg : g->group - *rel;
}

/* Window byte offset of generation @gen (>= 1); a window slot repeats. */
static inline uint64_t nnb_gen_offset(const struct nnb_geom *g, uint64_t gen)
{
	return ((gen - 1) % g->window_groups) * g->group;
}

static inline void nnb_put_be16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)v;
}

static inline void nnb_put_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

static inline uint32_t nnb_get_be32(const unsigned char *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline uint16_t nnb_get_be16(const unsigned char *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

/* The NXP2 bytes xdev_ext_mp_tx_encode() writes, checksum zero. */
static inline void nnb_hdr_encode(unsigned char *h, const struct nnb_geom *g,
				  uint64_t session, uint32_t gen, uint32_t j)
{
	uint32_t rel, len;

	nnb_dgram(g, j, &rel, &len);
	memset(h, 0, NNB_HDR_LEN);
	nnb_put_be32(h, NNB_MAGIC);
	h[4] = NNB_VERSION;
	h[5] = NNB_HDR_LEN;
	h[6] = NNB_DIR_WRITE;
	nnb_put_be32(h + 8, (uint32_t)(session >> 32));
	nnb_put_be32(h + 12, (uint32_t)session);
	nnb_put_be32(h + 16, gen);
	nnb_put_be16(h + 20, (uint16_t)j);
	nnb_put_be16(h + 22, (uint16_t)g->dgrams);
	nnb_put_be32(h + 24, g->group);
	nnb_put_be32(h + 28, rel);
	nnb_put_be32(h + 32, len);
}

/* Only the generation changes between two units' headers. */
static inline void nnb_hdr_set_gen(unsigned char *h, uint32_t gen)
{
	nnb_put_be32(h + 16, gen);
}

struct nnb_seg {
	uint64_t session;
	uint32_t gen, index, rel, len;
};

/*
 * Parse one received UDP payload of @udp_len bytes against @g.  0 for a
 * well-formed segment of this geometry, -EPROTO for an NXP2 datagram that
 * violates it, -ENOMSG for foreign traffic.
 */
static inline int nnb_hdr_parse(const unsigned char *h, size_t udp_len,
				const struct nnb_geom *g, struct nnb_seg *s)
{
	uint32_t rel, len;

	if (udp_len < NNB_HDR_LEN || nnb_get_be32(h) != NNB_MAGIC)
		return -ENOMSG;
	if (h[4] != NNB_VERSION || h[5] != NNB_HDR_LEN || h[6] != NNB_DIR_WRITE || h[7] ||
	    nnb_get_be32(h + 36))
		return -EPROTO;
	s->session = (uint64_t)nnb_get_be32(h + 8) << 32 | nnb_get_be32(h + 12);
	s->gen = nnb_get_be32(h + 16);
	s->index = nnb_get_be16(h + 20);
	s->rel = nnb_get_be32(h + 28);
	s->len = nnb_get_be32(h + 32);
	if (!s->session || !s->gen || nnb_get_be16(h + 22) != g->dgrams ||
	    s->index >= g->dgrams || nnb_get_be32(h + 24) != g->group)
		return -EPROTO;
	nnb_dgram(g, s->index, &rel, &len);
	if (s->rel != rel || s->len != len || udp_len != NNB_HDR_LEN + (size_t)len)
		return -EPROTO;
	return 0;
}

/* Independent payload: splitmix64 of the 8-byte word index, little endian. */
static inline uint64_t nnb_gen_word(uint64_t seed, uint64_t k)
{
	uint64_t x = seed + (k + 1) * 0x9e3779b97f4a7c15ULL;

	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

static inline unsigned char nnb_gen_byte(uint64_t seed, uint64_t off)
{
	return (unsigned char)(nnb_gen_word(seed, off >> 3) >> (8 * (off & 7)));
}

static inline void nnb_gen_fill(uint64_t seed, uint64_t off, unsigned char *p, size_t n)
{
	size_t i = 0;

	for (; i < n && ((off + i) & 7); i++)
		p[i] = nnb_gen_byte(seed, off + i);
	for (; i + 8 <= n; i += 8) {
		uint64_t w = nnb_gen_word(seed, (off + i) >> 3);

		for (unsigned b = 0; b < 8; b++)
			p[i + b] = (unsigned char)(w >> (8 * b));
	}
	for (; i < n; i++)
		p[i] = nnb_gen_byte(seed, off + i);
}

/* Offset of the first byte differing from the generator, or -1. */
static inline int64_t nnb_gen_check(uint64_t seed, uint64_t off, const unsigned char *p,
				    size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (p[i] != nnb_gen_byte(seed, off + i))
			return (int64_t)i;
	return -1;
}

/* --- control channel: fixed 112-byte messages, both ends little endian ---- */

#define NNB_CTL_MAGIC	0x4e4e4243U	/* "NNBC" */

enum nnb_msg_type {
	NNB_HELLO = 1,	/* f: direction, seed, mtu, size, window_bytes, producer_ip, max_groups */
	NNB_HELLO_ACK,	/* f: peer data port (host order) */
	NNB_BEGIN,	/* f: trial, wire_session, first_gen, groups, integrity, dst_port,
			 *    burst_groups, rate_mbps */
	NNB_READY,
	NNB_END,	/* forward: all sends locally released */
	NNB_RECEIPT,	/* f: trial, datagrams, bytes, duplicates, foreign, malformed,
			 *    missing, compare (1 ok, 0 not run, -1 mismatch),
			 *    receive buffers (UDP GRO: fewer than datagrams) */
	NNB_GO,		/* reverse: f: trial, burst, first_gen, groups */
	NNB_SENT,	/* reverse: f: trial, burst, datagrams, bytes, send errors */
	NNB_BYE,
	NNB_ERROR,	/* f[0]: errno-style code */
};

struct nnb_msg {
	uint32_t magic, type;
	uint64_t run_id;
	uint64_t f[12];
};

static inline int nnb_io_full(int fd, void *buf, size_t n, int writing, int timeout_ms)
{
	unsigned char *p = buf;

	while (n) {
		struct pollfd pfd = { .fd = fd, .events = writing ? POLLOUT : POLLIN };
		ssize_t r;
		int ready = poll(&pfd, 1, timeout_ms);

		if (ready < 0 && errno == EINTR)
			continue;
		if (ready <= 0)
			return ready ? -errno : -ETIMEDOUT;
		r = writing ? write(fd, p, n) : read(fd, p, n);
		if (r < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (r <= 0)
			return r ? -errno : -ECONNRESET;
		p += r;
		n -= (size_t)r;
	}
	return 0;
}

static inline int nnb_msg_send(int fd, uint64_t run_id, uint32_t type, const uint64_t *f,
			       unsigned nf)
{
	struct nnb_msg m = { .magic = NNB_CTL_MAGIC, .type = type, .run_id = run_id };

	for (unsigned i = 0; i < nf && i < 12; i++)
		m.f[i] = f[i];
	return nnb_io_full(fd, &m, sizeof(m), 1, 20000);
}

/* Receive one message of @type for @run_id; an ERROR or other type fails. */
static inline int nnb_msg_expect(int fd, uint64_t run_id, uint32_t type, struct nnb_msg *m,
				 int timeout_ms)
{
	int ret = nnb_io_full(fd, m, sizeof(*m), 0, timeout_ms);

	if (ret)
		return ret;
	if (m->magic != NNB_CTL_MAGIC || m->run_id != run_id)
		return -EPROTO;
	if (m->type == NNB_ERROR)
		return m->f[0] && m->f[0] < 4096 ? -(int)m->f[0] : -EIO;
	return m->type == type ? 0 : -EPROTO;
}

#endif

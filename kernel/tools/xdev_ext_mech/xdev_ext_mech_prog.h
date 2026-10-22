/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_PROG_H
#define XDEV_EXT_MECH_PROG_H

/*
 * Pure decisions of the mechanism programs in tools/xdev_ext_mech: NXP packet
 * parsing and group order on AF_XDP RX, NXP header encoding on AF_XDP TX,
 * the NVMe read/write SQE, and the copy-engine plan.  The BPF objects and
 * tools/testing/selftests/xdev_ext_mech_tools/xdev_ext_mech_prog_test.c compile the
 * same code; the test runs it against the user-space NXP pipeline
 * (nvme_xdp_pipeline_core.h) it mirrors.
 *
 * The includer supplies the integer types and struct xdev_ext_mech_peer,
 * struct xdp_desc and struct xdev_ext_ce_copy_desc: vmlinux.h in a BPF object,
 * the UAPI headers in user space.  UAPI enum values and macros never reach
 * vmlinux.h, so the programs use the XDEV_EXT_MP_* copies below, which the test
 * pins to the UAPI.  Everything here is bounded, branch-only code over byte
 * views, with no library call, so the verifier sees each access directly.
 */

#ifndef XDEV_EXT_MP_INLINE
#define XDEV_EXT_MP_INLINE static inline __attribute__((always_inline))
#endif

#ifndef EINVAL
#define EAGAIN		11
#define EINVAL		22
#define ERANGE		34
#define EOVERFLOW	75
#define EMSGSIZE	90
#define EXDEV		18
#define ECANCELED	125
#endif

#define XDEV_EXT_MP_ABI_VERSION		1U
#define XDEV_EXT_MP_CE_ABI_VERSION		2U
#define XDEV_EXT_MP_MAX_FRAMES		32U

/* enum xdev_ext_mech_build_ret, enum xdev_ext_mech_next */
#define XDEV_EXT_MP_BUILD_SUBMIT		1
#define XDEV_EXT_MP_BUILD_ABORT		2
#define XDEV_EXT_MP_NEXT			0
#define XDEV_EXT_MP_DONE			1
#define XDEV_EXT_MP_RETRY			2
#define XDEV_EXT_MP_ABORT			3
#define XDEV_EXT_MP_HOLD			4
#define XDEV_EXT_MP_PUBLISH			5
#define XDEV_EXT_MP_RECYCLE			6

/* enum xdev_ext_mech_callsite, enum xdev_ext_mech_dir */
#define XDEV_EXT_MP_SITE_WORKER		0U
#define XDEV_EXT_MP_SITE_RX_GENERIC		1U
#define XDEV_EXT_MP_SITE_RX_NATIVE		2U
#define XDEV_EXT_MP_SITE_URING_CMD		3U
#define XDEV_EXT_MP_SITE_RX_HOLD_RESULT	5U
#define XDEV_EXT_MP_DIR_TO_DEVICE		1U
#define XDEV_EXT_MP_DIR_FROM_DEVICE		2U

/* enum xdev_ext_ce_outcome, XDEV_EXT_CE_F_* */
#define XDEV_EXT_MP_CE_OK			0U
#define XDEV_EXT_MP_CE_PRE_SUBMIT_FAILED	1U
#define XDEV_EXT_MP_CE_F_COMPLETION_POINT	1U

/* NVMe read/write SQE (include/linux/nvme_xdev_ext_passthru.h) */
#define XDEV_EXT_MP_NVME_DESC_SIZE		64U
#define XDEV_EXT_MP_NVME_OP_WRITE		0x01U
#define XDEV_EXT_MP_NVME_OP_READ		0x02U
#define XDEV_EXT_MP_NVME_MAX_NLB		65536U

/*
 * SLBA choice of an NVMe build: WINDOW puts batch index k at k groups into
 * the window; OUTSIDE puts it past the window's end, which C must refuse.
 */
#define XDEV_EXT_MP_NVME_MODE_WINDOW		0U
#define XDEV_EXT_MP_NVME_MODE_OUTSIDE	1U

/*
 * NXP packet as nvme_xdp_pipeline.c builds it: Ethernet, option-less IPv4,
 * UDP, then the 40-byte NXP header (nvme_xdp_pipeline_core.h).
 */
#define XDEV_EXT_MP_ETH_LEN			14U
#define XDEV_EXT_MP_IP_LEN			20U
#define XDEV_EXT_MP_UDP_LEN			8U
#define XDEV_EXT_MP_NXP_LEN			40U
#define XDEV_EXT_MP_NXP_OFF			(XDEV_EXT_MP_ETH_LEN + XDEV_EXT_MP_IP_LEN + \
					 XDEV_EXT_MP_UDP_LEN)
#define XDEV_EXT_MP_PKT_HDR_LEN		(XDEV_EXT_MP_NXP_OFF + XDEV_EXT_MP_NXP_LEN)
#define XDEV_EXT_MP_ETH_P_IP			0x0800U
#define XDEV_EXT_MP_IPPROTO_UDP		17U
#define XDEV_EXT_MP_IP_TTL			64U
#define XDEV_EXT_MP_NXP_MAGIC		0x4e585032U	/* "NXP2" */
#define XDEV_EXT_MP_NXP_VERSION		2U
#define XDEV_EXT_MP_NXP_DIR_READ		1U
#define XDEV_EXT_MP_NXP_DIR_WRITE		2U
#define XDEV_EXT_MP_NXP_CSUM_OFF		36U
#define XDEV_EXT_MP_NXP_MAX_SEGMENTS		256U
#define XDEV_EXT_MP_NXP_ALIGN		8U	/* payload alignment of the layout */
#define XDEV_EXT_MP_CRC32C_SEED		0xffffffffU
/* NXP_RX_GROUP_TIMEOUT_NS of nvme_xdp_pipeline.c */
#define XDEV_EXT_MP_GROUP_TIMEOUT_NS		1000000000ULL

XDEV_EXT_MP_INLINE __u16 xdev_ext_mp_get_be16(const __u8 *p)
{
	return (__u16)((__u16)p[0] << 8 | p[1]);
}

XDEV_EXT_MP_INLINE __u32 xdev_ext_mp_get_be32(const __u8 *p)
{
	return (__u32)p[0] << 24 | (__u32)p[1] << 16 | (__u32)p[2] << 8 | p[3];
}

XDEV_EXT_MP_INLINE __u64 xdev_ext_mp_get_be64(const __u8 *p)
{
	return (__u64)xdev_ext_mp_get_be32(p) << 32 | xdev_ext_mp_get_be32(p + 4);
}

XDEV_EXT_MP_INLINE void xdev_ext_mp_put_be16(__u8 *p, __u16 v)
{
	p[0] = (__u8)(v >> 8);
	p[1] = (__u8)v;
}

XDEV_EXT_MP_INLINE void xdev_ext_mp_put_be32(__u8 *p, __u32 v)
{
	p[0] = (__u8)(v >> 24);
	p[1] = (__u8)(v >> 16);
	p[2] = (__u8)(v >> 8);
	p[3] = (__u8)v;
}

XDEV_EXT_MP_INLINE void xdev_ext_mp_put_be64(__u8 *p, __u64 v)
{
	xdev_ext_mp_put_be32(p, (__u32)(v >> 32));
	xdev_ext_mp_put_be32(p + 4, (__u32)v);
}

XDEV_EXT_MP_INLINE void xdev_ext_mp_put_le16(__u8 *p, __u16 v)
{
	p[0] = (__u8)v;
	p[1] = (__u8)(v >> 8);
}

XDEV_EXT_MP_INLINE void xdev_ext_mp_put_le64(__u8 *p, __u64 v)
{
	__u32 i;

	for (i = 0; i < 8; i++)
		p[i] = (__u8)(v >> (8 * i));
}

XDEV_EXT_MP_INLINE bool xdev_ext_mp_bytes_eq(const __u8 *a, const __u8 *b, __u32 n)
{
	__u8 diff = 0;
	__u32 i;

	for (i = 0; i < n; i++)
		diff |= a[i] ^ b[i];
	return !diff;
}

/* Folded one's-complement sum of a 20-byte IPv4 header; 0 when valid. */
XDEV_EXT_MP_INLINE __u16 xdev_ext_mp_ip_csum(const __u8 *ip)
{
	__u32 sum = 0, i;

	for (i = 0; i < XDEV_EXT_MP_IP_LEN; i += 2)
		sum += xdev_ext_mp_get_be16(ip + i);
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return (__u16)~sum;
}

/*
 * Payload bytes per NXP segment for an L3 MTU and a frame whose payload
 * starts at hdr_room: segment_data_limit of nxp_wire_mtu_layout_plan(),
 * with its error order.
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_seg_limit(__u32 mtu, __u32 frame_size,
				   __u32 hdr_room, __u32 *limit)
{
	__u32 mtu_data, frame_data, seg;

	if (hdr_room >= frame_size)
		return -EINVAL;
	if (mtu <= XDEV_EXT_MP_IP_LEN + XDEV_EXT_MP_UDP_LEN + XDEV_EXT_MP_NXP_LEN)
		return -EMSGSIZE;
	mtu_data = mtu - XDEV_EXT_MP_IP_LEN - XDEV_EXT_MP_UDP_LEN - XDEV_EXT_MP_NXP_LEN;
	frame_data = frame_size - hdr_room;
	seg = mtu_data < frame_data ? mtu_data : frame_data;
	seg &= ~(XDEV_EXT_MP_NXP_ALIGN - 1);
	if (!seg)
		return -EMSGSIZE;
	*limit = seg;
	return 0;
}

/* What the receiving session expects: all of it fixed at CREATE. */
struct xdev_ext_mp_rx_cfg {
	__u64 session_id;	/* the NXP session the sender stamps */
	__u32 mtu;		/* L3 MTU of the receiving device */
	__u32 frame_size;
	__u32 hdr_room;		/* payload offset in the chunk */
	__u32 seg_len;		/* payload bytes per frame of the layout */
	__u32 group_bytes;	/* NXP total_len of one group */
};

/* One NXP segment that passed every per-packet check. */
struct xdev_ext_mp_segment {
	__u64 session_id;
	__u32 generation;
	__u32 total_len;
	__u32 relative_offset;
	__u32 payload_len;
	__u32 payload_off;	/* chunk offset of the payload */
	__u16 index;
	__u16 count;
};

enum xdev_ext_mp_rx_class {
	XDEV_EXT_MP_RX_SEGMENT = 0,	/* an NXP segment of this session */
	XDEV_EXT_MP_RX_FOREIGN,	/* not NXP traffic: hand it to user space */
	XDEV_EXT_MP_RX_BAD,		/* NXP traffic failing a check: recycle it */
};

/*
 * Classify a received frame from its first XDEV_EXT_MP_PKT_HDR_LEN bytes @pkt,
 * found at chunk offset @data_off with packet length @data_len.  Frames
 * that are not an option-less, unfragmented IPv4/UDP datagram carrying the
 * NXP magic are FOREIGN.  Every other check of the user-space receiver
 * (pipeline_decode_rx_descriptor(), parse_wire_packet() without the CRC,
 * nxp_wire_header_parse(), nxp_wire_segment_validate() and
 * pipeline_validate_rx_packet() of nvme_xdp_pipeline.c) makes it BAD, and
 * so does a session layout whose seg_len is not the NXP segment size: C
 * groups by that layout.  The CRC needs the payload, so the caller checks
 * it after a SEGMENT.
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_rx_parse(const __u8 *pkt, __u32 data_off,
				  __u32 data_len,
				  const struct xdev_ext_mech_peer *peer,
				  const struct xdev_ext_mp_rx_cfg *cfg,
				  struct xdev_ext_mp_segment *seg)
{
	const __u8 *ip = pkt + XDEV_EXT_MP_ETH_LEN;
	const __u8 *udp = ip + XDEV_EXT_MP_IP_LEN;
	const __u8 *nxp = udp + XDEV_EXT_MP_UDP_LEN;
	__u32 ip_len, udp_len, payload_len, limit, count, offset, end;
	__u32 direction;
	__u16 index, nr;

	if (data_len < XDEV_EXT_MP_PKT_HDR_LEN ||
	    xdev_ext_mp_get_be16(pkt + 12) != XDEV_EXT_MP_ETH_P_IP ||
	    ip[0] != 0x45 || ip[9] != XDEV_EXT_MP_IPPROTO_UDP ||
	    (xdev_ext_mp_get_be16(ip + 6) & 0x3fff) ||
	    xdev_ext_mp_get_be32(nxp) != XDEV_EXT_MP_NXP_MAGIC)
		return XDEV_EXT_MP_RX_FOREIGN;

	/* The receiving UMEM's headroom puts the payload at hdr_room. */
	if (data_off > cfg->frame_size ||
	    data_off + XDEV_EXT_MP_PKT_HDR_LEN != cfg->hdr_room ||
	    cfg->hdr_room % XDEV_EXT_MP_NXP_ALIGN ||
	    data_len > cfg->frame_size - data_off)
		return XDEV_EXT_MP_RX_BAD;

	if (!xdev_ext_mp_bytes_eq(pkt, peer->local_mac, 6) ||
	    !xdev_ext_mp_bytes_eq(pkt + 6, peer->peer_mac, 6) ||
	    !xdev_ext_mp_bytes_eq(ip + 12, (const __u8 *)&peer->peer_ip, 4) ||
	    !xdev_ext_mp_bytes_eq(ip + 16, (const __u8 *)&peer->local_ip, 4))
		return XDEV_EXT_MP_RX_BAD;
	ip_len = xdev_ext_mp_get_be16(ip + 2);
	if (ip_len != data_len - XDEV_EXT_MP_ETH_LEN ||
	    (cfg->mtu && ip_len > cfg->mtu) ||
	    ip_len < XDEV_EXT_MP_IP_LEN + XDEV_EXT_MP_UDP_LEN + XDEV_EXT_MP_NXP_LEN ||
	    xdev_ext_mp_ip_csum(ip))
		return XDEV_EXT_MP_RX_BAD;
	if (!xdev_ext_mp_bytes_eq(udp, (const __u8 *)&peer->peer_port, 2) ||
	    !xdev_ext_mp_bytes_eq(udp + 2, (const __u8 *)&peer->local_port, 2))
		return XDEV_EXT_MP_RX_BAD;
	udp_len = xdev_ext_mp_get_be16(udp + 4);
	if (udp_len != ip_len - XDEV_EXT_MP_IP_LEN ||
	    udp_len < XDEV_EXT_MP_UDP_LEN + XDEV_EXT_MP_NXP_LEN)
		return XDEV_EXT_MP_RX_BAD;

	/* nxp_wire_header_parse() */
	if (nxp[4] != XDEV_EXT_MP_NXP_VERSION || nxp[5] != XDEV_EXT_MP_NXP_LEN || nxp[7])
		return XDEV_EXT_MP_RX_BAD;
	payload_len = udp_len - XDEV_EXT_MP_UDP_LEN - XDEV_EXT_MP_NXP_LEN;
	if (!payload_len || payload_len != xdev_ext_mp_get_be32(nxp + 32))
		return XDEV_EXT_MP_RX_BAD;
	direction = nxp[6];
	seg->session_id = xdev_ext_mp_get_be64(nxp + 8);
	seg->generation = xdev_ext_mp_get_be32(nxp + 16);
	seg->index = index = xdev_ext_mp_get_be16(nxp + 20);
	seg->count = nr = xdev_ext_mp_get_be16(nxp + 22);
	seg->total_len = xdev_ext_mp_get_be32(nxp + 24);
	seg->relative_offset = xdev_ext_mp_get_be32(nxp + 28);
	seg->payload_len = payload_len;
	seg->payload_off = data_off + XDEV_EXT_MP_PKT_HDR_LEN;

	/* nxp_wire_segment_validate(); offsets are in u64 there. */
	if (!seg->session_id || !seg->generation ||
	    (direction != XDEV_EXT_MP_NXP_DIR_READ &&
	     direction != XDEV_EXT_MP_NXP_DIR_WRITE) ||
	    !nr || nr > XDEV_EXT_MP_NXP_MAX_SEGMENTS || index >= nr ||
	    !seg->total_len ||
	    seg->relative_offset > seg->total_len ||
	    payload_len > seg->total_len - seg->relative_offset)
		return XDEV_EXT_MP_RX_BAD;
	end = seg->relative_offset + payload_len;
	if ((!index && seg->relative_offset) ||
	    (index == nr - 1 ? end != seg->total_len : end >= seg->total_len))
		return XDEV_EXT_MP_RX_BAD;

	/* pipeline_validate_rx_packet(): this session's layout, segment @index */
	if (direction != XDEV_EXT_MP_NXP_DIR_WRITE ||
	    seg->total_len != cfg->group_bytes ||
	    seg->session_id != cfg->session_id ||
	    xdev_ext_mp_seg_limit(cfg->mtu, cfg->frame_size, cfg->hdr_room, &limit) ||
	    limit != cfg->seg_len)
		return XDEV_EXT_MP_RX_BAD;
	count = 1 + (cfg->group_bytes - 1) / limit;
	if (count > XDEV_EXT_MP_NXP_MAX_SEGMENTS || nr != count)
		return XDEV_EXT_MP_RX_BAD;
	offset = index * limit;
	if (seg->relative_offset != offset ||
	    payload_len != (cfg->group_bytes - offset < limit ?
			    cfg->group_bytes - offset : limit))
		return XDEV_EXT_MP_RX_BAD;
	return XDEV_EXT_MP_RX_SEGMENT;
}

/*
 * NXP CRC with the two CRC kfuncs (nxp_wire_checksum()): CRC32C seeded with
 * XDEV_EXT_MP_CRC32C_SEED over a stack copy of the header whose checksum field
 * is zero, continued over the payload, inverted at the end.
 */
XDEV_EXT_MP_INLINE void xdev_ext_mp_nxp_crc_prep(__u8 *buf, const __u8 *nxp)
{
	__u32 i;

	for (i = 0; i < XDEV_EXT_MP_NXP_CSUM_OFF; i++)
		buf[i] = nxp[i];
	for (; i < XDEV_EXT_MP_NXP_LEN; i++)
		buf[i] = 0;
}

/* @crc: the running CRC after header and payload, before inversion. */
XDEV_EXT_MP_INLINE bool xdev_ext_mp_nxp_crc_ok(const __u8 *nxp, __u32 crc)
{
	return xdev_ext_mp_get_be32(nxp + XDEV_EXT_MP_NXP_CSUM_OFF) == (__u32)~crc;
}

XDEV_EXT_MP_INLINE void xdev_ext_mp_nxp_crc_store(__u8 *nxp, __u32 crc)
{
	xdev_ext_mp_put_be32(nxp + XDEV_EXT_MP_NXP_CSUM_OFF, ~crc);
}

/*
 * Group order of the user-space receiver: one collecting group; the first
 * segment without one begins the next generation (nxp_wire_group_begin()),
 * segments are accepted strictly in order (nxp_wire_group_accept()), a
 * complete group commits its generation, and a group collecting for
 * XDEV_EXT_MP_GROUP_TIMEOUT_NS is dropped (pipeline_rx_expire_group()).  The
 * order belongs to one mechanism session: a program that outlives a session
 * starts over for the next one, as a new user-space receiver would.
 */
struct xdev_ext_mp_rx_order {
	__u64 session_id;	/* mechanism session the order belongs to */
	__u64 started_ns;
	__u32 last_generation;	/* last complete group */
	__u32 generation;
	__u32 total_len;
	__u32 received_len;
	__u16 count;
	__u16 next;
	__u32 active;
};

/* One AF_XDP stage owns both the committed order and its admission candidate. */
struct xdev_ext_mp_rx_state {
	struct xdev_ext_mp_rx_order order;
	struct xdev_ext_mp_rx_order candidate;
	__u64 candidate_key;
	__u32 candidate_pos;
	__u32 candidate_valid;
};

/* Bind the order to mechanism session @session_id, resetting it on a change. */
XDEV_EXT_MP_INLINE void xdev_ext_mp_rx_order_session(struct xdev_ext_mp_rx_order *o,
					   __u64 session_id)
{
	if (o->session_id == session_id)
		return;
	o->session_id = session_id;
	o->started_ns = 0;
	o->last_generation = 0;
	o->generation = 0;
	o->total_len = 0;
	o->received_len = 0;
	o->count = 0;
	o->next = 0;
	o->active = 0;
}

/* XDEV_EXT_MP_HOLD when @s is the next segment of the group, else XDEV_EXT_MP_RECYCLE. */
XDEV_EXT_MP_INLINE int xdev_ext_mp_rx_order(struct xdev_ext_mp_rx_order *o,
				  const struct xdev_ext_mp_segment *s, __u64 now_ns)
{
	if (o->active && now_ns >= o->started_ns &&
	    now_ns - o->started_ns >= XDEV_EXT_MP_GROUP_TIMEOUT_NS)
		o->active = 0;
	if (!o->active) {
		if (o->last_generation == 0xffffffffU ||
		    s->generation != o->last_generation + 1)
			return XDEV_EXT_MP_RECYCLE;
		o->active = 1;
		o->generation = s->generation;
		o->total_len = s->total_len;
		o->received_len = 0;
		o->count = s->count;
		o->next = 0;
		o->started_ns = now_ns;
	}
	if (s->generation != o->generation || s->total_len != o->total_len ||
	    s->count != o->count || s->index != o->next ||
	    s->relative_offset != o->received_len ||
	    s->payload_len > o->total_len - o->received_len)
		return XDEV_EXT_MP_RECYCLE;
	o->received_len += s->payload_len;
	o->next++;
	if (o->next == o->count) {
		if (o->received_len != o->total_len)
			return XDEV_EXT_MP_RECYCLE;
		o->active = 0;
		o->last_generation = o->generation;
	}
	return XDEV_EXT_MP_HOLD;
}

/* One NXP segment to send. */
struct xdev_ext_mp_tx_seg {
	__u64 session_id;
	__u32 generation;
	__u32 total_len;
	__u32 relative_offset;
	__u32 payload_len;
	__u16 index;
	__u16 count;
};

/*
 * Write the XDEV_EXT_MP_PKT_HDR_LEN header bytes of one NXP WRITE segment from
 * the local end of @peer to its peer end, as build_packet() and
 * nxp_wire_header_encode() do.  The IPv4 checksum stays zero for C to fill,
 * the UDP checksum zero as the user-space sender leaves it, and the NXP
 * checksum zero for xdev_ext_mp_nxp_crc_store().  Errors are those of
 * nxp_wire_segment_validate(), then -EMSGSIZE past an IPv4 length.
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_tx_encode(__u8 *pkt, const struct xdev_ext_mech_peer *peer,
				   const struct xdev_ext_mp_tx_seg *s)
{
	__u8 *ip = pkt + XDEV_EXT_MP_ETH_LEN;
	__u8 *udp = ip + XDEV_EXT_MP_IP_LEN;
	__u8 *nxp = udp + XDEV_EXT_MP_UDP_LEN;
	__u32 i, end;

	if (!s->session_id || !s->generation || !s->count ||
	    s->count > XDEV_EXT_MP_NXP_MAX_SEGMENTS || s->index >= s->count ||
	    !s->total_len || !s->payload_len)
		return -EINVAL;
	if (s->relative_offset > s->total_len ||
	    s->payload_len > s->total_len - s->relative_offset)
		return -ERANGE;
	end = s->relative_offset + s->payload_len;
	if ((!s->index && s->relative_offset) ||
	    (s->index == s->count - 1 ? end != s->total_len :
					end >= s->total_len))
		return -ERANGE;
	if (s->payload_len > 0xffffU - XDEV_EXT_MP_IP_LEN - XDEV_EXT_MP_UDP_LEN -
			     XDEV_EXT_MP_NXP_LEN)
		return -EMSGSIZE;

	for (i = 0; i < 6; i++) {
		pkt[i] = peer->peer_mac[i];
		pkt[6 + i] = peer->local_mac[i];
	}
	xdev_ext_mp_put_be16(pkt + 12, XDEV_EXT_MP_ETH_P_IP);

	ip[0] = 0x45;
	ip[1] = 0;
	xdev_ext_mp_put_be16(ip + 2, (__u16)(XDEV_EXT_MP_IP_LEN + XDEV_EXT_MP_UDP_LEN +
					XDEV_EXT_MP_NXP_LEN + s->payload_len));
	xdev_ext_mp_put_be16(ip + 4, 0);
	xdev_ext_mp_put_be16(ip + 6, 0);
	ip[8] = XDEV_EXT_MP_IP_TTL;
	ip[9] = XDEV_EXT_MP_IPPROTO_UDP;
	xdev_ext_mp_put_be16(ip + 10, 0);
	for (i = 0; i < 4; i++) {
		ip[12 + i] = ((const __u8 *)&peer->local_ip)[i];
		ip[16 + i] = ((const __u8 *)&peer->peer_ip)[i];
	}

	for (i = 0; i < 2; i++) {
		udp[i] = ((const __u8 *)&peer->local_port)[i];
		udp[2 + i] = ((const __u8 *)&peer->peer_port)[i];
	}
	xdev_ext_mp_put_be16(udp + 4, (__u16)(XDEV_EXT_MP_UDP_LEN + XDEV_EXT_MP_NXP_LEN +
					 s->payload_len));
	xdev_ext_mp_put_be16(udp + 6, 0);

	xdev_ext_mp_put_be32(nxp, XDEV_EXT_MP_NXP_MAGIC);
	nxp[4] = XDEV_EXT_MP_NXP_VERSION;
	nxp[5] = XDEV_EXT_MP_NXP_LEN;
	nxp[6] = XDEV_EXT_MP_NXP_DIR_WRITE;
	nxp[7] = 0;
	xdev_ext_mp_put_be64(nxp + 8, s->session_id);
	xdev_ext_mp_put_be32(nxp + 16, s->generation);
	xdev_ext_mp_put_be16(nxp + 20, s->index);
	xdev_ext_mp_put_be16(nxp + 22, s->count);
	xdev_ext_mp_put_be32(nxp + 24, s->total_len);
	xdev_ext_mp_put_be32(nxp + 28, s->relative_offset);
	xdev_ext_mp_put_be32(nxp + 32, s->payload_len);
	xdev_ext_mp_put_be32(nxp + XDEV_EXT_MP_NXP_CSUM_OFF, 0);
	return 0;
}

/*
 * TX descriptor of a frame whose payload is [data_off, data_off + data_len)
 * of the chunk at UMEM offset @chunk: the packet starts the header bytes
 * before the payload and ends where the payload ends.
 */
XDEV_EXT_MP_INLINE void xdev_ext_mp_tx_desc(struct xdp_desc *d, __u64 chunk,
				  __u32 data_off, __u32 data_len)
{
	d->addr = chunk + data_off - XDEV_EXT_MP_PKT_HDR_LEN;
	d->len = XDEV_EXT_MP_PKT_HDR_LEN + data_len;
	d->options = 0;
}

/*
 * Fold one frame's xsk_kernel_xmit() result into the stage verdict,
 * starting from XDEV_EXT_MP_NEXT: any failure but -EAGAIN aborts, -EAGAIN asks
 * for a retry, a sent frame changes nothing.  C stops a batch at its first
 * failed send and reports -ECANCELED for every later frame (not attempted):
 * after a -EAGAIN those change nothing either.
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_tx_fold(int verdict, int err)
{
	if (err >= 0 || verdict == XDEV_EXT_MP_ABORT)
		return verdict;
	if (err == -ECANCELED && verdict == XDEV_EXT_MP_RETRY)
		return verdict;
	return err == -EAGAIN ? XDEV_EXT_MP_RETRY : XDEV_EXT_MP_ABORT;
}

/*
 * SLBA of batch @index (key minus the session's first key): @mode
 * XDEV_EXT_MP_NVME_MODE_WINDOW or XDEV_EXT_MP_NVME_MODE_OUTSIDE, groups of
 * @group_bytes whole LBAs.
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_nvme_slba(__u64 window_slba, __u64 window_nlb,
				   __u32 lba_shift, __u32 group_bytes,
				   __u64 index, __u32 mode, __u64 *slba)
{
	__u64 blocks, off, base = window_slba;

	if (lba_shift < 9 || lba_shift > 31 || !group_bytes ||
	    group_bytes & ((1U << lba_shift) - 1))
		return -EINVAL;
	if (mode == XDEV_EXT_MP_NVME_MODE_OUTSIDE) {
		if (window_nlb > ~0ULL - base)
			return -EOVERFLOW;
		base += window_nlb;
	} else if (mode != XDEV_EXT_MP_NVME_MODE_WINDOW) {
		return -EINVAL;
	}
	/*
	 * blocks < 2^23, so an index below 2^40 cannot overflow the product;
	 * no window holds 2^40 groups.  (A division-based check compiles to a
	 * 128-bit multiply the BPF backend cannot emit.)
	 */
	blocks = group_bytes >> lba_shift;
	if (index >> 40)
		return -EOVERFLOW;
	off = index * blocks;
	if (off > ~0ULL - base)
		return -EOVERFLOW;
	*slba = base + off;
	return 0;
}

/*
 * S0 at the uring_cmd callsite: slot @request_id mod the window's slots of
 * @bytes, placed as xdev_ext_mp_nvme_slba() places a batch index.
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_nvme_s0_slba(__u64 window_slba, __u64 window_nlb,
				      __u32 lba_shift, __u32 bytes,
				      __u64 request_id, __u32 mode,
				      __u64 *slba)
{
	__u64 blocks, slots;

	if (lba_shift < 9 || lba_shift > 31 || !bytes ||
	    bytes & ((1U << lba_shift) - 1))
		return -EINVAL;
	blocks = bytes >> lba_shift;
	slots = window_nlb / blocks;
	if (!slots)
		return -ERANGE;
	return xdev_ext_mp_nvme_slba(window_slba, window_nlb, lba_shift, bytes,
				request_id % slots, mode, slba);
}

/*
 * A READ (stage direction FROM_DEVICE) or WRITE (TO_DEVICE) of @bytes at
 * @slba in a zeroed 64-byte SQE: opcode, cdw10/cdw11 and cdw12[15:0] only,
 * little endian.  C owns every other field.
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_nvme_rw(__u8 *sqe, __u32 direction, __u64 slba,
				 __u32 bytes, __u32 lba_shift)
{
	__u32 nlb;

	if (lba_shift < 9 || lba_shift > 31 || !bytes ||
	    bytes & ((1U << lba_shift) - 1))
		return -EINVAL;
	nlb = bytes >> lba_shift;
	if (nlb > XDEV_EXT_MP_NVME_MAX_NLB)
		return -EMSGSIZE;
	if (direction == XDEV_EXT_MP_DIR_TO_DEVICE)
		sqe[0] = XDEV_EXT_MP_NVME_OP_WRITE;
	else if (direction == XDEV_EXT_MP_DIR_FROM_DEVICE)
		sqe[0] = XDEV_EXT_MP_NVME_OP_READ;
	else
		return -EINVAL;
	xdev_ext_mp_put_le64(sqe + 40, slba);
	xdev_ext_mp_put_le16(sqe + 48, (__u16)(nlb - 1));
	return 0;
}

/* A nonzero reserved dword (cdw2), which C must refuse. */
XDEV_EXT_MP_INLINE void xdev_ext_mp_nvme_set_reserved(__u8 *sqe)
{
	sqe[8] = 1;
}

/* NVMe complete: success goes on (DONE at the uring_cmd callsite). */
XDEV_EXT_MP_INLINE int xdev_ext_mp_nvme_next(__u32 callsite, __u32 status, int err)
{
	if (status || err)
		return XDEV_EXT_MP_ABORT;
	return callsite == XDEV_EXT_MP_SITE_URING_CMD ? XDEV_EXT_MP_DONE : XDEV_EXT_MP_NEXT;
}

/*
 * Device offset of batch @index: the window holds window_len / group_bytes
 * group slots, each owned by one campaign group.
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_ce_base(__u64 index, __u32 group_bytes,
				 __u64 window_len, __u64 *base)
{
	__u64 slots;

	if (!group_bytes)
		return -ERANGE;
	slots = window_len / group_bytes;
	if (!slots)
		return -ERANGE;
	if (index >= slots)
		return -ERANGE;
	*base = index * group_bytes;
	return 0;
}

/*
 * Copy-plan entry for frame @pos of @nr: its data span to @gpu_off, the
 * completion point on the last.  The device side must stay in the window
 * and in one @seg_size segment (0: one segment) and be at most the largest
 * entry (max_entry_len, else seg_size, else any).
 */
XDEV_EXT_MP_INLINE int xdev_ext_mp_ce_entry(struct xdev_ext_ce_copy_desc *d, __u32 pos,
				  __u32 nr, __u32 frame_off, __u32 len,
				  __u64 gpu_off, __u64 window_len,
				  __u32 seg_size, __u32 max_entry_len)
{
	__u32 max = max_entry_len ? max_entry_len :
		    seg_size ? seg_size : 0xffffffffU;
	__u64 last;

	if (!len)
		return -EINVAL;
	if (len > max)
		return -EMSGSIZE;
	if (gpu_off > window_len || len > window_len - gpu_off)
		return -ERANGE;
	last = gpu_off + len - 1;
	if (seg_size && gpu_off / seg_size != last / seg_size)
		return -EXDEV;
	d->frame_pos = pos;
	d->frame_off = frame_off;
	d->gpu_off = gpu_off;
	d->len = len;
	d->flags = pos + 1 == nr ? XDEV_EXT_MP_CE_F_COMPLETION_POINT : 0;
	return 0;
}

/* CE complete: C classified the outcome; only a pre-submit failure retries. */
XDEV_EXT_MP_INLINE int xdev_ext_mp_ce_next(__u32 outcome)
{
	if (outcome == XDEV_EXT_MP_CE_OK)
		return XDEV_EXT_MP_NEXT;
	return outcome == XDEV_EXT_MP_CE_PRE_SUBMIT_FAILED ? XDEV_EXT_MP_RETRY :
							XDEV_EXT_MP_ABORT;
}

#endif /* XDEV_EXT_MECH_PROG_H */

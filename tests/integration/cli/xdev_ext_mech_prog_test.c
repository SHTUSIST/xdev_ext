// SPDX-License-Identifier: GPL-2.0
/*
 * User-space checks of tools/xdev_ext_mech/xdev_ext_mech_prog.h, the pure part of the
 * mechanism programs in tools/xdev_ext_mech.  The BPF objects are built only in
 * the KVM harness; here the same helpers run against what they mirror: the
 * user-space NXP pipeline (nvme_xdp_pipeline_core.h and the packet code of
 * nvme_xdp_pipeline.c), the NVMe scratch-SQE validator and the pure
 * mechanism rules.  Build with -I <kernel tree>.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/if_xdp.h"

#include "include/uapi/linux/xdev_ext_mech.h"
#include "include/linux/nvme_xdev_ext_passthru.h"
#include "io_uring/xdev_ext_mech_core.h"
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "net/xdp/xsk_xdev_ext_mech_tx_core.h"
#include "nvme_xdp_pipeline_core.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                              \
	long long _expected = (long long)(expected);                          \
	checks++;                                                              \
	if (_actual != _expected) {                                            \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",         \
			__FILE__, __LINE__, #actual, _actual, _expected);      \
		failures++;                                                     \
	}                                                                       \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

/* The programs see only these copies of the UAPI values. */
_Static_assert(XDEV_EXT_MP_ABI_VERSION == XDEV_EXT_MECH_ABI_VERSION, "ABI");
_Static_assert(XDEV_EXT_MP_MAX_FRAMES == XDEV_EXT_MECH_MAX_FRAMES, "frames");
_Static_assert(XDEV_EXT_MP_BUILD_SUBMIT == XDEV_EXT_MECH_BUILD_SUBMIT &&
	       XDEV_EXT_MP_BUILD_ABORT == XDEV_EXT_MECH_BUILD_ABORT, "build returns");
_Static_assert(XDEV_EXT_MP_NEXT == XDEV_EXT_MECH_NEXT && XDEV_EXT_MP_DONE == XDEV_EXT_MECH_DONE &&
	       XDEV_EXT_MP_RETRY == XDEV_EXT_MECH_RETRY &&
	       XDEV_EXT_MP_ABORT == XDEV_EXT_MECH_ABORT && XDEV_EXT_MP_HOLD == XDEV_EXT_MECH_HOLD &&
	       XDEV_EXT_MP_PUBLISH == XDEV_EXT_MECH_PUBLISH &&
	       XDEV_EXT_MP_RECYCLE == XDEV_EXT_MECH_RECYCLE, "complete returns");
_Static_assert(XDEV_EXT_MP_SITE_WORKER == XDEV_EXT_MECH_SITE_WORKER &&
	       XDEV_EXT_MP_SITE_RX_GENERIC == XDEV_EXT_MECH_SITE_RX_GENERIC &&
	       XDEV_EXT_MP_SITE_URING_CMD == XDEV_EXT_MECH_SITE_URING_CMD, "callsites");
_Static_assert(XDEV_EXT_MP_DIR_TO_DEVICE == XDEV_EXT_MECH_DIR_TO_DEVICE &&
	       XDEV_EXT_MP_DIR_FROM_DEVICE == XDEV_EXT_MECH_DIR_FROM_DEVICE, "dirs");
_Static_assert(XDEV_EXT_MP_CE_OK == XDEV_EXT_CE_OK &&
	       XDEV_EXT_MP_CE_PRE_SUBMIT_FAILED == XDEV_EXT_CE_PRE_SUBMIT_FAILED,
	       "CE outcomes");
_Static_assert(XDEV_EXT_MP_CE_F_COMPLETION_POINT == XDEV_EXT_CE_F_COMPLETION_POINT,
	       "CE flags");
_Static_assert(XDEV_EXT_MP_NVME_DESC_SIZE == XDEV_EXT_NVME_MECH_DESC_SIZE &&
	       XDEV_EXT_MP_NVME_DESC_SIZE == NVME_XDEV_EXT_SQE_SIZE, "SQE size");
_Static_assert(XDEV_EXT_MP_NVME_OP_WRITE == NVME_XDEV_EXT_NVM_WRITE &&
	       XDEV_EXT_MP_NVME_OP_READ == NVME_XDEV_EXT_NVM_READ, "NVMe opcodes");
_Static_assert(XDEV_EXT_MP_NVME_MAX_NLB == NVME_XDEV_EXT_MAX_NLB, "NLB");
_Static_assert(XDEV_EXT_MP_NXP_MAGIC == NXP_WIRE_MAGIC &&
	       XDEV_EXT_MP_NXP_VERSION == NXP_WIRE_VERSION &&
	       XDEV_EXT_MP_NXP_LEN == NXP_WIRE_HEADER_LEN &&
	       XDEV_EXT_MP_NXP_LEN == XDEV_EXT_MECH_NXP_HDR_LEN &&
	       XDEV_EXT_MP_NXP_CSUM_OFF == XDEV_EXT_MECH_NXP_CSUM_OFF &&
	       XDEV_EXT_MP_NXP_MAX_SEGMENTS == NXP_WIRE_MAX_SEGMENTS &&
	       XDEV_EXT_MP_NXP_DIR_READ == NXP_IO_READ &&
	       XDEV_EXT_MP_NXP_DIR_WRITE == NXP_IO_WRITE, "NXP wire");
_Static_assert(XDEV_EXT_MP_IP_LEN + XDEV_EXT_MP_UDP_LEN == NXP_WIRE_IPV4_UDP_LEN,
	       "IPv4 + UDP");
_Static_assert(XDEV_EXT_MP_PKT_HDR_LEN == 14 + 20 + 8 + NXP_WIRE_HEADER_LEN,
	       "82 header bytes");
_Static_assert(XDEV_EXT_MP_CRC32C_SEED == XDEV_EXT_MECH_CRC32C_SEED, "CRC seed");

/* nvme_xdp_pipeline.c: FRAME_SIZE, XDP_PACKET_HEADROOM + PKT_START_OFF, MTU. */
#define REF_FRAME_SIZE		4096U
#define REF_RX_PACKET_OFFSET	(256U + 22U)
#define REF_HDR_ROOM		(REF_RX_PACKET_OFFSET + XDEV_EXT_MP_PKT_HDR_LEN)
#define REF_MTU			1500U
#define REF_GROUP_BYTES		8192U
#define REF_SESSION		0x1122334455667788ULL

static const struct xdev_ext_mech_peer rx_peer = {
	.local_mac = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
	.peer_mac = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
	.local_ip = 0x0200000aU,	/* 10.0.0.2 in memory order */
	.peer_ip = 0x0100000aU,		/* 10.0.0.1 */
	.local_port = 0x3412U,		/* 0x1234 */
	.peer_port = 0x31d4U,		/* 54321 */
};

/* The sender's view of the same pair. */
static struct xdev_ext_mech_peer tx_peer_of(const struct xdev_ext_mech_peer *rx)
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

static const struct xdev_ext_mp_rx_cfg ref_cfg = {
	.session_id = REF_SESSION,
	.mtu = REF_MTU,
	.frame_size = REF_FRAME_SIZE,
	.hdr_room = REF_HDR_ROOM,
	.seg_len = 1432,
	.group_bytes = REF_GROUP_BYTES,
};

/* nvme_xdp_pipeline.c compute_checksum(): 16-bit one's complement sum. */
static uint16_t ref_checksum(const void *data, int len)
{
	const uint16_t *ptr = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *ptr++;
		len -= 2;
	}
	if (len == 1)
		sum += *(const uint8_t *)ptr;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (uint16_t)~sum;
}

static __u32 sw_crc32c(__u32 crc, const void *p, size_t len)
{
	return nxp_wire_crc32c_update(crc, p, len);
}

static __u64 lcg_state = 0x243f6a8885a308d3ULL;

static __u32 lcg(void)
{
	lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
	return (__u32)(lcg_state >> 33);
}

/*
 * One received chunk the way nvme_xdp_pipeline -m tx puts it on the wire
 * (build_packet() + build_wire_packet()) and the receiver's kernel copies it
 * to REF_RX_PACKET_OFFSET of an RX chunk.
 */
struct ref_frame {
	__u8 chunk[REF_FRAME_SIZE];
	__u32 data_off;
	__u32 data_len;
	struct nxp_wire_segment seg;
};

static void ref_build(struct ref_frame *f, __u32 generation, __u16 index)
{
	struct nxp_wire_layout layout;
	struct nxp_wire_span span;
	__u8 *pkt = f->chunk + REF_RX_PACKET_OFFSET;
	__u8 *ip = pkt + 14, *udp = ip + 20;
	__u32 i;
	int ret;

	memset(f->chunk, 0xa5, sizeof(f->chunk));
	ret = nxp_wire_mtu_layout_plan(REF_SESSION, generation, REF_GROUP_BYTES,
				       REF_MTU, REF_FRAME_SIZE, REF_HDR_ROOM,
				       8, &layout);
	EXPECT_EQ(ret, 0);
	ret = nxp_wire_segment_at(&layout, NXP_IO_WRITE, index, &f->seg);
	EXPECT_EQ(ret, 0);
	for (i = 0; i < f->seg.payload_len; i++)
		pkt[XDEV_EXT_MP_PKT_HDR_LEN + i] = (__u8)(lcg() >> 7);

	memcpy(pkt, rx_peer.local_mac, 6);
	memcpy(pkt + 6, rx_peer.peer_mac, 6);
	pkt[12] = 0x08;
	pkt[13] = 0x00;
	ip[0] = 0x45;
	ip[1] = 0;
	nxp_wire_put_be16(ip + 2, (uint16_t)(20 + 8 + 40 + f->seg.payload_len));
	nxp_wire_put_be16(ip + 4, 0);
	nxp_wire_put_be16(ip + 6, 0);
	ip[8] = 64;
	ip[9] = 17;
	ip[10] = ip[11] = 0;
	memcpy(ip + 12, &rx_peer.peer_ip, 4);
	memcpy(ip + 16, &rx_peer.local_ip, 4);
	{
		uint16_t csum = ref_checksum(ip, 20);

		memcpy(ip + 10, &csum, 2);
	}
	memcpy(udp, &rx_peer.peer_port, 2);
	memcpy(udp + 2, &rx_peer.local_port, 2);
	nxp_wire_put_be16(udp + 4, (uint16_t)(8 + 40 + f->seg.payload_len));
	udp[6] = udp[7] = 0;
	span.data = pkt + XDEV_EXT_MP_PKT_HDR_LEN;
	span.len = f->seg.payload_len;
	ret = nxp_wire_header_encode(pkt + XDEV_EXT_MP_NXP_OFF, NXP_WIRE_HEADER_LEN,
				     &f->seg, &span, 1);
	EXPECT_EQ(ret, 0);
	f->data_off = REF_RX_PACKET_OFFSET;
	f->data_len = XDEV_EXT_MP_PKT_HDR_LEN + f->seg.payload_len;
}

/*
 * Every check the user-space receiver makes on one packet before its group
 * logic: pipeline_decode_rx_descriptor(), parse_wire_packet() (with the CRC)
 * and pipeline_validate_rx_packet() of nvme_xdp_pipeline.c.
 */
static int ref_receive(const struct ref_frame *f, struct nxp_wire_segment *out)
{
	const __u8 *pkt = f->chunk + f->data_off;
	const __u8 *ip = pkt + 14, *udp = ip + 20, *wire = udp + 8;
	struct nxp_wire_layout layout;
	struct nxp_wire_segment expected;
	struct nxp_wire_span span;
	uint32_t ip_len, udp_len;
	int ret;

	if (f->data_off != REF_RX_PACKET_OFFSET)
		return -EINVAL;
	if (f->data_len > REF_FRAME_SIZE - f->data_off)
		return -EMSGSIZE;
	if (f->data_len < 14 + 20 + 8 + NXP_WIRE_HEADER_LEN)
		return -EMSGSIZE;
	if (memcmp(pkt, rx_peer.local_mac, 6) ||
	    memcmp(pkt + 6, rx_peer.peer_mac, 6))
		return -EACCES;
	if (nxp_wire_get_be16(pkt + 12) != 0x0800)
		return -EPROTO;
	if ((ip[0] >> 4) != 4 || (ip[0] & 15) != 5 || ip[9] != 17 ||
	    memcmp(ip + 12, &rx_peer.peer_ip, 4) ||
	    memcmp(ip + 16, &rx_peer.local_ip, 4) ||
	    (nxp_wire_get_be16(ip + 6) & 0x3fff))
		return -EACCES;
	ip_len = nxp_wire_get_be16(ip + 2);
	if (ip_len != f->data_len - 14 || ip_len > REF_MTU ||
	    ip_len < 20 + 8 + NXP_WIRE_HEADER_LEN ||
	    ref_checksum(ip, 20) != 0)
		return -EPROTO;
	udp_len = nxp_wire_get_be16(udp + 4);
	if (memcmp(udp, &rx_peer.peer_port, 2) ||
	    memcmp(udp + 2, &rx_peer.local_port, 2))
		return -EACCES;
	if (udp_len != ip_len - 20 || udp_len < 8 + NXP_WIRE_HEADER_LEN)
		return -EPROTO;
	span.data = wire + NXP_WIRE_HEADER_LEN;
	span.len = udp_len - 8 - NXP_WIRE_HEADER_LEN;
	ret = nxp_wire_header_parse(wire, NXP_WIRE_HEADER_LEN, &span, 1, out);
	if (ret)
		return ret;
	if (out->direction == NXP_IO_READ)
		return -EACCES;
	if (out->direction != NXP_IO_WRITE ||
	    out->total_len != REF_GROUP_BYTES)
		return -EPROTO;
	if (out->session_id != REF_SESSION)
		return -ESTALE;
	ret = nxp_wire_mtu_layout_plan(REF_SESSION, out->generation,
				       REF_GROUP_BYTES, REF_MTU, REF_FRAME_SIZE,
				       REF_HDR_ROOM, 8, &layout);
	if (ret)
		return ret;
	ret = nxp_wire_segment_at(&layout, NXP_IO_WRITE, out->segment_index,
				  &expected);
	if (ret || out->segment_count != expected.segment_count ||
	    out->relative_offset != expected.relative_offset ||
	    out->payload_len != expected.payload_len)
		return -EPROTO;
	return 0;
}

/* The RX complete program: parse, then the two-kfunc CRC. */
static int prog_receive(const struct ref_frame *f, struct xdev_ext_mp_segment *seg)
{
	const __u8 *pkt = f->chunk + f->data_off;
	__u8 hdr[XDEV_EXT_MP_NXP_LEN];
	__u32 crc;
	int cls;

	cls = xdev_ext_mp_rx_parse(pkt, f->data_off, f->data_len, &rx_peer, &ref_cfg,
			      seg);
	if (cls != XDEV_EXT_MP_RX_SEGMENT)
		return cls;
	xdev_ext_mp_nxp_crc_prep(hdr, pkt + XDEV_EXT_MP_NXP_OFF);
	crc = sw_crc32c(XDEV_EXT_MP_CRC32C_SEED, hdr, sizeof(hdr));
	crc = sw_crc32c(crc, f->chunk + seg->payload_off, seg->payload_len);
	return xdev_ext_mp_nxp_crc_ok(pkt + XDEV_EXT_MP_NXP_OFF, crc) ?
	       XDEV_EXT_MP_RX_SEGMENT : XDEV_EXT_MP_RX_BAD;
}

static void test_byte_helpers(void)
{
	__u8 b[8] = { 0 };
	__u8 ip[20] = { 0x45, 0, 0, 0x54, 0, 0, 0x40, 0, 64, 17, 0, 0,
			10, 0, 0, 1, 10, 0, 0, 2 };
	uint16_t csum;

	xdev_ext_mp_put_be16(b, 0x1234);
	EXPECT_EQ(b[0], 0x12);
	EXPECT_EQ(xdev_ext_mp_get_be16(b), 0x1234);
	xdev_ext_mp_put_be32(b, 0x89abcdefU);
	EXPECT_EQ(nxp_wire_get_be32(b), 0x89abcdefU);
	EXPECT_EQ(xdev_ext_mp_get_be32(b), 0x89abcdefU);
	xdev_ext_mp_put_be64(b, 0x0102030405060708ULL);
	EXPECT_EQ(nxp_wire_get_be64(b), 0x0102030405060708ULL);
	EXPECT_EQ(xdev_ext_mp_get_be64(b), 0x0102030405060708ULL);
	xdev_ext_mp_put_le64(b, 0x0102030405060708ULL);
	EXPECT_EQ(b[0], 0x08);
	EXPECT_EQ(b[7], 0x01);
	xdev_ext_mp_put_le16(b, 0xbeef);
	EXPECT_EQ(b[0], 0xef);
	EXPECT_EQ(b[1], 0xbe);

	/* The folded checksum is what compute_checksum() leaves in the field. */
	csum = ref_checksum(ip, 20);
	EXPECT_EQ(xdev_ext_mp_ip_csum(ip), nxp_wire_get_be16((const __u8 *)&csum));
	memcpy(ip + 10, &csum, 2);
	EXPECT_EQ(xdev_ext_mp_ip_csum(ip), 0);
	ip[8]++;
	EXPECT_TRUE(xdev_ext_mp_ip_csum(ip) != 0);
}

static void test_seg_limit(void)
{
	struct nxp_wire_layout layout;
	__u32 limit;

	EXPECT_EQ(xdev_ext_mp_seg_limit(REF_MTU, REF_FRAME_SIZE, REF_HDR_ROOM,
				   &limit), 0);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(1, 1, REF_GROUP_BYTES, REF_MTU,
					   REF_FRAME_SIZE, REF_HDR_ROOM, 8,
					   &layout), 0);
	EXPECT_EQ(limit, layout.segment_data_limit);
	EXPECT_EQ(limit, 1432);
	EXPECT_EQ(layout.segment_count, 6);
	/* Frame room is the bound for jumbo MTU, the MTU for small ones. */
	EXPECT_EQ(xdev_ext_mp_seg_limit(9000, REF_FRAME_SIZE, REF_HDR_ROOM, &limit),
		  0);
	EXPECT_EQ(limit, (REF_FRAME_SIZE - REF_HDR_ROOM) & ~7U);
	EXPECT_EQ(xdev_ext_mp_seg_limit(68 + 7, REF_FRAME_SIZE, REF_HDR_ROOM,
				   &limit), -EMSGSIZE);
	EXPECT_EQ(xdev_ext_mp_seg_limit(68, REF_FRAME_SIZE, REF_HDR_ROOM, &limit),
		  -EMSGSIZE);
	EXPECT_EQ(xdev_ext_mp_seg_limit(REF_MTU, 360, 360, &limit), -EINVAL);
	for (__u32 mtu = 69; mtu < 9100; mtu += 37) {
		int want = nxp_wire_mtu_layout_plan(1, 1, REF_GROUP_BYTES, mtu,
						    REF_FRAME_SIZE,
						    REF_HDR_ROOM, 8, &layout);
		int got = xdev_ext_mp_seg_limit(mtu, REF_FRAME_SIZE, REF_HDR_ROOM,
					   &limit);

		if (want == -E2BIG)
			continue;	/* too many segments: a group-level bound */
		EXPECT_EQ(got, want);
		if (!want)
			EXPECT_EQ(limit, layout.segment_data_limit);
	}
}

static void test_rx_parse_valid(void)
{
	const struct xdev_ext_mech_layout l = {
		.frame_size = ref_cfg.frame_size, .hdr_room = ref_cfg.hdr_room,
		.seg_len = ref_cfg.seg_len, .group_bytes = ref_cfg.group_bytes,
	};
	/* bpf_xdev_ext_afxdp_hold() records the layout's frames per batch. */
	const int count = xdev_ext_mech_layout_frames(&l);
	struct nxp_wire_segment ref;
	struct xdev_ext_mech_group group;
	struct xdev_ext_mp_segment seg;
	struct ref_frame f;
	__u32 off, len;

	EXPECT_EQ(count, 6);
	xdev_ext_mech_group_init(&group, 7, (__u32)count);
	for (__u16 i = 0; i < 6; i++) {
		ref_build(&f, 7, i);
		EXPECT_EQ(ref_receive(&f, &ref), 0);
		EXPECT_EQ(prog_receive(&f, &seg), XDEV_EXT_MP_RX_SEGMENT);
		EXPECT_EQ(seg.session_id, REF_SESSION);
		EXPECT_EQ(seg.generation, 7);
		EXPECT_EQ(seg.index, i);
		EXPECT_EQ(seg.count, 6);
		EXPECT_EQ(seg.total_len, REF_GROUP_BYTES);
		EXPECT_EQ(seg.relative_offset, ref.relative_offset);
		EXPECT_EQ(seg.payload_len, ref.payload_len);
		EXPECT_EQ(seg.payload_len, i < 5 ? 1432 : 8192 - 5 * 1432);
		EXPECT_EQ(seg.payload_off, REF_HDR_ROOM);
		/*
		 * The hold the program records passes the core's checks, and
		 * the held span is the frame span a START batch of the same
		 * layout would carry.
		 */
		EXPECT_EQ(xdev_ext_mech_hold_check(seg.index, (__u32)count,
					      seg.payload_off, seg.payload_len,
					      f.data_off, f.data_len), 0);
		EXPECT_EQ(xdev_ext_mech_group_add(&group, seg.generation, seg.index,
					     (__u32)count), 0);
		EXPECT_EQ(xdev_ext_mech_layout_span(&l, i, &off, &len), 0);
		EXPECT_EQ(seg.payload_off, off);
		EXPECT_EQ(seg.payload_len, len);
	}
	EXPECT_TRUE(xdev_ext_mech_group_full(&group));
}

/* One field change and how each side must classify it. */
struct mutation {
	const char *name;
	__u32 at;		/* byte offset from the Ethernet header */
	__u8 xor;
	int cls;		/* the program's class */
	bool fix_ip_csum;	/* recompute the IPv4 checksum after the change */
	bool fix_crc;		/* recompute the NXP checksum after the change */
};

static const struct mutation mutations[] = {
	/* Not NXP traffic: user space drops it, the program publishes it. */
	{ "ethertype", 12, 0x01, XDEV_EXT_MP_RX_FOREIGN, false, false },
	{ "ip version", 14, 0x10, XDEV_EXT_MP_RX_FOREIGN, true, false },
	{ "ip ihl", 14, 0x01, XDEV_EXT_MP_RX_FOREIGN, true, false },
	{ "ip protocol", 23, 0x01, XDEV_EXT_MP_RX_FOREIGN, true, false },
	{ "ip more fragments", 20, 0x20, XDEV_EXT_MP_RX_FOREIGN, true, false },
	{ "ip fragment offset", 21, 0x01, XDEV_EXT_MP_RX_FOREIGN, true, false },
	{ "nxp magic", 42, 0x01, XDEV_EXT_MP_RX_FOREIGN, false, false },
	/* NXP traffic that fails a check: both sides drop it. */
	{ "dst mac", 0, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "src mac", 11, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "ip tot_len", 17, 0x01, XDEV_EXT_MP_RX_BAD, true, false },
	{ "ip checksum", 25, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "ip saddr", 29, 0x01, XDEV_EXT_MP_RX_BAD, true, false },
	{ "ip daddr", 33, 0x01, XDEV_EXT_MP_RX_BAD, true, false },
	{ "udp sport", 35, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "udp dport", 37, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "udp len", 39, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "nxp version", 46, 0x01, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp hdr len", 47, 0x01, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp no direction", 48, 0x02, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp read direction", 48, 0x03, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp flags", 49, 0x01, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp session", 57, 0x01, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp generation 0", 61, 0x03, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp segment index", 63, 0x02, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp segment count", 65, 0x01, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp total_len", 69, 0x01, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp relative_offset", 73, 0x08, XDEV_EXT_MP_RX_BAD, false, true },
	{ "nxp payload_len", 77, 0x01, XDEV_EXT_MP_RX_BAD, false, true },
	/* A damaged header or payload: only the CRC tells. */
	{ "nxp checksum", 81, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "nxp generation", 61, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "payload byte", 82 + 100, 0x01, XDEV_EXT_MP_RX_BAD, false, false },
	{ "last payload byte", 82 + 1431, 0x80, XDEV_EXT_MP_RX_BAD, false, false },
};

static void fix_ip_checksum(__u8 *pkt)
{
	uint16_t csum;

	pkt[24] = pkt[25] = 0;
	csum = ref_checksum(pkt + 14, 20);
	memcpy(pkt + 24, &csum, 2);
}

static void fix_nxp_checksum(__u8 *pkt, __u32 payload_len)
{
	struct nxp_wire_span span = {
		.data = pkt + XDEV_EXT_MP_PKT_HDR_LEN, .len = payload_len,
	};

	nxp_wire_put_be32(pkt + XDEV_EXT_MP_NXP_OFF + 36,
			  nxp_wire_checksum(pkt + XDEV_EXT_MP_NXP_OFF, &span, 1));
}

static void test_rx_parse_mutations(void)
{
	for (size_t m = 0; m < sizeof(mutations) / sizeof(mutations[0]); m++) {
		const struct mutation *mu = &mutations[m];
		struct nxp_wire_segment ref;
		struct xdev_ext_mp_segment seg;
		struct ref_frame f;
		__u8 *pkt;
		int got;

		ref_build(&f, 3, 1);
		pkt = f.chunk + f.data_off;
		pkt[mu->at] ^= mu->xor;
		if (mu->fix_ip_csum)
			fix_ip_checksum(pkt);
		if (mu->fix_crc)
			fix_nxp_checksum(pkt, f.seg.payload_len);
		got = prog_receive(&f, &seg);
		if (got != mu->cls)
			fprintf(stderr, "mutation '%s'\n", mu->name);
		EXPECT_EQ(got, mu->cls);
		/* User space never accepts any of these. */
		EXPECT_TRUE(ref_receive(&f, &ref) != 0);
	}
}

static void test_rx_parse_framing(void)
{
	struct nxp_wire_segment ref;
	struct xdev_ext_mp_segment seg;
	struct xdev_ext_mp_rx_cfg cfg = ref_cfg;
	struct ref_frame f;

	/* Shorter than the 82 header bytes: not NXP traffic. */
	ref_build(&f, 1, 0);
	f.data_len = XDEV_EXT_MP_PKT_HDR_LEN - 1;
	EXPECT_EQ(prog_receive(&f, &seg), XDEV_EXT_MP_RX_FOREIGN);
	EXPECT_TRUE(ref_receive(&f, &ref) != 0);

	/* The descriptor length must match the IPv4 length. */
	ref_build(&f, 1, 0);
	f.data_len++;
	EXPECT_EQ(prog_receive(&f, &seg), XDEV_EXT_MP_RX_BAD);
	EXPECT_TRUE(ref_receive(&f, &ref) != 0);

	/* The packet sits at a fixed chunk offset (UMEM headroom). */
	ref_build(&f, 1, 0);
	memmove(f.chunk + f.data_off + 8, f.chunk + f.data_off, f.data_len);
	f.data_off += 8;
	EXPECT_EQ(prog_receive(&f, &seg), XDEV_EXT_MP_RX_BAD);
	EXPECT_TRUE(ref_receive(&f, &ref) != 0);

	/* Past the chunk. */
	ref_build(&f, 1, 0);
	EXPECT_EQ(xdev_ext_mp_rx_parse(f.chunk + f.data_off, f.data_off,
				  REF_FRAME_SIZE, &rx_peer, &ref_cfg, &seg),
		  XDEV_EXT_MP_RX_BAD);

	/* Another session, a group size or an MTU the session does not use. */
	ref_build(&f, 1, 0);
	cfg.session_id = REF_SESSION + 1;
	EXPECT_EQ(xdev_ext_mp_rx_parse(f.chunk + f.data_off, f.data_off, f.data_len,
				  &rx_peer, &cfg, &seg), XDEV_EXT_MP_RX_BAD);
	cfg = ref_cfg;
	cfg.group_bytes = 4096;
	EXPECT_EQ(xdev_ext_mp_rx_parse(f.chunk + f.data_off, f.data_off, f.data_len,
				  &rx_peer, &cfg, &seg), XDEV_EXT_MP_RX_BAD);
	cfg = ref_cfg;
	cfg.mtu = 1400;
	cfg.seg_len = 1328;
	EXPECT_EQ(xdev_ext_mp_rx_parse(f.chunk + f.data_off, f.data_off, f.data_len,
				  &rx_peer, &cfg, &seg), XDEV_EXT_MP_RX_BAD);
	cfg = ref_cfg;
	cfg.seg_len = 1424;
	EXPECT_EQ(xdev_ext_mp_rx_parse(f.chunk + f.data_off, f.data_off, f.data_len,
				  &rx_peer, &cfg, &seg), XDEV_EXT_MP_RX_BAD);
	cfg = ref_cfg;
	cfg.mtu = 0;
	EXPECT_EQ(xdev_ext_mp_rx_parse(f.chunk + f.data_off, f.data_off, f.data_len,
				  &rx_peer, &cfg, &seg), XDEV_EXT_MP_RX_BAD);
	cfg = ref_cfg;
	cfg.session_id = 0;
	EXPECT_EQ(xdev_ext_mp_rx_parse(f.chunk + f.data_off, f.data_off, f.data_len,
				  &rx_peer, &cfg, &seg), XDEV_EXT_MP_RX_BAD);

	/* A packet the reference accepts is never anything but a segment. */
	for (int round = 0; round < 2000; round++) {
		__u32 at = lcg() % XDEV_EXT_MP_PKT_HDR_LEN;
		int want, got;

		ref_build(&f, 1 + lcg() % 4, (__u16)(lcg() % 6));
		f.chunk[f.data_off + at] ^= (__u8)(1U << (lcg() % 8));
		if (lcg() & 1)
			fix_ip_checksum(f.chunk + f.data_off);
		want = ref_receive(&f, &ref);
		got = prog_receive(&f, &seg);
		EXPECT_EQ(got == XDEV_EXT_MP_RX_SEGMENT, want == 0);
	}
}

static void test_crc_convention(void)
{
	struct ref_frame f;
	struct nxp_wire_span span;
	const __u8 *nxp;
	__u8 hdr[XDEV_EXT_MP_NXP_LEN];
	__u32 crc;

	ref_build(&f, 9, 5);
	nxp = f.chunk + f.data_off + XDEV_EXT_MP_NXP_OFF;
	span.data = f.chunk + REF_HDR_ROOM;
	span.len = f.seg.payload_len;
	xdev_ext_mp_nxp_crc_prep(hdr, nxp);
	EXPECT_EQ(memcmp(hdr, nxp, XDEV_EXT_MP_NXP_CSUM_OFF), 0);
	EXPECT_EQ(nxp_wire_get_be32(hdr + XDEV_EXT_MP_NXP_CSUM_OFF), 0);
	crc = sw_crc32c(XDEV_EXT_MP_CRC32C_SEED, hdr, sizeof(hdr));
	crc = sw_crc32c(crc, span.data, span.len);
	EXPECT_EQ(~crc, nxp_wire_checksum(nxp, &span, 1));
	EXPECT_EQ(~crc, xdev_ext_mech_nxp_csum(sw_crc32c, nxp, span.data, span.len));
	EXPECT_TRUE(xdev_ext_mp_nxp_crc_ok(nxp, crc));
	EXPECT_FALSE(xdev_ext_mp_nxp_crc_ok(nxp, crc ^ 1));
	memcpy(hdr, nxp, sizeof(hdr));
	xdev_ext_mp_nxp_crc_store(hdr, crc);
	EXPECT_EQ(memcmp(hdr, nxp, sizeof(hdr)), 0);
}

/*
 * The user-space receiver's group logic: one collecting slot, begin on the
 * first packet without one, accept, commit the generation on completion,
 * expire after NXP_RX_GROUP_TIMEOUT_NS (run_rx_write_pipeline() and
 * pipeline_rx_expire_group() of nvme_xdp_pipeline.c).
 */
struct ref_order {
	struct nxp_wire_group_rx group;
	__u32 last_wire_generation;
	__u64 started_ns;
	bool active;
};

static bool ref_order_accept(struct ref_order *r,
			     const struct nxp_wire_segment *s, __u64 now)
{
	if (r->active && now >= r->started_ns &&
	    now - r->started_ns >= XDEV_EXT_MP_GROUP_TIMEOUT_NS)
		r->active = false;
	if (!r->active) {
		memset(&r->group, 0, sizeof(r->group));
		r->group.last_generation = r->last_wire_generation;
		if (nxp_wire_group_begin(&r->group, REF_SESSION, s->generation,
					 NXP_IO_WRITE, s->total_len,
					 s->segment_count))
			return false;
		r->active = true;
		r->started_ns = now;
	}
	if (nxp_wire_group_accept(&r->group, s))
		return false;
	if (nxp_wire_group_finish(&r->group) == 0) {
		r->last_wire_generation = s->generation;
		r->active = false;
	}
	return true;
}

static struct xdev_ext_mp_segment mp_seg_of(const struct nxp_wire_segment *s)
{
	return (struct xdev_ext_mp_segment) {
		.session_id = s->session_id,
		.generation = s->generation,
		.total_len = s->total_len,
		.relative_offset = s->relative_offset,
		.payload_len = s->payload_len,
		.payload_off = REF_HDR_ROOM,
		.index = s->segment_index,
		.count = s->segment_count,
	};
}

static struct nxp_wire_segment wire_seg(__u32 generation, __u16 index)
{
	struct nxp_wire_layout layout = { 0 };
	struct nxp_wire_segment s = { 0 };

	EXPECT_EQ(nxp_wire_mtu_layout_plan(REF_SESSION, generation,
					   REF_GROUP_BYTES, REF_MTU,
					   REF_FRAME_SIZE, REF_HDR_ROOM, 8,
					   &layout), 0);
	EXPECT_EQ(nxp_wire_segment_at(&layout, NXP_IO_WRITE, index, &s), 0);
	return s;
}

static int order_step(struct xdev_ext_mp_rx_order *o, __u32 generation,
		      __u16 index, __u64 now)
{
	struct nxp_wire_segment w = wire_seg(generation, index);
	struct xdev_ext_mp_segment s = mp_seg_of(&w);

	return xdev_ext_mp_rx_order(o, &s, now);
}

static void test_rx_order_cases(void)
{
	struct xdev_ext_mp_rx_order o = { 0 };
	__u64 t = 1000;

	/* Group 1 in order. */
	for (__u16 i = 0; i < 6; i++)
		EXPECT_EQ(order_step(&o, 1, i, t), XDEV_EXT_MP_HOLD);
	EXPECT_EQ(o.last_generation, 1);
	EXPECT_FALSE(o.active);
	/* A segment of the committed group, a stale and a future one. */
	EXPECT_EQ(order_step(&o, 1, 0, t), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(order_step(&o, 3, 0, t), XDEV_EXT_MP_RECYCLE);
	/* Group 2 with a duplicate and a gap inside it. */
	EXPECT_EQ(order_step(&o, 2, 0, t), XDEV_EXT_MP_HOLD);
	EXPECT_EQ(order_step(&o, 2, 0, t), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(order_step(&o, 2, 2, t), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(order_step(&o, 3, 0, t), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(order_step(&o, 2, 1, t), XDEV_EXT_MP_HOLD);
	/* The group expires; the sender's retry of it starts over. */
	t += XDEV_EXT_MP_GROUP_TIMEOUT_NS;
	EXPECT_EQ(order_step(&o, 2, 2, t), XDEV_EXT_MP_RECYCLE);
	EXPECT_TRUE(o.active);
	EXPECT_EQ(o.next, 0);
	for (__u16 i = 0; i < 6; i++)
		EXPECT_EQ(order_step(&o, 2, i, t + i), XDEV_EXT_MP_HOLD);
	EXPECT_EQ(o.last_generation, 2);
	/* The last generation can never be followed. */
	o.last_generation = UINT32_MAX;
	EXPECT_EQ(order_step(&o, 1, 0, t), XDEV_EXT_MP_RECYCLE);
	EXPECT_FALSE(o.active);
}

/* A new session starts a new order; the same session keeps its own. */
static void test_rx_order_session(void)
{
	struct xdev_ext_mp_rx_order o = { 0 };

	xdev_ext_mp_rx_order_session(&o, 5);
	for (__u16 i = 0; i < 6; i++)
		EXPECT_EQ(order_step(&o, 1, i, 0), XDEV_EXT_MP_HOLD);
	EXPECT_EQ(order_step(&o, 2, 0, 0), XDEV_EXT_MP_HOLD);
	xdev_ext_mp_rx_order_session(&o, 5);
	EXPECT_EQ(o.last_generation, 1);
	EXPECT_TRUE(o.active);
	EXPECT_EQ(order_step(&o, 2, 1, 0), XDEV_EXT_MP_HOLD);
	/* The next session's sender starts again at generation 1. */
	xdev_ext_mp_rx_order_session(&o, 6);
	EXPECT_EQ(o.session_id, 6);
	EXPECT_EQ(o.last_generation, 0);
	EXPECT_FALSE(o.active);
	EXPECT_EQ(order_step(&o, 1, 0, 0), XDEV_EXT_MP_HOLD);
}

/* Fields the layout already pins are still checked by the order itself. */
static void test_rx_order_fields(void)
{
	struct xdev_ext_mp_rx_order o = { 0 };
	struct nxp_wire_segment w = wire_seg(1, 0);
	struct xdev_ext_mp_segment s = mp_seg_of(&w), bad;

	EXPECT_EQ(xdev_ext_mp_rx_order(&o, &s, 0), XDEV_EXT_MP_HOLD);
	w = wire_seg(1, 1);
	s = mp_seg_of(&w);
	bad = s;
	bad.relative_offset += 8;
	EXPECT_EQ(xdev_ext_mp_rx_order(&o, &bad, 0), XDEV_EXT_MP_RECYCLE);
	bad = s;
	bad.payload_len = REF_GROUP_BYTES;
	EXPECT_EQ(xdev_ext_mp_rx_order(&o, &bad, 0), XDEV_EXT_MP_RECYCLE);
	bad = s;
	bad.count = 7;
	EXPECT_EQ(xdev_ext_mp_rx_order(&o, &bad, 0), XDEV_EXT_MP_RECYCLE);
	bad = s;
	bad.total_len++;
	EXPECT_EQ(xdev_ext_mp_rx_order(&o, &bad, 0), XDEV_EXT_MP_RECYCLE);
	EXPECT_EQ(xdev_ext_mp_rx_order(&o, &s, 0), XDEV_EXT_MP_HOLD);
	EXPECT_EQ(o.next, 2);

	/* A last segment that leaves bytes missing never commits the group. */
	memset(&o, 0, sizeof(o));
	s = (struct xdev_ext_mp_segment) {
		.session_id = REF_SESSION, .generation = 1, .total_len = 100,
		.payload_len = 40, .index = 0, .count = 2,
	};
	EXPECT_EQ(xdev_ext_mp_rx_order(&o, &s, 0), XDEV_EXT_MP_HOLD);
	s.index = 1;
	s.relative_offset = 40;
	EXPECT_EQ(xdev_ext_mp_rx_order(&o, &s, 0), XDEV_EXT_MP_RECYCLE);
	EXPECT_TRUE(o.active);
	EXPECT_EQ(o.last_generation, 0);
}

static void test_rx_order_differential(void)
{
	struct xdev_ext_mp_rx_order o = { 0 };
	struct ref_order r = { 0 };
	__u32 base = 1;
	__u64 now = 5;

	for (int step = 0; step < 200000; step++) {
		__u32 generation = base + lcg() % 3;
		__u16 index;
		struct nxp_wire_segment w;
		struct xdev_ext_mp_segment s;
		bool want;
		int got;

		/* Mostly the next expected segment, sometimes any other. */
		if (r.active && (lcg() % 8))
			index = r.group.next_segment < 6 ?
				r.group.next_segment : 5;
		else
			index = (__u16)(lcg() % 6);
		if (!generation)
			continue;
		now += lcg() % 4 ? lcg() % 1000 :
			(__u64)(lcg() % 3) * (XDEV_EXT_MP_GROUP_TIMEOUT_NS / 2);
		w = wire_seg(generation, index);
		s = mp_seg_of(&w);
		want = ref_order_accept(&r, &w, now);
		got = xdev_ext_mp_rx_order(&o, &s, now);
		EXPECT_EQ(got, want ? XDEV_EXT_MP_HOLD : XDEV_EXT_MP_RECYCLE);
		EXPECT_EQ(o.last_generation, r.last_wire_generation);
		EXPECT_EQ(o.active, r.active);
		if (failures)
			break;
		if (lcg() % 50 == 0)
			base = r.last_wire_generation + (lcg() % 2);
		else if (!r.active)
			base = r.last_wire_generation;
	}
}

static void test_tx_encode(void)
{
	const struct xdev_ext_mech_peer tx = tx_peer_of(&rx_peer);
	const struct xsk_xdev_ext_mech_tx_bounds bd = {
		.hdr_room = REF_HDR_ROOM, .mtu = REF_MTU, .peer = tx,
	};
	const __u64 umem_addr = 9 * (__u64)REF_FRAME_SIZE;
	struct xdev_ext_mech_frame_info fi;
	struct ref_frame want;
	__u8 chunk[REF_FRAME_SIZE];
	struct xdp_desc d;

	for (__u16 i = 0; i < 6; i++) {
		struct xdev_ext_mp_tx_seg s;
		struct xdev_ext_mp_segment seg;
		struct ref_frame got;
		__u8 *pkt = chunk + REF_RX_PACKET_OFFSET;
		__u8 hdr[XDEV_EXT_MP_NXP_LEN];
		uint16_t csum;
		__u32 crc;

		ref_build(&want, 4, i);
		memset(chunk, 0xa5, sizeof(chunk));
		memcpy(chunk + REF_HDR_ROOM, want.chunk + REF_HDR_ROOM,
		       want.seg.payload_len);
		s = (struct xdev_ext_mp_tx_seg) {
			.session_id = REF_SESSION,
			.generation = 4,
			.total_len = REF_GROUP_BYTES,
			.relative_offset = want.seg.relative_offset,
			.payload_len = want.seg.payload_len,
			.index = i,
			.count = 6,
		};
		EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), 0);
		/* The program leaves both checksums to their owners. */
		EXPECT_EQ(nxp_wire_get_be16(pkt + 24), 0);
		EXPECT_EQ(nxp_wire_get_be32(pkt + XDEV_EXT_MP_NXP_OFF + 36), 0);
		xdev_ext_mp_nxp_crc_prep(hdr, pkt + XDEV_EXT_MP_NXP_OFF);
		crc = sw_crc32c(XDEV_EXT_MP_CRC32C_SEED, hdr, sizeof(hdr));
		crc = sw_crc32c(crc, chunk + REF_HDR_ROOM, s.payload_len);
		xdev_ext_mp_nxp_crc_store(pkt + XDEV_EXT_MP_NXP_OFF, crc);
		/* The AF_XDP class admits the descriptor the program builds. */
		xdev_ext_mp_tx_desc(&d, umem_addr, REF_HDR_ROOM, s.payload_len);
		fi = (struct xdev_ext_mech_frame_info) {
			.umem_addr = umem_addr,
			.data_off = REF_HDR_ROOM,
			.data_len = s.payload_len,
		};
		EXPECT_EQ(xsk_xdev_ext_mech_tx_check(&d, &fi, chunk, &bd), 0);
		/* C fills the IPv4 checksum before xsk_kernel_xmit(). */
		csum = ref_checksum(pkt + 14, 20);
		xsk_xdev_ext_mech_tx_finish(pkt);
		EXPECT_EQ(memcmp(pkt + 24, &csum, 2), 0);
		EXPECT_EQ(memcmp(chunk, want.chunk, sizeof(chunk)), 0);

		/* And the receiving program takes it. */
		memcpy(got.chunk, chunk, sizeof(chunk));
		got.data_off = REF_RX_PACKET_OFFSET;
		got.data_len = XDEV_EXT_MP_PKT_HDR_LEN + s.payload_len;
		EXPECT_EQ(prog_receive(&got, &seg), XDEV_EXT_MP_RX_SEGMENT);
	}
}

static void test_tx_encode_rejects(void)
{
	const struct xdev_ext_mech_peer tx = tx_peer_of(&rx_peer);
	const struct xdev_ext_mp_tx_seg ok = {
		.session_id = REF_SESSION, .generation = 1,
		.total_len = 8192, .relative_offset = 1432,
		.payload_len = 1432, .index = 1, .count = 6,
	};
	struct xdev_ext_mp_tx_seg s;
	__u8 pkt[XDEV_EXT_MP_PKT_HDR_LEN];

	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &ok), 0);
	s = ok; s.session_id = 0;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -EINVAL);
	s = ok; s.generation = 0;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -EINVAL);
	s = ok; s.index = 6;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -EINVAL);
	s = ok; s.count = 0;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -EINVAL);
	s = ok; s.count = 257; s.index = 1;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -EINVAL);
	s = ok; s.payload_len = 0;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -EINVAL);
	s = ok; s.total_len = 0;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -EINVAL);
	/* The segment rules of nxp_wire_segment_validate(). */
	s = ok; s.index = 0;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -ERANGE);
	s = ok; s.index = 5;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -ERANGE);
	s = ok; s.relative_offset = 8192 - 1432;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -ERANGE);
	s = ok; s.relative_offset = 8000;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -ERANGE);
	s = ok; s.payload_len = 65536 - 68;
	s.total_len = 0x7fffffff;
	EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s), -EMSGSIZE);
	for (int round = 0; round < 20000; round++) {
		struct nxp_wire_segment w = {
			.direction = NXP_IO_WRITE,
			.session_id = lcg() % 4,
			.generation = lcg() % 3,
			.segment_index = (uint16_t)(lcg() % 8),
			.segment_count = (uint16_t)(lcg() % 8),
			.total_len = lcg() % 9000,
			.relative_offset = lcg() % 9000,
			.payload_len = lcg() % 2000,
		};

		s = (struct xdev_ext_mp_tx_seg) {
			.session_id = w.session_id,
			.generation = w.generation,
			.total_len = w.total_len,
			.relative_offset = w.relative_offset,
			.payload_len = w.payload_len,
			.index = w.segment_index,
			.count = w.segment_count,
		};
		EXPECT_EQ(xdev_ext_mp_tx_encode(pkt, &tx, &s),
			  nxp_wire_segment_validate(&w));
	}
}

static void test_tx_desc_and_complete(void)
{
	struct xdp_desc d;

	memset(&d, 0xff, sizeof(d));
	xdev_ext_mp_tx_desc(&d, 7 * 4096ULL, REF_HDR_ROOM, 1432);
	EXPECT_EQ(d.addr, 7 * 4096ULL + REF_RX_PACKET_OFFSET);
	EXPECT_EQ(d.len, XDEV_EXT_MP_PKT_HDR_LEN + 1432);
	EXPECT_EQ(d.options, 0);
	/* The descriptor ends exactly at the end of the data span. */
	EXPECT_EQ(d.addr + d.len, 7 * 4096ULL + REF_HDR_ROOM + 1432);

	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_NEXT, 0), XDEV_EXT_MP_NEXT);
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_NEXT, -EAGAIN), XDEV_EXT_MP_RETRY);
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_RETRY, 0), XDEV_EXT_MP_RETRY);
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_RETRY, -EBUSY), XDEV_EXT_MP_ABORT);
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_NEXT, -ENXIO), XDEV_EXT_MP_ABORT);
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_ABORT, -EAGAIN), XDEV_EXT_MP_ABORT);
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_ABORT, 0), XDEV_EXT_MP_ABORT);
	/* xsk_kernel_xmit() returns the length on success. */
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_NEXT, 1514), XDEV_EXT_MP_NEXT);
	/* -ECANCELED only marks frames after a -EAGAIN as not attempted. */
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_RETRY, -ECANCELED), XDEV_EXT_MP_RETRY);
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_NEXT, -ECANCELED), XDEV_EXT_MP_ABORT);
	EXPECT_EQ(xdev_ext_mp_tx_fold(XDEV_EXT_MP_ABORT, -ECANCELED), XDEV_EXT_MP_ABORT);
}

struct tx_fail {
	__u32 slot;		/* frame whose send fails */
	int err;
	__u32 calls;
};

static int tx_fail_xmit(void *arg, __u32 slot)
{
	struct tx_fail *f = arg;

	f->calls++;
	return slot == f->slot ? f->err : 0;
}

/*
 * The fold over the per-frame results C really writes
 * (xsk_xdev_ext_mech_tx_run(): 0 sent, the failure, then -ECANCELED for every
 * later frame): a -EAGAIN anywhere asks for RETRY, which C takes
 * (xdev_ext_mech_retry_ok()) and resumes after the frames already sent.
 */
static void test_tx_fold_of_c_results(void)
{
	static const int fails[] = { -EAGAIN, -ENXIO, -ENOBUFS, -EINVAL };
	const __u32 n = 6;
	__u64 words[XDEV_EXT_MP_MAX_FRAMES], *sent[XDEV_EXT_MP_MAX_FRAMES];
	__s32 err[XDEV_EXT_MP_MAX_FRAMES];
	struct tx_fail f;
	__u32 slot, i, k;
	int status, v;

	for (i = 0; i < n; i++)
		sent[i] = &words[i];
	for (k = 0; k < sizeof(fails) / sizeof(fails[0]); k++) {
		for (slot = 0; slot < n; slot++) {
			memset(words, 0, sizeof(words));
			f = (struct tx_fail) { .slot = slot, .err = fails[k] };
			status = xsk_xdev_ext_mech_tx_run(1, n, sent, err,
						     tx_fail_xmit, &f);
			EXPECT_EQ(status, fails[k]);
			EXPECT_EQ(f.calls, slot + 1);
			v = XDEV_EXT_MP_NEXT;
			for (i = 0; i < n; i++)
				v = xdev_ext_mp_tx_fold(v, err[i]);
			EXPECT_EQ(v, fails[k] == -EAGAIN ? XDEV_EXT_MP_RETRY :
							  XDEV_EXT_MP_ABORT);
			EXPECT_EQ(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP, 0,
						    status),
				  fails[k] == -EAGAIN);
			if (fails[k] != -EAGAIN)
				continue;
			/* The RETRY of the same batch sends only the rest. */
			f = (struct tx_fail) { .slot = n };
			status = xsk_xdev_ext_mech_tx_run(1, n, sent, err,
						     tx_fail_xmit, &f);
			EXPECT_EQ(status, 0);
			EXPECT_EQ(f.calls, n - slot);
			v = XDEV_EXT_MP_NEXT;
			for (i = 0; i < n; i++)
				v = xdev_ext_mp_tx_fold(v, err[i]);
			EXPECT_EQ(v, XDEV_EXT_MP_NEXT);
		}
	}
}

static void test_nvme(void)
{
	const struct nvme_xdev_ext_mech_bounds bounds = {
		.window_slba = 4096, .window_nlb = 64 * 16,
		.capacity_lbas = 1 << 20, .data_len = 8192,
		.lba_shift = 9, .write = 1,
	};
	struct nvme_xdev_ext_mech_bounds rb = bounds;
	struct nvme_xdev_ext_decoded dec;
	__u8 sqe[XDEV_EXT_MP_NVME_DESC_SIZE];
	__u64 slba;

	/* Group k of the window: 16 LBAs per 8 KiB at 512-byte LBAs. */
	for (__u64 k = 0; k < 64; k++) {
		EXPECT_EQ(xdev_ext_mp_nvme_slba(4096, 1024, 9, 8192, k,
					   XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), 0);
		EXPECT_EQ(slba, 4096 + 16 * k);
		memset(sqe, 0, sizeof(sqe));
		EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, slba, 8192,
					 9), 0);
		EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &dec), 0);
		EXPECT_EQ(dec.slba, slba);
		EXPECT_EQ(dec.nlb, 16);
		EXPECT_EQ(dec.byte_length, 8192);
		EXPECT_EQ(dec.write, 1);
		EXPECT_EQ(xdev_ext_mech_slots_used(sqe, sizeof(sqe), 1), 1);
		/* The same SQE as a READ for a READ stage. */
		memset(sqe, 0, sizeof(sqe));
		EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_FROM_DEVICE, slba, 8192,
					 9), 0);
		rb.write = 0;
		EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &rb, &dec), 0);
		EXPECT_EQ(dec.write, 0);
		EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &dec),
			  -EOPNOTSUPP);
	}
	/* 4 KiB LBAs. */
	EXPECT_EQ(xdev_ext_mp_nvme_slba(0, 1024, 12, 8192, 3,
				   XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), 0);
	EXPECT_EQ(slba, 6);
	/* Past the window: C must refuse it. */
	EXPECT_EQ(xdev_ext_mp_nvme_slba(4096, 1024, 9, 8192, 64,
				   XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), 0);
	memset(sqe, 0, sizeof(sqe));
	EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, slba, 8192, 9), 0);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &dec), -ERANGE);
	/* The window-reject mode is outside for every group. */
	for (__u64 k = 0; k < 64; k++) {
		EXPECT_EQ(xdev_ext_mp_nvme_slba(4096, 1024, 9, 8192, k,
					   XDEV_EXT_MP_NVME_MODE_OUTSIDE, &slba), 0);
		memset(sqe, 0, sizeof(sqe));
		EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, slba, 8192,
					 9), 0);
		EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &dec), -ERANGE);
	}
	EXPECT_EQ(xdev_ext_mp_nvme_slba(4096, 1024, 9, 8192, 0, 7, &slba), -EINVAL);
	EXPECT_EQ(xdev_ext_mp_nvme_slba(4096, 1024, 9, 8191, 0,
				   XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), -EINVAL);
	EXPECT_EQ(xdev_ext_mp_nvme_slba(~0ULL - 8, 1024, 9, 8192, 1,
				   XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), -EOVERFLOW);
	EXPECT_EQ(xdev_ext_mp_nvme_slba(4096, 1024, 9, 8192, ~0ULL >> 2,
				   XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), -EOVERFLOW);

	/* S0: a slot of the window chosen from the request id. */
	for (__u64 id = 0; id < 200; id++) {
		EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(4096, 1024, 9, 8192, id,
					      XDEV_EXT_MP_NVME_MODE_WINDOW, &slba),
			  0);
		EXPECT_EQ(slba, 4096 + 16 * (id % 64));
		memset(sqe, 0, sizeof(sqe));
		EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, slba, 8192,
					 9), 0);
		EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &dec), 0);
		/* And past the window in the window-reject mode. */
		EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(4096, 1024, 9, 8192, id,
					      XDEV_EXT_MP_NVME_MODE_OUTSIDE, &slba),
			  0);
		EXPECT_EQ(slba, 4096 + 1024 + 16 * (id % 64));
		memset(sqe, 0, sizeof(sqe));
		EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, slba, 8192,
					 9), 0);
		EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &dec), -ERANGE);
	}
	EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(4096, 15, 9, 8192, 0,
				      XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), -ERANGE);
	EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(4096, 1024, 9, 0, 0,
				      XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), -EINVAL);
	EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(4096, 1024, 9, 100, 0,
				      XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), -EINVAL);
	EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(4096, 1024, 9, 8192, 0, 2, &slba),
		  -EINVAL);
	/* A nonzero reserved dword is refused. */
	EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(4096, 1024, 9, 8192, 1,
				      XDEV_EXT_MP_NVME_MODE_WINDOW, &slba), 0);
	memset(sqe, 0, sizeof(sqe));
	EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, slba, 8192, 9), 0);
	xdev_ext_mp_nvme_set_reserved(sqe);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &dec), -EPERM);

	EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, 0, 0, 8192, 9), -EINVAL);
	EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, 0, 0, 9), -EINVAL);
	EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, 0, 8193, 9),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, 0, 8192, 8),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, 0,
				 (65536U + 1) << 9, 9), -EMSGSIZE);
	memset(sqe, 0, sizeof(sqe));
	EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe, XDEV_EXT_MP_DIR_TO_DEVICE, 0, 65536U << 9, 9),
		  0);
	EXPECT_EQ(nvme_xdev_ext_sqe_dw(sqe, 12), 0xffff);

	EXPECT_EQ(xdev_ext_mp_nvme_next(XDEV_EXT_MP_SITE_WORKER, 0, 0), XDEV_EXT_MP_NEXT);
	EXPECT_EQ(xdev_ext_mp_nvme_next(XDEV_EXT_MP_SITE_URING_CMD, 0, 0), XDEV_EXT_MP_DONE);
	EXPECT_EQ(xdev_ext_mp_nvme_next(XDEV_EXT_MP_SITE_WORKER, 0x4002, 0),
		  XDEV_EXT_MP_ABORT);
	EXPECT_EQ(xdev_ext_mp_nvme_next(XDEV_EXT_MP_SITE_WORKER, 0, -EIO), XDEV_EXT_MP_ABORT);
	EXPECT_EQ(xdev_ext_mp_nvme_next(XDEV_EXT_MP_SITE_URING_CMD, 2, 0), XDEV_EXT_MP_ABORT);
	EXPECT_TRUE(xdev_ext_mech_ret_legal(XDEV_EXT_MECH_CLASS_NVME,
				       XDEV_EXT_MECH_MEMBER_COMPLETE,
				       XDEV_EXT_MECH_SITE_URING_CMD,
				       xdev_ext_mp_nvme_next(XDEV_EXT_MP_SITE_URING_CMD,
							0, 0)));
}

/* A CE plan from the programs' helpers, checked with the core's span rules. */
static void test_ce_plan(void)
{
	const struct xdev_ext_mech_layout l = {
		.frame_size = 4096, .hdr_room = REF_HDR_ROOM,
		.seg_len = 1432, .group_bytes = 8192,
	};
	struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
	struct xdev_ext_ce_copy_desc d[XDEV_EXT_MECH_MAX_FRAMES];
	const __u64 window = 2 << 20;
	int nr = xdev_ext_mech_layout_frames(&l);
	__u32 index[XDEV_EXT_MECH_MAX_FRAMES];
	struct xdev_ext_ce_plan plan = {};
	struct xdev_ext_ce_geom g;
	__u64 base;

	/* The CE class's geometry: 64 KiB segments, 128 pool chunks. */
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, window, window, 64 << 10, 0,
				   128 * 4096, 0, 4096, 128), 0);
	EXPECT_EQ(nr, 6);
	for (int i = 0; i < nr; i++) {
		index[i] = 100 + i;
		f[i].umem_addr = (__u64)(100 + i) * 4096;
		EXPECT_EQ(xdev_ext_mech_layout_span(&l, (__u32)i, &f[i].data_off,
					       &f[i].data_len), 0);
	}
	for (__u64 k = 0; k < 600; k++) {
		struct xdev_ext_mech_cover c;
		__u64 off;

		/* Later groups must not overwrite an earlier active campaign slot. */
		if (k >= 256) {
			__u64 unchanged = base;
			EXPECT_EQ(xdev_ext_mp_ce_base(k, 8192, window, &base), -ERANGE);
			EXPECT_EQ(base, unchanged);
		} else {
			EXPECT_EQ(xdev_ext_mp_ce_base(k, 8192, window, &base), 0);
			EXPECT_EQ(base, k * 8192);
		}
		/* Recheck full plan geometry even after a rejected new group;
		 * base remains the last admitted exclusive slot. */
		off = base;
		memset(d, 0, sizeof(d));
		for (int i = 0; i < nr; i++) {
			EXPECT_EQ(xdev_ext_mp_ce_entry(&d[i], (__u32)i, (__u32)nr,
						  f[i].data_off, f[i].data_len,
						  off, window, 64 << 10,
						  64 << 10), 0);
			off += f[i].data_len;
		}
		EXPECT_EQ(xdev_ext_mech_slots_used((const __u8 *)d, sizeof(d[0]),
					      XDEV_EXT_MECH_MAX_FRAMES), nr);
		xdev_ext_mech_cover_init(&c, f, (__u32)nr);
		for (int i = 0; i < nr; i++) {
			EXPECT_EQ(xdev_ext_mech_cover_take(&c, d[i].frame_pos,
						      d[i].frame_off,
						      d[i].len), 0);
			EXPECT_TRUE(xdev_ext_mech_span_in(d[i].gpu_off, d[i].len,
						     window));
			EXPECT_TRUE(xdev_ext_mech_span_one_segment(d[i].gpu_off,
							      d[i].len,
							      64 << 10));
			EXPECT_EQ(d[i].flags & ~XDEV_EXT_CE_F_KNOWN_MASK, 0);
			EXPECT_EQ(d[i].flags,
				  i == nr - 1 ? XDEV_EXT_CE_F_COMPLETION_POINT : 0);
			for (int j = 0; j < i; j++)
				EXPECT_FALSE(xdev_ext_mech_spans_overlap(
					d[j].gpu_off, d[j].len, d[i].gpu_off,
					d[i].len));
		}
		EXPECT_TRUE(xdev_ext_mech_cover_done(&c));
		/* The plan the CE class admits (io_uring/xdev_ext_mech_ce_core.h). */
		EXPECT_EQ(xdev_ext_ce_plan_check(&g, f, index, (__u32)nr, d,
					    (__u32)nr, &plan), 0);
		EXPECT_EQ(plan.total, l.group_bytes);
		EXPECT_EQ(plan.host_off[0], 100 * 4096 + REF_HDR_ROOM);
	}
	EXPECT_EQ(xdev_ext_mp_ce_base(0, 8192, 8191, &base), -ERANGE);
	EXPECT_EQ(xdev_ext_mp_ce_base(0, 0, window, &base), -ERANGE);
	EXPECT_EQ(xdev_ext_mp_ce_entry(d, 0, 1, 360, 0, 0, window, 0, 0), -EINVAL);
	EXPECT_EQ(xdev_ext_mp_ce_entry(d, 0, 1, 360, 100, window - 99, window, 0,
				  0), -ERANGE);
	EXPECT_EQ(xdev_ext_mp_ce_entry(d, 0, 1, 360, 100, (64 << 10) - 50, window,
				  64 << 10, 0), -EXDEV);
	EXPECT_EQ(xdev_ext_mp_ce_entry(d, 0, 1, 360, 4000, 0, window, 0, 2048),
		  -EMSGSIZE);
	EXPECT_EQ(xdev_ext_mp_ce_entry(d, 0, 1, 360, 4000, 0, window, 0, 0), 0);
	EXPECT_EQ(xdev_ext_mp_ce_entry(d, 0, 1, 360, 4000, ~0ULL - 10, ~0ULL, 0, 0),
		  -ERANGE);

	EXPECT_EQ(xdev_ext_mp_ce_next(XDEV_EXT_CE_OK), XDEV_EXT_MP_NEXT);
	EXPECT_EQ(xdev_ext_mp_ce_next(XDEV_EXT_CE_PRE_SUBMIT_FAILED), XDEV_EXT_MP_RETRY);
	EXPECT_EQ(xdev_ext_mp_ce_next(XDEV_EXT_CE_AMBIGUOUS), XDEV_EXT_MP_ABORT);
	EXPECT_EQ(xdev_ext_mp_ce_next(77), XDEV_EXT_MP_ABORT);
	EXPECT_TRUE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_CE, 0,
				      XDEV_EXT_CE_PRE_SUBMIT_FAILED));
}

int main(void)
{
	test_byte_helpers();
	test_seg_limit();
	test_rx_parse_valid();
	test_rx_parse_mutations();
	test_rx_parse_framing();
	test_crc_convention();
	test_rx_order_cases();
	test_rx_order_fields();
	test_rx_order_session();
	test_rx_order_differential();
	test_tx_encode();
	test_tx_encode_rejects();
	test_tx_desc_and_complete();
	test_tx_fold_of_c_results();
	test_nvme();
	test_ce_plan();

	if (failures) {
		fprintf(stderr, "FAIL: %u of %u checks\n", failures, checks);
		return 1;
	}
	printf("PASS: %u XDEV_EXT mechanism program checks\n", checks);
	return 0;
}

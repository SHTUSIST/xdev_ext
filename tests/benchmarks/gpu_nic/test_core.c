// SPDX-License-Identifier: GPL-2.0
/* Host checks of gpu_nic_core.h: plan, NXP wire, CRC32C, receiver and slot oracles. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "gpu_nic_core.h"

static unsigned int checks, failures;

#define EXPECT(value) do {                                                     \
	checks++;                                                              \
	if (!(value)) {                                                        \
		fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #value);    \
		failures++;                                                     \
	}                                                                       \
} while (0)

static void test_plan(void)
{
	struct gn_plan p;

	EXPECT(!gn_plan_init(&p, 64, 10, 1500, 8, 16));
	EXPECT(p.l.group_bytes == 64 && p.frames == 1 && p.groups == 10);
	EXPECT(p.l.seg_len == 1432 && p.l.hdr_room == 360 && p.l.frame_size == 4096);
	EXPECT(!gn_plan_init(&p, 4096, 1, 1500, 1, 1));
	EXPECT(p.l.group_bytes == 4096 && p.frames == 3);
	EXPECT(!gn_plan_init(&p, 4ULL << 20, 2, 1500, 64, 64));
	EXPECT(p.l.group_bytes == 32768 && p.frames == 23 && p.groups == 256);
	EXPECT(!gn_plan_init(&p, GN_INGEST_MESSAGE, 3, 1500, 8, 8));
	EXPECT(p.l.group_bytes == 32768 && p.groups == 36);
	/* A jumbo link: 3736-byte segments of 4 KiB frames, 64 KiB groups. */
	EXPECT(!gn_plan_init(&p, GN_EGRESS_MESSAGE, 1, 9000, 8, 8));
	EXPECT(p.l.seg_len == 3736 && p.l.group_bytes == 65536 && p.frames == 18);
	EXPECT(gn_plan_init(&p, 32, 1, 1500, 1, 1) == -EINVAL);
	EXPECT(gn_plan_init(&p, (4ULL << 20) + 8, 1, 1500, 1, 1) == -EINVAL);
	EXPECT(gn_plan_init(&p, 100, 1, 1500, 1, 1) == -EINVAL);
	EXPECT(gn_plan_init(&p, 40968, 1, 1500, 1, 1) == -ERANGE);
	EXPECT(gn_plan_init(&p, 4096, 1, 1500, 0, 1) == -EINVAL);
	EXPECT(gn_plan_init(&p, 4096, 1, 1500, 65, 1) == -EINVAL);
	EXPECT(gn_plan_init(&p, 4096, 0, 1500, 1, 1) == -EINVAL);
	EXPECT(gn_plan_init(&p, 4096, 1, 60, 1, 1) == -EINVAL);
	EXPECT(gn_pow2_floor(1) == 1 && gn_pow2_floor(45824) == 32768 && gn_pow2_floor(0) == 0);
}

static void test_crc(void)
{
	static const unsigned char check[] = "123456789";
	unsigned char buf[4096];
	unsigned int i;

	/* The standard CRC-32C check value with the usual inversions. */
	EXPECT(~gn_crc32c(~0U, check, 9) == 0xe3069283U);
	EXPECT(~gn_crc32c_sw(~0U, check, 9) == 0xe3069283U);
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (unsigned char)(i * 131 + 7);
	for (i = 0; i < 64; i++)
		EXPECT(gn_crc32c(i * 977, buf + i, sizeof(buf) - 2 * i) ==
		       gn_crc32c_sw(i * 977, buf + i, sizeof(buf) - 2 * i));
}

/* A baseline's packet is what the session's own RX parser accepts. */
static void test_wire_interop(void)
{
	unsigned char frame[4096], *pkt, payload[1432], nxp[40];
	struct xdev_ext_mech_peer tx_peer, rx_peer;
	struct xdev_ext_mp_segment seg, parsed;
	struct xdev_ext_mp_rx_cfg cfg;
	struct xdev_ext_mp_tx_seg s;
	struct gn_plan p;
	uint32_t off, len;
	__u16 csum;

	EXPECT(!gn_plan_init(&p, 4096, 1, 1500, 1, 4));
	memset(&tx_peer, 0, sizeof(tx_peer));
	memcpy(tx_peer.local_mac, "\x02\0\0\0\0\x01", 6);
	memcpy(tx_peer.peer_mac, "\x02\0\0\0\0\x02", 6);
	tx_peer.local_ip = htonl(0xc0000201);
	tx_peer.peer_ip = htonl(0xc0000202);
	tx_peer.local_port = htons(54321);
	tx_peer.peer_port = htons(12345);
	rx_peer = tx_peer;
	memcpy(rx_peer.local_mac, tx_peer.peer_mac, 6);
	memcpy(rx_peer.peer_mac, tx_peer.local_mac, 6);
	rx_peer.local_ip = tx_peer.peer_ip;
	rx_peer.peer_ip = tx_peer.local_ip;
	rx_peer.local_port = tx_peer.peer_port;
	rx_peer.peer_port = tx_peer.local_port;

	gn_segment(&p, 1, &off, &len);
	EXPECT(off == 1432 && len == 1432);
	xg_fill(payload, gn_group_offset(&p, 2) + off, len, 5);
	memset(frame, 0, sizeof(frame));
	/* The receiver's payload sits at hdr_room; the packet starts 82 bytes earlier. */
	pkt = frame + p.l.hdr_room - XDEV_EXT_MP_PKT_HDR_LEN;
	s = (struct xdev_ext_mp_tx_seg) { .session_id = 270019, .generation = 3,
		.total_len = 4096, .relative_offset = off, .payload_len = len,
		.index = 1, .count = 3 };
	EXPECT(!xdev_ext_mp_tx_encode(pkt, &tx_peer, &s));
	csum = xdev_ext_mp_ip_csum(pkt + XDEV_EXT_MP_ETH_LEN);
	xdev_ext_mp_put_be16(pkt + XDEV_EXT_MP_ETH_LEN + 10, csum);
	memcpy(frame + p.l.hdr_room, payload, len);
	xdev_ext_mp_put_be32(pkt + XDEV_EXT_MP_NXP_OFF + XDEV_EXT_MP_NXP_CSUM_OFF,
			gn_nxp_crc(pkt + XDEV_EXT_MP_NXP_OFF, payload, len));
	cfg = (struct xdev_ext_mp_rx_cfg) { .session_id = 270019, .mtu = 1500,
		.frame_size = 4096, .hdr_room = p.l.hdr_room, .seg_len = p.l.seg_len,
		.group_bytes = 4096 };
	EXPECT(xdev_ext_mp_rx_parse(pkt, p.l.hdr_room - XDEV_EXT_MP_PKT_HDR_LEN,
			       XDEV_EXT_MP_PKT_HDR_LEN + len, &rx_peer, &cfg, &seg) ==
	       XDEV_EXT_MP_RX_SEGMENT);
	EXPECT(seg.generation == 3 && seg.index == 1 && seg.payload_len == len);

	/* The header helper writes what the session's TX program writes. */
	EXPECT(!gn_nxp_header(nxp, &p, 270019, 2, 1));
	EXPECT(!memcmp(nxp, pkt + XDEV_EXT_MP_NXP_OFF, 36));
	EXPECT(!gn_nxp_parse(nxp, 40 + len, &p, 270019, &parsed));
	EXPECT(parsed.generation == 3 && parsed.index == 1 && parsed.relative_offset == off);
	EXPECT(gn_nxp_parse(nxp, 40 + len, &p, 270018, &parsed) == -EPROTO);
	EXPECT(gn_nxp_parse(nxp, 40 + len - 8, &p, 270019, &parsed) == -EPROTO);
	EXPECT(gn_nxp_header(nxp, &p, 270019, 2, 3) == -EINVAL);
	EXPECT(gn_nxp_header(nxp, &p, 0, 2, 0) == -EINVAL);
	nxp[6] = XDEV_EXT_MP_NXP_DIR_READ;
	EXPECT(gn_nxp_parse(nxp, 40 + len, &p, 270019, &parsed) == -EPROTO);

	/* One payload pass yields both the protocol verdict and the payload CRC. */
	{
		struct gn_crc_shift m;
		unsigned char zeros[1432], scratch[1432];
		uint32_t got;

		gn_crc_shift_init(&m, len, zeros);
		EXPECT(gn_segment_check(pkt + XDEV_EXT_MP_NXP_OFF, frame + p.l.hdr_room, &m, &got));
		EXPECT(got == gn_payload_crc(&p, 2, 1, 5, scratch));
		EXPECT(got != gn_payload_crc(&p, 1, 1, 5, scratch));
		EXPECT(got != gn_payload_crc(&p, 2, 0, 5, scratch));
		frame[p.l.hdr_room + 100] ^= 4;
		EXPECT(!gn_segment_check(pkt + XDEV_EXT_MP_NXP_OFF, frame + p.l.hdr_room, &m, &got));
		EXPECT(got != gn_payload_crc(&p, 2, 1, 5, scratch));
	}
}

static void test_slots(void)
{
	struct gn_plan p;
	unsigned char *slots, seen[8];
	uint64_t used;
	uint32_t s;

	EXPECT(!gn_plan_init(&p, 4096, 2, 1500, 4, 8));
	slots = malloc(4 * 4096);
	EXPECT(slots != NULL);
	if (!slots)
		return;
	for (s = 0; s < 4; s++)
		xg_fill(slots + s * 4096, s * 4096, 4096, ~9U);
	/* Two groups ran: two slots hold blocks, two keep the sentinel. */
	xg_fill(slots + 3 * 4096, gn_group_offset(&p, 0), 4096, 9);
	xg_fill(slots + 1 * 4096, gn_group_offset(&p, 1), 4096, 9);
	EXPECT(!gn_check_slots(slots, &p, 9, seen, &used) && used == 2);
	xg_fill(slots + 1 * 4096, gn_group_offset(&p, 0), 4096, 9);
	EXPECT(gn_check_slots(slots, &p, 9, seen, &used) == -EEXIST);
	xg_fill(slots + 1 * 4096, gn_group_offset(&p, 1), 4096, 9);
	slots[2 * 4096 + 17] ^= 1;
	EXPECT(gn_check_slots(slots, &p, 9, seen, &used) == -EBADMSG);
	xg_fill(slots + 2 * 4096, 2 * 4096, 4096, ~9U);
	xg_fill(slots + 1 * 4096, 1 * 4096, 4096, ~9U);
	EXPECT(gn_check_slots(slots, &p, 9, seen, &used) == -ENODATA);
	free(slots);
}

/* Copy calls per group: a 2D copy of the full segments plus one for a short tail. */
static void test_group_copy(void)
{
	struct gn_plan p;
	struct gn_group_copy c;
	uint64_t chunks[23];
	uint32_t i;

	EXPECT(!gn_plan_init(&p, 4ULL << 20, 1, 1500, 4, 4));
	c = gn_group_copy(&p);
	EXPECT(c.rows == 22 && c.width == 1432 && c.tail == 32768 - 22 * 1432 && c.calls == 2);
	EXPECT(!gn_plan_init(&p, 64, 1, 1500, 4, 4));
	c = gn_group_copy(&p);
	EXPECT(c.rows == 0 && c.tail == 64 && c.calls == 1);
	/* A jumbo link: 65536 = 17 x 3736 + 2024. */
	EXPECT(!gn_plan_init(&p, 65536, 1, 9000, 4, 4));
	c = gn_group_copy(&p);
	EXPECT(c.rows == 17 && c.tail == 2024 && c.calls == 2);
	EXPECT(!gn_plan_init(&p, 4ULL << 20, 1, 1500, 4, 4));
	for (i = 0; i < 23; i++)
		chunks[i] = 4096ULL * (100 + i) + 360;
	EXPECT(gn_chunks_strided(chunks, 23, 4096));
	EXPECT(!gn_chunks_strided(chunks, 23, 2048));
	chunks[7] += 4096;
	EXPECT(!gn_chunks_strided(chunks, 23, 4096));
	chunks[7] -= 4096 - 8;		/* same chunk, another data offset */
	EXPECT(!gn_chunks_strided(chunks, 23, 4096));
	EXPECT(gn_chunks_strided(chunks, 1, 4096));
	EXPECT(!gn_chunks_strided(chunks, 0, 4096));
}

int main(void)
{
	test_plan();
	test_group_copy();
	test_crc();
	test_wire_interop();
	test_slots();
	printf("gpu_nic core: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}

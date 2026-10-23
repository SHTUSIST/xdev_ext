/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Host test of nnb_wire.h against the product's own NXP2 encoder and session
 * layout (xdev_ext_mech_prog.h / xdev_ext_mech_ctl_core.h).  Not a device,
 * provider or performance test.  With --vectors it prints generator samples
 * that test_offline.py compares with its independent Python generator.
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
#include "nnb_wire.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "test_wire: line %d: %s\n", __LINE__, #c); \
	return 1; } } while (0)

static int check_geometry(uint32_t mtu)
{
	for (uint32_t size = NNB_MIN_SIZE; size <= NNB_MAX_SIZE; size <<= 1) {
		struct xdev_ext_mech_layout l;
		struct nnb_geom g;
		uint32_t limit, sum = 0, i;

		CHECK(!nnb_geom_init(&g, mtu, size, 64ULL << 20));
		CHECK(!xdev_ext_mp_seg_limit(mtu, 4096, XDEV_EXT_MECH_CTL_HDR_ROOM, &limit));
		CHECK(limit == g.seg && XDEV_EXT_MECH_CTL_HDR_ROOM == NNB_HDR_ROOM);
		/* The session batch the ctl tool would create for this group. */
		CHECK(!xdev_ext_mech_ctl_layout(mtu, g.group, &l));
		CHECK((uint32_t)xdev_ext_mech_layout_frames(&l) == g.dgrams);
		CHECK(g.group <= size && size % g.group == 0 && g.group % 4096 == 0);
		CHECK(g.dgrams <= NNB_MAX_FRAMES && g.groups_per_unit * g.group == size);
		CHECK(g.gso_dgrams * (NNB_HDR_LEN + g.seg) <= NNB_GSO_BYTES || g.gso_dgrams == 1);
		for (i = 0; i < g.dgrams; i++) {
			uint32_t rel, len, off, slen;

			nnb_dgram(&g, i, &rel, &len);
			CHECK(!xdev_ext_mech_layout_span(&l, i, &off, &slen));
			CHECK(off == NNB_HDR_ROOM && slen == len && rel == sum);
			sum += len;
		}
		CHECK(sum == g.group);
		CHECK(g.window_groups * g.group == g.window_bytes);
		CHECK(nnb_gen_offset(&g, 1) == 0 && nnb_gen_offset(&g, g.window_groups + 1) == 0);
		CHECK(nnb_gen_offset(&g, 2) == g.group);
	}
	return 0;
}

static int check_header(void)
{
	struct xdev_ext_mech_peer peer = { .local_mac = { 1 }, .peer_mac = { 2 } };
	struct xdev_ext_mp_tx_seg ts;
	unsigned char pkt[NNB_PKT_HDR_LEN], hdr[NNB_HDR_LEN], dgram[NNB_HDR_LEN + 4096];
	struct nnb_geom g;
	struct nnb_seg s;
	uint32_t rel = 0, len = 0;

	CHECK(!nnb_geom_init(&g, 1500, 1U << 20, 64ULL << 20));
	for (uint32_t j = 0; j < g.dgrams; j++) {
		nnb_dgram(&g, j, &rel, &len);
		ts = (struct xdev_ext_mp_tx_seg){ .session_id = 0x0102030405060708ULL,
			.generation = 77, .total_len = g.group, .relative_offset = rel,
			.payload_len = len, .index = (uint16_t)j, .count = (uint16_t)g.dgrams };
		CHECK(!xdev_ext_mp_tx_encode(pkt, &peer, &ts));
		nnb_hdr_encode(hdr, &g, 0x0102030405060708ULL, 77, j);
		CHECK(!memcmp(pkt + 42, hdr, NNB_HDR_LEN));
		memcpy(dgram, hdr, NNB_HDR_LEN);
		CHECK(!nnb_hdr_parse(dgram, NNB_HDR_LEN + len, &g, &s));
		CHECK(s.session == 0x0102030405060708ULL && s.gen == 77 && s.index == j &&
		      s.rel == rel && s.len == len);
		CHECK(nnb_hdr_parse(dgram, NNB_HDR_LEN + len + 1, &g, &s) == -EPROTO);
	}
	nnb_hdr_set_gen(hdr, 78);
	CHECK(!nnb_hdr_parse(hdr, NNB_HDR_LEN + len, &g, &s) && s.gen == 78);
	hdr[36] = 1;	/* nobody computes a checksum; a nonzero one is not NXP2-bench */
	CHECK(nnb_hdr_parse(hdr, NNB_HDR_LEN + len, &g, &s) == -EPROTO);
	hdr[36] = 0;
	hdr[23] ^= 1;	/* count */
	CHECK(nnb_hdr_parse(hdr, NNB_HDR_LEN + len, &g, &s) == -EPROTO);
	hdr[0] = 0;
	CHECK(nnb_hdr_parse(hdr, NNB_HDR_LEN + len, &g, &s) == -ENOMSG);
	return 0;
}

static int check_generator(void)
{
	unsigned char a[4099], b[4099];

	for (unsigned off = 0; off < 9; off++) {
		nnb_gen_fill(7, off, a, sizeof(a));
		for (size_t i = 0; i < sizeof(a); i++)
			b[i] = nnb_gen_byte(7, off + i);
		CHECK(!memcmp(a, b, sizeof(a)));
		CHECK(nnb_gen_check(7, off, a, sizeof(a)) == -1);
	}
	a[4000] ^= 1;
	CHECK(nnb_gen_check(7, 8, a, sizeof(a)) == 4000);
	nnb_gen_fill(8, 0, b, 64);
	nnb_gen_fill(7, 0, a, 64);
	CHECK(memcmp(a, b, 64));	/* the seed matters */
	return 0;
}

static int check_refusals(void)
{
	struct nnb_geom g;

	CHECK(nnb_geom_init(&g, 1500, 2048, 64ULL << 20) == -EINVAL);
	CHECK(nnb_geom_init(&g, 1500, 3U << 12, 64ULL << 20) == -EINVAL);
	CHECK(nnb_geom_init(&g, 1500, 8U << 20, 64ULL << 20) == -EINVAL);
	CHECK(nnb_geom_init(&g, 1500, 4096, (64ULL << 20) + 4096) == -EINVAL);
	CHECK(nnb_geom_init(&g, 60, 4096, 64ULL << 20) == -EINVAL);
	CHECK(nnb_geom_init(&g, 190, 4096, 64ULL << 20) == -EMSGSIZE);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 5 && !strcmp(argv[1], "--geometry")) {
		struct nnb_geom g;
		int ret = nnb_geom_init(&g, (uint32_t)strtoul(argv[2], NULL, 10),
					(uint32_t)strtoul(argv[3], NULL, 10), strtoull(argv[4], NULL, 10));

		if (ret) {
			printf("{\"error\":%d}\n", ret);
			return 0;
		}
		printf("{\"seg\":%u,\"group\":%u,\"dgrams\":%u,\"groups_per_unit\":%u,"
		       "\"window_units\":%" PRIu64 ",\"window_groups\":%" PRIu64 "}\n", g.seg, g.group,
		       g.dgrams, g.groups_per_unit, g.window_units, g.window_groups);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "--vectors")) {
		static const uint64_t offs[] = { 0, 1, 7, 8, 4095, 1ULL << 20, (64ULL << 20) - 1 };

		for (unsigned i = 0; i < sizeof(offs) / sizeof(offs[0]); i++)
			printf("%" PRIu64 " %u\n", offs[i], nnb_gen_byte(0x5eedULL, offs[i]));
		return 0;
	}
	if (check_geometry(1500) || check_geometry(9000) || check_geometry(4200) ||
	    check_header() || check_generator() || check_refusals())
		return 1;
	puts("nnb wire: geometry=ctl layout, header=xdev_ext_mp_tx_encode, generator, refusals PASS");
	return 0;
}

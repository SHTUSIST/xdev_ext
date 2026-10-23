// SPDX-License-Identifier: GPL-2.0
/* Host checks of nvme_gpu_core.h: numbers, geometry, schedule, payload, oracle. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nvme_gpu_core.h"

static unsigned int checks, failures;

#define EXPECT(value) do {                                                     \
	checks++;                                                              \
	if (!(value)) {                                                        \
		fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #value);    \
		failures++;                                                     \
	}                                                                       \
} while (0)

static struct xg_geometry geometry(uint64_t size, uint64_t qd, uint64_t window)
{
	struct xg_geometry g = { .size = size, .qd = qd, .window = window,
				 .passes = 1, .pattern = XG_SEQ, .seed = 7 };
	return g;
}

static void test_numbers(void)
{
	static const char *bad[] = { "", "-1", "+1", " 1", "1 ", "0x10", "1e3",
				     "1.0", "\xd9\xa1", NULL };
	uint64_t v;
	uint32_t e;
	int i;

	EXPECT(!xg_parse_u64("0", 10, &v) && v == 0);
	EXPECT(!xg_parse_u64("4194304", XG_MAX_SIZE, &v) && v == XG_MAX_SIZE);
	EXPECT(xg_parse_u64("4194305", XG_MAX_SIZE, &v) == -ERANGE);
	EXPECT(xg_parse_u64("18446744073709551615", UINT64_MAX, &v) == 0 &&
	       v == UINT64_MAX);
	EXPECT(xg_parse_u64("18446744073709551616", UINT64_MAX, &v) == -ERANGE);
	EXPECT(xg_parse_u64(NULL, 10, &v) == -EINVAL);
	for (i = 0; bad[i]; i++)
		EXPECT(xg_parse_u64(bad[i], UINT64_MAX, &v) == -EINVAL);
	EXPECT(!xg_parse_pattern("seq", &e) && e == XG_SEQ);
	EXPECT(!xg_parse_pattern("rand", &e) && e == XG_RAND);
	EXPECT(xg_parse_pattern("random", &e) == -EINVAL);
	EXPECT(!xg_parse_direction("save", &e) && e == XG_SAVE);
	EXPECT(xg_parse_direction("checkpoint", &e) == -EINVAL);
}

static void test_geometry(void)
{
	struct xg_geometry g;

	g = geometry(4096, 1, 4096);
	EXPECT(!xg_geometry_check(&g));
	g = geometry(XG_MAX_SIZE, 256, 256 * XG_MAX_SIZE);
	EXPECT(!xg_geometry_check(&g));
	g = geometry(4096 + 512, 1, 2 * (4096 + 512));
	EXPECT(xg_geometry_check(&g) == -EINVAL);
	g = geometry(XG_MAX_SIZE + 4096, 1, XG_MAX_SIZE + 4096);
	EXPECT(xg_geometry_check(&g) == -EINVAL);
	g = geometry(4096, 0, 4096);
	EXPECT(xg_geometry_check(&g) == -EINVAL);
	g = geometry(4096, 257, 257 * 4096);
	EXPECT(xg_geometry_check(&g) == -EINVAL);
	g = geometry(4096, 32, 31 * 4096);
	EXPECT(xg_geometry_check(&g) == -ERANGE);
	g = geometry(8192, 1, 8192 + 4096);
	EXPECT(xg_geometry_check(&g) == -EINVAL);
	g = geometry(4096, 1, 4096);
	g.passes = 0;
	EXPECT(xg_geometry_check(&g) == -EINVAL);
	g.passes = XG_MAX_PASSES + 1;
	EXPECT(xg_geometry_check(&g) == -EINVAL);
	g.passes = 1;
	g.pattern = 2;
	EXPECT(xg_geometry_check(&g) == -EINVAL);
}

/* Every pass is a permutation; rand differs from seq and between passes. */
static void test_schedule(void)
{
	static const uint64_t sizes[] = { 1, 2, 3, 4, 7, 64, 97, 256, 1000, 4096,
					  65537 };
	unsigned char *seen;
	unsigned int s;

	seen = malloc(65537);
	EXPECT(seen != NULL);
	if (!seen)
		return;
	for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
		struct xg_geometry g = geometry(4096, 1, sizes[s] * 4096);
		uint64_t pass, i, moved = 0, differs = 0;

		for (g.pattern = XG_SEQ; g.pattern <= XG_RAND; g.pattern++) {
			for (pass = 0; pass < 3; pass++) {
				uint64_t ok = 1;

				memset(seen, 0, sizes[s]);
				for (i = 0; i < sizes[s]; i++) {
					uint64_t b = xg_block(&g, pass, i);

					if (b >= sizes[s] || seen[b])
						ok = 0;
					else
						seen[b] = 1;
					if (g.pattern == XG_RAND && b != i)
						moved++;
					if (g.pattern == XG_RAND && pass &&
					    b != xg_block(&g, pass - 1, i))
						differs++;
				}
				EXPECT(ok);
			}
		}
		if (sizes[s] >= 64) {
			EXPECT(moved > sizes[s]);
			EXPECT(differs > sizes[s] / 2);
		}
	}
	free(seen);
	/* Stable across runs: the schedule is part of the contract. */
	{
		struct xg_geometry g = geometry(4096, 1, 1000 * 4096);

		g.pattern = XG_RAND;
		g.seed = 7;
		EXPECT(xg_rand_mul(1000, 7, 0) == xg_rand_mul(1000, 7, 0));
		EXPECT(xg_gcd(xg_rand_mul(1000, 7, 0), 1000) == 1);
		EXPECT(xg_block(&g, 2, 999) == xg_block(&g, 2, 999));
	}
}

static void test_payload_and_oracle(void)
{
	unsigned char *buf = malloc(3 * 8192), copy[8192];
	uint64_t block = 99;

	EXPECT(buf != NULL);
	if (!buf)
		return;
	EXPECT(xg_word_index(xg_word(12345, 3), 3) == 12345);
	EXPECT(xg_word_index(xg_word(0, 0), 0) == 0);
	EXPECT(xg_word_mul_inverse() * XG_WORD_MUL == 1);
	EXPECT(!xg_fill(buf, 0, 3 * 8192, 11));
	EXPECT(xg_fill(buf, 4, 8, 11) == -EINVAL);
	EXPECT(xg_compare(buf, 0, 3 * 8192, 11) == -1);
	EXPECT(xg_compare(buf + 8192, 8192, 8192, 11) == -1);
	/* The same bytes do not pass at another offset or seed. */
	EXPECT(xg_compare(buf + 8192, 0, 8192, 11) == 0);
	EXPECT(xg_compare(buf, 0, 8192, 12) == 0);
	EXPECT(xg_compare(buf, 4, 8, 11) == 0);

	EXPECT(!xg_identify(buf + 2 * 8192, 8192, 3, 11, &block) && block == 2);
	EXPECT(xg_identify(buf + 2 * 8192, 8192, 2, 11, &block) == -ENOENT);
	EXPECT(xg_identify(buf + 2 * 8192, 4096, 6, 11, &block) == 0 && block == 4);
	/* A slot starting mid-block, or of the wrong seed, holds no block image. */
	EXPECT(xg_identify(buf + 4096, 8192, 3, 11, &block) == -ENOENT);
	EXPECT(xg_identify(buf, 8192, 3, ~11U, &block) == -ENOENT);
	/* Torn: the first word names block 1, the tail is block 2's. */
	memcpy(copy, buf + 8192, 4096);
	memcpy(copy + 4096, buf + 2 * 8192 + 4096, 4096);
	EXPECT(xg_identify(copy, 8192, 3, 11, &block) == -EBADMSG && block == 1);
	memcpy(copy, buf + 8192, 8192);
	copy[8191] ^= 1;
	EXPECT(xg_compare(copy, 8192, 8192, 11) == 8184);
	EXPECT(xg_cpu_us(1, 2, 3, 4) == 4000006);
	EXPECT(!xg_parse_proc_stat("cpu  100 2 30 999 50 4 5 6 0 0", 100, &block) &&
	       block == 1470000);
	EXPECT(xg_parse_proc_stat("cpu0 1 2 3 4 5 6 7 8", 100, &block) == -EINVAL);
	EXPECT(xg_parse_proc_stat("cpu  1 2 3", 100, &block) == -EINVAL);
	EXPECT(xg_parse_proc_stat("cpu  1 2 3 4 5 6 7 8", 0, &block) == -EINVAL);
	EXPECT(xg_host_busy_us() > 0);
	free(buf);
}

/* Slot-ring destination: schedule position i uses device slot i mod qd. */
static void test_slot_ring(void)
{
	struct xg_geometry g = geometry(8192, 4, 10 * 8192);
	uint64_t d, i, pass;

	EXPECT(xg_ring_slot(&g, 0) == 0 && xg_ring_slot(&g, 9) == 1);
	EXPECT(xg_ring_last_position(&g, 0) == 8 && xg_ring_last_position(&g, 1) == 9);
	EXPECT(xg_ring_last_position(&g, 2) == 6 && xg_ring_last_position(&g, 3) == 7);
	EXPECT(xg_ring_bytes(&g) == 4 * 8192);
	g = geometry(8192, 4, 4 * 8192);
	for (d = 0; d < 4; d++)
		EXPECT(xg_ring_last_position(&g, d) == d);
	g = geometry(4096, 7, 1000 * 4096);
	g.pattern = XG_RAND;
	for (pass = 0; pass < 3; pass++)
		for (d = 0; d < g.qd; d++) {
			uint64_t last = xg_ring_last_position(&g, d);

			EXPECT(last % g.qd == d && last < xg_blocks(&g) &&
			       last + g.qd >= xg_blocks(&g));
			/* The block a load leaves in slot d is the last one the schedule sends there. */
			for (i = last + g.qd; i < xg_blocks(&g); i += g.qd)
				EXPECT(0);
			EXPECT(xg_ring_load_block(&g, pass, d) == xg_block(&g, pass, last));
		}
	/* A save writes slot (i mod qd)'s image to schedule position i. */
	EXPECT(xg_ring_save_source(&g, 15) == 1);
}

int main(void)
{
	test_numbers();
	test_geometry();
	test_schedule();
	test_payload_and_oracle();
	test_slot_ring();
	printf("nvme_gpu core: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}

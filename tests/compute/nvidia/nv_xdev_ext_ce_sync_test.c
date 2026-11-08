/* SPDX-License-Identifier: MIT */
/*
 * DMA-API ownership transfer of the copy-engine backend: a request syncs only
 * the pieces of the mapped host segments its plan entries cover.  The lookup
 * is checked against the former whole-table walk (every segment against every
 * entry) on fixed edge cases and on random segment tables and plans, and the
 * number of segments it visits must not grow with the size of the pool.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kernel-open/nvidia/nv-xdev_ext-ce-sync.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(expected, actual) do {                                  \
	long long expected_ = (long long)(expected);                         \
	long long actual_ = (long long)(actual);                             \
	checks++;                                                             \
	if (expected_ != actual_) {                                          \
		fprintf(stderr, "%s:%d expected %lld got %lld\n",           \
			__FILE__, __LINE__, expected_, actual_);                 \
		failures++;                                                     \
	}                                                                    \
} while (0)

#define MAX_SEGS 512U
#define MAX_ENTRIES 64U
#define MAX_PIECES (MAX_SEGS * MAX_ENTRIES)

struct entry { uint64_t off, len; };
struct piece { uint32_t seg; uint64_t seg_off, len; };

static struct piece got[MAX_PIECES], want[MAX_PIECES];

/* The former nv_xdev_ext_ce_sync() body: every segment against every entry. */
static unsigned int oracle(const struct nv_xdev_ext_ce_seg *s, uint32_t n,
			   const struct entry *x, uint32_t nx, struct piece *out)
{
	unsigned int count = 0;
	uint64_t base = 0;
	uint32_t i, j;

	for (i = 0; i < n; i++) {
		uint64_t end = s[i].end;

		for (j = 0; j < nx; j++) {
			uint64_t start = x[j].off > base ? x[j].off : base;
			uint64_t stop = x[j].off + x[j].len < end ? x[j].off + x[j].len : end;

			if (start >= stop)
				continue;
			out[count++] = (struct piece) { i, start - base, stop - start };
		}
		base = end;
	}
	return count;
}

/* Production lookup; *visits counts segments examined by seg_next. */
static unsigned int lookup(const struct nv_xdev_ext_ce_seg *s, uint32_t n,
			   const struct entry *x, uint32_t nx, struct piece *out,
			   unsigned int *visits)
{
	unsigned int count = 0;
	uint32_t j;

	for (j = 0; j < nx; j++) {
		nv_xdev_ext_gpu_u64 off = x[j].off, stop = x[j].off + x[j].len;
		nv_xdev_ext_gpu_u32 seg = nv_xdev_ext_ce_seg_first(s, n, off);
		struct nv_xdev_ext_ce_piece p;

		while (nv_xdev_ext_ce_seg_next(s, n, &seg, &off, stop, &p)) {
			out[count++] = (struct piece) { p.seg, p.seg_off, p.len };
			if (visits)
				(*visits)++;
		}
	}
	return count;
}

static int piece_cmp(const void *a, const void *b)
{
	const struct piece *x = a, *y = b;

	if (x->seg != y->seg)
		return x->seg < y->seg ? -1 : 1;
	if (x->seg_off != y->seg_off)
		return x->seg_off < y->seg_off ? -1 : 1;
	if (x->len != y->len)
		return x->len < y->len ? -1 : 1;
	return 0;
}

static void expect_same(const struct nv_xdev_ext_ce_seg *s, uint32_t n,
			const struct entry *x, uint32_t nx, int line)
{
	unsigned int a = lookup(s, n, x, nx, got, NULL);
	unsigned int b = oracle(s, n, x, nx, want);

	qsort(got, a, sizeof(got[0]), piece_cmp);
	qsort(want, b, sizeof(want[0]), piece_cmp);
	checks++;
	if (a != b || memcmp(got, want, (size_t)a * sizeof(got[0]))) {
		fprintf(stderr, "%s:%d lookup gave %u pieces, whole-table walk %u\n",
			__FILE__, line, a, b);
		failures++;
	}
}

static uint64_t rng = 0x9e3779b97f4a7c15ULL;
static uint64_t next_random(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng;
}

/* Page-aligned segments of 1..max_pages pages; returns the total bytes. */
static uint64_t random_table(struct nv_xdev_ext_ce_seg *s, uint32_t n,
			     unsigned int max_pages)
{
	uint64_t end = 0;
	uint32_t i;

	for (i = 0; i < n; i++) {
		end += (1 + next_random() % max_pages) * 4096ULL;
		s[i].end = end;
		s[i].dma = 0x100000000ULL + (next_random() % 4096) * 0x200000ULL;
	}
	return end;
}

int main(void)
{
	static struct nv_xdev_ext_ce_seg s[MAX_SEGS];
	struct entry x[MAX_ENTRIES];
	struct nv_xdev_ext_ce_piece p;
	nv_xdev_ext_gpu_u64 off;
	nv_xdev_ext_gpu_u32 seg;
	unsigned int round, visits;
	uint32_t i;

	/* Three segments: [0,8K) [8K,12K) [12K,28K). */
	s[0] = (struct nv_xdev_ext_ce_seg) { 0xA0000000ULL, 8192 };
	s[1] = (struct nv_xdev_ext_ce_seg) { 0xB0000000ULL, 12288 };
	s[2] = (struct nv_xdev_ext_ce_seg) { 0xC0000000ULL, 28672 };

	EXPECT_EQ(0, nv_xdev_ext_ce_seg_first(s, 3, 0));
	EXPECT_EQ(0, nv_xdev_ext_ce_seg_first(s, 3, 8191));
	EXPECT_EQ(1, nv_xdev_ext_ce_seg_first(s, 3, 8192));
	EXPECT_EQ(1, nv_xdev_ext_ce_seg_first(s, 3, 12287));
	EXPECT_EQ(2, nv_xdev_ext_ce_seg_first(s, 3, 12288));
	EXPECT_EQ(2, nv_xdev_ext_ce_seg_first(s, 3, 28671));
	EXPECT_EQ(3, nv_xdev_ext_ce_seg_first(s, 3, 28672));
	EXPECT_EQ(3, nv_xdev_ext_ce_seg_first(s, 3, UINT64_MAX));
	EXPECT_EQ(0, nv_xdev_ext_ce_seg_first(s, 0, 0));

	/* One entry crossing all three segments yields exactly three pieces. */
	off = 100;
	seg = nv_xdev_ext_ce_seg_first(s, 3, off);
	EXPECT_EQ(1, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 20000, &p));
	EXPECT_EQ(0, p.seg);
	EXPECT_EQ(100, p.seg_off);
	EXPECT_EQ(8092, p.len);
	EXPECT_EQ(1, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 20000, &p));
	EXPECT_EQ(1, p.seg);
	EXPECT_EQ(0, p.seg_off);
	EXPECT_EQ(4096, p.len);
	EXPECT_EQ(1, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 20000, &p));
	EXPECT_EQ(2, p.seg);
	EXPECT_EQ(0, p.seg_off);
	EXPECT_EQ(20000 - 12288, p.len);
	EXPECT_EQ(0, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 20000, &p));
	EXPECT_EQ(20000, off);

	/* An entry inside one segment touches that segment only. */
	off = 9000;
	seg = nv_xdev_ext_ce_seg_first(s, 3, off);
	EXPECT_EQ(1, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 9100, &p));
	EXPECT_EQ(1, p.seg);
	EXPECT_EQ(9000 - 8192, p.seg_off);
	EXPECT_EQ(100, p.len);
	EXPECT_EQ(0, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 9100, &p));

	/* Ending exactly on a segment end does not touch the next one. */
	off = 8192;
	seg = nv_xdev_ext_ce_seg_first(s, 3, off);
	EXPECT_EQ(1, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 12288, &p));
	EXPECT_EQ(1, p.seg);
	EXPECT_EQ(0, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 12288, &p));

	/* Past the mapping, or an empty range: no piece, no state change. */
	off = 28672;
	seg = nv_xdev_ext_ce_seg_first(s, 3, off);
	EXPECT_EQ(0, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 28673, &p));
	off = 4096;
	seg = nv_xdev_ext_ce_seg_first(s, 3, off);
	EXPECT_EQ(0, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 4096, &p));
	EXPECT_EQ(4096, off);
	/* A cursor not at its segment (caller bug) yields nothing, never a wrap. */
	off = 100;
	seg = 2;
	EXPECT_EQ(0, nv_xdev_ext_ce_seg_next(s, 3, &seg, &off, 20000, &p));

	/* Random tables and plans: same pieces as the whole-table walk. */
	for (round = 0; round < 4000; round++) {
		uint32_t n = 1 + next_random() % (round < 2000 ? 16 : MAX_SEGS);
		uint64_t total = random_table(s, n, 1 + next_random() % 32);
		uint32_t nx = 1 + next_random() % MAX_ENTRIES;

		for (i = 0; i < nx; i++) {
			x[i].off = next_random() % total;
			x[i].len = 1 + next_random() % (total - x[i].off);
			if (next_random() % 4 == 0)	/* frame-sized, page aligned */
				x[i].len = x[i].len < 4096 ? x[i].len : 4096 - x[i].off % 4096;
		}
		expect_same(s, n, x, nx, __LINE__);
	}

	/*
	 * Cost: one page-sized entry visits one segment however many segments
	 * the pool has (the whole-table walk examined all of them).
	 */
	for (i = 0; i < MAX_SEGS; i++)
		s[i] = (struct nv_xdev_ext_ce_seg) { 0x200000000ULL + (uint64_t)(MAX_SEGS - i) * 0x10000ULL,
						     (uint64_t)(i + 1) * 4096ULL };
	x[0] = (struct entry) { 300ULL * 4096ULL, 4096 };
	visits = 0;
	EXPECT_EQ(1, lookup(s, MAX_SEGS, x, 1, got, &visits));
	EXPECT_EQ(1, visits);
	EXPECT_EQ(300, got[0].seg);
	expect_same(s, MAX_SEGS, x, 1, __LINE__);

	printf("nv_xdev_ext_ce_sync_test: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}

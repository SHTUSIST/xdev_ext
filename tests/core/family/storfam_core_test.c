// SPDX-License-Identifier: GPL-2.0
/* Storage requirements: preserve payload order and NVMe's existing bounds. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !__has_include("include/linux/xdev_ext_storfam_core.h")
int main(void)
{
	puts("not ok 1 - no storage family rules");
	return 1;
}
#else
#include "include/linux/xdev_ext_storfam_core.h"

typedef __u32 u32;
typedef __u64 u64;
struct old_nvme_seg { u64 addr; u32 len; };

/* Frozen 713327e xdev_ext_peer_nvme_sgl_build body, not the new wrapper. */
static int old_nvme_sgl_build(const struct old_nvme_seg *seg, u32 nr,
		struct old_nvme_seg *out, u32 cap, u32 *n)
{
 u32 i, used = 0;
 if (!n) return -EINVAL;
 *n = 0;
 if (!seg || !out || !nr) return -EINVAL;
 for (i = 0; i < nr; i++) {
  if (!seg[i].len || ((seg[i].addr | seg[i].len) & 3)) return -EINVAL;
  if (seg[i].addr + seg[i].len < seg[i].addr) return -EOVERFLOW;
  if (used && out[used - 1].addr + out[used - 1].len == seg[i].addr &&
      seg[i].len <= (u32)~0U - out[used - 1].len) {
   out[used - 1].len += seg[i].len;
  } else {
   if (used == cap) return -EREMOTEIO;
   out[used++] = seg[i];
  }
 }
 *n = used;
 return 0;
}

/* Frozen window block from 713327e nvme_xdev_ext_mech_validate. */
static int old_window(u64 window_slba, u64 window_nlb, u64 slba, u64 nlb)
{
	const struct { u64 window_slba, window_nlb; } saved = {
		window_slba, window_nlb,
	};
	const typeof(saved) *bounds = &saved;
	u64 offset;

	if (slba < bounds->window_slba)
		return -ERANGE;
	offset = slba - bounds->window_slba;
	if (offset >= bounds->window_nlb ||
	    nlb > bounds->window_nlb - offset)
		return -ERANGE;
	return 0;
}

#define CHECK(cond) do { if (!(cond)) { \
	printf("# line %d: %s\n", __LINE__, #cond); return 1; \
} } while (0)

static int coalesce_literals(void)
{
	struct xdev_ext_stor_extent seg[] = {
		{0x2000, 16}, {0x2010, 32}, {0x1000, 16}, {0x1010, 4},
		{0x1008, 4}, /* overlap is not adjacency and order is not sorted */
	};
	const struct xdev_ext_stor_extent want[] = {
		{0x2000, 48}, {0x1000, 20}, {0x1008, 4},
	};
	struct xdev_ext_stor_extent out[6] = {{0}};
	__u32 n = 99, i;

	CHECK(xdev_ext_stor_coalesce(seg, 5, out, 3, 3, &n) == 0);
	CHECK(n == 3);
	for (i = 0; i < n; i++)
		CHECK(out[i].addr == want[i].addr && out[i].len == want[i].len);
	CHECK(xdev_ext_stor_coalesce(seg, 5, seg, 3, 3, &n) == 0);
	CHECK(n == 3);
	for (i = 0; i < n; i++)
		CHECK(seg[i].addr == want[i].addr && seg[i].len == want[i].len);
	/* A full output vector can still consume an adjacent input span. */
	seg[0] = (struct xdev_ext_stor_extent){0x1000, 4};
	seg[1] = (struct xdev_ext_stor_extent){0x1004, 4};
	CHECK(xdev_ext_stor_coalesce(seg, 2, out, 1, 3, &n) == 0);
	CHECK(n == 1 && out[0].addr == 0x1000 && out[0].len == 8);
	/* A merged length must not wrap through the 32-bit length field. */
	seg[0] = (struct xdev_ext_stor_extent){0, UINT32_MAX - 3};
	seg[1] = (struct xdev_ext_stor_extent){UINT32_MAX - 3, 4};
	CHECK(xdev_ext_stor_coalesce(seg, 2, out, 2, 3, &n) == 0);
	CHECK(n == 2 && out[0].len == UINT32_MAX - 3 && out[1].len == 4);
	return 0;
}

static int coalesce_errors(void)
{
	const struct {
		struct xdev_ext_stor_extent seg[2];
		__u32 nr, cap, mask;
		int ret;
	} cases[] = {
		{{{0x1000, 4}}, 0, 2, 3, -EINVAL},
		{{{0x1000, 0}}, 1, 2, 3, -EINVAL},
		{{{0x1001, 4}}, 1, 2, 3, -EINVAL},
		{{{0x1000, 6}}, 1, 2, 3, -EINVAL},
		{{{UINT64_MAX - 3, 4}}, 1, 2, 3, -EOVERFLOW},
		{{{0x1000, 4}}, 1, 0, 3, -EREMOTEIO},
		{{{0x1000, 4}, {0x2000, 4}}, 2, 1, 3, -EREMOTEIO},
		{{{0x1000, 4}, {0x2000, 0}}, 2, 2, 3, -EINVAL},
		{{{0x1000, 4}, {UINT64_MAX - 3, 4}}, 2, 2, 3, -EOVERFLOW},
		{{{0, UINT32_MAX - 3}, {UINT32_MAX - 3, 4}}, 2, 1, 3, -EREMOTEIO},
		{{{0x1004, 8}}, 1, 2, 7, -EINVAL},
		{{{0x1000, 4}}, 1, 2, 7, -EINVAL},
	};
	struct xdev_ext_stor_extent out[3], seg = {0x1000, 4};
	__u32 i, n;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		memset(out, 0xa5, sizeof(out));
		n = 99;
		CHECK(xdev_ext_stor_coalesce(cases[i].seg, cases[i].nr,
			out, cases[i].cap, cases[i].mask, &n) == cases[i].ret);
		CHECK(n == 0);
		CHECK(out[cases[i].cap].addr == UINT64_C(0xa5a5a5a5a5a5a5a5));
	}
	n = 99;
	CHECK(xdev_ext_stor_coalesce(NULL, 1, out, 2, 3, &n) == -EINVAL);
	CHECK(n == 0);
	n = 99;
	CHECK(xdev_ext_stor_coalesce(&seg, 1, NULL, 2, 3, &n) == -EINVAL);
	CHECK(n == 0);
	CHECK(xdev_ext_stor_coalesce(&seg, 1, out, 2, 3, NULL) == -EINVAL);
	/* Zero mask permits byte extents; mask 7 enforces eight-byte extents. */
	seg = (struct xdev_ext_stor_extent){3, 5};
	CHECK(xdev_ext_stor_coalesce(&seg, 1, out, 2, 0, &n) == 0);
	CHECK(n == 1 && out[0].addr == 3 && out[0].len == 5);
	seg = (struct xdev_ext_stor_extent){8, 8};
	CHECK(xdev_ext_stor_coalesce(&seg, 1, out, 2, 7, &n) == 0);
	CHECK(n == 1 && out[0].addr == 8 && out[0].len == 8);
	return 0;
}

static uint64_t seed = UINT64_C(0x838f9b243abc16d1);
static uint64_t random64(void)
{
	seed ^= seed << 13;
	seed ^= seed >> 7;
	seed ^= seed << 17;
	return seed;
}

static int coalesce_differential(void)
{
	struct xdev_ext_stor_extent seg[32], out[33], in_place[32];
	struct old_nvme_seg old_seg[32], old_out[33];
	__u32 trial, i, nr, cap, n, old_n, in_n;
	int ret, old_ret, in_ret;

	for (trial = 0; trial < 100000; trial++) {
		nr = 1 + random64() % 32;
		cap = random64() % 33;
		for (i = 0; i < nr; i++) {
			seg[i].addr = random64() & ~UINT64_C(3);
			seg[i].len = 4 * (1 + random64() % (1024 * 1024 / 4));
			if (i && random64() % 10 < 3)
				seg[i].addr = seg[i - 1].addr + seg[i - 1].len;
			old_seg[i] = (struct old_nvme_seg){seg[i].addr, seg[i].len};
			in_place[i] = seg[i];
		}
		memset(out, 0xa5, sizeof(out));
		memset(old_out, 0xa5, sizeof(old_out));
		n = old_n = in_n = 99;
		ret = xdev_ext_stor_coalesce(seg, nr, out, cap, 3, &n);
		old_ret = old_nvme_sgl_build(old_seg, nr, old_out, cap, &old_n);
		in_ret = xdev_ext_stor_coalesce(in_place, nr, in_place, cap, 3, &in_n);
		CHECK(ret == old_ret && n == old_n);
		CHECK(in_ret == ret && in_n == n);
		for (i = 0; i < 33; i++)
			CHECK(out[i].addr == old_out[i].addr && out[i].len == old_out[i].len);
		for (i = 0; i < n; i++)
			CHECK(in_place[i].addr == out[i].addr && in_place[i].len == out[i].len);
	}
	return 0;
}

static int window_literals(void)
{
	const struct {
		__u64 start, size, slba, nlb;
		int ret;
	} cases[] = {
		{100, 10, 99, 1, -ERANGE},
		{100, 10, 100, 10, 0},
		{100, 10, 100, 11, -ERANGE},
		{100, 10, 109, 1, 0},
		{100, 10, 109, 2, -ERANGE},
		{100, 10, 110, 0, -ERANGE},
		{100, 10, 101, 0, 0}, /* preserve the existing pure window rule */
		{100, 0, 100, 0, -ERANGE},
		{0, UINT64_MAX, UINT64_MAX - 1, 1, 0},
		{0, UINT64_MAX, UINT64_MAX, 0, -ERANGE},
		{UINT64_MAX - 3, 4, UINT64_MAX, 1, 0},
		{UINT64_MAX - 3, 4, UINT64_MAX, 2, -ERANGE},
		{1, UINT64_MAX, 2, UINT64_MAX, -ERANGE},
	};
	unsigned int i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		CHECK(xdev_ext_stor_window_check(cases[i].start, cases[i].size,
			cases[i].slba, cases[i].nlb) == cases[i].ret);
	return 0;
}

static int window_differential(void)
{
	u64 start, size, slba, nlb;
	u32 trial;

	for (trial = 0; trial < 100000; trial++) {
		start = random64();
		size = random64();
		slba = random64();
		nlb = random64();
		CHECK(xdev_ext_stor_window_check(start, size, slba, nlb) ==
			old_window(start, size, slba, nlb));
	}
	return 0;
}

int main(void)
{
	const struct { const char *name; int (*run)(void); } tests[] = {
		{"storage coalescing preserves payload order, in-place use and length limits", coalesce_literals},
		{"storage validates alignment, overflow and capacity with zero error count", coalesce_errors},
		{"100000 storage vectors match frozen NVMe SGL behavior", coalesce_differential},
		{"storage window handles exact boundaries without addition overflow", window_literals},
		{"100000 storage windows match frozen NVMe window behavior", window_differential},
	};
	unsigned int i;
	int failed = 0;

	puts("TAP version 13");
	printf("1..%zu\n", sizeof(tests) / sizeof(tests[0]));
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int ret = tests[i].run();

		printf("%s %u - %s\n", ret ? "not ok" : "ok", i + 1, tests[i].name);
		failed |= ret;
	}
	return failed;
}
#endif

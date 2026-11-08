// SPDX-License-Identifier: GPL-2.0
/* Host checks of xdg_core.h: size grid, group split, payload, slot oracle, statistics. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xdg_core.h"

static void sizes(void)
{
	uint64_t s[XDG_MAX_SIZES];
	int n = xdg_parse_sizes(NULL, s);

	assert(n == 17 && s[0] == 64 && s[16] == (4u << 20));
	for (int i = 1; i < n; i++)
		assert(s[i] == 2 * s[i - 1]);
	n = xdg_parse_sizes("4096,65536", s);
	assert(n == 2 && s[0] == 4096 && s[1] == 65536);
	assert(xdg_parse_sizes("100", s) == -EINVAL);		/* not a power of two */
	assert(xdg_parse_sizes("32", s) == -EINVAL);		/* below 64 B */
	assert(xdg_parse_sizes("8388608", s) == -EINVAL);	/* above 4 MiB */
	assert(xdg_parse_sizes("4096,,8192", s) == -EINVAL);
	assert(xdg_parse_sizes("", s) == -EINVAL);
	assert(xdg_parse_sizes("8192,4096", s) == -EINVAL);	/* ascending only */
}

static void split(void)
{
	uint64_t g, n;

	assert(!xdg_split(64, &g, &n) && g == 64 && n == 1);
	assert(!xdg_split(256u << 10, &g, &n) && g == (256u << 10) && n == 1);
	/* XDOMAIN carries at most 64 NHI frames of 4 KiB per batch. */
	assert(!xdg_split(4u << 20, &g, &n) && g == XDG_MAX_GROUP && n == 16);
	assert(xdg_split(0, &g, &n) == -EINVAL);
	assert(xdg_split(3u << 18, &g, &n) == -EINVAL);	/* 768 KiB is not 2^k */
}

static void payload(void)
{
	uint8_t a[4096], b[4096];
	uint64_t bad = 0;

	xdg_fill(a, sizeof(a), 7, 3);
	assert(!xdg_check(a, sizeof(a), 7, 3, &bad));
	assert(xdg_check(a, sizeof(a), 7, 4, &bad) && bad == 0);	/* other slot */
	assert(xdg_check(a, sizeof(a), 8, 3, &bad) && bad == 0);	/* other seed */
	memcpy(b, a, sizeof(b));
	b[1000] ^= 1;
	assert(xdg_check(b, sizeof(b), 7, 3, &bad) && bad == 1000);
	assert(xdg_identify(a, sizeof(a), 7, 8) == 3);
	assert(xdg_identify(b, sizeof(b), 7, 8) == -1);		/* torn image */
	xdg_fill(a, 64, 7, 0);
	assert(xdg_identify(a, 64, 7, 1) == 0);
}

static void oracle(void)
{
	int perm[4] = { 2, 0, 3, 1 }, dup[4] = { 0, 0, 3, 1 }, miss[4] = { 0, 1, 2, -1 };

	assert(!xdg_slot_oracle(perm, 4));
	assert(xdg_slot_oracle(dup, 4) == -EIO);
	assert(xdg_slot_oracle(miss, 4) == -EIO);
}

static void stats(void)
{
	uint64_t v[100];
	struct xdg_stats s;

	for (int i = 0; i < 100; i++)
		v[i] = (uint64_t)(100 - i);	/* 100..1, unsorted */
	assert(!xdg_stats(v, 100, &s));
	assert(s.n == 100 && s.min == 1 && s.max == 100);
	assert(s.median == 50);		/* lower median of an even count */
	assert(s.p99 == 99);		/* nearest rank: ceil(0.99 * 100) = 99th value */
	uint64_t one = 42;
	assert(!xdg_stats(&one, 1, &s) && s.median == 42 && s.p99 == 42);
	assert(xdg_stats(v, 0, &s) == -EINVAL);
	/* 1 GB in one second is 8 Gb/s. */
	assert(xdg_gbps(1000000000ull, 1000000000ull) == 8.0);
}

int main(void)
{
	sizes();
	split();
	payload();
	oracle();
	stats();
	printf("xdg_core: ok\n");
	return 0;
}

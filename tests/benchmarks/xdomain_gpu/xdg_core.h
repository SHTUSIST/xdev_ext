/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_XDG_CORE_H
#define XDEV_EVAL_XDG_CORE_H
/*
 * Pure host logic shared by the E4 VRAM<->VRAM tools (xdomain_gpu.c,
 * tcp_cuda.c, nccl_pingpong.c): the message-size grid, the split of one
 * message into XDOMAIN groups, the slot payload, the slot oracle and the
 * latency statistics.  No CUDA, NCCL, socket or kernel call, so
 * test_xdg_core.c checks it on any Linux host.
 *
 * Payload: 64-bit little-endian word w of a message in slot s carries
 * mix64(seed ^ s << 40 ^ w).  A message names its slot, so a receiver can
 * tell which sender slot an image came from and a torn or shifted copy
 * never matches.  Every tool fills and checks the same way, so the three
 * arms verify identical bytes.
 *
 * Statistics: median is the lower median, p99 the nearest-rank value
 * (rank ceil(0.99 n)); the half round trip is reported as RTT/2, a
 * symmetric estimate, not a measured one-way latency (no cross-host clock).
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define XDG_MIN_SIZE	64ULL
#define XDG_MAX_SIZE	(4ULL << 20)
#define XDG_MAX_SIZES	17
/* XDEV_EXT_XDOMAIN_MAX_ELEMS NHI frames of XDEV_EXT_XDOMAIN_MAX_FRAME bytes. */
#define XDG_MAX_GROUP	(64ULL * 4096ULL)
#define XDG_GOLDEN	0x9E3779B97F4A7C15ULL

/* Exit codes shared with tests/eval: 0 pass, 1 failure, 2 usage, 4 capability. */
enum { XDG_EXIT_PASS = 0, XDG_EXIT_FAIL = 1, XDG_EXIT_USAGE = 2, XDG_EXIT_UNAVAILABLE = 4 };

static inline int xdg_pow2(uint64_t v)
{
	return v && !(v & (v - 1));
}

/* ASCII decimal only. */
static inline int xdg_parse_u64(const char *s, size_t len, uint64_t max, uint64_t *out)
{
	uint64_t v = 0;

	if (!s || !len)
		return -EINVAL;
	for (size_t i = 0; i < len; i++) {
		if (s[i] < '0' || s[i] > '9' || v > (max - (uint64_t)(s[i] - '0')) / 10)
			return -EINVAL;
		v = v * 10 + (uint64_t)(s[i] - '0');
	}
	*out = v;
	return 0;
}

/* NULL: 64 B .. 4 MiB by powers of two.  Otherwise ascending powers of two, comma separated. */
static inline int xdg_parse_sizes(const char *list, uint64_t out[XDG_MAX_SIZES])
{
	int n = 0;

	if (!list) {
		for (uint64_t s = XDG_MIN_SIZE; s <= XDG_MAX_SIZE; s *= 2)
			out[n++] = s;
		return n;
	}
	for (const char *p = list;;) {
		const char *comma = strchr(p, ',');
		size_t len = comma ? (size_t)(comma - p) : strlen(p);
		uint64_t v;

		if (n == XDG_MAX_SIZES || xdg_parse_u64(p, len, XDG_MAX_SIZE, &v) ||
		    v < XDG_MIN_SIZE || !xdg_pow2(v) || (n && v <= out[n - 1]))
			return -EINVAL;
		out[n++] = v;
		if (!comma)
			return n;
		p = comma + 1;
	}
}

/* One message of @size bytes as @groups XDOMAIN groups of @group bytes. */
static inline int xdg_split(uint64_t size, uint64_t *group, uint64_t *groups)
{
	if (!xdg_pow2(size) || size > XDG_MAX_SIZE)
		return -EINVAL;
	*group = size < XDG_MAX_GROUP ? size : XDG_MAX_GROUP;
	*groups = size / *group;
	return 0;
}

static inline uint64_t xdg_mix64(uint64_t x)
{
	uint64_t z = x + XDG_GOLDEN;

	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static inline uint64_t xdg_word(uint64_t seed, uint64_t slot, uint64_t w)
{
	return xdg_mix64(seed ^ (slot << 40) ^ w);
}

/* @n is a multiple of 8 (every size of the grid is). */
static inline void xdg_fill(void *buf, uint64_t n, uint64_t seed, uint64_t slot)
{
	uint8_t *p = buf;

	for (uint64_t w = 0; w < n / 8; w++) {
		uint64_t v = xdg_word(seed, slot, w);

		for (int i = 0; i < 8; i++)
			p[8 * w + (uint64_t)i] = (uint8_t)(v >> (8 * i));
	}
}

/* 0 when @buf is the slot image; otherwise 1 and the first wrong byte. */
static inline int xdg_check(const void *buf, uint64_t n, uint64_t seed, uint64_t slot,
			    uint64_t *first_bad)
{
	const uint8_t *p = buf;

	for (uint64_t w = 0; w < n / 8; w++) {
		uint64_t v = xdg_word(seed, slot, w);

		for (int i = 0; i < 8; i++)
			if (p[8 * w + (uint64_t)i] != (uint8_t)(v >> (8 * i))) {
				*first_bad = 8 * w + (uint64_t)i;
				return 1;
			}
	}
	return 0;
}

/* The sender slot whose whole image @buf is, or -1. */
static inline int xdg_identify(const void *buf, uint64_t n, uint64_t seed, int nslots)
{
	uint64_t bad;

	for (int s = 0; s < nslots; s++)
		if (!xdg_check(buf, n, seed, (uint64_t)s, &bad))
			return s;
	return -1;
}

/* Every receiver slot holds a whole, distinct sender image and every image appears. */
static inline int xdg_slot_oracle(const int *ids, int nslots)
{
	uint64_t seen = 0;

	if (nslots <= 0 || nslots > 64)
		return -EINVAL;
	for (int i = 0; i < nslots; i++) {
		if (ids[i] < 0 || ids[i] >= nslots || (seen & (1ULL << ids[i])))
			return -EIO;
		seen |= 1ULL << ids[i];
	}
	return 0;
}

struct xdg_stats {
	uint64_t n, min, median, p99, max;
};

static inline int xdg_cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

/* Sorts @v in place. */
static inline int xdg_stats(uint64_t *v, uint64_t n, struct xdg_stats *s)
{
	uint64_t rank;

	if (!n)
		return -EINVAL;
	qsort(v, n, sizeof(*v), xdg_cmp_u64);
	rank = (99 * n + 99) / 100;	/* ceil(0.99 n), 1-based */
	*s = (struct xdg_stats){ .n = n, .min = v[0], .median = v[(n - 1) / 2],
				 .p99 = v[rank - 1], .max = v[n - 1] };
	return 0;
}

/* Gigabits per second of @bytes in @ns. */
static inline double xdg_gbps(uint64_t bytes, uint64_t ns)
{
	return ns ? (double)bytes * 8.0 / (double)ns : 0.0;
}

#endif /* XDEV_EVAL_XDG_CORE_H */

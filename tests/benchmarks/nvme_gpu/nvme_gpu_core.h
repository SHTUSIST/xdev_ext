/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_NVME_GPU_CORE_H
#define XDEV_EVAL_NVME_GPU_CORE_H

/*
 * Pure host logic shared by every NVMe<->GPU eval arm (bench_uring_cuda.cc,
 * bench_cufile_batch.cc, session_nvme_ce.c) and by tests/eval/gpu_nic: strict
 * CLI numbers, the campaign geometry, the seq/rand block schedule, the
 * position-encoding payload and the post-campaign oracles.  No CUDA, cuFile,
 * io_uring or kernel call, so test_core.c checks it on any Linux host.
 *
 * Payload: little-endian 64-bit word w of the window (absolute byte offset
 * 8w) holds (w ^ mix(seed)) * XG_WORD_MUL.  The multiplier is odd, so a word
 * decodes back to its own position: a copy at a wrong offset, a stale block
 * or a torn transfer never matches, and a slot image names the block it
 * holds.  Sentinel bytes use the bitwise complement of the seed.
 *
 * Schedule: pass p visits every block of the window exactly once.  seq is
 * the identity; rand is i -> (a*i + b) mod n with gcd(a, n) = 1, a and b
 * derived from seed and pass.  Within a pass every in-flight I/O names a
 * different block; across a pass boundary two in-flight I/Os may name one
 * block, and then they carry identical bytes.  qd <= n rejects campaigns
 * that could never fill their queue with distinct blocks.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define XG_MIN_SIZE		4096ULL
#define XG_MAX_SIZE		(4ULL << 20)
#define XG_MAX_QD		256ULL
#define XG_MAX_WINDOW		(64ULL << 30)
#define XG_MAX_PASSES		1000ULL
#define XG_MAX_STREAMS		16ULL
#define XG_WORD_MUL		0x9e3779b97f4a7c15ULL

enum xg_pattern { XG_SEQ = 0, XG_RAND = 1 };
enum xg_direction { XG_LOAD = 0, XG_SAVE = 1 };	/* NVMe->GPU, GPU->NVMe */

/* Exit codes shared with tests/eval: 0 pass, 1 failure, 2 usage, 4 capability. */
enum { XG_EXIT_PASS = 0, XG_EXIT_FAIL = 1, XG_EXIT_USAGE = 2, XG_EXIT_UNAVAILABLE = 4 };

struct xg_geometry {
	uint64_t size;		/* bytes per I/O, a 4 KiB multiple, 4 KiB..4 MiB */
	uint64_t qd;		/* I/Os in flight, 1..256 */
	uint64_t window;	/* window bytes, a multiple of size */
	uint64_t passes;	/* complete visits of the window */
	uint32_t pattern;	/* enum xg_pattern */
	uint32_t seed;
};

/* ASCII decimal only: no sign, space, prefix, exponent or empty string. */
static inline int xg_parse_u64(const char *s, uint64_t max, uint64_t *out)
{
	uint64_t v = 0;

	if (!s || !*s)
		return -EINVAL;
	for (; *s; s++) {
		unsigned int d;

		if (*s < '0' || *s > '9')
			return -EINVAL;
		d = (unsigned int)(*s - '0');
		if (v > (max - d) / 10)
			return -ERANGE;
		v = v * 10 + d;
	}
	*out = v;
	return 0;
}

static inline int xg_parse_pattern(const char *s, uint32_t *out)
{
	if (s && !strcmp(s, "seq"))
		*out = XG_SEQ;
	else if (s && !strcmp(s, "rand"))
		*out = XG_RAND;
	else
		return -EINVAL;
	return 0;
}

static inline int xg_parse_direction(const char *s, uint32_t *out)
{
	if (s && !strcmp(s, "load"))
		*out = XG_LOAD;
	else if (s && !strcmp(s, "save"))
		*out = XG_SAVE;
	else
		return -EINVAL;
	return 0;
}

static inline uint64_t xg_blocks(const struct xg_geometry *g)
{
	return g->window / g->size;
}

static inline int xg_geometry_check(const struct xg_geometry *g)
{
	if (g->size < XG_MIN_SIZE || g->size > XG_MAX_SIZE || g->size % XG_MIN_SIZE)
		return -EINVAL;
	if (!g->qd || g->qd > XG_MAX_QD || !g->passes || g->passes > XG_MAX_PASSES)
		return -EINVAL;
	if (!g->window || g->window > XG_MAX_WINDOW || g->window % g->size)
		return -EINVAL;
	if (g->pattern != XG_SEQ && g->pattern != XG_RAND)
		return -EINVAL;
	/* Fewer blocks than in-flight I/Os: the queue never holds distinct blocks. */
	if (xg_blocks(g) < g->qd)
		return -ERANGE;
	return 0;
}

static inline uint64_t xg_gcd(uint64_t a, uint64_t b)
{
	while (b) {
		uint64_t t = a % b;

		a = b;
		b = t;
	}
	return a;
}

static inline uint64_t xg_mix64(uint64_t x)
{
	/* splitmix64 finaliser */
	x += 0x9e3779b97f4a7c15ULL;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

/* The multiplier of pass @pass: coprime with @n, never 1 unless n <= 2. */
static inline uint64_t xg_rand_mul(uint64_t n, uint32_t seed, uint64_t pass)
{
	uint64_t a;

	if (n <= 2)
		return 1;
	a = 2 + xg_mix64(((uint64_t)seed << 32) ^ pass) % (n - 2);
	while (xg_gcd(a, n) != 1)
		a = a + 1 < n ? a + 1 : 2;
	return a;
}

/*
 * Block of schedule position @i (0..n-1) in pass @pass.  n <= 2^24 blocks
 * (64 GiB of 4 KiB I/O) keeps a*i below 2^48.
 */
static inline uint64_t xg_block(const struct xg_geometry *g, uint64_t pass,
				uint64_t i)
{
	uint64_t n = xg_blocks(g), a, b;

	if (g->pattern == XG_SEQ)
		return i;
	a = xg_rand_mul(n, g->seed, pass);
	b = xg_mix64(((uint64_t)g->seed << 32) ^ (pass + 0x5bd1e995ULL)) % n;
	return (a * i + b) % n;
}

/*
 * Slot-ring destination, the device layout of the session arm: a ring of qd
 * device slots of one block each, schedule position i using slot i mod qd.
 * A load leaves in slot d the block of the last position sent there; a save
 * writes slot (i mod qd)'s image to the block of position i.  Every slot is
 * used because n >= qd (xg_geometry_check).
 */
static inline uint64_t xg_ring_bytes(const struct xg_geometry *g)
{
	return g->qd * g->size;
}

static inline uint64_t xg_ring_slot(const struct xg_geometry *g, uint64_t i)
{
	return i % g->qd;
}

/* Last schedule position below n of slot @d (d < qd <= n). */
static inline uint64_t xg_ring_last_position(const struct xg_geometry *g, uint64_t d)
{
	return d + (xg_blocks(g) - 1 - d) / g->qd * g->qd;
}

static inline uint64_t xg_ring_load_block(const struct xg_geometry *g, uint64_t pass,
					  uint64_t d)
{
	return xg_block(g, pass, xg_ring_last_position(g, d));
}

static inline uint64_t xg_ring_save_source(const struct xg_geometry *g, uint64_t i)
{
	return xg_ring_slot(g, i);
}

static inline uint64_t xg_word(uint64_t word_index, uint32_t seed)
{
	return (word_index ^ xg_mix64(seed)) * XG_WORD_MUL;
}

/* Inverse of XG_WORD_MUL modulo 2^64 by Newton iteration. */
static inline uint64_t xg_word_mul_inverse(void)
{
	uint64_t x = XG_WORD_MUL;
	int i;

	for (i = 0; i < 6; i++)
		x *= 2 - XG_WORD_MUL * x;
	return x;
}

static inline uint64_t xg_word_index(uint64_t value, uint32_t seed)
{
	return (value * xg_word_mul_inverse()) ^ xg_mix64(seed);
}

static inline void xg_put64(unsigned char *p, uint64_t v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (unsigned char)(v >> (8 * i));
}

static inline uint64_t xg_get64(const unsigned char *p)
{
	uint64_t v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = v << 8 | p[i];
	return v;
}

/* Payload of window bytes [off, off + len); both 8-byte aligned. */
static inline int xg_fill(unsigned char *buf, uint64_t off, uint64_t len,
			  uint32_t seed)
{
	uint64_t i;

	if (off % 8 || len % 8)
		return -EINVAL;
	for (i = 0; i < len; i += 8)
		xg_put64(buf + i, xg_word((off + i) / 8, seed));
	return 0;
}

/* Byte offset of the first mismatch against the payload, or -1; misaligned
 * arguments compare as a mismatch at 0. */
static inline int64_t xg_compare(const unsigned char *buf, uint64_t off,
				 uint64_t len, uint32_t seed)
{
	uint64_t i;

	if (off % 8 || len % 8)
		return 0;
	for (i = 0; i < len; i += 8)
		if (xg_get64(buf + i) != xg_word((off + i) / 8, seed))
			return (int64_t)i;
	return -1;
}

/*
 * A session arm leaves each device window slot holding one whole block:
 * the block whose first word the slot starts with, below @nr_blocks.
 * 0 with *@block, -ENOENT when the slot holds no block image, -EBADMSG
 * when it starts like block *@block but differs later.
 */
static inline int xg_identify(const unsigned char *slot, uint64_t size,
			      uint64_t nr_blocks, uint32_t seed,
			      uint64_t *block)
{
	uint64_t w = xg_word_index(xg_get64(slot), seed);

	if (size % 8 || w % (size / 8) || w / (size / 8) >= nr_blocks)
		return -ENOENT;
	*block = w / (size / 8);
	return xg_compare(slot, *block * size, size, seed) < 0 ? 0 : -EBADMSG;
}

/* CPU time of the process in microseconds, from getrusage() fields. */
static inline uint64_t xg_cpu_us(long user_s, long user_us, long sys_s, long sys_us)
{
	return (uint64_t)user_s * 1000000ULL + (uint64_t)user_us +
	       (uint64_t)sys_s * 1000000ULL + (uint64_t)sys_us;
}

/*
 * Busy time of all CPUs, from the aggregate line of /proc/stat (user, nice,
 * system, irq, softirq, steal; idle and iowait excluded), in microseconds.
 * Process rusage misses the session's kernel worker thread and interrupt
 * work; this counts every arm the same way.  USER_HZ granularity (often
 * 10 ms): meaningful only for campaigns far longer than one tick.
 */
static inline int xg_parse_proc_stat(const char *line, long hz, uint64_t *busy_us)
{
	unsigned long long v[8] = { 0 };

	/* The aggregate line only: "cpu" then blanks, never "cpu0". */
	if (hz <= 0 || strncmp(line, "cpu ", 4) ||
	    sscanf(line + 4, "%llu %llu %llu %llu %llu %llu %llu %llu",
		   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) != 8)
		return -EINVAL;
	*busy_us = (uint64_t)(v[0] + v[1] + v[2] + v[5] + v[6] + v[7]) * 1000000ULL /
		   (uint64_t)hz;
	return 0;
}

static inline uint64_t xg_host_busy_us(void)
{
	char line[512];
	uint64_t busy = 0;
	FILE *f = fopen("/proc/stat", "re");

	if (!f)
		return 0;
	if (!fgets(line, sizeof(line), f) ||
	    xg_parse_proc_stat(line, sysconf(_SC_CLK_TCK), &busy))
		busy = 0;
	fclose(f);
	return busy;
}

#endif /* XDEV_EVAL_NVME_GPU_CORE_H */

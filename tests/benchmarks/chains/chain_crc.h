/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_CRC_H
#define CHAIN_CRC_H

/*
 * The NXP wire CRC32C of the user-space arms (staged chain_bench, uo_bench),
 * of the same class as the session's: bpf_xdev_ext_frame_crc32c() calls the
 * kernel's crc32c(), which on x86-64 is crc32c_arch() (arch/x86/lib/crc32.c):
 * the SSE4.2 crc32q instruction, three interleaved streams from 512 bytes
 * on.  chain_crc32c_fast() does the same: crc32q, and for lengths of three
 * lanes or more three interleaved streams per 3 x CHAIN_CRC_LANE bytes,
 * combined through precomputed linear shift tables (the kernel combines
 * with PCLMULQDQ; the result is identical).  Without SSE4.2 it falls back
 * to the byte table, and chain_crc32c_impl() names what ran so a result
 * can report it.  chain_crc32c() in chain_oracle.h stays the test oracle.
 *
 * No pre- or post-inversion, as crc32c(): the CRC is linear, so
 * crc(c, A || B) = shift(crc(c, A), |B|) ^ crc(0, B).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "chain_oracle.h"

#if defined(__x86_64__)
#include <nmmintrin.h>
#endif

#define CHAIN_CRC_LANE	256U	/* bytes per stream of the 3-way loop */

struct chain_crc_shift {
	uint32_t t[4][256];
};

static struct chain_crc_shift chain_crc_sh1, chain_crc_sh2;	/* LANE, 2 x LANE */
static int chain_crc_hw = -1;	/* -1 not probed, 0 table, 1 SSE4.2 */

/* @c advanced over @n zero bytes. */
static inline uint32_t chain_crc_zeros(uint32_t c, size_t n)
{
	static const uint8_t zero[2 * CHAIN_CRC_LANE];

	return chain_crc32c(c, zero, n);
}

static inline void chain_crc_shift_init(struct chain_crc_shift *sh, size_t n)
{
	uint32_t basis[32];
	unsigned int b, p, v;

	for (b = 0; b < 32; b++)
		basis[b] = chain_crc_zeros(1U << b, n);
	for (p = 0; p < 4; p++) {
		sh->t[p][0] = 0;
		for (v = 1; v < 256; v++)
			sh->t[p][v] = sh->t[p][v & (v - 1)] ^
				      basis[8 * p + __builtin_ctz(v)];
	}
}

static inline uint32_t chain_crc_shift(const struct chain_crc_shift *sh, uint32_t c)
{
	return sh->t[0][c & 0xff] ^ sh->t[1][(c >> 8) & 0xff] ^
	       sh->t[2][(c >> 16) & 0xff] ^ sh->t[3][c >> 24];
}

#if defined(__x86_64__)
static inline uint64_t chain_crc_load64(const uint8_t *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));
	return v;
}

__attribute__((target("sse4.2")))
static inline uint32_t chain_crc32c_sse42(uint32_t crc, const uint8_t *p, size_t len)
{
	uint64_t c0 = crc, c1, c2;
	size_t i;

	for (; len >= 3 * CHAIN_CRC_LANE; p += 3 * CHAIN_CRC_LANE,
	     len -= 3 * CHAIN_CRC_LANE) {
		c1 = c2 = 0;
		for (i = 0; i < CHAIN_CRC_LANE; i += 8) {
			c0 = _mm_crc32_u64(c0, chain_crc_load64(p + i));
			c1 = _mm_crc32_u64(c1, chain_crc_load64(p + CHAIN_CRC_LANE + i));
			c2 = _mm_crc32_u64(c2, chain_crc_load64(p + 2 * CHAIN_CRC_LANE + i));
		}
		c0 = chain_crc_shift(&chain_crc_sh2, (uint32_t)c0) ^
		     chain_crc_shift(&chain_crc_sh1, (uint32_t)c1) ^ (uint32_t)c2;
	}
	for (; len >= 8; p += 8, len -= 8)
		c0 = _mm_crc32_u64(c0, chain_crc_load64(p));
	for (; len; p++, len--)
		c0 = _mm_crc32_u8((uint32_t)c0, *p);
	return (uint32_t)c0;
}
#endif

/* Probe the CPU and build the shift tables; call before any timed window. */
static inline void chain_crc32c_init(void)
{
	if (chain_crc_hw >= 0)
		return;
	chain_crc_shift_init(&chain_crc_sh1, CHAIN_CRC_LANE);
	chain_crc_shift_init(&chain_crc_sh2, 2 * CHAIN_CRC_LANE);
#if defined(__x86_64__)
	chain_crc_hw = __builtin_cpu_supports("sse4.2") ? 1 : 0;
#else
	chain_crc_hw = 0;
#endif
}

static inline const char *chain_crc32c_impl(void)
{
	chain_crc32c_init();
	return chain_crc_hw ? "sse4.2-crc32q-3way" : "table";
}

static inline uint32_t chain_crc32c_fast(uint32_t crc, const void *buf, size_t len)
{
	if (chain_crc_hw < 0)
		chain_crc32c_init();
#if defined(__x86_64__)
	if (chain_crc_hw)
		return chain_crc32c_sse42(crc, buf, len);
#endif
	return chain_crc32c(crc, buf, len);
}

#endif /* CHAIN_CRC_H */

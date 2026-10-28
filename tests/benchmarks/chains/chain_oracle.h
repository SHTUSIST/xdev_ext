/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_ORACLE_H
#define CHAIN_ORACLE_H

/*
 * Expected bytes and the post-campaign checks of chain_bench and uo_bench.
 * run.py writes source windows and reference files from an independent
 * Python transcription of chain_byte(); test_run.py compares the two.
 * Nothing here runs inside a timed window: the benchmarks compare after the
 * campaign (or, in correctness mode only, between windows).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Bytes 0..7 carry the group index, so every group's content is unique. */
static inline uint64_t chain_mix(uint64_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 33;
	return x;
}

/* Incompressible payload byte @off of group @g. */
static inline uint8_t chain_byte(uint64_t seed, uint64_t g, uint64_t off)
{
	uint64_t x;

	if (off < 8)
		return (uint8_t)(g >> (8 * off));
	x = chain_mix(seed ^ g * 0x9e3779b97f4a7c15ULL ^
		      (off >> 3) * 0xc2b2ae3d27d4eb4fULL);
	return (uint8_t)(x >> (8 * (off & 7)));
}

/*
 * Compressible payload (IAA chains): 64-byte runs of one of 16 letters,
 * still led by the group index.
 */
static inline uint8_t chain_text_byte(uint64_t seed, uint64_t g, uint64_t off)
{
	if (off < 8)
		return (uint8_t)(g >> (8 * off));
	return (uint8_t)('a' + (chain_mix(seed ^ g * 0x9e3779b97f4a7c15ULL ^
					  (off >> 6)) & 15));
}

static inline void chain_fill(uint8_t *buf, size_t len, uint64_t seed,
			      uint64_t g, bool text)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = text ? chain_text_byte(seed, g, i) : chain_byte(seed, g, i);
}

/*
 * CRC32C (Castagnoli, reflected 0x82f63b78) without pre- or post-inversion,
 * the semantics of the kernel's crc32c() and of bpf_xdev_ext_crc32c().
 */
static inline uint32_t chain_crc32c(uint32_t crc, const void *buf, size_t len)
{
	static uint32_t table[256];
	static bool ready;
	const uint8_t *p = buf;
	size_t i;

	if (!ready) {
		for (uint32_t n = 0; n < 256; n++) {
			uint32_t c = n;

			for (int k = 0; k < 8; k++)
				c = c & 1 ? (c >> 1) ^ 0x82f63b78U : c >> 1;
			table[n] = c;
		}
		ready = true;
	}
	for (i = 0; i < len; i++)
		crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
	return crc;
}

/* Index of the first differing byte, or -1 when equal. */
static inline long long chain_first_diff(const uint8_t *a, const uint8_t *b,
					 size_t len)
{
	size_t i;

	if (!memcmp(a, b, len))
		return -1;
	for (i = 0; i < len; i++)
		if (a[i] != b[i])
			return (long long)i;
	return -1;
}

/*
 * CE window oracle: @window holds @slots slots @stride bytes apart, whose
 * first @len bytes are compared; @reference holds @len expected bytes for
 * each group of [0, @groups).  A slot is either the group whose index its
 * first 8 bytes name, byte for byte, or still all @pristine (never written);
 * no group sits in two slots, since one batch writes it once.  Every group
 * in @required must sit in some slot.  Which slot a batch uses is the
 * kernel's choice (the free batch list is LIFO, xdev_ext_mech_batch_put_locked
 * and xdev_ext_mech_batch_get_locked), so a later batch may overwrite any
 * finished group except the very last: only that one is always required.  Returns 0, the 1-based
 * slot that holds wrong bytes, or minus (1 + index into @required) of a
 * group that is missing; *@found counts the valid written slots.
 */
static inline long long chain_check_window(const uint8_t *window, uint32_t slots,
					   uint32_t stride, uint32_t len,
					   const uint8_t *reference,
					   uint64_t groups, uint8_t pristine,
					   const uint64_t *required,
					   unsigned int nr_required,
					   uint64_t *found)
{
	uint32_t s;
	unsigned int r;

	*found = 0;
	if (len < 8 || len > stride)
		return 1;
	for (s = 0; s < slots; s++) {
		const uint8_t *p = window + (size_t)s * stride;
		uint64_t g = 0;
		size_t i;
		bool clean = true;

		for (i = 0; i < len && clean; i++)
			clean = p[i] == pristine;
		if (clean)
			continue;
		for (i = 0; i < 8; i++)
			g |= (uint64_t)p[i] << (8 * i);
		if (g >= groups || memcmp(p, reference + (size_t)g * len, len))
			return s + 1;
		for (i = 0; i < s; i++)
			if (!memcmp(window + i * stride, p, 8))
				return s + 1;
		(*found)++;
	}
	for (r = 0; r < nr_required; r++) {
		bool hit = false;

		if (required[r] >= groups)
			return -(long long)r - 1;
		for (s = 0; s < slots && !hit; s++)
			hit = !memcmp(window + (size_t)s * stride,
				      reference + (size_t)required[r] * len, len);
		if (!hit)
			return -(long long)r - 1;
	}
	return 0;
}

#endif /* CHAIN_ORACLE_H */

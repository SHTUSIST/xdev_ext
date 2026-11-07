/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KV_RESTORE_PATTERN_H
#define KV_RESTORE_PATTERN_H
/*
 * Deterministic KV payload shared by every K-KV arm and its checks; the same
 * function as kv_layout.py pattern_block().  No xdev_ext header is needed, so
 * the baseline workers stay independent of the system under test.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#define KV_BLOCK	4096u

#define KV_GOLDEN	0x9E3779B97F4A7C15ULL
#define KV_SALT_TAG	(0x53414C54ULL << 32)
#define KV_BLOCK_MUL	0xD1342543DE82EF95ULL

static inline uint64_t kv_mix64(uint64_t x)
{
	uint64_t z = x + KV_GOLDEN;

	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static inline void kv_put_le64(uint8_t *p, uint64_t v)
{
	for (int i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

/* Object-relative 4 KiB block @block: word j = salt_j ^ mix64(seed ^ block * MUL). */
static inline void kv_pattern_block(uint64_t seed, uint64_t block, uint8_t out[KV_BLOCK])
{
	uint64_t word = kv_mix64(seed ^ (block * KV_BLOCK_MUL));

	for (uint32_t j = 0; j < KV_BLOCK / 8; j++)
		kv_put_le64(out + 8 * j, kv_mix64(seed ^ KV_SALT_TAG ^ j) ^ word);
}

/* Compare @len bytes at object offset @offset; -EIO with the first bad offset. */
static inline int kv_pattern_check(uint64_t seed, uint64_t offset, const uint8_t *buf,
				   size_t len, uint64_t *first_bad)
{
	uint8_t block[KV_BLOCK];
	uint64_t b = UINT64_MAX;
	size_t i;

	for (i = 0; i < len; i++) {
		uint64_t at = offset + i;

		if (at / KV_BLOCK != b) {
			b = at / KV_BLOCK;
			kv_pattern_block(seed, b, block);
		}
		if (buf[i] != block[at % KV_BLOCK]) {
			*first_bad = at;
			return -EIO;
		}
	}
	return 0;
}

/* FNV-1a 64 of @len bytes, for compact digests in records. */
static inline uint64_t kv_fnv1a(uint64_t h, const uint8_t *p, size_t len)
{
	for (size_t i = 0; i < len; i++)
		h = (h ^ p[i]) * 0x100000001B3ULL;
	return h;
}
#define KV_FNV_OFFSET 0xCBF29CE484222325ULL

#endif /* KV_RESTORE_PATTERN_H */

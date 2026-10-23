/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Independent user-space oracles for the in-frame CPU transform tests:
 * bitwise CRC32C (Castagnoli, reflected 0x82F63B78), XXH64 and SHA-256
 * written from their public specifications, sharing no code with the
 * kernel transforms or with the ctl tool.  Each oracle is checked against
 * published test vectors by the tests that use it.
 */
#ifndef XDEV_EXT_MECH_XFORM_ORACLE_H
#define XDEV_EXT_MECH_XFORM_ORACLE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Raw update with neither pre- nor post-inversion, as the kernel crc32c(). */
static inline uint32_t oracle_crc32c_update(uint32_t crc, const void *p, size_t len)
{
	const uint8_t *b = p;
	size_t i;
	int k;

	for (i = 0; i < len; i++) {
		crc ^= b[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0x82F63B78U & (0U - (crc & 1U)));
	}
	return crc;
}

static inline uint32_t oracle_crc32c(const void *p, size_t len)
{
	return ~oracle_crc32c_update(~0U, p, len);
}

#define ORACLE_P1 0x9E3779B185EBCA87ULL
#define ORACLE_P2 0xC2B2AE3D27D4EB4FULL
#define ORACLE_P3 0x165667B19E3779F9ULL
#define ORACLE_P4 0x85EBCA77C2B2AE63ULL
#define ORACLE_P5 0x27D4EB2F165667C5ULL

static inline uint64_t oracle_rotl64(uint64_t x, int r)
{
	return (x << r) | (x >> (64 - r));
}

static inline uint64_t oracle_le64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = v << 8 | p[i];
	return v;
}

static inline uint32_t oracle_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

static inline uint64_t oracle_xxh64_round(uint64_t acc, uint64_t input)
{
	acc += input * ORACLE_P2;
	acc = oracle_rotl64(acc, 31);
	return acc * ORACLE_P1;
}

static inline uint64_t oracle_xxh64_merge(uint64_t acc, uint64_t val)
{
	acc ^= oracle_xxh64_round(0, val);
	return acc * ORACLE_P1 + ORACLE_P4;
}

static inline uint64_t oracle_xxh64(const void *in, size_t len, uint64_t seed)
{
	const uint8_t *p = in, *end = p + len;
	uint64_t h;

	if (len >= 32) {
		uint64_t v1 = seed + ORACLE_P1 + ORACLE_P2, v2 = seed + ORACLE_P2;
		uint64_t v3 = seed, v4 = seed - ORACLE_P1;

		do {
			v1 = oracle_xxh64_round(v1, oracle_le64(p));
			v2 = oracle_xxh64_round(v2, oracle_le64(p + 8));
			v3 = oracle_xxh64_round(v3, oracle_le64(p + 16));
			v4 = oracle_xxh64_round(v4, oracle_le64(p + 24));
			p += 32;
		} while ((size_t)(end - p) >= 32);
		h = oracle_rotl64(v1, 1) + oracle_rotl64(v2, 7) + oracle_rotl64(v3, 12) +
		    oracle_rotl64(v4, 18);
		h = oracle_xxh64_merge(h, v1);
		h = oracle_xxh64_merge(h, v2);
		h = oracle_xxh64_merge(h, v3);
		h = oracle_xxh64_merge(h, v4);
	} else {
		h = seed + ORACLE_P5;
	}
	h += (uint64_t)len;
	while ((size_t)(end - p) >= 8) {
		h ^= oracle_xxh64_round(0, oracle_le64(p));
		h = oracle_rotl64(h, 27) * ORACLE_P1 + ORACLE_P4;
		p += 8;
	}
	if ((size_t)(end - p) >= 4) {
		h ^= (uint64_t)oracle_le32(p) * ORACLE_P1;
		h = oracle_rotl64(h, 23) * ORACLE_P2 + ORACLE_P3;
		p += 4;
	}
	while (p < end) {
		h ^= (*p) * ORACLE_P5;
		h = oracle_rotl64(h, 11) * ORACLE_P1;
		p++;
	}
	h ^= h >> 33;
	h *= ORACLE_P2;
	h ^= h >> 29;
	h *= ORACLE_P3;
	h ^= h >> 32;
	return h;
}

static const uint32_t oracle_sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t oracle_ror32(uint32_t x, int r)
{
	return (x >> r) | (x << (32 - r));
}

static inline void oracle_sha256_block(uint32_t h[8], const uint8_t *b)
{
	uint32_t w[64], a, bb, c, d, e, f, g, hh, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 |
		       (uint32_t)b[4 * i + 2] << 8 | b[4 * i + 3];
	for (i = 16; i < 64; i++)
		w[i] = w[i - 16] + (oracle_ror32(w[i - 15], 7) ^ oracle_ror32(w[i - 15], 18) ^
				    (w[i - 15] >> 3)) +
		       w[i - 7] + (oracle_ror32(w[i - 2], 17) ^ oracle_ror32(w[i - 2], 19) ^
				   (w[i - 2] >> 10));
	a = h[0]; bb = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
	for (i = 0; i < 64; i++) {
		t1 = hh + (oracle_ror32(e, 6) ^ oracle_ror32(e, 11) ^ oracle_ror32(e, 25)) +
		     ((e & f) ^ (~e & g)) + oracle_sha256_k[i] + w[i];
		t2 = (oracle_ror32(a, 2) ^ oracle_ror32(a, 13) ^ oracle_ror32(a, 22)) +
		     ((a & bb) ^ (a & c) ^ (bb & c));
		hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
	}
	h[0] += a; h[1] += bb; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static inline void oracle_sha256(const void *in, size_t len, uint8_t out[32])
{
	uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	const uint8_t *p = in;
	uint8_t tail[128];
	size_t full = len / 64 * 64, rest = len - full, n, i;
	uint64_t bits = (uint64_t)len * 8;

	for (i = 0; i < full; i += 64)
		oracle_sha256_block(h, p + i);
	memset(tail, 0, sizeof(tail));
	memcpy(tail, p + full, rest);
	tail[rest] = 0x80;
	n = rest + 1 + 8 <= 64 ? 64 : 128;
	for (i = 0; i < 8; i++)
		tail[n - 1 - i] = (uint8_t)(bits >> (8 * i));
	for (i = 0; i < n; i += 64)
		oracle_sha256_block(h, tail + i);
	for (i = 0; i < 8; i++) {
		out[4 * i] = (uint8_t)(h[i] >> 24);
		out[4 * i + 1] = (uint8_t)(h[i] >> 16);
		out[4 * i + 2] = (uint8_t)(h[i] >> 8);
		out[4 * i + 3] = (uint8_t)h[i];
	}
}

static inline void oracle_put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static inline void oracle_put_be64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* Published vectors: CRC-32C check value, XXH64 of "" and "abc" with seed 0,
 * SHA-256("abc") (FIPS 180-2 example). True when every oracle matches. */
static inline int oracle_self_test(void)
{
	static const uint8_t sha_abc[32] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
		0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};
	uint8_t d[32];

	if (oracle_crc32c("123456789", 9) != 0xE3069283U)
		return 0;
	if (oracle_xxh64("", 0, 0) != 0xEF46DB3751D8E999ULL ||
	    oracle_xxh64("abc", 3, 0) != 0x44BC2CF5AD770999ULL)
		return 0;
	oracle_sha256("abc", 3, d);
	return !memcmp(d, sha_abc, 32);
}

#endif

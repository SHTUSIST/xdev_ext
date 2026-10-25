/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_EXAMPLE_SHA256_H
#define XDEV_EXT_EXAMPLE_SHA256_H

/*
 * SHA-256 (FIPS 180-4) in plain BPF. Each 64-byte block of the padded
 * message is first turned into its 16 big-endian message words on the
 * stack: a whole block of the frame through one constant 64-byte view, the
 * last partial block word by word (a 4-byte view for a whole word, 1-byte
 * views around the end of the frame), followed by 0x80, zeros and the
 * message length in bits. One compression function therefore serves every
 * block. Every store of a message word is a 32-bit word at a constant
 * index, whatever branch produced it, so the verifier can merge the
 * branches. The 64 rounds are one open-coded loop over a 16-word message
 * schedule, which the verifier walks a few times instead of 64 times per
 * block. The appended form is the one of
 * XDEV_EXT_CPU_XFORM_SHA256_APPEND (io_uring/xdev_ext_mech_cpu_core.h): the
 * 32-byte digest behind the frame.
 */

static const __u32 ex_sha256_k[64] = {
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

EX_INLINE __u32 ex_ror32(__u32 x, int r)
{
	return (x >> r) | (x << (32 - r));
}

EX_INLINE __u32 ex_be32(const __u8 *p)
{
	return (__u32)p[0] << 24 | (__u32)p[1] << 16 | (__u32)p[2] << 8 | p[3];
}

/*
 * One compression of the block with message words @w into @h; @w is spent.
 * The 64 rounds are an open-coded loop: round t keeps the message schedule
 * word W[t] in w[t % 16], so the schedule index is a run-time value bounded
 * to 0..15.
 */
EX_INLINE void ex_sha256_block(__u32 h[8], __u32 w[16])
{
	__u32 a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5];
	__u32 g = h[6], hh = h[7], t1, t2, x, s0, s1, j;
	int t;

	ex_for(t, 0, 64) {
		j = (__u32)t & 15;
		if (t >= 16) {
			/* W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16] */
			x = w[(j + 1) & 15];
			s0 = ex_ror32(x, 7) ^ ex_ror32(x, 18) ^ (x >> 3);
			x = w[(j + 14) & 15];
			s1 = ex_ror32(x, 17) ^ ex_ror32(x, 19) ^ (x >> 10);
			w[j] += s0 + w[(j + 9) & 15] + s1;
		}
		t1 = hh + (ex_ror32(e, 6) ^ ex_ror32(e, 11) ^ ex_ror32(e, 25)) +
		     ((e & f) ^ (~e & g)) + ex_sha256_k[(__u32)t & 63] + w[j];
		t2 = (ex_ror32(a, 2) ^ ex_ror32(a, 13) ^ ex_ror32(a, 22)) +
		     ((a & bb) ^ (a & c) ^ (bb & c));
		hh = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = bb;
		bb = a;
		a = t1 + t2;
	}
	h[0] += a;
	h[1] += bb;
	h[2] += c;
	h[3] += d;
	h[4] += e;
	h[5] += f;
	h[6] += g;
	h[7] += hh;
}

/* Byte @m of the padded message of @len bytes, for @m below a whole word. */
EX_INLINE int ex_sha256_byte(ex_ctx *c, __u32 pos, __u32 len, __u32 m, __u32 *byte)
{
	const __u8 *p;

	if (m < len) {
		p = ex_frame_rw(c, pos, m, 1);
		if (!p)
			return -EX_EFAULT;
		*byte = p[0];
	} else {
		*byte = m == len ? 0x80 : 0;
	}
	return 0;
}

/*
 * The message words of block @blk of the padded message of the frame's
 * first @len bytes into @w.
 */
EX_INLINE int ex_sha256_words(ex_ctx *c, __u32 pos, __u32 len, __u32 blk, __u32 w[16])
{
	__u32 start = blk * 64, base, word, byte, k, i;
	__u64 bits = (__u64)len * 8;
	const __u8 *p;
	int err;

	if (start + 64 <= len) {
		p = ex_frame_rw(c, pos, start, 64);
		if (!p)
			return -EX_EFAULT;
		EX_UNROLL
		for (k = 0; k < 16; k++)
			w[k] = ex_be32(p + 4 * k);
		return 0;
	}
	EX_UNROLL
	for (k = 0; k < 16; k++) {
		base = start + 4 * k;
		if (base + 4 <= len) {
			p = ex_frame_rw(c, pos, base, 4);
			if (!p)
				return -EX_EFAULT;
			word = ex_be32(p);
		} else {
			word = 0;
			EX_UNROLL
			for (i = 0; i < 4; i++) {
				err = ex_sha256_byte(c, pos, len, base + i, &byte);
				if (err)
					return err;
				word |= byte << (24 - 8 * i);
			}
		}
		w[k] = word;
	}
	/* The length closes the last block: the one where it fits after 0x80. */
	if ((len + 8) / 64 == blk) {
		w[14] = (__u32)(bits >> 32);
		w[15] = (__u32)bits;
	}
	return 0;
}

/* SHA-256 of the frame's first @len bytes into @out (32 bytes, big endian). */
EX_INLINE int ex_sha256_frame(ex_ctx *c, __u32 pos, __u32 len, __u32 h[8])
{
	__u32 w[16];
	int blk, err;

	h[0] = 0x6a09e667;
	h[1] = 0xbb67ae85;
	h[2] = 0x3c6ef372;
	h[3] = 0xa54ff53a;
	h[4] = 0x510e527f;
	h[5] = 0x9b05688c;
	h[6] = 0x1f83d9ab;
	h[7] = 0x5be0cd19;
	/* Padded length: len + 1 + 8 rounded up to whole blocks. */
	ex_for(blk, 0, (len + 8) / 64 + 1) {
		err = ex_sha256_words(c, pos, len, (__u32)blk, w);
		if (err)
			return err;
		ex_sha256_block(h, w);
	}
	return 0;
}

/*
 * Append SHA-256(frame) behind every frame, like
 * XDEV_EXT_CPU_XFORM_SHA256_APPEND (stage length change +32).
 */
EX_INLINE int ex_sha256_append(ex_ctx *c)
{
	__u32 len, h[8], k;
	__u8 *p;
	int pos, err;

	ex_for(pos, 0, ex_nr_frames(c)) {
		len = ex_frame_len(c, pos);
		err = ex_sha256_frame(c, pos, len, h);
		if (err)
			return err;
		p = ex_frame_rw(c, pos, len, 32);
		if (!p)
			return -EX_EFAULT;
		EX_UNROLL
		for (k = 0; k < 8; k++) {
			p[4 * k] = (__u8)(h[k] >> 24);
			p[4 * k + 1] = (__u8)(h[k] >> 16);
			p[4 * k + 2] = (__u8)(h[k] >> 8);
			p[4 * k + 3] = (__u8)h[k];
		}
		if (ex_frame_set_len(c, pos, len + 32))
			return -EX_EINVAL;
	}
	return 0;
}

#endif

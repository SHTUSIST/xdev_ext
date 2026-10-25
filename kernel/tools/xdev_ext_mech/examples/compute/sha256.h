/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_EXAMPLE_SHA256_H
#define XDEV_EXT_EXAMPLE_SHA256_H

/*
 * SHA-256 (FIPS 180-4) in plain BPF. Each 64-byte block of the padded
 * message is first turned into its 16 big-endian message words on the
 * stack, so that one compression function serves every block. A whole block
 * of the frame comes from one constant 64-byte view. The block that holds
 * the end of the frame, and a block of padding only, are assembled byte by
 * byte without a branch: every byte is read from one view that covers the
 * end of the frame (at run-time indexes bounded by a mask), and masks
 * computed from the byte's position keep a data byte, put 0x80 right after
 * the data, or put 0. The bit length closes the last block.
 *
 * The shape is chosen for the verifier. Inside an open-coded loop that has
 * not yet converged the verifier merges few paths, so every branch in the
 * block code multiplies the work; the block code has a handful. Each message
 * word lives in its own 64-bit stack slot, so storing a data word and storing
 * a padding zero leave the same kind of slot (a 4-byte store of a known zero
 * would mark the bytes as zero and keep every pattern of zero words apart).
 * The 16 words of such a block are one open-coded loop too.
 * The 64 rounds are two open-coded loops, rounds 0..15 and 16..63 with the
 * message schedule in w[t % 16], which the verifier walks a few times
 * instead of 64 times per block.
 *
 * The appended form is the one of XDEV_EXT_CPU_XFORM_SHA256_APPEND
 * (io_uring/xdev_ext_mech_cpu_core.h): the 32-byte digest behind the frame.
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

/* One round of the compression; W[t] is @wt. */
#define EX_SHA256_ROUND(t, wt)							\
	do {									\
		t1 = hh + (ex_ror32(e, 6) ^ ex_ror32(e, 11) ^ ex_ror32(e, 25)) +	\
		     ((e & f) ^ (~e & g)) + ex_sha256_k[(__u32)(t) & 63] + (wt);	\
		t2 = (ex_ror32(a, 2) ^ ex_ror32(a, 13) ^ ex_ror32(a, 22)) +	\
		     ((a & bb) ^ (a & c) ^ (bb & c));				\
		hh = g;								\
		g = f;								\
		f = e;								\
		e = d + t1;							\
		d = c;								\
		c = bb;								\
		bb = a;								\
		a = t1 + t2;							\
	} while (0)

/*
 * One compression of the block with message words @w into @h; @w is spent.
 * Rounds 16..63 keep the message schedule word W[t] in w[t % 16], a
 * run-time stack index bounded to 0..15.
 */
EX_INLINE void ex_sha256_block(__u32 h[8], __u64 w[16])
{
	__u32 a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5];
	__u32 g = h[6], hh = h[7], t1, t2, x, s0, s1, j;
	int t;

	ex_for(t, 0, 16)
		EX_SHA256_ROUND(t, (__u32)w[(__u32)t & 15]);
	ex_for(t, 16, 64) {
		/* W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16] */
		j = (__u32)t & 15;
		x = (__u32)w[(j + 1) & 15];
		s0 = ex_ror32(x, 7) ^ ex_ror32(x, 18) ^ (x >> 3);
		x = (__u32)w[(j + 14) & 15];
		s1 = ex_ror32(x, 17) ^ ex_ror32(x, 19) ^ (x >> 10);
		w[j] = (__u32)(w[j] + s0 + w[(j + 9) & 15] + s1);
		EX_SHA256_ROUND(t, (__u32)w[j]);
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

/*
 * The 16 words of the block at message offset @start that holds the end of
 * the message (@len bytes) or only padding. @q views frame bytes from
 * offset @anchor on, @mask + 1 of them (a power of two), and covers every
 * data byte of the block. No branch: a byte at or past @len is read anyway
 * (inside @q) and masked off. The word loop is an open-coded loop, so the
 * word index is a run-time value bounded to 0..15.
 */
EX_INLINE void ex_sha256_tail(__u64 w[16], const __u8 *q, __u32 mask, __u32 anchor,
			      __u32 start, __u32 len)
{
	__u32 i, m, word, data;
	__s64 dist, lt, eq;
	int k;

	ex_for(k, 0, 16) {
		word = 0;
		EX_UNROLL
		for (i = 0; i < 4; i++) {
			m = start + 4 * (__u32)k + i;
			data = q[(m - anchor) & mask];
			dist = (__s64)m - (__s64)len;
			/* -1 when m < len, else 0; -1 when m == len, else 0. */
			lt = dist >> 63;
			eq = (((dist | -dist) >> 63) + 1) & 1;
			eq = -eq;
			/* Keep the compiler from turning the masks into branches. */
			EX_OPAQUE(lt);
			EX_OPAQUE(eq);
			word |= ((data & (__u32)lt) | (0x80U & (__u32)eq)) << (24 - 8 * i);
		}
		w[(__u32)k & 15] = word;
	}
}

/*
 * The message words of block @blk of the padded message of the frame's
 * first @len bytes into @w. The frame capacity is at least @len + 32 (the
 * stage declares +32), which every view below relies on.
 */
EX_INLINE int ex_sha256_words(ex_ctx *c, __u32 pos, __u32 len, __u32 blk, __u64 w[16])
{
	__u32 start = blk * 64, anchor, mask, k;
	__u64 bits = (__u64)len * 8;
	const __u8 *p;

	if (start + 64 <= len) {
		p = ex_frame_rw(c, pos, start, 64);
		if (!p)
			return -EX_EFAULT;
		EX_UNROLL
		for (k = 0; k < 16; k++)
			w[k] = ex_be32(p + 4 * k);
		return 0;
	}
	if (len >= 32) {
		/* The last 64 bytes, or the first 64 of a frame of 32..63 bytes. */
		anchor = len >= 64 ? len - 64 : 0;
		mask = 63;
		p = ex_frame_rw(c, pos, anchor, 64);
	} else {
		anchor = 0;
		mask = 31;
		p = ex_frame_rw(c, pos, 0, 32);
	}
	if (!p)
		return -EX_EFAULT;
	ex_sha256_tail(w, p, mask, anchor, start, len);
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
	__u64 w[16];
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

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_EXAMPLE_XXH64_H
#define XDEV_EXT_EXAMPLE_XXH64_H

/*
 * XXH64 in plain BPF. 32-byte stripes are read by an open-coded loop over
 * constant 32-byte views; the remainder of 0..31 bytes by at most three
 * 8-byte views, one 4-byte view and three 1-byte views, as the reference
 * algorithm consumes it. Only 64-bit adds, multiplies, shifts and xors.
 * The appended form is the one of XDEV_EXT_CPU_XFORM_XXH64_APPEND
 * (io_uring/xdev_ext_mech_cpu_core.h): the 64-bit hash, big endian.
 */

#define EX_XXH_P1 0x9E3779B185EBCA87ULL
#define EX_XXH_P2 0xC2B2AE3D27D4EB4FULL
#define EX_XXH_P3 0x165667B19E3779F9ULL
#define EX_XXH_P4 0x85EBCA77C2B2AE63ULL
#define EX_XXH_P5 0x27D4EB2F165667C5ULL

EX_INLINE __u64 ex_rotl64(__u64 x, int r)
{
	return (x << r) | (x >> (64 - r));
}

EX_INLINE __u64 ex_xxh64_round(__u64 acc, __u64 input)
{
	acc += input * EX_XXH_P2;
	acc = ex_rotl64(acc, 31);
	return acc * EX_XXH_P1;
}

EX_INLINE __u64 ex_xxh64_merge(__u64 acc, __u64 val)
{
	acc ^= ex_xxh64_round(0, val);
	return acc * EX_XXH_P1 + EX_XXH_P4;
}

/* XXH64 with @seed of bytes [@off, @off + @len) of frame @pos into *@out. */
EX_INLINE int ex_xxh64_range(ex_ctx *c, __u32 pos, __u32 off, __u32 len, __u64 seed,
			     __u64 *out)
{
	__u64 h, v1 = seed + EX_XXH_P1 + EX_XXH_P2, v2 = seed + EX_XXH_P2;
	__u64 v3 = seed, v4 = seed - EX_XXH_P1;
	int i, stripes = (int)(len / 32);
	__u32 base, rem = len % 32, k;
	const __u8 *p;

	ex_for(i, 0, stripes) {
		p = ex_frame_rw(c, pos, off + (__u32)i * 32, 32);
		if (!p)
			return -EX_EFAULT;
		v1 = ex_xxh64_round(v1, ex_le64(p));
		v2 = ex_xxh64_round(v2, ex_le64(p + 8));
		v3 = ex_xxh64_round(v3, ex_le64(p + 16));
		v4 = ex_xxh64_round(v4, ex_le64(p + 24));
	}
	if (stripes) {
		h = ex_rotl64(v1, 1) + ex_rotl64(v2, 7) + ex_rotl64(v3, 12) + ex_rotl64(v4, 18);
		h = ex_xxh64_merge(h, v1);
		h = ex_xxh64_merge(h, v2);
		h = ex_xxh64_merge(h, v3);
		h = ex_xxh64_merge(h, v4);
	} else {
		h = seed + EX_XXH_P5;
	}
	h += len;
	base = off + (__u32)stripes * 32;
	EX_UNROLL
	for (k = 0; k < 3; k++) {
		if (rem < 8)
			break;
		p = ex_frame_rw(c, pos, base, 8);
		if (!p)
			return -EX_EFAULT;
		h ^= ex_xxh64_round(0, ex_le64(p));
		h = ex_rotl64(h, 27) * EX_XXH_P1 + EX_XXH_P4;
		base += 8;
		rem -= 8;
	}
	if (rem >= 4) {
		p = ex_frame_rw(c, pos, base, 4);
		if (!p)
			return -EX_EFAULT;
		h ^= (__u64)ex_le32(p) * EX_XXH_P1;
		h = ex_rotl64(h, 23) * EX_XXH_P2 + EX_XXH_P3;
		base += 4;
		rem -= 4;
	}
	EX_UNROLL
	for (k = 0; k < 3; k++) {
		if (!rem)
			break;
		p = ex_frame_rw(c, pos, base, 1);
		if (!p)
			return -EX_EFAULT;
		h ^= (__u64)p[0] * EX_XXH_P5;
		h = ex_rotl64(h, 11) * EX_XXH_P1;
		base++;
		rem--;
	}
	h ^= h >> 33;
	h *= EX_XXH_P2;
	h ^= h >> 29;
	h *= EX_XXH_P3;
	h ^= h >> 32;
	*out = h;
	return 0;
}

/*
 * Append XXH64(frame, @seed) to every frame, big endian, like
 * XDEV_EXT_CPU_XFORM_XXH64_APPEND with stage parameter @seed (stage length
 * change +8).
 */
EX_INLINE int ex_xxh64_append(ex_ctx *c, __u64 seed)
{
	__u32 len;
	__u64 h;
	__u8 *p;
	int pos, err;

	ex_for(pos, 0, ex_nr_frames(c)) {
		len = ex_frame_len(c, pos);
		err = ex_xxh64_range(c, pos, 0, len, seed, &h);
		if (err)
			return err;
		p = ex_frame_rw(c, pos, len, 8);
		if (!p)
			return -EX_EFAULT;
		ex_put_be64(p, h);
		if (ex_frame_set_len(c, pos, len + 8))
			return -EX_EINVAL;
	}
	return 0;
}

#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_EXAMPLE_CRC32C_H
#define XDEV_EXT_EXAMPLE_CRC32C_H

/*
 * CRC32C in plain BPF, without a CRC kfunc: a table lookup per byte
 * (EX_CRC32C_SLICE8 0, 1 KiB table) or per eight bytes (EX_CRC32C_SLICE8 1,
 * 8 KiB of tables, the slice-by-8 method). The table lives in .rodata; every
 * index is masked to 0..255, so the verifier sees each access in bounds.
 *
 * A frame's length is a run-time value, but every view of a frame has a
 * constant size. The bytes are therefore read in EX_CRC32C_CHUNK-byte views
 * by an open-coded loop (bpf_for), and the remainder by a fixed ladder of
 * views of 128, 64, 32, 16, 8, 4, 2 and 1 bytes.
 *
 * The CRC convention is the one of the fixed transforms
 * (io_uring/xdev_ext_mech_cpu_core.h): ~crc32c(~0, payload), stored little
 * endian behind the payload.
 */

#include "crc32c_table.h"

#define EX_CRC32C_CHUNK 256U

EX_INLINE __u32 ex_crc32c_byte(__u32 crc, __u8 b)
{
	return ex_crc32c_tab[0][(crc ^ b) & 0xff] ^ (crc >> 8);
}

#if EX_CRC32C_SLICE8
/* Eight bytes: byte j needs 7 - j more zero bytes behind it, row 7 - j. */
EX_INLINE __u32 ex_crc32c_word8(__u32 crc, const __u8 *p)
{
	__u32 lo = crc ^ ex_le32(p), hi = ex_le32(p + 4);

	return ex_crc32c_tab[7][lo & 0xff] ^ ex_crc32c_tab[6][(lo >> 8) & 0xff] ^
	       ex_crc32c_tab[5][(lo >> 16) & 0xff] ^ ex_crc32c_tab[4][(lo >> 24) & 0xff] ^
	       ex_crc32c_tab[3][hi & 0xff] ^ ex_crc32c_tab[2][(hi >> 8) & 0xff] ^
	       ex_crc32c_tab[1][(hi >> 16) & 0xff] ^ ex_crc32c_tab[0][(hi >> 24) & 0xff];
}
#endif

/* Raw update over @n bytes at @p; @n is a constant at every call site. */
EX_INLINE __u32 ex_crc32c_block(__u32 crc, const __u8 *p, const __u32 n)
{
	__u32 k;

#if EX_CRC32C_SLICE8
	/* Unrolled, the table loads of 32 words exceed the BPF stack. */
	EX_NOUNROLL
	for (k = 0; k < n / 8; k++)
		crc = ex_crc32c_word8(crc, p + 8 * k);
#endif
	EX_UNROLL
	for (k = EX_CRC32C_SLICE8 ? n / 8 * 8 : 0; k < n; k++)
		crc = ex_crc32c_byte(crc, p[k]);
	return crc;
}

#define EX_CRC32C_TAIL(size)						\
	if (rem & (size)) {						\
		p = ex_frame_rw(c, pos, base, size);			\
		if (!p)							\
			return -EX_EFAULT;				\
		crc = ex_crc32c_block(crc, p, size);			\
		base += size;						\
	}

/*
 * Raw update (neither pre- nor post-inversion) of *@crcp over bytes
 * [@off, @off + @len) of frame @pos, counted from its first valid byte.
 * -EX_EFAULT, with *@crcp unchanged, if a view lies outside the frame.
 */
EX_INLINE int ex_crc32c_range(ex_ctx *c, __u32 pos, __u32 off, __u32 len, __u32 *crcp)
{
	int i, chunks = (int)(len / EX_CRC32C_CHUNK);
	__u32 crc = *crcp, base, rem = len % EX_CRC32C_CHUNK;
	const __u8 *p;

	ex_for(i, 0, chunks) {
		p = ex_frame_rw(c, pos, off + (__u32)i * EX_CRC32C_CHUNK, EX_CRC32C_CHUNK);
		if (!p)
			return -EX_EFAULT;
		crc = ex_crc32c_block(crc, p, EX_CRC32C_CHUNK);
	}
	base = off + (__u32)chunks * EX_CRC32C_CHUNK;
	EX_CRC32C_TAIL(128)
	EX_CRC32C_TAIL(64)
	EX_CRC32C_TAIL(32)
	EX_CRC32C_TAIL(16)
	EX_CRC32C_TAIL(8)
	EX_CRC32C_TAIL(4)
	EX_CRC32C_TAIL(2)
	EX_CRC32C_TAIL(1)
	*crcp = crc;
	return 0;
}

/*
 * Every frame ends with the CRC32C of the bytes before it (the layout of
 * XDEV_EXT_CPU_XFORM_CRC32C_SEAL and _APPEND). Like XDEV_EXT_CPU_XFORM_CRC32C_CHECK
 * (stage length change 0), or with @strip like XDEV_EXT_CPU_XFORM_CRC32C_STRIP
 * (length change -4): the four CRC bytes leave the frame. A frame shorter
 * than four bytes or with a wrong CRC fails the batch with -EBADMSG, before
 * any later frame is looked at. No byte is written.
 */
EX_INLINE int ex_crc32c_check(ex_ctx *c, int strip)
{
	const __u8 *p;
	__u32 len, crc;
	int pos, err;

	ex_for(pos, 0, ex_nr_frames(c)) {
		len = ex_frame_len(c, pos);
		if (len < 4)
			return -EX_EBADMSG;
		crc = ~0U;
		err = ex_crc32c_range(c, pos, 0, len - 4, &crc);
		if (err)
			return err;
		p = ex_frame_rw(c, pos, len - 4, 4);
		if (!p)
			return -EX_EFAULT;
		if (ex_le32(p) != ~crc)
			return -EX_EBADMSG;
		if (strip && ex_frame_set_len(c, pos, len - 4))
			return -EX_EINVAL;
	}
	return 0;
}

/*
 * Append the CRC32C of every frame behind it, like
 * XDEV_EXT_CPU_XFORM_CRC32C_APPEND (stage length change +4).
 */
EX_INLINE int ex_crc32c_append(ex_ctx *c)
{
	__u32 len, crc;
	__u8 *p;
	int pos, err;

	ex_for(pos, 0, ex_nr_frames(c)) {
		len = ex_frame_len(c, pos);
		crc = ~0U;
		err = ex_crc32c_range(c, pos, 0, len, &crc);
		if (err)
			return err;
		p = ex_frame_rw(c, pos, len, 4);
		if (!p)
			return -EX_EFAULT;
		ex_put_le32(p, ~crc);
		if (ex_frame_set_len(c, pos, len + 4))
			return -EX_EINVAL;
	}
	return 0;
}

#endif

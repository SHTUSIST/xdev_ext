/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_EXAMPLE_PARSE_H
#define XDEV_EXT_EXAMPLE_PARSE_H

/*
 * The header check of XDEV_EXT_CPU_XFORM_PARSE_STRIP
 * (io_uring/xdev_ext_mech_cpu_core.h), without the strip: a frame starts with
 * a header of @hdr bytes whose first four bytes hold, little endian, the
 * number of payload bytes behind the header. Moving the payload to the front
 * stays the kernel's fixed transform; this check writes nothing and keeps
 * every length (stage length change 0).
 */

#define EX_PARSE_HDR_MIN 4U	/* XDEV_EXT_CPU_PARSE_HDR_MIN */
#define EX_PARSE_HDR_MAX 256U	/* XDEV_EXT_CPU_PARSE_HDR_MAX */

/*
 * -EX_EINVAL for a header length the fixed transform refuses; -EX_EBADMSG
 * for a frame shorter than the header or with a wrong length word.
 */
EX_INLINE int ex_parse_check(ex_ctx *c, __u32 hdr)
{
	const __u8 *p;
	__u32 len;
	int pos;

	if (hdr < EX_PARSE_HDR_MIN || hdr > EX_PARSE_HDR_MAX)
		return -EX_EINVAL;
	ex_for(pos, 0, ex_nr_frames(c)) {
		len = ex_frame_len(c, pos);
		if (len < hdr)
			return -EX_EBADMSG;
		p = ex_frame_rw(c, pos, 0, 4);
		if (!p)
			return -EX_EFAULT;
		if (ex_le32(p) != len - hdr)
			return -EX_EBADMSG;
	}
	return 0;
}

#endif

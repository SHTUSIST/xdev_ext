/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_XDOMAIN_PROBE_CORE_H
#define _XDEV_EXT_XDOMAIN_PROBE_CORE_H
#include "xdev_ext_xdomain_core.h"

#define XD_PROBE_CTL_MAGIC 0x31425358U
#define XD_PROBE_DATA_MAGIC 0x31514458U
#define XD_PROBE_VERSION 1U
#define XD_PROBE_READY 1U
#define XD_PROBE_DONE 2U
#define XD_PROBE_PING 1U
#define XD_PROBE_PONG 2U
#define XD_PROBE_PING_LEN 128U
#define XD_PROBE_PONG_LEN 4096U
#define XD_PROBE_BYTES 16384U
struct xdev_ext_xd_probe_msg {
	__u64 src_inc, dst_inc;
	__u8 src_nonce[16], dst_nonce[16];
	__u8 type, channel, direction, origin;
};
static inline __u64 xdev_ext_xd_probe_worst_bytes(__u32 channels)
{
	return (__u64)XD_PROBE_BYTES * channels;
}
static inline bool xdev_ext_xd_probe_nonce_nonzero(const __u8 n[16])
{
	unsigned int i, v = 0;
	for (i = 0; i < 16; i++)
		v |= n[i];
	return v != 0;
}
static inline void xdev_ext_xd_probe_header(__u8 *out, __u32 len, __u32 magic,
					 const struct xdev_ext_xd_probe_msg *m)
{
	unsigned int i;
	for (i = 0; i < len; i++)
		out[i] = 0;
	xdev_ext_xd_put(out, magic, 4);
	out[4] = XD_PROBE_VERSION;
	out[5] = m->type;
	out[6] = m->channel;
	out[7] = m->direction;
	xdev_ext_xd_put(out + 8, m->src_inc, 8);
	xdev_ext_xd_put(out + 16, m->dst_inc, 8);
	for (i = 0; i < 16; i++) {
		out[24 + i] = m->src_nonce[i];
		out[40 + i] = m->dst_nonce[i];
	}
}
static inline int xdev_ext_xd_probe_common(const struct xdev_ext_xd_probe_msg *m)
{
	return !m->src_inc || !m->dst_inc || m->channel >= XDEV_EXT_XD_MAX_CHANNELS ||
		m->direction > 1 || !xdev_ext_xd_probe_nonce_nonzero(m->src_nonce) ? -EPROTO : 0;
}
static inline int xdev_ext_xd_probe_ctl_encode(__u8 out[128],
		const struct xdev_ext_xd_probe_msg *m, xdev_ext_xd_crc_fn crc)
{
	if (xdev_ext_xd_probe_common(m) || (m->type != XD_PROBE_READY && m->type != XD_PROBE_DONE) ||
	    (m->type == XD_PROBE_READY ? xdev_ext_xd_probe_nonce_nonzero(m->dst_nonce) :
					 !xdev_ext_xd_probe_nonce_nonzero(m->dst_nonce)))
		return -EPROTO;
	xdev_ext_xd_probe_header(out, 128, XD_PROBE_CTL_MAGIC, m);
	xdev_ext_xd_put(out + 56, XD_PROBE_PING_LEN, 4);
	xdev_ext_xd_put(out + 60, XD_PROBE_PONG_LEN, 4);
	xdev_ext_xd_put(out + 124, (__u32)~crc(~0U, out, 124), 4);
	return 0;
}
static inline void xdev_ext_xd_probe_read(const __u8 *in, struct xdev_ext_xd_probe_msg *m)
{
	unsigned int i;
	*m = (struct xdev_ext_xd_probe_msg){ .src_inc = xdev_ext_xd_get(in + 8, 8),
		.dst_inc = xdev_ext_xd_get(in + 16, 8), .type = in[5],
		.channel = in[6], .direction = in[7], .origin = in[56] };
	for (i = 0; i < 16; i++) {
		m->src_nonce[i] = in[24 + i];
		m->dst_nonce[i] = in[40 + i];
	}
}
static inline int xdev_ext_xd_probe_ctl_decode(const __u8 *in, __u32 len,
		xdev_ext_xd_crc_fn crc, struct xdev_ext_xd_probe_msg *m)
{
	unsigned int i;
	if (len != 128)
		return -EMSGSIZE;
	if (xdev_ext_xd_get(in, 4) != XD_PROBE_CTL_MAGIC)
		return -EPROTO;
	if (in[4] != XD_PROBE_VERSION)
		return -EPROTONOSUPPORT;
	if ((__u32)xdev_ext_xd_get(in + 124, 4) != (__u32)~crc(~0U, in, 124))
		return -EBADMSG;
	if (xdev_ext_xd_get(in + 56, 4) != XD_PROBE_PING_LEN ||
	    xdev_ext_xd_get(in + 60, 4) != XD_PROBE_PONG_LEN)
		return -EPROTO;
	for (i = 64; i < 124; i++)
		if (in[i])
			return -EPROTO;
	xdev_ext_xd_probe_read(in, m);
	m->origin = 0;
	if (!xdev_ext_xd_probe_nonce_nonzero(m->src_nonce) ||
	    (m->type == XD_PROBE_DONE && !xdev_ext_xd_probe_nonce_nonzero(m->dst_nonce)))
		return -EBADMSG;
	if (xdev_ext_xd_probe_common(m) || (m->type != XD_PROBE_READY && m->type != XD_PROBE_DONE) ||
	    (m->type == XD_PROBE_READY ? xdev_ext_xd_probe_nonce_nonzero(m->dst_nonce) :
					 !xdev_ext_xd_probe_nonce_nonzero(m->dst_nonce)))
		return -EPROTO;
	return 0;
}
static inline __u32 xdev_ext_xd_probe_pattern(__u32 seed, __u32 index, xdev_ext_xd_crc_fn crc)
{
	__u8 word[4];
	xdev_ext_xd_put(word, index, 4);
	return ~crc(seed, word, 4);
}
static inline int xdev_ext_xd_probe_data_encode(__u8 *out, __u32 len,
		const struct xdev_ext_xd_probe_msg *m, xdev_ext_xd_crc_fn crc)
{
	__u32 i, seed, word = 0;
	if (xdev_ext_xd_probe_common(m) || !xdev_ext_xd_probe_nonce_nonzero(m->dst_nonce) ||
	    (m->type != XD_PROBE_PING && m->type != XD_PROBE_PONG) ||
	    m->origin != (m->direction ^ (m->type == XD_PROBE_PONG)))
		return -EPROTO;
	if (len != (m->type == XD_PROBE_PING ? XD_PROBE_PING_LEN : XD_PROBE_PONG_LEN))
		return -EMSGSIZE;
	xdev_ext_xd_probe_header(out, len, XD_PROBE_DATA_MAGIC, m);
	out[56] = m->origin;
	xdev_ext_xd_put(out + 60, len, 4);
	seed = crc(~0U, out, 64);
	for (i = 64; i < len - 4; i++) {
		if (!(i & 3))
			word = xdev_ext_xd_probe_pattern(seed, (i - 64) / 4, crc);
		out[i] = (__u8)(word >> ((i & 3) * 8));
	}
	xdev_ext_xd_put(out + len - 4, (__u32)~crc(~0U, out, len - 4), 4);
	return 0;
}
static inline int xdev_ext_xd_probe_data_decode(const __u8 *in, __u32 len,
		xdev_ext_xd_crc_fn crc, struct xdev_ext_xd_probe_msg *m)
{
	__u32 i, seed, word = 0;
	if (len != XD_PROBE_PING_LEN && len != XD_PROBE_PONG_LEN)
		return -EMSGSIZE;
	if (xdev_ext_xd_get(in, 4) != XD_PROBE_DATA_MAGIC)
		return -EPROTO;
	if (in[4] != XD_PROBE_VERSION)
		return -EPROTONOSUPPORT;
	if ((__u32)xdev_ext_xd_get(in + len - 4, 4) != (__u32)~crc(~0U, in, len - 4))
		return -EBADMSG;
	xdev_ext_xd_probe_read(in, m);
	if (!xdev_ext_xd_probe_nonce_nonzero(m->src_nonce) ||
	    !xdev_ext_xd_probe_nonce_nonzero(m->dst_nonce))
		return -EBADMSG;
	if (xdev_ext_xd_probe_common(m) ||
	    (m->type != XD_PROBE_PING && m->type != XD_PROBE_PONG) || in[57] || in[58] || in[59] ||
	    m->origin != (m->direction ^ (m->type == XD_PROBE_PONG)))
		return -EPROTO;
	if (xdev_ext_xd_get(in + 60, 4) != len ||
	    len != (m->type == XD_PROBE_PING ? XD_PROBE_PING_LEN : XD_PROBE_PONG_LEN))
		return -EMSGSIZE;
	seed = crc(~0U, in, 64);
	for (i = 64; i < len - 4; i++) {
		if (!(i & 3))
			word = xdev_ext_xd_probe_pattern(seed, (i - 64) / 4, crc);
		if (in[i] != (__u8)(word >> ((i & 3) * 8)))
			return -EBADMSG;
	}
	return 0;
}
#endif

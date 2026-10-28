/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_XDOMAIN_EARLY_H
#define _XDEV_EXT_XDOMAIN_EARLY_H
#include "xdev_ext_xdomain_core.h"

#define XDEV_EXT_XD_MSG_V2_MAGIC 0x3244584eU
#define XDEV_EXT_XD_MSG_V2_VERSION 2U
#define XDEV_EXT_XD_HELLO 7U
#define XDEV_EXT_XD_CHALLENGE 8U
#define XDEV_EXT_XD_CONFIRM 9U

/* Host representation. All wire fields are encoded explicitly. */
struct xdev_ext_xd_msg_v2 {
	__u64 src_inc, dst_inc, tx_bind, rx_bind, group, credit, data_seq, key;
	__u32 total_len, seg_len;
	__u16 count, status;
	__u8 type, channel, tag[XDEV_EXT_XDOMAIN_TAG_LEN];
};
static inline int xdev_ext_xd_early_shape(__u32 total, __u32 seg, __u32 *count)
{
	__u64 frames, full, tail, n;
	if (!total || !seg || !count)
		return -EINVAL;
	frames = ((__u64)total + seg - 1) / seg;
	full = total / seg;
	tail = total % seg;
	n = full * (((__u64)seg + 4095) / 4096) + (tail + 4095) / 4096;
	if (frames > XDEV_EXT_MECH_MAX_FRAMES || n > XDEV_EXT_XDOMAIN_MAX_ELEMS)
		return -E2BIG;
	*count = n;
	return 0;
}
static inline void xdev_ext_xd_key_tag(__u8 tag[XDEV_EXT_XDOMAIN_TAG_LEN], __u64 key)
{
	unsigned int i;
	for (i = 0; i < XDEV_EXT_XDOMAIN_TAG_LEN; i++)
		tag[i] = i < 8 ? (__u8)(key >> (56 - 8 * i)) : 0;
}
static inline int xdev_ext_xd_msg_v2_layout(const struct xdev_ext_xd_msg_v2 *m)
{
	__u32 count;
	unsigned int i, tag = 0, bad = 0;
	if (!m || !m->src_inc || !m->dst_inc || !m->tx_bind ||
	    m->channel >= XDEV_EXT_XD_MAX_CHANNELS)
		return -EPROTO;
	for (i = 0; i < XDEV_EXT_XDOMAIN_TAG_LEN; i++) {
		tag |= m->tag[i];
		bad |= m->tag[i] ^ (i < 8 ? (__u8)(m->key >> (56 - 8 * i)) : 0);
	}
	switch (m->type) {
	case XDEV_EXT_XD_HELLO:
	case XDEV_EXT_XD_CHALLENGE:
	case XDEV_EXT_XD_CONFIRM:
		if ((m->type == XDEV_EXT_XD_HELLO ? !!m->rx_bind : !m->rx_bind) ||
		    m->group || m->credit || m->data_seq || m->key || m->status || tag ||
		    xdev_ext_xd_early_shape(m->total_len, m->seg_len, &count) || count != m->count)
			return -EPROTO;
		return 0;
	case XDEV_EXT_XD_CTS:
		return !m->rx_bind || !m->group || !m->credit || m->group >= m->credit ||
		       m->status || bad ||
		       xdev_ext_xd_early_shape(m->total_len, m->seg_len, &count) || count != m->count ? -EPROTO : 0;
	case XDEV_EXT_XD_ACK:
	case XDEV_EXT_XD_HELD:
		if (!m->credit || m->status)
			return -EPROTO;
		break;
	case XDEV_EXT_XD_FAIL:
		if (!m->status || m->status > 4095)
			return -EPROTO;
		break;
	case XDEV_EXT_XD_CANCEL:
		if (m->credit || m->status)
			return -EPROTO;
		break;
	default:
		return -EPROTO;
	}
	return !m->rx_bind || !m->group || m->data_seq || m->key || m->total_len ||
	       m->seg_len || m->count || tag ? -EPROTO : 0;
}
static inline int xdev_ext_xd_msg_v2_encode(__u8 out[128],
	const struct xdev_ext_xd_msg_v2 *m, xdev_ext_xd_crc_fn crc)
{
	unsigned int i;
	if (!out || !crc || xdev_ext_xd_msg_v2_layout(m))
		return -EINVAL;
	for (i = 0; i < 128; i++) out[i] = 0;
	xdev_ext_xd_put(out, XDEV_EXT_XD_MSG_V2_MAGIC, 4);
	out[4] = 2; out[5] = m->type; out[6] = m->channel;
	xdev_ext_xd_put(out + 8, m->src_inc, 8);
	xdev_ext_xd_put(out + 16, m->dst_inc, 8);
	xdev_ext_xd_put(out + 24, m->tx_bind, 8);
	xdev_ext_xd_put(out + 32, m->rx_bind, 8);
	xdev_ext_xd_put(out + 40, m->group, 8);
	xdev_ext_xd_put(out + 48, m->credit, 8);
	xdev_ext_xd_put(out + 56, m->data_seq, 8);
	xdev_ext_xd_put(out + 64, m->key, 8);
	xdev_ext_xd_put(out + 72, m->total_len, 4);
	xdev_ext_xd_put(out + 76, m->count, 2);
	xdev_ext_xd_put(out + 78, m->status, 2);
	xdev_ext_xd_put(out + 80, m->seg_len, 4);
	for (i = 0; i < XDEV_EXT_XDOMAIN_TAG_LEN; i++) out[96 + i] = m->tag[i];
	xdev_ext_xd_put(out + 124, (__u32)~crc(~0U, out, 124), 4);
	return 0;
}
static inline int xdev_ext_xd_msg_v2_decode(const __u8 *in, __u32 len,
	xdev_ext_xd_crc_fn crc, struct xdev_ext_xd_msg_v2 *m)
{
	struct xdev_ext_xd_msg_v2 decoded;
	unsigned int i;
	if (!in || !m || !crc || len != 128 ||
	    xdev_ext_xd_get(in, 4) != XDEV_EXT_XD_MSG_V2_MAGIC || in[4] != 2 ||
	    (__u32)xdev_ext_xd_get(in + 124, 4) != (__u32)~crc(~0U, in, 124))
		return -EBADMSG;
	if (in[7] || xdev_ext_xd_get(in + 84, 4) || xdev_ext_xd_get(in + 88, 8) ||
	    xdev_ext_xd_get(in + 120, 4))
		return -EPROTO;
	decoded = (struct xdev_ext_xd_msg_v2){
		.src_inc = xdev_ext_xd_get(in + 8, 8), .dst_inc = xdev_ext_xd_get(in + 16, 8),
		.tx_bind = xdev_ext_xd_get(in + 24, 8), .rx_bind = xdev_ext_xd_get(in + 32, 8),
		.group = xdev_ext_xd_get(in + 40, 8), .credit = xdev_ext_xd_get(in + 48, 8),
		.data_seq = xdev_ext_xd_get(in + 56, 8), .key = xdev_ext_xd_get(in + 64, 8),
		.total_len = xdev_ext_xd_get(in + 72, 4), .count = xdev_ext_xd_get(in + 76, 2),
		.status = xdev_ext_xd_get(in + 78, 2), .seg_len = xdev_ext_xd_get(in + 80, 4),
		.type = in[5], .channel = in[6],
	};
	for (i = 0; i < XDEV_EXT_XDOMAIN_TAG_LEN; i++) decoded.tag[i] = in[96 + i];
	if (xdev_ext_xd_msg_v2_layout(&decoded)) return -EPROTO;
	*m = decoded;
	return 0;
}
static inline int xdev_ext_xd_msg_v2_for_us(const struct xdev_ext_xd_msg_v2 *m,
	__u64 local_inc, __u64 remote_inc, __u32 channels)
{
	return !local_inc || !remote_inc || m->dst_inc != local_inc ||
	       m->src_inc != remote_inc || m->channel >= channels ? -ESTALE : 0;
}
#endif

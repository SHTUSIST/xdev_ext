/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_XDOMAIN_CORE_H
#define _XDEV_EXT_XDOMAIN_CORE_H

/*
 * Pure rules of the XDOMAIN class (Thunderbolt/USB4 host to host): the
 * 128-byte control message, the login packet, NHI ring budget and receive
 * frame checks. The module and the host tests compile the same code.
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/xdev_ext_mech.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>
#include "../../include/uapi/linux/xdev_ext_mech.h"
#endif

#define XDEV_EXT_XD_MSG_LEN	128U
#define XDEV_EXT_XD_MSG_MAGIC	0x3144584eU /* LE wire bytes "NXD1" */
#define XDEV_EXT_XD_MSG_VERSION	1U
#define XDEV_EXT_XD_RTS		1U /* sender announces a group */
#define XDEV_EXT_XD_CTS		2U /* receiver posted buffers: clear to send */
#define XDEV_EXT_XD_ACK		3U /* receiver's chain finished the group */
#define XDEV_EXT_XD_HELD		4U /* receiver has the group, chain still runs */
#define XDEV_EXT_XD_FAIL		5U /* receiver refused or failed the group */
#define XDEV_EXT_XD_CANCEL	6U /* sender withdraws an announced group */
#define XDEV_EXT_XD_DESC_CRC_ERROR	0x1U /* RING_DESC_CRC_ERROR */
#define XDEV_EXT_XD_DESC_BUFFER_OVERRUN	0x4U /* RING_DESC_BUFFER_OVERRUN */
#define XDEV_EXT_XD_DATA_RING	256U
/* Control RX buffers are 4096 bytes; control TX buffers are 128 bytes. */
#define XDEV_EXT_XD_CTL_RING	128U
#define XDEV_EXT_XD_MAX_CHANNELS	4U /* wire format limit */
#define XDEV_EXT_XD_CHANNELS_V1	1U /* DMA path credits limit this version */

struct xdev_ext_xd_msg {
	__u64 src_inc, dst_inc, stream, group, credit, data_seq;
	__u32 total_len;
	__u16 count, status;
	__u8 type, channel;
	__u8 tag[XDEV_EXT_XDOMAIN_TAG_LEN];
};

/* Like crc32c(): reflected CRC32C update, no implicit pre/post inversion. */
typedef __u32 (*xdev_ext_xd_crc_fn)(__u32 crc, const void *p, size_t len);

/* Login packet over tb_xdomain_request(): thunderbolt_ip_header + payload. */
struct xdev_ext_xd_login {
	__u32 route_hi, route_lo, length_sn;
	__u8 uuid[16], initiator_uuid[16], target_uuid[16];
	__u32 type, command_id;
	__u32 proto_version, channels, ctl_tx_path;
	__u32 data_tx_path[XDEV_EXT_XD_MAX_CHANNELS];
	__u64 incarnation;
	__u32 caps, reserved[3];
}; /* 120 bytes */

struct xdev_ext_xd_login_response {
	__u32 route_hi, route_lo, length_sn;
	__u8 uuid[16], initiator_uuid[16], target_uuid[16];
	__u32 type, command_id;
	__u32 status, rsvd0, rsvd1;
	__u64 incarnation;
	__u64 requester_incarnation;
}; /* 96 bytes */

#define XDEV_EXT_XD_LOGIN			1U
#define XDEV_EXT_XD_LOGIN_RESPONSE	2U
#define XDEV_EXT_XD_LOGOUT		3U
#define XDEV_EXT_XD_PROTO_VERSION		2U
#define XDEV_EXT_XD_CAP_E2E		(1U << 0)
#define XDEV_EXT_XD_PDF_START		1U
#define XDEV_EXT_XD_PDF_END		2U

static inline void xdev_ext_xd_put(__u8 *p, __u64 v, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		p[i] = (__u8)(v >> (8 * i));
}

static inline __u64 xdev_ext_xd_get(const __u8 *p, unsigned int n)
{
	__u64 v = 0;

	while (n--)
		v = (v << 8) | p[n];
	return v;
}

static inline int xdev_ext_xd_msg_layout(const struct xdev_ext_xd_msg *m)
{
	unsigned int i, tag = 0;

	for (i = 0; i < XDEV_EXT_XDOMAIN_TAG_LEN; i++)
		tag |= m->tag[i];
	if (!m->group || !m->stream)
		return -EPROTO;
	switch (m->type) {
	case XDEV_EXT_XD_RTS:
		return m->credit || !m->total_len || !m->count ||
		       m->count > XDEV_EXT_XDOMAIN_MAX_ELEMS || m->status ?
		       -EPROTO : 0;
	case XDEV_EXT_XD_CTS:
	case XDEV_EXT_XD_ACK:
	case XDEV_EXT_XD_HELD:
		return !m->credit || m->total_len || m->count || m->status ||
		       m->data_seq || tag ? -EPROTO : 0;
	case XDEV_EXT_XD_FAIL:
		return !m->status || m->total_len || m->count || m->data_seq ||
		       tag ? -EPROTO : 0;
	case XDEV_EXT_XD_CANCEL:
		return m->credit || m->total_len || m->count || m->status ||
		       m->data_seq || tag ? -EPROTO : 0;
	default:
		return -EPROTO;
	}
}

static inline int
xdev_ext_xd_msg_encode(__u8 out[XDEV_EXT_XD_MSG_LEN],
		       const struct xdev_ext_xd_msg *m, xdev_ext_xd_crc_fn crc)
{
	unsigned int i;

	if (xdev_ext_xd_msg_layout(m))
		return -EINVAL;
	for (i = 0; i < XDEV_EXT_XD_MSG_LEN; i++)
		out[i] = 0;
	xdev_ext_xd_put(out, XDEV_EXT_XD_MSG_MAGIC, 4);
	out[4] = XDEV_EXT_XD_MSG_VERSION;
	out[5] = m->type;
	out[6] = m->channel;
	xdev_ext_xd_put(out + 8, m->src_inc, 8);
	xdev_ext_xd_put(out + 16, m->dst_inc, 8);
	xdev_ext_xd_put(out + 24, m->stream, 8);
	xdev_ext_xd_put(out + 32, m->group, 8);
	xdev_ext_xd_put(out + 40, m->credit, 8);
	xdev_ext_xd_put(out + 48, m->total_len, 4);
	xdev_ext_xd_put(out + 52, m->count, 2);
	xdev_ext_xd_put(out + 54, m->status, 2);
	xdev_ext_xd_put(out + 56, m->data_seq, 8);
	for (i = 0; i < XDEV_EXT_XDOMAIN_TAG_LEN; i++)
		out[64 + i] = m->tag[i];
	xdev_ext_xd_put(out + 124, (__u32)~crc(~0U, out, 124), 4);
	return 0;
}

static inline int
xdev_ext_xd_msg_decode(const __u8 *in, __u32 len, xdev_ext_xd_crc_fn crc,
		       struct xdev_ext_xd_msg *m)
{
	unsigned int i;

	if (len < XDEV_EXT_XD_MSG_LEN ||
	    xdev_ext_xd_get(in, 4) != XDEV_EXT_XD_MSG_MAGIC ||
	    in[4] != XDEV_EXT_XD_MSG_VERSION || in[7] ||
	    (__u32)xdev_ext_xd_get(in + 124, 4) != (__u32)~crc(~0U, in, 124))
		return -EBADMSG;
	for (i = 88; i < 124; i++)
		if (in[i])
			return -EPROTO;
	*m = (struct xdev_ext_xd_msg){
		.src_inc = xdev_ext_xd_get(in + 8, 8),
		.dst_inc = xdev_ext_xd_get(in + 16, 8),
		.stream = xdev_ext_xd_get(in + 24, 8),
		.group = xdev_ext_xd_get(in + 32, 8),
		.credit = xdev_ext_xd_get(in + 40, 8),
		.data_seq = xdev_ext_xd_get(in + 56, 8),
		.total_len = (__u32)xdev_ext_xd_get(in + 48, 4),
		.count = (__u16)xdev_ext_xd_get(in + 52, 2),
		.status = (__u16)xdev_ext_xd_get(in + 54, 2),
		.type = in[5],
		.channel = in[6],
	};
	for (i = 0; i < XDEV_EXT_XDOMAIN_TAG_LEN; i++)
		m->tag[i] = in[64 + i];
	return xdev_ext_xd_msg_layout(m);
}

static inline int
xdev_ext_xd_msg_for_us(const struct xdev_ext_xd_msg *m, __u64 local_inc,
		       __u64 remote_inc, __u32 channels)
{
	if (!local_inc || !remote_inc || m->dst_inc != local_inc ||
	    m->src_inc != remote_inc || m->channel >= channels)
		return -ESTALE;
	return 0;
}

/* ring_frame.size is 12 bits; 0 represents a full 4096-byte RX frame. */
static inline int
xdev_ext_xd_rx_frame(__u32 flags, __u32 size_field, __u32 want)
{
	__u32 size = size_field ? size_field : XDEV_EXT_XDOMAIN_MAX_FRAME;

	if (flags & XDEV_EXT_XD_DESC_CRC_ERROR)
		return -EBADMSG;
	if (flags & XDEV_EXT_XD_DESC_BUFFER_OVERRUN)
		return -EOVERFLOW;
	return size == want ? 0 : -EMSGSIZE;
}

/* Upper bound of NHI frames per batch for a session layout. */
static inline __u32
xdev_ext_xd_layout_elems(const struct xdev_ext_mech_layout *l)
{
	__u64 frames, per_frame, total;

	if (!l->group_bytes || !l->seg_len)
		return 0;
	frames = ((__u64)l->group_bytes + l->seg_len - 1) / l->seg_len;
	per_frame = ((__u64)l->seg_len + XDEV_EXT_XDOMAIN_MAX_FRAME - 1) /
		    XDEV_EXT_XDOMAIN_MAX_FRAME;
	total = frames * per_frame;
	return total <= (__u32)~0U ? (__u32)total : 0;
}

/* Exact wire count: the final source frame may be shorter than seg_len. */
static inline __u32
xdev_ext_xd_layout_count(const struct xdev_ext_mech_layout *l)
{
	__u64 full, tail, per_frame, total;

	if (!l->group_bytes || !l->seg_len)
		return 0;
	full = l->group_bytes / l->seg_len;
	tail = l->group_bytes % l->seg_len;
	per_frame = ((__u64)l->seg_len + XDEV_EXT_XDOMAIN_MAX_FRAME - 1) /
		    XDEV_EXT_XDOMAIN_MAX_FRAME;
	total = full * per_frame +
		(tail + XDEV_EXT_XDOMAIN_MAX_FRAME - 1) / XDEV_EXT_XDOMAIN_MAX_FRAME;
	return total <= (__u32)~0U ? (__u32)total : 0;
}

/* All batches fit at once; the ring must retain one empty slot. */
static inline bool
xdev_ext_xd_budget_ok(__u32 depth, __u32 elems_per_batch, __u32 ring_size)
{
	return ring_size > 1 && depth && elems_per_batch &&
	       elems_per_batch <= XDEV_EXT_XDOMAIN_MAX_ELEMS &&
	       (__u64)depth * elems_per_batch <= ring_size - 1;
}

static inline int
xdev_ext_xd_login_check(const struct xdev_ext_xd_login *l, __u32 size,
			__u32 max_channels)
{
	__u32 i;

	if (size != sizeof(*l) ||
	    (l->length_sn & 0x3f) != (sizeof(*l) - 12) / 4 ||
	    l->type != XDEV_EXT_XD_LOGIN ||
	    l->proto_version != XDEV_EXT_XD_PROTO_VERSION ||
	    !l->channels || l->channels > XDEV_EXT_XD_MAX_CHANNELS ||
	    l->channels > max_channels || !l->incarnation || l->ctl_tx_path < 8)
		return -EPROTO;
	for (i = 0; i < l->channels; i++)
		if (l->data_tx_path[i] < 8)
			return -EPROTO;
	return 0;
}

#endif

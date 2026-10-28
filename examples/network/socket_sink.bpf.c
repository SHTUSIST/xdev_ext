// SPDX-License-Identifier: GPL-2.0
/* Ordinary socket compatibility copy: one full batch per UDP datagram. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

/* C supplies an immutable packet envelope and independently checks every
 * resulting coordinate. Protocol bytes and CRC remain reference BPF logic. */
static __always_inline __s32 socket_packet_build(
 const struct xdev_ext_mech_ctx *mctx, const struct xdev_ext_socket_mech_info *info)
{
 struct xdev_ext_socket_packet_desc *d;
 struct xdev_ext_mp_segment seg = {};
 struct xdev_ext_mp_rx_cfg cfg = {
  .session_id = info->wire_session, .mtu = info->mtu,
  .frame_size = info->l.frame_size, .hdr_room = info->l.hdr_room,
  .seg_len = info->l.seg_len, .group_bytes = info->l.group_bytes,
 };
 __u32 i = info->cursor, crc;
 __u8 pkt[XDEV_EXT_MP_PKT_HDR_LEN] = {}, hdr[XDEV_EXT_MP_NXP_LEN];
 struct xdev_ext_mech_peer peer = {};
 struct xdev_ext_mp_tx_seg tx = {};
 if (i >= info->nr_frames || i >= XDEV_EXT_MP_MAX_FRAMES)
  return XDEV_EXT_MP_BUILD_ABORT;
 d = (void *)bpf_xdev_ext_desc(mctx, 0, sizeof(*d));
 if (!d) return XDEV_EXT_MP_BUILD_ABORT;
 if (info->phase == XDEV_EXT_MP_SOCKET_PACKET_RX_PLAN) {
  if (xdev_ext_mp_nxp_parse(info->header, info->packet_len, &cfg, &seg) !=
      XDEV_EXT_MP_RX_SEGMENT)
   return XDEV_EXT_MP_BUILD_ABORT;
  d->key = seg.generation; d->frame_pos = seg.index;
  d->frame_off = seg.payload_off; d->len = seg.payload_len;
  d->relative_offset = seg.relative_offset;
 } else if (info->phase == XDEV_EXT_MP_SOCKET_PACKET_TX) {
  if (!mctx->base.src_offset || mctx->base.src_offset > 0xffffffffULL ||
      mctx->base.length != info->l.group_bytes)
   return XDEV_EXT_MP_BUILD_ABORT;
  tx = (struct xdev_ext_mp_tx_seg) {
   .session_id = info->wire_session, .generation = mctx->base.src_offset,
   .total_len = info->l.group_bytes, .count = info->nr_frames, .index = i,
   .relative_offset = i * info->l.seg_len, .payload_len = info->f[i].data_len,
  };
  if (xdev_ext_mp_tx_encode(pkt, &peer, &tx))
   return XDEV_EXT_MP_BUILD_ABORT;
  xdev_ext_mp_nxp_crc_prep(hdr, pkt + XDEV_EXT_MP_NXP_OFF);
  crc = bpf_xdev_ext_crc32c(hdr, sizeof(hdr), XDEV_EXT_MP_CRC32C_SEED);
  crc = bpf_xdev_ext_frame_crc32c(mctx, i, info->f[i].data_off,
                                info->f[i].data_len, crc);
  xdev_ext_mp_nxp_crc_store(pkt + XDEV_EXT_MP_NXP_OFF, crc);
  __builtin_memcpy(d->header, pkt + XDEV_EXT_MP_NXP_OFF, XDEV_EXT_MP_NXP_LEN);
  d->key = mctx->base.src_offset; d->frame_pos = i;
  d->frame_off = info->f[i].data_off; d->len = info->f[i].data_len;
  d->relative_offset = i * info->l.seg_len;
 } else return XDEV_EXT_MP_BUILD_ABORT;
 d->header_len = XDEV_EXT_MP_NXP_LEN;
 d->reserved = 0;
 return XDEV_EXT_MP_BUILD_SUBMIT;
}

static __always_inline __s32 socket_packet_check(
 const struct xdev_ext_mech_ctx *mctx, const struct xdev_ext_socket_mech_info *info)
{
 __u8 hdr[XDEV_EXT_MP_NXP_LEN];
 __u32 crc, i = info->cursor;
 if (i >= info->nr_frames || i >= XDEV_EXT_MP_MAX_FRAMES)
  return XDEV_EXT_MP_ABORT;
 xdev_ext_mp_nxp_crc_prep(hdr, info->header);
 crc = bpf_xdev_ext_crc32c(hdr, sizeof(hdr), XDEV_EXT_MP_CRC32C_SEED);
 crc = bpf_xdev_ext_frame_crc32c(mctx, i, info->f[i].data_off,
                               info->f[i].data_len, crc);
 return xdev_ext_mp_nxp_crc_ok(info->header, crc) ? XDEV_EXT_MP_NEXT : XDEV_EXT_MP_ABORT;
}

SEC("struct_ops/socket_sink_build")
__s32 BPF_PROG(socket_sink_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_socket_mech_info *info;
	struct xdev_ext_socket_send_desc *d;
	__u32 i;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (info && info->phase)
		return socket_packet_build(mctx, info);
	if (!info || !info->nr_frames || info->nr_frames > 32 ||
	    !mctx->base.length || (!info->wire_session && mctx->base.length > info->max_datagram))
		return XDEV_EXT_MP_BUILD_ABORT;
	for (i = 0; i < 32; i++) {
		if (i >= info->nr_frames)
			break;
		d = (void *)bpf_xdev_ext_desc(mctx, i, sizeof(*d));
		if (!d)
			return XDEV_EXT_MP_BUILD_ABORT;
		d->frame_pos = i;
		d->frame_off = info->f[i].data_off;
		d->len = info->f[i].data_len;
		d->flags = 0;
	}
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/socket_sink_complete")
__s32 BPF_PROG(socket_sink_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_socket_mech_cqe *cqe;
	const struct xdev_ext_socket_mech_info *info;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (info && info->phase == XDEV_EXT_MP_SOCKET_PACKET_RX_CHECK)
		return socket_packet_check(mctx, info);
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	return cqe && !cqe->status && (cqe->bytes_sent == mctx->base.length ||
		(cqe->bytes_received && cqe->bytes_received <= mctx->base.length)) ?
		XDEV_EXT_MP_NEXT : XDEV_EXT_MP_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_socket_mech_ops socket_sink_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)socket_sink_build,
	.complete = (void *)socket_sink_complete,
};
char LICENSE[] SEC("license") = "GPL";

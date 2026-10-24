// SPDX-License-Identifier: GPL-2.0
/* Reference native peer TX: experimental Ethernet frames, a 16-byte CPU
 * sequence/offset header, and GPU payload. No CPU payload read or checksum.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
SEC("struct_ops/net_peer_build")
__s32 BPF_PROG(net_peer_build, const struct xdev_ext_mech_ctx *mctx)
{
 const struct xdev_ext_net_mech_info *info;
 struct xdev_ext_net_send_desc *d;
 __u32 offset = 0, frame = 0, i, j;
 __u64 key = mctx->base.src_offset;
 (void)ctx;
 info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
 if (!info || !info->nr_frames || info->nr_frames > 16 || !info->generation)
  return XDEV_EXT_MP_BUILD_ABORT;
 if (info->direction == XDEV_EXT_MP_DIR_FROM_DEVICE) {
  if (info->header_room < 14 || info->header_room > 128) return XDEV_EXT_MP_BUILD_ABORT;
  for (i = 0; i < 16; i++) {
   if (i >= info->nr_frames) break;
   d = (void *)bpf_xdev_ext_desc(mctx, i, sizeof(*d));
   if (!d || !info->f[i].data_len) return XDEV_EXT_MP_BUILD_ABORT;
   d->frame_pos = i; d->frame_off = info->f[i].data_off;
   d->len = info->f[i].data_len; d->header_len = info->header_room;
  }
  return XDEV_EXT_MP_BUILD_SUBMIT;
 }
 if (info->mtu < 1040) return XDEV_EXT_MP_BUILD_ABORT;
 for (i = 0; i < 16; i++) {
  __u32 len;
  if (frame >= info->nr_frames || frame >= 16) break;
  if (!info->f[frame].data_len || info->f[frame].data_len > 16384)
   return XDEV_EXT_MP_BUILD_ABORT;
  len = info->f[frame].data_len - offset;
  if (len > 1024) len = 1024;
  d = (void *)bpf_xdev_ext_desc(mctx, i, sizeof(*d));
  if (!d) return XDEV_EXT_MP_BUILD_ABORT;
  d->frame_pos = frame; d->frame_off = info->f[frame].data_off + offset;
  d->len = len; d->header_len = 30;
  for (j = 0; j < 6; j++) {
   d->header[j] = info->peer.peer_mac[j];
   d->header[6 + j] = info->peer.local_mac[j];
  }
  d->header[12] = 0x88; d->header[13] = 0xb5;
  for (j = 0; j < 8; j++) d->header[14 + j] = key >> (56 - j * 8);
  for (j = 0; j < 4; j++) {
   d->header[22 + j] = offset >> (24 - j * 8);
   d->header[26 + j] = info->f[frame].data_len >> (24 - j * 8);
  }
  offset += len;
  if (offset == info->f[frame].data_len) { frame++; offset = 0; }
 }
 return frame == info->nr_frames ? XDEV_EXT_MP_BUILD_SUBMIT : XDEV_EXT_MP_BUILD_ABORT;
}
SEC("struct_ops/net_peer_complete")
__s32 BPF_PROG(net_peer_complete, const struct xdev_ext_mech_ctx *mctx)
{
 const struct xdev_ext_net_mech_cqe *cqe;
 (void)ctx;
 cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
 return cqe && !cqe->status && !cqe->outcome && cqe->bytes_sent == mctx->base.length ?
        XDEV_EXT_MP_NEXT : XDEV_EXT_MP_ABORT;
}
SEC(".struct_ops.link")
struct xdev_ext_net_mech_ops net_peer_ops = {
 .abi_version = XDEV_EXT_MP_ABI_VERSION,
 .build = (void *)net_peer_build, .complete = (void *)net_peer_complete,
};
char LICENSE[] SEC("license") = "GPL";

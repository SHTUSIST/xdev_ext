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
 __u32 offset = 0, i, j;
 __u64 key = mctx->base.src_offset;
 (void)ctx;
 info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
 if (!info || info->nr_frames != 1 || !info->generation || info->mtu < 1040 ||
     !info->f[0].data_len || info->f[0].data_len > 16384)
  return XDEV_EXT_MP_BUILD_ABORT;
 for (i = 0; i < 16; i++) {
  __u32 len;
  if (offset >= info->f[0].data_len) break;
  len = info->f[0].data_len - offset;
  if (len > 1024) len = 1024;
  d = (void *)bpf_xdev_ext_desc(mctx, i, sizeof(*d));
  if (!d) return XDEV_EXT_MP_BUILD_ABORT;
  d->frame_pos = 0; d->frame_off = info->f[0].data_off + offset;
  d->len = len; d->header_len = 30;
  for (j = 0; j < 6; j++) {
   d->header[j] = info->peer.peer_mac[j];
   d->header[6 + j] = info->peer.local_mac[j];
  }
  d->header[12] = 0x88; d->header[13] = 0xb5;
  for (j = 0; j < 8; j++) d->header[14 + j] = key >> (56 - j * 8);
  for (j = 0; j < 4; j++) {
   d->header[22 + j] = offset >> (24 - j * 8);
   d->header[26 + j] = info->f[0].data_len >> (24 - j * 8);
  }
  offset += len;
 }
 return offset == info->f[0].data_len ? XDEV_EXT_MP_BUILD_SUBMIT : XDEV_EXT_MP_BUILD_ABORT;
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

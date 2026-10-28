/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_NET_CORE_H
#define IO_URING_XDEV_EXT_MECH_NET_CORE_H
#include "xdev_ext_mech_core.h"
#include "xdev_ext_peer_net_core.h"
/* Ordered exact coverage means the BPF plan cannot duplicate, omit or read
 * beyond its current C-owned GPU payload span. CPU headers are separate.
 * A batch of several frames is covered frame after frame, in batch order.
 */
#define XDEV_EXT_NET_PLAN_FRAMES 1
static inline int xdev_ext_net_plan_check(const struct xdev_ext_net_mech_info *info,
                                         const struct xdev_ext_net_send_desc *d, __u32 nr)
{
 __u32 i, cur = 0, bytes = 0;
 const struct xdev_ext_mech_frame_info *f;
 int ret;
 if (!info || !d || !info->nr_frames || info->nr_frames > XDEV_EXT_MECH_MAX_FRAMES ||
     !nr || nr > XDEV_EXT_NET_MAX_ENTRIES)
  return -EINVAL;
 f = &info->f[0];
 for (i = 0; i < nr; i++) {
  if (d[i].frame_pos >= info->nr_frames || d[i].frame_pos < cur ||
      d[i].flags || d[i].reserved) return -EINVAL;
  if (d[i].frame_pos != cur) {
   /* The next frame starts only after this one is exactly covered. */
   if (bytes != f->data_len || d[i].frame_pos != cur + 1) return -EMSGSIZE;
   cur++; f = &info->f[cur]; bytes = 0;
  }
  if ((__u64)f->data_off + bytes != d[i].frame_off ||
      bytes > f->data_len || d[i].len > f->data_len - bytes) return -ERANGE;
  ret = xdev_ext_peer_net_check(info->mtu, d[i].header_len, d[i].len, 0);
  if (ret) return ret;
  bytes += d[i].len;
 }
 return cur + 1 == info->nr_frames && bytes == f->data_len ? 0 : -EMSGSIZE;
}
#endif

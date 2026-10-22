/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_NET_CORE_H
#define IO_URING_XDEV_EXT_MECH_NET_CORE_H
#include "xdev_ext_mech_core.h"
#include "xdev_ext_peer_net_core.h"
/* Ordered exact coverage means the BPF plan cannot duplicate, omit or read
 * beyond its current C-owned GPU payload span. CPU headers are separate.
 */
static inline int xdev_ext_net_plan_check(const struct xdev_ext_net_mech_info *info,
                                         const struct xdev_ext_net_send_desc *d, __u32 nr)
{
 __u32 i, bytes = 0;
 const struct xdev_ext_mech_frame_info *f;
 int ret;
 if (!info || !d || info->nr_frames != 1 || !nr || nr > XDEV_EXT_NET_MAX_ENTRIES)
  return -EINVAL;
 f = &info->f[0];
 for (i = 0; i < nr; i++) {
  if (d[i].frame_pos || d[i].flags || d[i].reserved) return -EINVAL;
  if ((__u64)f->data_off + bytes != d[i].frame_off ||
      bytes > f->data_len || d[i].len > f->data_len - bytes) return -ERANGE;
  ret = xdev_ext_peer_net_check(info->mtu, d[i].header_len, d[i].len, 0);
  if (ret) return ret;
  bytes += d[i].len;
 }
 return bytes == f->data_len ? 0 : -EMSGSIZE;
}
#endif

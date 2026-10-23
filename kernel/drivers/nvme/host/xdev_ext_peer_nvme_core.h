/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_PEER_NVME_CORE_H
#define _XDEV_EXT_PEER_NVME_CORE_H
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/errno.h>
#else
#include <stdint.h>
#include <errno.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#endif
struct xdev_ext_peer_nvme_plan { u64 slba; u32 bytes; u16 nlb; u8 opcode; };
static inline int xdev_ext_peer_nvme_plan(u8 lba_shift, u64 capacity_lbas,
                                         u16 metadata, u8 csi, u64 slba,
                                         u32 bytes, int write,
                                         struct xdev_ext_peer_nvme_plan *out)
{
 u64 nlb;
 if (!out || (write != 0 && write != 1) || lba_shift < 9 || lba_shift > 31 ||
     !bytes || (bytes & ((1U << lba_shift) - 1))) return -EINVAL;
 if (metadata || csi) return -EOPNOTSUPP;
 nlb = bytes >> lba_shift;
 if (nlb > 65536) return -E2BIG;
 if (slba >= capacity_lbas || nlb > capacity_lbas - slba) return -ERANGE;
 *out = (struct xdev_ext_peer_nvme_plan){ .slba = slba, .bytes = bytes,
                                         .nlb = nlb - 1, .opcode = write ? 1 : 2 };
 return 0;
}

/* Provider DMA spans in payload order; outputs are CPU-endian. */
#define XDEV_EXT_PEER_NVME_DPTR 1
struct xdev_ext_peer_nvme_seg { u64 addr; u32 len; };
static inline int xdev_ext_peer_nvme_sgl_build(
 const struct xdev_ext_peer_nvme_seg *seg, u32 nr,
 struct xdev_ext_peer_nvme_seg *out, u32 cap, u32 *n)
{
 u32 i, used = 0;
 if (!n) return -EINVAL;
 *n = 0;
 if (!seg || !out || !nr) return -EINVAL;
 for (i = 0; i < nr; i++) {
  if (!seg[i].len || ((seg[i].addr | seg[i].len) & 3)) return -EINVAL;
  if (seg[i].addr + seg[i].len < seg[i].addr) return -EOVERFLOW;
  if (used && out[used - 1].addr + out[used - 1].len == seg[i].addr &&
      seg[i].len <= (u32)~0U - out[used - 1].len) {
   out[used - 1].len += seg[i].len;
  } else {
   if (used == cap) return -EREMOTEIO;
   out[used++] = seg[i];
  }
 }
 *n = used;
 return 0;
}
static inline int xdev_ext_peer_nvme_prp_build(
 const struct xdev_ext_peer_nvme_seg *seg, u32 nr, u32 page_shift,
 u64 list_dma, u64 *list, u32 cap, u64 *prp1, u64 *prp2, u32 *n)
{
 u64 page, mask, entries = 0, second = 0;
 u32 i, used = 0;
 if (!n) return -EINVAL;
 *n = 0;
 if (!seg || !list || !prp1 || !prp2 || !nr ||
     page_shift < 12 || page_shift > 27) return -EINVAL;
 page = 1ULL << page_shift;
 mask = page - 1;
 /* Validate the entire vector before publishing a data pointer. */
 for (i = 0; i < nr; i++) {
  u64 pages;
  if (!seg[i].len || (seg[i].addr & (i ? mask : 3))) return -EINVAL;
  if (seg[i].addr + seg[i].len < seg[i].addr) return -EOVERFLOW;
  if (i + 1 < nr && ((seg[i].addr + seg[i].len) & mask)) return -EINVAL;
  pages = ((seg[i].addr & mask) + seg[i].len + mask) >> page_shift;
  entries += pages - (i == 0);
 }
 if (entries > 1 && entries > cap) return -EREMOTEIO;
 for (i = 0; i < nr; i++) {
  u64 addr = seg[i].addr, left = seg[i].len;
  if (!i) {
   u64 first = page - (addr & mask);
   if (left <= first) continue;
   addr += first;
   left -= first;
  }
  while (left) {
   second = addr;
   if (entries > 1) list[used++] = addr;
   if (left <= page) break;
   left -= page;
   addr += page;
  }
 }
 *prp1 = seg[0].addr;
 *prp2 = entries > 1 ? list_dma : entries ? second : 0;
 *n = used;
 return 0;
}
#endif

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
#endif

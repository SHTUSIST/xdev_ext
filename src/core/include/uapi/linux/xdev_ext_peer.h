/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_XDEV_EXT_PEER_H
#define _UAPI_LINUX_XDEV_EXT_PEER_H
#include <linux/types.h>
#include <linux/ioctl.h>
/* /dev/xdev_ext_peer: returns an O_CLOEXEC allocation fd from ioctl result.
 * Caller must synchronize CUDA producers before a peer reads VRAM, and wait
 * for a successful peer completion before launching CUDA consumers.
 */
struct xdev_ext_peer_register {
 __s32 gpu_fd;
 __u32 flags;
 __u64 gpu_va;
 __u64 len;
 __u64 generation; /* output, paired with every peer request */
};
#define XDEV_EXT_PEER_REGISTER _IOWR('X', 0xe0, struct xdev_ext_peer_register)
/* NVMe generic namespace /dev/ngXnY. One DMA-contiguous GPU page span, no
 * host/CE fallback. flags=0 reads NVMe into VRAM; WRITE reads VRAM to NVMe.
 */
#define XDEV_EXT_PEER_NVME_F_WRITE 1U
struct xdev_ext_peer_nvme_rw {
 __s32 allocation_fd;
 __u32 flags;
 __u64 generation;
 __u64 offset;
 __u64 slba;
 __u32 bytes;
 __u32 reserved;
};
#define XDEV_EXT_PEER_NVME_MAX_DESCS 64U
struct xdev_ext_peer_nvme_desc {
 __u64 offset;
 __u64 slba;
 __u32 bytes;
 __u32 reserved;
};
/* The kernel executes this bounded list in order without user continuation.
 * Stop on the first failure; completed is the successfully completed prefix.
 * A failed accepted command is never resent. Its allocation is retained when
 * device DMA quiescence cannot be established from the native result.
 */
struct xdev_ext_peer_nvme_batch {
 __s32 allocation_fd;
 __u32 flags;
 __u64 generation;
 __u32 nr;
 __u32 completed;
 __s32 status;
 __u32 reserved;
 struct xdev_ext_peer_nvme_desc desc[XDEV_EXT_PEER_NVME_MAX_DESCS];
};
#define XDEV_EXT_PEER_NVME_BATCH _IOWR('N', 0xe1, struct xdev_ext_peer_nvme_batch)
#define XDEV_EXT_PEER_NVME_RW _IOW('N', 0xe0, struct xdev_ext_peer_nvme_rw)
#define XDEV_EXT_PEER_NET_MAX_DESCS 32U
#define XDEV_EXT_PEER_NET_HEADER_MAX 128U
struct xdev_ext_peer_net_desc {
 __u64 offset;
 __u32 bytes;
 __u16 header_len;
 __u16 reserved;
 __u8 header[XDEV_EXT_PEER_NET_HEADER_MAX];
};
/* TX only. A request for RX (or any unknown flags) is rejected. CPU headers
 * include complete Ethernet/protocol checksums; payload is never CPU mapped.
 * completed counts successful native TX CQEs, not remote delivery/ACKs.
 */
struct xdev_ext_peer_net_batch {
 __s32 allocation_fd;
 __u32 ifindex;
 __u64 generation;
 __u32 queue;
 __u32 flags;
 __u32 nr;
 __u32 completed;
 __s32 status;
 __u32 reserved;
 struct xdev_ext_peer_net_desc desc[XDEV_EXT_PEER_NET_MAX_DESCS];
};
#define XDEV_EXT_PEER_NET_TX _IOWR('X', 0xe2, struct xdev_ext_peer_net_batch)
#endif

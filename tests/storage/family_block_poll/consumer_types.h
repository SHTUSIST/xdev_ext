/* External native/accessor field boundary only; real member layouts below. */
#ifdef STORAGE_CURRENT_COMMON
#ifndef STORAGE_POLL_CONSUMER_TYPES_H
#define STORAGE_POLL_CONSUMER_TYPES_H
#include <linux/nvme_xdev_ext_passthru.h>
#define XDEV_EXT_MECH_POOL_PEER 2
#define FMODE_READ 1
#define FMODE_WRITE 2
#define GFP_KERNEL 0
#define BLK_MQ_REQ_NOWAIT 1
#define NVME_REQ_USERCMD 1U
#define NVME_REQ_XDEV_EXT_PEER 2U
#define NVME_REQ_CANCELLED 4U
#define NVME_CMD_SGL_METABUF 0x40
#define NVME_CTRL_LIVE 1
#define NVME_NS_READY 0
#define NVME_NS_REMOVING 1
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define atomic_read(p) (*(p))
#define atomic_set(p,v) (*(p)=(v))
#define test_bit(b,p) ((*(p)>>(b))&1)
#define get_disk_ro(d) ((d)->ro)
#define get_capacity(d) ((d)->capacity)
#define nvme_ctrl_state(c) ((c)->state)
#define blk_status_to_errno(e) (e)
#define blk_rq_bytes(r) ((r)->bytes)
typedef int atomic_t;
typedef u64 dma_addr_t;
typedef u64 sector_t;
enum dma_data_direction {DMA_BIDIRECTIONAL,DMA_TO_DEVICE,DMA_FROM_DEVICE,DMA_NONE};
struct file_operations {int (*uring_cmd)(void);};
struct file {unsigned f_mode;const struct file_operations *f_op;};
struct gendisk {bool ro;u64 capacity,diskseq;};
struct nvme_ctrl_ops {const char *name;void *peer_rw;};
struct device {bool is_pci;};
struct pci_dev {struct device dev;};
#define dev_is_pci(d) ((d)->is_pci)
#define to_pci_dev(d) ((struct pci_dev *)(d))
struct nvme_ctrl {const struct nvme_ctrl_ops *ops;int state;struct device *dev;};
struct nvme_ns_head {u8 lba_shift,pi_type;u16 ms,pi_size;u32 ns_id;struct {u8 csi,eui64[8],nguid[16],uuid[16];} ids;};
struct nvme_ns {struct request_queue *queue;struct nvme_ctrl *ctrl;struct nvme_ns_head *head;struct gendisk *disk;unsigned long flags;void *cdev;};
struct xdev_ext_mech_pool {int kind;u32 frame_size;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;u32 depth,state;};
struct xdev_ext_mech_stage {void *priv;bool poll;struct xdev_ext_mech_session *s;struct file *file;unsigned direction;u64 arg0,arg1;};
#include "actual_command_boundary.inc"
#define __aligned(n) __attribute__((aligned(n)))
#define XDEV_EXT_PEER_HOST_TEST 1
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_storfam_block.h>
#ifndef STORAGE_COMMON_TU
#include "actual_member_types.inc"
struct nvme_request {struct nvme_command *cmd;unsigned flags;int status;union {u64 u64;} result;struct nvme_xdev_ext_peer_trace *peer_trace;};
#endif
#endif
#else
#ifndef STORAGE_POLL_CONSUMER_TYPES_H
#define STORAGE_POLL_CONSUMER_TYPES_H
#ifdef STORAGE_MEMBER_FAMILY
#include <linux/nvme_xdev_ext_passthru.h>
#else
#include <linux/xdev_ext_storfam_core.h>
#endif
#ifndef NVME_XDEV_EXT_SQE_SIZE
#define NVME_XDEV_EXT_SQE_SIZE 64U
#endif
#define NVME_XDEV_EXT_PEER_MAX_SPANS 512U
#ifndef NVME_XDEV_EXT_NVM_WRITE
#define NVME_XDEV_EXT_NVM_WRITE 1U
#endif
#ifndef NVME_XDEV_EXT_NVM_READ
#define NVME_XDEV_EXT_NVM_READ 2U
#endif
#ifndef XDEV_EXT_MECH_POOL_PEER
#define XDEV_EXT_MECH_POOL_PEER 2
#endif
#ifndef XDEV_EXT_MECH_DIR_TO_DEVICE
#define XDEV_EXT_MECH_DIR_TO_DEVICE 1
#endif
#ifndef XDEV_EXT_MECH_DIR_FROM_DEVICE
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 2
#endif
#define FMODE_READ 1
#define FMODE_WRITE 2
#define GFP_KERNEL 0
#define BLK_MQ_REQ_NOWAIT 1
#define NVME_REQ_USERCMD 1U
#define NVME_REQ_XDEV_EXT_PEER 2U
#define NVME_REQ_CANCELLED 4U
#define NVME_CMD_SGL_METABUF 0x40
#define NVME_CTRL_LIVE 1
#define NVME_NS_READY 0
#define NVME_NS_REMOVING 1
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define le16_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define atomic_read(p) (*(p))
#define atomic_set(p,v) (*(p)=(v))
#define test_bit(b,p) ((*(p)>>(b))&1)
#define get_disk_ro(d) ((d)->ro)
#define get_capacity(d) ((d)->capacity)
#define nvme_ctrl_state(c) ((c)->state)
#define blk_status_to_errno(e) (e)
#define blk_rq_bytes(r) ((r)->bytes)
typedef int atomic_t;
typedef u64 dma_addr_t;
struct file {unsigned f_mode;};
struct gendisk {bool ro;u64 capacity,diskseq;};
typedef u64 sector_t;
struct nvme_ctrl_ops {const char *name;void *peer_rw;};
struct device {bool is_pci;};
struct pci_dev {struct device dev;};
#define dev_is_pci(d) ((d)->is_pci)
#define to_pci_dev(d) ((struct pci_dev *)(d))
struct nvme_ctrl {const struct nvme_ctrl_ops *ops;int state;struct device *dev;};
struct nvme_ns_head {u8 lba_shift,pi_type;u16 ms,pi_size;u32 ns_id;struct {u8 csi,eui64[8],nguid[16],uuid[16];} ids;};
struct nvme_ns {struct request_queue *queue;struct nvme_ctrl *ctrl;struct nvme_ns_head *head;struct gendisk *disk;unsigned long flags;};
struct xdev_ext_mech_pool {int kind;};
#ifndef STORAGE_MEMBER_FAMILY
struct xdev_ext_mech_layout {u32 group_bytes;};
#endif
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;};
struct xdev_ext_mech_stage {void *priv;bool poll;struct xdev_ext_mech_session *s;struct file *file;unsigned direction;u64 arg0,arg1;};
#ifndef STORAGE_MEMBER_FAMILY
struct xdev_ext_mech_stage_uapi {u32 flags;};
#endif
struct nvme_sgl_desc {u64 addr;u32 length;u8 reserved[3],type;};
struct nvme_xdev_ext_peer_trace {const struct xdev_ext_peer_fd_lease *leases;u32 nr_leases,bytes;const char *origin;u64 cookie;};
#define xdev_ext_peer_nvme_seg xdev_ext_stor_extent
struct nvme_command {struct {u8 opcode,flags;u32 nsid;u64 slba;u16 length;} rw;struct {u8 flags;u32 cdw12;} common;};
struct nvme_request {struct nvme_command *cmd;unsigned flags;int status;union {u64 u64;} result;struct nvme_xdev_ext_peer_trace *peer_trace;};
struct nvme_xdev_ext_mech_slot;
struct nvme_xdev_ext_peer_slot;
struct nvme_xdev_ext_peer_res;
#ifdef STORAGE_MEMBER_FAMILY
#include <linux/xdev_ext_storfam_block.h>
#endif
/* Byte-for-byte declarations extracted from baseline/candidate, not invented slot strides. */
#include "actual_member_types.inc"
#endif
#endif /* STORAGE_CURRENT_COMMON */

/* External native/accessor field boundary only; real member layouts below. */
#ifndef STORAGE_POLL_CONSUMER_TYPES_H
#define STORAGE_POLL_CONSUMER_TYPES_H
#include <linux/xdev_ext_storfam_core.h>
#define NVME_XDEV_EXT_SQE_SIZE 64U
#define NVME_XDEV_EXT_PEER_MAX_SPANS 512U
#define NVME_XDEV_EXT_NVM_WRITE 1U
#define NVME_XDEV_EXT_NVM_READ 2U
#define XDEV_EXT_MECH_POOL_PEER 2
#define XDEV_EXT_MECH_DIR_TO_DEVICE 1
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 2
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
#define test_bit(b,p) ((*(p)>>(b))&1)
#define get_disk_ro(d) ((d)->ro)
#define get_capacity(d) ((d)->capacity)
#define nvme_ctrl_state(c) ((c)->state)
#define blk_status_to_errno(e) (e)
#define blk_rq_bytes(r) ((r)->bytes)
typedef int atomic_t;
typedef u64 dma_addr_t;
struct file {unsigned f_mode;};
struct gendisk {bool ro;u64 capacity;};
struct nvme_ctrl_ops {const char *name;void *peer_rw;};
struct nvme_ctrl {const struct nvme_ctrl_ops *ops;int state;};
struct nvme_ns_head {u8 lba_shift;u16 ms;struct {u8 csi;} ids;};
struct nvme_ns {struct request_queue *queue;struct nvme_ctrl *ctrl;struct nvme_ns_head *head;struct gendisk *disk;unsigned long flags;};
struct xdev_ext_mech_pool {int kind;};
struct xdev_ext_mech_layout {u32 group_bytes;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;};
struct xdev_ext_mech_stage {void *priv;bool poll;struct xdev_ext_mech_session *s;struct file *file;unsigned direction;u64 arg0,arg1;};
struct xdev_ext_mech_stage_uapi {u32 flags;};
struct nvme_sgl_desc {u64 addr;u32 length;u8 reserved[3],type;};
struct nvme_xdev_ext_peer_trace {const struct xdev_ext_peer_fd_lease *leases;u32 nr_leases,bytes;const char *origin;u64 cookie;};
#define xdev_ext_peer_nvme_seg xdev_ext_stor_extent
struct nvme_command {struct {u8 opcode,flags;u32 nsid;u64 slba;u16 length;} rw;struct {u8 flags;u32 cdw12;} common;};
struct nvme_request {struct nvme_command *cmd;unsigned flags;int status;union {u64 u64;} result;struct nvme_xdev_ext_peer_trace *peer_trace;};
struct nvme_xdev_ext_mech_slot;
struct nvme_xdev_ext_peer_slot;
struct nvme_xdev_ext_peer_res;
/* Byte-for-byte declarations extracted from baseline/candidate, not invented slot strides. */
#include "actual_member_types.inc"
#endif

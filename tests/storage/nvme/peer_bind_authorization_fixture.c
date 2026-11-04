/* SPDX-License-Identifier: GPL-2.0 */
/* OS object adapters; production bind and command-effects policy run verbatim. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "include/linux/nvme_xdev_ext_passthru.h"
#include "include/linux/xdev_ext_storfam_runtime.h"
#include <stddef.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef int atomic_t;
typedef uint64_t dma_addr_t;
typedef uint32_t u32;
typedef uint64_t u64;
#define GFP_KERNEL 0
#define kzalloc(n,f) calloc(1,n)
#define kfree free
#define cpu_to_le32(n) (n)
#define CAP_SYS_RAWIO 17
#define CAP_SYS_ADMIN 21
#define FMODE_READ 1
#define FMODE_WRITE 2
#define NVME_IOCTL_PARTITION 2
#define NVME_CMD_EFFECTS_CSUPP 1
#define NVME_CMD_EFFECTS_LBCC 2
#define NVME_CMD_EFFECTS_UUID_SEL 4
#define NVME_CMD_EFFECTS_SCOPE_MASK 8
#define nvme_cmd_write 1
#define nvme_cmd_read 2
#define nvme_cmd_vendor_start 0xc0
#define nvme_fabrics_command 0x7f
#define nvme_admin_identify 6
#define NVME_ID_CNS_NS 0
#define NVME_ID_CNS_CS_NS 1
#define NVME_ID_CNS_NS_CS_INDEP 2
#define NVME_ID_CNS_CS_CTRL 3
#define NVME_ID_CNS_CTRL 4
#define XDEV_EXT_MECH_DIR_TO_DEVICE 1
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 2
#define XDEV_EXT_MECH_POOL_PEER 3
struct nvme_command {
 union {
  struct { unsigned opcode, nsid; } rw;
  struct { unsigned opcode, nsid; } common;
  struct { unsigned opcode, nsid, cns; } identify;
 };
};
struct file { unsigned f_mode; bool native_ns; };
struct nvme_ops { const char *name; bool peer_rw; };
struct device { bool is_pci; };
struct pci_dev { struct device dev; };
#define dev_is_pci(d) ((d)->is_pci)
#define to_pci_dev(d) ((struct pci_dev *)(d))
struct nvme_ctrl { struct nvme_ops *ops; struct device *dev; };
struct nvme_ns_head { unsigned ns_id; u8 lba_shift,pi_type; u16 ms,pi_size;
 struct { u8 csi,eui64[8],nguid[16],uuid[16]; } ids; };
struct gendisk { u64 capacity,diskseq; };
struct request_queue;
struct nvme_ns { struct nvme_ctrl *ctrl; struct nvme_ns_head *head;
 struct request_queue *queue; struct gendisk *disk; unsigned long flags; };
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define atomic_set(p,v) (*(p)=(v))
#define atomic_read(p) (*(p))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define SECTOR_SHIFT 9
#define NVME_NS_READY 0
#define NVME_NS_REMOVING 1
typedef u64 sector_t;
static sector_t get_capacity(struct gendisk *d) { return d->capacity; }
static bool test_bit(unsigned bit,const unsigned long *p) { return !!(*p&(1UL<<bit)); }
struct blk_mq_hw_ctx { unsigned queue_num; };
struct request { struct blk_mq_hw_ctx *mq_hctx; };
struct bio;struct page;
struct nvme_sgl_desc { u64 addr;u32 length;u8 flags[4]; };
struct xdev_ext_peer_fd_lease;
#define xdev_ext_peer_nvme_seg xdev_ext_stor_extent
#define NVME_XDEV_EXT_PEER_MAX_SPANS 512
/* FAMILY_TYPES */
/* MEMBER_TYPES */
struct xdev_ext_mech_pool { unsigned kind; };
struct xdev_ext_mech_session { struct xdev_ext_mech_layout layout; struct xdev_ext_mech_pool pool; };

struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; struct file *file; unsigned direction; bool poll; unsigned arg0,arg1; void *priv; };
static struct nvme_ops ops={"pcie",true};
static struct nvme_ctrl ctrl={.ops=&ops};
static struct nvme_ns_head head={.ns_id=1,.lba_shift=9};
static struct gendisk disk={.capacity=32,.diskseq=1};
static char queue_identity;
static struct nvme_ns ns={.ctrl=&ctrl,.head=&head,.queue=(void *)&queue_identity,.disk=&disk,.flags=1};
static unsigned effects=NVME_CMD_EFFECTS_CSUPP, resources;
static bool rawio, admin;
static bool capable(int cap) { return cap==CAP_SYS_RAWIO ? rawio : admin; }
static unsigned nvme_command_effects(struct nvme_ctrl *c,struct nvme_ns *n,unsigned op)
{ assert(c==&ctrl && n==&ns); assert(op==nvme_cmd_read || op==nvme_cmd_write); return effects; }
static bool nvme_is_write(struct nvme_command *c) { return c->common.opcode==nvme_cmd_write; }
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s) { return &s->layout; }
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static struct nvme_ns *nvme_xdev_ext_class_ns(struct file *f) { return f->native_ns ? &ns : NULL; }
/* These authority cases are unpolled; an unexpected poll query is a failure. */
struct request_queue;
static bool xdev_ext_stor_block_poll_capable(const struct request_queue *q) { (void)q; abort(); }
/* Keep the published fixture's boundary observations while invoking the
 * actual inline capture and portable identity admission, without replacing
 * either production decision. */
static void fixture_capture_observe(struct nvme_ns *n) { assert(n==&ns); }
static void fixture_bind_observe(const struct nvme_xdev_ext_identity *i,u32 bytes)
{ assert(i->nsid==1);assert(bytes==4096); }
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int ret) { (void)st;(void)ret;abort(); }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { (void)b;abort(); }
static void xdev_ext_mech_trace_plan(struct xdev_ext_mech_batch *b,u64 l,u32 bytes,u32 plan,int ret)
{ (void)b;(void)l;(void)bytes;(void)plan;(void)ret;abort(); }
static int blk_mq_poll_hw_queue(struct request_queue *q,u32 index,void *iob)
{ (void)q;(void)index;(void)iob;abort(); }
#define WARN_ON_ONCE(v) (v)
#define kvfree free
static void bio_uninit(struct bio *b) { (void)b;abort(); }
static void dma_free_coherent(struct device *d,size_t n,void *cpu,dma_addr_t dma)
{ (void)d;(void)n;(void)cpu;(void)dma;abort(); }
static int nvme_xdev_ext_class_resources_init(struct xdev_ext_mech_stage *st) { assert(st->priv); resources++; return 0; }
static int nvme_xdev_ext_peer_resources_init(struct xdev_ext_mech_stage *st) { assert(st->priv); return 0; }
/* PRODUCTION */
static int bind_case(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_stage_uapi *u)
{ int rc=nvme_xdev_ext_class_bind(st,u); if (!rc) { free(st->priv); st->priv=NULL; } return rc; }
int main(void)
{
 struct xdev_ext_mech_session s={.layout={.group_bytes=4096},.pool={XDEV_EXT_MECH_POOL_PEER}};
 struct file f={FMODE_READ,true};
 struct xdev_ext_mech_stage st={.s=&s,.file=&f,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.arg0=4,.arg1=8};
 struct xdev_ext_mech_stage_uapi u={0};
 rawio=false; admin=false;
 assert(bind_case(&st,&u)==0 && resources==1);
 puts("ok - no RAWIO: READ authority comes from namespace fd and supported effects");
 f.f_mode=FMODE_WRITE; st.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;
 assert(bind_case(&st,&u)==0 && resources==2);
 f.f_mode=FMODE_READ; assert(bind_case(&st,&u)==-EBADF && resources==2);
 st.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE; f.f_mode=FMODE_WRITE;
 assert(bind_case(&st,&u)==-EBADF && resources==2);
 f.f_mode=FMODE_READ; effects=0;
 assert(bind_case(&st,&u)==-EACCES && resources==2);
 effects=NVME_CMD_EFFECTS_CSUPP | 0x100;
 assert(bind_case(&st,&u)==-EACCES && resources==2);
 effects=NVME_CMD_EFFECTS_CSUPP | NVME_CMD_EFFECTS_LBCC;
 assert(bind_case(&st,&u)==-EACCES && resources==2);
 effects=NVME_CMD_EFFECTS_CSUPP;
 st.arg0=31; st.arg1=2;
 assert(bind_case(&st,&u)==-ERANGE && resources==2);
 st.arg0=4; st.arg1=8; ops.peer_rw=false;
 assert(bind_case(&st,&u)==-EOPNOTSUPP && resources==2);
 ops.peer_rw=true; ops.name="tcp";
 assert(bind_case(&st,&u)==-EOPNOTSUPP && resources==2);
 ops.name="pcie"; f.native_ns=false;
 assert(bind_case(&st,&u)==-EOPNOTSUPP && resources==2);
 puts("ok - access modes, native effects, namespace type, window and transport reject before resources");
 return 0;
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Kernel/native boundaries only; production mechanisms are extracted by run.py. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint64_t sector_t; typedef uint64_t dma_addr_t; typedef unsigned blk_opf_t;
#define __KERNEL__ 1
#define CONFIG_BLOCK 1
#define REQ_POLLED 0x100U
#define CONFIG_XDEV_EXT_MECH_ZEROCOPY 1
#include <linux/nvme_xdev_ext_passthru.h>
#include <linux/xdev_ext_storfam_core.h>
#include <linux/xdev_ext_storfam_runtime.h>
#include <linux/xdev_ext_storfam_block.h>
#include "xdev_ext_peer_nvme_core.h"
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define ERR_CAST(p) ((void *)(p))
#define WARN_ON_ONCE(x) (!!(x))
#define EXPORT_SYMBOL_GPL(x)
#define PAGE_SIZE 4096U
#define SECTOR_SHIFT 9
#define SZ_4K 4096U
#define BIO_MAX_INLINE_VECS 256
#define GFP_KERNEL 1
#define BLK_MQ_REQ_NOWAIT 1
#define BLK_FEAT_POLL 1
#define HCTX_TYPE_POLL 2
#define REQ_POLLED 0x100U
#define REQ_FAILFAST_MASK 0xe00U
#define NVME_NS_READY 0
#define NVME_NS_REMOVING 1
#define NVME_CTRL_LIVE 1
#define NVME_REQ_USERCMD 1
#define NVME_REQ_XDEV_EXT_ZC 2
#define NVME_REQ_XDEV_EXT_PEER 4
#define NVME_CMD_SGL_METABUF 0x40
#define NVME_SGL_FMT_DATA_DESC 0
#define NVME_SGL_FMT_LAST_SEG_DESC 3
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define cpu_to_le64(x) ((u64)(x))
#define le16_to_cpu(x) ((u16)(x))
#define le32_to_cpu(x) ((u32)(x))
#define le64_to_cpu(x) ((u64)(x))
typedef struct { int counter; } atomic_t;
static int atomic_read(const atomic_t *a) { return a->counter; }
static void atomic_set(atomic_t *a,int n) { a->counter=n; }
struct page { unsigned char bytes[4096]; };
struct bio { unsigned bi_inline_vecs[256]; unsigned bi_vcnt; unsigned bytes; };
struct queue_limits { u32 features, dma_alignment, dma_pad_mask; };
struct blk_mq_tag_set { unsigned nr_maps; struct { unsigned nr_queues; } map[3]; };
struct request_queue { struct queue_limits limits; struct blk_mq_tag_set *tag_set; u32 virt_boundary,max_segments,max_segment_size,max_hw_sectors; int id; };
static struct request_queue queue_a,queue_b;
struct blk_mq_hw_ctx { u32 queue_num; };
struct nvme_sgl_desc { u64 addr; u32 length; u8 reserved[3]; u8 type; };
struct nvme_command { union { struct {u8 opcode,flags;u16 command_id;u32 nsid;u32 cdw2,cdw3;u64 metadata; union {struct {u64 prp1,prp2;};struct nvme_sgl_desc sgl;} dptr;u64 slba;u16 length,control;u32 dsmgmt,reftag;u16 apptag,appmask;} rw; struct {u8 opcode,flags;u16 command_id;u32 nsid;u32 cdw2,cdw3;u64 metadata;u64 dptr[2];u32 cdw10,cdw11,cdw12,cdw13,cdw14,cdw15;} common; u8 bytes[64]; }; };
struct request { blk_opf_t cmd_flags; struct blk_mq_hw_ctx *mq_hctx; void *end_io_data; int (*end_io)(struct request *,int); struct bio *bio; struct nvme_command command; struct {struct nvme_command *cmd; unsigned flags; void *peer_trace;} pdu; };
struct device { bool pci; int marker; };
struct pci_dev { struct device dev; };
struct nvme_ctrl_ops { const char *name; void *peer_rw; };
struct nvme_ctrl { struct device *dev,*device; const struct nvme_ctrl_ops *ops; bool sgl; int state; };
struct gendisk { u64 capacity,diskseq; bool ro; };
struct nvme_ns_head { u8 lba_shift; u32 ns_id; u16 ms,pi_size; u8 pi_type; struct {u8 csi,eui64[8],nguid[16],uuid[16];} ids; };
struct cdev { int unused; };
struct nvme_ns { struct nvme_ns_head *head; struct gendisk *disk; struct request_queue *queue; struct nvme_ctrl *ctrl; unsigned long flags; struct cdev cdev; };
struct inode { struct cdev *i_cdev; };
struct file_operations { void (*uring_cmd)(void); };
struct file { const struct file_operations *f_op; struct inode *inode; unsigned f_mode; };
#define FMODE_READ 1U
#define FMODE_WRITE 2U
struct xdev_ext_mech_pool { u32 kind,frame_size; };
struct xdev_ext_mech_session { struct xdev_ext_mech_layout layout; struct xdev_ext_mech_pool pool; u32 depth; int state; };
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; struct file *file; void *priv; u64 arg0,arg1; u32 direction; bool poll; };
struct xdev_ext_mech_frame { void *kaddr; u64 umem_addr; u32 index,data_off,data_len; };
struct xdev_ext_mech_batch { void *priv; struct xdev_ext_mech_stage *stage; u32 bytes,nr; u64 id,ticket; struct xdev_ext_mech_frame frames[32]; };
struct xdev_ext_family_hooks_hdr { unsigned family; };
struct xdev_ext_stor_hooks {struct xdev_ext_family_hooks_hdr hdr;u32 extent_align_mask,max_extents;};
struct xdev_ext_peer_fd_lease { struct { u64 dma_address; u32 len; } lease; };
struct nvme_xdev_ext_peer_trace { struct xdev_ext_peer_fd_lease *leases; u32 nr_leases,bytes;const char *origin;u64 cookie; };
enum dma_data_direction {DMA_TO_DEVICE,DMA_FROM_DEVICE};
/* GCC function-entry observation preserves production source bodies. */
static void *watch_functions[8];static char watch_codes[8],watch_trace[64];
static unsigned watch_count,watch_length;
void __attribute__((no_instrument_function)) __cyg_profile_func_enter(void *fn,void *caller)
{
 (void)caller;
 for(unsigned i=0;i<watch_count;i++)if(fn==watch_functions[i] && watch_length<63){watch_trace[watch_length++]=watch_codes[i];watch_trace[watch_length]=0;}
}
void __attribute__((no_instrument_function)) __cyg_profile_func_exit(void *fn,void *caller){(void)fn;(void)caller;}
static char events[4096]; static unsigned event_count;
static void ev(char c) {assert(event_count+1<sizeof(events));events[event_count++]=c;events[event_count]=0;}
static int alloc_call,alloc_fail,live_allocs; static size_t alloc_sizes[32];
static void *zalloc(size_t n) {alloc_sizes[alloc_call++]=n;ev('A');if(alloc_call==alloc_fail)return NULL;void *p=calloc(1,n);if(p)live_allocs++;return p;}
#define kzalloc(n,g) zalloc(n)
#define kcalloc(n,s,g) zalloc((n)*(s))
#define kvcalloc(n,s,g) zalloc((n)*(s))
static void free_mem(void *p) {if(p){live_allocs--;ev('F');free(p);}}
#define kfree(p) free_mem(p)
#define kvfree(p) free_mem(p)
static void *dma_alloc_coherent(struct device *d,size_t n,dma_addr_t *dma,int g) { (void)d;(void)g;*dma=0x200000;return zalloc(n); }
static void dma_free_coherent(struct device *d,size_t n,void *p,dma_addr_t dma) {(void)d;(void)n;(void)dma;free_mem(p);}
static struct bio *bio_kmalloc(unsigned n,int g){(void)n;(void)g;return zalloc(sizeof(struct bio));}
static void bio_uninit(struct bio *b){(void)b;ev('U');}
static void bio_init(struct bio *b,void *disk,void *vec,unsigned n,unsigned op){(void)disk;(void)vec;(void)n;(void)op;b->bytes=0;b->bi_vcnt=0;ev('M');}
static unsigned bio_add_page(struct bio *b,struct page *p,unsigned n,unsigned off){(void)p;(void)off;b->bytes+=n;b->bi_vcnt++;return n;}
static int append_errno;
static int blk_rq_append_bio(struct request *r,struct bio *b){ev('B');if(append_errno)return append_errno;r->bio=b;return 0;}
static u32 queue_virt_boundary(const struct request_queue *q){return q->virt_boundary;}
static u32 queue_max_segments(const struct request_queue *q){return q->max_segments;}
static u32 queue_max_segment_size(const struct request_queue *q){return q->max_segment_size;}
static u32 queue_max_hw_sectors(const struct request_queue *q){return q->max_hw_sectors;}
static u32 blk_lim_dma_alignment_and_pad(const struct queue_limits *l){return l->dma_alignment|l->dma_pad_mask;}
static bool dev_is_pci(const struct device *d){return d->pci;}
#define to_pci_dev(d) container_of(d,struct pci_dev,dev)
static bool test_bit(unsigned n,const unsigned long *v){return !!(*v&(1UL<<n));}
static u64 get_capacity(const struct gendisk *d){return d->capacity;}
static bool get_disk_ro(const struct gendisk *d){return d->ro;}
static bool nvme_ctrl_sgl_supported(const struct nvme_ctrl *c){return c->sgl;}
static int nvme_ctrl_state(const struct nvme_ctrl *c){return c->state;}
static struct inode *file_inode(struct file *f){ev('N');return f->inode;}
static void nvme_ns_chr_uring_cmd(void){}
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s){return &s->layout;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s){return s->depth;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b){return b->priv;}
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b){return b->bytes;}
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b){return b->id;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b){return b->nr;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 i,struct xdev_ext_mech_frame *f){if(i>=b->nr)return -ERANGE;*f=b->frames[i];return 0;}
static struct page pages[32];
static struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *po,u32 *n){(void)p;*po=off%4096;*n=4096-*po;return &pages[f->index];}
static int effects_allowed=1;
static bool nvme_xdev_ext_mech_cmd_allowed(struct nvme_ns *ns,struct file *f,bool w){(void)ns;(void)f;(void)w;ev('E');return effects_allowed;}
static int dead_errno;
static void nvme_xdev_ext_class_mark_dead(struct xdev_ext_mech_stage *);
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err){ev('D');dead_errno=err;nvme_xdev_ext_class_mark_dead(st);}
static unsigned plan_calls; static int plan_errno;
static void xdev_ext_mech_trace_plan(struct xdev_ext_mech_batch *b,u64 slba,u32 bytes,u32 aux,int ret){(void)b;(void)slba;(void)bytes;(void)aux;ev('T');plan_calls++;plan_errno=ret;}
static unsigned rq_allocs,rq_frees,posts;static int tag_errno;static bool force_unpolled;static struct request_queue *allocated_queue;static struct nvme_command last_command;
static struct request req;static struct blk_mq_hw_ctx hctx={.queue_num=17};
static struct request *blk_mq_alloc_request(struct request_queue *q,blk_opf_t op,int f){assert(f==1);ev('R');rq_allocs++;allocated_queue=q;if(tag_errno)return ERR_PTR(tag_errno);memset(&req,0,sizeof(req));req.mq_hctx=&hctx;req.cmd_flags=force_unpolled?op&~REQ_POLLED:op;return &req;}
static bool blk_rq_is_poll(struct request *r){return r->cmd_flags&REQ_POLLED;}
static void blk_mq_free_request(struct request *r){assert(r==&req);ev('Q');rq_frees++;}
static unsigned nvme_req_op(struct nvme_command *c){return c->rw.opcode==1?1:0;}
static void nvme_init_request(struct request *r,struct nvme_command *c){ev('I');r->command=*c;r->pdu.cmd=&r->command;last_command=*c;}
#define nvme_req(r) (&(r)->pdu)
static void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b,u64 cookie,u64 slba,u32 bytes,u32 aux){(void)b;(void)cookie;(void)slba;(void)bytes;(void)aux;ev('S');}
static void blk_execute_rq_nowait(struct request *r,bool at_head){(void)r;(void)at_head;ev('X');posts++;}
static int nvme_xdev_ext_class_end_io(struct request *r,int err){(void)r;return err;}
static int nvme_xdev_ext_peer_end_io(struct request *r,int err){(void)r;return err;}
static int nvme_xdev_ext_class_bounce(struct xdev_ext_mech_stage *s,struct xdev_ext_mech_batch *b,struct request *r,void *bp){(void)s;(void)b;(void)r;(void)bp;return -EREMOTEIO;}
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p){(void)p;return NULL;}
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p){(void)p;return 5;}
static int xdev_ext_peer_lease_split(struct file *f,struct pci_dev *d,u64 g,u64 off,u32 len,enum dma_data_direction dir,struct xdev_ext_peer_fd_lease *l){(void)f;(void)d;(void)g;(void)off;(void)len;(void)dir;(void)l;return -EFAULT;}
static void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *l,bool q){(void)l;(void)q;}
static void nvme_xdev_ext_peer_trace_release(struct nvme_xdev_ext_peer_trace *t,bool q){(void)t;(void)q;}
static u32 poll_keys[256],poll_count;static struct request_queue *polled_queue;static int poll_negative_key=-1;
static int blk_mq_poll_hw_queue(struct request_queue *q,u32 key,void *batch){assert(!batch);polled_queue=q;poll_keys[poll_count++]=key;return (int)key==poll_negative_key?-EIO:1;}
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 t){(void)b;(void)t;return 0;}
static void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,u64 t,int s){(void)b;(void)t;(void)s;}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 t,int s,bool u){(void)b;(void)t;(void)s;(void)u;}

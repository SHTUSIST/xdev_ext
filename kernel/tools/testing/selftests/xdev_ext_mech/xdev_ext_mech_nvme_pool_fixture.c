/* SPDX-License-Identifier: GPL-2.0 */
/* OS shims only: production owns the resource and completion transitions. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/linux/nvme_xdev_ext_passthru.h"
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int atomic_t;
typedef int blk_status_t;
#define PAGE_SHIFT 12
#define PAGE_SIZE (1U << PAGE_SHIFT)
#define BIO_MAX_INLINE_VECS 256
#define GFP_KERNEL 0
#define BLK_MQ_REQ_NOWAIT 1
#define NVME_REQ_USERCMD 1
#define NVME_REQ_XDEV_EXT_ZC 2
#define NVME_REQ_CANCELLED 4
#define XDEV_EXT_MECH_SESSION_ZOMBIE 5
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(t,a,b) ((t)min(a,b))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define atomic_read(p) (*(p))
#define WARN_ON_ONCE(x) (!!(x))
#define cpu_to_le32(v) (v)
#define le64_to_cpu(v) (v)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define nvme_req(r) (&(r)->nvme)
struct page { unsigned char data[PAGE_SIZE]; };
struct nvme_ns_head;
struct gendisk;
struct request_queue;
struct nvme_ns { void *queue; };
struct bio {
 unsigned int bi_inline_vecs[256];
 unsigned int used, capacity, bytes;
 struct bio *bi_next;
};
struct nvme_command {
 struct { u8 opcode; u32 nsid; } rw;
 struct { u32 cdw10,cdw11,cdw12; } common;
};
struct xdev_ext_mech_batch;
struct nvme_xdev_ext_mech_slot;
/* PRODUCTION_TYPES */
#define XDEV_EXT_MECH_POOL_PEER 3
struct xdev_ext_mech_pool { struct page pages[2]; unsigned int kind; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; struct xdev_ext_mech_layout layout; unsigned int depth,state; };
struct xdev_ext_mech_frame { void *kaddr; u64 umem_addr; u32 index,data_off,data_len; void *pool_priv; };
struct xdev_ext_mech_batch { struct nvme_xdev_ext_mech_batch priv; u64 id,ticket; bool claimed,uncertain; int status; };
struct xdev_ext_mech_stage { struct nvme_xdev_ext_mech_stage *priv; struct xdev_ext_mech_session *s; };
enum rq_end_io_ret { RQ_END_IO_FREE };
struct request {
 struct { unsigned int flags; unsigned short status; struct { u64 u64; } result; } nvme;
 unsigned int cmd_flags,rq_flags;
 union {unsigned int residual;unsigned int __data_len;};
 struct bio *bio;
 enum rq_end_io_ret (*end_io)(struct request *,blk_status_t);
 void *end_io_data;
};
/* Host-page pool tests must never execute the separately tested GPU branch. */
static int nvme_xdev_ext_peer_submit(struct xdev_ext_mech_stage *st,
                                    struct xdev_ext_mech_batch *b)
{ (void)st; (void)b; abort(); }
static const char *mode;
static unsigned int hot,hot_allocs,cold_allocs,submitted,completed,live,bio_endios;
static struct request *pending[4];
static unsigned int pending_count;
static struct nvme_xdev_ext_mech_completion old_done;
static struct request requests[512];
static unsigned int next_request;
static void *kmalloc(size_t n,int flags)
{ (void)flags; if(hot)hot_allocs++;else cold_allocs++;
#ifdef CONFIG_XDEV_EXT_MECH_KVM_BOUNCE
 if(!strcmp(mode,"init-fail") && !hot && cold_allocs==4)return NULL;
#else
 if(!strcmp(mode,"init-fail") && !hot && cold_allocs==3)return NULL;
#endif
 void *p=calloc(1,n);if(p)live++;return p; }
static void *kcalloc(size_t n,size_t size,int flags)
{ return kmalloc(n*size,flags); }
static void kfree(void *p) { if(p)live--;free(p); }
static struct page *alloc_page(int flags) { return kmalloc(sizeof(struct page),flags); }
static void __free_page(struct page *page) { kfree(page); }
static struct bio *bio_kmalloc(unsigned short n,int flags)
{ struct bio *bio=kmalloc(sizeof(*bio),flags); if(bio)bio->capacity=n;return bio; }
static void bio_init(struct bio *bio,void *dev,void *vecs,unsigned int n,unsigned int flags)
{ (void)dev;(void)vecs;(void)flags;bio->used=0;bio->bytes=0;bio->capacity=n;bio->bi_next=NULL; }
static void bio_uninit(struct bio *bio) { bio->used=0; }
static unsigned int bio_add_page(struct bio *bio,struct page *page,unsigned int len,unsigned int off)
{ (void)page;(void)off;if(!strcmp(mode,"short-map") || bio->used==bio->capacity)return 0;bio->used++;bio->bytes+=len;return len; }
static int blk_rq_append_bio(struct request *req,struct bio *bio)
{ req->bio=bio;req->residual=bio->bytes;return 0; }
static unsigned int blk_rq_bytes(struct request *req) { return req->residual; }
static struct nvme_xdev_ext_mech_batch *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { return &b->priv; }
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { return b->id; }
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b) { return b->ticket; }
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { (void)b;return 2; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { (void)b;return 1024; }
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 pos,struct xdev_ext_mech_frame *f)
{ (void)b;if(pos>=2)return -ERANGE;*f=(struct xdev_ext_mech_frame){.index=pos,.data_off=384,.data_len=512};return 0; }
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s) { return &s->layout; }
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s) { return s->depth; }
static u32 xdev_ext_mech_session_state(struct xdev_ext_mech_session *s) { return s->state; }
static u32 xdev_ext_mech_layout_frames(const struct xdev_ext_mech_layout *l) { return DIV_ROUND_UP(l->group_bytes,l->seg_len); }
static struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *pool,const struct xdev_ext_mech_frame *f,u32 off,u32 *page_off,u32 *len)
{ *page_off=off%PAGE_SIZE;*len=PAGE_SIZE-*page_off;return f->index<2 ? &pool->pages[f->index] : NULL; }
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 ticket)
{ if(b->ticket!=ticket || b->claimed)return -ESTALE;b->claimed=true;return 0; }
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int err,bool uncertain)
{ if(b->ticket!=ticket)abort();b->status=err;b->uncertain=uncertain;completed++; }
static int blk_status_to_errno(blk_status_t err) { return err ? -EIO : 0; }
static int nvme_req_op(struct nvme_command *cmd) { (void)cmd;return 0; }
static struct request *blk_mq_alloc_request(void *q,int op,unsigned int flags)
{ (void)q;(void)op;if(flags!=BLK_MQ_REQ_NOWAIT)abort();if(!strcmp(mode,"tags"))return ERR_PTR(-EAGAIN);return &requests[next_request++]; }
static void blk_mq_free_request(struct request *req) { (void)req; }
static void nvme_init_request(struct request *req,struct nvme_command *cmd) { (void)req;(void)cmd; }
static int nvme_xdev_ext_class_recheck(struct xdev_ext_mech_stage *st) { (void)st;return 0; }
static struct nvme_xdev_ext_queue_caps nvme_xdev_ext_class_caps(const struct nvme_xdev_ext_mech_stage *p)
{ (void)p;return (struct nvme_xdev_ext_queue_caps){.page_size=PAGE_SIZE,.max_segments=256,.max_segment_size=1U<<20,.max_bytes=1U<<20,.lba_size=512}; }
static int nvme_xdev_ext_class_bounce(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,struct request *req,struct nvme_xdev_ext_mech_batch *bp)
{ (void)st;(void)b;(void)req;(void)bp;return -EREMOTEIO; }
static void nvme_xdev_ext_class_bounce_release(struct xdev_ext_mech_batch *b,struct nvme_xdev_ext_mech_batch *bp,bool copy_back)
{ (void)b;(void)bp;(void)copy_back; }
/* External block-layer services only; the completion loop below is extracted
 * verbatim from block/blk-mq.c, including its preserved end_io bookkeeping. */
#define RQF_FLUSH_SEQ 1
#define BLK_STS_OK 0
#define REQ_OP_READ 0
#define BIO_TRACE_COMPLETION 0
#define req_op(r) ((r)->cmd_flags)
#define trace_block_rq_complete(r,e,n) ((void)(r),(void)(e),(void)(n))
#define blk_integrity_rq(r) false
#define blk_integrity_complete(r,n) ((void)(r),(void)(n))
#define blk_crypto_rq_put_keyslot(r) ((void)(r))
#define blk_account_io_completion(r,n) ((void)(r),(void)(n))
#define bio_clear_flag(b,f) ((void)(b),(void)(f))
#define blk_zone_update_request_bio(r,b) ((void)(r),(void)(b))
static void bio_endio(struct bio *bio) {(void)bio;bio_endios++;}
/* BLOCK_BATCH_COMPLETION */
static void blk_execute_rq_nowait(struct request *req,bool at_head)
{ (void)at_head;submitted++;
 if(!strcmp(mode,"capacity")){pending[pending_count++]=req;return;}
 if(!strcmp(mode,"stale") && submitted==1)old_done=*(struct nvme_xdev_ext_mech_completion *)req->end_io_data;
 if(!strncmp(mode,"batch",5)) {
  if(!strcmp(mode,"batch-short"))req->residual=512;
  if(!strcmp(mode,"batch-foreign")) {static struct bio foreign;foreign=*req->bio;req->bio=&foreign;}
  blk_complete_request(req);
 } else {req->bio=NULL;req->residual=!strcmp(mode,"short-native") ? 512 : 0;}
 req->end_io(req,0); }
/* PRODUCTION_FUNCTIONS */
int main(int argc,char **argv)
{
 struct nvme_ns ns={};
 struct nvme_xdev_ext_mech_stage p={.ns=&ns};
 struct xdev_ext_mech_session session={.layout={.frame_size=4096,.hdr_room=384,.seg_len=512,.group_bytes=1024},.depth=2};
 struct xdev_ext_mech_stage st={.priv=&p,.s=&session};
 struct xdev_ext_mech_batch batches[3]={},*b=&batches[0];
 struct xdev_ext_nvme_mech_cqe cqe;
 unsigned int i,rounds,denied=0,retained=0,uncertain=0;
 int rc;
 mode=argc>1 ? argv[1] : "flow";
 /* POOL_INIT */
 if(rc)goto out;
 hot=1;
 if(!strcmp(mode,"capacity")) {
  for(i=0;i<3;i++) {
   b=&batches[i];b->id=b->ticket=i+1;b->priv.validated=true;b->priv.batch_id=b->id;
   rc=nvme_xdev_ext_class_submit(&st,b);
   if(i<2 && rc)abort();
   if(i==2 && rc==-EAGAIN)denied++;
  }
  pending[0]->bio=NULL;pending[0]->residual=0;pending[0]->end_io(pending[0],0);
  nvme_xdev_ext_class_fill_cqe(&st,&batches[0],&cqe);
  rc=nvme_xdev_ext_class_submit(&st,&batches[2]);
  if(rc)goto out;
  for(i=1;i<3;i++) {
   pending[i]->bio=NULL;pending[i]->residual=0;pending[i]->end_io(pending[i],0);
   nvme_xdev_ext_class_fill_cqe(&st,&batches[i],&cqe);
  }
 } else {
  rounds=!strcmp(mode,"flow") ? 256 : !strcmp(mode,"stale") ? 2 : 1;
  for(i=0;i<rounds;i++) {
   memset(b,0,sizeof(*b));b->id=b->ticket=i+1;b->priv.validated=true;b->priv.batch_id=b->id;
   rc=nvme_xdev_ext_class_submit(&st,b);
   if(rc)break;
   nvme_xdev_ext_class_fill_cqe(&st,b,&cqe);
  }
 }
 if(!strcmp(mode,"stale")) {
  struct request stale={.end_io_data=&old_done};
  nvme_xdev_ext_class_end_io(&stale,0);
 }
 uncertain=b->uncertain;
 /* POOL_COUNT */
 hot=0;
 /* POOL_FREE */
out:
 printf("rc=%d hot_allocs=%u cold_allocs=%u submitted=%u completed=%u live=%u denied=%u retained=%u uncertain=%u status=%d bio_endios=%u\n",
        rc,hot_allocs,cold_allocs,submitted,completed,live,denied,retained,uncertain,b->status,bio_endios);
 return 0;
}

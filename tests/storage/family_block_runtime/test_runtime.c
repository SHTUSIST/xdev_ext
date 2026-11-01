/* SPDX-License-Identifier: GPL-2.0 */
#include "kernel_boundary.h"
#include "nvme_xdev_ext_passthru.h"
#ifdef BLOCK_NEW
#include <linux/xdev_ext_storfam_block.h>
#endif
static unsigned checks,failures;
static const char *label;
static void eq(const char *s,long long g,long long w){checks++;if(g!=w){failures++;fprintf(stderr,"FAIL %s %s got=%lld want=%lld\n",label,s,g,w);}}
#define EQ(n,g,w) eq(n,(long long)(g),(long long)(w))
struct trace_piece {struct page *page;u32 off,len;};
static struct trace_piece accepted[512];
static unsigned adds,inits,uninits,appends,bounces,frames,pages,byte_queries;
static unsigned family_caps,family_preflight,family_append;
static int partial_at,append_error,frame_error_at=-1;
static struct nvme_xdev_ext_mech_slot *active_slot;
static struct request *active_request;
static u16 active_vecs;
static long nvme_xdev_ext_mech_bounces;
static char events[1024];static unsigned nr_events;
static void event(char c){events[nr_events++]=c;events[nr_events]=0;}
// Compile authoritative core accessors/page resolution unchanged. The macros
// rename only entry points so observers can inject frame-accessor errors.
#define xdev_ext_mech_session_pool production_pool
#define xdev_ext_mech_batch_nr_frames production_nr
#define xdev_ext_mech_batch_bytes production_bytes
#define xdev_ext_mech_batch_frame production_frame
#define xdev_ext_mech_frame_page production_page
#include "actual_core.inc"
#undef xdev_ext_mech_session_pool
#undef xdev_ext_mech_batch_nr_frames
#undef xdev_ext_mech_batch_bytes
#undef xdev_ext_mech_batch_frame
#undef xdev_ext_mech_frame_page
struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return production_pool(s);}
u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch *b){return production_nr(b);}
u32 xdev_ext_mech_batch_bytes(const struct xdev_ext_mech_batch *b){byte_queries++;return production_bytes(b);}
int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch *b,u32 pos,struct xdev_ext_mech_frame *f){frames++;if((int)pos==frame_error_at)return -ESTALE;return production_frame(b,pos,f);}
struct page *xdev_ext_mech_frame_page(const struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *page_off,u32 *len){pages++;return production_page(p,f,off,page_off,len);}
int native_bio_add_page(struct bio *bio,struct page *page,unsigned len,unsigned off){
 EQ("append-same-slot-bio",bio==active_slot->bio,1);EQ("append-bio-live",active_slot->bio_live,1);
 accepted[adds]=(struct trace_piece){page,off,len};adds++;event('A');return (int)adds==partial_at?(int)len-1:(int)len;
}
void native_bio_init(struct bio *bio,void *dev,struct bio_vec *vecs,unsigned nr,unsigned flags){
 EQ("init-slot-bio",bio==active_slot->bio,1);EQ("init-device-NULL",dev==NULL,1);EQ("init-inline-vec-identity",vecs==bio->bi_inline_vecs,1);EQ("init-original-capacity",nr,active_vecs);EQ("init-original-command-flags",flags,active_request->cmd_flags);
 inits++;event('I');bio->initialized=1;
}
void native_bio_uninit(struct bio *bio){EQ("uninit-same-bio",bio==active_slot->bio,1);EQ("uninit-before-live-clear",active_slot->bio_live,1);EQ("uninit-initialized",bio->initialized,1);uninits++;event('U');bio->initialized=0;}
int native_append_bio(struct request *r,struct bio *bio){EQ("request-identity",r==active_request,1);EQ("request-bio-identity",bio==active_slot->bio,1);appends++;event('R');if(!append_error)r->bio=bio;return append_error;}
#ifdef BLOCK_NEW
struct xdev_ext_stor_queue_caps __real_xdev_ext_stor_block_caps(struct request_queue*,u8);
int __real_xdev_ext_stor_block_preflight(struct xdev_ext_mech_pool*,struct xdev_ext_mech_batch*,const struct xdev_ext_stor_queue_caps*);
int __real_xdev_ext_stor_block_append(struct xdev_ext_mech_pool*,struct xdev_ext_mech_batch*,struct request*,struct bio*);
struct xdev_ext_stor_queue_caps __wrap_xdev_ext_stor_block_caps(struct request_queue *q,u8 shift){family_caps++;return __real_xdev_ext_stor_block_caps(q,shift);}
int __wrap_xdev_ext_stor_block_preflight(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_batch *b,const struct xdev_ext_stor_queue_caps *c){family_preflight++;return __real_xdev_ext_stor_block_preflight(p,b,c);}
int __wrap_xdev_ext_stor_block_append(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_batch *b,struct request *r,struct bio *bio){family_append++;return __real_xdev_ext_stor_block_append(p,b,r,bio);}
#endif
// Original production bounce body remains the only fallback algorithm. The
// observer records entry and verifies failed direct append retired its bio.
#define nvme_xdev_ext_class_bounce actual_bounce
#include "actual_bounce.inc"
#undef nvme_xdev_ext_class_bounce
static int nvme_xdev_ext_class_bounce(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,struct request *r,struct nvme_xdev_ext_mech_batch *bp){bounces++;event('B');if(bp->slot)EQ("fallback-sees-bio-not-live",bp->slot->bio_live,0);return actual_bounce(st,b,r,bp);}
#include "actual_map.inc"
static struct page opaque_pages[512];static struct page *page_list[512],*bounce_pages[128];
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_mech_batch batch;
static struct request_queue queue;
static struct nvme_ns ns;
static struct nvme_xdev_ext_mech_stage member;
static struct bio slot_bio;
static struct request request;
static struct nvme_xdev_ext_mech_slot slot;
static struct nvme_xdev_ext_mech_batch bp;
static void reset(void){
 memset(&session,0,sizeof(session));memset(&batch,0,sizeof(batch));memset(&slot_bio,0,sizeof(slot_bio));memset(&bp,0,sizeof(bp));memset(&member,0,sizeof(member));
 for(unsigned i=0;i<512;i++){opaque_pages[i].opaque_id=i;page_list[i]=&opaque_pages[i];if(i<128)bounce_pages[i]=&opaque_pages[384+i];}
 session.pool=(struct xdev_ext_mech_pool){.pages=page_list,.frame_size=4096,.nr_frames=128,.nr_pages=512};
 queue=(struct request_queue){.limits={3},.boundary=0,.segments=64,.segment_size=4096,.sectors=256};
 ns.queue=&queue;member.ns=&ns;member.identity.lba_shift=9;member.nr_vecs=64;member.write=false;
 stage=(struct xdev_ext_mech_stage){.s=&session,.priv=&member};
 batch.nr_frames=1;batch.bytes=4096;batch.f[0]=(struct xdev_ext_mech_frame){.index=0,.data_off=0,.data_len=4096};
 slot=(struct nvme_xdev_ext_mech_slot){.bio=&slot_bio,.bounce=bounce_pages,.nr_bounce=128};bp.slot=&slot;
 request=(struct request){.cmd_flags=0x1234};active_slot=&slot;active_request=&request;active_vecs=member.nr_vecs;
 adds=inits=uninits=appends=bounces=frames=pages=byte_queries=family_caps=family_preflight=family_append=0;
 partial_at=append_error=0;frame_error_at=-1;nr_events=0;events[0]=0;nvme_xdev_ext_mech_bounces=0;
}
static int map(void){return nvme_xdev_ext_class_map(&stage,&batch,&request,&bp);}
static void consumption(unsigned append){
#ifdef BLOCK_NEW
 EQ("family-caps-consumed",family_caps,1);EQ("family-preflight-consumed",family_preflight,1);EQ("family-append-consumed",family_append,append);
#else
 (void)append;
#endif
}
static void unchanged_plan(void){EQ("no-published-bio",bp.bio==NULL,1);}
static void map_cases(void){
 label="map-success";reset();EQ("errno",map(),0);consumption(1);EQ("owned-bio-published",bp.bio==&slot_bio,1);EQ("request-owned-bio",request.bio==&slot_bio,1);EQ("bio-live",slot.bio_live,1);EQ("no-uninit-on-success",uninits,0);EQ("no-bounce",bounces,0);EQ("events",strcmp(events,"IAR"),0);
 label="frame-crosses-physical-pages";reset();session.pool.frame_size=8192;batch.f[0].data_off=3584;batch.f[0].data_len=1024;batch.bytes=1024;EQ("errno",map(),0);EQ("pieces",adds,2);EQ("piece0-page",accepted[0].page==page_list[0],1);EQ("piece0-off",accepted[0].off,3584);EQ("piece0-len",accepted[0].len,512);EQ("piece1-page",accepted[1].page==page_list[1],1);EQ("piece1-off",accepted[1].off,0);EQ("piece1-len",accepted[1].len,512);
 label="two-frames-same-actual-page";reset();session.pool.frame_size=512;batch.nr_frames=2;batch.bytes=1024;batch.f[0].data_len=512;batch.f[1]=(struct xdev_ext_mech_frame){.index=1,.data_len=512};queue.segments=1;EQ("errno",map(),0);EQ("physical-pieces-not-segments",adds,2);EQ("same-page-identity",accepted[0].page==accepted[1].page,1);EQ("second-offset",accepted[1].off,512);
 for(unsigned bytes=2048;bytes<=8192;bytes*=4){label="host-current-byte-mismatch";reset();batch.bytes=bytes;bp.slot=NULL;EQ("errno",map(),-EPROTO);consumption(0);EQ("no-init",inits,0);EQ("no-bounce",bounces,0);unchanged_plan();}
 label="same-page-pieces-exceed-slot-vectors";reset();session.pool.frame_size=512;batch.nr_frames=2;batch.bytes=1024;batch.f[0].data_len=512;batch.f[1]=(struct xdev_ext_mech_frame){.index=1,.data_len=512};queue.segments=1;member.nr_vecs=1;active_vecs=1;EQ("piece-count-capacity-refusal",map(),-EREMOTEIO);EQ("no-bounce-for-slot",bounces,0);EQ("no-bio-init",inits,0);
 label="done-before-byte-and-piece-limit";reset();batch.nr_frames=BIO_MAX_INLINE_VECS+1;batch.bytes=5120;queue.limits.align_and_pad=0;
 for(unsigned i=0;i<batch.nr_frames;i++){batch.f[i]=(struct xdev_ext_mech_frame){.index=i,.data_len=513};}
 EQ("errno",map(),-EMSGSIZE);EQ("no-fallback",bounces,0);
 label="bytes-before-piece-limit";reset();batch.nr_frames=BIO_MAX_INLINE_VECS+1;batch.bytes=5120;
 for(unsigned i=0;i<batch.nr_frames;i++){batch.f[i]=(struct xdev_ext_mech_frame){.index=i,.data_len=512};}
 EQ("errno",map(),-EPROTO);EQ("no-fallback",bounces,0);
 label="slot-absent-direct-refusal";reset();bp.slot=NULL;EQ("errno",map(),-EREMOTEIO);consumption(0);EQ("no-bounce",bounces,0);EQ("no-init",inits,0);
 label="slot-too-small-direct-refusal";reset();member.nr_vecs=0;active_vecs=0;EQ("errno",map(),-EREMOTEIO);consumption(0);EQ("no-bounce",bounces,0);EQ("no-init",inits,0);
 label="frame-error-before-slot";reset();bp.slot=NULL;frame_error_at=0;EQ("errno",map(),-ESTALE);EQ("no-page-visit",pages,0);EQ("no-bounce",bounces,0);EQ("no-bio",adds,0);
 label="missing-page-before-slot";reset();bp.slot=NULL;page_list[0]=NULL;EQ("errno",map(),-EFAULT);EQ("no-bounce",bounces,0);EQ("no-init",inits,0);
 label="zero-frame";reset();batch.nr_frames=0;batch.bytes=0;EQ("errno",map(),-EINVAL);EQ("no-bounce",bounces,0);
 label="size-before-slot";reset();bp.slot=NULL;queue.sectors=1;EQ("errno",map(),-EMSGSIZE);EQ("no-bounce",bounces,0);
 label="append-EAGAIN-no-fallback";reset();append_error=-EAGAIN;EQ("errno",map(),-EAGAIN);consumption(1);EQ("uninit-on-error",uninits,1);EQ("live-cleared",slot.bio_live,0);EQ("no-bounce",bounces,0);EQ("order",strcmp(events,"IARU"),0);unchanged_plan();
 label="append-partial-EREMOTEIO";reset();partial_at=1;
#ifdef TEST_BOUNCE
 EQ("errno",map(),0);EQ("fallback-called",bounces,1);EQ("bounce-after-uninit",strncmp(events,"IAUB",4),0);EQ("first-bio-retired",uninits,1);EQ("same-bio-reinitialized",inits,2);EQ("bounce-published-owned-bio",bp.bio==&slot_bio,1);
#else
 EQ("errno",map(),-EREMOTEIO);EQ("fallback-called",bounces,1);EQ("order",strcmp(events,"IAUB"),0);EQ("uninit",uninits,1);EQ("live-cleared",slot.bio_live,0);unchanged_plan();
#endif
 label="preflight-page-gap-original-fallback";reset();batch.nr_frames=2;batch.bytes=1024;batch.f[0].data_len=512;batch.f[1]=(struct xdev_ext_mech_frame){.index=1,.data_len=512};queue.boundary=4095;
#ifdef TEST_BOUNCE
 EQ("errno",map(),0);EQ("bounce-count",bounces,1);
#else
 EQ("errno",map(),-EREMOTEIO);EQ("bounce-count",bounces,1);EQ("no-bio-init",inits,0);
#endif
 label="preflight-alignment-original-fallback";reset();batch.f[0].data_off=1;batch.f[0].data_len=512;batch.bytes=512;
#ifdef TEST_BOUNCE
 EQ("errno",map(),0);EQ("bounce-count",bounces,1);EQ("no-direct-append",family_append,0);
#else
 EQ("errno",map(),-EREMOTEIO);EQ("bounce-count",bounces,1);EQ("no-bio-init",inits,0);
#endif
}
#ifdef BLOCK_NEW
static void runtime_cases(void){
 label="family-caps-real-queue";reset();queue.boundary=4095;queue.limits.align_and_pad=7;queue.segments=3;queue.segment_size=16384;queue.sectors=64;
 struct xdev_ext_stor_queue_caps c=xdev_ext_stor_block_caps(&queue,12);
 EQ("boundary",c.virt_boundary_mask,4095);EQ("page-size",c.page_size,4096);EQ("alignment-pad",c.dma_align_mask,7);EQ("max-segments",c.max_segments,3);EQ("max-segment",c.max_segment_size,16384);EQ("max-bytes",c.max_bytes,32768);EQ("LBA-size",c.lba_size,4096);
 label="preflight-positive-piece-count";reset();session.pool.frame_size=512;batch.nr_frames=2;batch.bytes=1024;batch.f[0].data_len=512;batch.f[1]=(struct xdev_ext_mech_frame){.index=1,.data_len=512};queue.segments=1;c=xdev_ext_stor_block_caps(&queue,9);EQ("pieces",xdev_ext_stor_block_preflight(&session.pool,&batch,&c),2);EQ("preflight-no-bio-side-effect",inits+adds+appends+uninits,0);
 for(unsigned bytes=2048;bytes<=8192;bytes*=4){label="preflight-current-bytes";reset();batch.bytes=bytes;c=xdev_ext_stor_block_caps(&queue,9);EQ("errno",xdev_ext_stor_block_preflight(&session.pool,&batch,&c),-EPROTO);}
 label="piece-limit-after-current-bytes";reset();batch.nr_frames=BIO_MAX_INLINE_VECS+1;batch.bytes=batch.nr_frames*512;
 for(unsigned i=0;i<batch.nr_frames;i++){batch.f[i]=(struct xdev_ext_mech_frame){.index=i,.data_len=512};}
 c=xdev_ext_stor_block_caps(&queue,9);EQ("piece-limit",xdev_ext_stor_block_preflight(&session.pool,&batch,&c),-EREMOTEIO);batch.bytes*=2;EQ("bytes-before-piece-limit",xdev_ext_stor_block_preflight(&session.pool,&batch,&c),-EPROTO);
 label="LBA-before-piece-limit-and-bytes";c.dma_align_mask=0;for(unsigned i=0;i<batch.nr_frames;i++){batch.f[i].data_len=513;}EQ("LBA-first",xdev_ext_stor_block_preflight(&session.pool,&batch,&c),-EMSGSIZE);
 label="append-borrows-preinitialized-bio";reset();slot.bio_live=true;slot_bio.initialized=1;EQ("errno",xdev_ext_stor_block_append(&session.pool,&batch,&request,&slot_bio),0);EQ("no-runtime-init-uninit",inits+uninits,0);EQ("one-native-append",appends,1);EQ("same-caller-bio",request.bio==&slot_bio,1);
 label="append-native-partial";reset();slot.bio_live=true;slot_bio.initialized=1;partial_at=1;EQ("errno",xdev_ext_stor_block_append(&session.pool,&batch,&request,&slot_bio),-EREMOTEIO);EQ("no-native-append",appends,0);EQ("no-runtime-uninit",uninits,0);
 label="append-native-EAGAIN";reset();slot.bio_live=true;slot_bio.initialized=1;append_error=-EAGAIN;EQ("errno",xdev_ext_stor_block_append(&session.pool,&batch,&request,&slot_bio),-EAGAIN);EQ("one-native-append",appends,1);EQ("no-runtime-uninit",uninits,0);
 label="append-missing-page";reset();slot.bio_live=true;slot_bio.initialized=1;page_list[0]=NULL;EQ("errno",xdev_ext_stor_block_append(&session.pool,&batch,&request,&slot_bio),-EFAULT);EQ("no-native-append",appends,0);EQ("no-runtime-uninit",uninits,0);
 label="append-accessor-failure";reset();slot.bio_live=true;slot_bio.initialized=1;frame_error_at=0;EQ("errno",xdev_ext_stor_block_append(&session.pool,&batch,&request,&slot_bio),-ESTALE);EQ("no-native-append",appends,0);
}
#endif
int main(void){map_cases();
#ifdef BLOCK_NEW
 runtime_cases();
#endif
 printf("storage_block_runtime assertions=%u failures=%u bounce=%u\n",checks,failures,
#ifdef TEST_BOUNCE
 1U
#else
 0U
#endif
 );return failures?1:0;}

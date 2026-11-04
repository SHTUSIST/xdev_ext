/* SPDX-License-Identifier: GPL-2.0 */
#include "native_boundary.h"
#ifdef POLL_NEW
#include <linux/xdev_ext_storfam_block.h>
#endif
static unsigned checks,failures;
static const char *label;
static void eq(const char *s,long long got,long long want){checks++;if(got!=want){failures++;fprintf(stderr,"FAIL %s %s got=%lld want=%lld\n",label,s,got,want);}}
#define EQ(s,g,w) eq(s,(long long)(g),(long long)(w))
enum event {NS=1,CAPABLE,ALLOW,IDENTITY,WINDOW,ALLOC,CHECK,INIT,SLOT,MAP,ARM,TRACE,EXEC,CLAIM,PUBLISH,FREE,PUT};
static unsigned events[128],nr_events;
static void event(unsigned e){if(nr_events>=128)abort();events[nr_events++]=e;}
static unsigned count(unsigned e){unsigned n=0;for(unsigned i=0;i<nr_events;i++)n+=events[i]==e;return n;}
static unsigned pos(unsigned e){for(unsigned i=0;i<nr_events;i++)if(events[i]==e)return i;return 999;}
static void before(unsigned a,unsigned b){EQ("ordered-boundaries",pos(a)<pos(b),1);}
static struct request_queue queue;
static struct blk_mq_queue_map maps[3];
static struct blk_mq_tag_set tags;
static struct blk_mq_hw_ctx hctx;
static struct request request;
static struct nvme_request native;
static struct nvme_command captured;
static struct nvme_ctrl_ops ctrl_ops;
static struct nvme_ctrl ctrl;
static struct nvme_ns_head head;
static struct gendisk disk;
static struct nvme_ns ns;
static struct file file;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_stage stage;
static struct nvme_xdev_ext_mech_stage member;
static struct nvme_xdev_ext_mech_batch bp;
static struct nvme_xdev_ext_mech_slot host_slot;
static struct nvme_xdev_ext_peer_slot peer_slot;
static struct nvme_xdev_ext_peer_res peer_res;
static struct xdev_ext_mech_batch batch;
static struct xdev_ext_mech_stage_uapi uapi;
static int alloc_error,map_error,slot_error,recheck_error,claim_error,completion_error;
static bool namespace_present,allowed,early;
static unsigned family_capable,family_check,family_arm,claim_calls,publish_calls;
static blk_opf_t allocation_opf,native_opf;
static struct xdev_ext_stor_completion *active_done;
static void reset(bool peer){
 memset(&member,0,sizeof(member));memset(&bp,0,sizeof(bp));memset(&host_slot,0,sizeof(host_slot));memset(&peer_slot,0,sizeof(peer_slot));memset(&request,0,sizeof(request));memset(&native,0,sizeof(native));memset(&uapi,0,sizeof(uapi));memset(maps,0,sizeof(maps));
 maps[2].nr_queues=1;tags=(struct blk_mq_tag_set){.nr_maps=3,.map=maps};queue=(struct request_queue){.limits={.features=BLK_FEAT_POLL},.tag_set=&tags,.sectors=1024};hctx=(struct blk_mq_hw_ctx){.type=HCTX_TYPE_POLL,.queue_num=7};request.mq_hctx=&hctx;
 ctrl_ops=(struct nvme_ctrl_ops){.name="pcie",.peer_rw=(void*)(uintptr_t)1};ctrl=(struct nvme_ctrl){.ops=&ctrl_ops,.state=NVME_CTRL_LIVE};head=(struct nvme_ns_head){.lba_shift=9};disk=(struct gendisk){.capacity=4096};ns=(struct nvme_ns){.queue=&queue,.ctrl=&ctrl,.head=&head,.disk=&disk,.flags=1};file.f_mode=FMODE_READ|FMODE_WRITE;
 session=(struct xdev_ext_mech_session){.pool={.kind=peer?XDEV_EXT_MECH_POOL_PEER:0},.layout={.group_bytes=512}};stage=(struct xdev_ext_mech_stage){.priv=&member,.poll=true,.s=&session,.file=&file,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE};peer_res=(struct nvme_xdev_ext_peer_res){.slots=&peer_slot,.nr_slots=1};member.ns=&ns;member.peer=&peer_res;member.slots=&host_slot;member.nr_slots=1;
 batch=(struct xdev_ext_mech_batch){.id=17,.ticket=0x55,.priv=&bp};bp.validated=true;bp.batch_id=17;bp.rw=(struct xdev_ext_stor_rw){.slba=2,.nlb=1,.byte_length=512};host_slot.done.poll_queue=peer_slot.done.poll_queue=91;
 nr_events=family_capable=family_check=family_arm=claim_calls=publish_calls=0;alloc_error=map_error=slot_error=recheck_error=claim_error=completion_error=0;namespace_present=allowed=true;early=false;native_opf=UINT32_C(0x80000003);allocation_opf=0;active_done=peer?&peer_slot.done:&host_slot.done;
}
void boundary_read(const void *p,size_t n){(void)p;(void)n;}
void boundary_before_write(const void *p,size_t n,const void *v){if(p==&active_done->poll_live&&n==sizeof(bool)&&*(const bool*)v){event(ARM);EQ("queue-before-live",active_done->poll_queue,7);EQ("batch-before-live",active_done->b==&batch,1);EQ("ticket-before-live",active_done->ticket,0x55);EQ("callback-before-live",request.end_io!=NULL,1);EQ("context-before-live",request.end_io_data==active_done,1);}}
#define blk_rq_is_poll production_blk_rq_is_poll
#include "actual_blk_predicate.inc"
#undef blk_rq_is_poll
bool blk_rq_is_poll(struct request *r){event(CHECK);return production_blk_rq_is_poll(r);}
int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 ticket){event(CLAIM);claim_calls++;EQ("actual-claim-batch",b==&batch,1);EQ("actual-captured-ticket",ticket,0x55);EQ("clear-before-actual-claim",active_done->poll_live,0);return claim_error;}
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int status,bool uncertain){event(PUBLISH);publish_calls++;EQ("publish-batch",b==&batch,1);EQ("publish-ticket",ticket,0x55);EQ("publish-status",status,completion_error);EQ("UNKNOWN-keeps-resource",uncertain,completion_error!=0);}
void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,u64 ticket,int status){(void)b;(void)ticket;(void)status;}
#include "actual_stor_done.inc"
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s){return &s->layout;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b){return b->priv;}
u32 xdev_ext_mech_batch_bytes(const struct xdev_ext_mech_batch *b){(void)b;return 512;}
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b){return b->id;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
static struct nvme_ns *nvme_xdev_ext_class_ns(struct file *f){event(NS);EQ("namespace-file",f==&file,1);return namespace_present?&ns:NULL;}
static bool nvme_xdev_ext_mech_cmd_allowed(struct nvme_ns *n,struct file *f,bool write){(void)n;(void)f;(void)write;event(ALLOW);return allowed;}
static int nvme_xdev_ext_capture_identity(struct nvme_ns *n,struct nvme_xdev_ext_identity *i,const struct nvme_ns_head **h,const struct gendisk **d,const struct request_queue **q){event(IDENTITY);*i=(struct nvme_xdev_ext_identity){.nsid=4,.lba_shift=9};*h=n->head;*d=n->disk;*q=n->queue;return 0;}
static int nvme_xdev_ext_mech_bind_window(const struct nvme_xdev_ext_identity *i,bool w,u64 a,u64 b,u32 bytes,struct xdev_ext_stor_window *out){(void)i;(void)w;(void)a;(void)b;(void)bytes;(void)out;event(WINDOW);return 0;}
static void *kzalloc(size_t n,int flags){(void)flags;return calloc(1,n);}
static void kfree(void *p){free(p);}
static int nvme_xdev_ext_class_resources_init(struct xdev_ext_mech_stage *st){(void)st;return 0;}
static int nvme_xdev_ext_peer_resources_init(struct xdev_ext_mech_stage *st){(void)st;return 0;}
static bool nvme_ctrl_sgl_supported(struct nvme_ctrl *c){(void)c;return true;}
static int nvme_xdev_ext_class_recheck(struct xdev_ext_mech_stage *st){(void)st;return recheck_error;}
static blk_opf_t nvme_req_op(struct nvme_command *cmd){(void)cmd;return native_opf;}
static u32 nvme_xdev_ext_sqe_dw(const u8 *sqe,unsigned n){(void)sqe;(void)n;return 0;}
static struct nvme_request *nvme_req(struct request *r){EQ("native-rq-identity",r==&request,1);return &native;}
static struct request *blk_mq_alloc_request(struct request_queue *q,blk_opf_t opf,unsigned flags){event(ALLOC);EQ("allocation-queue",q==&queue,1);EQ("NOWAIT-preserved",flags,BLK_MQ_REQ_NOWAIT);allocation_opf=opf;request.cmd_flags=opf;return alloc_error?ERR_PTR(alloc_error):&request;}
static void blk_mq_free_request(struct request *r){event(FREE);EQ("free-rq",r==&request,1);}
static void nvme_init_request(struct request *r,struct nvme_command *c){event(INIT);EQ("init-rq",r==&request,1);captured=*c;native.cmd=&captured;}
static struct nvme_xdev_ext_mech_slot *nvme_xdev_ext_class_slot_get(struct xdev_ext_mech_stage *s,struct nvme_xdev_ext_mech_batch *b){(void)s;event(SLOT);if(slot_error)return ERR_PTR(slot_error);b->slot=&host_slot;host_slot.runtime.busy=true;return &host_slot;}
static struct nvme_xdev_ext_peer_slot *nvme_xdev_ext_peer_slot_get(struct nvme_xdev_ext_peer_res *p,struct nvme_xdev_ext_mech_batch *b){(void)p;event(SLOT);if(slot_error)return ERR_PTR(slot_error);b->peer_slot=&peer_slot;peer_slot.runtime.busy=true;return &peer_slot;}
static void nvme_xdev_ext_class_slot_put(struct xdev_ext_mech_stage *s,struct nvme_xdev_ext_mech_batch *b){(void)s;(void)b;event(PUT);}
static void nvme_xdev_ext_peer_slot_put(struct nvme_xdev_ext_peer_res *p,struct nvme_xdev_ext_mech_batch *b){(void)p;(void)b;event(PUT);}
static int nvme_xdev_ext_class_map(struct xdev_ext_mech_stage *s,struct xdev_ext_mech_batch *b,struct request *r,struct nvme_xdev_ext_mech_batch *private){(void)s;(void)b;event(MAP);private->bio=(void*)(uintptr_t)0x1000;r->bio=private->bio;r->bytes=512;return map_error;}
static int nvme_xdev_ext_peer_map(struct xdev_ext_mech_stage *s,struct xdev_ext_mech_batch *b,struct nvme_xdev_ext_peer_slot *slot,u32 bytes,struct nvme_command *c){(void)s;(void)b;(void)slot;(void)bytes;(void)c;event(MAP);return map_error;}
static void nvme_xdev_ext_mech_cqe(int status,u64 result,struct xdev_ext_nvme_mech_cqe *c){c->err=status;c->result=result;}
static void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b,u64 cookie,u64 slba,u32 bytes,u32 desc){(void)cookie;(void)slba;(void)bytes;(void)desc;event(TRACE);EQ("trace-batch",b==&batch,1);EQ("live-before-trace",active_done->poll_live,stage.poll);EQ("callback-before-trace",request.end_io!=NULL,1);}
static void blk_execute_rq_nowait(struct request *r,bool at_head){event(EXEC);EQ("execute-at-head",at_head,0);EQ("execute-rq",r==&request,1);EQ("envelope-batch",active_done->b==&batch,1);EQ("envelope-ticket",active_done->ticket,0x55);EQ("envelope-end_io_data",r->end_io_data==active_done,1);EQ("live-before-execute",active_done->poll_live,stage.poll);if(early){native.status=completion_error;EQ("real-end_io-free",r->end_io(r,completion_error),RQ_END_IO_FREE);memset(r,0xa5,sizeof(*r));}}
#ifdef POLL_NEW
bool __real_xdev_ext_stor_block_poll_capable(const struct request_queue*);
int __real_xdev_ext_stor_block_poll_check(bool,struct request*);
void __real_xdev_ext_stor_block_poll_arm(bool,struct request*,struct xdev_ext_stor_completion*);
bool __wrap_xdev_ext_stor_block_poll_capable(const struct request_queue *q){event(CAPABLE);family_capable++;return __real_xdev_ext_stor_block_poll_capable(q);}
int __wrap_xdev_ext_stor_block_poll_check(bool poll,struct request *r){family_check++;return __real_xdev_ext_stor_block_poll_check(poll,r);}
void __wrap_xdev_ext_stor_block_poll_arm(bool poll,struct request *r,struct xdev_ext_stor_completion *d){family_arm++;__real_xdev_ext_stor_block_poll_arm(poll,r,d);}
#endif
#include "actual_old_poll.inc"
#include "nvme_xdev_ext_class_bind.inc"
#include "nvme_xdev_ext_class_complete.inc"
#include "nvme_xdev_ext_class_ready.inc"
#include "nvme_xdev_ext_class_end_io.inc"
#include "nvme_xdev_ext_peer_complete.inc"
#include "nvme_xdev_ext_peer_end_io.inc"
/* Actual independent native-plan arithmetic, not a poll decision. */
#define __KERNEL__ 1
#include <xdev_ext_peer_nvme_core.h>
#undef __KERNEL__
#include "nvme_xdev_ext_peer_submit.inc"
#include "nvme_xdev_ext_class_submit.inc"
static void binding(void){
 label="bind-native-capability-order";reset(false);queue.limits.features=0;EQ("poll-refused",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);EQ("namespace-before-poll",count(NS),1);EQ("no-authority-after-poll-refusal",count(ALLOW),0);EQ("no-identity-after-refusal",count(IDENTITY),0);
 reset(false);queue.limits.features=0;stage.poll=false;EQ("plain-bind",nvme_xdev_ext_class_bind(&stage,&uapi),0);before(NS,ALLOW);before(ALLOW,IDENTITY);before(IDENTITY,WINDOW);
#ifdef POLL_NEW
 EQ("plain-no-family-capability",family_capable,0);
#endif
 kfree(stage.priv);
 reset(false);namespace_present=false;EQ("lookup-error-first",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);
#ifdef POLL_NEW
 EQ("missing-namespace-no-capability",family_capable,0);
#endif
 reset(false);file.f_mode=0;stage.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;queue.limits.features=0;EQ("poll-before-write-permission",nvme_xdev_ext_class_bind(&stage,&uapi),-EOPNOTSUPP);
 reset(false);EQ("poll-bind",nvme_xdev_ext_class_bind(&stage,&uapi),0);
#ifdef POLL_NEW
 EQ("actual-bind-consumes-family",family_capable,1);before(NS,CAPABLE);before(CAPABLE,ALLOW);
#endif
 kfree(stage.priv);
}
static int submit(bool peer){return peer?nvme_xdev_ext_peer_submit(&stage,&batch):nvme_xdev_ext_class_submit(&stage,&batch);}
static void no_work(void){EQ("no-slot",count(SLOT),0);EQ("no-map",count(MAP),0);EQ("no-init",count(INIT),0);EQ("no-arm",count(ARM),0);EQ("no-trace",count(TRACE),0);EQ("no-execute",count(EXEC),0);}
static void submissions(void){for(unsigned peer=0;peer<2;peer++){
 label=peer?"PEER-real-submit":"host-real-submit";
 reset(peer);alloc_error=-EAGAIN;hctx.type=HCTX_TYPE_DEFAULT;EQ("allocation-error-wins",submit(peer),-EAGAIN);EQ("allocation-once",count(ALLOC),1);EQ("no-check-on-alloc-error",count(CHECK),0);EQ("no-free-on-alloc-error",count(FREE),0);no_work();
 reset(peer);request.mq_hctx=NULL;EQ("missing-hctx-rejected",submit(peer),-EOPNOTSUPP);EQ("free-once",count(FREE),1);no_work();
 reset(peer);hctx.type=HCTX_TYPE_DEFAULT;EQ("wrong-hctx-rejected",submit(peer),-EOPNOTSUPP);EQ("free-once",count(FREE),1);no_work();
 reset(peer);slot_error=-EBUSY;EQ("slot-error",submit(peer),-EBUSY);EQ("request-freed",count(FREE),1);EQ("no-map",count(MAP),0);before(ALLOC,CHECK);before(CHECK,SLOT);
 reset(peer);map_error=-EREMOTEIO;EQ("map-error",submit(peer),-EREMOTEIO);EQ("slot-put-once",count(PUT),1);EQ("request-free-once",count(FREE),1);EQ("no-execute",count(EXEC),0);
 for(unsigned poll=0;poll<2;poll++)for(unsigned err=0;err<2;err++){
  reset(peer);stage.poll=poll;early=true;completion_error=err?-EIO:0;EQ("actual-success-submit",submit(peer),0);EQ("actual-alloc-opf",allocation_opf,native_opf|(poll?REQ_POLLED:0));EQ("slot-acquired-once",count(SLOT),1);EQ("mapped-once",count(MAP),1);EQ("one-execute",count(EXEC),1);EQ("no-preaccept-free",count(FREE),0);EQ("accepted-slot-not-returned",count(PUT),0);EQ("early-claim",claim_calls,1);EQ("early-publish",publish_calls,1);EQ("early-live-cleared",active_done->poll_live,0);EQ("busy-owned-through-completion",peer?peer_slot.runtime.busy:host_slot.runtime.busy,1);EQ("UNKNOWN-preserved",active_done->uncertain,err!=0);if(poll){before(ALLOC,CHECK);before(CHECK,SLOT);before(ARM,TRACE);}else EQ("plain-queue-preserved",active_done->poll_queue,91);before(TRACE,EXEC);before(EXEC,CLAIM);if(peer)before(MAP,INIT);else before(INIT,SLOT);
#ifdef POLL_NEW
  EQ("real-check-family-consumer",family_check,1);EQ("real-arm-family-consumer",family_arm,1);
#endif
 }
 reset(peer);stage.poll=false;native_opf|=REQ_POLLED;EQ("plain-existing-POLLED-submit",submit(peer),0);EQ("plain-keeps-existing-POLLED",allocation_opf,native_opf);
 reset(peer);early=true;claim_error=-ESTALE;EQ("stale-early-submit",submit(peer),0);EQ("stale-claim-clears-live",active_done->poll_live,0);EQ("stale-no-publish",publish_calls,0);EQ("stale-keeps-slot",count(PUT),0);
}}
int main(void){binding();submissions();printf("storage_block_poll_consumers assertions=%u failures=%u\n",checks,failures);return failures?1:0;}

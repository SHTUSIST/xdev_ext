/* SPDX-License-Identifier: GPL-2.0 */
#include "native_boundary.h"
#ifdef POLL_NEW
#include <linux/xdev_ext_storfam_block.h>
#endif
static unsigned checks,failures;
static const char *label;
static void eq(const char *s,long long got,long long want){checks++;if(got!=want){failures++;fprintf(stderr,"FAIL %s %s got=%lld want=%lld\n",label,s,got,want);}}
#define EQ(s,g,w) eq(s,(long long)(g),(long long)(w))
static struct request_queue queue;
static struct blk_mq_tag_set tags;
static struct blk_mq_queue_map maps[3];
static struct nvme_ns ns;
static struct nvme_xdev_ext_mech_slot host[70];
static struct nvme_xdev_ext_peer_slot peer[70];
static struct nvme_xdev_ext_peer_res peer_res;
static struct nvme_xdev_ext_mech_stage member;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_mech_batch batch;
static unsigned called[256],nr_called;
static int answers[256],claim_error;
static unsigned claim_calls,complete_calls,publish_calls,helper_checks,write_calls,live_published;
static struct xdev_ext_stor_completion *observed_done,*callback_done;
static u32 published_queue;
static unsigned family_polls;
#ifdef STORAGE_MEMBER_FAMILY
static const struct xdev_ext_stor_dev_ops fixture_poll_ops;
/* This fixture bypasses CREATE; install borrowed views at resource injection,
 * never immediately before a production poll or between repeated polls. */
static void fixture_install_views(void){
 member.family.st=&stage;member.family.dev=&fixture_poll_ops;member.family.member=&member;
 member.family.poll_views[0]=(struct xdev_ext_stor_poll_view){.first=member.nr_slots?&host[0].done:NULL,.stride=sizeof(host[0]),.count=member.nr_slots};
 member.family.poll_views[1]=(struct xdev_ext_stor_poll_view){.first=member.peer&&member.peer->nr_slots?&peer[0].done:NULL,.stride=sizeof(peer[0]),.count=member.peer?member.peer->nr_slots:0};
}
#else
static void fixture_install_views(void){}
#endif
static void reset(void){memset(host,0,sizeof(host));memset(peer,0,sizeof(peer));memset(answers,0,sizeof(answers));memset(called,0,sizeof(called));memset(&member,0,sizeof(member));memset(maps,0,sizeof(maps));tags=(struct blk_mq_tag_set){.nr_maps=3,.map=maps};maps[2].nr_queues=1;queue=(struct request_queue){.limits={.features=BLK_FEAT_POLL},.tag_set=&tags};ns.queue=&queue;peer_res=(struct nvme_xdev_ext_peer_res){.slots=peer,.nr_slots=0};member=(struct nvme_xdev_ext_mech_stage){.ns=&ns,.slots=host,.nr_slots=0,.peer=&peer_res};stage=(struct xdev_ext_mech_stage){.priv=&member,.poll=true};batch=(struct xdev_ext_mech_batch){.id=17,.ticket=0x55};nr_called=claim_calls=complete_calls=publish_calls=helper_checks=write_calls=live_published=family_polls=0;claim_error=0;observed_done=callback_done=NULL;published_queue=7;fixture_install_views();}
void boundary_read(const void *p,size_t n){(void)p;(void)n;}
void boundary_before_write(const void *p,size_t n,const void *v){
 if(observed_done&&p==&observed_done->poll_live&&n==sizeof(bool)){write_calls++;if(*(const bool*)v){live_published++;EQ("queue-before-live-publication",observed_done->poll_queue,published_queue);EQ("batch-before-publication",observed_done->b==&batch,1);EQ("ticket-before-publication",observed_done->ticket,0x55);}}
}
// Actual pinned public block predicate is compiled, not a REQ_POLLED model.
#define blk_rq_is_poll production_blk_rq_is_poll
#include "actual_blk_predicate.inc"
#undef blk_rq_is_poll
bool blk_rq_is_poll(struct request *r){helper_checks++;return production_blk_rq_is_poll(r);}
int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 ticket){claim_calls++;EQ("claim-batch",b==&batch,1);EQ("captured-ticket",ticket,0x55);EQ("clear-before-claim",callback_done&& !callback_done->poll_live,1);return claim_error;}
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int status,bool uncertain){(void)b;(void)ticket;(void)status;(void)uncertain;publish_calls++;}
void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,u64 ticket,int status){(void)b;(void)ticket;(void)status;}
static int complete(struct xdev_ext_mech_batch *b,void *native,int status,bool *uncertain){(void)b;(void)native;complete_calls++;*uncertain=status!=0;return status;}
#include "actual_stor_done.inc"
int blk_mq_poll_hw_queue(struct request_queue *q,unsigned index,void *batch_ptr){EQ("native-queue-identity",q==&queue,1);EQ("native-poll-batch-NULL",batch_ptr==NULL,1);EQ("inactive-poison-not-polled",index!=0xdeadbeefU,1);if(nr_called>=256)abort();called[nr_called]=index;int ret=answers[nr_called++];if(callback_done){xdev_ext_stor_done(callback_done,-EIO,NULL,complete,NULL);}return ret;}
#ifdef POLL_NEW
int __real_xdev_ext_stor_block_poll(struct request_queue*,const struct xdev_ext_stor_poll_view*,u32);
int __wrap_xdev_ext_stor_block_poll(struct request_queue *q,const struct xdev_ext_stor_poll_view *v,u32 nr){family_polls++;EQ("two-borrowed-views",nr,2);if(nr==2){EQ("host-view-count",v[0].count,member.nr_slots);EQ("peer-view-count",v[1].count,member.peer?member.peer->nr_slots:0);EQ("host-stride",v[0].stride,sizeof(host[0]));EQ("peer-stride",v[1].stride,sizeof(peer[0]));EQ("host-first",v[0].first== (member.nr_slots?&host[0].done:NULL),1);EQ("peer-first",v[1].first== (member.peer&&member.peer->nr_slots?&peer[0].done:NULL),1);}return __real_xdev_ext_stor_block_poll(q,v,nr);}
#endif
#include "actual_old_poll.inc"
#include "actual_class_poll.inc"
static bool capable(void){
#ifdef POLL_NEW
 return xdev_ext_stor_block_poll_capable(&queue);
#else
 return nvme_xdev_ext_poll_capable(&queue);
#endif
}
static blk_opf_t opf(bool poll,blk_opf_t value){stage.poll=poll;
#ifdef POLL_NEW
 return xdev_ext_stor_block_poll_opf(poll,value);
#else
 return nvme_xdev_ext_poll_opf(&stage,value);
#endif
}
static int check(bool poll,struct request *r){stage.poll=poll;
#ifdef POLL_NEW
 return xdev_ext_stor_block_poll_check(poll,r);
#else
 return nvme_xdev_ext_poll_check(&stage,r);
#endif
}
static void arm(bool poll,struct request *r,struct xdev_ext_stor_completion *d){stage.poll=poll;
#ifdef POLL_NEW
 xdev_ext_stor_block_poll_arm(poll,r,d);
#else
 nvme_xdev_ext_poll_arm(&stage,r,d);
#endif
}
static void decisions(void){
 label="capability-short-circuit";reset();queue.limits.features=0;queue.tag_set=(void*)(uintptr_t)1;EQ("no-feature",capable(),0);queue.limits.features=BLK_FEAT_POLL;queue.tag_set=NULL;EQ("no-tag-set",capable(),0);queue.tag_set=&tags;tags.nr_maps=HCTX_TYPE_POLL;tags.map=(void*)(uintptr_t)1;EQ("nr_maps-before-map-access",capable(),0);tags.map=maps;tags.nr_maps=3;maps[2].nr_queues=0;EQ("no-poll-queues",capable(),0);maps[2].nr_queues=1;EQ("capable",capable(),1);
 label="opf-bits";reset();const blk_opf_t values[]={0,3,REQ_POLLED,UINT32_C(0x80000003),UINT32_C(0x80000003)|REQ_POLLED};for(unsigned i=0;i<ARRAY_SIZE(values);i++){EQ("false-preserves-bits",opf(false,values[i]),values[i]);EQ("true-adds-only-polled",opf(true,values[i]),values[i]|REQ_POLLED);}
 label="actual-hctx-check";reset();EQ("false-NULL",check(false,NULL),0);EQ("false-no-predicate-access",helper_checks,0);struct request r={.cmd_flags=REQ_POLLED};EQ("hctx-NULL",check(true,&r),-EOPNOTSUPP);struct blk_mq_hw_ctx h={.type=HCTX_TYPE_DEFAULT,.queue_num=7};r.mq_hctx=&h;EQ("hctx-default-despite-flag",check(true,&r),-EOPNOTSUPP);h.type=HCTX_TYPE_POLL;EQ("hctx-poll",check(true,&r),0);EQ("predicate-three-calls",helper_checks,3);
 label="arm-false-preserves-envelope";reset();struct xdev_ext_stor_completion d={.b=&batch,.ticket=0x55,.uncertain=true,.poll_live=true,.poll_queue=91};observed_done=&d;arm(false,NULL,&d);EQ("live-cleared",d.poll_live,0);EQ("queue-preserved",d.poll_queue,91);EQ("batch-preserved",d.b==&batch,1);EQ("ticket-preserved",d.ticket,0x55);EQ("uncertain-preserved",d.uncertain,1);EQ("one-live-write",write_calls,1);
 label="arm-true-publication";write_calls=0;h.type=HCTX_TYPE_POLL;h.queue_num=7;r.mq_hctx=&h;arm(true,&r,&d);EQ("queue7",d.poll_queue,7);EQ("live",d.poll_live,1);EQ("live-published-once",live_published,1);EQ("write-once",write_calls,1);EQ("uncertain-unchanged",d.uncertain,1);
}
static void populate(void){member.nr_slots=3;peer_res.nr_slots=2;const unsigned h[]={7,7,8},p[]={8,9};for(unsigned i=0;i<3;i++)host[i].done=(struct xdev_ext_stor_completion){.b=&batch,.ticket=0x55,.poll_live=true,.poll_queue=h[i]};for(unsigned i=0;i<2;i++)peer[i].done=(struct xdev_ext_stor_completion){.b=&batch,.ticket=0x55,.poll_live=true,.poll_queue=p[i]};fixture_install_views();}
static void views(void){
 label="merged-two-layouts";reset();populate();answers[0]=2;answers[1]=-5;answers[2]=3;EQ("result5",nvme_xdev_ext_class_poll(&stage),5);EQ("three-native-polls",nr_called,3);EQ("queue-order0",called[0],7);EQ("queue-order1",called[1],8);EQ("queue-order2",called[2],9);
#ifdef POLL_NEW
 EQ("one-family-call",family_polls,1);
#endif
 nr_called=0;EQ("fresh-per-call-seen",nvme_xdev_ext_class_poll(&stage),5);EQ("same-three-polls",nr_called,3);
 label="first-zero-still-deduplicates";nr_called=0;answers[0]=0;answers[1]=-5;answers[2]=3;EQ("result3",nvme_xdev_ext_class_poll(&stage),3);EQ("record-before-native-result",nr_called,3);
 label="inactive-poison-and-empty";reset();member.nr_slots=1;host[0].done.poll_queue=0xdeadbeefU;member.peer=NULL;fixture_install_views();EQ("no-live-result",nvme_xdev_ext_class_poll(&stage),0);EQ("no-native-poll",nr_called,0);member.slots=NULL;member.nr_slots=0;fixture_install_views();EQ("empty-NULL-arrays",nvme_xdev_ext_class_poll(&stage),0);
 label="seen64-tail-continues";reset();member.nr_slots=64;peer_res.nr_slots=5;for(unsigned i=0;i<64;i++)host[i].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=i};const unsigned tail[]={0,64,64,1,65};for(unsigned i=0;i<5;i++)peer[i].done=(struct xdev_ext_stor_completion){.poll_live=true,.poll_queue=tail[i]};for(unsigned i=0;i<256;i++)answers[i]=1;fixture_install_views();EQ("literal-result67",nvme_xdev_ext_class_poll(&stage),67);EQ("literal-call-count67",nr_called,67);for(unsigned i=0;i<64;i++)EQ("first64-order",called[i],i);EQ("tail64-first",called[64],64);EQ("tail64-repeat",called[65],64);EQ("tail65",called[66],65);
}
static void callbacks(void){
 const int errors[]={0,-EALREADY,-ESTALE};for(unsigned i=0;i<3;i++){label="actual-stor-done-sync-poll";reset();member.nr_slots=1;host[0].done=(struct xdev_ext_stor_completion){.b=&batch,.ticket=0x55,.poll_live=true,.poll_queue=7};callback_done=&host[0].done;claim_error=errors[i];answers[0]=1;fixture_install_views();EQ("first-poll",nvme_xdev_ext_class_poll(&stage),1);EQ("live-cleared-even-rejected-claim",callback_done->poll_live,0);EQ("claim-once",claim_calls,1);EQ("complete-only-valid-claim",complete_calls,errors[i]?0:1);EQ("publish-only-valid-claim",publish_calls,errors[i]?0:1);unsigned before=nr_called;EQ("next-poll-skip",nvme_xdev_ext_class_poll(&stage),0);EQ("no-extra-native-poll",nr_called,before);}
#ifdef POLL_NEW
 label="direct-zero-view-runtime";reset();EQ("zero-views",__real_xdev_ext_stor_block_poll(&queue,NULL,0),0);struct xdev_ext_stor_poll_view v={.first=NULL,.stride=64,.count=0};EQ("empty-view",__real_xdev_ext_stor_block_poll(&queue,&v,1),0);EQ("no-poll",nr_called,0);
#endif
}
int main(void){decisions();views();callbacks();printf("storage_block_poll assertions=%u failures=%u\n",checks,failures);return failures?1:0;}

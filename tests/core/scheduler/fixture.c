/* SPDX-License-Identifier: GPL-2.0 */
#include "shim.h"
#define XDEV_EXT_MECH_CLASS_F_ORDERED (1U << 0)
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM (1U << 2)
#define min(a,b) ((a)<(b)?(a):(b))
#define hweight32(x) __builtin_popcount(x)
#define smp_store_release(p,v) __atomic_store_n(p,v,__ATOMIC_RELEASE)
#define list_empty(h) ((h)->next==(h))
#define list_for_each_entry_safe(p,n,h,m) \
 for((p)=list_entry((h)->next,typeof(*(p)),m), (n)=list_entry((p)->m.next,typeof(*(p)),m); \
 &(p)->m!=(h); (p)=(n),(n)=list_entry((n)->m.next,typeof(*(n)),m))
#define llist_entry(p,t,m) container_of(p,t,m)
#define llist_for_each_safe(p,n,h) for((p)=(h); (p)&&((n)=(p)->next,1); (p)=(n))
static void list_splice_init(struct list_head *a,struct list_head *b) {
 if(list_empty(a))return;
 b->next=a->next;b->prev=a->prev;b->next->prev=b;b->prev->next=b;INIT_LIST_HEAD(a);
}
static struct llist_node *llist_del_all(struct llist_head *h) {struct llist_node *n=h->first;h->first=NULL;return n;}
static struct llist_node *llist_reverse_order(struct llist_node *h) {
 struct llist_node *r=NULL;while(h){struct llist_node*n=h->next;h->next=r;r=h;h=n;}return r;
}
static void kthread_mod_delayed_work(struct kthread_worker*w,struct kthread_delayed_work*d,int delay){(void)w;(void)d;(void)delay;}
/* Stage polling is off in every scheduler case; only CREATE can turn it on. */
static void kthread_queue_delayed_work(struct kthread_worker*w,struct kthread_delayed_work*d,int delay){(void)w;(void)d;(void)delay;abort();}
struct xdev_ext_mech_session;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops;
struct xdev_ext_mech_pool;
/* STRUCTURES */
enum xdev_ext_mech_end {XDEV_EXT_MECH_END_DONE,XDEV_EXT_MECH_END_ABORT,XDEV_EXT_MECH_END_SEQUESTER};
/* PROTOTYPES */
static unsigned ends, aborted, released, quarantined, attempts[4], accepts[4];
static unsigned recycle_calls, callback_calls[4], producer_publications;
static unsigned assertions, delayed_drains, first_refs, first_busy;
static struct xdev_ext_mech_batch *accepted[4];
static u64 tickets[4];
static unsigned priv[5][32],cookies[5][32];
static int refusal[4];
static bool inline_done[4];
static int failures;
#define CHECK(c,m) do {assertions++;if(!(c)){fprintf(stderr,"FAIL: %s\n",m);failures++;}}while(0)
#define REQUIRE(c,m) do {assertions++;if(!(c)){fprintf(stderr,"FAIL: %s\n",m);failures++;return 1;}}while(0)
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session*s){return xdev_ext_mech_sess_admits(&s->ss);}
static int xdev_ext_mech_stop_reason(struct xdev_ext_mech_session*s){return s->stop_err?:-ESHUTDOWN;}
static void xdev_ext_mech_count(struct xdev_ext_mech_session*s,u32 n,u64 k){s->cnt[n]+=k;}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool*p,u32 i,u32 from,u32 to){
 return xdev_ext_mech_frame_move(&p->state[i],from,to);
}
static void xdev_ext_mech_end(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b,int how,int err){
 (void)err;ends++;
 if(how==XDEV_EXT_MECH_END_SEQUESTER){quarantined++;return;}
 CHECK(!xdev_ext_mech_life_busy(&s->life[0]),"core retired provider custody while consumer still in flight");
 if(how==XDEV_EXT_MECH_END_ABORT)aborted++;
 /* Session teardown stays a fixture boundary. Frame retirement and provider
  * custody transfer are the production implementation, not a direct put. */
 if (!xdev_ext_mech_frames_release(s,b))released++;
 else CHECK(false,"production frame release failed");
}
static void xdev_ext_mech_abort(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b,int err){
 xdev_ext_mech_batch_step(&b->bs,XDEV_EXT_MECH_EV_ABORT,0);xdev_ext_mech_end(s,b,XDEV_EXT_MECH_END_ABORT,err);
}
static bool xdev_ext_mech_order_blocked(struct xdev_ext_mech_session*s,const struct xdev_ext_mech_batch*b){return false;}
static void xdev_ext_mech_order_park(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b){abort();}
static void xdev_ext_mech_order_kick(struct xdev_ext_mech_session*s){}
static void xdev_ext_mech_transform_undo(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b){}
static int xdev_ext_mech_transform_landed(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b,bool seq){CHECK(!b->transform.active,"unexpected transform");return 0;}
static struct xdev_ext_binding_ctx_v2 xdev_ext_mech_base(struct xdev_ext_mech_stage*st,u32 bytes){return (struct xdev_ext_binding_ctx_v2){0};}
static void xdev_ext_mech_fill_info(struct xdev_ext_mech_session*s,struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){}
static void xdev_ext_mech_worker_args(struct xdev_ext_mech_session*s,struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b,u32 member,const struct xdev_ext_binding_ctx_v2*base,struct xdev_ext_mech_call_args*a){memset(a,0,sizeof(*a));a->b=b;}
static int xdev_ext_mech_call(struct xdev_ext_mech_stage*st,const struct xdev_ext_mech_call_args*a,s32*ret,void*unused){*ret=XDEV_EXT_MECH_NEXT;return 0;}
static int xdev_ext_mech_build(struct xdev_ext_mech_session*s,struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){
 ((unsigned*)xdev_ext_mech_batch_priv(b))[0]=0xabc000+st->index;return 0;
}
/* PRODUCTION */
static void delivered(struct xdev_ext_mech_batch *b,u64 ticket,int err) {
 u32 stage=b->bs.stage, before=xdev_ext_mech_life_phase(&b->s->life[0]);
 callback_calls[stage]++;
 xdev_ext_mech_batch_complete(b,ticket,err);
 if(stage==0 && before==XDEV_EXT_MECH_L_IO_PENDING &&
    xdev_ext_mech_life_phase(&b->s->life[0])==XDEV_EXT_MECH_L_READY)
  producer_publications++;
}
static int native_submit(struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){
 unsigned k=st->index;attempts[k]++;
 if(refusal[k]&&!inline_done[k])return refusal[k];
 accepts[k]++;accepted[k]=b;tickets[k]=xdev_ext_mech_batch_ticket(b);
 ((unsigned*)xdev_ext_mech_batch_cookie(b))[0]=0xdef000+k;
 if(inline_done[k])delivered(b,tickets[k],0);
 return refusal[k];
}
static const struct xdev_ext_mech_class_ops cls={.submit=native_submit};
static void recycle(struct xdev_ext_mech_pool*p,struct xdev_ext_mech_frame*f){
 CHECK(p->state[f->index]==XDEV_EXT_MECH_F_K_FREE,"provider recycle sees K_FREE custody");
 recycle_calls++;
}
static const struct xdev_ext_mech_pool_ops pool_ops={.recycle=recycle};
static void callback(unsigned k,int err){delivered(accepted[k],tickets[k],err);}
static int report(struct xdev_ext_mech_session*s,const char*mode){
 printf("# {\"case\":\"%s\",\"assertions\":%u,\"failures\":%d,"
  "\"submitted\":[%lu,%lu,%lu,%lu],\"completed\":[%lu,%lu,%lu,%lu],"
  "\"callback_invocations\":[%u,%u,%u,%u],\"producer_ready_publications\":%u,"
  "\"first_completion_refs\":%u,\"first_completion_busy\":%u,\"delayed_drains\":%u,"
  "\"terminal_groups\":%u,\"aborted_groups\":%u,\"released_groups\":%u,"
  "\"recycle_calls\":%u,\"quarantined_groups\":%u,\"final_refs\":%u,"
  "\"final_busy\":%u,\"final_phase\":%u,\"generation\":%llu,"
  "\"final_custody\":%u,\"warnings\":%u}\n",
  mode,assertions,failures,s->submitted[0],s->submitted[1],s->submitted[2],s->submitted[3],
  s->completed[0],s->completed[1],s->completed[2],s->completed[3],
  callback_calls[0],callback_calls[1],callback_calls[2],callback_calls[3],producer_publications,
  first_refs,first_busy,delayed_drains,ends,aborted,released,recycle_calls,quarantined,
  xdev_ext_mech_life_refs(s->life),xdev_ext_mech_life_busy(s->life),
  xdev_ext_mech_life_phase(s->life),(unsigned long long)xdev_ext_mech_life_gen(s->life),
  s->pool.state[0],warnings);
 return failures!=0;
}
static int exercise(const char*mode){
 struct xdev_ext_mech_session session={0},*s=&session;
 struct xdev_ext_mech_batch root={0},child[4]={0};
 struct xdev_ext_mech_life life;u8 custody=XDEV_EXT_MECH_F_HELD,owner=0;
 xdev_ext_mech_life_init(&life);s->life=&life;s->batches=&root;s->depth=1;s->nr_stages=3;
 bool failing=!strcmp(mode,"fail") || !strcmp(mode,"fail-reverse");
 bool late_error=!strcmp(mode,"late-error") || !strcmp(mode,"late-error-reverse");
 if(failing || late_error || !strcmp(mode,"dependent"))s->nr_stages=4;
 s->transform_owner=&owner;
 s->priv_size=sizeof(priv[0]);s->layout.group_bytes=128;
 s->pool=(struct xdev_ext_mech_pool){.ops=&pool_ops,.state=&custody,.nr_frames=1};
 INIT_LIST_HEAD(&s->retry);INIT_LIST_HEAD(&s->ordered);xdev_ext_mech_sess_init(&s->ss);
 for(u32 i=0;i<s->nr_stages;i++){
  u32 c=i==2 && strcmp(mode,"same-class")?XDEV_EXT_MECH_CLASS_AFXDP:XDEV_EXT_MECH_CLASS_NVME;
  u32 d=i?XDEV_EXT_MECH_DIR_TO_DEVICE:XDEV_EXT_MECH_DIR_FROM_DEVICE;
  s->st[i]=(struct xdev_ext_mech_stage){.s=s,.index=i,.cls=&cls,.class_id=c,.direction=d};
  s->plan[i]=(struct xdev_ext_mech_stage_uapi){.class_id=c,.direction=d,.flags=i==2?XDEV_EXT_MECH_STAGE_F_FANOUT:0};
 }
 root.s=s;root.nr_frames=1;root.present=1;root.bytes=128;root.priv=priv[0];root.cookie=cookies[0];root.id=1;
 root.f[0]=(struct xdev_ext_mech_frame){.index=0,.data_len=128};INIT_LIST_HEAD(&root.node);
 xdev_ext_mech_bstate_init(&root.bs,s->nr_stages);xdev_ext_mech_batch_step(&root.bs,XDEV_EXT_MECH_EV_READY,0);
 /* FAN_ALLOC */
 if(!strcmp(mode,"inline")){inline_done[1]=inline_done[2]=true;refusal[1]=-EAGAIN;}
 if(!strcmp(mode,"eagain"))refusal[2]=-EAGAIN;
 xdev_ext_mech_batch_run(s,&root);
 REQUIRE(accepts[0]==1,"NVMe producer submitted exactly once");
 callback(0,0);
 REQUIRE(xdev_ext_mech_life_phase(&life)==XDEV_EXT_MECH_L_READY,"producer callback publishes before worker");
 REQUIRE(xdev_ext_mech_life_refs(&life)==s->nr_stages-1,"publication installs all consumer references");
 CHECK(life.valid_len==128,"producer publishes the entire valid byte span");
 CHECK(custody==XDEV_EXT_MECH_F_INFLIGHT,"producer callback retains provider custody until worker");
 if(!strcmp(mode,"duplicate")){
  u64 word=life.ctrl;callback(0,0);
  CHECK(life.ctrl==word && producer_publications==1,"duplicate producer cannot publish READY twice");
 }
 xdev_ext_mech_batch_drain(&s->drain_work);
 if(!strcmp(mode,"inline")){
  CHECK(accepts[1]==1&&accepts[2]==1,"both inline consumers accepted despite callback-then-EAGAIN");
  CHECK(ends==1&&released==1&&recycle_calls==1,"inline consumers cross group barrier and recycle once");
  CHECK(!warnings,"inline production warning count is zero");return report(s,mode);
 }
 REQUIRE(accepts[1]==1&&attempts[2]==1,"both fanout consumers submitted before either completes");
 if(!strcmp(mode,"eagain")){
  REQUIRE(accepts[2]==0,"EAGAIN branch never accepted");callback(1,0);xdev_ext_mech_batch_drain(&s->drain_work);
  CHECK(!ends,"unaccepted branch retains group custody");
  CHECK(xdev_ext_mech_life_phase(&life)==XDEV_EXT_MECH_L_READY,"after accepted peer completes EAGAIN branch is READY");
  CHECK(xdev_ext_mech_life_refs(&life)==1,"EAGAIN did not consume its reference");
  refusal[2]=0;xdev_ext_mech_retry_work(&s->retry_work.work);
  CHECK(accepts[1]==1&&accepts[2]==1,"retry submits only refused branch");callback(2,0);xdev_ext_mech_batch_drain(&s->drain_work);
 }else{
  REQUIRE(accepts[2]==1,"second consumer accepted");
  CHECK(accepted[1]!=accepted[2],"concurrent branches have independent batch identities");
  CHECK(&accepted[1]->completion!=&accepted[2]->completion,"completion tickets live in independent words");
  CHECK(accepted[1]->priv!=accepted[2]->priv&&accepted[1]->cookie!=accepted[2]->cookie,"private metadata and callback cookies are independent");
  CHECK(((unsigned*)accepted[1]->priv)[0]==0xabc001&&((unsigned*)accepted[2]->priv)[0]==0xabc002,"second descriptor cannot overwrite first private state");
  CHECK(xdev_ext_mech_life_busy(&life)==(BIT(1)|BIT(2)),"both consumer claims are live concurrently");
  if(!strcmp(mode,"stop"))xdev_ext_mech_sess_stop(&s->ss);
  if(!strcmp(mode,"quarantine")){
   callback_calls[2]++;
   xdev_ext_mech_batch_sequester(accepted[2],tickets[2],-EIO);xdev_ext_mech_batch_drain(&s->drain_work);
   CHECK(!ends&&!released,"ambiguous branch cannot reclaim while peer still pending");
   callback(1,0);xdev_ext_mech_batch_drain(&s->drain_work);
   CHECK(quarantined==1&&!released,"group ambiguity permanently retains provider custody");
   CHECK(xdev_ext_mech_life_phase(&life)!=XDEV_EXT_MECH_L_FREE,"ambiguous native owner remains pinned");
   CHECK(custody==XDEV_EXT_MECH_F_SEQUESTERED&&!recycle_calls,"quarantine never returns provider custody");
   CHECK(!warnings,"quarantine production warning count is zero");return report(s,mode);
  }
  unsigned first=(!strcmp(mode,"reverse") || !strcmp(mode,"delay-reverse") ||
                  !strcmp(mode,"fail-reverse") || !strcmp(mode,"late-error-reverse"))?2:1, last=first==1?2:1;
  u64 generation=xdev_ext_mech_life_gen(&life);
  callback(first,failing?-EIO:0);
  first_refs=xdev_ext_mech_life_refs(&life);first_busy=xdev_ext_mech_life_busy(&life);
  CHECK(first_refs==(failing?1:s->nr_stages-2),"first callback drops only its reference (and cancels unissued dependents on error)");
  CHECK(first_busy==BIT(last),"first callback retains precisely the other consumer claim");
  CHECK(xdev_ext_mech_life_gen(&life)==generation,"first completion cannot increment generation");
  CHECK(xdev_ext_mech_life_phase(&life)==XDEV_EXT_MECH_L_OUT_PENDING,"first completion retains pending peer");
  xdev_ext_mech_batch_drain(&s->drain_work);CHECK(!ends&&!released,"worker cannot retire group before last completion");
  CHECK(custody==XDEV_EXT_MECH_F_INFLIGHT&&!recycle_calls,"pending peer retains provider custody");
  if(!strcmp(mode,"delay") || !strcmp(mode,"delay-reverse") || failing || late_error){
   u64 word=life.ctrl,claim;
   for(unsigned i=0;i<(late_error?1U:64U);i++){
    xdev_ext_mech_batch_drain(&s->drain_work);delayed_drains++;
    CHECK(life.ctrl==word && custody==XDEV_EXT_MECH_F_INFLIGHT && !recycle_calls,
          "idle worker passes cannot recycle a delayed consumer's frame");
   }
   CHECK(xdev_ext_mech_life_claim(&life,0,&claim)==-EBUSY,"next producer cannot claim an outstanding shared frame");
   CHECK(xdev_ext_mech_pool_frame_move(&s->pool,0,XDEV_EXT_MECH_F_K_FREE,XDEV_EXT_MECH_F_HELD)==-EBUSY,
         "allocator cannot loan a frame still owned by delayed consumer");
  }
  if(!strcmp(mode,"duplicate")){u64 word=life.ctrl;callback(first,0);xdev_ext_mech_batch_drain(&s->drain_work);CHECK(life.ctrl==word&&!ends,"duplicate callback cannot decrement twice");}
  if(late_error)
   CHECK(!s->last_err && !accepts[3] && first_refs==2,
         "successful peer leaves the delayed consumer and dependent references intact");
  callback(last,late_error?-EIO:0);
  if(!strcmp(mode,"dependent")){
   CHECK(xdev_ext_mech_life_phase(&life)==XDEV_EXT_MECH_L_READY && xdev_ext_mech_life_refs(&life)==1,"group final completion preserves dependent reference");
   CHECK(xdev_ext_mech_life_gen(&life)==generation && !accepts[3],"dependent starts only after worker barrier");
   xdev_ext_mech_batch_drain(&s->drain_work);
   REQUIRE(accepts[3]==1 && !ends,"group barrier dispatches dependent once without retiring");
   callback(3,0);
  }
  CHECK(xdev_ext_mech_life_phase(&life)==XDEV_EXT_MECH_L_FREE,"last completion frees frame in callback");
  CHECK(xdev_ext_mech_life_gen(&life)==generation+1,"last completion increments generation exactly once");
  CHECK(!xdev_ext_mech_life_refs(&life)&&!xdev_ext_mech_life_busy(&life),"last callback clears references and claims");
  CHECK(custody==XDEV_EXT_MECH_F_INFLIGHT&&!recycle_calls,"last callback waits for worker before provider recycle");
  xdev_ext_mech_batch_drain(&s->drain_work);
  if(failing || late_error)CHECK(!accepts[3]&&aborted==1&&s->last_err==-EIO,"failure suppresses later dependent stage and retains native error");
 }
 CHECK(ends==1&&released==1,"group releases provider custody exactly once");
 CHECK(recycle_calls==1&&custody==XDEV_EXT_MECH_F_K_FREE,"production release returns shared frame exactly once");
 CHECK(s->completed[0]==1&&s->completed[1]==1&&s->completed[2]==1,"worker consumes each native completion exactly once");
 CHECK(producer_publications==1,"one producer READY publication per batch");
 if(!strcmp(mode,"late")){u64 word=life.ctrl;callback(1,0);callback(2,-EIO);xdev_ext_mech_batch_drain(&s->drain_work);CHECK(life.ctrl==word&&ends==1,"late callbacks after barrier cannot recycle again");}
 if(!strcmp(mode,"reuse")){
  u64 old_tickets[3]={tickets[0],tickets[1],tickets[2]},word;
  REQUIRE(!xdev_ext_mech_pool_frame_move(&s->pool,0,XDEV_EXT_MECH_F_K_FREE,XDEV_EXT_MECH_F_HELD),"allocator reuses returned frame");
  xdev_ext_mech_bstate_init(&root.bs,s->nr_stages);
  xdev_ext_mech_batch_step(&root.bs,XDEV_EXT_MECH_EV_READY,0);root.id++;
  xdev_ext_mech_batch_run(s,&root);
  REQUIRE(accepts[0]==2 && tickets[0]!=old_tickets[0],"reused producer has a new completion ticket");
  word=life.ctrl;delivered(&root,old_tickets[0],0);
  CHECK(life.ctrl==word && producer_publications==1,"old producer ticket cannot publish the reused frame");
  callback(0,0);xdev_ext_mech_batch_drain(&s->drain_work);
  REQUIRE(accepts[1]==2 && accepts[2]==2,"reused frame reaches both consumers");
  REQUIRE(tickets[1]!=old_tickets[1] && tickets[2]!=old_tickets[2],"each reused child has a new ticket");
  word=life.ctrl;
  delivered(accepted[1],old_tickets[1],0);delivered(accepted[2],old_tickets[2],-EIO);
  xdev_ext_mech_batch_drain(&s->drain_work);
  CHECK(life.ctrl==word && ends==1 && recycle_calls==1 && !s->last_err,
        "old consumer tickets cannot drop current references, recycle, or poison status");
  callback(2,0);xdev_ext_mech_batch_drain(&s->drain_work);
  CHECK(xdev_ext_mech_life_refs(&life)==1 && custody==XDEV_EXT_MECH_F_INFLIGHT && ends==1,
        "reused frame also waits for last consumer");
  callback(1,0);xdev_ext_mech_batch_drain(&s->drain_work);
  CHECK(s->completed[0]==2&&s->completed[1]==2&&s->completed[2]==2,"only current tickets contribute completion counts");
  CHECK(ends==2&&released==2&&recycle_calls==2&&producer_publications==2,"each reused batch publishes and retires exactly once");
  CHECK(xdev_ext_mech_life_gen(&life)==2 && !xdev_ext_mech_life_refs(&life) &&
        custody==XDEV_EXT_MECH_F_K_FREE,"two batch generations retired without stale-ticket interference");
 }
 CHECK(!warnings,"production warning count is zero");return report(s,mode);
}
int main(int argc,char**argv){return argc==2?exercise(argv[1]):2;}

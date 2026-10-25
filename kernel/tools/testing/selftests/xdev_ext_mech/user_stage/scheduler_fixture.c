/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Host fixture of the USER stage: scheduler_test.py pastes the real session
 * core (io_uring/xdev_ext_mech.c: acquire, submit, native completion handoff,
 * landing, drain, stage kick, CPU-length record) and the real USER class
 * (io_uring/xdev_ext_mech_user.c: build default, validate, submit, reap,
 * progress, dead marking) into this file.  Only work queues, device
 * submission and the program call are host stand-ins.  A user thread is
 * played by the test through the class's own shared-region structures.
 *
 * Chain: stage 0 a native producer (NVMe READ class id), stage 1 USER, stage 2
 * a native consumer (DMA class id, so a length change may reach it).
 */
#include "fanout_scheduler/shim.h"
#include "io_uring/xdev_ext_mech_user_core.h"

typedef __s64 s64;
#define XDEV_EXT_MECH_CLASS_F_ORDERED (1U << 0)
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM (1U << 2)
#define min(a,b) ((a)<(b)?(a):(b))
#define hweight32(x) __builtin_popcount(x)
#define smp_store_release(p,v) __atomic_store_n(p,v,__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n(p,__ATOMIC_ACQUIRE)
#define smp_mb() __sync_synchronize()
#define time_after_eq(a,b) ((long)((a)-(b)) >= 0)
#define list_empty(h) ((h)->next==(h))
#define list_for_each_entry_safe(p,n,h,m) \
 for((p)=list_entry((h)->next,typeof(*(p)),m), (n)=list_entry((p)->m.next,typeof(*(p)),m); \
 &(p)->m!=(h); (p)=(n),(n)=list_entry((n)->m.next,typeof(*(n)),m))
#define llist_entry(p,t,m) container_of(p,t,m)
#define llist_for_each_safe(p,n,h) for((p)=(h); (p)&&((n)=(p)->next,1); (p)=(n))
static unsigned long jiffies = 1000;
static void list_splice_init(struct list_head *a,struct list_head *b) {
 if(list_empty(a))return;
 b->next=a->next;b->prev=a->prev;b->next->prev=b;b->prev->next=b;INIT_LIST_HEAD(a);
}
static struct llist_node *llist_del_all(struct llist_head *h) {struct llist_node *n=h->first;h->first=NULL;return n;}
static struct llist_node *llist_reverse_order(struct llist_node *h) {
 struct llist_node *r=NULL;while(h){struct llist_node*n=h->next;h->next=r;r=h;h=n;}return r;
}
/* A model of the session's progress_work: pending or not, and its delay. */
static void *progress_work_of_session;
static unsigned progress_kicks, retry_arms;
static bool pw_pending;
static long pw_delay=-1;
static bool kthread_mod_delayed_work(struct kthread_worker*w,struct kthread_delayed_work*d,unsigned long delay){
 (void)w;
 if((void*)d!=progress_work_of_session){retry_arms++;return true;}
 if(!delay)progress_kicks++;
 pw_pending=true;pw_delay=(long)delay;return true;
}
/* Stage polling is off in every case; only progress_work may be queued. */
static bool kthread_queue_delayed_work(struct kthread_worker*w,struct kthread_delayed_work*d,unsigned long delay){
 (void)w;
 if((void*)d!=progress_work_of_session)abort();
 if(pw_pending)return false;
 pw_pending=true;pw_delay=(long)delay;return true;
}
struct xdev_ext_mech_session;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops;
struct xdev_ext_mech_pool;
struct xdev_ext_user_obj;
/* STRUCTURES */
enum xdev_ext_mech_end {XDEV_EXT_MECH_END_DONE,XDEV_EXT_MECH_END_ABORT,XDEV_EXT_MECH_END_SEQUESTER};
/* PROTOTYPES */
static int failures;
#define CHECK(c,m) do {if(!(c)){fprintf(stderr,"FAIL: %s (line %d)\n",m,__LINE__);failures++;}}while(0)
#define REQUIRE(c,m) do {if(!(c)){fprintf(stderr,"FAIL: %s (line %d)\n",m,__LINE__);return 1;}}while(0)
static unsigned ends, attempts[3], accepts[3];
static int end_how=-1, end_err=1;
static struct xdev_ext_mech_batch *accepted[3];
static u64 tickets[3];
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session*s){return xdev_ext_mech_sess_admits(&s->ss);}
static int xdev_ext_mech_stop_reason(struct xdev_ext_mech_session*s){return s->stop_err?:-ESHUTDOWN;}
static void xdev_ext_mech_count(struct xdev_ext_mech_session*s,u32 n,u64 k){s->cnt[n]+=k;}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool*p,u32 i,u32 from,u32 to){
 return xdev_ext_mech_frame_move(&p->state[i],from,to);
}
static u32 xdev_ext_mech_pool_frame_state_raw(struct xdev_ext_mech_pool*p,u32 i){return p->state[i];}
/* Stand-in for frame release at the end of a batch: frames must be HELD with
 * a FREE or READY lifecycle, exactly what xdev_ext_mech_frames_release()
 * requires before it returns custody. */
static void xdev_ext_mech_end(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b,int how,int err){
 ends++;end_how=how;end_err=err;
 for(u32 i=0;i<b->nr_frames;i++){
  struct xdev_ext_mech_life*l=&s->life[b->f[i].index];
  u32 ph=xdev_ext_mech_life_phase(l);
  CHECK(xdev_ext_mech_pool_frame_state_raw(&s->pool,b->f[i].index)==XDEV_EXT_MECH_F_HELD,"frames are HELD at the end");
  CHECK(ph==XDEV_EXT_MECH_L_FREE||ph==XDEV_EXT_MECH_L_READY,"lifecycle FREE or READY at the end");
  if(ph==XDEV_EXT_MECH_L_READY)CHECK(!xdev_ext_mech_life_release(l,xdev_ext_mech_life_gen(l)),"terminal READY releases");
  xdev_ext_mech_pool_frame_move(&s->pool,b->f[i].index,XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_K_FREE);
 }
 xdev_ext_mech_sess_batch_end(&s->ss,false);
}
static void xdev_ext_mech_abort(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b,int err){
 xdev_ext_mech_batch_step(&b->bs,XDEV_EXT_MECH_EV_ABORT,0);xdev_ext_mech_end(s,b,XDEV_EXT_MECH_END_ABORT,err);
}
static bool xdev_ext_mech_order_blocked(struct xdev_ext_mech_session*s,const struct xdev_ext_mech_batch*b){(void)s;(void)b;return false;}
static void xdev_ext_mech_order_park(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b){(void)s;(void)b;abort();}
static void xdev_ext_mech_order_kick(struct xdev_ext_mech_session*s){(void)s;}
static void xdev_ext_mech_transform_undo(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b){(void)s;(void)b;}
static int xdev_ext_mech_transform_landed(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b,bool seq){(void)s;(void)seq;CHECK(!b->transform.active,"unexpected transform");return 0;}
static struct xdev_ext_binding_ctx_v2 xdev_ext_mech_base(struct xdev_ext_mech_stage*st,u32 bytes){(void)st;(void)bytes;return (struct xdev_ext_binding_ctx_v2){0};}
static void xdev_ext_mech_fill_info(struct xdev_ext_mech_session*s,struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){(void)s;(void)st;(void)b;}
static void xdev_ext_mech_worker_args(struct xdev_ext_mech_session*s,struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b,u32 member,const struct xdev_ext_binding_ctx_v2*base,struct xdev_ext_mech_call_args*a){(void)s;(void)st;(void)member;(void)base;memset(a,0,sizeof(*a));a->b=b;}
static int xdev_ext_mech_call(struct xdev_ext_mech_stage*st,const struct xdev_ext_mech_call_args*a,s32*ret,void*unused){(void)st;(void)a;(void)unused;*ret=XDEV_EXT_MECH_NEXT;return 0;}
/* The program's build returns BUILD_DEFAULT: the class default, slot rule, validate. */
static int xdev_ext_mech_build(struct xdev_ext_mech_session*s,struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){
 u8 scratch[64]={0};int err;(void)s;
 if(!st->cls->default_build)return 0;
 err=st->cls->default_build(st,b,scratch);
 if(!err)err=st->cls->validate(st,b,scratch,(u32)xdev_ext_mech_slots_used(scratch,st->cls->desc_size,st->cls->desc_cap));
 return err;
}
/* PRODUCTION */
static int native_submit(struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){
 unsigned k=st->index;attempts[k]++;
 accepts[k]++;accepted[k]=b;tickets[k]=xdev_ext_mech_batch_ticket(b);
 return 0;
}
static const struct xdev_ext_mech_class_ops native_cls={.submit=native_submit};
/* A stage whose progress runs after USER's in the same pass and kicks USER:
 * a user kick arriving while the pass runs. */
static unsigned long kick_progress(struct xdev_ext_mech_stage*st){
 xdev_ext_mech_stage_kick(&st->s->st[1]);return 0;
}
static const struct xdev_ext_mech_class_ops native_kick_cls={.submit=native_submit,.progress=kick_progress};
static const struct xdev_ext_mech_class_ops user_cls={
 .class_id=XDEV_EXT_MECH_CLASS_USER,.desc_size=sizeof(struct xdev_ext_user_desc),.desc_cap=1,
 .default_build=xdev_ext_user_default_build,.validate=xdev_ext_user_validate,
 .submit=xdev_ext_user_submit,.progress=xdev_ext_user_progress,.mark_dead=xdev_ext_user_mark_dead,
};
static const struct xdev_ext_mech_pool_ops pool_ops={0};
static void callback(unsigned k,int err){xdev_ext_mech_batch_complete(accepted[k],tickets[k],err);}

#define DEPTH_MAX 2
#define FRAMES 2
#define TIMEOUT 50
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_batch batches[DEPTH_MAX];
static struct xdev_ext_mech_life life[DEPTH_MAX*FRAMES];
static u8 custody[DEPTH_MAX*FRAMES];
static struct xdev_ext_user_stage *us;
static void *region;
static struct xdev_ext_user_ring_offsets off;
static struct eventfd_ctx efd;

static void setup(u32 depth,u32 entries,s64 delta,bool varlen){
 struct xdev_ext_mech_session*s=&session;
 memset(s,0,sizeof(*s));memset(batches,0,sizeof(batches));
 for(u32 i=0;i<DEPTH_MAX*FRAMES;i++){xdev_ext_mech_life_init(&life[i]);custody[i]=XDEV_EXT_MECH_F_HELD;}
 s->life=life;s->batches=batches;s->depth=depth;s->nr_stages=3;s->frames=FRAMES;
 s->layout=(struct xdev_ext_mech_layout){4096,0,4096,FRAMES*4096};
 s->pool=(struct xdev_ext_mech_pool){.ops=&pool_ops,.state=custody,.nr_frames=DEPTH_MAX*FRAMES,.frame_size=4096};
 INIT_LIST_HEAD(&s->retry);INIT_LIST_HEAD(&s->ordered);xdev_ext_mech_sess_init(&s->ss);
 progress_work_of_session=&s->progress_work;
 for(u32 i=0;i<3;i++){
  u32 c=i==0?XDEV_EXT_MECH_CLASS_NVME:i==1?XDEV_EXT_MECH_CLASS_USER:XDEV_EXT_MECH_CLASS_DMA;
  u32 d=i?XDEV_EXT_MECH_DIR_TO_DEVICE:XDEV_EXT_MECH_DIR_FROM_DEVICE;
  s->st[i]=(struct xdev_ext_mech_stage){.s=s,.index=i,.cls=i==1?&user_cls:&native_cls,.class_id=c,.direction=d};
  s->plan[i]=(struct xdev_ext_mech_stage_uapi){.class_id=c,.direction=d,.fd=i==1?7:5,
   .flags=i==1&&varlen?XDEV_EXT_USER_F_VARLEN:0,.arg0=i==1?100:0,.arg1=i==1?(u64)delta:64};
 }
 if(xdev_ext_user_layout(entries,4096,&off))abort();
 region=calloc(1,off.mmap_size);
 us=calloc(1,sizeof(*us)+depth*sizeof(us->held[0]));
 us->hdr=(void*)((char*)region+off.hdr);us->ready=(void*)((char*)region+off.ready);
 us->done=(void*)((char*)region+off.done);us->slots=(void*)((char*)region+off.slots);
 us->evfd=&efd;us->delta=delta;us->varlen=varlen;us->timeout=TIMEOUT;us->entries=entries;us->depth=depth;
 us->kflags=XDEV_EXT_USER_K_NEED_KICK;us->hdr->kernel_flags=us->kflags;
 s->st[1].priv=us;
 ends=0;end_how=-1;end_err=1;progress_kicks=retry_arms=0;event_signals=0;
 memset(attempts,0,sizeof(attempts));memset(accepts,0,sizeof(accepts));
}
static struct xdev_ext_mech_batch *start(u32 slot,u32 len){
 struct xdev_ext_mech_session*s=&session;
 struct xdev_ext_mech_batch*b=&batches[slot];
 memset(b,0,sizeof(*b));
 /* The pool allocator's part: these frames are HELD by the new batch. */
 for(u32 i=0;i<FRAMES;i++)custody[slot*FRAMES+i]=XDEV_EXT_MECH_F_HELD;
 b->s=s;b->nr_frames=FRAMES;b->present=(1U<<FRAMES)-1;b->bytes=FRAMES*4096;b->id=100+slot;b->key=7+slot;
 for(u32 i=0;i<FRAMES;i++)b->f[i]=(struct xdev_ext_mech_frame){.index=slot*FRAMES+i,.umem_addr=(slot*FRAMES+i)*4096ULL,.data_len=4096};
 INIT_LIST_HEAD(&b->node);xdev_ext_mech_bstate_init(&b->bs,s->nr_stages);xdev_ext_mech_batch_step(&b->bs,XDEV_EXT_MECH_EV_READY,0);
 xdev_ext_mech_sess_batch_begin(&s->ss);
 xdev_ext_mech_batch_run(s,b);
 if(accepts[0]==0||accepted[0]!=b)return NULL;
 /* The producer's native completion: the device wrote len bytes per frame. */
 for(u32 i=0;i<FRAMES;i++)b->f[i].data_len=len;
 b->bytes=FRAMES*len;
 callback(0,0);
 xdev_ext_mech_batch_drain(&s->drain_work);
 accepts[0]=0;
 return b;
}
/* The user thread: take the next ready entry. */
static struct xdev_ext_user_ready take(void){
 struct xdev_ext_user_ready r=us->ready[us->hdr->ready_cons&(us->entries-1)];
 us->hdr->ready_cons++;
 return r;
}
static void post(u32 slot,u64 ticket,s32 status){
 struct xdev_ext_user_done*d=&us->done[us->hdr->done_prod&(us->entries-1)];
 d->slot=slot;d->ticket=ticket;d->status=status;
 us->hdr->done_prod++;
}
static unsigned long progress(void){return xdev_ext_user_progress(&session.st[1]);}
/* The worker takes the pending progress_work and runs it. */
static void run_progress_work(void){pw_pending=false;xdev_ext_mech_progress_work(&session.progress_work.work);}
static void drain(void){xdev_ext_mech_batch_drain(&session.drain_work);}
static bool held_out_pending(struct xdev_ext_mech_batch*b){
 for(u32 i=0;i<FRAMES;i++){
  struct xdev_ext_mech_life*l=&life[b->f[i].index];
  if(xdev_ext_mech_life_phase(l)!=XDEV_EXT_MECH_L_OUT_PENDING||xdev_ext_mech_life_owner(l)!=1||
     xdev_ext_mech_life_busy(l)!=BIT(1)||custody[b->f[i].index]!=XDEV_EXT_MECH_F_INFLIGHT)return false;
 }
 return true;
}

static int exercise(const char*mode){
 struct xdev_ext_mech_session*s=&session;
 struct xdev_ext_mech_batch*b;
 struct xdev_ext_user_ready r;
 u64 claim,gen;
 bool varlen=!strcmp(mode,"varlen");
 s64 delta=!strcmp(mode,"complete")||!strcmp(mode,"badlen")?4:0;

 setup(!strcmp(mode,"full")?1:2,!strcmp(mode,"full")?1:2,delta,varlen);
 if(!strcmp(mode,"sleep"))us->hdr->user_flags=XDEV_EXT_USER_F_SLEEPING;
 b=start(0,4092);
 REQUIRE(b,"the producer stage ran");
 /* Held by the user thread: OUT_PENDING with the USER stage as sole owner,
  * INFLIGHT custody, visible in the ready ring, nothing at the device stage. */
 REQUIRE(attempts[1]==0&&accepts[1]==0,"USER is not a native submit");
 REQUIRE(us->nr_held==1&&us->held[0].b==b,"the class holds the batch in its slot");
 CHECK(held_out_pending(b),"held frames are OUT_PENDING, exclusively owned by stage 1, INFLIGHT");
 CHECK(xdev_ext_mech_life_acquire(&life[b->f[0].index],2,0,&claim)==-EBUSY,"the next stage cannot acquire a held frame");
 CHECK(attempts[2]==0,"no device stage was attempted while held");
 CHECK(progress_kicks==1,"the first held batch arms the deadline once");
 CHECK(us->hdr->ready_prod==1,"one ready entry published");
 CHECK(event_signals==(unsigned)!strcmp(mode,"sleep"),"eventfd only for a sleeping user thread");
 r=take();
 CHECK(r.slot==0&&r.nr_frames==FRAMES&&r.ticket==xdev_ext_mech_batch_ticket(b)&&r.batch_id==100&&r.key==7&&r.arg==0,"ready entry describes the batch");
 CHECK(us->slots[0].ticket==r.ticket&&us->slots[0].nr_frames==FRAMES,"slot table carries ticket and frames");
 CHECK(us->slots[0].f[1].umem_addr==4096&&us->slots[0].f[1].data_off==0&&us->slots[0].f[1].data_len==4092&&
       us->slots[0].f[1].capacity==4096&&us->slots[0].f[1].out_len==4092,"slot frame: address, span, capacity, preset length");
 CHECK(progress()==TIMEOUT,"an empty pass returns the time to the deadline");
 CHECK(us->hdr->kernel_flags&XDEV_EXT_USER_K_NEED_KICK,"idle kernel asks for a kick");
 gen=xdev_ext_mech_life_gen(&life[b->f[0].index]);

 if(!strcmp(mode,"complete")||!strcmp(mode,"sleep")||!strcmp(mode,"varlen")){
  u32 out=!strcmp(mode,"complete")?4096:!strcmp(mode,"varlen")?1:4092;
  us->slots[0].f[0].out_len=out;us->slots[0].f[1].out_len=out;
  post(0,r.ticket,0);
  progress();
  CHECK(us->nr_held==0&&!us->held[0].b&&us->slots[0].ticket==0,"completion releases the slot");
  CHECK(us->hdr->done_cons==1,"completion consumed");
  for(u32 i=0;i<FRAMES;i++){
   struct xdev_ext_mech_life*l=&life[b->f[i].index];
   CHECK(xdev_ext_mech_life_phase(l)==XDEV_EXT_MECH_L_READY&&l->valid_len==out&&xdev_ext_mech_life_refs(l)==1&&
         xdev_ext_mech_life_gen(l)==gen,"republished READY with the new length for the next stage");
  }
  CHECK(attempts[2]==0,"the device stage starts only on the worker");
  drain();
  REQUIRE(accepts[2]==1&&accepted[2]==b,"the next stage received the batch");
  CHECK(b->f[0].data_len==out&&b->f[1].data_len==out&&b->bytes==2*out,"the next stage sees the user's length");
  callback(2,0);drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_DONE,"batch done");
 }else if(!strcmp(mode,"deadline")){
  jiffies+=TIMEOUT-1;
  CHECK(progress()==1,"one jiffy before the deadline nothing is cancelled");
  CHECK(us->nr_held==1&&ends==0,"still held");
  jiffies+=1;
  CHECK(progress()==0,"no deadline remains");
  CHECK(us->nr_held==0&&s->cnt[XDEV_EXT_MECH_CNT_TIMEOUTS]==1,"deadline cancels and counts a timeout");
  drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-ETIMEDOUT,"deadline aborts the batch with -ETIMEDOUT");
  CHECK(attempts[2]==0,"a cancelled batch never reaches the device stage");
  CHECK(xdev_ext_mech_life_phase(&life[b->f[0].index])==XDEV_EXT_MECH_L_FREE&&
        xdev_ext_mech_life_gen(&life[b->f[0].index])==gen+1,"cancel drops the claim: FREE, next generation");
  post(0,r.ticket,0);progress();
  CHECK(s->cnt[XDEV_EXT_MECH_CNT_REJECTS]==1&&ends==1&&us->hdr->done_cons==1,"a late completion is refused");
  CHECK(s->ss.state==XDEV_EXT_MECH_SESSION_ACTIVE,"the session stays ACTIVE");
 }else if(!strcmp(mode,"stop")||!strcmp(mode,"dead")){
  unsigned kicks=progress_kicks;
  if(!strcmp(mode,"stop"))xdev_ext_mech_sess_stop(&s->ss);
  else{xdev_ext_user_mark_dead(&s->st[1]);CHECK(progress_kicks==kicks+1,"marking dead kicks the worker");}
  CHECK(progress()==0,"stopping pass");
  drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==(!strcmp(mode,"stop")?-ESHUTDOWN:-EPIPE),"held batch cancelled with the stop reason");
  CHECK(us->hdr->kernel_flags&XDEV_EXT_USER_K_STOPPED,"user space sees STOPPED");
  CHECK(event_signals==1,"one wakeup for the stop");
  progress();
  CHECK(event_signals==1,"no second wakeup");
  CHECK(attempts[2]==0,"nothing reached the device stage");
 }else if(!strcmp(mode,"stale")){
  post(5,r.ticket,0);post(0,r.ticket+1,0);
  progress();
  post(1,r.ticket,0);
  progress();
  CHECK(s->cnt[XDEV_EXT_MECH_CNT_REJECTS]==3&&us->nr_held==1&&ends==0,"out-of-range, wrong-ticket and unheld-slot entries are refused");
  us->hdr->done_prod+=1000;
  progress();
  CHECK(s->cnt[XDEV_EXT_MECH_CNT_REJECTS]==3+1+us->entries&&us->nr_held==1,"a runaway producer: one reject, then only the newest entries, each refused");
  us->hdr->done_cons=0;  /* user scribbles the kernel index; the kernel keeps its own */
  us->hdr->done_prod=us->done_cons;
  post(0,r.ticket,0);progress();drain();
  CHECK(us->nr_held==0&&accepts[2]==1,"a valid completion still completes");
  callback(2,0);drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_DONE,"batch done");
 }else if(!strcmp(mode,"badlen")){
  us->slots[0].f[0].out_len=4096;us->slots[0].f[1].out_len=4095;
  post(0,r.ticket,0);progress();drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-EPROTO,"a length off the rule fails the batch");
  CHECK(s->cnt[XDEV_EXT_MECH_CNT_PROTOCOL_ERR]==1&&attempts[2]==0,"counted, never forwarded");
  CHECK(b->f[0].data_len==4092,"no length applied before every frame passed");
 }else if(!strcmp(mode,"status")){
  post(0,r.ticket,-EIO);progress();drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-EIO,"a user errno fails the batch with it");
  CHECK(s->cnt[XDEV_EXT_MECH_CNT_PROTOCOL_ERR]==0,"an errno is no protocol error");
  b=start(1,4092);
  REQUIRE(b,"second batch");
  r=take();
  post(1,r.ticket,7);progress();drain();
  CHECK(ends==2&&end_err==-EPROTO&&s->cnt[XDEV_EXT_MECH_CNT_PROTOCOL_ERR]==1,"a positive status is -EPROTO");
 }else if(!strcmp(mode,"full")){
  /* The user thread never consumes ready entries; after the deadline the
   * single-entry ring is still full. */
  us->hdr->ready_cons=0;
  jiffies+=TIMEOUT;progress();drain();
  CHECK(ends==1&&end_err==-ETIMEDOUT,"first batch cancelled");
  accepts[0]=0;
  b=start(0,4092);
  CHECK(!b||us->nr_held==0,"no second hand-out into a full ring");
  CHECK(ends==2&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-ENOBUFS,"a full ready ring refuses the submit with -ENOBUFS");
  CHECK(us->hdr->ready_prod==1,"no ready entry overwritten");
  CHECK(custody[0]==XDEV_EXT_MECH_F_K_FREE&&custody[1]==XDEV_EXT_MECH_F_K_FREE,"refused batch frames went back");
 }else if(!strcmp(mode,"multi")){
  struct xdev_ext_mech_batch*b2;
  struct xdev_ext_user_ready r2;
  jiffies+=10;
  b2=start(1,4092);
  REQUIRE(b2&&us->nr_held==2,"two batches held");
  CHECK(progress_kicks==1,"a second held batch does not re-arm");
  r2=take();
  CHECK(r2.slot==1&&r2.ticket==xdev_ext_mech_batch_ticket(b2),"second ready entry");
  CHECK(progress()==TIMEOUT-10,"the delay follows the oldest held batch");
  post(1,r2.ticket,0);progress();drain();
  CHECK(accepts[2]==1&&accepted[2]==b2&&us->held[0].b==b,"completion out of order completes only its own batch");
  callback(2,0);drain();
  post(0,r.ticket,0);progress();drain();
  CHECK(accepts[2]==2&&accepted[2]==b,"then the first");
  callback(2,0);drain();
  CHECK(ends==2&&us->nr_held==0,"both done");
 }else if(!strcmp(mode,"kick-race")){
  run_progress_work();
  CHECK(pw_pending&&pw_delay==TIMEOUT,"a pass with a held batch re-arms at the deadline");
  s->st[2].cls=&native_kick_cls;
  run_progress_work();
  CHECK(pw_pending&&pw_delay==0,"a kick during the pass is not pushed back to the deadline");
  s->st[2].cls=&native_cls;
  post(0,r.ticket,0);
  run_progress_work();
  CHECK(us->nr_held==0,"the kicked pass reaps the completion");
  CHECK(!pw_pending,"nothing held: no re-arm");
 }else return 2;
 CHECK(!warnings,"production warning count is zero");
 return failures!=0;
}
int main(int argc,char**argv){return argc==2?exercise(argv[1]):2;}

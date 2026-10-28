/* SPDX-License-Identifier: GPL-2.0 */
/* OS shims only: custody, release, stop, notify and IOU queue bodies are real. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_core.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"
#include "io_uring/xdev_ext_mech_notify.h"
#include "io_uring/xdev_ext_mech_step.h"
typedef __u32 u32;
typedef __u64 u64;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define BIT(x) (1U<<(x))
#define WARN_ON_ONCE(x) (!!(x))
#define hweight32(x) __builtin_popcount(x)
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM (1U << 2)
#define atomic64_read(x) (*(x))
#define atomic64_add(n,p) (*(p)+=(n))
#define atomic64_inc(p) (++*(p))
static unsigned int test_lock_depth, locked_custody_moves, reschedules;
static void test_handoff_hook(unsigned phase);
#define cond_resched() do { assert(!test_lock_depth); reschedules++; } while (0)
#define spin_lock_irqsave(lock,flags) do { (void)(lock); (flags)=0; test_lock_depth++; } while (0)
#define spin_unlock_irqrestore(lock,flags) do { (void)(lock); (void)(flags); assert(test_lock_depth); test_lock_depth--; } while (0)
#define lockdep_assert_held(lock) ((void)(lock))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
struct list_head { int unused; };
#define LIST_HEAD(n) struct list_head n = {0}
#define list_splice_init(a,b) do { (void)(a); (void)(b); } while (0)
#define list_del_init(a) ((void)(a))
#define list_for_each_entry_safe(b,n,h,m) for ((b)=NULL,(n)=NULL; (void)(h),(b); (b)=(n))
struct kthread_work { int unused; };
struct xdev_ext_mech_frame { u32 index; };
struct xdev_ext_mech_pool;
struct xdev_ext_mech_pool_ops {
 int (*alloc)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *,u32);
 void (*recycle)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *);
};
struct xdev_ext_mech_pool { u32 kind; u32 nr_frames; __u8 *state; void *priv; const struct xdev_ext_mech_pool_ops *ops; };
struct io_xdev_ext_umem_mech { int lock; u32 head,nr,*idx; };
struct xdev_ext_mech_stage;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_class_ops {
 u32 flags;
 void (*batch_end)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,int);
 void (*batch_release)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,bool);
 unsigned long (*progress)(struct xdev_ext_mech_stage *);
};
struct xdev_ext_mech_stage { u32 direction; const struct xdev_ext_mech_class_ops *cls; };
static void verify_final_release(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,bool);
static const struct xdev_ext_mech_class_ops class_callbacks = {.batch_release=verify_final_release};
struct xdev_ext_mech_session {
 int lock,worker,evfd,stop_err,last_err; bool worker_gone;
 int native_controls,drain_wq;
 bool start_recycle,start_return_pending,start_preparing;
 u32 start_legacy_events, start_user_len;
 u64 start_left,done,aborted,cnt[XDEV_EXT_MECH_CNT_NR];
 struct xdev_ext_mech_sess ss;
 struct xdev_ext_mech_notify_state notify;
 struct xdev_ext_mech_pool pool;
 struct xdev_ext_mech_layout layout;
 struct xdev_ext_mech_life *life;
 __u8 *transform_owner;
 struct xdev_ext_mech_stage st[1];
 struct xdev_ext_mech_stage_uapi plan[1];
 u32 frames, depth, nr_stages; u64 start_seq; bool start_to_user;
 struct list_head open,retry;
 struct kthread_work stop_work,kick_work,reap_work,retry_work,progress_work;
};
struct xdev_ext_mech_batch {
 bool to_user; u32 nr_frames,present;
 u64 ticket;
 struct {u32 state;} bs;
 struct xdev_ext_mech_frame f[8];
 struct list_head node;
};
/* Trace observation is disabled in this custody/notification fixture. */
static bool trace_native_event_enabled(void) { return false; }
static void xdev_ext_mech_trace_frame(struct xdev_ext_mech_batch *b,
 const char *phase,u32 pos,u64 ticket,int status) {
 (void)b;(void)phase;(void)pos;(void)ticket;(void)status;
}
static void xdev_ext_mech_trace_batch(struct xdev_ext_mech_batch *b,
 const char *phase,u64 ticket,int status) {
 (void)b;(void)phase;(void)ticket;(void)status;
}
enum {XDEV_EXT_MECH_END_DONE, XDEV_EXT_MECH_END_ABORT, XDEV_EXT_MECH_END_SEQUESTER};
static struct xdev_ext_mech_session *event_session;
/* The extracted terminal path must settle frame custody before allowing a
 * class to release its resource lease. Unknown fate must never pass as safe.
 */
static void verify_final_release(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,bool sequestered) {
 (void)st;assert(!test_lock_depth);
 if(sequestered)return;
 for(u32 i=0;i<b->nr_frames;i++)if(b->present&BIT(i)) {
  __u8 phase=event_session->pool.state[b->f[i].index];
  assert(phase==XDEV_EXT_MECH_F_USER || phase==XDEV_EXT_MECH_F_K_FREE);
 }
}
static unsigned events,at_event_published,at_event_queued,stopwork_queued;
static int system_unbound_wq;
static void eventfd_signal(int ignored) {
 (void)ignored; events++;
 at_event_published=event_session->cnt[XDEV_EXT_MECH_CNT_PUBLISHED];
 at_event_queued=((struct io_xdev_ext_umem_mech *)event_session->pool.priv)->nr;
}
static void queue_work(int q,struct kthread_work *w) {(void)q;(void)w;}
static void kthread_queue_work(int q,struct kthread_work *w) {(void)q;if(w==&event_session->stop_work)stopwork_queued++;}
static void kthread_cancel_delayed_work_sync(struct kthread_work *w) {(void)w;}
static void kthread_mod_delayed_work(int q,struct kthread_work *w,unsigned long delay) {(void)q;(void)w;(void)delay;}
static bool xdev_ext_mech_session_admits(const struct xdev_ext_mech_session *s) {return xdev_ext_mech_sess_admits(&s->ss);}
#define atomic_read(x) (*(x))
#define wake_up(x) ((void)(x))
/* PRODUCTION_SETTLED */
/* PRODUCTION_SETTLE */
static void xdev_ext_mech_set_err_locked(struct xdev_ext_mech_session *s,int err) {if(err&&!s->stop_err)s->last_err=err;}
static int xdev_ext_mech_stop_reason(struct xdev_ext_mech_session *s) {return s->stop_err?s->stop_err:-ESHUTDOWN;}
static void xdev_ext_mech_retry_kick(struct xdev_ext_mech_session *s) {(void)s;}
static void xdev_ext_mech_order_kick(struct xdev_ext_mech_session *s) {(void)s;}
static void xdev_ext_mech_abort(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,int e) {(void)s;(void)b;(void)e;abort();}
static u32 xdev_ext_mech_pool_frame_state(struct xdev_ext_mech_pool *p,u32 i) {return p->state[i];}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p,u32 i,u32 from,u32 to) {
 if(i>=p->nr_frames)return -ERANGE;
 int ret=xdev_ext_mech_frame_move(&p->state[i],from,to);
 if(from==XDEV_EXT_MECH_F_USER&&to==XDEV_EXT_MECH_F_K_FREE) {
  if(test_lock_depth)locked_custody_moves++;
  if(!ret)test_handoff_hook(1);
 }
 return ret;
}
/* PRODUCTION_POOL */
static void hook_recycle(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_frame *f) {
 io_xdev_ext_umem_mech_recycle(p,f);test_handoff_hook(2);
}
/* PRODUCTION_NOTIFY */
/* PRODUCTION_COUNT */
/* PRODUCTION_MOVE */
/* PRODUCTION_RELEASE */
/* PRODUCTION_STOP */
/* PRODUCTION_RETURN_IDLE */
static bool xdev_ext_mech_batch_put_locked(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,bool seq) {
 (void)b; bool last=xdev_ext_mech_sess_batch_end(&s->ss,seq); xdev_ext_mech_settle_locked(s);
 xdev_ext_mech_notify_locked(s,false); return last;
}
/* PRODUCTION_END */
/* PRODUCTION_STOP_WORK */
/* PRODUCTION_TAKE */
/* User-copy hooks deterministically interleave a completed async STOP. */
struct io_ring_ctx { int unused; };
static bool stop_during_copy, copy_fails, complete_during_copy;
static struct xdev_ext_mech_batch *copy_batch;
static unsigned stop_phase, hook_count;
static bool early_wake,early_settle;
static void test_handoff_hook(unsigned phase) {
 if(stop_phase!=phase || ++hook_count!=1)return;
 stop_phase=0;
 xdev_ext_mech_session_stop(event_session,-ENODEV);
 xdev_ext_mech_stop_work(&event_session->stop_work);
 early_wake=events!=0;early_settle=xdev_ext_mech_settled(event_session);
}
static struct xdev_ext_mech_session *xdev_ext_mech_find(struct io_ring_ctx *ctx,u64 id)
{ (void)ctx; (void)id; return event_session; }
static bool xdev_ext_mech_rx_first(struct xdev_ext_mech_session *s) { (void)s; return false; }
static int copy_from_user(void *out,const void *in,size_t n) {memcpy(out,in,n);return 0;}
#define __user
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x)>=(uintptr_t)-4095)
#define IS_ERR_OR_NULL(x) (!(x) || IS_ERR(x))
#define GFP_KERNEL 0
#define kmemdup(p,n,flags) memdup_array_user(p,1,n)
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define kfree(x) free(x)
static void *memdup_array_user(const void *p,size_t n,size_t size)
{
 assert(!test_lock_depth); /* User copies may fault; never run under a spinlock. */
 if(complete_during_copy) {
  xdev_ext_mech_end(event_session,copy_batch,XDEV_EXT_MECH_END_DONE,0);
  early_wake=events!=0;
 }
 if(stop_during_copy) {
  xdev_ext_mech_session_stop(event_session,-ENODEV);
  xdev_ext_mech_stop_work(&event_session->stop_work);
  early_wake=events!=0;early_settle=xdev_ext_mech_settled(event_session);
 }
 if(copy_fails)return (void *)(intptr_t)-EFAULT;
 void *copy=malloc(n*size);assert(copy);memcpy(copy,p,n*size);return copy;
}
/* PRODUCTION_START */

static const struct xdev_ext_mech_pool_ops ops={io_xdev_ext_umem_mech_alloc,hook_recycle};
static void setup_n(struct xdev_ext_mech_session *s,struct io_xdev_ext_umem_mech *m,__u8 *state,u32 lent,u32 groups,u32 capacity) {
 memset(s,0,sizeof(*s)); memset(m,0,sizeof(*m)); memset(state,XDEV_EXT_MECH_F_USER,capacity);
 m->idx=calloc(capacity,sizeof(*m->idx));s->life=calloc(capacity,sizeof(*s->life));s->transform_owner=calloc(capacity,1);assert(m->idx&&s->life&&s->transform_owner);
 xdev_ext_mech_sess_init(&s->ss); s->pool=(struct xdev_ext_mech_pool){.nr_frames=capacity,.state=state,.priv=m,.ops=&ops};
 s->st[0].direction=XDEV_EXT_MECH_DIR_TO_DEVICE;s->st[0].cls=&class_callbacks;s->nr_stages=1;s->start_recycle=true;s->start_return_pending=true;
 s->layout=(struct xdev_ext_mech_layout){.frame_size=1,.group_bytes=1,.seg_len=1};
 s->frames=1;s->start_left=1;s->evfd=1;event_session=s;events=0;stopwork_queued=0;
 for(u32 i=0;i<lent;i++) {u64 token;assert(!xdev_ext_mech_life_claim(&s->life[i],0,&token));assert(!xdev_ext_mech_life_publish(&s->life[i],token,1,1));}
 for(u32 i=0;i<lent;i++){struct xdev_ext_mech_frame f={.index=i};state[i]=XDEV_EXT_MECH_F_K_FREE;ops.recycle(&s->pool,&f);}
 struct xdev_ext_mech_notify_arm arm={.session_id=1,.batches_target=groups};assert(!xdev_ext_mech_notify_arm(&s->notify,&arm));
}
static void setup(struct xdev_ext_mech_session *s,struct io_xdev_ext_umem_mech *m,__u8 *state,u32 lent,u32 groups) {
 setup_n(s,m,state,lent,groups,8);
}
static void admit(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b) {
 memset(b,0,sizeof(*b));b->to_user=true;b->nr_frames=1;b->present=1;
 assert(!ops.alloc(&s->pool,b->f,1));assert(!xdev_ext_mech_sess_batch_begin(&s->ss));
}
static int check(bool ok,const char *msg){if(!ok){fprintf(stderr,"FAIL: %s\n",msg);return 1;}return 0;}
int main(int argc,char **argv) {
 struct xdev_ext_mech_session s;struct io_xdev_ext_umem_mech m;__u8 state[8];struct xdev_ext_mech_batch a,b;
 assert(argc==2);
 if(!strcmp(argv[1],"completion_copy")) {
  setup(&s,&m,state,1,3);admit(&s,&a);s.start_left=0;s.pool.kind=XDEV_EXT_MECH_POOL_IOU_UMEM;
  s.start_recycle=false;s.start_return_pending=false;xdev_ext_mech_notify_init(&s.notify);
  struct io_ring_ctx ctx={0};u32 idx[]={1,2};
  struct xdev_ext_mech_start req={.session_id=1,.nr_batches=2,.first_seq=1,
   .flags=XDEV_EXT_MECH_START_F_USER_FRAMES,.nr_user_frames=2,.user_frames=(uintptr_t)idx};
  complete_during_copy=true;copy_batch=&a;
  int ret=xdev_ext_mech_start(&ctx,&req);
  return check(!ret&&s.done==1&&!s.ss.inflight,"overlapped prior batch did not complete")|
   check(!early_wake,"legacy completion bypassed preparing wake gate")|
   check(events==1,"legacy completion notification was lost during START copy");
 }
 if(!strcmp(argv[1],"large_start") || !strcmp(argv[1],"loan_stop") ||
    !strcmp(argv[1],"queue_stop") || !strcmp(argv[1],"queue_stop_recycle") ||
    !strcmp(argv[1],"loan_stop_recycle") || !strcmp(argv[1],"copy_gate") ||
    !strcmp(argv[1],"copy_fail_stop") || !strcmp(argv[1],"loan_fail_stop")) {
  bool large=!strcmp(argv[1],"large_start"),fail_loan=!strcmp(argv[1],"loan_fail_stop");
  bool recycling=strstr(argv[1],"_recycle")!=NULL;
  u32 nr=large?262144:recycling?2:3;__u8 *states=malloc(nr);u32 *idx=malloc(nr*sizeof(*idx));assert(states&&idx);
  setup_n(&s,&m,states,0,nr,nr);s.pool.kind=XDEV_EXT_MECH_POOL_IOU_UMEM;
  s.depth=2;s.start_left=0;s.start_recycle=false;s.start_return_pending=false;
  s.start_recycle=recycling;
  for(u32 i=0;i<nr;i++)idx[i]=i;
  if(fail_loan)idx[1]=0;
  stop_during_copy=!strcmp(argv[1],"copy_gate")||!strcmp(argv[1],"copy_fail_stop");
  copy_fails=!strcmp(argv[1],"copy_fail_stop");
  stop_phase=(!strcmp(argv[1],"loan_stop")||!strcmp(argv[1],"loan_stop_recycle")||fail_loan)?1:
    (!strcmp(argv[1],"queue_stop")||!strcmp(argv[1],"queue_stop_recycle"))?2:0;
  struct io_ring_ctx ctx={0};
  struct xdev_ext_mech_start req={.session_id=1,.nr_batches=nr,.first_seq=1,
   .flags=XDEV_EXT_MECH_START_F_USER_FRAMES|(recycling?XDEV_EXT_MECH_START_F_RECYCLE:0),.nr_user_frames=nr,.user_frames=(uintptr_t)idx};
  int ret=xdev_ext_mech_start(&ctx,&req),bad=0;
  if(large) {
   bad|=check(!ret&&m.nr==nr,"legacy large USER START failed to lend whole pool");
   bad|=check(!locked_custody_moves,"large USER custody loop held IRQ-off spinlock");
   bad|=check(reschedules>0,"large USER handoff never offered a reschedule");
   return bad;
  }
  bad|=check(!early_wake,"STOP notified during unfinished START handoff");
  bad|=check(!early_settle,"STOP drain settled during unfinished START handoff");
  bad|=check(ret==(copy_fails?-EFAULT:fail_loan?-EBUSY:-ESHUTDOWN),"wrong interrupted START result");
  /* stop_work already ran during the transaction; finalization must requeue it. */
  if(m.nr)bad|=check(stopwork_queued>=2,"STOP during loan handoff was not rescheduled");
  if(s.start_return_pending)xdev_ext_mech_stop_work(&s.stop_work);
  bad|=check(!m.nr&&!s.start_return_pending&&!s.start_preparing&&!s.start_left,
    "interrupted START stranded loans or gates");
  bad|=check(xdev_ext_mech_settled(&s)&&events==1&&at_event_queued==0,
    "interrupted START did not finish drain and terminal notification");
  for(u32 i=0;i<nr;i++)bad|=check(states[i]==XDEV_EXT_MECH_F_USER&&
    xdev_ext_mech_life_phase(&s.life[i])==XDEV_EXT_MECH_L_FREE,"interrupted START retained custody");
  return bad;
 }
 if(!strcmp(argv[1],"copy_stop_recycle")||!strcmp(argv[1],"copy_stop_legacy")||
    !strcmp(argv[1],"start_accepted")||!strcmp(argv[1],"start_bad_frames")) {
  bool accepted=!strcmp(argv[1],"start_accepted");
  bool bad_frames=!strcmp(argv[1],"start_bad_frames");
  bool recycle=strcmp(argv[1],"copy_stop_legacy")!=0;
  struct io_ring_ctx ctx={0};u32 idx[]={0,1,2};
  setup(&s,&m,state,0,3);s.pool.kind=XDEV_EXT_MECH_POOL_IOU_UMEM;
  s.depth=2;s.start_left=0;s.start_recycle=false;s.start_return_pending=false;
  struct xdev_ext_mech_start req={.session_id=1,.nr_batches=3,.first_seq=1,
   .flags=XDEV_EXT_MECH_START_F_USER_FRAMES|(recycle?XDEV_EXT_MECH_START_F_RECYCLE:0),
   .nr_user_frames=recycle?2:3,.user_frames=(uintptr_t)idx};
  stop_during_copy=!accepted&&!bad_frames;
  if(bad_frames)idx[1]=idx[0];
  int ret=xdev_ext_mech_start(&ctx,&req);
  if(!accepted&&!bad_frames&&s.start_return_pending)xdev_ext_mech_stop_work(&s.stop_work);
  if(accepted) {
   int bad=check(!ret&&m.nr==2&&s.start_return_pending&&s.start_left==3,
     "ordinary START failed to atomically install loans and its wake gate");
   xdev_ext_mech_session_stop(&s,0);
   bad|=check(events==0,"STOP bypassed the newly installed loan gate");
   xdev_ext_mech_stop_work(&s.stop_work);
   bad|=check(!m.nr&&!s.start_return_pending&&events==1&&at_event_published==2,
     "STOP after accepted START did not return all safe loans before notification");
   for(u32 i=0;i<2;i++)bad|=check(state[i]==XDEV_EXT_MECH_F_USER,
     "STOP after accepted START retained user loan");
   return bad;
  }
  int bad=check(ret==(bad_frames?-EBUSY:-ESHUTDOWN),"START did not reject stopped admission or duplicate user frames")|
   check(!m.nr&&!s.start_return_pending&&!s.start_left,"rejected START installed loans or a stale wake gate")|
   check(events==(bad_frames?0U:1U)&&at_event_queued==0,"STOP notification exposed stranded loans");
  for(u32 i=0;i<req.nr_user_frames;i++)bad|=check(state[i]==XDEV_EXT_MECH_F_USER&&
   xdev_ext_mech_life_phase(&s.life[i])==XDEV_EXT_MECH_L_FREE,"rejected START changed frame custody or lifecycle");
  if(!bad)printf("production START/STOP %s: PASS\n",argv[1]);
  return bad;
 }
 setup(&s,&m,state,!strcmp(argv[1],"long")?8:!strcmp(argv[1],"unsafe")?3:2,!strcmp(argv[1],"long")?257:!strcmp(argv[1],"unsafe")?4:3);
 if(!strcmp(argv[1],"long")) {
  struct xdev_ext_mech_batch batch[8];u32 left=257;
  s.start_left=left;
  while(left) {
   u32 count=left<8?left:8;
   for(u32 i=0;i<count;i++){admit(&s,&batch[i]);s.start_left--;left--;}
   /* Force a whole completion drain before admitting another wave. */
   for(u32 i=0;i<count;i++)xdev_ext_mech_end(&s,&batch[i],XDEV_EXT_MECH_END_DONE,0);
  }
  int bad=check(s.done==257&&!s.ss.inflight,"long flow lost a completion")|
   check(m.nr==0&&s.cnt[XDEV_EXT_MECH_CNT_PUBLISHED]==8,"257/8 tail retained loans")|
   check(events==1&&at_event_published==8&&at_event_queued==0,"257/8 terminal wake raced ownership");
  for(u32 i=0;i<8;i++)bad|=check(state[i]==XDEV_EXT_MECH_F_USER,"257/8 frame not returned USER");
  if(!bad)puts("production recycle 257 groups / depth 8: PASS");
  return bad;
 }
 admit(&s,&a);admit(&s,&b);
 if(!strcmp(argv[1],"unsafe")) {
  struct xdev_ext_mech_batch ambiguous;
  admit(&s,&ambiguous);
  xdev_ext_mech_end(&s,&a,XDEV_EXT_MECH_END_DONE,0);
  /* The other two borrowed frames are device-owned or ambiguous. */
  state[1]=XDEV_EXT_MECH_F_INFLIGHT;state[2]=XDEV_EXT_MECH_F_SEQUESTERED;
  xdev_ext_mech_end(&s,&ambiguous,XDEV_EXT_MECH_END_SEQUESTER,-EIO);
  if(check(stopwork_queued>0,"ambiguous result never schedules return of safe queued loans"))return 1;
  xdev_ext_mech_stop_work(&s.stop_work);
  return check(state[0]==XDEV_EXT_MECH_F_USER,"STOP did not return safe queued frame")|
   check(state[1]==XDEV_EXT_MECH_F_INFLIGHT&&state[2]==XDEV_EXT_MECH_F_SEQUESTERED,"STOP returned unsafe frame")|
   check(events==1&&at_event_published==1&&at_event_queued==0,"STOP wake preceded safe return");
 }
 if(!strcmp(argv[1],"abort")) {
  xdev_ext_mech_end(&s,&a,XDEV_EXT_MECH_END_DONE,0);
  xdev_ext_mech_end(&s,&b,XDEV_EXT_MECH_END_ABORT,-EIO);
  if(check(stopwork_queued>0,"abort suppresses exception wake without scheduling loan return"))return 1;
  xdev_ext_mech_stop_work(&s.stop_work);
  return check(state[0]==XDEV_EXT_MECH_F_USER&&state[1]==XDEV_EXT_MECH_F_USER,"abort retained safe loans")|
   check(events==1&&at_event_published==2&&at_event_queued==0,"abort wake preceded loan return");
 }
 xdev_ext_mech_end(&s,&a,XDEV_EXT_MECH_END_DONE,0);xdev_ext_mech_end(&s,&b,XDEV_EXT_MECH_END_DONE,0);
 assert(m.nr==2&&s.done==2&&events==0);
 if(!strcmp(argv[1],"stop_late"))s.start_return_pending=false;
 if(!strcmp(argv[1],"stop")||!strcmp(argv[1],"stop_late")) {
  xdev_ext_mech_session_stop(&s,0);
  if(check(events==0,"STOP notified before worker returned queued loans"))return 1;
  xdev_ext_mech_stop_work(&s.stop_work);
 } else {
  admit(&s,&a);s.start_left=0;xdev_ext_mech_end(&s,&a,XDEV_EXT_MECH_END_DONE,0);
 }
 int bad=check(state[0]==XDEV_EXT_MECH_F_USER&&state[1]==XDEV_EXT_MECH_F_USER,"terminal retained K_FREE loan")|
  check(s.cnt[XDEV_EXT_MECH_CNT_PUBLISHED]==2&&m.nr==0,"terminal did not drain all loans")|
  check(events==1&&at_event_published==2&&at_event_queued==0,"notification preceded final ownership return");
 if(!bad&&!strcmp(argv[1],"tail")) {
  u32 idx[]={0,1};
  bad|=check(!xdev_ext_mech_take_user_frames(&s,idx,2),"same frames cannot be lent on subsequent START");
  bad|=check(m.nr==2,"subsequent START queue contains stale or missing entries");
  admit(&s,&a);admit(&s,&b);bad|=check(m.nr==0,"subsequent START cannot allocate all frames");
 }
 if(!bad)printf("production recycle %s: PASS\n",argv[1]);
 return bad;
}

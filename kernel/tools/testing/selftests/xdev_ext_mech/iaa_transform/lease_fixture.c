/* SPDX-License-Identifier: GPL-2.0 */
/* Only OS/provider boundary shims and independent test schedules live here. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_core.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"
#include "io_uring/xdev_ext_mech_step.h"
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define BIT(x) (1U<<(x))
#define min(a,b) ((a)<(b)?(a):(b))
#define GENMASK_ULL(h,l) ((~0ULL << (l)) & (~0ULL >> (63-(h))))
#define hweight32(x) __builtin_popcount(x)
static bool warn_once(bool c) {return c;}
#define WARN_ON_ONCE(x) warn_once(!!(x))
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM (1U << 2)
#define XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE (1U << 1)
#define atomic64_inc(p) (++*(p))
#define atomic64_dec(p) (--*(p))
#define spin_lock_irqsave(l,f) do {(void)(l);(f)=0;} while(0)
#define spin_unlock_irqrestore(l,f) do {(void)(l);(void)(f);} while(0)
#define N 80
#define FS 1024U
struct page {u32 id;};
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;void *pool_priv;};
struct xdev_ext_mech_pool;
struct xdev_ext_mech_pool_ops {
 int (*resolve)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *);
 void (*recycle)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *);
 void (*sync_for_cpu)(struct xdev_ext_mech_pool *,const struct xdev_ext_mech_frame *);
};
struct xdev_ext_mech_pool {u32 kind,nr_frames,frame_size,capabilities;u8 state[N];const struct xdev_ext_mech_pool_ops *ops;};
struct xdev_ext_mech_stage;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_class_ops {u32 flags;int (*submit)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *);};
struct xdev_ext_mech_session;
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;u32 index,direction;const struct xdev_ext_mech_class_ops *cls;};
struct xdev_ext_mech_session {
 struct xdev_ext_mech_pool pool;struct xdev_ext_mech_stage st[2];
 struct xdev_ext_mech_life life[N];u8 transform_owner[N];
 bool start_recycle;u64 start_left;u64 count[XDEV_EXT_MECH_CNT_NR];
 int lock,last_err;bool admits;u64 submitted[2];
};
struct xdev_ext_mech_batch {
 struct xdev_ext_mech_session *s;struct xdev_ext_mech_bstate bs;bool fifo_accepted;
 struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
 u32 nr_frames,present,bytes;bool to_user,sequester,locally_cancelled;
 int status;u64 ticket;struct xdev_ext_mech_completion completion;
 struct {struct xdev_ext_mech_frame dst[XDEV_EXT_MECH_MAX_FRAMES];u64 token[XDEV_EXT_MECH_MAX_FRAMES];u32 nr,produced;bool active;} transform;
};
static u32 page_map[N],released[N],synced[N],resolve_fail_index=N,queues;
static u32 fail_source_return_index=N;
static struct page pages[N];
static struct xdev_ext_mech_frame frame(u32 index,u32 len) {
 return (struct xdev_ext_mech_frame){.index=index,.umem_addr=(u64)index*FS,.data_len=len};
}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p,u32 i,u32 from,u32 to) {
 if(i>=p->nr_frames)return -ERANGE;
 if(i==fail_source_return_index && to==XDEV_EXT_MECH_F_K_FREE)return -EIO;
 return xdev_ext_mech_frame_move(&p->state[i],from,to);
}
static u32 xdev_ext_mech_pool_frame_state(struct xdev_ext_mech_pool *p,u32 i) {return p->state[i];}
static struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *po,u32 *len) {
 if(f->index>=p->nr_frames || off>=FS)return NULL;
 *po=off;*len=FS-off;return &pages[page_map[f->index]];
}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s) {return s->admits;}
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s,u32 counter,u32 n) {s->count[counter]+=n;}
static int resolve(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_frame *f) {(void)p;return f->index==resolve_fail_index?-EIO:0;}
static void recycle(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_frame *f) {(void)p;released[f->index]++;}
static void sync_cpu(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f) {(void)p;synced[f->index]++;}
static void xdev_ext_mech_batch_queue(struct xdev_ext_mech_batch *b) {(void)b;queues++;}
/* xdev_ext_mech_frames_move */
/* xdev_ext_mech_frames_release */
static bool xdev_ext_mech_transform_alias(struct xdev_ext_mech_pool *,const struct xdev_ext_mech_frame *,const struct xdev_ext_mech_frame *);
/* xdev_ext_mech_transform_reserve */
/* xdev_ext_mech_transform_unreserve */
/* xdev_ext_mech_transform_alias */
/* xdev_ext_mech_batch_transform_begin */
/* xdev_ext_mech_batch_completion_claim */
/* xdev_ext_mech_batch_completion_publish */
/* xdev_ext_mech_batch_transform_complete */
/* xdev_ext_mech_batch_transform_produced */
/* xdev_ext_mech_transform_landed */
/* xdev_ext_mech_transform_undo */
/* xdev_ext_mech_submit */
static bool synchronous_refusal;
static int refusing_submit(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b) {
 (void)st;struct xdev_ext_mech_frame d=frame(10,FS);
 int ret=xdev_ext_mech_batch_transform_begin(b,&d,1);if(ret)return ret;
 if(synchronous_refusal)xdev_ext_mech_batch_transform_complete(b,b->ticket,0,173,false);
 return -EAGAIN;
}
static const struct xdev_ext_mech_pool_ops poolops={resolve,recycle,sync_cpu};
static const struct xdev_ext_mech_class_ops transformops={.flags=XDEV_EXT_MECH_CLASS_F_TRANSFORM};
static void setup(struct xdev_ext_mech_session *s) {
 memset(s,0,sizeof(*s));memset(released,0,sizeof(released));memset(synced,0,sizeof(synced));queues=0;resolve_fail_index=N;fail_source_return_index=N;
 s->pool=(struct xdev_ext_mech_pool){.kind=XDEV_EXT_MECH_POOL_IOU_UMEM,.nr_frames=N,.frame_size=FS,.ops=&poolops};
 for(u32 i=0;i<N;i++){page_map[i]=i;pages[i].id=i;}
 for(u32 i=0;i<2;i++)s->st[i]=(struct xdev_ext_mech_stage){.s=s,.index=i,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.cls=&transformops};
 s->admits=true;
}
static void source(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,u32 index) {
 memset(b,0,sizeof(*b));b->s=s;b->f[0]=frame(index,700);b->nr_frames=1;b->present=1;b->bytes=700;
 s->pool.state[index]=XDEV_EXT_MECH_F_INFLIGHT;u64 t;
 assert(!xdev_ext_mech_life_begin_produce(&s->life[index],false,&t));
 assert(!xdev_ext_mech_life_publish(&s->life[index],t,700));
 assert(!xdev_ext_mech_life_begin_consume(&s->life[index],&t));
 assert(!xdev_ext_mech_completion_begin(&b->completion,&b->ticket));
}
static void source_landed(struct xdev_ext_mech_batch *b,bool seq) {
 u32 i=b->f[0].index;struct xdev_ext_mech_session *s=b->s;
 assert(!xdev_ext_mech_pool_frame_move(&s->pool,i,XDEV_EXT_MECH_F_INFLIGHT,seq?XDEV_EXT_MECH_F_SEQUESTERED:XDEV_EXT_MECH_F_HELD));
 if(!seq)assert(!xdev_ext_mech_life_complete_consume(&s->life[i],xdev_ext_mech_life_token(&s->life[i])));
}
static int failures;
#define CHECK(c,msg) do {if(!(c)){fprintf(stderr,"FAIL: %s\n",msg);failures++;}}while(0)
int main(int argc,char **argv) {
 assert(argc==2);const char *mode=argv[1];
 struct xdev_ext_mech_session s;struct xdev_ext_mech_batch b;setup(&s);
 if(!strcmp(mode,"reserve_exclusive")) {
  CHECK(!xdev_ext_mech_transform_reserve(&s.st[0],10,3),"first reserve failed");
  CHECK(xdev_ext_mech_transform_reserve(&s.st[1],9,3)<0,"overlapping stage reserve accepted");
  CHECK(s.pool.state[9]==XDEV_EXT_MECH_F_USER&&!s.transform_owner[9]&&s.transform_owner[10]==1&&s.transform_owner[11]==1,"overlapping reserve disturbed prior stage custody");
  xdev_ext_mech_transform_unreserve(&s.st[1],10,1);
  CHECK(s.transform_owner[10]==1&&s.pool.state[10]==XDEV_EXT_MECH_F_HELD,"wrong stage unreserved another stage's frame");return !!failures;
 }
 if(!strcmp(mode,"cross_batch_alias")) {
  struct xdev_ext_mech_batch other;source(&s,&b,0);source(&s,&other,1);
  assert(!xdev_ext_mech_transform_reserve(&s.st[0],10,2));page_map[11]=page_map[10];
  struct xdev_ext_mech_frame first=frame(10,FS),second=frame(11,FS);
  int a=xdev_ext_mech_batch_transform_begin(&b,&first,1);
  int z=xdev_ext_mech_batch_transform_begin(&other,&second,1);
  CHECK(a<0 || z<0,"different depth slots accepted overlapping physical destination leases");
  CHECK(!(b.transform.active && other.transform.active),"overlapping physical destinations became concurrently active");
  return !!failures;
 }
 if(!strcmp(mode,"reserve_fail")) {
  s.pool.state[11]=XDEV_EXT_MECH_F_HELD;
  CHECK(xdev_ext_mech_transform_reserve(&s.st[0],10,3)!=0,"reservation accepted occupied frame");
  CHECK(s.pool.state[10]==XDEV_EXT_MECH_F_USER && !s.transform_owner[10],"failed reservation leaked preceding frame");
  CHECK(s.pool.state[11]==XDEV_EXT_MECH_F_HELD && !s.transform_owner[11],"failed reservation changed foreign owner");return !!failures;
 }
 if(!strcmp(mode,"depth")) {
  struct xdev_ext_mech_batch batches[8];assert(!xdev_ext_mech_transform_reserve(&s.st[0],16,16));
  for(u32 i=0;i<8;i++) {source(&s,&batches[i],i);struct xdev_ext_mech_frame d=frame(16+2*i,FS);CHECK(!xdev_ext_mech_batch_transform_begin(&batches[i],&d,1),"depth-eight lease refused");}
  for(u32 i=0;i<8;i++)CHECK(s.pool.state[i]==XDEV_EXT_MECH_F_INFLIGHT&&s.pool.state[16+2*i]==XDEV_EXT_MECH_F_INFLIGHT,"lease was recycled before first completion");
  for(u32 i=8;i-->0;) {struct xdev_ext_mech_batch *q=&batches[i];u32 n=100+i*73;xdev_ext_mech_batch_transform_complete(q,q->ticket,0,n,false);assert(!xdev_ext_mech_completion_consume(&q->completion,q->ticket,&q->status));source_landed(q,false);CHECK(!xdev_ext_mech_transform_landed(&s,q,false),"reverse-order landing failed");CHECK(q->bytes==n&&q->f[0].index==16+2*i&&s.life[16+2*i].valid_len==n,"parallel output metadata crossed leases");}
  return !!failures;
 }
 source(&s,&b,0);assert(!xdev_ext_mech_transform_reserve(&s.st[0],10,3));
 if(!strcmp(mode,"second_source_return_failure")) {
  b.f[1]=frame(1,700);b.nr_frames=2;b.present=3;b.bytes=1400;
  s.pool.state[1]=XDEV_EXT_MECH_F_INFLIGHT;u64 token;
  assert(!xdev_ext_mech_life_begin_produce(&s.life[1],false,&token));
  assert(!xdev_ext_mech_life_publish(&s.life[1],token,700));
  assert(!xdev_ext_mech_life_begin_consume(&s.life[1],&token));
 }
 if(!strcmp(mode,"preaccept") || !strcmp(mode,"sync_refuse")) {
  static const struct xdev_ext_mech_class_ops refusalops={.flags=XDEV_EXT_MECH_CLASS_F_TRANSFORM,.submit=refusing_submit};
  s.st[0].cls=&refusalops;synchronous_refusal=!strcmp(mode,"sync_refuse");
  assert(!xdev_ext_mech_completion_cancel(&b.completion,b.ticket));
  s.pool.state[0]=XDEV_EXT_MECH_F_HELD;b.bs.state=XDEV_EXT_MECH_B_READY;
  int r=xdev_ext_mech_submit(&s,&s.st[0],&b);
  if(synchronous_refusal) {
   CHECK(r==0&&s.submitted[0]==1&&queues==1,"sync accepted completion lost against negative submit return");
   CHECK(b.transform.active&&s.pool.state[10]==XDEV_EXT_MECH_F_INFLIGHT,"sync completion prematurely rolled back destination");
  } else {
   CHECK(r==-EAGAIN&&s.submitted[0]==0,"preaccept refusal was counted as accepted");
   CHECK(!b.transform.active&&s.pool.state[10]==XDEV_EXT_MECH_F_HELD&&xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_FREE,"preaccept refusal stranded destination lease");
   CHECK(s.pool.state[0]==XDEV_EXT_MECH_F_HELD&&xdev_ext_mech_life_phase(&s.life[0])==XDEV_EXT_MECH_L_OUT_PENDING,"submit refusal changed outer source lifecycle ownership");
   CHECK(xdev_ext_mech_submit(&s,&s.st[0],&b)==-EAGAIN,"preaccept retry cannot reacquire destination lease");
  }
  return !!failures;
 }
 struct xdev_ext_mech_frame dst[]={frame(10,FS),frame(11,FS),frame(12,FS)};
 u32 nr=!strcmp(mode,"partial_tail")?3:2;
 bool invalid=false;
 if(!strcmp(mode,"alias")){page_map[10]=page_map[0];invalid=true;}
 if(!strcmp(mode,"duplicate_dst")){dst[1]=dst[0];invalid=true;}
 if(!strcmp(mode,"wrong_stage")){s.transform_owner[11]=2;invalid=true;}
 if(!strcmp(mode,"busy_dst")){u64 t;assert(!xdev_ext_mech_life_begin_produce(&s.life[11],false,&t));invalid=true;}
 if(!strcmp(mode,"resolve_fail")){resolve_fail_index=11;invalid=true;}
 if(!strcmp(mode,"short_source")){s.life[0].valid_len=699;invalid=true;}
 if(!strcmp(mode,"source_ready")){assert(!xdev_ext_mech_life_complete_consume(&s.life[0],xdev_ext_mech_life_token(&s.life[0])));invalid=true;}
 int ret=xdev_ext_mech_batch_transform_begin(&b,dst,nr);
 if(invalid) {
  CHECK(ret<0,"invalid transform lease was accepted");CHECK(!b.transform.active,"invalid transform marked lease active");
  CHECK(s.pool.state[10]==XDEV_EXT_MECH_F_HELD&&s.pool.state[11]==XDEV_EXT_MECH_F_HELD,"failed begin leaked destination custody");
  CHECK(xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_FREE,"failed begin left first destination producer active");
  CHECK(xdev_ext_mech_life_phase(&s.life[0])==(!strcmp(mode,"source_ready")?XDEV_EXT_MECH_L_READY:XDEV_EXT_MECH_L_OUT_PENDING),"begin failure released source before outer rollback");return !!failures;
 }
 CHECK(!ret,"valid transform lease was refused");if(ret)return 1;
 CHECK(xdev_ext_mech_life_phase(&s.life[0])==XDEV_EXT_MECH_L_OUT_PENDING,"begin released source read lease");
 if(!strcmp(mode,"pending")) {
  xdev_ext_mech_transform_unreserve(&s.st[0],10,2);
  CHECK(s.transform_owner[10]==1&&s.pool.state[10]==XDEV_EXT_MECH_F_INFLIGHT,"unbind recycled pending destination");
  CHECK(s.pool.state[0]==XDEV_EXT_MECH_F_INFLIGHT&&!released[0],"pending request released source");return !!failures;
 }
 bool unknown=!strcmp(mode,"unknown");
 u32 produced=!strcmp(mode,"partial_tail")?FS+37:!strcmp(mode,"zero")?0:!strcmp(mode,"overcap")?2*FS+1:173;
 if(!strcmp(mode,"stale")) {
  xdev_ext_mech_batch_transform_complete(&b,b.ticket+1,0,999,false);
  CHECK(!b.transform.produced&&!queues,"stale completion changed result or queued work");
 }
 xdev_ext_mech_batch_transform_complete(&b,b.ticket,unknown?-ETIMEDOUT:!strcmp(mode,"native_error")?-EIO:0,produced,unknown);
 if(!strcmp(mode,"duplicate"))xdev_ext_mech_batch_transform_complete(&b,b.ticket,-EIO,999,true);
 CHECK(queues==1,"callback was delivered more than once");
 CHECK(!xdev_ext_mech_completion_consume(&b.completion,b.ticket,&b.status),"winning completion not consumable");
 CHECK(b.sequester==unknown,"duplicate/stale callback changed quarantine metadata");
 source_landed(&b,unknown);
 if(!strcmp(mode,"second_source_return_failure")) {
  assert(!xdev_ext_mech_pool_frame_move(&s.pool,1,XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_HELD));
  assert(!xdev_ext_mech_life_complete_consume(&s.life[1],xdev_ext_mech_life_token(&s.life[1])));
  fail_source_return_index=1;
 }
 if(!strcmp(mode,"release_failure"))fail_source_return_index=0;
 if(!strcmp(mode,"destination_generation"))s.life[11].ctrl+=8;
 bool seq=xdev_ext_mech_transform_landed(&s,&b,unknown);
 if(!strcmp(mode,"second_source_return_failure")) {
  CHECK(seq&&b.transform.active,"partial source return did not report retained transform lease");
  CHECK(s.pool.state[0]==XDEV_EXT_MECH_F_K_FREE&&released[0]==1&&xdev_ext_mech_life_phase(&s.life[0])==XDEV_EXT_MECH_L_FREE,"safe completed first source was unnecessarily retained or returned twice");
  CHECK(s.pool.state[1]==XDEV_EXT_MECH_F_HELD&&!released[1]&&xdev_ext_mech_life_phase(&s.life[1])==XDEV_EXT_MECH_L_FREE,"failed second source return was recycled or lost custody");
  CHECK(s.pool.state[10]==XDEV_EXT_MECH_F_SEQUESTERED&&s.pool.state[11]==XDEV_EXT_MECH_F_SEQUESTERED,"partial source return failed to quarantine every destination");
  CHECK(b.f[0].index==0&&b.f[1].index==1&&b.nr_frames==2&&b.bytes==1400,"partial source return advanced batch metadata");
 } else if(!strcmp(mode,"release_failure")||!strcmp(mode,"destination_generation")) {
  CHECK(seq,"ownership/generation failure did not quarantine transform");
  CHECK(s.pool.state[0]==XDEV_EXT_MECH_F_SEQUESTERED&&s.pool.state[10]==XDEV_EXT_MECH_F_SEQUESTERED&&s.pool.state[11]==XDEV_EXT_MECH_F_SEQUESTERED,"ownership/generation failure failed to quarantine both sets");
  CHECK(!released[0]&&b.f[0].index==0&&b.bytes==700,"unsafe transform released old source or advanced batch");
 } else if(unknown) {
  CHECK(seq&&b.transform.active,"unknown completion dropped retained lease");
  CHECK(s.pool.state[0]==XDEV_EXT_MECH_F_SEQUESTERED&&s.pool.state[10]==XDEV_EXT_MECH_F_SEQUESTERED&&s.pool.state[11]==XDEV_EXT_MECH_F_SEQUESTERED,"unknown did not quarantine both frame sets");
  CHECK(!released[0]&&xdev_ext_mech_life_phase(&s.life[0])==XDEV_EXT_MECH_L_OUT_PENDING&&xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_IO_PENDING,"unknown retired or published active lifecycle");
 } else if(!strcmp(mode,"zero")||!strcmp(mode,"overcap")||!strcmp(mode,"native_error")) {
  CHECK(b.status<0&&!seq,"invalid produced did not become definitive failure");
  CHECK(b.f[0].index==0&&b.bytes==700,"failed output advanced batch metadata");
  CHECK(xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_FREE&&!synced[10],"invalid output published destination READY");
 } else {
  CHECK(!seq&&!b.status&&!b.transform.active,"valid short completion failed");
  CHECK(b.bytes==produced&&xdev_ext_mech_batch_transform_produced(&b)==produced,"actual produced was replaced by fixed input/capacity");
  CHECK(b.f[0].index==10&&b.nr_frames==(produced>FS?2:1),"batch did not replace source with cropped output set");
  CHECK(s.life[10].valid_len==min(produced,FS)&&xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_READY&&synced[10]==1,"first output lacks exact length or DMA sync");
  CHECK(released[0]==1&&xdev_ext_mech_life_phase(&s.life[0])==XDEV_EXT_MECH_L_FREE,"definitive success did not release old source");
  u32 unused=produced>FS?12:11;
  CHECK(xdev_ext_mech_life_phase(&s.life[unused])==XDEV_EXT_MECH_L_FREE&&s.pool.state[unused]==XDEV_EXT_MECH_F_HELD&&!released[unused],"unused output frame escaped stage reservation");
  if(produced>FS)CHECK(b.f[1].data_len==37&&s.life[11].valid_len==37,"last output frame was not cropped to produced remainder");
 }
 return !!failures;
}

// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t __u16;typedef uint32_t u32;typedef uint64_t u64;
typedef uint32_t __u32;typedef uint64_t __u64;typedef int32_t s32;typedef int spinlock_t;
#define XDEV_EXT_MP_HOLD 4
#define XDEV_EXT_MP_RECYCLE 6
#define XDEV_EXT_MP_GROUP_TIMEOUT_NS 1000000000ULL
#define XDEV_EXT_MECH_HOLD 4
#define XDEV_EXT_MECH_PUBLISH 5
#define XDEV_EXT_MECH_RECYCLE 6
#define XDEV_EXT_MECH_ABORT 3
#define XDEV_EXT_MECH_SITE_RX_NATIVE 2
#define XDEV_EXT_MECH_SITE_RX_HOLD_RESULT 5
#define XDEV_EXT_REL_HOLD 1
#define XDEV_EXT_MECH_CNT_NATIVE_PUBLISH 0
#define XDEV_EXT_MECH_CNT_PROTOCOL_ERR 1
#define XDEV_EXT_MECH_F_USER 0
#define XDEV_EXT_MECH_F_K_FREE 1
#define XDEV_EXT_MECH_F_HELD 2
#define XDEV_EXT_MECH_F_NIC_RX 5
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))
#define spin_lock_irqsave(p,f) do { (f)=0; if((*(p))++) abort(); }while(0)
#define spin_unlock_irqrestore(p,f) do { (void)(f);if(--(*(p)))abort(); }while(0)
struct xdev_ext_mech_hold_intent {u64 key;u32 pos,count,span_off,span_len;};
struct xdev_ext_mech_frame {void *kaddr,*pool_priv;u64 umem_addr;u32 index,data_off,data_len;};
/* PENDING_TYPES */
/* PROTOCOL */
struct xsk_xdev_ext_mech_stage {void *rel;bool dead; /* PENDING_MEMBER */ };
struct xdev_ext_mech_pool {u32 nr_frames;u8 state[4096];};
struct list_head {int boundary;};
struct xdev_ext_mech_batch {struct list_head node;int bs;u64 id,key,bytes;int abort_err,status;u32 present,nr_frames,life_active;bool sequester,to_user,fifo_accepted;};
struct xdev_ext_mech_session {bool admits;struct xdev_ext_mech_pool *pool;struct list_head free;int ss,nr_stages;u64 next_batch_id;};
struct xdev_ext_mech_stage {struct xsk_xdev_ext_mech_stage *priv;struct xdev_ext_mech_session *s;};
struct xdp_sock {struct xdev_ext_mech_stage *xdev_ext_mech_rx,*xdev_ext_mech_tx;bool zc;struct xdev_ext_mech_pool *pool;};
struct xdp_buff_xsk {u32 index,data_off;};
struct xdev_ext_rel_msg {u64 group;u32 index,count,payload_len;};
struct xdev_ext_afxdp_rx_hold_cqe {u64 key;u32 pos;int err;};
static struct xdev_ext_mp_rx_order order,candidate;
static u32 held,completed,recycled,kicks,busy,expected_key=1,expected_pos;
static u32 owned[4096],owned_count;
static int last_err;
static bool stop_during_commit;
static int begin_error;
static struct xdev_ext_mech_batch free_batch;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return s->pool;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s){return s->admits;}
static u32 xdev_ext_mech_pool_frame_state(struct xdev_ext_mech_pool *p,u32 i){return i<p->nr_frames?p->state[i]:99;}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p,u32 i,u32 from,u32 to){if(i>=p->nr_frames||p->state[i]!=from)return -EBUSY;p->state[i]=to;return 0;}
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err){if(!last_err)last_err=err;st->s->admits=false;st->priv->dead=true;}
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st){(void)st;kicks++;}
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s,int counter,u64 n){(void)s;(void)counter;(void)n;}
static void xdev_ext_mech_frame_recycle(struct xdev_ext_mech_session *s,struct xdev_ext_mech_frame *f){if(s->pool->state[f->index]!=XDEV_EXT_MECH_F_NIC_RX)abort();s->pool->state[f->index]=XDEV_EXT_MECH_F_K_FREE;recycled++;}
static int xsk_xdev_ext_mech_pool_resolve(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_frame *f){if(f->index>=p->nr_frames)return -ERANGE;f->kaddr=(void *)(uintptr_t)(f->index+1);return 0;}
static void xsk_xdev_ext_mech_frame(struct xdev_ext_mech_pool *p,struct xdp_buff_xsk *b,struct xdev_ext_mech_frame *f){(void)p;*f=(struct xdev_ext_mech_frame){.index=b->index,.data_off=b->data_off};}
static int xsk_rel_rx(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_frame *f,struct xdev_ext_rel_msg *m){(void)st;(void)f;(void)m;abort();}
static int xsk_rel_hold_commit(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_hold_intent *h,const struct xdev_ext_mech_frame *f){(void)st;(void)h;(void)f;abort();}
static bool xsk_xdev_ext_mech_rx_runs(u32 site,bool active,bool zc){(void)site;(void)zc;return active;}
static int xsk_xdev_ext_mech_rx_call(struct xdev_ext_mech_stage *st,struct xsk_xdev_ext_mech_stage *xst,const struct xdev_ext_mech_frame *f,u32 site,s32 *ret,struct xdev_ext_mech_hold_intent *h,const struct xdev_ext_afxdp_rx_hold_cqe *cqe){
 (void)st;(void)xst;
 if(site==XDEV_EXT_MECH_SITE_RX_HOLD_RESULT){if(!cqe->err)order=candidate;*ret=cqe->err?XDEV_EXT_MECH_RECYCLE:XDEV_EXT_MECH_HOLD;return 0;}
 struct xdev_ext_mp_segment seg={.generation=f->index/6+1,.index=f->index%6,.count=6,.relative_offset=(f->index%6)*100,.payload_len=100,.total_len=600};
 candidate=order;*ret=xdev_ext_mp_rx_order(&candidate,&seg,1);
 if(*ret==XDEV_EXT_MECH_HOLD)*h=(struct xdev_ext_mech_hold_intent){.key=seg.generation,.pos=seg.index,.count=6,.span_off=f->data_off,.span_len=100};
 return 0;
}
static int xsk_xdev_ext_mech_rx_verdict(u32 site,bool ran,int err,s32 ret,const struct xdev_ext_mech_hold_intent *h,u32 off,u32 len,bool *perr,bool *npub){(void)site;(void)h;(void)off;(void)len;*perr=false;*npub=false;return ran&&!err?ret:XDEV_EXT_MECH_PUBLISH;}
static int xsk_xdev_ext_mech_rx_hold_result(int admission,int err,s32 ret,bool *perr){(void)ret;*perr=!!err;return admission?XDEV_EXT_MECH_RECYCLE:XDEV_EXT_MECH_HOLD;}
/* Native list availability and lifecycle initialization are scheduling seams.
 * The exact production core function decides the errno for an empty free list.
 */
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define list_first_entry_or_null(head,type,member) (busy<8?&free_batch:NULL)
static void list_del_init(struct list_head *node){(void)node;}
static int xdev_ext_mech_sess_batch_begin(int *ss){(void)ss;return begin_error;}
static void xdev_ext_mech_bstate_init(int *bs,int stages){*bs=stages;}
/* CORE_BATCH_GET */
/* Hold/frame admission remains a controlled external core boundary. */
static int xdev_ext_mech_hold_commit(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_hold_intent *h,const struct xdev_ext_mech_frame *f){
 if(stop_during_commit){st->s->admits=false;return -ESHUTDOWN;}
 if(!st->s->admits)return -ESHUTDOWN;
 if(!h->pos){struct xdev_ext_mech_batch *b=xdev_ext_mech_batch_get_locked(st->s);if(IS_ERR(b))return PTR_ERR(b);}
 if(h->key!=expected_key||h->pos!=expected_pos)return -EPROTO;
 if(st->s->pool->state[f->index]!=XDEV_EXT_MECH_F_NIC_RX)return -EBUSY;
 st->s->pool->state[f->index]=XDEV_EXT_MECH_F_HELD;owned[owned_count++]=f->index;held++;
 if(!h->pos)busy++;
 if(++expected_pos==6){expected_pos=0;expected_key++;}return 0;
}
/* PENDING_FUNCTIONS */
/* RX_FUNCTION */
static u32 pending_count(struct xdp_sock *xs){(void)xs;/* PENDING_COUNT */}
static void progress(struct xdp_sock *xs,bool stop){struct xdev_ext_mech_stage st=*xs->xdev_ext_mech_rx;(void)st;/* PROGRESS */}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line=%d expression=%s held=%u completed=%u recycled=%u pending=%u last_err=%d\n",__LINE__,#x,held,completed,recycled,pending_count(&xs),last_err);return 1;}}while(0)
static void retire(struct xdp_sock *xs){for(u32 i=0;i<owned_count;i++){if(xs->pool->state[owned[i]]!=XDEV_EXT_MECH_F_HELD)abort();xs->pool->state[owned[i]]=XDEV_EXT_MECH_F_K_FREE;}owned_count=0;completed+=busy;busy=0;}
int main(int argc,char **argv){
 if(argc!=2)return 2;
 struct xdev_ext_mech_pool pool={.nr_frames=4096};
 struct xdev_ext_mech_session session={.admits=true,.pool=&pool};
 struct xsk_xdev_ext_mech_stage xst={0};struct xdev_ext_mech_stage st={.priv=&xst,.s=&session};
 struct xdp_sock xs={.xdev_ext_mech_rx=&st,.pool=&pool,.zc=true};
 u32 capacity=!strcmp(argv[1],"full")?6:2000;(void)capacity;
 /* INITIALIZE */
 if(!strcmp(argv[1],"flow")){
  for(u32 i=0;i<257*6;i++){struct xdp_buff_xsk f={.index=i};pool.state[i]=XDEV_EXT_MECH_F_NIC_RX;CHECK(xsk_xdev_ext_mech_rx(&xs,&f,100,2)==XDEV_EXT_MECH_HOLD);}
  CHECK(pending_count(&xs)==257*6&&!held&&!recycled);
  for(u32 n=0;pending_count(&xs)&&n<1000;n++){progress(&xs,false);retire(&xs);}
  CHECK(!pending_count(&xs)&&completed==257&&held==257*6&&!last_err&&!recycled);
 }else{
  u32 count=!strcmp(argv[1],"full")?7:6;
  for(u32 i=0;i<count;i++){struct xdp_buff_xsk f={.index=i};pool.state[i]=XDEV_EXT_MECH_F_NIC_RX;xsk_xdev_ext_mech_rx(&xs,&f,100,2);}
  if(!strcmp(argv[1],"full")){CHECK(last_err==-EOVERFLOW&&pending_count(&xs)==6&&recycled==1);progress(&xs,true);CHECK(!pending_count(&xs)&&recycled==7&&!held);}
  else if(!strcmp(argv[1],"stop")){session.admits=false;progress(&xs,true);progress(&xs,true);CHECK(!pending_count(&xs)&&recycled==6&&!held&&!last_err);}
  else if(!strcmp(argv[1],"again")){begin_error=-EAGAIN;progress(&xs,false);CHECK(pending_count(&xs)==6&&!held&&!last_err);begin_error=0;progress(&xs,false);retire(&xs);CHECK(!pending_count(&xs)&&held==6&&completed==1&&!last_err);}
  else if(!strcmp(argv[1],"stop-race")){stop_during_commit=true;progress(&xs,false);CHECK(!pending_count(&xs)&&recycled==6&&!held&&!last_err);}
  else if(!strcmp(argv[1],"stale")){pool.state[0]=XDEV_EXT_MECH_F_HELD;progress(&xs,false);CHECK(last_err==-EPROTO&&pool.state[0]==XDEV_EXT_MECH_F_HELD);progress(&xs,true);CHECK(!pending_count(&xs)&&recycled==5);}
  else if(!strcmp(argv[1],"duplicate")){struct xdp_buff_xsk f={.index=0};/* The real RX entry must guard ownership before order rejects it. */
   (void)f;/* DUPLICATE */
   CHECK(last_err==-EPROTO&&pool.state[0]==XDEV_EXT_MECH_F_NIC_RX&&pending_count(&xs)==6&&!recycled);progress(&xs,true);CHECK(recycled==6);
  }else return 2;
 }
 return 0;
}

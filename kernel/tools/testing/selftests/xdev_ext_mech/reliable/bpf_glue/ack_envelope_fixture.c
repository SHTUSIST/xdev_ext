// SPDX-License-Identifier: GPL-2.0
/* Kernel primitives and invocation admission are host boundaries; all named
 * extracted production bodies and BPF code below remain unchanged. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmlinux.h"
#include PROGRAM
#include "io_uring/xdev_ext_policy.h"
#include "include/linux/xdev_ext_binding.h"
#include "net/xdp/xsk_xdev_ext_mech_tx_core.h"
typedef __u8 u8; typedef __u32 u32; typedef __u64 u64; typedef __s32 s32;
#define __bpf_kfunc
#define PF_XDP 44
#define XSK_BOUND 1
#define GFP_KERNEL 0
#define READ_ONCE(x) (x)
#define data_race(x) ((void)(x))
#define spin_lock_init(x) ((void)(x))
#define spin_lock_irqsave(l,f) do {(void)(l);(f)=0;}while(0)
#define spin_unlock_irqrestore(l,f) do {(void)(l);(void)(f);}while(0)
#define mutex_lock(x) ((void)(x))
#define mutex_unlock(x) ((void)(x))
#define kzalloc(n,g) calloc(1,n)
#define kvcalloc(n,s,g) calloc(n,s)
#define kfree(p) free(p)
#define kvfree(p) free(p)
struct xdev_ext_mech_stage;
struct xdp_sock;
struct sock {int sk_family; struct xdp_sock *owner;};
struct socket {struct sock *sk;};
struct net_device {u32 mtu;};
struct xdp_sock {int mutex,state; bool zc,tx,rx; struct net_device *dev; struct xdev_ext_mech_stage *xdev_ext_mech_tx,*xdev_ext_mech_rx;};
struct xdev_ext_mech_pool {void *priv; const void *ops; u32 nr_frames;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool *pool; struct xdev_ext_mech_layout l; struct xdev_ext_mech_peer peer; u64 id;};
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s; void *priv,*file; u32 direction,index; bool poll;};
struct xdev_ext_mech_frame {u64 umem_addr;u32 index,data_off,data_len;void *kaddr,*pool_priv;};
struct xdev_ext_mech_batch {u64 key; struct xdev_ext_mech_stage *st;};
struct xsk_rel_rx_intent {u64 group;u32 index,attempt;u8 calls,valid;};
struct xsk_mech_reliable {struct xsk_rel_rx_intent rx_intent; struct xdev_ext_rel_policy policy; struct xdev_ext_rel_tx tx;struct xdev_ext_rel_rx rx;u64 ack_pending[32],owed_since[32],nr_groups;u8 owed_dup[32];bool build_must;};
struct xsk_xdev_ext_mech_stage {struct xdp_sock *xs;struct socket *sock;struct {int lock;u32 capacity;int *entries;}pending;u32 mtu,tx_nr_sent;int *tx_sent;struct xsk_mech_reliable *rel;struct xdev_ext_afxdp_reliable_info rx_info;};
struct xsk_xdev_ext_mech_provider {struct xdp_sock *xs;bool zc;u32 source_first;int tx_lock;};
/* ACTUAL_CALL_STRUCTS */
static const int xsk_xdev_ext_mech_pool_ops;
static struct xdev_ext_mech_call active;
static unsigned kicks,dead_calls,publication_count;
static int reliable_bind_error;
static int publication_release,publication_envelope;
static struct xdev_ext_rel_cfg cfg={.session=9,.first_group=1,.timeout_ns=100,.window=4,.max_attempts=8,.group_bytes=8192,.seg_len=1408};
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return s->pool;}
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s){return &s->l;}
static const struct xdev_ext_mech_peer *xdev_ext_mech_session_peer(struct xdev_ext_mech_session *s){return &s->peer;}
static u64 xdev_ext_mech_session_id(struct xdev_ext_mech_session *s){return s->id;}
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s){(void)s;return 4;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b){(void)b;return 0;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 i,struct xdev_ext_mech_frame *f){(void)b;(void)i;(void)f;return -ENOENT;}
static u64 xdev_ext_mech_batch_key(struct xdev_ext_mech_batch *b){return b->key;}
static struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(struct xdev_ext_mech_batch *b){return b->st;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s){(void)s;return true;}
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err){(void)st;(void)err;dead_calls++;}
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st){(void)st;kicks++;}
/* No stage here asks for polling; ../../poll tests the AF_XDP poll bind. */
struct xsk_xdev_ext_mech_stage;
static int xsk_mech_poll_bind(struct xsk_xdev_ext_mech_stage *xst,struct xdp_sock *xs,bool tx,bool reliable){(void)xst;(void)xs;(void)tx;(void)reliable;abort();}
static u64 ktime_get_ns(void){return 1000;}
static struct socket *sock_from_file(void *f){return f;}
static struct xdp_sock *xdp_sk(struct sock *s){return s->owner;}
static int xsk_rel_bind(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_stage_uapi *u){
 (void)u;struct xsk_xdev_ext_mech_stage *xst=st->priv;
 if (reliable_bind_error) return reliable_bind_error;
 xst->rel=calloc(1,sizeof(*xst->rel)); if(!xst->rel)return -ENOMEM;
 if(xdev_ext_rel_tx_init(&xst->rel->tx,&cfg)||xdev_ext_rel_rx_init(&xst->rel->rx,&cfg))abort();
 xdev_ext_rel_policy_from_legacy(&xst->rel->policy,4,100,8);return 0;
}
static bool envelope_valid(const struct xdev_ext_afxdp_reliable_info *in){return in->wire_session==9 && in->base.l.group_bytes==8192 && in->base.l.seg_len==1408 && in->base.l.frame_size==4096 && in->base.nr_frames==1 && in->base.mtu==1500 && in->base.peer.local_mac[5]==1 && in->base.peer.peer_mac[5]==2;}
static void publish(struct xdev_ext_mech_stage **where,struct xdev_ext_mech_stage *st,int release){
 publication_count++;publication_release=release;publication_envelope=envelope_valid(&((struct xsk_xdev_ext_mech_stage*)st->priv)->rx_info);*where=st;
}
#define WRITE_ONCE(where,st) publish(&(where),(st),0)
#define smp_store_release(where,st) publish((where),(st),1)
static struct xdev_ext_mech_call *xdev_ext_mech_call_of(const struct xdev_ext_mech_ctx *ctx){return ctx==&active.ctx?&active:NULL;}
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *,const struct xdev_ext_mech_call_args *,s32 *,struct xdev_ext_mech_hold_intent *);
static __u32 crc32(__u32,const void *,size_t);
#define crc32c crc32
static void xp_dma_sync_for_cpu(void *p){(void)p;abort();}
/* ACTUAL_PROTOTYPES */
/* ACTUAL_FUNCTIONS */
static __u32 crc32(__u32 crc,const void *buf,size_t n){const u8 *p=buf;while(n--){crc^=*p++;for(int i=0;i<8;i++)crc=(crc>>1)^(0x82f63b78U&(0U-(crc&1)));}return crc;}
__u64 bpf_ktime_get_ns(void){return 1000;}
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c,const size_t n){return c==&active.ctx&&n==active.info_size?(u8*)active.info:NULL;}
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c,__u32 slot,const size_t n){return c==&active.ctx&&slot<active.desc_cap&&n==sizeof(struct xdp_desc)?active.scratch+slot*n:NULL;}
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c,__u32 slot,const size_t n){return c==&active.ctx&&!slot&&n==active.cqe_size?(u8*)active.cqe:NULL;}
__u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *c,__u32 pos,__u32 off,const size_t n){return c==&active.ctx&&pos<active.nr_frames&&off<=4096&&n<=4096-off?(u8*)active.frames[pos].kaddr+off:NULL;}
__u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *c,__u32 pos,__u32 off,const size_t n){return bpf_xdev_ext_frame(c,pos,off,n);}
__u32 bpf_xdev_ext_crc32c(const void *p,__u32 n,__u32 seed){return crc32(seed,p,n);}
__u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *c,__u32 pos,__u32 off,__u32 n,__u32 seed){const u8 *p=bpf_xdev_ext_frame(c,pos,off,n);return p?crc32(seed,p,n):0;}
__u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *c,const size_t n){(void)c;(void)n;return NULL;}
int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *c,__u64 key,__u32 pos,__u32 off,__u32 len){(void)c;(void)key;(void)pos;(void)off;(void)len;return -EOPNOTSUPP;}
__u8 *bpf_xdev_ext_rel_tx_view(const struct xdev_ext_mech_ctx *c,const size_t n){(void)c;(void)n;return NULL;}
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_call_args *a,s32 *ret,struct xdev_ext_mech_hold_intent *hold){
 (void)hold;active=(struct xdev_ext_mech_call){.st=st,.member=a->member,.callsite=a->callsite,.info=a->info,.info_size=a->info_size,.frames=a->frames,.nr_frames=a->nr_frames,.cqe=a->cqe,.cqe_size=a->cqe_size,.scratch=a->scratch,.desc_cap=a->desc_cap};
 active.ctx.class_id=XDEV_EXT_MECH_CLASS_AFXDP;active.ctx.callsite=a->callsite;active.ctx.nr_frames=a->nr_frames;
 active.ctx.base=*a->base;
 *ret=rel_afxdp_complete(NULL,&active.ctx);return active.protocol_error?-EPROTO:0;
}
static unsigned checks,failures;
#define CHECK(label,x) do{checks++;if(!(x)){failures++;printf("FAIL %s\n",label);}else printf("PASS %s\n",label);}while(0)
struct fixture {struct net_device dev;struct xdp_sock xs;struct sock sk;struct socket sock;struct xsk_xdev_ext_mech_provider provider;struct xdev_ext_mech_pool pool;struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;};
static void setup(struct fixture *f,bool tx){
 memset(f,0,sizeof(*f));f->dev.mtu=1500;f->xs=(struct xdp_sock){.state=XSK_BOUND,.tx=true,.rx=true,.dev=&f->dev};f->sk=(struct sock){.sk_family=PF_XDP,.owner=&f->xs};f->sock.sk=&f->sk;
 f->provider.xs=&f->xs;f->pool=(struct xdev_ext_mech_pool){.priv=&f->provider,.ops=&xsk_xdev_ext_mech_pool_ops,.nr_frames=128};
 f->s=(struct xdev_ext_mech_session){.pool=&f->pool,.l={.frame_size=4096,.hdr_room=384,.group_bytes=8192,.seg_len=1408},.id=123};
 f->s.peer=(struct xdev_ext_mech_peer){.local_mac={2,0,0,0,0,1},.peer_mac={2,0,0,0,0,2},.local_ip=0x0100000a,.peer_ip=0x0200000a,.local_port=0x3412,.peer_port=0x7856};
 f->st=(struct xdev_ext_mech_stage){.s=&f->s,.file=&f->sock,.direction=tx?XDEV_EXT_MECH_DIR_TO_DEVICE:XDEV_EXT_MECH_DIR_FROM_DEVICE};
 struct xdev_ext_mech_stage_uapi u={.flags=XDEV_EXT_AFXDP_F_RELIABLE};CHECK("actual_bind_success",xsk_xdev_ext_mech_bind(&f->st,&u)==0);
 CHECK("published_once",publication_count==1);publication_count=0;
 CHECK(tx?"TX_release_publication":"RX_release_publication",publication_release==1);
 CHECK(tx?"TX_envelope_valid_at_publication":"RX_envelope_valid_at_publication",publication_envelope);
}
static void cleanup(struct fixture *f){struct xsk_xdev_ext_mech_stage *x=f->st.priv;free(x->pending.entries);free(x->rel);free(x->tx_sent);free(x);}
static void open_sender(struct fixture *f){struct xsk_mech_reliable *r=((struct xsk_xdev_ext_mech_stage*)f->st.priv)->rel;
 memset(&r->rx_intent,0,sizeof(r->rx_intent));CHECK("tx_init",!xdev_ext_rel_tx_init(&r->tx,&cfg));CHECK("real_open",xdev_ext_rel_tx_open(&r->tx,1,8192,6)==XDEV_EXT_REL_SEND);CHECK("real_native_begin",xdev_ext_rel_tx_native_begin(&r->tx,1,10)==XDEV_EXT_REL_SEND);CHECK("real_native_done",xdev_ext_rel_tx_native_done(&r->tx,1,1,0,false,20)==XDEV_EXT_REL_NONE);
}
static void reverse_peer(struct xdev_ext_mech_peer *p){
 u8 mac[6];memcpy(mac,p->local_mac,6);memcpy(p->local_mac,p->peer_mac,6);memcpy(p->peer_mac,mac,6);
 u32 ip=p->local_ip;p->local_ip=p->peer_ip;p->peer_ip=ip;
 __u16 port=p->local_port;p->local_port=p->peer_port;p->peer_port=port;
}

/* Exercise the same bind body without a reliable provider and on failure.
 * Only reliable resource registration is a fixture boundary; this ensures its
 * error does not publish a partially initialized callback view. */
static void init_bind_fixture(struct fixture *f, bool tx)
{
 memset(f, 0, sizeof(*f));
 f->dev.mtu = 1500;
 f->xs = (struct xdp_sock) { .state = XSK_BOUND, .tx = true, .rx = true, .dev = &f->dev };
 f->sk = (struct sock) { .sk_family = PF_XDP, .owner = &f->xs };
 f->sock.sk = &f->sk;
 f->provider.xs = &f->xs;
 f->pool = (struct xdev_ext_mech_pool) { .priv = &f->provider,
  .ops = &xsk_xdev_ext_mech_pool_ops, .nr_frames = 128 };
 f->s = (struct xdev_ext_mech_session) { .pool = &f->pool,
  .l = { .frame_size = 4096, .hdr_room = 384, .group_bytes = 8192, .seg_len = 1408 },
  .peer = { .local_mac = { 2, 0, 0, 0, 0, 1 }, .peer_mac = { 2, 0, 0, 0, 0, 2 } } };
 f->st = (struct xdev_ext_mech_stage) { .s = &f->s, .file = &f->sock,
  .direction = tx ? XDEV_EXT_MECH_DIR_TO_DEVICE : XDEV_EXT_MECH_DIR_FROM_DEVICE };
}
static void nonreliable_and_failed_bind(void)
{
 for (unsigned tx = 0; tx < 2; tx++) {
  struct fixture f;
  struct xdev_ext_mech_stage_uapi u = {};
  struct xsk_xdev_ext_mech_stage *x;

  init_bind_fixture(&f, tx);
  publication_count = 0;
  CHECK("nonreliable_bind", !xsk_xdev_ext_mech_bind(&f.st, &u));
  x = f.st.priv;
  CHECK("nonreliable_no_reliable_state", !x->rel);
  CHECK("nonreliable_published_once", publication_count == 1 && publication_release);
  CHECK("nonreliable_direction", tx ? f.xs.xdev_ext_mech_tx == &f.st :
   f.xs.xdev_ext_mech_rx == &f.st);
  CHECK("nonreliable_layout", !memcmp(&x->rx_info.base.l, &f.s.l, sizeof(f.s.l)));
  CHECK("nonreliable_peer", !memcmp(&x->rx_info.base.peer, &f.s.peer, sizeof(f.s.peer)));
  CHECK("nonreliable_frame_and_session", x->rx_info.base.nr_frames == 1 &&
   x->rx_info.base.mtu == 1500 && !x->rx_info.wire_session);
  cleanup(&f);

  init_bind_fixture(&f, tx);
  publication_count = 0;
  reliable_bind_error = -EIO;
  u.flags = XDEV_EXT_AFXDP_F_RELIABLE;
  CHECK("failed_bind_error_preserved", xsk_xdev_ext_mech_bind(&f.st, &u) == -EIO);
  CHECK("failed_bind_no_publication", !publication_count &&
   !f.xs.xdev_ext_mech_tx && !f.xs.xdev_ext_mech_rx);
  CHECK("failed_bind_no_private_state", !f.st.priv);
  reliable_bind_error = 0;
 }
}

int main(void){
 struct fixture rx,tx;u8 chunk[4096]={};struct xdp_desc d={};struct xdev_ext_mech_frame frame={.kaddr=chunk,.data_off=278,.data_len=106};
 setup(&rx,false);struct xsk_mech_reliable *rr=((struct xsk_xdev_ext_mech_stage*)rx.st.priv)->rel;
 for(u32 i=0;i<6;i++)CHECK("actual_claim_data",xdev_ext_rel_rx_claim(&rr->rx,1,i,1)==(i==5?XDEV_EXT_REL_SUBMIT:XDEV_EXT_REL_HOLD));
 CHECK("not_ack_before_native_completion",!rr->ack_pending[1]);
 struct xdev_ext_mech_batch batch={.key=1,.st=&rx.st};xsk_rel_batch_end(&rx.st,&batch,0);
 CHECK("actual_native_completion_owes_ack",rr->ack_pending[1]==1&&rr->rx.entry[1].state==XDEV_EXT_REL_RX_DONE);
 struct xdev_ext_afxdp_reliable_info build;
 xsk_xdev_ext_mech_fill_info(&rx.st,NULL,&build);build.wire_group=1;build.base.nr_frames=1;build.base.f[0]=(struct xdev_ext_mech_frame_info){.data_off=384};
 active=(struct xdev_ext_mech_call){.st=&rx.st,.member=XDEV_EXT_MECH_MEMBER_BUILD,.callsite=XDEV_EXT_MECH_SITE_WORKER,.info=&build,.info_size=sizeof(build),.frames=&frame,.nr_frames=1,.scratch=(u8*)&d,.desc_cap=1};active.ctx.class_id=XDEV_EXT_MECH_CLASS_AFXDP;active.ctx.callsite=XDEV_EXT_MECH_SITE_WORKER;
 CHECK("actual_bpf_build_ack",rel_afxdp_build(NULL,&active.ctx)==XDEV_EXT_MP_BUILD_SUBMIT);
 CHECK("ack_descriptor_bounds",d.addr==278&&d.len==106);
 CHECK("actual_packet_identity_and_crc",!xsk_rel_packet_check(&rx.st,&d,&build.base.f[0],chunk,1,0,0,0,0));
 xsk_xdev_ext_mech_tx_finish(chunk+278);
 u32 crc;u8 hdr[64];memcpy(hdr,chunk+320,64);memset(hdr+56,0,4);crc=crc32(~0U,hdr,64);
 struct xdev_ext_rel_msg msg={};CHECK("actual_wire_decode_ack",!xdev_ext_rel_wire_decode(chunk+320,0,crc,&cfg,&msg)&&msg.type==XDEV_EXT_REL_ACK&&msg.session==9&&msg.group==1&&msg.credit==6);
 setup(&tx,true);reverse_peer(&rx.s.peer);reverse_peer(&tx.s.peer);
 struct fixture *targets[2]={&rx,&tx};
 for(unsigned i=0;i<2;i++){
  struct fixture *f=targets[i];open_sender(f);struct xsk_xdev_ext_mech_stage *x=f->st.priv;s32 ret=-1;unsigned before=kicks;
  CHECK("actual_C_rx_admission",xsk_rel_rx(&f->st,&frame,&msg)==XDEV_EXT_REL_HOLD);
  CHECK("actual_rx_call_dispatch",!xsk_xdev_ext_mech_rx_call(&f->st,x,&frame,XDEV_EXT_MECH_SITE_RX_NATIVE,&ret,NULL,NULL));
  CHECK(i?"TX_ACK_reaches_real_control":"RX_ACK_reaches_real_control",x->rel->rx_intent.calls==1);
  CHECK(i?"TX_ACK_confirms_real_sender":"RX_ACK_confirms_real_sender",x->rel->tx.entry[1].acked&&x->rel->tx.entry[1].terminal==XDEV_EXT_REL_COMPLETE&&kicks==before+1);
  CHECK("ack_recycled_without_data_hold",ret==XDEV_EXT_MP_RECYCLE);
 }

 /* CRC/peer/size admission controls use actual C RX envelope verification,
  * matching production ordering: reject before BPF when admission fails. */
 struct xsk_xdev_ext_mech_stage *rxst=rx.st.priv;
 open_sender(&rx);chunk[376]^=1;
 CHECK("bad_CRC_rejected_before_BPF",xsk_rel_rx(&rx.st,&frame,&msg)==XDEV_EXT_REL_BAD);
 CHECK("bad_CRC_cannot_confirm",!rxst->rel->tx.entry[1].acked&&!rxst->rel->rx_intent.calls);chunk[376]^=1;
 chunk[278]^=1;CHECK("foreign_peer_rejected",xsk_rel_rx(&rx.st,&frame,&msg)==XDEV_EXT_REL_BAD);chunk[278]^=1;
 frame.data_len=105;CHECK("short_frame_rejected",xsk_rel_rx(&rx.st,&frame,&msg)==XDEV_EXT_REL_BAD);frame.data_len=106;
 /* Valid CRC with wrong session reaches C wire_verify but real BPF identity
  * decode rejects it. No control call and no sender acknowledgment. */
 chunk[335]^=1;memcpy(hdr,chunk+320,64);memset(hdr+56,0,4);crc=crc32(~0U,hdr,64);xdev_ext_rel_put(chunk+376,crc^~0U,4);
 CHECK("wrong_session_passes_C_CRC_only",xsk_rel_rx(&rx.st,&frame,&msg)==XDEV_EXT_REL_HOLD);
 s32 ret=-1;CHECK("wrong_session_BPF_runs",!xsk_xdev_ext_mech_rx_call(&rx.st,rxst,&frame,XDEV_EXT_MECH_SITE_RX_NATIVE,&ret,NULL,NULL));
 CHECK("wrong_session_cannot_control_or_confirm",!rxst->rel->rx_intent.calls&&!rxst->rel->tx.entry[1].acked);
 chunk[335]^=1;memcpy(hdr,chunk+320,64);memset(hdr+56,0,4);crc=crc32(~0U,hdr,64);xdev_ext_rel_put(chunk+376,crc^~0U,4);
 /* Real guarded control helper rejects foreign callback, duplicate intent,
  * impossible credit, and ACK arriving before any native transmit. */
 open_sender(&rx);active=(struct xdev_ext_mech_call){.st=&rx.st,.member=XDEV_EXT_MECH_MEMBER_COMPLETE,.callsite=XDEV_EXT_MECH_SITE_RX_NATIVE};active.ctx.class_id=XDEV_EXT_MECH_CLASS_AFXDP;
 struct xdev_ext_mech_ctx foreign={};CHECK("unsealed_ctx_rejected",bpf_xdev_ext_rel_rx_control(&foreign,1,1,6,XDEV_EXT_REL_ACK)==-EINVAL);
 CHECK("unsealed_ctx_no_ack",!rxst->rel->tx.entry[1].acked);
 CHECK("impossible_credit_rejected",bpf_xdev_ext_rel_rx_control(&active.ctx,1,1,999,XDEV_EXT_REL_ACK)==-ERANGE);
 CHECK("impossible_credit_no_ack",!rxst->rel->tx.entry[1].acked);
 CHECK("duplicate_intent_rejected",bpf_xdev_ext_rel_rx_control(&active.ctx,1,1,6,XDEV_EXT_REL_ACK)==-EALREADY&&active.protocol_error);
 memset(&rxst->rel->rx_intent,0,sizeof(rxst->rel->rx_intent));xdev_ext_rel_tx_init(&rxst->rel->tx,&cfg);xdev_ext_rel_tx_open(&rxst->rel->tx,1,8192,6);
 CHECK("untransmitted_ACK_rejected",bpf_xdev_ext_rel_rx_control(&active.ctx,1,1,6,XDEV_EXT_REL_ACK)==-EINVAL&&!rxst->rel->tx.entry[1].acked);
 /* Failed native DATA completion owes no ACK, retaining failed custody. */
 xdev_ext_rel_rx_init(&rr->rx,&cfg);memset(rr->ack_pending,0,sizeof(rr->ack_pending));for(u32 i=0;i<6;i++)xdev_ext_rel_rx_claim(&rr->rx,1,i,1);
 xsk_rel_batch_end(&rx.st,&batch,-EIO);CHECK("failed_native_no_ACK",!rr->ack_pending[1]&&rr->rx.entry[1].state==XDEV_EXT_REL_RX_FAILED&&dead_calls==1);
 cleanup(&tx);cleanup(&rx);nonreliable_and_failed_bind();printf("checks=%u failures=%u\n",checks,failures);return failures?1:0;
}

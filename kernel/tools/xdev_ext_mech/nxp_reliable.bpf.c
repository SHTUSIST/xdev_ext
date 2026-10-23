// SPDX-License-Identifier: GPL-2.0
/* v3 protocol glue; C owns admission, retained frames and native custody.
 * C also owns the payload CRC32C, once per direction: it writes the TX CRC
 * after its identity check and verifies the RX CRC before this program runs,
 * so neither callback reads payload bytes. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#ifndef EBUSY
#define EBUSY 16
#endif
#ifndef EBADMSG
#define EBADMSG 74
#define EEXIST 17
#define ERANGE 34
#define ESTALE 116
#define EAGAIN 11
#define EREMOTEIO 121
#endif
#include "../../include/linux/xdev_ext_mech_reliable_core.h"

static __always_inline int rel_packet(__u8 *pkt,const struct xdev_ext_mech_peer *p,
                                      const struct xdev_ext_rel_msg *m)
{
 __u8 *ip=pkt+14,*udp=pkt+34;
 __u32 i,len=92+m->payload_len;
 for(i=0;i<6;i++) { pkt[i]=p->peer_mac[i];pkt[6+i]=p->local_mac[i]; }
 xdev_ext_rel_put(pkt+12,0x800,2);
 for(i=0;i<20;i++) ip[i]=0;
 ip[0]=0x45; ip[8]=64; ip[9]=17; xdev_ext_rel_put(ip+2,len,2);
 for(i=0;i<4;i++) { ip[12+i]=((const __u8 *)&p->local_ip)[i];ip[16+i]=((const __u8 *)&p->peer_ip)[i]; }
 for(i=0;i<2;i++) { udp[i]=((const __u8 *)&p->local_port)[i];udp[2+i]=((const __u8 *)&p->peer_port)[i]; }
 xdev_ext_rel_put(udp+4,len-20,2);udp[6]=udp[7]=0;
 return xdev_ext_rel_wire_encode(pkt+42,m);
}
/* Validate an unordered bounded snapshot; C revalidates the chosen entry. */
static __always_inline __u64 rel_choose_resend(const struct xdev_ext_rel_tx_view *v,
                                               const struct xdev_ext_rel_policy *p)
{
 __u32 i,j,best=~0U,seen=0;
 __u64 chosen=0;
 if (!v->window || v->window>XDEV_EXT_REL_MAX_WINDOW || v->count>v->window ||
     v->rr_next>=v->window || p->resend_order>2) return 0;
 for(i=0;i<XDEV_EXT_REL_MAX_WINDOW;i++) {
  const struct xdev_ext_rel_tx_candidate *c;
  __u32 rank;
  if (i>=v->count) break;
  c=&v->candidate[i];
  if (!c->group || !c->attempt || c->slot>=v->window || c->slot!=c->group % v->window ||
      (seen & (1U<<c->slot))) return 0;
  seen |= 1U<<c->slot;
  /* Duplicate groups necessarily have duplicate validated slots. */
  j=c->slot;
  rank=p->resend_order==2 ? (j+v->window-v->rr_next)%v->window : j;
  if (!chosen || (p->resend_order==1 ? c->group<chosen : rank<best)) {
   chosen=c->group; best=rank;
  }
 }
 return chosen;
}

SEC("struct_ops/rel_afxdp_build")
__s32 BPF_PROG(rel_afxdp_build,const struct xdev_ext_mech_ctx *ctxm)
{
 const struct xdev_ext_afxdp_reliable_info *in;
 struct xdev_ext_rel_msg reply={};
 __u32 i;
 int k;
 (void)ctx;
 if (ctxm->callsite==XDEV_EXT_MP_SITE_WORKER_SELECT) {
  const struct xdev_ext_rel_tx_view *v=(const void *)bpf_xdev_ext_rel_tx_view(ctxm,sizeof(*v));
  struct xdev_ext_rel_policy p={};
  __u64 group;
  if (!v || bpf_xdev_ext_rel_policy(ctxm,&p,sizeof(p))) return -EINVAL;
  group=rel_choose_resend(v,&p);
  return group && v->window ? (__s32)(group % v->window)+1 : 0;
 }
 in=(const void *)bpf_xdev_ext_info(ctxm,sizeof(*in));
 if (!in || !in->wire_session || !in->wire_group ||
     !in->base.nr_frames || in->base.nr_frames>32) return XDEV_EXT_MP_BUILD_ABORT;
 if (!in->wire_type) {
  struct xdev_ext_rel_rx_view v={};
  struct xdev_ext_rel_policy p={};
  if (bpf_xdev_ext_rel_rx_view(ctxm,in->wire_group,&v,sizeof(v)) ||
      bpf_xdev_ext_rel_policy(ctxm,&p,sizeof(p))) return XDEV_EXT_MP_BUILD_ABORT;
  if (!v.must_emit && p.ack_rule!=XDEV_EXT_MP_REL_ACK_EACH &&
      !(p.ack_rule==XDEV_EXT_MP_REL_ACK_EVERY_N && v.owed_count>=p.ack_every))
   return XDEV_EXT_MP_BUILD_DEFAULT;
  reply=(struct xdev_ext_rel_msg){.session=in->wire_session,.group=in->wire_group,
   .attempt=v.latest_attempt,.credit=v.credit,.type=XDEV_EXT_REL_ACK};
  if (v.slot_group==in->wire_group && v.state==XDEV_EXT_REL_RX_SUBMITTED && v.reply==XDEV_EXT_REL_HELD)
   reply.type=XDEV_EXT_REL_HELD;
  else if (p.ack_rule!=XDEV_EXT_MP_REL_ACK_EACH && v.owed<v.base_group) {
   reply.type=XDEV_EXT_REL_ACK_CUM; reply.group=v.base_group-1;
  }
 } else if (!in->wire_attempt) return XDEV_EXT_MP_BUILD_ABORT;
 bpf_for(k,0,(int)in->base.nr_frames) {
  const struct xdev_ext_mech_frame_info *f;
  struct xdev_ext_rel_msg m={};
  struct xdp_desc *d;
  __u8 *pkt;
  i=(__u32)k;
  if(i>=32) return XDEV_EXT_MP_BUILD_ABORT;
  f=&in->base.f[i];
  if(f->data_off<106) return XDEV_EXT_MP_BUILD_ABORT;
  pkt=bpf_xdev_ext_afxdp_hdr(ctxm,i,f->data_off-106,106);
  if(!pkt) return XDEV_EXT_MP_BUILD_ABORT;
  if (!in->wire_type) m=reply;
  else {
   m.session=in->wire_session;m.group=in->wire_group;m.attempt=in->wire_attempt;
   m.type=in->wire_type;m.credit=in->wire_credit;
  }
  if(m.type==XDEV_EXT_REL_DATA) {
   m.total_len=in->base.l.group_bytes;m.index=i;m.count=in->base.nr_frames;
   m.relative_offset=i*in->base.l.seg_len;m.payload_len=f->data_len;
  }
  /* The encoded header leaves the CRC field zero for C to fill. */
  if(rel_packet(pkt,&in->base.peer,&m)) return XDEV_EXT_MP_BUILD_ABORT;
  d=(void *)bpf_xdev_ext_desc(ctxm,i,sizeof(*d));
  if(!d) return XDEV_EXT_MP_BUILD_ABORT;
  d->addr=f->umem_addr+f->data_off-106;d->len=106+f->data_len;d->options=0;
 }
 return XDEV_EXT_MP_BUILD_SUBMIT;
}
SEC("struct_ops/rel_afxdp_complete")
__s32 BPF_PROG(rel_afxdp_complete,const struct xdev_ext_mech_ctx *ctxm)
{
 const struct xdev_ext_afxdp_reliable_info *in;
 struct xdev_ext_rel_cfg cfg={};
 struct xdev_ext_rel_msg m;
 const __u8 *pkt;
 __u32 i,crc,off,len;
 (void)ctx;
 if(ctxm->callsite==XDEV_EXT_MP_SITE_WORKER) {
  const struct xdev_ext_afxdp_tx_cqe *c;
  for(i=0;i<32;i++) {
   if(i>=ctxm->nr_frames) break;
   c=(const void *)bpf_xdev_ext_cqe(ctxm,i,sizeof(*c));
   if(!c || c->err) return XDEV_EXT_MP_ABORT;
  }
  return XDEV_EXT_MP_NEXT;
 }
 if(ctxm->callsite==XDEV_EXT_MP_SITE_RX_HOLD_RESULT) {
  const struct xdev_ext_afxdp_rx_hold_cqe *c=(const void *)bpf_xdev_ext_cqe(ctxm,0,sizeof(*c));
  return c && !c->err ? XDEV_EXT_MP_HOLD : XDEV_EXT_MP_RECYCLE;
 }
 in=(const void *)bpf_xdev_ext_info(ctxm,sizeof(*in));
 if(!in) return XDEV_EXT_MP_RECYCLE;
 off=in->base.f[0].data_off;len=in->base.f[0].data_len;
 if(len<106) return XDEV_EXT_MP_RECYCLE;
 pkt=bpf_xdev_ext_frame(ctxm,0,off,106);
 if(!pkt) return XDEV_EXT_MP_RECYCLE;
 /* xsk_rel_decode() verified this stored CRC over these same bytes before
  * calling here; decode the identity without a second payload pass. */
 crc=(__u32)xdev_ext_rel_be(pkt+98,4)^0xffffffffU;
 cfg.session=in->wire_session;cfg.first_group=1;cfg.timeout_ns=1;
 cfg.window=1;cfg.max_attempts=1;cfg.group_bytes=in->base.l.group_bytes;cfg.seg_len=in->base.l.seg_len;
 if(xdev_ext_rel_wire_decode(pkt+42,len-106,crc,&cfg,&m)) return XDEV_EXT_MP_RECYCLE;
 if (m.type!=XDEV_EXT_REL_DATA) {
  bpf_xdev_ext_rel_rx_control(ctxm,m.group,m.attempt,m.credit,m.type);
  return XDEV_EXT_MP_RECYCLE;
 } else {
  struct xdev_ext_rel_rx_view v={};
  __u32 verdict=XDEV_EXT_REL_HOLD;
  if (bpf_xdev_ext_rel_rx_view(ctxm,m.group,&v,sizeof(v))) return XDEV_EXT_MP_RECYCLE;
  if (v.slot_group==m.group && v.state) {
   if (v.total_len!=m.total_len || v.count!=m.count) verdict=XDEV_EXT_REL_BAD;
   else if (v.state==XDEV_EXT_REL_RX_DONE) verdict=XDEV_EXT_REL_REPLAY_ACK;
   else if (v.state==XDEV_EXT_REL_RX_SUBMITTED)
    verdict=v.owed ? XDEV_EXT_REL_RECYCLE : XDEV_EXT_REL_REPLAY_HELD;
   else if (v.state==XDEV_EXT_REL_RX_FAILED || (v.present & (1U<<m.index))) verdict=XDEV_EXT_REL_RECYCLE;
  } else if (m.group<v.base_group) verdict=XDEV_EXT_REL_STALE;
  else if (m.group>=v.credit) verdict=XDEV_EXT_REL_BACKPRESSURE;
  if (bpf_xdev_ext_rel_rx_data(ctxm,m.group,m.index,m.attempt,verdict) || verdict!=XDEV_EXT_REL_HOLD)
   return XDEV_EXT_MP_RECYCLE;
 }
 if (bpf_xdev_ext_afxdp_hold(ctxm,m.group,m.index,off+106,m.payload_len)) return XDEV_EXT_MP_RECYCLE;
 return XDEV_EXT_MP_HOLD;
}
SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops nxp_afxdp_ops={
 .abi_version=XDEV_EXT_MP_ABI_VERSION,.build=(void *)rel_afxdp_build,
 .complete=(void *)rel_afxdp_complete,
};
char LICENSE[] SEC("license")="GPL";

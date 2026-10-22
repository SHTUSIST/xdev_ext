// SPDX-License-Identifier: GPL-2.0
/* v3 protocol glue; C owns admission, retained frames and native custody. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#ifndef EBUSY
#define EBUSY 16
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
SEC("struct_ops/rel_afxdp_build")
__s32 BPF_PROG(rel_afxdp_build,const struct xdev_ext_mech_ctx *ctxm)
{
 const struct xdev_ext_afxdp_reliable_info *in;
 __u32 i,crc;
 int k;
 (void)ctx;
 in=(const void *)bpf_xdev_ext_info(ctxm,sizeof(*in));
 if (!in || !in->wire_session || !in->wire_group || !in->wire_attempt ||
     !in->base.nr_frames || in->base.nr_frames>32) return XDEV_EXT_MP_BUILD_ABORT;
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
  m.session=in->wire_session;m.group=in->wire_group;m.attempt=in->wire_attempt;
  m.type=in->wire_type;m.credit=in->wire_credit;
  if(m.type==XDEV_EXT_REL_DATA) {
   m.total_len=in->base.l.group_bytes;m.index=i;m.count=in->base.nr_frames;
   m.relative_offset=i*in->base.l.seg_len;m.payload_len=f->data_len;
  }
  if(rel_packet(pkt,&in->base.peer,&m)) return XDEV_EXT_MP_BUILD_ABORT;
  crc=bpf_xdev_ext_crc32c(pkt+42,64,0xffffffffU);
  if(m.payload_len) crc=bpf_xdev_ext_frame_crc32c(ctxm,i,f->data_off,f->data_len,crc);
  xdev_ext_rel_put(pkt+98,crc^0xffffffffU,4);
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
 __u8 header[64];
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
 for(i=0;i<64;i++) header[i]=pkt[42+i];
 for(i=56;i<60;i++) header[i]=0;
 crc=bpf_xdev_ext_crc32c(header,64,0xffffffffU);
 crc=bpf_xdev_ext_frame_crc32c(ctxm,0,off+106,len-106,crc);
 cfg.session=in->wire_session;cfg.first_group=1;cfg.timeout_ns=1;
 cfg.window=1;cfg.max_attempts=1;cfg.group_bytes=in->base.l.group_bytes;cfg.seg_len=in->base.l.seg_len;
 if(xdev_ext_rel_wire_decode(pkt+42,len-106,crc,&cfg,&m) || m.type!=XDEV_EXT_REL_DATA)
  return XDEV_EXT_MP_RECYCLE;
 if(bpf_xdev_ext_afxdp_hold(ctxm,m.group,m.index,off+106,m.payload_len)) return XDEV_EXT_MP_RECYCLE;
 return XDEV_EXT_MP_HOLD;
}
SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops nxp_afxdp_ops={
 .abi_version=XDEV_EXT_MP_ABI_VERSION,.build=(void *)rel_afxdp_build,
 .complete=(void *)rel_afxdp_complete,
};
char LICENSE[] SEC("license")="GPL";

// SPDX-License-Identifier: GPL-2.0
/* Execute the real RX-call envelope and shared frame accessors. Scheduling and
 * struct_ops dispatch are supplied by the host; access decisions are not. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "vmlinux.h"
#include "include/linux/xdev_ext_binding.h"
#include "include/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_core.h"
typedef __u64 u64;
typedef __u32 u32;
typedef __u8 u8;
typedef __s32 s32;
#define __bpf_kfunc
#define XDEV_EXT_MECH_CALL_MAGIC 0x55424d43U
#define READ_ONCE(v) (v)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
/* PRODUCTION_FRAME */
/* PRODUCTION_CALL */
/* PRODUCTION_CALL_OF */
/* PRODUCTION_ARGS */
struct xdev_ext_mech_session { u64 id; };
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; void *priv; };
struct xdp_sock { bool zc; };
struct xsk_xdev_ext_mech_stage {
 struct xdp_sock *xs;
 struct xdev_ext_afxdp_reliable_info rx_info;
 u64 bpf_state[256 / sizeof(u64)];
};
static u64 xdev_ext_mech_session_id(const struct xdev_ext_mech_session *s) { return s->id; }
static u32 crc32c(u32 seed, const void *ptr, size_t len)
{
 const u8 *p=ptr;
 while (len--) {
  seed ^= *p++;
  for (int i=0;i<8;i++) seed=(seed>>1)^(0x82f63b78U & (0U-(seed&1)));
 }
 return seed;
}
/* PRODUCTION_FRAME_BYTES */
/* PRODUCTION_BPF_FRAME */
/* PRODUCTION_BPF_CRC */
/* PRODUCTION_STATE */
static unsigned int checks, failures, invocations;
#define EXPECT(c,msg) do { checks++; if (!(c)) { failures++; \
 fprintf(stderr,"FAIL: %s\n",msg); } } while (0)
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *st,
 const struct xdev_ext_mech_call_args *a, s32 *ret, struct xdev_ext_mech_hold_intent *hold)
{
 struct xdev_ext_mech_call c={0};
 (void)hold;
 c.magic=XDEV_EXT_MECH_CALL_MAGIC; c.member=a->member; c.callsite=a->callsite;
 c.ctx.class_id=XDEV_EXT_MECH_CLASS_AFXDP; c.ctx.member=a->member;
 c.ctx.callsite=a->callsite; c.ctx.nr_frames=a->nr_frames;
 c.frames=a->frames; c.nr_frames=a->nr_frames; c.frame_size=4096; c.st=st;
 c.info=a->info; c.info_size=a->info_size;
 c.cqe=a->cqe; c.cqe_size=a->cqe_size; c.cqe_cap=a->cqe_cap;
 invocations++;
 const struct xdev_ext_afxdp_reliable_info *info=a->info;
 EXPECT(a->info_size==sizeof(*info),"RX envelope carries the extended info with its legacy base");
 if (a->callsite==XDEV_EXT_MECH_SITE_RX_HOLD_RESULT) {
  const struct xdev_ext_mech_frame_info no_frame={0};
  EXPECT(info->base.nr_frames==0 && !memcmp(&info->base.f[0],&no_frame,sizeof(no_frame)),
         "HOLD_RESULT must also clear the legacy info frame view");
  const struct xdev_ext_afxdp_rx_hold_cqe *q=a->cqe;
  EXPECT(a->nr_frames==0 && c.ctx.nr_frames==0,"HOLD_RESULT must expose nr_frames=0");
  EXPECT(a->frames==NULL,"HOLD_RESULT must have no frame view");
  EXPECT(bpf_xdev_ext_frame(&c.ctx,0,0,1)==NULL,"HOLD_RESULT frame read must return NULL");
  EXPECT(bpf_xdev_ext_frame_crc32c(&c.ctx,0,0,1,0)==0 && c.protocol_error,
         "HOLD_RESULT payload CRC read must be rejected and latched");
  EXPECT(a->cqe_size==sizeof(*q) && a->cqe_cap==1 && q->key==7 && q->pos==2,
         "HOLD_RESULT retains its exact result CQE");
 } else {
  EXPECT(info->base.nr_frames==1 && info->base.f[0].umem_addr==a->frames[0].umem_addr &&
         info->base.f[0].data_off==a->frames[0].data_off &&
         info->base.f[0].data_len==a->frames[0].data_len,
         "normal RX preserves the legacy info payload span inside its base");
  EXPECT(a->nr_frames==1 && a->frames!=NULL,"normal RX retains one frame view");
  EXPECT(bpf_xdev_ext_frame(&c.ctx,0,0,1)!=NULL,"normal RX frame read remains usable");
  c.protocol_error=0;
  (void)bpf_xdev_ext_frame_crc32c(&c.ctx,0,0,1,0);
  EXPECT(!c.protocol_error,"normal RX payload CRC remains usable");
 }
 *ret=XDEV_EXT_MECH_HOLD;
 return 0;
}
/* PRODUCTION_RX_CALL */
static void test_state_gate(struct xdev_ext_mech_stage *st)
{
#ifdef XDEV_EXT_TEST_HAS_STATE
 struct xdev_ext_mech_call c={0};
 c.magic=XDEV_EXT_MECH_CALL_MAGIC; c.st=st;
 for (u32 cls=0; cls<=4; cls++) for (u32 member=0;member<=3;member++)
  for (u32 site=0;site<=XDEV_EXT_MECH_SITE_RX_HOLD_RESULT+1;site++) {
   bool allowed=cls==XDEV_EXT_MECH_CLASS_AFXDP && member==XDEV_EXT_MECH_MEMBER_COMPLETE &&
      (site==XDEV_EXT_MECH_SITE_RX_GENERIC || site==XDEV_EXT_MECH_SITE_RX_NATIVE ||
       site==XDEV_EXT_MECH_SITE_RX_HOLD_RESULT);
   c.ctx.class_id=cls; c.member=member; c.ctx.member=member;
   c.callsite=site; c.ctx.callsite=site;
   EXPECT((bpf_xdev_ext_afxdp_state(&c.ctx,256)!=NULL)==allowed,
          "state kfunc must allow exactly AF_XDP complete at three RX sites");
   EXPECT(bpf_xdev_ext_afxdp_state(&c.ctx,0)==NULL,"state kfunc refuses zero length");
   EXPECT(bpf_xdev_ext_afxdp_state(&c.ctx,257)==NULL,"state kfunc refuses over 256 bytes");
  }
 c.ctx.class_id=XDEV_EXT_MECH_CLASS_AFXDP; c.member=XDEV_EXT_MECH_MEMBER_COMPLETE;
 c.callsite=XDEV_EXT_MECH_SITE_RX_HOLD_RESULT;
 EXPECT(bpf_xdev_ext_afxdp_state(&c.ctx,1)==(__u8 *)((struct xsk_xdev_ext_mech_stage *)st->priv)->bpf_state,
        "state kfunc returns this stage's own state storage");
 c.st=NULL;
 EXPECT(bpf_xdev_ext_afxdp_state(&c.ctx,1)==NULL,"state kfunc rejects absent stage");
 c.st=st; void *saved=st->priv; st->priv=NULL;
 EXPECT(bpf_xdev_ext_afxdp_state(&c.ctx,1)==NULL,"state kfunc rejects absent stage private data");
 st->priv=saved; c.magic=0;
 EXPECT(bpf_xdev_ext_afxdp_state(&c.ctx,1)==NULL,"state kfunc rejects unsealed envelope");
#else
 (void)st;
 EXPECT(false,"production bpf_xdev_ext_afxdp_state is missing");
#endif
}
int main(void)
{
 struct xdp_sock xs={0};
 struct xsk_xdev_ext_mech_stage xst={.xs=&xs};
 struct xdev_ext_mech_session s={.id=41};
 struct xdev_ext_mech_stage st={.s=&s,.priv=&xst};
 u8 data[4096]={0};
 struct xdev_ext_mech_frame f={.kaddr=data,.data_off=278,.data_len=1514};
 struct xdev_ext_afxdp_rx_hold_cqe q={.key=7,.pos=2};
 s32 ret;
 EXPECT(xsk_xdev_ext_mech_rx_call(&st,&xst,&f,XDEV_EXT_MECH_SITE_RX_GENERIC,&ret,NULL,NULL)==0,
        "generic RX call succeeds");
 xs.zc=true;
 EXPECT(xsk_xdev_ext_mech_rx_call(&st,&xst,&f,XDEV_EXT_MECH_SITE_RX_NATIVE,&ret,NULL,NULL)==0,
        "native RX call succeeds");
 EXPECT(xsk_xdev_ext_mech_rx_call(&st,&xst,&f,XDEV_EXT_MECH_SITE_RX_HOLD_RESULT,&ret,NULL,&q)==0,
        "HOLD_RESULT call succeeds");
 EXPECT(invocations==3,"all three real RX envelope paths executed");
 test_state_gate(&st);
 printf("RX result/state: %u checks, %u failures\n",checks,failures);
 return !!failures;
}

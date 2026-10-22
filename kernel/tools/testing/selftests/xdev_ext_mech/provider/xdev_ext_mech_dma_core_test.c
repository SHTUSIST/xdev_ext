// SPDX-License-Identifier: GPL-2.0
/* Compiles the real kernel portable helper; no local validator or mock. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_dma_core.h"

static unsigned int checks, failures;
#define EQ(a, b) do { \
 long long av = (long long)(a), bv = (long long)(b); checks++; \
 if (av != bv) { fprintf(stderr, "%s:%d got %lld expected %lld\n", \
 __func__, __LINE__, av, bv); failures++; } } while (0)
#define TRUE(a) EQ(!!(a), 1)
#define FALSE(a) EQ(!!(a), 0)
#define BOTH (XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE)
#define FRAME 4096U
#define WINDOW 65536ULL
#define HOST (16ULL * FRAME)

_Static_assert(XDEV_EXT_MECH_CLASS_DMA == 6, "DMA class ID is independent of policy");
_Static_assert(XDEV_EXT_MECH_CLASS_MAX == 9, "mechanism class maximum");
_Static_assert(XDEV_EXT_BINDING_BACKEND_MAX == 6, "legacy policy ABI frozen");
_Static_assert(sizeof(struct xdev_ext_dma_copy_desc) == 24, "DMA native plan ABI");
_Static_assert(sizeof(struct xdev_ext_dma_mech_cqe) == 24, "DMA completion ABI");
_Static_assert(XDEV_EXT_DMA_MAX_ENTRIES == 32, "bounded plan");

static const struct xdev_ext_mech_frame_info frames[] = {
 { .umem_addr = 2 * FRAME, .data_off = 256, .data_len = 1024 },
 { .umem_addr = 5 * FRAME, .data_off = 256, .data_len = 1024 },
 { .umem_addr = 7 * FRAME, .data_off = 256, .data_len = 512 },
};
static const __u32 indices[] = { 2, 5, 7 };
static struct xdev_ext_dma_geom geometry(__u32 segment, __u32 limit, __u32 align,
                                    __u32 dirs)
{
 struct xdev_ext_dma_geom g;
 memset(&g, 0, sizeof(g));
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, segment, limit, HOST, 0,
                     FRAME, 16, align, dirs), 0);
 return g;
}
static struct xdev_ext_dma_copy_desc entry(__u32 pos, __u32 off, __u64 dev, __u32 len)
{
 struct xdev_ext_dma_copy_desc d = { .frame_pos=pos, .frame_off=off,
                              .device_off=dev, .len=len };
 return d;
}
static void good(struct xdev_ext_dma_copy_desc *d)
{
 d[0] = entry(0, 256, 0, 1024);
 d[1] = entry(1, 256, 1024, 1024);
 d[2] = entry(2, 256, 2048, 512);
}
/* Every rejected call must leave the complete output object untouched. */
static void reject(const struct xdev_ext_dma_geom *g,
                   const struct xdev_ext_mech_frame_info *f, const __u32 *idx,
                   __u32 nf, __u32 dir, const struct xdev_ext_dma_copy_desc *d,
                   __u32 n, int error)
{
 struct xdev_ext_dma_plan p, before;
 memset(&p, 0xa5, sizeof(p));
 memcpy(&before, &p, sizeof(p));
 EQ(xdev_ext_dma_plan_check(g, f, idx, nf, dir, d, n, &p), error);
 EQ(memcmp(&p, &before, sizeof(p)), 0);
}
#define REJECT(g,d,n,e) reject(g,frames,indices,3,XDEV_EXT_MECH_DIR_TO_DEVICE,d,n,e)

static void test_geometry(void)
{
 struct xdev_ext_dma_geom g = geometry(4096, 0, 64, BOTH);
 __u64 off = 0xfeed;
 EQ(g.segment_size, 4096);
 EQ(g.max_entry_len, 4096);
 EQ(g.directions, BOTH);
 EQ(g.alignment, 64);
 EQ(xdev_ext_dma_max_entry_len(4096, 512), 512);
 EQ(xdev_ext_dma_max_entry_len(4096, 0), 4096);
 EQ(xdev_ext_dma_max_entry_len(0, 0), UINT32_MAX);
 EQ(xdev_ext_dma_geom_init(&g, 0, 0, 0, 0, HOST, 0, FRAME, 16, 1, BOTH), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW-1, 0, 0, HOST, 0, FRAME, 16, 1, BOTH), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST, 0, 0, 16, 1, BOTH), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST, 0, FRAME, 0, 1, BOTH), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST, 1, FRAME, 16, 1, BOTH), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST, 0, FRAME, 17, 1, BOTH), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST, 0, FRAME, 16, 0, BOTH), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST, 0, FRAME, 16, 3, BOTH), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST, 0, FRAME, 16, 1, 0), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST, 0, FRAME, 16, 1, BOTH|0x80000000U), -EINVAL);
 EQ(xdev_ext_dma_geom_init(&g, WINDOW, WINDOW, 0, 0, HOST+512, 512, FRAME, 16, 1, BOTH), 0);
 EQ(xdev_ext_dma_host_off(&g, 5, 256, 1024, &off), 0);
 EQ(off, 512+5*FRAME+256);
 off = 0xfeed;
 EQ(xdev_ext_dma_host_off(&g, 16, 0, 1, &off), -ERANGE);
 EQ(off, 0xfeed);
 EQ(xdev_ext_dma_host_off(&g, 0, UINT32_MAX, 2, &off), -ERANGE);
 EQ(off, 0xfeed);
 EQ(xdev_ext_dma_host_off(&g, 0, FRAME-1, 2, &off), -ERANGE);
 EQ(off, 0xfeed);
}
static void test_accepted(void)
{
 struct xdev_ext_dma_geom g = geometry(4096, 0, 64, BOTH);
 struct xdev_ext_dma_copy_desc d[32];
 struct xdev_ext_dma_plan p;
 struct xdev_ext_mech_frame_info f[3];
 __u32 i;
 good(d);
 for (i=XDEV_EXT_MECH_DIR_TO_DEVICE; i<=XDEV_EXT_MECH_DIR_FROM_DEVICE; i++) {
  EQ(xdev_ext_dma_plan_check(&g, frames, indices, 3, i, d, 3, &p), 0);
  EQ(p.n, 3); EQ(p.total, 2560);
  EQ(p.host_off[0], 2*FRAME+256);
  EQ(p.host_off[1], 5*FRAME+256);
  EQ(p.host_off[2], 7*FRAME+256);
 }
 /* Host order stays exact; device order is free within disjoint spans. */
 d[0]=entry(0,256,8192,512); d[0].flags=XDEV_EXT_DMA_F_KNOWN_MASK;
 d[1]=entry(0,768,0,512);
 d[2]=entry(1,256,4096,1024);
 d[3]=entry(2,256,2048,512);
 EQ(xdev_ext_dma_plan_check(&g,frames,indices,3,XDEV_EXT_MECH_DIR_TO_DEVICE,d,4,&p),0);
 EQ(p.n,4); EQ(p.total,2560); EQ(p.host_off[1],2*FRAME+768);
 /* Segment end and window end are inclusive boundary successes. */
 good(d); d[0].device_off=4096-1024; d[1].device_off=4096;
 d[2].device_off=WINDOW-512;
 EQ(xdev_ext_dma_plan_check(&g,frames,indices,3,XDEV_EXT_MECH_DIR_TO_DEVICE,d,3,&p),0);
 /* No segmentation permits an entry spanning an old segment boundary. */
 g=geometry(0,0,1,BOTH); good(d); d[0].device_off=4095;
 d[1].device_off=8192; d[2].device_off=0;
 EQ(xdev_ext_dma_plan_check(&g,frames,indices,3,XDEV_EXT_MECH_DIR_TO_DEVICE,d,3,&p),0);
 /* Empty frames skipped, and all 32 bounded descriptor slots used. */
 memcpy(f,frames,sizeof(f)); f[1].data_len=0;
 good(d); d[1]=d[2];
 EQ(xdev_ext_dma_plan_check(&g,f,indices,3,XDEV_EXT_MECH_DIR_TO_DEVICE,d,2,&p),0);
 EQ(p.total,1536);
 f[0].data_off=0; f[0].data_len=1024;
 for (i=0;i<32;i++) d[i]=entry(0,i*32,i*64,32);
 EQ(xdev_ext_dma_plan_check(&g,f,indices,1,XDEV_EXT_MECH_DIR_TO_DEVICE,d,32,&p),0);
 EQ(p.total,1024); EQ(p.n,32);
}
static void test_rejected(void)
{
 struct xdev_ext_dma_geom g=geometry(4096,0,1,BOTH);
 struct xdev_ext_dma_copy_desc d[33];
 struct xdev_ext_mech_frame_info f[33];
 __u32 idx[33], i;
 good(d); REJECT(&g,d,0,-EINVAL); REJECT(&g,d,33,-E2BIG);
 good(d); d[2].len=0; REJECT(&g,d,3,-EINVAL);
 for (i=2;i<32;i++) {
  good(d); d[2].flags=1U<<i; REJECT(&g,d,3,-EOPNOTSUPP);
 }
 good(d); g.max_entry_len=512; REJECT(&g,d,3,-EMSGSIZE);
 g=geometry(4096,0,1,BOTH);
 good(d); d[2].frame_pos=3; REJECT(&g,d,3,-EINVAL);
 good(d); d[1].frame_off=255; REJECT(&g,d,3,-EINVAL);
 good(d); d[1].frame_off=257; REJECT(&g,d,3,-EINVAL);
 good(d); d[0].frame_pos=1; REJECT(&g,d,3,-EINVAL);
 d[0]=entry(0,256,0,512); d[1]=entry(0,767,1024,512);
 REJECT(&g,d,3,-EINVAL);
 good(d); d[2].len=513; REJECT(&g,d,3,-ERANGE);
 good(d); d[3]=entry(2,768,4096,1); REJECT(&g,d,4,-ERANGE);
 good(d); REJECT(&g,d,2,-ENODATA);
 good(d); d[2].len=511; REJECT(&g,d,3,-ENODATA);
 good(d); d[2].device_off=WINDOW-511; REJECT(&g,d,3,-ERANGE);
 good(d); d[2].device_off=UINT64_MAX-255; REJECT(&g,d,3,-ERANGE);
 good(d); d[2].device_off=4095; REJECT(&g,d,3,-EXDEV);
 good(d); d[2].device_off=2047; REJECT(&g,d,3,-EEXIST);
 good(d); d[2].device_off=128; REJECT(&g,d,3,-EEXIST);
 good(d); d[2].device_off=0; REJECT(&g,d,3,-EEXIST);
 memcpy(f,frames,sizeof(frames)); memcpy(idx,indices,sizeof(indices));
 good(d); f[2].data_off=FRAME-256; d[2].frame_off=FRAME-256;
 reject(&g,f,idx,3,XDEV_EXT_MECH_DIR_TO_DEVICE,d,3,-ERANGE);
 memcpy(f,frames,sizeof(frames)); good(d); idx[2]=16;
 reject(&g,f,idx,3,XDEV_EXT_MECH_DIR_TO_DEVICE,d,3,-ERANGE);
 for (i=0;i<33;i++) { f[i].data_off=0; f[i].data_len=1; idx[i]=0; }
 good(d); reject(&g,f,idx,33,XDEV_EXT_MECH_DIR_TO_DEVICE,d,3,-EINVAL);
 /* Unsupported and invalid direction cannot select a native operation. */
 good(d); g.directions=XDEV_EXT_DMA_DIR_FROM_DEVICE;
 REJECT(&g,d,3,-EOPNOTSUPP);
 g.directions=BOTH;
 reject(&g,frames,indices,3,0,d,3,-EOPNOTSUPP);
 reject(&g,frames,indices,3,32,d,3,-EOPNOTSUPP);
 reject(&g,frames,indices,3,UINT32_MAX,d,3,-EOPNOTSUPP);
 /* Test each alignment operand separately, including a late failure. */
 g=geometry(4096,0,64,BOTH);
 good(d); d[2].device_off=2049; REJECT(&g,d,3,-EINVAL);
 good(d); d[2].len=511; REJECT(&g,d,3,-EINVAL);
 memcpy(f,frames,sizeof(frames)); memcpy(idx,indices,sizeof(indices));
 good(d); f[2].data_off=257; d[2].frame_off=257;
 reject(&g,f,idx,3,XDEV_EXT_MECH_DIR_TO_DEVICE,d,3,-EINVAL);
 g.first_page_off=1; good(d); REJECT(&g,d,3,-EINVAL);
}
static void test_completions(void)
{
 static const int statuses[]={0,-EIO,-EBUSY,-ETIMEDOUT,1,-5000};
 static const __u64 bytes[]={0,2559,2560,2561,UINT64_MAX};
 __u32 i,j,hw;
 struct xdev_ext_dma_mech_cqe c;
 __u8 state=XDEV_EXT_DMA_CK_IDLE;
 FALSE(xdev_ext_dma_cookie_finish(&state));
 TRUE(xdev_ext_dma_cookie_arm(&state)); FALSE(xdev_ext_dma_cookie_arm(&state));
 TRUE(xdev_ext_dma_cookie_finish(&state)); FALSE(xdev_ext_dma_cookie_finish(&state));
 FALSE(xdev_ext_dma_cookie_disarm(&state));
 TRUE(xdev_ext_dma_cookie_arm(&state)); TRUE(xdev_ext_dma_cookie_disarm(&state));
 FALSE(xdev_ext_dma_cookie_finish(&state)); EQ(state,XDEV_EXT_DMA_CK_IDLE);
 for (i=0;i<sizeof(statuses)/sizeof(statuses[0]);i++)
  for (j=0;j<sizeof(bytes)/sizeof(bytes[0]);j++) for (hw=0;hw<2;hw++) {
   int status=statuses[i], err=777;
   __u32 want=(!status && hw && bytes[j]==2560) ? XDEV_EXT_DMA_OK :
                    hw ? XDEV_EXT_DMA_AMBIGUOUS : XDEV_EXT_DMA_PRE_SUBMIT_FAILED;
   __u32 got=xdev_ext_dma_classify(status,hw,bytes[j],2560);
   EQ(got,want);
   EQ(xdev_ext_dma_disposition(got,status,&err),want==XDEV_EXT_DMA_AMBIGUOUS);
   if (want==XDEV_EXT_DMA_AMBIGUOUS)
    EQ(err,status<0 && status>=-4095 ? status : -EIO);
   else EQ(err,want);
   memset(&c,0xa5,sizeof(c));
   xdev_ext_dma_cqe_fill(&c,XDEV_EXT_DMA_CK_DONE,got,status,bytes[j],2560,3);
   EQ(c.outcome,want); EQ(c.provider_status,(__u32)status);
   EQ(c.bytes_done,bytes[j]<2560 ? bytes[j] : 2560);
   EQ(c.entries_done,want==XDEV_EXT_DMA_OK ? 3 : 0); EQ(c.rsvd,0);
  }
 xdev_ext_dma_cqe_fill(&c,XDEV_EXT_DMA_CK_ARMED,XDEV_EXT_DMA_OK,0,2560,2560,3);
 EQ(c.outcome,XDEV_EXT_DMA_PRE_SUBMIT_FAILED); EQ(c.bytes_done,0); EQ(c.entries_done,0);
 /* Hardware ambiguity is terminal despite arbitrary complete returns. */
 for (i=0;i<4;i++) {
  struct xdev_ext_mech_bstate b;
  int err;
  xdev_ext_mech_bstate_init(&b,4);
  EQ(xdev_ext_mech_batch_step(&b,XDEV_EXT_MECH_EV_READY,0),0);
  EQ(xdev_ext_mech_batch_step(&b,XDEV_EXT_MECH_EV_SUBMIT,0),0);
  TRUE(xdev_ext_dma_disposition(xdev_ext_dma_classify(0,true,2559,2560),0,&err));
  EQ(err,-EIO);
  EQ(xdev_ext_mech_batch_step(&b,XDEV_EXT_MECH_EV_SEQUESTER,0),0);
  EQ(xdev_ext_mech_batch_step(&b,i==0 ? XDEV_EXT_MECH_EV_NEXT : i==1 ? XDEV_EXT_MECH_EV_DONE :
                        i==2 ? XDEV_EXT_MECH_EV_RETRY : XDEV_EXT_MECH_EV_RELEASE,0),-EINVAL);
  EQ(b.state,XDEV_EXT_MECH_B_SEQUESTERED);
 }
}
static void test_info_and_common(void)
{
 struct xdev_ext_mech_layout l={.frame_size=FRAME,.hdr_room=256,.seg_len=1024,.group_bytes=2560};
 struct xdev_ext_dma_geom g=geometry(4096,512,64,BOTH);
 struct xdev_ext_dma_mech_info info;
 unsigned int i;
 memset(&info,0xa5,sizeof(info));
 EQ(xdev_ext_dma_info_fill(&info,&l,&g,frames,3),0);
 EQ(info.l.group_bytes,2560); EQ(info.window_len,WINDOW);
 EQ(info.segment_size,4096); EQ(info.max_entry_len,512);
 EQ(info.alignment,64); EQ(info.directions,BOTH); EQ(info.nr_frames,3); EQ(info.rsvd,0);
 for (i=0;i<3;i++) EQ(memcmp(&info.f[i],&frames[i],sizeof(frames[i])),0);
 for (;i<32;i++) EQ(info.f[i].umem_addr|info.f[i].data_off|info.f[i].data_len,0);
 EQ(xdev_ext_dma_info_fill(&info,&l,&g,NULL,0),0); EQ(info.nr_frames,0);
 EQ(xdev_ext_dma_info_fill(&info,&l,&g,frames,33),-E2BIG);
 TRUE(xdev_ext_mech_class_known(XDEV_EXT_MECH_CLASS_DMA));
 TRUE(xdev_ext_mech_ret_legal(XDEV_EXT_MECH_CLASS_DMA,XDEV_EXT_MECH_MEMBER_BUILD,
                       XDEV_EXT_MECH_SITE_WORKER,XDEV_EXT_MECH_BUILD_SUBMIT));
 FALSE(xdev_ext_mech_ret_legal(XDEV_EXT_MECH_CLASS_DMA,XDEV_EXT_MECH_MEMBER_COMPLETE,
                        XDEV_EXT_MECH_SITE_RX_NATIVE,XDEV_EXT_MECH_HOLD));
}
int main(void)
{
 test_geometry(); test_accepted(); test_rejected(); test_completions();
 test_info_and_common();
 if(failures) { fprintf(stderr,"FAIL %u/%u DMA production checks\n",failures,checks); return 1; }
 printf("PASS %u DMA production checks\n",checks); return 0;
}

/* Controlled user-space dependencies for the actual checked-in policy body.
 * This is not a device/provider model, BPF verifier or performance test. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#define BPF_MAP_TYPE_ARRAY 2
#define __uint(name,val) int (*name)[val]
#define __type(name,val) val *name
void *bpf_map_lookup_elem(const void *,const void *);
#include "../../../kernel/tools/xdev_ext_mech/hft_benchmark.bpf.c"
#include "benchmark_policy.h"
#include "hft_runtime.h"
_Static_assert(sizeof(struct hft_guard_record)==sizeof(struct hftb_guard_record),"userspace/BPF history ABI");
static struct xdev_ext_afxdp_mech_info af;
static struct xdev_ext_nvme_mech_info nv;
static struct xdev_ext_afxdp_tx_cqe tx;
static struct xdev_ext_nvme_mech_cqe nc;
static struct xdp_desc descriptor;
static unsigned char frame[4096],sqe[64];
static struct hftb_guard_record history[4];
static int fail_view;
void *bpf_map_lookup_elem(const void *map,const void *key)
{(void)map;uint32_t n=*(const uint32_t *)key;return n<4?&history[n]:NULL;}
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c,const size_t n)
{(void)c;if(n==sizeof(af))return (void *)&af;if(n==sizeof(nv))return (void *)&nv;return NULL;}
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c,__u32 slot,const size_t n)
{(void)c;if(slot)return NULL;if(n==sizeof(descriptor))return (void *)&descriptor;if(n==64)return sqe;return NULL;}
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c,__u32 slot,const size_t n)
{(void)c;if(slot)return NULL;if(n==sizeof(tx))return (void *)&tx;if(n==sizeof(nc))return (void *)&nc;return NULL;}
__u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *c,__u32 pos,__u32 off,const size_t n)
{(void)c;return fail_view||pos||off>4096||n>4096-off?NULL:frame+off;}
__u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *c,__u32 pos,__u32 off,const size_t n)
{(void)c;return pos||off>512||n>512-off?NULL:frame+off;}
#define CHECK(c) do{if(!(c)){fprintf(stderr,"line %u\n",__LINE__);return 1;}}while(0)
int main(void)
{
 struct xdev_ext_mech_ctx c={.callsite=XDEV_EXT_MP_SITE_WORKER,.nr_frames=1};
 c.base.src_offset=1;c.base.direction=XDEV_EXT_MP_DIR_FROM_DEVICE;c.base.length=512;
 hftb_session=0x1020304050607080ULL;hftb_payload=512;hftb_depth=2;hftb_groups=4;
 af.nr_frames=1;af.l=(struct xdev_ext_mech_layout){4096,512,512,512};af.f[0]=(struct xdev_ext_mech_frame_info){8192,512,512};
 unsigned char lm[6]={1},pm[6]={2};CHECK(!hftb_setup_template(hftb_network_template,lm,pm,1,2,3,4,512));
 memset(frame,0xa5,430);memset(frame+512,0x6d,512);memset(frame+1024,0x5a,3072);
 CHECK(hftb_afxdp_build(NULL,&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 CHECK(descriptor.addr==8192+430&&descriptor.len==594&&!descriptor.options);
 const unsigned char expected[40]={0x48,0x46,0x54,0x31,1,40,2,0,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0,0,0,1,0,0,0,1,0,0,2,0,0,0,0,0,0,0,2,0,0,0,0,0};
 CHECK(!memcmp(frame+472,expected,40));for(unsigned i=512;i<1024;i++)CHECK(frame[i]==0x6d);
 frame[0]=0x11;CHECK(hftb_afxdp_complete(NULL,&c)==XDEV_EXT_MP_NEXT);CHECK(history[0].committed&&history[0].raw_prefix[0]==0x11&&history[0].raw_tail[3071]==0x5a);
 CHECK(hftb_afxdp_complete(NULL,&c)==XDEV_EXT_MP_ABORT); /* never overwrite */
 c.base.src_offset=3;frame[0]=0xa5;CHECK(hftb_afxdp_complete(NULL,&c)==XDEV_EXT_MP_NEXT);CHECK(history[0].raw_prefix[0]==0x11&&history[2].raw_prefix[0]==0xa5);
 c.base.src_offset=2;af.f[0].umem_addr=12288;fail_view=1;CHECK(hftb_afxdp_complete(NULL,&c)==XDEV_EXT_MP_ABORT&&!history[1].committed);fail_view=0;
 tx.err=-11;CHECK(hftb_afxdp_complete(NULL,&c)==XDEV_EXT_MP_ABORT&&!history[1].committed);tx.err=0;
 af.f[0].umem_addr=1;CHECK(hftb_afxdp_build(NULL,&c)==XDEV_EXT_MP_BUILD_ABORT);af.f[0].umem_addr=12288;
 nv.window_slba=100;nv.window_nlb=4;nv.lba_shift=9;nv.l.group_bytes=512;
 CHECK(hftb_nvme_build(NULL,&c)==XDEV_EXT_MP_BUILD_SUBMIT);CHECK(sqe[0]==2);
 CHECK(hftb_nvme_complete(NULL,&c)==XDEV_EXT_MP_NEXT);nc.status=1;CHECK(hftb_nvme_complete(NULL,&c)==XDEV_EXT_MP_ABORT);
 puts("actual BPF body: wire/descriptors/payload untouched/full guards/immutable history/null-view/errors/NVMe PASS");return 0;
}

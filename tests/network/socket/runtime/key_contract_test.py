#!/usr/bin/env python3
"""Execute the real NVMe/CE BPF builders with the guest's actual START keys."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(os.environ['XDEV_EXT_KERNEL_SOURCE']) if os.environ.get('XDEV_EXT_KERNEL_SOURCE') else Path(__file__).resolve().parents[5]

def function(source, name):
    start = source.index('__s32 BPF_PROG(' + name + ',')
    brace = source.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/if_xdp.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"
#include "tools/testing/selftests/xdev_ext_mech/socket_guest/observations.h"
#define BPF_PROG(name,args...) name(unsigned long long *ctx,args)
static struct xdev_ext_nvme_mech_info nvme_info;
static struct xdev_ext_ce_mech_info ce_info;
static struct socket_guest_observations observed;
static int socket_observations;
static bool ce_call;
static unsigned char nvme_sqe[64];
static struct xdev_ext_ce_copy_desc ce_desc[4];
static __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx,size_t n)
{(void)ctx;assert(n==(ce_call?sizeof(ce_info):sizeof(nvme_info)));return ce_call?(void *)&ce_info:(void *)&nvme_info;}
static __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx,__u32 slot,size_t n)
{(void)ctx;if(ce_call){assert(slot<4&&n==sizeof(ce_desc[0]));return (void *)&ce_desc[slot];}assert(!slot&&n==sizeof(nvme_sqe));return nvme_sqe;}
static void *bpf_map_lookup_elem(void *map,const __u32 *key)
{assert(map==&socket_observations&&!*key);return &observed;}
'''
MAIN = r'''
static unsigned long long le64(const unsigned char *p)
{unsigned long long v=0;for(unsigned i=0;i<8;i++)v|=(unsigned long long)p[i]<<(8*i);return v;}
int main(void)
{
 struct xdev_ext_mech_ctx m={};
 nvme_info.l=(struct xdev_ext_mech_layout){.frame_size=4096,.hdr_room=256,.seg_len=2048,.group_bytes=8192};
 nvme_info.window_slba=512;nvme_info.window_nlb=257*16;nvme_info.lba_shift=9;
 ce_info.l=nvme_info.l;ce_info.nr_frames=4;ce_info.window_depth=8;ce_info.gpu_window_len=262144;
 ce_info.lease_generation=1;
 for(unsigned i=0;i<4;i++){ce_info.f[i].data_off=256;ce_info.f[i].data_len=2048;}
 m.base.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;m.base.length=8192;
 for(unsigned group=0;group<257;group++) {
  m.base.src_offset=GUEST_FIRST_KEY+group;ce_call=false;memset(nvme_sqe,0,sizeof(nvme_sqe));
  int result=nxp_nvme_build(NULL,&m);
  if(result!=XDEV_EXT_MP_BUILD_SUBMIT){fprintf(stderr,"RED actual NVMe BPF rejects guest first_seq=%u key=%llu key_base=%llu group=%u result=%d\n",GUEST_FIRST_KEY,(unsigned long long)m.base.src_offset,(unsigned long long)key_base,group,result);return 1;}
  assert(le64(nvme_sqe+40)==512+(unsigned long long)group*16);
  ce_call=true;ce_info.window_slot=group%8;
  for(unsigned stage=0;stage<2;stage++) {
   memset(ce_desc,0,sizeof(ce_desc));
   assert(socket_guest_ce_build(NULL,&m)==XDEV_EXT_MECH_BUILD_SUBMIT);
   if(observed.last_group[group%8]!=group){fprintf(stderr,"RED actual CE BPF labels guest key=%llu as source group=%llu, expected group=%u\n",(unsigned long long)m.base.src_offset,(unsigned long long)observed.last_group[group%8],group);return 1;}
   for(unsigned i=0;i<4;i++)assert(ce_desc[i].frame_pos==i&&ce_desc[i].frame_off==256&&ce_desc[i].len==2048&&ce_desc[i].gpu_off==(group%8)*8192+i*2048);
  }
 }
 assert(observed.build==514&&!observed.invalid&&observed.slot_mask==255);
 m.base.src_offset=key_base-1;ce_call=false;assert(nxp_nvme_build(NULL,&m)==XDEV_EXT_MP_BUILD_ABORT);
 /* Campaign bounds belong to this observer. NVMe BPF may construct an
  * out-of-window proposal; the kernel C descriptor validator rejects it.
  */
 ce_call=true;
 m.base.src_offset=key_base+257;assert(socket_guest_ce_build(NULL,&m)==XDEV_EXT_MECH_BUILD_ABORT);
 m.base.src_offset=key_base-1;assert(socket_guest_ce_build(NULL,&m)==XDEV_EXT_MECH_BUILD_ABORT);
 puts("PASS actual NVMe/CE BPF: 257 guest START keys map source groups 0..256, all four spans and eight slots preserved");
 return 0;
}
'''

def main():
    guest=(ROOT/'tools/testing/selftests/xdev_ext_mech/socket_guest/socket_runtime.c').read_text()
    nvme=(ROOT/'tools/xdev_ext_mech/nxp_mech.bpf.c').read_text()
    ce=(ROOT/'tools/testing/selftests/xdev_ext_mech/socket_guest/ce_observe.bpf.c').read_text()
    first=int(re.search(r'\.first_seq\s*=\s*(\d+)',guest)[1])
    key_decl=re.search(r'__u64 key_base\s*=\s*\d+\s*;',nvme)[0]
    source=PRELUDE+f'\n#define GUEST_FIRST_KEY {first}U\n'+key_decl+'\nstatic __u32 nvme_mode;\n'+function(nvme,'nxp_nvme_build')+'\n'+function(ce,'socket_guest_ce_build')+MAIN
    with tempfile.TemporaryDirectory(prefix='xdev-socket-key-contract-') as tmp:
        path=Path(tmp);(path/'actual.c').write_text(source)
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fsanitize=undefined','-I'+str(ROOT),str(path/'actual.c'),'-o',str(path/'actual')],check=True)
        raise SystemExit(subprocess.run([str(path/'actual')]).returncode)

if __name__=='__main__':
    main()

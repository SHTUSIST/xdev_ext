#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Cross-check the CLI's actual reference NVMe and NET BPF builders.

This executes descriptor/header construction with metadata adapters. It does
not create a provider, back payload memory, or certify physical DMA/packets.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[5]


def function(source, name):
    start = source.index('__s32 BPF_PROG(' + name + ',')
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/if_xdp.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"
#define BPF_PROG(name,args...) name(void *ctx,args)
#define S0_MODE_RESERVED 2U
static __u32 mode;
static bool net_call;
static struct xdev_ext_nvme_mech_info nvme_info;
static struct xdev_ext_net_mech_info net_info;
static unsigned char sqe[64];
static struct xdev_ext_net_send_desc desc[16];
static void *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c,size_t n)
{(void)c;assert(n==(net_call?sizeof(net_info):sizeof(nvme_info)));return net_call?(void*)&net_info:(void*)&nvme_info;}
static void *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c,__u32 i,size_t n)
{(void)c;if(net_call){assert(i<16&&n==sizeof(desc[0]));return &desc[i];}assert(!i&&n==sizeof(sqe));return sqe;}
'''
MAIN = r'''
static uint64_t little(const unsigned char *p)
{uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static uint64_t big(const unsigned char *p,unsigned bytes)
{uint64_t v=0;for(unsigned i=0;i<bytes;i++)v=(v<<8)|p[i];return v;}
int main(void)
{
 enum { GROUPS=257, BYTES=8192 };
 struct xdev_ext_mech_ctx c={.base={.direction=XDEV_EXT_MP_DIR_FROM_DEVICE,.length=BYTES}};
 nvme_info.window_slba=512;nvme_info.window_nlb=GROUPS*(BYTES/512);nvme_info.lba_shift=9;
 net_info.nr_frames=1;net_info.generation=19;net_info.mtu=1500;net_info.f[0].data_len=BYTES;
 for(unsigned key=0;key<GROUPS;key++){
  /* Production core starts batch_id at one, START first_seq defaults to
   * zero, and advances both once per group. nvme_s0 selects by batch_id.
   */
  c.base.src_offset=key;c.base.request_id=key+1;
  net_call=false;memset(sqe,0,sizeof(sqe));
  assert(nvme_s0_build(NULL,&c)==XDEV_EXT_MP_BUILD_SUBMIT);
  assert(little(sqe+40)==512+(uint64_t)((key+1)%GROUPS)*(BYTES/512));
  net_call=true;memset(desc,0,sizeof(desc));
  assert(net_peer_build(NULL,&c)==XDEV_EXT_MP_BUILD_SUBMIT);
  for(unsigned i=0;i<8;i++){
   assert(desc[i].len==1024&&desc[i].frame_off==i*1024&&desc[i].header_len==30);
   assert(big(desc[i].header+14,8)==key);
   assert(big(desc[i].header+22,4)==i*1024&&big(desc[i].header+26,4)==BYTES);
  }
  assert(!desc[8].len);
 }
 puts("ok 1 - actual reference programs preserve 257 stream group keys and eight exact offsets; source group=(key+1)%257");
 net_info.f[0].data_len=16384;memset(desc,0,sizeof(desc));
 assert(net_peer_build(NULL,&c)==XDEV_EXT_MP_BUILD_SUBMIT&&desc[15].len==1024);
 net_info.f[0].data_len=16385;
 assert(net_peer_build(NULL,&c)==XDEV_EXT_MP_BUILD_ABORT);
 puts("ok 2 - actual NET reference plan's 16-entry maximum is 16384 bytes");
 return 0;
}
'''


def main():
    nvme = (ROOT/'tools/xdev_ext_mech/nvme_s0.bpf.c').read_text()
    net = (ROOT/'tools/xdev_ext_mech/net_peer.bpf.c').read_text()
    core = (ROOT/'io_uring/xdev_ext_mech.c').read_text()
    # Detect a changed caller convention rather than silently modeling it.
    assert 'b->id = ++s->next_batch_id;' in core
    assert 'b->key = s->start_seq++;' in core
    cli = (ROOT/'tools/xdev_ext_mech/xdev_ext_peer_chain.c').read_text()
    assert '"nvme_s0"' in cli and 'struct xdev_ext_mech_start start = {.nr_batches = groups};' in cli
    source = SHIM + function(nvme, 'nvme_s0_build') + function(net, 'net_peer_build') + MAIN
    with tempfile.TemporaryDirectory(prefix='quality-peer-cli-mapping-') as tmp:
        path = Path(tmp)
        (path/'actual.c').write_text(source)
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fsanitize=undefined','-I'+str(ROOT),str(path/'actual.c'),'-o',str(path/'actual')],check=True)
        subprocess.run([str(path/'actual')],check=True)


if __name__ == '__main__':
    main()

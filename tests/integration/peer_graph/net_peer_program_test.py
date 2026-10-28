#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute reference BPF program C with metadata-only kfunc adapters.
This tests protocol descriptors, not verifier acceptance or physical packets.
"""
from pathlib import Path
import subprocess
import tempfile
KERNEL=Path(__file__).resolve().parents[5]
program=(KERNEL/'tools/xdev_ext_mech/net_peer.bpf.c').read_text()
program='\n'.join(line for line in program.splitlines() if not line.startswith('#include'))
shim=r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_xdp.h>
#include "MECH"
#include "PROG"
#define SEC(s)
#define BPF_PROG(name,...) name(void *ctx,__VA_ARGS__)
struct xdev_ext_net_mech_ops { __u32 abi_version,flags; __s32(*prepare)(const struct xdev_ext_mech_ctx*);__s32(*build)(const struct xdev_ext_mech_ctx*);__s32(*complete)(const struct xdev_ext_mech_ctx*); };
static struct xdev_ext_net_mech_info info;
static struct xdev_ext_net_send_desc desc[16];
static struct xdev_ext_net_mech_cqe completion;
static int unavailable;
static void *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c,size_t n){(void)c;assert(n==sizeof(info));return unavailable?NULL:&info;}
static void *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c,__u32 i,size_t n){(void)c;assert(i<16&&n==sizeof(desc[0]));return &desc[i];}
static void *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c,__u32 i,size_t n){(void)c;assert(!i&&n==sizeof(completion));return &completion;}
'''.replace('"MECH"','"'+str(KERNEL/'include/uapi/linux/xdev_ext_mech.h')+'"').replace('"PROG"','"'+str(KERNEL/'tools/xdev_ext_mech/xdev_ext_mech_prog.h')+'"')
main=r'''
int main(void)
{
 struct xdev_ext_mech_ctx ctx={.base={.src_offset=0x0102030405060708ULL,.length=8192}};
 info.nr_frames=1;info.generation=9;info.mtu=1500;info.f[0].data_len=8192;
 for(int i=0;i<6;i++){info.peer.local_mac[i]=i;info.peer.peer_mac[i]=i+10;}
 assert(net_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_SUBMIT);
 for(int i=0;i<8;i++){
  assert(!desc[i].frame_pos&&desc[i].frame_off==(unsigned)i*1024&&desc[i].len==1024&&desc[i].header_len==30);
  assert(!memcmp(desc[i].header,info.peer.peer_mac,6)&&!memcmp(desc[i].header+6,info.peer.local_mac,6));
  assert(desc[i].header[12]==0x88&&desc[i].header[13]==0xb5&&desc[i].header[14]==1&&desc[i].header[21]==8);
 }
 assert(!desc[8].len);
 puts("ok 1 - actual reference BPF emits bounded CPU headers and exact GPU offsets without a payload view");
 unavailable=1;assert(net_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT);unavailable=0;
 info.mtu=1039;assert(net_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT);info.mtu=1500;
 info.f[0].data_len=16385;assert(net_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT);info.f[0].data_len=8192;
 completion.bytes_sent=8192;assert(net_peer_complete(NULL,&ctx)==XDEV_EXT_MP_NEXT);
 completion.outcome=2;assert(net_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);completion.outcome=0;
 completion.status=-EIO;assert(net_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);completion.status=0;
 completion.bytes_sent--;assert(net_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
 puts("ok 2 - actual reference BPF refuses unrepresentable plans and interprets only full successful CQEs as NEXT");
 memset(desc,0,sizeof(desc));info.nr_frames=2;info.f[0].data_len=2048;info.f[1].data_len=3072;info.f[1].data_off=32;
 assert(net_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_SUBMIT);
 assert(desc[0].frame_pos==0&&desc[1].frame_pos==0&&desc[2].frame_pos==1&&desc[2].frame_off==32&&desc[4].frame_off==2080&&!desc[5].len);
 memset(desc,0,sizeof(desc));info.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;info.header_room=42;info.f[0].data_len=1472;info.f[1].data_len=1472;
 assert(net_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_SUBMIT);
 assert(desc[0].frame_pos==0&&desc[0].len==1472&&desc[0].header_len==42&&desc[1].frame_pos==1&&desc[1].frame_off==32&&!desc[2].len);
 puts("ok 3 - reference BPF builds bounded multi-frame TX and one RX packet descriptor per frame");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='xdev-net-program-') as directory:
 p=Path(directory);(p/'test.c').write_text(shim+program+main)
 subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)

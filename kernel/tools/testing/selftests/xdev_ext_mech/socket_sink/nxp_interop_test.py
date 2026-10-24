#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real UDP + production socket adapter and BPF bodies vs AF_XDP reference codec.

Only kernel scheduling/kfunc views are shimmed. No AF_XDP socket or verifier
acceptance is claimed by this host test; the opposite endpoint uses the exact
production AF_XDP wire encoder/parser and independently computed CRC/payload.
"""
from pathlib import Path
import os, re, subprocess, tempfile, unittest
ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent

PRELUDE = r'''
#include <linux/if_xdp.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"
#define BPF_PROG(name,args...) name(unsigned long long *ctx,args)
static const struct xdev_ext_mech_call_args *packet_args;
static unsigned builds, checks;
static int corrupt_plan;
static __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c, size_t n)
{(void)c;assert(n==packet_args->info_size);return (void *)packet_args->info;}
static __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c, __u32 i, size_t n)
{(void)c;assert(n==packet_args->desc_size);return i<packet_args->desc_cap?packet_args->scratch+i*n:NULL;}
static __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c, __u32 i, size_t n)
{(void)c;assert(n==packet_args->cqe_size);return i<packet_args->cqe_cap?(void *)packet_args->cqe:NULL;}
static __u32 bpf_xdev_ext_crc32c(const void *data, __u32 n, __u32 crc)
{const unsigned char *p=data;while(n--){crc^=*p++;for(unsigned j=0;j<8;j++)crc=(crc>>1)^((crc&1)?0x82f63b78:0);}return crc;}
static __u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *c,__u32 i,__u32 off,__u32 n,__u32 crc)
{(void)c;assert(i<packet_args->nr_frames&&off<=2048&&n<=2048-off);return bpf_xdev_ext_crc32c((u8 *)packet_args->frames[i].kaddr+off,n,crc);}
'''
CALL = r'''
static int run_packet(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_call_args *a,s32 *ret)
{
 struct xdev_ext_mech_ctx m={.base=*a->base,.nr_frames=a->nr_frames};
 assert(a->b&&a->nr_frames==a->b->nr&&a->frames);
 for(unsigned i=0;i<a->nr_frames;i++)assert(a->frames[i].kaddr==a->b->f[i].kaddr);
 (void)st;packet_args=a;m.base.src_offset=a->b->key;m.base.length=a->b->bytes;
 if(a->member==XDEV_EXT_MECH_MEMBER_BUILD){builds++;*ret=socket_sink_build(NULL,&m);}
 else{checks++;*ret=socket_sink_complete(NULL,&m);}
 if(corrupt_plan&&a->member==XDEV_EXT_MECH_MEMBER_BUILD&&*ret==XDEV_EXT_MP_BUILD_SUBMIT){
  struct xdev_ext_socket_packet_desc *d=(void *)a->scratch;
  switch(corrupt_plan){case 1:d->key++;break;case 2:d->frame_pos++;break;case 3:d->frame_off++;break;
   case 4:d->len++;break;case 5:d->relative_offset++;break;case 6:d->header_len++;break;case 7:d->reserved++;break;}
 }
 return 0;
}
'''

class Interop(unittest.TestCase):
    def test_real_datagrams(self):
        adapter = re.sub(r'^#include[^\n]*\n', '', (ROOT/'io_uring/xdev_ext_mech_socket.c').read_text(),flags=re.M).split('static const struct xdev_ext_mech_class_ops')[0]
        bpf = re.sub(r'^#(?:include|define BPF_NO_KFUNC_PROTOTYPES)[^\n]*\n', '', (ROOT/'tools/xdev_ext_mech/socket_sink.bpf.c').read_text(),flags=re.M).split('SEC(".struct_ops.link")')[0]
        bpf = re.sub(r'^SEC\([^\n]+\)\n','',bpf,flags=re.M)
        fixture = (HERE/'rx_fixture.c').read_text().split('int main(',1)[0].replace('#define HDR 16U','#define HDR 88U').replace('#define SEG 1000U','#define SEG 1432U').replace('b->ticket = ++r->next_ticket;', 'b->id = b->ticket = ++r->next_ticket;')
        shim = (HERE/'shim.h').read_text().replace('static int forced_send =', 'static int eagain_call;\nstatic int forced_send =').replace('if(forced_send!=999999)return forced_send;','if(eagain_call&&send_calls==eagain_call)return -EAGAIN;\n if(forced_send!=999999)return forced_send;')
        code = shim+PRELUDE+bpf+CALL+adapter+fixture+(HERE/'nxp_interop_fixture.c').read_text()
        with tempfile.TemporaryDirectory(prefix='socket-nxp-') as tmp:
            c=Path(tmp)/'test.c';exe=Path(tmp)/'test';c.write_text(code)
            command=[os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=undefined','-fno-sanitize-recover=undefined','-pthread','-I'+str(ROOT),str(c),'-o',str(exe)]
            p=subprocess.run(command,capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            p=subprocess.run([str(exe)],capture_output=True,text=True,timeout=15);print(p.stdout,end='');self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            # The same behavioral oracle must reject the original raw-UDP
            # substitution, which is still available as explicit S1 mode.
            raw = code.replace('.flags=XDEV_EXT_SOCKET_F_NXP,.arg0=270019,.arg1=1500',
                               '.flags=0,.arg0=0,.arg1=0')
            self.assertNotEqual(raw, code)
            c.write_text(raw)
            p=subprocess.run(command,capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            p=subprocess.run([str(exe)],capture_output=True,text=True,timeout=15)
            self.assertNotEqual(p.returncode,0,'original raw UDP substitution escaped the mixed-wire oracle')
            self.assertIn('FAIL case=nxp_interop',p.stderr)
            print('PASS negative control: original raw-UDP substitution rejected by the same runtime oracle')

if __name__=='__main__':unittest.main(verbosity=2)

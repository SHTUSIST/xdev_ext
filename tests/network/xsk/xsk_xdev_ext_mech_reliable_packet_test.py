#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the shared production C packet/CRC admission boundary."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[4]
source = (root/'net/xdp/xsk_xdev_ext_mech_reliable.inc').read_text()
function = re.search(r'^static int xsk_rel_packet_check\([^;]*?\)\s*\{.*?^}', source, re.M | re.S)
assert function is not None
fixture = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/types.h>
#include "include/linux/xdev_ext_mech_reliable_core.h"
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
struct xdp_desc { u64 addr;u32 len,options; };
struct xdev_ext_mech_frame_info { u64 umem_addr;u32 data_off,data_len; };
struct xdev_ext_mech_peer { u32 unused; };
struct xdev_ext_mech_layout { u32 hdr_room; };
struct xsk_xdev_ext_mech_tx_bounds { u32 hdr_room,mtu;struct xdev_ext_mech_peer peer; };
struct xsk_mech_reliable { struct xdev_ext_rel_rx rx; struct xdev_ext_rel_tx tx; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel;u32 mtu; };
struct xdev_ext_mech_session { struct xdev_ext_mech_layout layout;struct xdev_ext_mech_peer peer; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv;struct xdev_ext_mech_session *s; };
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s){return &s->layout;}
static const struct xdev_ext_mech_peer *xdev_ext_mech_session_peer(struct xdev_ext_mech_session *s){return &s->peer;}
/* The envelope checker has its own production TX tests. Exercise v3 admission
 * here with an envelope it already admitted, not a substitute protocol. */
static int xsk_xdev_ext_mech_tx_check(const struct xdp_desc *d,const struct xdev_ext_mech_frame_info *fi,
 const u8 *chunk,const struct xsk_xdev_ext_mech_tx_bounds *bd)
{ (void)d;(void)fi;(void)chunk;(void)bd;return 0; }
static u32 crc32c(u32 crc,const void *data,unsigned int len)
{
 const u8 *p=data;
 unsigned int i,j;
 for(i=0;i<len;i++){crc^=p[i];for(j=0;j<8;j++)crc=(crc>>1)^((crc&1)?0x82f63b78U:0);}
 return crc;
}
/* PRODUCTION */
static void encode(u8 *pkt,const struct xdev_ext_rel_msg *m)
{
 u32 crc;
 if(xdev_ext_rel_wire_encode(pkt+42,m))abort();
 crc=crc32c(~0U,pkt+42,64);crc=crc32c(crc,pkt+106,m->payload_len);
 xdev_ext_rel_put(pkt+98,crc^~0U,4);
}
int main(void)
{
 struct xsk_mech_reliable r={};
 struct xsk_xdev_ext_mech_stage xst={.rel=&r,.mtu=1500};
 struct xdev_ext_mech_session session={.layout={.hdr_room=384}};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&session};
 struct xdev_ext_rel_cfg cfg={.session=44,.first_group=1,.timeout_ns=100,.window=2,.max_attempts=3,.group_bytes=1024,.seg_len=512};
 struct xdev_ext_rel_msg m={.session=44,.group=1,.attempt=1,.total_len=1024,.payload_len=512,.count=2,.type=XDEV_EXT_REL_DATA};
 struct xdp_desc d={.addr=278,.len=618};
 struct xdev_ext_mech_frame_info fi={.data_off=384,.data_len=512};
 u8 chunk[4096]={},*pkt=chunk+278;
 unsigned int checks=0;
 xdev_ext_rel_tx_init(&r.tx,&cfg);
 encode(pkt,&m);
 if(xsk_rel_packet_check(&st,&d,&fi,chunk,1,1,0,XDEV_EXT_REL_DATA,0)){ abort(); }
 checks++;
 /* C is the only CRC writer: whatever a builder left in the field, the
  * stored CRC covers exactly the bytes C admitted, payload included. */
 chunk[384]^=1;memset(pkt+98,0,4);
 if(xsk_rel_packet_check(&st,&d,&fi,chunk,1,1,0,XDEV_EXT_REL_DATA,0)){ abort(); }
 { u32 crc;u8 hdr[64];memcpy(hdr,pkt+42,64);memset(hdr+56,0,4);
   crc=crc32c(~0U,hdr,64);crc=crc32c(crc,pkt+106,512);
   if(xdev_ext_rel_be(pkt+98,4)!=(crc^~0U)){ abort(); } }
 checks++;
 chunk[384]^=1;
 m.group=2;encode(pkt,&m);
 if(!xsk_rel_packet_check(&st,&d,&fi,chunk,1,1,0,XDEV_EXT_REL_DATA,0)){ abort(); }
 checks++;
 m.group=1;m.attempt=2;encode(pkt,&m);
 if(!xsk_rel_packet_check(&st,&d,&fi,chunk,1,1,0,XDEV_EXT_REL_DATA,0)){ abort(); }
 checks++;
 m.attempt=1;m.index=1;m.relative_offset=512;encode(pkt,&m);
 if(!xsk_rel_packet_check(&st,&d,&fi,chunk,1,1,0,XDEV_EXT_REL_DATA,0)){ abort(); }
 checks++;
 m.index=0;m.relative_offset=0;m.session=45;encode(pkt,&m);
 if(!xsk_rel_packet_check(&st,&d,&fi,chunk,1,1,0,XDEV_EXT_REL_DATA,0)){ abort(); }
 checks++;
 m.session=44;encode(pkt,&m);d.len--;
 if(!xsk_rel_packet_check(&st,&d,&fi,chunk,1,1,0,XDEV_EXT_REL_DATA,0)){ abort(); }
 checks++;
 printf("PASS: %u production reliable packet admission cases\n",checks);
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='xdev_ext-reliable-packet-') as temp:
    path = Path(temp)
    (path/'probe.c').write_text(fixture.replace('/* PRODUCTION */',function[0]))
    subprocess.run([os.environ.get('CC','cc'),'-O1','-g','-Wall','-Wextra','-Werror',
                    '-fsanitize=undefined',
                    '-fno-sanitize-recover=undefined','-I'+str(root),str(path/'probe.c'),
                    '-o',str(path/'probe')],check=True)
    subprocess.run([str(path/'probe')],check=True)

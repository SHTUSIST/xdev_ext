#!/usr/bin/env python3
"""Explicit finite-config ABI, real config loading, CREATE, and RX admission."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ.get('KERNEL_DIR',str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
FIXTURE=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "include/linux/xdev_ext_mech_reliable_core.h"
#include "io_uring/xdev_ext_mech_step.h"
typedef __u32 u32;typedef __u64 u64;
#define __user
#define u64_to_user_ptr(v) ((void *)(uintptr_t)(v))
#define spin_lock_irqsave(p,f) do {++*(p);f=0;}while(0)
#define spin_unlock_irqrestore(p,f) do {--*(p);(void)f;}while(0)
static size_t copy_size;static bool copy_error;
static int copy_from_user(void *to,const void *from,size_t n) {copy_size=n;if(copy_error||!from)return 1;memcpy(to,from,n);return 0;}
struct xdev_ext_mech_frame {int unused;};
struct xsk_mech_reliable {struct xdev_ext_rel_tx tx;struct xdev_ext_rel_rx rx;u64 nr_groups;u64 ack_pending[32];};
struct xsk_xdev_ext_mech_stage {struct xsk_mech_reliable *rel;};
struct xsk_xdev_ext_mech_provider {int tx_lock;};
struct xdev_ext_mech_pool {struct xsk_xdev_ext_mech_provider *priv;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;};
struct xdev_ext_mech_stage {struct xsk_xdev_ext_mech_stage *priv;struct xdev_ext_mech_session *s;u32 direction;};
static struct xdev_ext_rel_msg packet;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) {return &s->pool;}
static int xsk_rel_decode(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_frame *f,struct xdev_ext_rel_msg *m) {(void)st;(void)f;*m=packet;return 0;}
static unsigned kicks;
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) {(void)st;kicks++;}
/* PRODUCTION */
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char **argv) {
 const char *mode=argc>1?argv[1]:"create";
 if(!strcmp(mode,"create")) {
  struct xdev_ext_mech_create c={.abi_version=1,.nr_stages=2,.pool_kind=XDEV_EXT_MECH_POOL_XSK,.pool_fd=3,.depth=4,.eventfd=-1,.layout={.frame_size=4096,.seg_len=16,.group_bytes=16},
   .st={{.class_id=XDEV_EXT_MECH_CLASS_AFXDP,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=3,.flags=XDEV_EXT_AFXDP_F_RELIABLE},{.class_id=XDEV_EXT_MECH_CLASS_NVME,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=4}}};
  u32 frames=0;CHECK(!xdev_ext_mech_create_check(&c,&frames));
#ifdef XDEV_EXT_AFXDP_F_FINITE
  c.st[0].flags|=XDEV_EXT_AFXDP_F_FINITE;CHECK(!xdev_ext_mech_create_check(&c,&frames));
  c.st[0].flags=XDEV_EXT_AFXDP_F_FINITE;CHECK(xdev_ext_mech_create_check(&c,&frames)==-EINVAL);
  c.st[0].flags=1U<<31;CHECK(xdev_ext_mech_create_check(&c,&frames)==-EINVAL);
  c.st[0].flags=0;c.st[1].flags=XDEV_EXT_AFXDP_F_RELIABLE;CHECK(xdev_ext_mech_create_check(&c,&frames)==-EINVAL);
#else
  CHECK(!"finite ABI absent");
#endif
  return 0;
 }
#ifdef XDEV_EXT_AFXDP_F_FINITE
 if(!strcmp(mode,"config")) {
  struct xdev_ext_afxdp_reliable_finite_config input={.base={.first_group=101,.timeout_ns=10,.window=4,.max_attempts=3},.nr_groups=2};
  struct xdev_ext_mech_stage_uapi u={.flags=XDEV_EXT_AFXDP_F_RELIABLE,.arg1=(uintptr_t)&input};
  struct xdev_ext_afxdp_reliable_config cfg;u64 nr=99;
  CHECK(sizeof(input.base)==24&&sizeof(input)==32&&offsetof(__typeof__(input),nr_groups)==24);
  CHECK(!xsk_rel_config_load(&u,&cfg,&nr)&&copy_size==24&&!nr);
  u.flags|=XDEV_EXT_AFXDP_F_FINITE;CHECK(!xsk_rel_config_load(&u,&cfg,&nr)&&copy_size==32&&nr==2&&cfg.first_group==101);
  input.nr_groups=0;CHECK(xsk_rel_config_load(&u,&cfg,&nr)==-EINVAL);
  input.nr_groups=~0ULL;CHECK(xsk_rel_config_load(&u,&cfg,&nr)==-EOVERFLOW);
  input.nr_groups=2;input.base.first_group=~0ULL-4;CHECK(xsk_rel_config_load(&u,&cfg,&nr)==-EOVERFLOW);
  copy_error=true;CHECK(xsk_rel_config_load(&u,&cfg,&nr)==-EFAULT);
  copy_error=false;u.flags=XDEV_EXT_AFXDP_F_FINITE;CHECK(xsk_rel_config_load(&u,&cfg,&nr)==-EINVAL);
  return 0;
 }
 if(!strcmp(mode,"rx")) {
  struct xdev_ext_rel_cfg cfg={.session=17,.first_group=101,.timeout_ns=10,.window=4,.max_attempts=3,.group_bytes=16,.seg_len=16};
  struct xsk_mech_reliable r={.nr_groups=2};CHECK(!xdev_ext_rel_rx_init(&r.rx,&cfg));CHECK(!xdev_ext_rel_tx_init(&r.tx,&cfg));
  struct xsk_xdev_ext_mech_stage xst={.rel=&r};struct xsk_xdev_ext_mech_provider p={0};struct xdev_ext_mech_session s={.pool={.priv=&p}};
  struct xdev_ext_mech_stage st={.priv=&xst,.s=&s,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE};struct xdev_ext_mech_frame f={0};struct xdev_ext_rel_msg m;
  packet=(struct xdev_ext_rel_msg){.session=17,.group=103,.attempt=1,.total_len=16,.payload_len=16,.count=1,.type=XDEV_EXT_REL_DATA};
  struct xsk_mech_reliable before=r;CHECK(xsk_rel_rx(&st,&f,&m)==XDEV_EXT_REL_BAD);CHECK(!memcmp(&r,&before,sizeof(r))&&!kicks&&!p.tx_lock);
  packet.group=101;CHECK(xsk_rel_rx(&st,&f,&m)==XDEV_EXT_REL_HOLD);CHECK(xdev_ext_rel_rx_commit(&r.rx,&m)==XDEV_EXT_REL_SUBMIT);CHECK(xdev_ext_rel_rx_finish(&r.rx,101,0)==XDEV_EXT_REL_REPLAY_ACK);
  CHECK(xsk_rel_rx(&st,&f,&m)==XDEV_EXT_REL_REPLAY_ACK&&r.ack_pending[101%4]==101&&kicks==1);
  packet.group=102;CHECK(xsk_rel_rx(&st,&f,&m)==XDEV_EXT_REL_HOLD);
  r.nr_groups=0;packet.group=103;CHECK(xsk_rel_rx(&st,&f,&m)==XDEV_EXT_REL_HOLD);
  CHECK(!p.tx_lock);return 0;
 }
#else
 CHECK(!"finite config/RX admission implementation absent");
#endif
 return 1;
}
'''
class FiniteRx(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  source=(ROOT/'net/xdp/xsk_xdev_ext_mech_reliable.inc').read_text()
  names=['xsk_rel_rx']
  if 'static int xsk_rel_config_load(' in source:names.insert(0,'xsk_rel_config_load')
  code='\n'.join(re.search(r'^static int '+n+r'\([^;{}]*\)\s*\{.*?^\}',source,re.M|re.S)[0] for n in names)
  cls.tmp=tempfile.TemporaryDirectory(prefix='finite-rx-');cls.addClassCleanup(cls.tmp.cleanup)
  p=Path(cls.tmp.name);(p/'probe.c').write_text(FIXTURE.replace('/* PRODUCTION */',code));cls.binary=p/'probe'
  subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-I',str(ROOT),str(p/'probe.c'),'-o',str(cls.binary)],check=True)
 def test_real_create_and_finite_rx_contract(self):
  for mode in ('create','config','rx'):
   with self.subTest(mode=mode):
    r=subprocess.run([str(self.binary),mode],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)

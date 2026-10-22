#!/usr/bin/env python3
"""Exercise real worker admission at fixed-group device boundaries."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[4]
PRELUDE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#define XDEV_EXT_MECH_CLASS_F_ORDERED 1
struct cls { unsigned flags; };
struct xdev_ext_mech_stage { unsigned class_id; struct cls *cls; };
struct xdev_ext_mech_batch { struct {unsigned stage;} bs; unsigned bytes; int node; };
struct xdev_ext_mech_session { struct xdev_ext_mech_stage st[4]; struct xdev_ext_mech_layout layout; int retry; void *worker; int retry_work; };
static int aborted, submitted, acquired;
static bool xdev_ext_mech_session_admits(void *s) {(void)s;return true;}
static int xdev_ext_mech_stop_reason(void *s) {(void)s;return -ESHUTDOWN;}
static void xdev_ext_mech_abort(void *s,void *b,int err) {(void)s;(void)b;aborted=err;}
static bool xdev_ext_mech_order_blocked(void *s,void *b) {(void)s;(void)b;return false;}
static void xdev_ext_mech_order_park(void *s,void *b) {(void)s;(void)b;abort();}
static int xdev_ext_mech_life_acquire(void *s,void *b) {(void)s;(void)b;acquired++;return 0;}
static int xdev_ext_mech_build(void *s,void *st,void *b) {(void)s;(void)st;(void)b;return 0;}
static int xdev_ext_mech_submit(void *s,void *st,void *b) {(void)s;(void)st;(void)b;submitted++;return 0;}
static void xdev_ext_mech_life_undo(void *s,void *b) {(void)s;(void)b;}
static void list_add_tail(void *a,void *b) {(void)a;(void)b;abort();}
static void kthread_mod_delayed_work(void *a,void *b,int c) {(void)a;(void)b;(void)c;abort();}
static void xdev_ext_mech_order_kick(void *s) {(void)s;}
'''
MAIN = r'''
int main(int argc,char **argv) {
 struct cls cls={0};
 struct xdev_ext_mech_session s={0};
 struct xdev_ext_mech_batch b={0};
 if(argc!=4)return 2;
 s.st[0].class_id=!strcmp(argv[1],"nvme") ? XDEV_EXT_MECH_CLASS_NVME :
  !strcmp(argv[1],"nxp") ? XDEV_EXT_MECH_CLASS_AFXDP :
  !strcmp(argv[1],"iaa") ? XDEV_EXT_MECH_CLASS_IAA :
  !strcmp(argv[1],"dma") ? XDEV_EXT_MECH_CLASS_DMA : XDEV_EXT_MECH_CLASS_CE;
 s.st[0].cls=&cls;
 s.layout.group_bytes=4096;b.bytes=atoi(argv[2]);
 xdev_ext_mech_batch_run(&s,&b);
 if(atoi(argv[3])) return !(aborted==-EOPNOTSUPP && !submitted && !acquired);
 return !(!aborted && submitted==1 && acquired==1);
}
'''
class FixedGroupBoundary(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  text=(ROOT/'io_uring/xdev_ext_mech.c').read_text()
  match=re.search(r'^static void xdev_ext_mech_batch_run\([^;{}]*\)\n\{\n.*?^\}',text,re.M|re.S)
  assert match
  cls.tmp=tempfile.TemporaryDirectory(prefix='xdev-ext-varlen-');cls.addClassCleanup(cls.tmp.cleanup)
  path=Path(cls.tmp.name);src=path/'test.c';cls.exe=path/'test'
  src.write_text(PRELUDE+match[0]+MAIN)
  subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(ROOT),str(src),'-o',str(cls.exe)],check=True)
 def check_boundary(self,kind,size,refuse):
  result=subprocess.run([str(self.exe),str(kind),str(size),str(int(refuse))])
  self.assertEqual(result.returncode,0,f'class={kind} bytes={size} refuse={refuse}')
 def test_nvme_refuses_variable_payload_before_native_or_lifecycle(self):self.check_boundary("nvme",1000,True)
 def test_nxp_refuses_variable_payload_before_native_or_lifecycle(self):self.check_boundary("nxp",1000,True)
 def test_nvme_accepts_restored_group(self):self.check_boundary("nvme",4096,False)
 def test_nxp_accepts_restored_group(self):self.check_boundary("nxp",4096,False)
 def test_iaa_accepts_actual_compressed_length(self):self.check_boundary("iaa",1000,False)
 def test_dma_accepts_actual_compressed_length(self):self.check_boundary("dma",1000,False)
 def test_ce_accepts_actual_compressed_length(self):self.check_boundary("ce",1000,False)
if __name__=='__main__':unittest.main(verbosity=2)

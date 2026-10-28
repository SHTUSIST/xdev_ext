#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""An accepted socket RX FIFO must admit the next key without claiming ZC."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'core_lifecycle'))
from lease_boundary import build, ROOT
SCENARIO=r'''
static int accept(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b)
{(void)st;(void)b;return 0;}
int main(void)
{
 struct xdev_ext_mech_session s;struct xdev_ext_mech_batch b;
 struct xdev_ext_mech_class_ops ops={.flags=XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE,.submit=accept};
 for(unsigned int mode=0;mode<5;mode++) {
  bool expected=mode==0||mode==3;
  (void)failures;setup(&s);memset(&b,0,sizeof(b));b.s=&s;b.nr_frames=1;b.present=1;b.f[0]=frame(0,700);b.bytes=700;
  b.bs.state=XDEV_EXT_MECH_B_READY;b.bs.nr_stages=2;
  s.pool.state[0]=XDEV_EXT_MECH_F_HELD;
  s.st[0].cls=&ops;s.st[0].class_id=mode==2||mode==3?XDEV_EXT_MECH_CLASS_AFXDP:XDEV_EXT_MECH_CLASS_SOCKET;
  s.st[0].direction=mode==0||mode==4?XDEV_EXT_MECH_DIR_FROM_DEVICE:XDEV_EXT_MECH_DIR_TO_DEVICE;
  s.pool.capabilities=mode==3?XDEV_EXT_BINDING_CAP_ZERO_COPY:0;
  ops.flags=mode==4?0:XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE;
  assert(!xdev_ext_mech_submit(&s,&s.st[0],&b));
  assert(b.fifo_accepted==expected);
  assert(xdev_ext_mech_order_holds_ex(2,0,1,&b.bs,b.fifo_accepted)==!expected);
 }
 puts("PASS socket RX FIFO admission without zero-copy capability");
}
'''
class SocketRxCoreFifo(unittest.TestCase):
 def test_real_core_submit(self):
  with tempfile.TemporaryDirectory() as tmp:
   exe=build(SCENARIO,tmp)
   p=subprocess.run([str(exe)],capture_output=True,text=True)
   self.assertEqual(p.returncode,0,p.stdout+p.stderr)
 def test_class_declares_fifo(self):
  source=(ROOT/'io_uring/xdev_ext_mech_socket.c').read_text().split('static const struct xdev_ext_mech_class_ops',1)[1]
  self.assertRegex(source,r'\.flags\s*=\s*XDEV_EXT_MECH_CLASS_F_ORDERED\s*\|\s*XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE')
if __name__=='__main__':unittest.main(verbosity=2)

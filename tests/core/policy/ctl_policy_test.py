#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import os,shlex,subprocess,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
class CtlPolicy(unittest.TestCase):
 def test_real_ctl_options_and_create_bytes(self):
  with tempfile.TemporaryDirectory() as d:
   binary=Path(d)/'ctl-test'
   cmd=[os.environ.get('CC','gcc'),'-O2','-Wall','-Wextra','-Werror','-I',str(ROOT)]+shlex.split(os.environ.get('CPPFLAGS',''))+[str(HERE/'ctl_policy_test.c'),str(ROOT/'tools/xdev_ext_mech/lib/xdev_ext_session.c'),str(ROOT/'tools/xdev_ext_mech/lib/xdev_ext_link.c'),str(ROOT/'tools/xdev_ext_xsk_redirect.c'),str(ROOT/'tools/xdev_ext_gpu_identity.c'),*shlex.split(os.environ.get('LDFLAGS','')), '-lbpf','-lelf','-lz','-ldl','-o',str(binary)]
   r=subprocess.run(cmd,capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
   r=subprocess.run([binary],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stdout+r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)

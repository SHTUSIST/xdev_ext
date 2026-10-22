#!/usr/bin/env python3
"""Compile the real public helper; no replacement status decision."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('KERNEL_DIR',str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
class Portable(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(prefix='transport-portable-')
  cls.addClassCleanup(cls.tmp.cleanup)
  cls.bin=Path(cls.tmp.name)/'probe'
  subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror',
   '-fsanitize=undefined','-fno-sanitize-recover=undefined','-I',str(ROOT),
   str(HERE/'portable_test.c'),'-o',str(cls.bin)],check=True)
 def case(self,name):
  r=subprocess.run([str(self.bin),name],capture_output=True,text=True)
  self.assertEqual(r.returncode,0,r.stdout+r.stderr)
 def test_legacy_168_layout(self): self.case('abi')
 def test_all_batch_counters_good_last_error_cannot_pass(self): self.case('legacy-error')
 def test_all_batch_counters_good_nonactive_cannot_pass(self): self.case('legacy-state')
 def test_ce_nonactive_cannot_pass(self): self.case('ce-state')
 def test_transport_32_abi_and_every_fail_closed_field(self): self.case('transport')
if __name__=='__main__': unittest.main(verbosity=2)

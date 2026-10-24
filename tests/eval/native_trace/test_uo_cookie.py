# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
class UOCookie(unittest.TestCase):
 def test_reused_slot_delayed_cookie_retains_generation(self):
  header=ROOT/'tests/eval/userspace_orchestrator/uo_native_trace.h'
  self.assertTrue(header.exists(), 'immutable U native cookie absent')
  source=r'''
#include "HEADER"
int main(void) {
 uint32_t k; uint64_t g;
 uint64_t first=uo_native_cookie(1), reused=uo_native_cookie(17);
 if (!first || first==reused) return 1;
 if (uo_native_cookie_decode(first,16,&k,&g) || k!=1 || g!=1) return 2;
 if (uo_native_cookie_decode(reused,16,&k,&g) || k!=1 || g!=17) return 3;
 if (uo_native_cookie_decode(0,16,&k,&g) != -EPROTO) return 4;
 if (uo_native_cookie(UINT64_MAX)) return 5;
 if (uo_native_cookie_decode(first,0,&k,&g) != -EPROTO) return 6;
 return 0;
}'''.replace('HEADER',str(header))
  with tempfile.TemporaryDirectory() as tmp:
   c=Path(tmp)/'test.c'; c.write_text(source); binary=Path(tmp)/'test'
   result=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertEqual(subprocess.run([str(binary)]).returncode,0)
if __name__=='__main__': unittest.main()

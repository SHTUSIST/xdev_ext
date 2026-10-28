# SPDX-License-Identifier: GPL-2.0
"""Execute real class validation with the real pointer-free admission validator."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
SOURCE=Path(os.environ.get('NATIVE_TRACE_TEST_SOURCE',ROOT/'kernel/drivers/nvme/host/xdev_ext_mech_nvme.c'))
def body(text,name):
 start=text.index('static int '+name+'('); a=text.index('{',start); n=1; end=a+1
 while n:
  n+=(text[end]=='{')-(text[end]=='}'); end+=1
 return text[start:end]
class ProviderBoundary(unittest.TestCase):
 def test_reject_plan_traced_without_native_accept(self):
  prefix=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "HEADER"
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
struct xdev_ext_mech_batch { u32 bytes; };
struct xdev_ext_mech_stage { void *priv; u64 arg0,arg1; };
struct nvme_xdev_ext_mech_stage { struct nvme_xdev_ext_identity identity; bool write; };
struct nvme_xdev_ext_mech_batch { bool validated; u8 sqe[64]; u64 batch_id; };
static struct nvme_xdev_ext_mech_batch bp;
static unsigned traces; static int seen_status; static u64 seen_lba; static u32 seen_bytes,seen_plan;
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { (void)b; return &bp; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { return b->bytes; }
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { (void)b; return 19; }
static void __attribute__((unused)) xdev_ext_mech_trace_plan(struct xdev_ext_mech_batch *b,u64 lba,u32 bytes,u32 plan,int status)
{ (void)b; traces++; seen_status=status; seen_lba=lba; seen_bytes=bytes; seen_plan=plan; }
'''.replace('HEADER',str(ROOT/'kernel/include/linux/nvme_xdev_ext_passthru.h'))
  suffix=r'''
int main(void) {
 struct nvme_xdev_ext_mech_stage p={ .identity={.capacity_lbas=4096,.lba_shift=9} };
 struct xdev_ext_mech_stage st={.priv=&p,.arg0=32,.arg1=16};
 struct xdev_ext_mech_batch b={.bytes=4096};
 u8 sqe[64]={2}; int ret;
 sqe[40]=32; sqe[48]=7;
 ret=nvme_xdev_ext_class_validate(&st,&b,sqe,1);
 if(ret || !bp.validated || traces!=1 || seen_status || seen_lba!=32 || seen_bytes!=4096 || seen_plan!=(2|(7<<8))) return 1;
 sqe[40]=48; traces=0;
 ret=nvme_xdev_ext_class_validate(&st,&b,sqe,1);
 if(!ret || bp.validated || traces!=1 || seen_status!=ret || seen_lba!=48) return 2;
 sqe[40]=32; sqe[8]=1; traces=0;
 ret=nvme_xdev_ext_class_validate(&st,&b,sqe,1);
 if(!ret || bp.validated || traces!=1 || seen_status!=ret || seen_lba!=32) return 3;
 return 0;
}
'''
  with tempfile.TemporaryDirectory() as tmp:
   c=Path(tmp)/'test.c'; c.write_text(prefix+body(SOURCE.read_text(),'nvme_xdev_ext_class_validate')+suffix)
   binary=Path(tmp)/'test'
   result=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertEqual(subprocess.run([str(binary)]).returncode,0,'provider class validation event missing or wrong')
if __name__=='__main__': unittest.main()

# SPDX-License-Identifier: GPL-2.0
"""Execute real class validation with the real pointer-free admission validator."""
from pathlib import Path
import os
import runpy
import subprocess
import tempfile
import unittest
import sys
_LAYOUT_FILE = next(p / 'tools/layout.py' for p in Path(__file__).resolve().parents
                    if (p / 'tools/layout.py').is_file())
ROOT = runpy.run_path(str(_LAYOUT_FILE))['canonical_root'](Path(__file__))
_LEGACY = runpy.run_path(str(ROOT / 'tests/storage/nvme/_legacy_storfam_fixture.py'))
LegacySelection, selected_source, adapt_fixture, COMMAND_BOUNDARY = (
 _LEGACY[name] for name in ('LegacySelection', 'selected_source', 'adapt_fixture', 'COMMAND_BOUNDARY'))
HELPERS=runpy.run_path(str(ROOT/'tests/integration/peer_graph/nvme_peer_async_test.py'))
SOURCE=Path(os.environ.get('NATIVE_TRACE_TEST_SOURCE',ROOT/'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c'))
def body(text,name):
 start=text.index('static int '+name+'('); a=text.index('{',start); n=1; end=a+1
 while n:
  n+=(text[end]=='{')-(text[end]=='}'); end+=1
 return text[start:end]
def declaration(text,name):
 start=text.index('struct '+name+' {'); end=text.index('\n};',start)+3
 return text[start:end]
class ProviderBoundary(unittest.TestCase):
 def test_reject_plan_traced_without_native_accept(self):
  prefix=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "HEADER"
#include "RUNTIME_HEADER"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
/* External Linux storage only; validation never reads or mutates atomic_t. */
typedef struct { int counter; } atomic_t;
struct xdev_ext_mech_batch { u32 bytes; };
struct xdev_ext_mech_stage { void *priv; u64 arg0,arg1; };
/* Complete production declarations, with their real typed window/rw fields. */
PROVIDER_TYPES
static struct nvme_xdev_ext_mech_batch bp;
static unsigned traces; static int seen_status; static u64 seen_lba; static u32 seen_bytes,seen_plan;
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { (void)b; return &bp; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { return b->bytes; }
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { (void)b; return 19; }
static void __attribute__((unused)) xdev_ext_mech_trace_plan(struct xdev_ext_mech_batch *b,u64 lba,u32 bytes,u32 plan,int status)
{ (void)b; traces++; seen_status=status; seen_lba=lba; seen_bytes=bytes; seen_plan=plan; }
'''.replace('RUNTIME_HEADER','include/linux/xdev_ext_storfam_runtime.h').replace(
 'HEADER','include/linux/nvme_xdev_ext_passthru.h')
  suffix=r'''
int main(void) {
 struct nvme_xdev_ext_mech_stage p={ .identity={.capacity_lbas=4096,.lba_shift=9},
  .window={.slba=32,.nlb=16,.capacity_lbas=4096,.lba_shift=9} };
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
   if 'NATIVE_TRACE_TEST_SOURCE' in os.environ and 'NATIVE_TRACE_TEST_ROOT' not in os.environ:
    raise ValueError('SETUP NATIVE_TRACE_TEST_SOURCE requires NATIVE_TRACE_TEST_ROOT')
   selected=selected_source(Path(os.environ.get('NATIVE_TRACE_TEST_ROOT',ROOT)),SOURCE if 'NATIVE_TRACE_TEST_SOURCE' in os.environ else None)
   text=selected.read('drivers/nvme/host/xdev_ext_mech_nvme.c')
   types='\n'.join(declaration(text,name) for name in ('nvme_xdev_ext_mech_stage','nvme_xdev_ext_mech_batch'))
   production = body(text,'nvme_xdev_ext_class_validate')
   if 'struct xdev_ext_stor_stage family;' in text:
    prefix, prefix_edits=adapt_fixture(prefix,[dict(old='typedef uint64_t u64;',new='typedef __u64 u64;\ntypedef u64 dma_addr_t;\n'+COMMAND_BOUNDARY,count=1,reason='native scalar and command ABI',source_owner='external OS boundary')])
    types = selected.declarations()
    if 'enum xdev_ext_stor_host_path host_path;' in types:
     types = selected.definition('include/linux/xdev_ext_storfam_block.h',
                                 'xdev_ext_stor_host_path', 'enum') + '\n' + types
    production = selected.closure('validate','strict')
    production += '\nstatic const struct xdev_ext_stor_dev_ops fixture_ops={.decode=nvme_xdev_ext_member_decode};\n'
    suffix, suffix_edits=adapt_fixture(suffix,[dict(old='.window={.slba=32,.nlb=16,.capacity_lbas=4096,.lba_shift=9}',new='.family={.window={.slba=32,.nlb=16,.capacity_lbas=4096,.lba_shift=9},.dev=&fixture_ops}',count=1,reason='embedded immutable window',source_owner='io_uring/family/xdev_ext_storfam_block.c'),dict(old='bp.validated',new='bp.family.validated',count=3,reason='embedded validated state',source_owner='io_uring/family/xdev_ext_storfam_block.c')])
   selected.verify()
   c=Path(tmp)/'test.c'; c.write_text(prefix.replace('PROVIDER_TYPES',types)+production+suffix)
   binary=Path(tmp)/'test'
   result=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(HELPERS['host_headers'](selected.root,Path(tmp)/'headers')),str(c),'-o',str(binary)],capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertEqual(subprocess.run([str(binary)]).returncode,0,'provider class validation event missing or wrong')
if __name__=='__main__': unittest.main()

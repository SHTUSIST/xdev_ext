# SPDX-License-Identifier: GPL-2.0
"""Execute tracing helpers against the production packed-claim lifecycle ABI."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
def function(text,name):
 start=text.index(name+'(');start=text.rfind('\n',0,start)+1
 # trace_frame has a forward declaration: select the definition.
 while text.index(';',start)<text.index('{',start):
  start=text.index(name+'(',start+len(name));start=text.rfind('\n',0,start)+1
 a=text.index('{',start);n=1;end=a+1
 while n:n+=(text[end]=='{')-(text[end]=='}');end+=1
 return text[start:end]
PREFIX=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "HEADER"
typedef __u32 u32; typedef __u64 u64;
#define min(a,b) ((a)<(b)?(a):(b))
#define XDEV_EXT_MECH_CLASS_AFXDP 2
struct stage { u32 class_id; };
struct xdev_ext_mech_session { u32 nr_stages;struct stage st[1];struct xdev_ext_mech_life life[2];u64 id; };
struct frame { u32 index,data_len,data_off;u64 umem_addr; };
struct xdev_ext_mech_batch {
 struct xdev_ext_mech_session *s;struct { u32 stage; } bs;
 struct frame f[2];u32 nr_frames;u64 id,key,ticket,life_token[2];
 u64 trace_cookie,trace_lba;u32 trace_bytes,trace_opcode;
};
static u64 observed;
static u64 xdev_ext_mech_session_id(struct xdev_ext_mech_session *s) {return s->id;}
static bool trace_native_event_enabled(void) {return true;}
/* Dependency compatibility stub solely isolates the old expression's value.
 * This is exactly the old 3-bit encoding, not a replacement lifecycle model.
 */
static u64 __attribute__((unused)) xdev_ext_mech_life_token(const struct xdev_ext_mech_life *l)
{return l->ctrl>>3;}
static void xdev_ext_native_event_emit(const char *phase,const char *origin,
 u64 sid,u64 bid,u64 key,u32 frame,u64 generation,u32 stage,u64 ticket,u32 cls,
 int accepted,int status,u64 cookie,u64 address,u32 bytes,u64 aux,u64 sequence,
 u32 ordinal,u32 offset,u32 length)
{
 (void)phase;(void)origin;(void)sid;(void)bid;(void)key;(void)frame;(void)stage;
 (void)ticket;(void)cls;(void)accepted;(void)status;(void)cookie;(void)address;
 (void)bytes;(void)aux;(void)sequence;(void)ordinal;(void)offset;(void)length;
 observed=generation;
}
'''
SUFFIX=r'''
int main(int argc,char **argv) {
 int mode=argc==2?atoi(argv[1]):-1;
 for(u64 gen=0;gen<=7;gen+=7) {
  struct xdev_ext_mech_session s={.nr_stages=1,.id=919};
  struct xdev_ext_mech_batch b={.s=&s,.nr_frames=1};
  s.life[0].ctrl=gen<<XDEV_EXT_MECH_L_GEN_SHIFT;
  if(xdev_ext_mech_life_claim(&s.life[0],0,&b.life_token[0]))return 1;
  if(b.life_token[0]==gen)return 2;
  observed=~(u64)0;
  if(mode==0)xdev_ext_mech_trace_frame(&b,"native_complete",0,39,0);
  if(mode==1)xdev_ext_mech_trace_descriptor_bind(&b,0,9,4096,512);
  if(mode==2)xdev_ext_mech_trace_frame(&b,"record_admit",0,0,0);
  if(mode==3)xdev_ext_mech_trace_frame(&b,"class_validate",0,0,0);
  if(observed!=gen){fprintf(stderr,"packed claim=%llu emitted generation=%llu canonical=%llu\n",(unsigned long long)b.life_token[0],(unsigned long long)observed,(unsigned long long)gen);return 3;}
 }
 return 0;
}
'''
class LifecycleGeneration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup)
  c=Path(cls.tmp.name)/'test.c';cls.binary=Path(cls.tmp.name)/'test'
  source=(ROOT/'kernel/io_uring/xdev_ext_mech.c').read_text()
  functions='\n'.join(function(source,name) for name in ['xdev_ext_mech_trace_frame','xdev_ext_mech_trace_descriptor_bind'])
  c.write_text(PREFIX.replace('HEADER',str(ROOT/'kernel/io_uring/xdev_ext_mech_lifecycle.h'))+functions+SUFFIX)
  built=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',str(c),'-o',str(cls.binary)],capture_output=True,text=True)
  if built.returncode:raise RuntimeError(built.stderr)
 def check_mode(self,mode):
  result=subprocess.run([str(self.binary),str(mode)],capture_output=True,text=True)
  self.assertEqual(result.returncode,0,result.stderr)
 def test_native_generation_excludes_claim_owner_state_bits(self):self.check_mode(0)
 def test_descriptor_binding_generation_excludes_claim_owner_state_bits(self):self.check_mode(1)
 def test_admission_uses_current_canonical_generation(self):self.check_mode(2)
 def test_validation_uses_current_canonical_generation(self):self.check_mode(3)
if __name__=='__main__':unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""CPU-only checks of actual repeat-START helpers; never GPU/driver performance."""
import json,os,re,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
C=Path(os.environ.get("CE_REPEAT_TEST_SOURCE",Path(__file__).with_name("ce_repeat_start_probe.c")))
def function(source,name):
 pos=source.index(name+'(');start=source.rfind('\nstatic ',0,pos)+1;brace=source.index('{',pos);depth=1;end=brace+1
 while depth:
  depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[start:end]
class Repeat(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not C.exists():raise AssertionError('new repeat-START production helper is missing')
  cls.runs=[];cls.output=os.environ.get("CE_REPEAT_TEST_OUTPUT");cls.source=C.read_text();build=ROOT/'build';build.mkdir(exist_ok=True);cls.tmp=tempfile.TemporaryDirectory(prefix='repeat-host-',dir=build);cls.addClassCleanup(cls.tmp.cleanup);work=Path(cls.tmp.name)
  es=Path(__file__).with_name('eval_session.h').read_text();a=es.index('struct es_run {');b=es.index('};',a)+2
  header=next((ROOT/name for name in ('src/core/include/uapi/linux/xdev_ext_mech.h','kernel/include/uapi/linux/xdev_ext_mech.h') if (ROOT/name).is_file()),None)
  if header is None:raise AssertionError('real xdev_ext_mech.h missing from both canonical/native UAPI layouts')
  prefix='''#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include "UAPI"
'''.replace('UAPI',str(header))
  prefix+='\n'.join(l for l in cls.source.splitlines() if l.startswith('#define RP_'))+'\n'+es[a:b]+'''
static struct xdev_ext_mech_notify_arm seen;
static int observed_fd, inject, calls;
static int es_mech(int ring, __u32 op, __u64 arg) {
 uint64_t n=1; (void)ring;
 if(op!=XDEV_EXT_MECH_OP_NOTIFY_ARM || read(observed_fd,&n,8)!=-1 || errno!=EAGAIN) return -EIO;
 seen=*(struct xdev_ext_mech_notify_arm *)(uintptr_t)arg;calls++;
 if(inject && write(observed_fd,&n,8)!=8) return -EIO;
 return 0;
}
'''
  helpers='\n'.join(function(cls.source,n) for n in ('rp_valid','rp_pattern','rp_check','rp_arm'))
  main=r'''
#define CHECK(x) do { if(!(x)){fprintf(stderr,"check line %d\n",__LINE__);return 1;} } while(0)
int main(int argc,char **argv) {
 struct xdev_ext_mech_stats s={.session_id=7,.state=XDEV_EXT_MECH_SESSION_ACTIVE,.batches_done=64,.published=128,.submitted={64},.completed={64}};
 struct es_run r={.ring=-1,.efd=-1,.session=7};uint64_t n=11;unsigned char *buf=malloc(RP_BYTES);unsigned i;
 CHECK(argc==2 && buf);
 if(!strcmp(argv[1],"counters")) {
  CHECK(!rp_valid(&s,7,64,128));CHECK(rp_valid(&s,8,64,128));CHECK(rp_valid(&s,7,32,128));CHECK(rp_valid(&s,7,64,64));
  s.inflight=1;CHECK(rp_valid(&s,7,64,128));s.inflight=0;s.completed[0]=32;CHECK(rp_valid(&s,7,64,128));s.completed[0]=64;s.submitted[1]=1;CHECK(rp_valid(&s,7,64,128));
 } else if(!strcmp(argv[1],"oracle")) {
  CHECK(rp_pattern(0,0)==0x35 && rp_pattern(1,0)==0x52);
  for(i=0;i<RP_BYTES;i++)buf[i]=rp_pattern(3,i%RP_FRAME);
  CHECK(!rp_check(buf,3));CHECK(rp_check(buf,2));buf[RP_BYTES-1]^=1;CHECK(rp_check(buf,3));memset(buf,0xa5,RP_BYTES);CHECK(rp_check(buf,3));
 } else {
  observed_fd=r.efd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);CHECK(r.efd>=0);CHECK(write(r.efd,&n,8)==8);
  CHECK(!rp_arm(&r,32,64));CHECK(calls==1 && seen.batches_target==64 && seen.published_target==128 && seen.session_id==7);
  CHECK(!rp_arm(&r,64,128));CHECK(calls==2 && seen.batches_target==96 && seen.published_target==192);
  inject=1;CHECK(rp_arm(&r,96,192)==-EIO);CHECK(rp_arm(&r,UINT64_MAX,192)==-EOVERFLOW);close(r.efd);
 }
 free(buf);puts("RP_HOST_HELPER=PASS");return 0;
}
'''
  generated=prefix+helpers+main;path=work/'host.c';path.write_text(generated);cls.binary=work/'host';argv=['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(path),'-o',str(cls.binary)]
  r=subprocess.run(argv,capture_output=True,text=True,timeout=30);cls.compile_error=r.stdout+r.stderr if r.returncode else None
  out=os.environ.get('CE_REPEAT_TEST_OUTPUT')
  if out:
   dst=Path(out);dst.mkdir(parents=True,exist_ok=True);(dst/'host.c').write_text(generated);(dst/'compile.json').write_text(json.dumps(dict(argv=argv,exit=r.returncode,stdout=r.stdout,stderr=r.stderr),indent=2)+'\n')
 @classmethod
 def tearDownClass(cls):
  if cls.output:(Path(cls.output)/'runs.json').write_text(json.dumps(cls.runs,indent=2)+'\n')
 def run_case(self,name):
  self.assertIsNone(self.compile_error,self.compile_error);r=subprocess.run([str(self.binary),name],capture_output=True,text=True,timeout=5);self.runs.append(dict(case=name,exit=r.returncode,stdout=r.stdout,stderr=r.stderr));self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('RP_HOST_HELPER=PASS',r.stdout)
 def test_exact_cumulative_and_incremental_counters(self):self.run_case('counters')
 def test_last_byte_old_round_and_poison(self):self.run_case('oracle')
 def test_real_eventfd_drain_rearm_and_early_old_wake(self):self.run_case('rearm')
 def test_fixed_geometry_timer_and_single_create_contract(self):
  s=self.source;self.assertEqual(len(re.findall(r'\bes_create\(',s)),1);self.assertIn('round < RP_ROUNDS',s);self.assertIn('.first_seq = before + 1',s)
  timed=s[s.index('t0 = es_now_ns();'):s.index('t1 = es_now_ns();')];self.assertIn('es_wait_terminal',timed);self.assertNotIn('rp_check',timed);self.assertNotIn('es_settle',timed);self.assertNotIn('es_ce_access',timed)
if __name__=='__main__':unittest.main()

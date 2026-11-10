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
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/mman.h>
#define CE_REPEAT_SOURCE "host-fixture"
#define XG_EXIT_FAIL 1
#include "UAPI"
'''.replace('UAPI',str(header))
  prefix+='\n'.join(l for l in cls.source.splitlines() if l.startswith('#define RP_'))+'\n'+es[a:b]+'''
static struct xdev_ext_mech_notify_arm seen;
static int observed_fd, inject, calls, stop_rc;
static volatile sig_atomic_t alarm_hits;
static int eintr_seen;
static int es_mech(int ring, __u32 op, __u64 arg) {
 uint64_t n=1; (void)ring;
 if(op==XDEV_EXT_MECH_OP_STOP) return stop_rc;
 if(op!=XDEV_EXT_MECH_OP_NOTIFY_ARM || read(observed_fd,&n,8)!=-1 || errno!=EAGAIN) return -EIO;
 seen=*(struct xdev_ext_mech_notify_arm *)(uintptr_t)arg;calls++;
 if(inject && write(observed_fd,&n,8)!=8) return -EIO;
 return 0;
}
'''
  prefix+=function(es,'es_now_ns')+'\n'+'''
static ssize_t audited_read(int fd, void *buf, size_t n) { ssize_t got=read(fd,buf,n);if(got<0 && errno==EINTR)eintr_seen++;return got; }
static void on_alarm(int sig) { uint64_t one=1;(void)sig;alarm_hits++;if(write(observed_fd,&one,8)!=8)_exit(9); }
#define read audited_read
'''
  helpers='\n'.join(function(cls.source,n) for n in ('rp_valid','rp_pattern','rp_check','rp_arm','rp_rounds','rp_is_spin','rp_spin','rp_cpu_ns','rp_report'))
  main=r'''
#define CHECK(x) do { if(!(x)){fprintf(stderr,"check line %d\n",__LINE__);return 1;} } while(0)
int main(int argc,char **argv) {
 struct xdev_ext_mech_stats s={.session_id=7,.state=XDEV_EXT_MECH_SESSION_ACTIVE,.batches_done=64,.published=128,.submitted={64},.completed={64}};
 struct es_run r={.ring=-1,.efd=-1,.session=7};uint64_t n=11;unsigned char *buf=malloc(RP_BYTES);unsigned i;
 CHECK(argc==2 && buf);
 if(!strcmp(argv[1],"spin")) {
  struct sigaction sa={.sa_handler=on_alarm};struct itimerval timer={.it_value={.tv_usec=10000}};char short_data[4]={0};int shortfd;__u64 deadline;
  observed_fd=r.efd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);CHECK(r.efd>=0);n=1;CHECK(write(r.efd,&n,8)==8);CHECK(!rp_spin(&r,es_now_ns()+1000000000ULL));
  CHECK(write(r.efd,&n,8)==8);CHECK(rp_spin(&r,es_now_ns()-1)==-ETIMEDOUT);CHECK(read(r.efd,&n,8)==8);CHECK(rp_spin(&r,es_now_ns()+1000000ULL)==-ETIMEDOUT);
  CHECK(!sigaction(SIGALRM,&sa,NULL));CHECK(!fcntl(r.efd,F_SETFL,0));CHECK(!setitimer(ITIMER_REAL,&timer,NULL));deadline=es_now_ns()+1000000000ULL;CHECK(!rp_spin(&r,deadline));CHECK(alarm_hits==1 && eintr_seen>=1);close(r.efd);
  shortfd=memfd_create("rp-short",MFD_CLOEXEC);CHECK(shortfd>=0 && write(shortfd,short_data,4)==4 && lseek(shortfd,0,SEEK_SET)==0);r.efd=shortfd;CHECK(rp_spin(&r,es_now_ns()+1000000000ULL)==-EIO);close(shortfd);r.efd=-1;CHECK(rp_spin(&r,es_now_ns()+1000000000ULL)==-EBADF);
 } else if(!strcmp(argv[1],"aba-report") || !strcmp(argv[1],"default-report")) {
  unsigned g;bool aba=!strcmp(argv[1],"aba-report");CHECK(rp_rounds(false)==7 && rp_rounds(true)==21);CHECK(rp_cpu_ns()>0);
  observed_fd=r.efd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);CHECK(r.efd>=0);
  for(g=0;g<rp_rounds(aba);g++) { CHECK(rp_is_spin(aba,g)==(aba && g>=7 && g<14));CHECK(!rp_arm(&r,g*32,g*64));CHECK(seen.batches_target==(g+1)*32 && seen.published_target==(g+1)*64);s.batches_done=s.submitted[0]=s.completed[0]=(g+1)*32;s.published=(g+1)*64;CHECK(!rp_valid(&s,7,(g+1)*32,(g+1)*64));for(i=0;i<RP_BYTES;i++)buf[i]=rp_pattern(g,i%RP_FRAME);CHECK(!rp_check(buf,g));if(g)CHECK(rp_check(buf,g-1));rp_report(aba,g,7,&s,1000,1100,80); }close(r.efd);
 } else if(!strcmp(argv[1],"stop-fail") || !strcmp(argv[1],"stop-missing") || !strcmp(argv[1],"stop-ok")) {
  int stop;stop_rc=!strcmp(argv[1],"stop-fail")?-EIO:(!strcmp(argv[1],"stop-missing")?-ENOENT:0);
STOP_BLOCK
  puts("AFTER_STOP");
 } else if(!strcmp(argv[1],"counters")) {
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
  begin=cls.source.index(' if (r.session) {');end=cls.source.index(' (void)es_close(&r);',begin);main=main.replace('STOP_BLOCK',cls.source[begin:end])
  generated=prefix+helpers+main;path=work/'host.c';path.write_text(generated);cls.binary=work/'host';argv=['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(path),'-o',str(cls.binary)]
  r=subprocess.run(argv,capture_output=True,text=True,timeout=30);cls.compile_error=r.stdout+r.stderr if r.returncode else None
  out=os.environ.get('CE_REPEAT_TEST_OUTPUT')
  if out:
   dst=Path(out);dst.mkdir(parents=True,exist_ok=True);(dst/'host.c').write_text(generated);(dst/'compile.json').write_text(json.dumps(dict(argv=argv,exit=r.returncode,stdout=r.stdout,stderr=r.stderr),indent=2)+'\n')
 @classmethod
 def tearDownClass(cls):
  if cls.output:(Path(cls.output)/'runs.json').write_text(json.dumps(cls.runs,indent=2)+'\n')
 def run_case(self,name,expected=0):
  self.assertIsNone(self.compile_error,self.compile_error);r=subprocess.run([str(self.binary),name],capture_output=True,text=True,timeout=5);self.runs.append(dict(case=name,exit=r.returncode,stdout=r.stdout,stderr=r.stderr));self.assertEqual(r.returncode,expected,r.stdout+r.stderr);
  if expected:return r
  self.assertIn('RP_HOST_HELPER=PASS',r.stdout);return r
 def test_exact_cumulative_and_incremental_counters(self):self.run_case('counters')
 def test_last_byte_old_round_and_poison(self):self.run_case('oracle')
 def test_real_eventfd_drain_rearm_and_early_old_wake(self):self.run_case('rearm')
 def test_fixed_geometry_timer_and_single_create_contract(self):
  s=self.source;self.assertEqual(len(re.findall(r'\bes_create\(',s)),1);self.assertIn('round < rp_rounds(wait_aba)',s);self.assertIn('.first_seq = before + 1',s)
  timed=s[s.index('t0 = es_now_ns();'):s.index('t1 = es_now_ns();')];self.assertIn('es_wait_terminal',timed);self.assertNotIn('rp_check',timed);self.assertNotIn('es_settle',timed);self.assertNotIn('es_ce_access',timed);self.assertNotIn('rp_cpu_ns',timed)
 def test_real_eventfd_spin_deadline_signal_eintr_short_and_error(self):self.run_case('spin')
 def test_default_seven_output_and_optional_21_counters(self):
  for mode,total,prefix in [('default-report',7,'CE_REPEAT_START'),('aba-report',21,'CE_WAIT_ABA')]:
   result=self.run_case(mode);lines=[line for line in result.stdout.splitlines() if line.startswith(prefix+' ')];self.assertEqual(len(lines),total)
   for g,line in enumerate(lines):
    f=dict(re.findall(r'(\w+)=(\S+)',line));self.assertEqual(f['absolute_notify_target'],str((g+1)*32));self.assertEqual(f['published'],str((g+1)*64));self.assertEqual(f['done'],str((g+1)*32));self.assertEqual(f['first_seq'],str(g*32+1))
    if total==21:
     self.assertEqual(f['phase'],str(g//7));self.assertEqual(f['mode'],'spin' if 7<=g<14 else 'block');self.assertEqual(f['local_round'],str(g%7));self.assertEqual(f['global_round'],str(g));self.assertEqual(f['start_ns'],'1000');self.assertEqual(f['terminal_ns'],'1100');self.assertEqual(f['caller_cpu_ns'],'80');self.assertEqual(f['caller_cpu_scope'],'guest-thread-before-t0_after-t1')
    else:self.assertNotIn('caller_cpu',line)
   if total==7:self.assertEqual(lines[0],'CE_REPEAT_START SOURCE=host-fixture session=7 round=0 size=65536 frame=4096 depth=4 batches=32 first_seq=1 absolute_notify_target=32 published=64 native_submitted=32 native_completed=32 done=32 delta_done=32 elapsed_ns=100 oracle=PASS diagnostic=internal')
 def test_stop_failure_still_withholds_before_release(self):
  for case in ('stop-fail','stop-missing'):
   result=self.run_case(case,1);self.assertIn('release=withheld',result.stderr);self.assertNotIn('AFTER_STOP',result.stdout)
  self.assertIn('AFTER_STOP',self.run_case('stop-ok').stdout)
if __name__=='__main__':unittest.main()

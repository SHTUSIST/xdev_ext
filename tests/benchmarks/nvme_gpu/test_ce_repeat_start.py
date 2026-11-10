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
#define XG_EXIT_USAGE 2
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
  policy_api='static int rp_policy(' in cls.source
  prefix+='\n#define RP_POLICY_API '+str(int(policy_api))+r'''
static char policy_written[8],policy_readback[8]="Y\n";
static int policy_opens,policy_closes,policy_fail,policy_puts;
static FILE *policy_open(const char *path,const char *mode) {
 if(strcmp(path,"/sys/module/nvidia/parameters/xdev_ext_ce_diag_old_kick")) {errno=EINVAL;return NULL;}
 policy_opens++;
 if(policy_fail==1 || (policy_fail==3 && !strcmp(mode,"r"))) {errno=EACCES;return NULL;}
 return !strcmp(mode,"w")?fmemopen(policy_written,sizeof(policy_written),"w"):fmemopen(policy_readback,strlen(policy_readback),"r");
}
static int policy_close(FILE *f) {int rc=fclose(f);policy_closes++;return (policy_fail==2 && policy_closes==1)||(policy_fail==4 && policy_closes==2)?EOF:rc;}
static int policy_put(int c,FILE *f) {policy_puts++;if(policy_fail==5 && policy_puts==2)return EOF;return fputc(c,f);}
static size_t policy_read(void *buf,size_t size,size_t n,FILE *f) {if(policy_fail==6){memcpy(buf,"Y\n",2);return 2;}return fread(buf,size,n,f);}
#define fopen policy_open
#define fclose policy_close
#define fputc policy_put
#define fread policy_read
'''
  helpers='\n'.join(function(cls.source,n) for n in ('rp_valid','rp_pattern','rp_check','rp_arm','rp_rounds','rp_is_spin','rp_spin','rp_cpu_ns','rp_report'))
  helpers+='\n'+(function(cls.source,'rp_policy') if policy_api else 'static int rp_policy(unsigned int round) { (void)round; return -ENOSYS; }')
  options=cls.source[cls.source.index(' for (i = 1; i < (unsigned int)argc; i++) {'):cls.source.index(' if (es_ce_is_sim(dev)')]
  helpers+='\nstatic int actual_options(int argc,char **argv) { const char *dev="/dev/nvidia0";unsigned int i;bool wait_aba=false,policy_aba=false;\n'+options+'\n(void)dev;return 100+(wait_aba?1:0)+(policy_aba?2:0); }\n'
  gate=cls.source[cls.source.index('  if (policy_aba && !(round % RP_ROUNDS)'):cls.source.index('  deadline = es_now_ns()')] if policy_api else 'ret=XG_EXIT_FAIL;break;'
  main=r'''
#define CHECK(x) do { if(!(x)){fprintf(stderr,"check line %d\n",__LINE__);return 1;} } while(0)
int main(int argc,char **argv) {
 struct xdev_ext_mech_stats s={.session_id=7,.state=XDEV_EXT_MECH_SESSION_ACTIVE,.batches_done=64,.published=128,.submitted={64},.completed={64}};
 struct es_run r={.ring=-1,.efd=-1,.session=7};uint64_t n=11;unsigned char *buf=malloc(RP_BYTES);unsigned i;
 CHECK(argc==2 && buf);
 (void)policy_open;(void)policy_close;(void)policy_put;(void)policy_read;
 if(!strcmp(argv[1],"policy-options")) {
  char *a[]={"probe"},*b[]={"probe","--wait-aba"},*c[]={"probe","--submit-policy-aba"},*d[]={"probe","--wait-aba","--submit-policy-aba"},*e[]={"probe","--submit-policy-aba","--wait-aba"},*f[]={"probe","--submit-policy-aba","--submit-policy-aba"};
  CHECK(actual_options(1,a)==100 && actual_options(2,b)==101 && actual_options(2,c)==102);
  CHECK(actual_options(3,d)==2 && actual_options(3,e)==2 && actual_options(3,f)==2);
 } else if(!strcmp(argv[1],"policy-gate")) {
  bool policy_aba=true;unsigned int round=7;int ret=0,before=policy_opens;
  s.native_publish=1;
  for(;;) { POLICY_GATE break; }
  CHECK(ret==XG_EXIT_FAIL && policy_opens==before);
  s.native_publish=0;strcpy(policy_readback,"N\n");ret=0;
  for(;;) { POLICY_GATE break; }
  CHECK(!ret && policy_opens==before+2);
 } else if(!strcmp(argv[1],"spin")) {
  struct sigaction sa={.sa_handler=on_alarm};struct itimerval timer={.it_value={.tv_usec=10000}};char short_data[4]={0};int shortfd;__u64 deadline;
  observed_fd=r.efd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);CHECK(r.efd>=0);n=1;CHECK(write(r.efd,&n,8)==8);CHECK(!rp_spin(&r,es_now_ns()+1000000000ULL));
  CHECK(write(r.efd,&n,8)==8);CHECK(rp_spin(&r,es_now_ns()-1)==-ETIMEDOUT);CHECK(read(r.efd,&n,8)==8);CHECK(rp_spin(&r,es_now_ns()+1000000ULL)==-ETIMEDOUT);
  CHECK(!sigaction(SIGALRM,&sa,NULL));CHECK(!fcntl(r.efd,F_SETFL,0));CHECK(!setitimer(ITIMER_REAL,&timer,NULL));deadline=es_now_ns()+1000000000ULL;CHECK(!rp_spin(&r,deadline));CHECK(alarm_hits==1 && eintr_seen>=1);close(r.efd);
  shortfd=memfd_create("rp-short",MFD_CLOEXEC);CHECK(shortfd>=0 && write(shortfd,short_data,4)==4 && lseek(shortfd,0,SEEK_SET)==0);r.efd=shortfd;CHECK(rp_spin(&r,es_now_ns()+1000000000ULL)==-EIO);close(shortfd);r.efd=-1;CHECK(rp_spin(&r,es_now_ns()+1000000000ULL)==-EBADF);
 } else if(!strcmp(argv[1],"policy-io")) {
  unsigned g;const char *bad[]={"1\n","Y","N\n","Y\nx"};
  for(g=0;g<21;g++) {int before=policy_opens;strcpy(policy_readback,g/7==1?"N\n":"Y\n");memset(policy_written,0,8);CHECK(!rp_policy(g));CHECK(policy_opens-before==(g%7?0:2));if(!(g%7))CHECK(!strcmp(policy_written,g/7==1?"N\n":"Y\n"));}
  CHECK(policy_opens==6 && policy_closes==6);
  for(g=0;g<4;g++){strcpy(policy_readback,bad[g]);policy_closes=policy_puts=0;CHECK(rp_policy(0)<0 && policy_closes==2);}
  strcpy(policy_readback,"Y\n");
  for(policy_fail=1;policy_fail<=6;policy_fail++){policy_closes=policy_puts=0;CHECK(rp_policy(0)<0);CHECK(policy_closes==(policy_fail==1?0:((policy_fail==4 || policy_fail==6)?2:1)));}
  policy_fail=0;
 } else if(!strcmp(argv[1],"aba-report") || !strcmp(argv[1],"default-report") || !strcmp(argv[1],"policy-report")) {
  unsigned g;bool aba=!strcmp(argv[1],"aba-report"),policy=!strcmp(argv[1],"policy-report");CHECK(rp_rounds(false)==7 && rp_rounds(true)==21);CHECK(rp_cpu_ns()>0);
  observed_fd=r.efd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);CHECK(r.efd>=0);
  for(g=0;g<rp_rounds(aba || policy);g++) { CHECK(rp_is_spin(aba,g)==(aba && g>=7 && g<14));CHECK(!rp_arm(&r,g*32,g*64));CHECK(seen.batches_target==(g+1)*32 && seen.published_target==(g+1)*64);s.batches_done=s.submitted[0]=s.completed[0]=(g+1)*32;s.published=(g+1)*64;CHECK(!rp_valid(&s,7,(g+1)*32,(g+1)*64));for(i=0;i<RP_BYTES;i++)buf[i]=rp_pattern(g,i%RP_FRAME);CHECK(!rp_check(buf,g));if(g)CHECK(rp_check(buf,g-1));
#if RP_POLICY_API
rp_report(aba,policy,g,7,&s,1000,1100,80);
#else
rp_report(aba,g,7,&s,1000,1100,80);
#endif
}close(r.efd);
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
  begin=cls.source.index(' if (r.session) {');end=cls.source.index(' (void)es_close(&r);',begin);main=main.replace('STOP_BLOCK',cls.source[begin:end]).replace('POLICY_GATE',gate)
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
  s=self.source;self.assertEqual(len(re.findall(r'\bes_create\(',s)),1);self.assertIn('round < rp_rounds(wait_aba || policy_aba)',s);self.assertIn('.first_seq = before + 1',s)
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
 def test_private_policy_flag_quiescent_rearm_and_timer_contract(self):
  s=self.source;self.assertIn('--submit-policy-aba',s);self.assertIn('wait_aba && policy_aba',s)
  self.assertIn('s.native_publish || rp_policy(round)',s)
  self.assertLess(s.index('rp_arm(&r, before, published)'),s.index('rp_policy(round)'))
  self.assertLess(s.index('rp_policy(round)'),s.index('t0 = es_now_ns();'))
  self.assertEqual(len(re.findall(r'\bes_create\(',s)),1);self.assertEqual(len(re.findall(r'\bes_ce_open\(',s)),1)
 def test_actual_private_argv_mutual_exclusion_and_quiescent_native_gate(self):
  self.run_case('policy-options');self.run_case('policy-gate')
 def test_private_policy_YN_EOF_failures_and_exact_three_boundaries(self):self.run_case('policy-io')
 def test_private_policy_all21_BLOCK_same_session_and_work(self):
  result=self.run_case('policy-report');lines=[l for l in result.stdout.splitlines() if l.startswith('CE_POLICY_ABA ')]
  self.assertEqual(len(lines),21)
  for g,line in enumerate(lines):
   f=dict(re.findall(r'(\w+)=(\S+)',line));self.assertEqual(f['mode'],'block');self.assertEqual(f['session'],'7');self.assertEqual(f['phase'],str(g//7));self.assertEqual(f['global_round'],str(g));self.assertEqual(f['local_round'],str(g%7));self.assertEqual(f['policy'],'direct-watchdog' if 7<=g<14 else 'old-kick');self.assertEqual(f['readback'],'N' if 7<=g<14 else 'Y');self.assertEqual(f['done'],str((g+1)*32));self.assertEqual(f['published'],str((g+1)*64));self.assertEqual(f['caller_cpu'],'NOT_MEASURED')
 def test_stop_failure_still_withholds_before_release(self):
  for case in ('stop-fail','stop-missing'):
   result=self.run_case(case,1);self.assertIn('release=withheld',result.stderr);self.assertNotIn('AFTER_STOP',result.stdout)
  self.assertIn('AFTER_STOP',self.run_case('stop-ok').stdout)
if __name__=='__main__':unittest.main()

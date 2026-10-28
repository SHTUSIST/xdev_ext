#!/usr/bin/env python3
"""Run unchanged production post-wait receiver finalization with API/OS shims.

The code under test starts at reliable linger and includes actual error paths
and report selection. Shims return deterministic late errors, pending controls,
and STOP failures. No substitute PASS decision is compiled.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ.get('KERNEL_DIR',str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
FIXTURE=r'''
#include <time.h>
#include <unistd.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_fallback.h"
enum { CTL_SETUP=2, CTL_FAIL=1 };
struct ctl_opts { bool reliable,expect_window_reject,drv_mode,close_inflight,expect_timeout,fq_dup,shared_umem_probe; char *detach_pin; __u64 groups,ce_len,timeout_ms,max_attempts,retry_timeout_ms; };
struct ctl_run { int ring; __u64 session; };
static int late_error,stop_error,controls,pending,unknown;
static char events[128];static unsigned int n;
static void event(char c) { events[n++]=c;events[n]=0; }
static int fake_nanosleep(const struct timespec *a,struct timespec *b) { (void)a;(void)b;event('L');return 0; }
#define nanosleep fake_nanosleep
static __u64 ctl_now_ns(void) { return 0; }
static void ctl_err(const char *fmt,...) { (void)fmt; }
static int ctl_stats(int ring,__u64 id,struct xdev_ext_mech_stats *s)
{ (void)ring;(void)id;event('S');*s=(struct xdev_ext_mech_stats){.session_id=id,.state=XDEV_EXT_MECH_SESSION_ACTIVE,.last_err=late_error,.batches_done=2,.held=6,.recycled=6,.submitted={0,2},.completed={2,2}};return 0; }
static void ctl_print_stats(const struct xdev_ext_mech_stats *s) { (void)s; }
static int ctl_mech(int ring,int op,__u64 id)
{ (void)ring;(void)id;if(op!=XDEV_EXT_MECH_OP_STOP) return -EINVAL;event('X');return stop_error; }
static int ctl_report(bool pass,const char *line) { event('R');puts(line);return !pass; }
static int tracked_notify_result(const struct xdev_ext_mech_stats *s,__u64 groups)
{ event('N');return xdev_ext_mech_ctl_notify_result(s,groups); }
#define xdev_ext_mech_ctl_notify_result tracked_notify_result
#ifdef XDEV_EXT_MECH_TRANSPORT_STATS_VERSION
static int ctl_transport_stats(int ring,__u64 id,struct xdev_ext_mech_transport_stats *s)
{ (void)ring;event('T');*s=(struct xdev_ext_mech_transport_stats){.size=sizeof(*s),.version=XDEV_EXT_MECH_TRANSPORT_STATS_VERSION,.session_id=id,.native_controls=controls,.pending_acks=pending,.uncertain_controls=unknown};return 0; }
#endif
#ifdef XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_2
/* Observational only: a failed counter query must not change the verdict. */
static int ctl_transport_counters(int ring,__u64 id,struct xdev_ext_mech_transport_stats_v2 *s)
{ (void)ring;(void)id;(void)s;return -EINVAL; }
#endif
/* New observational NIC query is outside this reliable-control oracle. */
static int ctl_nic_accounting(int ring,__u64 id,struct xdev_ext_mech_transport_stats_v3 *s)
{ (void)ring;memset(s,0,sizeof(*s));s->v2.v1.session_id=id;return 0; }
static void ctl_print_nic_accounting(__u32 path,const struct xdev_ext_mech_transport_stats_v3 *s)
{ (void)path;(void)s; }
/* PRODUCTION_SOCKET_REPORT */
/* PRODUCTION_HELPER */
static int finalize(struct ctl_opts *o)
{
 struct ctl_run r={.ring=3,.session=7};
 __u32 path=XDEV_EXT_MECH_CTL_NIC_AFXDP_ZC;
 struct { __u32 nr; } pool={0};
 struct xdev_ext_mech_create c={0};
 struct xdev_ext_mech_transport_stats_v3 accounting;
 struct xdev_ext_mech_stats s={.session_id=7,.state=XDEV_EXT_MECH_SESSION_ACTIVE,.batches_done=2,.held=6,.recycled=6,.submitted={0,2},.completed={2,2}};
 bool freed=false,coarse=true;int ret=0,verdict=CTL_SETUP,probe=0;__u32 frames=3,pushed=0;char line[512];
 /* PRODUCTION_FINALIZATION */
out:
 return verdict;
}
int main(int argc,char **argv)
{
 struct ctl_opts o={.reliable=true,.groups=2,.max_attempts=1,.retry_timeout_ms=1};
 if(argc!=2) return 2;
 if(!strcmp(argv[1],"late-error")) late_error=-EIO;
 if(!strcmp(argv[1],"stop-error")) stop_error=-EBUSY;
 if(!strcmp(argv[1],"native")) controls=1;
 if(!strcmp(argv[1],"pending")) pending=1;
 if(!strcmp(argv[1],"unknown")) unknown=1;
 int verdict=finalize(&o);
 printf("FINAL verdict=%d events=%s\n",verdict,events);
 return 0;
}
'''
class FinalResult(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  source=(ROOT/'tools/xdev_ext_mech/xdev_ext_mech_ctl.c').read_text()
  fn=source[source.index('static int cmd_nic_nvme('):]
  start=re.search(r'\n\s*if \(o->reliable\)\s*\{',fn)
  if not start: raise RuntimeError('production reliable finalization absent')
  block=fn[start.start():fn.index('\nout:',start.start())]
  cls.tmp=tempfile.TemporaryDirectory(prefix='transport-final-result-');cls.addClassCleanup(cls.tmp.cleanup)
  p=Path(cls.tmp.name);helper=re.search(r'^static int ctl_finish_reliable\([^;{}]*\)\s*\{.*?^\}',source,re.M|re.S)[0]
  (p/'probe.c').write_text(FIXTURE.replace('/* PRODUCTION_SOCKET_REPORT */',re.search(r'^static bool ctl_socket_rx_report\([^;{}]*\)\s*\{.*?^\}',source,re.M|re.S)[0]).replace('/* PRODUCTION_HELPER */',helper).replace('/* PRODUCTION_FINALIZATION */',block));cls.bin=p/'probe'
  subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=undefined','-fno-sanitize-recover=undefined','-I',str(ROOT),str(p/'probe.c'),'-o',str(cls.bin)],check=True)
 def case(self,name,pass_expected):
  p=subprocess.run([str(self.bin),name],check=True,capture_output=True,text=True)
  result=re.search(r'FINAL verdict=(\d+) events=(\w+)',p.stdout)
  self.assertIsNotNone(result,p.stdout)
  self.assertEqual(int(result[1]),0 if pass_expected else 1,p.stdout)
  if not pass_expected: self.assertNotIn('=PASS',p.stdout)
  return result[2]
 def test_success_freezes_and_drains_before_pass(self):
  events=self.case('ok',True)
  self.assertRegex(events,r'LSNTXR$',events)
 def test_final_stats_late_error_never_passes(self): self.case('late-error',False)
 def test_final_native_control_never_passes(self): self.case('native',False)
 def test_final_pending_ack_never_passes(self): self.case('pending',False)
 def test_final_uncertain_ack_never_passes(self): self.case('unknown',False)
 def test_stop_ebusy_never_passes(self): self.case('stop-error',False)
if __name__=='__main__': unittest.main(verbosity=2)

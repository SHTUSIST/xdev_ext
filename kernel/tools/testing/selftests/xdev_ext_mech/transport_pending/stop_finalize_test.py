#!/usr/bin/env python3
"""Actual STOP drain/release and native callback errors through final unbind."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ.get('KERNEL_SRC',str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
path=ROOT/'tools/testing/selftests/xdev_ext_mech/provider/faults/run.py'
spec=importlib.util.spec_from_file_location('provider_extract',path)
extract=importlib.util.module_from_spec(spec);spec.loader.exec_module(extract)
EXTRA=r'''
static void cancelled_in_wait(void) {
 xdev_ext_mech_batch_complete_cancelled(wait_batch,pending_ticket,-ECANCELED);
 observe_retire(wait_batch);
}
static void native_error_in_wait(void) {
 xdev_ext_dma_complete(pending_cookie,pending_ticket,-EIO,false,0);
 observe_retire(wait_batch);
}
static void fatal_in_wait(void) {
 xdev_ext_mech_stage_dead(&wait_batch->s->st[0],-EIO);
 complete_in_wait();
}
static int final_stop(const char *mode) {
 struct xdev_ext_mech_session *s=bound_session();u8 *states=s->pool.state;
 int expected=0;
 if(!strcmp(mode,"first")) {
  xdev_ext_mech_session_stop(s,-EIO);xdev_ext_mech_session_stop(s,-ENXIO);expected=-EIO;
  EQ(s->last_err,-EIO,"first real fatal remains stable");
 } else if(!strcmp(mode,"late")) {
  xdev_ext_mech_session_stop(s,0);xdev_ext_mech_stage_dead(&s->st[0],-EIO);expected=-EIO;
  EQ(s->last_err,-EIO,"STOP0 does not seal error latch");
 } else if(!strcmp(mode,"unbind")) {sync_subject=&s->st[0];expected=-EIO;
 } else if(!strcmp(mode,"pending-fatal")) {
  wait_batch=batch_new(s);EQ(submit(wait_batch),0,"accepted native before stop");
  wait_hook=fatal_in_wait;expected=-EIO;
 } else if(!strcmp(mode,"published-before-stop")||!strcmp(mode,"published-before-fatal")) {
  EQ(s->ss.state,XDEV_EXT_MECH_SESSION_ACTIVE,"real active session before native callback");
  wait_batch=batch_new(s);EQ(submit(wait_batch),0,"accepted native before callback/STOP race");
  xdev_ext_dma_complete(pending_cookie,pending_ticket,-EIO,false,0);
  xdev_ext_mech_session_stop(s,!strcmp(mode,"published-before-fatal")?-ENXIO:0);
  observe_retire(wait_batch);expected=-EIO;
 } else if(!strcmp(mode,"native-error")) {
  wait_batch=batch_new(s);EQ(submit(wait_batch),0,"native failure owner before stop");
  wait_hook=native_error_in_wait;expected=-EIO;
 } else if(!strcmp(mode,"cancelled-native")) {
  wait_batch=batch_new(s);EQ(submit(wait_batch),0,"locally cancelled batch before stop");
  wait_hook=cancelled_in_wait;
 } else if(!strcmp(mode,"cancel")) {
  xdev_ext_mech_session_stop(s,0);xdev_ext_mech_set_err_locked(s,-ECANCELED);
  EQ(s->last_err,0,"normal stop cancellation is not a native fatal");
 }
 EQ(xdev_ext_mech_session_destroy(s),expected,"STOP returns final error after native unbind sync");
 EQ(host_unbinds,1,"native mappings released once after definite drain");
 EQ(region_unbinds,1,"region released after callbacks synchronized");
 EQ(owner.refs,0,"module references released after definite drain");
 free(states);return 0;
}
'''
class FinalStop(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  source=(ROOT/'io_uring/xdev_ext_mech.c').read_text()
  code=extract.generate()
  definitions='\n'.join(extract.function(source,n) for n in ('xdev_ext_mech_stage_dead','xdev_ext_mech_set_err_locked','xdev_ext_mech_batch_complete_cancelled'))
  code=code.replace('static struct module owner;',definitions+'\nstatic struct xdev_ext_mech_stage *sync_subject;\nstatic struct module owner;')
  code=code.replace('host_unbinds++;free(h);','host_unbinds++;if(sync_subject)xdev_ext_mech_stage_dead(sync_subject,-EIO);free(h);')
  code=code.replace('int main(int argc,char **argv) {',EXTRA+'\nint main(int argc,char **argv) {')
  code=code.replace('if(argc!=2)return 2;','if(argc!=2)return 2;\n return final_stop(argv[1]);')
  cls.tmp=tempfile.TemporaryDirectory(prefix='stop-finalize-');cls.addClassCleanup(cls.tmp.cleanup)
  p=Path(cls.tmp.name);(p/'probe.c').write_text(code);cls.binary=p/'probe'
  subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=undefined','-pthread','-I'+str(ROOT),str(p/'probe.c'),'-o',str(cls.binary)],check=True)
 def test_drain_and_synchronized_final_errors(self):
  for mode in ('idle','first','late','unbind','pending-fatal','native-error','published-before-stop','published-before-fatal','cancelled-native','cancel'):
   with self.subTest(mode=mode):
    run=subprocess.run([str(self.binary),mode],capture_output=True,text=True)
    self.assertEqual(run.returncode,0,run.stdout+run.stderr)
if __name__=='__main__':unittest.main(verbosity=2)

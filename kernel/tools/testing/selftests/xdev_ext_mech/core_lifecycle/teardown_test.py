#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real STOP drain, release decision and worker teardown after the drain bound.

The DMA adapter, session_destroy, session_release, quarantine and the reap
work are extracted verbatim through provider/faults/run.py.  Only the OS
boundary changes: a delayed kthread work records whether its timer is armed,
and kthread_destroy_worker() records any timer still armed when the worker
would be freed (the kernel WARNs and later runs the timer on freed memory).

A batch is retired with the real leave_locked() accounting, as in
transport_pending/stop_finalize_test.py; worker scheduling, batch_landed and
BPF execution still need KVM acceptance.
"""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
EXTRACT = HERE.parent / 'provider/faults/run.py'
spec = importlib.util.spec_from_file_location('provider_extract', EXTRACT)
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)

BOUNDARY = (
    ('struct kthread_delayed_work { struct kthread_work work; };',
     'struct kthread_delayed_work { struct kthread_work work; int armed; };'),
    ('static void kthread_cancel_delayed_work_sync(struct kthread_delayed_work *w) {(void)w;}',
     'static void kthread_cancel_delayed_work_sync(struct kthread_delayed_work *w) {w->armed=0;}'),
    ('static void kthread_destroy_worker(struct kthread_worker *w) {(void)w;destroyed_workers++;}',
     'static unsigned armed_at_destroy;static unsigned (*armed_probe)(void);\n'
     'static void kthread_destroy_worker(struct kthread_worker *w) {(void)w;destroyed_workers++;'
     'if(armed_probe)armed_at_destroy+=armed_probe();}'),
    ('static void native_unbind_host(void *h) {host_unbinds++;free(h);}',
     'static int native_unbind_host(void *h) {host_unbinds++;free(h);return 0;}'),
)

SCENARIOS = r'''
static struct xdev_ext_mech_session *tracked;
static unsigned tracked_armed(void) {
 return (unsigned)tracked->progress_work.armed+(unsigned)tracked->retry_work.armed;
}
/* Real accounting of one landed batch; true when it dropped the last reference. */
static bool retire(struct xdev_ext_mech_batch *b) {
 struct xdev_ext_mech_session *s=b->s;int result;
 assert(!xdev_ext_mech_completion_consume(&b->completion,b->ticket,&result));b->status=result;
 assert(!xdev_ext_mech_frames_move(s,b,XDEV_EXT_MECH_F_INFLIGHT,
  b->sequester?XDEV_EXT_MECH_F_SEQUESTERED:XDEV_EXT_MECH_F_HELD));
 b->queued=0;s->inbox.first=NULL;
 return xdev_ext_mech_leave_locked(s,b->sequester);
}
static int lifecycle(const char *mode) {
 struct xdev_ext_mech_session *s=bound_session();u8 *states=s->pool.state;
 struct xdev_ext_mech_batch *b=batch_new(s);
 /* The worker acquires producer lifecycle before native submission. */
 s->life=calloc(s->pool.nr_frames,sizeof(*s->life));assert(s->life);s->owns_life=true;
 s->plan[0]=(struct xdev_ext_mech_stage_uapi){.class_id=s->st[0].class_id,
  .direction=s->st[0].direction};
 b->producing=true;
 assert(!xdev_ext_mech_life_claim(&s->life[b->f[0].index],s->st[0].index,&b->life_token[0]));
 b->life_active=BIT(0);
 tracked=s;armed_probe=tracked_armed;
 EQ(submit(b),0,"accepted native command before STOP");
 if(!strcmp(mode,"quarantine_armed")) {
  /* Ambiguous outcome already landed; a provider progress timer is armed. */
  xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,127);
  EQ(retire(b),false,"creator reference outlives the ambiguous batch");
  s->progress_work.armed=1;s->retry_work.armed=1;
  EQ(xdev_ext_mech_session_destroy(s),-EBUSY,"ambiguous session is quarantined");
  EQ(destroyed_workers,1,"last reference destroys the quarantined worker");
  EQ(armed_at_destroy,0,"quarantine destroyed the worker with an armed delayed work");
  EQ(owner.refs,1,"quarantine keeps the provider module pin");
  EQ(host_unbinds,0,"quarantine keeps the host mapping");
  EQ(states[1],XDEV_EXT_MECH_F_SEQUESTERED,"ambiguous frame stays sequestered");
  return 0;
 }
 if(!strcmp(mode,"native_control")) atomic_inc(&s->native_controls);
 /* The drain bound passes while the accepted command is still in flight. */
 EQ(xdev_ext_mech_session_destroy(s),-EBUSY,"STOP after the drain bound keeps every reference");
 EQ(owner.refs,1,"pending command keeps the provider module pin");
 EQ(host_unbinds+region_unbinds+pool_releases+file_puts,0,"pending command keeps mappings, pool and files");
 EQ(states[1],XDEV_EXT_MECH_F_INFLIGHT,"timeout cannot recycle a device-owned frame");
 EQ(destroyed_workers,0,"the worker stays for the late completion");
 CHECK(s->ss.state!=XDEV_EXT_MECH_SESSION_ACTIVE,"STOP closed admission");
 if(!strcmp(mode,"pending"))return 0;
 bool native_control=!strcmp(mode,"native_control");
 bool exact=!strcmp(mode,"late_exact")||native_control;
 u64 life_ctrl=s->life[b->f[0].index].ctrl,claim=b->life_token[0];
 if(native_control)
  EQ(s->ss.state,XDEV_EXT_MECH_SESSION_ZOMBIE,"outstanding native control quarantines before completion");
 xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,exact?128:127);
 /* An exact provider completion cannot resolve another outstanding native
  * control: the already-ZOMBIE session must retain lifecycle custody. */
 EQ(b->sequester,!exact||native_control,"provider and session classify the late completion");
 if(native_control) {
  EQ(s->ss.state,XDEV_EXT_MECH_SESSION_ZOMBIE,"exact completion cannot revive a quarantined session");
  EQ(s->life[b->f[0].index].ctrl,life_ctrl,"quarantine retains the lifecycle ownership word");
  EQ(b->life_active,BIT(0),"quarantine keeps the native lifecycle claim active");
  EQ(b->life_token[0],claim,"quarantine retains the native lifecycle claim token");
  EQ(xdev_ext_mech_life_phase(&s->life[b->f[0].index]),XDEV_EXT_MECH_L_IO_PENDING,
   "quarantine cannot recycle the device-owned lifecycle");
 }
 s->progress_work.armed=1;
 EQ(retire(b),true,"late completion drops the last reference");
 xdev_ext_mech_reap(&s->reap_work);
 EQ(accepts,1,"an accepted command is never reissued");
 EQ(destroyed_workers,1,"last reference destroys the worker once");
 EQ(armed_at_destroy,0,"reap destroyed the worker with an armed delayed work");
 if(!strcmp(mode,"late_exact")) {
  EQ(owner.refs,0,"definite late completion releases the provider module pin");
  EQ(host_unbinds,1,"definite late completion unbinds the host mapping once");
  EQ(region_unbinds,1,"definite late completion unbinds the region once");
  EQ(pool_releases,1,"definite late completion releases the pinned pool");
  EQ(file_puts,1,"definite late completion puts the device file");
  free(states);
 } else {
  EQ(owner.refs,1,"unknown outcome keeps the provider module pin");
  EQ(host_unbinds+region_unbinds+pool_releases+file_puts,0,"unknown outcome keeps every reference");
  if(!strcmp(mode,"late_ambiguous"))
   EQ(states[1],XDEV_EXT_MECH_F_SEQUESTERED,"ambiguous late frame stays sequestered");
 }
 return 0;
}
'''


def build(root=None):
    if root:
        os.environ['KERNEL_SRC'] = str(root)
        extract.ROOT = Path(root).resolve()
    core = extract.source('io_uring/xdev_ext_mech.c')
    code = extract.generate()
    # The shared provider fixture predates lifecycle completion handoff. Keep
    # that decision, CPU synchronization and checked unbind in production C.
    code = code.replace('#include "io_uring/xdev_ext_mech_step.h"',
                        '#include "io_uring/xdev_ext_mech_step.h"\n'
                        '#include "io_uring/xdev_ext_mech_produced.h"\n'
                        '#define min(a,b) ((a)<(b)?(a):(b))', 1)
    helpers = '\n\n'.join(extract.function(core, name) for name in (
        'xdev_ext_mech_sync_for_cpu', 'xdev_ext_mech_trim_produced',
        'xdev_ext_mech_batch_handoff', 'xdev_ext_mech_batch_frame_claim',
        'xdev_ext_mech_unbind_checked'))
    marker = extract.function(core, 'xdev_ext_mech_batch_completion_publish')
    code = code.replace(marker, helpers + '\n' + marker, 1)
    code = code.replace(extract.function(core, 'xdev_ext_mech_session_release'),
                        'static void xdev_ext_mech_quarantine(struct xdev_ext_mech_session *s);\n' +
                        extract.function(core, 'xdev_ext_mech_session_release'), 1)
    for old, new in BOUNDARY:
        if old not in code:
            raise RuntimeError('fixture boundary changed: ' + old)
        code = code.replace(old, new)
    late = re.search(r'^static void xdev_ext_mech_release_late\(', core, re.M)
    tail = (extract.function(core, 'xdev_ext_mech_release_late') + '\n' if late else '')
    tail += extract.function(core, 'xdev_ext_mech_reap') + '\n'
    if late:
        tail = 'static void xdev_ext_mech_release_late(struct xdev_ext_mech_session *s);\n' + tail
    code = code.replace('/* Native provider fixture:', tail + '/* Native provider fixture:', 1)
    code = code.replace('int main(int argc,char **argv) {', SCENARIOS + '\nint main(int argc,char **argv) {')
    code = code.replace('if(argc!=2)return 2;',
                        'if(argc!=2)return 2;\n if(!strncmp(argv[1],"life_",5)){int bad=lifecycle(argv[1]+5);'
                        'if(!bad)printf("PASS %s %u checks\\n",argv[1],checks);return bad;}')
    return code


class Teardown(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev_ext-core-teardown-')
        cls.addClassCleanup(cls.tmp.cleanup)
        path = Path(cls.tmp.name)
        (path / 'probe.c').write_text(build())
        cls.binary = path / 'probe'
        built = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra',
                                '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                                '-Wno-unused-parameter', '-fsanitize=undefined',
                                '-fno-sanitize-recover=undefined', '-pthread', '-I' + str(extract.ROOT),
                                str(path / 'probe.c'), '-o', str(cls.binary)],
                               capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError(built.stdout + built.stderr)

    def probe(self, mode):
        run = subprocess.run([str(self.binary), 'life_' + mode], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('PASS life_' + mode, run.stdout)

    def test_quarantine_cancels_armed_delayed_work_before_freeing_worker(self):
        self.probe('quarantine_armed')

    def test_pending_command_at_drain_bound_keeps_every_reference(self):
        self.probe('pending')

    def test_definite_late_completion_releases_session_without_reissue(self):
        self.probe('late_exact')

    def test_ambiguous_late_completion_stays_quarantined_and_reap_cancels_timers(self):
        self.probe('late_ambiguous')

    def test_native_control_reference_forces_quarantine_even_after_exact_completion(self):
        self.probe('native_control')


if __name__ == '__main__':
    unittest.main(verbosity=2)

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
import sys

HERE = Path(__file__).resolve().parent
for _base in (HERE, *HERE.parents):
    if (_base / 'view.json').is_file() or (_base / 'source-layout.json').is_file():
        _shared = _base / 'tests/compute/transform_source.py'
        if not _shared.is_file():
            raise RuntimeError('missing owned transform source helper')
        sys.path.insert(0, str(_shared.parent))
        break
else:
    raise RuntimeError('missing owned checkout/view')
from transform_source import owned_dependency, verify_entry  # noqa: E402
verify_entry(__file__, 'tests/core/lifecycle/runtime/teardown_test.py')
EXTRACT = owned_dependency(__file__, 'tests/core/provider/faults/run.py')
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
)

# These shims implement only kthread/OS synchronization; production progress and
# release bodies below decide admission, native cleanup and lifetime ordering.
HOOK_BOUNDARY = r"""
static pthread_mutex_t hook_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hook_cv=PTHREAD_COND_INITIALIZER;
static bool hook_test,hook_entered,hook_allow,hook_returned,hook_sync_started;
static bool unbind_before_hook_return;
static unsigned late_kicks,hook_calls,rcu_at_unbind,cancel_at_unbind;
static void *hook_work;
static struct xdev_ext_mech_session *hook_session;
static void core_hook_sync(void) {
 if(!hook_test)return;
 assert(!pthread_mutex_lock(&hook_lock));
 hook_sync_started=true;pthread_cond_broadcast(&hook_cv);
 while(!hook_returned)pthread_cond_wait(&hook_cv,&hook_lock);
 assert(!pthread_mutex_unlock(&hook_lock));
}
static void core_hook_unbind(void) {
 if(!hook_test)return;
 /* An actual native disconnect may callback after worker admission closes. */
 xdev_ext_mech_stage_kick(&hook_session->st[0]);
 assert(!pthread_mutex_lock(&hook_lock));
 if(!hook_returned)unbind_before_hook_return=true;
 rcu_at_unbind=rcu_calls;cancel_at_unbind=cancel_calls;
 pthread_cond_broadcast(&hook_cv);
 /* Keep old-source failure deterministic without dereferencing freed host. */
 while(!hook_returned)pthread_cond_wait(&hook_cv,&hook_lock);
 assert(!pthread_mutex_unlock(&hook_lock));
}
static unsigned long blocking_progress(struct xdev_ext_mech_stage *st) {
 struct xdev_ext_dma_stage *cs=st->priv;
 void *borrowed=cs->copy.host;
 assert(borrowed);
 assert(!pthread_mutex_lock(&hook_lock));
 hook_calls++;hook_entered=true;pthread_cond_broadcast(&hook_cv);
 while(!hook_allow)pthread_cond_wait(&hook_cv,&hook_lock);
 assert(cs->copy.host==borrowed); /* Hook still legitimately borrows host. */
 assert(!pthread_mutex_unlock(&hook_lock));
 return 0;
}
static void *hook_thread(void *unused) {
 (void)unused;
 xdev_ext_mech_progress_work(&hook_session->progress_work.work);
 assert(!pthread_mutex_lock(&hook_lock));
 hook_returned=true;pthread_cond_broadcast(&hook_cv);
 assert(!pthread_mutex_unlock(&hook_lock));
 return NULL;
}
static void *release_thread(void *report) {
 int *result=malloc(sizeof(*result));assert(result);
 *result=xdev_ext_mech_session_release_report(hook_session,report);
 return result;
}
static int empty_progress_release(const char *mode) {
 struct xdev_ext_mech_session *s=bound_session();
 struct xdev_ext_mech_class_ops cls=*s->st[0].cls;
 struct xdev_ext_mech_stop_report report={0};
 u8 *states=s->pool.state;
 pthread_t progress,releaser;
 void *result;
 cls.progress=blocking_progress;s->st[0].cls=&cls;
 s->progress_ready=strcmp(mode,"failed_create")!=0;
 hook_test=true;hook_session=s;hook_work=&s->progress_work;
 if(!s->progress_ready) {
  /* Early queued work on failed CREATE must never borrow partial host. */
  xdev_ext_mech_progress_work(&s->progress_work.work);
  EQ(hook_calls,0,"partial CREATE has no ready progress consumer");
  hook_returned=true;
  EQ(xdev_ext_mech_session_release_report(s,NULL),0,"failed CREATE final release");
  EQ(late_kicks,0,"disconnect cannot requeue a gone worker");
  EQ(rcu_calls,1,"failed CREATE final release has exactly one RCU barrier");
  EQ(cancel_calls,3,"failed CREATE cancels each delayed work once");
  EQ(destroyed_workers,1,"failed CREATE destroys its worker once");
  free(states);return 0;
 }
 assert(!pthread_create(&progress,NULL,hook_thread,NULL));
 assert(!pthread_mutex_lock(&hook_lock));
 while(!hook_entered)pthread_cond_wait(&hook_cv,&hook_lock);
 assert(!pthread_mutex_unlock(&hook_lock));
 if(!strcmp(mode,"failed_unbind"))host_unmap_error=-EIO;
 assert(!pthread_create(&releaser,NULL,release_thread,
                        !strcmp(mode,"report")?&report:NULL));
 assert(!pthread_mutex_lock(&hook_lock));
 /* OLD reaches native unbind before synchronizing; GREEN reaches cancel. */
 while(!unbind_before_hook_return&&!hook_sync_started)
  pthread_cond_wait(&hook_cv,&hook_lock);
 hook_allow=true;pthread_cond_broadcast(&hook_cv);
 assert(!pthread_mutex_unlock(&hook_lock));
 assert(!pthread_join(progress,NULL));assert(!pthread_join(releaser,&result));
 bool failed=!strcmp(mode,"failed_unbind");
 EQ(*(int*)result,failed?-EIO:0,"final release preserves native cleanup result");free(result);
 EQ(unbind_before_hook_return,false,"native unbind before full progress hook return");
 EQ(hook_calls,1,"one actual empty progress consumer");
 EQ(late_kicks,0,"disconnect late kick cannot queue after worker_gone");
 EQ(host_unbinds,1,"one native host-unbind attempt after hook return");
 EQ(rcu_at_unbind,1,"exactly one RCU barrier before native disconnect");
 EQ(cancel_at_unbind,3,"all three delayed works cancelled before disconnect");
 EQ(rcu_calls,1,"final release adds no duplicate RCU barrier");
 EQ(cancel_calls,3,"final release cancels each delayed work once");
 EQ(destroyed_workers,failed?0:1,"only successful cleanup destroys worker once");
 if(failed) {
  EQ(region_unbinds,0,"failed host unbind retains region");
  EQ(owner.refs,1,"failed unbind retains module pin");
  EQ(pool_releases+file_puts,0,"failed unbind retains pool and file");
  EQ(s->ss.state,XDEV_EXT_MECH_SESSION_ZOMBIE,"failed unbind quarantines session");
  CHECK(s->st[0].priv!=NULL,"failed unbind retains stage context");
 } else {
  EQ(region_unbinds,1,"region released once");EQ(owner.refs,0,"module pin released");
  free(states);
 }
 return 0;
}
"""

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
 /* The real END path notifies every provider of the final frame fate before
  * dropping the batch reference. Keep native window leases in that boundary. */
 for(u32 i=0;i<s->nr_stages;i++)
  if(s->st[i].cls->batch_release)
   s->st[i].cls->batch_release(&s->st[i],b,b->sequester);
 return xdev_ext_mech_leave_locked(s,b->sequester);
}
static int lifecycle(const char *mode) {
 struct xdev_ext_mech_session *s=bound_session();u8 *states=s->pool.state;
 struct xdev_ext_mech_batch *b=batch_new(s);
 /* The worker acquires producer lifecycle before native submission. */
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
 EQ(s->worker_gone,false,"accepted deferred drain keeps progress admission open");
 EQ(rcu_calls,0,"accepted deferred drain has no final-release RCU barrier");
 EQ(cancel_calls,0,"accepted deferred drain has not cancelled its worker");
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
 EQ(rcu_calls,1,"late final release has one RCU barrier");
 EQ(cancel_calls,3,"late final release cancels each delayed work once");
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


def build(root=None, mutation=None):
    if root:
        os.environ['KERNEL_SRC'] = str(root)
        extract.ROOT = Path(root).resolve()
    core = extract.source('io_uring/xdev_ext_mech.c')
    original_source = extract.source
    if mutation == 'old_unbind_order':
        release = extract.function(core, 'xdev_ext_mech_session_release_disposition')
        start = release.index('\tspin_lock_irqsave(&s->lock, flags);')
        end = release.index('\tif (report) {', start)
        prefix = release[start:end]
        changed = release[:start] + release[end:]
        changed = changed.replace('\tif (report) {', '\tif (report) {\n' + prefix, 1)
        core = core.replace(release, changed, 1)
    elif mutation == 'premature_worker_gone':
        destroy = extract.function(core, 'xdev_ext_mech_session_destroy_report')
        changed = destroy.replace('xdev_ext_mech_session_stop(s, 0);',
                                  'xdev_ext_mech_session_stop(s, 0);\n s->worker_gone = true;', 1)
        if changed == destroy:
            raise RuntimeError('SETUP premature worker mutant anchor')
        core = core.replace(destroy, changed, 1)
    elif mutation is not None:
        raise RuntimeError('unknown mutation')
    if mutation:
        extract.source = lambda path: core if path == 'io_uring/xdev_ext_mech.c' else original_source(path)
    try:
        code = extract.generate()
    finally:
        extract.source = original_source
    code = code.replace('void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) {(void)st;queued_work++;}',
                        'void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st);')
    code = code.replace('#define synchronize_rcu() ((void)0)', 'static unsigned rcu_calls;\n#define synchronize_rcu() (++rcu_calls)')
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
    # Compile the real ready gate, stage kick and entire worker function.
    progress = extract.function(core, 'xdev_ext_mech_stage_kick') + '\n' + extract.function(core, 'xdev_ext_mech_progress_work') + '\n'
    marker = 'static void xdev_ext_mech_quarantine(struct xdev_ext_mech_session *s);'
    boundary = 'static void core_hook_sync(void);static void core_hook_unbind(void);\n'
    boundary += 'static void *hook_work;static unsigned late_kicks;\n'
    boundary += 'static void xdev_ext_mech_order_kick(struct xdev_ext_mech_session *s){(void)s;}\n'
    boundary += 'static void kthread_mod_delayed_work(struct kthread_worker *w,struct kthread_delayed_work *d,unsigned long t){(void)w;(void)d;(void)t;late_kicks++;}\n'
    boundary += 'static void kthread_queue_delayed_work(struct kthread_worker *w,struct kthread_delayed_work *d,unsigned long t){(void)w;(void)d;(void)t;}\n'
    code = code.replace(marker, boundary + progress + marker, 1)
    code = code.replace('static void kthread_cancel_delayed_work_sync(struct kthread_delayed_work *w) {w->armed=0;}',
        'static void kthread_cancel_delayed_work_sync(struct kthread_delayed_work *w) {cancel_calls++;if(w==hook_work)core_hook_sync();w->armed=0;}')
    # Forward declarations must precede the actual OS boundary definitions.
    code = code.replace('static void kthread_cancel_delayed_work_sync(',
        'static void core_hook_sync(void);static void *hook_work;static unsigned cancel_calls;\nstatic void kthread_cancel_delayed_work_sync(', 1)
    code = code.replace('static void kthread_flush_worker(struct kthread_worker *w) {(void)w;}',
        'static void kthread_flush_worker(struct kthread_worker *w) {(void)w;core_hook_sync();}')
    code = code.replace('static int native_unbind_host(void *h) {host_unbinds++;',
        'static void core_hook_unbind(void);\nstatic int native_unbind_host(void *h) {core_hook_unbind();host_unbinds++;')
    code = code.replace('int main(int argc,char **argv) {', HOOK_BOUNDARY + SCENARIOS + '\nint main(int argc,char **argv) {')
    code = code.replace('if(argc!=2)return 2;',
                        'if(argc!=2)return 2;\n if(!strncmp(argv[1],"empty_",6)){int bad=empty_progress_release(argv[1]+6);if(!bad)printf("PASS %s %u checks\\n",argv[1],checks);return bad;}\n if(!strncmp(argv[1],"life_",5)){int bad=lifecycle(argv[1]+5);'
                        'if(!bad)printf("PASS %s %u checks\\n",argv[1],checks);return bad;}')
    return code


class Teardown(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev_ext-core-teardown-')
        cls.addClassCleanup(cls.tmp.cleanup)
        path = Path(cls.tmp.name)
        # Shared executor includes use the provider fixture's OS primitives.
        for name in ('atomic', 'fs', 'list', 'module', 'mutex', 'xdev_ext_mech', 'slab'):
            header = path / 'linux' / (name + '.h')
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text('/* OS boundary: definitions are supplied by the fixture. */\n')
        code = build()
        include_root = extract.compiler_headers(extract.ROOT, path / 'qualified-include', code,
                                               reader=extract.source, search=('', 'io_uring'))
        (path / 'probe.c').write_text(code)
        cls.binary = path / 'probe'
        cls.compile_argv = [os.environ.get('CC', 'cc'), '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                            '-Wno-unused-parameter', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', '-pthread', '-I' + str(path),
                            '-I' + str(include_root), '-I' + str(include_root / 'io_uring'),
                            str(path / 'probe.c'), '-o', str(cls.binary)]
        built = subprocess.run(cls.compile_argv, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError(built.stdout + built.stderr)

    def probe(self, mode):
        run = subprocess.run([str(self.binary), 'life_' + mode], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('PASS life_' + mode, run.stdout)

    def test_compiling_old_order_and_premature_stop_mutants_are_rejected(self):
        for mutation, mode, message in (
            ('old_unbind_order', 'empty_legacy', 'native unbind before full progress hook return'),
            ('premature_worker_gone', 'life_pending', 'accepted deferred drain keeps progress admission open')):
            with self.subTest(mutation=mutation):
                path = Path(self.tmp.name)
                source = path / (mutation + '.c')
                source.write_text(build(mutation=mutation))
                binary = path / mutation
                argv = self.compile_argv[:-3] + [str(source), '-o', str(binary)]
                built = subprocess.run(argv, capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                run = subprocess.run([str(binary), mode], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn(message, run.stderr)

    def test_empty_progress_borrow_is_synchronized_before_legacy_unbind(self):
        self.probe_empty('legacy')

    def test_report_release_synchronizes_the_same_hook(self):
        self.probe_empty('report')

    def test_failed_create_early_progress_and_disconnect_kick(self):
        self.probe_empty('failed_create')

    def test_failed_unbind_has_one_barrier_and_retains_every_pin(self):
        self.probe_empty('failed_unbind')

    def probe_empty(self, mode):
        run = subprocess.run([str(self.binary), 'empty_' + mode], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('PASS empty_' + mode, run.stdout)

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

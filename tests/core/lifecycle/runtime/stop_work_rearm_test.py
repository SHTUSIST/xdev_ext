#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Production stop_work must not arm progress_work once the worker is going.

stop_work queued before the last reference can still run inside the flush of
kthread_destroy_worker().  A progress timer it arms there outlives the
worker (WARN, then a timer callback on freed memory).  The fixture is the
recycle-tail boundary with a class whose progress callback keeps asking for
another tick, as AF_XDP RX-pending drain and reliable transport do.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
TAIL = HERE.parent / 'xdev_ext_mech_recycle_tail_fixture.c'

import sys
sys.path.insert(0, str(HERE.parent))
from xdev_ext_mech_recycle_tail_test import function  # noqa: E402

BOUNDARY = (
    ('static const struct xdev_ext_mech_class_ops class_callbacks = {.batch_release=verify_final_release};',
     'static unsigned long pending_progress(struct xdev_ext_mech_stage *st) {(void)st;return 1;}\n'
     'static const struct xdev_ext_mech_class_ops class_callbacks = '
     '{.batch_release=verify_final_release,.progress=pending_progress};'),
    ('static void kthread_mod_delayed_work(int q,struct kthread_work *w,unsigned long delay) '
     '{(void)q;(void)w;(void)delay;}',
     'static unsigned arms,arms_after_gone,arms_unlocked;\n'
     'static void kthread_mod_delayed_work(int q,struct kthread_work *w,unsigned long delay) '
     '{(void)q;(void)w;(void)delay;arms++;arms_after_gone+=event_session->worker_gone;'
     'arms_unlocked+=!test_lock_depth;}'),
)

SCENARIO = r'''
static int rearm(const char *mode) {
 struct xdev_ext_mech_session s;struct io_xdev_ext_umem_mech m;__u8 state[8];
 setup(&s,&m,state,0,1);s.start_return_pending=false;
 s.progress_ready=strcmp(mode,"binding")!=0;
 xdev_ext_mech_session_stop(&s,0);
 if(!strcmp(mode,"gone"))s.worker_gone=true; /* the last reference left meanwhile */
 xdev_ext_mech_stop_work(&s.stop_work);
 if(!strcmp(mode,"binding"))
  return check(arms==0,"STOP called class progress before full bind publication");
 if(!strcmp(mode,"gone"))
  return check(arms_after_gone==0,"stop_work armed progress_work after worker_gone");
 return check(arms>0,"stop_work no longer re-arms progress for a live worker")|
  check(arms_unlocked==0,"progress re-arm is not ordered against worker_gone by s->lock");
}
'''


class StopWorkRearm(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the current ordered/recycle core closure and its exact OS
        # fields, preserving XDEV_EXT_RECYCLE_SOURCE and all rearm scenarios.
        from ordered_frames_test import build

        def rearm_boundary(fixture, core):
            for old, new in BOUNDARY:
                if old not in fixture:
                    raise RuntimeError('recycle fixture boundary changed: ' + old)
                fixture = fixture.replace(old, new)
            fixture = fixture.replace(' return ordered_scenario(argv[1]);\n', '')
            fixture = fixture.replace('int main(int argc,char **argv) {',
                                      SCENARIO + 'int main(int argc,char **argv) {', 1)
            return fixture.replace(' assert(argc==2);\n',
                ' assert(argc==2);\n if(!strncmp(argv[1],"rearm_",6))return rearm(argv[1]+6);\n', 1)

        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-stop-rearm-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = build(cls.temp.name, rearm_boundary)

    def probe(self, mode):
        run = subprocess.run([str(self.binary), 'rearm_' + mode], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_stop_work_before_full_bind_never_enters_class_progress(self):
        self.probe('binding')

    def test_stop_work_after_worker_gone_arms_no_timer(self):
        self.probe('gone')

    def test_stop_work_rearms_progress_for_live_worker_under_session_lock(self):
        self.probe('live')


if __name__ == '__main__':
    unittest.main(verbosity=2)

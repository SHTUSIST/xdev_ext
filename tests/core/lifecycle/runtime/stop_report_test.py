#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""STOP_REPORT returns real terminal observations before the session is freed."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('provider_extract', HERE.parent / 'provider/faults/run.py')
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)

ABI = r'''
#include <stddef.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "include/uapi/linux/xdev_ext_policy.h"
_Static_assert(XDEV_EXT_MECH_OP_STOP == 3, "legacy STOP opcode remains 3");
_Static_assert(XDEV_EXT_MECH_OP_STOP_REPORT == 9, "pointer STOP_REPORT opcode 9");
_Static_assert(XDEV_EXT_MECH_STOP_REPORT_VERSION == 1, "STOP_REPORT version 1");
_Static_assert(sizeof(struct xdev_ext_mech_stop_report) == 400, "STOP_REPORT size");
_Static_assert(offsetof(struct xdev_ext_mech_stop_report, session_id) == 8, "64-bit id");
_Static_assert(offsetof(struct xdev_ext_mech_stop_report, stats) == 16, "stats offset");
_Static_assert(offsetof(struct xdev_ext_mech_stop_report, transport) == 184, "transport offset");
_Static_assert(sizeof(((struct xdev_ext_mech_stop_report *)0)->transport) == 216, "full v4 transport snapshot");
int main(void) { return 0; }
'''

class StopReport(unittest.TestCase):
    def test_public_abi_preserves_legacy_stop_and_full_width_id(self):
        with tempfile.TemporaryDirectory(prefix='xdev-stop-report-abi-') as tmp:
            src = Path(tmp) / 'abi.c'
            src.write_text(ABI)
            built = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Werror',
                                    '-I' + str(extract.ROOT), str(src), '-o', str(Path(tmp) / 'abi')],
                                   capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)

BOUNDARY = r'''
#define __user
#define __must_hold(x)
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
#define list_del_rcu list_del
struct io_ring_ctx { pthread_mutex_t uring_lock; struct list_head xdev_ext_mech_sessions; };
static void *copy_read_fault;
static bool copy_write_fault;
static unsigned copy_writes;
static int copy_from_user(void *dst,const void *src,size_t n) {
 if(src==copy_read_fault)return 1;
 memcpy(dst,src,n);return 0;
}
static int copy_to_user(void *dst,const void *src,size_t n) {
 if(copy_write_fault)return 1;
 copy_writes++;memcpy(dst,src,n);return 0;
}
static const void *memchr_inv(const void *ptr,int c,size_t n) {
 const unsigned char *p=ptr;for(size_t i=0;i<n;i++)if(p[i]!=(unsigned char)c)return p+i;return NULL;
}
static int xdev_ext_mech_create(struct io_ring_ctx *c,void *p){(void)c;(void)p;abort();}
static int xdev_ext_mech_start(struct io_ring_ctx *c,void *p){(void)c;(void)p;abort();}
static int xdev_ext_mech_stats(struct io_ring_ctx *c,void *p){(void)c;(void)p;abort();}
static int xdev_ext_mech_notify_arm_op(struct io_ring_ctx *c,void *p){(void)c;(void)p;abort();}
static int xdev_ext_mech_transport_stats(struct io_ring_ctx *c,void *p){(void)c;(void)p;abort();}
static int xdev_ext_mech_user_stage_create(void *p){(void)p;abort();}
static int xdev_ext_mech_stage_caps_op(struct io_ring_ctx *c,void *p){(void)c;(void)p;abort();}
/* STOP_REPORT tests never dispatch these new operations. Abort preserves that
 * scope instead of manufacturing a successful CREATE_REPORT/diagnostic query. */
static int xdev_ext_mech_create_report_op(struct io_ring_ctx *c,void *p){(void)c;(void)p;abort();}
static int xdev_ext_mech_stage_diag_op(struct io_ring_ctx *c,void *p){(void)c;(void)p;abort();}
static int xdev_ext_mech_session_release_report(struct xdev_ext_mech_session *,struct xdev_ext_mech_stop_report *);
static int xdev_ext_mech_session_destroy_report(struct xdev_ext_mech_session *,struct xdev_ext_mech_stop_report *);
static void xdev_ext_mech_stats_fill(struct xdev_ext_mech_session *,struct xdev_ext_mech_stats *);
static void xdev_ext_mech_transport_stats_fill(struct xdev_ext_mech_session *,struct xdev_ext_mech_transport_stats_v4 *,u32);
'''

def build():
    core = extract.source('io_uring/xdev_ext_mech.c')
    code = extract.generate()
    code = code.replace('#include "include/uapi/linux/xdev_ext_mech.h"',
                        '#include "include/uapi/linux/xdev_ext_mech.h"\n#include "include/uapi/linux/xdev_ext_policy.h"')
    # The shared extractor supplies the clock and real report helper bodies.
    # Replace its legacy-only flush trap with this report test's observable OS
    # boundary instead of adding a second function definition.
    flush = 'static void kthread_flush_worker(struct kthread_worker *w) {(void)w;assert(!"unexpected report capture on legacy STOP");}'
    if code.count(flush) != 1:
        raise RuntimeError('missing shared legacy flush boundary')
    code = code.replace(flush,
                        'static void kthread_flush_worker(struct kthread_worker *w) {(void)w;flushed_workers++;if(sync_hook)sync_hook();}')
    code = code.replace('static void kthread_destroy_worker(struct kthread_worker *w) {(void)w;destroyed_workers++;}',
                        'static unsigned flushed_workers;static void (*sync_hook)(void);\nstatic void kthread_destroy_worker(struct kthread_worker *w) {(void)w;destroyed_workers++;if(sync_hook)sync_hook();}')
    marker = 'static void xdev_ext_mech_quarantine(struct xdev_ext_mech_session *s);'
    if marker not in code:
        raise RuntimeError('missing fixture setup insertion point')
    code = code.replace(marker, BOUNDARY + '\n' + marker, 1)
    additional = '\n\n'.join(extract.function(core, name) for name in (
        'xdev_ext_mech_find',
        'xdev_ext_mech_stop_op','xdev_ext_mech_stop_report_op','io_xdev_ext_mech_register'))
    code = code.replace('/* Native provider fixture:', additional + '\n/* Native provider fixture:', 1)
    scenarios = (HERE / 'stop_report_fixture.c.in').read_text()
    code = code.replace('int main(int argc,char **argv) {', scenarios + '\nint main(int argc,char **argv) {')
    code = code.replace('if(argc!=2)return 2;', 'if(argc!=2)return 2;\n if(!strncmp(argv[1],"report_",7)){int bad=report_case(argv[1]+7);if(!bad)printf("PASS %s %u checks\\n",argv[1],checks);return bad;}')
    return code

class StopReportBehavior(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev-stop-report-')
        cls.addClassCleanup(cls.tmp.cleanup)
        path = Path(cls.tmp.name)
        (path / 'probe.c').write_text(build())
        cls.binary = path / 'probe'
        result = subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra',
            '-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter',
            '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',
            '-I'+str(extract.ROOT),str(path/'probe.c'),'-o',str(cls.binary)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError(result.stdout+result.stderr)

    def probe(self, mode):
        env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0:abort_on_error=1')
        result=subprocess.run([str(self.binary),'report_'+mode],capture_output=True,text=True,timeout=10,env=env)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('PASS report_'+mode,result.stdout)


for case in ('size','version','stats_input','transport_input','read_fault','unknown','cmd_refs',
             'quarantine','deferred','unbind_error','late_error','write_fault','legacy','success'):
    setattr(StopReportBehavior,'test_'+case,lambda self,case=case:self.probe(case))

if __name__ == '__main__':
    unittest.main(verbosity=2)

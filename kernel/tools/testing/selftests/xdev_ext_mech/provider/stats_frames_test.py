#!/usr/bin/env python3
"""Execute production landing accounting and complete STATS fill, without worker scheduling."""
import pathlib,re,subprocess,tempfile,unittest
HERE=pathlib.Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'io_uring/xdev_ext_mech.c').is_file())
def function(text,name):
    m=re.search(r'^(?:static )?[^;{}]*\b'+name+r'\([^;{}]*\)\n\{\n.*?^\}',text,re.M|re.S)
    if not m:raise AssertionError('missing production function '+name)
    return m[0]
class Frames(unittest.TestCase):
    def test_real_landing_counter_and_stats(self):
        core=(ROOT/'io_uring/xdev_ext_mech.c').read_text()
        header=(ROOT/'include/linux/xdev_ext_mech.h').read_text()
        counters=re.search(r'enum xdev_ext_mech_counter \{.*?\n\};',header,re.S)[0]
        landed=function(core,'xdev_ext_mech_batch_landed')
        # Execute the complete unmodified accounting prefix before CQE/BPF dispatch.
        accounting=landed[:landed.index('\n\tif (cls->cqe_size)')]+'\n}\n'
        code=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "include/uapi/linux/xdev_ext_mech.h"
typedef uint64_t u64;typedef uint32_t u32;typedef int32_t s32;
#define READ_ONCE(x) (x)
#define WARN_ON_ONCE(x) (x)
#define atomic64_read(p) (*(p))
#define atomic64_inc(p) (++*(p))
#define atomic64_add(n,p) (*(p)+=(n))
#define hweight32(x) __builtin_popcount(x)
#define spin_lock_irqsave(l,f) do{(void)(l);(f)=0;}while(0)
#define spin_unlock_irqrestore(l,f) do{(void)(l);(void)(f);}while(0)
#define XDEV_EXT_MECH_SESSION_ZOMBIE 5
#define XDEV_EXT_MECH_F_INFLIGHT 3
#define XDEV_EXT_MECH_F_SEQUESTERED 4
#define XDEV_EXT_MECH_F_HELD 2
/* COUNTERS */
struct xdev_ext_mech_class_ops { int unused; };
struct xdev_ext_mech_stage { const struct xdev_ext_mech_class_ops *cls; };
struct xdev_ext_mech_call_args { int unused; };
struct xdev_ext_mech_batch { struct { unsigned stage; } bs; bool sequester; unsigned present; };
struct xdev_ext_mech_session { u64 id,cnt[XDEV_EXT_MECH_CNT_NR],submitted[4],completed[4],done,aborted;
 struct { unsigned state,inflight,sequestered; } ss;int last_err,lock;struct xdev_ext_mech_stage st[4]; };
static int xdev_ext_mech_frames_move(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,int from,int to)
{ (void)s;(void)b;(void)from;assert(to==XDEV_EXT_MECH_F_SEQUESTERED);return 0; }
static void xdev_ext_mech_notify_locked(struct xdev_ext_mech_session *s,bool urgent) {(void)s;(void)urgent;}
/* COUNT */
/* LANDED_ACCOUNTING */
/* STATS */
int main(void) {
 struct xdev_ext_mech_session s={.id=9,.ss={.state=1,.sequestered=1}};
 struct xdev_ext_mech_class_ops cls={0};s.st[0].cls=&cls;
 struct xdev_ext_mech_batch b={.sequester=true,.present=3};
 xdev_ext_mech_batch_landed(&s,&b);
 struct xdev_ext_mech_stats out;xdev_ext_mech_stats_fill(&s,&out);
 assert(out.sequestered==2);assert(out.completed[0]==1);assert(s.ss.sequestered==1);
 puts("PASS real landing accounting and STATS: one quarantined batch, two sequestered frames");
 return 0;
}
'''.replace('/* COUNTERS */',counters).replace('/* COUNT */',function(core,'xdev_ext_mech_count')).replace('/* LANDED_ACCOUNTING */',accounting).replace('/* STATS */',function(core,'xdev_ext_mech_stats_fill'))
        with tempfile.TemporaryDirectory(prefix='xdev-ext-stats-') as tmp:
            c=pathlib.Path(tmp)/'test.c';c.write_text(code);exe=pathlib.Path(tmp)/'test'
            r=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-variable','-Wno-unused-value','-I'+str(ROOT),str(c),'-o',str(exe)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            r=subprocess.run([str(exe)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr);print(r.stdout.strip())
        runtime=(HERE/'dma_provider_runtime.c').read_text()
        # The guest must use this field's proven frame-count unit.
        self.assertTrue('stats.sequestered==start.nr_user_frames' in runtime,'guest must expect frames rather than batches')
if __name__=='__main__':unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Execute real landing/STATS and produced retirement, without worker scheduling."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("provider_extract", HERE / "faults/run.py")
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)
ROOT = extract.ROOT


class Frames(unittest.TestCase):
    def test_real_landing_counter_and_stats(self):
        core = (ROOT / "io_uring/xdev_ext_mech.c").read_text()
        landed = extract.function(core, "xdev_ext_mech_batch_landed")
        # Execute the complete unmodified prefix before CQE/BPF dispatch.
        accounting = landed[:landed.index("\n\tif (cls->cqe_size)")] + "\n}\n"
        helpers = r"""
typedef __s32 s32;
#define hweight32(v) __builtin_popcount(v)
/* CALL_ARGS */
/* Trace observation is disabled at this host boundary; no decision is stubbed. */
static void xdev_ext_mech_trace_batch(struct xdev_ext_mech_batch *b,
                                    const char *phase,u64 ticket,int status)
{ (void)b;(void)phase;(void)ticket;(void)status; }
""".replace("/* CALL_ARGS */", extract.structure(
            (ROOT / "include/linux/xdev_ext_mech.h").read_text(), "xdev_ext_mech_call_args")) + extract.function(core, "xdev_ext_mech_recycle_produced_tail") + "\n" + accounting
        code = extract.generate()
        stats = extract.function(core, "xdev_ext_mech_stats_fill")
        # STOP_REPORT's release fixture already includes the actual filler.
        # Older source snapshots still need the same verbatim dependency here.
        if stats not in code:
            helpers += "\n" + stats
        code = code.replace("/* Native provider fixture:",
                                          helpers + "\n/* Native provider fixture:", 1)
        code = code.replace("int main(int argc,char **argv)", "int provider_main(int argc,char **argv)", 1)
        code += r"""
static unsigned tail_recycles;
static void stats_recycle(struct xdev_ext_mech_pool *pool,struct xdev_ext_mech_frame *frame)
{ assert(frame->index==1 && pool->state[1]==XDEV_EXT_MECH_F_K_FREE);tail_recycles++; }
int main(void) {
 struct xdev_ext_mech_session s={.id=9,.ss={.state=1,.sequestered=1}};
 struct xdev_ext_mech_class_ops cls={0};s.st[0].cls=&cls;
 struct xdev_ext_mech_batch b={.sequester=true,.present=3};
 u8 states[2]={XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_INFLIGHT};
 s.pool.state=states;s.pool.nr_frames=2;b.nr_frames=2;
 b.f[0].index=0;b.f[1].index=1;
 xdev_ext_mech_batch_landed(&s,&b);
 struct xdev_ext_mech_stats out;xdev_ext_mech_stats_fill(&s,&out);
 assert(out.sequestered==2);assert(out.completed[0]==1);assert(s.ss.sequestered==1);
 assert(states[0]==XDEV_EXT_MECH_F_SEQUESTERED && states[1]==XDEV_EXT_MECH_F_SEQUESTERED);
 puts("PASS real landing accounting and STATS: one quarantined batch, two sequestered frames");
 /* A successful short producer already invalidated its unproduced lifecycle
  * tail. Exercise the real worker retirement and actual custody transition. */
 u8 owners[2]={0};
 const struct xdev_ext_mech_pool_ops tail_ops={.recycle=stats_recycle};
 s.pool.ops=&tail_ops;s.transform_owner=owners;
 states[0]=states[1]=XDEV_EXT_MECH_F_HELD;
 b=(struct xdev_ext_mech_batch){.produced_set=true,.produced_used=1,.nr_frames=2,.present=3};
 b.f[0].index=0;b.f[1].index=1;
 assert(!xdev_ext_mech_recycle_produced_tail(&s,&b));
 assert(b.nr_frames==1 && b.present==1 && tail_recycles==1);
 assert(states[0]==XDEV_EXT_MECH_F_HELD && states[1]==XDEV_EXT_MECH_F_K_FREE);
 assert(s.cnt[XDEV_EXT_MECH_CNT_RECYCLED]==1);
 puts("PASS real produced tail retirement and custody transition");
 return 0;
}
"""
        with tempfile.TemporaryDirectory(prefix="xdev-ext-stats-") as temporary:
            path = Path(temporary)
            source = path / "test.c"
            source.write_text(code)
            executable = path / "test"
            command = [os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-Wall", "-Wextra",
                       "-Werror", "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-parameter",
                       "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-pthread",
                       "-I" + str(ROOT), str(source), "-o", str(executable)]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            run = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            print(run.stdout.strip())
        runtime = (HERE / "dma_provider_runtime.c").read_text()
        # The guest must use this field's proven frame-count unit.
        self.assertTrue('stats.sequestered==start.nr_user_frames' in runtime,'guest must expect frames rather than batches')


if __name__ == "__main__":
    unittest.main(verbosity=2)

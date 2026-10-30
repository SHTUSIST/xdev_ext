# SPDX-License-Identifier: GPL-2.0
"""Execute the actual collective timing/catch path with delayed kernel END.

Only CUDA calls and session statistics are Host boundaries. No GPU, live kernel,
physical DMA or performance is exercised. A missing/wrong prefix wait makes the
actual driver emit an interval while native custody is still pending.
"""
import importlib.util
import os
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]


def function(source, marker):
    start = source.index(marker)
    start = source.rfind('\n', 0, start) + 1
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class NativeCompletionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='tp-end-')
        out = Path(cls.directory.name)
        spec = importlib.util.spec_from_file_location('tp_end_layout', ROOT / 'tools/layout.py')
        layout = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = layout
        spec.loader.exec_module(layout)
        view = layout.materialize_view(ROOT, out / 'source-view')
        (out / 'cuda.h').write_bytes(
            (ROOT / 'tests/compute/tp/driver_boundary.h').read_bytes())
        driver = (ROOT / 'tests/benchmarks/tp/driver.cc').read_text()
        start = driver.index('uint64_t start=now_ns();\n   if(o.mode==1)')
        end = driver.index('for(unsigned j=0;j<o.depth;++j)', start)
        measured = driver[start:end]
        echo = (ROOT / 'tests/benchmarks/tp/echo.h').read_text()
        helpers = (function(echo, 'static uint64_t monotonic_ns()') + '\n' +
                   function(echo, 'void wait_native_complete('))
        caught = function(driver, 'catch(const std::exception &e)')
        caught = caught[caught.index('catch('):]
        code = r'''
#include <cerrno>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>
#include <time.h>
#include <sched.h>
#include <unistd.h>
#include <peer_endpoint_owner.h>
#include "tests/benchmarks/tp/options.h"
static uint64_t ticks, target;
static unsigned reads[2], completed[2], intervals, premature;
static bool retained;
static std::string scenario;
static int native_check(int rc) {if(rc)throw std::runtime_error("native failure");return rc;}
#define NATIVE(c) native_check(c)
#define CU(c) native_check(c)
struct xdev_ext_peer_endpoint {unsigned index;};
struct xdev_ext_session {unsigned index;};
static xdev_ext_peer_endpoint endpoints[2]={{0},{1}};
static xdev_ext_session sessions[2]={{0},{1}};
extern "C" xdev_ext_session *xdev_ext_peer_endpoint_session(xdev_ext_peer_endpoint *e)
{return &sessions[e->index];}
extern "C" int xdev_ext_session_stats(xdev_ext_session *s,xdev_ext_mech_stats *out) {
 *out={};out->inflight=7; // Later admitted work is allowed after this prefix.
 unsigned count=++reads[s->index];
 completed[s->index]=count==1?unsigned(target-1):unsigned(target);
 out->batches_done=completed[s->index];
 if(scenario=="timeout")out->batches_done=completed[s->index]=0;
 if(scenario=="api_error")return -EIO;
 if(scenario=="last_error")out->last_err=-EIO;
 if(scenario=="abort")out->batches_abort=1;
 if(scenario=="held")out->held=1;
 if(scenario=="sequestered")out->sequestered=1;
 if(scenario=="timeouts")out->timeouts=1;
 if(scenario=="protocol")out->protocol_err=1;
 if(scenario=="rejects")out->rejects=1;
 return 0;
}
extern "C" int xdev_ext_cuda_peer_owner_get_view(xdev_ext_cuda_peer_owner *,xdev_ext_cuda_peer_owner_view *v) {
 v->tx_endpoint=&endpoints[0];v->rx_endpoint=&endpoints[1];return 0;
}
static int boundary_clock(clockid_t,timespec *t) {ticks+=10;t->tv_sec=0;t->tv_nsec=ticks;return 0;}
#define clock_gettime boundary_clock
struct tp_eval_echo {
 xdev_ext_cuda_peer_owner_view view{};
 tp_eval_options options;
''' + helpers + r'''
};
#undef clock_gettime
using xdev_tp_work=int;
using xdev_tp_dtype=unsigned;
static int item;
struct tp_eval_owner {
 bool started=true;
 xdev_ext_cuda_peer_owner *bootstrap=nullptr;
 void *comm=nullptr,*stream=nullptr;
 std::vector<uint64_t> inputs{1},outputs{2};
};
static int xdev_tp_allreduce_sum(void *,uint64_t,uint64_t,uint64_t,unsigned,void *,uint64_t,int **w) {*w=&item;return 0;}
static int xdev_tp_logits_gather(void *,uint64_t,uint64_t,uint64_t,uint64_t,unsigned,int,int,void *,uint64_t,int **w) {*w=&item;return 0;}
static int cuGraphLaunch(void *,void *) {return 0;}
static int cuStreamSynchronize(void *) {return 0;}
static int xdev_tp_work_wait(int *,uint64_t) {return 0;}
static uint64_t now_ns() {return ++ticks;}
static int boundary_printf(const char *format,...) {
 if(std::string(format).find("\"interval\"")!=std::string::npos) {
  ++intervals;
  premature+=completed[0]<target || completed[1]<target;
 }
 return 0;
}
struct retained_stop {};
static int boundary_pause() {retained=true;throw retained_stop{};}
#define printf boundary_printf
#define pause boundary_pause
static int measured_call(tp_eval_owner &owner,const tp_eval_options &o) {
 uint64_t iteration=1;
 void *exec=nullptr;
 std::vector<int *> works(o.depth,&item);
 try {
''' + measured + r'''
 return 0;
 } ''' + caught + r'''
}
#undef pause
#undef printf
int main(int argc,char **argv) {
 if(argc!=3)return 2;
 scenario=argv[1];tp_eval_options o;o.mode=unsigned(std::stoul(argv[2]));
 o.depth=o.mode==1?1:2;o.timeout_ns=1000;
 target=2*o.depth;tp_eval_owner owner;
 bool failed=false;
 try {failed=measured_call(owner,o)!=0;} catch(const retained_stop &) {failed=true;}
 bool error=scenario!="delayed";
 bool ok=error?(failed&&retained&&intervals==0):(intervals==1&&!premature&&!retained&&!failed);
 if(!ok)std::fprintf(stderr,"END_ASSERT scenario=%s mode=%u intervals=%u premature=%u retained=%d reads=%u,%u\n",
  scenario.c_str(),o.mode,intervals,premature,retained,reads[0],reads[1]);
 return ok?0:1;
}
'''
        source = out / 'boundary.cc'
        source.write_text(code)
        cls.executable = out / 'boundary'
        command = [os.environ.get('CXX', 'g++'), '-std=c++17', '-O0',
                   '-Wall', '-Wextra', '-Wno-unused-function',
                   '-I' + str(out), '-I' + str(ROOT),
                   '-I' + str(ROOT / 'src/compute/cuda'),
                   '-I' + str(view.root / 'kernel/tools/xdev_ext_mech/lib'),
                   '-I' + str(ROOT / 'src/core/include/uapi'),
                   str(source), '-o', str(cls.executable)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if built.returncode:
            raise RuntimeError('boundary compilation is not behavior RED:\n' + built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def check_case(self, case):
        for mode in (1, 2):
            with self.subTest(case=case, mode=mode):
                run = subprocess.run([str(self.executable), case, str(mode)],
                                     capture_output=True, text=True, timeout=5)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_interval_waits_for_both_kernel_end_prefixes(self):
        self.check_case('delayed')

    def test_native_errors_retain_owner_without_success_interval(self):
        for case in ('api_error', 'last_error', 'abort', 'held', 'sequestered',
                     'timeouts', 'protocol', 'rejects', 'timeout'):
            self.check_case(case)


if __name__ == '__main__':
    unittest.main()

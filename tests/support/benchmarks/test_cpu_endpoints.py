#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute extracted production timer bodies against independent event clocks.

No device, SDK, workload model, production test hook or performance result.
Only dependency calls are replaced. The production statements, branch order,
clock reads, original denominator assignment and journal call run unchanged.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
for ancestor in HERE.parents:
    candidates = (ancestor / 'tests/benchmarks', ancestor / 'tests/eval')
    BENCH = next((p for p in candidates if (p / 'gds/bench_cufile.cc').is_file()), None)
    if BENCH:
        break
else:
    raise RuntimeError('benchmark sources are not mapped')


def source(name):
    return (BENCH / name).read_text()


def function(text, name):
    match = re.search(r"^[^\n;#{}]*\b" + re.escape(name) +
                      r"\s*\([^;]*?\)\s*\{", text, re.M)
    if match is None:
        raise AssertionError('missing actual function ' + name)
    opening = text.index('{', match.start())
    depth = 0
    for i in range(opening, len(text)):
        depth += {'{': 1, '}': -1}.get(text[i], 0)
        if depth == 0:
            return text[match.start():i + 1]
    raise AssertionError('unbalanced actual function ' + name)


def span(text, begin, end, *, occurrence=0):
    """Copy actual statements, including the terminating statement."""
    start = -1
    for _ in range(occurrence + 1):
        start = text.index(begin, start + 1)
    stop = text.index(end, start) + len(end)
    return text[start:stop]


PREFIX = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <vector>
#include <string>
using std::uint64_t;
static uint64_t tick = 100;
static unsigned clocks;
struct Row { std::string metric; uint64_t key, start, end, stored_at; };
struct Timer { uint64_t count = 0; };
static Timer endpoint_timer, uo_cpu_timer;
static std::vector<Row> rows;
static std::vector<std::string> events;
static uint64_t now_ns() { ++clocks; events.push_back("clock"); return tick; }
static uint64_t es_now_ns() { return now_ns(); }
static uint64_t cb_now_ns() { return now_ns(); }
static uint64_t uo_now() { return now_ns(); }
static int cpu_timer_store(Timer *t, const char *metric, uint64_t key,
                           uint64_t start, uint64_t end) {
    rows.push_back({metric, key, start, end, tick}); ++t->count;
    events.push_back("store"); return 0;
}
static void reset() { tick=100; clocks=0; rows.clear(); events.clear();
                       endpoint_timer.count=uo_cpu_timer.count=0; }
static void check_row(unsigned i, const char *metric, uint64_t key,
                      uint64_t start, uint64_t end) {
    assert(i < rows.size()); const Row &r=rows[i];
    assert(r.metric==metric && r.key==key && r.start==start && r.end==end);
    assert(r.stored_at>=end);
}
'''


class ActualEndpointBodies(unittest.TestCase):
    def compile_run(self, body, *, expect_failure=False, prefix=PREFIX):
        with tempfile.TemporaryDirectory(prefix='cpu-endpoint-') as tmp:
            root = Path(tmp)
            path = root / 'body.cc'
            path.write_text(prefix + '\n' + body)
            command = shlex.split(os.environ.get('CXX', 'g++')) + [
                '-std=c++17', '-O0', '-Wall', '-Wextra', '-Werror',
                '-Wno-unused-function', '-Wno-unused-variable',
                '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                str(path), '-o', str(root / 'body')]
            built = subprocess.run(command, text=True, capture_output=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(root / 'body')], text=True, capture_output=True, timeout=5)
            if expect_failure:
                self.assertNotEqual(ran.returncode, 0, 'wrong-cutoff mutation escaped observer')
                self.assertIn('Assertion', ran.stderr)
            else:
                self.assertEqual(ran.returncode, 0, ran.stderr)
            return ran

    def test_actual_clock_helpers_keep_original_raw_and_monotonic_domains(self):
        cases = (
            ('chains/chain_bench.h', 'cb_now_ns', 'CLOCK_MONOTONIC_RAW'),
            ('userspace_orchestrator/uo_bench.c', 'uo_now', 'CLOCK_MONOTONIC_RAW'),
            ('nvme_nic/nnb_producer.c', 'nnb_now', 'CLOCK_MONOTONIC_RAW'),
            ('nvme_gpu/eval_session.h', 'es_now_ns', 'CLOCK_MONOTONIC'),
            ('nvme_gpu/bench_uring_cuda.cc', 'now_ns', 'CLOCK_MONOTONIC'),
            ('nvme_gpu/bench_cufile_batch.cc', 'now_ns', 'CLOCK_MONOTONIC'),
            ('gds/bench_cufile.cc', 'now_ns', 'CLOCK_MONOTONIC'),
            ('gpu_nic/afxdp_cuda.cu', 'now_ns', 'CLOCK_MONOTONIC'),
            ('gpu_nic/udp_pinned_cuda.cu', 'now_ns', 'CLOCK_MONOTONIC'),
        )
        for path, name, clock in cases:
            with self.subTest(path=path):
                body = function(source(path), name)
                self.compile_run(r'''
#include <cassert>
#include <cstdint>
#include <ctime>
using __u64=uint64_t;
static unsigned reads;
static int observed=-1;
static int observed_clock_gettime(clockid_t clock,timespec *ts) {
    ++reads; observed=clock; ts->tv_sec=2; ts->tv_nsec=37; return 0;
}
#define clock_gettime observed_clock_gettime
''' + body + '\nint main(){assert(' + name + '()==2000000037ULL);'
                    'assert(reads==1 && observed==' + clock + ');}', prefix='')

    def test_actual_cufile_batch_and_async_pass_retire_all_original_work_before_end(self):
        text = source('nvme_gpu/bench_cufile_batch.cc')
        for mode in ('batch', 'async'):
            with self.subTest(mode=mode):
                body = function(text, 'pass_' + mode)
                expected = 60 if mode == 'batch' else 100
                self.compile_run(r'''
#include <algorithm>
struct Geometry { uint64_t size=4096; };
struct Wave { std::vector<int> params=std::vector<int>(2); unsigned outstanding=0; uint64_t submitted=0; };
struct AsyncSlot { bool busy=false; uint64_t started=0,pos=0; ssize_t bytes=0; int done=0; };
struct Run { struct {Geometry g; uint64_t timeout_ms=1000; bool ring=false,block=false;} o;
    std::vector<Wave> waves=std::vector<Wave>(2);
    std::vector<AsyncSlot> slots=std::vector<AsyncSlot>(2);
    std::vector<int> dev_busy=std::vector<int>(2); bool loading=true;
};
static unsigned submitted,completed;
static uint64_t xg_blocks(const Geometry*) { return 5; }
static uint64_t xg_ring_slot(const Geometry*,uint64_t pos) { return pos%2; }
static bool load(const Run &r) { return r.loading; }
static int submit_wave(Run&,Wave &w,uint64_t,uint64_t &next,uint64_t n,unsigned width) {
    w.outstanding=std::min<uint64_t>(width,n-next);next+=w.outstanding;
    submitted+=w.outstanding;tick+=7;w.submitted=tick;return 0;
}
static int reap_wave(Run&,Wave &w,bool,uint64_t) {
    unsigned n=w.outstanding;w.outstanding=0;completed+=n;tick+=13;return int(n);
}
using cudaError_t=int;
static constexpr int cudaErrorNotReady=1;
static bool cuda_ok(int e,const char*) { return e==0; }
static int cudaEventQuery(int) { ++completed;tick+=13;return 0; }
static int cudaEventSynchronize(int) { return 0; }
static bool submit_async(Run &r,AsyncSlot &s,uint64_t,uint64_t pos) {
    s.busy=true;s.pos=pos;s.bytes=ssize_t(r.o.g.size);s.started=tick;
    if(r.loading && r.o.ring)r.dev_busy[pos%2]=1;
    ++submitted;tick+=7;return true;
}
''' + body + r'''
int main() {
    for(bool loading:{false,true})for(bool ring:{false,true})for(bool block:{false,true}){
        reset();submitted=completed=0;Run r;r.loading=loading;r.o.ring=ring;r.o.block=block;
        uint64_t io_ns=0;
        assert(pass_''' + mode + r'''(r,0,io_ns)==0);
        assert(submitted==5 && completed==5 && rows.size()==1);
        assert(io_ns==''' + str(expected) + r''');
        check_row(0,"io_ns",0,100,''' + str(100 + expected) + r''');
        assert(rows[0].stored_at==rows[0].end);
    }
}
''')

    @staticmethod
    def gds_adapter_fixture(failure):
        # Actual complete main control flow, including parser, capacity choice,
        # execute/finish, original return status and journal publication.
        body = function(source('gds/bench_cufile.cc'), 'main')
        body = body.replace('int main(', 'int production_main(', 1)
        return r'''
#include <cstdlib>
#include <new>
struct Resources {};
static bool fail_publish=false;
static unsigned initialized,executed,finished,published;
static bool number(const char *text,uint64_t limit,uint64_t &value) {
    char *end=nullptr;value=std::strtoull(text,&end,10);
    return text[0] && !*end && value && value<=limit;
}
static int cpu_timer_init(Timer *,const char *,size_t capacity) {
    ++initialized; return capacity>1048576?1:0;
}
static void endpoint_timer_cleanup() {}
static int execute(Resources &,const char *,uint64_t,size_t,uint64_t,const char *) {
    ++executed;events.push_back("original-workload");
    events.push_back("original-oracle-pass");
    std::printf("original-workload-and-oracle-pass\n");return 0;
}
static int finish(Resources &,int original_result) {
    ++finished;events.push_back("original-finish");return original_result;
}
static int cpu_timer_publish(Timer *) {
    ++published;assert(executed==1 && finished==1);
    assert(events.back()=="original-finish");events.push_back("publish");
    return fail_publish?1:0;
}
''' + body + r'''
int main() {
    reset();fail_publish=''' + ('true' if failure == 'publish' else 'false') + r''';
    char program[]="gds",workload[]="llm-load",bytes[]=''' + (
        '"1073741824"' if failure == 'capacity' else '"4096"') + r''';
    char chunk[]="4096",iterations[]=''' + (
        '"1000"' if failure == 'capacity' else '"1"') + r''',directory[]="/unused";
    char *argv[]={program,workload,bytes,chunk,iterations,directory,nullptr};
    int result=production_main(6,argv);
    assert(initialized==1);
    assert(executed==1 && finished==1);
    assert(result==0); // A journal refusal changes CPU eligibility, not workload success.
    if(!''' + ('true' if failure == 'capacity' else 'false') + r''')assert(published==1);
}
'''

    def test_gds_adapter_success_keeps_original_workload_status_and_publishes_after_finish(self):
        result = self.compile_run(self.gds_adapter_fixture('none'))
        self.assertEqual(result.stdout, 'original-workload-and-oracle-pass\n')

    def test_gds_oversized_journal_keeps_original_legal_workload_and_oracle(self):
        result = self.compile_run(self.gds_adapter_fixture('capacity'))
        self.assertEqual(result.stdout, 'original-workload-and-oracle-pass\n')

    def test_gds_publication_error_keeps_original_success_and_raw_output(self):
        result = self.compile_run(self.gds_adapter_fixture('publish'))
        self.assertEqual(result.stdout, 'original-workload-and-oracle-pass\n')

    def test_actual_gds_final_byte_oracle_gates_publication_before_success(self):
        text = source('gds/bench_cufile.cc')
        oracle = span(text, 'GDS_CAMPAIGN_EVENT("oracle-begin");',
                      'if (!file_ok_bytes) { std::fprintf(stderr, "checkpoint file payload mismatch in campaign history\\n"); return 1; }')
        main = function(text, 'main').replace('int main(', 'int production_main(', 1)
        self.compile_run(r'''
#include <cstdlib>
#include <new>
#include <sys/stat.h>
struct Resources { void *gpu=nullptr; int ordinary=42; };
static unsigned executed,finished,published;
static int fault;
static bool number(const char *text,uint64_t limit,uint64_t &value) {
    char *end=nullptr;value=std::strtoull(text,&end,10);
    return text[0] && !*end && value && value<=limit;
}
static int cpu_timer_init(Timer *,const char *,size_t) { return 0; }
static void endpoint_timer_cleanup() {}
static unsigned char pattern(uint64_t index,uint64_t iteration) {
    return (index*37+index/251+iteration*53)%256;
}
static std::vector<unsigned char> file_source;
static int observed_fstat(int,struct stat *saved) {
    events.push_back("file-stat");saved->st_size=off_t(file_source.size());return 0;
}
static ssize_t pread_all(int,void *destination,size_t size,off_t) {
    events.push_back("file-readback");std::memcpy(destination,file_source.data(),size);return ssize_t(size);
}
static constexpr int cudaMemcpyDeviceToHost=1;
static int cudaMemcpy(void *destination,const void *source,size_t size,int) {
    events.push_back("device-readback");std::memcpy(destination,source,size);return 0;
}
static int cudaDeviceSynchronize() { events.push_back("oracle-sync");return 0; }
static bool cuda_ok(int e,const char*) { return e==0; }
#define fstat observed_fstat
#define GDS_CAMPAIGN_EVENT(name) events.push_back(name)
static int execute(Resources &res,const char *workload,uint64_t bytes,size_t,uint64_t iterations,const char*) {
    ++executed;bool checkpoint=!std::strcmp(workload,"checkpoint");
    // Deliberately bounded memory substitutes; the actual original comparison
    // statements and byte-by-byte file oracle below execute unchanged.
    std::vector<unsigned char> expected{3,1,4,1,5,9},device=expected;
    size_t history=expected.size();uint64_t file_bytes=bytes*iterations;
    std::vector<unsigned char> observed(history),stored(size_t(file_bytes),0);
    file_source.assign(size_t(file_bytes),0);
    for(uint64_t trial=0;trial<iterations;++trial)for(uint64_t i=0;i<bytes;++i)
        file_source[size_t(trial*bytes+i)]=(i*37+i/251+trial*53)%256;
    if(fault==1)device[0]^=1;
    if(fault==2)file_source[0]^=1;
    res.gpu=device.data();
''' + oracle + r'''
    return 0;
}
static int finish(Resources &,int result) { ++finished;events.push_back("finish");return result; }
static int cpu_timer_publish(Timer *) {
    ++published;assert(executed==1 && finished==1);
    assert(events.front()=="oracle-begin");
    assert(events[events.size()-2]=="oracle-end" && events.back()=="finish");
    assert(fault==0);return 0;
}
''' + main + r'''
int main() {
    for(bool checkpoint:{false,true})for(int corruption:{0,1,2}) {
        if(!checkpoint && corruption==2)continue;
        reset();executed=finished=published=0;fault=corruption;
        char program[]="gds",load[]="llm-load",save[]="checkpoint",bytes[]="4096";
        char chunk[]="4096",iterations[]="1",directory[]="/unused";
        char *argv[]={program,checkpoint?save:load,bytes,chunk,iterations,directory,nullptr};
        int result=production_main(6,argv);
        assert(executed==1 && finished==1);
        assert(result==(corruption?1:0));
        assert(published==(corruption?0u:1u));
    }
}
''')

    @staticmethod
    def gds_body(branch, fsync=False):
        text = source('gds/bench_cufile.cc')
        if branch == 'per-chunk':
            text = text[text.index('#ifdef GDS_PER_CHUNK_ORACLE'):text.index('#else', text.index('#ifdef GDS_PER_CHUNK_ORACLE'))]
        else:
            text = text[text.index('#else', text.index('#ifdef GDS_PER_CHUNK_ORACLE')):]
        if fsync:
            return span(text, 'uint64_t start = now_ns();\n            if (fsync', 'io_ns += end - start;')
        return span(text, 'uint64_t start = now_ns();\n            ssize_t count', 'io_ns += end - start;')

    @staticmethod
    def gds_fixture(body, *, fsync=False):
        return r'''
struct Resource { int file=4, direct=5; void *gpu=nullptr; };
static ssize_t cuFileRead(int, void *, size_t size, off_t, off_t) {
    events.push_back("read"); tick+=11; return ssize_t(size);
}
static ssize_t cuFileWrite(int, void *, size_t size, off_t, off_t) {
    events.push_back("write"); tick+=11; return ssize_t(size);
}
static int cudaDeviceSynchronize() { events.push_back("completion"); tick+=29; return 0; }
static bool cuda_ok(int code, const char *) { return code==0; }
static int fsync(int) { events.push_back("fsync"); tick+=73; return 0; }
static int actual(bool checkpoint, uint64_t &io_ns) {
    (void)checkpoint; Resource res; size_t part=4096, guard=4096; uint64_t offset=8192, region=16384;
    off_t buffer=12288;
''' + body + r'''
    return 0;
}
int main() {
    for (bool checkpoint : {false,true}) {
        reset(); uint64_t io_ns=0;
        assert(actual(checkpoint, io_ns)==0);
        assert(rows.size()==1 && clocks==2);
        check_row(0,"io_ns",0,100,''' + ('173' if fsync else '140') + r''');
        assert(io_ns==''' + ('73' if fsync else '40') + r''');
        assert(rows[0].stored_at==tick);
        assert(events==std::vector<std::string>({"clock",''' + (
            '"fsync"' if fsync else 'checkpoint ? "write" : "read", "completion"') + r''',"clock","store"}));
    }
}
'''

    def test_gds_both_preprocessor_branches_capture_completed_io_and_separate_fsync(self):
        for branch in ('per-chunk', 'campaign'):
            for fsync in (False, True):
                with self.subTest(branch=branch, fsync=fsync):
                    self.compile_run(self.gds_fixture(self.gds_body(branch, fsync), fsync=fsync))

    def test_wrong_gds_cutoff_before_completion_is_detected(self):
        body = self.gds_body('campaign')
        completion = 'if (!cuda_ok(cudaDeviceSynchronize(), "I/O completion")) return 1;'
        self.assertEqual(body.count(completion), 1)
        # Mutate only the extracted copy, never production: clock before completion.
        body = body.replace(completion, '').replace('uint64_t end = now_ns();',
                                                    'uint64_t end = now_ns();\n' + completion)
        self.compile_run(self.gds_fixture(body), expect_failure=True)

    @staticmethod
    def session_fixture(which, *, wrong=False):
        if which == 'nvme-gpu':
            text = source('nvme_gpu/session_nvme_ce.c')
            body = span(text, 't0 = es_now_ns();', 'p->io_ns = t1 - t0;')
            if wrong:
                # Move the original end read to immediately after terminal wake.
                body = body.replace('t1 = es_now_ns();', '')
                body = body.replace('/* A terminal notification',
                                    't1 = es_now_ns();\n /* A terminal notification')
            setup = 'int ret=0; Pass pass{}, *p=&pass; uint64_t n=2, groups=1, frames=2; unsigned *user=nullptr;'
            tail = 'assert(ret==0 && p->io_ns==130); check_row(0,"io_ns",0,100,230);'
        else:
            text = source('gpu_nic/session_gpu_nic.c')
            body = span(text, 't0 = es_now_ns();', 'es_print_stats(&st);')
            setup = 'int err=0; struct { bool ingest; } o{ingest}; struct { uint64_t groups; } p{2}; Stats st{}; uint64_t cpu=0, busy=0;'
            tail = 'assert(err==0 && t1-t0==(ingest?20:30) && cpu==t1-t0 && busy==t1-t0); check_row(0,"io_ns",0,100,ingest?120:130);'
        return r'''
struct Stats { uint64_t batches_done=2, submitted[2]={2,2}, completed[2]={2,2}; };
struct Pass { uint64_t cpu_us=0,host_busy_us=0,io_ns=0; Stats stats; };
static int es_start(int *,uint64_t,unsigned *,unsigned) { events.push_back("start");tick+=10;return 0; }
static int es_wait_terminal(int *,uint64_t) { events.push_back("terminal");tick+=20;return 0; }
static int es_settle(int *,uint64_t,uint64_t,Stats *) { events.push_back("settle");tick+=100;return 0; }
static int es_stats(int *,Stats *) { return 0; }
static void es_print_stats(Stats *) {}
static uint64_t es_cpu_us() { return tick; }
static uint64_t xg_host_busy_us() { return tick; }
using __u32=unsigned;
#define XG_EXIT_FAIL 1
static int actual(bool ingest) {
    (void)ingest; int r=0; uint64_t t0=0,t1=0,deadline=1000000,cpu0=100,busy0=100;
''' + setup + '\n' + body + '\n' + tail + r'''
    assert(rows.size()==1 && clocks==2);
    assert(tick==(ingest?220:230) || tick==230);
    return 0;
''' + ('out: return 1;' if 'goto out;' in body else '') + r'''
}
int main() { for (bool ingest : {false,true}) { reset(); assert(actual(ingest)==0); } }
'''

    def test_nvme_gpu_session_keeps_settle_inside_original_io_denominator(self):
        self.compile_run(self.session_fixture('nvme-gpu'))

    def test_gpu_nic_session_keeps_terminal_wake_before_settle_both_directions(self):
        self.compile_run(self.session_fixture('gpu-nic'))

    def test_wrong_nvme_gpu_terminal_only_cutoff_is_detected(self):
        self.compile_run(self.session_fixture('nvme-gpu', wrong=True), expect_failure=True)

    def test_closed_uo_and_staged_store_only_measured_windows_after_original_end(self):
        for family in ('userspace_orchestrator/uo_bench.c', 'chains/chain_staged.c'):
            with self.subTest(family=family):
                text = source(family)
                if family.startswith('userspace'):
                    body = span(text, 'uint64_t t0 = uo_now(), t1;', 'first += s->burst;')
                else:
                    body = span(text, 'uint64_t t0 = cb_now_ns(), t1;', 'first += nb;')
                self.compile_run(r'''
struct Usage {};
static constexpr int RUSAGE_SELF=0, UO_FAIL=1, CB_FAIL=1;
static int getrusage(int,Usage*) { return 0; }
struct Run { Timer cpu_timer; uint64_t buffer[4]={}, *samples=buffer, nr_samples=0;
    Usage ru1; };
static int uo_window(Run *,uint64_t,uint64_t,void *) { tick+=41;return 0; }
static int sg_window(int *,uint64_t,uint64_t,void *) { tick+=41;return 0; }
static int uo_fail(Run*,int,const char*,...) { return 1; }
static void cb_fail(Run*,int,const char*,...) {}
static int actual() {
    Run result, *u=&result, *r=&result;
    struct { uint64_t burst; } spec{8}, *s=&spec;
    uint64_t first=0, warm=1, nb=8; int ret=0, x=0;
    for (uint64_t w=0;w<3;++w) {
''' + body + r'''
    }
    assert(rows.size()==2 && result.nr_samples==2 && first==24 && clocks==6);
    assert(result.samples[0]==41 && result.samples[1]==41);
    check_row(0,"window_ns",0,141,182); check_row(1,"window_ns",1,182,223);
    return 0;
''' + ('out: return 1;' if 'goto out;' in body else '') + r'''
}
int main(){reset();assert(actual()==0);}
''')

    def test_nvme_nic_original_release_receipt_durable_endpoints_and_trial_filter(self):
        text = source('nvme_nic/nnb_producer.c')
        body = span(text, 'if (!c->correctness && !strcmp(kind, "trial")) {',
                    '\n\t/* Integrity trials and correctness runs carry no timing. */')
        self.compile_run(r'''
struct Config { bool correctness,reverse; };
static int actual(bool reverse,bool correctness,const char *kind) {
    Config config{correctness,reverse}, *c=&config;
    struct {uint64_t t_start,t_release;} t{100,137};
    uint64_t t_receipt=211,trial=7;
    tick=211;
''' + body + r'''
    if (correctness || std::strcmp(kind,"trial")) { assert(rows.empty()); return 0; }
    check_row(0,reverse?"durable_ns":"local_release_ns",7,100,137);
    assert(rows.size()==(reverse?1u:2u));
    if (!reverse) check_row(1,"receipt_ns",7,100,211);
    assert(clocks==0); return 0;
}
int main(){for(bool reverse:{false,true})for(bool correctness:{false,true})
    for(const char *kind:{"trial","warmup","integrity"}) {
        reset(); assert(actual(reverse,correctness,kind)==0);
    }}
''')


if __name__ == '__main__':
    unittest.main()

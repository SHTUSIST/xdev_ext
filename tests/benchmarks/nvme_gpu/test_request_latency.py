#!/usr/bin/env python3
"""Actual request control and scheduler at host API boundaries, never GPU timings."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_session_timing import function
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def declaration(source, name):
    start = source.index('struct '+name+' {')
    return source[start:source.index('\n};', start)+3]


class SessionRequests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix='e3-request-')
        cls.addClassCleanup(temp.cleanup)
        cls.out = Path(temp.name)
        source = (HERE / 'session_nvme_ce.c').read_text()
        fixture = (HERE / 'timer_fixture.c.in').read_text()
        for name, token in [('sn_opts','SN_OPTS'), ('sn_pass','SN_PASS')]:
            fixture = fixture.replace('@'+token+'@', declaration(source,name))
        fixture = fixture[:fixture.index('int main(')]
        a = fixture.index('static uint64_t tick=100;')
        fixture = fixture[:a] + SESSION_API + fixture[fixture.index('@SN_SESSION@',a):]
        bodies = declaration(source, 'sn_request_row') + '\n'
        for name in ('sn_request_valid','sn_request_arm','sn_request_close','sn_request_campaign','sn_request_export','sn_session'):
            bodies += function(source,name)+'\n'
        fixture = fixture.replace('@SN_SESSION@', bodies) + SESSION_MAIN
        path = cls.out/'case.c'; path.write_text(fixture)
        result = subprocess.run([os.environ.get('CC','cc'), '-std=gnu11','-Wall','-Wextra','-Werror','-DE3_REQUEST_QUALIFICATION=0',
              '-fsanitize=undefined','-fno-sanitize-recover=undefined', '-I',str(ROOT),'-I',str(HERE),str(path),'-o',str(cls.out/'case')],capture_output=True,text=True)
        if result.returncode: raise AssertionError(result.stderr)
        cmd=[os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-DE3_REQUEST_QUALIFICATION=1',
              '-fsanitize=undefined','-fno-sanitize-recover=undefined','-I',str(ROOT),'-I',str(HERE),str(path),'-o',str(cls.out/'qualified')]
        r=subprocess.run(cmd,capture_output=True,text=True)
        if r.returncode:raise AssertionError(r.stderr)

    def run_case(self, fault=0):
        return subprocess.run([str(self.out/'case'),str(fault)],capture_output=True,text=True,timeout=5)

    def test_one_create_three_absolute_requests(self):
        r = self.run_case(); self.assertEqual(r.returncode,0,r.stderr)
        x=json.loads(r.stdout)
        self.assertEqual((x['rc'],x['starts'],x['arms'],x['creates'],x['closed']), (0,3,3,1,0))
        self.assertEqual(x['rows'], [[0,1,0,100,130,230], [1,2,8,230,260,360], [2,3,16,360,390,490]])
        self.assertEqual(x['span'],390)

    def test_counter_notify_clock_deadline_and_start_fail_closed(self):
        for fault in (*range(1,12),13,14):
            with self.subTest(fault=fault):
                r=self.run_case(fault)
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertEqual(json.loads(r.stdout)['rc'],1)

    def test_session_exclusive_csv_after_strict_close(self):
        import csv
        import io
        with tempfile.TemporaryDirectory(prefix='e3-session-export-') as d:
            path=Path(d)/'rows'
            r=subprocess.run([str(self.out/'case'),'0',str(path)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertIn('EVAL_STOP=PASS',r.stderr)
            self.assertIn('E3_REQUEST_DIAGNOSTIC=PASS',r.stdout)
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            old=path.read_bytes()
            rows=list(csv.DictReader(io.StringIO('\n'.join(old.decode().splitlines()[1:]))))
            self.assertEqual([[int(row[k]) for k in ('pos','key','slba','done','published','sub0','comp0','sub1','comp1')] for row in rows],[[0,1,0,1,1,1,1,1,1],[1,2,8,2,2,2,2,2,2],[2,3,16,3,3,3,3,3,3]])
            again=subprocess.run([str(self.out/'case'),'0',str(path)],capture_output=True,text=True)
            self.assertNotIn('E3_REQUEST_DIAGNOSTIC=PASS',again.stdout)
            self.assertEqual(json.loads(again.stdout)['rc'],1)
            self.assertEqual(path.read_bytes(),old)

    def test_session_qualification_reads_every_settled_payload(self):
        r=subprocess.run([str(self.out/'qualified'),'0'],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)['rc'],0)
        self.assertIn('readbacks=32',r.stderr)
        plain=self.run_case();self.assertIn('readbacks=0',plain.stderr)
        for fault in (15,16):
            r=subprocess.run([str(self.out/'qualified'),str(fault)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(json.loads(r.stdout)['rc'],1)

    def test_stop_error_withholds_release(self):
        r=self.run_case(12)
        self.assertEqual(r.returncode,1)
        self.assertEqual(r.stdout,'')
        self.assertIn('release=withheld',r.stderr)


SESSION_API = r"""
#include <unistd.h>
#include <fcntl.h>
static uint64_t tick=100, done;
static unsigned starts,arms,creates,closed,reads;
static int fault;
static __u64 es_now_ns(void){return fault==7?0:tick;}
static __u64 es_cpu_us(void){return tick;}
static __u64 test_busy_us(void){return tick;}
#define xg_host_busy_us test_busy_us
static int es_ring_open(struct es_run*r){r->ring=42;r->efd=43;return 0;}
static int es_register(int ring,unsigned code,void*arg){(void)ring;(void)code;(void)arg;return 0;}
static int es_create(struct es_run*r,struct xdev_ext_mech_create*c,__u64 n){(void)c;(void)n;creates++;r->session=1;return 0;}
static int es_start(struct es_run*r,__u64 n,const __u32*u,__u32 nr){(void)r;(void)n;(void)u;(void)nr;starts++;tick+=10;return 0;}
static int es_wait_terminal(struct es_run*r,__u64 deadline){(void)r;(void)deadline;tick+=20;return fault==9?-EIO:0;}
static int es_stats(struct es_run*r,struct xdev_ext_mech_stats*s){memset(s,0,sizeof(*s));s->session_id=r->session;s->state=XDEV_EXT_MECH_SESSION_ACTIVE;s->batches_done=s->published=done;s->submitted[0]=s->completed[0]=s->submitted[1]=s->completed[1]=done;if(done){if(fault==1)s->published--;if(fault==2)s->completed[1]--;if(fault==3)s->inflight=1;if(fault==4)s->held=1;if(fault==10)s->native_publish=1;if(fault==11)s->submitted[2]=1;if(fault==14)s->state=XDEV_EXT_MECH_SESSION_STOPPED;}return 0;}
static int es_settle(struct es_run*r,__u64 n,__u64 deadline,struct xdev_ext_mech_stats*s){(void)deadline;tick+=100;done=n;return es_stats(r,s);}
static int es_mech(int ring,__u32 op,__u64 arg){(void)ring;
 if(op==XDEV_EXT_MECH_OP_NOTIFY_ARM){struct xdev_ext_mech_notify_arm*a=(void*)(uintptr_t)arg;arms++;return a->session_id==1&&a->batches_target==done+1&&a->published_target==done+1?0:-EPROTO;}
 if(op==XDEV_EXT_MECH_OP_START){struct xdev_ext_mech_start*s=(void*)(uintptr_t)arg;starts++;if(fault==8)tick+=1000000001ULL;else tick+=10;return fault==6?-EIO: s->session_id==1&&s->nr_batches==1&&s->first_seq==done+1&&s->nr_user_frames==1&&s->flags==(XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_RECYCLE)&&*(__u32*)(uintptr_t)s->user_frames==0?0:-EPROTO;}
 if(op==XDEV_EXT_MECH_OP_STOP)return fault==12?-ENOENT:0;
 return -EINVAL;}
static ssize_t fake_read(int fd,void*p,size_t n){(void)fd;(void)p;(void)n;if(fault==5&&arms){return 8;}errno=EAGAIN;return -1;}
static int fake_close(int fd){if(fd!=42&&fd!=43)return close(fd);if(fault==13){errno=EIO;return -1;}return 0;}
#define read fake_read
#define close fake_close
static void es_print_stats(struct xdev_ext_mech_stats*s){(void)s;}
static int es_close(struct es_run*r){(void)r;closed++;return 0;}
#if E3_REQUEST_QUALIFICATION
static int es_ce_access(struct es_ce*c,bool write,__u64 off,void*buf,__u64 n){(void)c;(void)off;if(write)return -EINVAL;reads++;xg_fill(buf,(done-1)*4096,n,1);if(fault==15)((unsigned char*)buf)[0]^=1;if(fault==16)((unsigned char*)buf)[n-1]^=1;return 0;}
#endif
static bool sn_capability_errno(int e){(void)e;return false;}
static int sn_unavailable(const char*msg,int e){(void)msg;(void)e;return 4;}
"""
SESSION_MAIN = r"""
int main(int argc,char**argv){if(argc<2||argc>3)return 2;fault=atoi(argv[1]);struct sn_opts o={.request_log="unused",.direction=XG_LOAD,.lba_size=512,.frame_size=4096,.timeout_ms=1000,.g={.size=4096,.qd=1,.window=(E3_REQUEST_QUALIFICATION?32:3)*4096,.passes=1,.seed=1}};struct es_ce ce={.fd={44,-1},.len=4096};struct sn_pass p={0};int rc=sn_session(&o,&ce,45,&p);if(argc==3&&rc==0){o.request_log=argv[2];rc=sn_request_export(&o,&p);}fprintf(stderr,"readbacks=%u\n",reads);printf("{\"rc\":%d,\"starts\":%u,\"arms\":%u,\"creates\":%u,\"closed\":%u,\"span\":%llu,\"rows\":[",rc,starts,arms,creates,closed,(unsigned long long)p.io_ns);for(unsigned i=0;i<3&&p.rows;i++){struct sn_request_row*r=&p.rows[i];printf("%s[%llu,%llu,%llu,%llu,%llu,%llu]",i?",":"",(unsigned long long)r->pos,(unsigned long long)r->key,(unsigned long long)r->slba,(unsigned long long)r->t0_ns,(unsigned long long)r->terminal_ns,(unsigned long long)r->settled_ns);}puts("]}");free(p.rows);return 0;}
"""



class BaselineRequests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp=tempfile.TemporaryDirectory(prefix='e3-staged-api-');cls.addClassCleanup(temp.cleanup)
        cls.out=Path(temp.name)
        (cls.out/'cuda_runtime_api.h').write_text(CUDA_API)
        (cls.out/'liburing.h').write_text(URING_API)
        result=subprocess.run([os.environ.get('CXX','g++'),'-std=c++17','-O1','-Wall','-Wextra','-Werror',
            '-fsanitize=undefined','-fno-sanitize-recover=undefined','-I',str(cls.out),str(HERE/'bench_uring_cuda.cc'),'-o',str(cls.out/'staged')],capture_output=True,text=True)
        if result.returncode:raise AssertionError(result.stderr)
        command=[os.environ.get('CXX','g++'),'-std=c++17','-O1','-Wall','-Wextra','-Werror',
            '-DE3_REQUEST_QUALIFICATION=1','-I',str(cls.out),str(HERE/'bench_uring_cuda.cc'),'-o',str(cls.out/'qualified')]
        r=subprocess.run(command,capture_output=True,text=True)
        if r.returncode:raise AssertionError(r.stderr)

    def run_case(self, diagnostic=True, failure='', qualification=False, count=3, extra=(), existing=False):
        with tempfile.TemporaryDirectory(prefix='e3-staged-case-') as d:
            file=Path(d)/'input';file.write_bytes(bytes(count*4096));rows=Path(d)/'rows'
            if existing:rows.write_text('original')
            args=[str(self.out/('qualified' if qualification else 'staged')),'--direction','load','--file',str(file),'--size','4096','--qd','1','--window-bytes',str(count*4096),'--passes','1','--seed','1','--streams','2','--timeout-ms','1000']
            if diagnostic:args+=['--diagnostic-request-latency',str(rows)]
            r=subprocess.run(args+list(extra),env=dict(os.environ,E3_FAKE_FAILURE=failure),capture_output=True,text=True,timeout=5)
            return r,rows.read_text() if rows.exists() else None,rows.stat().st_mode&0o777 if rows.exists() else None

    def test_original_scheduler_exports_three_independent_rows(self):
        r,rows,mode=self.run_case()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('E3_REQUEST_DIAGNOSTIC=PASS',r.stdout)
        self.assertIsNotNone(rows);self.assertEqual(mode,0o600)
        self.assertEqual(len([x for x in rows.splitlines() if not x.startswith('#')]),4)

    def test_rows_retain_exact_schedule_and_ordered_boundaries(self):
        import csv
        import io
        r,rows,_=self.run_case()
        self.assertEqual(r.returncode,0,r.stderr)
        table=list(csv.DictReader(io.StringIO('\n'.join(rows.splitlines()[1:]))))
        for i,row in enumerate(table):
            self.assertEqual([int(row[k]) for k in ('pos','block','slba','slot','stream','bytes','status')], [i,i,i*8,0,0,4096,1])
            self.assertLess(int(row['t0_ns']),int(row['nvme_cqe_ns']))
            self.assertLess(int(row['nvme_cqe_ns']),int(row['retired_ns']))

    def test_exclusive_output_and_diagnostic_geometry(self):
        r,rows,_=self.run_case(existing=True)
        self.assertEqual(r.returncode,1);self.assertEqual(rows,'original')
        for extra in (('--qd','2'),('--streams','1'),('--direction','save'),('--pattern','rand'),('--completion-wait','poll'),('--passes','2'),('--size','8192'),('--timeout-ms','10001')):
            with self.subTest(extra=extra):
                r,rows,_=self.run_case(extra=extra)
                self.assertEqual(r.returncode,2,r.stderr);self.assertIsNone(rows)

    def test_qualification_is_separate_and_checks_each_payload(self):
        r,rows,_=self.run_case(qualification=True,count=32)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('profile=qualification-only',rows)
        self.assertEqual(r.stderr.count('API readback'),33)
        plain,_,_=self.run_case(count=32)
        self.assertEqual(plain.returncode,0,plain.stderr)
        self.assertEqual(plain.stderr.count('API readback'),1)
        for api in ('bad-first','bad-last','final-drain'):
            r,rows,_=self.run_case(qualification=True,count=32,failure=api)
            self.assertEqual(r.returncode,1,r.stderr);self.assertIsNone(rows)
        for diagnostic,count in ((True,3),(False,32),(True,4096)):
            r,rows,_=self.run_case(qualification=True,diagnostic=diagnostic,count=count)
            self.assertEqual(r.returncode,2,r.stderr);self.assertIsNone(rows)

    def test_runtime_initialization_precedes_owned_fd_baseline(self):
        r,rows,_=self.run_case(failure='runtime-fd')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIsNotNone(rows)

    def test_completion_api_errors_never_export(self):
        for api in ('short-CQE','wrong-slot','EventQuery','fd-leak'):
            with self.subTest(api=api):
                r,rows,_=self.run_case(failure=api)
                self.assertEqual(r.returncode,1,r.stderr);self.assertIsNone(rows)

    def test_default_scheduler_transcript_unchanged(self):
        plain,_,_=self.run_case(False)
        diag,_,_=self.run_case(True)
        self.assertEqual(plain.returncode,0,plain.stderr)
        self.assertEqual(diag.returncode,0,diag.stderr)
        def operations(r):return [x for x in r.stderr.splitlines() if x.startswith('API ')]
        self.assertEqual(operations(plain),operations(diag))
        self.assertEqual(json.loads(plain.stdout)['staging_slots'],2)

    def test_cuda_cleanup_failure_never_exports(self):
        for api in ('EventDestroy','StreamDestroy','HostUnregister','Free','final-drain'):
            with self.subTest(api=api):
                r,rows,_=self.run_case(failure=api)
                self.assertEqual(r.returncode,1,r.stderr)
                self.assertIsNone(rows)
                self.assertNotIn('PASS',r.stdout)

CUDA_API = r"""
#pragma once
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
using cudaError_t=int;
using cudaEvent_t=int*;
using cudaStream_t=int*;
constexpr int cudaSuccess=0,cudaErrorNotReady=34,cudaMemcpyHostToDevice=1,cudaMemcpyDeviceToHost=2;
constexpr unsigned cudaHostRegisterDefault=0,cudaEventDisableTiming=2,cudaEventBlockingSync=1,cudaStreamNonBlocking=1;
static int e3_stream_id,e3_destroyed_events,e3_copies;
inline bool fail(const char*s){const char*f=std::getenv("E3_FAKE_FAILURE");return f&&!std::strcmp(f,s);}
inline const char*cudaGetErrorString(int){return "test API injected failure";}
inline int cudaGetDeviceCount(int*n){*n=1;return 0;}
inline int cudaSetDevice(int){if(fail("runtime-fd")){int retained=open("/dev/null",O_RDONLY);(void)retained;}return 0;}
inline int cudaHostRegister(void*,size_t,unsigned){std::fprintf(stderr,"API host-register\n");return 0;}
inline int cudaHostUnregister(void*){std::fprintf(stderr,"API host-unregister\n");return fail("HostUnregister");}
inline int cudaMalloc(void**p,size_t n){*p=std::malloc(n);return *p?0:1;}
inline int cudaFree(void*p){std::free(p);return fail("Free");}
inline int cudaEventCreateWithFlags(int**p,unsigned){*p=new int(0);return 0;}
inline int cudaEventDestroy(int*p){e3_destroyed_events++;delete p;return fail("EventDestroy");}
inline int cudaStreamCreateWithFlags(int**p,unsigned){*p=new int(e3_stream_id++);std::fprintf(stderr,"API stream-create %d\n",**p);return 0;}
inline int cudaStreamDestroy(int*p){delete p;return fail("StreamDestroy");}
inline int cudaMemcpy(void*d,const void*s,size_t n,int kind){if(kind==cudaMemcpyDeviceToHost)std::fprintf(stderr,"API readback\n");std::memcpy(d,s,n);return 0;}
inline int cudaMemcpyAsync(void*d,const void*s,size_t n,int,int*stream){std::fprintf(stderr,"API copy %zu stream=%d\n",n,*stream);std::memcpy(d,s,n);e3_copies++;if((fail("bad-first")&&e3_copies==1)||(fail("bad-last")&&e3_copies==32))static_cast<unsigned char*>(d)[fail("bad-last")?n-1:0]^=1;return 0;}
inline int cudaEventRecord(int*e,int*){*e=1;return 0;}
inline int cudaEventQuery(int*e){if(fail("EventQuery"))return 1;if(*e==1){*e=2;return cudaErrorNotReady;}return 0;}
inline int cudaEventSynchronize(int*){return 0;}
inline int cudaDeviceSynchronize(){std::fprintf(stderr,"API sync phase=%s\n",e3_destroyed_events?"cleanup":"live");return fail("final-drain")&&e3_destroyed_events>0;}
"""
URING_API = r"""
#pragma once
#include <vector>
#include <deque>
#include <sys/uio.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
constexpr unsigned IOSQE_FIXED_FILE=1;
struct __kernel_timespec{long long tv_sec,tv_nsec;};
struct io_uring_sqe{unsigned flags=0;void*buf=nullptr;unsigned len=0;unsigned long long off=0;bool write=false;void*data=nullptr;};
struct io_uring_cqe{int res;void*data;};
struct io_uring{int fd=-1;std::vector<io_uring_sqe> pending;std::deque<io_uring_cqe> ready;};
inline int io_uring_queue_init(unsigned,io_uring*,unsigned){return 0;}
inline int io_uring_register_files(io_uring*r,int*f,unsigned){r->fd=*f;return 0;}
inline int io_uring_register_buffers(io_uring*,iovec*,unsigned n){std::fprintf(stderr,"API buffers %u\n",n);return 0;}
inline int io_uring_unregister_buffers(io_uring*){return 0;}
inline int io_uring_unregister_files(io_uring*){return 0;}
inline void io_uring_queue_exit(io_uring*){if(fail("fd-leak")){int leaked=open("/dev/null",O_RDONLY);(void)leaked;}}
inline io_uring_sqe*io_uring_get_sqe(io_uring*r){r->pending.emplace_back();return &r->pending.back();}
inline void io_uring_prep_read_fixed(io_uring_sqe*s,int,void*b,unsigned n,unsigned long long off,int){s->buf=b;s->len=n;s->off=off;s->write=false;}
inline void io_uring_prep_write_fixed(io_uring_sqe*s,int,void*b,unsigned n,unsigned long long off,int){s->buf=b;s->len=n;s->off=off;s->write=true;}
inline void io_uring_sqe_set_data(io_uring_sqe*s,void*d){s->data=d;}
inline void*io_uring_cqe_get_data(io_uring_cqe*c){return c->data;}
inline int io_uring_submit(io_uring*r){for(auto&s:r->pending){std::fprintf(stderr,"API read-fixed %llu %u\n",s.off,s.len);ssize_t n=s.write?pwrite(r->fd,s.buf,s.len,s.off):pread(r->fd,s.buf,s.len,s.off);if(fail("short-CQE"))n--;r->ready.push_back({n<0?-errno:int(n),fail("wrong-slot")?reinterpret_cast<void*>(999):s.data});}int n=r->pending.size();r->pending.clear();return n;}
inline int io_uring_peek_cqe(io_uring*r,io_uring_cqe**c){if(r->ready.empty())return -EAGAIN;*c=&r->ready.front();return 0;}
inline void io_uring_cqe_seen(io_uring*r,io_uring_cqe*){r->ready.pop_front();}
inline int io_uring_wait_cqe_timeout(io_uring*r,io_uring_cqe**c,__kernel_timespec*){return io_uring_peek_cqe(r,c);}
"""

class SessionDiagnosticOptions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        for parent in Path(__file__).resolve().parents:
            if (parent/'tools/layout.py').is_file():
                sys.path.insert(0,str(parent/'tools'))
                break
        from layout import canonical_root
        canonical=canonical_root(Path(__file__))
        sys.path.insert(0,str(canonical/'tests/support/benchmarks'))
        from ce_vmm_contract import parser, Compiled, COMMON
        cls.parser=parser(canonical,'nvme_gpu');cls.addClassCleanup(cls.parser.close)
        source=(canonical/'tests/benchmarks/nvme_gpu/session_nvme_ce.c').read_text()
        prelude=COMMON+'\n#define SN_IO_ALIGN 4096ULL\n#define E3_REQUEST_QUALIFICATION 1\n#include "'+str(HERE/'nvme_gpu_core.h')+'"\n'
        main='int main(int argc,char**argv){struct sn_opts o;printf("%d\\n",sn_parse(argc,argv,&o));return 0;}'
        cls.qualified=Compiled(prelude+declaration(source,'sn_opts')+function(source,'sn_usage')+function(source,'sn_parse')+main)
        cls.addClassCleanup(cls.qualified.close)

    def args(self):
        return ['--direction','load','--ng','/nonexistent/ng','--slba','0','--lba-size','512','--file','/nonexistent/file','--ce-dev','/dev/xdev_ext_ce_sim','--ce-va','0','--size','4096','--qd','1','--window-bytes','12288','--passes','1','--timeout-ms','1000','--diagnostic-request-latency','unused']

    def test_session_qualification_requires_exact_private_profile(self):
        for size,want in ((131072,0),(12288,2),(16777216,2)):
            args=self.args()+['--window-bytes',str(size)]
            r=subprocess.run([str(self.qualified.binary),*args],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(int(r.stdout),want)
        r=subprocess.run([str(self.qualified.binary),*self.args()[:-2],'--window-bytes','131072'],capture_output=True,text=True)
        self.assertEqual(int(r.stdout),2)

    def test_session_diagnostic_parser_is_bounded(self):
        self.assertEqual(self.parser.run(*self.args())['rc'],0)
        for extra in (('--direction','save'),('--qd','2'),('--slba','1'),('--lba-size','4096'),('--frame-size','8192'),('--pattern','rand'),('--passes','2'),('--seed','2'),('--timeout-ms','10001'),('--window-bytes','16781312')):
            with self.subTest(extra=extra):self.assertEqual(self.parser.run(*(self.args()+list(extra)))['rc'],2)

if __name__ == '__main__': unittest.main()

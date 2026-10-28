#!/usr/bin/env python3
"""Host-only boundaries; never submits, maps a controller or times GPU I/O."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import native_contract as n

class Boundaries(unittest.TestCase):
    def test_cpp_byte_oracle_and_completion(self):
        header=Path(__file__).with_name('native_core.h')
        self.assertTrue(header.exists(),'missing production C++ full-byte/completion helpers')
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'test.cpp';exe=Path(td)/'test'
            src.write_text('''#include "native_core.h"
#include <cassert>
int main(){ unsigned char e[4608]={},a[4608]={},g[32];
for(auto &b:g)b=0xa5;
assert(bam::verify(e,4608,a,4608,g,32,g,32));
a[4607]=1;assert(!bam::verify(e,4608,a,4608,g,32,g,32));a[4607]=0;
assert(!bam::verify(e,4608,a,4607,g,32,g,32));
g[31]=0;assert(!bam::verify(e,4608,a,4608,g,32,g,32));
assert(bam::completion(9,9,1,1,1,1,1)==0);
assert(bam::completion(9,8,1,1,1,1,1)!=0);
assert(bam::completion(9,9,2,1,1,1,1)!=0);
assert(bam::completion(9,9,1,1,1,1,3)!=0);
assert(bam::completion(9,9,1,1,2,1,1)!=0);
assert(bam::completion(9,9,1,1,1,1,0)!=0);
}''')
            subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-I',str(header.parent),str(src),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
    def test_qualification_rejects_native_geometry_truncation_and_timeout(self):
        r=dict(schema_version=1,upstream_revision=n.REVISION,backend='bam-native',gpu_initiated=True,
            controller='/dev/libnvm9',namespace_id=1,namespace_blocks=1024,lba_size=512,page_size=4096,
            region_start_lba=1,region_blocks=8,direction='read',allow_write=False,approved=True,
            exclusive=True,gpu_uuid='GPU-host-only-receipt',execution='physical',iommu='disabled',
            acs='disabled',above_4g=True,cuda_capability=80)
        self.assertEqual(n.qualify(r)['namespace_id'],1)
        for change in [dict(page_size=2**32),dict(lba_size=2**32,page_size=2**32),
                       dict(timeout_policy='kill'),dict(timeout_seconds=1),dict(namespace_id=True),
                       dict(approved=1),dict(schema_version=True)]:
            with self.subTest(change=change),self.assertRaises(ValueError):n.qualify(dict(r,**change))
    def test_runner_usage_and_rejected_receipt_have_no_success(self):
        script=Path(__file__).with_name('run_native.py')
        with tempfile.TemporaryDirectory() as td:
            receipt=Path(td)/'receipt.json';receipt.write_text('{}')
            r=subprocess.run(['python3',str(script),'--qualify',str(receipt),'--mode','correctness'],capture_output=True,text=True)
            self.assertEqual(r.returncode,4);self.assertEqual(r.stdout,'')
            r=subprocess.run(['python3',str(script),'--qualify',str(receipt),'--mode','performance'],capture_output=True,text=True)
            self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,'')
    def test_production_quarantine_retains_unknown_after_closed_log_pipe(self):
        # Compile the actual production body, not a duplicate or GPU emulator.
        source=Path(__file__).with_name('bench_native.cu').read_text()
        start=source.index('[[noreturn]] static void quarantine(')
        brace=source.index('{',start);depth=1;end=brace+1
        while depth:
            depth+=(source[end]=='{')-(source[end]=='}');end+=1
        code='#include <cstdio>\n#include <csignal>\n#include <unistd.h>\n'+source[start:end]+\
            '\nint main(){quarantine("accepted UNKNOWN command");}\n'
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'quarantine.cpp';exe=Path(td)/'quarantine';src.write_text(code)
            subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror',str(src),'-o',str(exe)],check=True)
            reader,writer=os.pipe();os.close(reader)
            try:
                process=subprocess.Popen([str(exe)],stderr=writer,restore_signals=True)
            finally:os.close(writer)
            try:
                try:
                    code=process.wait(timeout=0.2)
                    self.fail('UNKNOWN resource owner terminated after diagnostic EPIPE: '+str(code))
                except subprocess.TimeoutExpired:pass
            finally:
                # Host-only fixture has no DMA/resources. Terminate only the fixture.
                if process.poll() is None:process.kill()
                process.wait()
            # A readable diagnostic pipe still receives the real UNKNOWN record.
            process=subprocess.Popen([str(exe)],stderr=subprocess.PIPE,restore_signals=True)
            try:
                with self.assertRaises(subprocess.TimeoutExpired):process.communicate(timeout=0.2)
            finally:
                if process.poll() is None:process.kill()
                _,diagnostic=process.communicate()
            self.assertIn(b'"state":"unknown"',diagnostic)
            self.assertIn(b'accepted UNKNOWN command',diagnostic)
    def test_sigpipe_policy_precedes_all_main_logs_and_allocations(self):
        source=Path(__file__).with_name('bench_native.cu').read_text()
        main=source[source.index('int main(int argc,char** argv) {'):]
        self.assertIn('std::signal(SIGPIPE,SIG_IGN)',main)
        policy=main.index('std::signal(SIGPIPE,SIG_IGN)')
        self.assertLess(policy,main.index('std::fprintf'))
        self.assertLess(policy,main.index('new Session'))
    def test_bool_and_overflow(self):
        for v in (True,False,1.0,'1',None,2**64):
            with self.subTest(v=v),self.assertRaises(ValueError):n.plan_io(v,4096,512,0,16)
        with self.assertRaises(ValueError):n.plan_io(512,4096,512,0,2**64//512)
        self.assertEqual(n.plan_io(512,4096,512,0,1)[0]['lba'],0)
    def test_plan_partition_many_exact_tails(self):
        for blocks in range(1,65):
            p=n.plan_io(blocks*512,4096,512,19,blocks)
            self.assertEqual(sum(x['blocks'] for x in p),blocks)
            self.assertEqual(p[-1]['lba']+p[-1]['blocks'],19+blocks)
            self.assertEqual([x['offset'] for x in p],list(range(0,blocks*512,4096)))
    def test_unknown_state_rejected(self):
        for s in ('timeout','cancelled',None,False):
            with self.assertRaises(ValueError):n.completion_policy(s)
    def test_oracle_all_byte_and_guard_mutations(self):
        e=bytes((i*29+i//251+7)%256 for i in range(513));g=b'\xa5'*32
        for i in range(len(e)):
            a=bytearray(e);a[i]^=1;self.assertFalse(n.verify_image(e,a,g,g))
        for i in range(32):
            bad=bytearray(g);bad[i]=0
            self.assertFalse(n.verify_image(e,e,bad,g));self.assertFalse(n.verify_image(e,e,g,bad))

if __name__=='__main__':unittest.main(verbosity=2)

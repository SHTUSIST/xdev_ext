#!/usr/bin/env python3
"""Host-only boundaries; never submits, maps a controller or times GPU I/O."""
import json
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

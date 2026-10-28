# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[4]
class OptionsTest(unittest.TestCase):
    def test_real_driver_admission_rejects_serial_depth_and_overflow(self):
        code='''#include "tests/benchmarks/tp/options.h"
#include <cassert>
int main() {
 tp_eval_options o; o.rank=0; o.mode=1; o.depth=2;
 assert(tp_eval_geometry(o)<0);
 o.mode=2; assert(tp_eval_geometry(o)==0); assert(o.frame_count>=2);
 o.elements=~0ULL; assert(tp_eval_geometry(o)<0);
 o.elements=16; o.depth=0; assert(tp_eval_geometry(o)<0);
 o.depth=1; o.iterations=~0ULL; assert(tp_eval_geometry(o)<0);
 o.iterations=2; o.rank=2; assert(tp_eval_geometry(o)<0);
 o.rank=1; assert(tp_eval_geometry(o)==0);
 o.operation=4; o.mode=1; assert(tp_eval_geometry(o)==0);
 o.mode=2; assert(tp_eval_geometry(o)==0);
 o.depth=2; assert(tp_eval_geometry(o)==-EINVAL);
 o.operation=1; assert(tp_eval_geometry(o)==0);
 o.operation=3; assert(tp_eval_geometry(o)==0);
}'''
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'probe.cc'; source.write_text(code)
            build=subprocess.run(['g++','-std=c++17','-Wall','-Wextra','-Werror','-I'+str(ROOT),str(source),'-o',d+'/probe'],capture_output=True,text=True)
            self.assertEqual(build.returncode,0,build.stderr)
            run=subprocess.run([d+'/probe'],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
if __name__=='__main__': unittest.main()

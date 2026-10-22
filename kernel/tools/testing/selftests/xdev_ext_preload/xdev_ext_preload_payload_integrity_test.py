#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual ordinary-libc guest workload fault negatives; no kernel/provider model."""
from pathlib import Path
import hashlib,json,os,shlex,subprocess,unittest

HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ.get('INTEGRITY_WORKLOAD_SOURCE',str(HERE/'xdev_ext_preload_mech_workload.c')))
OUT=Path(os.environ.get('XDEV_EXT_PRELOAD_TEST_DIR',str(HERE))).resolve()
BUILD=Path(os.environ.get('INTEGRITY_BUILD_DIR',str(OUT/'payload-integrity')))
RECORDS=[]

class WorkloadIntegrity(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  BUILD.mkdir(parents=True,exist_ok=True)
  cc=shlex.split(os.environ.get('CC','gcc'))
  for src,target,extra in [(SOURCE,'workload',['-pthread']),(HERE/'xdev_ext_preload_payload_fault_fixture.c','fault.so',['-shared','-fPIC','-ldl'])]:
   subprocess.run(cc+['-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(src),'-o',str(BUILD/target)]+extra,check=True,capture_output=True,text=True,timeout=30)
 @classmethod
 def tearDownClass(cls):
  (BUILD/'results.json').write_text(json.dumps(dict(source=str(SOURCE),source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),records=RECORDS),indent=2)+'\n')
 def run_case(self,fault,concurrent=False):
  env={k:v for k,v in os.environ.items() if not k.startswith('XDEV') and k!='LD_PRELOAD'}
  if fault:env.update(LD_PRELOAD=str(BUILD/'fault.so'),INTEGRITY_FAULT=fault)
  args=['concurrency','4','1','65'] if concurrent else ['base']
  p=subprocess.run([str(BUILD/'workload')]+args,env=env,capture_output=True,text=True,timeout=45)
  RECORDS.append(dict(fault=fault,concurrent=concurrent,args=args,exit=p.returncode,stdout=p.stdout,stderr=p.stderr))
  return p
 def reject(self,fault,concurrent=False):
  p=self.run_case(fault,concurrent)
  self.assertNotIn('XDEV_EXT_MECH_APP=PASS',p.stdout,p.stdout+p.stderr)
  self.assertNotIn('XDEV_EXT_MECH_ACTOR=PASS',p.stdout,p.stdout+p.stderr)
  self.assertNotEqual(p.returncode,0,p.stdout+p.stderr)
 def test_plain_base_still_accepts_original_input(self):
  p=self.run_case(None);self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  self.assertIn('XDEV_EXT_MECH_APP=PASS calls=257',p.stdout)
 def test_source_and_wire_corruption_rejected_base(self):
  self.reject('source-and-wire')
 def test_source_and_wire_corruption_rejected_concurrent(self):
  self.reject('source-and-wire',True)
 def test_large_fallback_source_and_wire_corruption_rejected(self):
  self.reject('fallback-large')
 def test_seven_byte_fallback_source_and_wire_corruption_rejected(self):
  self.reject('fallback-seven')
 def test_receive_middle_corruption_rejected(self):
  for c in [False,True]:
   with self.subTest(concurrent=c):self.reject('receive-middle',c)
 def test_receive_last_corruption_rejected(self):
  for c in [False,True]:
   with self.subTest(concurrent=c):self.reject('receive-last',c)
 def test_receive_truncation_rejected(self):
  for c in [False,True]:
   with self.subTest(concurrent=c):self.reject('receive-truncate',c)

if __name__=='__main__':unittest.main(verbosity=2)

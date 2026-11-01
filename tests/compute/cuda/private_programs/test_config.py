#!/usr/bin/env python3
"""Contract-only admission tests. Direct production module; no Torch import."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

PINS=['/sys/fs/bpf/test/tx-user-producer','/sys/fs/bpf/test/tx-xdomain','/sys/fs/bpf/test/tx-user-terminal','/sys/fs/bpf/test/rx-xdomain','/sys/fs/bpf/test/rx-user-consumer']
# Literal class-global-needed masks for stage-private masks0..31.
NEEDS=[3,3,3,3,3,3,3,3,3,3,1,1,3,3,1,1,3,3,3,3,3,2,3,2,3,3,1,1,3,2,1,0]
parser=argparse.ArgumentParser();parser.add_argument('source');parser.add_argument('--legacy',action='store_true');args,extra=parser.parse_known_args()
spec=importlib.util.spec_from_file_location('independent_private_config',Path(args.source)/'src/compute/torch/xdev_tp_torch/config.py')
config=importlib.util.module_from_spec(spec);spec.loader.exec_module(config)

class Admission(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  p=Path(self.temp.name)
  self.elf=str(p/'default.bpf.o');self.ptx=str(p/'payload.ptx')
  Path(self.elf).write_bytes(b'ordinary-input-fixture');Path(self.ptx).write_text('build-only-input')
  self.base=dict(version=1,rank=0,world_size=2,device_index=0,mode=1,link_token=7,allocation_bytes=65536,group_bytes=4096,depth=1,nr_batches=1,first_sequence=1,timeout_ns=1000000,communicator_id=17,epoch=1,max_payload_bytes=4032,nvidia_node='/dev/nvidia-test-unopened',bpf_object=self.elf,user_bpf_object=self.elf,ptx_path=self.ptx)
 def validate(self,options):return config.validate_options(options,rank=0,device_index=0,environ={})
 def test_legacy_inputs(self):
  self.assertEqual(self.validate(self.base),self.base)
  for key in ('bpf_object','user_bpf_object'):
   x=copy.deepcopy(self.base);x.pop(key)
   with self.assertRaises(ValueError):self.validate(x)
  x=copy.deepcopy(self.base);x['class_program_fd']=19
  with self.assertRaises(ValueError):self.validate(x)
 @unittest.skipIf(args.legacy,'new config behavior')
 def test_all32_distributions(self):
  for mask in range(32):
   x=copy.deepcopy(self.base);values=[PINS[i] if mask&(1<<i) else None for i in range(5)]
   x.update(tx_program_pins=values[:3],rx_program_pins=values[3:])
   with self.subTest(mask=mask):
    y=self.validate(x);self.assertEqual(y['tx_program_pins'],values[:3]);self.assertEqual(y['rx_program_pins'],values[3:])
    for bit,key in ((1,'user_bpf_object'),(2,'bpf_object')):
     z=copy.deepcopy(x);z.pop(key)
     if NEEDS[mask]&bit:
      with self.assertRaises(ValueError):self.validate(z)
     else:self.validate(z)
     z=copy.deepcopy(x);z[key]=None
     if NEEDS[mask]&bit:
      with self.assertRaises(ValueError):self.validate(z)
     else:self.validate(z)
 @unittest.skipIf(args.legacy,'new config behavior')
 def test_absent_and_allnull(self):
  self.validate(self.base)
  for key,length in (('tx_program_pins',3),('rx_program_pins',2)):
   x=copy.deepcopy(self.base);x[key]=[None]*length;self.validate(x)
 @unittest.skipIf(args.legacy,'new config behavior')
 def test_invalid_arrays_items(self):
  for key,count in (('tx_program_pins',3),('rx_program_pins',2)):
   for value in (None,{},'absolute-pin',[],[None]*(count-1),[None]*(count+1)):
    x=copy.deepcopy(self.base);x[key]=value
    with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.validate(x)
   for invalid in ('','relative/pin','/pin\x00hidden',0,False,{},[],3.14):
    for slot in range(count):
     x=copy.deepcopy(self.base);x[key]=[None]*count;x[key][slot]=invalid
     with self.subTest(key=key,slot=slot,value=invalid),self.assertRaises(ValueError):self.validate(x)
 @unittest.skipIf(args.legacy,'new config behavior')
 def test_pin_paths_do_not_require_stat(self):
  x=copy.deepcopy(self.base);x['tx_program_pins']=PINS[:3];x['rx_program_pins']=PINS[3:]
  x.pop('bpf_object');x.pop('user_bpf_object');self.validate(x)
 @unittest.skipIf(args.legacy,'new config behavior')
 def test_rank_local_pins_excluded_from_agreement(self):
  x=copy.deepcopy(self.base);x['tx_program_pins']=PINS[:3];x['rx_program_pins']=PINS[3:]
  y=copy.deepcopy(x);y['tx_program_pins']=[p+'-other-rank' for p in PINS[:3]];y['rx_program_pins']=[None,None]
  self.assertEqual(config.agreement_key(self.validate(x)),config.agreement_key(self.validate(y)))
  y['epoch']=2;self.assertNotEqual(config.agreement_key(x),config.agreement_key(y))
 @unittest.skipIf(args.legacy,'new config behavior')
 def test_unused_ELF_still_validates_supplied_type(self):
  for key in ('bpf_object','user_bpf_object'):
   for invalid in ('',0,False,[],{}):
    x=copy.deepcopy(self.base);x['tx_program_pins']=PINS[:3];x['rx_program_pins']=PINS[3:];x[key]=invalid
    with self.subTest(key=key,value=invalid),self.assertRaises(ValueError):self.validate(x)
 @unittest.skipIf(args.legacy,'new config behavior')
 def test_json_serialized_nul(self):
  x=copy.deepcopy(self.base);x['tx_program_pins']=['/pin\x00tail',None,None]
  path=Path(self.temp.name)/'input.json';path.write_text(json.dumps(x))
  with self.assertRaises(ValueError):config.load_options(str(path),rank=0,group=0,device_index=0,environ={})

if __name__=='__main__':unittest.main(argv=[__file__]+extra,verbosity=2)

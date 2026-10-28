# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import importlib.util
import unittest
ROOT=Path(__file__).resolve().parents[4]
class RunnerTest(unittest.TestCase):
 def test_actual_route_qualification_does_not_accept_environment_only(self):
  path=ROOT/'tests/benchmarks/tp/run.py'
  self.assertTrue(path.is_file(),'real runner is missing')
  spec=importlib.util.spec_from_file_location('tp_eval_run',path)
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  env={'NCCL_NET':'Socket','NCCL_SOCKET_IFNAME':'=thunderbolt0'}
  with self.assertRaises(ValueError):m.qualify_nccl_route(env,'',{'thunderbolt0':dict(addresses=['1.2.3.4'],rx_bytes=10,tx_bytes=10)})
  with self.assertRaises(ValueError):m.qualify_nccl_route(dict(env,NCCL_ALGO='Ring'),'NET/Socket : Using [0]thunderbolt0:1.2.3.4',{'thunderbolt0':dict(addresses=['1.2.3.4'],rx_bytes=10,tx_bytes=10)})
  m.qualify_nccl_route(env,'NET/Socket : Using [0]thunderbolt0:1.2.3.4',{'thunderbolt0':dict(addresses=['1.2.3.4'],rx_bytes=10,tx_bytes=10)})
if __name__=='__main__':unittest.main()

class RawCompletionTest(unittest.TestCase):
 def test_raw_summary_rejects_interval_from_another_rank(self):
  import json
  import tempfile
  path=ROOT/'tests/benchmarks/tp/run.py'
  spec=importlib.util.spec_from_file_location('tp_eval_run_raw',path)
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  events=[dict(record='event',sequence=1,timestamp=t,kind=k,clock=2,rank=0,payload_bytes=4,wire_bytes=68,logical_inflight=n) for t,k,n in [(10,1,1),(20,3,1),(30,4,1),(40,5,0)]]
  records=events+[dict(record='validation',sequence=1,rank=0,direction='rx',payload_bytes=4,valid=True),dict(record='metadata',communicator=1,epoch=1,rank=0,clock=2,trace_dropped=0,requested_depth=1,native_high_water=1,completed=1,native_mode=2,handoff_mode='gpu'),dict(record='interval',start=100,end=200,rank=1,clock=1,kind='allreduce',completed=True,custody_released=True)]
  with tempfile.TemporaryDirectory() as d:
   raw=Path(d)/'raw.jsonl';raw.write_text(''.join(json.dumps(r)+'\n' for r in records))
   with self.assertRaises(ValueError):m.analyze_file(raw)

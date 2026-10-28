#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host process/error controls for the local Redis response runner."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TARGET=Path(os.environ.get('REDIS_TARGET',str(Path(__file__).resolve().parent)))
FAKE=r'''#!/usr/bin/env python3
import os,socket,sys
from pathlib import Path
Path(PID).write_text(str(os.getpid()))
if MODE=='exit':sys.exit(17)
s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[sys.argv.index('--unixsocket')+1]);s.listen(1)
c,_=s.accept();f=c.makefile('rb')
def command():
 line=f.readline()
 if not line:return []
 count=int(line[1:-2]);args=[]
 for _ in range(count):
  n=int(f.readline()[1:-2]);args.append(f.read(n));assert f.read(2)==b'\r\n'
 return args
assert command()==[b'PING'];c.sendall(b'+PONG\r\n')
if MODE=='death':sys.exit(18)
assert command()[0]==b'SET';c.sendall(b'+OK\r\n')
assert command()[0]==b'GET'
if MODE=='short':c.sendall(b'$9\r\nabc')
else:c.sendall(b'$1\r\nx\r\n')
'''

class Lifecycle(unittest.TestCase):
 def module(self):
  path=TARGET/'run_redis_fragmented_eval.py';self.assertTrue(path.is_file(),'missing correctness runner')
  spec=importlib.util.spec_from_file_location('runner_extra',path);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
 def cli(self,*args,env=None):
  self.module();return subprocess.run([sys.executable,str(TARGET/'run_redis_fragmented_eval.py'),*args],capture_output=True,text=True,timeout=30,env=env)
 def test_line_and_bulk_fragmentation_and_short_eof(self):
  m=self.module()
  class OneByte(io.BytesIO):
   def read(self,n=-1):return super().read(min(n,1) if n>=0 else 1)
  self.assertEqual(m.read_response(OneByte(b'*2\r\n$4\r\na\x00\r\n\r\n:7\r\n')),[b'a\x00\r\n',7])
  for wire in (b'+OK\r',b':7',b'$7\r\nabc',b'*1\r\n$0\r\n\r'):
   with self.subTest(wire=wire),self.assertRaises((ValueError,EOFError,RuntimeError)):m.read_response(OneByte(wire))
 def failed_server(self,mode):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);scratch=root/'scratch';scratch.mkdir();pid=root/'pid';fake=root/'server'
   fake.write_text(FAKE.replace('PID',repr(str(pid))).replace('MODE',repr(mode)));fake.chmod(0o700);out=root/'out.json'
   p=self.cli('--redis-server',str(fake),'--mode','correctness','--output',str(out),'--scratch-root',str(scratch),'--timeout','1')
   self.assertNotEqual(p.returncode,0,p.stdout);self.assertNotIn('PASS',p.stdout);self.assertFalse(out.exists());self.assertEqual(list(scratch.iterdir()),[])
   self.assertTrue(pid.exists());child=int(pid.read_text())
   with self.assertRaises(ProcessLookupError):os.kill(child,0)
 def test_startup_exit_has_no_success_or_owned_process(self):self.failed_server('exit')
 def test_server_death_after_readiness_has_no_success(self):self.failed_server('death')
 def test_short_native_response_has_no_success(self):self.failed_server('short')
 def test_wrong_complete_response_has_no_success(self):self.failed_server('wrong')
 def test_trailing_extra_response_is_rejected(self):
  server=r'''#!/usr/bin/env python3
import socket,sys
s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[sys.argv.index('--unixsocket')+1]);s.listen(1)
c,_=s.accept();f=c.makefile('rb');data={}
def bulk(v):return b'$'+str(len(v)).encode()+b'\r\n'+v+b'\r\n'
while True:
 line=f.readline()
 if not line:break
 args=[]
 for _ in range(int(line[1:-2])):
  n=int(f.readline()[1:-2]);args.append(f.read(n));assert f.read(2)==b'\r\n'
 op=args[0]
 if op==b'PING':reply=b'+PONG\r\n'
 elif op==b'SET':data[args[1]]=args[2];reply=b'+OK\r\n'
 elif op==b'GET':reply=bulk(data[args[1]])
 elif op==b'RPUSH':data[args[1]]=args[2:];reply=b':'+str(len(args)-2).encode()+b'\r\n'
 elif op in (b'MGET',b'LRANGE'):
  values=[data[k] for k in args[1:]] if op==b'MGET' else data[args[1]]
  reply=b'*'+str(len(values)).encode()+b'\r\n'+b''.join(bulk(v) for v in values)
  if op==b'LRANGE' and args[1].startswith(b'LRANGE_256x4K'):reply+=b'+UNSOLICITED\r\n'
 elif op==b'QUIT':c.sendall(b'+OK\r\n');break
 else:raise AssertionError(op)
 c.sendall(reply)
'''
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);fake=root/'extra-server';fake.write_text(server);fake.chmod(0o700);out=root/'out.json'
   p=self.cli('--redis-server',str(fake),'--mode','correctness','--output',str(out),'--timeout','2')
   self.assertNotEqual(p.returncode,0,p.stdout);self.assertFalse(out.exists());self.assertNotIn('PASS',p.stdout)
 def test_setup_failure_does_not_launch_server(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);marker=root/'called';fake=root/'server';fake.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")\n');fake.chmod(0o700)
   scratch=root/'not-a-directory';scratch.write_text('held');out=root/'out.json'
   p=self.cli('--redis-server',str(fake),'--mode','correctness','--output',str(out),'--scratch-root',str(scratch))
   self.assertNotEqual(p.returncode,0);self.assertFalse(marker.exists());self.assertFalse(out.exists())
 def test_cleanup_preserves_unrelated_process(self):
  sentinel=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],start_new_session=True)
  try:
   with tempfile.TemporaryDirectory() as td:
    root=Path(td);fake=root/'slow';fake.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n');fake.chmod(0o700)
    p=self.cli('--redis-server',str(fake),'--mode','correctness','--output',str(root/'out.json'),'--timeout','0.15')
    self.assertNotEqual(p.returncode,0);self.assertIsNone(sentinel.poll())
  finally:sentinel.terminate();sentinel.wait(timeout=5)
 def test_real_preload_is_mapped_and_baseline_is_also_verified(self):
  self.module();server=shutil.which('redis-server');cc=shutil.which('cc');self.assertIsNotNone(server);self.assertIsNotNone(cc)
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);c=root/'probe.c';lib=root/'probe.so';c.write_text('int redis_fragmented_probe(void){return 1;}\n')
   subprocess.run([cc,'-shared','-fPIC',str(c),'-o',str(lib)],check=True,capture_output=True)
   out=root/'out.json';env={**os.environ,'LD_PRELOAD':str(lib),'UBR_LEFTOVER':'1','XDEV_EXT_LEFTOVER':'1'}
   p=self.cli('--redis-server',server,'--mode','correctness','--output',str(out),'--preload',str(lib),env=env)
   self.assertEqual(p.returncode,0,p.stderr);data=json.loads(out.read_text());self.assertEqual(data['status'],'PASS');arms={a['name']:a for a in data['arms']}
   self.assertEqual(set(arms),{'baseline','preload'});self.assertFalse(arms['baseline']['library_mapped']);self.assertTrue(arms['preload']['library_mapped'])
   for arm in arms.values():self.assertEqual(len(arm['cases']),9);self.assertTrue(all(c['verified'] for c in arm['cases']))
 def test_missing_requested_preload_capability_exits_four(self):
  self.module();server=shutil.which('redis-server');self.assertIsNotNone(server)
  with tempfile.TemporaryDirectory() as td:
   out=Path(td)/'out.json';p=self.cli('--redis-server',server,'--mode','correctness','--output',str(out),'--preload',str(Path(td)/'absent.so'))
   self.assertEqual(p.returncode,4,p.stderr);self.assertNotIn('PASS',p.stdout);self.assertFalse(out.exists())

if __name__=='__main__':unittest.main(verbosity=2)

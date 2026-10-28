#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent response-correctness contracts, no throughput measurement."""
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

TARGET = Path(os.environ.get('REDIS_TARGET', str(Path(__file__).resolve().parent)))

class Contract(unittest.TestCase):
    def module(self):
        path=TARGET/'run_redis_fragmented_eval.py'
        self.assertTrue(path.is_file(), 'missing isolated Redis fragmented-response correctness runner')
        spec=importlib.util.spec_from_file_location('redis_under_test',path)
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        return module

    def test_original_nine_shapes(self):
        m=self.module()
        expected=[('GET_256K','get',1,262144),('GET_512K','get',1,524288),('GET_1M','get',1,1048576),('GET_2M','get',1,2097152),('MGET_16x16K','mget',16,16384),('MGET_32x16K','mget',32,16384),('MGET_64x8K','mget',64,8192),('LRANGE_128x4K','lrange',128,4096),('LRANGE_256x4K','lrange',256,4096)]
        self.assertEqual([(w.name,w.kind,w.item_count,w.value_bytes) for w in m.WORKLOADS],expected)

    def test_binary_and_empty_and_nil_response(self):
        decode=self.module().decode_response
        self.assertEqual(decode(b'$5\r\na\x00\r\nb\r\n'), b'a\x00\r\nb')
        self.assertEqual(decode(b'*3\r\n$0\r\n\r\n$-1\r\n*0\r\n'), [b'',None,[]])
        self.assertEqual(decode(b'+OK\r\n'),b'OK');self.assertEqual(decode(b':128\r\n'),128)

    def test_truncated_invalid_and_extra_bytes_rejected(self):
        decode=self.module().decode_response
        for wire in (b'',b'$4\r\nabc',b'$1\r\naXX',b'$-2\r\n',b'*-2\r\n',b'*2\r\n$1\r\na\r\n',b'$1\r\na\r\n$1\r\nb\r\n',b'-ERR broken\r\n',b':x\r\n'):
            with self.subTest(wire=wire),self.assertRaises((ValueError,EOFError,RuntimeError)):
                decode(wire)

    def test_bounded_parser_rejects_oversized_counts_and_recursion(self):
        m=self.module()
        for wire in (b'$999999999999999999999\r\n',b'*99999999999999999999\r\n',b'*1\r\n'*1000+b'$0\r\n\r\n'):
            with self.subTest(wire=wire[:40]),self.assertRaises((ValueError,EOFError,RuntimeError)):
                m.decode_response(wire)

    def test_fragmented_stream_consumption(self):
        m=self.module()
        class Short(io.BytesIO):
            def read(self,n=-1):return super().read(min(n,3) if n>=0 else 3)
            def readline(self,n=-1):
                # Keep normal readline; bulk reads still return actual short chunks.
                return super().readline(n)
        self.assertEqual(m.read_response(Short(b'*2\r\n$7\r\nabcdefg\r\n$4\r\nwxyz\r\n')), [b'abcdefg',b'wxyz'])

    def test_exact_oracle_detects_every_position_and_array_order(self):
        m=self.module();expected=[b'abcdefg',b'123456789',b'\x00\xffq']
        self.assertTrue(m.verify_reply(expected,expected))
        for i,part in enumerate(expected):
            for j in range(len(part)):
                value=bytearray(part);value[j]^=1;actual=list(expected);actual[i]=bytes(value)
                self.assertFalse(m.verify_reply(actual,expected))
        for actual in (expected[:-1],expected+[b''],expected[::-1],b'abcdefg', [b'abcdefg',b'123456789',b'\x00\xffqX']):
            self.assertFalse(m.verify_reply(actual,expected))

    def test_payload_is_unique_binary_and_exact_length(self):
        m=self.module()
        for n in (0,1,4097,16385):
            self.assertEqual(len(m.payload(0,n)),n)
        self.assertNotEqual(m.payload(0,4097),m.payload(1,4097))
        self.assertEqual(m.payload(3,4097),m.payload(3,4097))
        self.assertIn(b'\x00',m.payload(0,4097))

    def test_baseline_environment_clears_inherited_preloads(self):
        m=self.module();original={'PATH':'/bin','LD_PRELOAD':'/foreign.so','UBR_STATS':'1','XDEV_EXT_MODE':'unsafe','KEEP_THIS':'yes'}
        env=m.server_env(None,original)
        self.assertNotIn('LD_PRELOAD',env);self.assertNotIn('UBR_STATS',env);self.assertNotIn('XDEV_EXT_MODE',env)
        self.assertEqual(env['KEEP_THIS'],'yes');self.assertEqual(original['LD_PRELOAD'],'/foreign.so')
        self.assertEqual(m.server_env('/explicit.so',original)['LD_PRELOAD'],'/explicit.so')

    def cli(self,*args,timeout=30):
        self.module()
        return subprocess.run([sys.executable,str(TARGET/'run_redis_fragmented_eval.py'),*args],capture_output=True,text=True,timeout=timeout)

    def test_absent_dependency_is_not_run_no_success_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'result.json';p=self.cli('--redis-server',str(Path(td)/'missing'),'--mode','correctness','--output',str(out))
            self.assertEqual(p.returncode,4,p.stderr);self.assertNotIn('PASS',p.stdout)
            self.assertFalse(out.exists())

    def test_real_redis_nine_shapes_correctness_and_no_metrics(self):
        server=shutil.which('redis-server')
        self.assertIsNotNone(server,'real redis-server is a declared test dependency')
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'result.json';scratch=Path(td)/'scratch';scratch.mkdir()
            p=self.cli('--redis-server',server,'--mode','correctness','--output',str(out),'--scratch-root',str(scratch),timeout=60)
            self.assertEqual(p.returncode,0,p.stderr)
            data=json.loads(out.read_text());self.assertEqual(data['status'],'PASS');self.assertEqual(data['scope'],'redis-response-correctness')
            self.assertEqual({r['name'] for r in data['cases']},{w.name for w in self.module().WORKLOADS})
            self.assertTrue(all(r['verified'] for r in data['cases']))
            text=out.read_text().lower()
            for metric in ('rps','throughput','latency_ms','speedup'):self.assertNotIn(metric,text)
            self.assertEqual(list(scratch.iterdir()),[], 'runner left its temporary socket/process directory')

    def test_readiness_timeout_reaps_only_its_owned_child(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);pid=root/'child.pid';fake=root/'slow-server'
            fake.write_text('#!/usr/bin/env python3\nimport os,time\nfrom pathlib import Path\nPath('+repr(str(pid))+').write_text(str(os.getpid()))\ntime.sleep(30)\n');fake.chmod(0o700)
            out=root/'result.json';scratch=root/'scratch';scratch.mkdir()
            p=self.cli('--redis-server',str(fake),'--mode','correctness','--output',str(out),'--scratch-root',str(scratch),'--timeout','0.2',timeout=10)
            self.assertNotEqual(p.returncode,0);self.assertTrue(pid.exists());child=int(pid.read_text())
            with self.assertRaises(ProcessLookupError):os.kill(child,0)
            self.assertEqual(list(scratch.iterdir()),[])
            self.assertNotIn('PASS',p.stdout)

    def test_invalid_preload_is_not_a_successful_baseline(self):
        server=shutil.which('redis-server');self.assertIsNotNone(server)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);lib=root/'bad.so';lib.write_text('not a dynamic library');scratch=root/'scratch';scratch.mkdir()
            p=self.cli('--redis-server',server,'--mode','correctness','--output',str(root/'result.json'),'--preload',str(lib),'--scratch-root',str(scratch),'--timeout','2',timeout=20)
            self.assertNotEqual(p.returncode,0);self.assertNotIn('PASS',p.stdout)
            self.assertEqual(list(scratch.iterdir()),[])

if __name__=='__main__':unittest.main(verbosity=2)

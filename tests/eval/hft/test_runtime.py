#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Executable semantic checks: real UDP producer and independent receiver."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent

SHIM=r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
static unsigned arrived;
static _Thread_local unsigned entered;
ssize_t pread(int fd,void *buffer,size_t n,off_t offset)
{
 ssize_t (*original)(int,void *,size_t,off_t)=dlsym(RTLD_NEXT,"pread");
 const char *fault=getenv("HFT_TEST_FAULT");
 if(fault && !strcmp(fault,"overlap") && !entered++) {
  pthread_mutex_lock(&lock);
  arrived++;
  if(arrived==4) {
   fputs("HFT_TEST_SIMULTANEOUS_READ_ACTORS=4\n",stderr);
   pthread_cond_broadcast(&condition);
  }
  while(arrived<4) pthread_cond_wait(&condition,&lock);
  pthread_mutex_unlock(&lock);
 }
 ssize_t result=original(fd,buffer,n,offset);
 if(fault && !strcmp(fault,"constant") && result>0) memset(buffer,0,(size_t)result);
 return result;
}
ssize_t sendmsg(int fd,const struct msghdr *msg,int flags)
{
 ssize_t (*original)(int,const struct msghdr *,int)=dlsym(RTLD_NEXT,"sendmsg");
 ssize_t result=original(fd,msg,flags);
 const char *fault=getenv("HFT_TEST_FAULT");
 return fault && !strcmp(fault,"short") && result>0 ? result-1:result;
}
'''


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='.runtime-test-',dir=HERE)
        cls.directory=Path(cls.temp.name)
        source=cls.directory/'shim.c';source.write_text(SHIM)
        cls.library=cls.directory/'shim.so'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-shared','-fPIC',str(source),'-o',str(cls.library),'-ldl','-pthread'],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    def invoke(self,fault,actors=1):
        env=dict(os.environ,LD_PRELOAD=str(self.library),HFT_TEST_FAULT=fault)
        return subprocess.run([sys.executable,str(HERE/'run.py'),'--backend','posix','--actors',str(actors),
            '--burst','3','--bursts','2','--depth','4'],env=env,text=True,capture_output=True,timeout=30)
    def test_full_producer_constant_payload_valid_crc_rejected(self):
        result=self.invoke('constant')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'')
        self.assertIn('payload bytes',result.stderr)
    def test_actual_short_datagram_result_is_error_not_positive_success(self):
        result=self.invoke('short')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'')
    def test_four_actors_reach_first_read_together_and_oracle_complete(self):
        # Each actual actor waits inside its first real pread until all four
        # have arrived, then performs the original syscall. A sequential
        # implementation deadlocks and fails this bounded acceptance.
        result=self.invoke('overlap',4)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['validated_packets'],24)
        self.assertIn('HFT_TEST_SIMULTANEOUS_READ_ACTORS=4',result.stderr)
        # The runner captures producer diagnostics; successful correctness
        # still has only the exact public result line.

class ProducerResultTests(unittest.TestCase):
    def test_actual_runner_rejects_native_stats_and_stop_mutations(self):
        import run as runner
        from test_contract import valid_record
        from test_oracle import PROFILE
        independent=valid_record(PROFILE,'session')
        raw={k:independent[k] for k in ('read_submissions','send_submissions','guards_ok',
            'local_release_complete','session_stats','stop_ret')}
        raw.update(read_cqes=0,send_result_cqes=0,send_notif_cqes=0,zc_copied_packets=0,registration_calls=0)
        validated={k:independent[k] for k in ('status','validated_packets','validated_bytes')}
        runner.checked_result(PROFILE,'session',raw,validated,independent['source_sha'])
        for key in raw['session_stats']:
            mutant=copy.deepcopy(raw)
            mutant['session_stats'][key]='UNKNOWN' if key=='state' else True
            with self.subTest(field=key),self.assertRaises(ValueError):
                runner.checked_result(PROFILE,'session',mutant,validated,independent['source_sha'])
        for value in (False,None,1,-11):
            mutant=copy.deepcopy(raw);mutant['stop_ret']=value
            with self.subTest(stop=value),self.assertRaises(ValueError):
                runner.checked_result(PROFILE,'session',mutant,validated,independent['source_sha'])

if __name__=='__main__': unittest.main()

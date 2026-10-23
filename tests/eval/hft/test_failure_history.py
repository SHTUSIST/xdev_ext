#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual producer and session teardown bodies: admission and failed-run evidence.

No device emulation or timing results. Only syscall/BPF-map dependencies at the
teardown boundary are controlled; the checked-in branch/loop runs unchanged.
"""
import json
import os
import socket
import threading
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def block(text, start):
    begin = text.index(start)
    brace = text.index('{', begin)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[begin:end]


class FailureHistoryTests(unittest.TestCase):
    def compile_run(self, source, extra=(), arguments=()):
        with tempfile.TemporaryDirectory(dir=HERE) as tmp:
            src, binary = Path(tmp) / 'body.c', Path(tmp) / 'body'
            src.write_text(source)
            build = subprocess.run([os.environ.get('CC', 'gcc'), '-std=gnu11', '-Wall', '-Wextra',
                '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-pthread', '-I', str(HERE),
                str(src), *map(str, extra), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            return subprocess.run([str(binary), *arguments], capture_output=True, text=True)

    def session_history(self, probe, result, mask, bad=-1, unsafe=0, started=1):
        text = (HERE / 'hft_session.c').read_text()
        body = block(text, 'if(!unsafe)')
        source = r'''
#include <stdio.h>
#include "hft_runtime.h"
struct bpf_map {int unused;};
static struct bpf_map map;
static unsigned mask, lookups;
static int bad;
static struct bpf_map *bpf_object__find_map_by_name(void *o,const char *n){(void)o;(void)n;return &map;}
static int bpf_map__fd(struct bpf_map *m){(void)m;return 1;}
static int bpf_map_lookup_elem(int fd,const unsigned *key,void *out){
 (void)fd;lookups++;struct hft_guard_record *r=out;memset(r,0,sizeof(*r));
 if(mask&(1U<<*key)){r->committed=1;r->generation=*key+1;r->frame_pos=*key%2;
 r->payload_bytes=512;r->slot_addr=(2+*key%2)*4096;r->raw_prefix[0]=0x11;}
 return (int)*key==bad?-1:0;
}
static void ctl_xsk_close(void *x){(void)x;}
static void bpf_link__destroy(void *x){(void)x;}
static void bpf_object__close(void *x){(void)x;}
static int close(int fd){(void)fd;return 0;}
int main(int argc,char **argv){
 (void)argc;mask=atoi(argv[3]);bad=atoi(argv[4]);
 struct hft_config config={.measured=1,.probe=atoi(argv[1]),.depth=2,.payload=512,.burst=2,.bursts=2};
 const struct hft_config *c=&config;struct hft_guard_record rows[4]={0};
 struct hft_actor actor={.c=c,.history=rows,.history_count=4},*a=&actor;
 void *obj=&map,*links[2]={0};struct {void *umem;}x={0};
 int ret=atoi(argv[2]),started=atoi(argv[6]),unsafe=atoi(argv[5]),guarded=0,ring=-1,efd=-1,ng=-1,block=-1;
''' + body + r'''
 printf("%d %u %u %u %u %u %u\n",ret,lookups,rows[0].committed,rows[1].committed,
 rows[2].committed,rows[3].committed,rows[0].raw_prefix[0]);return 0;}
'''
        result = self.compile_run(source, arguments=map(str, (probe, result, mask, bad, unsafe, started)))
        self.assertEqual(result.returncode, 0, result.stderr)
        return list(map(int, result.stdout.split()))

    def test_zero_start_probe_does_not_require_committed_workload_history(self):
        result = self.session_history(1, 0, 0)
        self.assertEqual(result[0], 0, 'zero-submission admission must succeed after STOP')
        self.assertEqual(result[1], 0, 'probe must not read nonexistent workload history')

    def test_failed_workload_retains_all_committed_generations_including_after_gaps(self):
        result = self.session_history(0, 1, 5)
        self.assertEqual(result, [1, 4, 1, 0, 1, 0, 0x11])

    def test_map_lookup_failure_does_not_hide_later_committed_records(self):
        result = self.session_history(0, 1, 5, bad=1)
        self.assertEqual(result, [1, 4, 1, 0, 1, 0, 0x11])

    def test_successful_workload_still_requires_all_records(self):
        self.assertEqual(self.session_history(0, 0, 15)[0], 0)
        self.assertEqual(self.session_history(0, 0, 5)[0], 1)

    def test_all_configured_slots_are_identified_before_sparse_workload(self):
        for backend in ('posix', 'uring', 'session'):
            text = (HERE / ('hft_' + backend + '.c')).read_text()
            if backend == 'posix':
                body = text[text.index(' for(;initialized<c->depth;initialized++)'):text.index(' /* All actors')]
            elif backend == 'uring':
                body = block(text, 'for(;allocated<c->depth;allocated++)')
            else:
                body = block(text, 'for(unsigned i=0;i<(c->measured?2*c->depth:64);i++)')
            source = r'''
#include <stdio.h>
#include <sys/uio.h>
#include "hft_runtime.h"
int main(void){
 struct hft_config config={.measured=1,.depth=2,.payload=512,.burst=1,.bursts=1};
 const struct hft_config *c=&config;struct hft_actor actor={.c=c},*a=&actor;
 struct hft_buffer slots[8]={0};struct iovec iov[8];unsigned initialized=0,allocated=0;
 struct {void *umem;}x={.umem=calloc(4,4096)};
''' + body + r'''
 (void)iov;
 printf("%llu %llu\n",(unsigned long long)a->frame_slots[0],(unsigned long long)a->frame_slots[1]);
 for(unsigned i=0;i<8;i++)free(slots[i].allocation);
 free(x.umem);return 0;}
'''
            with self.subTest(backend=backend):
                result = self.compile_run(source, extra=[HERE/'hft_posix.c'])
                self.assertEqual(result.returncode, 0, result.stderr)
                addresses = list(map(int, result.stdout.split()))
                self.assertTrue(all(addresses), 'unused configured slots must already have identity')
                self.assertEqual(len(set(addresses)), 2)

    def test_unknown_stop_and_prestart_refusal_do_not_read_native_map(self):
        self.assertEqual(self.session_history(0, 1, 15, unsafe=1), [1, 0, 0, 0, 0, 0, 0])
        self.assertEqual(self.session_history(0, 4, 0, started=0), [4, 0, 0, 0, 0, 0, 0])

    def test_actual_posix_peer_receipt_failure_keeps_completed_raw_history(self):
        source = r'''
#include <stdio.h>
#include "hft_runtime.h"
int main(int argc,char **argv){
 (void)argc;pthread_barrier_t barrier;_Atomic int startup_error=0;
 struct hft_config c={.measured=1,.depth=2,.payload=512,.burst=2,.bursts=2,
 .session_base=77,.peer_ip="127.0.0.1",.control_ip="127.0.0.1",.reference=argv[1],
 .peer_port=atoi(argv[2]),.control_port=atoi(argv[3])};
 struct hft_actor a={.c=&c,.barrier=&barrier,.startup_error=&startup_error};
 pthread_barrier_init(&barrier,NULL,1);int ret=hft_posix(&a);pthread_barrier_destroy(&barrier);
 printf("%d %u %u %u %u %u\n",ret,a.history[0].committed,a.history[1].committed,
 a.history[2].committed,a.history[3].committed,a.history[0].raw_prefix[0]);
 free(a.history);return 0;}
'''
        with tempfile.TemporaryDirectory(dir=HERE) as tmp, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
            path=Path(tmp)/'source';path.write_bytes(bytes(2048))
            data.bind(('127.0.0.1',0));control.bind(('127.0.0.1',0));control.settimeout(5)
            received=[]
            def reject_receipt():
                request,peer=control.recvfrom(2048);received.append(json.loads(request))
                control.sendto(b'{"status":"error"}',peer)
            peer=threading.Thread(target=reject_receipt);peer.start()
            result=self.compile_run(source,extra=[HERE/'hft_posix.c'],
                arguments=[str(path),str(data.getsockname()[1]),str(control.getsockname()[1])])
            peer.join(timeout=6)
            self.assertFalse(peer.is_alive())
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(list(map(int,result.stdout.split())),[1,1,1,0,0,0xa5])
            self.assertEqual(received[0]['first'],0)

    def test_actual_replay_failure_exports_only_completed_raw_records(self):
        source = r'''
#include "hft_runtime.h"
int hft_source_info(const char *p){(void)p;return 4;}
int hft_source_geometry(const struct hft_config *c){(void)c;return 0;}
int hft_session_gate(const struct hft_config *c){(void)c;return 0;}
int hft_posix(struct hft_actor *a){
 if(hft_history_setup(a))return 1;
 for(unsigned i=0;i<3;i+=2){struct hft_guard_record *r=&a->history[i];
 r->committed=1;r->generation=i+1;r->frame_pos=i%a->c->depth;r->payload_bytes=a->c->payload;
 r->slot_addr=4096;r->raw_prefix[0]=0x11;}
 return 1;
}
int hft_uring(struct hft_actor *a){return hft_posix(a);}
int hft_session(struct hft_actor *a){return hft_posix(a);}
'''
        for backend in ('posix', 'uring-fixed-zc', 'session'):
            args = [backend,'unused','64','512','2','2','2','1','1','192.0.2.2','1000',
                    '192.0.2.1','1001','source','ng','0','4096','eth0','0','192.0.2.1',
                    '02:00:00:00:00:01','02:00:00:00:00:02','1002','obj','config','0','hardware','77','0']
            with self.subTest(backend=backend):
                result = self.compile_run(source, extra=[HERE/'hft_replay.c'], arguments=args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '', 'failed execution cannot publish performance')
                records = [json.loads(line) for line in result.stderr.splitlines()]
                history = [r for r in records if 'guard_history' in r]
                self.assertEqual(len(history), 1, 'committed raw evidence was lost on failure')
                self.assertIs(history[0]['local_release_complete'], False)
                self.assertEqual([r['generation'] for r in history[0]['guard_history']], [1, 3])
                self.assertTrue(all(r['raw_prefix'].startswith('11') for r in history[0]['guard_history']))
                self.assertTrue(all('io_ns' not in r for r in records))


if __name__ == '__main__':
    unittest.main()

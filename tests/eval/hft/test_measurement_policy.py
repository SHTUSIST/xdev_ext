#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Strict HFT measurement contracts; user-space hooks, no device or timing run."""
import io
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

import hardware_measure as hardware
import hardware_gate as gate
from strict_fixture import PROFILE, IDENTITY, POLICY, changed, expected_header, packet

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def body(source, marker):
    """Extract a real checked-in C body, retaining every statement in it."""
    start = source.index(marker)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == '{': depth += 1
        elif source[end] == '}': depth -= 1
        end += 1
    return source[start:end]


class Condition:
    def __enter__(self): return self
    def __exit__(self, *unused): return False
    def notify_all(self): pass
    def wait(self, *unused): raise ValueError('fixture has no missing-data wait')


def legacy_probe():
    """Execute actual PeerRun methods; input iterator is not a network provider."""
    from test_oracle import packet as nxp_packet
    p = dict(PROFILE, bursts=1)
    packets = [nxp_packet(p, 0, g) for g in range(2)]
    events = []
    original = hardware.oracle.Validator
    class ObservedValidator(original):
        def add(self, data):
            events.append('full_oracle')
            return super().add(data)
    state = hardware.PeerRun.__new__(hardware.PeerRun)
    state.p, state.first, state.identity = p, 1, IDENTITY
    state.validator, state.condition = ObservedValidator(p), Condition()
    state.stop, state.error = threading.Event(), None
    state.output, state.capture_bytes = io.BytesIO(), 0
    class Input:
        def __init__(self): self.rows = iter(packets)
        def recvmsg(self, *unused):
            try: return next(self.rows), [], 0, ('fixture', 0)
            except StopIteration:
                state.stop.set()
                raise socket.timeout()
    state.udp = Input()
    state.receive()
    if state.error: raise state.error
    with patch.object(hardware, 'time', types.SimpleNamespace(monotonic=lambda: 0)):
        reply = state.burst(dict(version=1, op='BURST', identity=IDENTITY,
            actor=0, first_generation=1, packet_count=2))
    return events, reply, state.output.getvalue(), packets


class MeasurementPolicyTests(unittest.TestCase):
    def capture_class(self):
        cls = getattr(hardware, 'BenchmarkCapture', None)
        self.assertTrue(callable(cls), 'FEATURE_ABSENT RED: header-only RAM BenchmarkCapture absent')
        return cls

    def capture(self, observer=None, capacity=None):
        count = PROFILE['burst_packets'] * PROFILE['bursts']
        return self.capture_class()(dict(PROFILE), dict(IDENTITY),
            count * (PROFILE['payload_bytes'] + 40) if capacity is None else capacity,
            observer=observer)

    def compile_run(self, source):
        with tempfile.TemporaryDirectory(prefix='.strict-c-body-', dir=HERE) as directory:
            src = Path(directory) / 'probe.c'
            binary = Path(directory) / 'probe'
            src.write_text(source)
            result = subprocess.run(['cc', '-std=c11', '-D_GNU_SOURCE', '-O0', '-Wall',
                '-I' + str(HERE), '-I' + str(ROOT / 'kernel/tools/xdev_ext_mech'),
                str(src), '-o', str(binary), '-pthread'], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, 'actual C-body hook must compile:\n' + result.stderr)
            result = subprocess.run([str(binary)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, 'actual C-body hook failed:\n' + result.stderr)
            return result.stdout.splitlines()

    def test_actual_receiver_defers_oracle_until_campaign_complete(self):
        if not hasattr(hardware, 'BenchmarkCapture'):
            events, _, _, _ = legacy_probe()
            self.assertEqual(events, [], 'EXISTING_BODY RED: actual PeerRun runs full oracle before receipt')
            return
        capture = self.capture()
        with patch.object(hardware.oracle, 'Validator', side_effect=AssertionError('online full oracle')), \
             patch.object(hardware.oracle, 'crc32c', side_effect=AssertionError('online CRC')), \
             patch('hashlib.sha256', side_effect=AssertionError('online SHA')):
            for g in range(1, 3): capture.capture_receive(packet(PROFILE, g))
            reply = capture.received_receipt(1, 2, IDENTITY)
        self.assertEqual(reply['status'], 'received')

    def test_actual_receipt_does_not_claim_payload_validated(self):
        if not hasattr(hardware, 'BenchmarkCapture'):
            _, reply, _, _ = legacy_probe()
        else:
            capture = self.capture()
            for g in range(1, 3): capture.capture_receive(packet(PROFILE, g))
            reply = capture.received_receipt(1, 2, IDENTITY)
        self.assertFalse(any(key.startswith('validated_') for key in reply),
                         'EXISTING_BODY RED: receipt falsely declares full validation in active path')
        self.assertEqual(reply['version'], 2)
        self.assertEqual(reply['status'], 'received')
        self.assertEqual(reply['received_packets'], 2)
        self.assertEqual(reply['received_bytes'], 1024)

    def test_old_probe_positive_control_full_capture_bytes(self):
        _, reply, actual, packets = legacy_probe()
        self.assertEqual(actual, b''.join(struct.pack('!I', len(row)) + row for row in packets))
        self.assertEqual(reply['packet_count'], 2)

    def test_ram_capture_copies_complete_bytes_before_commit_and_receipt(self):
        events = []
        capture = self.capture(observer=lambda event, metadata: events.append(event))
        expected = [packet(PROFILE, 2), packet(PROFILE, 1)]
        for data in expected:
            mutable = bytearray(data)
            capture.capture_receive(mutable)
            mutable[-1] ^= 1
        self.assertEqual(capture.packets, expected)
        self.assertTrue(all(type(value) is bytes for value in capture.packets))
        receipt = capture.received_receipt(1, 2, IDENTITY)
        self.assertEqual(receipt['received_bytes'], 1024)
        self.assertEqual(events, ['capture_commit', 'capture_commit', 'received_receipt'])

    def test_bad_payload_tail_is_received_online_and_kept_for_final_oracle(self):
        capture = self.capture()
        bad = changed(packet(PROFILE, 1), -1)
        capture.capture_receive(bad)
        capture.capture_receive(packet(PROFILE, 2))
        self.assertEqual(capture.received_receipt(1, 2, IDENTITY)['status'], 'received')
        self.assertEqual(capture.packets[0], bad)

    def test_capacity_is_reserved_before_any_start_or_ready(self):
        required = 4 * (512 + 40)
        cls = self.capture_class()
        for capacity in (0, required - 1):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                cls(dict(PROFILE), dict(IDENTITY), capacity)
        self.capture(capacity=required)

    def test_missing_and_foreign_receipt_refused(self):
        capture = self.capture()
        capture.capture_receive(packet(PROFILE, 1))
        with self.assertRaises(ValueError): capture.received_receipt(1, 2, IDENTITY)
        capture.capture_receive(packet(PROFILE, 2))
        for field, value in [('token', 'old-run'), ('session_base', PROFILE['session_base'] + 1)]:
            identity = dict(IDENTITY); identity[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                capture.received_receipt(1, 2, identity)

    def test_every_header_field_duplicate_stale_foreign_extra_truncation_poison_receipt(self):
        self.capture_class()
        good = packet(PROFILE, 1)
        mutants = [(changed(good, i), False) for i in range(40)]
        mutants += [(good[:-1], False), (good + b'\0', False), (good, True),
                    (expected_header(PROFILE['session_base'], 0, 512) + good[40:], False),
                    (expected_header(PROFILE['session_base'], 5, 512) + good[40:], False)]
        for index, (bad, truncated) in enumerate(mutants):
            capture = self.capture()
            with self.subTest(mutant=index), self.assertRaises(ValueError):
                capture.capture_receive(bad, truncation=truncated)
            with self.assertRaises(ValueError): capture.received_receipt(1, 2, IDENTITY)
        capture = self.capture(); capture.capture_receive(good)
        with self.assertRaises(ValueError): capture.capture_receive(good)
        with self.assertRaises(ValueError): capture.received_receipt(1, 2, IDENTITY)

    def test_explicit_selector_has_no_fallback_to_production_nxp(self):
        select = getattr(hardware, 'select_measurement_policy', None)
        self.assertTrue(callable(select), 'FEATURE_ABSENT RED: strict measured policy selector absent')
        selected = select(POLICY)
        self.assertEqual(selected['measurement_policy'], POLICY)
        self.assertEqual(selected['wire_version'], 1)
        self.assertEqual(selected['map_names'], ['hftb_nvme_ops', 'hftb_afxdp_ops'])
        self.assertEqual(Path(selected['bpf_source']).name, 'hft_benchmark.bpf.c')
        for wrong in ('', 'NXP2', 'benchmark-policy-v2'):
            with self.subTest(policy=wrong), self.assertRaises(ValueError): select(wrong)

    def test_physical_entry_refuses_without_policy_hardware_and_emits_no_performance(self):
        result = subprocess.run([sys.executable, '-B', str(HERE / 'hardware_measure.py'),
            'measure', '--measurement-policy', POLICY], text=True, capture_output=True)
        self.assertEqual(result.returncode, 4, 'FEATURE_ABSENT RED: strict selector/refusal must exit4, not argparse exit2')
        self.assertEqual(result.stdout, '')
        self.assertIn('"start_issued": false', result.stderr)
        for forbidden in ('ratio_posix', 'total_completion_ns', '"status": "ok"'):
            self.assertNotIn(forbidden, result.stderr)

    def test_real_measured_encoder_body_uses_checksum_free_hft1(self):
        source = (HERE / 'hft_posix.c').read_text()
        actual = body(source, 'int hft_encode(')
        optional = '#include "benchmark_policy.h"\n' if (HERE / 'benchmark_policy.h').exists() else ''
        lines = self.compile_run('''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_xdp.h>
#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"
#include "hft_runtime.h"
#include "xdev_ext_mech_prog.h"
''' + optional + '''
static unsigned checksum_calls;
static uint32_t crc32c(uint32_t crc,const unsigned char *p,size_t n)
{(void)p;(void)n;checksum_calls++;return crc;}
''' + actual + '''
int main(void) {
 unsigned char memory[4096];memset(memory,0x6d,sizeof(memory));
 struct hft_config config={.payload=512,.session_base=0x1020304050607080ULL,.measured=1};
 struct hft_actor actor={.c=&config};struct hft_buffer buffer={.allocation=memory,.payload=memory+512};
 int result=hft_encode(&buffer,&actor,0);
 printf("%d %u\\n",result,checksum_calls);
 for(unsigned i=472;i<1024;i++)printf("%02x",memory[i]);puts("");return 0;
}
''')
        self.assertEqual(lines[0], '0 0', 'EXISTING_BODY RED: real measured encoder still calculates transfer CRC')
        self.assertEqual(bytes.fromhex(lines[1]), expected_header(PROFILE['session_base'], 1, 512) + b'\x6d' * 512)

    def test_independent_c_encoder_exact_all_fields_and_canaries(self):
        self.assertTrue((HERE / 'benchmark_policy.h').is_file(), 'FEATURE_ABSENT RED: independent HFT1 encoder absent')
        lines = self.compile_run('''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "benchmark_policy.h"
int main(void) {
 unsigned char memory[42];memset(memory,0x6d,sizeof(memory));
 int result=hftb_encode_header(memory+1,0x1020304050607080ULL,0x11223344,1024);
 printf("%d\\n",result);for(unsigned i=0;i<42;i++)printf("%02x",memory[i]);puts("");
 printf("%d %d %d %d\\n",hftb_encode_header(memory+1,0,1,512),
 hftb_encode_header(memory+1,1,0,512),hftb_encode_header(memory+1,1,1,513),hftb_encode_header(memory+1,1,1,4096));
 return 0;
}
''')
        self.assertEqual(lines[0], '0')
        self.assertEqual(bytes.fromhex(lines[1]), b'\x6d' + expected_header(PROFILE['session_base'], 0x11223344, 1024) + b'\x6d')
        self.assertTrue(all(int(value) < 0 for value in lines[2].split()))

    def test_actual_native_burst_body_starts_timer_before_notify_arm(self):
        source = (HERE / 'hft_session.c').read_text()
        loop = body(source, 'for(unsigned b=0;b<c->bursts;b++)')
        stats_ok = body(source, 'static int stats_ok(')
        lines = self.compile_run('''
#include <stdint.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"
#include "hft_runtime.h"
static int mech(int fd,unsigned op,uintptr_t argument) {
 (void)fd;
 if(op==XDEV_EXT_MECH_OP_NOTIFY_ARM)puts("arm");
 else if(op==XDEV_EXT_MECH_OP_START)puts("start");
 else if(op==XDEV_EXT_MECH_OP_STATS) {
  struct xdev_ext_mech_stats *s=(void *)argument;puts("stats");
  s->state=XDEV_EXT_MECH_SESSION_ACTIVE;s->batches_done=2;
  s->submitted[0]=s->submitted[1]=s->completed[0]=s->completed[1]=2;
 } else return -1;return 0;
}
static int fixture_poll(struct pollfd *p,nfds_t count,int timeout)
{(void)count;(void)timeout;p->revents=POLLIN;puts("completion");return 1;}
static ssize_t fixture_read(int fd,void *out,size_t size)
{(void)fd;*(uint64_t *)out=1;return (ssize_t)size;}
void hft_burst_begin(struct hft_actor *a,unsigned b){(void)a;(void)b;puts("begin");}
void hft_burst_release(struct hft_actor *a,unsigned b){(void)a;(void)b;puts("release");}
void hft_burst_done(struct hft_actor *a,unsigned b){(void)a;(void)b;puts("done");}
int hft_receipt(int fd,const struct hft_actor *a,unsigned b)
{(void)fd;(void)a;(void)b;puts("receipt");return 0;}
#define poll fixture_poll
#define read fixture_read
''' + stats_ok + '''
int main(void) {
 struct hft_config config={.payload=512,.burst=2,.bursts=1,.measured=1};
 const struct hft_config *c=&config;struct hft_actor actor={.c=c},*a=&actor;
 struct xdev_ext_mech_create create={.session_id=77};
 struct xdev_ext_mech_stats stats={0};int ring=1,efd=2,ctl=3,started=0;
''' + loop + '''
 return started?0:1;
 out:return 1;
}
''')
        self.assertEqual(sorted(lines), sorted(['begin', 'arm', 'start', 'completion', 'stats', 'release', 'receipt', 'done']))
        for first, later in [('begin', 'arm'), ('arm', 'start'), ('start', 'completion'),
                ('completion', 'stats'), ('stats', 'release'), ('release', 'receipt'), ('receipt', 'done')]:
            self.assertLess(lines.index(first), lines.index(later),
                'EXISTING_BODY RED: actual native burst event order ' + repr(lines))

    def test_actual_send_zc_body_retains_slot_until_late_notification(self):
        lines = self.compile_run('''
#define HFT_HAVE_URING
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../kernel/include/uapi/linux/io_uring.h"
#include "hft_runtime.h"
#include "hft_send_zc.h"
int main(void) {
 struct hft_slot slot;struct hft_counts counts={0};struct io_uring_cqe cqe={0};
 hft_slot_init(&slot,0);if(hft_slot_read_begin(&slot,10))return 1;
 if(hft_slot_read_complete(&slot,10,512,512)||hft_slot_send_begin(&slot,11,552))return 1;
 cqe.user_data=11;cqe.res=552;cqe.flags=IORING_CQE_F_MORE;
 if(wait_zc_cqes(&slot,&cqe,&counts))return 1;
 printf("before-notif %d\\n",hft_slot_reusable(&slot));
 cqe.res=0;cqe.flags=IORING_CQE_F_NOTIF;
 if(wait_zc_cqes(&slot,&cqe,&counts))return 1;
 printf("after-notif %d\\n",hft_slot_reusable(&slot));
 hft_slot_init(&slot,0);if(hft_slot_read_begin(&slot,20))return 1;
 if(hft_slot_read_complete(&slot,20,512,512)||hft_slot_send_begin(&slot,21,552))return 1;
 cqe.user_data=21;cqe.res=551;cqe.flags=IORING_CQE_F_MORE;
 printf("short-result %d\\n",wait_zc_cqes(&slot,&cqe,&counts));
 printf("short-reusable %d\\n",hft_slot_reusable(&slot));return 0;
}
''')
        self.assertEqual(lines[:2], ['before-notif 0', 'after-notif 1'])
        self.assertLess(int(lines[2].split()[1]), 0)
        self.assertEqual(lines[3], 'short-reusable 0')

    def test_actual_posix_body_keeps_reads_and_receive_in_timer_but_not_guard_comparison(self):
        actual = body((HERE / 'hft_posix.c').read_text(), 'int hft_posix(')
        lines = self.compile_run('''
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "hft_runtime.h"
static unsigned active,guard_comparisons,read_calls,send_calls,receipts;
void hft_setup_begin(struct hft_actor *a){(void)a;}
void hft_setup_done(struct hft_actor *a){(void)a;}
void hft_teardown_begin(struct hft_actor *a){(void)a;}
void hft_teardown_done(struct hft_actor *a){(void)a;}
void hft_burst_begin(struct hft_actor *a,unsigned b){(void)a;(void)b;active=1;}
void hft_burst_release(struct hft_actor *a,unsigned b){(void)a;(void)b;}
void hft_burst_done(struct hft_actor *a,unsigned b){(void)a;(void)b;active=0;}
int hft_allocate(struct hft_buffer *b,unsigned index,unsigned size) {
 b->allocation=malloc(4096);if(!b->allocation)return -1;
 b->payload=b->allocation+512;b->bytes=4096;hft_slot_init(&b->life,index);(void)size;return 0;
}
int hft_buffer_ok(const struct hft_buffer *b,unsigned size)
{(void)b;(void)size;if(active)guard_comparisons++;return 1;}
int hft_encode(struct hft_buffer *b,const struct hft_actor *a,unsigned group)
{(void)b;(void)a;(void)group;return 0;}
int hft_connect(const char *ip,unsigned port){(void)ip;(void)port;return 8;}
int hft_data_connect(const struct hft_config *c){(void)c;return 9;}
int hft_receipt(int fd,const struct hft_actor *a,unsigned first)
{(void)fd;(void)a;(void)first;if(!active)return -1;receipts++;return 0;}
static int fixture_open(const char *path,int flags){(void)path;(void)flags;return 7;}
static int fixture_close(int fd){(void)fd;return 0;}
static int fixture_barrier(pthread_barrier_t *barrier){(void)barrier;return 0;}
static ssize_t fixture_pread(int fd,void *buffer,size_t size,off_t offset)
{(void)fd;(void)offset;if(!active)return -1;memset(buffer,7,size);read_calls++;return (ssize_t)size;}
static ssize_t fixture_sendmsg(int fd,const struct msghdr *msg,int flags)
{(void)fd;(void)flags;if(!active)return -1;size_t n=0;for(size_t i=0;i<msg->msg_iovlen;i++)n+=msg->msg_iov[i].iov_len;send_calls++;return (ssize_t)n;}
#define open fixture_open
#define close fixture_close
#define pread fixture_pread
#define sendmsg fixture_sendmsg
#define pthread_barrier_wait fixture_barrier
''' + actual + '''
int main(void) {
 struct hft_config config={.payload=512,.depth=2,.burst=2,.bursts=1,.measured=1};
 _Atomic int error=0;struct hft_actor actor={.c=&config,.startup_error=&error};
 int result=hft_posix(&actor);
 printf("%d %u %u %u %u\\n",result,read_calls,send_calls,receipts,guard_comparisons);return 0;
}
''')
        self.assertEqual(lines, ['0 2 2 1 0'],
            'EXISTING_BODY RED: extra full guard comparisons run inside the real POSIX burst')

    def test_actual_source_admission_full_readback_does_not_hash_each_read(self):
        from strict_fixture import expected_payload
        p = dict(PROFILE)
        source = b''.join(expected_payload(p, g) for g in range(4))
        events = []
        class DigestObserver:
            def update(self, data): events.append(('digest-update', len(data)))
            def hexdigest(self): return 'a' * 64
        class AdmissionPath:
            # Isolated file metadata/readback dependencies, not a provider/device.
            def __init__(self, path): self.path = str(path)
            def __truediv__(self, part): return AdmissionPath(self.path + '/' + part)
            def __str__(self): return self.path
            @property
            def name(self): return self.path.rsplit('/', 1)[-1]
            def resolve(self): return '/pci/fixture-namespace' if self.path.startswith('/sys/') else self.path
            def exists(self): return True
            def is_file(self): return self.path == '/fixture-reference'
            def stat(self):
                kind = stat.S_IFBLK if self.path == '/fixture-block' else stat.S_IFCHR
                if self.path == '/fixture-reference': kind = stat.S_IFREG
                return types.SimpleNamespace(st_mode=kind | 0o400, st_dev=1, st_ino=2,
                                             st_size=len(source), st_mtime_ns=3)
            def open(self, *args, **kwargs): return io.BytesIO(source)
        args = types.SimpleNamespace(source_block='/fixture-block', source_ng='/fixture-ng',
            reference='/fixture-reference', slba=0, nlb=4, measurement_policy=POLICY)
        geometry = dict(lba_bytes=512, capacity_bytes=4096, dio_mem_align=512, dio_offset_align=512)
        with patch.object(gate, 'Path', AdmissionPath), \
             patch.object(gate, 'command', return_value=__import__('json').dumps(geometry)), \
             patch('hashlib.sha256', side_effect=lambda *args, **kwargs: DigestObserver()):
            result = gate.source(args, p)
        self.assertTrue(result['read_only'])
        self.assertEqual(result['groups'], 4)
        success_updates = list(events)
        source = changed(source, -1)
        with patch.object(gate, 'Path', AdmissionPath), \
             patch.object(gate, 'command', return_value=__import__('json').dumps(geometry)), \
             patch('hashlib.sha256', side_effect=lambda *args, **kwargs: DigestObserver()), \
             self.assertRaises(hardware.correctness.Failure):
            gate.source(args, p)
        self.assertEqual(success_updates, [], 'EXISTING_BODY RED: source admission performs per-read SHA updates')


if __name__ == '__main__':
    unittest.main()

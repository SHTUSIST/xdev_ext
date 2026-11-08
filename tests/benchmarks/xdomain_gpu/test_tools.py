#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""E4 baseline tools on one host, without a GPU, NCCL or Thunderbolt link.

tcp_cuda runs both ranks over loopback TCP with --fake-gpu (host memory in
place of VRAM): the protocol, the timing loop and the verification are
exercised; the numbers are not a result (execution host-fake,
performance_claim none).  nccl_pingpong and xdomain_gpu are checked for
their options, their dry runs and their refusal without the libraries or
devices they need.
"""
import ctypes.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CC = os.environ.get('CC', 'cc')
BUILD = tempfile.TemporaryDirectory(prefix='xdg-tools-')


def libbpf_ok():
    return not subprocess.run(['pkg-config', '--atleast-version=1.0', 'libbpf'],
                              capture_output=True).returncode


def build(target):
    r = subprocess.run(['make', '-s', '-C', str(HERE), f'BUILD={BUILD.name}',
                        f'{BUILD.name}/{target}'], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)
    return Path(BUILD.name) / target


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def lines(text):
    return [json.loads(l) for l in text.splitlines() if l.startswith('{')]


class TcpCuda(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin = build('tcp_cuda')

    def pair(self, mode, extra0=(), extra1=(), sizes='64,4096,262144'):
        port = free_port()
        common = ['--mode', mode, '--sizes', sizes, '--fake-gpu', '--iters', '20',
                  '--warmup', '3', '--stream-messages', '40', '--window', '4']
        r1 = subprocess.Popen([str(self.bin), '--rank', '1', '--listen', f'127.0.0.1:{port}',
                               *common, *extra1], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
        r0 = subprocess.run([str(self.bin), '--rank', '0', '--peer', f'127.0.0.1:{port}',
                             *common, *extra0], capture_output=True, text=True, timeout=60)
        out1, err1 = r1.communicate(timeout=60)
        return r0, (r1.returncode, out1, err1)

    def test_pingpong_round_trips_verify_on_both_ranks(self):
        r0, (code1, out1, err1) = self.pair('pingpong')
        self.assertEqual(r0.returncode, 0, r0.stderr)
        self.assertEqual(code1, 0, err1)
        recs = lines(r0.stdout)
        self.assertEqual([r['size'] for r in recs], [64, 4096, 262144])
        for r in recs:
            self.assertEqual(r['arm'], 'tcp-cudamemcpy')
            self.assertEqual(r['mode'], 'pingpong')
            self.assertEqual(r['rtt_ns']['n'], 20)
            self.assertEqual(r['half_rtt_ns_median'], r['rtt_ns']['median'] // 2)
            self.assertIs(r['verified'], True)
            self.assertIs(r['peer_verified'], True)
            self.assertEqual(r['execution'], 'host-fake')
            self.assertEqual(r['performance_claim'], 'none')
            self.assertIs(r['tcp_nodelay'], True)
            self.assertEqual(r['clock'], 'CLOCK_MONOTONIC rank 0')

    def test_stream_is_timed_and_verified_at_the_receiver(self):
        r0, (code1, out1, err1) = self.pair('stream')
        self.assertEqual(r0.returncode, 0, r0.stderr)
        self.assertEqual(code1, 0, err1)
        recv = lines(out1)
        self.assertEqual(len(recv), 3)
        for r in recv:
            self.assertEqual(r['mode'], 'stream')
            self.assertEqual(r['role'], 'receiver')
            self.assertEqual(r['messages'], 40)
            self.assertEqual(r['verified_bytes'], 40 * r['size'])
            self.assertIs(r['verified'], True)
            self.assertGreater(r['elapsed_ns'], 0)
            self.assertIn('gbps', r)

    def test_nodelay_off_is_recorded(self):
        r0, (code1, _, err1) = self.pair('pingpong', extra0=['--no-nodelay'],
                                         extra1=['--no-nodelay'], sizes='4096')
        self.assertEqual(r0.returncode, 0, r0.stderr)
        self.assertIs(lines(r0.stdout)[0]['tcp_nodelay'], False)

    def test_ranks_with_different_settings_refuse_to_run(self):
        r0, (code1, _, _) = self.pair('pingpong', extra0=['--seed', '9'], sizes='4096')
        self.assertNotEqual(r0.returncode, 0)
        self.assertNotEqual(code1, 0)

    def test_usage_errors(self):
        for argv in ([], ['--rank', '2', '--peer', 'h:1'], ['--rank', '0'],
                     ['--rank', '0', '--peer', 'h:1', '--sizes', '100'],
                     ['--rank', '0', '--peer', 'h:1', '--mode', 'bogus']):
            with self.subTest(argv=argv):
                r = subprocess.run([str(self.bin), *argv], capture_output=True, text=True)
                self.assertEqual(r.returncode, 2, r.stderr)

    @unittest.skipIf(ctypes.util.find_library('cuda'), 'a CUDA driver is installed here')
    def test_without_a_cuda_driver_it_is_unavailable(self):
        r = subprocess.run([str(self.bin), '--rank', '0', '--peer', '127.0.0.1:9',
                            '--sizes', '4096'], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 4, r.stderr)


class NcclPingpong(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin = build('nccl_pingpong')

    def test_dry_run_prints_the_plan(self):
        r = subprocess.run([str(self.bin), '--rank', '0', '--peer', '127.0.0.1:9', '--sizes',
                            '64,4096', '--dry-run'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        plan = json.loads(r.stdout)
        self.assertEqual(plan['arm'], 'nccl-sendrecv')
        self.assertEqual(plan['sizes'], [64, 4096])
        self.assertIs(plan['dry_run'], True)

    def test_usage_errors(self):
        for argv in ([], ['--rank', '0'], ['--rank', '1', '--peer', 'h:1'],
                     ['--rank', '0', '--peer', 'h:1', '--iters', '0']):
            with self.subTest(argv=argv):
                r = subprocess.run([str(self.bin), *argv], capture_output=True, text=True)
                self.assertEqual(r.returncode, 2, r.stderr)

    @unittest.skipIf(ctypes.util.find_library('nccl'), 'NCCL is installed here')
    def test_without_nccl_it_is_unavailable(self):
        r = subprocess.run([str(self.bin), '--rank', '0', '--peer', '127.0.0.1:9',
                            '--sizes', '4096'], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 4, r.stderr)


XD_BIN = os.environ.get('XDOMAIN_GPU_BIN')
XD_COMMON = ['--gpu-bdf', '0000:01:00.0', '--ce-dev', '/dev/nvidia0', '--link-token', '7']


@unittest.skipUnless(XD_BIN or libbpf_ok(), 'needs libbpf >= 1.0 (or XDOMAIN_GPU_BIN)')
class XdomainGpu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin = Path(XD_BIN) if XD_BIN else build('xdomain_gpu')

    def plan(self, *extra):
        r = subprocess.run([str(self.bin), '--rank', '0', '--peer', '127.0.0.1:9', *XD_COMMON,
                            '--dry-run', *extra], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return {p['size']: p for p in lines(r.stdout)}

    def test_pingpong_plan_one_message_per_start(self):
        p = self.plan('--sizes', '64,4096,262144,4194304')
        # Below 256 KiB a message is one group: one batch, depth and window 1.
        self.assertEqual((p[64]['group_bytes'], p[64]['groups_per_message'], p[64]['depth']),
                         (64, 1, 1))
        self.assertEqual(p[64]['frames_per_group'], 1)
        self.assertEqual(p[262144]['frames_per_group'], 64)
        # 4 MiB is 16 groups of 256 KiB (64 NHI frames of 4 KiB per batch).
        big = p[4194304]
        self.assertEqual((big['group_bytes'], big['groups_per_message'], big['depth'],
                          big['window'], big['batches_per_start']), (262144, 16, 16, 16, 16))
        self.assertEqual(big['ring_frames'], 16 * 64)
        self.assertEqual(big['vram_window_bytes'], 4194304)

    def test_stream_plan_keeps_the_window_in_flight(self):
        p = self.plan('--mode', 'stream', '--sizes', '4096,4194304', '--stream-messages', '100')
        self.assertEqual((p[4096]['depth'], p[4096]['window']), (32, 32))
        self.assertEqual(p[4096]['batches_per_start'], 100)
        self.assertEqual(p[4194304]['batches_per_start'], 1600)
        self.assertEqual(p[4194304]['vram_window_bytes'], 32 * 262144)
        # Fewer messages than slots would leave RX slots unwritten: raised to fill them.
        q = self.plan('--mode', 'stream', '--sizes', '4096', '--stream-messages', '3')
        self.assertEqual(q[4096]['batches_per_start'], 32)

    def test_usage_errors(self):
        for argv in ([], ['--rank', '0', '--peer', 'h:1'],
                     ['--rank', '0', '--peer', 'h:1', '--gpu-bdf', 'b', '--ce-dev', 'c'],
                     ['--rank', '0', '--peer', 'h:1', *XD_COMMON, '--service', 'x'],
                     ['--rank', '0', '--peer', 'h:1', *XD_COMMON, '--window', '33'],
                     ['--rank', '1', '--peer', 'h:1', *XD_COMMON]):
            with self.subTest(argv=argv):
                r = subprocess.run([str(self.bin), *argv], capture_output=True, text=True)
                self.assertEqual(r.returncode, 2, r.stderr)

    @unittest.skipIf(os.path.exists('/dev/xdev_ext_peer'), 'this host runs the xdev_ext kernel')
    def test_without_the_kernel_it_is_unavailable(self):
        r = subprocess.run([str(self.bin), '--rank', '0', '--peer', '127.0.0.1:9', *XD_COMMON,
                            '--sizes', '4096'], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn('/dev/xdev_ext_peer', r.stderr)


if __name__ == '__main__':
    unittest.main()

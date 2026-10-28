#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests of the reliable-random QEMU cable (E17: loss, reorder, slow receiver).

Real NXP v3 Ethernet bytes from an independent fixture builder. The injector
is the production class; the end-to-end case runs the production proxy main()
over two AF_UNIX QEMU stream sockets. No root, guest, BPF or network access.
Timing here only checks that the delay is applied; it is not a measurement.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
WIRE = Path(os.environ.get('RELIABLE_WIRE', str(HERE / 'xdev_ext_mech_zc_wire.py')))
SESSION = 270019


def load():
    spec = importlib.util.spec_from_file_location('random_wire', WIRE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def crc32c(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff


def ip_checksum(data):
    value = sum(struct.unpack('!10H', data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return ~value & 0xffff


def frame(kind=1, group=1, index=0, attempt=1, session=SESSION, seg=64, count=4, credit=5):
    """Independent v3 builder: DATA left->right, ACK(2)/HELD(3) right->left."""
    data = kind == 1
    payload = bytes((group * 13 + index * 29 + i) & 255 for i in range(seg if data else 0))
    hdr = bytearray(64)
    struct.pack_into('!IBBBBQQIIHHIIIQII', hdr, 0, 0x4e585033, 3, 64, kind, 0, session, group,
                     attempt, seg * count if data else 0, index if data else 0,
                     count if data else 0, index * seg if data else 0, len(payload), 0,
                     0 if data else credit, 0, 0)
    struct.pack_into('!I', hdr, 56, crc32c(hdr + payload))
    left_mac, right_mac = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    left_ip, right_ip = socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2')
    src_mac, dst_mac = (left_mac, right_mac) if data else (right_mac, left_mac)
    src_ip, dst_ip = (left_ip, right_ip) if data else (right_ip, left_ip)
    ports = (54321, 12345) if data else (12345, 54321)
    udp = struct.pack('!HHHH', *ports, 8 + len(hdr) + len(payload), 0)
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp) + len(hdr) + len(payload),
                               0, 0, 64, 17, 0, src_ip, dst_ip))
    struct.pack_into('!H', ip, 10, ip_checksum(ip))
    return dst_mac + src_mac + b'\x08\x00' + bytes(ip) + udp + bytes(hdr) + payload


def flow(groups=40):
    out = []
    for group in range(1, groups + 1):
        out += [frame(1, group, index) for index in range(4)]
        out += [frame(3, group), frame(2, group)]
    return out


class RandomInjector(unittest.TestCase):
    def setUp(self):
        self.wire = load()

    def make(self, **kw):
        try:
            return self.wire.FaultInjector('reliable-random', **kw)
        except (TypeError, ValueError) as error:
            self.fail(f'production cable lacks reliable-random: {error}')

    def test_parameters_are_validated(self):
        self.make()
        for kw in (dict(loss=1.0), dict(loss=-0.1), dict(reorder=1.5), dict(slow_receiver_us=-1),
                   dict(seed=-1)):
            with self.subTest(**kw), self.assertRaises(ValueError):
                self.wire.FaultInjector('reliable-random', **kw)
        for fault in ('none', 'reliable-drop-data'):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.wire.FaultInjector(fault, loss=0.1)

    def test_fixture_is_a_valid_v3_frame(self):
        for kind in (1, 2, 3):
            with self.subTest(kind=kind):
                self.assertIsNotNone(self.wire.FaultInjector._reliable_any(frame(kind)))

    def test_loss_drops_whole_frames_of_both_directions_deterministically(self):
        frames = flow()
        runs = []
        for seed in (7, 7, 8):
            injector = self.make(loss=0.25, seed=seed)
            runs.append(([out for f in frames for out in injector.process_frame(f)], dict(injector.stats)))
        self.assertEqual(runs[0], runs[1])
        self.assertNotEqual(runs[0][0], runs[2][0])
        out, stats = runs[0]
        self.assertTrue(set(out) <= set(frames))
        self.assertEqual(stats['matched'], len(frames))
        self.assertEqual(stats['dropped'], len(frames) - len(out))
        self.assertEqual(stats['dropped'], stats['dropped_data'] + stats['dropped_control'])
        self.assertGreater(stats['dropped_data'], 0)
        self.assertGreater(stats['dropped_control'], 0)
        self.assertTrue(0.1 < stats['dropped'] / len(frames) < 0.4, stats)
        self.assertEqual(stats['forwarded_data'] + stats['forwarded_control'], len(out))
        self.assertEqual(stats['duplicated'], 0)

    def test_decisions_per_class_do_not_depend_on_interleaving(self):
        data = [f for f in flow() if f[48] == 1]
        control = [f for f in flow() if f[48] != 1]
        a, b = self.make(loss=0.3, seed=3), self.make(loss=0.3, seed=3)
        out_a = [o for f in data + control for o in a.process_frame(f)]
        out_b = [o for f in control + data for o in b.process_frame(f)]
        self.assertEqual(sorted(out_a), sorted(out_b))

    def test_reorder_swaps_adjacent_frames_and_idle_flush_releases(self):
        injector = self.make(reorder=1.0)
        a, b, c = frame(1, 1, 0), frame(1, 1, 1), frame(1, 1, 2)
        self.assertEqual(injector.process_frame(a, 0), [])
        self.assertEqual(injector.process_frame(b, 0), [b, a])
        self.assertEqual(injector.process_frame(c, 0), [])
        ack = frame(2, 1)
        self.assertEqual(injector.process_frame(ack, 1), [])
        self.assertEqual(injector.flush(0), [c])
        self.assertEqual(injector.flush(0), [])
        self.assertEqual(injector.flush(), [ack])
        self.assertEqual(injector.stats['reordered'], 1)
        self.assertEqual(injector.stats['forwarded_data'], 3)
        self.assertEqual(injector.stats['forwarded_control'], 1)

    def test_slow_receiver_delays_data_only(self):
        injector = self.make(slow_receiver_us=1500)
        self.assertEqual(injector.delay_us(frame(1)), 1500)
        self.assertEqual(injector.delay_us(frame(2)), 0)
        self.assertEqual(injector.delay_us(frame(3)), 0)
        self.assertEqual(injector.delay_us(b'ARP unrelated'), 0)
        self.assertEqual(injector.stats['delayed'], 1)

    def test_foreign_and_corrupt_frames_never_consume_decisions(self):
        injector = self.make(loss=0.99, seed=1)
        good = frame(1, 2, 1)
        others = [frame(1, 2, 1, session=SESSION + 1), good[:-1]]
        for offset in (46, 86, 98):  # version, reserved, stored CRC
            bad = bytearray(good)
            bad[offset] ^= 1
            others.append(bytes(bad))
        for other in others:
            self.assertEqual(injector.process_frame(other), [other])
        self.assertEqual(injector.stats['matched'], 0)

    def test_scripted_modes_are_unchanged(self):
        injector = self.wire.FaultInjector('none')
        for f in flow(2):
            self.assertEqual(injector.process_frame(f), [f])
        self.assertEqual(injector.stats['matched'], 0)


def connect(path):
    for _ in range(200):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(path))
            return sock
        except OSError:
            sock.close()
            time.sleep(0.02)
    raise RuntimeError('proxy socket did not appear')


def read_records(sock, timeout):
    sock.settimeout(timeout)
    data = bytearray()
    try:
        while True:
            part = sock.recv(65536)
            if not part:
                break
            data += part
    except socket.timeout:
        pass
    out = []
    while len(data) >= 4:
        size, = struct.unpack('!I', data[:4])
        out.append(bytes(data[4:4 + size]))
        del data[:4 + size]
    return out


class RandomProxyProcess(unittest.TestCase):
    def test_proxy_main_applies_seeded_loss_and_slow_receiver(self):
        wire = load()
        data = [frame(1, g, i) for g in range(1, 11) for i in range(4)]
        acks = [frame(2, g) for g in range(1, 11)]
        args = dict(loss=0.2, seed=11, slow_receiver_us=2000)
        model = wire.FaultInjector('reliable-random', **args)
        want_data = [o for f in data for o in model.process_frame(f, 0)]
        want_acks = [o for f in acks for o in model.process_frame(f, 1)]
        with tempfile.TemporaryDirectory(prefix='xdev-wire-', dir=os.environ.get('TMPDIR')) as tmp:
            tmp = Path(tmp)
            proxy = subprocess.Popen([sys.executable, str(WIRE), '--left', str(tmp / 'l.sock'),
                                      '--right', str(tmp / 'r.sock'), '--stats', str(tmp / 'stats.json'),
                                      '--fault', 'reliable-random', '--loss', '0.2', '--seed', '11',
                                      '--slow-receiver-us', '2000'],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            left = right = None
            try:
                left = connect(tmp / 'l.sock')
                right = connect(tmp / 'r.sock')
                start = time.monotonic()
                left.sendall(b''.join(struct.pack('!I', len(f)) + f for f in data))
                right.sendall(b''.join(struct.pack('!I', len(f)) + f for f in acks))
                got_data = read_records(right, 1.0)
                elapsed = time.monotonic() - start
                got_acks = read_records(left, 0.3)
            finally:
                proxy.terminate()
                output, _ = proxy.communicate(timeout=10)
                for sock in (left, right):
                    if sock is not None:
                        sock.close()
            stats = json.loads((tmp / 'stats.json').read_text())
        self.assertEqual(proxy.returncode, 0, output)
        self.assertEqual(got_data, want_data)
        self.assertEqual(got_acks, want_acks)
        self.assertGreaterEqual(elapsed, len(want_data) * 0.002)
        self.assertEqual(stats['mode'], 'reliable-random')
        self.assertEqual((stats['loss'], stats['seed'], stats['slow_receiver_us']), (0.2, 11, 2000))
        self.assertEqual(stats['dropped'], len(data) + len(acks) - len(want_data) - len(want_acks))
        self.assertEqual(stats['delayed'], len(want_data))
        self.assertEqual(stats['errors'], [])
        self.assertIn('XDEV_EXT_ZC_WIRE_RANDOM mode=reliable-random loss=0.2 reorder=0.0 seed=11', output)


if __name__ == '__main__':
    unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise the production QEMU cable fault injector with real Ethernet bytes."""
import importlib.util
import os
from pathlib import Path
import socket
import struct
import unittest

KERNEL = Path(os.environ.get('KERNEL_DIR', str(Path(__file__).resolve().parents[5])))
WIRE = Path(os.environ.get(
    'RELIABLE_WIRE',
    str(KERNEL / 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_wire.py')))
spec = importlib.util.spec_from_file_location('production_wire', WIRE)
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)

SESSION = 270019
GROUP = 2
SEG_LEN = 1408
MODES = ('reliable-drop-data', 'reliable-drop-ack',
         'reliable-duplicate-ack', 'reliable-replay-group')


def crc32c(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff


def ip_checksum(data):
    words = struct.unpack('!10H', data)
    value = sum(words)
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return ~value & 0xffff


def packet(kind=1, index=2, session=SESSION, group=GROUP,
           attempt=1, reverse=None):
    """Independent byte fixture, not the implementation under test."""
    if reverse is None:
        reverse = kind == 2
    hdr = bytearray(64)
    struct.pack_into('!IBBBBQQIIHHIIIQII', hdr, 0,
                     0x4e585033, 3, 64, kind, 0, session, group, attempt,
                     8192 if kind == 1 else 0,
                     index if kind == 1 else 0,
                     6 if kind == 1 else 0,
                     index * SEG_LEN if kind == 1 else 0,
                     (1152 if index == 5 else SEG_LEN) if kind == 1 else 0,
                     0, 6 if kind == 2 else 0, 0, 0)
    # Header fields at offsets 44/60 are reserved; credit is at offset 48.
    payload = bytes(((index * 29 + i) & 255 for i in range(
        (1152 if index == 5 else SEG_LEN) if kind == 1 else 0)))
    struct.pack_into('!I', hdr, 56, crc32c(hdr + payload))
    left_mac, right_mac = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    left_ip, right_ip = socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2')
    src_mac, dst_mac = (right_mac, left_mac) if reverse else (left_mac, right_mac)
    src_ip, dst_ip = (right_ip, left_ip) if reverse else (left_ip, right_ip)
    src_port, dst_port = (12345, 54321) if reverse else (54321, 12345)
    udp = struct.pack('!HHHH', src_port, dst_port, 8 + len(hdr) + len(payload), 0)
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0,
                              20 + len(udp) + len(hdr) + len(payload),
                              0, 0, 64, 17, 0, src_ip, dst_ip))
    struct.pack_into('!H', ip, 10, ip_checksum(ip))
    return dst_mac + src_mac + b'\x08\x00' + ip + udp + hdr + payload


class ReliableFaultTests(unittest.TestCase):
    def injector(self, mode):
        # Unsupported modes fail visibly against the real production class.
        try:
            return wire.FaultInjector(mode)
        except ValueError as error:
            self.fail(f'production cable lacks {mode}: {error}')

    def test_fixture_is_valid_and_uses_v3_layout(self):
        data = packet()
        self.assertEqual(len(data), 14 + 20 + 8 + 64 + 1408)
        self.assertEqual(ip_checksum(data[14:34]), 0)
        hdr = bytearray(data[42:106])
        stored, = struct.unpack_from('!I', hdr, 56)
        hdr[56:60] = bytes(4)
        self.assertEqual(crc32c(hdr + data[106:]), stored)
        self.assertEqual(struct.unpack_from('!Q', hdr, 48)[0], 0)
        ack = packet(2)
        self.assertEqual(len(ack), 106)
        self.assertEqual(struct.unpack_from('!Q', ack, 90)[0], 6)

    def test_drop_data_once_then_forward_same_retry(self):
        injector = self.injector('reliable-drop-data')
        data = packet()
        self.assertEqual(injector.process_frame(data), [])
        retry = packet(attempt=2)
        self.assertEqual(injector.process_frame(retry), [retry])
        self.assertEqual(injector.stats['dropped'], 1)

    def test_drop_ack_reverse_direction_once(self):
        injector = self.injector('reliable-drop-ack')
        data, ack = packet(), packet(2)
        self.assertEqual(injector.process_frame(data), [data])
        self.assertEqual(injector.process_frame(ack), [])
        self.assertEqual(injector.process_frame(ack), [ack])
        self.assertEqual(injector.stats['dropped'], 1)

    def test_duplicate_ack_preserves_exact_bytes(self):
        injector = self.injector('reliable-duplicate-ack')
        ack = packet(2)
        self.assertEqual(injector.process_frame(ack), [ack, ack])
        self.assertEqual(injector.process_frame(ack), [ack])
        self.assertEqual(injector.stats['duplicated'], 1)

    def test_replay_entire_group_after_last_segment(self):
        injector = self.injector('reliable-replay-group')
        group = [packet(index=i) for i in range(6)]
        received = []
        for frame in group:
            received.extend(injector.process_frame(frame))
        self.assertEqual(received, group + group)
        self.assertEqual(injector.process_frame(group[0]), [group[0]])
        self.assertEqual(injector.stats['duplicated'], 6)

    def test_foreign_session_group_and_direction_are_untouched(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                injector = self.injector(mode)
                fixtures = [packet(session=SESSION + 1), packet(group=GROUP + 1),
                            packet(2, session=SESSION + 1), packet(2, reverse=False)]
                for frame in fixtures:
                    self.assertEqual(injector.process_frame(frame), [frame])
                self.assertEqual(injector.stats['dropped'], 0)
                self.assertEqual(injector.stats['duplicated'], 0)

    def test_truncated_reserved_crc_and_version_do_not_consume_fault(self):
        for mode, valid in [('reliable-drop-data', packet()),
                            ('reliable-drop-ack', packet(2))]:
            with self.subTest(mode=mode):
                injector = self.injector(mode)
                corrupt = []
                for offset in (46, 86, 98):  # version, reserved, stored CRC
                    bad = bytearray(valid)
                    bad[offset] ^= 1
                    corrupt.append(bytes(bad))
                corrupt.extend((valid[:105], valid[:-1]))
                for frame in corrupt:
                    self.assertEqual(injector.process_frame(frame), [frame])
                self.assertEqual(injector.stats['dropped'], 0)
                self.assertEqual(injector.process_frame(valid), [])

    def test_legacy_modes_remain_available(self):
        frame = packet()
        for mode in ('none', 'drop-middle', 'duplicate-middle'):
            injector = wire.FaultInjector(mode)
            self.assertEqual(injector.process_frame(frame), [frame])


if __name__ == '__main__':
    unittest.main()

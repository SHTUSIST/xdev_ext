#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Deterministic wire-fault host behavior, using actual packet bytes.

The proxy replaces QEMU's virtual wire; tests never alter native completions.
No root, guest, socket, BPF loading or server access is required here.
"""

import importlib.util
from pathlib import Path
import struct
import sys
import unittest


HERE = Path(__file__).resolve().parent
WIRE = HERE / "xdev_ext_mech_zc_wire.py"


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def packet(*, generation=2, index=2, count=6, session=270019):
    payload = bytes((i * 7 + 19) & 255 for i in range(1432))
    nxp = bytearray(struct.pack("!IBBBBQIHHIIII", 0x4e585032, 2, 40, 2, 0,
                                session, generation, index, count, 8192,
                                index * 1432, len(payload), 0))
    struct.pack_into("!I", nxp, 36, crc32c(nxp + payload))
    udp = struct.pack("!HHHH", 54321, 12345, 8 + len(nxp) + len(payload), 0)
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(nxp) + len(payload),
                               0, 0, 64, 17, 0,
                               bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])))
    struct.pack_into("!H", ip, 10, checksum(ip))
    eth = bytes.fromhex("0200000000020200000000010800")
    return eth + ip + udp + nxp + payload


def mutate(frame, offset, value):
    changed = bytearray(frame)
    changed[offset:offset + len(value)] = value
    return bytes(changed)


class WireFaultBehaviorTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(WIRE.is_file(), "missing deterministic QEMU wire injector")
        spec = importlib.util.spec_from_file_location("xdev_ext_mech_zc_wire", WIRE)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertTrue(callable(getattr(module, "FaultInjector", None)),
                        "wire helper must expose FaultInjector(fault='none')")
        self.factory = module.FaultInjector

    def counts(self, injector, *, matched=0, dropped=0, duplicated=0):
        for key, expected in (("matched", matched), ("dropped", dropped),
                              ("duplicated", duplicated)):
            self.assertEqual(injector.stats[key], expected, key)

    def test_explicit_none_and_default_never_change_wire(self):
        for injector in (self.factory(), self.factory(fault="none")):
            with self.subTest(injector=injector):
                for frame in (packet(), packet(generation=1), b"", b"ARP unrelated"):
                    self.assertEqual(injector.process_frame(frame), [frame])
                self.counts(injector)

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            self.factory(fault="drop")

    def test_drop_actually_removes_exactly_one_middle_frame(self):
        injector = self.factory(fault="drop-middle")
        before = packet(generation=1)
        target = packet()
        after = packet(index=3)
        self.assertEqual(injector.process_frame(before), [before])
        self.assertEqual(injector.process_frame(target), [])
        self.assertEqual(injector.process_frame(after), [after])
        self.assertEqual(injector.process_frame(target), [target])
        self.counts(injector, matched=1, dropped=1)

    def test_duplicate_sends_two_identical_unmodified_frames_once(self):
        injector = self.factory(fault="duplicate-middle")
        target = packet()
        self.assertEqual(injector.process_frame(target), [target, target])
        self.assertEqual(injector.process_frame(target), [target])
        self.counts(injector, matched=1, duplicated=1)

    def test_distinct_generations_and_segments_never_consume_the_fault(self):
        for mode in ("drop-middle", "duplicate-middle"):
            injector = self.factory(fault=mode)
            frames = [packet(generation=1), packet(generation=3),
                      packet(index=0), packet(index=1), packet(index=3),
                      packet(index=5), packet(count=5), packet(session=270020)]
            for frame in frames:
                self.assertEqual(injector.process_frame(frame), [frame])
            self.counts(injector)
            self.assertEqual(len(injector.process_frame(packet())), 0 if mode == "drop-middle" else 2)

    def test_precise_network_and_nxp_fields_are_checked(self):
        target = packet()
        # Ethernet 14, IPv4 20, UDP 8, NXP 40: assertions use wire offsets,
        # independently of the implementation's parser or constants.
        changes = [
            (0, bytes.fromhex("020000000003")),       # destination MAC
            (6, bytes.fromhex("020000000004")),       # source MAC
            (12, b"\x86\xdd"),                      # IPv6 EtherType
            (14, b"\x65"),                          # wrong IP version
            (20, b"\x00\x01"),                      # fragmented IPv4
            (23, b"\x06"),                          # TCP, not UDP
            (26, bytes([192, 0, 2, 9])),              # source IP
            (30, bytes([192, 0, 2, 9])),              # destination IP
            (34, struct.pack("!H", 54320)),           # source port
            (36, struct.pack("!H", 12344)),           # destination port
            (42, b"NXP1"),                           # magic
            (46, b"\x01"),                          # NXP version
            (47, b"\x20"),                          # NXP header length
            (48, b"\x01"),                          # READ, not WRITE
            (49, b"\x01"),                          # reserved flags
            (66, struct.pack("!I", 4096)),           # group total_len
            (70, struct.pack("!I", 0)),              # wrong relative offset
            (74, struct.pack("!I", 128)),            # inconsistent payload len
        ]
        for offset, value in changes:
            with self.subTest(offset=offset):
                injector = self.factory(fault="drop-middle")
                other = mutate(target, offset, value)
                self.assertEqual(injector.process_frame(other), [other])
                self.counts(injector)
                self.assertEqual(injector.process_frame(target), [])

    def test_truncation_and_invalid_lengths_do_not_consume_fault(self):
        target = packet()
        invalid = [target[:length] for length in (0, 13, 33, 41, 81, len(target) - 1)]
        invalid += [mutate(target, 16, struct.pack("!H", 20)),
                    mutate(target, 38, struct.pack("!H", 8)),
                    mutate(target, 38, struct.pack("!H", 65535))]
        for frame in invalid:
            with self.subTest(length=len(frame)):
                injector = self.factory(fault="drop-middle")
                self.assertEqual(injector.process_frame(frame), [frame])
                self.counts(injector)
                self.assertEqual(injector.process_frame(target), [])

    def test_instances_do_not_share_fault_state(self):
        a = self.factory(fault="drop-middle")
        b = self.factory(fault="drop-middle")
        self.assertEqual(a.process_frame(packet()), [])
        self.counts(b)
        self.assertEqual(b.process_frame(packet()), [])


if __name__ == "__main__":
    unittest.main()

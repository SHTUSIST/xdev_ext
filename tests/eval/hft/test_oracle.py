#!/usr/bin/env python3
"""Independent reference, CRC32C and full-set oracle; no producer imports."""
import hashlib
import json
import os
from pathlib import Path
import random
import stat
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ORACLE = HERE / "oracle.py"
PROFILE = dict(schema=1, record_bytes=64, payload_bytes=512, burst_packets=2,
               depth=8, bursts=2, actors=4, seed=0x1020304050607080,
               session_base=0x4846540000000000)


def reference_payload(profile, actor, group):
    size = profile["record_bytes"]
    result = bytearray()
    for record in range(profile["payload_bytes"] // size):
        result += struct.pack("!IHHIHH", 0x4846544d, actor, size, group, record, 0)
        result += bytes((profile["seed"] + 29*actor + 17*group +
                         11*record + 7*j) & 255 for j in range(16, size))
    return bytes(result)


def reference_file(profile):
    return b"".join(reference_payload(profile, actor, group)
                    for actor in range(profile["actors"])
                    for group in range(profile["burst_packets"] * profile["bursts"]))


def crc32c(data):
    crc = 0xffffffff
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def packet(profile, actor, group, *, payload=None, session=None, generation=None,
           header_changes=None):
    payload = reference_payload(profile, actor, group) if payload is None else payload
    fields = [0x4e585032, 2, 40, 2, 0,
              profile["session_base"] + actor if session is None else session,
              group + 1 if generation is None else generation,
              0, 1, profile["payload_bytes"], 0, profile["payload_bytes"], 0]
    for index, value in (header_changes or {}).items():
        fields[index] = value
    fmt = "!IBBBBQIHHIIII"
    wire = struct.pack(fmt, *fields) + payload
    fields[-1] = crc32c(wire)
    return struct.pack(fmt, *fields) + payload


def packets(profile):
    return [packet(profile, actor, group) for actor in range(profile["actors"])
            for group in range(profile["burst_packets"] * profile["bursts"])]


def capture_bytes(datagrams):
    return b"".join(struct.pack("!I", len(data)) + data for data in datagrams)


class IndependentOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".oracle-test-", dir=HERE)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps(PROFILE))
        self.reference = self.root / "reference.bin"
        self.capture = self.root / "capture.bin"

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, action, *args):
        result = subprocess.run([sys.executable, str(ORACLE), action, "--manifest",
                                 str(self.manifest), *map(str, args)],
                                text=True, capture_output=True, timeout=15)
        self.assertTrue(ORACLE.is_file(), "absent oracle; actual subprocess exit="
                        + str(result.returncode) + "; stderr=" + result.stderr)
        return result

    def verify(self, data, valid):
        self.capture.write_bytes(data)
        result = self.invoke("verify", "--capture", self.capture)
        self.assertEqual(result.returncode, 0 if valid else 1,
                         f"stdout={result.stdout}\nstderr={result.stderr}")
        if valid:
            self.assertEqual(json.loads(result.stdout), dict(status="ok",
                validated_packets=16, validated_bytes=8192))
            self.assertEqual(len(result.stdout.splitlines()), 1)
        else:
            self.assertEqual(result.stdout, "")

    def test_independent_crc_known_vector_and_geometry(self):
        self.assertEqual(crc32c(b"123456789"), 0xe3069283)
        self.assertEqual(len(packet(PROFILE, 0, 0)), 552)
        self.assertEqual(len(reference_file(PROFILE)), 8192)

    def test_generate_exact_every_byte_and_private_exclusive_file(self):
        result = self.invoke("generate", "--reference", self.reference)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.reference.read_bytes(), reference_file(PROFILE))
        self.assertEqual(stat.S_IMODE(self.reference.stat().st_mode), 0o600)
        saved = self.reference.stat()
        result = self.invoke("generate", "--reference", self.reference)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.reference.read_bytes(), reference_file(PROFILE))
        self.assertEqual(self.reference.stat().st_ino, saved.st_ino)
        self.assertEqual(self.reference.stat().st_mtime_ns, saved.st_mtime_ns)

    def test_ordered_and_reordered_full_set_accepted(self):
        data = packets(PROFILE)
        self.verify(capture_bytes(data), True)
        random.Random(6701).shuffle(data)
        self.verify(capture_bytes(data), True)

    def test_missing_duplicate_extra_foreign_and_stale_rejected(self):
        valid = packets(PROFILE)
        mutants = {
            "missing": valid[:-1], "duplicate": valid + [valid[0]],
            "duplicate-replaces-missing": valid[:-1] + [valid[0]],
            "extra-generation": valid + [packet(PROFILE, 0, 4)],
            "stale-generation": [packet(PROFILE, 0, 0, generation=0)] + valid[1:],
            "wrong-session": [packet(PROFILE, 0, 0, session=9)] + valid[1:],
            "wrong-actor-payload": [packet(PROFILE, 0, 0,
                 payload=reference_payload(PROFILE, 1, 0))] + valid[1:],
        }
        for name, data in mutants.items():
            with self.subTest(mutant=name):
                self.verify(capture_bytes(data), False)

    def test_all_payload_bytes_checked_even_with_valid_crc(self):
        valid = packets(PROFILE)
        original = reference_payload(PROFILE, 0, 0)
        for index in (0, 15, 16, 63, 64, 255, 511):
            payload = bytearray(original)
            payload[index] ^= 0x80
            with self.subTest(corrupt_index=index):
                self.verify(capture_bytes([packet(PROFILE, 0, 0, payload=payload)]
                                           + valid[1:]), False)
        constant = [packet(PROFILE, a, g, payload=bytes(512))
                    for a in range(4) for g in range(4)]
        self.verify(capture_bytes(constant), False)

    def test_crc_header_fields_and_truncation_rejected(self):
        valid = packets(PROFILE)
        corrupt = bytearray(valid[0]); corrupt[-1] ^= 1
        self.verify(capture_bytes([corrupt] + valid[1:]), False)
        for index, value in ((0, 0), (1, 1), (2, 39), (3, 1), (4, 1),
                             (7, 1), (8, 2), (9, 511), (10, 1), (11, 511)):
            with self.subTest(header_index=index):
                self.verify(capture_bytes([packet(PROFILE, 0, 0,
                    header_changes={index: value})] + valid[1:]), False)
        for data in (b"", b"\x00", struct.pack("!I", 0xffffffff),
                     capture_bytes(valid)[:-1], capture_bytes(valid) + b"\0",
                     capture_bytes([valid[0][:-1]] + valid[1:]),
                     capture_bytes([valid[0] + b"extra"] + valid[1:])):
            with self.subTest(length=len(data)):
                self.verify(data, False)

    def test_invalid_manifest_never_creates_reference(self):
        for key, value in (("actors", True), ("actors", 0), ("depth", 0),
                           ("record_bytes", 65), ("payload_bytes", 513),
                           ("seed", -1), ("seed", 2**64),
                           ("session_base", 2**64-1)):
            self.manifest.write_text(json.dumps(dict(PROFILE, **{key: value})))
            with self.subTest(key=key, value=value):
                result = self.invoke("generate", "--reference", self.reference)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertFalse(self.reference.exists())


if __name__ == "__main__":
    unittest.main()

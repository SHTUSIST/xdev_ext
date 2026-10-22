#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent byte oracle for a bounded, host-software compatibility workload.

Fixture CLI: build/mixed_hft_shape AUDIT CAPTURE [COUNT], default COUNT=65,
valid range 1..4096. No hardware, accelerator, or performance claim is made.
For sequence s=1..COUNT, the UDP tick's first five little-endian u64 fields are
(s, 9900+(37*s)%211, bid+2+s%7, 1+(3*s)%97, 1+(5*s)%89).
Its sixth field is FNV-1a-64 of the first 40 bytes. The output is six LE u64s:
(s, input_checksum, floor((bid+ask)/2), ema, action, output_checksum), where
ema=(95*previous_ema+5*mid)//100, previous_ema starts at 10000, action is
int(abs(mid-ema)>1), and output_checksum covers the first 40 output bytes.
Audit records start at offset 16, surrounded by 16 bytes of A5 and 5A; capture
is exactly the output records, with no guards. Each record is 48 bytes.

The fixture must validate sequence/checksum, finish each buffered pwrite before
its TCP send, check feeder/sink status, and use bounded loopback port-0 actors.
The separate app runner owns actual preload/model execution and counter checks.
"""
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BINARY = HERE / 'build' / 'mixed_hft_shape'
RECORD_SIZE = 48
PREFIX = b'\xa5' * 16
SUFFIX = b'\x5a' * 16


def fnv1a(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def tick_bytes(sequence):
    bid = 9900 + (37 * sequence) % 211
    fields = (sequence, bid, bid + 2 + sequence % 7,
              1 + (3 * sequence) % 97, 1 + (5 * sequence) % 89)
    payload = struct.pack('<5Q', *fields)
    return payload + struct.pack('<Q', fnv1a(payload))


def expected_outputs(count):
    if type(count) is not int or not 1 <= count <= 4096:
        raise ValueError('count outside fixture contract')
    records, previous = [], 10000
    for sequence in range(1, count + 1):
        _, bid, ask, _, _, input_checksum = struct.unpack('<6Q', tick_bytes(sequence))
        mid = (bid + ask) // 2
        previous = (95 * previous + 5 * mid) // 100
        payload = struct.pack('<5Q', sequence, input_checksum, mid, previous,
                              int(abs(mid - previous) > 1))
        records.append(payload + struct.pack('<Q', fnv1a(payload)))
    capture = b''.join(records)
    return PREFIX + capture + SUFFIX, capture


def expected_summary(count):
    return {'evidence': 'ordinary-libc-workload', 'scope': 'compatibility',
            'records': count, 'udp_records': count, 'audit_records': count,
            'tcp_records': count, 'record_bytes': RECORD_SIZE,
            'feeder_status': 0, 'sink_status': 0}


def validate_result(returncode, stdout, audit, capture, count):
    """Reject success text unless exit, actor statuses, and every byte agree."""
    if returncode != 0:
        raise ValueError(f'workload exit={returncode}')
    try:
        summary = json.loads(stdout)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError('missing or malformed workload JSON') from error
    expected = expected_summary(count)
    if not isinstance(summary, dict) or summary.keys() != expected.keys():
        raise ValueError('missing or unexpected workload summary fields')
    for name, value in expected.items():
        if type(summary[name]) is not type(value) or summary[name] != value:
            raise ValueError(f'workload summary differs: {name}')
    expected_audit, expected_capture = expected_outputs(count)
    if audit != expected_audit:
        raise ValueError('audit full bytes/positions/guards differ')
    if capture != expected_capture:
        raise ValueError('TCP full stream bytes differ')


def invoke_fixture(work, count=None):
    audit, capture = work / 'audit.bin', work / 'capture.bin'
    args = [str(BINARY), str(audit), str(capture)]
    if count is not None:
        args.append(str(count))
    clean = {key: value for key, value in os.environ.items()
             if not key.startswith('XDEV_EXT_') and key != 'LD_PRELOAD'}
    completed = subprocess.run(args, env=clean, capture_output=True, text=True, timeout=30)
    # Retain the actual stdout/stderr beside files for a caller preserving work.
    (work / 'stdout.txt').write_text(completed.stdout)
    (work / 'stderr.txt').write_text(completed.stderr)
    return completed, audit, capture


class OracleContract(unittest.TestCase):
    def test_fnv_known_vectors(self):
        self.assertEqual(fnv1a(b''), 0xcbf29ce484222325)
        self.assertEqual(fnv1a(b'hello'), 0xa430d84680aabd0b)

    def test_first_tick_and_record_arithmetic(self):
        fields = struct.unpack('<6Q', tick_bytes(1))
        self.assertEqual(fields[:5], (1, 9937, 9940, 4, 6))
        audit, capture = expected_outputs(1)
        output = struct.unpack('<6Q', capture)
        self.assertEqual(output[:5], (1, fields[-1], 9938, 9996, 1))
        self.assertEqual(len(audit), 80)
        self.assertEqual(len(capture), 48)

    def test_summary_requires_integer_counts_and_actor_success(self):
        audit, capture = expected_outputs(1)
        good = expected_summary(1)
        validate_result(0, json.dumps(good), audit, capture, 1)
        for field, bad in (('records', True), ('udp_records', '1'),
                           ('feeder_status', 1), ('sink_status', 7)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_result(0, json.dumps(dict(good, **{field: bad})), audit, capture, 1)


class MixedHftFixture(unittest.TestCase):
    def require_binary(self):
        self.assertTrue(BINARY.is_file(),
                        'missing mixed HFT causal fixture: build/mixed_hft_shape')

    def test_complete_pipeline_default_single_and_maximum(self):
        self.require_binary()
        for argument, count in ((None, 65), (1, 1), (4096, 4096)):
            with self.subTest(count=count), tempfile.TemporaryDirectory(
                    prefix='mixed-hft-', dir=BINARY.parent) as temp:
                completed, audit, capture = invoke_fixture(Path(temp), argument)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                validate_result(completed.returncode, completed.stdout,
                                audit.read_bytes(), capture.read_bytes(), count)

    def test_invalid_counts_exit_nonzero(self):
        self.require_binary()
        for count in ('0', '-1', '4097', 'junk', '1x', '18446744073709551616'):
            with self.subTest(count=count), tempfile.TemporaryDirectory(
                    prefix='mixed-hft-invalid-', dir=BINARY.parent) as temp:
                completed, _, _ = invoke_fixture(Path(temp), count)
                self.assertNotEqual(completed.returncode, 0,
                                    f'invalid count accepted: {count}\n{completed.stdout}')

    def test_reject_mutations_of_actual_outputs_and_success_reports(self):
        self.require_binary()
        with tempfile.TemporaryDirectory(prefix='mixed-hft-mutants-', dir=BINARY.parent) as temp:
            completed, audit_path, capture_path = invoke_fixture(Path(temp))
            audit, capture = audit_path.read_bytes(), capture_path.read_bytes()
            validate_result(completed.returncode, completed.stdout, audit, capture, 65)
            summary = json.loads(completed.stdout)

            def reject(name, bad_audit=audit, bad_capture=capture,
                       returncode=0, stdout=completed.stdout):
                with self.subTest(mutant=name), self.assertRaises(ValueError):
                    validate_result(returncode, stdout, bad_audit, bad_capture, 65)

            # Actual output mutations include checksum-preserving corruption:
            # a fixture computing both copies incorrectly cannot pass the oracle.
            for field in (0, 8, 16, 24, 32):
                modified = bytearray(capture)
                modified[field] ^= 1
                modified[40:48] = struct.pack('<Q', fnv1a(modified[:40]))
                bad_capture = bytes(modified)
                reject(f'field-{field}-with-valid-checksum',
                       PREFIX + bad_capture + SUFFIX, bad_capture)
            checksum = bytearray(capture)
            checksum[40] ^= 1
            reject('record-checksum', bad_capture=bytes(checksum))
            reject('delete-tick', PREFIX + capture[48:] + SUFFIX, capture[48:])
            duplicated = capture[:48] + capture
            reject('duplicate-tick', PREFIX + duplicated + SUFFIX, duplicated)
            swapped = capture[48:96] + capture[:48] + capture[96:]
            reject('reordered-audit-offsets', PREFIX + swapped + SUFFIX)
            reject('reordered-stream', bad_capture=swapped)
            reject('audit-truncated-one-byte', audit[:-1])
            reject('prefix-guard', b'\x00' + audit[1:])
            reject('suffix-guard', audit[:-1] + b'\x00')
            reject('stream-truncated-one-byte', bad_capture=capture[:-1])
            reject('stream-extra-byte', bad_capture=capture + b'\x00')
            reject('nonzero-workload-exit', returncode=1)
            for field in ('feeder_status', 'sink_status'):
                reject(field, stdout=json.dumps(dict(summary, **{field: 1})))
            reject('short-count-with-exit-zero',
                   stdout=json.dumps(dict(summary, records=64, tcp_records=64)))
            reject('missing-summary', stdout='')
            reject('duplicated-summary', stdout=completed.stdout + completed.stdout)
            missing = dict(summary)
            del missing['sink_status']
            reject('missing-actor-status', stdout=json.dumps(missing))


if __name__ == '__main__':
    unittest.main(verbosity=2)

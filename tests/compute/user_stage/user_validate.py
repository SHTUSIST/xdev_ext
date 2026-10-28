#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host side of the USER stage guest test (user_kvm.sh).

make-images DIR       private source and destination NVMe images
validate --dir DIR --log LOG --result JSON
                      every guest marker, no failed TAP line, no kernel debug
                      report, and an independent whole-disk check: the
                      destination must hold the CRC32C-sealed copy, the
                      deadline and malformed copies without their failed
                      batches, and guard bytes everywhere else (no batch of
                      stop-held, kill or kill-owner reached the disk)
The plans are duplicated, not shared, with guest/user_stage_e2e.c: a guest
that drifts from them fails here. CRC32C here is table-driven; the guest's
is bitwise.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
LBA = 512
FRAME = 4096
DISK_BYTES = 16 << 20
GUARD = 0x6B
# name: (destination slba, source slba, group bytes, groups, failed slots)
SEAL = (2048, 2048, 8192, 64)
COPIES = {'deadline': (8192, 8192, 4096, 8, {3}), 'malformed': (9216, 9216, 4096, 6, {2, 3, 4})}
UNTOUCHED = {'stop-held': (10240, 800), 'kill': (12288, 800), 'kill-owner': (14336, 800)}
CASES = ('refuse', 'seal', 'append', 'append-bad', 'deadline', 'malformed', 'stop-held', 'kill', 'kill-owner')
MARKERS = (
    'XDEV_EXT_USER_STAGE_E2E=PASS cases=' + ','.join(CASES) + ' timing=none',
    'XDEV_EXT_USER_E2E=PASS',
    'XDEV_EXT_USER_DMESG=PASS no_quarantine=1 no_deferred_drain=1 no_warning=1',
    'XDEV_EXT_USER_GUEST=PASS',
    'XDEV_EXT_USER_GUEST_EXIT=0',
)


def _table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return table


TABLE = _table()


def crc32c(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc = TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def pattern(name, size):
    return hashlib.shake_256(b'XDEV_EXT USER stage ' + name.encode()).digest(size)


def make_images(directory):
    directory = Path(directory)
    (directory / 'source.raw').write_bytes(pattern('source', DISK_BYTES))
    (directory / 'destination.raw').write_bytes(bytes([GUARD]) * DISK_BYTES)


def expected_destination(source):
    expected = bytearray([GUARD]) * DISK_BYTES
    dst, src, group, groups = SEAL
    for j in range(groups * group // FRAME):
        frame = bytearray(source[src * LBA + j * FRAME:src * LBA + (j + 1) * FRAME])
        frame[FRAME - 4:] = crc32c(frame[:FRAME - 4]).to_bytes(4, 'little')
        expected[dst * LBA + j * FRAME:dst * LBA + (j + 1) * FRAME] = frame
    for dst, src, group, groups, failed in COPIES.values():
        for j in range(groups):
            if j not in failed:
                expected[dst * LBA + j * group:dst * LBA + (j + 1) * group] = \
                    source[src * LBA + j * group:src * LBA + (j + 1) * group]
    return expected


def check_images(directory):
    directory = Path(directory)
    source = (directory / 'source.raw').read_bytes()
    destination = (directory / 'destination.raw').read_bytes()
    if source != pattern('source', DISK_BYTES):
        return 'source image changed'
    if len(destination) != DISK_BYTES:
        return 'destination size changed'
    expected = expected_destination(source)
    if destination != expected:
        first = next(i for i in range(DISK_BYTES) if destination[i] != expected[i])
        return f'destination differs from the expected copies plus guards at byte {first} (lba {first // LBA})'
    return None


def debug_counts(text):
    # Canonical tests/compute/user_stage and the materialized native selftests
    # tree share the same real helper, at their respective stable locations.
    for directory in (HERE.parents[1] / 'integration/session/native',
                      HERE.parents[1] / 'xdev_ext_integration'):
        helper = directory / 'xdev_ext_mech_zc_debug.py'
        if helper.is_file():
            spec = importlib.util.spec_from_file_location('_xdev_ext_user_stage_debug', helper)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module.debug_reports(text)
    raise ModuleNotFoundError('USER validator requires the real xdev_ext_mech_zc_debug.py helper')


def check_log(text):
    errors = []
    for marker in MARKERS:
        if not re.search('^' + re.escape(marker) + r'\s*$', text, re.M):
            errors.append('missing marker: ' + marker)
    for case in CASES:
        if not re.search(r'^XDEV_EXT_USER_CASE=PASS case=' + re.escape(case) + r'\s*$', text, re.M):
            errors.append('missing case: ' + case)
    if re.search(r'^not ok\b', text, re.M):
        errors.append('a guest TAP check failed')
    if re.search(r'^FAIL\b', text, re.M):
        errors.append('a guest step failed')
    counts = debug_counts(text)
    if any(counts.values()):
        errors.append('kernel debug report: ' + json.dumps(counts, sort_keys=True))
    return errors


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    images = sub.add_parser('make-images')
    images.add_argument('dir')
    validate = sub.add_parser('validate')
    validate.add_argument('--dir', required=True)
    validate.add_argument('--log', required=True)
    validate.add_argument('--result', required=True)
    args = parser.parse_args()
    if args.command == 'make-images':
        make_images(args.dir)
        return 0
    text = Path(args.log).read_text(errors='replace').replace('\r', '')
    errors = check_log(text)
    image_error = check_images(args.dir)
    if image_error:
        errors.append(image_error)
    result = {'verdict': 'FAIL' if errors else 'PASS', 'errors': errors,
              'claim': 'KVM correctness only; QEMU NVMe; user thread in the guest; no timing'}
    Path(args.result).write_text(json.dumps(result, indent=2) + '\n')
    print('XDEV_EXT_USER_VALIDATE=' + result['verdict'])
    for error in errors:
        print('# ' + error)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())

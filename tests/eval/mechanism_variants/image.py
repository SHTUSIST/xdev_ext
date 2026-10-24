#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent LBA signatures and entire downstream payload oracle.

Seeding creates a regular image fragment, never opens a block device.
"""
import argparse
import hashlib
from pathlib import Path
import struct


def lba_bytes(lba):
    return b''.join(hashlib.sha256(b'xdev-ext-e2-lba-v1\0' +
                   struct.pack('<QI', lba, piece)).digest() for piece in range(16))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('seed', 'verify'))
    p.add_argument('path', type=Path)
    p.add_argument('--variant', choices=('reverse', 'gray'))
    p.add_argument('--first-request-id', type=int, choices=(0, 1))
    a = p.parse_args()
    if a.command == 'seed':
        with a.path.open('xb') as out:
            out.write(b''.join(lba_bytes(lba) for lba in range(2048, 2112)))
        return
    if a.variant is None or a.first_request_id is None:
        p.error('verify requires variant and actual first request ID')
    # Oracle literal tables are deliberately separate from the BPF mapping.
    slots = {'reverse': (0,4,2,6,1,5,3,7), 'gray': (0,1,3,2,6,7,5,4)}[a.variant]
    expected = b''.join(lba_bytes(lba)
                       for rid in range(a.first_request_id, a.first_request_id + 16)
                       for lba in range(2048 + slots[rid & 7]*8,
                                        2056 + slots[rid & 7]*8))
    actual = a.path.read_bytes()
    if actual != expected:
        mismatch = next((i for i, (x,y) in enumerate(zip(actual,expected)) if x != y),
                        min(len(actual),len(expected)))
        p.exit(1, f'E2 independent oracle FAIL byte={mismatch} actual_len={len(actual)} expected_len={len(expected)}\n')
    print(f'E2_SINK_ORACLE=PASS variant={a.variant} first_request_id={a.first_request_id} bytes={len(actual)} performance_claim=none')


if __name__ == '__main__':
    main()

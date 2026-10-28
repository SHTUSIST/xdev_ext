#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent whole-image oracle for ordered_frames_guest.

BEFORE is an exact snapshot before the test, AFTER after guest shutdown.
Only six selected two-frame spans at DST_SLBA may differ. The Python oracle
reconstructs bytes directly, without guest logs, slots, or C helper output.
"""
import argparse
import json
from pathlib import Path

FRAME = 4096
SPAN_OFFSET = 512
SPAN_BYTES = 3072
SELECTED = ((7, 3), (9, 1), (7, 3), (9, 1), (7, 3), (9, 1))
MAX_BYTES = 128 * 1024 * 1024


def validate(before, after, dst_slba):
    before, after = Path(before), Path(after)
    size = before.stat().st_size
    if not size or size > MAX_BYTES or size % 4096 or after.stat().st_size != size:
        raise ValueError('scratch images must have the same nonzero 4 KiB-aligned size, at most 128 MiB')
    start = dst_slba * 512
    end = start + 6 * 2 * SPAN_BYTES
    if dst_slba < 0 or end > size:
        raise ValueError('complete expected output span must fit the scratch image')
    # The only expected update is computed from the independently frozen
    # frame list and original allocation pattern, not from actual output.
    update = bytes((67 + index * 37 + pos * 11 + (pos // 256) * 19) % 256
                   for pair in SELECTED for index in pair
                   for pos in range(SPAN_OFFSET, SPAN_OFFSET + SPAN_BYTES))
    checked = 0
    with before.open('rb') as baseline, after.open('rb') as actual:
        while checked < size:
            n = min(1024 * 1024, size - checked)
            want = bytearray(baseline.read(n))
            have = actual.read(n)
            lo, hi = max(start, checked), min(end, checked + n)
            if hi > lo:
                want[lo - checked:hi - checked] = update[lo - start:hi - start]
            if have != want:
                offset = checked + next(i for i, (a, b) in enumerate(zip(have, want)) if a != b)
                raise ValueError(f'whole-image byte mismatch at {offset} (within output={start <= offset < end})')
            checked += n
    return {'verdict': 'PASS', 'whole_image_bytes': checked, 'messages': 6,
            'selected': [7, 3, 9, 1], 'span_offset': SPAN_OFFSET,
            'span_bytes': SPAN_BYTES, 'dst_slba': dst_slba}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('before')
    p.add_argument('after')
    p.add_argument('dst_slba', type=lambda s: int(s, 0))
    args = p.parse_args()
    try:
        result = validate(args.before, args.after, args.dst_slba)
    except (OSError, ValueError) as error:
        print(json.dumps({'verdict': 'FAIL', 'error': str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

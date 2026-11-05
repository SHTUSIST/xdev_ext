#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host whole-disk oracle of the NVMe window handle test (prototype for ASK.69).

window_validate.py SOURCE_BEFORE DESTINATION: the source must be the
position-unique image of its own seed (8-byte word at byte offset o:
low32 = ((o // 512) << 7) | (((o % 512) // 8) << 1) | 1, high32 = seed);
destination windows W0 (tenant), W1 (victim) and W5 (raw-fd session) must be
exact copies of the same source windows and every other byte the guard 0x6b.
Prints one JSON object; exit 0 only for PASS.
"""
import json
import struct
import sys

LBA = 512
WIN_NLB = 64
WIN_BYTES = WIN_NLB * LBA
SPAN = 4 << 20
GUARD = 0x6b
WRITTEN = {0: 'tenant', 1: 'victim', 5: 'raw'}


def expected_source(seed, span=SPAN):
    image = bytearray(span)
    for o in range(0, span, 8):
        struct.pack_into('<II', image, o, ((o // LBA) << 7) | (((o % LBA) // 8) << 1) | 1, seed)
    return image


def validate(source, destination):
    if len(source) != SPAN or len(destination) != SPAN:
        return {'state': 'FAIL', 'reason': 'image size', 'source': len(source),
                'destination': len(destination)}
    seed = struct.unpack_from('<I', source, 4)[0]
    if bytes(expected_source(seed)) != bytes(source):
        return {'state': 'FAIL', 'reason': 'source is not the position-unique image of its seed',
                'seed': '0x%08x' % seed}
    expect = bytearray([GUARD]) * SPAN
    for w in WRITTEN:
        expect[w * WIN_BYTES:(w + 1) * WIN_BYTES] = source[w * WIN_BYTES:(w + 1) * WIN_BYTES]
    if bytes(expect) == bytes(destination):
        return {'state': 'PASS', 'seed': '0x%08x' % seed,
                'written_windows': {str(w): name for w, name in sorted(WRITTEN.items())}}
    first = next(i for i in range(SPAN) if expect[i] != destination[i])
    window = first // WIN_BYTES
    return {'state': 'FAIL', 'reason': 'destination differs from the expected image',
            'first_mismatch_byte': first, 'lba': first // LBA, 'window': window,
            'window_role': WRITTEN.get(window, 'guard'), 'seed': '0x%08x' % seed}


def main(argv):
    if len(argv) != 3:
        print('usage: window_validate.py SOURCE_BEFORE DESTINATION', file=sys.stderr)
        return 2
    with open(argv[1], 'rb') as s, open(argv[2], 'rb') as d:
        result = validate(s.read(), d.read())
    print(json.dumps(result, sort_keys=True))
    return 0 if result['state'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host whole-disk oracle of the NVMe window handle test.

window_validate.py SOURCE_BEFORE DESTINATION: the source must be the
position-unique image of its own seed (8-byte word at byte offset o:
low32 = ((o // 512) << 7) | (((o % 512) // 8) << 1) | 1, high32 = seed);
destination windows W0 (tenant), W1 (victim), W5 (raw-fd session), W6
(victim2) and W7 (tenant2) must be exact copies of the same source windows and
every other byte the guard 0x6b.

window_validate.py --multi SOURCE_BEFORE DESTINATION AUX KILL_MIN: the
multi-tenant mode (window_multi.h). Rounds r = 0..3 (kill, escape, unknown,
timeout), tenant i at destination window 4r + i: innocent windows (i >= 1)
are exact copies of the same source windows; the killed tenant's window
(round 0, tenant 0) holds, per 4 KiB group, either its own source group or
guard, and at least KILL_MIN exact groups; the other faulty windows and every
byte past window 15 are guard; AUX, the faulty tenant's private namespace,
still holds only 0x3c.
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
WRITTEN = {0: 'tenant', 1: 'victim', 5: 'raw', 6: 'victim2', 7: 'tenant2'}
GROUP = 4096
AUX_FILL = 0x3c
ROUNDS = ('kill', 'escape', 'unknown', 'timeout')
TENANTS = 4


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


def _window(image, w):
    return bytes(image[w * WIN_BYTES:(w + 1) * WIN_BYTES])


def validate_multi(source, destination, aux, kill_min):
    if len(source) != SPAN or len(destination) != SPAN or len(aux) != SPAN:
        return {'state': 'FAIL', 'reason': 'image size'}
    seed = struct.unpack_from('<I', source, 4)[0]
    if bytes(expected_source(seed)) != bytes(source):
        return {'state': 'FAIL', 'reason': 'source is not the position-unique image of its seed',
                'seed': '0x%08x' % seed}
    if bytes(aux) != bytes([AUX_FILL]) * SPAN:
        return {'state': 'FAIL', 'reason': 'the faulty tenant namespace changed'}
    guard_group = bytes([GUARD]) * GROUP
    killed = []
    for r, name in enumerate(ROUNDS):
        for i in range(TENANTS):
            w = TENANTS * r + i
            got = _window(destination, w)
            if i:
                if got != _window(source, w):
                    return {'state': 'FAIL', 'reason': 'innocent window is not its exact source window',
                            'round': name, 'tenant': i, 'window': w}
                continue
            if name != 'kill':
                if got != bytes([GUARD]) * WIN_BYTES:
                    return {'state': 'FAIL', 'reason': 'faulty window is not guard', 'round': name,
                            'window': w}
                continue
            want = _window(source, w)
            for g in range(WIN_BYTES // GROUP):
                piece = got[g * GROUP:(g + 1) * GROUP]
                if piece == want[g * GROUP:(g + 1) * GROUP]:
                    killed.append(g)
                elif piece != guard_group:
                    return {'state': 'FAIL', 'reason': 'killed tenant group is neither exact nor guard',
                            'window': w, 'group': g}
    if len(killed) < kill_min:
        return {'state': 'FAIL', 'reason': 'fewer exact killed-tenant groups than it completed',
                'exact_groups': killed, 'kill_min': kill_min}
    tail = TENANTS * len(ROUNDS) * WIN_BYTES
    if bytes(destination[tail:]) != bytes([GUARD]) * (SPAN - tail):
        return {'state': 'FAIL', 'reason': 'bytes past the round windows are not guard'}
    return {'state': 'PASS', 'seed': '0x%08x' % seed, 'killed_exact_groups': killed,
            'kill_min': kill_min, 'rounds': list(ROUNDS)}


def main(argv):
    if len(argv) == 6 and argv[1] == '--multi':
        with open(argv[2], 'rb') as s, open(argv[3], 'rb') as d, open(argv[4], 'rb') as a:
            result = validate_multi(s.read(), d.read(), a.read(), int(argv[5]))
        print(json.dumps(result, sort_keys=True))
        return 0 if result['state'] == 'PASS' else 1
    if len(argv) != 3:
        print('usage: window_validate.py SOURCE_BEFORE DESTINATION | --multi SOURCE DESTINATION AUX KILL_MIN',
              file=sys.stderr)
        return 2
    with open(argv[1], 'rb') as s, open(argv[2], 'rb') as d:
        result = validate(s.read(), d.read())
    print(json.dumps(result, sort_keys=True))
    return 0 if result['state'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))

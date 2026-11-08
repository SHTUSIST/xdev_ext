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

window_validate.py --reset SOURCE_BEFORE DESTINATION AUX EXACT: the reset
round of window_multi.h (tenant i at destination window 16 + i). Each 4 KiB
group of an innocent window (i >= 1) is its own source group or guard (a
write the controller reset aborted may or may not have landed); the
innocents listed in EXACT (comma separated, '-' for none: those that STOPped
with 0 after all their batches) hold their whole source window. Each group
of the faulty window is guard or its own AUX group: the reset ends its
swallowed READs, the fault is lifted, and its later batches copy its private
namespace into its own window. Every other byte is guard; AUX still holds
only 0x3c.

window_validate.py --frame-reuse SOURCE_BEFORE DESTINATION AUX: one old
UNKNOWN write at W0 group 0 is exact source W0 group 0 or guard; the new
session's one write at W1 group 0 is exact source W1 group 0. Every other
destination byte is guard; AUX stays unchanged. The guest independently
checks source preservation, frame 0's new bytes and guards on frames 1..7;
the runner compares SOURCE_BEFORE against the post-run source disk.
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
RESET_ROUND = 4


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


def validate_reset(source, destination, aux, exact):
    if len(source) != SPAN or len(destination) != SPAN or len(aux) != SPAN:
        return {'state': 'FAIL', 'reason': 'image size'}
    seed = struct.unpack_from('<I', source, 4)[0]
    if bytes(expected_source(seed)) != bytes(source):
        return {'state': 'FAIL', 'reason': 'source is not the position-unique image of its seed',
                'seed': '0x%08x' % seed}
    if bytes(aux) != bytes([AUX_FILL]) * SPAN:
        return {'state': 'FAIL', 'reason': 'the faulty tenant namespace changed'}
    guard_group = bytes([GUARD]) * GROUP
    first = TENANTS * RESET_ROUND
    exact_groups = {}
    for i in range(TENANTS):
        w = first + i
        got = _window(destination, w)
        if not i:
            own = _window(aux, w)
            for g in range(WIN_BYTES // GROUP):
                piece = got[g * GROUP:(g + 1) * GROUP]
                if piece != guard_group and piece != own[g * GROUP:(g + 1) * GROUP]:
                    return {'state': 'FAIL', 'reason': 'faulty group is neither guard nor its own private group',
                            'window': w, 'group': g}
            continue
        want = _window(source, w)
        exact_groups[i] = []
        for g in range(WIN_BYTES // GROUP):
            piece = got[g * GROUP:(g + 1) * GROUP]
            if piece == want[g * GROUP:(g + 1) * GROUP]:
                exact_groups[i].append(g)
            elif piece != guard_group:
                return {'state': 'FAIL', 'reason': 'innocent group is neither exact nor guard',
                        'tenant': i, 'window': w, 'group': g}
        if i in exact and got != want:
            return {'state': 'FAIL', 'reason': 'innocent that STOPped cleanly is not its exact source window',
                    'tenant': i, 'window': w, 'exact_groups': exact_groups[i]}
    if bytes(destination[:first * WIN_BYTES]) != bytes([GUARD]) * (first * WIN_BYTES):
        return {'state': 'FAIL', 'reason': 'bytes before the reset round windows are not guard'}
    tail = (first + TENANTS) * WIN_BYTES
    if bytes(destination[tail:]) != bytes([GUARD]) * (SPAN - tail):
        return {'state': 'FAIL', 'reason': 'bytes past the reset round windows are not guard'}
    return {'state': 'PASS', 'seed': '0x%08x' % seed, 'exact_tenants': sorted(exact),
            'innocent_exact_groups': {str(i): g for i, g in exact_groups.items()}}


def validate_reuse(source, destination, aux):
    """Two STARTs, key 1 each: only group 0 of bound windows W0 and W1.

    A's UNKNOWN write may have landed before reset; C must copy W1 exactly.
    Allowing a whole window here would hide unintended batches/offsets.
    """
    if len(source) != SPAN or len(destination) != SPAN or len(aux) != SPAN:
        return {'state': 'FAIL', 'reason': 'image size'}
    seed = struct.unpack_from('<I', source, 4)[0]
    if bytes(expected_source(seed)) != bytes(source):
        return {'state': 'FAIL', 'reason': 'source is not the position-unique image of its seed'}
    if bytes(aux) != bytes([AUX_FILL]) * SPAN:
        return {'state': 'FAIL', 'reason': 'the unused auxiliary namespace changed'}
    guard_group = bytes([GUARD]) * GROUP
    old = bytes(destination[:GROUP])
    if old != guard_group and old != bytes(source[:GROUP]):
        return {'state': 'FAIL', 'reason': 'old write group is neither its own source nor guard'}
    if bytes(destination[WIN_BYTES:WIN_BYTES + GROUP]) != bytes(source[WIN_BYTES:WIN_BYTES + GROUP]):
        return {'state': 'FAIL', 'reason': 'reused frame did not write the new source group'}
    for start, end in ((GROUP, WIN_BYTES), (WIN_BYTES + GROUP, SPAN)):
        if bytes(destination[start:end]) != bytes([GUARD]) * (end - start):
            return {'state': 'FAIL', 'reason': 'destination outside the two first groups changed',
                    'range_start': start, 'range_end': end}
    return {'state': 'PASS', 'seed': '0x%08x' % seed, 'old_write_landed': old != guard_group,
            'old_group_byte': 0, 'reused_group_byte': WIN_BYTES, 'group_bytes': GROUP}


def main(argv):
    if len(argv) == 5 and argv[1] == '--frame-reuse':
        with open(argv[2], 'rb') as s, open(argv[3], 'rb') as d, open(argv[4], 'rb') as a:
            result = validate_reuse(s.read(), d.read(), a.read())
        print(json.dumps(result, sort_keys=True))
        return 0 if result['state'] == 'PASS' else 1
    if len(argv) == 6 and argv[1] == '--reset':
        exact = set() if argv[5] == '-' else {int(t) for t in argv[5].split(',')}
        with open(argv[2], 'rb') as s, open(argv[3], 'rb') as d, open(argv[4], 'rb') as a:
            result = validate_reset(s.read(), d.read(), a.read(), exact)
        print(json.dumps(result, sort_keys=True))
        return 0 if result['state'] == 'PASS' else 1
    if len(argv) == 6 and argv[1] == '--multi':
        with open(argv[2], 'rb') as s, open(argv[3], 'rb') as d, open(argv[4], 'rb') as a:
            result = validate_multi(s.read(), d.read(), a.read(), int(argv[5]))
        print(json.dumps(result, sort_keys=True))
        return 0 if result['state'] == 'PASS' else 1
    if len(argv) != 3:
        print('usage: window_validate.py SOURCE_BEFORE DESTINATION | --multi SOURCE DESTINATION AUX KILL_MIN'
              ' | --reset SOURCE DESTINATION AUX EXACT | --frame-reuse SOURCE DESTINATION AUX', file=sys.stderr)
        return 2
    with open(argv[1], 'rb') as s, open(argv[2], 'rb') as d:
        result = validate(s.read(), d.read())
    print(json.dumps(result, sort_keys=True))
    return 0 if result['state'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))

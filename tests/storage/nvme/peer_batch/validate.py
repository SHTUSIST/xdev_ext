#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host oracle for the concurrent multi-page peer batch guest test.

It regenerates the three disk images, rebuilds the guest's plan on its own
(the random phases from the same generator, the discontiguous request from
the boundary the guest observed), computes every expected pool and disk
image, and compares the whole destination image byte for byte, including all
guard bytes. It checks the TAP stream, the command counts and orders the
guest read from the NVMe tracepoints, the UNKNOWN retention observations and
the kernel console. The plan is duplicated here on purpose, not imported from
the guest program. Correctness only: no timing is read or reported.
"""
import argparse
import functools
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parents[2] / 'integration/session/native'
sys.path.insert(0, str(NATIVE))
from xdev_ext_mech_zc_debug import check_console  # noqa: E402

LBA = 512
KIB = 1024
MIB = 1024 * KIB
SRC_BYTES = 64 * MIB
DST_BYTES = 64 * MIB
ERR_BYTES = 4 * MIB
SRC_LBAS = SRC_BYTES // LBA
P_BYTES = 6 * MIB + 68 * KIB
Q_BYTES = 1 * MIB
GUARD = 0x6b
ERR_SECTOR = 2368
DUMP_A, DUMP_B, DUMP_Q = 16 * MIB, 24 * MIB, 40 * MIB
WRITE_REGION = 14 * MIB
U64 = (1 << 64) - 1
FINAL = 'XDEV_EXT_PEER_BATCH=PASS phases=A,B,C,D,E pool=system-heap requesters=3 timing=none'
EINVAL, ERANGE, EOVERFLOW, ESTALE, E2BIG = 22, 34, 75, 116, 7
REFUSALS = (('D1-duplicate-target', EINVAL), ('D2-overlap-last', EINVAL), ('D3-write-lba-overlap', EINVAL),
            ('D4-target-past-pool', ERANGE), ('D5-lba-past-namespace', ERANGE), ('D6-offset-wrap', EOVERFLOW),
            ('D7-lba-wrap', ERANGE), ('D8-wrong-generation', ESTALE), ('D9-over-transfer-limit', E2BIG),
            ('E2-quarantined-allocation', ESTALE))


@functools.lru_cache(maxsize=None)
def image(tag, size):
    out = bytearray()
    for sector in range(size // LBA):
        out += hashlib.sha256(tag + sector.to_bytes(8, 'little')).digest() * 16
    return bytes(out)


def source_image():
    return image(b'xdev-peer-batch', SRC_BYTES)


def error_image():
    return image(b'xdev-peer-batch-err', ERR_BYTES)


@functools.lru_cache(maxsize=None)
def pattern(kind, size):
    if kind == 'p':
        return bytes((((o * 131 + 7) ^ (o >> 9)) & 0xff) for o in range(size))
    if kind == 'w':
        return bytes((((o * 197 + 11) ^ (o >> 10) ^ 0xa5) & 0xff) for o in range(size))
    return bytes((((o * 61 + 3) ^ 0x96) & 0xff) for o in range(size))


class Rng:
    def __init__(self):
        self.seed = 0x42ba7c4

    def __call__(self):
        self.seed = (self.seed * 6364136223846793005 + 1442695040888963407) & U64
        return (self.seed >> 33) & 0xffffffff


def shuffled(rng, n):
    slot = list(range(n))
    for k in range(n - 1, 0, -1):
        j = rng() % (k + 1)
        slot[k], slot[j] = slot[j], slot[k]
    return slot


def plans(boundary):
    """Every batch of the guest program, in order: (case, write, descriptors)."""
    rng = Rng()
    out = [('A1', 0, [(0, 4096, MIB)]),
           ('A2', 0, [(3 * MIB, 16384, MIB), (MIB, 8192, MIB), (2 * MIB, 12288, MIB)]),
           ('A3', 0, [(boundary - 33280, 24576, 65536), (4 * MIB + 1024, 24832, 3072), (4 * MIB + 7680, 24840, 4096)])]
    slot = shuffled(rng, 48)
    b = []
    for k in range(40):
        head = 512 * (rng() % 64)
        size = 512 * (1 + rng() % 192)
        lba = rng() % (SRC_LBAS - 256)
        b.append((slot[k] * 128 * KIB + head, lba, size))
    for k in (7, 23):
        b[k] = (b[k][0], b[3][1], b[k][2])
    out.append(('B', 0, b))
    out.append(('C1', 1, [(0, 0, MIB)]))
    slot = shuffled(rng, 32)
    c = []
    for k in range(32):
        lba = 4096 + slot[k] * 768 + rng() % 128
        size = 512 * (1 + rng() % 512)
        source = 512 * (rng() % ((P_BYTES - 256 * KIB) // 512))
        c.append((source, lba, size))
    out.append(('C2', 1, c))
    d2 = [(i * 256 * KIB, i * 64, 65536) for i in range(6)]
    d2[5] = (65536 - 512, d2[5][1], 65536)
    d4 = [(i * 512 * KIB, i * 128, 65536) for i in range(5)]
    d4[4] = (P_BYTES - 4096, d4[4][1], 65536)
    d5 = [(i * 512 * KIB, i * 128, 4096) for i in range(3)]
    d5[2] = (d5[2][0], SRC_LBAS - 1, 1024)
    out += [('D1-duplicate-target', 0, [(0, 0, 4096), (65536, 8, 4096), (131072, 16, 4096), (65536, 24, 4096)]),
            ('D2-overlap-last', 0, d2),
            ('D3-write-lba-overlap', 1, [(0, 100, 8192), (MIB, 115, 1024)]),
            ('D4-target-past-pool', 0, d4),
            ('D5-lba-past-namespace', 0, d5),
            ('D6-offset-wrap', 0, [(0, 10, 4096), ((1 << 64) - 4096, 20, 8192)]),
            ('D7-lba-wrap', 0, [(0, 10, 4096), (8192, (1 << 64) - 8, 4096)]),
            ('D8-wrong-generation', 0, [(0, 10, 4096)]),
            ('D9-over-transfer-limit', 0, [(0, 10, 4096), (MIB, 100, MIB + 4096)]),
            ('E1', 0, [(i * 128 * KIB, 2048 + i * 128, 65536) for i in range(6)]),
            ('E2-quarantined-allocation', 0, [(0, 0, 4096)])]
    return out


def plan_line(case, write, descs):
    return 'PLAN case=%s write=%d nr=%d' % (case, write, len(descs)) + ''.join(
        ' %d:%d:%d' % d for d in descs)


def first_difference(a, b):
    step = 1 << 20
    for base in range(0, len(a), step):
        if a[base:base + step] != b[base:base + step]:
            return base + next(i for i in range(step) if a[base + i] != b[base + i])
    return -1


def make_images(directory):
    directory = Path(directory)
    (directory / 'source.raw').write_bytes(source_image())
    (directory / 'error.raw').write_bytes(error_image())
    (directory / 'destination.raw').write_bytes(bytes([GUARD]) * DST_BYTES)


def check_tap(lines):
    if lines.count('TAP version 13') != 1:
        raise ValueError('TAP: exactly one "TAP version 13" header required')
    plan = [line for line in lines if re.fullmatch(r'1\.\.[0-9]+', line)]
    if len(plan) != 1:
        raise ValueError('TAP: exactly one plan line required')
    numbers = []
    for line in lines:
        if re.match(r'not ok [0-9]+', line):
            raise ValueError('TAP: failed check: ' + line)
        match = re.match(r'ok ([0-9]+) - ', line)
        if match:
            if re.search(r'#\s*(SKIP|TODO)', line, re.I):
                raise ValueError('TAP: skipped or todo check: ' + line)
            numbers.append(int(match.group(1)))
    count = int(plan[0][3:])
    if numbers != list(range(1, count + 1)):
        raise ValueError('TAP: checks %d do not match plan 1..%d' % (len(numbers), count))
    return count


def observations(lines):
    seen = {}
    for line in lines:
        if line.startswith('OBSERVE '):
            fields = dict(item.split('=', 1) for item in line.split()[1:] if '=' in item)
            case = fields.pop('case', '')
            for key, value in fields.items():
                if (case, key) in seen:
                    raise ValueError('duplicate observation %s %s' % (case, key))
                seen[(case, key)] = value
    return seen


def number(seen, case, key):
    try:
        return int(seen[(case, key)])
    except (KeyError, ValueError):
        raise ValueError('missing or malformed observation %s %s' % (case, key)) from None


def apply(target, data, descs, write):
    for offset, lba, size in descs:
        if write:
            target[lba * LBA:lba * LBA + size] = data[offset:offset + size]
        else:
            target[offset:offset + size] = data[lba * LBA:lba * LBA + size]


def expected_regions(seen, source, error):
    boundary = number(seen, 'pool', 'boundary')
    if boundary % 4096 or not 4 * MIB + 128 * KIB <= boundary <= P_BYTES - 64 * KIB:
        raise ValueError('discontiguity boundary outside the frozen window')
    if number(seen, 'pool', 'physical_runs') < 2:
        raise ValueError('pool has no physical discontinuity')
    batches = plans(boundary)
    by_case = {case: descs for case, _, descs in batches}
    pool = bytearray(pattern('p', P_BYTES))
    for case in ('A1', 'A2', 'A3'):
        apply(pool, source, by_case[case], False)
    after_a = bytes(pool)
    apply(pool, source, by_case['B'], False)
    after_b = bytes(pool)
    written = pattern('w', P_BYTES)
    dest = bytearray([GUARD]) * DST_BYTES
    apply(dest, written, by_case['C1'], True)
    apply(dest, written, by_case['C2'], True)
    issued = number(seen, 'E1', 'setups')
    if not 3 <= issued <= 6:
        raise ValueError('phase E issued count outside 3..6')
    q = bytearray(pattern('q', Q_BYTES))
    apply(q, error, [d for k, d in enumerate(by_case['E1']) if k != 2 and k < issued], False)
    dest[DUMP_A:DUMP_A + P_BYTES] = after_a
    dest[DUMP_B:DUMP_B + P_BYTES] = after_b
    dest[DUMP_Q:DUMP_Q + Q_BYTES] = q
    return batches, dest


def validate(images, log):
    images = Path(images)
    source, error = (images / 'source.raw').read_bytes(), (images / 'error.raw').read_bytes()
    dest = (images / 'destination.raw').read_bytes()
    if source != source_image():
        raise ValueError('source image changed or differs from the generated pattern')
    if error != error_image():
        raise ValueError('error image changed or differs from the generated pattern')
    if len(dest) != DST_BYTES:
        raise ValueError('destination image size differs from the plan')
    lines = [line.strip() for line in log.replace('\r', '').splitlines()]
    if 'XDEV_EXT_PEER_BATCH_GUEST_EXIT=0' not in lines:
        raise ValueError('guest exit status 0 not reported')
    checks = check_tap(lines)
    if lines.count(FINAL) != 1:
        raise ValueError('final PASS line missing')
    seen = observations(lines)
    if number(seen, 'queue', 'max_hw_sectors_kb') != 1024:
        raise ValueError('queue transfer limit is not 1 MiB')
    batches, expected = expected_regions(seen, source, error)
    want = tuple(plan_line(case, write, descs) for case, write, descs in batches)
    got = tuple(line for line in lines if line.startswith('PLAN '))
    if got != want:
        raise ValueError('guest plan differs from the host plan')
    # The failed command's own destination is unspecified: take the dump's bytes there.
    expected = bytearray(expected)
    failed = DUMP_Q + 2 * 128 * KIB
    expected[failed:failed + 65536] = dest[failed:failed + 65536]
    if dest != bytes(expected):
        raise ValueError('destination image differs from the plan at byte %d' % first_difference(dest, expected))
    if (number(seen, 'A1', 'setups'), number(seen, 'A1', 'lens'), number(seen, 'A1', 'slba')) != (1, 2047, 4096):
        raise ValueError('1 MiB request was not one 2048-LBA command')
    for case, count in (('A2', 3), ('B', 40), ('C2', 32)):
        if number(seen, case, 'setups') != count:
            raise ValueError('%s: native command count differs from the plan' % case)
    for case in ('A2', 'B'):
        if number(seen, case, 'max_outstanding') < 2:
            raise ValueError('%s: commands were never in flight together' % case)
    for case, errno in REFUSALS:
        if (number(seen, case, 'ret'), number(seen, case, 'completed'), number(seen, case, 'status')) != \
                (-errno, 0, -errno) or seen.get((case, 'setups')) != '0,0,0':
            raise ValueError('%s: refusal did not hold before any command' % case)
    status = number(seen, 'E1', 'ret')
    if status <= 0 or number(seen, 'E1', 'status') != status or number(seen, 'E1', 'completed') != 2:
        raise ValueError('phase E: native failure status or completed prefix')
    if number(seen, 'E1', 'd2_setups') != 1 or number(seen, 'E1', 'completes') != number(seen, 'E1', 'setups'):
        raise ValueError('phase E: failed command resubmitted or an issued command not completed')
    if number(seen, 'E3', 'vmpin_before_close') != number(seen, 'E3', 'vmpin_after_close'):
        raise ValueError('phase E: MEMLOCK charge of the UNKNOWN allocation was returned')
    if not seen.get(('E3', 'attached')):
        raise ValueError('phase E: requester attachment of the UNKNOWN allocation released')
    console = '\n'.join(lines[lines.index('XDEV_EXT_PEER_BATCH_DMESG_BEGIN') + 1:
                              lines.index('XDEV_EXT_PEER_BATCH_DMESG_END')]) \
        if 'XDEV_EXT_PEER_BATCH_DMESG_BEGIN' in lines and 'XDEV_EXT_PEER_BATCH_DMESG_END' in lines else None
    if console is None:
        raise ValueError('kernel console section missing')
    check_console(console)
    return dict(checks=checks, boundary=number(seen, 'pool', 'boundary'),
                physical_runs=number(seen, 'pool', 'physical_runs'),
                max_outstanding=dict(A2=number(seen, 'A2', 'max_outstanding'), B=number(seen, 'B', 'max_outstanding'),
                                     C2=number(seen, 'C2', 'max_outstanding')),
                completion_inversions=dict(A2=number(seen, 'A2', 'completion_inversions'),
                                           B=number(seen, 'B', 'completion_inversions'),
                                           C2=number(seen, 'C2', 'completion_inversions')),
                e1=dict(status=status, completed=2, issued=number(seen, 'E1', 'setups')),
                destination_sha256=hashlib.sha256(dest).hexdigest())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('make-images').add_argument('directory')
    sub.add_parser('err-sector')
    v = sub.add_parser('validate')
    v.add_argument('--images', required=True)
    v.add_argument('--log', required=True)
    v.add_argument('--result', required=True)
    args = parser.parse_args(argv)
    if args.action == 'make-images':
        make_images(args.directory)
        return 0
    if args.action == 'err-sector':
        print(ERR_SECTOR)
        return 0
    try:
        summary = validate(args.images, Path(args.log).read_text())
    except (ValueError, OSError) as error:
        Path(args.result).write_text(json.dumps(dict(status='FAIL', reason=str(error)), indent=2) + '\n')
        print('XDEV_EXT_PEER_BATCH_HOST=FAIL ' + str(error))
        return 1
    Path(args.result).write_text(json.dumps(dict(status='PASS', **summary), indent=2, sort_keys=True) + '\n')
    print('XDEV_EXT_PEER_BATCH_HOST=PASS checks=%d boundary=%d issued_e1=%d' %
          (summary['checks'], summary['boundary'], summary['e1']['issued']))
    return 0


if __name__ == '__main__':
    sys.exit(main())

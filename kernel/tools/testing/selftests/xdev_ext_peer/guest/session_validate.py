#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-side oracle for the guest POOL_PEER session test.

Independent of the guest program: it regenerates the source pattern, keeps
its own copy of the case plan, and compares the raw disk images that QEMU
wrote after the guest powered off.  It also checks the console for the TAP
verdict, module unload, and every kernel debug report family that the KVM
harness already rejects.  Correctness only: no timing is read or reported.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

LBA = 512
DISK_BYTES = 16 << 20
DEST_GUARD = 0x6b
PASS_PREFIX = 'XDEV_EXT_PEER_SESSION=PASS'
UNLOAD_MARKER = 'XDEV_EXT_PEER_SESSION_UNLOAD=PASS module=xdev_ext_peer_sw'
EXIT_RE = re.compile(r'^XDEV_EXT_SESSION_GUEST_EXIT=(\d+)$', re.M)
# Kept in step with peer_session_e2e.c by the PLAN-line comparison below.
PLANS = (
    dict(name='reject-map', frame=4096, seg=4096, group=4096, depth=1, groups=4,
         src_slba=2048, dst_slba=16384, copies=False),
    dict(name='cli', frame=65536, seg=16384, group=16384, depth=1, groups=64,
         src_slba=2048, dst_slba=4096, copies=True),
    dict(name='depth4', frame=4096, seg=4096, group=8192, depth=4, groups=96,
         src_slba=8192, dst_slba=10240, copies=True),
    dict(name='fd-release', frame=32768, seg=32768, group=32768, depth=2, groups=8,
         src_slba=12288, dst_slba=14336, copies=True),
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'xdev_ext_integration'))
from xdev_ext_mech_zc_debug import debug_reports  # noqa: E402  (existing harness oracle)


def plan_bytes(p):
    return p['groups'] * p['group']


def plan_line(p):
    return ('PLAN case={name} frame={frame} seg={seg} group={group} depth={depth} '
            'groups={groups} src_slba={src_slba} dst_slba={dst_slba} copies={c}').format(
                c=int(p['copies']), **p)


def source_pattern(size=DISK_BYTES):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(b'xdev-ext-peer-session-source' + counter.to_bytes(8, 'little')).digest()
        counter += 1
    return bytes(out[:size])


def expected_destination(source, size=DISK_BYTES):
    dest = bytearray([DEST_GUARD]) * size
    for p in PLANS:
        if p['copies']:
            s, d, n = p['src_slba'] * LBA, p['dst_slba'] * LBA, plan_bytes(p)
            dest[d:d + n] = source[s:s + n]
    return bytes(dest)


def first_difference(a, b):
    return next(i for i in range(min(len(a), len(b))) if a[i] != b[i])


def check_images(source_after, dest_after):
    if len(source_after) != DISK_BYTES or len(dest_after) != DISK_BYTES:
        raise ValueError('image size mismatch')
    original = source_pattern()
    if source_after != original:
        raise ValueError(f'source image changed at byte {first_difference(source_after, original)}')
    expected = expected_destination(original)
    if dest_after != expected:
        raise ValueError(f'destination image differs at byte {first_difference(dest_after, expected)}')
    return dict(source_bytes=len(source_after), destination_bytes=len(dest_after),
                copied_bytes=sum(plan_bytes(p) for p in PLANS if p['copies']))


def check_log(text):
    lines = text.splitlines()
    if 'TAP version 13' not in lines:
        raise ValueError('TAP header missing')
    if any(re.match(r'^not ok\b', line) for line in lines):
        raise ValueError('TAP not ok present')
    oks = [line for line in lines if re.match(r'^ok \d+ - ', line)]
    if any(re.search(r'#\s*(SKIP|TODO)', line, re.I) for line in oks):
        raise ValueError('TAP skip/todo directive present')
    numbers = [int(line.split()[1]) for line in oks]
    plans = [line for line in lines if re.match(r'^1\.\.\d+$', line)]
    if len(plans) != 1 or numbers != list(range(1, len(oks) + 1)) or int(plans[0][3:]) != len(oks):
        raise ValueError('TAP plan does not match ok lines')
    got = [line for line in lines if line.startswith('PLAN ')]
    if got != [plan_line(p) for p in PLANS]:
        raise ValueError('guest PLAN lines differ from host oracle plan')
    if sum(line.startswith(PASS_PREFIX + ' ') for line in lines) != 1:
        raise ValueError('session PASS marker missing')
    if UNLOAD_MARKER not in lines:
        raise ValueError('provider unload marker missing')
    exits = EXIT_RE.findall(text)
    if exits != ['0']:
        raise ValueError(f'guest exit status {exits}')
    reports = debug_reports(text)
    if any(reports.values()):
        raise ValueError('kernel debug diagnostic: ' + json.dumps(reports, sort_keys=True))
    return dict(ok=len(oks), not_ok=0, skip=0, **{'debug_' + k: n for k, n in reports.items()})


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='action', required=True)
    make = sub.add_parser('make-source')
    make.add_argument('path', type=Path)
    val = sub.add_parser('validate')
    val.add_argument('--source', type=Path, required=True)
    val.add_argument('--dest', type=Path, required=True)
    val.add_argument('--log', type=Path, required=True)
    val.add_argument('--result', type=Path, required=True)
    args = ap.parse_args()
    if args.action == 'make-source':
        args.path.write_bytes(source_pattern())
        return 0
    result = dict(verdict='FAIL')
    try:
        result.update(check_log(args.log.read_text(errors='replace')))
        result.update(check_images(args.source.read_bytes(), args.dest.read_bytes()))
        result['verdict'] = 'PASS'
    except ValueError as error:
        result['error'] = str(error)
    args.result.write_text(json.dumps(result, sort_keys=True) + '\n')
    print('XDEV_EXT_PEER_SESSION_HOST=' + result['verdict'] + ' ' + json.dumps(result, sort_keys=True))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())

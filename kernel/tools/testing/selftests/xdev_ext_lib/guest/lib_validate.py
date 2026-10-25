#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host oracle and plan of the libxdev_ext guest test.

The plan below is the single source of the scenario parameters: lib_kvm.sh
hands `shell_plan()` to the guest.  After QEMU powers off, the oracle
regenerates the source pattern, compares the raw destination image (which
only the independent AF_PACKET receiver wrote) against the source windows,
and checks the console for the library's own result lines, the receiver's
lines and every kernel debug report family of the existing KVM harness.
Correctness only: no timing is read or reported.
"""
import argparse
import functools
import hashlib
import json
from pathlib import Path
import re
import sys

LBA = 512
DISK_BYTES = 16 << 20
DEST_GUARD = 0x6b
MTU = 1500
SEG = (MTU - 20 - 8 - 40) & ~7      # NXP segment of the 4096/360 layout
# expect=pass: every batch reaches the wire and the receiver; expect=fail:
# the window holds only groups-1 batches, so the library must report the
# failure and still release the session (no receiver).
PLANS = (
    dict(name='oneshot-zc', api='oneshot', mode='zc', slba=2048, nlb=1024, groups=64,
         depth=16, group_bytes=8192, wire=270101, src_port=54321, dst_port=12345,
         dst_offset=0, expect='pass'),
    dict(name='steps-copy', api='steps', mode='copy', slba=8192, nlb=592, groups=37,
         depth=8, group_bytes=8192, wire=270102, src_port=54322, dst_port=12346,
         dst_offset=4 << 20, expect='pass'),
    dict(name='oneshot-window-short', api='oneshot', mode='zc', slba=0, nlb=48, groups=4,
         depth=4, group_bytes=8192, wire=270103, src_port=54323, dst_port=12347,
         dst_offset=0, expect='fail'),
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'xdev_ext_integration'))
from xdev_ext_mech_zc_debug import debug_reports  # noqa: E402  (existing harness oracle)


def frames_per_group(p):
    return -(-p['group_bytes'] // SEG)


def shell_plan():
    """One line per scenario: name:api:mode:slba:nlb:groups:depth:bytes:wire:sport:dport:off:expect."""
    return ''.join('{name}:{api}:{mode}:{slba}:{nlb}:{groups}:{depth}:{group_bytes}:{wire}:'
                   '{src_port}:{dst_port}:{dst_offset}:{expect}\n'.format(**p) for p in PLANS)


@functools.lru_cache(maxsize=2)
def source_pattern(size=DISK_BYTES):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(b'xdev-ext-lib-source' + counter.to_bytes(8, 'little')).digest()
        counter += 1
    return bytes(out[:size])


def expected_destination(source, size=DISK_BYTES):
    dest = bytearray([DEST_GUARD]) * size
    for p in PLANS:
        if p['expect'] == 'pass':
            s, n = p['slba'] * LBA, p['groups'] * p['group_bytes']
            dest[p['dst_offset']:p['dst_offset'] + n] = source[s:s + n]
    return bytes(dest)


def first_difference(a, b):
    return next(i for i in range(min(len(a), len(b))) if a[i] != b[i])


def one(lines, prefix, what):
    got = [line for line in lines if line.startswith(prefix)]
    if len(got) != 1:
        raise ValueError(f'{what}: expected one line starting {prefix!r}, got {len(got)}')
    return got[0]


def fields(line):
    return dict(re.findall(r'(\w+)=(\S+)', line))


def check_pass(lines, p):
    g, f = p['groups'], frames_per_group(p)
    zc = p['mode'] == 'zc'
    api = p['api']
    r = fields(one(lines, f'XDEV_EXT_LIB_RESULT api={api} ', f"{p['name']} result line"))
    want = dict(ret='0', zero_copy='1' if zc else '0', wait_err='0', nic_err='0',
                stop_err='0', retained='0')
    if any(r.get(k) != val for k, val in want.items()) or int(r.get('session', '0')) <= 0:
        raise ValueError(f"{p['name']} result line: {r}")
    s = fields(one(lines, f'XDEV_EXT_LIB_STATS api={api} ', f"{p['name']} stats line"))
    want = dict(state='1', last_err='0', batches_done=str(g), batches_abort='0', rejects='0',
                sequestered='0', timeouts='0', inflight='0', protocol_err='0',
                submitted0=str(g), completed0=str(g))
    if (any(s.get(k) != val for k, val in want.items()) or int(s['submitted1']) < g or
            s['completed1'] != s['submitted1']):
        raise ValueError(f"{p['name']} stats line: {s}")
    n = fields(one(lines, f'XDEV_EXT_LIB_NIC api={api} ', f"{p['name']} nic line"))
    ops, nbytes = str(g * f), str(g * p['group_bytes'])
    want = (dict(nic_copy_ops='0', nic_copy_bytes='0', nic_zc_ops=ops, nic_zc_bytes=nbytes) if zc else
            dict(nic_copy_ops=ops, nic_copy_bytes=nbytes, nic_zc_ops='0', nic_zc_bytes='0'))
    if n != dict(api=api, **want):
        raise ValueError(f"{p['name']} nic line: {n}")
    one(lines, f'XDEV_EXT_LIB_EXIT api={api} ret=0 ', f"{p['name']} exit line")


def check_fail(lines, p):
    r = fields(one(lines, f"XDEV_EXT_LIB_RESULT api={p['api']} ", f"{p['name']} negative result line"))
    if int(r.get('ret', '0')) >= 0 or r.get('retained') != '0' or r.get('stop_err') != '0':
        raise ValueError(f"{p['name']} negative result: {r}")
    s = fields(one(lines, f"XDEV_EXT_LIB_STATS api={p['api']} ", f"{p['name']} negative stats line"))
    if s.get('inflight') != '0' or s.get('sequestered') != '0':
        raise ValueError(f"{p['name']} negative stats: {s}")


def check_log(text):
    # Each scenario's lines are the span after the previous scenario marker.
    lines = text.splitlines()
    names, start = [], 0
    for p in PLANS:
        mark = [i for i, line in enumerate(lines) if line.startswith(f"XDEV_EXT_LIB_SCENARIO name={p['name']} ")]
        if len(mark) != 1 or mark[0] < start:
            raise ValueError(f"{p['name']} scenario marker: {len(mark)}")
        span, start = lines[start:mark[0]], mark[0] + 1
        m = fields(lines[mark[0]])
        if p['expect'] == 'pass':
            if m.get('tx_exit') != '0' or m.get('rx_exit') != '0':
                raise ValueError(f"{p['name']} scenario exits: {m}")
            check_pass(span, p)
            g, f = p['groups'], frames_per_group(p)
            rx = fields(one(span, 'XDEV_EXT_LIB_RX result=', f"{p['name']} receiver line"))
            want = dict(result='complete', groups=str(g), unique=str(g * f), duplicates='0',
                        bad='0', expected=str(g * f))
            if any(rx.get(k) != val for k, val in want.items()):
                raise ValueError(f"{p['name']} receiver line: {rx}")
        else:
            if m.get('tx_exit') in (None, '0') or m.get('rx_exit') != 'none':
                raise ValueError(f"{p['name']} negative scenario exits: {m}")
            check_fail(span, p)
        names.append(p['name'])
    exits = re.findall(r'^XDEV_EXT_LIB_GUEST_EXIT=(\d+)$', text, re.M)
    if exits != ['0']:
        raise ValueError(f'guest exit status {exits}')
    reports = debug_reports(text)
    if any(reports.values()):
        raise ValueError('kernel debug diagnostic: ' + json.dumps(reports, sort_keys=True))
    return dict(scenarios=names, **{'debug_' + k: n for k, n in reports.items()})


def check_images(source_after, dest_after):
    if len(source_after) != DISK_BYTES or len(dest_after) != DISK_BYTES:
        raise ValueError('image size mismatch')
    original = source_pattern()
    if source_after != original:
        raise ValueError(f'source image changed at byte {first_difference(source_after, original)}')
    expected = expected_destination(original)
    if dest_after != expected:
        raise ValueError(f'destination image differs at byte {first_difference(dest_after, expected)}')
    return dict(checked_bytes=sum(p['groups'] * p['group_bytes'] for p in PLANS if p['expect'] == 'pass'))


def check(log_text, source_after, dest_after):
    result = check_log(log_text)
    result.update(check_images(source_after, dest_after))
    return result


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='action', required=True)
    make = sub.add_parser('make-source')
    make.add_argument('path', type=Path)
    make_dst = sub.add_parser('make-dest')
    make_dst.add_argument('path', type=Path)
    sub.add_parser('plan')
    val = sub.add_parser('validate')
    val.add_argument('--source', type=Path, required=True)
    val.add_argument('--dest', type=Path, required=True)
    val.add_argument('--log', type=Path, required=True)
    val.add_argument('--result', type=Path, required=True)
    args = ap.parse_args()
    if args.action == 'make-source':
        args.path.write_bytes(source_pattern())
        return 0
    if args.action == 'make-dest':
        args.path.write_bytes(bytes([DEST_GUARD]) * DISK_BYTES)
        return 0
    if args.action == 'plan':
        sys.stdout.write(shell_plan())
        return 0
    result = dict(verdict='FAIL')
    try:
        result.update(check(args.log.read_text(errors='replace'), args.source.read_bytes(),
                            args.dest.read_bytes()))
        result['verdict'] = 'PASS'
    except ValueError as error:
        result['error'] = str(error)
    args.result.write_text(json.dumps(result, sort_keys=True) + '\n')
    print('XDEV_EXT_LIB_HOST=' + result['verdict'] + ' ' + json.dumps(result, sort_keys=True))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())

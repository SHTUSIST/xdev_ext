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
    dict(name='steps-zc', api='steps', mode='zc', slba=12288, nlb=336, groups=21,
         depth=4, group_bytes=8192, wire=270104, src_port=54324, dst_port=12348,
         dst_offset=8 << 20, expect='pass'),
    dict(name='steps-copy', api='steps', mode='copy', slba=8192, nlb=592, groups=37,
         depth=8, group_bytes=8192, wire=270102, src_port=54322, dst_port=12346,
         dst_offset=4 << 20, expect='pass'),
    dict(name='oneshot-window-short', api='oneshot', mode='zc', slba=0, nlb=48, groups=4,
         depth=4, group_bytes=8192, wire=270103, src_port=54323, dst_port=12347,
         dst_offset=0, expect='fail'),
)

# IOU_UMEM pool scenarios of xdev_ext_lib_iou (NVMe -> [CE -> CE ->] NVMe on
# the ring's own UMEM).  src/dst are source and destination LBAs, one per
# handle.  expect: exact (every byte), either (each group is the source
# group or untouched guard: STOP while transfers were accepted), untouched.
# ce_fail/ce_delay_us are written to the CE stand-in's parameters first.
IOU_PLANS = (
    dict(name='iou-single', kind='single', groups=32, depth=4, group_bytes=8192,
         src=(16384,), dst=(20480,), ce_fail='none', ce_delay_us=0, timeout_ms=60000,
         expect='exact'),
    dict(name='iou-threads', kind='threads', groups=24, depth=4, group_bytes=8192,
         src=(17408, 18432), dst=(22528, 23552), ce_fail='none', ce_delay_us=0,
         timeout_ms=60000, expect='exact'),
    dict(name='iou-procs', kind='procs', groups=24, depth=4, group_bytes=8192,
         src=(19456, 20480), dst=(24576, 25600), ce_fail='none', ce_delay_us=0,
         timeout_ms=60000, expect='exact'),
    # 7 s per CE transfer: past the kernel's 5 s STOP drain bound.
    dict(name='iou-retain', kind='retain', groups=2, depth=2, group_bytes=8192,
         src=(21504,), dst=(26624,), ce_fail='none', ce_delay_us=7000000,
         timeout_ms=60000, expect='either'),
    dict(name='iou-zombie', kind='zombie', groups=4, depth=2, group_bytes=8192,
         src=(22528,), dst=(28672,), ce_fail='ambiguous', ce_delay_us=0,
         timeout_ms=20000, expect='untouched'),
)
EBUSY = '-16'
STATE_ACTIVE, STATE_ERROR, STATE_ZOMBIE = '1', '2', '5'

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'xdev_ext_integration'))
from xdev_ext_mech_zc_debug import debug_reports  # noqa: E402  (existing harness oracle)


def frames_per_group(p):
    return -(-p['group_bytes'] // SEG)


def shell_plan():
    """One line per scenario: name:api:mode:slba:nlb:groups:depth:bytes:wire:sport:dport:off:expect."""
    return ''.join('{name}:{api}:{mode}:{slba}:{nlb}:{groups}:{depth}:{group_bytes}:{wire}:'
                   '{src_port}:{dst_port}:{dst_offset}:{expect}\n'.format(**p) for p in PLANS)


def shell_plan_iou():
    """name:kind:groups:depth:bytes:src1:dst1:src2:dst2:ce_fail:ce_delay_us:timeout_ms:expect."""
    out = ''
    for p in IOU_PLANS:
        second = (p['src'][1], p['dst'][1]) if len(p['src']) > 1 else ('-', '-')
        out += (f"{p['name']}:{p['kind']}:{p['groups']}:{p['depth']}:{p['group_bytes']}:"
                f"{p['src'][0]}:{p['dst'][0]}:{second[0]}:{second[1]}:{p['ce_fail']}:"
                f"{p['ce_delay_us']}:{p['timeout_ms']}:{p['expect']}\n")
    return out


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
    for p in IOU_PLANS:
        if p['expect'] == 'exact':
            n = p['groups'] * p['group_bytes']
            for s, d in zip(p['src'], p['dst']):
                dest[d * LBA:d * LBA + n] = source[s * LBA:s * LBA + n]
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
    s = fields(one(lines, f"XDEV_EXT_LIB_STATS api={p['api']} ", f"{p['name']} negative stats line"))
    # The wait snapshot may precede the drain (inflight > 0); STOP then
    # returns 0 or, after a full release, the session's final error.
    if (int(r.get('ret', '0')) >= 0 or r.get('retained') != '0' or
            r.get('stop_err') not in ('0', s.get('last_err'))):
        raise ValueError(f"{p['name']} negative result: {r}")
    if s.get('sequestered') != '0' or s.get('last_err') == '0':
        raise ValueError(f"{p['name']} negative stats: {s}")


def iou_stats(span, p, idx, phase):
    s = fields(one(span, f"XDEV_EXT_LIB_IOU_STATS name={p['name']} idx={idx} phase={phase} ",
                   f"{p['name']} idx {idx} {phase} stats line"))
    s['submitted'] = [int(x) for x in s['submitted'].split('/')]
    s['completed'] = [int(x) for x in s['completed'].split('/')]
    return s


def iou_result(span, p, idx):
    return fields(one(span, f"XDEV_EXT_LIB_IOU_RESULT name={p['name']} idx={idx} ",
                      f"{p['name']} idx {idx} result line"))


def check_iou_exact(span, p):
    g, sessions = p['groups'], set()
    for idx in range(len(p['src'])):
        r = iou_result(span, p, idx)
        want = dict(ret='0', wait_err='0', stop_err='0', close_err='0', retained='0')
        if any(r.get(k) != val for k, val in want.items()) or int(r.get('session', '0')) <= 0:
            raise ValueError(f"{p['name']} idx {idx} result line: {r}")
        sessions.add(r['session'])
        s = iou_stats(span, p, idx, 'wait')
        want = dict(state=STATE_ACTIVE, last_err='0', batches_done=str(g), batches_abort='0',
                    rejects='0', sequestered='0', timeouts='0', inflight='0', protocol_err='0')
        if (any(s.get(k) != val for k, val in want.items()) or s['session'] != r['session'] or
                s['submitted'] != [g, g, 0, 0] or s['completed'] != [g, g, 0, 0]):
            raise ValueError(f"{p['name']} idx {idx} stats line: {s}")
        if p['kind'] == 'procs':
            c = fields(one(span, f"XDEV_EXT_LIB_IOU_CHILD name={p['name']} idx={idx} ",
                           f"{p['name']} child line"))
            if c.get('exit') != '0':
                raise ValueError(f"{p['name']} child {idx}: {c}")
    if len(sessions) != len(p['src']):
        raise ValueError(f"{p['name']} sessions not distinct: {sorted(sessions)}")


def check_iou_retain(span, p):
    """STOP while accepted CE transfers outlast the drain bound: kept, then released."""
    g, n = p['groups'], p['name']
    s = iou_stats(span, p, 0, 'before-stop')
    if (s['state'] != STATE_ACTIVE or int(s['inflight']) == 0 or s['sequestered'] != '0' or
            s['submitted'][1] <= s['completed'][1] or s['submitted'][3] or s['completed'][3]):
        raise ValueError(f"{n} before-stop stats: {s}")
    r = fields(one(span, f"XDEV_EXT_LIB_RETAIN name={n} phase=stop ", f"{n} stop line"))
    if r != dict(name=n, phase='stop', stop=EBUSY, retained='1'):
        raise ValueError(f"{n} stop: {r}")
    r = fields(one(span, f"XDEV_EXT_LIB_RETAIN name={n} phase=stats-after-stop ", f"{n} stats-after-stop line"))
    if r.get('stats') != '0':
        raise ValueError(f"{n} stats-after-stop: {r}")
    s = iou_stats(span, p, 0, 'after-stop')
    if (s['state'] == STATE_ACTIVE or int(s['inflight']) == 0 or s['sequestered'] != '0' or
            s['submitted'][3] > g):
        raise ValueError(f"{n} after-stop stats: {s}")
    r = fields(one(span, f"XDEV_EXT_LIB_RETAIN name={n} phase=close-held ", f"{n} close-held line"))
    if r.get('close') != EBUSY:
        raise ValueError(f"{n} close-held: {r}")
    r = fields(one(span, f"XDEV_EXT_LIB_RETAIN name={n} phase=released ", f"{n} released line"))
    if r.get('close') != '0':
        raise ValueError(f"{n} released: {r}")
    r = iou_result(span, p, 0)
    if r.get('ret') != '0' or r.get('stop_err') != EBUSY or r.get('close_err') != '0' or r.get('retained') != '1':
        raise ValueError(f"{n} idx 0 result line: {r}")


def check_iou_zombie(span, p):
    """Ambiguous CE outcomes: sequestered, quarantined, close refuses for good."""
    n = p['name']
    r = iou_result(span, p, 0)
    if (r.get('ret') != '0' or r.get('wait_err') in (None, '0') or r.get('stop_err') != EBUSY or
            r.get('close_err') != EBUSY or r.get('retained') != '1'):
        raise ValueError(f"{n} wait/result line: {r}")
    s = iou_stats(span, p, 0, 'error')
    if (s['state'] == STATE_ACTIVE or int(s['sequestered']) == 0 or s['last_err'] == '0' or
            s['batches_done'] != '0' or s['submitted'][3] or s['completed'][3]):
        raise ValueError(f"{n} error stats: {s}")
    z = fields(one(span, f"XDEV_EXT_LIB_ZOMBIE name={n} phase=stop ", f"{n} stop line"))
    if z != dict(name=n, phase='stop', stop=EBUSY, retained='1', stats='0'):
        raise ValueError(f"{n} stop: {z}")
    for phase in ('after-stop', 'after-close'):
        s = iou_stats(span, p, 0, phase)
        if (s['state'] != STATE_ZOMBIE or int(s['sequestered']) == 0 or s['submitted'][3] or
                s['completed'][3]):
            raise ValueError(f"{n} {phase} stats: {s}")
    z = fields(one(span, f"XDEV_EXT_LIB_ZOMBIE name={n} phase=close ", f"{n} close line"))
    if z != dict(name=n, phase='close', close1=EBUSY, close2=EBUSY, stats='0'):
        raise ValueError(f"{n} close: {z}")


IOU_CHECKS = dict(single=check_iou_exact, threads=check_iou_exact, procs=check_iou_exact,
                  retain=check_iou_retain, zombie=check_iou_zombie)


def check_iou_scenario(span, m, p):
    if m.get('tx_exit') != '0' or m.get('rx_exit') != 'none':
        raise ValueError(f"{p['name']} scenario exits: {m}")
    IOU_CHECKS[p['kind']](span, p)
    one(span, f"XDEV_EXT_LIB_IOU_EXIT name={p['name']} ret=0 ", f"{p['name']} exit line")


def check_log(text):
    # Each scenario's lines are the span after the previous scenario marker.
    report = scenario_report(text)
    errors = [e for e in report.values() if e != 'PASS']
    if errors:
        raise ValueError('; '.join(errors))
    exits = re.findall(r'^XDEV_EXT_LIB_GUEST_EXIT=(\d+)$', text, re.M)
    if exits != ['0']:
        raise ValueError(f'guest exit status {exits}')
    reports = debug_reports(text)
    if any(reports.values()):
        raise ValueError('kernel debug diagnostic: ' + json.dumps(reports, sort_keys=True))
    return dict(scenarios=list(report), **{'debug_' + k: n for k, n in reports.items()})


def scenario_report(text):
    """Every scenario's verdict, so one failure does not hide the others."""
    lines = text.splitlines()
    report, start = {}, 0
    for p in PLANS + IOU_PLANS:
        mark = [i for i, line in enumerate(lines) if line.startswith(f"XDEV_EXT_LIB_SCENARIO name={p['name']} ")]
        if len(mark) != 1 or mark[0] < start:
            report[p['name']] = f"{p['name']} scenario marker: {len(mark)}"
            continue
        span, start = lines[start:mark[0]], mark[0] + 1
        try:
            (check_iou_scenario if 'kind' in p else check_scenario)(span, fields(lines[mark[0]]), p)
            report[p['name']] = 'PASS'
        except ValueError as error:
            report[p['name']] = str(error)
    return report


def check_scenario(span, m, p):
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


def check_images(source_after, dest_after):
    if len(source_after) != DISK_BYTES or len(dest_after) != DISK_BYTES:
        raise ValueError('image size mismatch')
    original = source_pattern()
    if source_after != original:
        raise ValueError(f'source image changed at byte {first_difference(source_after, original)}')
    expected = bytearray(expected_destination(original))
    # 'either' windows: accept each group as source or guard, then compare all.
    for p in IOU_PLANS:
        if p['expect'] != 'either':
            continue
        gb = p['group_bytes']
        for s, d in zip(p['src'], p['dst']):
            for g in range(p['groups']):
                got = dest_after[d * LBA + g * gb:d * LBA + (g + 1) * gb]
                src = original[s * LBA + g * gb:s * LBA + (g + 1) * gb]
                if got == src:
                    expected[d * LBA + g * gb:d * LBA + (g + 1) * gb] = src
                elif got != bytes([DEST_GUARD]) * gb:
                    raise ValueError(f"{p['name']} group {g} is neither the source group nor untouched")
    if dest_after != expected:
        raise ValueError(f'destination image differs at byte {first_difference(dest_after, bytes(expected))}')
    return dict(checked_bytes=sum(p['groups'] * p['group_bytes'] for p in PLANS if p['expect'] == 'pass') +
                sum(p['groups'] * p['group_bytes'] * len(p['dst']) for p in IOU_PLANS))


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
    sub.add_parser('plan-iou')
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
    if args.action == 'plan-iou':
        sys.stdout.write(shell_plan_iou())
        return 0
    result = dict(verdict='FAIL')
    log_text = args.log.read_text(errors='replace')
    result['scenario_results'] = scenario_report(log_text)
    try:
        result.update(check(log_text, args.source.read_bytes(),
                            args.dest.read_bytes()))
        result['verdict'] = 'PASS'
    except ValueError as error:
        result['error'] = str(error)
    args.result.write_text(json.dumps(result, sort_keys=True) + '\n')
    print('XDEV_EXT_LIB_HOST=' + result['verdict'] + ' ' + json.dumps(result, sort_keys=True))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())

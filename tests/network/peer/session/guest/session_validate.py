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
# copies: NONE nothing reaches the destination; ALL every group is copied;
# PART (teardown in flight) each group is the source group or untouched guard.
NONE, ALL, PART = 0, 1, 2
# Kept in step with peer_session_e2e.c by the PLAN-line comparison below.
PLANS = (
    dict(name='reject-map', frame=4096, seg=4096, group=4096, depth=1, groups=4,
         src_slba=2048, dst_slba=16384, copies=NONE),
    dict(name='cli', frame=65536, seg=16384, group=16384, depth=1, groups=64,
         src_slba=2048, dst_slba=4096, copies=ALL),
    dict(name='depth4', frame=4096, seg=4096, group=8192, depth=4, groups=96,
         src_slba=8192, dst_slba=10240, copies=ALL),
    dict(name='stop-inflight', frame=4096, seg=4096, group=4096, depth=4, groups=1024,
         src_slba=16384, dst_slba=18432, copies=PART),
    dict(name='kill-inflight', frame=4096, seg=4096, group=4096, depth=4, groups=512,
         src_slba=24576, dst_slba=26624, copies=PART),
    dict(name='fd-release', frame=32768, seg=32768, group=32768, depth=2, groups=8,
         src_slba=12288, dst_slba=14336, copies=ALL),
    dict(name='epoch-4k-0', frame=4096, seg=4096, group=4096, depth=1, groups=1,
         src_slba=512, dst_slba=512, copies=ALL),
    dict(name='epoch-4k-1', frame=4096, seg=4096, group=4096, depth=1, groups=1,
         src_slba=528, dst_slba=528, copies=ALL),
    dict(name='epoch-64k-0', frame=65536, seg=65536, group=65536, depth=1, groups=1,
         src_slba=768, dst_slba=768, copies=ALL),
    dict(name='epoch-64k-1', frame=65536, seg=65536, group=65536, depth=1, groups=1,
         src_slba=1024, dst_slba=1024, copies=ALL),
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
        if p['copies'] == ALL:
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
    expected = bytearray(expected_destination(original))
    partial = {}
    for p in PLANS:
        if p['copies'] != PART:
            continue
        copied = 0
        for g in range(p['groups']):
            s, d = p['src_slba'] * LBA + g * p['group'], p['dst_slba'] * LBA + g * p['group']
            if dest_after[d:d + p['group']] == original[s:s + p['group']]:
                expected[d:d + p['group']] = original[s:s + p['group']]
                copied += 1
        partial[p['name']] = copied
    if dest_after != expected:
        raise ValueError(f'destination image differs at byte {first_difference(dest_after, bytes(expected))}')
    return dict(source_bytes=len(source_after), destination_bytes=len(dest_after),
                copied_bytes=sum(plan_bytes(p) for p in PLANS if p['copies'] == ALL),
                partial_groups_copied=partial)


def native_observations(lines):
    observed = {}
    for p, action in ((PLANS[3], 'STOP'), (PLANS[4], 'SIGKILL')):
        prefix = f"# {p['name']} before {action}: "
        samples = [(i, line) for i, line in enumerate(lines) if line.startswith(prefix)]
        if len(samples) != 1:
            raise ValueError(f"native inflight observation missing or duplicated for {p['name']}")
        index, line = samples[0]
        match = re.fullmatch(re.escape(prefix) +
                             r'done=(\d+) abort=(\d+) inflight=(\d+) sequestered=(\d+) '
                             r'submitted=(\d+)/(\d+) completed=(\d+)/(\d+) last_err=(-?\d+) state=(\d+)', line)
        if not match:
            raise ValueError(f"native inflight observation malformed for {p['name']}")
        done, abort, inflight, sequestered, s0, s1, c0, c1, error, state = map(int, match.groups())
        if not (state == 1 and not error and not sequestered and
                done + abort < p['groups'] and 0 < inflight <= p['depth'] and
                c0 <= s0 <= p['groups'] and c1 <= s1 <= p['groups'] and
                (s0 > c0 or s1 > c1)):
            raise ValueError(f"native inflight observation invalid for {p['name']}: {line}")
        if action == 'STOP':
            actions = [i for i, text in enumerate(lines)
                       if re.fullmatch(r'# stop-inflight STOP returned (0|-125)', text)]
        else:
            actions = [i for i, text in enumerate(lines)
                       if re.fullmatch(r'ok \d+ - kill-inflight: owner died of SIGKILL', text)]
        if len(actions) != 1 or index >= actions[0]:
            raise ValueError(f"native inflight observation must precede teardown for {p['name']}")
        observed[p['name']] = dict(done=done, abort=abort, inflight=inflight,
                                  submitted=[s0, s1], completed=[c0, c1], state=state)
    return observed


def epoch_observations(lines):
    """Require every one-group epoch and its retained mapping/last-fd proof."""
    cases = PLANS[6:]
    samples = [line for line in lines if line.startswith(('# epoch ', '# epoch-provider '))]
    if len(samples) != 2 * len(cases) + 1:
        raise ValueError('epoch receipt missing, duplicated or unknown')

    def fields(line, prefix):
        if not line.startswith(prefix):
            raise ValueError('epoch receipt missing or out of order: ' + prefix)
        pairs = [part.split('=', 1) for part in line[len(prefix):].split()]
        if any(len(pair) != 2 for pair in pairs) or len({p[0] for p in pairs}) != len(pairs):
            raise ValueError('epoch receipt fields malformed or duplicated')
        return dict(pairs)

    fixed = dict(helper='shared', raw_uapi='1', ready='EXTERNAL_READY', gpu_applicable='0',
                 groups='1', create='0', claim_busy='-16', start='0', stop='0', stop_proved='1',
                 stats_valid='1', transport_valid='1', done='1', abort='0', rejects='0',
                 timeouts='0', protocol_err='0', last_err='0', inflight='0', sequestered='0',
                 native_controls='0', pending_acks='0', uncertain_controls='0', native_safe='1',
                 held='0', epoch_closed='1')
    counter_names = {'pins', 'unpins', 'maps', 'unmaps', 'live_pins', 'live_maps'}

    def counters(line, prefix):
        values = fields(line, prefix)
        if set(values) != counter_names or any(not re.fullmatch(r'\d+', x) for x in values.values()):
            raise ValueError('epoch provider counters malformed')
        return {k: int(x) for k, x in values.items()}

    cached = None
    for i, p in enumerate(cases):
        name = p['name']
        values = fields(samples[2 * i], f'# epoch {name}: ')
        if values != dict(fixed, first_seq=str(i)):
            raise ValueError('epoch snapshot invalid for ' + name)
        counts = counters(samples[2 * i + 1], f'# epoch {name} provider: ')
        if (counts['live_pins'] != 1 or counts['live_maps'] != 2 or
                counts['pins'] - counts['unpins'] != 1 or
                counts['maps'] - counts['unmaps'] != 2):
            raise ValueError('epoch cached pin/map accounting invalid for ' + name)
        if cached is not None and counts != cached:
            raise ValueError('epoch registration mapping cache changed for ' + name)
        cached = counts
    final = counters(samples[-1], '# epoch-provider last-close: ')
    if (final['live_pins'] or final['live_maps'] or
            final['pins'] != cached['pins'] or final['maps'] != cached['maps'] or
            final['unpins'] != cached['unpins'] + 1 or
            final['unmaps'] != cached['unmaps'] + 2 or
            final['pins'] != final['unpins'] or final['maps'] != final['unmaps']):
        raise ValueError('epoch last allocation fd close did not balance pin/map counts')
    return dict(cases=[p['name'] for p in cases], cached=cached, last_close=final)


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
    marker = next(line for line in lines if line.startswith(PASS_PREFIX + ' '))
    case_field = re.search(r'(?:^| )cases=([^ ]+)(?: |$)', marker)
    if not case_field or case_field[1].split(',') != [p['name'] for p in PLANS]:
        raise ValueError('session PASS case list missing, duplicated or different')
    if UNLOAD_MARKER not in lines:
        raise ValueError('provider unload marker missing')
    exits = EXIT_RE.findall(text)
    if exits != ['0']:
        raise ValueError(f'guest exit status {exits}')
    reports = debug_reports(text)
    if any(reports.values()):
        raise ValueError('kernel debug diagnostic: ' + json.dumps(reports, sort_keys=True))
    return dict(ok=len(oks), not_ok=0, skip=0, epoch_observations=epoch_observations(lines),
                native_inflight_observations=native_observations(lines),
                **{'debug_' + k: n for k, n in reports.items()})


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

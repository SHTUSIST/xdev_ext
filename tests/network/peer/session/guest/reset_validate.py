#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-side oracle for the guest reset-recovery test (peer_reset_e2e).

Keeps its own copy of the case plan: every case must report PASS with its
exact check count, numbered without gaps, with no not-ok/skip line, and the
provider module must unload after the last case. The kernel console must be
free of every debug report family the KVM harness rejects. Correctness only:
no timing is read or reported, and nothing here is about physical DMA.
"""
import argparse
import json
from pathlib import Path
import re
import sys

# Case -> check count, kept in step with peer_reset_e2e.c: four common
# checks (opt-in, devices, two liveness waits) plus the case's own.
CASES = (('control', 9), ('error-status', 13), ('timeout-cancel', 10), ('owner-open', 10))
UNLOAD_MARKER = 'XDEV_EXT_PEER_RESET_UNLOAD=PASS module=xdev_ext_peer_sw'
EXIT_RE = re.compile(r'^XDEV_EXT_RESET_GUEST_EXIT=(\d+)$', re.M)
CASE_RE = re.compile(r'^XDEV_EXT_PEER_RESET_CASE=(\S+) (PASS|FAIL)(?: checks=(\d+))?$')

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'xdev_ext_integration'))
from xdev_ext_mech_zc_debug import debug_reports  # noqa: E402  (existing harness oracle)


def check_log(text):
    lines = [line.rstrip('\r') for line in text.splitlines()]
    if any(re.match(r'^not ok\b', line) for line in lines):
        raise ValueError('TAP not ok present: ' + next(l for l in lines if l.startswith('not ok')))
    if any(re.match(r'^ok \d+ .*#\s*(SKIP|TODO)', line, re.I) for line in lines):
        raise ValueError('TAP skip/todo directive present')
    verdicts = [CASE_RE.match(line) for line in lines]
    verdicts = [m for m in verdicts if m]
    got = [(m[1], m[2], int(m[3]) if m[3] else None) for m in verdicts]
    want = [(name, 'PASS', count) for name, count in CASES]
    if got != want:
        raise ValueError('case verdicts %s differ from plan %s' % (got, want))
    for name, count in CASES:
        numbers = [int(m[1]) for m in (re.match(r'^ok (\d+) - ' + re.escape(name) + ': ', l)
                                       for l in lines) if m]
        if numbers != list(range(1, count + 1)):
            raise ValueError('case %s ok lines %s are not 1..%d' % (name, numbers, count))
    if UNLOAD_MARKER not in lines:
        raise ValueError('provider unload marker missing')
    exits = EXIT_RE.findall(text)
    if exits != ['0']:
        raise ValueError('guest exit status %s' % exits)
    reports = debug_reports(text)
    if any(reports.values()):
        raise ValueError('kernel debug diagnostic: ' + json.dumps(reports, sort_keys=True))
    return dict(cases=[name for name, _ in CASES], checks=sum(c for _, c in CASES),
                **{'debug_' + k: n for k, n in reports.items()})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', type=Path, required=True)
    ap.add_argument('--result', type=Path, required=True)
    args = ap.parse_args()
    result = dict(verdict='FAIL')
    try:
        result.update(check_log(args.log.read_text(errors='replace')))
        result['verdict'] = 'PASS'
    except ValueError as error:
        result['error'] = str(error)
    args.result.write_text(json.dumps(result, sort_keys=True) + '\n')
    print('XDEV_EXT_PEER_RESET_HOST=' + result['verdict'] + ' ' + json.dumps(result, sort_keys=True))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())

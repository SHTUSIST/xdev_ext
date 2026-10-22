#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Focused guest debug profile identity and actual console diagnostic checks."""
import hashlib
import json
from pathlib import Path
import re
import sys

REQUIRED = ('DEBUG_KERNEL', 'PROVE_LOCKING', 'LOCKDEP', 'DEBUG_ATOMIC_SLEEP',
            'KASAN', 'KASAN_GENERIC', 'DETECT_HUNG_TASK')


def check_config(text, enabled):
    values = dict(re.findall(r'^CONFIG_([A-Z0-9_]+)=(\S+)$', text, re.M))
    if enabled:
        missing = [key for key in REQUIRED if values.get(key) != 'y']
        if missing:
            raise ValueError('debug kernel config missing: ' + ','.join(missing))
        if values.get('KASAN_KUNIT_TEST') == 'y':
            raise ValueError('deliberate KASAN KUnit error reports must be disabled')
    elif any(values.get(key) == 'y' for key in
             ('PROVE_LOCKING', 'DEBUG_ATOMIC_SLEEP', 'KASAN', 'KASAN_GENERIC')):
        raise ValueError('debug kernel cannot certify the default profile')


def identity(config, enabled):
    data = config.read_bytes()
    check_config(data.decode(), enabled)
    return dict(debug_locking=bool(enabled), config_sha256=hashlib.sha256(data).hexdigest())


def record_identity(config, profile, enabled):
    profile.write_text(json.dumps(identity(config, enabled), sort_keys=True) + '\n')


def check_identity(config, profile, enabled):
    if json.loads(profile.read_text()) != identity(config, enabled):
        raise ValueError('run-only debug profile or kernel config identity mismatch')


def debug_reports(text):
    # Exact report families from kernel/locking/lockdep.c, plus detector
    # disable messages: instrumentation that switched itself off cannot pass.
    patterns = dict(
        lockdep=r'possible circular locking|possible recursive locking|inconsistent lock state|'
                r'inconsistent \{.*\}.*usage|possible irq lock inversion|bad unlock balance|'
                r'held lock freed|suspicious RCU usage|Nested lock was not taken|'
                r'bad contention detected|still has locks held|lock held when returning to user space|'
                r'\S+-safe -> \S+-unsafe lock order detected|'
                r'turning off the locking correctness validator|lockdep is turned off',
        atomic_sleep=r'sleeping function called from invalid context|scheduling while atomic',
        kasan=r'BUG: KASAN', hung=r'blocked for more than')
    counts = dict.fromkeys((*patterns, 'diagnostic'), 0)
    for line in text.splitlines():
        matched = False
        for kind, pattern in patterns.items():
            if re.search(pattern, line):
                counts[kind] += 1
                matched = True
        # Preserve a truthful FAIL sub-verdict for an unclassified kernel
        # report, even when no known lockdep/KASAN family matches it.
        if not matched and re.search(r'BUG:|WARNING:|Oops:|Kernel panic', line):
            counts['diagnostic'] += 1
    return counts


def check_console(text):
    counts = debug_reports(text)
    if any(counts.values()):
        raise ValueError('kernel debug diagnostic: ' + json.dumps(counts, sort_keys=True))
    return counts


def main():
    action, source, output, enabled = sys.argv[1:]
    if enabled not in ('0', '1'):
        raise ValueError('debug profile must be 0 or 1')
    source, output, enabled = Path(source), Path(output), enabled == '1'
    if action == 'record':
        record_identity(source, output, enabled)
    elif action == 'reuse':
        check_identity(source, output, enabled)
    elif action == 'config':
        check_config(source.read_text(), enabled)
    elif action == 'console':
        counts = debug_reports(source.read_text())
        output.write_text(json.dumps(dict(enabled=enabled, **counts), sort_keys=True) + '\n')
        verdict = 'FAIL' if any(counts.values()) else 'PASS'
        print(f'XDEV_EXT_MECH_LOCKDEP={verdict} enabled={int(enabled)} ' +
              ' '.join(f'{kind}={count}' for kind, count in counts.items()))
        return int(verdict == 'FAIL')
    else:
        raise ValueError('unknown debug action: ' + action)
    return 0


if __name__ == '__main__':
    sys.exit(main())

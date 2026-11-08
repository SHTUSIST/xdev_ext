#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile and run recovery_cases.c against the actual peer region core.

The test unit is the actual src/core/io_uring/xdev_ext_peer.c (host-test
mode) plus the actual allocation-fd close from xdev_ext_peer_fd.c, built with
the shared peer host shim, under UBSan and ASan. Exit 0 PASS, 1 FAIL, 2 SETUP
(compile/extraction error, never a behavioural verdict). No device, no DMA.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
CORE = 'src/core/io_uring/xdev_ext_peer.c'
FD = 'src/core/io_uring/xdev_ext_peer_fd.c'
STORFAM = 'src/storage/io_uring/family/xdev_ext_storfam.c'
HEADER = 'src/core/include/linux/xdev_ext_peer.h'
SHIM = 'tests/network/peer/session/xdev_ext_peer_test_shim.h'
PROFILES = (
    ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=undefined']),
    ('asan', ['-O1', '-g', '-fsanitize=address', '-fno-omit-frame-pointer']),
)


class Setup(Exception):
    pass


def block(text, pattern):
    match = re.search(pattern, text, re.M)
    if not match:
        raise Setup('missing actual source block: ' + pattern)
    i = text.index('{', match.start()) + 1
    depth = 1
    while depth and i < len(text):
        depth += (text[i] == '{') - (text[i] == '}')
        i += 1
    if depth:
        raise Setup('unbalanced actual source block: ' + pattern)
    return text[match.start():i]


def assemble(root, core=None, fd=None, storfam=None):
    """One translation unit: shim, actual core, actual fd close and lease
    releases, the actual storage-family UNKNOWN retirement, cases."""
    root = Path(root)
    core = (root / CORE).read_text() if core is None else core
    fd = (root / FD).read_text() if fd is None else fd
    storfam = (root / STORFAM).read_text() if storfam is None else storfam
    shim = (root / SHIM).read_text()
    plain_file = 'struct file { const struct file_operations *f_op; int refs; };'
    if shim.count(plain_file) != 1:
        raise Setup('shim struct file anchor')
    shim = shim.replace(plain_file, 'struct file { const struct file_operations *f_op; int refs; '
                        'void *private_data; };')
    relative = '#include "../include/linux/xdev_ext_peer.h"'
    if core.count(relative) != 1:
        raise Setup('core host-test include anchor')
    core = core.replace(relative, '#include "' + str(root / HEADER) + '"')
    pieces = [
        '#include <assert.h>\n#include <stdio.h>\n#include <string.h>\n',
        shim,
        'struct inode;\n#define list_for_each_entry_safe(p,n,h,m) for (p=container_of((h)->next,'
        '__typeof__(*p),m), n=container_of(p->m.next,__typeof__(*p),m); &p->m!=(h); '
        'p=n,n=container_of(n->m.next,__typeof__(*n),m))\n',
        '#define XDEV_EXT_PEER_HOST_TEST\n', core, '\n',
        'struct xdev_ext_peer_authority;\n',
        block(fd, r'^struct xdev_ext_peer_fd \{') + ';\n',
        block(fd, r'^struct xdev_ext_peer_fd_map \{') + ';\n',
        block(fd, r'^static int xdev_ext_peer_fd_close\(') + '\n',
        block(fd, r'^void xdev_ext_peer_fd_release\(') + '\n',
        block(fd, r'^bool xdev_ext_peer_fd_release_unknown\(') + '\n',
        block(storfam, r'^bool xdev_ext_stor_leases_retire_unknown\(') + '\n',
        (HERE / 'recovery_cases.c').read_text(),
    ]
    return ''.join(pieces)


def run_unit(source, directory, name='recovery'):
    """Returns (verdict, log, checks) over every sanitizer profile."""
    path = Path(directory) / (name + '.c')
    path.write_text(source)
    log, checks = [], None
    for profile, flags in PROFILES:
        binary = Path(directory) / (name + '-' + profile)
        command = ['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread', *flags,
                   str(path), '-o', str(binary)]
        built = subprocess.run(command, capture_output=True, text=True)
        log.append('$ ' + ' '.join(command) + '\n' + built.stdout + built.stderr)
        if built.returncode:
            return 'SETUP', '\n'.join(log), checks
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=0',
                   UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1')
        try:
            result = subprocess.run([str(binary)], capture_output=True, text=True, env=env, timeout=60)
        except subprocess.TimeoutExpired as expired:
            # A unit that never finishes is a behavioural failure, not a pass.
            log.append('# profile %s timed out after 60 s\n%s' % (profile, expired.stdout or ''))
            return 'FAIL', '\n'.join(log), checks
        log.append('# profile ' + profile + ' exit ' + str(result.returncode) + '\n' +
                   result.stdout + result.stderr)
        plan = re.findall(r'^1\.\.(\d+)$', result.stdout, re.M)
        oks = len(re.findall(r'^ok \d+ ', result.stdout, re.M))
        if result.returncode or 'not ok' in result.stdout or len(plan) != 1 or int(plan[0]) != oks:
            return 'FAIL', '\n'.join(log), checks
        checks = oks
    return 'PASS', '\n'.join(log), checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=HERE.parents[2])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = args.source_root.resolve()
    record = {'scope': 'host software state machine only; no device, DMA, IOMMU or timing'}
    try:
        record['inputs'] = {p: hashlib.sha256((root / p).read_bytes()).hexdigest()
                            for p in (CORE, FD, STORFAM, HEADER, SHIM)}
        record['inputs']['tests/core/peer_quarantine/recovery_cases.c'] = hashlib.sha256(
            (HERE / 'recovery_cases.c').read_bytes()).hexdigest()
        source = assemble(root)
    except (Setup, OSError) as error:
        print('SETUP peer-quarantine ' + str(error))
        return 2
    with tempfile.TemporaryDirectory(prefix='peer-quarantine-') as directory:
        verdict, log, checks = run_unit(source, directory)
    print(log)
    record.update(verdict=verdict, checks=checks, profiles=[p for p, _ in PROFILES])
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'output.log').write_text(log)
        (args.output / 'unit.c').write_text(source)
        (args.output / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
    print('%s peer-quarantine checks=%s profiles=%d' % (verdict, checks, len(PROFILES)))
    return {'PASS': 0, 'FAIL': 1}.get(verdict, 2)


if __name__ == '__main__':
    sys.exit(main())

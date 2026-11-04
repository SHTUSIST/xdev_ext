#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real child command producing ordinary archive inputs, never guest evidence."""
import argparse
import hashlib
import json
import shlex
from pathlib import Path
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(scratch, source, specification, label):
    spec = json.loads(Path(specification).read_text())
    # Record every actual launch, including a launch rejected before writes.
    with (scratch / 'recording-launches.jsonl').open('a') as stream:
        stream.write(json.dumps(sys.argv[1:]) + '\n')
    # A wrapper's next child must see case1 frozen before any live overwrite.
    index = scratch / 'recording-invocations.jsonl'
    earlier = index.read_text().splitlines() if index.exists() else []
    if earlier and spec.get('check_prior_archive'):
        cases = list((scratch / 'acceptance/cases').glob('*/archive-files.json'))
        if len(cases) < len(earlier):
            raise RuntimeError('next child started before preceding case freeze')
        for manifest in cases:
            hashes = json.loads(manifest.read_text())
            for name, expected in hashes.items():
                target = manifest.parent / name
                if digest(target) != expected:
                    raise RuntimeError('previous frozen case changed before next child')
    with index.open('a') as stream:
        stream.write(json.dumps(sys.argv[1:]) + '\n')
    generated = {
        'source-before.raw', 'source.raw', 'destination-before.raw', 'destination.raw',
        'expected.raw', 'compat.raw', 'peer.raw', 'initramfs.cpio.gz',
        'build/.config', 'build/Module.symvers', 'build/include/config/kernel.release',
        'build/arch/x86/boot/bzImage', 'tools/actual-tool',
        'evidence/guest.log', 'evidence/qemu.exit', 'evidence/qemu.command',
        'evidence/nested/actual-events.log',
    }
    for name in generated:
        path = scratch / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(('archive-recording-only:' + label + ':' + name + '\n').encode())
    (scratch / 'build/xdev-ext-source.commit').write_text(spec['revision'] + '\n')
    (scratch / 'build/xdev-ext-debug-profile.json').write_text(json.dumps({'recording_only': label}) + '\n')
    if spec.get('e2_metadata'):
        (scratch / 'build/xdev-ext-e2-mode.txt').write_text('mechanism_variants=1\nsource_commit=' + spec['revision'] + '\n')
    if 'recorded_qemu_argv' in spec:
        # This is a parser/archive input only; it is never executed and is never
        # presented to a guest oracle as a successful QEMU run.
        (scratch / 'evidence/qemu.command').write_text(shlex.join(spec['recorded_qemu_argv']) + '\n')
        (scratch / 'evidence/e2-artifacts.raw.log').write_bytes(b'ordinary B3 parser/archive transport bytes\n')
    for manifest, rows in spec['manifests'].items():
        output = scratch / manifest
        output.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for name, context in rows:
            target = Path(name) if Path(name).is_absolute() else Path(context) / name
            lines.append(digest(target) + '  ' + name + '\n')
        output.write_text(''.join(lines))
    print('RECORDING_CHILD label=' + label, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scratch', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--specification', required=True, type=Path)
    parser.add_argument('--label', default='first')
    parser.add_argument('--exit-code', default=0, type=int)
    args = parser.parse_args()
    record(args.scratch, args.source, args.specification, args.label)
    return args.exit_code


if __name__ == '__main__':
    sys.exit(main())

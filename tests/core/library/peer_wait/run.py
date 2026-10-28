#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Deterministic real-library CPU endpoint wait tests; no hardware or Git."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    test_dir = Path(__file__).resolve().parent
    root = (args.source_root or test_dir.parents[3]).resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    # Use the canonical layout owner; do not duplicate or modify its mapping.
    spec = importlib.util.spec_from_file_location('peer_wait_layout', root / 'tools/layout.py')
    layout_module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = layout_module
    spec.loader.exec_module(layout_module)
    layout = layout_module.load_layout(root)
    view = out / 'view'
    inputs = []
    for source, logical in layout.by_source.items():
        if logical.startswith('kernel/') and (source.endswith('.h') or source in (
                'src/lib/xdev_ext_session.c', 'src/lib/xdev_ext_user.c',
                'src/lib/xdev_ext_link.c', 'src/lib/xdev_ext_peer_message.c')):
            destination = view / logical
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / source, destination)
            inputs.append(source)
    (out / 'inputs.json').write_text(json.dumps({'canonical_root': str(root),
                                               'inputs': inputs}, indent=2) + '\n')
    kernel = view / 'kernel'
    lib = kernel / 'tools/xdev_ext_mech/lib'
    flags = ['-std=gnu11', '-O0', '-g', '-Wall', '-Wextra', '-Werror',
             '-I', str(kernel), '-I', str(lib)]
    compiler = os.environ.get('CC', 'gcc')
    objects = []
    with (out / 'build.log').open('w') as log:
        for unit in ('xdev_ext_session', 'xdev_ext_user', 'xdev_ext_link', 'xdev_ext_peer_message'):
            obj = out / (unit + '.o')
            command = [compiler, *flags]
            if unit == 'xdev_ext_user':
                command += ['-include', str(test_dir / 'wait_hooks.h')]
            command += ['-c', str(lib / (unit + '.c')), '-o', str(obj)]
            print('+', ' '.join(command), flush=True)
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
            objects.append(str(obj))
        binary = out / 'peer_wait_test'
        command = [compiler, *flags, str(test_dir / 'peer_wait_test.c'), *objects,
                   '-Wl,--wrap=poll', '-Wl,--wrap=clock_gettime', '-Wl,--wrap=nanosleep',
                   '-Wl,--wrap=read', '-Wl,--wrap=mmap', '-o', str(binary)]
        print('+', ' '.join(command), flush=True)
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    result = subprocess.run([str(binary)], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=15)
    (out / 'tap.log').write_text(result.stdout)
    print(result.stdout, end='')
    (out / 'verdict.json').write_text(json.dumps({'kind': 'host-cpu-wait-contract',
        'build_exit': 0, 'test_exit': result.returncode, 'environment': 'local host; injected kernel replies and controlled syscall/atomic boundaries',
        'scope': 'CPU endpoint event-wait correctness; no physical DMA or performance evidence'}, indent=2) + '\n')
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())

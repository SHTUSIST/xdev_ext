#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-frame endpoint: links the real endpoint object with a recorded session
layer (frame_endpoint_test.c). No io_uring, device, CE or XDOMAIN runs."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--no-sanitize', action='store_true')
    parser.add_argument('--source-view', type=Path, help='reuse one validated source view serially')
    args = parser.parse_args()
    here = Path(__file__).resolve()
    root = args.source_root.resolve() if args.source_root else next(
        p for p in here.parents if (p / 'tools/layout.py').is_file())
    sys.path.insert(0, str(root / 'tools'))
    from layout import load_layout, materialize_view
    out = (args.output or Path(tempfile.mkdtemp(prefix='frame-endpoint-'))).resolve()
    out.mkdir(parents=True, exist_ok=True)
    layout = load_layout(root)
    view = materialize_view(root, args.source_view or out / 'source-view').root
    lib = view / layout.logical('src/lib/libxdev_ext.h')
    test = view / layout.logical('tests/core/library/frame_endpoint_test.c')
    endpoint = lib.parent / 'xdev_ext_frame_endpoint.c'
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror']
    if not args.no_sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=undefined']
    binary = out / 'frame_endpoint_test'
    command = [*shlex.split(os.environ.get('CC', 'gcc')), *flags, '-I', str(lib.parent),
               str(test), str(endpoint), '-o', str(binary)]
    print('+', shlex.join(command), flush=True)
    if subprocess.run(command).returncode:
        print('SETUP: compile/link failed (not a behaviour result)')
        return 2
    return subprocess.run([str(binary)]).returncode


if __name__ == '__main__':
    raise SystemExit(main())

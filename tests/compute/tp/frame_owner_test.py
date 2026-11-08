#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-frame endpoint owner (frame_endpoint_owner.cc) under recorded CUDA,
OS, program and endpoint boundaries (frame_owner_boundary.cc). No GPU, CE,
XDOMAIN or device execution."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path)
    p.add_argument('--source-view', type=Path, help='reuse one validated source view serially')
    a = p.parse_args()
    root = a.source_root.resolve()
    out = (a.output or Path(tempfile.mkdtemp(prefix='tp-frame-owner-'))).resolve()
    out.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(root / 'tools'))
    from layout import load_layout, materialize_view
    layout = load_layout(root)
    view = materialize_view(root, a.source_view or out / 'source-view').root
    facade = out / 'boundary'
    facade.mkdir(exist_ok=True)
    shutil.copyfile(HERE / 'driver_boundary.h', facade / 'cuda.h')
    owner = view / layout.logical('src/compute/cuda/frame_endpoint_owner.cc')
    exe = out / 'frame-owner'
    cmd = [os.environ.get('CXX', 'g++'), '-std=c++17', '-O0', '-g', '-Wall', '-Wextra',
           '-Wno-unused-function', '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
           '-I' + str(facade), '-I' + str(view / 'kernel/include/uapi')]
    for name in ('src/lib/libxdev_ext.h', 'src/cli/include/xdev_ext_nv_p2p_ioctl.h',
                 'src/compute/cuda/frame_endpoint_owner.h'):
        cmd.append('-I' + str((view / layout.logical(name)).parent))
    cmd += ['-DTP_FRAME_OWNER_SOURCE="' + str(owner) + '"', str(HERE / 'frame_owner_boundary.cc'),
            '-o', str(exe)]
    built = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    (out / 'compile.log').write_text(built.stdout + built.stderr)
    result = {'scope': 'host frame owner with recorded boundaries; no device', 'command': cmd,
              'compile_exit': built.returncode}
    if built.returncode:
        print(built.stderr[-4000:])
        result.update(exit=2, state='SETUP_ERROR')
    else:
        run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60,
                             env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
        (out / 'run.log').write_text(run.stdout + run.stderr)
        print(run.stdout + run.stderr, end='')
        result.update(exit=run.returncode, state='SCOPED_PASS' if not run.returncode else 'BEHAVIOR_RED')
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result['exit']


if __name__ == '__main__':
    raise SystemExit(main())

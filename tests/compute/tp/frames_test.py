#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""TP host-frame d1 route: two ranks through loopback host-frame endpoints.

Compiles frames_boundary.cc with the unchanged production library and CUDA
kernels (run on the host) and controlled Driver/endpoint boundaries. Host
software evidence only: no GPU, copy engine, XDOMAIN or timing.
"""
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
    out = (a.output or Path(tempfile.mkdtemp(prefix='tp-frames-'))).resolve()
    out.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(root / 'tools'))
    from layout import load_layout, materialize_view
    layout = load_layout(root)
    view = materialize_view(root, a.source_view or out / 'source-view').root
    facade = out / 'driver-boundary'
    facade.mkdir(exist_ok=True)
    shutil.copyfile(HERE / 'driver_boundary.h', facade / 'cuda.h')
    production = view / layout.logical('src/compute/collectives/xdev_tp.cc')
    kernels = view / layout.logical('src/compute/collectives/xdev_tp.cu')
    exe = out / 'frames-boundary'
    sys.path.insert(0, str(HERE))
    from ce_place_test import endpoint_objects
    try:
        objects = endpoint_objects(root, view, layout, out)
    except (OSError, RuntimeError) as error:
        result = dict(scope='host TP host-frame d1 route; no device', exit=2,
                      state='SETUP_ERROR', error=str(error))
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('SETUP: ' + str(error))
        return 2
    cmd = [os.environ.get('CXX', 'g++'), '-std=c++17', '-O1', '-g', '-Wall', '-Wextra',
           '-Wno-unused-function', '-Wno-misleading-indentation', '-pthread',
           '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
           '-I' + str(facade),
           '-I' + str((view / layout.logical('src/lib/libxdev_ext.h')).parent),
           '-I' + str((view / layout.logical('src/compute/cuda/libxdev_ext_cuda.h')).parent),
           '-DTP_LIBRARY_SOURCE="' + str(production) + '"',
           '-DTP_KERNEL_SOURCE="' + str(kernels) + '"',
           str(HERE / 'frames_boundary.cc'), *objects, '-o', str(exe)]
    built = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    (out / 'compile.log').write_text(built.stdout + built.stderr)
    result = {'scope': 'host TP host-frame d1 route; no GPU, CE, XDOMAIN or timing',
              'command': cmd, 'compile_exit': built.returncode}
    if built.returncode:
        print(built.stderr[-4000:])
        result.update(exit=2, state='SETUP_ERROR')
    else:
        # The fake Driver never frees function handles and the retained-failure
        # case keeps its communicator by design; leaks are not under test here.
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
        run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=120, env=env)
        (out / 'run.log').write_text(run.stdout + run.stderr)
        print(run.stdout + run.stderr, end='')
        result.update(exit=run.returncode, state='SCOPED_PASS' if not run.returncode else 'BEHAVIOR_RED')
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result['exit']


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual native/CUDA source retirement of an unused captured template."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
CASES = ('never_replayed', 'slot_reuse', 'graph_held', 'stream_pending',
         'stream_unknown', 'read_unknown', 'begun_pending', 'wrong_key', 'partial_capture',
         'foreign_older', 'foreign_newer')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root, out = a.source_root.resolve(), a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    result = {'scope': 'complete actual native/CUDA source with frozen host Driver boundary; no GPU/SDK qualification', 'cases': []}
    try:
        spec = importlib.util.spec_from_file_location('never_replayed_layout', root / 'tools/layout.py')
        m = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = m
        spec.loader.exec_module(m)
        layout = m.load_layout(root)
        view = m.materialize_view(root, out / 'source-view')
        spec = importlib.util.spec_from_file_location('never_replayed_span', root / 'tests/core/admission_report/run.py')
        extract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(extract)
        (out / 'actual-span.inc').write_text(extract.function((root / 'src/lib/xdev_ext_user.c').read_text(), 'xdev_ext_user_batch_peer_span'))
        (out / 'empty.inc').write_text('// Complete actual library already included above frozen boundary.\n')
        facade = out / 'driver-boundary'
        facade.mkdir(exist_ok=True)
        shutil.copyfile(HERE / 'driver_boundary.h', facade / 'cuda.h')
        cmd = [os.environ.get('CXX', 'g++'), '-std=c++17', '-O0', '-g', '-Wall', '-Wextra',
               '-Wno-misleading-indentation', '-pthread', '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
               '-I' + str(facade), '-DTP_PHASED_KERNELS', '-DTP_HAS_BATCH', str(HERE / 'work_never_replayed_boundary.cc'), '-o', str(out / 'never-replayed')]
        for logical in ('src/lib/libxdev_ext.h', 'src/compute/cuda/libxdev_ext_cuda.h'):
            cmd.append('-I' + str((view.root / layout.logical(logical)).parent))
        for macro, path in {'TP_LIBRARY_SOURCE': view.root / layout.logical('src/compute/collectives/xdev_tp.cc'),
                            'TP_KERNEL_SOURCE': view.root / layout.logical('src/compute/collectives/xdev_tp.cu'),
                            'TP_PEER_SPAN_SOURCE': out / 'actual-span.inc', 'TP_EMPTY_SOURCE': out / 'empty.inc'}.items():
            cmd.append('-D' + macro + '="' + str(path) + '"')
        built = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
        (out / 'compile.log').write_text(built.stdout + built.stderr)
        result.update(compile_exit=built.returncode, compile_command=cmd)
        if built.returncode:
            raise RuntimeError('native boundary compile failed; not behavior RED')
        for case in CASES:
            run = subprocess.run([str(out / 'never-replayed'), case], text=True, capture_output=True, timeout=15)
            (out / (case + '.log')).write_text(run.stdout + run.stderr)
            print(run.stdout + run.stderr, end='')
            if run.returncode not in (0, 1):
                raise RuntimeError(case + ' setup/crash, not behavior RED')
            result['cases'].append({'case': case, 'exit': run.returncode})
        result['exit'] = int(any(c['exit'] for c in result['cases']))
        result['state'] = 'BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:
        result.update(exit=2, state='SETUP_ERROR', error=str(error))
        print(error)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result['exit']


if __name__ == '__main__':
    raise SystemExit(main())

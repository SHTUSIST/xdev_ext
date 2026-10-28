#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual echo driver branch/header/kernels at existing call boundaries."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
CASES = ('rank0', 'rank1', 'bad_payload_rank0', 'bad_payload_rank1',
         'bad_key_rank0', 'bad_key_rank1', 'geometry_rank1', 'cutoff_rank0', 'cutoff_rank1')


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = a.source_root.resolve()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    result = {'scope': 'actual echo source under host CUDA/endpoint/session boundaries; no SDK/GPU/timing evidence', 'cases': []}
    try:
        spec = importlib.util.spec_from_file_location('echo_layout', root / 'tools/layout.py')
        m = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = m
        spec.loader.exec_module(m)
        layout = m.load_layout(root)
        view = m.materialize_view(root, out / 'source-view')
        spec = importlib.util.spec_from_file_location('echo_extract', root / 'tests/core/admission_report/run.py')
        extract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(extract)
        source = root / 'tests/benchmarks/tp'
        (out / 'actual-kernels.inc').write_text('\n'.join(extract.function((source / 'verify.cu').read_text(), name) for name in ('tp_eval_echo_fill', 'tp_eval_echo_check')))
        (out / 'actual-span.inc').write_text(extract.function((root / 'src/lib/xdev_ext_user.c').read_text(), 'xdev_ext_user_batch_peer_span'))
        (out / 'actual-driver.inc').write_text(block((source / 'driver.cc').read_text(), 'if(o.operation==4) {'))
        boundary = out / 'boundary'
        boundary.mkdir(exist_ok=True)
        shutil.copyfile(HERE / 'driver_boundary.h', boundary / 'cuda.h')
        cmd = [os.environ.get('CXX', 'g++'), '-std=c++17', '-O0', '-g', '-Wall', '-Wextra',
               '-Wno-misleading-indentation', '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
               '-I' + str(boundary), str(HERE / 'echo_boundary.cc'), '-o', str(out / 'echo-boundary')]
        for logical in ('src/lib/libxdev_ext.h', 'src/compute/cuda/peer_endpoint_owner.h'):
            cmd.append('-I' + str((view.root / layout.logical(logical)).parent))
        for macro, path in {'TP_ECHO_OPTIONS': source / 'options.h', 'TP_ECHO_SOURCE': source / 'echo.h',
                            'TP_ECHO_KERNELS': out / 'actual-kernels.inc', 'TP_ECHO_SPAN': out / 'actual-span.inc',
                            'TP_ECHO_DRIVER': out / 'actual-driver.inc'}.items():
            cmd.append('-D' + macro + '="' + str(path) + '"')
        built = subprocess.run(cmd, text=True, capture_output=True, timeout=60)
        (out / 'compile.log').write_text(built.stdout + built.stderr)
        result.update(compile_exit=built.returncode, compile_command=cmd)
        if built.returncode:
            raise RuntimeError('echo boundary compile failed; not behavior RED')
        for case in CASES:
            run = subprocess.run([str(out / 'echo-boundary'), case], text=True, capture_output=True, timeout=15)
            (out / (case + '.log')).write_text(run.stdout + run.stderr)
            print(run.stdout + run.stderr, end='')
            if run.returncode not in (0, 1):
                raise RuntimeError(case + ' setup/crash, not behavior RED')
            result['cases'].append({'case': case, 'exit': run.returncode})
        result.update(exit=int(any(c['exit'] for c in result['cases'])))
        result['state'] = 'BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:
        result.update(exit=2, state='SETUP_ERROR', error=str(error))
        print(error)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result['exit']


if __name__ == '__main__':
    raise SystemExit(main())

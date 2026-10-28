#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual d2 graph/device algorithms; no SDK/GPU/ordering/DMA evidence."""
import argparse
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
CASES = ('success', 'bad_payload', 'bad_short_tail', 'bad_key', 'duplicate_key',
         'stale_ticket', 'zero_ticket', 'producer_key', 'producer_status', 'tx_geometry', 'ready_status', 'zero_span', 'zero_frames',
         'too_many_frames', 'span_bounds', 'address_bounds', 'geometry',
         'terminal_key', 'terminal_status', 'terminal_ticket', 'alias_allocation',
         'visibility_failure', 'capture_failure', 'instantiate_failure',
         'launch_failure', 'sync_failure', 'observe_failure', 'end_timeout',
         'end_abort', 'end_held', 'end_sequestered', 'end_error', 'destroy_failure', 'graph_destroy_failure')
KERNELS = ('tp_eval_echo_gpu_begin', 'tp_eval_echo_gpu_produce',
           'tp_eval_echo_gpu_consume', 'tp_eval_echo_gpu_terminal')


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root, out = a.source_root.resolve(), a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    result = {'scope': 'real d2 echo at host CUDA/native boundaries; branch arithmetic only; no SDK/GPU/ordering/DMA/performance evidence', 'cases': []}
    try:
        source = root / 'tests/benchmarks/tp'
        for name in ('echo_gpu.h', 'echo_device.h'):
            if not (source / name).is_file():
                raise RuntimeError('missing implementation file (not behavior RED): ' + name)
        spec = importlib.util.spec_from_file_location('echo_extract', root / 'tests/core/admission_report/run.py')
        extract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(extract)
        (out / 'actual-gpu-kernels.inc').write_text('\n'.join(extract.function((source / 'verify.cu').read_text(), name) for name in KERNELS))
        (out / 'actual-driver.inc').write_text(block((source / 'driver.cc').read_text(), 'if(o.operation==4) {'))
        boundary = out / 'boundary'
        boundary.mkdir(exist_ok=True)
        (boundary / 'cuda.h').write_text((HERE / 'driver_boundary.h').read_text() + '\n#ifndef TP_ECHO_GPU_CUDA_EXTRA\n#define TP_ECHO_GPU_CUDA_EXTRA\ntypedef void *CUgraphExec;\nenum {CU_STREAM_CAPTURE_MODE_THREAD_LOCAL=1};\n#endif\n')
        # Actual C++ compilation needs only the logical header projection.
        # Do not materialize the full Linux/NVIDIA/product source tree.
        spec = importlib.util.spec_from_file_location('echo_gpu_layout', root / 'tools/layout.py')
        layout_module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = layout_module
        spec.loader.exec_module(layout_module)
        layout = layout_module.load_layout(root)
        headers = out / 'headers'
        for src, logical in layout.by_source.items():
            if src.endswith('.h') and src.startswith(('src/lib/', 'src/compute/cuda/', 'src/core/include/uapi/')):
                target = headers / logical
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / src, target)
        lib_include = (headers / layout.logical('src/lib/libxdev_ext.h')).parent
        cuda_include = (headers / layout.logical('src/compute/cuda/peer_endpoint_owner.h')).parent
        cmd = [os.environ.get('CXX', 'g++'), '-std=c++17', '-O0', '-g', '-Wall', '-Wextra',
               '-Wno-misleading-indentation', '-Wno-unused-function',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
               '-I' + str(boundary), '-I' + str(lib_include),
               '-I' + str(cuda_include),
               str(HERE / 'echo_gpu_boundary.cc'), '-o', str(out / 'echo-gpu-boundary')]
        paths = {'TP_ECHO_OPTIONS': source / 'options.h', 'TP_ECHO_SOURCE': source / 'echo.h',
                 'TP_ECHO_DEVICE': source / 'echo_device.h', 'TP_ECHO_GPU_SOURCE': source / 'echo_gpu.h',
                 'TP_ECHO_GPU_KERNELS': out / 'actual-gpu-kernels.inc', 'TP_ECHO_DRIVER': out / 'actual-driver.inc'}
        cmd += ['-D' + key + '="' + str(path) + '"' for key, path in paths.items()]
        built = subprocess.run(cmd, text=True, capture_output=True, timeout=60)
        (out / 'compile.log').write_text(built.stdout + built.stderr)
        result.update(compile_exit=built.returncode, compile_command=cmd)
        if built.returncode:
            raise RuntimeError('boundary compilation failed; not behavior RED')
        for case in CASES:
            for rank in (0, 1):
                run = subprocess.run([str(out / 'echo-gpu-boundary'), case, str(rank)], text=True, capture_output=True, timeout=10)
                name = case + '_rank' + str(rank)
                (out / (name + '.log')).write_text(run.stdout + run.stderr)
                print(run.stdout + run.stderr, end='')
                if run.returncode not in (0, 1):
                    raise RuntimeError(name + ' setup/crash/UB, not behavior RED')
                result['cases'].append({'case': name, 'exit': run.returncode})
        result['exit'] = int(any(c['exit'] for c in result['cases']))
        result['state'] = 'BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:
        result.update(exit=2, state='SETUP_ERROR', error=str(error))
        print(error)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result['exit']


if __name__ == '__main__':
    raise SystemExit(main())

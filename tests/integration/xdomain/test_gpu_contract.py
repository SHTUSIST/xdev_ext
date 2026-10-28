#!/usr/bin/env python3
"""Official-header Driver API contract test; never loads a CUDA driver."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def run(cmd):
    print('+ ' + ' '.join(map(str, cmd)), flush=True)
    return subprocess.run(list(map(str, cmd)), check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cuda-home', default=os.environ.get('CUDA_HOME', ''))
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    home = Path(args.cuda_home) if args.cuda_home else None
    if home is None or not (home / 'include/cuda.h').is_file():
        print('UNAVAILABLE: official SDK include/cuda.h required', file=sys.stderr)
        return 2
    if args.build_dir:
        args.build_dir.mkdir(parents=True, exist_ok=True)
        return build(home, args.build_dir)
    with tempfile.TemporaryDirectory(prefix='tb-gpu-contract-') as temp:
        return build(home, Path(temp))


def build(home, out):
    flags = ['-std=c++17', '-Wall', '-Wextra', '-Werror', '-pthread',
             '-I' + str(home / 'include'), '-I' + str(HERE)]
    obj = out / 'gpu_contract_test.o'
    rc = run(['g++', *flags, '-c', HERE / 'gpu_contract_test.cc', '-o', obj])
    if rc:
        print('FAILED: test object did not compile against official headers')
        return rc
    print('official-header test object compiled; linking real implementation', flush=True)
    objects = [obj]
    guard = HERE / 'check_contract.c'
    if guard.exists():
        guard_obj = out / 'check_contract.o'
        rc = run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread',
                  '-I' + str(HERE), '-c', guard, '-o', guard_obj])
        if rc:
            return rc
        objects.append(guard_obj)
    adapter = HERE / 'gpu_adapter.cc'
    if adapter.exists():
        adapter_obj = out / 'gpu_adapter.o'
        rc = run(['g++', *flags, '-c', adapter, '-o', adapter_obj])
        if rc:
            return rc
        objects.append(adapter_obj)
    exe = out / 'gpu_contract_test'
    rc = run(['g++', '-pthread', *objects, '-Wl,--wrap=open',
              '-Wl,--wrap=close', '-Wl,--wrap=fstat', '-Wl,--wrap=read', '-o', exe])
    if rc:
        print('RED: implementation link failed (test object already compiled)', flush=True)
        return rc
    return run([exe])


if __name__ == '__main__':
    raise SystemExit(main())

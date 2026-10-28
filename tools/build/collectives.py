#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build actual two-rank collective CUDA/Driver artifacts; never run link stubs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--cuda-home', type=Path, required=True)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--libbpf-include', type=Path)
    parser.add_argument('--libbpf-archive', type=Path)
    parser.add_argument('--arch', default='sm_80')
    parser.add_argument('--host-cxx', default='g++-14')
    args = parser.parse_args()
    os.umask(0o077)
    root = args.source_root.resolve()
    sdk = args.cuda_home.resolve()
    base = args.base_build.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = root / 'src/compute/collectives'
    nvcc = sdk / 'bin/nvcc'
    stub = next((path for path in (
        sdk / 'lib64/stubs/libcuda.so',
        sdk / 'targets/x86_64-linux/lib/stubs/libcuda.so',
    ) if path.is_file()), None)
    dependencies = {
        'base_shared': str(base / 'libxdev_ext_cuda.so'),
        'base_archive': str(base / 'libxdev_ext.a'),
        'cuda_stub': str(stub) if stub else None,
    }
    receipt = {
        'status': 'failed', 'execution': 'not-run',
        'source_root': str(root), 'sdk': str(sdk), 'arch': args.arch,
        'dependencies': dependencies, 'sources': [], 'commands': [],
        'artifacts': {}, 'runtime_stub_execution': False,
    }
    inputs = [source / name for name in (
        'xdev_tp.cc', 'xdev_tp.cu', 'xdev_tp.h', 'xdev_tp_wire.h',
        'xdev_tp_algorithms.h', 'xdev_tp_device.h',
    )]
    owner = root / 'src/compute/cuda/peer_endpoint_owner.cc'
    inputs += [owner, owner.with_suffix('.h')]
    inputs += [root / 'tools/layout.py', root / 'source-layout.json',
               Path(__file__).resolve(), sdk / 'include/cuda.h']
    inputs += [Path(value) for value in dependencies.values() if value]

    def finish(status, code, reason=None):
        receipt['status'] = status
        if reason:
            receipt['reason'] = reason
        receipt['sources'] = [
            {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            if path.is_file() else {'path': str(path), 'missing': True}
            for path in dict.fromkeys(inputs)
        ]
        receipt['artifact_hashes'] = {
            name: {'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                   'bytes': Path(path).stat().st_size}
            for name, path in receipt['artifacts'].items() if Path(path).is_file()
        }
        target = out / 'receipt.json'
        if target.is_file():
            target.rename(out / f'previous-receipt-{time.time_ns()}.json')
        target.write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'status': status, 'execution': 'not-run',
                          'receipt': str(target), 'reason': reason}))
        return code

    def run(command):
        command = list(map(str, command))
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            record = {'argv': command, 'returncode': result.returncode,
                      'stdout': result.stdout, 'stderr': result.stderr}
        except OSError as error:
            record = {'argv': command, 'returncode': 127,
                      'stdout': '', 'stderr': str(error)}
        receipt['commands'].append(record)
        if record['returncode']:
            sys.stderr.write(record['stderr'])
        return record['returncode']

    if not re.fullmatch(r'sm_[0-9]{2,3}[a-z]?', args.arch):
        return finish('failed', 1, 'Invalid CUDA architecture')
    if not re.fullmatch(r'g\+\+(?:-[0-9]+)?', Path(args.host_cxx).name):
        return finish('failed', 1, 'Host compiler must be GCC G++')
    if not nvcc.is_file() or not stub or not (sdk / 'include/cuda.h').is_file():
        return finish('unavailable', 2, 'Official SDK compiler/header/link stub missing')
    if any(not path.is_file() for path in inputs):
        return finish('unavailable', 2, 'Canonical source or built base dependency missing')
    if bool(args.libbpf_include) != bool(args.libbpf_archive):
        return finish('unavailable', 2, 'Both real libbpf dependency paths are required')
    bpf_flags = []
    if args.libbpf_archive:
        archive = args.libbpf_archive.resolve()
        header = args.libbpf_include.resolve() / 'bpf/libbpf.h'
        inputs += [archive, header]
        if not archive.is_file() or not header.is_file():
            return finish('unavailable', 2, 'Real libbpf dependency missing')
        bpf_flags = ['-I' + str(header.parents[1])]
        bpf_link = [str(archive)]
        receipt['dependencies']['libbpf_archive'] = str(archive)
    else:
        if run(['pkg-config', '--atleast-version=1.0', 'libbpf']):
            return finish('unavailable', 2, 'Real libbpf >= 1.0 required for owner bootstrap')
        if run(['pkg-config', '--libs', 'libbpf']):
            return finish('unavailable', 2, 'Real libbpf link dependencies unavailable')
        bpf_link = shlex.split(receipt['commands'][-1]['stdout'])
    receipt['dependencies']['libbpf_link_args'] = bpf_link
    view = out / 'source-view'
    if run([sys.executable, root / 'tools/layout.py', 'view', '--root', root,
            '--output', view]):
        return finish('failed', 1, 'Ordinary-copy source view failed')
    lib = view / 'kernel/tools/xdev_ext_mech/lib'
    public = view / 'tests/eval/tp/tests/public_api_link.cc'
    other_public = view / 'tests/eval/tp/tp_library_link_test.cc'
    inputs += [public, other_public]
    inputs += list(lib.glob('*.h'))
    if not public.is_file() or not other_public.is_file():
        return finish('unavailable', 2, 'Actual public link consumers missing')
    include = ['-I' + str(sdk / 'include'), '-I' + str(lib),
               '-I' + str(view / 'kernel/include/uapi'), '-I' + str(source),
               '-I' + str(root / 'src/compute/cuda'), '-I' + str(root / 'src/lib'),
               '-I' + str(root / 'src/core/include/uapi'), *bpf_flags]
    for compiler in (args.host_cxx, nvcc):
        if run([compiler, '--version']):
            return finish('unavailable', 2, 'Compiler unavailable')
    for kind in ('ptx', 'cubin'):
        artifact = out / f'xdev_tp.{kind}'
        if run([nvcc, '--' + kind, '-arch=' + args.arch, '-std=c++17',
                '-ccbin', args.host_cxx, *include, source / 'xdev_tp.cu', '-o', artifact]):
            return finish('failed', 1, 'Actual collective CUDA compilation failed')
        receipt['artifacts'][kind] = str(artifact)
    common = ['-std=c++17', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fPIC']
    obj = out / 'xdev_tp.o'
    if run([args.host_cxx, *common, *include, '-c', source / 'xdev_tp.cc', '-o', obj]):
        return finish('failed', 1, 'Actual collective Driver library compilation failed')
    owner_obj = out / 'peer_endpoint_owner.o'
    if run([args.host_cxx, *common, *include, '-c', owner, '-o', owner_obj]):
        return finish('failed', 1, 'Actual duplex owner compilation failed')
    shared = out / 'libxdev_tp.so'
    # The CUDA stub is only a link input, never a runtime search directory.
    link = ['-L' + str(base), '-lxdev_ext_cuda', str(base / 'libxdev_ext.a'),
            '-L' + str(stub.parent), '-lcuda', *bpf_link, '-lelf', '-lz', '-ldl']
    if run([args.host_cxx, '-shared', '-Wl,--no-undefined', obj, owner_obj, *link, '-o', shared]):
        return finish('failed', 1, 'Actual collective shared-library link failed')
    receipt['artifacts']['shared'] = str(shared)
    for name, consumer in (('link_test', public), ('abi_link_test', other_public)):
        target = out / ('tp_library_link_test' if name == 'link_test' else 'tp_abi_link_test')
        if run([args.host_cxx, *common, *include, consumer, '-L' + str(out),
                '-lxdev_tp', *link, '-Wl,-rpath-link,' + str(base), '-o', target]):
            return finish('failed', 1, 'Actual public collective consumer link failed')
        receipt['artifacts'][name] = str(target)
    return finish('built', 0)


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile actual PEER/CUDA libraries and owner example; never execute stubs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cuda-home', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--arch', default='sm_80')
    p.add_argument('--host-cxx', default='g++')
    p.add_argument('--libbpf-include', type=Path)
    p.add_argument('--libbpf-archive', type=Path)
    args = p.parse_args()
    source = Path(__file__).resolve().parent
    repo = source.parents[2]
    lib = repo / 'kernel/tools/xdev_ext_mech/lib'
    examples = lib.parent / 'examples'
    uapi = repo / 'kernel/include/uapi/linux'
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sdk = args.cuda_home.resolve()
    nvcc = sdk / 'bin/nvcc'
    include = sdk / 'include'
    stub = next((q for q in [sdk/'lib64/stubs/libcuda.so',
                            sdk/'targets/x86_64-linux/lib/stubs/libcuda.so']
                 if q.is_file()), None)
    c_sources = [lib / f'xdev_ext_{n}.c' for n in
                 ['session', 'user', 'prog', 'run', 'link', 'peer_message']]
    cuda_sources = [lib/'libxdev_ext_cuda.cc', lib/'libxdev_ext_cuda_kernels.cu',
                    examples/'peer_message.cc', examples/'peer_message_owner.cu']
    headers = [lib/n for n in ['libxdev_ext.h', 'libxdev_ext_internal.h',
                               'libxdev_ext_peer_message.h', 'libxdev_ext_cuda.h',
                               'libxdev_ext_cuda_device.h']]
    headers += [uapi/n for n in ['io_uring.h', 'xdev_ext_mech.h',
                                 'xdev_ext_peer.h', 'xdev_ext_binding.h']]
    headers += [lib.parent/n for n in ['xdev_ext_mech_ctl_core.h',
                                      'xdev_ext_mech_prog.h']]
    inputs = c_sources + cuda_sources + headers + [Path(__file__).resolve(),
                                                   source/'cuda_library_link_test.cc',
                                                   include/'cuda.h']
    receipt = dict(status='failed', execution='not-run', commands=[],
                   sdk=str(sdk), arch=args.arch, sources=[], artifacts={},
                   link_stub=str(stub), runtime_stub_execution=False)

    def finish(status, code, reason=None):
        receipt['status'] = status
        if reason:
            receipt['reason'] = reason
        for q in inputs:
            receipt['sources'].append(dict(path=str(q), sha256=hashlib.sha256(q.read_bytes()).hexdigest())
                                      if q.is_file() else dict(path=str(q), missing=True))
        receipt['artifact_hashes'] = {
            name: dict(sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                       bytes=Path(path).stat().st_size)
            for name, path in receipt['artifacts'].items() if Path(path).is_file()
        }
        previous = out/'receipt.json'
        if previous.is_file():
            try:
                failed = json.loads(previous.read_text()).get('status') == 'failed'
            except (OSError, json.JSONDecodeError):
                failed = True
            if failed:
                previous.rename(out/f'failed-receipt-{time.time_ns()}.json')
        previous.write_text(json.dumps(receipt, indent=2)+'\n')
        print(json.dumps(dict(status=status, execution='not-run', receipt=str(out/'receipt.json'))))
        return code

    def run(argv):
        argv = list(map(str, argv))
        try:
            result = subprocess.run(argv, text=True, capture_output=True, check=False)
            record = dict(argv=argv, returncode=result.returncode,
                          stdout=result.stdout, stderr=result.stderr)
        except OSError as e:
            record = dict(argv=argv, returncode=127, stdout='', stderr=str(e))
        receipt['commands'].append(record)
        if record['returncode']:
            print(record['stderr'])
        return record

    if not re.fullmatch(r'sm_[0-9]{2,3}[a-z]?', args.arch):
        return finish('failed', 1, 'Invalid CUDA architecture')
    if not re.fullmatch(r'g\+\+(?:-[0-9]+)?', Path(args.host_cxx).name):
        return finish('failed', 1, 'Host compiler must be GCC G++')
    if not nvcc.is_file() or not (include/'cuda.h').is_file() or not stub:
        return finish('unavailable', 2, 'Official SDK nvcc/header/link stub missing')
    if args.libbpf_include or args.libbpf_archive:
        if not args.libbpf_include or not args.libbpf_archive:
            return finish('unavailable', 2, 'Both real libbpf include and archive are required')
        if not (args.libbpf_include/'bpf/libbpf.h').is_file() or not args.libbpf_archive.is_file():
            return finish('unavailable', 2, 'Real libbpf dependency paths missing')
        bpf_cflags, bpf_libs = ['-I'+str(args.libbpf_include)], [str(args.libbpf_archive)]
        inputs += [args.libbpf_include/'bpf/libbpf.h', args.libbpf_archive]
    else:
        version = run(['pkg-config', '--atleast-version=1.0', 'libbpf'])
        if version['returncode']:
            return finish('unavailable', 2, 'Real libbpf >=1.0 required')
        cflags = run(['pkg-config', '--cflags', 'libbpf'])
        libs = run(['pkg-config', '--libs', 'libbpf'])
        if cflags['returncode'] or libs['returncode']:
            return finish('unavailable', 2, 'libbpf pkg-config failed')
        bpf_cflags, bpf_libs = shlex.split(cflags['stdout']), shlex.split(libs['stdout'])
    if any(not q.is_file() for q in inputs):
        return finish('unavailable', 2, 'Production source missing')
    for tool in ['gcc', args.host_cxx, nvcc]:
        if run([tool, '--version'])['returncode']:
            return finish('unavailable', 2, 'Compiler unavailable')
    common = ['-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fPIC']
    objects = []
    for q in c_sources:
        obj = out/(q.stem+'.o')
        if run(['gcc', '-std=gnu11', *common, *bpf_cflags, '-c', q, '-o', obj])['returncode']:
            return finish('failed', 1, 'C library compilation failed')
        objects.append(obj)
    archive = out/'libxdev_ext.a'
    if run(['ar', 'rcs', archive, *objects])['returncode']:
        return finish('failed', 1, 'Library archive failed')
    for name, q in [('libxdev_ext_cuda', lib/'libxdev_ext_cuda_kernels.cu'),
                    ('peer_message_owner', examples/'peer_message_owner.cu')]:
        for kind, flag in [('ptx', '--ptx'), ('cubin', '--cubin')]:
            artifact = out/(name+'.'+kind)
            if run([nvcc, flag, '-arch='+args.arch, '-std=c++17',
                    '-ccbin', args.host_cxx, '-I'+str(lib), q, '-o', artifact])['returncode']:
                return finish('failed', 1, 'Real CUDA kernel compilation failed')
            receipt['artifacts'][name+'.'+kind] = str(artifact)
    cuda_obj = out/'libxdev_ext_cuda.o'
    if run([args.host_cxx, '-std=c++17', *common, '-I'+str(include),
            '-c', lib/'libxdev_ext_cuda.cc', '-o', cuda_obj])['returncode']:
        return finish('failed', 1, 'Driver library compilation failed')
    link = ['-L'+str(stub.parent), '-lcuda', *bpf_libs, '-lelf', '-lz', '-ldl']
    shared = out/'libxdev_ext_cuda.so'
    core_objects = [q for q in objects if q.stem not in ['xdev_ext_prog', 'xdev_ext_run']]
    if run([args.host_cxx, '-shared', '-Wl,--no-undefined', cuda_obj,
            *core_objects, '-L'+str(stub.parent), '-lcuda', '-o', shared])['returncode']:
        return finish('failed', 1, 'Driver library link failed')
    executable = out/'peer_message'
    if run([args.host_cxx, '-std=c++17', *common, '-I'+str(include),
            examples/'peer_message.cc', cuda_obj, archive, *link, '-o', executable])['returncode']:
        return finish('failed', 1, 'Owner example link failed')
    link_test = out/'cuda_library_link_test'
    if run([args.host_cxx, '-std=c++17', *common, '-I'+str(include),
            source/'cuda_library_link_test.cc', cuda_obj, archive, *link,
            '-o', link_test])['returncode']:
        return finish('failed', 1, 'Public CUDA consumer link failed')
    receipt['artifacts'].update(archive=str(archive), shared=str(shared),
                                executable=str(executable), link_test=str(link_test))
    return finish('built', 0)


if __name__ == '__main__':
    raise SystemExit(main())

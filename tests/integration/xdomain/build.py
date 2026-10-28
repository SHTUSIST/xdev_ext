#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile the real CUDA/PTX agent without executing any CUDA operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


def required_sources(source_root: Path) -> list[Path]:
    """Return every production translation unit and project header used by build."""
    names = ['check_contract.c', 'epoch_control.c', 'gpu_adapter.cc',
             'agent_supervisor.cc', 'xdomain_agent.cc', 'xdomain_gpu_pattern.cu',
             'xdomain_gpu_pattern.h', 'check_contract.h', 'epoch_control.h',
             'gpu_adapter.h', 'agent_supervisor.h', 'observer_contract.h',
             'native_trace_owner.cc', 'native_trace_owner.h',
             'platform_facts.py', 'native_barrier.py', 'action_provider.py',
             'check_protocol.py']
    abi_names = ['xdev_ext_mech.h', 'xdev_ext_policy.h',
                 'xdev_ext_binding.h', 'xdev_ext_peer.h', 'io_uring.h']
    uapi = source_root.parents[2] / 'kernel/include/uapi/linux'
    return ([source_root / name for name in names] +
            [uapi / name for name in abi_names])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cuda-home', required=True, type=Path)
    parser.add_argument('--host-cxx', default='g++')
    parser.add_argument('--arch', default='sm_80')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parent
    repo = source.parents[2]
    sdk = args.cuda_home.resolve()
    nvcc = sdk / 'bin/nvcc'
    header_candidates = [sdk / 'include/cuda.h', sdk / 'targets/x86_64-linux/include/cuda.h']
    header = next((p for p in header_candidates if p.is_file()), header_candidates[0])
    stub_candidates = [sdk / 'lib64/stubs/libcuda.so', sdk / 'lib/stubs/libcuda.so',
                       sdk / 'targets/x86_64-linux/lib/stubs/libcuda.so']
    stub = next((p for p in stub_candidates if p.is_file()), stub_candidates[0])
    paths = required_sources(source)
    receipt = {'status': 'unavailable', 'execution': 'not-run', 'missing': [],
               'sdk': {'root': str(sdk), 'nvcc': str(nvcc), 'cuda_h': str(header),
                       'libcuda_stub': str(stub), 'provenance': None},
               'tool_versions': {}, 'commands': [],
               'sources': [str(p) for p in paths],
               'artifacts': {'ptx': None, 'executable': None}}
    produced = {}
    for parent in [sdk, *list(sdk.parents)[:4]]:
        provenance = parent / 'manifest.json'
        if provenance.is_file():
            receipt['sdk']['provenance'] = str(provenance)
            break

    def finish(status, code, reason=None):
        receipt['status'] = status
        if reason:
            receipt['reason'] = reason
        for key, path in produced.items():
            receipt['artifacts'][key] = str(path)
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'status': status, 'execution': 'not-run',
                          'missing': receipt['missing'], 'receipt': str(out / 'receipt.json')}))
        return code

    def run(argv):
        argv = [str(x) for x in argv]
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, check=False)
            record = {'argv': argv, 'returncode': p.returncode,
                      'stdout': p.stdout, 'stderr': p.stderr}
        except OSError as exc:
            record = {'argv': argv, 'returncode': 127, 'stdout': '', 'stderr': str(exc)}
        receipt['commands'].append(record)
        return record

    if not nvcc.is_file() or not os.access(nvcc, os.X_OK):
        receipt['missing'].append('nvcc')
    if not header.is_file():
        receipt['missing'].append('cuda.h')
    if not stub.is_file():
        receipt['missing'].append('libcuda')
    bpf = run(['pkg-config', '--cflags', '--libs', 'libbpf'])
    if bpf['returncode']:
        receipt['missing'].append('libbpf')
    if not shutil.which(args.host_cxx):
        receipt['missing'].append('host-cxx')
    if not shutil.which('gcc'):
        receipt['missing'].append('gcc')
    absent = [str(p) for p in paths if not p.is_file()]
    if absent:
        receipt['missing_sources'] = absent
    if receipt['missing'] or absent:
        return finish('unavailable', 2, 'Missing build prerequisites or production sources')
    if not re.fullmatch(r'sm_[0-9]{2,3}[a-z]?', args.arch):
        return finish('failed', 1, 'Unsupported CUDA architecture spelling')
    for tool, name in [(nvcc, 'nvcc'), (args.host_cxx, 'host-cxx'), ('gcc', 'gcc')]:
        record = run([tool, '--version'])
        receipt['tool_versions'][name] = record['stdout'] + record['stderr']
        if record['returncode']:
            return finish('failed', 1, 'Tool version query failed')
    # CUDA header is large; inspect its bounded prefix rather than matching it whole.
    with header.open(errors='replace') as stream:
        for _ in range(400):
            line = stream.readline()
            if not line:
                break
            match = re.match(r'#define CUDA_VERSION\s+(\d+)', line)
            if match:
                receipt['sdk']['cuda_version'] = int(match.group(1))
                break
    sdk_includes = ['-I' + str(header.parent), '-I' + str(source)]
    includes = sdk_includes + ['-iquote' + str(repo / 'kernel/include/uapi')]
    bpf_flags = shlex.split(bpf['stdout'])
    ptx = out / 'xdomain_gpu_pattern.ptx'
    executable = out / 'xdomain_agent'
    # Old outputs cannot satisfy a compiler that returned success without output.
    for path in [ptx, executable, *(out / (p.name + '.o') for p in paths
                                  if p.suffix in ('.c', '.cc'))]:
        if path.is_file() or path.is_symlink():
            path.unlink()
    compute = 'compute_' + args.arch.removeprefix('sm_')
    pattern = next(p for p in paths if p.name == 'xdomain_gpu_pattern.cu')
    if run([nvcc, '-std=c++17', '--ptx', '-arch=' + compute,
            '-ccbin', args.host_cxx, *sdk_includes, pattern,
            '-o', ptx])['returncode']:
        return finish('failed', 1, 'PTX compilation failed')
    if ptx.is_file() and ptx.stat().st_size:
        produced['ptx'] = ptx
    else:
        return finish('failed', 1, 'PTX compiler did not produce PTX')
    objects = []
    for path in paths:
        if path.suffix not in ('.c', '.cc'):
            continue
        obj = out / (path.name + '.o')
        tool, standard = ('gcc', 'c11') if path.suffix == '.c' else (args.host_cxx, 'c++17')
        if run([tool, '-std=' + standard, '-Wall', '-Wextra', '-Werror', '-pthread',
                *includes, *bpf_flags, '-c', path, '-o', obj])['returncode']:
            return finish('failed', 1, 'Host compilation failed')
        objects.append(obj)
    # The stub supplies build-time symbols only. There is intentionally no RPATH.
    if run([args.host_cxx, '-pthread', *objects, '-L' + str(stub.parent),
            '-lcuda', *bpf_flags, '-o', executable])['returncode']:
        return finish('failed', 1, 'Agent link failed')
    if not ptx.is_file() or not ptx.stat().st_size or not executable.is_file():
        return finish('failed', 1, 'Compiler did not produce required artifacts')
    produced['executable'] = executable
    # Deploy the actual fixed-import modules used by the owner beside its binary.
    # They are build prerequisites above, never manufactured placeholders.
    for path in paths:
        if path.suffix == '.py':
            target = out / path.name
            if path.resolve() != target.resolve():
                shutil.copyfile(path, target)
            produced[path.stem] = target
    receipt['source_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    receipt['artifact_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in produced.values()}
    return finish('built', 0)


if __name__ == '__main__':
    sys.exit(main())

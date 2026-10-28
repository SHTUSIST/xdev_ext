#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build the real ATen/PyBind Driver bridge without importing the result.

Native libxdev_tp must already be built with the official SDK. This entry uses
CppExtension, never CUDAExtension or nvcc; CUDA Driver stubs are link inputs only.
At runtime use a qualified real NVIDIA driver, never LD_LIBRARY_PATH=.../stubs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys


def validate_torch_version(version):
    if version.split('+')[0] != '2.8.0':
        raise RuntimeError('The bridge requires real torch 2.8.0')


def build_configuration(root, cuda_home, native_library, native_view=None):
    root, cuda_home, native_library = map(Path, (root, cuda_home, native_library))
    native_view = Path(native_view) if native_view is not None else root/'build/source-view'
    header = cuda_home / 'include/cuda.h'
    if not header.is_file():
        raise FileNotFoundError(f'official CUDA Driver header missing: {header}')
    if not native_library.is_file():
        raise FileNotFoundError(f'real native collective library missing: {native_library}')
    with native_library.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            raise RuntimeError('native collective library must be a built ELF shared object')
    return dict(sources=[str(root/'src/compute/torch/bridge.cc')],
                include_dirs=[str(native_view/'kernel/tools/xdev_ext_mech/lib'),
                              str(native_view/'kernel/include/uapi'),
                              str(root/'src/compute/collectives'), str(root/'src/compute/cuda'), str(header.parent)],
                extra_objects=[str(native_library)], libraries=['cuda'],
                runtime_library_dirs=[])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cuda-home', type=Path, required=True)
    parser.add_argument('--native-library', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--host-cxx', default='g++')
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=True)
    receipt = dict(status='failed', execution='not-run', imported=False,
                   runtime_stub_execution=False, extension_kind='CppExtension',
                   source=str(root/'src/compute/torch/bridge.cc'))
    def finish(code, reason=None):
        if reason: receipt['reason'] = reason
        (out/'framework-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
        print(json.dumps(dict(status=receipt['status'], execution='not-run',
                              receipt=str(out/'framework-receipt.json'))))
        return code
    try:
        if not re.fullmatch(r'g\+\+(?:-[0-9]+)?', Path(args.host_cxx).name):
            raise RuntimeError('GCC G++ is required for the host bridge')
        sys.path.insert(0, str(root/'tools'))
        import layout
        view = layout.materialize_view(root, out/'source-view')
        receipt['native_view'] = str(view.root)
        receipt['provenance'] = layout.provenance(root)
        config = build_configuration(root, args.cuda_home.resolve(), args.native_library.resolve(), view.root)
        candidates = [args.cuda_home/'lib64/stubs',
                      args.cuda_home/'targets/x86_64-linux/lib/stubs']
        stub_dir = next((p.resolve() for p in candidates if (p/'libcuda.so').is_file()), None)
        if stub_dir is None:
            raise FileNotFoundError('official CUDA Driver link stub missing')
        # No path to stubs is placed in RPATH or runtime environment.
        receipt['link_stub'] = str(stub_dir/'libcuda.so')
        import torch
        validate_torch_version(torch.__version__)
        from setuptools import Distribution
        from torch.utils.cpp_extension import BuildExtension, CppExtension
        receipt['dependencies'] = dict(torch=torch.__version__, torch_cuda=torch.version.cuda,
            cxx11_abi=bool(torch._C._GLIBCXX_USE_CXX11_ABI), python=sys.version,
            cuda_header=str(args.cuda_home/'include/cuda.h'))
        receipt['configuration'] = config
        os.environ['CXX'] = args.host_cxx
        cc_name = Path(args.host_cxx).name.replace('g++', 'gcc')
        os.environ['CC'] = str(Path(args.host_cxx).with_name(cc_name)) if '/' in args.host_cxx else cc_name
        os.environ['MAX_JOBS'] = '1'
        extension = CppExtension('xdev_tp_torch._native', **config,
            library_dirs=[str(stub_dir)], extra_compile_args=['-O2', '-g0', '-std=c++17'])
        distribution = Distribution(dict(name='xdev-tp-torch', ext_modules=[extension],
            cmdclass={'build_ext': BuildExtension.with_options(use_ninja=False)}))
        command = distribution.get_command_obj('build_ext')
        command.build_lib = str(out/'python')
        command.build_temp = str(out/'objects')
        command.ensure_finalized()
        command.run()  # compile/link only; no extension import or CUDA execution
        for directory, package in [('torch', 'xdev_tp_torch'), ('vllm', 'xdev_tp_vllm')]:
            shutil.copytree(root/'src/compute'/directory/package, out/'python'/package,
                            dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
        inputs = [Path(__file__).resolve(), root/'src/compute/torch/bridge.cc',
                  args.native_library.resolve(), args.cuda_home/'include/cuda.h']
        inputs += list((root/'src/compute/torch/xdev_tp_torch').glob('*.py'))
        inputs += list((root/'src/compute/vllm/xdev_tp_vllm').glob('*.py'))
        inputs += list((root/'src/compute/collectives').glob('*.h'))
        inputs += [root/'src/compute/cuda/peer_endpoint_owner.h',
                   root/'src/compute/cuda/peer_endpoint_owner.cc']
        # Record the unchanged native headers' canonical origins, never claim
        # that an ordinary generated view is a separate Git source checkout.
        headers = list((view.root/'kernel/tools/xdev_ext_mech/lib').glob('*.h'))
        headers += [view.root/'kernel/include/uapi/linux'/name for name in
                    ('xdev_ext_mech.h', 'xdev_ext_peer.h', 'xdev_ext_binding.h')]
        receipt['native_header_origins'] = [dict(native=str(p),
            canonical=str(root/view.source_origins[p.relative_to(view.root).as_posix()]))
            for p in headers if p.is_file()]
        inputs += [Path(item['canonical']) for item in receipt['native_header_origins']]
        inputs += [root/'source-layout.json', root/'tools/layout.py',
                   root/'src/compute/torch/pyproject.toml', root/'src/compute/vllm/pyproject.toml']
        receipt['inputs'] = [dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in inputs]
        artifacts = list((out/'python/xdev_tp_torch').glob('_native*.so'))
        if len(artifacts) != 1:
            raise RuntimeError('build did not produce exactly one real extension')
        receipt['artifacts'] = [dict(path=str(p), bytes=p.stat().st_size,
            sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in artifacts]
        receipt['status'] = 'built'
        return finish(0)
    except Exception as error:
        return finish(1, f'{type(error).__name__}: {error}')


if __name__ == '__main__':
    raise SystemExit(main())

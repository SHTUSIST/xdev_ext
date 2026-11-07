#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build only: real native driver and optional BPF from genuine target BTF header."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def main():
    root=next(p for p in Path(__file__).resolve().parents if (p/'source-layout.json').is_file())
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--libbpf-build',required=True,type=Path)
    parser.add_argument('--libbpf-archive',type=Path)
    parser.add_argument('--vmlinux-h',type=Path)
    parser.add_argument('--bpf-object',type=Path)
    parser.add_argument('--cc',default='gcc')
    parser.add_argument('--clang',default=os.environ.get('BPF_CLANG','clang'))
    args=parser.parse_args()
    sys.path.insert(0,str(root/'tests/compute/ce/random_target'))
    from runtime_validate import load
    helper=load('random_native_build_helper',root/'tests/compute/ce/random_target/run.py')
    out=helper.build_directory(root,args.output)
    receipt=dict(schema=1,status='setup',exit_code=None,commands=[],runtime_executed=False,performance=False)
    helper.write_json(out/'run.json',receipt)
    try:
        sys.path.insert(0,str(root/'tools'))
        from layout import materialize_view
        view=materialize_view(root,out/'view')
        receipt['canonical_root']=str(root)
        receipt['source_view']=str(view.root/'view.json')
        kernel=view.root/'kernel'
        lib=kernel/'tools/xdev_ext_mech/lib'
        test=kernel/'tools/testing/selftests/xdev_ext_mech/nvme_ce_random'
        bpf=args.libbpf_build.resolve()
        archive=args.libbpf_archive.resolve() if args.libbpf_archive else bpf/'libbpf.a'
        if not (bpf/'include/bpf/libbpf.h').is_file() or not archive.is_file():
            raise ValueError('actual modern libbpf include and archive required')
        compiler=shlex.split(args.cc)
        if not compiler: raise ValueError('empty compiler')
        command=compiler+['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror',
            '-I'+str(kernel),'-I'+str(bpf/'include'),'-I'+str(kernel/'tools/xdev_ext_mech/examples/storage'),
            str(test/'driver.c'),str(test/'private_loader.c'),str(lib/'xdev_ext_session.c'),
            str(kernel/'tools/xdev_ext_xsk_shared.c'),str(kernel/'tools/xdev_ext_xsk_steer.c'),
            str(kernel/'tools/xdev_ext_xsk_redirect.c'),str(kernel/'tools/xdev_ext_gpu_identity.c'),
            str(archive),'-lelf','-lz','-ldl',*shlex.split(os.environ.get('LDFLAGS','')),'-o',str(out/'nvme-ce-random')]
        if helper.invoke(command,out,'compile-native',receipt):
            return helper.finish(out,receipt,'setup',2)
        command=compiler+['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror',
            '-I'+str(kernel),'-I'+str(bpf/'include'),'-I'+str(kernel/'tools/xdev_ext_mech/examples/storage'),
            str(test/'loader_check.c'),str(test/'private_loader.c'),str(archive),'-lelf','-lz',*shlex.split(os.environ.get('LDFLAGS','')),
            '-o',str(out/'private-loader-check')]
        if helper.invoke(command,out,'compile-private-check',receipt):
            return helper.finish(out,receipt,'setup',2)
        if args.bpf_object:
            if not args.bpf_object.is_file(): raise ValueError('missing supplied actual BPF object')
            shutil.copyfile(args.bpf_object,out/'nvme_ce_request.bpf.o')
            receipt['bpf_source']='supplied actual object; external build provenance required'
            receipt['supplied_bpf_sources_unverified']=True
        else:
            if not args.vmlinux_h or not args.vmlinux_h.is_file():
                raise ValueError('genuine target --vmlinux-h required; no synthetic BTF')
            includes=out/'include';includes.mkdir()
            shutil.copyfile(args.vmlinux_h,includes/'vmlinux.h')
            command=shlex.split(args.clang)+['-target','bpf','-D__TARGET_ARCH_x86','-O2','-g',
                '-Wall','-Wextra','-Werror','-I'+str(includes),'-I'+str(kernel/'tools/xdev_ext_mech'),
                '-I'+str(bpf/'include'),'-I/usr/include/x86_64-linux-gnu','-c',
                str(kernel/'tools/xdev_ext_mech/examples/storage/nvme_ce_request.bpf.c'),'-o',str(out/'nvme_ce_request.bpf.o')]
            if helper.invoke(command,out,'compile-bpf',receipt):
                return helper.finish(out,receipt,'setup',2)
            receipt['bpf_source']='actual paired source with supplied target BTF header'
        # Hash the actual immutable copied bytes consumed by the compiler,
        # including reused lib/CUDA/UAPI headers; never relabel a later dirty
        # canonical file as the already compiled input.
        receipt['inputs']={source:hashlib.sha256((view.root/logical).read_bytes()).hexdigest()
                           for logical,source in view.source_origins.items()
                           if source.startswith(('src/lib/','src/cli/','src/core/include/uapi/',
                                                 'src/storage/include/uapi/','src/bpf/',
                                                 'examples/storage/nvme_ce_request','tests/integration/nvme_ce_random/'))
                           and source.endswith(('.c','.h','.py'))}
        receipt['artifacts']={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in ('nvme-ce-random','private-loader-check','nvme_ce_request.bpf.o')}
        helper.write_json(out/'build-result.json',receipt|dict(status='build-only',exit_code=0))
        return helper.finish(out,receipt,'build-only',0)
    except Exception as error:
        print('SETUP: '+str(error),file=sys.stderr);receipt['error']=str(error)
        return helper.finish(out,receipt,'setup',2)


if __name__=='__main__':
    try: code=main()
    except Exception as error:
        print('SETUP: '+str(error),file=sys.stderr);code=2
    raise SystemExit(code)

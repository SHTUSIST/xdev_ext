#!/usr/bin/env python3
"""Build only against pinned official BaM/submodules and the real CUDA SDK."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from native_contract import REVISION
HERE=Path(__file__).resolve().parent

def git(tree,*args):
    return subprocess.check_output(['git','-C',str(tree),*args],text=True,stderr=subprocess.PIPE).strip()

def check_tree(tree,revision):
    if git(tree,'rev-parse','HEAD')!=revision:
        raise ValueError('wrong upstream/submodule revision: '+str(tree))
    if git(tree,'status','--porcelain','--untracked-files=all'):
        raise ValueError('upstream/submodule must be pristine: '+str(tree))

def verify_upstream(tree,lock):
    check_tree(tree,lock['revision'])
    for s in [lock['submodule'],*lock['recursive_submodules']]:
        path=tree/s['path'];check_tree(path,s['revision'])
        parent=tree if s['path']==lock['submodule']['path'] else tree/lock['submodule']['path']
        rel=s['path'] if parent==tree else Path(s['path']).relative_to(lock['submodule']['path']).as_posix()
        if git(parent,'ls-tree','HEAD',rel).split()[2]!=s['revision']:
            raise ValueError('submodule gitlink mismatch')
    # Parent cleanliness includes nested submodule changes; exact trees are used.
    for path in lock['native_sources']:
        if not (tree/path).is_file():raise ValueError('missing official native source '+path)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream',required=True,type=Path);p.add_argument('--cuda-root',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path);p.add_argument('--arch',default='80',choices=['70','75','80','86','89','90'])
    p.add_argument('--host-compiler',default='g++')
    a=p.parse_args();sdk=a.cuda_root.resolve();tree=a.upstream.resolve();out=a.output.resolve()
    try:
        nvcc=sdk/'bin/nvcc'
        if not nvcc.is_file() or not (sdk/'include/cuda_runtime.h').is_file() or not (sdk/'lib64/libcudart.so').is_file():
            raise ValueError('official CUDA SDK incomplete/missing')
        lock=json.loads((HERE/'native.lock.json').read_text());verify_upstream(tree,lock)
        if out.exists():raise ValueError('output must be a new directory')
        if not shutil.which(a.host_compiler):raise ValueError('host compiler absent')
        version=subprocess.check_output([str(nvcc),'--version'],text=True,stderr=subprocess.STDOUT)
        if not re.search(r'release (1[23])\.',version):raise ValueError('supported official CUDA 12/13 SDK required')
    except (OSError,ValueError,subprocess.CalledProcessError,KeyError) as e:
        print('NOT_RUN: '+str(e),file=sys.stderr);return 4
    out.mkdir(parents=True)
    commands=[]
    def run(cmd):
        commands.append(cmd)
        with (out/'commands.json').open('w') as f:json.dump(commands,f,indent=2)
        with (out/'build.log').open('a') as f:
            f.write('\n$ '+repr(cmd)+'\n');f.flush()
            subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,check=True)
    try:
        # Copy only build inputs. Original checkout is never patched or built in.
        local=out/'upstream';shutil.copytree(tree/'include',local/'include',symlinks=True,ignore=shutil.ignore_patterns('.git'))
        shutil.copytree(tree/'src',local/'src');shutil.copyfile(tree/'LICENSE',local/'LICENSE')
        # Compiler-name collision in pinned libcxx. This is the ONLY native patch;
        # old Linux module patch remains historical and is not silently applied.
        traits=local/'include/freestanding/libcxx/include/type_traits'
        before=traits.read_text();after=re.sub(r'\b__is_convertible\b','__bam_libcpp_is_convertible',before)
        if before==after:raise ValueError('locked libcxx compatibility patch no longer applies')
        traits.write_text(after)
        import difflib
        (out/'native-compat.patch').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/include/freestanding/libcxx/include/type_traits',tofile='b/include/freestanding/libcxx/include/type_traits')))
        includes=['-I'+str(local/'include'),'-I'+str(local/'include/freestanding/include'),
                  '-I'+str(local/'src'),'-I'+str(sdk/'include')]
        objects=[]
        for source in sorted((local/'src').glob('*.cpp'))+sorted((local/'src/linux').glob('*.cpp')):
            obj=out/(source.relative_to(local/'src').as_posix().replace('/','_')+'.o')
            run([a.host_compiler,'-std=gnu++17','-O2','-fPIC','-pthread','-D_CUDA','-D__CUDA__',*includes,'-c',str(source),'-o',str(obj)])
            objects.append(str(obj))
        run([a.host_compiler,'-shared','-pthread',*objects,'-L'+str(sdk/'lib64'),'-lcudart','-o',str(out/'libnvm.so')])
        run([str(nvcc),'-std=c++17','-O2','--cudart','shared','-ccbin',a.host_compiler,
             '-arch=sm_'+a.arch,'-D__CUDA__',*includes,'-I'+str(HERE),str(HERE/'bench_native.cu'),
             '-L'+str(out),'-lnvm','-Xlinker','-rpath=$ORIGIN','-L'+str(sdk/'lib64'),
             '-Xlinker','-rpath='+str(sdk/'lib64'),'-o',str(out/'bam-native')])
        elf=out/'bam-native'
        if elf.read_bytes()[:4]!=b'\x7fELF':raise ValueError('compiler output is not ELF')
        record=dict(state='built-not-run',upstream_revision=REVISION,cuda_version=version,
                    arch=a.arch,host_compiler=a.host_compiler,cuda_root=str(sdk),
                    binary_sha256=hashlib.sha256(elf.read_bytes()).hexdigest(),
                    native_patch='native-compat.patch',physical_execution=False)
        (out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps(record));return 0
    except (OSError,ValueError,subprocess.CalledProcessError) as e:
        (out/'build-failure.txt').write_text(str(e)+'\n')
        print('BUILD_FAILED: '+str(e)+'; see '+str(out/'build.log'),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())

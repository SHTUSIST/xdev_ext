#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build real TP E6/E7 driver and GPU oracle; never execute CUDA link stubs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cuda-home',type=Path,required=True)
    p.add_argument('--native-receipt',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--arch',default='sm_80')
    p.add_argument('--host-cxx',default='g++')
    p.add_argument('--libbpf-include',type=Path)
    p.add_argument('--libbpf-archive',type=Path)
    args=p.parse_args(argv)
    root=Path(__file__).resolve().parents[2]
    source=root/'tests/benchmarks/tp'
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    sdk=args.cuda_home.resolve()
    receipt=dict(status='failed',execution='not-run',runtime_stub_execution=False,
                 sdk=str(sdk),arch=args.arch,commands=[],artifacts={},sources=[])
    inputs=[Path(__file__).resolve(),args.native_receipt.resolve()]
    inputs += [source/n for n in ['driver.cc','owner.h','echo.h','options.h','verify.cu','run.py','accounting.py']]
    inputs += list((root/'src/compute/collectives').glob('*.h'))
    inputs += [root/'src/compute/cuda/peer_endpoint_owner.h',
               root/'src/compute/cuda/peer_endpoint_owner.cc',root/'src/lib/libxdev_ext.h',root/'src/lib/libxdev_ext_peer_message.h',
               root/'src/compute/cuda/libxdev_ext_cuda.h',sdk/'include/cuda.h']
    inputs += list((root/'src/core/include/uapi/linux').glob('xdev_ext*.h'))
    def run(command):
        command=list(map(str,command))
        r=subprocess.run(command,capture_output=True,text=True,check=False)
        receipt['commands'].append(dict(argv=command,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr))
        if r.returncode:
            raise RuntimeError('build command failed: '+shlex.join(command)+'\n'+r.stderr)
        return r.stdout
    try:
        if not re.fullmatch(r'g\+\+(?:-[0-9]+)?',Path(args.host_cxx).name):
            raise ValueError('GCC G++ host compiler required')
        if not re.fullmatch(r'sm_[0-9]{2,3}[a-z]?',args.arch):
            raise ValueError('invalid CUDA architecture')
        native=json.loads(args.native_receipt.read_text())
        if native.get('status')!='built' or native.get('execution')!='not-run':
            raise ValueError('actual native build-only receipt required')
        shared=Path(native['artifacts']['shared'])
        base_shared=Path(native['dependencies']['base_shared'])
        archive=Path(native['dependencies']['base_archive'])
        stub=Path(native['dependencies']['cuda_stub'])
        inputs += [shared,base_shared,archive,stub]
        view=args.native_receipt.resolve().parent/'source-view'
        base_headers=view/'kernel/tools/xdev_ext_mech/lib'
        if not (base_headers/'libxdev_ext.h').is_file():
            raise ValueError('native build ordinary-copy dependency view required')
        inputs += list(base_headers.glob('*.h'))
        for q in [shared,base_shared]:
            with q.open('rb') as f:
                if f.read(4)!=b'\x7fELF':raise ValueError('actual ELF library required')
        if not stub.is_file() or not (sdk/'bin/nvcc').is_file():
            raise ValueError('official SDK compiler/link stub missing')
        if args.libbpf_include or args.libbpf_archive:
            if not args.libbpf_include or not args.libbpf_archive:
                raise ValueError('both real libbpf paths required')
            inputs += [args.libbpf_archive,args.libbpf_include/'bpf/libbpf.h']
            bpf_cflags=['-I'+str(args.libbpf_include)]
            bpf_libs=[str(args.libbpf_archive)]
        else:
            run(['pkg-config','--atleast-version=1.0','libbpf'])
            bpf_cflags=shlex.split(run(['pkg-config','--cflags','libbpf']))
            bpf_libs=shlex.split(run(['pkg-config','--libs','libbpf']))
        if any(not q.is_file() for q in inputs):
            raise ValueError('source or real dependency missing')
        run([args.host_cxx,'--version']);run([sdk/'bin/nvcc','--version'])
        for extension,flag in [('ptx','--ptx'),('cubin','--cubin')]:
            target=out/('tp_eval_verify.'+extension)
            run([sdk/'bin/nvcc',flag,'-arch='+args.arch,'-std=c++17','-ccbin',args.host_cxx,
                 source/'verify.cu','-o',target])
            receipt['artifacts'][extension]=str(target)
        target=out/'tp_eval'
        run([args.host_cxx,'-std=c++17','-O2','-g','-Wall','-Wextra','-Werror',
             '-I'+str(sdk/'include'),'-I'+str(base_headers),
             '-I'+str(view/'kernel/include/uapi'),'-I'+str(root/'src/lib'),
             '-I'+str(root/'src/compute/cuda'),'-I'+str(root/'src/core/include/uapi'),
             *bpf_cflags,source/'driver.cc',shared,base_shared,archive,
             '-L'+str(stub.parent),'-lcuda',*bpf_libs,'-lelf','-lz','-ldl','-pthread','-o',target])
        receipt['artifacts']['executable']=str(target)
        receipt['native_receipt']=str(args.native_receipt.resolve())
        receipt['runtime_library_dirs']=list(dict.fromkeys([str(shared.parent),str(base_shared.parent)]))
        receipt['status']='built'
    except (OSError,ValueError,KeyError,RuntimeError) as e:
        receipt['reason']=str(e)
    for q in inputs:
        receipt['sources'].append(dict(path=str(q),sha256=hashlib.sha256(q.read_bytes()).hexdigest())
                                  if q.is_file() else dict(path=str(q),missing=True))
    receipt['artifact_hashes']={k:hashlib.sha256(Path(v).read_bytes()).hexdigest() for k,v in receipt['artifacts'].items()}
    target_receipt=out/'eval-receipt.json'
    if target_receipt.exists():
        import time
        target_receipt.rename(out/('previous-eval-receipt-'+str(time.time_ns())+'.json'))
    target_receipt.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(status=receipt['status'],execution='not-run',receipt=str(target_receipt))))
    return 0 if receipt['status']=='built' else 1

if __name__=='__main__':raise SystemExit(main())

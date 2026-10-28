#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""EARLY selection at actual owned CUDA caller boundaries; no device/performance."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent


def build_owner(root,out):
    spec=importlib.util.spec_from_file_location('early_selection_layout',root/'tools/layout.py')
    m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
    layout=m.load_layout(root)
    headers=out/'headers'
    for src,logical in layout.by_source.items():
        if src.endswith('.h') and src.startswith(('src/lib/','src/compute/cuda/','src/core/include/uapi/')):
            path=headers/logical;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/src,path)
    boundary=out/'boundary';boundary.mkdir(exist_ok=True)
    shutil.copyfile(root/'tests/compute/tp/driver_boundary.h',boundary/'cuda.h')
    helper=(root/'tests/compute/tp/owner_lifetime_boundary.cc').read_text()
    # Only the dependency observer changes. Complete production owner is included
    # exactly as before; no project selection/body statements are transformed.
    marker='unsigned i=o->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE;allocation_fds[i]=o->allocation_fd;'
    if helper.count(marker)!=1:raise RuntimeError('existing endpoint boundary changed; not behavior RED')
    helper=helper.replace(marker,'unsigned i=o->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE;observed_flags[i]=o->flags;observed_direction[i]=o->direction;observed_endpoints++;allocation_fds[i]=o->allocation_fd;')
    helper=helper.replace('int main(int argc,char **argv){','int existing_owner_lifetime_main(int argc,char **argv){',1)
    fixture=out/'actual-owner-boundary.inc';fixture.write_text(helper)
    declared='xdev_ext_cuda_peer_owner_open_flags(' in (root/'src/compute/cuda/peer_endpoint_owner.h').read_text()
    command=[os.environ.get('CXX','g++'),'-std=c++17','-O0','-g','-Wall','-Wextra','-Wno-misleading-indentation',
             '-I'+str(boundary),'-I'+str(headers/'kernel/include/uapi')]
    for src in ('src/lib/libxdev_ext.h','src/compute/cuda/libxdev_ext_cuda.h'):
        command+=['-I'+str((headers/layout.logical(src)).parent)]
    command+=['-DTP_OWNER_SOURCE="'+str(root/'src/compute/cuda/peer_endpoint_owner.cc')+'"',
              '-DEARLY_OWNER_BOUNDARY="'+str(fixture)+'"','-DEARLY_SELECTION_NEW_API='+str(int(declared)),
              str(HERE/'owner_selection.cc'),'-o',str(out/'owner-selection')]
    built=subprocess.run(command,text=True,capture_output=True,timeout=60)
    (out/'owner-compile.log').write_text(built.stdout+built.stderr)
    if built.returncode:raise RuntimeError('owner fixture compilation/setup failure, not behavior RED')
    return declared,command


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv);root=args.source_root.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    result={'scope':'actual owned CUDA caller selection with controlled OS/CUDA/endpoint dependencies; no hardware/performance','cases':[]}
    try:
        declared,command=build_owner(root,out)
        result.update(adapter='new-api' if declared else 'frozen-legacy-behavior-probe',compile_exit=0,compile_command=command)
        cases=[]
        for mode in (1,2):
            for abi,flags in [('old',0),('new',0),('new',2),('new',1),('new',3),('new',4),('new',2147483648)]:
                cases.append(('success',mode,flags,abi))
            for fault in ('mem_second','register_second','event_sync'):
                cases.append((fault,mode,2,'new'))
        for fault,mode,flags,abi in cases:
            name=f'{fault}-d{mode}-flags{flags}-{abi}'
            run=subprocess.run([str(out/'owner-selection'),fault,str(mode),str(flags),abi,str(out/'boundary/cuda.h')],capture_output=True,text=True,timeout=10)
            (out/(name+'.log')).write_text(run.stdout+run.stderr);print(run.stdout+run.stderr,end='')
            if run.returncode not in (0,1):raise RuntimeError(name+' crashed; not behavior RED')
            result['cases'].append({'name':name,'exit':run.returncode})
        result['exit']=int(any(c['exit'] for c in result['cases']));result['state']='BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:
        result.update(exit=2,state='SETUP_ERROR',error=str(error));print(error)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result['exit']


if __name__=='__main__':raise SystemExit(main())

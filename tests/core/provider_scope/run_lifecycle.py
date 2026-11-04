#!/usr/bin/env python3
"""Compile actual DMA C against independent kernel boundaries, no device actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

CANDIDATE_CASES=['legacy-clean','legacy-unknown','lifetime','registration','bind-lifetime','same-owner',
                 'acquire-errors','admission-order','scope-precedence','lease-alloc','region-error',
                 'host-error','polled-error','direction-error','geometry-error','depth-window',
                 'host-retain','region-retain','independent-alias','unknown-mixed','legacy-known-mixed',
                 'group-same','group-shifted','group-disjoint','group-distinct','cleanup-hold','partial-cleanup']

def fingerprint(path):
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--dma-source',type=Path)
    p.add_argument('--scope-header',type=Path)
    p.add_argument('--mode',choices=['candidate','legacy-control'],default='candidate')
    p.add_argument('--case',default='all',choices=['all']+CANDIDATE_CASES)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--sanitize',action='store_true')
    args=p.parse_args();root=args.source_root.resolve();out=args.output.resolve();here=Path(__file__).resolve().parent
    out.mkdir(parents=True,exist_ok=True);fixtures=out/'fixtures';fixtures.mkdir(exist_ok=True)
    for name in ['kernel_boundary.h','lifecycle.c','contract.h','run_lifecycle.py']:shutil.copy2(here/name,fixtures/name)
    shutil.copytree(here/'shim',fixtures/'shim',dirs_exist_ok=True)
    source=args.dma_source.resolve() if args.dma_source else root/'src/core/io_uring/xdev_ext_mech_dma.c'
    public=root/'src/core/include/linux/xdev_ext_mech.h'
    scope=args.scope_header.resolve() if args.scope_header else root/'src/core/include/linux/xdev_ext_dma_scope_core.h'
    receipt={'mode':args.mode,'cohort':'actual production DMA control flow','source_root':str(root),'commands':[],'runs':[]}
    required=[source,public]+([scope] if args.mode=='candidate' else [])
    # Follow the selected adapter's production include edges. Historical DMA
    # sources without the shared helpers must keep their own actual algorithms.
    shared_sources={}
    if source.is_file():
        adapter=source.read_text()
        for header,unit,macro in (
                ('xdev_ext_compfam_copy_runtime.h','xdev_ext_compfam_copy.c','XDEV_COPY_RUNTIME_SOURCE'),
                ('xdev_ext_compfam_copy_lease.h','xdev_ext_compfam_copy_lease.c','XDEV_COPY_LEASE_SOURCE')):
            if re.search(r'^\s*#\s*include\s*"'+re.escape(header)+r'"',adapter,re.M):
                path=root/'src/compute/io_uring'/unit
                required.append(path);shared_sources[macro]=path
    receipt['shared_sources']={macro:str(path) for macro,path in shared_sources.items()}
    if any(not path.is_file() for path in required):
        receipt.update(status='SETUP',reason='required production source/API unavailable')
        (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print('SETUP: production scoped API/source unavailable');return 2
    receipt['inputs']=[fingerprint(path) for path in required]
    evidence=out/'production-inputs';evidence.mkdir(exist_ok=True)
    for path in required:shutil.copy2(path,evidence/path.name)
    command=['gcc','-O1','-g','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
             '-D__KERNEL__','-DXDEV_PUBLIC_HEADER="'+str(public)+'"','-DXDEV_DMA_SOURCE="'+str(source)+'"',
             '-I'+str(fixtures/'shim'),'-I'+str(root/'src/core/include'),
             '-I'+str(root/'src/core/io_uring'),'-I'+str(root/'src/compute/include'),
             '-I'+str(root/'src/compute/io_uring'),'-I'+str(fixtures)]
    if args.mode=='candidate':command+=['-DXDEV_SCOPE_HEADER="'+str(scope)+'"']
    else:command+=['-DDMA_SCOPE_LEGACY_CONTROL']
    for macro,path in shared_sources.items():command+=['-D'+macro+'="'+str(path)+'"']
    if args.sanitize:command+=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
    command+=[str(fixtures/'lifecycle.c'),'-o',str(out/'lifecycle')]
    result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/'compile.log').write_text(result.stdout);print(result.stdout,end='');receipt['commands'].append({'argv':command,'exit':result.returncode})
    if result.returncode:
        receipt['status']='SETUP';(out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');return 2
    cases=(['legacy-clean','legacy-unknown'] if args.mode=='legacy-control' else CANDIDATE_CASES) if args.case=='all' else [args.case]
    failed=False
    environment=os.environ.copy()
    if args.sanitize:
        # Quarantined stage/batch allocations intentionally survive process
        # exit. Keep ASan/UBSan memory checks; leak reclamation is not an oracle.
        environment['ASAN_OPTIONS']=environment.get('ASAN_OPTIONS','')+':detect_leaks=0'
        receipt['sanitizer_boundary']='ASan/UBSan, leak detection disabled for intentional retained objects'
    for case in cases:
        command=[str(out/'lifecycle'),case]
        try:
            result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20,env=environment)
            code=result.returncode;output=result.stdout
        except subprocess.TimeoutExpired as error:
            code=124;output=error.stdout or ''
            if isinstance(output,bytes):output=output.decode(errors='replace')
            output+='\nTIMEOUT\n'
        (out/(case+'.log')).write_text(output);print(output,end='');receipt['runs'].append({'case':case,'command':command,'exit':code});failed|=code!=0
    receipt['inputs_after']=[fingerprint(path) for path in required]
    receipt['status']='INPUT_CHANGED' if receipt['inputs_after']!=receipt['inputs'] else ('ASSERTION_FAILURE' if failed else 'PASS')
    if receipt['status']=='INPUT_CHANGED':failed=True
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');return 1 if failed else 0

if __name__=='__main__':raise SystemExit(main())

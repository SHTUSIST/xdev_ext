#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent op10 conformance on real lib/ctl; external syscalls only."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source-root',type=Path)
    p.add_argument('--out','--output',dest='out',required=True,type=Path)
    p.add_argument('--libbpf-build',type=Path,default=os.environ.get('LIBBPF_BUILD'))
    a=p.parse_args()
    test=Path(__file__).resolve().parent
    root=(a.source_root or test.parents[3]).resolve()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location('r3_layout',root/'tools/layout.py')
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    layout=module.load_layout(root);view=out/'view';inputs=[]
    # Isolated build view; no changes to canonical source or layout manifest.
    for source,logical in layout.by_source.items():
        if logical.startswith('kernel/') and (source.endswith('.h') or source in (
                'src/lib/xdev_ext_session.c','src/lib/xdev_ext_link.c',
                'src/cli/xdev_ext_mech_ctl.c','src/cli/xdev_ext_xsk_redirect.c','src/cli/xdev_ext_gpu_identity.c')):
            dst=view/logical;dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/source,dst);inputs.append(source)
    (out/'inputs.json').write_text(json.dumps({'canonical_root':str(root),'inputs':inputs},indent=2)+'\n')
    kernel=view/'kernel';lib=kernel/'tools/xdev_ext_mech/lib'
    bpf=Path(a.libbpf_build) if a.libbpf_build else None
    cc=os.environ.get('CC','gcc');flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-I',str(kernel),'-I',str(lib)]
    if bpf:flags+=['-I',str(bpf/'include')]
    commands=[ [cc,*flags,str(test/'test.c'),str(lib/'xdev_ext_session.c'),'-o',str(out/'test')],
        [cc,*flags,str(kernel/'tools/xdev_ext_mech/xdev_ext_mech_ctl.c'),str(lib/'xdev_ext_link.c'),str(lib/'xdev_ext_session.c'),str(kernel/'tools/xdev_ext_xsk_redirect.c'),str(kernel/'tools/xdev_ext_gpu_identity.c'),str(test/'ctl_hooks.c'),'-Wl,--wrap=syscall','-Wl,--wrap=ioctl','-Wl,--wrap=open',str(bpf/'libbpf.a') if bpf else '-lbpf','-lelf','-lz','-ldl','-o',str(out/'ctl')] ]
    verdict={'classification':'postimplementation-independent-conformance','scope':'normal lib/ctl CREATE_REPORT op10; injected external syscall replies; no kernel admission, stage_diag, hardware, performance','build_exit':0,'test_exit':None,'ctl':[]}
    with (out/'build.log').open('w') as log:
        for command in commands:
            log.write('+ '+' '.join(command)+'\n');log.flush()
            result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
            if result.returncode:
                verdict['build_exit']=result.returncode
                (out/'verdict.json').write_text(json.dumps(verdict,indent=2)+'\n')
                print('SETUP: compiler/linker error; see',out/'build.log');return 2
    result=subprocess.run([str(out/'test')],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
    (out/'tap.log').write_text(result.stdout);print(result.stdout,end='');verdict['test_exit']=result.returncode
    failed=bool(result.returncode)
    for name,diagnostics,unsupported in [('diagnostics',True,False),('unsupported',True,True),('legacy',False,False)]:
        command=[str(out/'ctl'),'cpu-chain','--src-ng','/dev/ng0n1','--slba','0','--nlb','8','--dst-ng','/dev/ng0n1','--dst-slba','8','--dst-nlb','8','--xform','crc32c-seal','--groups','1','--depth','1','--group-bytes','4096']
        if diagnostics:command+=['--diagnostics']
        env=dict(os.environ)
        env.pop('R3_UNSUPPORTED',None)
        if unsupported:env['R3_UNSUPPORTED']='1'
        result=subprocess.run(command,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
        (out/('ctl-'+name+'.log')).write_text(result.stdout)
        expected=['HOOK op=10','diagnostics=unavailable'] if unsupported else (['HOOK op=10','result=-18','rollback_errno=-5','phase=12','stage=0','cleanup=1','valid=15','requester=0003:04:02.1','reachability=3','refused=1'] if diagnostics else ['HOOK op=1'])
        errors=[f'missing {s}' for s in expected if s not in result.stdout]
        ops=[line for line in result.stdout.splitlines() if line.startswith('HOOK op=')]
        if len(ops)!=1:errors.append('expected exactly one CREATE attempt and no START/STOP')
        if result.returncode==0:errors.append('failed CREATE must leave command failed')
        verdict['ctl'].append({'name':name,'exit':result.returncode,'errors':errors})
        print(('not ok' if errors else 'ok')+' - ctl '+name+': '+('; '.join(errors) or 'metadata and single attempt'))
        failed|=bool(errors)
    (out/'verdict.json').write_text(json.dumps(verdict,indent=2)+'\n')
    return 1 if failed else 0
if __name__=='__main__':raise SystemExit(main())

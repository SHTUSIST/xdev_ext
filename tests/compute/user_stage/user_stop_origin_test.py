#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent actual USER/core completion-origin contracts.

The existing qualified strict_async generator supplies complete production USER
and real core external completion/publication/handoff bodies. Only its final
exercise/main is replaced. Return 1 for behavior failures, 2 for setup and 0
for all selected cases passing. No kernel, provider, device or DMA is introduced.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
CASES=('user-zero','user-error','user-protocol','user-badlen','user-unknown',
       'core-error','core-unknown','stale-duplicate','active-zero')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod)
    return mod


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--case',choices=CASES)
    a=p.parse_args();root=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    receipt={'scope':'host actual USER TU and core completion/publication; no kernel or hardware',
             'source_root':str(root),'cases':[]}
    try:
        layoutmod=load('user_stop_layout',root/'tools/layout.py')
        layout=layoutmod.load_layout(root)
        view=layoutmod.materialize_view(root,out/'source-view')
        strict_path=view.root/layout.logical('tests/compute/user_stage/strict_async_test.py')
        sys.path.insert(0,str(strict_path.parent))
        kernel=view.root/'kernel';os.environ['KERNEL_SRC']=str(kernel)
        strict=load('user_stop_strict',strict_path)
        code=strict.generate()
        marker='static int exercise(const char *mode)'
        if code.count(marker)!=1:raise RuntimeError('strict test entry boundary changed')
        code=code[:code.index(marker)]+(HERE/'user_stop_origin_fixture.c').read_text()
        cfile=out/'actual.c';binary=out/'actual';cfile.write_text(code)
        cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
             '-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter',
             '-fsanitize=undefined','-fno-sanitize-recover=undefined','-pthread',
             '-I'+str(kernel),'-I'+str(strict_path.parent.parent),'-I'+str(strict_path.parent),
             str(cfile),'-o',str(binary)]
        built=subprocess.run(cmd,text=True,capture_output=True,timeout=60)
        (out/'compile.log').write_text(built.stdout+built.stderr)
        receipt.update(compile_command=cmd,compile_exit=built.returncode)
        if built.returncode:raise RuntimeError('compile failed; no behavior RED')
        for name in CASES:
            if a.case is not None and name!=a.case:continue
            run=subprocess.run([str(binary),name],text=True,capture_output=True,timeout=15)
            (out/(name+'.log')).write_text(run.stdout+run.stderr)
            receipt['cases'].append({'case':name,'exit':run.returncode})
            print(run.stdout+run.stderr,end='')
            if run.returncode not in (0,1):raise RuntimeError(name+' crashed; no behavior RED')
        receipt['exit']=int(any(r['exit'] for r in receipt['cases']))
        receipt['state']='BEHAVIOR_RED' if receipt['exit'] else 'SCOPED_PASS'
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        receipt.update(exit=2,state='SETUP_ERROR',error=str(exc));print('SETUP: '+str(exc),file=sys.stderr)
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('state='+receipt['state']+' exit='+str(receipt['exit']))
    return receipt['exit']


if __name__=='__main__':raise SystemExit(main())

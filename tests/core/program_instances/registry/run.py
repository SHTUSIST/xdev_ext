#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production PRIVATE registry semantics with controlled OS/ref shims."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

HERE=Path(__file__).resolve().parent


def function(text,name):
    match=re.search(r'^[A-Za-z_][^;{}=()]*?\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{',text,re.M)
    if not match:raise RuntimeError('missing actual definition '+name)
    depth=0
    for at in range(text.index('{',match.start()),len(text)):
        depth+={'{':1,'}':-1}.get(text[at],0)
        if not depth:return text[match.start():at+1]
    raise RuntimeError('unbalanced actual definition '+name)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(argv);root=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    result={'scope':'actual production registry/reg/flag bodies; host OS/ref/synchronization boundaries only','cases':[]}
    try:
        ops=(root/'src/core/io_uring/xdev_ext_mech_ops.c').read_text();core=(root/'src/core/io_uring/xdev_ext_ops_core.c').read_text()
        header=(root/'src/core/io_uring/xdev_ext_ops_core.h').read_text();mech=(root/'src/core/include/linux/xdev_ext_mech.h').read_text()
        binding=(root/'src/core/include/linux/xdev_ext_binding.h').read_text()
        struct=header[header.index('struct xdev_ext_ops_registry {'):header.index('\n};',header.index('struct xdev_ext_ops_registry {'))+3]
        known=re.search(r'^#define XDEV_EXT_MECH_OPS_KNOWN_FLAGS[^\n]*',mech,re.M)
        if not known:raise RuntimeError('actual flags declaration missing; setup only')
        names=[(header,'xdev_ext_ops_is_current'),(core,'xdev_ext_ops_publish'),(core,'xdev_ext_ops_retract'),(core,'xdev_ext_ops_pin'),(core,'xdev_ext_ops_unpin'),(ops,'xdev_ext_mech_flags_known'),(ops,'xdev_ext_mech_reg'),
               (ops,'xdev_ext_mech_unreg'),(binding,'xdev_ext_binding_backend_known'),(binding,'xdev_ext_binding_ops_flags_valid')]
        fixture=(HERE/'registry_fixture.c.in').read_text().replace('@REGISTRY_STRUCT@',struct).replace('@FLAGS_CONSTANT@',known.group())
        component=root/'src/core/io_uring/programs/instances.c'
        present=component.is_file()
        # Mechanical source inclusion only; no registry/pin/liveness logic is
        # substituted. Standard kernel includes are supplied by labeled shims.
        body=re.sub(r'^#include[^\n]*\n','',component.read_text(),flags=re.M) if present else ''
        fixture=fixture.replace('@PRIVATE_COMPONENT@',body)
        signature=function(ops,'xdev_ext_mech_unreg').split('{',1)[0]
        unreg='xdev_ext_mech_unreg(link->class_id,(void *)link->ops'+(',link' if 'struct bpf_link' in signature else '')+');'
        lifetime=(HERE/'lifetime_fixture.c.in').read_text().replace('@ACTUAL_UNREGISTER_CALL@',unreg)
        fixture=fixture.replace('@LIFETIME_FUNCTIONS@',lifetime)
        result['adapter']='actual-private-component' if present else 'actual-baseline-reg-and-flags'
        fixture=fixture.replace('@ACTUAL_FUNCTIONS@' ,'\n'.join(function(text,name) for text,name in names))
        path=out/'registry.c';path.write_text(fixture);binary=out/'registry'
        cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-O0','-g','-Wall','-Wextra','-Werror','-Wno-unused-function',
             '-I'+str(root/'src/core/include/uapi/linux'),'-I'+str(HERE),
             '-DINSTANCE_API_PRESENT='+str(int(present)),'-DINSTANCE_FAMILY_HEADER=\"'+str(root/'src/core/include/linux/xdev_ext_family_core.h')+'\"',str(path),'-o',str(binary)]
        built=subprocess.run(cmd,text=True,capture_output=True,timeout=30);(out/'compile.log').write_text(built.stdout+built.stderr)
        result.update(compile_exit=built.returncode,compile_command=cmd)
        if built.returncode:raise RuntimeError('actual registry fixture compile/setup failure, not behavior RED')
        cases=['flags','coexist','null','global','policy']
        if present:cases+=['life-'+name for name in ('fd-errors','same-map','reentrant-put','detached-live-fd','wrong-withdraw','pin-failure','wrong-class','independent')]
        else:result['private_lifetime_scope']='unavailable before implementation; not a PASS'
        for case in cases:
            run=subprocess.run([str(binary),case],text=True,capture_output=True,timeout=5)
            (out/(case+'.log')).write_text(run.stdout+run.stderr);print(run.stdout+run.stderr,end='')
            if run.returncode not in (0,1):raise RuntimeError(case+' crash/setup, not behavior RED')
            result['cases'].append({'case':case,'exit':run.returncode})
        result['exit']=int(any(c['exit'] for c in result['cases']));result['state']='BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:result.update(exit=2,state='SETUP_ERROR',error=str(error));print(error)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result['exit']


if __name__=='__main__':raise SystemExit(main())

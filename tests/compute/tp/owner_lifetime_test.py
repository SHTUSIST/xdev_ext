#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Complete production duplex owner under controlled CUDA/OS failure boundaries."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent
CASES=('success','mem_second','register_second','event_record','event_sync','native_stop','control_close','endpoint_close','authority_close','mem_free','required_classes')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);r={'scope':'actual complete owner TU with CUDA/syscall/message boundaries; no GPU/device execution','cases':[]}
    try:
        spec=importlib.util.spec_from_file_location('tp_owner_layout',a.source_root/'tools/layout.py');m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
        layout=m.load_layout(a.source_root);view=m.materialize_view(a.source_root,out/'source-view');facade=out/'boundary';facade.mkdir(exist_ok=True);shutil.copyfile(HERE/'driver_boundary.h',facade/'cuda.h')
        source=a.source_root/'src/compute/cuda/peer_endpoint_owner.cc';binary=out/'owner-lifetime'
        extract_spec=importlib.util.spec_from_file_location('tp_owner_extract',a.source_root/'tests/core/admission_report/run.py');extract=importlib.util.module_from_spec(extract_spec);extract_spec.loader.exec_module(extract)
        core=(a.source_root/'src/core/io_uring/xdev_ext_ops_core.c').read_text();ops=(a.source_root/'src/core/io_uring/xdev_ext_mech_ops.c').read_text();rules=(a.source_root/'src/core/io_uring/xdev_ext_mech_core.h').read_text()
        registry=out/'actual-registry.c';registry.write_text('''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <linux/xdev_ext_family_core.h>
typedef __u32 u32;
struct module {int unused;};struct bpf_link {int unused;};struct mutex {bool held;};struct static_key_false {int unused;};
struct xdev_ext_ops_registry {struct mutex lock;struct static_key_false *key;const void **slots;u32 nr_slots,nr_active;};
static void mutex_lock(struct mutex *m){assert(!m->held);m->held=true;}
static void mutex_unlock(struct mutex *m){assert(m->held);m->held=false;}
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_access_pointer(p) (p)
#define rcu_dereference(p) (p)
#define rcu_assign_pointer(p,v) ((p)=(v))
static void synchronize_rcu(void){}
static void static_branch_enable(struct static_key_false *p){(void)p;}
static void static_branch_disable(struct static_key_false *p){(void)p;}
static bool bpf_struct_ops_get(const void *p){return p!=NULL;}
static const void *registry_slots[XDEV_EXT_MECH_CLASS_MAX];
static struct xdev_ext_ops_registry xdev_ext_mech_registry={.slots=registry_slots,.nr_slots=XDEV_EXT_MECH_CLASS_MAX};
''' + extract.function(rules,'xdev_ext_mech_class_known')+'\n'+
          '\n'.join(extract.function(core,n) for n in ('xdev_ext_ops_publish','xdev_ext_ops_retract','xdev_ext_ops_pin'))+'\n'+extract.function(ops,'xdev_ext_mech_ops_get')+'''
int owner_registry_attach(unsigned id,const void *p){return xdev_ext_ops_publish(&xdev_ext_mech_registry,id,p,(struct bpf_link *)1);}
int owner_registry_detach(unsigned id,const void *p){return xdev_ext_ops_retract(&xdev_ext_mech_registry,id,p)?0:-ENOENT;}
bool owner_registry_has(unsigned id){bool pinned;struct module *owner;return xdev_ext_mech_ops_get(id,&pinned,&owner)!=NULL;}
''')
        registry_obj=out/'registry.o';registry_cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-I'+str(view.root/'kernel/include'),'-I'+str(view.root/'kernel/include/uapi'),'-c',str(registry),'-o',str(registry_obj)]
        registry_build=subprocess.run(registry_cmd,text=True,capture_output=True,timeout=30);(out/'registry-compile.log').write_text(registry_build.stdout+registry_build.stderr)
        if registry_build.returncode:raise RuntimeError('real C registry boundary failed to compile; not behavior RED')
        cmd=[os.environ.get('CXX','g++'),'-std=c++17','-O0','-g','-Wall','-Wextra','-Wno-misleading-indentation','-I'+str(facade),'-I'+str(view.root/'kernel/include/uapi'),
          '-DTP_OWNER_SOURCE="'+str(source.resolve())+'"',str(HERE/'owner_lifetime_boundary.cc'),str(registry_obj),'-o',str(binary)]
        for path in ('src/lib/libxdev_ext.h','src/compute/cuda/libxdev_ext_cuda.h'):cmd.insert(1,'-I'+str((view.root/layout.logical(path)).parent))
        built=subprocess.run(cmd,text=True,capture_output=True,timeout=60);(out/'compile.log').write_text(built.stdout+built.stderr);r.update(compile_exit=built.returncode,compile_command=cmd)
        if built.returncode:raise RuntimeError('owner boundary compile failed; not behavior RED')
        for case in CASES:
            run=subprocess.run([str(binary),case,str(facade/'cuda.h')],text=True,capture_output=True,timeout=15);(out/(case+'.log')).write_text(run.stdout+run.stderr);print(run.stdout+run.stderr,end='')
            if run.returncode not in (0,1):raise RuntimeError(case+' setup/crash, not behavior RED')
            r['cases'].append({'case':case,'exit':run.returncode})
        r['exit']=int(any(c['exit'] for c in r['cases']));r['state']='BEHAVIOR_RED' if r['exit'] else 'SCOPED_PASS'
    except Exception as error:r.update(exit=2,state='SETUP_ERROR',error=str(error));print(str(error))
    (out/'result.json').write_text(json.dumps(r,indent=2)+'\n');return r['exit']


if __name__=='__main__':raise SystemExit(main())

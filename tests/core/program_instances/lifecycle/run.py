#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""PRIVATE pins through existing native pending/drain/UNKNOWN and C defaults."""
import argparse,importlib.util,json,os,re,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def definition(text,name):
 match=re.search(r'^\w[^;{}]*?\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{',text,re.M)
 if not match:raise RuntimeError('missing actual '+name)
 depth=0
 for at in range(text.index('{',match.start()),len(text)):
  depth+={'{':1,'}':-1}.get(text[at],0)
  if not depth:return text[match.start():at+1]
 raise RuntimeError('unbalanced '+name)

def generate(root):
 os.environ['KERNEL_SRC']=str(root)
 extract=load('private_native_extract',root/'tests/core/provider/faults/run.py');extract.function=definition
 text=extract.generate()
 core=(root/'src/core/io_uring/xdev_ext_mech.c').read_text();ops=(root/'src/core/io_uring/xdev_ext_mech_ops.c').read_text()
 shared=(root/'src/core/io_uring/xdev_ext_ops_core.c').read_text();header=(root/'src/core/io_uring/xdev_ext_ops_core.h').read_text();abi=(root/'src/core/include/linux/xdev_ext_mech.h').read_text()
 text=text.replace(definition(text,'xdev_ext_ops_unpin'),'')
 # Retire only the default-only fixture trap; the real component supplies put.
 try:old=definition(text,'xdev_ext_mech_instance_put')
 except RuntimeError:old=None
 if old:text=text.replace(old,'')
 layout=re.search(r'^#define XDEV_EXT_MECH_OPS_TYPE\(name\).*?^}',abi,re.M|re.S)
 if not layout:raise RuntimeError('actual ops layout missing')
 types=layout.group()+'\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_mech_c_ops);'
 start=header.index('struct xdev_ext_ops_registry {');registry=header[start:header.index('\n};',start)+3].replace('struct mutex lock;','pthread_mutex_t lock;')
 boundary=(HERE/'program_boundary.h').read_text().replace('/* ACTUAL_OPS_TYPES */',types).replace('/* ACTUAL_GLOBAL_REGISTRY_STRUCT */',registry)
 names=[(header,'xdev_ext_ops_is_current'),(shared,'xdev_ext_ops_publish'),(shared,'xdev_ext_ops_pin'),(shared,'xdev_ext_ops_unpin'),(ops,'xdev_ext_mech_ops_get'),(ops,'xdev_ext_mech_ops_current')]
 helpers='\n'.join(definition(source,name) for source,name in names)
 first=definition(text,'xdev_ext_mech_class_put');text=text.replace(first,boundary+'\n'+helpers+'\n'+first,1)
 private=re.sub(r'^#include[^\n]*\n','',(root/'src/core/io_uring/programs/instances.c').read_text(),flags=re.M)
 early='\n'.join(definition(core,n) for n in ('xdev_ext_mech_programs_current','xdev_ext_mech_session_admits','xdev_ext_mech_stop_reason'))
 stop=definition(text,'xdev_ext_mech_session_stop');notifiers='\n'.join(definition(core,n) for n in ('xdev_ext_mech_generation_gone','xdev_ext_mech_instance_gone'))
 text=text.replace(stop,stop+'\n'+private+'\n'+early+'\n'+notifiers+'\n'+definition(ops,'__xdev_ext_mech_set_c_ops'),1)
 late='static void xdev_ext_mech_release_late(struct xdev_ext_mech_session *);\n'+definition(core,'xdev_ext_mech_release_late')+'\n'+definition(core,'xdev_ext_mech_reap')
 marker='/* Native provider fixture:';text=text.replace(marker,late+'\n'+marker,1)
 text=text.replace('int main(int argc,char **argv) {','int existing_provider_main(int argc,char **argv) {',1)
 cases=(HERE/'cases.c').read_text();bind=definition(core,'xdev_ext_mech_session_bind')
 prefix=bind[:bind.index('\n\ts->create_failed_stage = U32_MAX;')].replace('xdev_ext_mech_session_bind(','selected_prefix(',1)+'\n return 0;\n}'
 return text+'\n'+cases.replace('/* ACTUAL_SELECTION_PREFIX */',prefix)

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args(argv);root=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 result={'scope':'existing actual DMA adapter/provider boundary + real PRIVATE selection/STOP/reap/release; controlled host callback/module/BPF refs, no hardware or memory-order certification','cases':[]}
 try:
  layout=load('private_native_layout',root/'tools/layout.py').load_layout(root);headers=out/'headers'
  for (component,native),source in layout.by_native.items():
   if component=='linux' and native.endswith('.h'):
    path=headers/native;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((root/source).read_bytes())
  src=out/'lifecycle.c';src.write_text(generate(root));binary=out/'lifecycle'
  cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-DCONFIG_XDEV_EXT_MECH_C_REFERENCE=1','-I'+str(headers),str(src),'-o',str(binary)]
  built=subprocess.run(cmd,capture_output=True,text=True,timeout=60);(out/'compile.log').write_text(built.stdout+built.stderr);result.update(compile_exit=built.returncode,compile_command=cmd)
  if built.returncode:raise RuntimeError('native lifetime composition compile/setup failure; not behavior evidence')
  for case in ('late-exact','late-ambiguous','native-control','c-reference'):
   ran=subprocess.run([str(binary),case],capture_output=True,text=True,timeout=15);(out/(case+'.log')).write_text(ran.stdout+ran.stderr);print(ran.stdout+ran.stderr,end='')
   if ran.returncode not in (0,1) or 'runtime error:' in ran.stderr:raise RuntimeError(case+' crash/sanitizer/setup failure; not behavior evidence')
   result['cases'].append({'case':case,'exit':ran.returncode})
  result['exit']=int(any(c['exit'] for c in result['cases']));result['state']='BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
 except Exception as error:result.update(exit=2,state='SETUP_ERROR',error=str(error));print(error)
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result['exit']
if __name__=='__main__':raise SystemExit(main())

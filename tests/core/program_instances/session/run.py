#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Original real CREATE/bind/report/release composition; new selector wire.

OS/device/PREPARE invocation boundaries reuse the independently qualified
admission fixture. This mode certifies wire/control-flow only, not private
instance lookup or sealed invocation. Those require core-call/actual guest.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'source-layout.json').is_file())
CASES=('default_delivery','prepare_report','unknown_retention','copyout_failure','unused_selector','outer_shape','pool_role_unchanged')
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,default=ROOT);p.add_argument('--output',type=Path,required=True);p.add_argument('--case',choices=CASES);p.add_argument('--suite',choices=('core','library'),default='core');a=p.parse_args()
 root=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 result={'scope':'actual core CREATE/bind/release wire control flow; host environmental device/BPF boundaries','hardware':False,'kernel_execution':False,'commands':[],'cases':[]}
 try:
  mapping=module('sp_layout',root/'tools/layout.py').load_layout(root);native=out/'headers'
  for (component,name),source in mapping.by_native.items():
   if component=='linux' and name.endswith('.h'):
    dst=native/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((root/source).read_bytes())
  if a.suite=='library':
   source_name=mapping.by_native[('linux','tools/xdev_ext_mech/lib/xdev_ext_session.c')]
   target=native/'tools/xdev_ext_mech/lib/xdev_ext_session.c';target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/source_name).read_bytes())
   (out/'session_wire.h').write_bytes((HERE/'wire.h').read_bytes());exe=out/'library'
   cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(native),'-I'+str(out),str(HERE/'library.c'),str(target),'-o',str(exe)]
   r=subprocess.run(cmd,text=True,capture_output=True,timeout=60);(out/'compile.log').write_text(r.stdout+r.stderr);result.update(compile_command=cmd,compile_exit=r.returncode)
   if r.returncode:raise RuntimeError('library compile failed; setup only')
   r=subprocess.run([str(exe)],text=True,capture_output=True,timeout=15);(out/'library.log').write_text(r.stdout+r.stderr)
   result.update(exit=r.returncode,state='SETUP_ERROR' if r.returncode==2 else 'BEHAVIOR_RED' if r.returncode else 'SCOPED_PASS');print(r.stdout+r.stderr,end='')
   (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return r.returncode
  admission=root/'tests/core/admission_report';extract=module('sp_admission_extract',admission/'run.py')
  core=(root/'src/core/io_uring/xdev_ext_mech.c').read_text();rq=(root/'src/core/io_uring/family/xdev_ext_requester.c').read_text()
  groups={'REQUESTER':(rq,('xdev_ext_requester_bind','xdev_ext_requester_unbind')),'ADMITS':(core,tuple(n for n in ('xdev_ext_mech_programs_current','xdev_ext_mech_session_admits') if n+'(' in core)),'BATCH_GET':(core,('xdev_ext_mech_batch_get_locked',)),'BIND':(core,('xdev_ext_mech_class_bind','xdev_ext_mech_session_bind')),'RELEASE':(core,('xdev_ext_mech_unbind_checked','xdev_ext_mech_session_release_disposition','xdev_ext_mech_session_release_report','xdev_ext_mech_session_release')),'CREATE':(core,('xdev_ext_mech_create_common','xdev_ext_mech_create','xdev_ext_mech_create_report_op')+tuple(n for n in ('xdev_ext_mech_create_programs_op',) if n+'(' in core)),'CAPS':(core,('xdev_ext_mech_stage_caps_op',)),'DISPATCH':(core,('io_xdev_ext_mech_register',))}
  text=(admission/'fixture.c.in').read_text();bodies={}
  # Extend only the private host session shape. The actual selected-instance
  # registry is outside this default-only wire suite; every use aborts.
  def replace_once(old,new):
   nonlocal text
   if text.count(old)!=1:raise RuntimeError('environment boundary anchor changed: '+old)
   text=text.replace(old,new)
  replace_once('typedef uint32_t u32;', 'typedef int32_t s32; typedef uint32_t u32;')
  replace_once('struct xdev_ext_mech_session {', 'struct xdev_ext_mech_instance;\nstruct xdev_ext_mech_session {\n struct xdev_ext_mech_instance *instances[XDEV_EXT_MECH_MAX_STAGES];')
  replace_once('static int xdev_ext_mech_all_lock', '#include "default_boundary.h"\nstatic int xdev_ext_mech_all_lock')
  (out/'default_boundary.h').write_bytes((HERE/'default_boundary.h').read_bytes())
  for token,(source,names) in groups.items():
   selected=[extract.function(source,n) for n in names]
   for n,s in zip(names,selected):bodies[n]=hashlib.sha256(s.encode()).hexdigest()
   text=text.replace('/* '+token+' */','\n'.join(selected))
  # Keep qualified environment/setup helpers, replace its main only; no old case is rewritten.
  text=text.replace('int main(int argc,char **argv)','int sp_unused_original_main(int argc,char **argv)')
  text+='\n'+(HERE/'core_cases.c').read_text()
  (out/'wire.h').write_bytes((admission/'wire.h').read_bytes());(out/'session_wire.h').write_bytes((HERE/'wire.h').read_bytes())
  src=out/'core.c';src.write_text(text);exe=out/'core'
  cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-Wno-unused-variable','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(native),'-I'+str(out),str(src),'-o',str(exe)]
  r=subprocess.run(cmd,text=True,capture_output=True,timeout=60);(out/'compile.log').write_text(r.stdout+r.stderr);result.update(compile_command=cmd,compile_exit=r.returncode,source_bodies=bodies)
  if r.returncode:raise RuntimeError('compile failed; setup only')
  for name in ([a.case] if a.case else CASES):
   r=subprocess.run([str(exe),name],text=True,capture_output=True,timeout=15);(out/(name+'.log')).write_text(r.stdout+r.stderr)
   if r.returncode not in (0,1):raise RuntimeError(name+' crashed/setup exit='+str(r.returncode))
   result['cases'].append({'case':name,'exit':r.returncode});print(('ok' if not r.returncode else 'not ok')+' - '+name);print(r.stdout+r.stderr,end='')
  result['exit']=int(any(c['exit'] for c in result['cases']));result['state']='BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
 except (OSError,RuntimeError,ValueError,subprocess.SubprocessError) as e:result.update(exit=2,state='SETUP_ERROR',error=str(e));print('SETUP:',e)
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('state='+result['state']);return result['exit']
if __name__=='__main__':raise SystemExit(main())

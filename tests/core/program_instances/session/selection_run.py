#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compose actual private registry, session binding, sealed invoke and release."""
import argparse,importlib.util,json,re,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'source-layout.json').is_file())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,default=ROOT);p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 result={'scope':'actual instance component, session bind/current/notifier, call/sealed-invoke/kfunc and release; single-threaded host OS/BPF-ref and CPU class/PREPARE boundary, not kernel synchronization or physical DMA','exit':2,'state':'SETUP_ERROR'}
 try:
  r=subprocess.run([sys.executable,str(HERE/'run.py'),'--source-root',str(root),'--output',str(out/'wire'),'--case','default_delivery'],capture_output=True,text=True,timeout=60);(out/'wire.log').write_text(r.stdout+r.stderr)
  if r.returncode:raise RuntimeError('wire composition unavailable; setup only for selected-call suite')
  text=(out/'wire/core.c').read_text();definition=load('sp_selection_extract',root/'tests/core/identity/call_identity_test.py').definition
  header=(root/'src/core/include/linux/xdev_ext_mech.h').read_text();internal=(root/'src/core/io_uring/xdev_ext_mech_internal.h').read_text();ops=(root/'src/core/io_uring/xdev_ext_mech_ops.c').read_text();core=(root/'src/core/io_uring/xdev_ext_mech.c').read_text()
  layout=re.search(r'^#define XDEV_EXT_MECH_OPS_TYPE\(name\).*?^}',header,re.M|re.S)
  if not layout:raise RuntimeError('actual struct_ops layout unavailable')
  declarations=layout.group()+'\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);\n'+'\n'.join(definition(header,n,True) for n in ('xdev_ext_mech_frame','xdev_ext_mech_call','xdev_ext_mech_call_args'))+'\n'+definition(internal,'xdev_ext_mech_target',True)
  boundary=(HERE/'selection_boundary.h').read_text().replace('/* SELECTION_DECLARATIONS */',declarations)
  def replace(old,new):
   nonlocal text
   if text.count(old)!=1:raise RuntimeError('environment anchor changed '+old[:60])
   text=text.replace(old,new)
  replace('#include "default_boundary.h"',boundary)
  replace('copyouts++;', 'copyouts++;host_copyout_hook();')
  replace('static int xdev_ext_mech_all_lock,xdev_ext_mech_live_lock;', 'static int xdev_ext_mech_all_lock;static struct host_mutex xdev_ext_mech_live_lock;')
  replace('u64 id; u32 frames,nr_stages,nr_bound;', 'int stop_err;struct xdev_ext_mech_layout layout;u64 id; u32 frames,nr_stages,nr_bound;')
  replace(definition(text,'xdev_ext_mech_ops_get'),'static const void *xdev_ext_mech_ops_get(u32 id,bool *p,void **m) { assert(id==9);default_gets++;*p=true;*m=NULL;assert(bpf_struct_ops_get(host_default));return host_default; }')
  replace(definition(text,'xdev_ext_mech_ops_put'),'static void xdev_ext_mech_ops_put(const void *o,bool p,void *m) { (void)m;if(p)bpf_struct_ops_put(o); }')
  replace(definition(text,'xdev_ext_mech_stop_reason'),'static bool xdev_ext_mech_programs_current(const struct xdev_ext_mech_session *);\n'+definition(core,'xdev_ext_mech_stop_reason'))
  replace(definition(text,'xdev_ext_mech_ops_current'),'static bool xdev_ext_mech_ops_current(u32 id,const void *ops,bool pinned) { assert(id==9&&pinned);return ops==host_default; }')
  replace(definition(text,'class_bind'),'static int class_bind(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_stage_uapi *u) { (void)u;describes++;st->priv=st;return 0; }')
  replace('id==XDEV_EXT_MECH_CLASS_NET?&net_class:NULL','id==XDEV_EXT_MECH_CLASS_CPU?&net_class:NULL')
  # The original core entry remains intact and renamed, never executes here.
  replace('int main(int argc,char **argv)','int sp_unused_wire_main(int argc,char **argv)')
  body=re.sub(r'^#include[^\n]*\n','',(root/'src/core/io_uring/programs/instances.c').read_text(),flags=re.M)
  active=re.search(r'^(?:static\s+)?DEFINE_PER_CPU\([^;]*\bxdev_ext_mech_active_call\s*\);',ops,re.M).group()
  magic=re.search(r'^#define XDEV_EXT_MECH_CALL_MAGIC\b.*$',header,re.M).group()
  invoke=[active,magic,definition(ops,'xdev_ext_mech_prepare_call',True),*re.findall(r'^(?:static\s+)?DEFINE_(?:HASHTABLE|(?:RAW_)?SPINLOCK)\([^;]*\);',ops,re.M),'typedef __s32 (*xdev_ext_mech_cb_t)(const struct xdev_ext_mech_ctx *ctx);']
  invoke.extend(definition(ops,n) for n in ('xdev_ext_mech_prepare_current','xdev_ext_mech_call_of','xdev_ext_mech_member_fn','xdev_ext_mech_ops_has_member','xdev_ext_mech_args_ok','xdev_ext_mech_invoke','xdev_ext_mech_frame_bytes','xdev_ext_mech_compute_frame','bpf_xdev_ext_frame_rw'))
  text+='\n'+body+'\n'+ '\n'.join(invoke)+'\n'+ '\n'.join(definition(core,n) for n in ('xdev_ext_mech_stage_ops','xdev_ext_mech_call','xdev_ext_mech_stage_has_member','xdev_ext_mech_instance_gone'))+'\n'+(HERE/'selection_cases.c').read_text()
  src=out/'selection.c';src.write_text(text);binary=out/'selection';cmd=['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-unused-variable','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(out/'wire/headers'),'-I'+str(out/'wire'),str(src),'-o',str(binary)]
  r=subprocess.run(cmd,text=True,capture_output=True,timeout=60);(out/'compile.log').write_text(r.stdout+r.stderr);result.update(compile_command=cmd,compile_exit=r.returncode)
  if r.returncode:raise RuntimeError('selected composition compile failed; not behavioral RED')
  r=subprocess.run([str(binary)],text=True,capture_output=True,timeout=15);(out/'selection.log').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr,end='')
  if r.returncode not in (0,1) or 'runtime error:' in r.stderr:raise RuntimeError('selected composition crashed/sanitizer; setup/diagnosis, not behavioral RED')
  result.update(exit=r.returncode,state='BEHAVIOR_RED' if r.returncode else 'SCOPED_PASS')
 except (OSError,RuntimeError,ValueError,AttributeError,AssertionError,subprocess.SubprocessError) as e:result['error']=str(e);print('SETUP:',e)
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('state='+result['state']);return result['exit']
if __name__=='__main__':raise SystemExit(main())

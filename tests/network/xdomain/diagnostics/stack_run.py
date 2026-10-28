#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compose existing actual-stack/NHI7 software fixture with true class diagnostics.

Only OS mutex and observation boundaries are adapted; production bodies and old
oracles remain unmodified. This is host software evidence, no kernel or hardware.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent
CASES=('pending-release','slot-reuse','error-unknown','cts-capacity','ack-decrement','ack-orders','lifecycle','control-capacity')
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

def replace(text,old,new):
 if text.count(old)!=1:raise RuntimeError('qualified environment anchor count: '+old[:100])
 return text.replace(old,new,1)

def execute(root,out,regs,selected,mutation):
 result=dict(scope='host actual-main/class/link/NHI/retention composition; no kernel/hardware/DMA/performance',cases=[])
 try:
  layout=load('stack_diag_layout',root/'tools/layout.py').load_layout(root)
  kernel=out/'source/kernel';kernel.mkdir(parents=True,exist_ok=True)
  for (component,name),source in layout.by_native.items():
   if component!='linux':continue
   dst=kernel/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/source,dst)
  shutil.copyfile(regs,kernel/'drivers/thunderbolt/nhi_regs.h')
  fixture=kernel/'tools/testing/selftests/xdev_ext_mech/xdomain'
  comp=fixture/'stack_kernel_compat.h';text=comp.read_text()
  text=replace(text,'struct mutex {unsigned held;};','#include <pthread.h>\n#include <sched.h>\nstruct mutex {unsigned held;pthread_mutex_t native;};\nvoid stack_diag_mutex_before(struct mutex *);\nvoid stack_diag_mutex_after(struct mutex *);')
  text=replace(text,'extern unsigned stack_spins,stack_mutexes;','extern _Thread_local unsigned stack_spins,stack_mutexes;')
  text=replace(text,'static inline void mutex_init(struct mutex *m){m->held=0;}','static inline void mutex_init(struct mutex *m){m->held=0;assert(!pthread_mutex_init(&m->native,NULL));}')
  text=replace(text,'static inline void mutex_lock(struct mutex *m){if(m->held)stack_lock_error();assert(!m->held);m->held=1;stack_mutexes++;}','static inline void mutex_lock(struct mutex *m){stack_diag_mutex_before(m);assert(!pthread_mutex_lock(&m->native));assert(!m->held);m->held=1;stack_mutexes++;stack_diag_mutex_after(m);}')
  text=replace(text,'static inline void mutex_unlock(struct mutex *m){assert(m->held&&stack_mutexes);m->held=0;stack_mutexes--;}','static inline void mutex_unlock(struct mutex *m){assert(m->held&&stack_mutexes);m->held=0;stack_mutexes--;assert(!pthread_mutex_unlock(&m->native));}')
  text=replace(text,'#define DEFINE_MUTEX(n) struct mutex n={0}','#define DEFINE_MUTEX(n) struct mutex n={.native=PTHREAD_MUTEX_INITIALIZER}')
  text=replace(text,'typedef struct {unsigned held;} spinlock_t;','typedef struct {unsigned held;pthread_mutex_t native;} spinlock_t;')
  text=replace(text,'static inline void spin_lock_init(spinlock_t *s){s->held=0;}','static inline void spin_lock_init(spinlock_t *s){s->held=0;assert(!pthread_mutex_init(&s->native,NULL));}')
  text=replace(text,'static inline void spin_lock_irq(spinlock_t *s){if(s->held)stack_lock_error();assert(!s->held);s->held=1;stack_spins++;}','static inline void spin_lock_irq(spinlock_t *s){assert(!pthread_mutex_lock(&s->native));assert(!s->held);s->held=1;stack_spins++;}')
  text=replace(text,'static inline void spin_unlock_irq(spinlock_t *s){assert(s->held&&stack_spins);s->held=0;stack_spins--;}','static inline void spin_unlock_irq(spinlock_t *s){assert(s->held&&stack_spins);s->held=0;stack_spins--;assert(!pthread_mutex_unlock(&s->native));}')
  text=replace(text,'#define DEFINE_SPINLOCK(n) spinlock_t n={0}','#define DEFINE_SPINLOCK(n) spinlock_t n={.native=PTHREAD_MUTEX_INITIALIZER}')
  comp.write_text(text)
  boundary=fixture/'stack_boundary.c';text=boundary.read_text()
  text=replace(text,'unsigned stack_spins,stack_mutexes;','_Thread_local unsigned stack_spins,stack_mutexes;')
  include='#include "../../../../../io_uring/family/xdev_ext_requester_retention.c"'
  text=replace(text,include,'#define xdev_ext_requester_retention_snapshot actual_stack_retention_snapshot\n'+include+'\n#undef xdev_ext_requester_retention_snapshot')
  boundary.write_text(text+'\n'+(HERE/'stack_boundary.c').read_text())
  cls=fixture/'stack_x5.c';cls.write_text(cls.read_text()+'\n'+(HERE/'stack_class.c').read_text())
  ring=fixture/'stack_x4.c';text=ring.read_text()
  text=replace(text,'#define xdev_ext_xd_class_ctl stack_record_dispatch','struct xdev_ext_requester_retention_stats;\nvoid stack_diag_native(struct tb_ring *,struct tb_ring_snapshot *);\nvoid stack_diag_retention(struct pci_dev *,struct xdev_ext_requester_retention_stats *);\n#define tb_ring_snapshot(r,s) stack_diag_native(r,s)\n#define xdev_ext_requester_retention_snapshot stack_diag_retention\n#define xdev_ext_xd_class_ctl stack_record_dispatch')
  ring.write_text(text)
  if mutation:
   cls=kernel/'io_uring/xdomain/xdev_ext_xdomain_class.c';text=cls.read_text()
   if mutation=='omit-ack':text=replace(text,'d.ack_owed++;','d.ack_owed += 0;')
   elif mutation=='omit-cts':text=replace(text,'d.cts_owed++;','d.cts_owed += 0;')
   elif mutation=='omit-downstream':text=replace(text,'d.downstream_release_pending++;','d.downstream_release_pending += 0;')
   else:raise RuntimeError('unknown mutation')
   cls.write_text(text)
  stack=load('stack_diag_stack',fixture/'stack_test.py');env=out/'facade';stack.facade(kernel,env)
  load('stack_diag_nhi',fixture/'stack_nhi_source.py').generate(kernel,env)
  nhi_cases=fixture/'stack_nhi_cases.c';nhi_cases.write_text(replace(nhi_cases.read_text(),'int main(int argc, char **argv)','int stack_existing_nhi_main(int argc, char **argv)'))
  casefile=fixture/'stack_diag_cases.c';casefile.write_text((HERE/'stack_cases.c').read_text())
  probe=out/'probe.c';probe.write_text('#define STACK_INTERNAL\n#include "stack_kernel_compat.h"\n#include "stack_nhi_api.h"\n#define tb_ring_tx stack_ring_tx\n#define tb_ring_rx stack_ring_rx\n#include "'+str(kernel/'io_uring/xdomain/xdev_ext_xdomain_probe.c')+'"\n')
  expected=json.loads((fixture/'nhi_stack_expected.json').read_text());sources=[fixture/n for n in expected['wrappers']]+[casefile,probe]
  binary=out/'stack-diag';cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-O0','-g','-DSTACK_STARTUP_EVENTS','-DSTACK_REAL_NHI','-Wall','-Wextra','-Werror=implicit-function-declaration','-Wno-unused-function','-Wno-unused-parameter','-pthread','-I'+str(env),'-I'+str(fixture),'-I'+str(kernel),'-idirafter',str(kernel/'include'),'-idirafter',str(kernel/'include/uapi'),'-I'+str(kernel/'tools/xdev_ext_mech')]+[str(s) for s in sources]+['-o',str(binary)]
  (out/'compile-command.json').write_text(json.dumps(cmd,indent=2)+'\n')
  build=subprocess.run(cmd,text=True,capture_output=True,timeout=90);(out/'compile.log').write_text(build.stdout+build.stderr)
  result['compile_exit']=build.returncode
  if build.returncode:raise RuntimeError('compile failure; no semantic RED')
  for name in selected:
   runenv=dict(os.environ,STACK_TRACE='1')
   run=subprocess.run([str(binary),name],text=True,capture_output=True,timeout=40,env=runenv)
   (out/(name+'.log')).write_text(run.stdout+run.stderr)
   ok=not run.returncode and 'STACK_DIAG '+name+' assertions=' in run.stdout
   result['cases'].append(dict(name=name,exit=run.returncode,pass_=ok))
   print(run.stdout,end='')
   if not ok:print('\n'.join(run.stderr.splitlines()[-20:]))
  result.update(state='PASS' if all(x['pass_'] for x in result['cases']) else 'BEHAVIOR_FAILURE',exit=int(any(not x['pass_'] for x in result['cases'])))
 except (OSError,RuntimeError,ValueError,AssertionError,subprocess.SubprocessError) as e:
  result.update(state='SETUP_ERROR',exit=2,error=str(e));print(str(e))
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('STACK_DIAG_STATE '+result['state']);return result['exit']

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--nhi-regs',type=Path,required=True);p.add_argument('--case',choices=CASES);p.add_argument('--mutation',choices=('omit-ack','omit-downstream','omit-cts'));a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 return execute(a.source_root.resolve(),a.output.resolve(),a.nhi_regs.resolve(),[a.case] if a.case else CASES,a.mutation)
if __name__=='__main__':raise SystemExit(main())

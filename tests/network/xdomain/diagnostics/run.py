#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent Task2 contracts. Return behavior=1, setup=2, all selected pass=0.

The core suite executes the actual register dispatcher and ring-local lookup;
its class hook is an explicit boundary and cannot certify XDOMAIN sampling.
The native suite executes the entire actual NHI ring prefix with the retained
qualified MMIO/IRQ/work boundary. Missing snapshot is a runtime feature RED.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
CORE_CASES = ('query','owner','unknown-session','stage-bounds','unsupported-class',
              'stopped','stale','size','version','dirty-output','dirty-reserved',
              'read-fault','write-fault')
NATIVE_CASES = ('enqueue-refill-irq','poll-refill','stopped-undrained','restart',
                'rx-posted-membership','quarantined-allocation')
CLASS_CASES = ('cts','ack','fail-local','fail-chain','fail-sequester','rts-admitted',
               'rts-unadmitted','final-wait','downstream','downstream-unquiesced',
               'downstream-no-live-slot','unused-reply','mixed')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod)
    return mod


def headers(root,out):
    mod=load('diag_layout',root/'tools/layout.py')
    for (component,name),source in mod.load_layout(root).by_native.items():
        if component=='linux' and name.endswith('.h'):
            dst=out/name;dst.parent.mkdir(parents=True,exist_ok=True)
            dst.write_bytes((root/source).read_bytes())


def core_unit(root,out):
    source=(root/'src/core/io_uring/xdev_ext_mech.c').read_text()
    extract=load('diag_extract',root/'tests/core/admission_report/run.py').function
    dispatch=extract(source,'io_xdev_ext_mech_register')
    body=extract(source,'xdev_ext_mech_find')+'\n'
    # Follow the *registered* op rather than accepting an unused future helper.
    match=re.search(r'case\s+XDEV_EXT_MECH_OP_STAGE_DIAG\s*:\s*return\s+(\w+)\s*\(',dispatch)
    if match:
        body+=extract(source,match[1])+'\n'
    body+=dispatch
    return (HERE/'core.c.in').read_text().replace('/* PRODUCTION */',body)


def native_unit(root,out):
    contracts=root/'tests/network/xdomain/contracts'
    sys.path.insert(0,str(contracts))
    from xdomain_ring_test import no_includes,declaration
    from xdomain_fixture import definition
    source=(root/'src/network/drivers/thunderbolt/nhi.c').read_text()
    header=(root/'src/network/include/linux/thunderbolt.h').read_text()
    regs=out/'nhi_regs.h'
    if not regs.exists():
        raise RuntimeError('pass the pinned upstream --nhi-regs input for NHI composition')
    compat=(contracts/'xdomain_nhi_compat.h').read_text()
    # Hook the external flush primitive before it drains actual ring_work.
    # No production code, list mutation, snapshot, or expected count is replaced.
    compat=compat.replace('static bool flush_work(struct work_struct *w) {',
        'static void diag_before_flush(struct work_struct *);\nstatic bool flush_work(struct work_struct *w) { diag_before_flush(w);',1)
    present=bool(re.search(r'\bstruct\s+tb_ring_snapshot\s*\{',header))
    snap=declaration(header,'struct tb_ring_snapshot') if present else (
        'struct tb_ring_snapshot {u32 in_flight,software_pending;bool running,notify_pending;};\n')
    unit=compat+'\n'+declaration(header,'enum ring_desc_flags')+no_includes(regs.read_text())+'\n'
    unit+=declaration(header,'struct tb_nhi')+declaration(header,'struct tb_ring')+snap
    unit+='typedef void (*ring_cb)(struct tb_ring *,struct ring_frame *,bool);\n'
    unit+=declaration(header,'struct ring_frame')
    unit+='\n'.join(re.findall(r'^#define (?:RING_FLAG_\w+|TB_FRAME_SIZE)\b[^\n]*',header,re.M))+'\n'
    unit+='extern void tb_ring_snapshot(struct tb_ring *,struct tb_ring_snapshot *) __attribute__((weak));\n'
    unit+=no_includes(source[:source.index('int nhi_mailbox_cmd(')])+'\n'
    unit+=definition(source,'nhi_interrupt_work')+'\n'+definition(source,'nhi_msi')+'\n'
    return unit+(HERE/'native.c').read_text()


def class_unit(root,out):
    contracts=root/'tests/network/xdomain/contracts'
    mod=load('diag_class_extract',contracts/'xdomain_class_test.py')
    k=out/'headers'
    mech=(k/'include/linux/xdev_ext_mech.h').read_text()
    link=(root/'src/network/io_uring/xdomain/xdev_ext_xdomain.h').read_text()
    core=(root/'src/core/io_uring/xdev_ext_mech.c').read_text()
    family=(root/'src/network/io_uring/family/xdev_ext_netfam.c').read_text()
    declarations='\n'.join(mod.struct(mech,name) for name in (
        'xdev_ext_mech_frame','xdev_ext_family_hooks_hdr','xdev_ext_mech_stage',
        'xdev_ext_mech_class_ops','xdev_ext_xdomain_proto_result','xdev_ext_mech_call_args'))
    for name in ('xdev_ext_requester.h','xdev_ext_netfam.h'):
        declarations+=mod.no_includes((k/'include/linux'/name).read_text())+'\n'
    declarations+=mod.no_includes(link)
    helpers=('xdev_ext_mech_settled','xdev_ext_mech_settle_locked',
        'xdev_ext_mech_progress_work','xdev_ext_mech_session_stop','xdev_ext_mech_session_stop_started_ns',
        'xdev_ext_mech_stage_native_get','xdev_ext_mech_stage_native_put','xdev_ext_mech_end')
    if '\nvoid xdev_ext_mech_stage_stop(' in core:helpers+=('xdev_ext_mech_stage_stop',)
    enum=re.search(r'enum xdev_ext_mech_end\s*\{[^}]+\};',core)
    if not enum:raise RuntimeError('missing core disposition enum')
    corebody=enum[0]+'\n'+'\n'.join(mod.function(core,n) for n in helpers)
    clstext=(root/'src/network/io_uring/xdomain/xdev_ext_xdomain_class.c').read_text()
    have='(*stage_diag)' in mod.struct(mech,'xdev_ext_mech_class_ops')
    host=(contracts/'xdomain_host.h').read_text()
    host=host.replace('#define GFP_KERNEL 0',
        'static unsigned diag_allocations;\nstatic void *diag_calloc(size_t n,size_t s) {diag_allocations++;return calloc(n,s);}\n#define GFP_KERNEL 0',1)
    for macro in ('#define kzalloc(n,g) calloc(1,n)',
                  '#define kcalloc(n,s,g) calloc(n,s)',
                  '#define kvcalloc(n,s,g) calloc(n,s)'):
        if host.count(macro)!=1:raise RuntimeError('qualified allocation boundary changed')
        host=host.replace(macro,macro.replace(') calloc(',') diag_calloc('),1)
    # New external link observation is deliberately bounded here; actual link,
    # NHI membership and retention are independently tested in other suites.
    boundary=(HERE/'class_boundary.c').read_text()
    generated=host.replace('@KERNEL@',str(k)).replace('@UAPI@',str(k/'include/uapi/linux/xdev_ext_mech.h'))
    generated=generated.replace('@PROG@',str(root/'src/bpf/xdomain/xdev_ext_mech_prog.h'))
    # Resolve the canonical BPF header using layout, without editing the map.
    layout=load('diag_class_layout',root/'tools/layout.py').load_layout(root)
    prog=layout.by_native[('linux','tools/xdev_ext_mech/xdev_ext_mech_prog.h')]
    generated=generated.replace(str(root/'src/bpf/xdomain/xdev_ext_mech_prog.h'),str(root/prog))
    bpf=layout.by_native[('linux','tools/xdev_ext_mech/xdomain_peer.bpf.c')]
    generated=generated.replace('@DECLARATIONS@',declarations)
    generated=generated.replace('@CORE@',corebody)
    generated=generated.replace('@FAMILY@',mod.region(family,'/* xdev_ext_netfam runtime begin */','/* xdev_ext_netfam runtime end */'))
    generated=generated.replace('@BPF@',mod.no_includes((root/bpf).read_text()))
    generated=generated.replace('@CLASS@',boundary+'\n'+mod.no_includes(clstext))
    generated=generated.replace('@BOUNDARIES@',(contracts/'xdomain_boundaries.c').read_text())
    generated=generated.replace('@CASES@',(HERE/'class.c').read_text())
    generated=generated.replace('@PRESSURE@','')
    return '#define DIAG_CLASS_HAS_HOOK '+str(int(have))+'\n'+generated


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--suite',choices=('core','native','class','all'),default='all')
    p.add_argument('--case')
    p.add_argument('--nhi-regs',type=Path,help='read-only pinned upstream nhi_regs.h dependency')
    a=p.parse_args();root=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    result={'scope':'host extracted production correctness; no kernel or hardware',
            'source_root':str(root),'cases':[],'compile':[],'uncovered':[
                'XDOMAIN class protocol facts and incarnation/retention sampling concurrency',
                'full kernel locking, production startup, physical DMA and performance']}
    try:
        native=out/'headers';headers(root,native)
        if a.nhi_regs:
            shutil.copyfile(a.nhi_regs,out/'nhi_regs.h')
            result['upstream_nhi_regs']=str(a.nhi_regs.resolve())
        for suite,make,cases in (('core',core_unit,CORE_CASES),('native',native_unit,NATIVE_CASES),('class',class_unit,CLASS_CASES)):
            if a.suite not in ('all',suite):continue
            selected=[x for x in cases if a.case is None or x==a.case]
            if not selected:raise RuntimeError('case not in selected suite: '+str(a.case))
            cfile=out/(suite+'.c');binary=out/suite;cfile.write_text(make(root,out))
            cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-O0','-g','-Wall','-Wextra',
                 '-Werror=implicit-function-declaration','-Wno-unused-function','-Wno-unused-parameter',
                 '-Wno-unused-variable','-pthread','-I'+str(native/'include'),str(cfile),'-o',str(binary)]
            build=subprocess.run(cmd,text=True,capture_output=True,timeout=60)
            (out/(suite+'-compile.log')).write_text(build.stdout+build.stderr)
            result['compile'].append({'suite':suite,'exit':build.returncode,'command':cmd})
            if build.returncode:raise RuntimeError(suite+' compile failed; no behavioral verdict')
            for name in selected:
                run=subprocess.run([str(binary),name],text=True,capture_output=True,timeout=15)
                (out/(suite+'-'+name+'.log')).write_text(run.stdout+run.stderr)
                result['cases'].append({'suite':suite,'case':name,'exit':run.returncode})
                print(run.stdout+run.stderr,end='')
                if run.returncode not in (0,1):raise RuntimeError(suite+'/'+name+' crashed; no behavior RED')
        result['exit']=int(any(c['exit'] for c in result['cases']))
        result['state']='BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except (OSError,RuntimeError,ValueError,AssertionError,subprocess.SubprocessError) as exc:
        result.update(exit=2,state='SETUP_ERROR',error=str(exc));print('SETUP: '+str(exc),file=sys.stderr)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('state='+result['state']+' exit='+str(result['exit']))
    return result['exit']


if __name__=='__main__':raise SystemExit(main())

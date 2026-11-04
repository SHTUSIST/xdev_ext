#!/usr/bin/env python3
"""Selected-source mutation harness. Only compiled assertion failures are kills."""
import argparse, contextlib, io, json, pathlib, re, shutil, sys
import run

def replace_once(text,old,new):
    if text.count(old)!=1: raise RuntimeError('mutation target not unique: '+old[:80])
    return text.replace(old,new,1)

def alter_function(path,name,change):
    text=path.read_text(); original=run.block(text,name)
    path.write_text(replace_once(text,original,change(original)))

def inject_start(text,statement):
    at=text.index('{')+1
    return text[:at]+'\n'+statement+'\n'+text[at:]

def last_return(text,statement):
    at=text.rfind('return 0;')
    if at<0: raise RuntimeError('missing success return')
    return text[:at]+statement+'\n'+text[at:]

def detach_validate(text):
    name='xdev_ext_comp_copy_validate'
    if name+'(' not in text:
        return replace_once(text, 'xdev_ext_comp_copy_stage_validate(&cs->copy,',
            'xdev_ext_comp_copy_stage_validate(&(struct xdev_ext_comp_copy_stage){.window=cs->copy.window},')
    at=text.index(name+'(')+len(name)+1
    i=at; depth=0; comma=at
    while i<len(text):
        c=text[i]
        if c=='(': depth+=1
        if c==')':
            if not depth: break
            depth-=1
        if c==',' and not depth: comma=i
        i+=1
    if i==len(text): raise RuntimeError('cannot find validate arguments')
    return text[:comma+1]+' (struct xdev_ext_comp_copy_plan[1]){{0}}'+text[i:]

def main():
    p=argparse.ArgumentParser(); p.add_argument('--source-root',required=True,type=pathlib.Path); p.add_argument('--phase',choices=['baseline','typed'],default='baseline'); p.add_argument('--output',required=True,type=pathlib.Path); a=p.parse_args()
    source=a.source_root.resolve(); out=a.output.resolve(); out.mkdir(parents=True,exist_ok=True)
    with contextlib.redirect_stdout(io.StringIO()) as log:
        control=run.compile_run(source,a.phase,out/'control')
    (out/'control.console.log').write_text(log.getvalue())
    if control: print('SETUP: mutation control must pass; status',control); return 2
    deps=(out/'control/dependencies.d').read_text().replace('\\\n',' ').split()[1:]
    selected={run.CE,run.DMA,'src/core/include/linux/xdev_ext_mech.h'}
    for d in deps:
        f=pathlib.Path(d).resolve()
        if f.is_relative_to(source) and f.relative_to(source).parts[0]=='src': selected.add(str(f.relative_to(source)))
    if a.phase=='typed': selected.add(run.TYPED)
    shared=(source/run.RUNTIME_HEADER).is_file()
    if shared: selected.update((run.RUNTIME,run.RUNTIME_HEADER,run.TYPED))
    for rel in ('src/compute/io_uring/xdev_ext_compfam_copy_lease.h','src/compute/io_uring/xdev_ext_compfam_copy_lease.c'):
        if (source/rel).is_file(): selected.add(rel)
    (out/'selected-sources.json').write_text(json.dumps(sorted(selected),indent=2)+'\n')
    cases=[
      ('host-offset-plus-one','src/core/io_uring/xdev_ext_mech_window_copy_core.h',None,lambda s:replace_once(s,'at = g->first_page_off +','at = 1 + g->first_page_off +')),
      ('flags-wrong-errno','src/core/io_uring/xdev_ext_mech_window_copy_core.h',None,lambda s:replace_once(s,'if (e.flags & ~known_flags)\n\t\t\treturn -EOPNOTSUPP;','if (e.flags & ~known_flags)\n\t\t\treturn -EINVAL;')),
      ('dma-partial-output','src/core/io_uring/xdev_ext_mech_dma_core.h',None,lambda s:replace_once(s,'tmp.host_off, &tmp.total','plan->host_off, &tmp.total')),
      ('ce-no-slot-confinement',run.CE,'xdev_ext_ce_validate',lambda s:replace_once(s,'return -ERANGE;','return 0;')),
      ('dma-no-slot-confinement',run.DMA,'xdev_ext_dma_validate',lambda s:replace_once(s,'return -ERANGE;','return 0;')),
      ('ce-ignore-dead',run.CE,'xdev_ext_ce_stage_xfers',lambda s:replace_once(s,'READ_ONCE(cs->dead)','false')),
      ('dma-ignore-dead',run.DMA,'xdev_ext_dma_stage_xfers',lambda s:replace_once(s,'READ_ONCE(cs->dead)','false')),
    ]
    if shared:
        # Two historical class labels now target the same shared dead/slot
        # algorithms. Keep both labels and their unchanged rejection oracles.
        cases=[(name,run.RUNTIME,'xdev_ext_comp_copy_stage_submit',change)
               if name in ('ce-ignore-dead','dma-ignore-dead') else
               (name,run.TYPED,'xdev_ext_comp_copy_validate',lambda s:inject_start(s,'slot = 1;'))
               if 'no-slot-confinement' in name else (name,rel,fn,change)
               for name,rel,fn,change in cases]
    if a.phase=='typed':
        # Legacy helper mutants remain required, class slot loop is now family-owned.
        cases=[c for c in cases if 'no-slot-confinement' not in c[0]]+[
          ('typed-force-slot-one',run.TYPED,'xdev_ext_comp_copy_validate',lambda s:inject_start(s,'slot = 1;')),
          ('typed-ignore-batch-slot',run.TYPED,'xdev_ext_comp_copy_transfer',lambda s:inject_start(s,'batch_id = plan->batch_id; slot = plan->slot;')),
          ('typed-zero-generation',run.TYPED,'xdev_ext_comp_copy_transfer',lambda s:last_return(s,'out[0].generation = 0;')),
          ('typed-zero-owner',run.TYPED,'xdev_ext_comp_copy_transfer',lambda s:last_return(s,'out[0].owner = 0;')),
          ('ce-detached-admitted-plan',run.CE,'xdev_ext_ce_validate',detach_validate),
          ('dma-detached-admitted-plan',run.DMA,'xdev_ext_dma_validate',detach_validate),
        ]
    results=[]
    for name,rel,fn,change in cases:
        case=out/name; root=case/'source'; root.mkdir(parents=True,exist_ok=True)
        for selected_rel in selected:
            dest=root/selected_rel; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source/selected_rel,dest)
        path=root/rel
        try:
            if fn: alter_function(path,fn,change)
            else: path.write_text(change(path.read_text()))
            with contextlib.redirect_stdout(io.StringIO()) as log: status=run.compile_run(root,a.phase,case/'build')
            (case/'console.log').write_text(log.getvalue())
            output=(case/'build/run.log').read_text() if (case/'build/run.log').exists() else ''
            killed=status==1 and ('ASSERT ' in output or 'Assertion ' in output)
            result={'name':name,'status':'DETECTED' if killed else 'SURVIVED' if status==0 else 'SETUP','compile_ok':(case/'build/compile.log').exists() and not (case/'build/compile.log').read_text(),'exit':status}
        except (OSError,RuntimeError) as e: result={'name':name,'status':'SETUP','reason':str(e)}
        results.append(result); print(name+': '+result['status'])
    (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    if any(r['status']=='SETUP' for r in results): return 2
    return 1 if any(r['status']!='DETECTED' for r in results) else 0
if __name__=='__main__': sys.exit(main())

#!/usr/bin/env python3
"""Compile actual production copy-class bodies with declared boundary controls."""
import argparse, difflib, hashlib, json, pathlib, re, shutil, subprocess, sys
HERE=pathlib.Path(__file__).resolve().parent
DEFAULT_OUT=pathlib.Path(__file__).resolve().parents[4]/'build'/'compute-runtime-tests'

def struct(text,name):
    m=re.search(r'^struct '+re.escape(name)+r' \{',text,re.M)
    if not m: raise RuntimeError('SETUP missing public type '+name)
    end=text.index('\n};',m.start())+3
    return text[m.start():end]

def generate(root,out,mutation=None):
    inc=out/'include'; native=out/'io_uring'
    inc.mkdir(parents=True,exist_ok=True); native.mkdir(exist_ok=True)
    receipt=[]
    edits=[]
    for base in ['src/core/include','src/compute/include']:
        for p in (root/base).rglob('*.h'):
            dst=inc/p.relative_to(root/base); dst.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,dst)
    for name in ['atomic','bug','export','fs','init','limits','list','module','mutex','printk','slab','string','refcount']:
        (inc/'linux'/(name+'.h')).write_text('/* Declared kernel boundary supplied by boundary.h. */\n')
    for base in ['src/core/io_uring','src/compute/io_uring']:
        for p in (root/base).glob('*.h'): shutil.copyfile(p,native/p.name)
    public=(root/'src/core/include/linux/xdev_ext_mech.h').read_text()
    types=['xdev_ext_mech_frame','xdev_ext_mech_stage','xdev_ext_mech_pool','xdev_ext_ce_region','xdev_ext_ce_xfer','xdev_ext_ce_backend_ops','xdev_ext_dma_scope_info','xdev_ext_dma_scope_ops','xdev_ext_dma_region','xdev_ext_dma_xfer','xdev_ext_dma_provider_ops','xdev_ext_mech_class_ops']
    (out/'public.h').write_text('\n'.join(struct(public,n) for n in types))
    parts=['#include "boundary.h"\n#include "xdev_ext_mech_core.h"\n#include "xdev_ext_mech_lifecycle.h"\n']
    core=(root/'src/core/io_uring/xdev_ext_mech.c').read_text()
    owner_names=['xdev_ext_mech_batch_ce_owners_valid','xdev_ext_mech_batch_dma_owners_valid']
    for name in owner_names:
        match=re.search(r'^bool '+name+r'\(',core,re.M)
        if not match: raise RuntimeError('SETUP missing core function '+name)
        end=core.index('\n}',match.start())+2
        body=core[match.start():end]
        receipt.append({'path':'src/core/io_uring/xdev_ext_mech.c','function':name,'sha256':hashlib.sha256(body.encode()).hexdigest()})
        if mutation=='ce_owner_phase' and name==owner_names[0]:
            body=body.replace('smp_load_acquire(&b->completion.ctrl) != expected','(smp_load_acquire(&b->completion.ctrl) != expected && smp_load_acquire(&b->completion.ctrl) != ((ticket << 3) | XDEV_EXT_MECH_C_COMPLETING))').replace('return smp_load_acquire(&b->completion.ctrl) == expected;','return true;')
        if mutation and body!=core[match.start():end]: edits.append({'path':'src/core/io_uring/xdev_ext_mech.c','function':name,'before':core[match.start():end],'after':body})
        parts.append(body+'\n')
    paths=['src/compute/io_uring/xdev_ext_mech_ce.c','src/core/io_uring/xdev_ext_mech_dma.c']
    runtime=root/'src/compute/io_uring/xdev_ext_compfam_copy.c'
    if runtime.exists():
        paths.insert(0,str(runtime.relative_to(root)))
        parts.insert(0,'#define RUNTIME_AVAILABLE 1\n')
    for path in paths:
        text=(root/path).read_text()
        receipt.append({'path':path,'sha256':hashlib.sha256(text.encode()).hexdigest(),'bytes':len(text.encode())})
        if mutation:
            before=text
            text=mutate(path,text,mutation,runtime.exists())
            if text!=before:edits.append({'path':path,'before':before,'after':text})
        quoted=re.findall(r'^#include "([^"]+)"',text,re.M)
        text=re.sub(r'^#include[^\n]*\n','',text,flags=re.M)
        parts.extend('#include "'+name+'"\n' for name in quoted)
        parts.append('\n#line 1 "'+path+'"\n'+text+'\n')
    parts.append('#include "probe.c"\n')
    if mutation and not edits:raise RuntimeError('SETUP mutation applied no production edit: '+mutation)
    if edits:
        patch=''.join(''.join(difflib.unified_diff(e['before'].splitlines(True),e['after'].splitlines(True),fromfile=e['path'],tofile=e['path'])) for e in edits)
        (out/'mutation.patch').write_text(patch)
        (out/'mutation-edits.json').write_text(json.dumps([{'path':e['path'],'function':e.get('function'),'before_sha256':hashlib.sha256(e['before'].encode()).hexdigest(),'after_sha256':hashlib.sha256(e['after'].encode()).hexdigest()} for e in edits],indent=2)+'\n')
    (out/'actual.c').write_text(''.join(parts))
    (out/'sources.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return out/'actual.c'

def mutate(path,s,name,runtime=False):
    if runtime:return runtime_mutate(path,s,name)
    # Each applied edit changes executable production behavior, never test controls.
    changes={
      'ce_initial_hold':('xdev_ext_mech_ce.c','cs->cleanup_held = true;\n\tfound->cleanup_holds++;','cs->cleanup_held = false;'),
      'ce_region_restore':('xdev_ext_mech_ce.c','cs->region.ops = cs->ops;','/* mutant erased native compatibility restoration */'),
      'ce_cleanup_hold':('xdev_ext_mech_ce.c','err = xdev_ext_ce_lease_cleanup_begin(cs);','err = 0;'),
      'ce_native_identity':('xdev_ext_mech_ce.c','err = cs->ops->submit(&cs->region, cs->host,','err = cs->region.ops->submit(&cs->region, cs->host,'),
      'ce_cleanup_scan':('xdev_ext_mech_ce.c','if (!other->cleanup_holds &&','if (true &&'),
      'ce_own_hold':('xdev_ext_mech_ce.c','else if (group->cleanup_holds)','else if (false)'),
      'ce_configured_identity':('xdev_ext_mech_ce.c','a->ops,\n\t\t\t\t\ta->window_start, a->window_len,\n\t\t\t\t\theld->ops, held->window_start, held->window_len','a->region.ops,\n\t\t\t\t\ta->window_start, a->region.len,\n\t\t\t\t\theld->region.ops, held->window_start, held->region.len'),
      'ce_capacity':('xdev_ext_mech_ce.c','#define XDEV_EXT_CE_MAX_BACKENDS\t4','#define XDEV_EXT_CE_MAX_BACKENDS\t3'),
      'ce_transfer':('xdev_ext_mech_ce.c','.gpu_off\t= x[i].device_off,','.gpu_off\t= x[i].device_off + 1,'),
      'dma_transfer':('xdev_ext_mech_dma.c','.device_off\t= x[i].device_off,','.device_off\t= x[i].device_off + 1,'),
      'ce_normalize':('xdev_ext_mech_ce.c','status = xdev_ext_ce_completion_status(status, hw_submitted, bytes_done,\n\t\t((const struct xdev_ext_ce_batch *)xdev_ext_mech_batch_priv(ck->b))->total);','status = status;'),
      'dma_owner':('xdev_ext_mech_dma.c','if (!xdev_ext_mech_batch_dma_owners_valid(ck->b, ticket, cb->x, cb->n))','if (false)'),
      'dma_normalize':('xdev_ext_mech_dma.c','if (!status && !hw_submitted)','if (!status && (!hw_submitted || bytes_done != cb->total))'),
      'dma_cleanup':('xdev_ext_mech_dma.c','xdev_ext_dma_lease_cleanup(cs, true);','/* mutant omits retained exclusion */'),
      'ce_stale_read':('xdev_ext_mech_ce.c','if (xdev_ext_mech_batch_completion_claim(ck->b, ticket))','if ((READ_ONCE(ck->cs->dead), xdev_ext_mech_batch_completion_claim(ck->b, ticket)))'),
      'dma_stale_read':('xdev_ext_mech_dma.c','if (xdev_ext_mech_batch_completion_claim(ck->b, ticket))','if ((READ_ONCE(ck->cs->dead), xdev_ext_mech_batch_completion_claim(ck->b, ticket)))'),
      'dma_scope_early':('xdev_ext_mech_dma.c','/* No new foreign native access may race the unmap result itself. */','if (cs->scope) { xdev_ext_dma_scope_put(cs->scope); cs->scope = NULL; }\n /* mutant early scope put */'),
      'ce_pin_unlock':('xdev_ext_mech_ce.c','b->fops == file->f_op && try_module_get(b->owner)','b->fops == file->f_op && (mutex_unlock(&xdev_ext_ce_backend_lock), try_module_get(b->owner), mutex_lock(&xdev_ext_ce_backend_lock), true)'),
      'dma_pin_unlock':('xdev_ext_mech_dma.c','p->ops->fops == file->f_op && try_module_get(p->ops->owner)','p->ops->fops == file->f_op && (mutex_unlock(&xdev_ext_dma_provider_lock), try_module_get(p->ops->owner), mutex_lock(&xdev_ext_dma_provider_lock), true)'),
    }
    if name=='ce_configured_identity' and path.endswith('xdev_ext_mech_ce.c'):
        start=s.index('static int xdev_ext_ce_lease_get(')
        end=s.index('\n}',start)+2
        body=s[start:end]
        for a,b in [('a->ops','a->region.ops'),('a->window_len','a->region.len'),('held->ops','held->region.ops'),('held->window_len','held->region.len')]:
            if a not in body: raise RuntimeError('SETUP mutant anchor '+name+' '+a)
            body=body.replace(a,b)
        return s[:start]+body+s[end:]
    if name=='ce_detach_early' and path.endswith('xdev_ext_mech_ce.c'):
        marker='\tif (cs->host) {'
        if marker not in s: raise RuntimeError('SETUP mutant anchor '+name)
        return s.replace(marker,'\tif (cs->lease_group && !xdev_ext_ce_lease_unbind(cs)) return -EBUSY;\n'+marker,1)
    if name=='dma_alloc_order' and path.endswith('xdev_ext_mech_dma.c'):
        old='new = kmalloc(sizeof(*new), GFP_KERNEL);'
        s=s.replace(old,'mutex_lock(&xdev_ext_dma_provider_lock);\n list_for_each_entry(p, &xdev_ext_dma_providers, node) {\n if (p->ops->fops == ops->fops) { mutex_unlock(&xdev_ext_dma_provider_lock); return -EBUSY; }\n }\n mutex_unlock(&xdev_ext_dma_provider_lock);\n '+old,1)
        return s
    if name=='dead_order' and path.endswith(('xdev_ext_mech_ce.c','xdev_ext_mech_dma.c')):
        a='if (READ_ONCE(cs->dead))\n\t\treturn -ENODEV;\n\tif (staged != b)\n\t\treturn -EPROTO;'
        b='if (staged != b)\n\t\treturn -EPROTO;\n\tif (READ_ONCE(cs->dead))\n\t\treturn -ENODEV;'
        if a not in s: raise RuntimeError('SETUP mutant anchor '+name)
        return s.replace(a,b,1)
    target,a,b=changes.get(name,('','',''))
    if path.endswith(target) and target:
        if a not in s: raise RuntimeError('SETUP mutant anchor '+name)
        return s.replace(a,b)
    return s

def function_edit(source,name,edit):
    match=re.search(r'^(?:static )?(?:int|void|bool|u32) '+re.escape(name)+r'\(',source,re.M)
    if not match:raise RuntimeError('SETUP missing actual function '+name)
    end=source.index('\n}',match.start())+2
    body=source[match.start():end];changed=edit(body)
    if changed==body:raise RuntimeError('SETUP no actual function edit '+name)
    return source[:match.start()]+changed+source[end:]

def replace_exact(body,old,new):
    if old not in body:raise RuntimeError('SETUP absent mutation statement '+old)
    return body.replace(old,new)

def runtime_mutate(path,s,name):
    shared=path.endswith('xdev_ext_compfam_copy.c')
    ce=path.endswith('xdev_ext_mech_ce.c');dma=path.endswith('xdev_ext_mech_dma.c')
    if shared:
        if name=='dma_alloc_order':
            def move_alloc(body):
                block='\tif (!registry->fixed) {\n\t\tnew = kmalloc(sizeof(*new), GFP_KERNEL);\n\t\tif (!new)\n\t\t\treturn -ENOMEM;\n\t}\n'
                body=replace_exact(body,block,'')
                late=block.replace('if (!new)\n\t\t\treturn -ENOMEM;','if (!new) {\n\t\t\tmutex_unlock(&registry->lock);\n\t\t\treturn -ENOMEM;\n\t\t}')
                return replace_exact(body,'\tif (registry->fixed) {',late+'\tif (registry->fixed) {')
            return function_edit(s,'xdev_ext_comp_copy_registry_register',move_alloc)
        if name in ['ce_pin_unlock','dma_pin_unlock']:
            guard='registry->fixed' if name.startswith('ce_') else '!registry->fixed'
            old='try_module_get(p->member.owner)'
            new='('+guard+' ? (mutex_unlock(&registry->lock), try_module_get(p->member.owner), mutex_lock(&registry->lock), true) : try_module_get(p->member.owner))'
            return function_edit(s,'xdev_ext_comp_copy_registry_get',lambda b:replace_exact(b,old,new))
        if name=='dead_order':
            old='if (READ_ONCE(cs->dead))\n\t\terr = -ENODEV;\n\telse if (staged != b)\n\t\terr = -EPROTO;'
            new='if (staged != b)\n\t\terr = -EPROTO;\n\telse if (READ_ONCE(cs->dead))\n\t\terr = -ENODEV;'
            return function_edit(s,'xdev_ext_comp_copy_stage_submit',lambda b:replace_exact(b,old,new))
        if name=='common_transfer_bypass':
            old='err = xdev_ext_comp_copy_transfer(&cs->plan, xdev_ext_mech_batch_id(b),\n\t\t\txdev_ext_mech_batch_slot(b), b, xdev_ext_comp_copy_claim, cs->transfer);'
            return function_edit(s,'xdev_ext_comp_copy_stage_submit',lambda b:replace_exact(b,old,'err = 0;'))
        if name=='common_stale_read':
            return function_edit(s,'xdev_ext_comp_copy_complete',lambda b:replace_exact(b,'if (xdev_ext_mech_batch_completion_claim(ck->b, ticket))','if ((READ_ONCE(ck->cs->dead), xdev_ext_mech_batch_completion_claim(ck->b, ticket)))'))
        if name=='common_null_fixed':
            return function_edit(s,'xdev_ext_comp_copy_registry_unregister',lambda b:replace_exact(b,'if (registry->fixed && !identity)','if (false)'))
    if ce or dma:
        cls='ce' if ce else 'dma'
        if name==cls+'_transfer':
            field='gpu_off' if ce else 'device_off'
            return function_edit(s,'xdev_ext_'+cls+'_copy_submit',lambda b:replace_exact(b,'.'+field+' = x[i].device_off,','.'+field+' = x[i].device_off + 1,'))
        if name==cls+'_stale_read':
            return function_edit(s,'xdev_ext_'+cls+'_complete',lambda b:replace_exact(b,'\n\txdev_ext_comp_copy_complete(','\n\t(void)READ_ONCE(((struct xdev_ext_comp_copy_cookie *)ck)->cs->dead);\n\txdev_ext_comp_copy_complete('))
        if name==cls+'_submit_bypass':
            return function_edit(s,'xdev_ext_'+cls+'_submit',lambda b:replace_exact(b,'return xdev_ext_comp_copy_stage_submit(&cs->copy, st, b);','return -EOPNOTSUPP;'))
        if name==cls+'_complete_bypass':
            return function_edit(s,'xdev_ext_'+cls+'_complete',lambda b:replace_exact(b,'xdev_ext_comp_copy_complete((struct xdev_ext_comp_copy_cookie *)ck, ticket,\n\t\tstatus, hw_submitted, bytes_done, &xdev_ext_'+cls+'_copy_ops);','return;'))
        if ce and name=='ce_normalize':
            return function_edit(s,'xdev_ext_ce_copy_classify',lambda b:replace_exact(b,'*status = xdev_ext_ce_completion_status(*status, *hw_submitted, bytes_done,\n\t\tcb->total);','*status = *status;'))
        if dma and name=='dma_normalize':
            return function_edit(s,'xdev_ext_dma_copy_classify',lambda b:replace_exact(b,'if (!*status && !*hw_submitted)','if (!*status && (!*hw_submitted || bytes_done != cb->total))'))
        if dma and name=='dma_owner':
            return function_edit(s,'xdev_ext_dma_copy_classify',lambda b:replace_exact(b,'if (!xdev_ext_mech_batch_dma_owners_valid(b, ticket, cb->x, cb->n))','if (false)'))
        if dma and name=='dma_scope_early':
            return function_edit(s,'xdev_ext_dma_copy_unbind_begin',lambda b:replace_exact(b,'\n\t/* Retain configured exclusion','\n\tif (cs->scope) { xdev_ext_dma_scope_put(cs->scope); cs->scope = NULL; }\n\t/* Retain configured exclusion'))
        if ce and name=='ce_cleanup_hold':
            return function_edit(s,'xdev_ext_ce_copy_unbind_begin',lambda b:replace_exact(b,'return xdev_ext_ce_lease_cleanup_begin(cs);','return 0;'))
        if ce and name=='ce_native_identity':
            return function_edit(s,'xdev_ext_ce_copy_submit',lambda b:replace_exact(b,'return cs->ops->submit(&cs->region, copy->host,','return cs->region.ops->submit(&cs->region, copy->host,'))
        if ce and name=='ce_detach_early':
            return function_edit(s,'xdev_ext_ce_copy_unbind_begin',lambda b:replace_exact(b,'return xdev_ext_ce_lease_cleanup_begin(cs);','int err = xdev_ext_ce_lease_cleanup_begin(cs);\n\tif (err) return err;\n\treturn cs->lease_group && !xdev_ext_ce_lease_unbind(cs) ? -EBUSY : 0;'))
        # These actual lease/bind source bodies retain their original seam and meaning.
        old_names=['ce_capacity','ce_initial_hold','ce_region_restore','ce_cleanup_scan','ce_own_hold','ce_configured_identity','dma_cleanup']
        if name in old_names:return mutate(path,s,name,False)
    return s

def execute(root,out,sanitize=False,mutation=None):
    if out.exists():
        original=out
        seq=2
        while out.exists():
            out=original.with_name(original.name+'-'+str(seq)); seq+=1
    out.mkdir(parents=True,exist_ok=True)
    try:
        source=generate(root,out,mutation)
    except (RuntimeError,OSError,ValueError) as e:
        (out/'setup.log').write_text(str(e)+'\n')
        return {'status':'SETUP','exit':2,'log':str(out/'setup.log')}
    flags=['gcc','-std=gnu11','-O1','-g','-fno-strict-aliasing','-funsigned-char','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-function','-Wno-missing-field-initializers','-Werror=implicit-function-declaration','-I'+str(HERE),'-I'+str(out),'-I'+str(out/'include'),'-I'+str(out/'io_uring')]
    if (root/'src/compute/io_uring/xdev_ext_compfam_copy.c').exists(): flags+=['-finstrument-functions']
    if sanitize: flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
    flags += [str(source),'-o',str(out/'probe')]
    c=subprocess.run(flags,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/'compile.log').write_text(c.stdout)
    (out/'command.json').write_text(json.dumps(flags,indent=2)+'\n')
    if c.returncode: return {'status':'SETUP','exit':c.returncode,'log':str(out/'compile.log')}
    r=subprocess.run([str(out/'probe')],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
    (out/'run.log').write_text(r.stdout)
    return {'status':'PASS' if r.returncode==0 else ('SEMANTIC_RED' if r.returncode==70 else 'EXECUTION_ERROR'),'exit':r.returncode,'log':str(out/'run.log')}

def main():
    p=argparse.ArgumentParser();p.add_argument('--source-root',required=True,type=pathlib.Path);p.add_argument('--phase',choices=['baseline','runtime','mutations'],required=True);p.add_argument('--output',type=pathlib.Path,default=DEFAULT_OUT);a=p.parse_args()
    if a.phase=='runtime' and not (a.source_root/'src/compute/io_uring/xdev_ext_compfam_copy.c').exists():
        print('SETUP/NOT_IMPLEMENTED: common runtime absent');return 2
    results={}
    if a.phase=='mutations':
        names=['ce_capacity','dma_alloc_order','ce_pin_unlock','dma_pin_unlock','ce_transfer','dma_transfer','dead_order','ce_stale_read','dma_stale_read','dma_normalize','ce_normalize','dma_owner','dma_cleanup','dma_scope_early','ce_owner_phase','ce_initial_hold','ce_region_restore','ce_cleanup_hold','ce_native_identity','ce_cleanup_scan','ce_own_hold','ce_configured_identity','ce_detach_early']
        if (a.source_root/'src/compute/io_uring/xdev_ext_compfam_copy.c').exists():names+=['common_transfer_bypass','common_stale_read','ce_submit_bypass','dma_submit_bypass','ce_complete_bypass','dma_complete_bypass','common_null_fixed']
        for n in names:
            results[n]=execute(a.source_root,a.output/'mutations'/n,mutation=n)
            print(n,results[n]['status'],results[n]['exit'],flush=True)
        ok=all(x['status']=='SEMANTIC_RED' for x in results.values())
    else:
        for name,san in [('gcc',False),('ubsan',True)]:
            results[name]=execute(a.source_root,a.output/a.phase/name,san)
            print(name,results[name]['status'],results[name]['exit'],flush=True)
        ok=all(x['status']=='PASS' for x in results.values())
        if ok:
            supplements=json.loads((HERE/'supplement-observables.json').read_text())
            for name,result in results.items():
                actual=[line for line in pathlib.Path(result['log']).read_text().splitlines() if line.startswith('SUPP ')]
                result['supplement_parity']=actual==supplements
                print(name,'NULL supplement parity',actual==supplements)
                ok=ok and actual==supplements
        if a.phase=='runtime' and ok:
            golden_path=HERE/'baseline-observables.json'
            if not golden_path.exists():
                print('SETUP missing independently frozen baseline observables');ok=False
            else:
                expected=json.loads(golden_path.read_text())
                for name,result in results.items():
                    actual=[line for line in pathlib.Path(result['log']).read_text().splitlines() if line.startswith(('OBS ','CQE ','ABI ','XFER '))]
                    same=actual==expected
                    result['observable_parity']=same
                    print(name,'observable parity',same)
                    ok=ok and same
    receipt=a.output/(a.phase+'-receipt.json')
    if receipt.exists():
        seq=1
        while (a.output/(a.phase+'-receipt-'+str(seq)+'.json')).exists():seq+=1
        shutil.copyfile(receipt,a.output/(a.phase+'-receipt-'+str(seq)+'.json'))
    receipt.write_text(json.dumps(results,indent=2)+'\n')
    return 0 if ok else 1
if __name__=='__main__':sys.exit(main())

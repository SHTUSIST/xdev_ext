#!/usr/bin/env python3
"""Independent execution of CE production bodies; no CE policy substitution."""
import argparse, hashlib, json, pathlib, re, subprocess, sys
P=pathlib.Path(__file__).resolve().parent

def function(text,name):
    m=re.search(r'^static (?:int|void|bool) '+name+r'\([^;]*?\n\{',text,re.M)
    if not m: raise RuntimeError('SETUP missing actual function '+name)
    end=m.end(); depth=1
    while depth:
        if text[end]=='{':depth+=1
        if text[end]=='}':depth-=1
        end+=1
    return text[m.start():end]

def main():
    a=argparse.ArgumentParser();a.add_argument('--source-root',type=pathlib.Path,required=True);a.add_argument('--phase',choices=['old-red','repaired','mutations'],required=True);a.add_argument('--output',type=pathlib.Path,default=P/'artifacts');n=a.parse_args()
    n.source_root=n.source_root.resolve();n.output=n.output.resolve()
    n.output.mkdir(parents=True,exist_ok=True)
    if n.phase=='mutations':
        base=n.output/'base'
        result=subprocess.run([sys.executable,str(P/'run.py'),'--source-root',str(n.source_root),'--phase','repaired','--output',str(base)])
        if result.returncode:
            return result.returncode
        return subprocess.run([sys.executable,str(P/'run_mutants.py'),'--base-evidence',str(base),'--recipes',str(P/'mutation-recipes.json'),'--output',str(n.output/'mutants')]).returncode
    src=n.source_root/'src'; ce=(src/'compute/io_uring/xdev_ext_mech_ce.c').read_text(); hdr=(src/'core/include/linux/xdev_ext_mech.h').read_text(); core=(src/'core/io_uring/xdev_ext_mech.c').read_text()
    if n.phase!='old-red' and 'xdev_ext_compfam_copy_lease.h' not in ce and not all(re.search(r'\b'+name+r'\s*\(',ce) for name in ['xdev_ext_ce_lease_bind_ready','xdev_ext_ce_lease_cleanup_begin']):
        print('SETUP: repaired helpers absent');return 2
    # Keep all executable CE function bodies byte-for-byte. Omit kernel includes
    # and passive module/class registration initializer after mark_dead only.
    body=ce[:ce.index('static const struct xdev_ext_comp_hooks')]
    body=re.sub(r'^#include <linux/.*\n','',body,flags=re.M)
    runtime_paths = [src/'compute/io_uring/xdev_ext_compfam_copy_runtime.h',
                     src/'compute/io_uring/xdev_ext_compfam_copy.c']
    runtime_sources = {}
    if runtime_paths[0].exists():
        for path in runtime_paths:
            raw = path.read_text()
            runtime_sources[str(path.relative_to(n.source_root))] = raw
        header, runtime = runtime_sources.values()
        header = re.sub(r'^#include <linux/.*\n', '', header, flags=re.M)
        runtime = runtime.replace('#include "xdev_ext_compfam_copy_runtime.h"', '')
        runtime = re.sub(r'^#include <linux/.*\n', '', runtime, flags=re.M)
        body = body.replace('#include "xdev_ext_compfam_copy_runtime.h"', '')
        body = header + '\n' + runtime + '\n' + body
    lease_paths = [src/'compute/io_uring/xdev_ext_compfam_copy_lease.h',
                   src/'compute/io_uring/xdev_ext_compfam_copy_lease.c']
    if lease_paths[0].exists():
        for path in lease_paths:
            runtime_sources[str(path.relative_to(n.source_root))] = path.read_text()
        lease_header, lease = (path.read_text() for path in lease_paths)
        lease_header = re.sub(r'^#include <linux/.*\n', '', lease_header, flags=re.M)
        lease = re.sub(r'^#include[^\n]*\n', '', lease, flags=re.M)
        body = body.replace('#include "xdev_ext_compfam_copy_lease.h"', '')
        body = lease_header + '\n' + lease + '\n' + body
    types=hdr[hdr.index('struct xdev_ext_ce_region {'):hdr.index('/* Worker context: record an exclusive')]
    ops=hdr[hdr.index("struct xdev_ext_ce_backend_ops {"):hdr.index("/* Module init, process context: -EBUSY")]
    (n.output/'actual-ce.c').write_text(body)
    (n.output/'actual-api.h').write_text(types+ops)
    (n.output/'actual-checked.c').write_text(function(core,'xdev_ext_mech_unbind_checked'))
    cmd=['gcc','-DCE_REPAIRED='+str(int(lease_paths[0].exists() or 'u32 cleanup_holds;' in ce or re.search(r'u32\s+cleanup_holds;',ce) is not None)),'-DCE_SHARED_RUNTIME='+str(int(bool(runtime_sources))),'-std=gnu11','-O0','-g','-fno-strict-aliasing','-funsigned-char','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-function','-I'+str(n.output),'-I'+str(src/'compute/io_uring'),'-I'+str(src/'core/io_uring'),'-I'+str(src/'core/include/linux'),'-I'+str(src/'compute/include/linux'),str(P/'harness.c'),'-o',str(n.output/'ce-residual')]
    build=subprocess.run(cmd,text=True,capture_output=True);(n.output/'build.log').write_text(build.stdout+build.stderr)
    if build.returncode:
        print('SETUP: actual source failed to compile');print(build.stderr);return 2
    run=subprocess.run([str(n.output/'ce-residual'),n.phase],text=True,capture_output=True);(n.output/'run.log').write_text(run.stdout+run.stderr);print(run.stdout,end='');print(run.stderr,end='',file=sys.stderr)
    receipt={'source_sha256':{str(path.relative_to(n.source_root)):hashlib.sha256(path.read_bytes()).hexdigest() for path in [src/'compute/io_uring/xdev_ext_mech_ce.c',src/'core/include/linux/xdev_ext_mech.h',src/'core/io_uring/xdev_ext_mech.c']+runtime_paths+lease_paths if path.exists()},'phase':n.phase,'ce_sha256':hashlib.sha256(ce.encode()).hexdigest(),'compile_command':cmd,'compile_exit':build.returncode,'execution_exit':run.returncode,'boundary':'actual CE functions and checked-unbind; native callbacks/core accessors/kernel primitives are host stubs; no physical DMA or performance claim'}
    (n.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return run.returncode
if __name__=='__main__':
    try:
        status=main()
    except (OSError, ValueError, RuntimeError) as error:
        print('SETUP: '+str(error));status=2
    sys.exit(status)

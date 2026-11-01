#!/usr/bin/env python3
"""Root replay only: link real library C from an existing native view, no tree copy."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

def fingerprint(path):
    return {'path':str(path),'bytes':path.stat().st_size,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root',type=Path,required=True,
                        help='Existing prepared kernel native root containing tools/xdev_ext_mech/lib')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case',choices=['all','success','peer','retained-copy'],default='all')
    parser.add_argument('--boundary-root',type=Path,
                        help='Directory with unchanged v4 ownership_boundary.c/.h and abi_transport.h')
    parser.add_argument('--libbpf-include',type=Path,required=True)
    parser.add_argument('--libbpf-archive',type=Path,required=True)
    args=parser.parse_args()
    here=Path(__file__).resolve().parent
    boundary=args.boundary_root.resolve() if args.boundary_root else here
    native=args.native_root.resolve();out=args.output.resolve()
    if out.exists() and any(out.iterdir()):parser.error('output must be fresh or empty')
    out.mkdir(parents=True,exist_ok=True);fixtures=out/'fixtures';fixtures.mkdir()
    for name in ['library_integration.c','library_integration_boundary.c','library_integration_boundary.h','run_library_integration.py']:
        shutil.copy2(here/name,fixtures/name)
    for name in ['ownership_boundary.c','ownership_boundary.h','abi_transport.h']:
        shutil.copy2(boundary/name,fixtures/name)
    cli=native/'tools';lib=cli/'xdev_ext_mech/lib'
    inputs=[lib/'xdev_ext_session.c',cli/'xdev_ext_xsk_shared.c',cli/'xdev_ext_xsk_steer.c',
            lib/'libxdev_ext.h',native/'include/uapi/linux/io_uring.h',native/'include/uapi/linux/xdev_ext_mech.h']
    for path in inputs:
        if not path.is_file():parser.error('required existing native input absent: '+str(path))
    receipt={'case':args.case,'native_root':str(native),'production_tree_copied':False,
             'inputs':[fingerprint(p) for p in inputs],'commands':[],'runs':[]}
    common=['gcc','-O1','-g','-std=gnu11','-Wall','-Wextra','-Werror','-ffunction-sections','-fdata-sections',
            '-I'+str(native),'-I'+str(cli),'-I'+str(lib),'-I'+str(fixtures),'-I'+str(args.libbpf_include.resolve())]
    adapted=['socket','getsockopt','setsockopt','bind','close','fcntl','fcntl64','ioctl','syscall']
    rename=['-D__wrap_'+name+'=manager_'+name for name in adapted]
    wraps=['socket','close','fstat','fstat64','getsockopt','getsockname','connect','setsockopt','fcntl','fcntl64',
           'if_nametoindex','sendmsg','sendto','send','recvmsg','recvfrom','recv','bind',
           'open','open64','openat','mkdir','mkdirat','unlink','unlinkat','ioctl','syscall',
           'fstatfs','fstatfs64','statfs','statfs64','stat','lstat','fstatat','rmdir',
           'bpf_xdp_query_id','bpf_xdp_query','bpf_xdp_attach','bpf_xdp_detach',
           'eventfd','mmap','mmap64','munmap']
    compile_boundary=common+rename+['-c',str(fixtures/'ownership_boundary.c'),'-o',str(out/'manager-boundary.o')]
    compile_binary=common+[str(fixtures/'library_integration.c'),str(fixtures/'library_integration_boundary.c'),
                           str(out/'manager-boundary.o')]+[str(p) for p in inputs[:3]]+[
                           '-Wl,--gc-sections','-o',str(out/'library-integration')]
    compile_binary+=['-Wl,--wrap='+name for name in wraps]
    compile_binary += [str(args.libbpf_archive.resolve()),'-lelf','-lz']
    log=[]
    for command in [compile_boundary,compile_binary]:
        result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        receipt['commands'].append({'argv':command,'exit':result.returncode});log.append(result.stdout)
        print(result.stdout,end='')
        if result.returncode:
            receipt['status']='infrastructure-error';(out/'compile.log').write_text(''.join(log))
            (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');return 2
    (out/'compile.log').write_text(''.join(log))
    cases=['success','peer','retained-copy'] if args.case=='all' else [args.case]
    failed=False
    for case in cases:
        command=[str(out/'library-integration'),str(out/('sandbox-'+case)),case]
        try:
            result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
            status=result.returncode;output=result.stdout
        except subprocess.TimeoutExpired as error:
            status=124;output=error.stdout or ''
            if isinstance(output,bytes):output=output.decode(errors='replace')
            output+='\nTIMEOUT\n'
        (out/(case+'.log')).write_text(output);print(output,end='')
        receipt['runs'].append({'case':case,'argv':command,'exit':status});failed|=status!=0
    receipt['inputs_after']=[fingerprint(p) for p in inputs]
    if receipt['inputs']!=receipt['inputs_after']:
        receipt['status']='input-changed-during-run';failed=True
    else:receipt['status']='assertion-failure' if failed else 'pass'
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return 1 if failed else 0

if __name__=='__main__':raise SystemExit(main())

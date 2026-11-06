#!/usr/bin/env python3
"""Independent host contract tests. Never configures host networking."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--case',choices=['rings','rx-map-failure','receive-options','dispatcher','socket-identity','ownership'],default='rings')
    p.add_argument('--scenario',default='socket-cookie-unavailable')
    p.add_argument('--libbpf-include',type=Path)
    p.add_argument('--libbpf-archive',type=Path)
    args=p.parse_args()
    root=args.source_root.resolve(); out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=True)
    fixture=out/'fixtures'; fixture.mkdir(exist_ok=True)
    here=Path(__file__).resolve().parent
    for name in ['session_rings.c','dispatcher.c','socket_identity.c','contract_api.h',
                 'ownership.c','ownership_boundary.c','ownership_boundary.h','receive_options.c','abi_transport.h']:
        shutil.copy2(here/name,fixture/name)
    shutil.copy2(__file__,fixture/'run.py')
    spec=importlib.util.spec_from_file_location('layout',root/'tools/layout.py')
    layout=importlib.util.module_from_spec(spec); spec.loader.exec_module(layout)
    view=layout.materialize_view(root,out/'production').root
    kernel=view/'kernel'
    lib=kernel/'tools/xdev_ext_mech/lib'
    cli=kernel/'tools'
    # Frozen-plan additions can exist before root refreshes source-layout.json.
    # Copy literal, documented paths; do not parse implementation to choose tests.
    additions=['xdev_ext_xsk_shared.c','xdev_ext_xsk_steer.c',
               'include/xdev_ext_xsk_shared.h','include/xdev_ext_xsk_shared_prog.h',
               'include/xdev_ext_xsk_steer.h']
    for name in additions:
        source=root/'src/cli'/name
        if source.is_file():
            (cli/name).parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,cli/name)
    wrappers=['socket','if_nametoindex','eventfd','close','setsockopt','getsockopt','bind','mmap','munmap']
    command=['gcc','-O1','-g','-std=gnu11','-Wall','-Wextra','-Werror','-ffunction-sections','-fdata-sections',
             '-I'+str(kernel),'-I'+str(lib),'-I'+str(cli),'-I'+str(fixture)]
    if args.libbpf_include: command+=['-I'+str(args.libbpf_include.resolve())]
    if args.case in ['rings','rx-map-failure','receive-options']:
        # The library links the XSK redirect helper (transmit-only zero-copy XDP mode).
        sources=[fixture/('receive_options.c' if args.case=='receive-options' else 'session_rings.c'),lib/'xdev_ext_session.c',
                 cli/'xdev_ext_xsk_redirect.c']
    else:
        fixture_name={'dispatcher':'dispatcher.c','socket-identity':'socket_identity.c','ownership':'ownership.c'}[args.case]
        sources=[fixture/fixture_name]
        wrappers=[]
        if args.case in ['socket-identity','ownership']:
            wrappers=['socket','close','fstat','fstat64','getsockopt','getsockname','connect','setsockopt','fcntl','fcntl64',
                      'if_nametoindex','sendmsg','sendto','send','recvmsg','recvfrom','recv','bind',
                      'open','open64','openat','mkdir','mkdirat','unlink','unlinkat','ioctl','syscall']
        if args.case=='ownership':
            sources.append(fixture/'ownership_boundary.c')
            wrappers+=['fstatfs','fstatfs64','statfs','statfs64','stat','lstat','fstatat','rmdir',
                       'bpf_xdp_query_id','bpf_xdp_query','bpf_xdp_attach','bpf_xdp_detach']
    for name in ['xdev_ext_xsk_shared.c','xdev_ext_xsk_steer.c']:
        if (cli/name).is_file():sources.append(cli/name)
    executable=out/'contract_test'
    command += [str(s) for s in sources]+['-Wl,--gc-sections','-o',str(executable)]
    command += ['-Wl,--wrap='+name for name in wrappers]
    if args.libbpf_archive:command += [str(args.libbpf_archive.resolve()),'-lelf','-lz']
    receipt={'source_root':str(root),'case':args.case,'compile_command':command}
    compiled=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    (out/'compile.log').write_text(compiled.stdout)
    receipt['compile_exit']=compiled.returncode
    print(compiled.stdout,end='')
    if compiled.returncode:
        receipt['status']='infrastructure-error'; result=2
    else:
        scenarios=[args.scenario]
        if args.scenario=='all' and args.case=='socket-identity':
            scenarios=['valid-control','wrong-domain','wrong-type','wrong-netns-cookie',
                       'socket-cookie-unavailable','netns-cookie-unavailable','diag-unavailable',
                       'wrong-inode','wrong-diag-cookie','wrong-ifindex','wrong-queue',
                       'diag-info-missing','diag-info-short','xdp-options-unavailable','xdp-options-short',
                       'unknown-flags','bad-mode','bad-queue','zero-port','short-size','missing-magic-filter']
        if args.scenario=='all' and args.case=='ownership':
            scenarios=['basic','queue-conflict','flow-conflict','tuple-conflict','foreign-rule',
                       'changed-rule','foreign-link','replaced-link','corrupt-pin','namespaces',
                       'multiprocess','fork-policy','insertion-crash','recorded-crash','changed-crash-rule']
        receipt['runs']=[];result=0;combined=[]
        for scenario in scenarios:
            run=[str(executable)]
            if args.case=='rx-map-failure':run.append(args.case)
            if args.case=='socket-identity':run.append(scenario)
            if args.case=='ownership':run += [str(out/('sandbox-'+scenario)),scenario]
            try:
                executed=subprocess.run(run,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
                run_exit=executed.returncode;log=executed.stdout
            except subprocess.TimeoutExpired as error:
                run_exit=124;log=(error.stdout or b'').decode() if isinstance(error.stdout,bytes) else (error.stdout or '')
                log+='\nTIMEOUT: fixture or manager deadlock\n'
            (out/(scenario+'.log')).write_text(log)
            print(log,end='');combined.append(log)
            receipt['runs'].append({'scenario':scenario,'command':run,'exit':run_exit})
            if run_exit:result=1
        (out/'run.log').write_text(''.join(combined))
        receipt.update(run_exit=result,status='pass' if result==0 else 'assertion-failure')
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return result

if __name__=='__main__':raise SystemExit(main())

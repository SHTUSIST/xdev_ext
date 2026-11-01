#!/usr/bin/env python3
"""Compile real selected production units; headers-only official CUDA input."""
import argparse
import json
import os
from pathlib import Path
import subprocess

p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('sdk_include',type=Path);p.add_argument('--new',action='store_true');p.add_argument('--extension',action='store_true');a=p.parse_args()
root=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);tests=Path(__file__).resolve().parent
(out/'context.json').write_text(json.dumps({'source':str(root),'sdk_include':str(a.sdk_include.resolve()),'new':a.new,'extension':a.extension},indent=2))
# Narrow header lookup aliases for canonical sources retaining legacy quoted
# include spellings. No source copy, generated runtime or complete source view.
compat=out/'header_lookup';nested=compat/'lookup/a/b';nested.mkdir(parents=True,exist_ok=True)
def link(dst,src):
 dst.parent.mkdir(parents=True,exist_ok=True)
 if not dst.exists() and not dst.is_symlink():dst.symlink_to(src)
link(compat/'include/uapi',root/'src/core/include/uapi')
link(compat/'lookup/include/uapi',root/'src/core/include/uapi')
for h in (root/'src/cli/include').glob('*.h'):link(compat/'lookup/include'/h.name,h)
for h in ['xdev_ext_mech_core.h','xdev_ext_mech_notify.h']:link(compat/'lookup/io_uring'/h,root/'src/core/io_uring'/h)
link(compat/'lookup/a/xdev_ext_mech_ctl_core.h',root/'src/cli/xdev_ext_mech_ctl_core.h')
inc=[a.sdk_include,root/'src/compute/cuda',root/'src/lib',root/'src/core/include/uapi',root/'src/core/include',root/'src/core/include/linux',root/'src/core/io_uring',root/'src/compute/io_uring',root/'src/network/io_uring',root/'src/storage/io_uring',root/'src/bpf',root/'src/cli/include',nested]
includes=['-isystem',str(inc[0])]+[arg for path in inc[1:] for arg in ['-I',str(path)]]
status=[]
def run(cmd,name,env=None):
 (out/(name+'.command.json')).write_text(json.dumps([str(x) for x in cmd]))
 r=subprocess.run([str(x) for x in cmd],capture_output=True,text=True,env=env)
 (out/(name+'.log')).write_text(r.stdout+r.stderr);(out/(name+'.exit')).write_text(str(r.returncode)+'\n');status.append((name,r.returncode))
 return r
mode=['-DCUDA_PRIVATE_NEW=1'] if a.new else []
# Declarations compiled separately with strict C/C++17 syntax, then linked into
# the actual production-control binary; absent new API is SETUP.
for profile in ['gcc','ubsan']:
 folder=out/profile;folder.mkdir(exist_ok=True)
 flags=['-O1','-g','-Wall','-Wextra','-Werror','-ffunction-sections','-fdata-sections']
 if profile=='ubsan':flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
 units=[('gcc','c11',tests/'declarations.c'),('g++','c++17',tests/'declarations.cc'),('g++','c++17',tests/'control.cc'),('g++','c++17',root/'src/compute/cuda/peer_endpoint_owner.cc'),('g++','c++17',root/'src/compute/cuda/libxdev_ext_cuda.cc'),('gcc','gnu11',root/'src/lib/xdev_ext_peer_message.c'),('gcc','gnu11',root/'src/lib/xdev_ext_session.c'),('gcc','gnu11',root/'src/lib/xdev_ext_user.c')]
 objects=[];setup=False
 for i,(compiler,std,source) in enumerate(units):
  obj=folder/(str(i)+'.o');extra=['-pedantic-errors'] if source.name.startswith('declarations.') else []
  r=run([compiler,*flags,'-std='+std,*extra,*mode,*includes,'-c',source,'-o',obj],profile+'-compile-'+str(i))
  if r.returncode:
   print('SETUP',profile,source.name,r.returncode);print(r.stdout+r.stderr);setup=True;break
  objects.append(obj)
 if setup:continue
 binary=folder/'control'
 r=run(['g++',*flags,'-Wl,--gc-sections','-Wl,--wrap=open','-Wl,--wrap=close','-Wl,--wrap=ioctl','-Wl,--wrap=syscall',*objects,'-o',binary],profile+'-link')
 if r.returncode:print('SETUP',profile,'link',r.stderr);continue
 env=dict(os.environ);ptx=out/'opaque-control-input.ptx';ptx.write_text('CONTROL BOUNDARY INPUT ONLY; NEVER EXECUTED\n');env['XDEV_EXT_CUDA_PTX']=str(ptx)
 cases=[['legacy'],['endpoint'],['legacy-invalid'],['early','0']]
 if a.extension:cases=[['extension','31']]
 if a.new:
  cases=[['distribution',str(i)] for i in range(32)]
  cases += [['early','31']]
  cases += [[x] for x in ['legacy-invalid','endpoint','invalid','null-unused-ELF','fd0','repeated','d2','event-retained','controller-retained','STOP-retained','cancel-retained','cancel-released','TX-failure','RX-failure']]
  cases += [['event-retained','31','1'],['endpoint-failure','31','1'],['endpoint-failure','31','2']]
  cases += [['lookup-failure','31',str(i)] for i in range(5)]+[['global-failure',str(i)] for i in range(2)]
 for i,case in enumerate(cases):
  r=run([binary,*case],profile+'-case-'+str(i),env);print((r.stdout+r.stderr).strip())
(out/'status.json').write_text(json.dumps(status,indent=2))
exit(2 if any(rc and ('-compile-' in name or name.endswith('-link')) for name,rc in status) else 1 if any(rc for name,rc in status) else 0)

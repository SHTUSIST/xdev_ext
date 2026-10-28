#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build the actual-kernel program selection driver and actual BPF objects.

No remote execution. --driver-only checks GCC source linkage only. A complete
build requires a genuine generated vmlinux.h; no fake kernel BTF is supplied.
"""
import argparse,hashlib,importlib.util,json,os,shlex,shutil,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'source-layout.json').is_file())
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,default=ROOT);p.add_argument('--output',type=Path,required=True);p.add_argument('--vmlinux-h',type=Path);p.add_argument('--libbpf-build',type=Path);p.add_argument('--driver-only',action='store_true');p.add_argument('--run',action='store_true');p.add_argument('--wire-only',action='store_true');a=p.parse_args()
 root=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 result={'scope':'actual kernel io_uring/struct_ops selection driver; build does not certify runtime','compile':[],'runtime_exit':None,'hardware':False,'performance':False}
 try:
  spec=importlib.util.spec_from_file_location('sp_guest_layout',root/'tools/layout.py');m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
  native=out/'headers'
  for (component,name),source in m.load_layout(root).by_native.items():
   if component=='linux' and name.endswith('.h'):
    dst=native/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((root/source).read_bytes())
  (out/'session_wire.h').write_bytes((HERE.parent/'session/wire.h').read_bytes())
  flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','libbpf'],text=True)) if not a.libbpf_build else ['-I'+str(a.libbpf_build/'include'),str(a.libbpf_build/'libbpf.a'),'-lelf','-lz']
  commands=[['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-I'+str(native),'-I'+str(out),str(HERE/'session_programs.c'),*flags,'-o',str(out/'session-programs')]]
  if not a.driver_only:
   if not a.vmlinux_h or not a.vmlinux_h.is_file():raise RuntimeError('genuine --vmlinux-h required for BPF build')
   inc=out/'include';inc.mkdir(exist_ok=True);shutil.copyfile(a.vmlinux_h,inc/'vmlinux.h')
   modes={'default':(43,0,0,0),'a':(17,1,0,0),'b':(23,1,0,0),'fail':(17,1,1,0),'wrong':(17,1,0,1)}
   for name,(tag,private,fail,wrong) in modes.items():
    commands.append([os.environ.get('BPF_CLANG','clang'),'-target','bpf','-D__TARGET_ARCH_x86','-O2','-g','-Wall','-Werror','-I'+str(inc),'-I'+str(native/'tools/xdev_ext_mech'),'-I/usr/include/x86_64-linux-gnu','-DSP_TAG='+str(tag),'-DSP_PRIVATE_MODE='+str(private),'-DSP_FAIL_PREPARE='+str(fail),'-DSP_WRONG_CLASS='+str(wrong),'-c',str(HERE/'programs.bpf.c'),'-o',str(out/(name+'.bpf.o'))])
  for n,cmd in enumerate(commands):
   r=subprocess.run(cmd,text=True,capture_output=True,timeout=120);(out/f'compile-{n}.log').write_text(r.stdout+r.stderr);result['compile'].append({'argv':cmd,'exit':r.returncode})
   if r.returncode:raise RuntimeError('compile failed; see compile-'+str(n)+'.log')
  result['test_sources']={str(q.relative_to(root)):hashlib.sha256(q.read_bytes()).hexdigest() for q in (HERE/'programs.bpf.c',HERE/'session_programs.c',HERE.parent/'session/wire.h')}
  if a.run:
   if a.driver_only and not a.wire_only:raise RuntimeError('driver-only permits runtime wire-only, not absent BPF objects')
   cmd=[str(out/'session-programs'),'--wire-only' if a.wire_only else str(out)]
   r=subprocess.run(cmd,text=True,capture_output=True,timeout=180);(out/'runtime.log').write_text(r.stdout+r.stderr);result.update(runtime_command=cmd,runtime_exit=r.returncode);print(r.stdout+r.stderr,end='')
   result['exit']=int(r.returncode!=0);result['state']='BEHAVIOR_RED' if r.returncode else 'KERNEL_SCOPED_PASS'
  else:result.update(exit=0,state='DRIVER_BUILD_ONLY' if a.driver_only else 'BPF_AND_DRIVER_BUILD_ONLY')
 except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as e:result.update(exit=2,state='SETUP_ERROR',error=str(e));print('SETUP:',e)
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('state='+result['state']);return result['exit']
if __name__=='__main__':raise SystemExit(main())

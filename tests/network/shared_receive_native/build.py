#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build genuine exported-builder native acceptance; run only pure selfcheck."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import os
import subprocess
import sys
HERE=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate-root',type=Path,required=True)
    p.add_argument('--libbpf-build',type=Path,required=True)
    p.add_argument('--libbpf-archive',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not a.output.is_absolute():
        p.error('--output must be absolute and fresh')
    out=a.output.resolve()
    try:out.mkdir(parents=True,exist_ok=False)
    except OSError as e:
        print('SETUP_ERROR fresh output required:',e,file=sys.stderr);return 2
    result={'state':'SETUP_ERROR','exit':2,'native_runtime_executed':False,'performance':False,'commands':[]}
    try:
        candidate=a.candidate_root.resolve();lib=a.libbpf_build.resolve()
        archive=a.libbpf_archive.resolve() if a.libbpf_archive else lib/'libbpf.a'
        source=candidate/'src/cli/xdev_ext_xsk_shared.c'
        includes=candidate/'src/cli/include'
        if not source.is_file() or not archive.is_file() or not (lib/'include/bpf/bpf.h').is_file():
            raise RuntimeError('canonical shared source and genuine modern libbpf required')
        command=['gcc','-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror',
                 '-ffunction-sections','-fdata-sections','-I'+str(includes),
                 '-I'+str(lib/'include'),str(HERE/'native.c'),str(source),
                 str(archive),'-lelf','-lz',*shlex.split(os.environ.get('LDFLAGS','')),
                 '-Wl,--gc-sections','-o',str(out/'shared-xdp-native')]
        commands=[command,[str(out/'shared-xdp-native'),'--selfcheck']]
        for i,cmd in enumerate(commands):
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
            (out/f'command-{i}.log').write_text(r.stdout+r.stderr)
            result['commands'].append({'argv':cmd,'exit':r.returncode})
            if r.returncode:raise RuntimeError(f'command {i} failed; inspect command-{i}.log')
        # Candidate implementation is a compiler input only; author does not inspect/hash it.
        inputs=[HERE/'native.c',HERE/'packets.h',HERE/'build.py',
                includes/'xdev_ext_xsk_shared.h',includes/'xdev_ext_xsk_redirect.h']
        result['inputs']={str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in inputs}
        result['candidate_compilation_input_not_inspected']=str(source)
        result['output_sha256']=hashlib.sha256((out/'shared-xdp-native').read_bytes()).hexdigest()
        result.update(state='GCC_BUILD_AND_PURE_ORACLE_ONLY',exit=0)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as e:
        result['error']=str(e);print('SETUP_ERROR:',e,file=sys.stderr)
    (out/'build-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(f"state={result['state']} native_runtime_executed=false positive_redirect=NOT_RUN_NO_BOUND_XSK")
    return result['exit']
if __name__=='__main__':raise SystemExit(main())

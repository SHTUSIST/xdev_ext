#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual CUDA source host-lane coverage, not GPU throughput or SDK evidence."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);receipt={'scope':'actual CUDA source host lanes only; no GPU execution or SDK qualification'}
    try:
        spec=importlib.util.spec_from_file_location('tp_partition_layout',a.source_root/'tools/layout.py');m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
        layout=m.load_layout(a.source_root);view=m.materialize_view(a.source_root,out/'source-view');source=view.root/layout.logical('src/compute/collectives/xdev_tp.cu')
        facade=out/'boundary';facade.mkdir(exist_ok=True);shutil.copyfile(HERE/'driver_boundary.h',facade/'cuda.h')
        binary=out/'partition';cmd=[os.environ.get('CXX','g++'),'-std=c++17','-O0','-g','-Wall','-Wextra','-Wno-misleading-indentation',
          '-I'+str(facade),'-DTP_KERNEL_SOURCE="'+str(source)+'"',str(HERE/'kernel_partition_probe.cc'),'-o',str(binary)]
        for name in ('src/lib/libxdev_ext.h','src/compute/cuda/libxdev_ext_cuda.h'):
            cmd.insert(1,'-I'+str((view.root/layout.logical(name)).parent))
        if 'void xdev_tp_pack_payload(' in source.read_text():cmd.insert(1,'-DTP_PHASED_KERNELS')
        build=subprocess.run(cmd,text=True,capture_output=True,timeout=60);(out/'compile.log').write_text(build.stdout+build.stderr);receipt.update(compile_exit=build.returncode,compile_command=cmd)
        if build.returncode:raise RuntimeError('compile failed; not behavior RED')
        run=subprocess.run([str(binary)],text=True,capture_output=True,timeout=10);(out/'runtime.log').write_text(run.stdout+run.stderr);print(run.stdout+run.stderr,end='')
        if run.returncode not in (0,1):raise RuntimeError('runtime setup failed')
        receipt.update(exit=run.returncode,state='BEHAVIOR_RED' if run.returncode else 'SCOPED_PASS')
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:receipt.update(exit=2,state='SETUP_ERROR',error=str(exc));print(str(exc),file=sys.stderr)
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');return receipt['exit']


if __name__=='__main__':raise SystemExit(main())

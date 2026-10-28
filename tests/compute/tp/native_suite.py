#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Minimal actual-source TP host acceptance entry for CI.

Official CUDA SDK linking and real ATen dependency acceptance are separate.
The frozen six Tensor-dependent cases remain explicitly BLOCKED in the scoped
native receipt; this command does not certify the full 75-vector pipeline.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ENTRIES=(('algorithms','algorithm_resume_test.py',()),
         ('frozen-native','resume_behavior.py',('--native-only',)),
         ('partition','kernel_partition_test.py',()),
         ('ready-custody','library_boundary_regressions.py',()),
         ('retired-stats','work_stats_retirement_test.py',()),
         ('batch','batch_pipeline_test.py',()),
         ('trace','gpu_trace_runtime_test.py',()),
         ('owner','owner_lifetime_test.py',()))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);r={'scope':'native TP host source correctness only; official SDK/GPU/Tensor acceptance separate','entries':[]}
    for name,entry,extra in ENTRIES:
        cmd=[sys.executable,str(HERE/entry),'--source-root',str(a.source_root.resolve()),'--output',str(out/name),*extra]
        run=subprocess.run(cmd,text=True,capture_output=True,timeout=300);(out/(name+'.log')).write_text(run.stdout+run.stderr)
        r['entries'].append({'name':name,'command':cmd,'exit':run.returncode});print(name+' exit='+str(run.returncode),flush=True)
    r['exit']=int(any(e['exit'] for e in r['entries']));r['state']='FAIL' if r['exit'] else 'SCOPED_PASS'
    (out/'result.json').write_text(json.dumps(r,indent=2)+'\n');return r['exit']


if __name__=='__main__':raise SystemExit(main())

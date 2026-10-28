#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Recheck frozen algorithm vectors after actual shared-helper changes.

Mutations are private production-header copies with the same five fault classes
as the prior accepted campaign. Public vectors, wire and adapter bytes stay intact.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--mutations',action='store_true')
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);result={'scope':'same-source host algorithms; no GPU execution','runs':[]}
    try:
        spec=importlib.util.spec_from_file_location('tp_algorithm_layout',a.source_root/'tools/layout.py');m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
        layout=m.load_layout(a.source_root);view=m.materialize_view(a.source_root,out/'source-view')
        header=view.root/layout.logical('src/compute/collectives/xdev_tp_algorithms.h');original=header.read_text()
        probe=view.root/layout.logical('tests/compute/tp/native_algorithm_probe.cc')
        checker=view.root/layout.logical('tests/compute/tp/collective_behavior.py');adapter=view.root/layout.logical('tests/compute/tp/native_algorithm_probe.py')
        challenges=[('baseline',None,None)]
        if a.mutations:challenges += [
            ('sum_drops_peer','return encode(dtype,decode(dtype,a)+decode(dtype,b));','return encode(dtype,decode(dtype,a));'),
            ('gather_flattens_rows','return row*(2*width)+rank*width+column;','return rank*width*2+row*width+column;'),
            ('result_ignores_header','if ((rc = validate_header(s, header))) return rc;','/* deliberately omit peer header validation */'),
            ('pack_leaves_padding','while (offset < index.bytes) {','while (offset < s.wire_bytes) {'),
            ('pack_assumes_contiguous','return reinterpret_cast<unsigned char *>(spans[low].address + offset - start);','return reinterpret_cast<unsigned char *>(spans[0].address + offset);')]
        for name,old,new in challenges:
            work=out/name;work.mkdir(exist_ok=True);binary=work/'probe'
            command=[os.environ.get('CXX','g++'),'-std=c++17','-O0','-g','-I'+str(header.parent)]
            if old is not None:
                if original.count(old)!=1:raise RuntimeError('mutation anchor changed: '+name)
                mutated=work/'xdev_tp_algorithms.h';mutated.write_text(original.replace(old,new));command+=['-include',str(mutated)]
            command += [str(probe),'-o',str(binary)]
            built=subprocess.run(command,text=True,capture_output=True,timeout=60);(work/'compile.log').write_text(built.stdout+built.stderr)
            if built.returncode:raise RuntimeError(name+' compile failure; not mutation catch')
            env=dict(os.environ,XDEV_TP_ALGORITHM_PROBE=str(binary))
            cmd=[sys.executable,str(checker),'--probe',str(adapter),'--family','algorithm','--receipt',str(work/'observations.json')]
            run=subprocess.run(cmd,env=env,text=True,capture_output=True,timeout=120);(work/'runtime.tap').write_text(run.stdout+run.stderr)
            obs=json.loads((work/'observations.json').read_text());good=run.returncode==0 if old is None else run.returncode==1 and obs['fail_count']>0
            result['runs'].append({'name':name,'compile_exit':built.returncode,'runtime_exit':run.returncode,'pass_count':obs['pass_count'],'fail_count':obs['fail_count'],'accepted':good,'compile_command':command})
            print(name,'passes='+str(obs['pass_count']),'failures='+str(obs['fail_count']),'accepted='+str(good))
        result['exit']=int(any(not r['accepted'] for r in result['runs']));result['state']='FAIL' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:result.update(exit=2,state='SETUP_ERROR',error=str(error));print(str(error),file=sys.stderr)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result['exit']


if __name__=='__main__':raise SystemExit(main())

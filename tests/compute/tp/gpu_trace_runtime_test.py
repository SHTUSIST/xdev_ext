#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Trace records must come from actual runtime source phases on every replay.

Host timestamp fallback is not GPU timing evidence. Checks only event/key/depth
records and overflow from the real kernels; no host counter substitutes them.
"""
import argparse
import json
from pathlib import Path
from collective_behavior import compare
from native_library_probe import build,observe

HERE=Path(__file__).resolve().parent


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);result={'scope':'actual CUDA trace phase software execution; no GPU timestamps or performance evidence','cases':[]}
    try:
        exe=build(a.source_root,out/'build')
        case=next(c for c in json.loads((HERE/'collective_vectors.json').read_text())['cases'] if c['name']=='d2_capture_pending_and_fresh_replay_keys')
        for capacity in (32,8):
            request=dict(case['request'],trace_capacity=capacity)
            observed,code=observe({'request':request},exe)
            if code:raise RuntimeError(str(observed))
            errors=compare(case['expected'],observed,request.get('dtype'))
            if observed.get('trace_result')!=0:errors.append('actual trace read failed')
            records=observed.get('trace_records',[]);count=min(15,capacity)
            if len(records)!=count:errors.append('runtime record count '+str(len(records))+' expected '+str(count))
            if observed.get('trace_dropped')!=max(0,15-capacity):errors.append('actual overflow counter did not report dropped runtime records')
            for i,record in enumerate(records):
                want={'sequence':23+i//5,'kind':1+i%5,'clock':2,'rank':0,'logical_inflight':0 if i%5==4 else 1,'error':0}
                for field,value in want.items():
                    if record.get(field)!=value:errors.append(str(i)+': '+field+' expected '+str(value)+' got '+str(record.get(field)))
            result['cases'].append({'capacity':capacity,'observed':observed,'errors':errors});print('capacity',capacity,'records',len(records),'errors',errors)
        result['exit']=int(any(c['errors'] for c in result['cases']));result['state']='BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:result.update(exit=2,state='SETUP_ERROR',error=str(error));print(str(error))
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result['exit']


if __name__=='__main__':raise SystemExit(main())

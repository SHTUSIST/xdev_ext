#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent accepted-ready custody regressions against real TP wrapper.

These additional contract cases preserve the original 75 frozen vectors.
The peer boundary returns a consumed message before the production wrapper
validates role/key, so a mismatch is accepted native custody, not preflight.
"""
import argparse
import json
from pathlib import Path
from native_library_probe import build,observe


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    receipt={'scope':'host actual TP public wrapper with endpoint fault injection; no GPU/SDK qualification','cases':[]}
    try:exe=build(a.source_root,out/'build')
    except Exception as exc:receipt.update(state='SETUP_ERROR',exit=2,error=str(exc));(out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(str(exc));return 2
    for fault in ('wrong_role','wrong_key','before_take'):
        request={'schema':1,'family':'lifecycle','request':{'action':'fault_after_ready','fault':fault}}
        observation,code=observe(request,exe);errors=[]
        if code:errors.append('adapter setup failure: '+str(observation))
        elif fault=='before_take':
            for key,want in {'status':-110,'ready_consumed_count':0,'work_handle_nonnull':False,'communicator_poisoned':False,'retained':False,'ready_after_second':0}.items():
                if observation.get(key)!=want:errors.append(key+' expected '+str(want)+' got '+str(observation.get(key)))
        else:
            for key,want in {'status':-71,'ready_consumed_count':1,'work_handle_nonnull':True,'communicator_poisoned':True,'retained':True,'error':-71,'second_submit_result':-71,'ready_after_second':1,'next_calls_after_second':1}.items():
                if observation.get(key)!=want:errors.append(key+' expected '+str(want)+' got '+str(observation.get(key)))
        receipt['cases'].append({'fault':fault,'observed':observation,'errors':errors,'status':'FAIL' if errors else 'PASS'})
        print(('not ok' if errors else 'ok')+' - '+fault+' '+json.dumps(observation))
        for error in errors:print('# '+error)
    receipt['exit']=int(any(c['errors'] for c in receipt['cases']));receipt['state']='BEHAVIOR_RED' if receipt['exit'] else 'SCOPED_PASS'
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');return receipt['exit']


if __name__=='__main__':raise SystemExit(main())

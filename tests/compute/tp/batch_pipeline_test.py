#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Optional actual batch wrapper/phase pipeline conformance, host boundaries only."""
import argparse
import json
from pathlib import Path
from native_library_probe import build,observe


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);result={'scope':'actual batch public API and CUDA source phases on host; no GPU/performance evidence','cases':[]}
    try:
        exe=build(a.source_root,out/'build')
        for scenario in ('valid','invalid_later','d1','partial_enqueue'):
            observed,code=observe({'request':{'action':'batch','scenario':scenario}},exe);errors=[]
            if code:raise RuntimeError(str(observed))
            if observed.get('missing_batch_feature'):errors.append('runtime batch feature is absent; pipeline not executed')
            else:
                if scenario=='valid':
                    expected={'status':0,'handles':2,'completed':2,'logical_high_water':2,'logical_inflight':0,'error':0,'wait_order':[1,1,2,2,3,3]}
                elif scenario in ('invalid_later','d1'):
                    expected={'status':-95 if scenario=='d1' else -22,'handles':0,'nodes_before_retry':0,'ready_consumed_count':0,'completed':0,'logical_high_water':0,'error':0}
                else:
                    expected={'status':-5,'second_submit_result':-5}
                    if observed.get('handles',0)<1:errors.append('partial accepted enqueue lost all inspectable work handles')
                    if observed.get('nodes_before_retry')!=observed.get('nodes_after_retry'):errors.append('poisoned batch retry enqueued new work')
                for field,want in expected.items():
                    if observed.get(field)!=want:errors.append(field+' expected '+str(want)+' got '+str(observed.get(field)))
            result['cases'].append({'scenario':scenario,'observed':observed,'errors':errors});print(scenario,json.dumps(observed));print('\n'.join(errors))
        result['exit']=int(any(c['errors'] for c in result['cases']));result['state']='BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:result.update(exit=2,state='SETUP_ERROR',error=str(error));print(str(error))
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result['exit']


if __name__=='__main__':raise SystemExit(main())

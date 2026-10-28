#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Resume frozen cases with explicit actual-behavior versus dependency verdicts.

The original comparison implementation and vectors are read unchanged. Missing
production bridge/accounting is BLOCKED, never PASS or behavioral RED.
"""
import argparse
import json
from pathlib import Path
import sys
from collective_behavior import compare
from native_library_probe import build,observe
from production_observers import observe as observe_production_helpers

HERE=Path(__file__).resolve().parent


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--family',action='append');p.add_argument('--native-only',action='store_true',help='select reachable native/accounting cases, record the six real ATen dependency cases separately')
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    result={'scope':'host actual production library observation; no official SDK/GPU acceptance',
            'cases':[],'pass_count':0,'fail_count':0,'blocked_count':0}
    cases=json.loads((HERE/'collective_vectors.json').read_text())['cases']
    cases=[c for c in cases if c['family']!='algorithm' and (not a.family or c['family'] in a.family)]
    if a.native_only:
        result['outside_selected_scope']=[{'name':c['name'],'status':'BLOCKED','reason':'actual ATen extension/Tensor dependency'} for c in cases if c['family']=='bridge' or c['request'].get('contiguous') is False]
        cases=[c for c in cases if c['family']!='bridge' and c['request'].get('contiguous') is not False]
    try:exe=build(a.source_root,out/'build') if any(c['family'] not in ('accounting','bridge') for c in cases) else None
    except Exception as exc:
        result.update(state='SETUP_ERROR',error=str(exc),exit=2);(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(str(exc),file=sys.stderr);return 2
    print('TAP version 13\n1..'+str(len(cases)))
    for i,case in enumerate(cases,1):
        request={key:case[key] for key in ('name','family','request')};request['schema']=1
        record={'name':case['name'],'family':case['family']}
        try:
            if case['family'] in ('bridge','accounting') or case['request'].get('contiguous') is False:
                observed,code=observe_production_helpers(request,a.source_root)
            else:observed,code=observe(request,exe)
            record['observed']=observed
            if 'blocked' in observed:
                status='BLOCKED';result['blocked_count']+=1
            elif code or 'setup_error' in observed:
                status='SETUP_ERROR';result['blocked_count']+=1
            else:
                errors=compare(case['expected'],observed,case['request'].get('dtype'))
                status='FAIL' if errors else 'PASS';record['errors']=errors
                result['fail_count' if errors else 'pass_count']+=1
        except Exception as exc:status='SETUP_ERROR';record['error']=str(exc);result['blocked_count']+=1
        record['status']=status;result['cases'].append(record)
        print(('ok ' if status=='PASS' else 'not ok ')+str(i)+' - '+case['name']+(' # '+status if status!='PASS' else ''))
        if status=='FAIL':print('# '+json.dumps(record['errors']))
    result['state']='BEHAVIOR_RED' if result['fail_count'] else 'BLOCKED' if result['blocked_count'] else 'SCOPED_PASS'
    result['exit']=1 if result['fail_count'] else 2 if result['blocked_count'] else 0
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ('state','pass_count','fail_count','blocked_count')}));return result['exit']


if __name__=='__main__':raise SystemExit(main())

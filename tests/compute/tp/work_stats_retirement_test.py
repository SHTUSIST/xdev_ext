#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual captured work retirement must preserve communicator lifetime totals.

Reuses the frozen replay request and numeric oracle unchanged. The only new
assertion compares actual public stats before and after successful destruction.
"""
import argparse
import json
from pathlib import Path
from collective_behavior import compare
from native_library_probe import build,observe

HERE=Path(__file__).resolve().parent


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    result={'scope':'host actual captured production phases and public work/stats retirement; no GPU execution'}
    try:
        exe=build(a.source_root,out/'build')
        case=next(c for c in json.loads((HERE/'collective_vectors.json').read_text())['cases'] if c['name']=='d2_capture_pending_and_fresh_replay_keys')
        observed,code=observe({k:case[k] for k in ('name','family','request')},exe)
        if code:raise RuntimeError(str(observed))
        errors=compare(case['expected'],observed,case['request'].get('dtype'))
        if observed.get('destroy_after_graph')!=0:errors.append('actual completed graph work failed to destroy')
        before,after=observed['stats_before_destroy'],observed['stats_after_destroy']
        if before.get('completed',0)<=0:errors.append('no actual completed work before retirement')
        for field,value in before.items():
            if after.get(field)!=value:errors.append(field+' lifetime total changed at work destroy: '+str(value)+' -> '+str(after.get(field)))
        result.update(observed=observed,errors=errors,exit=int(bool(errors)),state='BEHAVIOR_RED' if errors else 'SCOPED_PASS')
    except Exception as error:result.update(exit=2,state='SETUP_ERROR',error=str(error))
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));return result['exit']


if __name__=='__main__':raise SystemExit(main())

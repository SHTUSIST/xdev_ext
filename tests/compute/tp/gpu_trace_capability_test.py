#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual configured d2 trace API must support an initially empty runtime log.

This feature RED proves no GPU record was generated. Runtime replay trace
records, dropped accounting and official compilation are separate checks.
"""
import argparse
import json
from pathlib import Path
from native_library_probe import build,observe


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);r={'scope':'actual empty d2 trace public API; no GPU trace execution'}
    try:
        exe=build(a.source_root,out/'build');o,code=observe({'request':{'action':'trace_capability'}},exe)
        if code:raise RuntimeError(str(o))
        errors=[]
        for k,w in {'status':0,'written':0,'ready_consumed_count':0}.items():
            if o.get(k)!=w:errors.append(k+' expected '+str(w)+' got '+str(o.get(k)))
        r.update(observed=o,errors=errors,exit=int(bool(errors)),state='BEHAVIOR_RED' if errors else 'SCOPED_PASS')
    except Exception as error:r.update(exit=2,state='SETUP_ERROR',error=str(error))
    (out/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r));return r['exit']


if __name__=='__main__':raise SystemExit(main())

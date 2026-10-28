#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Runtime capability RED for the authorized optional actual batch ABI.

A weak boundary permits compile/link success on the old implementation. This
does not certify a pipeline, counters or any batch semantics until exercised.
"""
import argparse
import json
from pathlib import Path
from native_library_probe import build,observe


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    receipt={'scope':'host full library runtime batch-entry capability only; no pipeline or GPU acceptance'}
    try:
        exe=build(a.source_root,out/'build');observed,code=observe({'request':{'action':'batch_capability'}},exe)
        receipt['observed']=observed
        if code:raise RuntimeError(str(observed))
        receipt['exit']=int(observed.get('batch_entry_available') is not True)
        receipt['state']='MISSING_FEATURE_RUNTIME_RED' if receipt['exit'] else 'CAPABILITY_PRESENT_NOT_CONFORMANCE'
    except Exception as error:receipt.update(exit=2,state='SETUP_ERROR',error=str(error))
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt));return receipt['exit']


if __name__=='__main__':raise SystemExit(main())

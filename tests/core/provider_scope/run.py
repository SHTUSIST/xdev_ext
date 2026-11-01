#!/usr/bin/env python3
"""Independent DMA scope comparator replay; absent new interface is SETUP."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=['candidate','legacy-adapter'],default='candidate')
    p.add_argument('--scope-header',type=Path)
    p.add_argument('--legacy-header',type=Path)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();here=Path(__file__).resolve().parent;out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=True);fixtures=out/'fixtures';fixtures.mkdir(exist_ok=True)
    for name in ['contract.h','legacy_adapter.h','comparisons.c','run.py']:shutil.copy2(here/name,fixtures/name)
    header=args.legacy_header if args.mode=='legacy-adapter' else args.scope_header
    receipt={'mode':args.mode,'case':'comparisons','candidate_source_read_by_test_author':False}
    if header is None or not header.is_file():
        receipt.update(status='SETUP',reason='explicit production comparator header unavailable')
        (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print('SETUP: comparator header unavailable');return 2
    header=header.resolve();shutil.copy2(header,out/'input-header.h')
    command=['gcc','-O1','-g','-std=gnu11','-Wall','-Wextra','-Werror','-I'+str(fixtures)]
    if args.mode=='legacy-adapter':command+=['-DDMA_SCOPE_LEGACY_ADAPTER','-DXDEV_LEGACY_HEADER="'+str(header)+'"']
    else:command+=['-DXDEV_SCOPE_HEADER="'+str(header)+'"']
    command+=[str(fixtures/'comparisons.c'),'-o',str(out/'comparisons')]
    result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    receipt.update(compile_command=command,compile_exit=result.returncode,header=str(header))
    (out/'compile.log').write_text(result.stdout);print(result.stdout,end='')
    if result.returncode:
        receipt['status']='SETUP';code=2
    else:
        executed=subprocess.run([str(out/'comparisons')],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20)
        (out/'run.log').write_text(executed.stdout);print(executed.stdout,end='')
        receipt.update(run_exit=executed.returncode,status='PASS' if not executed.returncode else 'ASSERTION_FAILURE')
        code=executed.returncode
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');return code

if __name__=='__main__':raise SystemExit(main())

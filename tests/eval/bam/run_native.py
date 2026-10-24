#!/usr/bin/env python3
"""Qualified correctness only. No process timeout: UNKNOWN must stay pinned."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from native_contract import qualify, plan_io, verify_image

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qualify', required=True, type=Path)
    p.add_argument('--mode', choices=['correctness'], required=True)
    p.add_argument('--binary',type=Path,default=Path(__file__).parent/'native-build'/'bam-native')
    p.add_argument('--original',type=Path,help='independently preserved complete approved-region image')
    p.add_argument('--seed',type=Path,help='write payload; original is restored before success')
    p.add_argument('--bytes',type=int,dest='length')
    a=p.parse_args()
    try:
        q=qualify(json.loads(a.qualify.read_text()))
        size=q['region_blocks']*q['lba_size']
        if size > 64*1024*1024:
            raise ValueError('correctness region limited to 64 MiB')
        length=a.length if a.length is not None else size
        plan_io(length,q['page_size'],q['lba_size'],q['region_start_lba'],q['region_blocks'])
        if not a.original or not a.original.is_file() or a.original.stat().st_size != size:
            raise ValueError('complete independent original image required')
        if q['direction']=='write' and (not a.seed or not a.seed.is_file() or a.seed.stat().st_size != length):
            raise ValueError('exact write seed required')
        if q['direction']=='read' and a.seed:
            raise ValueError('read direction cannot have write seed')
        if not a.binary.is_file() or not os.access(a.binary,os.X_OK):
            raise ValueError('native binary missing')
        if not stat.S_ISCHR(os.stat(q['controller']).st_mode):
            raise ValueError('libnvm controller is not a character device')
    except (ValueError,OSError,json.JSONDecodeError) as e:
        print('NOT_RUN: '+str(e),file=sys.stderr);return 4
    cmd=[str(a.binary.resolve()),'--authorized-native-v1',q['controller'],str(q['namespace_id']),
         str(q['namespace_blocks']),str(q['lba_size']),str(q['page_size']),str(q['region_start_lba']),
         str(q['region_blocks']),str(length),q['gpu_uuid'],str(q['cuda_capability']),
         q['direction'],str(a.original.resolve()),str(a.seed.resolve()) if a.seed else '-']
    # Inherit stderr. Hold stdout until terminal machine record is validated.
    try:
        result=subprocess.run(cmd,stdout=subprocess.PIPE,text=True,check=False)
    except OSError as e:
        print("NOT_RUN: "+str(e),file=sys.stderr);return 4
    if result.returncode:
        if result.stdout: print(result.stdout,file=sys.stderr,end='')
        return 4 if result.returncode==127 else (result.returncode if result.returncode in (1,4) else 1)
    try:
        record=json.loads(result.stdout)
        if record.get('backend')!='bam-native' or record.get('state')!='success' or record.get('mode')!='correctness':
            raise ValueError('invalid native terminal record')
        if record.get('full_image_verified') is not True or record.get('original_restored') is not True:
            raise ValueError('missing complete oracle/restoration')
        print(json.dumps(record,sort_keys=True));return 0
    except (ValueError,json.JSONDecodeError) as e:
        print(str(e),file=sys.stderr);return 1

if __name__=='__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Compile actual public declarations against frozen ABI literals."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

def declaration(text,name):
    start=text.index('struct '+name+' {')
    end=text.index('\n};',start)+3
    if end-start>8192:raise ValueError('public declaration exceeds bounded ABI fixture input')
    return text[start:end]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--public-header',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    receipt={'public_header':str(args.public_header),'expected_layout':'literal baseline x86-64 sizes/offsets/signatures'}
    try:
        text=args.public_header.read_text()
        selected=[declaration(text,name) for name in ['xdev_ext_dma_region','xdev_ext_dma_xfer','xdev_ext_dma_provider_ops']]
    except (OSError,ValueError) as error:
        receipt.update(status='SETUP',reason=str(error));(out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print('SETUP:',error);return 2
    (out/'actual_public_dma_types.h').write_text('\n\n'.join(selected)+'\n')
    shutil.copy2(Path(__file__).with_name('abi.c'),out/'abi.c')
    uapi=args.public_header.resolve().parents[1]/'uapi/linux/xdev_ext_mech.h'
    command=['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-DXDEV_DMA_UAPI_HEADER="'+str(uapi)+'"','-I'+str(out),str(out/'abi.c'),'-o',str(out/'abi')]
    result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    receipt.update(command=command,compile_exit=result.returncode,status='ASSERTION_FAILURE' if result.returncode else 'PASS')
    (out/'compile.log').write_text(result.stdout);print(result.stdout,end='')
    if not result.returncode:
        executed=subprocess.run([str(out/'abi')]);receipt['run_exit']=executed.returncode;print('public DMA ABI PASS')
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');return 1 if result.returncode else 0

if __name__=='__main__':raise SystemExit(main())

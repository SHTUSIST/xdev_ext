#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute real CE simulator copy with independent data/guard expectations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent

def function(source,name):
 start=source.index('static ',source.index(name)-40)
 opening=source.index('{',source.index(name,start));end=opening+1;level=1
 while level:
  level+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[start:end]

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--output',type=Path)
 p.add_argument('--mutations',action='store_true')
 args=p.parse_args()
 with tempfile.TemporaryDirectory(prefix='ce-copy-contract-') as temp:
  out=args.output.resolve() if args.output else Path(temp)
  out.mkdir(parents=True,exist_ok=True)
  source=(HERE/'xdev_ext_ce_sim.c').read_text()
  engine='\n'.join(function(source,n) for n in ('xdev_ext_ce_sim_in','xdev_ext_ce_sim_copy'))
  variants={'baseline':engine}
  if args.mutations:
   poison='\t/* H2D has finished every read before changing any Host payload. */'
   assert engine.count(poison)==1,'poison block missing'
   start=engine.index(poison);end=engine.index('\n\treturn 0;',start)
   block=engine[start:end]
   variants['remove-poison']=engine[:start]+engine[end:]
   copy_loop='\tfor (i = 0; i < req->n; i++) {\n\t\tvoid *dev'
   assert engine.count(copy_loop)==1
   variants['early-poison']=engine[:start].replace(copy_loop,block+'\n'+copy_loop)+engine[end:]
   validation_start=engine.index('\tfor (i = 0; i < req->n; i++) {')
   validation_end=engine.index(copy_loop)
   validation=engine[validation_start:validation_end]
   check=validation[validation.index('\n')+1:validation.rfind('\n\t}')]
   variants['partial-precheck']=engine[:validation_start]+engine[validation_end:].replace(
       '\n\t\tvoid *dev','\n'+check+'\n\t\tvoid *dev',1)
  records=[]
  for name,body in variants.items():
   for profile,flags in [('ubsan',['-fsanitize=undefined','-fno-sanitize-recover=all']),
                         ('asan',['-fsanitize=address','-fno-omit-frame-pointer'])]:
    path=out/(name+'-'+profile);path.mkdir(exist_ok=True)
    (path/'engine.h').write_text(body)
    binary=path/'copy-contract'
    command=[os.environ.get('CC','gcc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
             *flags,'-I'+str(path),str(HERE/'copy_contract.c'),'-o',str(binary)]
    build=subprocess.run(command,capture_output=True,text=True)
    (path/'build.log').write_text(build.stdout+build.stderr)
    if build.returncode:print(build.stderr);return 2
    run=subprocess.run([str(binary)],env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0'),
                       capture_output=True,text=True,timeout=20)
    log=run.stdout+run.stderr;(path/'run.log').write_text(log+'\nexit=%d\n'%run.returncode)
    passed=(run.returncode==0 and 'PASS ' in log) if name=='baseline' else (
            run.returncode==1 and 'D2H_ASSERT ' in log)
    records.append(dict(variant=name,profile=profile,exit=run.returncode,passed=passed))
    print(('PASS ' if passed else 'FAIL ')+name+' '+profile+' '+log.splitlines()[-1],flush=True)
  verdict='PASS' if all(x['passed'] for x in records) else 'FAIL'
  (out/'result.json').write_text(json.dumps(dict(verdict=verdict,source_sha256=hashlib.sha256(
   source.encode()).hexdigest(),results=records),indent=2)+'\n')
  return 0 if verdict=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())

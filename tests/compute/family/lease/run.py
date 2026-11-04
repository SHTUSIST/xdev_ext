#!/usr/bin/env python3
"""Independent lease cohort: compile actual source, never a lease model."""
import argparse, pathlib, re, subprocess, json, hashlib
P=pathlib.Path(__file__).resolve().parent
A=argparse.ArgumentParser(); A.add_argument('--source-root',required=True); A.add_argument('--phase',choices=['baseline','shared','mutations','shared-mutations'],default='baseline'); A.add_argument('--out',required=True); a=A.parse_args()
S=pathlib.Path(a.source_root).resolve(); O=pathlib.Path(a.out).resolve(); O.mkdir(parents=True,exist_ok=True)
# Only actual production headers, never tests/probes or prior oracles.
files=list((S/'src').rglob('*.h')); byname={}
for p in files: byname.setdefault(p.name,[]).append(p)
read={}; headers={}
def expand(p):
 p=p.resolve()
 if p in read:return ''
 txt=p.read_text(); read[p]=hashlib.sha256(txt.encode()).hexdigest()
 def inc(m):
  name=m.group(1); base=pathlib.Path(name).name
  if base.startswith('xdev_ext'):
   candidates=byname.get(base,[])
   if (p.parent/name).is_file(): return expand(p.parent/name)
   if name.startswith('uapi/'): candidates=[q for q in candidates if '/uapi/' in str(q)]
   elif name.startswith('linux/'): candidates=[q for q in candidates if '/include/linux/' in str(q)]
   if len(candidates)!=1:raise RuntimeError(('ambiguous include',name,candidates))
   return expand(candidates[0])
  return '' if name.startswith(('linux/','asm/','uapi/')) else m.group(0)
 return '\n#line 1 "'+str(p)+'"\n'+re.sub(r'^\s*#include\s*[<"]([^>"]+)[>"]\s*$',inc,txt,flags=re.M)
# Expand complete real headers before boundary core definitions and complete TUs.
units=['src/compute/io_uring/xdev_ext_mech_ce.c','src/core/io_uring/xdev_ext_mech_dma.c','src/compute/io_uring/xdev_ext_compfam_copy.c']
if a.phase in ('shared','shared-mutations'):units.insert(0,'src/compute/io_uring/xdev_ext_compfam_copy_lease.c')
head=expand(S/'src/core/include/linux/xdev_ext_mech.h')+expand(S/'src/compute/include/linux/xdev_ext_compfam.h')
# Complete source expansion preserves algorithms; includes resolved once in one TU.
for u in units:
 if not (S/u).is_file():print('SETUP required actual source absent: '+u);raise SystemExit(2)
body=''.join(expand(S/u) for u in units)
source=(P/'boundary.h').read_text()+'\n'+head+'\n'+(P/'core.h').read_text()+'\n'+body+'\n'+'\n#line 1 \"independent-cases.c\"\n'+(P/'cases.c').read_text()
(O/'cohort.c').write_text(source); (O/'source-freeze.json').write_text(json.dumps({'baseline':'e51d72605ec53c5472121e149774d27565e434fc','source_root':str(S),'read':{str(k.relative_to(S)):v for k,v in read.items()}},indent=2)+'\n')
cmd=['gcc','-std=gnu11','-O0','-g','-fno-strict-aliasing','-funsigned-char','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-function','-Wno-missing-field-initializers','-fsanitize=undefined','-fno-sanitize-recover=all',str(O/'cohort.c'),'-o',str(O/'cohort')]
if a.phase in ('shared','shared-mutations'):cmd[1:1]=['-DLEASE_SHARED=1','-finstrument-functions']
r=subprocess.run(cmd,text=True,capture_output=True); (O/'compile.log').write_text(r.stdout+r.stderr); (O/'command.json').write_text(json.dumps(cmd)+'\n')
if r.returncode:print('SETUP compiler failure: '+str(O/'compile.log'));raise SystemExit(2)
r=subprocess.run([str(O/'cohort')],text=True,capture_output=True); (O/'run.log').write_text(r.stdout+r.stderr); print(r.stdout+r.stderr,end='')
if r.returncode:raise SystemExit(r.returncode)
if a.phase in ('mutations','shared-mutations'):
 mode='shared' if a.phase=='shared-mutations' else 'baseline'
 raise SystemExit(subprocess.run(['python3',str(P/'mutations.py'),'--baseline',str(O),'--out',str(O/'mutations'),'--mode',mode]).returncode)
raise SystemExit(0)

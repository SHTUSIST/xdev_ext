#!/usr/bin/env python3
"""Actual production pure/kernel-function projections at thin native boundary."""
import argparse
import json
from pathlib import Path
import re
import subprocess
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--new',action='store_true');a=p.parse_args()
root=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);tests=Path(__file__).resolve().parent
status=[]
def function(text,name,which=0,optional=False):
 matches=list(re.finditer(r'\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{',text))
 if len(matches)<=which:
  if optional:return ''
  raise ValueError('SETUP: missing production function '+name)
 m=matches[which];start=text.rfind('\n',0,m.start())+1
 prev=text[text.rfind('\n',0,max(0,start-1))+1:max(0,start-1)]
 if prev.strip().startswith(('static ','int ','struct ','u32 ','u64 ')) and '{' not in prev and '}' not in prev:start-=len(prev)+1
 brace=text.index('{',m.start());depth=0;quote=None;escape=False;line=False;block=False;i=brace
 while i<len(text):
  c=text[i];n=text[i+1:i+2]
  if line:
   if c=='\n':line=False
  elif block:
   if c=='*' and n=='/':block=False;i+=1
  elif quote:
   if escape:escape=False
   elif c=='\\':escape=True
   elif c==quote:quote=None
  elif c=='/' and n=='/':line=True;i+=1
  elif c=='/' and n=='*':block=True;i+=1
  elif c in ('"',"'"):quote=c
  elif c=='{':depth+=1
  elif c=='}':
   depth-=1
   if depth==0:return text[start:i+1]+'\n'
  i+=1
 raise ValueError('SETUP: unbalanced production function '+name)

def run(cmd,name):
 (out/(name+'.command.json')).write_text(json.dumps([str(x) for x in cmd]))
 r=subprocess.run([str(x) for x in cmd],capture_output=True,text=True)
 (out/(name+'.log')).write_text(r.stdout+r.stderr);(out/(name+'.exit')).write_text(str(r.returncode)+'\n');status.append((name,r.returncode))
 if r.returncode:print(r.stdout+r.stderr)
 return r

(out/'context.json').write_text(json.dumps({'source':str(root),'new':a.new,'boundary_PAGE_SIZE':4096,'boundary_BIO_MAX_INLINE_VECS':4,'scope':'real production decisions; thin native API observations; no DMA/device proof'},indent=2))
if a.new:
 missing=[str(root/f) for f in ['src/storage/include/linux/xdev_ext_storfam_block.h','src/storage/io_uring/family/xdev_ext_storfam_block.c'] if not (root/f).is_file()]
 if missing:
  (out/'setup.json').write_text(json.dumps({'state':'SETUP','missing':missing},indent=2));print('SETUP missing new runtime:',missing);exit(2)
try:
 pinned='89be9a83ccf1f88522317ce02f854f30d6115c41'
 if json.loads((root/'third_party/sources.lock.json').read_text())['components']['linux']['commit']!=pinned:
  raise ValueError('SETUP: native block fixture requires Linux lock '+pinned)
 def required(pattern,text):
  m=re.search(pattern,text,re.M|re.S)
  if not m:raise ValueError('SETUP: missing actual native declaration '+pattern)
  return m.group(0)+'\n'
 blktypes=(root/'src/core/include/linux/blk_types.h').read_text()
 mqheader=(root/'src/core/include/linux/blk-mq.h').read_text()
 native_types=required(r'^typedef[^;\n]*\bblk_opf_t;',blktypes)
 native_types+=required(r'^#define REQ_OP_BITS[^\n]*',blktypes)+required(r'^enum req_flag_bits\s*\{.*?^\};',blktypes)
 native_types+=required(r'^#define REQ_POLLED[^\n]*',blktypes)+required(r'^enum hctx_type\s*\{.*?^\};',mqheader)
 (out/'actual_block_native.inc').write_text(native_types)
 core=(root/'src/core/io_uring/xdev_ext_mech.c').read_text();header=(root/'src/core/include/linux/xdev_ext_mech.h').read_text()
 core_parts='\n'.join(function(core,n) for n in ['xdev_ext_mech_session_pool','xdev_ext_mech_batch_nr_frames','xdev_ext_mech_batch_bytes','xdev_ext_mech_batch_frame'])+function(header,'xdev_ext_mech_frame_page')
 (out/'actual_core.inc').write_text(core_parts)
 native=(root/'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c').read_text()
 map_parts='\n'.join(function(native,n,optional=True) for n in ['nvme_xdev_ext_class_caps','nvme_xdev_ext_class_walk'])+function(native,'nvme_xdev_ext_class_map')
 (out/'actual_map.inc').write_text(map_parts)
 bounce_enabled=function(native,'nvme_xdev_ext_class_bounce_copy')+function(native,'nvme_xdev_ext_class_bounce',which=0)
 bounce_disabled=function(native,'nvme_xdev_ext_class_bounce',which=1)
 shim=out/'shim/linux';shim.mkdir(parents=True,exist_ok=True)
 for h in ['bio.h','blkdev.h','blk-mq.h','blk_types.h','mm.h','module.h','kernel.h','export.h','xdev_ext_mech.h']:(shim/h).write_text('#include "kernel_boundary.h"\n')
 include=['-I',str(tests),'-I',str(out),'-I',str(out/'shim'),'-I',str(root/'src/storage/include/linux'),'-I',str(root/'src/storage/include'),'-I',str(root/'src/core/include/linux')]
 mode=['-DBLOCK_NEW=1','-DCONFIG_BLOCK=1'] if a.new else []
 for profile in ['gcc','ubsan']:
  flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare']
  if profile=='ubsan':flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
  seg=out/(profile+'-seg');r=run(['gcc',*flags,*mode,*include,tests/'test_seg.c','-o',seg],profile+'-seg-compile')
  if not r.returncode:
   r=run([seg],profile+'-seg-run');print(r.stdout.strip())
  for bounce,body in [(0,bounce_disabled),(1,bounce_enabled)]:
   folder=out/(profile+'-bounce'+str(bounce));folder.mkdir(exist_ok=True);(folder/'actual_bounce.inc').write_text(body)
   binary=folder/'runtime';options=['-DTEST_BOUNCE=1'] if bounce else []
   cmd=['gcc',*flags,*mode,*options,'-I',str(folder),*include,tests/'test_runtime.c']
   if a.new:
    obj=folder/'family.o'
    r=run(['gcc',*flags,*mode,*include,'-include',tests/'kernel_boundary.h','-c',root/'src/storage/io_uring/family/xdev_ext_storfam_block.c','-o',obj],profile+'-family-compile-'+str(bounce))
    if r.returncode:continue
    cmd += [obj,'-Wl,--wrap=xdev_ext_stor_block_caps','-Wl,--wrap=xdev_ext_stor_block_preflight','-Wl,--wrap=xdev_ext_stor_block_append']
   r=run([*cmd,'-o',binary],profile+'-runtime-compile-'+str(bounce))
   if not r.returncode:
    r=run([binary],profile+'-runtime-run-'+str(bounce));print(r.stdout.strip())
except Exception as e:
 (out/'setup-error.txt').write_text(str(e));print(e);exit(2)
(out/'status.json').write_text(json.dumps(status,indent=2))
exit(2 if any(rc and 'compile' in n for n,rc in status) else 1 if any(rc for n,rc in status) else 0)

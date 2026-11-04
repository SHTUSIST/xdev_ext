#!/usr/bin/env python3
"""Copy-source semantic mutations; build errors are SETUP, never detection.

Candidate transforms are specified from frozen API/semantics, not its implementation.
No files in the supplied source are written. The root runs candidate mode independently.
"""
import argparse,json,re,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--new',action='store_true');a=p.parse_args()
source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
testdir=Path(__file__).resolve().parent
N='src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c'
R='src/storage/io_uring/family/xdev_ext_storfam_block.c'
H='src/storage/include/linux/xdev_ext_storfam_block.h'

def once(text,old,new):
 if text.count(old)!=1:raise ValueError('SETUP mutation anchor count '+str(text.count(old))+': '+old)
 return text.replace(old,new,1)

def function_span(text,name):
 m=re.search(r'\b'+name+r'\s*\([^;{}]*\)\s*\{',text)
 if not m:raise ValueError('SETUP missing function '+name)
 start=text.index('{',m.start());depth=1;i=start+1
 # Only scan brace-balanced C function; mutation anchors themselves are exact.
 while i<len(text):
  if text[i]=='{':depth+=1
  elif text[i]=='}':
   depth-=1
   if not depth:return start,i+1
  i+=1
 raise ValueError('SETUP unbalanced function '+name)

def modify_function(text,name,edit):
 lo,hi=function_span(text,name);return text[:lo]+edit(text[lo:hi])+text[hi:]

def subonce(body,pattern,replacement):
 body,n=re.subn(pattern,replacement,body,count=1)
 if n!=1:raise ValueError('SETUP missing semantic anchor '+pattern)
 return body

def call_limit(body):
 # Replace nr_views argument at the real family-call boundary, regardless of local view name.
 name='xdev_ext_stor_block_poll';start=body.index(name+'(')+len(name)+1;depth=0;commas=[];i=start
 while i<len(body):
  c=body[i]
  if c=='(':depth+=1
  elif c==')':
   if not depth:break
   depth-=1
  elif c==',' and not depth:commas.append(i)
  i+=1
 if len(commas)!=2:raise ValueError('SETUP family call arity')
 return body[:commas[-1]+1]+' 1'+body[i:]

old_prefix='nvme_xdev_ext_poll_';new_prefix='xdev_ext_stor_block_poll_'
prefix=new_prefix if a.new else old_prefix
poll_name='xdev_ext_stor_block_poll' if a.new else 'nvme_xdev_ext_class_poll'
poll_file=R if a.new else N
cases=[
 ('hctx-check-skipped',R if a.new else N,prefix+'check',lambda b:'{ return 0; }'),
 ('false-opf-clears-POLLED',H if a.new else N,prefix+'opf',lambda b:subonce(b,r':\s*opf\s*;',': opf & ~REQ_POLLED;')),
 ('arm-live-before-queue',R if a.new else N,prefix+'arm',lambda b:subonce(b,r'(done->poll_queue\s*=\s*[^;]+;)\s*(WRITE_ONCE\(done->poll_live, true\);)',r'\2\n\1')),
 ('arm-wrong-queue',R if a.new else N,prefix+'arm',lambda b:subonce(b,r'(\w+->mq_hctx->queue_num)',r'\1 + 1')),
 ('missing-PEER',N,'nvme_xdev_ext_class_poll',call_limit if a.new else lambda b:once(b,'i < 2','i < 1')),
 ('wrong-done-stride',N,'nvme_xdev_ext_class_poll',lambda b:subonce(b,r'\.stride\s*=\s*sizeof\(\*p->slots\)', '.stride = sizeof(struct xdev_ext_stor_completion)') if a.new else once(b,'&p->slots[j].done','(struct xdev_ext_stor_completion *)((char *)&p->slots[0].done + j * sizeof(struct xdev_ext_stor_completion))')),
 ('seen-reset-per-view',poll_file,poll_name,lambda b:subonce(b,r'(for\s*\([^{}]*\)\s*\{)',r'\1\n nr_seen = 0;')),
 ('stop-at-seen64',poll_file,poll_name,lambda b:subonce(b,r'(\w+\s*=\s*blk_mq_poll_hw_queue\()',r'if (nr_seen >= ARRAY_SIZE(seen)) return found;\n\1')),
 ('negative-key-forgotten',poll_file,poll_name,lambda b:subonce(b,r'(if\s*\(ret\s*>\s*0\))',r'if (ret <= 0 && nr_seen) nr_seen--;\n\1')),
 ('negative-propagated',poll_file,poll_name,lambda b:subonce(b,r'(if\s*\(ret\s*>\s*0\))',r'if (ret < 0) return ret;\n\1')),
 ('host-consumer-skips-check',N,'nvme_xdev_ext_class_submit',lambda b:subonce(b,r'ret\s*=\s*(?:nvme_xdev_ext_poll_check|xdev_ext_stor_block_poll_check)\([^;]+;', 'ret = 0;')),
 ('PEER-consumer-skips-check',N,'nvme_xdev_ext_peer_submit',lambda b:subonce(b,r'ret\s*=\s*(?:nvme_xdev_ext_poll_check|xdev_ext_stor_block_poll_check)\([^;]+;', 'ret = 0;')),
]

def overlay(dest):
 def tree(src,dst,parts):
  dst.mkdir(parents=True,exist_ok=True)
  for item in src.iterdir():
   relevant=[p[1:] for p in parts if p and p[0]==item.name]
   if relevant and any(relevant):tree(item,dst/item.name,relevant)
   elif relevant:(dst/item.name).write_bytes(item.read_bytes())
   else:(dst/item.name).symlink_to(item,target_is_directory=item.is_dir())
 tree(source,dest,[Path(x).parts for x in [N,R,H]])

summary=[]
for name,path,func,edit in cases:
 case=out/name;case.mkdir(exist_ok=True);copy=case/'source'
 try:
  overlay(copy);original=(copy/path).read_text();changed=modify_function(original,func,edit)
  (copy/path).write_text(changed)
  import difflib
  (case/'mutation.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile=path,tofile=path)))
  cmd=[sys.executable,str(testdir/'run.py'),str(copy),str(case/'run')]+(['--new'] if a.new else [])
  result=subprocess.run(cmd,capture_output=True,text=True);(case/'driver.log').write_text(result.stdout+result.stderr)
  (case/'command.json').write_text(json.dumps(cmd));(case/'exit').write_text(str(result.returncode)+'\n')
  statuses=json.loads((case/'run/status.json').read_text())
  compiled=all(rc==0 for step,rc in statuses if 'compile' in step)
  failed=any(rc!=0 for step,rc in statuses if step.endswith('-run'))
  verdict='DETECTED' if compiled and failed else 'SETUP' if not compiled else 'SURVIVED'
 except Exception as e:verdict='SETUP';(case/'error.txt').write_text(str(e))
 summary.append({'mutation':name,'verdict':verdict});print(name,verdict,flush=True)
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
sys.exit(0 if all(s['verdict']=='DETECTED' for s in summary) else 1)

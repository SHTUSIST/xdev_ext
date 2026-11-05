#!/usr/bin/env python3
"""Copy-source semantic mutations; build errors are SETUP, never detection.

Candidate transforms are specified from frozen API/semantics, not its implementation.
No files in the supplied source are written. The root runs candidate mode independently.
"""
import argparse,json,re,subprocess,sys,shutil,runpy
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--new',action='store_true');a=p.parse_args()
source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
testdir=Path(__file__).resolve().parent
_LAYOUT_FILE = next(p / 'tools/layout.py' for p in Path(__file__).resolve().parents
                    if (p / 'tools/layout.py').is_file())
_TOOL_ROOT = runpy.run_path(str(_LAYOUT_FILE))['canonical_root'](Path(__file__))
_LEGACY = runpy.run_path(str(_TOOL_ROOT / 'tests/storage/nvme/_legacy_storfam_fixture.py'))
LegacySelection, NATIVE_OWNER = (_LEGACY[name] for name in ('LegacySelection', 'N'))
selection=LegacySelection(source)
source=selection.root
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
 if len(list(re.finditer(pattern,body)))!=1:raise ValueError('SETUP semantic anchor count: '+pattern)
 body,n=re.subn(pattern,replacement,body,count=1)
 if n!=1:raise ValueError('SETUP missing semantic anchor '+pattern)
 return body

def call_limit(body):
 # Replace nr_views argument at the real family-call boundary, regardless of local view name.
 name='xdev_ext_stor_block_poll'
 if body.count(name+'(')!=1:raise ValueError('SETUP family call count')
 start=body.index(name+'(')+len(name)+1;depth=0;commas=[];i=start
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

def reset_seen_per_view(body):
 # Match the complete outer view-loop header, never the nested slot loop.
 if a.new:
  anchor='for (i = 0; i < nr_views; i++) {'
  return once(body,anchor,anchor+'\n nr_seen = 0;')
 return subonce(body,r'(for\s*\(\s*i\s*=\s*0\s*;\s*i\s*<\s*2\s*;\s*i\+\+\s*\)\s*\{)',r'\1\n nr_seen = 0;')

old_prefix='nvme_xdev_ext_poll_';new_prefix='xdev_ext_stor_block_poll_'
prefix=new_prefix if a.new else old_prefix
poll_name='xdev_ext_stor_block_poll' if a.new else 'nvme_xdev_ext_class_poll'
poll_file=R if a.new else N
member_family='struct xdev_ext_stor_stage family;' in (source/N).read_text()
current_common='return xdev_ext_storfam_submit(&p->family, b, &bp->family);' in (source/N).read_text()
cases=[
 ('hctx-check-skipped',R if a.new else N,prefix+'check',lambda b:'{ return 0; }'),
 ('false-opf-clears-POLLED',H if a.new else N,prefix+'opf',lambda b:subonce(b,r':\s*opf\s*;',': opf & ~REQ_POLLED;')),
 ('arm-live-before-queue',R if a.new else N,prefix+'arm',lambda b:subonce(b,r'(done->poll_queue\s*=\s*[^;]+;)\s*(WRITE_ONCE\(done->poll_live, true\);)',r'\2\n\1')),
 ('arm-wrong-queue',R if a.new else N,prefix+'arm',lambda b:subonce(b,r'(\w+->mq_hctx->queue_num)',r'\1 + 1')),
 ('missing-PEER',N,'nvme_xdev_ext_member_poll' if member_family else 'nvme_xdev_ext_class_poll',call_limit if a.new else lambda b:once(b,'i < 2','i < 1')),
 ('wrong-done-stride',R if member_family else N,'xdev_ext_storfam_poll' if member_family else 'nvme_xdev_ext_class_poll',lambda b:once(b,'return ss->dev->poll(', 'ss->poll_views[0].stride = sizeof(struct xdev_ext_stor_completion);\n return ss->dev->poll(') if member_family else subonce(b,r'\.stride\s*=\s*sizeof\(\*p->slots\)', '.stride = sizeof(struct xdev_ext_stor_completion)') if a.new else once(b,'&p->slots[j].done','(struct xdev_ext_stor_completion *)((char *)&p->slots[0].done + j * sizeof(struct xdev_ext_stor_completion))')),
 ('seen-reset-per-view',poll_file,poll_name,reset_seen_per_view),
 ('stop-at-seen64',poll_file,poll_name,lambda b:subonce(b,r'(\w+\s*=\s*blk_mq_poll_hw_queue\()',r'if (nr_seen >= ARRAY_SIZE(seen)) return found;\n\1')),
 ('negative-key-forgotten',poll_file,poll_name,lambda b:subonce(b,r'(if\s*\(ret\s*>\s*0\))',r'if (ret <= 0 && nr_seen) nr_seen--;\n\1')),
 ('negative-propagated',poll_file,poll_name,lambda b:subonce(b,r'(if\s*\(ret\s*>\s*0\))',r'if (ret < 0) return ret;\n\1')),
 ('host-consumer-skips-check',R if current_common else N,'xdev_ext_storfam_submit' if current_common else 'nvme_xdev_ext_class_submit',lambda b:once(b,'ret = xdev_ext_stor_block_poll_check(ss->st->poll, req);','ret = peer ? xdev_ext_stor_block_poll_check(ss->st->poll, req) : 0;') if current_common else subonce(b,r'ret\s*=\s*(?:nvme_xdev_ext_poll_check|xdev_ext_stor_block_poll_check)\([^;]+;', 'ret = 0;')),
 ('PEER-consumer-skips-check',R if current_common else N,'xdev_ext_storfam_submit' if current_common else 'nvme_xdev_ext_peer_submit',lambda b:once(b,'ret = xdev_ext_stor_block_poll_check(ss->st->poll, req);','ret = peer ? 0 : xdev_ext_stor_block_poll_check(ss->st->poll, req);') if current_common else subonce(b,r'ret\s*=\s*(?:nvme_xdev_ext_poll_check|xdev_ext_stor_block_poll_check)\([^;]+;', 'ret = 0;')),
]

if current_common:
 selection.declarations();selection.closure('poll','strict');selection.poll_common_source()
 selection.read('include/linux/blk_types.h')
else:
 for native in [NATIVE_OWNER,'io_uring/family/xdev_ext_storfam.c','include/linux/blk_types.h']:
  selection.read(native)
 if a.new or member_family:selection.read('io_uring/family/xdev_ext_storfam_block.c')
 if member_family:selection.read('drivers/nvme/host/nvme.h')
 mapping=selection._selection.mapping
 if mapping is None:raise ValueError('SETUP mutation copies require selected canonical source-layout.json')
 for (component,native) in mapping.by_native:
  if component=='linux' and native.endswith('.h') and (
      native.startswith(('include/linux/xdev_ext_','include/uapi/linux/xdev_ext_','drivers/nvme/host/xdev_ext_','io_uring/xdev_ext_')) or
      native in ('include/linux/nvme_xdev_ext_passthru.h','include/uapi/linux/nvme_ioctl.h')):
   selection.read(native)

def overlay(dest):
 if dest.exists():raise ValueError('SETUP disposable source already exists')
 dest.mkdir(parents=True)
 inventory=[];size=0
 for relative in ['source-layout.json','third_party/sources.lock.json']:
  original=selection.root/relative
  if not original.is_file():raise ValueError('SETUP missing disposable metadata: '+relative)
  target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True)
  payload=original.read_bytes();size+=len(payload);target.write_bytes(payload);inventory.append(relative)
 for native in selection.report()['inputs']:
  original=selection._selection.file(native)
  relative=original.relative_to(selection.root)
  target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True)
  payload=original.read_bytes();size+=len(payload)
  if size>2*1024*1024:raise ValueError('SETUP disposable source limit exceeded')
  target.write_bytes(payload);inventory.append(str(relative))
 (dest.parent/'source-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')

def expected_stages():
 return {profile+'-'+step for profile in ['gcc','ubsan'] for step in
         (['no-block-compile','no-block-run','poll-compile','poll-run','consumers-compile','consumers-run']+
          (['runtime-compile'] if a.new else []))}

baseline=out/'baseline'
command=[sys.executable,str(testdir/'run.py'),str(source),str(baseline)]+(['--new'] if a.new else [])
baseline_result=subprocess.run(command,capture_output=True,text=True)
(out/'baseline-driver.log').write_text(baseline_result.stdout+baseline_result.stderr)
(out/'baseline-command.json').write_text(json.dumps(command))
try:baseline_status=json.loads((baseline/'status.json').read_text())
except (OSError,ValueError):baseline_status=[]
if baseline_result.returncode or {name for name,rc in baseline_status}!=expected_stages() or any(rc for name,rc in baseline_status):
 (out/'summary.json').write_text(json.dumps([{'mutation':name,'verdict':'SETUP','reason':'baseline failed'} for name,_,_,_ in cases],indent=2)+'\n')
 raise SystemExit(2)

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
  compiled={step for step,rc in statuses}==expected_stages() and all(rc==0 for step,rc in statuses if 'compile' in step)
  failed=False;assertions=[]
  for step,rc in statuses:
   if rc and step.endswith('-run'):
    log=(case/'run'/(step+'.log')).read_text()
    named=re.findall(r'^FAIL ([^\n]+)',log,re.M)
    original_main_failure=re.search(r'assertions=[1-9][0-9]* failures=[1-9][0-9]*',log)
    original_no_work_stop=(rc==1 and re.search(r'^FAIL (?:host-real-submit|PEER-real-submit) no-slot got=1 want=0$',log,re.M) and
                           re.search(r'^FIXTURE_ASSERTION_STOP actual-SLOT invalid-hctx original-no_work failures=[1-9][0-9]*$',log,re.M))
    if named and (original_main_failure or original_no_work_stop):
     failed=True;assertions.extend(named)
  verdict='DETECTED' if compiled and failed else 'SETUP' if not compiled or any(rc for step,rc in statuses) else 'SURVIVED'
 except Exception as e:verdict='SETUP';(case/'error.txt').write_text(str(e))
 finally:
  if copy.exists():shutil.rmtree(copy)
 summary.append({'mutation':name,'verdict':verdict,'assertions':assertions if verdict=='DETECTED' else []});print(name,verdict,flush=True)
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
sys.exit(0 if all(s['verdict']=='DETECTED' for s in summary) else 1)

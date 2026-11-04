#!/usr/bin/env python3
import sys,pathlib,importlib.util,re,json,hashlib,subprocess,argparse,difflib
sys.dont_write_bytecode=True
A=pathlib.Path(__file__).resolve().parent;H=A
sp=importlib.util.spec_from_file_location('cohort',H/'assemble.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
old=m.old;original_transform=old.transform_assertions
PROOFS=[]
def transform(s,label):
 orig=s;edits=[]
 def sub(pattern,replacement):
  nonlocal s
  matches=list(re.finditer(pattern,s))
  for match in reversed(matches):
   before=match.group();after=match.expand(replacement) if isinstance(replacement,str) else replacement(match)
   edits.append(dict(at=match.start(),before=before,after=after));s=s[:match.start()]+after+s[match.end():]
 # Real initializer fixture supplies its namespace queue metadata.
 sub(r'(?= private_batch=\(struct nvme_xdev_ext_mech_batch\))', ' queue_a.queuedata=queue_b.queuedata=&ns;queue_a.disk=queue_b.disk=&disk;disk.private_data=&ns;')
 # Field lvalues relocated as specified by CONTRACT3. Native identity fields remain native.
 for field in ('window','dead','slots','pool','nr_slots','nr_vecs','peer'):
  sub(r'\bp->'+field+r'\b','p->family.'+field)
  sub(r'member7\(\)->'+field+r'\b','member7()->family.'+field)
 for field in ('sqe','rw','batch_id','validated','bio','bounce','nr_bounce'):
  sub(r'\bprivate_batch\.'+field+r'\b','private_batch.family.'+field)
 sub(r'\bprivate_batch\.slot\b','private_batch.family.host_io');sub(r'\bprivate_batch\.peer_slot\b','private_batch.family.peer_io')
 sub(r'struct nvme_xdev_ext_mech_slot\b','struct xdev_ext_stor_io');sub(r'struct nvme_xdev_ext_peer_slot\b','struct xdev_ext_stor_io')
 # Opaque slots use trusted stride. Test-only fixture allocations retain depth and separate arrays.
 sub(r'p->family\.peer->slots=zalloc\(3\*sizeof\(\*p->family\.peer->slots\)\);', 'p->family.peer->slots=zalloc(3*p->family.dev->peer_slot_bytes);')
 sub(r'p->family\.peer->slots\[([^\]]+)\]',r'(*xdev_ext_storfam_peer_io(&p->family,\1))')
 sub(r'member7\(\)->family\.peer->slots\[([^\]]+)\]',r'(*xdev_ext_storfam_peer_io(&member7()->family,\1))')
 sub(r'p->family\.peer->sgl_bytes\b','p->family.peer->list_bytes')
 sub(r'\(\*xdev_ext_storfam_peer_io\(&p->family,([^\)]+)\)\)\.sgl_dma',r'(*xdev_ext_storfam_peer_io(&p->family,\1)).list_dma')
 sub(r'private_batch\.family\.peer_io->sgl\b','private_batch.family.peer_io->list_cpu')
 sub(r'private_batch\.family\.peer_io->trace\b','(*(struct nvme_xdev_ext_peer_trace *)private_batch.family.peer_io->peer_native)')
 sub(r'slot->trace\b','(*(struct nvme_xdev_ext_peer_trace *)slot->peer_native)')
 # Direct private helper probes now invoke their actual common owners.
 sub(r'nvme_xdev_ext_class_slot_get\(&stage,&private_batch\)', 'xdev_ext_storfam_host_get(&((struct nvme_xdev_ext_mech_stage *)stage.priv)->family,&private_batch.family)')
 sub(r'nvme_xdev_ext_class_slot_put\(&stage,&private_batch\)', 'xdev_ext_storfam_host_put(&((struct nvme_xdev_ext_mech_stage *)stage.priv)->family,&private_batch.family)')
 sub(r'nvme_xdev_ext_class_map\(&stage,&batch,&req,&private_batch\)', 'xdev_ext_storfam_host_map(&((struct nvme_xdev_ext_mech_stage *)stage.priv)->family,&batch,&req,&private_batch.family)')
 # Publish borrowed poll fixture with actual unlike owner strides (fixture only).
 anchor='p->family.peer->slots=zalloc(3*p->family.dev->peer_slot_bytes);'
 if anchor in s:
  sub(re.escape(anchor),anchor+'p->family.poll_views[1]=(struct xdev_ext_stor_poll_view){.first=&xdev_ext_storfam_peer_io(&p->family,0)->done,.stride=p->family.dev->peer_slot_bytes,.count=3};')
 rev=s
 for e in reversed(edits):
  at=e['at'];assert rev[at:at+len(e['after'])]==e['after'];rev=rev[:at]+e['before']+rev[at+len(e['after']):]
 assert rev==orig
 PROOFS.append(dict(label=label,reverse_exact=True,original_sha256=hashlib.sha256(orig.encode()).hexdigest(),reverse_sha256=hashlib.sha256(rev.encode()).hexdigest(),edits=edits))
 return s

def remap(original,unused):return transform(original,'golden/assertions.c'),'',original
old.transform_assertions=remap
original_boundary=m.boundary
def boundary():
 s,atom=original_boundary()
 s=s.replace("typedef uint64_t u64;", "typedef __u64 u64;")
 s=s.replace("unsigned flags,status,retries;", "u8 flags,retries;u16 status;")
 s=s.replace('void __attribute__((no_instrument_function)) __cyg_profile_func_enter', 'static void (*adapter_enter)(void *),(*adapter_exit)(void *);\nvoid __attribute__((no_instrument_function)) __cyg_profile_func_enter')
 s=s.replace('(void)caller;\n for(unsigned i=0;', '(void)caller;if(adapter_enter)adapter_enter(fn);\n for(unsigned i=0;')
 s=s.replace('{(void)fn;(void)caller;}','{(void)caller;if(adapter_exit)adapter_exit(fn);}')
 return s,atom
m.boundary=boundary
original_assemble=m.assemble

def assemble(root,out,config,mutation=None):
 c,inc=original_assemble(root,out,config,mutation)
 shared=out.parent/'test-inputs'
 (shared/'assertions_7b.c').write_text(transform((H/'assertions_7b.c').read_text(),'assertions_7b.c'))
 (out.parent/'PROOFS.json').write_text(json.dumps(PROOFS,indent=2)+'\n')
 return c,inc
m.assemble=assemble

def snapshot(root):
 paths=sorted(set([m.NATIVE,m.BLOCK,m.RUNTIME,m.REQ,m.FD,m.RC,m.CORE,m.TRACE,old.NVME,old.MECH,*m.b.HEADERS.values()]))
 inputs=json.loads((A/'INPUTS.json').read_text())
 tests={name:hashlib.sha256((A/name).read_bytes()).hexdigest() for name in inputs['files']}
 tests['INPUTS.json']=hashlib.sha256((A/'INPUTS.json').read_bytes()).hexdigest()
 return dict(source_root=str(root.resolve()),source_layout='canonical src/{core,storage}',sources={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths},tests=tests)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source-root',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);ap.add_argument('--suite',choices=['extended','golden','common','all'],default='all');a=ap.parse_args();a.out.mkdir(exist_ok=False)
 before=snapshot(a.source_root);(a.out/'SOURCE.json').write_text(json.dumps(before,indent=2)+'\n')
 rows=[]
 cases=[]
 if a.suite in ('all','extended'):cases += [(v,v,'extended',False) for v in ('strict','bounce','disabled')]
 if a.suite in ('all','golden'):cases += [('golden-gcc','strict','golden',False),('golden-ubsan','strict','golden',True)]
 if a.suite in ('all','common'):cases += [('common','strict','common',False)]
 for name,config,suite,ubsan in cases:
  out=a.out/name;out.mkdir();row=dict(name=name)
  try:
   c,inc=assemble(a.source_root,out,config)
   text=c.read_text()
   if suite=='common':
    text=m.replace(text,'#include "assertions.c"\n#include "assertions_7b.c"','')+'\n#include "common_gate.c"\n';(out/'common_gate.c').write_bytes((H/'common_gate.c').read_bytes())
    text=text.replace('#include "common_gate.c"','#define main frozen_common_main\n#include "common_gate.c"\n#undef main\n#include "extra_common.c"');(out/'extra_common.c').write_bytes((A/'extra_common.c').read_bytes())
   if suite=='golden':
    text=m.replace(text,'#include "assertions_7b.c"','\n#include "candidate.c.in"')
    observer = """static void __attribute__((no_instrument_function)) observe_entry(void *fn){if(fn==(void *)nvme_init_request){events[event_count++]='I';events[event_count]=0;}}
static void __attribute__((no_instrument_function)) observe_exit(void *fn){if(fn==(void *)nvme_init_request)last_command=req.command;}
static void __attribute__((constructor,no_instrument_function)) enable_observer(void){adapter_enter=observe_entry;adapter_exit=observe_exit;}
"""
    text=m.replace(text,'#include "assertions.c"',observer+'\n#include "assertions.c"')
    (out/'candidate.c.in').write_text(transform((m.GOLDEN/'candidate.c.in').read_text(),'golden/candidate.c.in'))
    (out/'candidate_adapter.h').write_bytes((m.GOLDEN/'candidate_adapter.h').read_bytes())
   c.write_text(text)
   cmd=['gcc','-DTEST_'+config.upper(),'-std=gnu11','-O0','-g0','-finstrument-functions','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-parameter','-Werror=implicit-function-declaration','-I'+str(inc),'-I'+str(out),str(c),'-o',str(a.out/'working')]
   if config=='disabled':cmd.remove('-DTEST_DISABLED')
   if suite=='golden':cmd[cmd.index('-g0')]='-g'
   if ubsan:cmd[1:1]=['-fsanitize=undefined','-fno-sanitize-recover=all']
   cr=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);(out/'compile.log').write_text(cr.stdout);row.update(compile_exit=cr.returncode,command=cmd)
   if cr.returncode:row['verdict']='SETUP'
   else:
    rr=subprocess.run([str(a.out/'working')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15);(out/'run.log').write_text(rr.stdout);row.update(run_exit=rr.returncode,output=rr.stdout,verdict='PASS' if rr.returncode==0 else 'FAIL')
  except Exception as e:row.update(verdict='SETUP',error=str(e))
  rows.append(row);print(row,flush=True)
 if (a.out/'working').exists():(a.out/'working').unlink()
 (a.out/'RESULT.json').write_text(json.dumps(dict(results=rows),indent=2)+'\n');(a.out/'PROOFS.json').write_text(json.dumps(PROOFS,indent=2)+'\n')
 after=snapshot(a.source_root);(a.out/'SOURCE-AFTER.json').write_text(json.dumps(after,indent=2)+'\n');print('SOURCE_INPUTS_STABLE',before==after,flush=True)
 return int(before!=after or any(v['verdict']!='PASS' for v in rows))
if __name__=='__main__':sys.exit(main())

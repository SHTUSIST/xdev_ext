#!/usr/bin/env python3
"""Independent 7B host boundary. Production algorithms remain complete actual definitions."""
import argparse,hashlib,importlib.util,json,pathlib,subprocess,sys,re,runpy
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent
GOLDEN=HERE.parent/'native_member_7a'
sp=importlib.util.spec_from_file_location('old',GOLDEN/'run_candidate.py');old=importlib.util.module_from_spec(sp);sp.loader.exec_module(old)
b=old.base
# The actual NVMe compatibility header includes this shared type/helper owner.
# Extend only this fixture's inherited inventory; snapshot and copy use it alike.
b.HEADERS={**b.HEADERS,
 'linux/xdev_ext_cmd_lifecycle.h':'src/core/include/linux/xdev_ext_cmd_lifecycle.h'}
NATIVE,BLOCK,RUNTIME=old.NATIVE,old.BLOCK,old.RUNTIME
REQ='src/core/io_uring/family/xdev_ext_requester.c'
FD='src/core/io_uring/xdev_ext_peer_fd.c'
RC='src/core/include/linux/xdev_ext_requester_core.h'
CORE='src/storage/drivers/nvme/host/core.c'
TRACE='src/storage/drivers/nvme/host/xdev_ext_native_peer_trace.h'
RH='src/core/include/linux/xdev_ext_requester.h'
PH='src/core/include/linux/xdev_ext_peer.h'
REQUESTER_FIXTURE='tests/storage/nvme/_legacy_storfam_fixture.py'
REQUESTER_SOURCES=(RH,PH,REQUESTER_FIXTURE,
 'tests/integration/peer_graph/nvme_peer_async_test.py',
 'tests/storage/nvme/_locked_requester_native.h','tests/storage/nvme/_locked_nvme_opcode.h','tools/layout.py',
 'source-layout.json','third_party/sources.lock.json')

def function(s,name):
 if name=='nvme_xdev_ext_class_bounce':s=s.split('#ifndef NVME_XDEV_EXT_MECH_BOUNCE_AVAILABLE')[0]
 ms=list(re.finditer(r'\b'+re.escape(name)+r'\s*\([^;{}]*?\)\s*\{',s,re.S))
 if len(ms)!=1:raise b.Setup('exact function '+name+' count '+str(len(ms)))
 m=ms[0];start=s.rfind('\n',0,m.start())+1
 if not s[start:m.start()].strip():start=s.rfind('\n',0,start-1)+1
 return b.function(s[:start]+'\n\n'+s[start:],name)

def replace(s,a,z):
 if s.count(a)!=1:raise b.Setup('boundary anchor count '+str(s.count(a))+': '+a[:70])
 return s.replace(a,z,1)

def boundary_func(s,symbol):
 matches=[line for line in s.splitlines() if re.search(r'\b'+re.escape(symbol)+r'\s*\([^;{}]*\)\s*\{',line)]
 if len(matches)!=1:raise b.Setup('boundary function '+symbol)
 return matches[0]+'\n'

def boundary():
 s='#define __aligned(n) __attribute__((aligned(n)))\n'+(GOLDEN/'boundary.h').read_text()
 s=replace(s,'#define CONFIG_XDEV_EXT_MECH_ZEROCOPY 1','#ifdef TEST_STRICT\n#define CONFIG_XDEV_EXT_MECH_ZEROCOPY 1\n#endif\n#ifdef TEST_BOUNCE\n#define CONFIG_XDEV_EXT_MECH_KVM_BOUNCE 1\n#endif')
 atom=s[s.index('typedef struct { int counter; } atomic_t;'):s.index('struct page {')];s=s.replace(atom,'')
 for symbol in ['nvme_req_op','nvme_init_request','nvme_xdev_ext_class_end_io','nvme_xdev_ext_peer_end_io','nvme_xdev_ext_class_bounce','xdev_ext_peer_mech_pool_file','xdev_ext_peer_mech_pool_generation','xdev_ext_peer_lease_split','xdev_ext_peer_fd_release','nvme_xdev_ext_peer_trace_release','xdev_ext_mech_batch_completion_claim','xdev_ext_mech_trace_native_complete','xdev_ext_mech_batch_completion_publish']:
  s=replace(s,boundary_func(s,symbol).strip(),'')
 s=replace(s,'struct nvme_xdev_ext_peer_trace { struct xdev_ext_peer_fd_lease *leases; u32 nr_leases,bytes;const char *origin;u64 cookie; };','')
 s=replace(s,'struct xdev_ext_peer_fd_lease { struct { u64 dma_address; u32 len; } lease; };','struct xdev_ext_peer_fd_lease { struct file *file; struct { u64 dma_address,ticket; u32 len; void *mapping; } lease; };')
 s=replace(s,'static int append_errno;','static int append_errno,append_error_once;')
 s=replace(s,"ev('B');if(append_errno)return append_errno;","ev('B');if(append_error_once){int e=append_error_once;append_error_once=0;return e;}if(append_errno)return append_errno;")
 s=replace(s,'struct blk_mq_hw_ctx { u32 queue_num; };','struct blk_mq_hw_ctx { u32 queue_num,type; };')
 s=replace(s,'struct request { blk_opf_t cmd_flags; struct blk_mq_hw_ctx *mq_hctx; void *end_io_data; int (*end_io)(struct request *,int); struct bio *bio; struct nvme_command command; struct {struct nvme_command *cmd; unsigned flags; void *peer_trace;} pdu; };',
 '''typedef int blk_status_t; enum rq_end_io_ret {RQ_END_IO_FREE};
struct nvme_ctrl;struct nvme_request {struct nvme_command *cmd; unsigned flags,status,retries;void *peer_trace;struct nvme_ctrl *ctrl;union {u64 u64;} result;};
struct request {blk_opf_t cmd_flags;struct blk_mq_hw_ctx *mq_hctx;void *end_io_data;enum rq_end_io_ret (*end_io)(struct request *,blk_status_t);struct bio *bio;struct nvme_command command;struct nvme_request pdu;struct request_queue *q;unsigned rq_flags,timeout,residual;};''')
 s=replace(s,'u32 virt_boundary,max_segments,max_segment_size,max_hw_sectors; int id;','u32 virt_boundary,max_segments,max_segment_size,max_hw_sectors; int id;void *queuedata;struct gendisk *disk;')
 s=replace(s,'struct gendisk { u64 capacity,diskseq; bool ro; };','struct gendisk { u64 capacity,diskseq; bool ro;void *private_data; };')
 s=replace(s,'bool sgl; int state;','bool sgl; int state;bool passthru_err_log_enabled;')
 s=replace(s,'u8 lba_shift; u32 ns_id;','bool passthru_err_log_enabled;u8 lba_shift; u32 ns_id;')
 # OS functions deferred until all boundary data exists.
 alloc=boundary_func(s,'blk_mq_alloc_request');s=s.replace(alloc,'')
 alloc=replace(alloc,'req.mq_hctx=&hctx;','req.mq_hctx=&hctx;req.q=q;req.pdu.cmd=&req.command;allocated_op=op;')
 execute=boundary_func(s,'blk_execute_rq_nowait');s=s.replace(execute,'')
 execute=replace(execute,"ev('X');posts++;","ev('X');posts++;if(early_complete){r->pdu.status=early_native_status;r->residual=early_residual;r->end_io(r,early_transport);r->cmd_flags=0xdeadbeef;}")
 page=boundary_func(s,'xdev_ext_mech_frame_page');s=s.replace(page,'');page=replace(page,'(void)p;','(void)p;if(page_fault)return NULL;')
 s+='\n#include "boundary_ext.h"\n'+alloc+execute+page
 return s,atom

def requester_dependencies(root,src,bd,inc,out):
 """Actual requester storage/admission; explicit existing provider/PCI facts."""
 utility=runpy.run_path(str(root/REQUESTER_FIXTURE))
 selected=utility['LegacySelection'](root)
 bd=selected.requester_type_projection(bd)
 old_stage=old.declaration(bd,'struct xdev_ext_mech_stage {')
 actual_stage=selected.requester_stage()
 stage_fields=[]
 for field in ('caps','create_reporting','create_phase','create_requester_id','create_requester'):
  fields=re.findall(r'^[ \t]*[^;{}\n]*\b'+field+r'\b[^;{}\n]*;',actual_stage,re.M)
  if len(fields)!=1:raise b.Setup('actual requester stage field count: '+field)
  stage_fields.append(fields[0])
 # Append genuine new storage while preserving every old positional member.
 bd=replace(bd,old_stage,old_stage.rstrip()[:-2]+'\n'+'\n'.join(stage_fields)+'\n};\n')
 binder=selected.definition('io_uring/family/xdev_ext_requester.c','xdev_ext_requester_bind')
 unbinder=selected.definition('io_uring/family/xdev_ext_requester.c','xdev_ext_requester_unbind')
 requester=selected.definition('include/linux/xdev_ext_requester.h','xdev_ext_requester','struct')
 backing=selected.definition('include/linux/xdev_ext_peer.h','xdev_ext_peer_backing','struct')
 project=('#ifndef _LINUX_XDEV_EXT_REQUESTER_H\n#define _LINUX_XDEV_EXT_REQUESTER_H\n'
          '#include <linux/xdev_ext_requester_core.h>\n'
          'struct file; struct pci_dev; struct xdev_ext_mech_stage;\n'+requester+'\n'+backing+'\n')
 project+='\n'.join(body[:body.index('{')].rstrip()+';' for body in (binder,unbinder))+'\n#endif\n'
 (inc/'linux/xdev_ext_requester.h').write_text(project)
 (inc/'linux/xdev_ext_requester_core.h').write_text(src[RC])
 # Reuse already explicit dependency facts, adapting only the original OS
 # device field spelling. The real binder captures authority and decides.
 facts=replace(utility['REQUESTER_DEPENDENCY_FACTS'],'.is_pci=true','.pci=true')
 cap=re.search(r'^#define CAP_SYS_ADMIN[^\n]*',utility['POLL_OS'],re.M)
 if not cap:raise b.Setup('existing requester capability boundary missing')
 facts=cap[0]+'\n'+function(utility['POLL_OS'],'capable')+'\n'+facts
 bd+='\n'+'\n'.join(selected._native_command_declarations())+'\n'+facts
 selected.verify()
 (out/'requester-dependencies.json').write_text(json.dumps({
  'selected':selected.report(),'actual_bodies':['xdev_ext_requester_bind','xdev_ext_requester_unbind','xdev_ext_admit_decide'],
  'external_facts':{'owner':REQUESTER_FIXTURE,'provider_pci':'REQUESTER_DEPENDENCY_FACTS','capability':'POLL_OS.capable'},
  'field_spelling_projection':'.is_pci=true -> .pci=true'},indent=2)+'\n')
 return bd,binder+'\n'+unbinder+'\n',utility['WINDOW_NAMESPACE_FILE']

def namespace_native(source,bd,namespace_file,out):
 """Qualified namespace-file projection; retain every active native body."""
 file_type=old.declaration(bd,'struct file {')
 file_ops=old.declaration(bd,'struct file_operations {')
 if re.search(r'\bprivate_data\b',file_type) or re.search(r'\brelease\b',file_ops):
  raise b.Setup('namespace-file boundary cannot represent window handles')
 start=source.index('struct nvme_xdev_ext_window_handle {')
 end=source.index('static struct nvme_ns *nvme_xdev_ext_class_ns(',start)
 excluded=source[start:end]
 window_names=('nvme_xdev_ext_window_release','nvme_xdev_ext_window_access',
  'nvme_xdev_ext_window_ioctl','nvme_xdev_ext_window_target','nvme_xdev_ext_window_admit')
 for name in window_names:function(excluded,name)
 projected=source[:start]+namespace_file+'\n\n'+source[end:]
 retained=('nvme_xdev_ext_class_ns','nvme_xdev_ext_member_bind',
  'nvme_xdev_ext_member_requester','nvme_xdev_ext_class_bind')
 for name in retained:
  if projected.count(function(source,name))!=1:raise b.Setup('native body projection count: '+name)
 (out/'namespace-file-projection.json').write_text(json.dumps({
  'profile':'opened-namespace-files-only','native_owner':NATIVE,
  'excluded_span':{'offset':start,'length':end-start,'functions':window_names},
  'replacement_owner':REQUESTER_FIXTURE,'replacement':'WINDOW_NAMESPACE_FILE',
  'retained_actual_bodies':retained,
  'case_preparation':'unchanged; required requester state must come from actual CREATE'},indent=2)+'\n')
 return b.no_includes(projected)

def evidence_boundary(header):
 """Actual epoch/evidence constants; the UNKNOWN release records like the
 existing release boundary (an unbound requester proves nothing)."""
 none=re.search(r'^#define XDEV_EXT_PEER_EPOCH_NONE [^\n]*\n',header,re.M)
 enum=re.search(r'^enum xdev_ext_peer_evidence \{.*?^\};\n',header,re.M|re.S)
 if not none or not enum:raise b.Setup('actual peer evidence declarations missing')
 return (none.group(0)+enum.group(0)+'#ifndef max\n#define max(a,b) ((a)>(b)?(a):(b))\n#endif\n'
  'struct xdev_ext_peer_requester;\n'
  'static int xdev_ext_peer_release_unknown(void *vp,u64 ticket,struct xdev_ext_peer_requester *rq,u64 epoch,bool *q)\n'
  '{ (void)rq;(void)epoch;if(q)*q=false;return xdev_ext_peer_release(vp,ticket,false); }\n'
  'static int xdev_ext_peer_requester_evidence(struct xdev_ext_peer_requester *rq,u64 epoch)\n'
  '{ return !rq||epoch==XDEV_EXT_PEER_EPOCH_NONE?XDEV_EXT_PEER_EVIDENCE_NEVER:XDEV_EXT_PEER_EVIDENCE_PENDING; }\n')

def assemble(root,out,config,mutation=None):
 paths=[NATIVE,BLOCK,RUNTIME,REQ,FD,RC,CORE,TRACE,old.NVME,old.MECH,*REQUESTER_SOURCES]
 src={p:(root/p).read_text() for p in paths}
 if mutation:
  m=MUTANTS[mutation];p,sym,a,z,want=m;body=function(src[p],sym);changed=replace(body,a,z)
  if mutation=='host_init_after_slot':changed=replace(changed,'done = &slot->done;','nvme_init_request(req, &cmd);\n\tdone = &slot->done;')
  if mutation=='peer_init_before_map':changed=replace(changed,'slot = nvme_xdev_ext_peer_slot_get(p->peer, bp);','nvme_init_request(req, &cmd);\n\tslot = nvme_xdev_ext_peer_slot_get(p->peer, bp);')
  src[p]=replace(src[p],body,changed)
  if mutation=='bounce_count_after_execute':
   body=function(src[NATIVE],'nvme_xdev_ext_class_submit');src[NATIVE]=replace(src[NATIVE],body,replace(body,'blk_execute_rq_nowait(req, false);','blk_execute_rq_nowait(req, false);\n\tif (bp->bounce) atomic64_inc(&nvme_xdev_ext_mech_bounces);'))
 inc=out.parent/'shared-include';inc.mkdir(exist_ok=True)
 for name,path in b.HEADERS.items():
  f=inc/name;f.parent.mkdir(parents=True,exist_ok=True);
  if not f.exists():f.write_bytes((root/path).read_bytes())
 bd,atom=boundary()
 bd,requester_code,namespace_file=requester_dependencies(root,src,bd,inc,out)
 native=namespace_native(src[NATIVE],bd,namespace_file,out)
 shared=out.parent/'test-inputs';shared.mkdir(exist_ok=True)
 if not (shared/'boundary.h').exists():
  (shared/'boundary.h').write_text(bd);(shared/'boundary_ext.h').write_bytes((HERE/'boundary_ext.h').read_bytes())
 for name in ('boundary.h','boundary_ext.h'):(out/name).symlink_to(pathlib.Path('../test-inputs')/name)
 (inc/'linux/atomic.h').write_text(atom);(inc/'linux/errno.h').write_text('#include <asm-generic/errno.h>\n');(inc/'linux/blk_types.h').write_text('')
 c='#include "boundary.h"\n'
 c+=old.declaration(src[old.MECH],'struct xdev_ext_mech_class_ops {')
 c+=function(src[REQ],'xdev_ext_peer_lease_split')+requester_code+function(src[FD],'xdev_ext_peer_fd_release')
 c+=evidence_boundary(src[PH])+function(src[FD],'xdev_ext_peer_fd_release_unknown')
 c+=b.no_includes(src[TRACE])
 c+=function(src[old.NVME],'nvme_req_op')+function(src[CORE],'nvme_clear_nvme_request')+function(src[CORE],'nvme_init_request')
 if 'nvme_xdev_ext_peer_build_cmd(' in function(src[NATIVE],'nvme_xdev_ext_member_encode_dptr'):
  c+=function(src[CORE],'nvme_xdev_ext_peer_build_cmd')
 c+=b.no_includes(src[RUNTIME])+b.no_includes(src[BLOCK])+function(src[old.NVME],'nvme_xdev_ext_capture_identity')
 c+=native
 original=(GOLDEN/'assertions.c').read_text();remap,inject,reverse=old.transform_assertions(original,True)
 # Only add entry observation for the real native initializer; unchanged old literal event order retained.
 # Old cohort executes separately under its frozen recipe. This harness includes its fixture/functions unchanged.
 remap=replace(remap,'int main(void)', 'int frozen_original_main(void)')

 if not (shared/'assertions.c').exists():
  (shared/'assertions.c').write_text(remap);(shared/'assertions.reverse.c').write_text(reverse);(shared/'assertions_7b.c').write_bytes((HERE/'assertions_7b.c').read_bytes())
 for name in ('assertions.c','assertions.reverse.c','assertions_7b.c'):(out/name).symlink_to(pathlib.Path('../test-inputs')/name)
 c+='\n#include "assertions.c"\n#include "assertions_7b.c"\n'

 (out/'characterization.c').write_text(c)
 return out/'characterization.c',inc

exec((HERE/'mutations.py').read_text())

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source-root',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);ap.add_argument('--mutants',action='store_true');ap.add_argument('--only');ap.add_argument('--common',action='store_true');a=ap.parse_args();root=a.source_root.resolve();out=a.out.resolve();out.mkdir(exist_ok=False)
 sources=sorted(set([NATIVE,BLOCK,RUNTIME,REQ,FD,RC,CORE,TRACE,old.NVME,old.MECH,*REQUESTER_SOURCES,*b.HEADERS.values()]))
 (out/'SOURCE.json').write_text(json.dumps({'source_root':str(root),'files':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in sources}},indent=2)+'\n')
 results=[]
 cases=[('strict','strict',None),('bounce','bounce',None),('disabled','disabled',None)]+([(n,'bounce' if n.startswith('bounce_') else 'strict',n) for n in MUTANTS] if a.mutants else [])
 if a.only:cases=[v for v in cases if v[0]==a.only]
 for name,config,m in cases:
  case=out/name;case.mkdir();row={'name':name,'config':config}
  try:
   c,inc=assemble(root,case,config,m)
   if a.common:
    text=c.read_text();text=replace(text,'#include \"assertions.c\"\n#include \"assertions_7b.c\"','')+'\n#include \"common_gate.c\"\n';c.write_text(text);(case/'common_gate.c').write_bytes((HERE/'common_gate.c').read_bytes())
   cmd=['gcc','-std=gnu11','-O0','-g0','-finstrument-functions','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-parameter','-Werror=implicit-function-declaration','-I'+str(inc),'-I'+str(case),str(c),'-o',str(out/'test-working')]
   if config!='disabled':cmd.insert(1,'-DTEST_'+config.upper())
   cr=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30);(case/'compile.log').write_text(cr.stdout);row.update(compile_exit=cr.returncode,compile_command=cmd)
   if cr.returncode:row['verdict']='SETUP'
   else:
    rr=subprocess.run([str(out/'test-working')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=10);(case/'run.log').write_text(rr.stdout);row.update(run_exit=rr.returncode,output=rr.stdout)
    if m:row.update(expected_assertion=MUTANTS[m][-1],verdict='KILLED' if rr.returncode==1 and 'ASSERTION '+MUTANTS[m][-1]+' ' in rr.stdout else 'SURVIVED' if rr.returncode==0 else 'WRONG_FAILURE')
    else:row['verdict']='PASS' if rr.returncode==0 else 'FAIL'
  except (b.Setup,ValueError,FileNotFoundError) as e:row.update(verdict='SETUP',error=str(e))
  results.append(row);print(row['verdict'],name,row.get('output',row.get('error',''))[-250:],flush=True)
 if (out/'test-working').exists():(out/'test-working').unlink()
 report={'results':results,'scope':'host actual function/header boundary only; no native kernel/DMA/performance','verdict':'PASS' if all(r['verdict'] in ('PASS','KILLED') for r in results) else 'NOT_READY'}
 (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');return int(report['verdict']!='PASS')
if __name__=='__main__':sys.exit(main())

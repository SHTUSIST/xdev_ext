#!/usr/bin/env python3
"""Independent 7B host boundary. Production algorithms remain complete actual definitions."""
import argparse,hashlib,importlib.util,json,pathlib,subprocess,sys,re
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent
GOLDEN=HERE.parent/'native_member_7a'
sp=importlib.util.spec_from_file_location('old',GOLDEN/'run_candidate.py');old=importlib.util.module_from_spec(sp);sp.loader.exec_module(old)
b=old.base
NATIVE,BLOCK,RUNTIME=old.NATIVE,old.BLOCK,old.RUNTIME
REQ='src/core/io_uring/family/xdev_ext_requester.c'
FD='src/core/io_uring/xdev_ext_peer_fd.c'
RC='src/core/include/linux/xdev_ext_requester_core.h'
CORE='src/storage/drivers/nvme/host/core.c'
TRACE='src/storage/drivers/nvme/host/xdev_ext_native_peer_trace.h'

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

def assemble(root,out,config,mutation=None):
 paths=[NATIVE,BLOCK,RUNTIME,REQ,FD,RC,CORE,TRACE,old.NVME,old.MECH]
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
 bd,atom=boundary();shared=out.parent/'test-inputs';shared.mkdir(exist_ok=True)
 if not (shared/'boundary.h').exists():
  (shared/'boundary.h').write_text(bd);(shared/'boundary_ext.h').write_bytes((HERE/'boundary_ext.h').read_bytes())
 for name in ('boundary.h','boundary_ext.h'):(out/name).symlink_to(pathlib.Path('../test-inputs')/name)
 (inc/'linux/atomic.h').write_text(atom);(inc/'linux/errno.h').write_text('#include <asm-generic/errno.h>\n');(inc/'linux/blk_types.h').write_text('')
 c='#include "boundary.h"\n'
 c+=old.declaration(src[old.MECH],'struct xdev_ext_mech_class_ops {')
 c+=function(src[RC],'xdev_ext_lease_shrink')+function(src[REQ],'xdev_ext_peer_lease_split')+function(src[FD],'xdev_ext_peer_fd_release')
 c+=b.no_includes(src[TRACE])
 c+=function(src[old.NVME],'nvme_req_op')+function(src[CORE],'nvme_clear_nvme_request')+function(src[CORE],'nvme_init_request')
 c+=b.no_includes(src[RUNTIME])+b.no_includes(src[BLOCK])+function(src[old.NVME],'nvme_xdev_ext_capture_identity')
 c+=b.no_includes(src[NATIVE])
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
 sources=sorted(set([NATIVE,BLOCK,RUNTIME,REQ,FD,RC,CORE,TRACE,old.NVME,old.MECH,*b.HEADERS.values()]))
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

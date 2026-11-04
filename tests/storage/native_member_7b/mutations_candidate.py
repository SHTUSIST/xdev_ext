#!/usr/bin/env python3
import pathlib,sys,json,subprocess,argparse
sys.dont_write_bytecode=True
import adapter as a
m=a.m;H=a.H
# Each row preserves the old mutation name and designated assertion. Only owner/signature anchors change.
D={}
def add(name,sym,before,after,want=None,suite='extended',config=None):
 D[name]=dict(symbol=sym,before=before,after=after,expected=want or m.MUTANTS[name][-1],suite=suite,config=config or ('bounce' if name.startswith('bounce_') else 'strict'))
add('host_post_return_request_touch','xdev_ext_storfam_submit','ss->dev->post(ss->member, req, io, b, &sb->command, peer);\n\treturn 0;','ss->dev->post(ss->member, req, io, b, &sb->command, peer);\n\treturn req->cmd_flags == 0xdeadbeef ? -EIO : 0;')
add('host_wrong_DRV_op','xdev_ext_storfam_submit','sb->posting.write ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN','sb->posting.write ? REQ_OP_WRITE : REQ_OP_READ')
add('host_init_after_slot','xdev_ext_storfam_submit','if (!peer)\n\t\tss->dev->request_init(ss->member, req, &sb->command, false);','/* relocated below slot */')
add('peer_init_before_map','xdev_ext_storfam_submit','ss->dev->request_init(ss->member, req, &sb->command, true);','/* relocated before slot */')
add('host_cdw12_upper_lost','nvme_xdev_ext_member_encode','(nvme_xdev_ext_sqe_dw(admitted_sqe, 12) & 0xffff0000U) |','0 |')
add('host_bounce_wrong_errno','xdev_ext_storfam_host_map','if (ret != -EREMOTEIO)','if (false)')
for name in ['host_owned_bio_check_lost','host_native_status_lost','host_cancelled_lost','done_wrong_ticket','done_claim_skip','done_stale_classifies','peer_error_known']:
 _,sym,b,z,w=m.MUTANTS[name];add(name,sym,b.replace('bp->bio','bp->family.bio'),z)
add('host_UNKNOWN_slot_returned','xdev_ext_storfam_host_put','if (!slot || slot->done.uncertain)','if (!slot)')
add('host_ZOMBIE_slot_returned','xdev_ext_storfam_consume','if (xdev_ext_mech_session_state(ss->st->s) != XDEV_EXT_MECH_SESSION_ZOMBIE)\n\t\t\txdev_ext_storfam_host_put(ss, sb);','if (true)\n\t\t\txdev_ext_storfam_host_put(ss, sb);')
add('peer_frame_order_reversed','xdev_ext_storfam_peer_map','xdev_ext_mech_batch_frame(b, pos, &f)','xdev_ext_mech_batch_frame(b, nr - 1 - pos, &f)')
add('peer_lease_count_after_validation','xdev_ext_storfam_peer_map','io->nr_leases++;','if (l->lease.len) io->nr_leases++;')
add('peer_capacity_extra_acquire','xdev_ext_storfam_peer_map','if (io->nr_leases == ss->peer->max_pieces)','if (io->nr_leases > ss->peer->max_pieces)')
add('peer_SGL_PDU_flag_lost','nvme_xdev_ext_member_request_init','nvme_req(req)->cmd->common.flags |= NVME_CMD_SGL_METABUF;','nvme_req(req)->cmd->common.flags |= 0;')
add('peer_PRP_wrong_page','nvme_xdev_ext_member_encode_dptr','cmd->rw.dptr.prp1 = cpu_to_le64(prp1);','cmd->rw.dptr.prp1 = cpu_to_le64(prp1 + 4096);')
add('peer_drift_before_provider','xdev_ext_storfam_submit','ret = xdev_ext_storfam_peer_map(ss, b, io, sb->posting.byte_length);','ret = sb->rw.nlb != sb->posting.nlb ? -EPROTO : xdev_ext_storfam_peer_map(ss, b, io, sb->posting.byte_length);')
add('peer_UNKNOWN_slot_returned','xdev_ext_storfam_peer_put','if (!quiesced)','if (false)')
add('peer_ZOMBIE_retired','xdev_ext_storfam_consume','if (xdev_ext_mech_session_state(ss->st->s) != XDEV_EXT_MECH_SESSION_ZOMBIE)\n\t\t\txdev_ext_storfam_peer_put(ss, sb);','if (true)\n\t\t\txdev_ext_storfam_peer_put(ss, sb);')
add('peer_release_order_reversed','xdev_ext_storfam_peer_put','&io->leases[i], quiesced','&io->leases[io->nr_leases - 1 - i], quiesced')
add('peer_preaccept_unquiesced','xdev_ext_storfam_peer_put','quiesced = !io->done.uncertain;','quiesced = ((struct nvme_xdev_ext_peer_trace *)io->peer_native)->cookie && !io->done.uncertain;')
add('bounce_copyback_lost','xdev_ext_storfam_host_ready','if (!status && !uncertain && sb->bounce &&','if (false && !status && !uncertain && sb->bounce &&')
add('bounce_count_preallocated','nvme_xdev_ext_member_post','if (sb->bounce) {','if (io->bounce) {')
add('bounce_count_after_execute','nvme_xdev_ext_member_post','atomic64_inc(&nvme_xdev_ext_mech_bounces);','/* relocated after execute */')
add('old_native_gate_unused_common','xdev_ext_storfam_submit_check','return ss->dev->identity(ss->member, true, &ss->geometry);','return nvme_xdev_ext_member_identity(ss->member, true, &ss->geometry);','candidate_class_submit_consumes_identity_hook','golden')
add('queue_alloc_hook_skip','xdev_ext_storfam_submit','blk_mq_alloc_request(ss->dev->queue(ss->member),','blk_mq_alloc_request(nvme_xdev_ext_member_queue(ss->member),','candidate_class_alloc_consumes_queue_hook','golden')
add('peer_view_omit','xdev_ext_storfam_poll','ARRAY_SIZE(ss->poll_views)','1','class_poll_positive_only_sum2','golden')
# New common ownership/API consumers, specified by CONTRACT2-7, use frozen common literals.
add('common_HOST_view_wrong_stride','xdev_ext_storfam_host_resources_init','.stride = sizeof(*p->slots),','.stride = sizeof(*p->slots) + 8,','common_HOST_view_stride_io','common')
add('common_PEER_view_wrong_stride','xdev_ext_storfam_peer_resources_init','.stride = ss->dev->peer_slot_bytes,','.stride = sizeof(struct xdev_ext_stor_io),','common_PEER_view_native_stride','common')
add('common_busy_unbind_ignored','xdev_ext_storfam_unbind','return xdev_ext_storfam_peer_resources_free(ss) &&\n\t       xdev_ext_storfam_host_resources_free(ss);','return true;','common_unbind_busy_false','common')
add('common_encode_callback_bypassed','xdev_ext_storfam_submit','ss->dev->encode(ss->member, &sb->rw, sb->sqe,','nvme_xdev_ext_member_encode(ss->member, &sb->rw, sb->sqe,','common_class_consumes_encode','common')
add('common_init_callback_bypassed','xdev_ext_storfam_submit','ss->dev->request_init(ss->member, req, &sb->command, false);','nvme_xdev_ext_member_request_init(ss->member, req, &sb->command, false);','common_post_same_command','common')
add('common_post_callback_bypassed','xdev_ext_storfam_submit','ss->dev->post(ss->member, req, io, b, &sb->command, peer);','nvme_xdev_ext_member_post(ss->member, req, io, b, &sb->command, peer);','common_class_consumes_post','common')
add('common_dptr_callback_bypassed','xdev_ext_storfam_submit','ss->dev->encode_dptr(ss->member, &sb->command,','nvme_xdev_ext_member_encode_dptr(ss->member, &sb->command,','common_consumes_DPTR','common')
add('common_DPTR_capacity_wrong','xdev_ext_storfam_submit','XDEV_EXT_STOR_PEER_MAX_SPANS, io->list_cpu,','256, io->list_cpu,','common_DP_control_capacity512','common')
add('common_DPTR_list_bytes_wrong','xdev_ext_storfam_submit','io->list_dma, SZ_4K);','io->list_dma, 2048);','common_DP_list_bytes4096','common')
add('common_retire_callback_bypassed','xdev_ext_storfam_peer_put','ss->dev->retire_peer(ss->member, io, quiesced);','nvme_xdev_ext_member_retire_peer(ss->member, io, quiesced);','common_consume_native_retire_once','common')
add('common_retire_before_handles','xdev_ext_storfam_peer_put','for (i = 0; i < io->nr_leases; i++)','ss->dev->retire_peer(ss->member, io, quiesced);\n\tfor (i = 0; i < io->nr_leases; i++)','common_retire_after_fd_handle','common')
add('extra_encode_NSID_rebuilt','xdev_ext_storfam_submit','if (ret)\n\t\treturn ret;\n\treq = blk_mq_alloc_request', 'if (ret)\n\t\treturn ret;\n\tsb->command.bytes[4] = 7;\n\treq = blk_mq_alloc_request','extra_custom_NSID13_SLBA103_full_PDU64','extra')
add('extra_encode_SLBA_rebuilt','xdev_ext_storfam_submit','if (ret)\n\t\treturn ret;\n\treq = blk_mq_alloc_request', 'if (ret)\n\t\treturn ret;\n\tsb->command.bytes[40] = 100;\n\treq = blk_mq_alloc_request','extra_custom_NSID13_SLBA103_full_PDU64','extra')
add('extra_coherent_list_rebuilt','xdev_ext_storfam_submit','ss->dev->request_init(ss->member, req, &sb->command, true);','((u8 *)io->list_cpu)[2] = 0x10;\n\t\tss->dev->request_init(ss->member, req, &sb->command, true);','extra_custom_coherent_list32','extra')
# Preserve the remaining original 7A mutant semantics on actual 7B owners.
# The first 45 recipes above remain unchanged; golden literals are reused intact.
def old_add(name,symbol,before,after):
 add(name,symbol,before,after,m.old.MUTANTS[name][-1],'golden')
old_add('identity_hook_skip','xdev_ext_storfam_submit_check','return ss->dev->identity(ss->member, true, &ss->geometry);','return 0;')
old_add('dead_gate_skip','xdev_ext_storfam_submit_check','if (atomic_read(&ss->dead))','if (false && atomic_read(&ss->dead))')
old_add('validated_gate_skip','xdev_ext_storfam_submit_check','!sb->validated || sb->batch_id != xdev_ext_mech_batch_id(batch)','false')
old_add('native_common_gate_bypass','xdev_ext_storfam_submit','ret = xdev_ext_storfam_submit_check(ss, b, sb);','ret = ss->dev->identity(ss->member, true, &ss->geometry);')
old_add('queue_map_hook_skip','xdev_ext_storfam_host_map','xdev_ext_stor_block_caps(p->dev->queue(p->member),','xdev_ext_stor_block_caps(nvme_xdev_ext_member_queue(p->member),')
old_add('decode_hook_skip','xdev_ext_storfam_validate','ss->dev->decode(ss->member, batch, scratch, &ss->window,','nvme_xdev_ext_member_decode(ss->member, batch, scratch, &ss->window,')
old_add('poll_hook_skip','xdev_ext_storfam_poll','ss->dev->poll(ss->member, ss->poll_views,','nvme_xdev_ext_member_poll(ss->member, ss->poll_views,')
old_add('host_view_omit','xdev_ext_storfam_poll','ss->dev->poll(ss->member, ss->poll_views,\n\t\t\t     ARRAY_SIZE(ss->poll_views))','ss->dev->poll(ss->member, ss->poll_views + 1, 1)')
old_add('native_poll_queue_skip','nvme_xdev_ext_member_poll','xdev_ext_stor_block_poll(p->family.dev->queue(member), views, nr_views)','xdev_ext_stor_block_poll(p->ns->queue, views, nr_views)')
# Generic mutation-specific adapter helpers call native functions defined later in this complete TU.
FORWARD=('nvme_xdev_ext_member_queue','nvme_xdev_ext_member_encode','nvme_xdev_ext_member_encode_dptr','nvme_xdev_ext_member_request_init','nvme_xdev_ext_member_post','nvme_xdev_ext_member_retire_peer','nvme_xdev_ext_member_identity','nvme_xdev_ext_member_decode','nvme_xdev_ext_member_poll')
def change(text,name,d):
 body=m.function(text,d['symbol']);changed=m.replace(body,d['before'],d['after'])
 if name=='host_init_after_slot':changed=m.replace(changed,'if (peer) {\n\t\tret = xdev_ext_storfam_peer_map', 'if (!peer) ss->dev->request_init(ss->member, req, &sb->command, false);\n\tif (peer) {\n\t\tret = xdev_ext_storfam_peer_map')
 if name=='peer_init_before_map':changed=m.replace(changed,'io = peer ? xdev_ext_storfam_peer_get(ss, sb) :','if (peer) ss->dev->request_init(ss->member, req, &sb->command, true);\n\tio = peer ? xdev_ext_storfam_peer_get(ss, sb) :')
 if name=='bounce_count_after_execute':changed=m.replace(changed,'blk_execute_rq_nowait(req, false);','blk_execute_rq_nowait(req, false);\n\tif (!peer && sb->bounce) atomic64_inc(&nvme_xdev_ext_mech_bounces);')
 if name=='common_retire_before_handles':changed=m.replace(changed,'xdev_ext_peer_fd_release(&io->leases[i], quiesced);\n\tss->dev->retire_peer(ss->member, io, quiesced);','xdev_ext_peer_fd_release(&io->leases[i], quiesced);')
 result=m.replace(text,body,changed)
 # Declarations only, not implementation replacements.
 declarations=''
 for sym in FORWARD:
  f=m.function(text,sym);declarations+=f[:f.index('{')].strip()+';\n'
 pos=result.index('/* CREATE adds exactly one node')
 return result[:pos]+declarations+result[pos:]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source-root',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);ap.add_argument('--only');v=ap.parse_args();v.out.mkdir(exist_ok=False);before=a.snapshot(v.source_root);(v.out/'SOURCE.json').write_text(json.dumps(before,indent=2)+'\n');rows=[]
 for name,d in D.items():
  if v.only and name!=v.only:continue
  case=v.out/name;case.mkdir();row=dict(name=name,expected_assertion=d['expected'],recipe=d)
  try:
   c,inc=a.assemble(v.source_root,case,d['config']);text=c.read_text()
   if d['suite'] in ('common','extra'):text=m.replace(text,'#include "assertions.c"\n#include "assertions_7b.c"','')+'\n#include "common_gate.c"\n';(case/'common_gate.c').write_bytes((H/'common_gate.c').read_bytes())
   if d['suite']=='extra':
    text=text.replace('#include "common_gate.c"','#define main frozen_common_main\n#include "common_gate.c"\n#undef main\n#include "extra_common.c"');(case/'extra_common.c').write_text((a.A/'extra_common.c').read_text().replace('frozen_common_main();unsigned before=common_checks;','unsigned before=common_checks;'))
   if d['suite']=='golden':
    text=m.replace(text,'#include "assertions_7b.c"','\n#include "candidate.c.in"');(case/'candidate.c.in').write_text(a.transform((m.GOLDEN/'candidate.c.in').read_text(),'golden/candidate.c.in'));(case/'candidate_adapter.h').write_bytes((m.GOLDEN/'candidate_adapter.h').read_bytes())
    text=m.replace(text,'#include "assertions.c"','''static void __attribute__((no_instrument_function)) observe_entry(void *fn){if(fn==(void *)nvme_init_request){events[event_count++]='I';events[event_count]=0;}}
static void __attribute__((no_instrument_function)) observe_exit(void *fn){if(fn==(void *)nvme_init_request)last_command=req.command;}
static void __attribute__((constructor,no_instrument_function)) enable_observer(void){adapter_enter=observe_entry;adapter_exit=observe_exit;}
#include "assertions.c"''')
   c.write_text(change(text,name,d));cmd=['gcc','-DTEST_'+d['config'].upper(),'-std=gnu11','-O0','-g0','-finstrument-functions','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-parameter','-Werror=implicit-function-declaration','-I'+str(inc),'-I'+str(case),str(c),'-o',str(v.out/'working')]
   cr=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);(case/'compile.log').write_text(cr.stdout);row.update(compile_exit=cr.returncode,compile_command=cmd)
   if cr.returncode:row['verdict']='SETUP'
   else:
    rr=subprocess.run([str(v.out/'working')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=10);(case/'run.log').write_text(rr.stdout);row.update(run_exit=rr.returncode,output=rr.stdout,verdict='KILLED' if rr.returncode==1 and 'ASSERTION '+d['expected']+' ' in rr.stdout else 'WRONG_FAILURE')
  except Exception as e:row.update(verdict='SETUP',error=str(e))
  rows.append(row);print(row['verdict'],name,row.get('output',row.get('error','')),flush=True)
 if (v.out/'working').exists():(v.out/'working').unlink()
 (v.out/'RESULT.json').write_text(json.dumps(dict(results=rows),indent=2)+'\n')
 after=a.snapshot(v.source_root);(v.out/'SOURCE-AFTER.json').write_text(json.dumps(after,indent=2)+'\n');print('SOURCE_INPUTS_STABLE',before==after,flush=True)
 return int(before!=after or any(r['verdict']!='KILLED' for r in rows))
if __name__=='__main__':sys.exit(main())

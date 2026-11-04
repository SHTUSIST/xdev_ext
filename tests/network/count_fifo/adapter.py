"""Only verbatim production extraction and OS-boundary instrumentation."""
import importlib.util,json,hashlib,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
FIXTURE=Path(__file__).resolve().parent.parent/'pool_dma'
# Literal old implementation from the preproducer old-source capture.
# This supplies only the deliberate detached-consumer mutation, never baseline.
DETACHED_OLD_PEEK = 'static inline int xsk_mech_zc_peek(struct xsk_mech_zc_ring *r,\n\t\t\t\t struct xsk_mech_zc_slot *s)\n{\n\t__u32 at;\n\n\tif (r->fatal || r->issued == r->prod)\n\t\treturn -ENOENT;\n\tat = r->issued++ & (r->capacity - 1);\n\ts[at].state = XSK_MECH_ZC_NATIVE;\n\ts[at].native_prev = r->native_count ? r->native_tail : XSK_MECH_ZC_NONE;\n\ts[at].native_next = XSK_MECH_ZC_NONE;\n\tif (r->native_count)\n\t\ts[r->native_tail].native_next = at;\n\telse\n\t\tr->native_head = at;\n\tr->native_tail = at;\n\tr->native_count++;\n\treturn at;\n}'
spec=importlib.util.spec_from_file_location('frozen_pool_adapter',FIXTURE/'adapter.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
SetupError=old.SetupError
OLD_MUTANTS={'cpu_derived_dma':'sync_span','data_only_sync':'sync_span','callback_under_lock':'callback_outside_lock','accepted_eagain_retry':'accepted_eagain_terminal','fifo_head_is_cons':'fifo_head_not_cons','accessor_outside_lock':'mapping_lock','compacted_frame_index':'BOUNDARY_ASSERT partial_sent: checksum_before_sync','checksum_before_prepare':'prefix_no_checksum','rollback_prod_missing':'prefix_prod_restore','unknown_lease_clear':'unknown_full_bytes','set_only_early_release':'set_only_lease'}
NEW_MUTANTS={
 'disconnected_public_consumer':('DISCONNECTED','','','xsk_xdev_ext_mech_tx_peek not wired to family peek'),
 'family_peek_no_membership':('xdev_ext_net_count_peek','r->native_count++;','(void)r;','native_fifo'),
 'family_unlink_resets_cons':('xdev_ext_net_count_mark_done','r->native_count--;','r->native_count--; r->cons = r->issued;','done_hole'),
 'family_tail_by_cons':('xdev_ext_net_count_tail','__u32 at = r->native_tail;','__u32 at = r->cons & (r->capacity - 1);','done_hole'),
 'family_overwrite_fatal':('xdev_ext_net_count_fail','result && !r->fatal','result','first_error_retained'),
 'family_retry_eagain':('xdev_ext_net_count_retire_result','result = -EIO;','result = -EAGAIN;','accepted_eagain_terminal'),
 'family_wrong_stride':('xdev_ext_net_count_entry','(size_t)at * v.stride','(size_t)at * sizeof(struct xdev_ext_net_count_entry)','native_fifo'),
 'family_rollback_issued':('xdev_ext_net_count_rollback','r->prod = start;','r->prod = start; r->issued = start;','rollback_issued_unchanged'),
 'set_only_retires':('xsk_xdev_ext_mech_tx_complete','if (!set_only)','if (true)','set_only_retains'),
 'stage_dead_under_lock':('xsk_xdev_ext_mech_tx_complete','spin_unlock_irqrestore(&p->tx_lock, flags);\n\t/* mark_dead','if (fatal && failed_stage) xdev_ext_mech_stage_dead(failed_stage, fatal);\n spin_unlock_irqrestore(&p->tx_lock, flags);\n\t/* mark_dead','stage_dead_outside_lock'),
 'control_unknown_cleared':('actual_xsk_rel_native_done','tb->completion.uncertain','false','control_custody'),
 'stop_first_pass_removed':('xsk_mech_zc_stop','FIRST_PASS','REMOVE','excess_quarantine'),
 'reliable_wrong_tag':('xsk_rel_enqueue','tb->control ? XSK_MECH_ZC_CONTROL : XSK_MECH_ZC_DATA','XSK_MECH_ZC_DATA','reliable_control_tag'),
}
def freeze_inputs(root):
 root=Path(root)
 paths=['src/network/net/xdp/xsk_xdev_ext_mech_zc_core.h','src/network/net/xdp/xsk_xdev_ext_mech.c','src/network/net/xdp/xsk_xdev_ext_mech_reliable.inc','src/network/include/linux/xdev_ext_netfam.h','src/network/io_uring/family/xdev_ext_netfam.c','src/network/net/xdp/xsk.c','src/network/net/xdp/xsk_buff_pool.c','src/network/include/net/xsk_buff_pool.h','src/core/io_uring/xdev_ext_mech.c','src/core/include/linux/xdev_ext_mech.h','src/network/net/xdp/xsk_xdev_ext_mech_tx_core.h','src/core/include/linux/xdev_ext_peer.h','src/core/io_uring/xdev_ext_mech_core.h','src/core/include/linux/xdev_ext_mech_reliable_core.h','src/core/include/uapi/linux/xdev_ext_mech.h','src/network/net/xdp/xsk_xdev_ext_mech_core.h']
 family='src/network/include/linux/xdev_ext_netfam_count.h'
 if (root/family).is_file():paths.append(family)
 return {'production_inputs':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths},'original_fixtures':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in FIXTURE.iterdir() if p.is_file()}}
def structure(root,overrides=None):
 root=Path(root);problems=[];overrides=overrides or {}
 def read(path):return overrides.get(path,(root/path).read_text())
 hp=root/'src/network/include/linux/xdev_ext_netfam_count.h'
 if not hp.exists(): problems.append('COUNT_FIFO shared family ownership absent')
 else:
  h=hp.read_text()
  for f in ['entry','fail','reserve','rollback','peek','set_result','mark_done','native','head','tail','reclaim','pending_end','stop_end','retire_result']:
   try:old.function(h,'xdev_ext_net_count_'+f)
   except SetupError:problems.append('family transition body missing: '+f)
 mech=read('src/network/net/xdp/xsk_xdev_ext_mech.c');rel=read('src/network/net/xdp/xsk_xdev_ext_mech_reliable.inc');zc=read('src/network/net/xdp/xsk_xdev_ext_mech_zc_core.h')
 edges={'xsk_xdev_ext_mech_tx_peek':['peek'],'xsk_xdev_ext_mech_tx_batch':['peek'],'xsk_xdev_ext_mech_tx_complete':['native','head','tail','set_result','reclaim'],'xsk_mech_zc_retire':['mark_done','retire_result'],'xsk_mech_zc_cancel_pending':['pending_end'],'xsk_mech_zc_stop':['fail','stop_end'],'xsk_xdev_ext_mech_zc_submit':['reserve','rollback']}
 for n,fs in edges.items():
  f=old.function(mech,n)
  for s in fs:
   if not re.search(r'\bxdev_ext_net_count_'+s+r'\s*\(',f):problems.append(n+' not wired to family '+s)
 if 'struct xdev_ext_net_count_ring' not in old.record(mech,'xsk_xdev_ext_mech_provider'):problems.append('provider ring does not declare family ownership')
 if 'struct xdev_ext_net_count_batch' not in old.record(mech,'xsk_xdev_ext_mech_tx_batch'):problems.append('batch countdown does not declare family ownership')
 if '.count' not in old.function(mech,'xsk_xdev_ext_mech_zc_submit'):problems.append('ordinary DATA shared metadata not published')
 f=old.function(rel,'xsk_rel_enqueue')
 if 'xdev_ext_net_count_reserve(' not in f or '.count' not in f:problems.append('reliable/control shared enqueue metadata not wired')
 for n in ['fail','reserve','peek','set_result','mark_done','native','tail','complete','reclaim','retire_result']:
  f=old.function(zc,'xsk_mech_zc_'+n)
  if re.search(r'\b(if|while|for)\s*\(',f) or 'xdev_ext_net_count_' not in f:problems.append('legacy '+n+' retains independent algorithm')
 return {'verdict':'OWNERSHIP_WIRING_RED' if problems else 'PASS','assertions':problems}
def generate(root,out,mutation=None):
 root=Path(root);out=Path(out)
 family_exists=(root/'src/network/include/linux/xdev_ext_netfam_count.h').exists()
 have,manifest=old.generate(root,out,mutation if mutation in OLD_MUTANTS and not family_exists else None)
 h=root/'src/network/include/linux/xdev_ext_netfam_count.h'
 if h.exists():
  s='\n'.join(l for l in h.read_text().splitlines() if not l.lstrip().startswith('#include'))
  j=out/'production_journal.h';j.write_text(s+'\n'+j.read_text())
 rel=(root/'src/network/net/xdp/xsk_xdev_ext_mech_reliable.inc').read_text()
 enqueue=old.function(rel,'xsk_rel_enqueue');manifest.append({'path':'src/network/net/xdp/xsk_xdev_ext_mech_reliable.inc','function':'xsk_rel_enqueue','bytes':len(enqueue)})
 p=out/'production.c.inc'
 reliable_core=(root/'src/core/include/linux/xdev_ext_mech_reliable_core.h').read_text()
 # Whole portable production protocol header; no protocol replacement.
 records=old.record(rel,'xsk_rel_data')+'\n'+old.record(rel,'xsk_rel_control')
 boundary='''
struct xsk_mech_reliable {struct xdev_ext_rel_tx tx;struct xsk_rel_data data[XDEV_EXT_REL_MAX_WINDOW];bool initial_unchecked;struct xdp_desc scratch[XDEV_EXT_REL_MAX_SEGMENTS];};
static u64 rel_now=100;static int native_refs,frame_moves,stage_kicks,build_calls;static u64 build_group;static u32 build_attempt;
static u64 ktime_get_ns(void){return rel_now;}
static u64 xdev_ext_mech_batch_key(struct xdev_ext_mech_batch*b){return b->id;}
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch*b){u32 n=0;for(u32 i=0;i<b->nr_frames;i++)n+=b->f[i].data_len;return n;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch*b){return b->nr_frames;}
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage*s){(void)s;REQUIRE("kick_outside_lock",!lock_depth);stage_kicks++;}
static void xdev_ext_mech_stage_native_put(struct xdev_ext_mech_stage*s){(void)s;REQUIRE("native_put_outside_lock",!lock_depth);native_refs--;}
#define XDEV_EXT_MECH_F_INFLIGHT 3
#define XDEV_EXT_MECH_F_HELD 2
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool*p,u32 i,int from,int to){(void)p;(void)i;REQUIRE("control_return_lock",lock_depth==1);REQUIRE("control_move",from==3&&to==2);frame_moves++;return 0;}
#define WARN_ON_ONCE(c) REQUIRE("production_warning",!(c))
/* BPF envelope builder boundary: presealed descriptor fixtures, no journal. */
static int xsk_rel_build(struct xdev_ext_mech_stage*s,struct xdev_ext_mech_batch*b,struct xsk_rel_control*c,u64 group,u32 attempt,u64 credit){(void)s;(void)b;(void)c;(void)credit;REQUIRE("build_outside_lock",!lock_depth);build_calls++;build_group=group;build_attempt=attempt;return 0;}
'''
 extra=[enqueue,old.function(rel,'xsk_rel_wakeup'),old.function(rel,'xsk_rel_submit'),old.function(rel,'xsk_rel_native_done').replace('xsk_rel_native_done(', 'actual_xsk_rel_native_done(',1),old.function(rel,'xsk_rel_resend')]
 for n in ['xsk_rel_wakeup','xsk_rel_submit','xsk_rel_native_done','xsk_rel_resend']:manifest.append({'path':'src/network/net/xdp/xsk_xdev_ext_mech_reliable.inc','function':n,'bytes':len(old.function(rel,n))})
 admit=(root/'src/network/net/xdp/xsk_xdev_ext_mech_core.h').read_text()
 core_rules=(root/'src/core/io_uring/xdev_ext_mech_core.h').read_text()
 uapi=(root/'src/core/include/uapi/linux/xdev_ext_mech.h').read_text()
 admit_code=old.record(uapi,'xdev_ext_mech_layout')+'\n'+old.record(admit,'xsk_xdev_ext_mech_sock_facts')+'\n'+old.function(core_rules,'xdev_ext_mech_layout_frames')+'\n'+old.function(admit,'xsk_xdev_ext_mech_pool_admit')
 p.write_text(p.read_text()+'\n'+reliable_core+'\n'+records+'\n'+boundary+'\n'+'\n'.join(extra)+'\n'+admit_code)
 if family_exists and mutation in OLD_MUTANTS:
  j=out/'production_journal.h';text=p.read_text();journal=j.read_text()
  def change(name,transform,in_header=False):
   nonlocal text,journal
   src=journal if in_header else text;before=old.function(src,name);after=transform(before)
   if before==after:raise SetupError('candidate preserved mutation anchor unavailable: '+mutation)
   if in_header:journal=src.replace(before,after,1)
   else:text=src.replace(before,after,1)
  if mutation=='accepted_eagain_retry':change('xdev_ext_net_count_retire_result',lambda f:re.sub(r'result\s*=\s*-EIO;', 'result = -EAGAIN;',f,count=1),True)
  elif mutation=='fifo_head_is_cons':change('xdev_ext_net_count_head',lambda f:f.replace('(int)r->native_head','(int)(r->cons & (r->capacity - 1))'),True)
  elif mutation=='data_only_sync':
   anchor='dma_sync_single_for_device(pool->dev, dma, size, DMA_BIDIRECTIONAL);'
   if anchor not in text:raise SetupError('candidate sync anchor missing')
   text=text.replace(anchor,'dma_sync_single_for_device(pool->dev, dma + 42, size - 42, DMA_BIDIRECTIONAL);',1)
  elif mutation=='cpu_derived_dma':text=text.replace('actual_xp_raw_get_dma(p,a);','(dma_addr_t)(uintptr_t)p->addrs + a;',1)
  elif mutation=='callback_under_lock':change('xsk_xdev_ext_mech_tx_complete',lambda f:f.replace('spin_unlock_irqrestore(&p->tx_lock, flags);\n\t/* mark_dead','xsk_mech_zc_done(&done);\n\tspin_unlock_irqrestore(&p->tx_lock, flags);\n\t/* mark_dead',1))
  elif mutation=='accessor_outside_lock':
   n='xsk_mech_pool_dma_sync_locked';before=old.function(text,n);renamed=before.replace(n+'(', 'actual_'+n+'(',1)
   wrapper='static void '+n+'(struct xsk_xdev_ext_mech_provider *p,const struct xdev_ext_net_lease *lease) {unsigned long flags=0; spin_unlock_irqrestore(&p->tx_lock,flags); actual_'+n+'(p,lease); spin_lock_irqsave(&p->tx_lock,flags);}'
   text=text.replace(before,renamed+'\n'+wrapper,1)
  elif mutation=='compacted_frame_index':change('xsk_xdev_ext_mech_zc_submit',lambda f:re.sub(r'(xdev_ext_net_lease_pool\([^,]+,\s*b,\s*)i,',r'\1(i == 2 && *xst->tx_tag[1] == xdev_ext_mech_batch_id(b) ? 1 : i),',f,count=1))
  elif mutation=='checksum_before_prepare':change('xsk_xdev_ext_mech_zc_submit',lambda f:re.sub(r'(err = xdev_ext_net_count_reserve\(&p->ring, nr, &start\);\s*if \(err\)\s*goto unlock;)',r'\1\n xsk_xdev_ext_mech_tx_finish(xst->tx_pkt[0]);',f,count=1))
  elif mutation=='rollback_prod_missing':change('xsk_xdev_ext_mech_zc_submit',lambda f:re.sub(r'xdev_ext_net_count_rollback\(&p->ring,\s*start\);','(void)start;',f,count=1))
  elif mutation=='unknown_lease_clear':change('xdev_ext_net_lease_pool_release',lambda f:f.replace('{','{\nquiesced=true;',1))
  elif mutation=='set_only_early_release':change('xsk_xdev_ext_mech_tx_complete',lambda f:f.replace('tb = slot->batch;', 'tb = slot->batch;\n xdev_ext_net_lease_pool_release(&tb->pool_lease[slot->slot],true);',1))
  p.write_text(text);j.write_text(journal)
 if mutation=='disconnected_public_consumer':
  if not family_exists:raise SetupError('new-family consumer disconnection unavailable')
  duplicate=DETACHED_OLD_PEEK.replace('xsk_mech_zc_peek(', 'detached_count_peek(',1)
  text=p.read_text();mechpath='src/network/net/xdp/xsk_xdev_ext_mech.c';source=(root/mechpath).read_text()
  for n in ['xsk_xdev_ext_mech_tx_peek','xsk_xdev_ext_mech_tx_batch']:
   before=old.function(text,n);after=re.sub(r'xdev_ext_net_count_peek\s*\(\s*&p->ring\s*,\s*xsk_mech_zc_view\s*\(\s*p->slots\s*\)\s*\)','detached_count_peek(&p->ring,p->slots)',before)
   if before==after:raise SetupError('direct public peek anchor unavailable')
   text=text.replace(before,after,1);source=source.replace(old.function(source,n),after,1)
  p.write_text(duplicate+'\n'+text);out.joinpath('mutation_structural.json').write_text(json.dumps(structure(root,{mechpath:source}),indent=2)+'\n')
 if mutation in NEW_MUTANTS and mutation!='disconnected_public_consumer':
  name,anchor,replacement,_=NEW_MUTANTS[mutation]
  target=out/'production_journal.h' if name.startswith('xdev_ext_net_count_') else p
  text=target.read_text()
  try:f=old.function(text,name)
  except SetupError:raise SetupError('new-family mutation unavailable: '+mutation)
  if mutation=='stop_first_pass_removed':
   m=re.search(r'\bfor\s*\(',f)
   if not m:raise SetupError('stop first-pass loop missing')
   brace=f.index('{',m.start());after=f[:m.start()]+f[old.balanced(f,brace):]
  else:
   if anchor not in f:raise SetupError('mutation anchor unavailable: '+mutation)
   after=f.replace(anchor,replacement) if mutation=='control_unknown_cleared' else f.replace(anchor,replacement,1)
  target.write_text(text.replace(f,after,1))
 return have,manifest

#!/usr/bin/env python3
"""Behavioral mutations of the already generated real-source baseline TU."""
import argparse,pathlib,subprocess,json,re,hashlib
p=argparse.ArgumentParser();p.add_argument('--baseline',required=True);p.add_argument('--out',required=True);p.add_argument('--mode',choices=['baseline','shared'],default='baseline');a=p.parse_args();B=pathlib.Path(a.baseline);O=pathlib.Path(a.out);O.mkdir(parents=True,exist_ok=True)
s=(B/'cohort.c').read_text();prefix,cases=s.split('#line 1 "independent-cases.c"',1)
# Exact executable branch/effect changes; absent anchors never count as kills.
M=[
('group_free_before_removal','if (empty)\n\t\tlist_del(&group->node);','/* remove omitted, group remains discoverable */',2),
('ce_live_consumer_bypass','return xdev_ext_ce_lease_get(cs, b);','return 0;',1),
('dma_live_consumer_bypass','return xdev_ext_dma_lease_get(cs, b);','return 0;',1),
('zero_generation_admitted','if (!generation)\n\t\treturn -EINVAL;','if (false)\n\t\treturn -EINVAL;',1),
('generation_is_ignored','return slot->generation == generation ? 0 : -EBUSY;','return 0;',1),
('serial_admitted','if (state->serial_batches && state->active_batches)','if (false)',1),
('overflow_wrap','if (state->active_batches == ~(__u32)0)','if (false)',1),
('quarantine_not_retained','if (state->quarantined)\n\t\treturn -EBUSY;','if (false)\n\t\treturn -EBUSY;',2),
('stale_finish_releases','if (slot->generation != generation)','if (false)',1),
('inactive_finish_quarantines','if (!slot->active)\n\t\treturn 0;','if (!slot->active) { state->quarantined = true; return 0; }',1),
('ce_serial_predicate_omitted','found->state.serial_batches = true;','found->state.serial_batches = false;',2),
('ce_native_ticket_generation','xdev_ext_mech_batch_id(b), conflict);','xdev_ext_mech_batch_ticket(b), conflict);',2),
('ce_initial_hold_omitted','cs->cleanup_held = true;\n\tfound->cleanup_holds++;','cs->cleanup_held = false;',1),
('ce_cleanup_skipped_own_active','if (!other->cleanup_holds &&\n\t\t    (group->state.active_batches || !other->state.active_batches))','if (group->state.active_batches || !other->state.active_batches)',1),
('ce_scan_past_first_hit','goto checked;','continue;',2),
('ce_own_hold_ignored','else if (group->cleanup_holds)','else if (false)',1),
('dma_own_hold_ignored','if (group->cleanup_holds) {','if (false) {',1),
('dma_duplicate_hold','if (cs->cleanup_held != hold) {','if (true) {',1),
('dma_scope_put_omitted','xdev_ext_dma_scope_put(cs->scope);','/* deliberately omitted external scope put */',1),
('ce_nonatomic_hold_detach','if (cs->lease_group && !xdev_ext_ce_lease_unbind(cs))','if (cs->lease_group) xdev_ext_ce_lease_bind_ready(cs);\n\tif (cs->lease_group && !xdev_ext_ce_lease_unbind(cs))',1),
('dma_clearhold_omitted','xdev_ext_dma_lease_cleanup(cs, false);','/* deliberately preserve stale hold */',1),
('ce_region_group_left_dangling','cs->lease_group = NULL;','/* dangling CE group */',2),
('ce_free_under_lock','mutex_unlock(&xdev_ext_ce_lease_lock);\n\tif (empty)\n\t\tkvfree(group);','if (empty) kvfree(group);\n\tmutex_unlock(&xdev_ext_ce_lease_lock);',1),
('dma_free_under_lock','mutex_unlock(&xdev_ext_dma_lease_lock);\n\tif (empty)\n\t\tkvfree(group);','if (empty) kvfree(group);\n\tmutex_unlock(&xdev_ext_dma_lease_lock);',1),
('scope_provider_namespace_merged','if (a->provider != b->provider)\n\t\treturn false;','if (false)\n\t\treturn false;',1),
]
# Candidate recipes keep every original semantic name, now scoped to real functions.
# A selective fault may identify a real policy only inside the mutation build;
# no such branch is added to production or to the frozen assertions.
SHARED=[
 ('group_free_before_removal','xdev_ext_comp_copy_lease_unbind','if (empty)\n\t\tlist_del(&group->node);','/* deliberately leave group discoverable */',1),
 ('ce_live_consumer_bypass','xdev_ext_ce_copy_lease_get','return xdev_ext_comp_copy_lease_get(&cs->lease,\n\t\txdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b));','return 0;',1),
 ('dma_live_consumer_bypass','xdev_ext_dma_copy_lease_get','return xdev_ext_comp_copy_lease_get(&cs->lease,\n\t\txdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b));','return 0;',1),
 ('zero_generation_admitted','xdev_ext_ce_lease_acquire','if (!generation)\n\t\treturn -EINVAL;','if (false)\n\t\treturn -EINVAL;',1),
 ('generation_is_ignored','xdev_ext_ce_lease_acquire','return slot->generation == generation ? 0 : -EBUSY;','return 0;',1),
 ('serial_admitted','xdev_ext_ce_lease_acquire','if (state->serial_batches && state->active_batches)','if (false)',1),
 ('overflow_wrap','xdev_ext_ce_lease_acquire','if (state->active_batches == ~(__u32)0)','if (false)',1),
 ('quarantine_not_retained','xdev_ext_ce_lease_finish','if (state->quarantined)\n\t\treturn -EBUSY;','if (false)\n\t\treturn -EBUSY;',1),
 ('stale_finish_releases','xdev_ext_ce_lease_finish','if (slot->generation != generation)','if (false)',1),
 ('inactive_finish_quarantines','xdev_ext_ce_lease_finish','if (!slot->active)\n\t\treturn 0;','if (!slot->active) { state->quarantined = true; return 0; }',1),
 ('ce_serial_predicate_omitted','xdev_ext_ce_lease_key_serial','return left->window_start != right->window_start &&\n\t\txdev_ext_ce_lease_key_overlap(a, b);','return false;',1),
 ('ce_native_ticket_generation','xdev_ext_ce_copy_lease_get','return xdev_ext_comp_copy_lease_get(&cs->lease,\n\t\txdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b));','return xdev_ext_comp_copy_lease_get(&cs->lease,\n\t\txdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_ticket(b));',1),
 ('ce_initial_hold_omitted','xdev_ext_ce_lease_bind','cs, true);','cs, false);',1),
 ('ce_cleanup_skipped_own_active','xdev_ext_comp_copy_lease_get_mode','if (!other->cleanup_holds &&\n\t\t    (group->state.active_batches || !other->state.active_batches))','if (group->state.active_batches || !other->state.active_batches)',1),
 ('ce_scan_past_first_hit','xdev_ext_comp_copy_lease_get_mode','goto checked;','continue;',1),
 ('ce_own_hold_ignored','xdev_ext_comp_copy_lease_get_mode','else if (group->cleanup_holds)','else if (group->cleanup_holds && domain->policy != &xdev_ext_ce_lease_policy)',1),
 ('dma_own_hold_ignored','xdev_ext_comp_copy_lease_get_mode','else if (group->cleanup_holds)','else if (group->cleanup_holds && domain->policy != &xdev_ext_dma_lease_policy)',1),
 ('dma_duplicate_hold','xdev_ext_comp_copy_lease_hold','if (region->cleanup_held != hold) {','if (region->cleanup_held != hold || domain->policy == &xdev_ext_dma_lease_policy) {',1),
 ('dma_scope_put_omitted','xdev_ext_dma_copy_unbind_end','xdev_ext_dma_scope_put(cs->scope);','/* deliberately omitted external scope put */',1),
 ('ce_nonatomic_hold_detach','xdev_ext_ce_copy_unbind_end','if (cs->lease.group &&','if (cs->lease.group) xdev_ext_comp_copy_lease_hold(&cs->lease, false);\n\tif (cs->lease.group &&',1),
 ('dma_clearhold_omitted','xdev_ext_dma_copy_unbind_end','xdev_ext_comp_copy_lease_hold(&cs->lease, false);','/* deliberately preserve stale hold */',1),
 ('ce_region_group_left_dangling','xdev_ext_comp_copy_lease_unbind','region->group = NULL;','/* deliberately leave dangling region group */',1),
 ('ce_free_under_lock','xdev_ext_comp_copy_lease_unbind','mutex_unlock(&domain->lock);\n\tif (empty)\n\t\tkvfree(group);','if (empty && domain->policy == &xdev_ext_ce_lease_policy) kvfree(group);\n\tmutex_unlock(&domain->lock);\n\tif (empty && domain->policy != &xdev_ext_ce_lease_policy) kvfree(group);',1),
 ('dma_free_under_lock','xdev_ext_comp_copy_lease_unbind','mutex_unlock(&domain->lock);\n\tif (empty)\n\t\tkvfree(group);','if (empty && domain->policy == &xdev_ext_dma_lease_policy) kvfree(group);\n\tmutex_unlock(&domain->lock);\n\tif (empty && domain->policy != &xdev_ext_dma_lease_policy) kvfree(group);',1),
 ('scope_provider_namespace_merged','xdev_ext_dma_scope_overlap','if (a->provider != b->provider)\n\t\treturn false;','if (false)\n\t\treturn false;',1),
 # Additional actual common authority/domain/policy and composition sensitivities.
 ('domains_merged','xdev_ext_dma_bind','&xdev_ext_dma_lease_domain','&xdev_ext_ce_lease_domain',1),
 ('ce_retained_private_lock','xdev_ext_ce_copy_lease_get','return xdev_ext_comp_copy_lease_get(&cs->lease,\n\t\txdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b));','mutex_lock(&xdev_ext_ce_lease_domain.lock); mutex_unlock(&xdev_ext_ce_lease_domain.lock);\n\treturn xdev_ext_comp_copy_lease_get(&cs->lease,\n\t\txdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b));',1),
 ('dma_retained_private_lock','xdev_ext_dma_copy_lease_get','return xdev_ext_comp_copy_lease_get','mutex_lock(&xdev_ext_dma_lease_domain.lock); mutex_unlock(&xdev_ext_dma_lease_domain.lock);\n\treturn xdev_ext_comp_copy_lease_get',1),
 ('ce_policy_allocates','xdev_ext_ce_lease_key_serial','return left->window_start','(void)kvzalloc(8, GFP_KERNEL);\n\treturn left->window_start',1),
 ('dma_policy_puts_module','xdev_ext_dma_lease_key_serial','return xdev_ext_dma_scope_serial(a, b);','module_put(NULL);\n\treturn xdev_ext_dma_scope_serial(a, b);',1),
 ('ce_policy_retains_transition','xdev_ext_ce_lease_key_serial','return left->window_start','struct xdev_ext_ce_lease_state hidden = {0}; struct xdev_ext_ce_lease_slot slot = {0};\n\t(void)xdev_ext_ce_lease_acquire(&hidden, &slot, 1, false);\n\treturn left->window_start',1),
 ('dma_busy_hold_normalized','xdev_ext_dma_copy_unbind_begin','if (cs->lease.group && xdev_ext_comp_copy_lease_busy(&cs->lease))\n\t\treturn -EBUSY;\n\t/* Retain configured exclusion throughout either native unmap. */\n\txdev_ext_comp_copy_lease_hold(&cs->lease, true);\n\treturn 0;','return xdev_ext_comp_copy_lease_cleanup_begin(&cs->lease);',1),
 ('dma_clearhold_detach_normalized','xdev_ext_dma_copy_unbind_end','xdev_ext_comp_copy_lease_hold(&cs->lease, false);\n\tif (cs->lease.group &&\n\t    WARN_ON_ONCE(!xdev_ext_comp_copy_lease_unbind(&cs->lease, false)))','if (cs->lease.group &&\n\t    WARN_ON_ONCE(!xdev_ext_comp_copy_lease_unbind(&cs->lease, true)))',1),
]

# These two original pure-helper faults now have an equivalent rejection in
# the actual common entry before the same helper. Mutate both occurrences of
# that identity rule, retaining all unrelated mode/hold/range/terminal guards.
# Every auxiliary body and local condition must still be uniquely identified.
SHARED_IDENTITY_GUARDS={
 'zero_generation_admitted':('xdev_ext_comp_copy_lease_get_mode',
  'else if (!batch_id)\n\t\tret = -EINVAL;',
  'else if (false)\n\t\tret = -EINVAL;'),
 'generation_is_ignored':('xdev_ext_comp_copy_lease_get_mode',
  'if (owner->active && owner->generation != batch_id) {',
  'if (false) {'),
}

def function_span(text,name):
 pattern=r'^(?:static\s+)?(?:inline\s+)?(?:int|void|bool)\s+'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{'
 hits=list(re.finditer(pattern,text,re.M))
 if len(hits)!=1:raise ValueError('function definitions='+str(len(hits)))
 m=hits[0];depth=0
 # Strip comments/strings while retaining offsets; braces in prose are not code.
 clean=re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda q:' '*(q.end()-q.start()),text,flags=re.S)
 for i in range(m.end()-1,len(text)):
  if clean[i]=='{':depth+=1
  elif clean[i]=='}':
   depth-=1
   if depth==0:return m.start(),i+1
 raise ValueError('unclosed function')

cmd=json.loads((B/'command.json').read_text());rows=[]
recipes=SHARED if a.mode=='shared' else [(name,None,old,new,want) for name,old,new,want in M]
for name,fn,old,new,want in recipes:
 d=O/name;d.mkdir(exist_ok=True);row={'name':name,'mode':a.mode,'function':fn,'expected_anchors':want}
 try:
  lo,hi=function_span(prefix,fn) if fn else (0,len(prefix))
 except ValueError as e:
  row.update(verdict='SETUP_FUNCTION',diagnostic=str(e));rows.append(row);print(name,row['verdict'],row['diagnostic']);continue
 body=prefix[lo:hi];count=body.count(old);row['anchors']=count;row['function_sha256']=hashlib.sha256(body.encode()).hexdigest()
 if count!=want:row['verdict']='SETUP_ANCHOR';rows.append(row);print(name,row['verdict'],'anchors',count,'want',want);continue
 replacements=-1 if a.mode=='baseline' and name=='quarantine_not_retained' else 1
 changed_body=body.replace(old,new,replacements)
 # Domain-selective test faults need a forward declaration because common TU
 # precedes adapters. These are mutation-only private C declarations.
 declarations=''
 for policy in ('xdev_ext_ce_lease_policy','xdev_ext_dma_lease_policy'):
  if policy in new and fn and fn.startswith('xdev_ext_comp_copy_lease_'):
   declarations+='static const struct xdev_ext_comp_copy_lease_policy '+policy+';\n'
 changed=prefix[:lo]+declarations+changed_body+prefix[hi:]
 if a.mode=='shared' and name in SHARED_IDENTITY_GUARDS:
  auxiliary,guard,replacement=SHARED_IDENTITY_GUARDS[name]
  try:
   alo,ahi=function_span(changed,auxiliary)
  except ValueError as e:
   row.update(verdict='SETUP_FUNCTION',diagnostic=str(e));rows.append(row);print(name,row['verdict'],row['diagnostic']);continue
  owner=changed[alo:ahi];anchors=owner.count(guard)
  row.update(auxiliary_function=auxiliary,auxiliary_anchors=anchors,
   auxiliary_expected_anchors=1,auxiliary_function_sha256=hashlib.sha256(owner.encode()).hexdigest())
  if anchors!=1:
   row.update(verdict='SETUP_ANCHOR',diagnostic='same-identity guard count='+str(anchors));rows.append(row);print(name,row['verdict'],row['diagnostic']);continue
  changed=changed[:alo]+owner.replace(guard,replacement,1)+changed[ahi:]
 # Preserve the original quarantine recipe's two guard changes exactly.
 if a.mode=='shared' and name=='quarantine_not_retained':
  qlo,qhi=function_span(changed,'xdev_ext_ce_lease_acquire')
  acquire=changed[qlo:qhi];qcount=acquire.count(old)
  row['auxiliary_function']='xdev_ext_ce_lease_acquire';row['auxiliary_anchors']=qcount
  if qcount!=1:
   row.update(verdict='SETUP_ANCHOR',diagnostic='quarantine acquire guard count='+str(qcount));rows.append(row);print(name,row['verdict']);continue
  changed=changed[:qlo]+acquire.replace(old,new,1)+changed[qhi:]
 src=d/'mutant.c';src.write_text(changed+'#line 1 "independent-cases.c"'+cases)
 mc=cmd.copy();mc[mc.index(str(B/'cohort.c'))]=str(src);mc[-1]=str(d/'mutant');(d/'command.json').write_text(json.dumps(mc)+'\n')
 r=subprocess.run(mc,text=True,capture_output=True);(d/'compile.log').write_text(r.stdout+r.stderr);row['compile_exit']=r.returncode
 if r.returncode:row['verdict']='SETUP_COMPILER'
 else:
  try:r=subprocess.run([str(d/'mutant')],capture_output=True,text=True,timeout=10)
  except subprocess.TimeoutExpired as e:
   row.update(verdict='RUNTIME_TIMEOUT',run_exit=None,diagnostic='runtime exceeded10seconds');rows.append(row);print(name,row['verdict']);continue
  (d/'run.log').write_text(r.stdout+r.stderr);row['run_exit']=r.returncode;row['diagnostic']=(r.stdout+r.stderr).strip();row['verdict']='ASSERT_KILL' if r.returncode==70 and 'ASSERT ' in r.stderr else 'SURVIVED_OR_OTHER'
  if 'ASSERT policy callback retained lease/ref/native authority' in r.stderr:
   row['assertion_expression']='predicate_depth && forbidden function entry (allocation/list/transition/ref/lock)'
  elif 'ASSERT ' in r.stderr:
   match=re.search(r'ASSERT (.*)',r.stderr);row['assertion_expression']=match.group(1)
 rows.append(row);print(name,row['verdict'],row.get('diagnostic',''))
(O/'results.json').write_text(json.dumps(rows,indent=2)+'\n');print('compiled_assert_kills',sum(r['verdict']=='ASSERT_KILL' for r in rows),'of',len(rows));raise SystemExit(0 if all(r['verdict']=='ASSERT_KILL' for r in rows) else 1)

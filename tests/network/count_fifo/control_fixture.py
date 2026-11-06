"""Counted, scoped, reversible typed CONTROL fixture migration.

The immutable raw source and unmodified four DATA transforms are the only inputs.
No production/extractor import, output construction, compiler or producer call.
"""
import re
from typed_fixture import (migrate as migrate_v1, invert as invert_v1,
                           FixtureContractError, _sha, _replace_scoped)

CONTRACT = 'typed-control-v2'
TRANSFORM_VERSION = 'count-typed-control-v2'

# Each entry owns one exact old source span; global includes/calls are counted
# separately and are reversed with the same occurrence/identity obligations.
TRANSFORMS = (
 ('C00-reset', 'good_reset',
  b' reset(n); observed_rel=NULL;',
  b' reset(n); v2_mixed_ordinary=v2_mixed_reliable=false; observed_rel=NULL;'),
 ('C00-facts', 'good_reset',
  b' struct xdev_ext_mech_layout l={.frame_size=4096,.hdr_room=64,.seg_len=16,.group_bytes=48};',
  b' v2_reset_facts();\n struct xdev_ext_mech_layout l = {.frame_size=4096,.hdr_room=64,.seg_len=16,.group_bytes=48};'),
 ('C01-C02', 'reliable_enqueue_cases',
  b'  good_reset(control?"control_enqueue":"reliable_enqueue");struct xdp_desc d[32];\n',
  b'  good_reset(control?"control_enqueue":"reliable_enqueue");\n  struct xdp_desc d[32];\n  if(control){v2_control_enqueue_case(count);continue;}\n'),
 ('C03-C05', 'reliable_real_callers',
  b'''  good_reset(unknown?"actual_control_unknown":"actual_control_definite");memset(&rel,0,sizeof(rel));xst.rel=&rel;observed_provider=NULL;
  struct xsk_rel_control c={0};c.tb.control=true;c.frame=(struct xdev_ext_mech_frame){.index=0,.umem_addr=0,.data_off=128,.data_len=16};c.busy=true;observed_control=&c;
  struct xdp_desc d={22,106,0};native_refs=1;frame_moves=0;unsigned long flags;
  spin_lock_irqsave(&p.tx_lock,flags);CHECK("control_actual_enqueue",!xsk_rel_enqueue(&st,&c.tb,&d,1));spin_unlock_irqrestore(&p.tx_lock,flags);
  CHECK("control_public_peek",xsk_tx_peek_release_desc_batch(&xp,64)==1);
  if(unknown)xsk_mech_zc_stop(&p,-ENXIO);else if(phase==2)xsk_tx_cancel_tail(&xp,1,-EIO);else xsk_tx_completed(&xp,1);
  CHECK("control_custody",c.uncertain==unknown&&c.busy==unknown&&native_refs==unknown&&frame_moves==!unknown&&p.ring.native_count==0&&c.tb.completion.pending==0);CHECK("control_mapped_return",sync_cpu_n==(phase==0));snapshot("control_done");
  xsk_mech_zc_stop(&p,-ENXIO);CHECK("control_no_double_put",native_refs==unknown&&frame_moves==!unknown);
''',
  b'''  good_reset(unknown?"actual_control_unknown":"actual_control_definite");v2_prepare_rel(&rel,3);xst.rel=&rel;observed_provider=NULL;
  v2_reserve_control(&rel,0);v2_reserve_control(&rel,1);struct xsk_rel_control *c=&rel.control[0];observed_control=c;
  struct xdp_desc d=v2_control_desc(0);v2_hold_ref(0);frame_moves=0;
  v2_hidden_id=phase==0?"C03/control_done":phase==1?"C04/control_done":"C05/control_done";
  CHECK("control_actual_enqueue",!v2_enqueue(&c->tb,&d,1));v2_metadata(c,0);
  CHECK("reliable_control_tag",p.slots[0].owner==XSK_MECH_ZC_CONTROL);
  CHECK("control_public_peek",v2_public_peek(64)==1);
  if(unknown)v2_stop(-ENXIO);else if(phase==2)v2_public_cancel(1,-EIO);else v2_public_complete(1);
  CHECK("control_custody",c->uncertain==unknown&&c->busy==unknown&&native_refs==unknown&&frame_moves==!unknown&&p.ring.native_count==0&&c->tb.completion.pending==0);
  CHECK("control_custody",pool.state[63]==(unknown?XDEV_EXT_MECH_F_INFLIGHT:XDEV_EXT_MECH_F_HELD)&&c->tb.pool_lease[0].kind==(unknown?XDEV_EXT_NET_LEASE_POOL_DMA:XDEV_EXT_NET_LEASE_NONE));
  CHECK("control_mapped_return",sync_cpu_n==(phase==0));snapshot("control_done");
  xsk_mech_zc_stop(&p,-ENXIO);CHECK("control_no_double_put",native_refs==unknown&&frame_moves==!unknown);
'''),
 ('C06-input', 'public_wrap_mixed',
  b''' good_reset("public_three_native_plus_pending");CHECK("submit",!xsk_xdev_ext_mech_submit(&st,&batch));
 struct xsk_xdev_ext_mech_tx_batch other={0};struct xdp_desc d={22,58,0};other.control=true;observed_provider=NULL;unsigned long flags;
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("shared_control_enqueue",!xsk_rel_enqueue(&st,&other,&d,1));spin_unlock_irqrestore(&p.tx_lock,flags);
''',
  b''' good_reset("public_three_native_plus_pending");struct xsk_mech_reliable r;
 v2_mixed_input(&r,false);CHECK("ordinary_dispatch",!xst.rel);CHECK("submit",!xsk_xdev_ext_mech_submit(&st,&batch));v2_mixed_bytes(false);
 xst.rel=&r;v2_reserve_control(&r,0);v2_reserve_control(&r,1);struct xsk_xdev_ext_mech_tx_batch *other=&r.control[0].tb;
 struct xdp_desc d=v2_control_desc(0);observed_provider=NULL;observed_control=&r.control[0];v2_hold_ref(0);unsigned long flags;
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("shared_control_enqueue",!xsk_rel_enqueue(&st,other,&d,1));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("reliable_control_tag",p.slots[3].owner==XSK_MECH_ZC_CONTROL);
'''),
 ('C06-countdown', 'public_wrap_mixed',
  b'callbacks==1&&other.completion.pending==1',
  b'callbacks==1&&other->completion.pending==1'),
 ('C06-terminal', 'public_wrap_mixed',
  b'CHECK("pending_control_done",reliable_done_count==1&&p.ring.cons==4);',
  b'CHECK("pending_control_done",!native_refs&&!r.control[0].busy&&pool.state[63]==XDEV_EXT_MECH_F_HELD&&!reliable_done_count&&p.ring.cons==4);'),
 ('C07', 'public_wrap_mixed',
  b''' good_reset("public_physical_wrap_interleave");observed_provider=NULL;p.ring.prod=p.ring.issued=p.ring.cons=62;
 struct xsk_xdev_ext_mech_tx_batch a={.batch=&batch},b={.control=true};struct xdp_desc pair[2]={{22,58,0},{4118,58,0}};
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("wrap_a",!xsk_rel_enqueue(&st,&a,pair,2));CHECK("wrap_b",!xsk_rel_enqueue(&st,&b,pair,2));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("wrap_peek3",xsk_tx_peek_release_desc_batch(&xp,3)==3&&p.ring.native_head==62&&p.ring.native_tail==0&&p.slots[63].native_next==0);snapshot("wrapped3");
 xsk_tx_cancel_tail(&xp,1,0);CHECK("wrap_tail_hole",p.slots[0].state==2&&p.ring.cons==62);xsk_tx_completed(&xp,2);
 CHECK("wrap_reclaim",p.ring.cons==65&&a.completion.pending==0&&b.completion.pending==1);snapshot("across_hole");
 CHECK("wrap_last",xsk_tx_peek_release_desc_batch(&xp,1)==1);xsk_tx_completed(&xp,1);CHECK("wrap_b_done",p.ring.cons==66&&reliable_done_count==2);snapshot("done");
''',
  b''' good_reset("public_physical_wrap_interleave");observed_provider=NULL;p.ring.prod=p.ring.issued=p.ring.cons=62;
 v2_mixed_input(&r,true);v2_reserve_control(&r,0);v2_reserve_control(&r,1);
 struct xsk_xdev_ext_mech_tx_batch a={.batch=&batch,.ticket=91};batch.priv=&a;
 struct xdp_desc reliable_pair[2]={{22,122,0},{4118,122,0}},c0=v2_control_desc(0),c1=v2_control_desc(1);
 r.data[1].batch=&batch;r.data[1].ticket=91;r.data[1].count=2;memcpy(r.data[1].desc,reliable_pair,sizeof(reliable_pair));
 v2_hold_ref(0);v2_hold_ref(1);observed_control=&r.control[1];
 spin_lock_irqsave(&p.tx_lock,flags);
 CHECK("wrap_protocol_open",xdev_ext_rel_tx_open(&r.tx,77,32,2)==XDEV_EXT_REL_SEND);
 CHECK("wrap_a",!xsk_rel_enqueue(&st,&a,reliable_pair,2));
 CHECK("wrap_native_begin",xdev_ext_rel_tx_native_begin(&r.tx,77,100)==XDEV_EXT_REL_SEND);a.attempt=r.tx.entry[1].attempt;
 CHECK("wrap_b",!xsk_rel_enqueue(&st,&r.control[0].tb,&c0,1)&&!xsk_rel_enqueue(&st,&r.control[1].tb,&c1,1));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("reliable_control_tag",p.slots[0].owner==XSK_MECH_ZC_CONTROL&&p.slots[1].owner==XSK_MECH_ZC_CONTROL);
 CHECK("wrap_peek3",v2_public_peek(3)==3&&p.ring.native_head==62&&p.ring.native_tail==0&&p.slots[63].native_next==0);snapshot("wrapped3");
 v2_public_cancel(1,0);CHECK("wrap_tail_hole",p.slots[0].state==2&&p.ring.cons==62);v2_public_complete(2);
 CHECK("wrap_reclaim",p.ring.cons==65&&!a.completion.pending&&!r.control[0].tb.completion.pending&&r.control[1].tb.completion.pending==1&&native_refs==1&&!r.control[0].busy&&r.control[1].busy);
 CHECK("wrap_protocol_done",!r.tx.entry[1].native_pending&&r.tx.entry[1].deadline_ns==110&&r.tx.entry[1].attempt==1&&r.tx.entry[1].live&&!r.tx.entry[1].terminal&&!r.tx.entry[1].acked&&!r.tx.retransmits);snapshot("across_hole");
 CHECK("wrap_last",v2_public_peek(1)==1);v2_public_complete(1);CHECK("wrap_b_done",p.ring.cons==66&&!native_refs&&!r.control[1].busy&&!reliable_done_count);snapshot("done");
 /* Retain the old U32 DATA vector independently of the C07 reliable pair. */
 struct xdp_desc pair[2]={{22,58,0},{4118,58,0}};
'''),
 ('C08', 'public_wrap_mixed',
  b''' good_reset("public_mixed_batches_stop");CHECK("mixed_batches_submit",!xsk_xdev_ext_mech_submit(&st,&batch));observed_provider=NULL;other=(struct xsk_xdev_ext_mech_tx_batch){.control=true};
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("mixed_batches_control",!xsk_rel_enqueue(&st,&other,&d,1));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("mixed_batches_peek",xsk_tx_peek_release_desc_batch(&xp,3)==3);xsk_tx_cancel_tail(&xp,1,0);snapshot("before_stop");xsk_mech_zc_stop(&p,-ENXIO);
 CHECK("mixed_batches_unknown",seq_callbacks==1&&callbacks==1&&reliable_done_count==1&&tb.completion.uncertain&&!other.completion.uncertain&&tb.pool_lease[0].kind==3&&tb.pool_lease[1].kind==3&&tb.pool_lease[2].kind==0&&p.ring.native_count==0&&p.ring.cons==4&&sync_cpu_n==1);snapshot("stopped");
''',
  b''' good_reset("public_mixed_batches_stop");v2_mixed_input(&r,false);CHECK("ordinary_dispatch",!xst.rel);CHECK("mixed_batches_submit",!xsk_xdev_ext_mech_submit(&st,&batch));v2_mixed_bytes(false);
 xst.rel=&r;v2_reserve_control(&r,0);v2_reserve_control(&r,1);other=&r.control[0].tb;d=v2_control_desc(0);observed_provider=NULL;observed_control=&r.control[0];v2_hold_ref(0);
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("mixed_batches_control",!xsk_rel_enqueue(&st,other,&d,1));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("reliable_control_tag",p.slots[3].owner==XSK_MECH_ZC_CONTROL);
 CHECK("mixed_batches_peek",v2_public_peek(3)==3);v2_public_cancel(1,0);snapshot("before_stop");v2_stop(-ENXIO);
 CHECK("mixed_batches_unknown",seq_callbacks==1&&callbacks==1&&!reliable_done_count&&tb.completion.uncertain&&!other->completion.uncertain&&tb.pool_lease[0].kind==3&&tb.pool_lease[1].kind==3&&tb.pool_lease[2].kind==0&&p.ring.native_count==0&&p.ring.cons==4&&sync_cpu_n==1);
 CHECK("mixed_pending_control_dead",dead_status==-ENXIO&&!other->cancelled_before_native&&!native_refs&&!r.control[0].busy&&pool.state[63]==XDEV_EXT_MECH_F_HELD&&!other->pool_lease[0].kind);snapshot("stopped");
'''),
 ('C06-observe-peek', 'public_wrap_mixed',
  b'CHECK("three_native_pending",xsk_tx_peek_release_desc_batch(&xp,3)',
  b'CHECK("three_native_pending",v2_public_peek(3)'),
 ('C06-observe-tail', 'public_wrap_mixed',
  b' xsk_tx_cancel_tail(&xp,1,0);CHECK("three_tail_hole",',
  b' v2_public_cancel(1,0);CHECK("three_tail_hole",'),
 ('C06-observe-head', 'public_wrap_mixed',
  b' xsk_tx_completed(&xp,2);CHECK("three_head_cross_hole",',
  b' v2_public_complete(2);CHECK("three_head_cross_hole",'),
 ('C06-observe-control', 'public_wrap_mixed',
  b'CHECK("pending_control_peek",xsk_tx_peek_release_desc_batch(&xp,1)==1);xsk_tx_completed(&xp,1);',
  b'CHECK("pending_control_peek",v2_public_peek(1)==1);v2_public_complete(1);'),
)

GLOBAL = (
 ('G1-prototype', b'static void good_reset(const char *n)\n', b'static void v2_reset_facts(void);\nstatic void good_reset(const char *n)\n'),
 ('G2-support', b'static unsigned long long hash_bytes(const void *,size_t);\n', b'static unsigned long long hash_bytes(const void *,size_t);\n#include "control_support.h"\n'),
 ('G3-cases', b'int main(int argc,char **argv)\n', b'#include "test_control_v2.c"\nint main(int argc,char **argv)\n'),
 ('G4-call', b' printf("COUNT_RESULT failures=%d\\n",failures);', b' control_v2_cases();\n printf("COUNT_RESULT failures=%d\\n",failures);'),
 ('G5-observe', b' for(int i=0;i<sync_dev_n;i++)printf("DMA %d addr=%llu len=%zu epoch=%d\\n",i,(unsigned long long)sync_addr[i],sync_len[i],sync_epoch[i]);\n', b' for(int i=0;i<sync_dev_n;i++)printf("DMA %d addr=%llu len=%zu epoch=%d\\n",i,(unsigned long long)sync_addr[i],sync_len[i],sync_epoch[i]);\n v2_snapshot_semantic(event);\n'),
 ('G6-open', b' fail_fast=getenv("COUNT_FAIL_FAST")!=NULL;', b' v2_semantic_open();\n fail_fast=getenv("COUNT_FAIL_FAST")!=NULL;'),
 ('G7-close', b' control_v2_cases();\n printf("COUNT_RESULT', b' control_v2_cases();v2_semantic_close();\n printf("COUNT_RESULT'),
)


def _global(source, entry, reverse=False):
    name, before, after = entry
    if reverse:
        before, after = after, before
    if source.count(before) != 1:
        raise FixtureContractError(name + ': expected exactly one full source anchor')
    offset = source.index(before)
    changed = source[:offset] + after + source[offset + len(before):]
    return changed, {
        'id': name, 'offset': offset, 'before': before.decode('ascii'),
        'after': after.decode('ascii'), 'before_count': 1,
        'after_count': source.count(after),
        'result_before_count': changed.count(before),
        'result_after_count': changed.count(after),
    }


def _apply(source, reverse=False):
    records = []
    entries = list(reversed(TRANSFORMS)) if reverse else TRANSFORMS
    for name, function, before, after in entries:
        if reverse:
            before, after = after, before
        if function == 'good_reset':
            # The immutable v1 scope helper accepts only `(void)`. This new
            # scope has a parameter; keep v1 untouched and delimit its exact
            # signature using the same comment/string-aware brace rule.
            signature = b'static void good_reset(const char *n)\n{'
            if source.count(signature) != 1:
                raise FixtureContractError(name + ': unique good_reset scope required')
            start = source.index(signature)
            brace = start + len(signature) - 1
            token = re.compile(rb'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
            depth = 0
            end = None
            for match in token.finditer(source, brace):
                if match.group() == b'{':
                    depth += 1
                elif match.group() == b'}':
                    depth -= 1
                    if depth == 0:
                        end = match.end()
                        break
            if end is None:
                raise FixtureContractError(name + ': unbalanced good_reset scope')
            body = source[start:end]
            if body.count(before) != 1 or body.count(after):
                raise FixtureContractError(name + ': exact scoped occurrence mismatch')
            changed = body.replace(before, after, 1)
            if changed.count(before) or changed.count(after) != 1:
                raise FixtureContractError(name + ': replacement occurrence mismatch')
            record = {'id': name, 'function': function, 'scope_start': start,
                      'scope_end': end, 'offset': start + body.index(before),
                      'before': before.decode('ascii'), 'after': after.decode('ascii'),
                      'before_count': 1, 'after_count': 0,
                      'result_before_count': 0, 'result_after_count': 1}
            source = source[:start] + changed + source[end:]
        else:
            source, record = _replace_scoped(source, name, function, before, after)
        records.append(record)
    return source, records


def _receipt(raw, generated, v1, forward, inverse, global_forward, global_inverse):
    return {'fixture_contract': CONTRACT, 'transform_version': TRANSFORM_VERSION,
            'os_facts_version': 'count-control-os-v2',
            'support_includes': ['control_support.h', 'test_control_v2.c'],
            'raw_bytes': len(raw), 'raw_sha256': _sha(raw),
            'generated_bytes': len(generated), 'generated_sha256': _sha(generated),
            'v1': v1, 'forward_count': len(forward), 'inverse_count': len(inverse),
            'forward': forward, 'inverse': inverse,
            'global_forward': global_forward, 'global_inverse': global_inverse,
            'global_forward_count': len(global_forward), 'global_inverse_count': len(global_inverse),
            'inverse_byte_equality': True}


def migrate(raw):
    source, v1 = migrate_v1(raw)
    source, forward = _apply(source)
    global_forward = []
    for entry in GLOBAL:
        source, record = _global(source, entry)
        global_forward.append(record)
    restored = source
    global_inverse = []
    for entry in reversed(GLOBAL):
        restored, record = _global(restored, entry, True)
        global_inverse.append(record)
    restored, inverse = _apply(restored, True)
    if invert_v1(restored, v1) != raw:
        raise FixtureContractError('v2 complete raw inverse mismatch')
    return source, _receipt(raw, source, v1, forward, inverse, global_forward, global_inverse)


def invert(generated, receipt):
    if not isinstance(receipt, dict) or receipt.get('fixture_contract') != CONTRACT or receipt.get('generated_sha256') != _sha(generated):
        raise FixtureContractError('v2 generated source/receipt identity mismatch')
    source = generated
    for entry in reversed(GLOBAL):
        source, _ = _global(source, entry, True)
    source, _ = _apply(source, True)
    raw = invert_v1(source, receipt['v1'])
    rebuilt, rebuilt_receipt = migrate(raw)
    if rebuilt != generated or rebuilt_receipt != receipt:
        raise FixtureContractError('v2 receipt/full inverse mismatch')
    return raw

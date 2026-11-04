"""Transparent verbatim C extraction. Never supplies production algorithms."""
from pathlib import Path
import re

class SetupError(Exception): pass

def balanced(text, start):
    # Remove comments/strings only for finding the matching delimiter; return original.
    token = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 0
    for m in token.finditer(text, start):
        if m.group() == '{': depth += 1
        elif m.group() == '}':
            depth -= 1
            if not depth: return m.end()
    raise SetupError('unbalanced C block')

def function(text, name):
    for m in re.finditer(r'^([^\n;{}]*\b'+re.escape(name)+r'\s*\([^;{}]*\))\s*\{', text, re.M):
        return text[m.start():balanced(text, text.index('{', m.start()))]
    raise SetupError('missing function '+name)

def record(text, name, enum=False):
    key = ('enum ' if enum else 'struct ')+name
    m = re.search(r'^'+re.escape(key)+r'\s*\{', text, re.M)
    if not m: raise SetupError('missing record '+name)
    return text[m.start():balanced(text, text.index('{',m.start()))]+';'

def generate(root, output, mutation=None):
    root=Path(root); output=Path(output)
    paths={
      'mech':'src/network/net/xdp/xsk_xdev_ext_mech.c',
      'core':'src/core/io_uring/xdev_ext_mech.c',
      'family':'src/network/io_uring/family/xdev_ext_netfam.c',
      'header':'src/network/include/linux/xdev_ext_netfam.h',
      'frame':'src/core/include/linux/xdev_ext_mech.h',
      'peer':'src/core/include/linux/xdev_ext_peer.h',
      'xsk':'src/network/net/xdp/xsk.c',
      'pool':'src/network/net/xdp/xsk_buff_pool.c',
      'poolh':'src/network/include/net/xsk_buff_pool.h',
      'tx':'src/network/net/xdp/xsk_xdev_ext_mech_tx_core.h',
      'zc':'src/network/net/xdp/xsk_xdev_ext_mech_zc_core.h',
      'rules':'src/core/io_uring/xdev_ext_mech_core.h'}
    src={k:(root/v).read_text() for k,v in paths.items()}
    have='xdev_ext_net_lease_pool(' in src['family']
    manifest=[]; pieces=[]
    def add(k,n):
        s=function(src[k],n); manifest.append({'path':paths[k],'function':n,'bytes':len(s.encode())}); pieces.append(s)
    types=[record(src['peer'],'xdev_ext_peer_lease'),record(src['peer'],'xdev_ext_peer_fd_lease'),record(src['frame'],'xdev_ext_mech_frame'),record(src['header'],'xdev_ext_net_lease_kind',True)]
    if have:
        types += [record(src['header'],'xdev_ext_net_pool_dma'),record(src['header'],'xdev_ext_net_pool_dma_ops')]
    types += [record(src['header'],'xdev_ext_net_lease')]
    tx = src['tx']; zc = src['zc']
    # Strip include directives only; retain every executable/header body byte.
    tx='\n'.join(l for l in tx.splitlines() if not l.lstrip().startswith('#include'))
    zc='\n'.join(l for l in zc.splitlines() if not l.lstrip().startswith('#include'))
    structures = [record(src['mech'],'xsk_xdev_ext_mech_provider'),record(src['mech'],'xsk_xdev_ext_mech_tx_batch')]
    output.joinpath('production_types.h').write_text('\n'.join(types))
    output.joinpath('production_journal.h').write_text(function(src['rules'],'xdev_ext_mech_span_in')+'\n'+tx+'\n'+zc+'\n'+'\n'.join(structures))
    add('core','xdev_ext_mech_batch_session'); add('core','xdev_ext_mech_batch_frame')
    add('family','xdev_ext_netfam_lease_host'); add('family','xdev_ext_netfam_release')
    if have:
        add('family','xdev_ext_net_lease_pool'); add('family','xdev_ext_net_lease_pool_release')
        add('mech','xsk_mech_pool_dma_check_locked')
        pieces[-1]=pieces[-1].replace('xsk_mech_pool_dma_check_locked(', 'actual_xsk_mech_pool_dma_check_locked(',1)
        pieces.append('static int xsk_mech_pool_dma_check_locked(void *owner,struct xdev_ext_mech_pool *pool,const struct xdev_ext_mech_frame *f,u32 off,u32 len) { int r=actual_xsk_mech_pool_dma_check_locked(owner,pool,f,off,len); boundary_check(f,r); return r; }')
        add('mech','xsk_mech_pool_dma_sync_locked')
        pieces.append('static const struct xdev_ext_net_pool_dma_ops xsk_mech_pool_dma_ops = {.check_locked = xsk_mech_pool_dma_check_locked};')
    add('poolh','xp_unaligned_extract_addr'); add('poolh','xp_unaligned_extract_offset'); add('poolh','xp_unaligned_add_offset_to_addr'); add('pool','__xp_raw_get_addr'); add('pool','__xp_raw_get_dma')
    add('pool','xp_raw_get_dma')
    # Renaming only: instrumentation wraps the OS mapping boundary, actual lookup remains verbatim.
    pieces[-1]=pieces[-1].replace('xp_raw_get_dma(', 'actual_xp_raw_get_dma(',1)
    pieces.append('static dma_addr_t xp_raw_get_dma(struct xsk_buff_pool *p,u64 a) { boundary_raw(p,a); return actual_xp_raw_get_dma(p,a); }')
    add('poolh','xp_dma_sync_for_device')
    for n in ['xsk_mech_zc_done','xsk_mech_zc_retire','xsk_mech_zc_cancel_pending','xsk_mech_zc_stop','xsk_xdev_ext_mech_pool_dead','xsk_xdev_ext_mech_tx_peek','xsk_xdev_ext_mech_tx_batch','xsk_xdev_ext_mech_tx_complete','xsk_xdev_ext_mech_zc_submit','xsk_xdev_ext_mech_submit','xsk_xdev_ext_mech_fill_cqe']:
        add('mech',n)
    add('pool','xp_find_dma_map'); add('pool','xp_dma_unmap')
    for n in ['xsk_tx_completed','xsk_tx_cancel_tail','xsk_tx_set_tail_result','xsk_tx_peek_desc','xsk_tx_release','xsk_tx_peek_release_fallback','xsk_tx_peek_release_desc_batch']:
        add('xsk',n)
    body='\n\n'.join(pieces)
    mutations={
      'data_only_sync':('dma_sync_single_for_device(pool->dev, dma, size, DMA_BIDIRECTIONAL);','dma_sync_single_for_device(pool->dev, dma + 42, size - 42, DMA_BIDIRECTIONAL);'),
      'cpu_derived_dma':('actual_xp_raw_get_dma(p,a);','(dma_addr_t)(uintptr_t)p->addrs + a;'),
      'callback_under_lock':('spin_unlock_irqrestore(&p->tx_lock, flags);\n\t/* mark_dead','xsk_mech_zc_done(&done);\n\tspin_unlock_irqrestore(&p->tx_lock, flags);\n\t/* mark_dead'),
      'accepted_eagain_retry':('if (result == -EAGAIN)\n\t\tresult = -EIO;','if (result == -EAGAIN)\n\t\tresult = -EAGAIN;'),
      'fifo_head_is_cons':('return r->native_count ? (int)r->native_head : -ENOENT;','return r->native_count ? (int)(r->cons & (r->capacity - 1)) : -ENOENT;'),
    }
    candidate_mutations={'accessor_outside_lock','compacted_frame_index','checksum_before_prepare','rollback_prod_missing','unknown_lease_clear','set_only_early_release'}
    if mutation in candidate_mutations:
        if not have: raise SetupError('candidate POOL_DMA API absent: '+mutation)
        def mutate_function(name, transform):
            nonlocal body
            before=function(body,name); after=transform(before)
            if after==before: raise SetupError('candidate mutation anchor missing '+mutation)
            body=body.replace(before,after,1)
        if mutation=='accessor_outside_lock':
            n='xsk_mech_pool_dma_sync_locked'
            before=function(body,n); renamed=before.replace(n+'(', 'actual_'+n+'(',1)
            wrapper='static void '+n+'(struct xsk_xdev_ext_mech_provider *p,const struct xdev_ext_net_lease *lease) {unsigned long flags=0; spin_unlock_irqrestore(&p->tx_lock,flags); actual_'+n+'(p,lease); spin_lock_irqsave(&p->tx_lock,flags);}'
            body=body.replace(before,renamed+'\n'+wrapper,1)
        elif mutation=='compacted_frame_index':
            mutate_function('xsk_xdev_ext_mech_zc_submit',lambda f: re.sub(r'(xdev_ext_net_lease_pool\([^,]+,\s*b,\s*)i,',r'\1(i == 2 && *xst->tx_tag[1] == xdev_ext_mech_batch_id(b) ? 1 : i),',f,count=1))
        elif mutation=='checksum_before_prepare':
            mutate_function('xsk_xdev_ext_mech_zc_submit',lambda f: re.sub(r'(err = xsk_mech_zc_reserve\(&p->ring, nr, &start\);\s*if \(err\)\s*goto unlock;)',r'\1\n xsk_xdev_ext_mech_tx_finish(xst->tx_pkt[0]);',f,count=1))
        elif mutation=='rollback_prod_missing':
            mutate_function('xsk_xdev_ext_mech_zc_submit',lambda f: re.sub(r'p->ring\.prod\s*=\s*start;', '(void)start;',f,count=1))
        elif mutation=='unknown_lease_clear':
            mutate_function('xdev_ext_net_lease_pool_release',lambda f:f.replace('{','{\nquiesced=true;',1))
        elif mutation=='set_only_early_release':
            mutate_function('xsk_xdev_ext_mech_tx_complete',lambda f:f.replace('tb = slot->batch;', 'tb = slot->batch;\n xdev_ext_net_lease_pool_release(&tb->pool_lease[slot->slot],true);',1))
    elif mutation:
        if mutation not in mutations: raise SetupError('unknown mutation')
        old,new=mutations[mutation]
        if old in body: body=body.replace(old,new,1)
        elif old in zc:
            j=output.joinpath('production_journal.h'); j.write_text(j.read_text().replace(old,new,1))
        else: raise SetupError('mutation anchor missing '+mutation)
    output.joinpath('production.c.inc').write_text(body)
    return have,manifest

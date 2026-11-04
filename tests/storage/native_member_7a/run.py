#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent 7A characterization. Compile errors are SETUP, never mutation kills."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NATIVE = 'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c'
IOCTL = 'src/storage/drivers/nvme/host/ioctl.c'
BLOCK = 'src/storage/io_uring/family/xdev_ext_storfam_block.c'
RUNTIME = 'src/storage/io_uring/family/xdev_ext_storfam.c'
FUNCS = ['nvme_xdev_ext_class_ns', 'nvme_xdev_ext_class_bind',
         'nvme_xdev_ext_class_unbind', 'nvme_xdev_ext_class_validate',
         'nvme_xdev_ext_class_recheck', 'nvme_xdev_ext_class_map',
         'nvme_xdev_ext_peer_slot_get', 'nvme_xdev_ext_peer_slot_put',
         'nvme_xdev_ext_peer_lease', 'nvme_xdev_ext_peer_map',
         'nvme_xdev_ext_peer_submit', 'nvme_xdev_ext_class_submit',
         'nvme_xdev_ext_class_poll', 'nvme_xdev_ext_class_mark_dead']

class Setup(Exception):
    pass

def function(text, name):
    """Locate an actual C definition, retaining its entire body unchanged."""
    matches = list(re.finditer(r'\b' + re.escape(name) + r'\s*\([^;{}]*?\)\s*\{', text, re.S))
    if len(matches) != 1:
        raise Setup(f'{name}: expected one definition, found {len(matches)}')
    m = matches[0]
    start = text.rfind('\n\n', 0, m.start()) + 2
    # Drop a preceding comment only; retain all native return/parameter types.
    lead = text[start:m.start()]
    if '*/' in lead:
        start += lead.rfind('*/') + 2
    pos = m.end() - 1
    depth = 0
    token = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    for t in token.finditer(text, pos):
        if t.group() == '{': depth += 1
        elif t.group() == '}':
            depth -= 1
            if depth == 0: return text[start:t.end()].strip() + '\n'
    raise Setup(f'{name}: unterminated body')

def no_includes(text):
    return re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)

HEADERS = {
 'linux/nvme_xdev_ext_passthru.h': 'src/storage/include/linux/nvme_xdev_ext_passthru.h',
 'linux/xdev_ext_storfam_core.h': 'src/storage/include/linux/xdev_ext_storfam_core.h',
 'linux/xdev_ext_storfam_runtime.h': 'src/storage/include/linux/xdev_ext_storfam_runtime.h',
 'linux/xdev_ext_storfam_block.h': 'src/storage/include/linux/xdev_ext_storfam_block.h',
 'linux/xdev_ext_desc_schema.h': 'src/core/include/linux/xdev_ext_desc_schema.h',
 'uapi/linux/nvme_ioctl.h': 'src/storage/include/uapi/linux/nvme_ioctl.h',
 'uapi/linux/xdev_ext_binding.h': 'src/core/include/uapi/linux/xdev_ext_binding.h',
 'uapi/linux/xdev_ext_mech.h': 'src/core/include/uapi/linux/xdev_ext_mech.h',
 'xdev_ext_peer_nvme_core.h': 'src/storage/drivers/nvme/host/xdev_ext_peer_nvme_core.h',
}

def assemble(root, out, mutation=None):
    source = {p: (root/p).read_text() for p in [NATIVE, IOCTL, BLOCK, RUNTIME]}
    headers = {k: (root/p).read_text() for k,p in HEADERS.items()}
    if mutation:
        target, symbol, old, new, _ = MUTANTS[mutation]
        if target in source:
            content = source[target]
            body = function(content, symbol) if symbol else content
            if body.count(old) != 1: raise Setup(f'{mutation}: mutation anchor count {body.count(old)}')
            changed = body.replace(old,new,1)
            source[target] = content.replace(body,changed,1) if symbol else changed
        else:
            body = headers[target]
            if body.count(old) != 1: raise Setup(f'{mutation}: header mutation anchor')
            headers[target] = body.replace(old,new,1)
    include = out/'include'
    for name, text in headers.items():
        path = include/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for name,text in {'linux/errno.h':'#include <asm-generic/errno.h>\n',
                      'linux/blk_types.h':'/* blk_opf_t supplied by boundary.h */\n'}.items():
        (include/name).write_text(text)
    native = source[NATIVE]
    anchor = '\n#ifndef CONFIG_XDEV_EXT_MECH_ZEROCOPY\n'
    if native.count(anchor) != 1: raise Setup('native declaration/resource section missing')
    prefix = no_includes(native.split(anchor)[0])
    c = '#include "boundary.h"\n'
    c += no_includes(source[RUNTIME]) + '\n' + no_includes(source[BLOCK]) + '\n'
    c += function(source[IOCTL], 'nvme_xdev_ext_capture_identity') + '\n' + prefix + '\n'
    c += '\n'.join(function(native, name) for name in FUNCS)
    c += '\n_Static_assert(sizeof(struct nvme_command)==64,"native command boundary size");\n'
    c += '#include "assertions.c"\n'
    path = out/'characterization.c'
    path.write_text(c)
    return path,include

# Each mutation is applied to a real production definition/header, then compiled.
# The last entry names the first literal assertion expected to reject it.
MUTANTS = {
 'dead_gate':(NATIVE,'nvme_xdev_ext_class_submit','if (atomic_read(&p->dead))','if (false && atomic_read(&p->dead))','dead_before_validated_identity'),
 'validated_gate':(NATIVE,'nvme_xdev_ext_class_submit','!bp->validated || bp->batch_id != xdev_ext_mech_batch_id(b)','false','validated_before_identity'),
 'batchid_gate':(NATIVE,'nvme_xdev_ext_class_submit','bp->batch_id != xdev_ext_mech_batch_id(b)','false','old_batchid_before_identity'),
 'gate_identity_skip':(NATIVE,'nvme_xdev_ext_class_submit','ret = nvme_xdev_ext_class_recheck(st);','ret = 0;','identity_missing_disk_ENODEV'),
 'identity_dead_skip':(NATIVE,'nvme_xdev_ext_class_recheck','xdev_ext_mech_stage_dead(st, ret);','(void)st;','identity_ENODEV_marks_dead'),
 'identity_queue_skip':(NATIVE,'nvme_xdev_ext_class_recheck','queue != p->queue','false','queue_pointer_drift_ESTALE'),
 'identity_head_skip':(NATIVE,'nvme_xdev_ext_class_recheck','head != p->head','false','head_pointer_drift_ESTALE'),
 'identity_disk_skip':(NATIVE,'nvme_xdev_ext_class_recheck','disk != p->disk','false','disk_pointer_drift_ESTALE'),
 'validated_not_clear':(NATIVE,'nvme_xdev_ext_class_validate','bp->validated = false;','/* mutation: retain validated */','count_clears_validated'),
 'slotcount_skip':(NATIVE,'nvme_xdev_ext_class_validate','if (n != 1)','if (false)','count_EPROTO_before_schema'),
 'saved_sqe63':(NATIVE,'nvme_xdev_ext_class_validate','memcpy(bp->sqe, scratch, NVME_XDEV_EXT_SQE_SIZE);','memcpy(bp->sqe, scratch, 40);','admitted_sqe_all64'),
 'batchid_wrong':(NATIVE,'nvme_xdev_ext_class_validate','bp->batch_id = xdev_ext_mech_batch_id(b);','bp->batch_id = 99;','admitted_batchid41'),
 'rw_wrong':(NATIVE,'nvme_xdev_ext_class_validate','.slba = decoded.slba, .nlb = decoded.nlb,','.slba = decoded.slba + 1, .nlb = decoded.nlb,','admitted_slba100'),
 'schema_forbidden':('linux/xdev_ext_desc_schema.h',None,'if (value & ~schema->writable[dw])','if (false && (value & ~schema->writable[dw]))','forbidden_sqe_EPERM'),
 'window_skip':('linux/xdev_ext_storfam_core.h',None,'if (offset >= window_nlb || nlb > window_nlb - offset)','if (false && (offset >= window_nlb || nlb > window_nlb - offset))','window_past_end_ERANGE'),
 'capture_cleanup':(NATIVE,'nvme_xdev_ext_class_bind','if (ret) {\n\t\tkfree(p);','if (ret) {\n\t\t(void)p;','capture_member_freed'),
 'effects_skip':(NATIVE,'nvme_xdev_ext_class_bind','if (!nvme_xdev_ext_mech_cmd_allowed(ns, st->file, write))','if (false)','effects_before_alloc'),
 'poll_capability_skip':(NATIVE,'nvme_xdev_ext_class_bind','if (st->poll && !xdev_ext_stor_block_poll_capable(ns->queue))','if (false)','poll_capability_alone'),
 'requester_class_device':(NATIVE,'nvme_xdev_ext_peer_resources_init','struct device *dev = p->ns->ctrl->dev;','struct device *dev = p->ns->ctrl->device;','peer_exact_native_requester'),
 'requester_nonpci_skip':(NATIVE,'nvme_xdev_ext_peer_resources_init','if (!dev || !dev_is_pci(dev))','if (!dev)','peer_nonPCI_original_EOPNOTSUPP'),
 'alloc_wrong_queue':(NATIVE,'nvme_xdev_ext_class_submit','blk_mq_alloc_request(p->ns->queue,','blk_mq_alloc_request(&queue_b,','native_alloc_uses_real_queue'),
 'map_wrong_queue':(NATIVE,'nvme_xdev_ext_class_map','xdev_ext_stor_block_caps(p->ns->queue, p->identity.lba_shift)','xdev_ext_stor_block_caps(&queue_a, p->identity.lba_shift)','map_consumes_current_queue'),
 'poll_wrong_queue':(NATIVE,'nvme_xdev_ext_class_poll','xdev_ext_stor_block_poll(p->ns->queue,','xdev_ext_stor_block_poll(&queue_a,','class_poll_current_real_queue'),
 'poll_skip':(NATIVE,'nvme_xdev_ext_class_poll','return xdev_ext_stor_block_poll(p->ns->queue, views, ARRAY_SIZE(views));','return 0;','class_poll_positive_only_sum2'),
 'peer_view_omitted':(NATIVE,'nvme_xdev_ext_class_poll','views, ARRAY_SIZE(views)','views, 1','class_poll_positive_only_sum2'),
 'view_wrong_stride':(NATIVE,'nvme_xdev_ext_class_poll','.stride = sizeof(*p->peer->slots),','.stride = sizeof(*p->slots),','class_poll_positive_only_sum2'),
 'poll_dedup_skip':(BLOCK,'xdev_ext_stor_block_poll','if (k < nr_seen)','if (false)','dualview_dedup_count3'),
 'poll_overflow_stop':(BLOCK,'xdev_ext_stor_block_poll','/* Past 64 recorded queues, keep polling unrecorded keys. */','if (nr_seen == 64) continue;','seen64_overflow_sum66'),
 'poll_negative_sum':(BLOCK,'xdev_ext_stor_block_poll','if (ret > 0)','if (ret != 0)','class_poll_positive_only_sum2'),
 'poll_inactive':(BLOCK,'xdev_ext_stor_block_poll','if (!READ_ONCE(done->poll_live))','if (false)','class_poll_positive_only_sum2'),
 'caps_wrong_maxbytes':(BLOCK,'xdev_ext_stor_block_caps','.max_bytes = queue_max_hw_sectors(queue) << SECTOR_SHIFT,','.max_bytes = 65536,','map_runtime_caps_EMSGSIZE'),
}
MUTANTS.update({
 'bind_flags_skip':(NATIVE,'nvme_xdev_ext_class_bind','if (u->flags || (!write && st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))','if (false)','flags_precede_namespace'),
 'strict_transport_skip':(NATIVE,'nvme_xdev_ext_class_bind','(strcmp(ns->ctrl->ops->name, "pcie") ||','(false ||','strict_transport_precedes_mode_effects'),
 'peer_capability_skip':(NATIVE,'nvme_xdev_ext_class_bind','if (!ns->ctrl->ops->peer_rw || strcmp(ns->ctrl->ops->name, "pcie"))','if (false)','peer_capability_before_readmode'),
 'readmode_skip':(NATIVE,'nvme_xdev_ext_class_bind','if (!write && !(st->file->f_mode & FMODE_READ))','if (false)','peer_readmode_before_effects'),
 'writemode_skip':(NATIVE,'nvme_xdev_ext_class_bind','if (write && !(st->file->f_mode & FMODE_WRITE))','if (false)','writemode_before_effects'),
 'failed_bind_priv_not_cleared':(NATIVE,'nvme_xdev_ext_class_bind','st->priv = NULL;','(void)st;','host_partial_create_no_priv'),
 'host_bio_cleanup_skip':(NATIVE,'nvme_xdev_ext_class_resources_free','kfree(slot->bio);','(void)slot;','host_partial_create_no_leak'),
 'peer_coherent_cleanup_skip':(NATIVE,'nvme_xdev_ext_peer_resources_free','dma_free_coherent(res->dma_dev, res->sgl_bytes, res->sgl,\n\t\t\t\t  res->sgl_dma);','(void)res;','unbind_balances_allocations'),
 'poll_reverse_views':(BLOCK,'xdev_ext_stor_block_poll','for (i = 0; i < nr_views; i++)','for (i = nr_views; i-- > 0;)','dualview_host_first_key9'),
})

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-root',type=pathlib.Path,default=ROOT)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args();root=args.source_root.resolve();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    _native_for_order=(root/NATIVE).read_text()
    _order_body=function(_native_for_order,'nvme_xdev_ext_class_bind')
    _poll_start=_order_body.index('\t/* No interrupt fallback:')
    _strict_end=_order_body.index('#endif',_poll_start)+len('#endif')
    _order_old=_order_body[_poll_start:_strict_end]
    _poll_end=_order_old.index('#ifdef CONFIG_XDEV_EXT_MECH_ZEROCOPY')
    _order_new=_order_old[_poll_end:]+'\n'+_order_old[:_poll_end]
    MUTANTS['native_poll_transport_reorder']=(NATIVE,'nvme_xdev_ext_class_bind',_order_old,_order_new,'native_authorization_function_order')
    # Trace mutation changes actual execution, not a text condition.
    MUTANTS['plan_trace_skip']=(NATIVE,'nvme_xdev_ext_class_validate','xdev_ext_mech_trace_plan(b,','if (false) xdev_ext_mech_trace_plan(b,','plan_trace_once')
    inputs = sorted(set([NATIVE,IOCTL,BLOCK,RUNTIME,*HEADERS.values()]))
    hashes = {p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in inputs}
    freeze = {'baseline':'d7ad4ab9fdda9b85d5ecb93bb5b97173dc8aed28','source_root':str(root),'sources':hashes,'test_sources':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.is_file()}}
    (out/'SOURCE.json').write_text(json.dumps(freeze,indent=2)+'\n')
    results=[]
    for name,sanitize in [('baseline-gcc',False),('baseline-ubsan',True)]+([(n,False) for n in MUTANTS] if args.mutants else []):
        case=out/name;case.mkdir(exist_ok=True)
        try:c,inc=assemble(root,case,name if name in MUTANTS else None)
        except Setup as e:
            results.append({'name':name,'verdict':'SETUP','error':str(e)});print(f'SETUP {name}: {e}',flush=True);continue
        cmd=['gcc','-std=gnu11','-O0','-g','-finstrument-functions','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-parameter','-Werror=implicit-function-declaration','-I'+str(inc),'-I'+str(HERE),str(c),'-o',str(case/'test')]
        if sanitize:cmd[1:1]=['-fsanitize=undefined','-fno-sanitize-recover=all']
        compile_run=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
        (case/'compile.log').write_text(compile_run.stdout)
        entry={'name':name,'compile_command':cmd,'compile_exit':compile_run.returncode}
        if compile_run.returncode:entry['verdict']='SETUP'
        else:
            run=subprocess.run([str(case/'test')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=10)
            (case/'run.log').write_text(run.stdout);entry.update(run_exit=run.returncode,run_command=[str(case/'test')],output=run.stdout)
            if name in MUTANTS:
                expected=MUTANTS[name][-1]
                entry['expected_assertion']=expected
                entry['verdict']='KILLED' if run.returncode==1 and f'ASSERTION {expected} ' in run.stdout else 'SURVIVED' if run.returncode==0 else 'WRONG_FAILURE'
            else:entry['verdict']='PASS' if run.returncode==0 else 'FAIL'
        results.append(entry);print(f'{entry["verdict"]} {name}',flush=True)
    verdict=('TESTS_READY' if args.mutants else 'BASELINE_PASS') if all(r['verdict'] in ('PASS','KILLED') for r in results) else 'NOT_READY'
    report={'verdict':verdict,'scope':'host characterization of real current production bodies, no hardware/native kernel claim','results':results}
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(verdict)
    return 0 if verdict in ('TESTS_READY','BASELINE_PASS') else 1

if __name__=='__main__':
    try:sys.exit(main())
    except (Setup,subprocess.TimeoutExpired,FileNotFoundError,FileExistsError,ValueError) as e:print(f'SETUP: {e}',file=sys.stderr);sys.exit(2)

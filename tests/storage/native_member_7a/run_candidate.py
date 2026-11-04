#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Frozen 7A candidate assembly. Never modify production or frozen test inputs."""
import argparse
import difflib
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
# Imported frozen helpers must not leave additional worktree artifacts.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('frozen_characterization', HERE/'run.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
NATIVE, BLOCK, RUNTIME = base.NATIVE, base.BLOCK, base.RUNTIME
NVME = 'src/storage/drivers/nvme/host/nvme.h'
MECH = 'src/core/include/linux/xdev_ext_mech.h'
ADAPTER = HERE/'candidate_adapter.h'
FIELD_MAP = [(f'p->{s}', f'p->family.{s}') for s in ('window', 'dead')]
FIELD_MAP += [(f'private_batch.{s}', f'private_batch.family.{s}') for s in ('sqe', 'rw', 'batch_id', 'validated')]
FUNCS = [
    'nvme_xdev_ext_class_ns', 'nvme_xdev_ext_member_bind',
    'nvme_xdev_ext_member_unbind', 'nvme_xdev_ext_member_requester',
    'nvme_xdev_ext_member_queue', 'nvme_xdev_ext_class_bind',
    'nvme_xdev_ext_class_unbind', 'nvme_xdev_ext_mech_fill_info',
    'nvme_xdev_ext_member_decode', 'nvme_xdev_ext_class_validate',
    'nvme_xdev_ext_member_identity', 'nvme_xdev_ext_class_map',
    'nvme_xdev_ext_peer_slot_get', 'nvme_xdev_ext_peer_slot_put',
    'nvme_xdev_ext_peer_lease', 'nvme_xdev_ext_peer_map',
    'nvme_xdev_ext_peer_submit', 'nvme_xdev_ext_class_submit',
    'nvme_xdev_ext_member_poll', 'nvme_xdev_ext_class_poll',
    'nvme_xdev_ext_class_bounce_release', 'nvme_xdev_ext_class_fill_cqe',
    'nvme_xdev_ext_peer_fill_cqe', 'nvme_xdev_ext_stage_fill_cqe',
    'nvme_xdev_ext_class_mark_dead',
]

# These only add public kernel/core boundary types, not storage algorithms.
EXTERNAL = '''
struct xdev_ext_mech_class_desc { unsigned boundary_unused; };
struct xdev_ext_rel_policy;
static const struct xdev_ext_mech_class_desc xdev_ext_mech_class_decls[16];
#define THIS_MODULE NULL
static int xdev_ext_mech_session_state(struct xdev_ext_mech_session *s) { return s->state; }
'''

MUTANTS = {
 'identity_hook_skip': (BLOCK, 'xdev_ext_storfam_submit_check',
   'return ss->dev->identity(ss->member, true, &ss->geometry);', 'return 0;',
   'identity_missing_disk_ENODEV'),
 'dead_gate_skip': (BLOCK, 'xdev_ext_storfam_submit_check',
   'if (atomic_read(&ss->dead))', 'if (false && atomic_read(&ss->dead))',
   'dead_before_validated_identity'),
 'validated_gate_skip': (BLOCK, 'xdev_ext_storfam_submit_check',
   '!sb->validated || sb->batch_id != xdev_ext_mech_batch_id(batch)', 'false',
   'validated_before_identity'),
 'native_common_gate_bypass': (NATIVE, 'nvme_xdev_ext_class_submit',
   'ret = xdev_ext_storfam_submit_check(&p->family, b, &bp->family);',
   'ret = p->family.dev->identity(p->family.member, true, &p->family.geometry);',
   'dead_no_stage_dead_callback'),
 'old_native_gate_unused_common': (NATIVE, 'nvme_xdev_ext_class_submit',
   'ret = xdev_ext_storfam_submit_check(&p->family, b, &bp->family);',
   'if (atomic_read(&p->family.dead)) return -ENODEV;\n'
   '\tif (!bp->family.validated || bp->family.batch_id != xdev_ext_mech_batch_id(b)) return -EPROTO;\n'
   '\tret = nvme_xdev_ext_member_identity(p, true, &p->family.geometry);',
   'candidate_class_submit_consumes_identity_hook'),
 'queue_alloc_hook_skip': (NATIVE, 'nvme_xdev_ext_class_submit',
   'blk_mq_alloc_request(p->family.dev->queue(p->family.member),', 'blk_mq_alloc_request(p->ns->queue,',
   'candidate_class_alloc_consumes_queue_hook'),
 'queue_map_hook_skip': (NATIVE, 'nvme_xdev_ext_class_map',
   'xdev_ext_stor_block_caps(p->family.dev->queue(p->family.member),', 'xdev_ext_stor_block_caps(p->ns->queue,',
   'candidate_class_submit_runtime_queue_caps'),
 'decode_hook_skip': (BLOCK, 'xdev_ext_storfam_validate',
   'ss->dev->decode(ss->member, batch, scratch, &ss->window,',
   'nvme_xdev_ext_member_decode(ss->member, batch, scratch, &ss->window,',
   'candidate_class_validate_consumes_decode_error'),
 'poll_hook_skip': (BLOCK, 'xdev_ext_storfam_poll',
   'ss->dev->poll(ss->member, ss->poll_views,',
   'nvme_xdev_ext_member_poll(ss->member, ss->poll_views,',
   'candidate_class_poll_consumes_family_hook_result'),
 'peer_view_omit': (BLOCK, 'xdev_ext_storfam_poll',
   'ARRAY_SIZE(ss->poll_views)', '1', 'class_poll_positive_only_sum2'),
 'host_view_omit': (BLOCK, 'xdev_ext_storfam_poll',
   'ss->dev->poll(ss->member, ss->poll_views,\n\t\t\t     ARRAY_SIZE(ss->poll_views))',
   'ss->dev->poll(ss->member, ss->poll_views + 1, 1)', 'class_poll_positive_only_sum2'),
 'native_poll_queue_skip': (NATIVE, 'nvme_xdev_ext_member_poll',
   'xdev_ext_stor_block_poll(p->family.dev->queue(member), views, nr_views)',
   'xdev_ext_stor_block_poll(p->ns->queue, views, nr_views)',
   'candidate_native_poll_uses_queue_hook'),
}

def declaration(source, anchor):
    start = source.index(anchor)
    opened = source.index('{', start)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|[{}]', source[opened:], re.S):
        if token.group() == '{': depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                end = opened + token.end()
                if source[end:end+1] != ';': raise base.Setup(f'{anchor}: missing semicolon')
                return source[start:end+1]+'\n'
    raise base.Setup(f'{anchor}: incomplete declaration')

def transform_assertions(original, fixture_views):
    text = original
    for old, new in FIELD_MAP:
        text = text.replace(old, new)
    injection = ''
    if fixture_views:
        anchor = 'p->peer->slots=zalloc(3*sizeof(*p->peer->slots));'
        injection = ('\n /* TEST-only resource injection: publish the same borrowed arrays. */\n'
          ' p->family.poll_views[0]=(struct xdev_ext_stor_poll_view){.first=&p->slots[0].done,.stride=sizeof(*p->slots),.count=p->nr_slots};\n'
          ' p->family.poll_views[1]=(struct xdev_ext_stor_poll_view){.first=&p->peer->slots[0].done,.stride=sizeof(*p->peer->slots),.count=p->peer->nr_slots};\n')
        if text.count(anchor) != 1: raise base.Setup('fixture injection anchor')
        text = text.replace(anchor, anchor+injection)
    reverse = text.replace(injection, '') if injection else text
    for old, new in reversed(FIELD_MAP): reverse = reverse.replace(new, old)
    if reverse != original: raise base.Setup('assertion reverse mapping differs')
    return text, injection, reverse

def assemble(root, out, fixture_views, mutation=None):
    paths = [NATIVE, BLOCK, RUNTIME, NVME, MECH]
    sources = {p:(root/p).read_text() for p in paths}
    if mutation:
        target, symbol, old, new, _ = MUTANTS[mutation]
        body = base.function(sources[target], symbol)
        if body.count(old) != 1: raise base.Setup(f'{mutation}: anchor {body.count(old)}')
        sources[target] = sources[target].replace(body, body.replace(old,new,1),1)
    inc = out/'include'
    for name, path in base.HEADERS.items():
        target = inc/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((root/path).read_bytes())
    boundary = (HERE/'boundary.h').read_text()
    atomic = boundary[boundary.index('typedef struct { int counter; } atomic_t;'):boundary.index('struct page {')]
    boundary = boundary.replace(atomic, '')
    (out/'boundary.h').write_text(boundary)
    (inc/'linux/atomic.h').write_text(atomic)
    (inc/'linux/errno.h').write_text('#include <asm-generic/errno.h>\n')
    (inc/'linux/blk_types.h').write_text('/* blk_opf_t supplied by boundary.h */\n')
    (out/'candidate_adapter.h').write_bytes(ADAPTER.read_bytes())
    original = (HERE/'assertions.c').read_text()
    remapped, injection, reverse = transform_assertions(original,fixture_views)
    (out/'assertions.c').write_text(remapped)
    (out/'assertions.reverse.c').write_text(reverse)
    (out/'assertions.diff').write_text(''.join(difflib.unified_diff(original.splitlines(True),remapped.splitlines(True),fromfile='frozen/assertions.c',tofile='generated/assertions.c')))
    (out/'candidate.c.in').write_bytes((HERE/'candidate.c.in').read_bytes())
    proof = {'field_map':FIELD_MAP,'fixture_injection':injection,
             'reverse_exact':True,'literal_expectations_changed':False,
             'original_sha256':hashlib.sha256(original.encode()).hexdigest(),
             'reverse_sha256':hashlib.sha256((out/'assertions.reverse.c').read_bytes()).hexdigest()}
    (out/'REMAP.json').write_text(json.dumps(proof,indent=2)+'\n')
    native = sources[NATIVE]
    prefix = base.no_includes(native.split('\n#ifndef CONFIG_XDEV_EXT_MECH_ZEROCOPY\n')[0])
    c = '#include "boundary.h"\n'+EXTERNAL
    c += declaration(sources[MECH], 'struct xdev_ext_mech_class_ops {')
    # Declarations are actual production signatures, needed only because the
    # complete block runtime precedes native definitions in this translation unit.
    for name in ('nvme_xdev_ext_member_decode','nvme_xdev_ext_member_poll'):
        body=base.function(native,name)
        c += body[:body.index('{')].strip()+';\n'
    c += base.no_includes(sources[RUNTIME])+'\n'+base.no_includes(sources[BLOCK])+'\n'
    c += base.function(sources[NVME], 'nvme_xdev_ext_capture_identity')+'\n'+prefix+'\n'
    c += 'static const struct xdev_ext_stor_dev_ops nvme_xdev_ext_member_ops;\n'
    for name in FUNCS:
        selection = native
        if name == 'nvme_xdev_ext_class_bounce_release':
            selection = native.split('#ifndef NVME_XDEV_EXT_MECH_BOUNCE_AVAILABLE\n',1)[1].split('#endif /* !NVME_XDEV_EXT_MECH_BOUNCE_AVAILABLE */',1)[0]
        c += base.function(selection, name)+'\n'
    c += declaration(native,'static const struct xdev_ext_stor_dev_ops nvme_xdev_ext_member_ops = {')
    c += declaration(native,'static const struct xdev_ext_mech_class_ops nvme_xdev_ext_mech_class = {')
    c += '\n_Static_assert(sizeof(struct nvme_command)==64,"native command boundary size");\n'
    c += '#define main frozen_baseline_main\n#include "assertions.c"\n#undef main\n'
    c += '#include "candidate.c.in"\n'
    result = out/'characterization.c'
    result.write_text(c)
    lineage = {'whole_runtime_no_includes':RUNTIME,'whole_block_no_includes':BLOCK,
        'whole_native_resource_prefix_no_includes':NATIVE,
        'native_definitions':FUNCS,'identity_definition':NVME,
        'actual_ops_rows':['nvme_xdev_ext_member_ops','nvme_xdev_ext_mech_class'],
        'public_class_ops_declaration':MECH,
        'production_body_replacement':False if not mutation else mutation,
        'boundary_delta':'Move unchanged atomic declarations into linux/atomic.h before block header; add external core registry/module/session-state declarations.',
        'generated_c_sha256':hashlib.sha256(c.encode()).hexdigest()}
    (out/'ASSEMBLY.json').write_text(json.dumps(lineage,indent=2)+'\n')
    (out/'boundary.diff').write_text(''.join(difflib.unified_diff((HERE/'boundary.h').read_text().splitlines(True),boundary.splitlines(True),fromfile='frozen/boundary.h',tofile='generated/boundary.h')))
    return result, inc

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-root',type=pathlib.Path,required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    parser.add_argument('--fixture-views',action='store_true')
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    root=args.source_root.resolve();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    inputs=sorted(set([NATIVE,BLOCK,RUNTIME,NVME,MECH,base.IOCTL,*base.HEADERS.values()]))
    (out/'SOURCE.json').write_text(json.dumps({'source_root':str(root),
        'sources':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in inputs},
        'tests':{p:hashlib.sha256((HERE/p).read_bytes()).hexdigest() for p in ('run.py','boundary.h','assertions.c','candidate.c.in','run_candidate.py')},
        'adapter':hashlib.sha256(ADAPTER.read_bytes()).hexdigest(),
        'test_inputs_recorded':True},indent=2)+'\n')
    results=[]
    cases=[('candidate-gcc',False),('candidate-ubsan',True)]
    if args.mutants: cases += [(name,False) for name in MUTANTS]
    for name,sanitized in cases:
        case=out/name;case.mkdir(exist_ok=True)
        entry={'name':name}
        try:
            c,inc=assemble(root,case,args.fixture_views,name if name in MUTANTS else None)
            cmd=['gcc','-std=gnu11','-O0','-g','-finstrument-functions','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-parameter','-Werror=implicit-function-declaration','-I'+str(inc),'-I'+str(case),str(c),'-o',str(case/'test')]
            if sanitized:cmd[1:1]=['-fsanitize=undefined','-fno-sanitize-recover=all']
            build=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
            (case/'compile.log').write_text(build.stdout)
            entry.update(compile_command=cmd,compile_exit=build.returncode)
            if build.returncode:entry['verdict']='SETUP'
            else:
                run=subprocess.run([str(case/'test')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=10)
                (case/'run.log').write_text(run.stdout)
                entry.update(run_command=[str(case/'test')],run_exit=run.returncode,output=run.stdout)
                if name in MUTANTS:
                    assertion=MUTANTS[name][-1];entry['expected_assertion']=assertion
                    entry['verdict']='KILLED' if run.returncode==1 and f'ASSERTION {assertion} ' in run.stdout else 'SURVIVED' if run.returncode==0 else 'WRONG_FAILURE'
                else:entry['verdict']='PASS' if run.returncode==0 else 'REAL_RED' if run.returncode==1 and 'ASSERTION ' in run.stdout else 'WRONG_FAILURE'
        except (base.Setup,subprocess.TimeoutExpired) as error:entry.update(verdict='SETUP',error=str(error))
        results.append(entry);print(entry['verdict'],name,flush=True)
    report={'status':'PASS' if all(r['verdict'] in ('PASS','KILLED') for r in results) else 'NOT_READY','scope':'host boundary assembly only','fixture_views':args.fixture_views,'results':results}
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':
    try:sys.exit(main())
    except (base.Setup,FileNotFoundError,FileExistsError) as error:print('SETUP:',error,file=sys.stderr);sys.exit(2)

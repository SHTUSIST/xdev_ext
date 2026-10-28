#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent early CTS contract through real NHI/XDOMAIN host composition."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'source-layout.json').is_file())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def assemble(out):
    """No shared source-view or hardlinks: resolve the needed include closure."""
    kernel = out / 'inputs/kernel'
    entries = json.loads((ROOT / 'source-layout.json').read_text())['files']
    native = {e['native_path']: ROOT / e['source'] for e in entries
              if e.get('component') == 'linux'}
    stack_rel = 'tools/testing/selftests/xdev_ext_mech/xdomain'
    peer_rel = 'tools/testing/selftests/xdev_ext_mech/peer_graph'
    stack_names = ['stack_boundary.c', 'stack_x3.c', 'stack_x4.c', 'stack_x5.c',
                   'stack_family.c', 'stack_x6.c', 'stack_kernel_compat.h', 'stack_test.py',
                   'stack_nhi.c', 'stack_nhi_source.py', 'stack_nhi_compat.h',
                   'stack_nhi_boundary.h', 'stack_nhi_api.h', 'stack_cases.c']
    pending = [f'{stack_rel}/{n}' for n in stack_names]
    pending += [f'{peer_rel}/{n}' for n in ('xdomain_retention_fixture.py',
                                         'xdomain_ring_test.py', 'xdomain_fixture.py')]
    pending += ['drivers/thunderbolt/nhi.c', 'include/linux/thunderbolt.h',
                'io_uring/family/xdev_ext_requester_retention.c', 'io_uring/xdev_ext_mech.c',
                'io_uring/xdomain/xdev_ext_xdomain_probe.c']
    copied = {}
    include = re.compile(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]', re.M)
    while pending:
        name = pending.pop()
        if name in copied:
            continue
        source = native[name]
        data = source.read_bytes()
        copied[name] = {'source': str(source.relative_to(ROOT)),
                        'sha256': hashlib.sha256(data).hexdigest()}
        dest = kernel / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        if source.suffix not in ('.c', '.h'):
            continue
        for inc in include.findall(data.decode()):
            # Project definitions stay real; Linux OS facilities use the shared facade.
            possibilities = [os.path.normpath(str(Path(name).parent / inc)), inc,
                             'include/' + inc, 'include/uapi/' + inc,
                             'tools/xdev_ext_mech/' + inc]
            for candidate in possibilities:
                if candidate in native:
                    pending.append(candidate)
                    break
    lock = json.loads((ROOT / 'third_party/sources.lock.json').read_text())
    commit = lock['components']['linux']['commit']
    upstream = ROOT / f'tests/support/fixtures/upstream/linux-{commit}/nhi_regs.h'
    dest = kernel / 'drivers/thunderbolt/nhi_regs.h'
    dest.write_bytes(upstream.read_bytes())
    copied['drivers/thunderbolt/nhi_regs.h'] = {
        'source': str(upstream.relative_to(ROOT)),
        'sha256': hashlib.sha256(upstream.read_bytes()).hexdigest()}
    (out / 'source-units.json').write_text(json.dumps(copied, indent=2) + '\n')
    (out / 'fixture-inputs.json').write_text(json.dumps({
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in ('run.py', 'cases.c', 'wire_cases.c', 'README.md')}, indent=2) + '\n')
    return kernel, kernel / stack_rel


def mutate(kernel,out,name):
    path=kernel/'io_uring/xdomain/xdev_ext_xdomain_class.c'
    source=path.read_text()
    helper=module('early_mutation_definition',kernel/'tools/testing/selftests/xdev_ext_mech/peer_graph/xdomain_fixture.py')
    edits=[]
    def change(old,new):
        nonlocal source
        if old not in source: raise ValueError('mutation anchor absent: '+name)
        source=source.replace(old,new,1);edits.append(dict(old=old,new=new))
    if name in ('pair','shape'):
        fn='xd_early_pair_match' if name=='pair' else 'xd_early_shape_match'
        old=helper.definition(source,fn)
        change(old,old[:old.index('{')]+'{ (void)xs;(void)m;return true; }')
    elif name=='key':
        change('xs->grant.key == xdev_ext_mech_batch_key(s->batch)','true')
        change('xs->grant.key != xdev_ext_mech_batch_key(b)','false')
    elif name=='single_posted':
        change('!xs->posted_groups &&','true &&')
    elif name=='ack_chain_guard':
        change('!r->chain_done || status || r->sequestered','false || status || r->sequestered')
    elif name=='ack_chain_boundary':
        old=helper.definition(source,'xdev_ext_xd_class_batch_end')
        new=old[:old.rfind('}')]+ '\nxdev_ext_xd_class_batch_release(st,b,false);\n}'
        prototype='static void xdev_ext_xd_class_batch_release(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,bool);\n'
        change(old,prototype+new)
    else: raise ValueError('unknown mutation '+name)
    path.write_text(source)
    (out/'mutation.json').write_text(json.dumps(dict(name=name,source='io_uring/xdomain/xdev_ext_xdomain_class.c',edits=edits),indent=2)+'\n')


def prepare(kernel, stack, out, sanitize=False):
    shared = module('early_shared_stack', stack / 'stack_test.py')
    facade = out / 'facade'
    shared.facade(kernel, facade)
    module('early_nhi_source', stack / 'stack_nhi_source.py').generate(kernel, facade)
    compat=stack/'stack_kernel_compat.h'
    compat.write_text(compat.read_text().replace('#define STACK_CTL_BYTES 256','#define STACK_CTL_BYTES 512'))
    # Environment plumbing: add the class flag to actual bind input. No policy
    # branch or protocol action is selected by the adapter.
    boundary = stack / 'stack_boundary.c'
    text = boundary.read_text()
    text = text.replace('.arg1=0};', '.arg1=0,.flags=early_flags};')
    text = '#include <pthread.h>\nstatic unsigned early_flags;\nstatic int early_wait_grant,early_race_mode;\nstatic unsigned early_grant_waits,early_race_hits,early_ack_during_post,early_callbacks_during_post;\nstatic int early_lease_fail_after,early_lease_fail_endpoint,early_lease_attempts;\nstatic pthread_barrier_t early_race_barrier;\n' + text
    if 'u64 xdev_ext_mech_batch_key(' not in text:
        text += '\nu64 xdev_ext_mech_batch_key(const struct xdev_ext_mech_batch *b){return b->key;}\n'
    text=text.replace('unsigned e=f->endpoint;','unsigned e=f->endpoint;\n if(early_lease_fail_after&&e==(unsigned)early_lease_fail_endpoint&&++early_lease_attempts>early_lease_fail_after)return -ENOMEM;',1)
    text += r'''
int early_override_grant_wait(void) { if(early_wait_grant){early_grant_waits++;return 1;}return 0; }
int early_netfam_lease(struct xdev_ext_netfam_stage *ns,struct xdev_ext_net_slot *slot,
                      u32 i,u64 off,u32 len,u32 buf_len)
{
 int ret=xdev_ext_netfam_lease(ns,slot,i,off,len,buf_len);
 if(!ret&&!ns->rx&&early_race_mode==4&&i==3){world->now+=31000000000ULL;jiffies=nsecs_to_jiffies(world->now);early_race_hits++;early_race_mode=0;}
 if(!ret&&!ns->rx&&early_race_mode==1&&i==3){
  assert(!stack_spins&&!stack_mutexes);early_race_hits++;
  pthread_barrier_wait(&early_race_barrier);pthread_barrier_wait(&early_race_barrier);
 }
 return ret;
}
int early_netfam_post(struct xdev_ext_netfam_stage *ns,struct xdev_ext_net_slot *slot)
{
 int ret=xdev_ext_netfam_post(ns,slot);
 if(!ret&&!ns->rx&&(early_race_mode==2||early_race_mode==3)){
  assert(!stack_spins&&!stack_mutexes);early_race_hits++;int mode=early_race_mode;early_race_mode=0;
  struct epoch *tx=world->side[0].current;u64 saved=tx->next_progress;
  tx->next_progress=UINT64_MAX;tx->s.kicked=false;
  assert(stack_pump(world,12000,1000000)==0);
  if(mode==2){assert(stack_release(world,1,37)==0);
   tx->next_progress=UINT64_MAX;tx->s.kicked=false;
   assert(stack_pump(world,12000,1000000)==0);}
  for(size_t i=0;i<world->logs;i++)
   if(world->log[i].kind==STACK_EV_CONTROL_RX&&world->log[i].endpoint==0&&world->log[i].control_type==3)early_ack_during_post++;
  for(size_t i=0;i<world->logs;i++)
   if(world->log[i].kind==STACK_EV_DATA_CALLBACK&&world->log[i].endpoint==0)early_callbacks_during_post++;
  tx->next_progress=saved;tx->s.kicked=true;
 }
 return ret;
}
'''
    text += '\n' + (HERE / 'cases.c').read_text()
    boundary.write_text(text)
    # Host invocation storage bridges the real reference BPF into the actual
    # class. This is explicitly not a private-kfunc/verifier certification.
    x6 = stack / 'stack_x6.c'
    bridge = x6.read_text()
    if 'XDEV_EXT_XDOMAIN_PROTO_V2_VERSION' in (kernel / 'include/uapi/linux/xdev_ext_mech.h').read_text():
        bridge = bridge.replace('.raw_len = sizeof(*info),', '.raw_len = args->info_size,')
        bridge = bridge.replace('memcpy(event.raw, info, sizeof(*info));', 'memcpy(event.raw, info, args->info_size);')
        if 'static int stack_x6_v2_verdict_decode(' in bridge:
            # Shared host storage now owns the versioned bridge. Preserve the
            # test-only grant-wait hook around that exact validation path.
            signature = 'int bpf_xdev_ext_xdomain_verdict_v2('
            if bridge.count(signature) != 1:
                raise ValueError('shared v2 verdict boundary changed')
            bridge = bridge.replace(signature, 'static int early_shared_xdomain_verdict_v2(', 1)
            bridge += r'''
extern int early_override_grant_wait(void);
int bpf_xdev_ext_xdomain_verdict_v2(const struct xdev_ext_mech_ctx *ctx,const void *in,__u32 size)
{
 struct xdev_ext_xdomain_proto_verdict verdict;
 int ret=stack_x6_v2_verdict_decode(ctx,in,size,&verdict);
 if(ret)return ret;
 if(active->info_size==sizeof(struct xdev_ext_xdomain_proto_info_v2)&&
    ((const struct xdev_ext_xdomain_proto_info *)active->info)->event==22&&early_override_grant_wait()){
  verdict.action=XDEV_EXT_XDP_ACT_WAIT;verdict.status=0;verdict.credit=0;
  verdict.wake_ns=ktime_get_boottime_ns()+1000000;
 }
 verdict.version=XDEV_EXT_XDOMAIN_PROTO_V2_VERSION;
 return early_shared_xdomain_verdict_v2(ctx,&verdict,sizeof(verdict));
}
'''
        else:
            bridge += r'''
extern int early_override_grant_wait(void);
int bpf_xdev_ext_xdomain_info_v2(const struct xdev_ext_mech_ctx *ctx,void *out,__u32 size)
{
 struct xdev_ext_xdomain_proto_info_v2 *p=out;
 if(!active||ctx!=active_ctx||!active->xdomain||size!=320)return -EINVAL;
 if(active->info_size!=256&&active->info_size!=320)return -EPROTO;
 memset(out,0,size);memcpy(out,active->info,active->info_size);
 p->base.size=320;p->base.version=2;return 0;
}
int bpf_xdev_ext_xdomain_verdict_v2(const struct xdev_ext_mech_ctx *ctx,const void *in,__u32 size)
{
 struct xdev_ext_xdomain_proto_verdict v;
 if(!active||ctx!=active_ctx||!active->xdomain||size!=64)return -EINVAL;
 memcpy(&v,in,64);
 if(v.size!=64||v.version!=2)return -EPROTO;
 if(active->info_size==320&&((const struct xdev_ext_xdomain_proto_info *)active->info)->event==22&&early_override_grant_wait()){
  v.action=XDEV_EXT_XDP_ACT_WAIT;v.status=0;v.credit=0;v.wake_ns=ktime_get_boottime_ns()+1000000;
 }
 if(active->info_size==256){if(v.action>17)return -EPROTO;v.version=1;}
 return bpf_xdev_ext_xdomain_verdict(ctx,&v,size);
}
'''
    x6.write_text(bridge)
    x5=stack/'stack_x5.c'
    unit=x5.read_text()
    unit=unit.replace('#include "../../../../../io_uring/xdomain/xdev_ext_xdomain_class.c"',
        'int early_netfam_lease(struct xdev_ext_netfam_stage *,struct xdev_ext_net_slot *,u32,u64,u32,u32);\n'
        'int early_netfam_post(struct xdev_ext_netfam_stage *,struct xdev_ext_net_slot *);\n'
        '#define xdev_ext_netfam_lease early_netfam_lease\n'
        '#define xdev_ext_netfam_post early_netfam_post\n'
        '#include "../../../../../io_uring/xdomain/xdev_ext_xdomain_class.c"')
    x5.write_text(unit)
    sources = [stack / n for n in ('stack_boundary.c', 'stack_x3.c', 'stack_x4.c',
        'stack_x5.c', 'stack_family.c', 'stack_x6.c', 'stack_nhi.c')]
    probe = out / 'startup-probe.c'
    probe.write_text('#define STACK_INTERNAL\n#include "stack_kernel_compat.h"\n'
        '#include "stack_nhi_api.h"\n#define tb_ring_tx stack_ring_tx\n'
        '#define tb_ring_rx stack_ring_rx\n#include "' +
        str(kernel / 'io_uring/xdomain/xdev_ext_xdomain_probe.c') + '"\n')
    sources.append(probe)
    command = ['gcc', '-std=gnu11', '-O0', '-g', '-DSTACK_REAL_NHI',
        '-DSTACK_STARTUP_EVENTS', '-Wall', '-Wextra', '-Werror=implicit-function-declaration',
        '-Wno-unused-function', '-Wno-unused-parameter', '-pthread', '-I', str(facade),
        '-I', str(stack), '-I', str(kernel), '-idirafter', str(kernel / 'include'),
        '-idirafter', str(kernel / 'include/uapi'), '-I', str(kernel / 'tools/xdev_ext_mech')]
    if sanitize:
        command += ['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
    command += [str(s) for s in sources] + ['-o', str(out / 'early-cts')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    (out / 'compile.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        print('EARLY_SETUP_ERROR: behavior not executed\n' + result.stderr)
        return False
    return True


def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case')
    parser.add_argument('--sanitize',action='store_true')
    parser.add_argument('--mutation',choices=['pair','shape','key','single_posted','ack_chain_guard','ack_chain_boundary'])
    args = parser.parse_args()
    ROOT = args.source_root.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    kernel, stack = assemble(out)
    if args.mutation:
        mutate(kernel,out,args.mutation)
    if args.case != 'wire' and not prepare(kernel, stack, out, args.sanitize):
        (out/'result.json').write_text(json.dumps(dict(status='setup-error',
            scope='host actual NHI/XDOMAIN composition', hardware=False,
            kernel_execution=False, compile_exit=1, cases=[]),indent=2)+'\n')
        return 2
    cases = ['opt_in', 'default_v1', 'early_happy', 'short_tail', 'ack_before_local',
        'delayed_peer_create', 'missing_confirm', 'unbound_wait_deadline', 'wrong_key',
        'wrong_shape', 'wrong_bind', 'old_inc', 'skip_group', 'same_count_shape',
        'wrong_seq', 'bad_reserved', 'bad_crc', 'duplicate_cts', 'stop_available',
        'armed_ticket','armed_pool','stop_before_post','old_bind','tx_before_grant',
        'zero_key','mixed_v1_tx','mixed_v1_rx','available_deadline','single_posted',
        'batch_end_only','consumer_error','consumer_sequester','unknown_stop',
        'control_full','bind_exhaustion','seq_overflow','window_reuse66','receipt_deadline','stop_after_lease','ack_before_post_return','local_before_post_return','partial_tx_lease','facts_selected_slot','facts_ack_key','pending_deadline','stop_pending_grant','first_cts_pair','first_cts_shape','expired_submit','expired_after_lease']
    if args.case:
        cases = [] if args.case == 'wire' else [args.case]
    records=[]
    print('TAP version 13\n1..' + str(len(cases)+(not args.case or args.case=='wire')), flush=True)
    for i, case in enumerate(cases, 1):
        r = subprocess.run([str(out / 'early-cts'), case], capture_output=True, text=True, timeout=30)
        log = r.stdout+r.stderr
        (out / (case+'.log')).write_text(log+'\nruntime_exit='+str(r.returncode)+'\n')
        ok = r.returncode == 0 and 'EARLY_ASSERTIONS ' in log
        semantic_red = r.returncode == 1 and 'STACK_ASSERT ' in log
        records.append(dict(case=case, runtime_exit=r.returncode, passed=ok,
            failure_kind=None if ok else 'behavioral' if semantic_red else 'runtime-error'))
        print(('ok ' if ok else 'not ok ')+str(i)+' - '+case+'\n'+log, flush=True)
    if not args.case or args.case == 'wire':
        wire_command=['gcc','-std=gnu11','-Wall','-Wextra','-I',str(kernel),
            '-I',str(kernel/'include/uapi'),str(HERE/'wire_cases.c'),'-o',str(out/'early-wire')]
        build=subprocess.run(wire_command,capture_output=True,text=True,timeout=30)
        (out/'wire-compile.log').write_text(build.stdout+build.stderr)
        if build.returncode:
            records.append(dict(case='wire',runtime_exit=None,passed=False,setup_error=True))
            print('not ok '+str(len(cases)+1)+' - wire # SETUP_ERROR behavior not executed',flush=True)
        else:
            r=subprocess.run([str(out/'early-wire')],capture_output=True,text=True,timeout=30)
            (out/'wire.log').write_text(r.stdout+r.stderr+'\n')
            records.append(dict(case='wire',runtime_exit=r.returncode,passed=r.returncode==0,
                failure_kind=None if r.returncode==0 else 'behavioral' if r.returncode==1 and 'EARLY_WIRE_ASSERT ' in r.stderr else 'runtime-error'))
            print(('ok ' if r.returncode==0 else 'not ok ')+str(len(cases)+1)+' - wire\n'+r.stdout+r.stderr,flush=True)
    failed=any(not r['passed'] for r in records)
    setup_error=any(r.get('setup_error') or r.get('failure_kind')=='runtime-error' for r in records)
    (out/'result.json').write_text(json.dumps(dict(status='setup-or-runtime-error' if setup_error else 'behavioral-red' if failed else 'pass',
        scope='host actual NHI/XDOMAIN composition', hardware=False, kernel_execution=False,
        compile_exit=0, sanitize=args.sanitize, cases=records), indent=2)+'\n')
    return int(failed)

if __name__ == '__main__':
    sys.exit(main())

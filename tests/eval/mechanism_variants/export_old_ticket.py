#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Export the existing actual-core recycle/old-ticket host fixture observation.

Native submission and OS scheduling retain that fixture's explicit host
boundaries. The production lifecycle, scheduler and completion entrance are
extracted unchanged by its existing generate(). This is never guest evidence.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

SNAPSHOT=r'''
static void e2_snapshot(const char *phase,struct xdev_ext_mech_session *s,
 struct xdev_ext_mech_batch *b,struct xdev_ext_mech_life *life,u8 custody,u64 oldticket) {
 printf("E2_OLD_TICKET_SNAPSHOT {\"phase\":\"%s\",\"old_ticket\":%llu,\"current_ticket\":%llu,\"accepted\":%u,\"published\":%llu,\"state\":{\"life_ctrl\":%llu,\"life_phase\":%u,\"life_refs\":%u,\"life_busy\":%u,\"life_owner\":%u,\"life_gen\":%llu,\"valid_len\":%u,\"completion_ctrl\":%llu,\"completion_result\":%d,\"ticket\":%llu,\"queued\":%u,\"life_active\":%u,\"life_token\":%llu,\"frame_custody\":%u,\"present\":%u,\"status\":%d,\"retired\":%u,\"released\":%u}}\n",
 phase,(unsigned long long)oldticket,(unsigned long long)b->ticket,accepts[0],
 (unsigned long long)s->cnt[XDEV_EXT_MECH_CNT_PUBLISHED],(unsigned long long)life->ctrl,
 xdev_ext_mech_life_phase(life),xdev_ext_mech_life_refs(life),xdev_ext_mech_life_busy(life),
 xdev_ext_mech_life_owner(life),(unsigned long long)xdev_ext_mech_life_gen(life),life->valid_len,
 (unsigned long long)b->completion.ctrl,b->completion.result,(unsigned long long)b->ticket,
 b->queued,b->life_active,(unsigned long long)b->life_token[0],custody,b->present,b->status,ends,released);
}
'''


def run(kernel,out,cc):
    kernel=kernel.resolve(); out=out.resolve()
    if out.exists(): raise ValueError('refuse existing software-evidence directory')
    here=kernel/'tools/testing/selftests/xdev_ext_mech/fanout_scheduler'
    original=kernel/'tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/recycle_input_test.py'
    # Read the established testcase instead of restating its lifecycle decisions.
    tree=ast.parse(original.read_text())
    assignment=next(node for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='case' for t in node.targets))
    case=assignment.value.func.value.value
    needle='u64 word=life.ctrl;xdev_ext_mech_batch_complete(&b,oldticket,0);'
    if case.count(needle)!=1: raise ValueError('existing fixture entrance changed; audit before adapting')
    os.environ['KERNEL_SRC']=str(kernel)
    spec=importlib.util.spec_from_file_location('e2_actual_core_generator',here/'run.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    core=(kernel/'io_uring/xdev_ext_mech.c').read_text()
    name='xdev_ext_mech_start_publication'
    body=module.definition(core,name)
    case=case.replace('START_PUBLICATION','REQUIRE(!'+name+'(&s,&b),"CPU input republished after allocator custody");')
    case=case.replace(needle,'u64 word=life.ctrl;e2_snapshot("before",&s,&b,&life,custody,oldticket);\n'+
                      'xdev_ext_mech_batch_complete(&b,oldticket,0);\n'+
                      'e2_snapshot("after",&s,&b,&life,custody,oldticket);')
    source=module.generate().replace('int main(int argc,char**argv)','int baseline_main(int argc,char**argv)')
    source=source+'\n'+body+SNAPSHOT+case
    out.mkdir(parents=True,mode=0o700)
    cfile=out/'old-ticket-fixture.c'; binary=out/'old-ticket-fixture'
    cfile.write_text(source)
    command=shlex.split(cc)+['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
      '-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter',
      '-fsanitize=undefined','-fno-sanitize-recover=undefined','-pthread','-I'+str(kernel),
      '-I'+str(here),str(cfile),'-o',str(binary)]
    build=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/'build.log').write_text(build.stdout)
    (out/'command.json').write_text(json.dumps(command,indent=2)+'\n')
    if build.returncode: raise ValueError('actual fixture build failed; see build.log')
    actual=subprocess.run([str(binary)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20)
    (out/'old-ticket.log').write_text(actual.stdout)
    if actual.returncode: raise ValueError('actual old-ticket fixture failed')
    observations=[json.loads(line.split(' ',1)[1]) for line in actual.stdout.splitlines() if line.startswith('E2_OLD_TICKET_SNAPSHOT ')]
    if len(observations)!=2 or [x['phase'] for x in observations]!=['before','after']:
        raise ValueError('missing actual before/after observations')
    before,after=observations
    if before['old_ticket']==before['current_ticket'] or before['state']!=after['state'] or before['accepted']!=after['accepted'] or before['published']!=after['published']:
        raise ValueError('old ticket changed current custody or acceptance/publication')
    negative=dict(entry='xdev_ext_mech_batch_complete',evidence_kind='actual-core-host-fixture',
       old_ticket=before['old_ticket'],current_ticket=before['current_ticket'],
       accepted_before=before['accepted'],accepted_after=after['accepted'],
       published_before=before['published'],published_after=after['published'],
       current_state_before=before['state'],current_state_after=after['state'],trace='old-ticket.log')
    (out/'old_ticket.json').write_text(json.dumps(negative,indent=2)+'\n')
    paths=[kernel/'io_uring/xdev_ext_mech.c',original,here/'run.py',here/'fixture.c',here/'shim.h']
    paths+=list((kernel/'io_uring').glob('xdev_ext_mech*.h'))+[kernel/'include/linux/xdev_ext_mech.h',kernel/'include/uapi/linux/xdev_ext_mech.h']
    ledger={str(p.relative_to(kernel)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    sha=subprocess.check_output(['git','-C',str(kernel),'rev-parse','HEAD'],text=True).strip()
    (out/'source.json').write_text(json.dumps(dict(kernel_git_sha=sha,evidence_kind='actual-core-host-fixture',source_sha256=ledger),indent=2)+'\n')
    return negative


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('kernel',type=Path); p.add_argument('output',type=Path)
    p.add_argument('--cc',default=os.environ.get('CC','cc')); a=p.parse_args()
    try: result=run(a.kernel,a.output,a.cc)
    except (OSError,ValueError,RuntimeError,StopIteration,subprocess.SubprocessError) as exc:
        p.exit(1,f'E2 actual-core software export FAIL: {exc}\n')
    print(f'E2_OLD_TICKET_HOST=PASS old_ticket={result["old_ticket"]} current_ticket={result["current_ticket"]} evidence=actual-core-host-fixture')
if __name__=='__main__': main()

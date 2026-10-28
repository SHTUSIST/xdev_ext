#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual registry -> admission/STOP/core worker -> XDOMAIN stop epoch tests."""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile
import xdomain_class_test as extract
import xdomain_review_protocol_test as fixture
HERE=Path(__file__).resolve().parent
CASES=('withdrawal_gap','late_stop','near_hard','stop_zero','overdue_armed','normal_stop_reason')

def source(kernel):
    s=fixture.source(kernel,HERE)
    core=(kernel/'io_uring/xdev_ext_mech.c').read_text()
    # New production helper delegates to the same actual session_stop body.
    # Pull it into this TU without replacing STOP or the timestamp accessor.
    stop_body=extract.function(core,'xdev_ext_mech_session_stop')
    helper=extract.function(core,'xdev_ext_mech_stage_stop') if '\nvoid xdev_ext_mech_stage_stop(' in core else ''
    if s.count(stop_body)!=1:raise ValueError('actual session STOP composition changed')
    if helper and helper not in s:s=s.replace(stop_body,stop_body+'\n'+helper)
    # Mcore START queue fields are real but this regression has no ordered
    # START loan. Fail closed if an unrelated queue-release boundary is entered.
    if 'struct xdev_ext_mech_start_queue *start_queue;' not in s:s=s.replace(' u64 stop_started_ns;', ' u64 stop_started_ns;\n struct xdev_ext_mech_start_queue *start_queue;\n bool start_ordered;')
    if ' bool ordered_loan;' not in s:s=s.replace(' unsigned claims,publishes,filled,ended,disposition_order;', ' bool ordered_loan;\n unsigned claims,publishes,filled,ended,disposition_order;')
    boundary='static int xdev_ext_mech_start_queue_release(struct xdev_ext_mech_session *s, struct xdev_ext_mech_batch *b, bool reusable) { (void)s;(void)b;(void)reusable;assert(!"ordered START queue outside STOP epoch scope");return -EOPNOTSUPP; }\n'
    if 'static int xdev_ext_mech_start_queue_release(' not in s:s=s.replace('enum xdev_ext_mech_end {',boundary+'enum xdev_ext_mech_end {',1)

    ops=(kernel/'io_uring/xdev_ext_mech_ops.c').read_text()
    registry=(kernel/'io_uring/xdev_ext_ops_core.c').read_text()
    registry_header=(kernel/'io_uring/xdev_ext_ops_core.h').read_text()
    old=' u64 stop_started_ns;'
    if s.count(old)!=1:raise ValueError('session scalar boundary changed')
    # Add actual private field declarations needed by the real admission and
    # generation notifier. Their production function bodies stay unchanged.
    private=extract.struct(core,'xdev_ext_mech_session')
    import re
    fields=[]
    for pattern in (r'const void \*ops\[XDEV_EXT_MECH_CLASS_MAX\];',r'bool pinned\[XDEV_EXT_MECH_CLASS_MAX\];',r'struct list_head all_node;'):
        match=re.search(pattern,private)
        if not match:raise ValueError('actual session field absent: '+pattern)
        fields.append(match.group())
    s=s.replace(old,old+'\n'+'\n'.join(fields))
    old='static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s) { return s->ss.state==XDEV_EXT_MECH_SESSION_ACTIVE; }'
    environment='''
#define __rcu
#define rcu_access_pointer(p) (p)
#define rcu_assign_pointer(p,v) ((p)=(v))
#define static_branch_disable(p) ((void)(p))
#define list_for_each_entry(pos,head,member) \\
 for((pos)=container_of((head)->next,typeof(*(pos)),member); &(pos)->member!=(head); \\
     (pos)=container_of((pos)->member.next,typeof(*(pos)),member))
static void (*stop_epoch_rcu_hook)(void);
static unsigned stop_epoch_rcu_calls;
static void synchronize_rcu(void) {
 assert(!held_spinlocks&&!held_mutexes);stop_epoch_rcu_calls++;
 if(stop_epoch_rcu_hook)stop_epoch_rcu_hook();
}
'''
    bodies=(extract.struct(registry_header,'xdev_ext_ops_registry')+
        '\nstatic const void *stop_epoch_registry_slots[XDEV_EXT_MECH_CLASS_MAX];\n'+
        'static struct xdev_ext_ops_registry xdev_ext_mech_registry={.slots=stop_epoch_registry_slots,.nr_slots=XDEV_EXT_MECH_CLASS_MAX};\n'+
        'static spinlock_t xdev_ext_mech_all_lock;\nstatic struct list_head xdev_ext_mech_all;\n'+
        'void xdev_ext_mech_generation_gone(u32 class_id,const void *ops);\n'+
        extract.function(registry_header,'xdev_ext_ops_is_current')+
        extract.function(registry,'xdev_ext_ops_retract')+
        extract.function(ops,'xdev_ext_mech_ops_current')+
        extract.function(core,'xdev_ext_mech_session_admits')+
        extract.function(ops,'xdev_ext_mech_unreg'))
    if s.count(old)!=1:raise ValueError('admission boundary changed')
    s=s.replace(old,environment+bodies)
    before,token,after=s.rpartition('int main(int argc,char **argv)')
    if not token:raise ValueError('terminal main absent')
    return (before+'int stop_epoch_unused_terminal_main(int argc,char **argv)'+after+'\n'+
        extract.function(core,'xdev_ext_mech_generation_gone')+'\n'+
        (HERE/'xdomain_review_stop_epoch_cases.c').read_text())

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,default=HERE.parents[4]);p.add_argument('--artifact-directory',type=Path);p.add_argument('--case',choices=CASES,action='append');a=p.parse_args()
    ctx=nullcontext(str(a.artifact_directory.resolve())) if a.artifact_directory else tempfile.TemporaryDirectory(prefix='xdomain-stop-epoch-')
    if a.artifact_directory:a.artifact_directory.mkdir(parents=True,exist_ok=True)
    with ctx as directory:
        out=Path(directory);src=out/'stop-epoch.c';binary=out/'stop-epoch';src.write_text(source(a.kernel.resolve()))
        command=['gcc','-std=gnu11','-O1','-g','-pthread','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(a.kernel.resolve()),str(src),'-o',str(binary)]
        print('COMMAND:',' '.join(command),flush=True);subprocess.run(command,check=True)
        failed=0
        for case in a.case or CASES:
            run=subprocess.run([str(binary),case],timeout=20)
            print(f"{'not ok' if run.returncode else 'ok'} - {case}; exit={run.returncode}",flush=True);failed+=bool(run.returncode)
        return bool(failed)
if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
        print('STOP EPOCH SETUP FAILURE:',error,file=sys.stderr);sys.exit(2)

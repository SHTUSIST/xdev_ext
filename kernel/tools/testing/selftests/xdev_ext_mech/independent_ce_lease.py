#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual CE registry functions, including fork, ABBA and quarantine.

Only kernel list/allocation/locking primitives are replaced by host equivalents.
The production ownership helpers and registry functions are compiled unchanged.
"""
from pathlib import Path
import argparse
import resource
import subprocess
import sys
import tempfile

KERNEL = Path(__file__).resolve().parents[4]


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


SHIM = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
typedef uint64_t u64;
typedef uint32_t u32;
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n={&(n),&(n)}
#define INIT_LIST_HEAD(n) do {(n)->next=(n);(n)->prev=(n);}while(0)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) \
 for(p=container_of((h)->next,__typeof__(*p),m); &p->m!=(h); \
 p=container_of(p->m.next,__typeof__(*p),m))
static void list_add_tail(struct list_head *n,struct list_head *h)
{n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
static bool list_empty(struct list_head *h){return h->next==h;}
#define mutex_lock pthread_mutex_lock
#define mutex_unlock pthread_mutex_unlock
static pthread_mutex_t *xdev_ext_ce_lease_mutex;
#define xdev_ext_ce_lease_lock (*xdev_ext_ce_lease_mutex)
static LIST_HEAD(xdev_ext_ce_lease_groups);
static unsigned warnings;
#define WARN_ON_ONCE(x) ((x)?(++warnings,true):false)
#define GFP_KERNEL 0
#define struct_size(p,m,n) (sizeof(*(p))+sizeof((p)->m[0])*(n))
static bool fail_allocation;
struct allocation {size_t len; max_align_t alignment; unsigned char data[];};
static void *kvzalloc(size_t size,int flags)
{
 (void)flags;if(fail_allocation)return NULL;
 struct allocation *a=mmap(NULL,sizeof(*a)+size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
 assert(a!=MAP_FAILED);a->len=sizeof(*a)+size;return a->data;
}
static void kvfree(void *p){struct allocation *a=container_of(p,struct allocation,data);assert(!munmap(a,a->len));}
struct xdev_ext_mech_session {u32 depth;};
struct xdev_ext_mech_batch {u32 slot;u64 generation;};
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;void *priv;};
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s){return s->depth;}
static u32 xdev_ext_mech_batch_slot(struct xdev_ext_mech_batch *b){return b->slot;}
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b){return b->generation;}
'''
STAGE = r'''
struct xdev_ext_ce_stage {
 struct list_head lease_node;
 struct xdev_ext_ce_lease_group *lease_group;
 u64 window_start;
 struct {const void *ops;u64 len;} region;
};
'''
MAIN = r'''
static const int provider;
static void bind_window(struct xdev_ext_mech_stage *st,struct xdev_ext_ce_stage *cs,u64 start,u64 len)
{st->priv=cs;cs->region.ops=&provider;cs->region.len=len;assert(!xdev_ext_ce_lease_bind(st,cs,start));}
static void bind_region(struct xdev_ext_mech_stage *st,struct xdev_ext_ce_stage *cs,u64 start)
{bind_window(st,cs,start,4096);}
static void same_base_preserves_depth(void)
{
 struct xdev_ext_mech_session session={8};
 struct xdev_ext_ce_stage regions[2]={0};
 struct xdev_ext_mech_stage stages[2]={{.s=&session},{.s=&session}};
 struct xdev_ext_mech_batch batches[8];
 bind_window(&stages[0],&regions[0],131072,65536);
 bind_window(&stages[1],&regions[1],131072,65536);
 for(unsigned i=0;i<8;i++) {
  batches[i]=(struct xdev_ext_mech_batch){.slot=i,.generation=1+i};
  assert(!xdev_ext_ce_lease_get(&regions[0],&batches[i]));
  assert(!xdev_ext_ce_lease_get(&regions[1],&batches[i]));
 }
 assert(regions[0].lease_group->state.active_batches==8);
 for(unsigned i=0;i<8;i++) {
  xdev_ext_ce_batch_release(&stages[0],&batches[i],false);
  xdev_ext_ce_batch_release(&stages[1],&batches[i],false);
 }
 assert(xdev_ext_ce_lease_unbind(&regions[1]));
 assert(xdev_ext_ce_lease_unbind(&regions[0]));
 assert(list_empty(&xdev_ext_ce_lease_groups));
}
static void shifted_windows_serialize_slots(void)
{
 struct xdev_ext_mech_session session={2};
 struct xdev_ext_ce_stage regions[2]={0};
 struct xdev_ext_mech_stage stages[2]={{.s=&session},{.s=&session}};
 struct xdev_ext_mech_batch first={.slot=0,.generation=1},next={.slot=1,.generation=2};
 struct xdev_ext_ce_geom geom;
 struct xdev_ext_ce_plan plan;
 struct xdev_ext_mech_frame_info frame={.data_off=0,.data_len=8192};
 struct xdev_ext_ce_copy_desc desc={.frame_pos=0,.frame_off=0,.gpu_off=8192,.len=8192};
 u32 index=1;
 unsigned char device[24576]={0};
 bind_window(&stages[0],&regions[0],262144,16384);
 bind_window(&stages[1],&regions[1],270336,16384);
 /* Both stage plans are individually valid, yet A slot1 aliases B slot0. */
 assert(!xdev_ext_ce_geom_init(&geom,16384,16384,0,0,16384,0,8192,2));
 assert(!xdev_ext_ce_plan_check(&geom,&frame,&index,1,&desc,1,&plan));
 index=0;desc.gpu_off=0;
 assert(!xdev_ext_ce_plan_check(&geom,&frame,&index,1,&desc,1,&plan));
 assert(regions[0].window_start+8192==regions[1].window_start);
 assert(!xdev_ext_ce_lease_get(&regions[0],&first));
 assert(!xdev_ext_ce_lease_get(&regions[1],&first));
 memset(device+8192,0x11,8192); /* First batch's still-live B slot0 payload. */
 int admission=xdev_ext_ce_lease_get(&regions[0],&next);
 if(!admission)memset(device+8192,0x22,8192); /* A slot1 native write. */
 for(unsigned i=8192;i<16384;i++)assert(device[i]==0x11);
 assert(admission==-EAGAIN);
 assert(regions[0].lease_group->state.active_batches==1);
 xdev_ext_ce_batch_release(&stages[0],&first,false);
 xdev_ext_ce_batch_release(&stages[1],&first,false);
 assert(!regions[0].lease_group->state.active_batches);
 assert(!xdev_ext_ce_lease_get(&regions[0],&next));
 assert(!xdev_ext_ce_lease_get(&regions[1],&next));
 memset(device+8192,0x22,8192);
 for(unsigned i=8192;i<16384;i++)assert(device[i]==0x22);
 xdev_ext_ce_batch_release(&stages[0],&next,false);
 xdev_ext_ce_batch_release(&stages[1],&next,false);
 first.generation=3;next.generation=4;
 assert(!xdev_ext_ce_lease_get(&regions[0],&first));
 xdev_ext_ce_batch_release(&stages[0],&first,true);
 xdev_ext_ce_batch_release(&stages[1],&first,true);
 assert(xdev_ext_ce_lease_get(&regions[0],&next)==-EBUSY);
 assert(regions[0].lease_group->state.active_batches==1);
 assert(!xdev_ext_ce_lease_unbind(&regions[1]));
 assert(!xdev_ext_ce_lease_unbind(&regions[0]));
 puts("ok - actual CE registry: valid shifted-window plans serialize slots, preserve payload, retry after final release and retain unknown ownership");
}
int main(void)
{
 pthread_mutexattr_t attr;pid_t child;int status;
 struct xdev_ext_mech_session sa={8},sb={8},failed={8};
 struct xdev_ext_ce_stage ar[2]={0},br[2]={0},fr={0};
 struct xdev_ext_mech_stage a[2]={{.s=&sa},{.s=&sa}},b[2]={{.s=&sb},{.s=&sb}},f={.s=&failed};
 struct xdev_ext_mech_batch batch[8],other={.slot=0,.generation=77};
 assert(!pthread_mutexattr_init(&attr));assert(!pthread_mutexattr_setpshared(&attr,PTHREAD_PROCESS_SHARED));
 /* The kernel registry is global across processes; allocate its lock shared too. */
 pthread_mutex_t *shared=mmap(NULL,sizeof(*shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
 assert(shared!=MAP_FAILED);assert(!pthread_mutex_init(shared,&attr));
 xdev_ext_ce_lease_mutex=shared;
 same_base_preserves_depth();
 fail_allocation=true;assert(xdev_ext_ce_lease_bind(&f,&fr,0)==-ENOMEM);fail_allocation=false;
 assert(list_empty(&xdev_ext_ce_lease_groups)); /* Failed CREATE registered nothing. */
 bind_region(&a[0],&ar[0],0);bind_region(&a[1],&ar[1],8192);
 bind_region(&b[0],&br[0],8192);bind_region(&b[1],&br[1],0); /* Reversed multirange order. */
 for(unsigned i=0;i<8;i++)batch[i]=(struct xdev_ext_mech_batch){.slot=i,.generation=10+i};
 assert(!xdev_ext_ce_lease_get(&ar[0],&batch[0]));
 assert(xdev_ext_ce_lease_get(&br[0],&other)==-EAGAIN); /* All ranges held before stage2. */
 assert(!br[0].lease_group->state.active_batches);
 assert(!xdev_ext_ce_lease_unbind(&ar[0])); /* Cannot unbind an active owner. */
 assert(!xdev_ext_ce_lease_get(&ar[1],&batch[0]));
 for(unsigned i=1;i<8;i++)assert(!xdev_ext_ce_lease_get(&ar[i%2],&batch[i]));
 assert(ar[0].lease_group->state.active_batches==8);
 child=fork();assert(child>=0);
 if(!child){assert(xdev_ext_ce_lease_get(&br[0],&other)==-EAGAIN);_exit(0);}
 assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
 struct xdev_ext_mech_batch stale=batch[0];stale.generation=99;
 xdev_ext_ce_batch_release(&a[0],&stale,false);
 assert(ar[0].lease_group->state.active_batches==8 && ar[0].lease_group->slots[0].generation==10);
 for(unsigned i=0;i<8;i++){xdev_ext_ce_batch_release(&a[0],&batch[i],false);xdev_ext_ce_batch_release(&a[1],&batch[i],false);}
 assert(!ar[0].lease_group->state.active_batches);
 assert(!xdev_ext_ce_lease_get(&br[0],&other)); /* Reversed order makes progress, no ABBA. */
 xdev_ext_ce_batch_release(&b[0],&other,false);xdev_ext_ce_batch_release(&b[1],&other,false);
 assert(!br[0].lease_group->state.active_batches);
 assert(xdev_ext_ce_lease_unbind(&br[1]));assert(xdev_ext_ce_lease_unbind(&br[0]));
 /* A failed native preaccept with known fate can release; an accepted unknown cannot. */
 batch[0].generation=100;assert(!xdev_ext_ce_lease_get(&ar[0],&batch[0]));
 xdev_ext_ce_batch_release(&a[0],&batch[0],false);assert(!ar[0].lease_group->state.active_batches);
 batch[0].generation=101;assert(!xdev_ext_ce_lease_get(&ar[0],&batch[0]));
 xdev_ext_ce_batch_release(&a[0],&batch[0],true);xdev_ext_ce_batch_release(&a[1],&batch[0],true);
 assert(ar[0].lease_group->state.quarantined && ar[0].lease_group->state.active_batches==1);
 assert(xdev_ext_ce_lease_get(&ar[0],&batch[0])==-EBUSY);
 bind_region(&b[0],&br[0],0);bind_region(&b[1],&br[1],8192);
 assert(xdev_ext_ce_lease_get(&br[0],&other)==-EAGAIN);
 assert(!br[0].lease_group->state.active_batches); /* Unknown retains every foreign conflict. */
 assert(xdev_ext_ce_lease_unbind(&br[1]));assert(xdev_ext_ce_lease_unbind(&br[0]));
 xdev_ext_ce_batch_release(&a[0],&batch[0],false);
 assert(!xdev_ext_ce_lease_unbind(&ar[0]) && !xdev_ext_ce_lease_unbind(&ar[1]));
 assert(ar[0].lease_group->state.active_batches==1 && warnings>=4);
 puts("ok - actual CE registry: depth8, all-range ABBA exclusion, failed bind cleanup, fork contention, stale/duplicate terminal and unknown retention");
 shifted_windows_serialize_slots();
 return 0;
}
'''


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutant', choices=('missing-get', 'early-release',
                                            'ignore-quarantine', 'first-range-only'))
    parser.add_argument('--check-mutations', action='store_true')
    args = parser.parse_args()
    if args.check_mutations:
        failures = {
            'missing-get': 'ValueError: substring not found',
            'early-release': "assert end.index('xdev_ext_mech_frames_release(') < end.index('cls->batch_release(')",
            'ignore-quarantine': 'ar[0].lease_group->state.quarantined && ar[0].lease_group->state.active_batches==1',
            'first-range-only': 'xdev_ext_ce_lease_get(&br[0],&other)==-EAGAIN',
        }
        for mutant, expected in failures.items():
            result = subprocess.run([sys.executable, '-B', __file__, '--mutant', mutant],
                                    capture_output=True, text=True, timeout=15)
            assert result.returncode != 0, 'production regression was not rejected: '+mutant
            evidence = result.stdout+result.stderr
            assert expected in evidence, evidence
            print('ok - rejected actual-function mutant '+mutant)
        return
    source = (KERNEL/'io_uring/xdev_ext_mech_ce.c').read_text()
    core = (KERNEL/'io_uring/xdev_ext_mech.c').read_text()
    if args.mutant == 'missing-get':
        source = source.replace('err = xdev_ext_ce_lease_get(cs, b);', 'err = 0;', 1)
    # Final frame disposition can turn an apparent completion into quarantine.
    end = function(core, 'static void xdev_ext_mech_end(')
    if args.mutant == 'early-release':
        start = end.index('\tfor (i = 0; i < s->nr_stages; i++)')
        stop = end.index('how == XDEV_EXT_MECH_END_SEQUESTER);', start)+len('how == XDEV_EXT_MECH_END_SEQUESTER);')
        release = end[start:stop]
        end = end[:start]+end[stop:]
        before = end.index('\tif (how != XDEV_EXT_MECH_END_SEQUESTER && xdev_ext_mech_frames_release(')
        end = end[:before]+release+'\n'+end[before:]
    assert end.index('xdev_ext_mech_frames_release(') < end.index('cls->batch_release(')
    assert end.index('cls->batch_release(') < end.index('xdev_ext_mech_batch_put_locked(')
    assert 'for (i = 0; i < s->nr_stages; i++)' in end
    assert 'how == XDEV_EXT_MECH_END_SEQUESTER' in end[end.index('cls->batch_release('):]
    group_start = source.index('struct xdev_ext_ce_lease_group {')
    group = source[group_start:source.index('\n};', group_start)+3]
    functions = ''.join(function(source, signature) for signature in (
        'static int xdev_ext_ce_lease_bind(', 'static int xdev_ext_ce_lease_get(',
        'static void xdev_ext_ce_batch_release(', 'static bool xdev_ext_ce_lease_unbind('))
    if args.mutant == 'ignore-quarantine':
        functions = functions.replace('xdev_ext_mech_batch_id(b), sequestered);',
                                      'xdev_ext_mech_batch_id(b), false);')
        # Keep the deliberately ignored parameter warning-free for this mutant.
        functions = functions.replace('int ret;\n\n\tif (WARN_ON_ONCE(slot >= group->depth))',
                                      'int ret;\n\t(void)sequestered;\n\n\tif (WARN_ON_ONCE(slot >= group->depth))')
    if args.mutant == 'first-range-only':
        functions = functions.replace('list_for_each_entry(a, &group->regions, lease_node)',
            'for (a=container_of(group->regions.next,__typeof__(*a),lease_node);a;a=NULL)')
        functions = functions.replace('list_for_each_entry(held, &other->regions, lease_node)',
            'for (held=container_of(other->regions.next,__typeof__(*held),lease_node);held;held=NULL)')
    submit = function(source, 'static int xdev_ext_ce_submit(')
    assert submit.index('xdev_ext_ce_lease_get(') < submit.index('xdev_ext_ce_cookie_arm(')
    assert submit.index('xdev_ext_ce_lease_get(') < submit.index('region.ops->submit(')
    with tempfile.TemporaryDirectory(prefix='independent-ce-lease-') as tmp:
        c, binary = Path(tmp)/'actual.c', Path(tmp)/'actual'
        headers = ('include/uapi/linux/xdev_ext_mech.h',
                   'io_uring/xdev_ext_mech_ce_core.h',
                   'io_uring/xdev_ext_mech_ce_lease.h')
        c.write_text(SHIM+''.join('\n#include "'+str(KERNEL/header)+'"\n'
                                 for header in headers)+group+STAGE+functions+MAIN)
        compiled = subprocess.run(['cc','-std=gnu11','-O1','-Wall','-Wextra','-Werror',
            '-fsanitize=undefined','-pthread',str(c),'-o',str(binary)], capture_output=True,text=True)
        assert compiled.returncode == 0, compiled.stderr
        result = subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
        print(result.stdout,end='')
        print(result.stderr,end='')
        raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()

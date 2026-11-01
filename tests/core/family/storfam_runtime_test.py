#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile actual storage runtime; no implementation or extraction may be absent."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[5]
FUNCTIONS = ('xdev_ext_stor_slot_add', 'xdev_ext_stor_slot_get',
             'xdev_ext_stor_slot_put', 'xdev_ext_stor_done')
SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "include/linux/xdev_ext_storfam_runtime.h"
#define EXPORT_SYMBOL_GPL(x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
struct xdev_ext_mech_batch { unsigned long long ticket; int claimed, views, traces, publishes, ready; };
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b, __u64 t)
{ if (t != b->ticket || b->claimed) return -ESTALE; b->claimed=1; return 0; }
static void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b, __u64 t,int status)
{ assert(t==b->ticket && b->views==1 && !b->ready && status==-EIO); b->traces++; }
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,__u64 t,int status,bool uncertain)
{ assert(t==b->ticket && b->traces==1 && b->ready==1 && status==-EIO && uncertain); b->publishes++; }
/* PRODUCTION */
static int complete(struct xdev_ext_mech_batch *b, void *native, int status, bool *uncertain)
{ assert(native==b && status==-EIO); b->views++; *uncertain=true; return status; }
static void ready(struct xdev_ext_mech_batch *b,int status,bool uncertain)
{ assert(b->traces==1 && status==-EIO && uncertain); b->ready++; }
int main(void)
{
 struct xdev_ext_stor_pool p={}; struct xdev_ext_stor_slot a={},b={};
 struct xdev_ext_stor_slot *first,*second;
 struct xdev_ext_mech_batch batch={.ticket=7};
 struct xdev_ext_stor_completion done={.b=&batch,.ticket=6,.poll_live=true};
 xdev_ext_stor_slot_add(&p,&a); xdev_ext_stor_slot_add(&p,&b);
 first=xdev_ext_stor_slot_get(&p,false); second=xdev_ext_stor_slot_get(&p,false);
 assert(first!=second && first->busy && second->busy);
 assert(PTR_ERR(xdev_ext_stor_slot_get(&p,true))==-EBUSY);
 assert(PTR_ERR(xdev_ext_stor_slot_get(&p,false))==-EAGAIN);
 xdev_ext_stor_slot_put(&p,first,true);
 assert(first->busy && PTR_ERR(xdev_ext_stor_slot_get(&p,false))==-EAGAIN);
 xdev_ext_stor_slot_put(&p,second,false);
 assert(!second->busy && xdev_ext_stor_slot_get(&p,false)==second);
 xdev_ext_stor_done(&done,-EIO,&batch,complete,ready);
 assert(!done.poll_live && !batch.views && !batch.publishes);
 done.ticket=7; done.poll_live=true;
 xdev_ext_stor_done(&done,-EIO,&batch,complete,ready);
 assert(done.uncertain && batch.views==1 && batch.traces==1 && batch.publishes==1);
 xdev_ext_stor_done(&done,-EIO,&batch,complete,ready);
 assert(batch.views==1 && batch.publishes==1);
 puts("ok - storage depth, occupied, quarantine, stale ticket, claim and publish order");
 return 0;
}
'''

def main():
    source = (ROOT/'io_uring/family/xdev_ext_storfam.c').read_text()
    production=[]
    for name in FUNCTIONS:
        m=re.search(r'^[A-Za-z_][^;{}]*\b'+name+r'\([^;{}]*\)\s*\{.*?^\}',source,re.M|re.S)
        if not m:
            raise AssertionError('missing production runtime symbol: '+name)
        production.append(m[0])
    code='\n'.join(production)
    with tempfile.TemporaryDirectory(prefix='storfam-runtime-') as tmp:
        p=Path(tmp)
        for name,body,want in [('actual',code,0),('no-claim',code.replace('if (xdev_ext_mech_batch_completion_claim(b, done->ticket))','if (0)'),1)]:
            if name=='no-claim' and body==code:
                raise AssertionError('claim mutation target missing')
            (p/'probe.c').write_text(SHIM.replace('/* PRODUCTION */',body))
            subprocess.run([os.environ.get('CC','gcc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=undefined','-fno-sanitize-recover=undefined','-I'+str(ROOT),str(p/'probe.c'),'-o',str(p/'probe')],check=True)
            r=subprocess.run([str(p/'probe')],capture_output=True,text=True)
            if (r.returncode!=0)!=bool(want):
                raise AssertionError((name,r.returncode,r.stdout,r.stderr))
            print(r.stdout.strip() if not want else 'ok mutation - removing claim rejected by executable assertions')

if __name__=='__main__': main()

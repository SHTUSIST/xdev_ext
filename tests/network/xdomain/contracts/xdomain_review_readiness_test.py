#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent two-end readiness contract; actual main TU at both endpoints."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from xdomain_ring_test import no_includes
from xdomain_retention_fixture import retention_unit
HERE=Path(__file__).resolve().parent
def replace_function(text,name,new):
    m=re.search(r'(?m)^(?:static )?(?:int|void) '+name+r'\(',text)
    assert m,name
    start=text.index('{',m.start());end=start+1;depth=1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    return text[:m.start()]+new+'\n'+text[end:]
def main():
    p=argparse.ArgumentParser();p.add_argument('--kernel',type=Path,default=HERE.parents[4]);p.add_argument('--keep-build',type=Path);a=p.parse_args();k=a.kernel.resolve()
    env='''
static unsigned long jiffies;
#define HZ 1000
#define time_before(a,b) ((long)((a)-(b))<0)
#define time_after(a,b) time_before(b,a)
#define time_before_eq(a,b) ((long)((a)-(b))<=0)
#define time_after_eq(a,b) time_before_eq(b,a)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
static unsigned long jiffies_to_msecs(unsigned long n){return n;}
struct review_ready_native {struct xdev_ext_xd_link *xl;bool running,paths;unsigned path_calls;};
static struct review_ready_native review_ready_states[2];
static struct xdev_ext_xd_link *review_ready_failed;
static struct review_ready_native *review_ready_native(struct xdev_ext_xd_link *xl)
{for(unsigned i=0;i<2;i++)if(review_ready_states[i].xl==xl)return &review_ready_states[i];
 for(unsigned i=0;i<2;i++)if(!review_ready_states[i].xl){review_ready_states[i].xl=xl;return &review_ready_states[i];}abort();}
static int xdev_ext_xd_handle_packet(const void *,size_t,void *);
'''
    boundaries=(HERE/'xdomain_login_boundaries.c').read_text()
    boundaries=replace_function(boundaries,'tb_xdomain_request',r'''
static int tb_xdomain_request(struct tb_xdomain *xd,const void *request,size_t size,int req_type,
                              void *reply,size_t reply_size,int resp_type,unsigned int timeout)
{
    (void)xd;(void)req_type;(void)resp_type;(void)timeout;
    assert(size==sizeof(struct xdev_ext_xd_login)&&reply_size==sizeof(struct xdev_ext_xd_login_response));
    memcpy(&last_request,request,size);requests++;
    unsigned before=responses;assert(xdev_ext_xd_handle_packet(request,size,NULL)==1);
    assert(responses==before+1);memcpy(reply,&last_response,reply_size);return 0;
}''')
    boundaries=replace_function(boundaries,'xdev_ext_xd_rings_start',r'''
int xdev_ext_xd_rings_start(struct xdev_ext_xd_link *xl)
{ assert(xl->ctl_mutex.held);struct review_ready_native *s=review_ready_native(xl);
  assert(!s->running);s->running=true;ring_starts++;return 0;}
''')
    boundaries=replace_function(boundaries,'xdev_ext_xd_rings_stop',r'''
void xdev_ext_xd_rings_stop(struct xdev_ext_xd_link *xl)
{ assert(xl->ctl_mutex.held);review_ready_native(xl)->running=false;ring_stops++; }
''')
    boundaries=replace_function(boundaries,'xdev_ext_xd_paths_enable',r'''
int xdev_ext_xd_paths_enable(struct xdev_ext_xd_link *xl,const struct xdev_ext_xd_login *peer)
{(void)peer;struct review_ready_native *s=review_ready_native(xl);assert(s->running);s->path_calls++;
 if(xl==review_ready_failed)return -EIO;s->paths=true;return 0;}
''')
    boundaries=replace_function(boundaries,'xdev_ext_xd_paths_disable',r'''
void xdev_ext_xd_paths_disable(struct xdev_ext_xd_link *xl)
{review_ready_native(xl)->paths=false;}
''')
    unit=(HERE/'xdomain_login_compat.h').read_text()+'\n#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n'+no_includes((k/'io_uring/xdomain/xdev_ext_xdomain.h').read_text())+env+boundaries+retention_unit(k)+no_includes((k/'io_uring/xdomain/xdev_ext_xdomain_main.c').read_text())+(HERE/'xdomain_review_readiness_cases.c').read_text()
    with tempfile.TemporaryDirectory(prefix='xdomain-review-ready-') as temp:
        src=Path(temp)/'ready.c';binary=Path(temp)/'ready';src.write_text(unit)
        if a.keep_build:a.keep_build.mkdir(parents=True,exist_ok=True);(a.keep_build/'readiness-unit.c').write_text(unit)
        build=subprocess.run(['gcc','-std=gnu11','-O0','-g','-Werror=implicit-function-declaration','-I',str(k),str(src),'-o',str(binary)],capture_output=True,text=True,timeout=60)
        if build.returncode:print('# SETUP_COMPILE_ERROR; not behavioral RED\n'+build.stdout+build.stderr);return 2
        names=['initial_login_EAGAIN_until_local_receive_paths_ready','setup_failure_never_positive_to_peer','both_real_peers_progress_without_up_precondition']
        print('TAP version 13\n1..3',flush=True);failed=False
        for i,name in enumerate(names,1):
            run=subprocess.run([str(binary),str(i)],capture_output=True,text=True,timeout=8)
            print(run.stdout+run.stderr,end='');ok=run.returncode==0;failed|=not ok
            print(('ok ' if ok else 'not ok ')+str(i)+' - '+name,flush=True)
        return int(failed)
if __name__=='__main__':sys.exit(main())

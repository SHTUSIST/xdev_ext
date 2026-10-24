#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent acceptance gate; reads actual ctl functions, never runs devices."""
import argparse, pathlib, re, subprocess, tempfile, sys, os, shlex
p=argparse.ArgumentParser(); p.add_argument('kernel',nargs='?',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[4]); a=p.parse_args()
k=a.kernel.resolve(); src=(k/'tools/xdev_ext_mech/xdev_ext_mech_ctl.c').read_text()
def fn(name):
    m=re.search(r'^static\s+(?:int|void)\s+'+name+r'\s*\(',src,re.M)
    if not m: raise AssertionError('missing actual '+name)
    start=src.index('{',m.start()); depth=1; end=start+1
    while depth:
        depth += (src[end]=='{')-(src[end]=='}'); end+=1
    return src[m.start():end]
body=fn('ctl_finish_reliable')
pre=r'''
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
struct ctl_run { int ring; __u64 session; };
static int alive, terr, aerr, cerr, serr, debt, failures;
static char events[64]; static unsigned ne;
static void event(char x){events[ne++]=x; events[ne]=0;}
static void ctl_print_stats(const struct xdev_ext_mech_stats *s){(void)s;}
static int ctl_transport_stats(int ring,__u64 session,struct xdev_ext_mech_transport_stats *s){
 (void)ring; event('T'); if(!alive||session!=99)return -ENOENT;
 *s=(struct xdev_ext_mech_transport_stats){.size=sizeof(*s),.version=XDEV_EXT_MECH_TRANSPORT_STATS_VERSION,.session_id=session,.pending_acks=debt};return terr;
}
static int ctl_transport_counters(int ring,__u64 session,struct xdev_ext_mech_transport_stats_v2 *s){
 (void)ring;event('C');if(!alive||session!=99)return -ENOENT;memset(s,0,sizeof(*s));return cerr;
}
static int ctl_mech(int ring,__u32 op,__u64 arg){
 (void)ring;
 if(op==XDEV_EXT_MECH_OP_STOP){event('S'); if(arg!=99)return -ENOENT;if(!serr)alive=0;return serr;}
 if(op==XDEV_EXT_MECH_OP_TRANSPORT_STATS){
  struct xdev_ext_mech_transport_stats_v3 *s=(void*)(uintptr_t)arg;event('A');
  if(!alive||s->v2.v1.session_id!=99)return -ENOENT;
  if(s->v2.v1.version!=XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3||s->v2.v1.size!=sizeof(*s))return -EINVAL;
  if(aerr)return aerr;s->nic_copy_ops=11;s->nic_zc_ops=7;s->nic_copy_bytes=110;s->nic_zc_bytes=70;return 0;
 }
 return -EINVAL;
}
'''
post=r'''
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %s line%d events=%s\n",#x,__LINE__,events);failures++;}}while(0)
static void run(int outcome,int tq,int aq,int cq,int sq,int d,int want,int snapshot){
 struct ctl_run r={.ring=1,.session=99};struct xdev_ext_mech_stats s={.session_id=99};
 struct xdev_ext_mech_transport_stats_v3 account={0};
 alive=1;terr=tq;aerr=aq;cerr=cq;serr=sq;debt=d;ne=0;events[0]=0;
 int ret=ctl_finish_reliable(&r,&s,outcome,snapshot?&account:NULL);
 CHECK(ret==want);CHECK(strchr(events,'S')!=NULL);CHECK(ne&&events[ne-1]=='S');
 CHECK(r.session==(sq==-EAGAIN?99:0));
 if(snapshot){CHECK(strchr(events,'A')!=NULL);CHECK(strchr(events,'A')<strchr(events,'S'));
  if(!aq){CHECK(account.v2.v1.session_id==99);CHECK(account.nic_copy_ops==11);CHECK(account.nic_zc_ops==7);CHECK(account.nic_copy_bytes==110);CHECK(account.nic_zc_bytes==70);}}
 else CHECK(strchr(events,'A')==NULL);
}
int main(void){
 run(0,0,0,0,0,0,0,1);run(-ETIMEDOUT,0,0,0,0,0,-ETIMEDOUT,1);
 run(-EIO,-EFAULT,-EINVAL,0,-EBUSY,0,-EIO,1);
 run(0,-EFAULT,0,0,0,0,-EFAULT,1);run(0,0,-EINVAL,0,0,0,-EINVAL,1);
 run(0,0,0,0,-EAGAIN,0,-EAGAIN,1);run(0,0,0,0,-EIO,0,-EIO,1);
 run(0,0,0,0,0,1,-EBUSY,1);run(0,0,0,-EIO,0,0,0,1);
 run(0,0,0,0,0,0,0,0);
 if(failures)return 1;puts("PASS actual finalizer: snapshot before STOP, success/error/debt/null cases");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='run-',dir=os.environ.get('XDEV_EXT_TEST_TMPDIR', str(pathlib.Path(__file__).parent))) as td:
    td=pathlib.Path(td); c=td/'probe.c'; out=td/'probe'
    c.write_text(pre+'\n'+fn('ctl_nic_accounting')+'\n'+body+'\n'+post)
    cmd=shlex.split(os.environ.get('CC','cc'))+['-std=gnu11','-Wall','-Wextra','-Wno-misleading-indentation','-I'+str(k),str(c),'-o',str(out)]
    res=subprocess.run(cmd,text=True,capture_output=True)
    if res.returncode:
        print('FAIL actual function acceptance compile'); print(res.stderr);sys.exit(1)
    res=subprocess.run([str(out)],text=True,capture_output=True); print(res.stdout);print(res.stderr,end='')
    if res.returncode:sys.exit(res.returncode)
# Source wiring guard is separate from the actual-function behavioral test above.
# The agreed API uses caller-local final snapshots; every late live query must
# be explicitly restricted to the non-reliable branch.
for name, dest in [('cmd_nic_nvme','accounting'),('ctl_run_source','src->accounting')]:
    text=fn(name)
    call=re.search(r'ctl_finish_reliable\s*\([^;]+;',text,re.S)
    assert call and re.search(r'&\s*'+re.escape(dest)+r'\s*(?::\s*NULL\s*)?\)',call.group()),name+' must pass its final snapshot'
    tail=text[call.end():]
    for m in re.finditer(r'ctl_nic_accounting\s*\(',tail):
        # Allow an immediate if/else-if condition explicitly excluding reliable.
        prefix=tail[max(0,m.start()-180):m.start()]
        assert re.search(r'if\s*\([^{};]*!o->reliable[^{};]*\)\s*\{?\s*(?:ret\s*=\s*|if\s*\()?$',prefix,re.S),name+' late live query not non-reliable guarded'
print('PASS source wiring: both reliable callers consume final snapshots; late queries non-reliable only')
# This existing host gate also covers the ordinary source terminal-error path.
subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('xdev_ext_mech_source_drain_test.py'))],
               env=dict(os.environ, XDEV_EXT_TEST_SRC=str(k)), check=True)

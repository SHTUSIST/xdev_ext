#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual source-wait and CLI error functions over bounded host inputs."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(os.environ.get('XDEV_EXT_TEST_SRC', Path(__file__).resolve().parents[4]))
text = Path(os.environ.get('XDEV_EXT_TEST_CTL_SOURCE',
                          ROOT/'tools/xdev_ext_mech/xdev_ext_mech_ctl.c')).read_text()


def function(name, optional=False):
    match = re.search(r'^static\s+int\s+' + name + r'\s*\(', text, re.M)
    if not match:
        if optional:
            return ''
        raise AssertionError('missing actual function: ' + name)
    start = text.index('{', match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]


prefix = r'''
#include <limits.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
enum { CTL_PASS=0, CTL_FAIL=1, CTL_SETUP=3 };
struct ctl_opts { const char *ifname,*src_ng; bool have_slba,have_nlb,reliable,expect_unbind;
 __u64 groups,slba,nlb; };
struct ctl_source { struct ctl_opts *o;const char *ifname;unsigned nr_stages,nic_path;
 struct xdev_ext_mech_stage_uapi st[4];struct xdev_ext_mech_transport_stats_v3 accounting;
 bool started; };
struct ctl_run { int ring,efd;__u64 session,deadline_ns;bool defer_stats,source_error_drain; };
static unsigned reads,queries,printed,failures,checks,first_inflight,final_inflight;
static int mode,final_error,command_error,command_started;
static __u64 now;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL mode=%d line=%d: %s\n",mode,__LINE__,#x);failures++;}}while(0)
static __u64 ctl_now_ns(void){return now;}
static int __attribute__((unused)) test_sleep(unsigned us){(void)us;now+=1000000000ULL;return 0;}
static int fake_poll(struct pollfd *p,nfds_t n,int ms){(void)n;(void)ms;p->revents=POLLIN;return 1;}
static ssize_t fake_read(int fd,void *p,size_t n){(void)fd;*(__u64*)p=1;reads++;return n;}
static int ctl_stats(int ring,__u64 session,struct xdev_ext_mech_stats *s){
 unsigned at=queries++;(void)ring;
 if(mode==4&&at)return -ENOENT;
 *s=(struct xdev_ext_mech_stats){.session_id=session,.state=XDEV_EXT_MECH_SESSION_ACTIVE,
  .last_err=-ESHUTDOWN,.batches_done=51,.batches_abort=6,.inflight=2,
  .submitted={59,52},.completed={58,51}};
 if(mode==0){s->last_err=0;s->inflight=0;s->batches_done=64;s->batches_abort=0;}
 if(at&&mode==1){s->state=at==1?XDEV_EXT_MECH_SESSION_STOPPING:XDEV_EXT_MECH_SESSION_STOPPED;
  s->inflight=at==1?1:0;s->last_err=-ECANCELED;}
 if(at&&mode==3)s->inflight=0;
 if(at&&mode==5){s->state=XDEV_EXT_MECH_SESSION_ZOMBIE;s->inflight=0;s->sequestered=6;}
 if(at&&mode==6){s->inflight=0;s->batches_done=51;s->batches_abort=13;}
 if(at&&mode==7){s->inflight=0;s->batches_done=UINT64_MAX;s->batches_abort=65;}
 if(at&&mode==8){s->state=XDEV_EXT_MECH_SESSION_STOPPED;s->inflight=0;s->last_err=-EIO;}
 if(at&&mode==9){s->state=XDEV_EXT_MECH_SESSION_STOPPING;s->inflight=0;s->batches_done=64;s->batches_abort=0;}
 if(at&&mode==11){s->state=XDEV_EXT_MECH_SESSION_STOPPED;s->inflight=0;s->last_err=-ECANCELED;}
 return 0;
}
static void ctl_print_stats(const struct xdev_ext_mech_stats *s){
 if(!printed)first_inflight=s->inflight;
 printed++;final_inflight=s->inflight;final_error=s->last_err;
}
static int ctl_peer(const struct ctl_opts *o){(void)o;return 0;}
static int test_open(const char *name,int flags){(void)name;(void)flags;return 17;}
static int test_close(int fd){(void)fd;return 0;}
static int ctl_run_source(struct ctl_source *src,struct xdev_ext_mech_stats *s,bool *frames){
 memset(s,0,sizeof(*s));*frames=true;src->started=command_started;return command_error;
}
static int ctl_report(bool pass,const char *line){(void)line;return pass?CTL_PASS:CTL_FAIL;}
static void ctl_print_nic_accounting(unsigned path,const struct xdev_ext_mech_transport_stats_v3 *s){(void)path;(void)s;}
#define poll fake_poll
#define read fake_read
#define usleep test_sleep
#define open test_open
#define close test_close
#define ctl_err(...) ((void)0)
'''

suffix = r'''
static void wait_case(int which){
 struct ctl_run r={.ring=1,.efd=2,.session=99,.deadline_ns=60000000000ULL,.source_error_drain=true};
 struct xdev_ext_mech_stats s={0};int ret;
 mode=which;now=0;reads=queries=printed=0;first_inflight=final_inflight=0;final_error=0;
 if(mode==10)r.defer_stats=true;
 if(mode==11)now=61000000000ULL;
 ret=ctl_wait_coarse(&r,64,&s);
 if(mode==11){CHECK(ret==-ETIMEDOUT);CHECK(reads==0);CHECK(queries==2);CHECK(final_inflight==0);return;}
 CHECK(reads==1);
 if(!mode){CHECK(!ret);CHECK(queries==1);CHECK(printed==0);return;}
 CHECK(ret==-ESHUTDOWN); /* Settling must never clear the original error. */
 if(mode==10){CHECK(queries==1);CHECK(printed==0);return;}
 CHECK(first_inflight==2);
 if(mode==1){CHECK(queries==3);CHECK(printed==2);CHECK(s.state==XDEV_EXT_MECH_SESSION_STOPPED);
  CHECK(final_inflight==0);CHECK(final_error==-ECANCELED);CHECK(now<5000000000ULL);}
 if(mode==2){CHECK(queries>2);CHECK(now>=5000000000ULL);CHECK(final_inflight==2);}
 if(mode==3){CHECK(queries>2);CHECK(now>=5000000000ULL);CHECK(s.state==XDEV_EXT_MECH_SESSION_ACTIVE);}
 if(mode==4){CHECK(queries==2);CHECK(s.inflight==2);CHECK(now==0);}
 if(mode==5){CHECK(queries==2);CHECK(s.state==XDEV_EXT_MECH_SESSION_ZOMBIE);CHECK(s.sequestered==6);}
 if(mode==6){CHECK(queries==2);CHECK(final_inflight==0);CHECK(s.batches_done==51&&s.batches_abort==13);}
 if(mode==7){CHECK(queries>2);CHECK(now>=5000000000ULL);}
 if(mode==8){CHECK(queries==2);CHECK(final_error==-EIO);CHECK(final_inflight==0);}
 if(mode==9){CHECK(queries>2);CHECK(now>=5000000000ULL);CHECK(s.state==XDEV_EXT_MECH_SESSION_STOPPING);}
}
int main(void){
 struct ctl_opts o={.ifname="local-fixture",.src_ng="local-fixture",.have_slba=true,.have_nlb=true,.groups=64};
 for(int i=0;i<=11;i++)wait_case(i);
 mode=12;command_started=0;command_error=-EINVAL;CHECK(cmd_nvme_nic(&o)==CTL_SETUP);
 command_started=1;command_error=-ECANCELED;CHECK(cmd_nvme_nic(&o)==CTL_FAIL);
 command_error=-EIO;CHECK(cmd_nvme_nic(&o)==CTL_FAIL);
 command_error=-ETIMEDOUT;CHECK(cmd_nvme_nic(&o)==CTL_FAIL);
 printf("source error lifecycle: checks=%u failures=%u; host boundaries only\n",checks,failures);
 return failures?1:0;
}
'''

with tempfile.TemporaryDirectory(prefix='source-drain-', dir=os.environ.get(
        'XDEV_EXT_TEST_TMPDIR', str(Path(__file__).parent))) as tmp:
    source, binary = Path(tmp)/'probe.c', Path(tmp)/'probe'
    source.write_text(prefix + function('ctl_source_error_drain', optional=True) + '\n' +
                      function('ctl_wait_coarse') + '\n' + function('cmd_nvme_nic') + suffix)
    command = shlex.split(os.environ.get('CC', 'gcc')) + [
        '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=undefined', '-fno-sanitize-recover=undefined', '-I'+str(ROOT),
        str(source), '-o', str(binary)]
    subprocess.run(command, check=True)
    result = subprocess.run([str(binary)], check=False)
    if result.returncode:
        raise SystemExit(result.returncode)

# Wiring checks accompany actual-function execution: final observations occur
# inside wait, before the shared source caller closes its ring/XSK.
start = text.index('static int ctl_run_source(')
end = text.index('\nstatic int cmd_nvme_nic(', start)
body = text[start:end]
assert '.source_error_drain = !o->expect_unbind' in body
assert body.index('src->started = true;') > body.index('ret = ctl_start(')
assert re.search(r'ret = ctl_start\([^;]+;\s*if \(ret\)\s*goto out;\s*src->started = true;', body)
assert body.index('ctl_wait_coarse(') < body.index('close(r.ring)')
assert 'ctl_mech(' not in function('ctl_source_error_drain')
for caller in ('cmd_nvme_nic', 'cmd_ce_chain', 'ctl_new_chain'):
    assert 'src.started ? CTL_FAIL : CTL_SETUP' in function(caller), caller
print('PASS source wiring: final wait before close, no cancellation, setup/runtime distinction in all callers')

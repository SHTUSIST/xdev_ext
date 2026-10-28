#!/usr/bin/env python3
"""Actual core STOP/accessor host slice; worker/notify boundaries only are stubs."""
import argparse,importlib.util,re,subprocess,sys,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,default=Path(__file__).resolve().parents[5]);p.add_argument('--artifact-directory',type=Path);a=p.parse_args()
temporary=tempfile.TemporaryDirectory(prefix="xdev-stop-clock-") if a.artifact_directory is None else None
b=Path(__file__).resolve().parent;kernel=a.kernel.resolve();out=a.artifact_directory or Path(temporary.name);out.mkdir(parents=True,exist_ok=True)
spec=importlib.util.spec_from_file_location('x5',b/'xdomain_class_test.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
core=(kernel/'io_uring/xdev_ext_mech.c').read_text();header=(kernel/'include/linux/xdev_ext_mech.h').read_text();name='xdev_ext_mech_session_stop_started_ns'
if not re.search(r'\bu64\s+'+name+r'\s*\(',header) or not re.search(r'(?m)^u64\s+'+name+r'\s*\(',core):
 print('not ok 1 - kernel-only STOP-start accessor missing (API RED; no behavioral test executed)');sys.exit(1)
private=m.struct(core,'xdev_ext_mech_session');fields=[]
for n in ('lock','start_left','start_ordered','start_recycle','start_return_pending','worker_gone','stop_err','last_err','start_preparing','stop_started_ns'):
 match=re.search(r'(?m)^\s*(spinlock_t|u64|u32|int|bool)\s+'+n+r'\s*;',private)
 if not match:raise RuntimeError('actual private scalar missing: '+n)
 fields.append(match.group(0))
queue_field=re.search(r'(?m)^\s*struct xdev_ext_mech_start_queue\s*\*start_queue\s*;',private)
if not queue_field:raise RuntimeError('actual START queue pointer missing')
fields.append(queue_field.group(0))
body='\n'.join(m.function(core,n) for n in ('xdev_ext_mech_settle_locked','xdev_ext_mech_session_stop',name))
s='''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "@CORE_HEADER@"
typedef uint64_t u64;typedef uint32_t u32;typedef unsigned spinlock_t;
struct kthread_worker;struct kthread_work { unsigned queued; };
struct xdev_ext_mech_session { @FIELDS@
 struct xdev_ext_mech_sess ss;int drain_wq;int native_controls;
 struct kthread_worker *worker;struct kthread_work stop_work;
};
static unsigned locks,clock_reads,lock_entries;static u64 now;
static void lock(spinlock_t*p){assert(!*p&&!locks);*p=1;locks++;lock_entries++;}
static void unlock(spinlock_t*p){assert(*p&&locks==1);*p=0;locks--;}
#define spin_lock_irqsave(p,f) do{(f)=0;lock(p);}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(f);unlock(p);}while(0)
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v,x) ((v)=(x))
#define atomic_read(p) (*(p))
#define wake_up(p) ((void)(p))
static u64 ktime_get_boottime_ns(void){assert(locks==1);clock_reads++;return now;}
static void xdev_ext_mech_notify_locked(struct xdev_ext_mech_session*s,bool terminal){(void)s;(void)terminal;assert(locks==1);}
static int kthread_queue_work(struct kthread_worker*w,struct kthread_work*k){(void)w;assert(locks==1);k->queued++;return 1;}
@BODY@
static u64 observed_stop_clock(struct xdev_ext_mech_session *s){unsigned before=lock_entries;u64 value=xdev_ext_mech_session_stop_started_ns(s);assert(lock_entries==before+1);return value;}
static struct xdev_ext_mech_session active(void){struct xdev_ext_mech_session s={0};xdev_ext_mech_sess_init(&s.ss);assert(!xdev_ext_mech_sess_batch_begin(&s.ss));return s;}
int main(void){puts("TAP version 13");
 struct xdev_ext_mech_session s=active();now=1000000;xdev_ext_mech_session_stop(&s,0);assert(s.ss.state==XDEV_EXT_MECH_SESSION_STOPPING);
 now=1001000000;assert(observed_stop_clock(&s)==1000000);assert(s.stop_work.queued);puts("ok 1 - worker lag does not move first STOP clock");
 xdev_ext_mech_session_stop(&s,-EIO);assert(observed_stop_clock(&s)==1000000&&s.stop_err==-EIO);now+=1000000000;xdev_ext_mech_session_stop(&s,-ENOLINK);assert(observed_stop_clock(&s)==1000000&&s.stop_err==-EIO);puts("ok 2 - repeated and late-error STOP preserve original time and first error");
 s=active();now=0;xdev_ext_mech_session_stop(&s,0);now=1000000000;xdev_ext_mech_session_stop(&s,-EIO);assert(observed_stop_clock(&s)==0);puts("ok 3 - zero is a valid first STOP timestamp, never an unset sentinel");
 s=(struct xdev_ext_mech_session){0};now=37;xdev_ext_mech_session_stop(&s,-ECANCELED);assert(observed_stop_clock(&s)==37);now=91;xdev_ext_mech_session_stop(&s,0);assert(observed_stop_clock(&s)==37);puts("ok 4 - NONE CREATE failure timestamps first successful STOP even after immediate settle");
 s=active();s.ss.state=XDEV_EXT_MECH_SESSION_ERROR;now=42;xdev_ext_mech_session_stop(&s,-EIO);now=99;xdev_ext_mech_session_stop(&s,0);assert(observed_stop_clock(&s)==42);puts("ok 5 - ERROR to STOPPING records first transition once");
 assert(!locks&&clock_reads==4);puts("1..5");return 0;
}
'''.replace('@CORE_HEADER@',str(kernel/'io_uring/xdev_ext_mech_core.h')).replace('@FIELDS@','\n'.join(fields)).replace('@BODY@',body)
(out/'test.c').write_text(s);cmd=['gcc','-std=gnu11','-O1','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(out/'test.c'),'-o',str(out/'test')]
print('GCC actual core STOP clock:',*cmd,flush=True);subprocess.run(cmd,check=True);subprocess.run([str(out/'test')],check=True)

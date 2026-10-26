/* SPDX-License-Identifier: GPL-2.0 */
/* Requirements: 2026-10-26-stop-report-closure.md, full V4 report revision.
 * Real epoch/guard; only external I/O is controlled. No device evidence. */
#include "epoch_control.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__func__,__LINE__,#x); exit(1); } } while (0)
#define MS UINT64_C(1000000)
_Static_assert(XDEV_EXT_MECH_OP_STOP==3,"legacy STOP preserved");
_Static_assert(XDEV_EXT_MECH_OP_STOP_REPORT==9,"new report opcode");
struct ledger {
 struct tb_guard *guard;
 uint64_t now,deadline;
 unsigned reports,legacy,polls,reads,closes,queries,retry,malformed;
 int error,arm_error;
 bool started,hold_on_return,interrupt_poll;
};
struct fixture { struct ledger io; struct tb_guard *guard; struct tb_epoch epoch; };
static int ring_open(void *p) { (void)p;return 41; }
static int event_open(void *p) { (void)p;return 42; }
static bool all_zero(const void *p,size_t n) {
 const unsigned char *s=p;for(size_t i=0;i<n;i++)if(s[i])return false;return true;
}
static void output_report(struct ledger *l,struct xdev_ext_mech_stop_report *r) {
 memset(r,0,sizeof(*r));r->size=sizeof(*r);r->version=1;r->session_id=991;
 r->stats.session_id=991;r->stats.batches_done=l->started?3:0;
 r->stats.recycled=19;r->stats.native_publish=11;
 r->stats.submitted[0]=l->started?7:0;r->stats.completed[0]=l->started?7:0;
 r->stats.state=XDEV_EXT_MECH_SESSION_STOPPED;
 r->transport.v3.v2.v1.size=sizeof(r->transport);r->transport.v3.v2.v1.version=4;
 r->transport.v3.v2.v1.session_id=991;
 r->transport.v3.v2.retransmits=29;r->transport.v3.v2.dup_suppressed=31;
 r->transport.v3.nic_zc_ops=37;r->transport.v3.nic_zc_bytes=4096;
 /* A nonzero observed tail distinguishes full V4 from invented V2 padding. */
 r->transport.rel_policy.version=1;r->transport.rel_policy.size=sizeof(r->transport.rel_policy);
 r->transport.rel_policy.window=7;r->transport.rel_policy.initial_credit=5;
 r->transport.rel_policy.rto_ns=12345;
 switch(l->malformed) {
 case 1:r->size--;break;
 case 2:r->version=2;break;
 case 3:r->session_id=992;break;
 case 4:r->stats.session_id=992;break;
 case 5:r->transport.v3.v2.v1.size--;break;
 case 6:r->transport.v3.v2.v1.version=3;break;
 case 7:r->transport.v3.v2.v1.session_id=992;break;
 case 8:r->transport.v3.v2.v1.rsvd=1;break;
 case 9:r->transport.v3.v2.rsvd2=1;break;
 default:break;
 }
}
static int mech(void *p,int fd,uint32_t op,void *arg) {
 struct ledger *l=p;CHECK(fd==41);
 switch(op) {
 case XDEV_EXT_MECH_OP_CREATE:
  ((struct xdev_ext_mech_create *)arg)->session_id=991;return 0;
 case XDEV_EXT_MECH_OP_NOTIFY_ARM:
  CHECK(((struct xdev_ext_mech_notify_arm *)arg)->session_id==991);return l->arm_error;
 case XDEV_EXT_MECH_OP_START:
  CHECK(((struct xdev_ext_mech_start *)arg)->session_id==991);l->started=true;return 0;
 case XDEV_EXT_MECH_OP_STOP:
  ++l->legacy;return -EOPNOTSUPP;
 case XDEV_EXT_MECH_OP_STOP_REPORT: {
  struct xdev_ext_mech_stop_report *r=arg;
  ++l->reports;CHECK(l->reports<=32);
  CHECK(r->size==sizeof(*r)&&r->version==1&&r->session_id==991);
  CHECK(all_zero(&r->stats,sizeof(r->stats))&&all_zero(&r->transport,sizeof(r->transport)));
  if(l->retry) {
   --l->retry;l->now+=5*MS;
   memset(r,0xa5,sizeof(*r)); /* Returned EAGAIN bytes must never taint retry. */
   return -EAGAIN;
  }
  output_report(l,r);
  if(l->hold_on_return)tb_guard_hold(l->guard,TB_HOLD_SIGNAL);
  return l->error;
 }
 case XDEV_EXT_MECH_OP_STATS:case XDEV_EXT_MECH_OP_TRANSPORT_STATS:
  ++l->queries;return -ENOENT; /* The successful kernel STOP destroys session. */
 default:CHECK(!"unexpected production operation");return -EINVAL;
 }
}
static int poll_event(void *p,int fd,uint64_t deadline) {
 struct ledger *l=p;CHECK(fd==42);++l->polls;
 CHECK(deadline>l->now&&deadline<=l->deadline&&deadline-l->now<=20*MS);
 if(l->interrupt_poll){l->interrupt_poll=false;l->now+=MS;return -EINTR;}
 l->now=deadline;return 0;
}
static int event_read(void *p,int fd,uint64_t *value) {
 struct ledger *l=p;CHECK(fd==42);++l->reads;*value=1;return 0;
}
static uint64_t now_ns(void *p) { return ((struct ledger *)p)->now; }
static int fd_close(void *p,int fd) {
 struct ledger *l=p;CHECK(fd==41||fd==42);++l->closes;return 0;
}
static void init(struct fixture *f,bool start) {
 memset(f,0,sizeof(*f));f->io.now=100*MS;f->io.deadline=200*MS;
 CHECK(tb_guard_new(TB_BACKING_EXISTING_PROVIDER,&f->guard)==0);
 CHECK(tb_guard_external_ready(f->guard,TB_READY_EXISTING_PROVIDER_REGISTERED)==0);
 f->io.guard=f->guard;
 struct tb_epoch_io io={.opaque=&f->io,.ring_setup=ring_open,.event_open=event_open,.mech=mech,
  .poll_event=poll_event,.event_read=event_read,.now_ns=now_ns,.fd_close=fd_close};
 CHECK(tb_epoch_init(&f->epoch,f->guard,&io)==0);
 struct xdev_ext_mech_create c={.abi_version=XDEV_EXT_MECH_ABI_VERSION,.nr_stages=1,
  .pool_kind=XDEV_EXT_MECH_POOL_PEER,.pool_fd=73,.layout={65536,0,65536,65536},.depth=1,.eventfd=-1};
 CHECK(tb_epoch_open(&f->epoch,&c)==0);
 if(start)CHECK(tb_epoch_start(&f->epoch,3,17)==0);
}
static void no_legacy_or_queries(const struct fixture *f) {
 CHECK(f->io.legacy==0);CHECK(f->io.queries==0);
}
static void valid_result(const struct fixture *f,const struct tb_epoch_result *r) {
 CHECK(r->stop_proved&&r->stats_valid&&r->transport_valid);
 CHECK(r->fate==TB_EPOCH_SAFE&&r->first_error==0&&r->stop_error==0);
 CHECK(r->stats.session_id==991&&r->stats.batches_done==(f->io.started?3U:0U));
 CHECK(r->stats.recycled==19&&r->stats.native_publish==11);
 CHECK(r->stats.submitted[0]==(f->io.started?7U:0U));
 CHECK(r->stats.completed[0]==(f->io.started?7U:0U));
 CHECK(r->stats.state==XDEV_EXT_MECH_SESSION_STOPPED);
 const struct xdev_ext_mech_transport_stats_v4 *t=&r->transport;
 CHECK(t->v3.v2.v1.size==sizeof(*t)&&t->v3.v2.v1.version==4&&t->v3.v2.v1.session_id==991);
 CHECK(t->v3.v2.retransmits==29&&t->v3.v2.dup_suppressed==31);
 CHECK(!t->v3.v2.v1.native_controls&&!t->v3.v2.v1.pending_acks&&!t->v3.v2.v1.uncertain_controls);
 CHECK(t->v3.nic_zc_ops==37&&t->v3.nic_zc_bytes==4096);
 CHECK(t->rel_policy.version==1&&t->rel_policy.size==sizeof(t->rel_policy));
 CHECK(t->rel_policy.window==7&&t->rel_policy.initial_credit==5&&t->rel_policy.rto_ns==12345);
}
static void successful(bool start,bool repeated,unsigned retry,bool interrupt) {
 struct fixture f;struct tb_epoch_result r;
 init(&f,start);f.io.retry=retry;f.io.interrupt_poll=interrupt;
 memset(&r,0xa5,sizeof(r));int rc=tb_epoch_stop(&f.epoch,f.io.deadline,&r);
 no_legacy_or_queries(&f);CHECK(rc==0);CHECK(f.io.reports==retry+1);valid_result(&f,&r);
 if(repeated) {
  struct tb_epoch_result first=r;
  memset(&r,0x5a,sizeof(r));f.io.error=-EIO;
  CHECK(tb_epoch_stop(&f.epoch,f.io.deadline,&r)==0);
  CHECK(f.io.reports==retry+1);valid_result(&f,&r);
  CHECK(memcmp(&r.stats,&first.stats,sizeof(r.stats))==0);
  CHECK(memcmp(&r.transport,&first.transport,sizeof(r.transport))==0);
 }
 CHECK(tb_epoch_close(&f.epoch)==0);CHECK(f.io.closes==2);CHECK(tb_guard_delete(f.guard)==0);
}
static void failed(int error,unsigned malformed,bool prior,bool cancelled,bool deadline) {
 struct fixture f;struct tb_epoch_result r;struct tb_guard_snapshot s;
 init(&f,false);
 if(prior){f.io.arm_error=-EIO;CHECK(tb_epoch_start(&f.epoch,3,17)==-EIO);}
 f.io.error=error;f.io.malformed=malformed;f.io.hold_on_return=cancelled;
 if(deadline)f.io.retry=100;
 memset(&r,0xa5,sizeof(r));int rc=tb_epoch_stop(&f.epoch,f.io.deadline,&r);
 no_legacy_or_queries(&f);CHECK(rc<0);
 if(error)CHECK(rc==error);
 if(malformed)CHECK(rc==-EPROTO);
 if(deadline)CHECK(rc==-ETIMEDOUT);
 CHECK(!r.stats_valid&&!r.transport_valid&&!r.stop_proved&&!f.epoch.stop_proved);
 CHECK(r.fate==TB_EPOCH_HELD);tb_guard_snapshot(f.guard,&s);
 CHECK(s.held&&s.phase==TB_PHASE_HELD&&s.cleanup_permissions==0);
 CHECK(r.stop_error==rc);CHECK(r.first_error==(prior?-EIO:rc));
 unsigned calls=f.io.reports;
 CHECK(tb_epoch_stop(&f.epoch,f.io.deadline,&r)==-EPERM);
 CHECK(f.io.reports==calls&&f.io.legacy==0);
 CHECK(tb_epoch_close(&f.epoch)==-EPERM&&f.io.closes==0);
 CHECK(f.epoch.ring_fd==41&&f.epoch.event_fd==42);
 CHECK(tb_guard_delete(f.guard)==-EPERM);
}
int main(int argc,char **argv) {
 CHECK(argc==2);const char *name=argv[1];
 if(!strcmp(name,"completed"))successful(true,false,0,false);
 else if(!strcmp(name,"bringup"))successful(false,false,0,false);
 else if(!strcmp(name,"idempotent"))successful(true,true,0,false);
 else if(!strcmp(name,"eagain-reset"))successful(true,false,2,false);
 else if(!strcmp(name,"poll-eintr"))successful(true,false,1,true);
 else if(!strcmp(name,"unsupported"))failed(-EOPNOTSUPP,0,false,false,false);
 else if(!strcmp(name,"invalid-opcode"))failed(-EINVAL,0,false,false,false);
 else if(!strcmp(name,"quarantine"))failed(-EBUSY,0,false,false,false);
 else if(!strcmp(name,"copy-fault"))failed(-EFAULT,0,false,false,false);
 else if(!strcmp(name,"release-error"))failed(-EIO,0,false,false,false);
 else if(!strcmp(name,"prior-error"))failed(-EBUSY,0,true,false,false);
 else if(!strcmp(name,"cancel-late-success"))failed(0,0,false,true,false);
 else if(!strcmp(name,"absolute-deadline"))failed(0,0,false,false,true);
 else if(!strncmp(name,"malformed-",10)) {
  unsigned n=(unsigned)strtoul(name+10,NULL,10);CHECK(n>=1&&n<=9);failed(0,n,false,false,false);
 }else CHECK(!"unknown independent test");
 printf("PASS %s: actual epoch/guard, external metadata only\n",name);return 0;
}

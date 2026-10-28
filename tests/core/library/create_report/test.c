/* SPDX-License-Identifier: GPL-2.0 */
/* Independent SDD oracle; only syscall boundaries are injected. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "include/uapi/linux/io_uring.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext_internal.h"

_Static_assert(sizeof(struct xdev_ext_mech_create_with_report) == 496, "accepted envelope");
_Static_assert(sizeof(struct xdev_ext_mech_create_report) == 288, "accepted report");
static unsigned checks, failures, cases, before;
#define EQ(a,b) do { long long av=(long long)(a), bv=(long long)(b); checks++; if(av!=bv) { fprintf(stderr,"# line %d %s got=%lld want=%lld\n",__LINE__,#a,av,bv); failures++; } } while(0)
#define BEGIN(n) do { before=failures; cases++; printf("# %s\n",n); } while(0)
#define END(n) printf("%s %u - %s\n", failures==before?"ok":"not ok",cases,n)
static struct xdev_ext_mech_create_report reply;
static struct xdev_ext_mech_create captured;
static int syscall_error, stop_error, wire_mutation;
static unsigned calls[32], bad_request, calls_total;
static int last_fd, last_pool, setup_fd;

static int unconsumed(const struct xdev_ext_mech_create_report *out)
{
 struct xdev_ext_mech_create_report zero={0};
 return !memcmp(out,&zero,sizeof(zero));
}
static struct xdev_ext_mech_create request(void)
{
 struct xdev_ext_mech_create c={.abi_version=XDEV_EXT_MECH_ABI_VERSION,
 .nr_stages=1,.pool_kind=XDEV_EXT_MECH_POOL_PEER,.pool_fd=51,
 .layout={65536,0,4096,4096},.depth=1,.eventfd=-1};
 c.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=52,.arg0=123};
 return c;
}
static void reset(int result, unsigned cleanup)
{
 memset(calls,0,sizeof(calls)); calls_total=bad_request=0; syscall_error=stop_error=wire_mutation=0;
 memset(&reply,0,sizeof(reply)); reply.size=288; reply.version=1;
 reply.result=result; reply.cleanup=cleanup;
 if(result) { reply.phase=12; reply.failed_stage=0; reply.valid=15;
 reply.requester.domain=3; reply.requester.bus=4; reply.requester.devfn=17;
 reply.caps.size=64; reply.caps.version=1; reply.caps.stage=0;
 reply.caps.family=XDEV_EXT_FAMILY_NETWORK; reply.caps.reachability=3; reply.caps.refused=1;
 } else { reply.session_id=71; reply.failed_stage=UINT32_MAX; }
}
static int setup(unsigned entries,struct io_uring_params *p)
{ (void)entries;(void)p;setup_fd=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK); return setup_fd; }
static int registration(int fd,unsigned opcode,void *arg,unsigned nr)
{
 struct io_uring_xdev_ext_mech *m=arg; void *p;
 calls_total++; last_fd=fd;
 if(nr!=1 || opcode!=IORING_REGISTER_XDEV_EXT_MECH) {bad_request++;return -EINVAL;}
 if(m->op>=32) {bad_request++;return -EINVAL;}
 calls[m->op]++; if(m->rsvd) bad_request++;
 p=(void *)(uintptr_t)m->arg;
 if(m->op==10) {
  struct xdev_ext_mech_create_with_report *e=p; struct xdev_ext_mech_create_report zero={0};
  if(e->size!=496 || e->version!=1 || memcmp(&e->report,&zero,sizeof(zero))) bad_request++;
  captured=e->create; last_pool=captured.pool_fd;
  if(syscall_error) return syscall_error;
  e->report=reply; if(!reply.result)e->create.session_id=reply.session_id;
  if(wire_mutation==1)e->size--;
  if(wire_mutation==2)e->version++;
  if(wire_mutation==3)e->create.session_id=999;
  return 0;
 }
 if(m->op==XDEV_EXT_MECH_OP_CREATE) {captured=*(struct xdev_ext_mech_create *)p;last_pool=captured.pool_fd;((struct xdev_ext_mech_create *)p)->session_id=71;return syscall_error;}
 if(m->op==XDEV_EXT_MECH_OP_STATS) {
  struct xdev_ext_mech_stats *s=p; if(!s->session_id) bad_request++;
  return -ENOENT;
 }
 if(m->op==XDEV_EXT_MECH_OP_STOP) {if(!m->arg)bad_request++;return stop_error;}
 return -EINVAL;
}
static struct xdev_ext_sys hooks={.io_uring_setup=setup,.io_uring_register=registration};
static void raw_negative(void)
{
 struct xdev_ext_mech_create c=request();struct xdev_ext_mech_create_report out;
 BEGIN("delivered negative is original error and complete value");reset(-EXDEV,1);memset(&out,0xa5,sizeof(out));
 EQ(xdev_ext_create_report_read(43,&c,&out),-EXDEV);EQ(memcmp(&out,&reply,sizeof(out)),0);
 EQ(calls[10],1);EQ(calls[XDEV_EXT_MECH_OP_CREATE],0);EQ(last_fd,43);EQ(bad_request,0);EQ(memcmp(&c,&captured,sizeof(c)),0); END("delivered negative is original error and complete value");
}
static void syscall_failure(void)
{
 struct xdev_ext_mech_create c=request();int errors[]={-EINVAL,-EOPNOTSUPP,-EFAULT,-EINTR};
 for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
 struct xdev_ext_mech_create_report out;BEGIN("syscall failure neither consumes output nor retries");reset(0,0);syscall_error=errors[i];memset(&out,0xa5,sizeof(out));
 EQ(xdev_ext_create_report_read(43,&c,&out),errors[i]);EQ(unconsumed(&out),1);EQ(calls_total,1);EQ(calls[10],1);EQ(calls[XDEV_EXT_MECH_OP_CREATE],0);END("syscall failure neither consumes output nor retries");
 }
}
static void delivery_identity(void)
{
 struct xdev_ext_mech_create c=request();
 for(int k=1;k<=3;k++) {
 struct xdev_ext_mech_create_report out;BEGIN("envelope identity must match complete delivery");reset(0,0);wire_mutation=k;memset(&out,0xa5,sizeof(out));
 EQ(xdev_ext_create_report_read(43,&c,&out),-EPROTO);EQ(unconsumed(&out),1);EQ(calls_total,1);END("envelope identity must match complete delivery");
 }
 struct xdev_ext_mech_create_report out;
 BEGIN("failed transport clears previously delivered negative report");reset(-EXDEV,1);out=reply;syscall_error=-EOPNOTSUPP;
 EQ(xdev_ext_create_report_read(43,&c,&out),-EOPNOTSUPP);EQ(unconsumed(&out),1);EQ(calls_total,1);END("failed transport clears previously delivered negative report");
}
static void malformed(void)
{
 struct xdev_ext_mech_create c=request();
 /* Each mutation independently falsifies the accepted response contract. */
 const char *names[]={"report size","report version","unknown valid","unknown cleanup","positive result","success missing ID","success failure phase","failed report nonzero ID","requester reserved","requester bus overflow","requester devfn overflow","caps size","caps version","caps foreign session","caps wrong stage","observed size","observed version","observed foreign session","observed wrong stage","observed unknown valid","observed unknown readiness","observed reversed time","observed reserved"};
 for(unsigned k=0;k<sizeof(names)/sizeof(names[0]);k++) {
 struct xdev_ext_mech_create_report out;BEGIN(names[k]);reset(k<7?0:-EXDEV,k<7?0:1);
 if(k>=15) {reply.valid|=16;reply.observed.size=sizeof(reply.observed);reply.observed.version=1;reply.observed.stage=0;reply.observed.valid=1;reply.observed.token=123;reply.observed.local_inc=2;reply.observed.remote_inc=3;reply.observed.capture_begin_ns=4;reply.observed.capture_end_ns=5;}
 switch(k) {
 case 0:reply.size--;break;case 1:reply.version++;break;case 2:reply.valid|=1U<<31;break;case 3:reply.cleanup=3;break;case 4:reply.result=1;break;case 5:reply.session_id=0;break;case 6:reply.phase=12;break;
 case 7:reply.session_id=71;break;case 8:reply.requester.rsvd=1;break;case 9:reply.requester.bus=256;break;case 10:reply.requester.devfn=256;break;
 case 11:reply.caps.size--;break;case 12:reply.caps.version++;break;case 13:reply.caps.session_id=71;break;case 14:reply.caps.stage=1;break;
 case 15:reply.observed.size--;break;case 16:reply.observed.version++;break;case 17:reply.observed.session_id=71;break;case 18:reply.observed.stage=1;break;case 19:reply.observed.valid|=1U<<31;break;case 20:reply.observed.readiness|=1U<<31;break;case 21:reply.observed.capture_end_ns=3;break;case 22:reply.observed.rsvd=1;break;
 }
 memset(&out,0xa5,sizeof(out));EQ(xdev_ext_create_report_read(43,&c,&out),-EPROTO);EQ(unconsumed(&out),1);EQ(calls_total,1);END(names[k]);
 }
}
static struct xdev_ext_session *new_session(int *authority)
{
 struct xdev_ext_session *s=NULL;*authority=eventfd(0,EFD_CLOEXEC);
 struct xdev_ext_peer_pool_opts p=XDEV_EXT_OPTS_INIT(xdev_ext_peer_pool_opts,.allocation_fd=*authority);
 EQ(xdev_ext_session_open_peer(&p,&s),0);return s;
}
static struct xdev_ext_create_opts options(void)
{
 struct xdev_ext_create_opts o=XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,.group_bytes=4096,.depth=1,.nr_stages=1);
 o.st[0]=request().st[0];return o;
}
static void released(void)
{
 int a;struct xdev_ext_mech_create_report out,saved;struct xdev_ext_create_opts o=options();
 BEGIN("released failed report survives library close");reset(-EXDEV,1);reply.rollback_errno=-EIO;struct xdev_ext_session *s=new_session(&a);
 EQ(xdev_ext_session_create_report(s,&o,&out),-EXDEV);saved=out;EQ(xdev_ext_session_id(s),0);EQ(xdev_ext_session_retained(s),0);
 EQ(xdev_ext_session_close(s),0);EQ(memcmp(&out,&saved,sizeof(out)),0);EQ(calls[10],1);EQ(calls[XDEV_EXT_MECH_OP_STATS],0);EQ(calls[XDEV_EXT_MECH_OP_STOP],0);EQ(fcntl(a,F_GETFD)>=0,1);close(a);END("released failed report survives library close");
}
static void retained(void)
{
 int a;struct xdev_ext_mech_create_report out,saved,retry_out;struct xdev_ext_create_opts o=options();
 BEGIN("retained failed CREATE blocks recreation and preserves owner authority");reset(-EXDEV,2);reply.rollback_errno=-EIO;struct xdev_ext_session *s=new_session(&a);
 EQ(xdev_ext_session_create_report(s,&o,&out),-EXDEV);saved=out;int pool=last_pool,ring=xdev_ext_session_ring_fd(s);
 EQ(xdev_ext_session_id(s),0);EQ(xdev_ext_session_retained(s),1);
 EQ(xdev_ext_session_create(s,&o),-EBUSY);EQ(xdev_ext_session_create_report(s,&o,&retry_out),-EBUSY);
 EQ(xdev_ext_session_close(s),-EBUSY);EQ(calls[10],1);EQ(calls[XDEV_EXT_MECH_OP_CREATE],0);EQ(calls[XDEV_EXT_MECH_OP_STATS],0);EQ(calls[XDEV_EXT_MECH_OP_STOP],0);EQ(fcntl(pool,F_GETFD)>=0,1);EQ(fcntl(ring,F_GETFD)>=0,1);EQ(memcmp(&out,&saved,sizeof(out)),0);EQ(bad_request,0);
 /* No release query token exists: intentionally retained until process exit. */
 close(a);END("retained failed CREATE blocks recreation and preserves owner authority");
}
static void success_and_legacy(void)
{
 int a,b;struct xdev_ext_mech_create_report out;struct xdev_ext_create_opts o=options();struct xdev_ext_mech_create old,new;
 BEGIN("new success publishes ID with unchanged legacy CREATE packing");reset(0,0);struct xdev_ext_session *s=new_session(&a);
 EQ(xdev_ext_session_create(s,&o),0);old=captured;EQ(calls[XDEV_EXT_MECH_OP_CREATE],1);EQ(calls[10],0);EQ(xdev_ext_session_id(s),71);EQ(xdev_ext_session_close(s),0);close(a);
 reset(0,0);s=new_session(&b);EQ(xdev_ext_session_create_report(s,&o,&out),0);new=captured;EQ(calls[10],1);EQ(calls[XDEV_EXT_MECH_OP_CREATE],0);EQ(xdev_ext_session_id(s),71);EQ(out.session_id,71);EQ(xdev_ext_session_retained(s),0);
 /* Owned descriptor numbers vary, all semantic CREATE fields must match. */
 old.pool_fd=new.pool_fd;old.eventfd=new.eventfd;EQ(memcmp(&old,&new,sizeof(old)),0);EQ(xdev_ext_session_close(s),0);close(b);END("new success publishes ID with unchanged legacy CREATE packing");
}
int main(void)
{
 setvbuf(stdout,NULL,_IOLBF,0);puts("TAP version 13");xdev_ext__set_sys(&hooks);
 raw_negative();syscall_failure();delivery_identity();malformed();released();retained();success_and_legacy();
 printf("1..%u\n# checks=%u failures=%u\n",cases,checks,failures);return failures?1:0;
}

/* SPDX-License-Identifier: GPL-2.0 */
#include "session_wire.h"
static struct sp_create_programs_wire selected_request(void)
{
 struct sp_create_programs_wire e={.size=520,.version=1,.program_fds={-1,-1,-1,-1}};
 e.request.size=496;e.request.version=1;e.request.create=request();return e;
}
static int dispatch_selected(struct sp_create_programs_wire *e)
{
 struct io_uring_xdev_ext_mech op={.op=12,.arg=(uintptr_t)e};
 return io_xdev_ext_mech_register(&ring,&op,1);
}
static int session_case(const char *name)
{
 struct sp_create_programs_wire e=selected_request(),before;
 int ret;
 reset();before=e;
 if(!strcmp(name,"default_delivery")) {
  ret=dispatch_selected(&e);
  if(ret){fprintf(stderr,"SESSION_ASSERT op12 delivered default CREATE result: syscall=%d expected0\n",ret);return 1;}
  CHECK(e.request.report.size==288&&e.request.report.version==1&&e.request.report.result==0);
  CHECK(e.request.create.session_id==117&&e.request.report.session_id==117);
  CHECK(e.size==before.size&&e.version==before.version&&!memcmp(e.program_fds,before.program_fds,16));
  CHECK(describes==1&&prepares==1&&published());
 } else if(!strcmp(name,"prepare_report")) {
  e.request.create.nr_stages=2;e.request.create.st[1]=e.request.create.st[0];prepare_stage=1;
  ret=dispatch_selected(&e);
  CHECK(ret==0&&e.request.report.result==-EACCES&&e.request.report.failed_stage==1);
  CHECK(e.request.report.cleanup==1&&!e.request.create.session_id&&!published());
  CHECK(!refs&&session_frees==1&&prepares==2);
 } else if(!strcmp(name,"unknown_retention")) {
  prepare_stage=0;checked_err=-EIO;ret=dispatch_selected(&e);
  CHECK(ret==0&&e.request.report.result==-EACCES&&e.request.report.rollback_errno==-EIO);
  CHECK(e.request.report.cleanup==2&&retained&&!session_frees&&!pool_frees);
 } else if(!strcmp(name,"copyout_failure")) {
  write_fault=true;ret=dispatch_selected(&e);
  CHECK(ret==-EFAULT&&!published()&&!queues&&session_frees==1&&!refs);
 } else if(!strcmp(name,"unused_selector")) {
  e.program_fds[3]=0;ret=dispatch_selected(&e);
  CHECK(ret==-EINVAL&&!describes&&!prepares&&!copyouts);
 } else if(!strcmp(name,"outer_shape")) {
  e.size=519;ret=dispatch_selected(&e);
  CHECK(ret==-EINVAL&&!describes&&!prepares&&!copyouts);
 } else if(!strcmp(name,"pool_role_unchanged")) {
  e.request.create.pool_kind=0;ret=dispatch_selected(&e);
  CHECK(ret==0&&e.request.report.result==-EINVAL&&!describes&&!prepares);
 } else return 2;
 printf("SESSION_CORE_ASSERTIONS %s 4\n",name);return 0;
}
int main(int argc,char **argv)
{ if(argc!=2)return 2;return session_case(argv[1]); }

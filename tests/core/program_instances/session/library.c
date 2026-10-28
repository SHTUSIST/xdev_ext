/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "include/uapi/linux/io_uring.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext_internal.h"
#include "session_wire.h"
extern int xdev_ext_create_programs_read(int,const struct xdev_ext_mech_create *,const int *,__u32,struct xdev_ext_mech_create_report *) __attribute__((weak));
extern int xdev_ext_session_create_programs(struct xdev_ext_session *,const struct xdev_ext_create_opts *,const int *,__u32,struct xdev_ext_mech_create_report *) __attribute__((weak));
static unsigned checks,failures,calls,legacy_calls,private_calls,bad;
static int sys_error,corrupt,setup_fd;
static struct xdev_ext_mech_create_report reply;
static struct sp_create_programs_wire captured;
#define EQ(a,b) do{long long av=(long long)(a),bv=(long long)(b);checks++;if(av!=bv){fprintf(stderr,"LIBRARY_ASSERT line%d %s got%lld want%lld\n",__LINE__,#a,av,bv);failures++;}}while(0)
static struct xdev_ext_mech_create request(void)
{
 struct xdev_ext_mech_create c={.abi_version=1,.nr_stages=2,.pool_kind=2,.pool_fd=-1,.layout={65536,0,4096,4096},.depth=1,.eventfd=-1};
 for(unsigned i=0;i<2;i++)c.st[i]=(struct xdev_ext_mech_stage_uapi){.class_id=9,.direction=1,.fd=-1,.arg0=10};
 return c;
}
static void reset(int result,int cleanup)
{
 calls=legacy_calls=private_calls=bad=0;sys_error=corrupt=0;
 memset(&reply,0,sizeof(reply));reply.size=288;reply.version=1;reply.result=result;reply.cleanup=cleanup;
 if(result){reply.phase=12;reply.failed_stage=0;reply.valid=15;reply.caps.size=64;reply.caps.version=1;reply.caps.stage=0;reply.caps.family=1;reply.caps.reachability=3;reply.caps.refused=1;}
 else{reply.session_id=71;reply.failed_stage=UINT32_MAX;}
}
static int setup(unsigned n,struct io_uring_params *p)
{(void)n;(void)p;setup_fd=eventfd(0,EFD_CLOEXEC);return setup_fd;}
static int registration(int fd,unsigned opcode,void *arg,unsigned count)
{
 struct io_uring_xdev_ext_mech *op=arg;struct xdev_ext_mech_create_report zero={0};
 if(opcode==IORING_REGISTER_XDEV_EXT_UMEM)return 0;
 if(opcode!=IORING_REGISTER_XDEV_EXT_MECH||count!=1||fd<0){bad++;return -EINVAL;}
 calls++;if(op->op!=12){legacy_calls++;return -EINVAL;}private_calls++;
 struct sp_create_programs_wire *e=(void *)(uintptr_t)op->arg;captured=*e;
 if(e->size!=520||e->version!=1||e->request.size!=496||e->request.version!=1||memcmp(&e->request.report,&zero,sizeof(zero)))bad++;
 if(e->program_fds[0]!=41||e->program_fds[1]!=42||e->program_fds[2]!=-1||e->program_fds[3]!=-1)bad++;
 if(sys_error)return sys_error;
 e->request.report=reply;if(!reply.result)e->request.create.session_id=71;
 if(corrupt==1)e->request.report.size=287;
 if(corrupt==2)e->request.create.session_id=99;
 if(corrupt==3)e->request.report.version=2;
 return 0;
}
static struct xdev_ext_sys hooks={.io_uring_setup=setup,.io_uring_register=registration};
static int zeroed(const void *p,size_t n){const unsigned char *b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;}
int main(void)
{
 int fds[2]={41,42};struct xdev_ext_mech_create c=request();struct xdev_ext_mech_create_report out;
 if(!xdev_ext_create_programs_read||!xdev_ext_session_create_programs){fprintf(stderr,"SETUP_MISSING_API: new library functions absent; not behavioral RED\n");return 2;}
 xdev_ext__set_sys(&hooks);
 reset(0,0);memset(&out,0xa5,sizeof(out));EQ(xdev_ext_create_programs_read(43,&c,fds,2,&out),0);EQ(calls,1);EQ(private_calls,1);EQ(legacy_calls,0);EQ(bad,0);EQ(out.session_id,71);EQ(c.session_id,0);EQ(memcmp(&c,&captured.request.create,sizeof(c)),0);
 for(unsigned i=0;i<4;i++){
  int errs[]={-EINVAL,-EOPNOTSUPP,-EFAULT,-EINTR};reset(0,0);sys_error=errs[i];memset(&out,0xa5,sizeof(out));
  EQ(xdev_ext_create_programs_read(43,&c,fds,2,&out),errs[i]);EQ(calls,1);EQ(legacy_calls,0);EQ(zeroed(&out,sizeof(out)),1);
 }
 reset(-EXDEV,1);EQ(xdev_ext_create_programs_read(43,&c,fds,2,&out),-EXDEV);EQ(memcmp(&out,&reply,sizeof(out)),0);EQ(calls,1);EQ(legacy_calls,0);
 reset(-EACCES,2);reply.rollback_errno=-EIO;EQ(xdev_ext_create_programs_read(43,&c,fds,2,&out),-EACCES);EQ(out.cleanup,2);EQ(out.rollback_errno,-EIO);
 for(int i=1;i<=3;i++){reset(0,0);corrupt=i;memset(&out,0xa5,sizeof(out));EQ(xdev_ext_create_programs_read(43,&c,fds,2,&out),-EPROTO);EQ(zeroed(&out,sizeof(out)),1);EQ(calls,1);}
 reset(0,0);EQ(xdev_ext_create_programs_read(43,&c,fds,1,&out),-EINVAL);EQ(calls,0);
 EQ(xdev_ext_create_programs_read(43,&c,NULL,2,&out),-EINVAL);EQ(calls,0);
 EQ(xdev_ext_create_programs_read(43,&c,fds,2,NULL),-EINVAL);EQ(calls,0);
 fds[0]=-2;EQ(xdev_ext_create_programs_read(43,&c,fds,2,&out),-EINVAL);EQ(calls,0);fds[0]=41;
 struct xdev_ext_pool_opts pool={.sz=sizeof(pool),.pool_kind=2,.nr_frames=4};struct xdev_ext_session *s=NULL;
 EQ(xdev_ext_session_open(&pool,&s),0);
 struct xdev_ext_create_opts opts={.sz=sizeof(opts),.group_bytes=4096,.depth=1,.nr_stages=2,.layout={65536,0,4096,4096}};memcpy(opts.st,c.st,sizeof(opts.st));
 reset(-EACCES,2);reply.rollback_errno=-EIO;
 EQ(xdev_ext_session_create_programs(s,&opts,fds,2,NULL),-EACCES);EQ(calls,1);
 EQ(xdev_ext_session_create_programs(s,&opts,fds,2,&out),-EBUSY);EQ(calls,1);
 /* An intentionally retained kernel allocation forbids the library freeing
  * the handle; this short syscall-boundary test exits without using the pool. */
 printf("SESSION_LIBRARY_ASSERTIONS %u failures=%u\n",checks,failures);return failures?1:0;
}

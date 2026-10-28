// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "session_wire.h"
struct program{struct bpf_object *object;struct bpf_map *map;struct bpf_link *link;};
struct session{int fd;void *memory;uint64_t id,done;};
#define REGISTERED_BYTES (4U*65536U)
#define GUARD_POISON 0xa6U
static void seed(struct session *s)
{memset(s->memory,GUARD_POISON,REGISTERED_BYTES);memset(s->memory,0,8);}
static unsigned checks,failures,cases;
#define CHECK(c) do{checks++;if(!(c)){failures++;fprintf(stderr,"GUEST_ASSERT %s:%d %s errno=%d\n",__func__,__LINE__,#c,errno);return 1;}}while(0)
static int mech(int fd,unsigned op,void *p)
{struct io_uring_xdev_ext_mech m={.op=op,.arg=(uintptr_t)p};int r=syscall(__NR_io_uring_register,fd,IORING_REGISTER_XDEV_EXT_MECH,&m,1);return r<0?-errno:r;}
static int ring_open(void){struct io_uring_params p={0};int fd=syscall(__NR_io_uring_setup,8,&p);return fd<0?-errno:fd;}
static int memory_open(struct session *s)
{
 s->fd=ring_open();if(s->fd<0)return s->fd;
 s->memory=mmap(NULL,4*65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,-1,0);
 if(s->memory==MAP_FAILED)return -errno;
 struct io_uring_xdev_ext_umem_reg r={.addr=(uintptr_t)s->memory,.size=4*65536,.frame_size=65536};
 int ret=syscall(__NR_io_uring_register,s->fd,IORING_REGISTER_XDEV_EXT_UMEM,&r,1);return ret<0?-errno:ret;
}
static struct sp_create_programs_wire request(int first,int second)
{
 struct sp_create_programs_wire e={.size=520,.version=1,.program_fds={first,second,-1,-1}};
 e.request.size=496;e.request.version=1;
 e.request.create=(struct xdev_ext_mech_create){.abi_version=1,.nr_stages=2,.pool_kind=2,.pool_fd=-1,.layout={.frame_size=65536,.hdr_room=0,.seg_len=4096,.group_bytes=4096},.depth=1,.eventfd=-1};
 for(unsigned i=0;i<2;i++)e.request.create.st[i]=(struct xdev_ext_mech_stage_uapi){.class_id=9,.direction=1,.fd=-1,.arg0=10};
 return e;
}
static int create(struct session *s,int a,int b)
{
 struct sp_create_programs_wire e=request(a,b);int ret=mech(s->fd,12,&e);
 if(ret)return ret;
 if(e.request.report.size!=288||e.request.report.version!=1)return -EPROTO;
 if(e.request.report.result)return e.request.report.result;
 if(!e.request.create.session_id||e.request.create.session_id!=e.request.report.session_id)return -EPROTO;
 s->id=e.request.report.session_id;return 0;
}
static int stats(struct session *s,struct xdev_ext_mech_stats *st)
{memset(st,0,sizeof(*st));st->session_id=s->id;return mech(s->fd,4,st);}
static int start(struct session *s)
{
 __u32 index=0;struct xdev_ext_mech_start p={.session_id=s->id,.nr_batches=1,.first_seq=s->done+1,.flags=XDEV_EXT_MECH_START_F_USER_FRAMES,.nr_user_frames=1,.user_frames=(uintptr_t)&index};
 return mech(s->fd,2,&p);
}
static int finish(struct session *s,uint64_t want)
{
 struct xdev_ext_mech_stats st;
 for(unsigned n=0;n<10000;n++){
  int ret=stats(s,&st);if(ret)return ret;
  if(st.last_err||st.batches_abort||st.sequestered)return st.last_err?st.last_err:-EIO;
  if(st.batches_done>s->done&&!st.inflight){uint64_t got;memcpy(&got,s->memory,8);if(got!=want){fprintf(stderr,"GUEST_WORD got=%llx want=%llx\n",(unsigned long long)got,(unsigned long long)want);return -EBADMSG;}
   const unsigned char *bytes=s->memory;
   for(size_t i=8;i<REGISTERED_BYTES;i++)if(bytes[i]!=GUARD_POISON){fprintf(stderr,"GUEST_GUARD offset=%zu got=%02x want=a6\n",i,bytes[i]);return -EBADMSG;}
   s->done=st.batches_done;return 0;}
  usleep(1000);
 }
 return -ETIMEDOUT;
}
static int execute(struct session *s,uint64_t want)
{seed(s);int ret=start(s);return ret?ret:finish(s,want);}
static void close_session(struct session *s)
{if(s->id)mech(s->fd,3,(void *)(uintptr_t)s->id);if(s->fd>=0)close(s->fd);if(s->memory&&s->memory!=MAP_FAILED)munmap(s->memory,4*65536);}
static int load(const char *directory,const char *name,struct program *p)
{
 char path[4096];snprintf(path,sizeof(path),"%s/%s.bpf.o",directory,name);
 p->object=bpf_object__open_file(path,NULL);long ret=libbpf_get_error(p->object);if(ret)return ret;
 ret=bpf_object__load(p->object);if(ret)return ret;
 p->map=bpf_object__find_map_by_name(p->object,"sp_ops");if(!p->map)return -ENOENT;
 p->link=bpf_map__attach_struct_ops(p->map);return libbpf_get_error(p->link);
}
static int fd(struct program *p){return bpf_link__fd(p->link);}
static int probe_wire(void)
{
 int ring=ring_open();CHECK(ring>=0);
 struct sp_create_programs_wire e=request(-1,-1);e.request.create.abi_version=0;
 int ret=mech(ring,12,&e);close(ring);
 CHECK(ret==0);CHECK(e.request.report.size==288&&e.request.report.version==1);
 CHECK(e.request.report.result==-EINVAL&&e.request.report.cleanup==0&&!e.request.report.session_id);
 puts("ok - actual opcode12 delivers rejected pure CREATE report");cases++;return 0;
}
int main(int argc,char **argv)
{
 if(argc==2&&!strcmp(argv[1],"--wire-only"))return probe_wire();
 if(argc!=2){fprintf(stderr,"usage: %s object-directory | --wire-only\n",argv[0]);return 2;}
 CHECK(!probe_wire());
 struct program global={0},a={0},b={0},wrong={0},fail={0};
 CHECK(!load(argv[1],"default",&global));CHECK(!load(argv[1],"a",&a));CHECK(!load(argv[1],"b",&b));
 struct session sa={.fd=-1},sb={.fd=-1},sg={.fd=-1};
 CHECK(!memory_open(&sa)&&!memory_open(&sb)&&!memory_open(&sg));
 CHECK(!create(&sa,fd(&a),fd(&b))&&!create(&sb,fd(&b),fd(&a))&&!create(&sg,-1,-1));
 seed(&sa);seed(&sb);seed(&sg);
 CHECK(!start(&sa)&&!start(&sb)&&!start(&sg));
 CHECK(!finish(&sa,0x1117)&&!finish(&sb,0x1711)&&!finish(&sg,0x2b2b));
 puts("ok - two private sessions repeated same class plus unchanged default exact payloads");cases++;
 struct bpf_link *second=bpf_map__attach_struct_ops(b.map);CHECK(!libbpf_get_error(second));
 struct session sibling={.fd=-1};CHECK(!memory_open(&sibling));CHECK(!create(&sibling,bpf_link__fd(second),-1));CHECK(!execute(&sibling,0x172b));
 CHECK(!bpf_link__detach(b.link));CHECK(start(&sa)<0&&start(&sb)<0);CHECK(!execute(&sibling,0x172b)&&!execute(&sg,0x2b2b));
 puts("ok - detach one same-map link preserves other link and default");cases++;
 struct bpf_link *reattach=bpf_map__attach_struct_ops(b.map);CHECK(!libbpf_get_error(reattach));
 struct session fresh={.fd=-1};CHECK(!memory_open(&fresh));CHECK(!create(&fresh,bpf_link__fd(reattach),-1));
 CHECK(!execute(&fresh,0x172b));CHECK(start(&sa)<0&&start(&sb)<0);CHECK(!execute(&sibling,0x172b));
 bpf_link__destroy(reattach);CHECK(start(&fresh)<0);CHECK(!execute(&sibling,0x172b)&&!execute(&sg,0x2b2b));
 puts("ok - reattach creates fresh liveness and last user link close retracts it");cases++;
 CHECK(!load(argv[1],"wrong",&wrong));CHECK(!load(argv[1],"fail",&fail));
 int nonlink=eventfd(0,EFD_CLOEXEC);CHECK(nonlink>=0);
 int badfds[]={1000000,nonlink,fd(&wrong),fd(&global)};int wants[]={-EBADF,-EINVAL,-EINVAL,-ENOENT};
 for(unsigned i=0;i<4;i++){
  struct session n={.fd=-1};CHECK(!memory_open(&n));CHECK(create(&n,badfds[i],-1)==wants[i]);
  CHECK(!n.id);close_session(&n);
 }
 close(nonlink);puts("ok - absent nonlink wrong-class and nonprivate explicit fd never fallback");cases++;
 struct session pf={.fd=-1};CHECK(!memory_open(&pf));
 struct sp_create_programs_wire e=request(fd(&a),fd(&fail));int ret=mech(pf.fd,12,&e);
 CHECK(ret==0&&e.request.report.result==-EACCES&&e.request.report.failed_stage==1&&e.request.report.cleanup==1&&!e.request.report.session_id);
 CHECK(!execute(&sg,0x2b2b)&&!execute(&sibling,0x172b));close_session(&pf);
 puts("ok - second PREPARE failure rolls back private pins without harming other programs");cases++;
 close_session(&sa);close_session(&sb);close_session(&sg);close_session(&sibling);close_session(&fresh);
 bpf_link__destroy(second);bpf_link__destroy(a.link);bpf_link__destroy(b.link);bpf_link__destroy(global.link);bpf_link__destroy(wrong.link);bpf_link__destroy(fail.link);
 bpf_object__close(a.object);bpf_object__close(b.object);bpf_object__close(global.object);bpf_object__close(wrong.object);bpf_object__close(fail.object);
 printf("SESSION_GUEST_ASSERTIONS checks=%u cases=%u failures=%u\n",checks,cases,failures);return failures?1:0;
}

// SPDX-License-Identifier: GPL-2.0
/* Independent guest: one controller START; NVMe READ -> CE TO -> CE FROM ->
 * ordinary SOCKET sink. CPU CE simulation and local UDP copy are explicit.
 * No disk writes, no per-batch controller pumping, no remote-ACK claim. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "observations.h"
#define GROUPS 257U
#define DEPTH 8U
#define PAYLOAD 8192U
#define FRAME 4096U
#define HEAD 256U
#define SEG 2048U
#define FRAMES 4U
#define POOL_FRAMES 64U
#define POOL_BYTES (POOL_FRAMES*FRAME)
#define CE_BYTES (256U*1024U)
static int bad;
#define REQUIRE(x) do{if(!(x)){fprintf(stderr,"FAIL socket_guest line=%d expr=%s errno=%d\n",__LINE__,#x,errno);bad=1;goto out;}}while(0)
static int mech(int ring,__u32 op,__u64 arg)
{
 struct io_uring_xdev_ext_mech r={.op=op,.arg=arg};
 int n=syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_MECH,&r,1);
 return n<0?-errno:n;
}
static uint64_t now_ms(void)
{struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static int refs(void)
{FILE *f=fopen("/sys/module/xdev_ext_ce_sim/refcnt","r");int n=-1;if(f){if(fscanf(f,"%d",&n)!=1)n=-1;fclose(f);}return n;}
static uint64_t device_stat(const char *name)
{
 char path[160];uint64_t n=UINT64_MAX;snprintf(path,sizeof(path),"/sys/module/xdev_ext_ce_sim/parameters/%s",name);
 FILE *f=fopen(path,"r");if(f){unsigned long long v;if(fscanf(f,"%llu",&v)==1)n=v;fclose(f);}return n;
}
static int exact_read(int fd,void *buf,size_t size,uint64_t offset)
{
 size_t done=0;while(done<size){ssize_t n=pread(fd,(char *)buf+done,size-done,offset+done);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;done+=n;}return 0;
}
struct receiver {int fd,error;unsigned datagrams;size_t bytes;const unsigned char *expected;};
static void *receive_all(void *arg)
{
 struct receiver *r=arg;unsigned char bytes[PAYLOAD+1];
 for(unsigned group=0;group<GROUPS;group++){
  ssize_t n;do{n=recv(r->fd,bytes,sizeof(bytes),0);}while(n<0&&errno==EINTR);
  if(n!=PAYLOAD || memcmp(bytes,r->expected+(size_t)group*PAYLOAD,PAYLOAD)){
   fprintf(stderr,"FAIL socket_guest peer group=%u got=%zd expected=%u errno=%d\n",group,n,PAYLOAD,errno);r->error=1;return NULL;
  }
  r->datagrams++;r->bytes+=n;
 }
 return NULL;
}
int main(int argc,char **argv)
{
 if(argc!=6){fprintf(stderr,"usage: socket_runtime CE_OBSERVE.bpf.o SOCKET_SINK.bpf.o NVME_CHAR NVME_BLOCK SOURCE_SLBA\n");return 1;}
 char *end;errno=0;uint64_t source_slba=strtoull(argv[5],&end,0);if(errno||*end||source_slba>UINT64_MAX/512)return 1;
 uint64_t source_off=source_slba*512,disk_size=0,deadline;
 struct bpf_object *ce_object=NULL,*socket_object=NULL;struct bpf_map *map=NULL;
 struct bpf_link *ce_link=NULL,*socket_link=NULL;
 struct socket_guest_observations obs={0};__u32 zero=0;
 struct io_uring_params params={0};
 struct io_uring_xdev_ext_umem_reg reg={.size=POOL_BYTES,.frame_size=FRAME};
 struct xdev_ext_mech_create create={.abi_version=XDEV_EXT_MECH_ABI_VERSION,.nr_stages=4,
  .pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM,.pool_fd=-1,.depth=DEPTH,.eventfd=-1,
  .layout={.frame_size=FRAME,.hdr_room=HEAD,.seg_len=SEG,.group_bytes=PAYLOAD}};
 __u32 indices[DEPTH*FRAMES];
 struct xdev_ext_mech_start start={.nr_batches=GROUPS,.first_seq=1,
  .flags=XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_RECYCLE,
  .nr_user_frames=DEPTH*FRAMES,.user_frames=(uintptr_t)indices};
 struct xdev_ext_mech_stats stats={0};
 unsigned char *pool=MAP_FAILED,*source_before=NULL,*source_after=NULL,*ce_data=NULL;
 int ng=-1,block=-1,ce=-1,ring=-1,tx=-1,rx=-1,created=0,stopped=0,watching=0,initial_refs=-1;
 pthread_t thread;struct receiver peer={0};
 struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};setrlimit(RLIMIT_MEMLOCK,&limit);
 block=open(argv[4],O_RDONLY|O_CLOEXEC);REQUIRE(block>=0);REQUIRE(!ioctl(block,BLKGETSIZE64,&disk_size));
 REQUIRE(disk_size && disk_size<=256ULL*1024*1024 && source_off<=disk_size && GROUPS*PAYLOAD<=disk_size-source_off);
 source_before=malloc(disk_size);source_after=malloc(disk_size);REQUIRE(source_before&&source_after);REQUIRE(!exact_read(block,source_before,disk_size,0));
 /* Unique real source groups prevent a reused slot or periodic fill passing. */
 for(unsigned g=0;g<GROUPS;g++)for(unsigned h=0;h<g;h++)REQUIRE(memcmp(source_before+source_off+(size_t)g*PAYLOAD,source_before+source_off+(size_t)h*PAYLOAD,PAYLOAD));
 ng=open(argv[3],O_RDONLY|O_CLOEXEC);REQUIRE(ng>=0);ce=open("/dev/xdev_ext_ce_sim",O_RDWR|O_CLOEXEC);REQUIRE(ce>=0);
 initial_refs=refs();REQUIRE(initial_refs>=1);REQUIRE(device_stat("accepted")==0&&device_stat("completed")==0&&device_stat("pending")==0);
 ce_data=malloc(CE_BYTES);REQUIRE(ce_data);memset(ce_data,0x38,CE_BYTES);REQUIRE(pwrite(ce,ce_data,CE_BYTES,0)==CE_BYTES);
 ce_object=bpf_object__open_file(argv[1],NULL);REQUIRE(ce_object&&!libbpf_get_error(ce_object));REQUIRE(!bpf_object__load(ce_object));
 map=bpf_object__find_map_by_name(ce_object,"socket_guest_ce_ops");REQUIRE(map);ce_link=bpf_map__attach_struct_ops(map);REQUIRE(!libbpf_get_error(ce_link));
 socket_object=bpf_object__open_file(argv[2],NULL);REQUIRE(socket_object&&!libbpf_get_error(socket_object));REQUIRE(!bpf_object__load(socket_object));
 map=bpf_object__find_map_by_name(socket_object,"socket_sink_ops");REQUIRE(map);socket_link=bpf_map__attach_struct_ops(map);REQUIRE(!libbpf_get_error(socket_link));
 rx=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);tx=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);REQUIRE(rx>=0&&tx>=0);
 int buffer=4*1024*1024;REQUIRE(!setsockopt(rx,SOL_SOCKET,SO_RCVBUF,&buffer,sizeof(buffer)));
 struct timeval timeout={.tv_sec=30};REQUIRE(!setsockopt(rx,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
 struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};socklen_t address_len=sizeof(address);
 REQUIRE(!bind(rx,(struct sockaddr *)&address,sizeof(address)));REQUIRE(!getsockname(rx,(struct sockaddr *)&address,&address_len));REQUIRE(!connect(tx,(struct sockaddr *)&address,address_len));
 ring=syscall(__NR_io_uring_setup,8,&params);REQUIRE(ring>=0);
 pool=mmap(NULL,POOL_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);REQUIRE(pool!=MAP_FAILED);memset(pool,0x97,POOL_BYTES);
 reg.addr=(uintptr_t)pool;REQUIRE(!syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_UMEM,&reg,1));
 create.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=ng,.arg0=source_slba,.arg1=GROUPS*(PAYLOAD/512)};
 create.st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_CE,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=ce,.arg0=0,.arg1=CE_BYTES};
 create.st[2]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_CE,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=ce,.arg0=0,.arg1=CE_BYTES};
 create.st[3]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_SOCKET,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=tx};
 REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_CREATE,(uintptr_t)&create));created=1;REQUIRE(refs()>=initial_refs+2);
 /* The core must retain the original file even after the caller closes its fd. */
 REQUIRE(!close(tx));tx=-1;
 for(unsigned i=0;i<DEPTH*FRAMES;i++)indices[i]=2*i+1;
 peer=(struct receiver){.fd=rx,.expected=source_before+source_off};REQUIRE(!pthread_create(&thread,NULL,receive_all,&peer));watching=1;
 start.session_id=create.session_id;REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_START,(uintptr_t)&start));
 deadline=now_ms()+30000;
 do{
  stats=(struct xdev_ext_mech_stats){.session_id=create.session_id};REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&stats));
  if((stats.batches_done==GROUPS&&stats.published==DEPTH*FRAMES&&!stats.inflight)||stats.batches_abort||stats.sequestered||stats.last_err)break;
  usleep(1000);
 }while(now_ms()<deadline);
 fprintf(stderr,"socket_guest diagnostic state=%u done=%llu abort=%llu rejects=%llu sequestered=%llu timeouts=%llu inflight=%llu last_err=%d stage_submitted=%llu,%llu,%llu,%llu stage_completed=%llu,%llu,%llu,%llu ce_accepted=%llu ce_completed=%llu\n",
  stats.state,(unsigned long long)stats.batches_done,(unsigned long long)stats.batches_abort,
  (unsigned long long)stats.rejects,(unsigned long long)stats.sequestered,
  (unsigned long long)stats.timeouts,(unsigned long long)stats.inflight,stats.last_err,
  (unsigned long long)stats.submitted[0],(unsigned long long)stats.submitted[1],
  (unsigned long long)stats.submitted[2],(unsigned long long)stats.submitted[3],
  (unsigned long long)stats.completed[0],(unsigned long long)stats.completed[1],
  (unsigned long long)stats.completed[2],(unsigned long long)stats.completed[3],
  (unsigned long long)device_stat("accepted"),(unsigned long long)device_stat("completed"));
 map=bpf_object__find_map_by_name(ce_object,"socket_observations");
 if(map && !bpf_map_lookup_elem(bpf_map__fd(map),&zero,&obs))
  fprintf(stderr,"socket_guest CE diagnostic build=%llu complete=%llu invalid=%llu slot_mask=%llu last_group=%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
   (unsigned long long)obs.build,(unsigned long long)obs.complete,
   (unsigned long long)obs.invalid,(unsigned long long)obs.slot_mask,
   (unsigned long long)obs.last_group[0],(unsigned long long)obs.last_group[1],
   (unsigned long long)obs.last_group[2],(unsigned long long)obs.last_group[3],
   (unsigned long long)obs.last_group[4],(unsigned long long)obs.last_group[5],
   (unsigned long long)obs.last_group[6],(unsigned long long)obs.last_group[7]);
 else fprintf(stderr,"socket_guest CE diagnostic lookup_failed errno=%d\n",errno);
 REQUIRE(stats.state==XDEV_EXT_MECH_SESSION_ACTIVE&&stats.batches_done==GROUPS&&!stats.batches_abort&&!stats.rejects&&!stats.sequestered&&!stats.timeouts&&!stats.inflight&&!stats.protocol_err&&!stats.last_err);
 for(unsigned i=0;i<4;i++)REQUIRE(stats.submitted[i]==GROUPS&&stats.completed[i]==GROUPS);
 REQUIRE(stats.published==DEPTH*FRAMES);
 REQUIRE(!pthread_join(thread,NULL));watching=0;REQUIRE(!peer.error&&peer.datagrams==GROUPS&&peer.bytes==(size_t)GROUPS*PAYLOAD);
 unsigned char extra[PAYLOAD+1];REQUIRE(recv(rx,extra,sizeof(extra),MSG_DONTWAIT)<0&&(errno==EAGAIN||errno==EWOULDBLOCK));
 map=bpf_object__find_map_by_name(ce_object,"socket_observations");REQUIRE(map);REQUIRE(!bpf_map_lookup_elem(bpf_map__fd(map),&zero,&obs));
 REQUIRE(obs.build==2*GROUPS&&obs.complete==2*GROUPS&&obs.slot_mask==255&&!obs.invalid);
 REQUIRE(pread(ce,ce_data,CE_BYTES,0)==CE_BYTES);
 for(unsigned slot=0;slot<DEPTH;slot++){REQUIRE(obs.last_group[slot]<GROUPS);REQUIRE(!memcmp(ce_data+slot*PAYLOAD,source_before+source_off+obs.last_group[slot]*PAYLOAD,PAYLOAD));}
 for(unsigned i=DEPTH*PAYLOAD;i<CE_BYTES;i++)REQUIRE(ce_data[i]==0x38);
 for(unsigned frame=0;frame<POOL_FRAMES;frame++)for(unsigned byte=0;byte<FRAME;byte++)if(!(frame&1)||byte<HEAD||byte>=HEAD+SEG)REQUIRE(pool[frame*FRAME+byte]==0x97);
 REQUIRE(!exact_read(block,source_after,disk_size,0));REQUIRE(!memcmp(source_before,source_after,disk_size));
 REQUIRE(device_stat("accepted")==2*GROUPS&&device_stat("completed")==2*GROUPS&&device_stat("pending")==0);
 REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_STOP,create.session_id));stopped=1;REQUIRE(refs()==initial_refs);
 REQUIRE(mech(ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&stats)==-ENOENT);
 printf("PASS socket_guest groups=257 depth=8 slots=8 controller_START=1 actual_nvme_source=1 unique_groups=257 datagrams=257 peer_bytes=%u full_compare=1 source_whole_disk_unchanged=1 pool_guards=1 ce_guards=1 ce_slot_data=1 stage_counts=257,257,257,257 ce_accepted=514 ce_completed=514 pending=0 original_socket_fd_closed=1 STOP=0 owner_refs_released=1 CE_CPU_simulation=1 socket_native_copy=1 local_completion_not_remote_ACK=1\n",GROUPS*PAYLOAD);
out:
 if(created&&!stopped&&ring>=0){int ret=mech(ring,XDEV_EXT_MECH_OP_STOP,create.session_id);if(ret)fprintf(stderr,"FAIL socket_guest cleanup_STOP=%d\n",ret);}
 if(watching){shutdown(rx,SHUT_RD);pthread_join(thread,NULL);}
 if(ring>=0)close(ring);
 if(pool!=MAP_FAILED)munmap(pool,POOL_BYTES);
 if(socket_link&&!libbpf_get_error(socket_link))bpf_link__destroy(socket_link);
 if(ce_link&&!libbpf_get_error(ce_link))bpf_link__destroy(ce_link);
 if(socket_object&&!libbpf_get_error(socket_object))bpf_object__close(socket_object);
 if(ce_object&&!libbpf_get_error(ce_object))bpf_object__close(ce_object);
 if(rx>=0)close(rx);
 if(tx>=0)close(tx);
 if(ce>=0)close(ce);
 if(ng>=0)close(ng);
 if(block>=0)close(block);
 free(source_before);free(source_after);free(ce_data);return bad?1:0;
}

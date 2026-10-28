// SPDX-License-Identifier: GPL-2.0
/* Software correctness only. Existing peer_sw supplies allocation RAM; the
 * real USER mmap protocol/core and NVMe provider perform all session work.
 * No libxdev_ext functions, payload mmap, added devices or timing results.
 * Usage: ordered_frames_guest DST_BLOCK DST_NG BPF_DIR DST_SLBA
 * DST must be a dedicated scratch device (<= 128 MiB). It is snapshotted in
 * full. Exactly six 6144-byte messages may change at DST_SLBA; STOP changes
 * no bytes. The independent Python validator checks before/after snapshots.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_mech.h"
#include "linux/xdev_ext_peer.h"
#include "../../../xdev_ext_peer/guest/sw_provider_uapi.h"

#define FRAME 4096U
#define OFF 512U
#define SEG 3072U
#define GROUP (2U * SEG)
#define MESSAGES 6U
#define DEPTH 2U
#define ENTRIES 2U
#define FIRST 101U
#define LIMIT_MS 120000U
static unsigned checks;
#define CHECK(c, msg) do { if (!(c)) { \
 fprintf(stderr,"not ok %u - %s (errno=%d %s)\n",++checks,msg,errno,strerror(errno)); \
 exit(1); } printf("ok %u - %s\n",++checks,msg); } while (0)
static const __u32 selected[] = {7,3,9,1};
static int mech(int fd,__u32 op,__u64 arg)
{
 struct io_uring_xdev_ext_mech r={.op=op,.arg=arg};
 int ret=syscall(__NR_io_uring_register,fd,IORING_REGISTER_XDEV_EXT_MECH,&r,1);
 return ret<0?-errno:ret;
}
static unsigned char payload(unsigned frame,unsigned byte)
{
 return (unsigned char)(0x43U+37U*frame+11U*byte+19U*(byte>>8));
}
static int open_ok(const char *name,int flags)
{
 int fd=open(name,flags|O_CLOEXEC);CHECK(fd>=0,name);return fd;
}
struct ops {struct bpf_object *obj;struct bpf_link *link;};
static void attach(struct ops *o,const char *dir,const char *name)
{
 char path[PATH_MAX];struct bpf_map *m;
 CHECK(snprintf(path,sizeof(path),"%s/%s.bpf.o",dir,name)<(int)sizeof(path),"BPF path fits");
 o->obj=bpf_object__open_file(path,NULL);
 CHECK(!libbpf_get_error(o->obj),"open BPF struct_ops");
 CHECK(!bpf_object__load(o->obj),"load BPF struct_ops");o->link=NULL;
 bpf_object__for_each_map(m,o->obj) if(bpf_map__type(m)==BPF_MAP_TYPE_STRUCT_OPS){o->link=bpf_map__attach_struct_ops(m);break;}
 CHECK(o->link&&!libbpf_get_error(o->link),"attach BPF struct_ops");
}
struct session {
 int ring;struct xdev_ext_mech_create c;struct xdev_ext_mech_user_stage u;
 unsigned char *map;struct xdev_ext_user_ring_hdr *h;
 struct xdev_ext_user_ready *ready;struct xdev_ext_user_done *done;
 struct xdev_ext_user_slot *slots;__u64 last_ticket[DEPTH];
};
static void create(struct session *s,int allocation,int ng,__u64 slba)
{
 struct io_uring_params p={0};memset(s,0,sizeof(*s));
 s->ring=syscall(__NR_io_uring_setup,8,&p);CHECK(s->ring>=0,"raw io_uring setup");
 s->u=(struct xdev_ext_mech_user_stage){.size=sizeof(s->u),.entries=ENTRIES,.eventfd=-1};
 CHECK(!mech(s->ring,XDEV_EXT_MECH_OP_USER_STAGE,(uintptr_t)&s->u),"raw USER stage create");
 s->map=mmap(NULL,s->u.off.mmap_size,PROT_READ|PROT_WRITE,MAP_SHARED,s->u.fd,0);
 CHECK(s->map!=MAP_FAILED,"raw USER metadata mmap");
 s->h=(void *)(s->map+s->u.off.hdr);s->ready=(void *)(s->map+s->u.off.ready);
 s->done=(void *)(s->map+s->u.off.done);s->slots=(void *)(s->map+s->u.off.slots);
 s->c=(struct xdev_ext_mech_create){.abi_version=XDEV_EXT_MECH_ABI_VERSION,
  .nr_stages=2,.pool_kind=XDEV_EXT_MECH_POOL_PEER,.pool_fd=allocation,
  .layout={FRAME,OFF,SEG,GROUP},.depth=DEPTH,.eventfd=-1};
 s->c.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_USER,
  .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=s->u.fd,
  .flags=XDEV_EXT_USER_F_STRICT_ASYNC|XDEV_EXT_MECH_STAGE_F_POLL,.arg0=60000};
 s->c.st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,
  .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=ng,.arg0=slba,.arg1=MESSAGES*GROUP/512};
 CHECK(!mech(s->ring,XDEV_EXT_MECH_OP_CREATE,(uintptr_t)&s->c),"strict PEER USER -> NVMe CREATE");
 struct xdev_ext_mech_start r={.session_id=s->c.session_id,.nr_batches=MESSAGES,.first_seq=FIRST,
  .flags=XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_ORDERED_FRAMES|XDEV_EXT_MECH_START_F_RECYCLE,
  .nr_user_frames=4,.user_frames=(uintptr_t)selected};
 CHECK(!mech(s->ring,XDEV_EXT_MECH_OP_START,(uintptr_t)&r),"one ordered START [7,3,9,1] for six messages");
}
static struct xdev_ext_mech_stats stats(struct session *s)
{
 struct xdev_ext_mech_stats st={.session_id=s->c.session_id};
 if(mech(s->ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&st))CHECK(false,"STATS during active session");
 return st;
}
static struct xdev_ext_user_ready take(struct session *s,unsigned ordinal)
{
 __u32 cons=__atomic_load_n(&s->h->ready_cons,__ATOMIC_RELAXED),prod=cons;
 for(unsigned n=0;n<LIMIT_MS;n++){
  prod=__atomic_load_n(&s->h->ready_prod,__ATOMIC_ACQUIRE);if(prod!=cons)break;usleep(1000);
 }
 CHECK(prod-cons>0&&prod-cons<=ENTRIES,"bounded raw ready window");
 struct xdev_ext_user_ready r=s->ready[cons&(ENTRIES-1)];
 CHECK(r.slot<DEPTH&&r.nr_frames==2&&r.key==FIRST+ordinal,"ready key and fixed shape follow START order");
 struct xdev_ext_user_slot *slot=&s->slots[r.slot];
 CHECK(r.ticket&&slot->ticket==r.ticket&&slot->nr_frames==2,"ready binds current slot/ticket");
 CHECK(r.ticket>s->last_ticket[r.slot],"recycled batch slot ticket increases");s->last_ticket[r.slot]=r.ticket;
 for(unsigned j=0;j<2;j++){
  struct xdev_ext_user_frame *f=&slot->f[j];
  CHECK(f->umem_addr==(__u64)selected[(ordinal%2)*2+j]*FRAME&&f->data_off==OFF&&
        f->data_len==SEG&&f->out_len==SEG&&f->capacity==FRAME-OFF,
        "raw PEER slot exposes exact allocation offset and complete span");
 }
 __atomic_store_n(&s->h->ready_cons,cons+1,__ATOMIC_RELEASE);return r;
}
static void complete(struct session *s,struct xdev_ext_user_ready r)
{
 __u32 prod=__atomic_load_n(&s->h->done_prod,__ATOMIC_RELAXED);
 __u32 cons=__atomic_load_n(&s->h->done_cons,__ATOMIC_ACQUIRE);
 CHECK(prod-cons<ENTRIES,"raw done ring has room");
 CHECK(__atomic_load_n(&s->slots[r.slot].ticket,__ATOMIC_ACQUIRE)==r.ticket,"external lease remains held until done publication");
 s->done[prod&(ENTRIES-1)]=(struct xdev_ext_user_done){.ticket=r.ticket,.slot=r.slot,.status=0};
 __atomic_store_n(&s->h->done_prod,prod+1,__ATOMIC_RELEASE);
 /* Deliberately no KICK: strict POLL must discover every done. */
}
static void wait_done(struct session *s,unsigned count)
{
 struct xdev_ext_mech_stats st={0};
 for(unsigned n=0;n<LIMIT_MS;n++){
  st=stats(s);if(st.batches_done==count&&!st.inflight)break;
  if(count==1&&st.batches_done==1)break;
  usleep(1000);
 }
 CHECK(st.batches_done==count&&!st.batches_abort&&!st.sequestered&&!st.last_err,
       "native completions count successful whole messages without isolation");
 if(count==MESSAGES)CHECK(!st.inflight&&st.published==4&&st.submitted[1]==MESSAGES&&st.completed[1]==MESSAGES,
                         "six native writes retire four loans once");
}
static void close_session(struct session *s)
{
 CHECK(!munmap(s->map,s->u.off.mmap_size),"unmap metadata after drain");
 CHECK(!close(s->u.fd)&&!close(s->ring),"close USER and ring after STOP");
}
struct stopping {struct session *s;int ret;};
static void *stop_thread(void *arg)
{
 struct stopping *v=arg;v->ret=mech(v->s->ring,XDEV_EXT_MECH_OP_STOP,v->s->c.session_id);return NULL;
}
static void stop_late(struct session *s)
{
 struct xdev_ext_user_ready a=take(s,0),b=take(s,1);struct stopping v={s,INT_MIN};pthread_t t;
 struct xdev_ext_mech_stats st=stats(s);
 CHECK(st.inflight==2&&!st.batches_done&&!st.submitted[1],"STOP starts with two external leases and no downstream DMA");
 CHECK(!pthread_create(&t,NULL,stop_thread,&v),"STOP runs concurrently with external completion");
 unsigned flags=0;
 for(unsigned n=0;n<500;n++){
  flags=__atomic_load_n(&s->h->kernel_flags,__ATOMIC_ACQUIRE);
  if(flags&XDEV_EXT_USER_K_DRAINING)break;
  usleep(1000);
 }
 CHECK(flags&XDEV_EXT_USER_K_DRAINING,"strict STOP publishes DRAINING before grace expires");
 CHECK(s->slots[a.slot].ticket==a.ticket&&s->slots[b.slot].ticket==b.ticket,"STOP retains both original tickets pending late completion");
 complete(s,a);complete(s,b);CHECK(!pthread_join(t,NULL),"join STOP after late status-zero done");
 CHECK(v.ret==0,"late done permits STOP drain/release");
 CHECK(!s->slots[a.slot].ticket&&!s->slots[b.slot].ticket,"drain clears matched external leases");
 st=(struct xdev_ext_mech_stats){.session_id=s->c.session_id};
 CHECK(mech(s->ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&st)==-ENOENT,"STOP removed released session");
}
static void read_disk(int fd,void *buf,size_t bytes)
{
 CHECK(pread(fd,buf,bytes,0)==(ssize_t)bytes,"read complete scratch destination with direct I/O");
}
int main(int argc,char **argv)
{
 CHECK(argc==5,"usage: DST_BLOCK DST_NG BPF_DIR DST_SLBA");
 char *end;errno=0;__u64 slba=strtoull(argv[4],&end,0);
 CHECK(!errno&&!*end&&slba<=UINT64_MAX/512,"valid destination LBA");
 int disk=open_ok(argv[1],O_RDONLY|O_DIRECT),ng=open_ok(argv[2],O_RDWR);
 __u64 bytes=0;CHECK(!ioctl(disk,BLKGETSIZE64,&bytes)&&bytes&&bytes<=128U*1024U*1024U&&!(bytes%4096),"bounded whole scratch device geometry");
 CHECK(slba*512<=bytes&&MESSAGES*GROUP<=bytes-slba*512,"entire output span fits scratch destination");
 unsigned char *before=NULL,*after=NULL,*expect=NULL;
 CHECK(!posix_memalign((void**)&before,4096,bytes)&&!posix_memalign((void**)&after,4096,bytes)&&!posix_memalign((void**)&expect,4096,bytes),"aligned whole-disk snapshots");
 read_disk(disk,before,bytes);memcpy(expect,before,bytes);
 unsigned char seed[PEER_SW_BYTES];
 for(unsigned i=0;i<PEER_SW_BYTES;i++)seed[i]=payload(i/FRAME,i%FRAME);
 int provider=open_ok("/dev/xdev_ext_peer_sw",O_RDWR),ctl=open_ok("/dev/xdev_ext_peer",O_RDWR);
 CHECK(pwrite(provider,seed,sizeof(seed),0)==sizeof(seed),"seed existing software allocation with distinct full frames");
 struct xdev_ext_peer_register reg={.gpu_fd=provider,.gpu_va=PEER_SW_VA,.len=PEER_SW_BYTES};
 int allocation=ioctl(ctl,XDEV_EXT_PEER_REGISTER,&reg);CHECK(allocation>=0&&reg.generation,"register existing provider allocation");
 struct ops nvme={0},user={0};attach(&nvme,argv[3],"ordered_frames_nvme");attach(&user,argv[3],"user_plan");
 struct session s;create(&s,allocation,ng,slba);
 struct xdev_ext_user_ready held=take(&s,0),other=take(&s,1);complete(&s,other);wait_done(&s,1);
 __u32 prod=__atomic_load_n(&s.h->ready_prod,__ATOMIC_ACQUIRE);
 for(unsigned n=0;n<20;n++){
  CHECK(__atomic_load_n(&s.h->ready_prod,__ATOMIC_ACQUIRE)==prod&&s.slots[held.slot].ticket==held.ticket,
        "free template1 cannot bypass externally held template0");usleep(1000);
 }
 complete(&s,held);
 for(unsigned ordinal=2;ordinal<MESSAGES;ordinal++)complete(&s,take(&s,ordinal));
 wait_done(&s,MESSAGES);CHECK(!mech(s.ring,XDEV_EXT_MECH_OP_STOP,s.c.session_id),"normal STOP releases successful session");close_session(&s);
 for(unsigned ordinal=0;ordinal<MESSAGES;ordinal++)for(unsigned j=0;j<2;j++)
  memcpy(expect+slba*512+ordinal*GROUP+j*SEG,seed+selected[(ordinal%2)*2+j]*FRAME+OFF,SEG);
 read_disk(disk,after,bytes);CHECK(!memcmp(after,expect,bytes),"whole destination oracle: six exact ordered spans and every outside byte unchanged");
 /* A new CREATE proves the same allocation was released; STOP with late
  * done must retain responsibility, suppress the consumer and preserve disk. */
 create(&s,allocation,ng,slba);stop_late(&s);close_session(&s);
 read_disk(disk,after,bytes);CHECK(!memcmp(after,expect,bytes),"whole destination unchanged by strict STOP/late-done drain");
 bpf_link__destroy(user.link);bpf_object__close(user.obj);bpf_link__destroy(nvme.link);bpf_object__close(nvme.obj);
 CHECK(!close(allocation)&&!close(ctl)&&!close(provider)&&!close(ng)&&!close(disk),"close provider and device resources");
 free(before);free(after);free(expect);
 puts("XDEV_EXT_ORDERED_FRAMES_GUEST=PASS messages=6 selected=7,3,9,1 raw_user=1 poll_without_kick=1 whole_disk=1 stop_late=1 timing=none");
 printf("1..%u\n",checks);return 0;
}

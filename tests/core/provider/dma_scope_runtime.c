// SPDX-License-Identifier: GPL-2.0
/* Native software correctness only: existing provider, pair and kernel path. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "dma_provider_fixture.h"
#include "dma_campaign.h"

#define FRAME 4096U
#define POOL_BYTES (32U * FRAME)
#define HEAD 256U
#define SEG 1024U
#define PAYLOAD (2U * SEG)
#define WAIT_MS 10000U
static int failure_line;
#define CHECK(v) do { if (!(v)) { \
 fprintf(stderr,"FAIL line %d: %s (errno=%d)\n",__LINE__,#v,errno); \
 failure_line=__LINE__; \
 goto out; } } while (0)

struct session {
 int fd, ring, created, stopped, stop_ret, dma_refs, ce_refs;
 unsigned char *window, *pool;
 /* Fixed expectations are generated before START, never from observed bytes. */
 unsigned char *initial, *expected, *pool_expected;
 struct xdev_ext_mech_create create;
 struct xdev_ext_mech_stats stats;
 struct dma_fixture_stats device;
};
struct test {
 const char *scenario, *dir;
 int ce, map_fd, receipt;
 struct bpf_object *object;
 struct bpf_link *dma_link, *ce_link;
 struct dma_fixture_observation obs;
 unsigned char *ce_bytes, *ce_expected;
 struct session first, second;
};

static int mech(int ring, __u32 op, __u64 arg)
{
 struct io_uring_xdev_ext_mech req={.op=op,.arg=arg};
 int ret=syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_MECH,&req,1);
 return ret<0 ? -errno : ret;
}
static uint64_t now_ms(void)
{
 struct timespec t;
 clock_gettime(CLOCK_MONOTONIC,&t);
 return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static int module_refs(const char *name)
{
 char path[160];
 int refs=-1;
 snprintf(path,sizeof(path),"/sys/module/%s/refcnt",name);
 FILE *f=fopen(path,"r");
 if(f) { if(fscanf(f,"%d",&refs)!=1)refs=-1; fclose(f); }
 return refs;
}
static int fixture_param(const char *name,unsigned value)
{
 char path[160],value_text[32];
 snprintf(path,sizeof(path),"/sys/module/xdev_ext_dma_provider_sim/parameters/%s",name);
 int fd=open(path,O_WRONLY|O_CLOEXEC);
 if(fd<0)return -1;
 int n=snprintf(value_text,sizeof(value_text),"%u\n",value);
 int ret=write(fd,value_text,(size_t)n)==n ? 0 : -1;
 if(close(fd))ret=-1;
 return ret;
}
static int blob(struct test *t,const char *phase,const char *suffix,
                const void *data,size_t bytes)
{
 char path[4096];
 int n=snprintf(path,sizeof(path),"%s/%s.%s",t->dir,phase,suffix);
 if(n<0 || (size_t)n>=sizeof(path)) { errno=ENAMETOOLONG;return -1; }
 int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
 if(fd<0)return -1;
 const unsigned char *p=data;
 int ret=0;
 while(bytes) {
  ssize_t written=write(fd,p,bytes);
  if(written<0 && errno==EINTR)continue;
  if(written<=0) { ret=-1;break; }
  p+=written;bytes-=(size_t)written;
 }
 if(fsync(fd))ret=-1;
 if(close(fd))ret=-1;
 return ret;
}
static int observe(struct test *t)
{
 __u32 zero=0;
 return bpf_map_lookup_elem(t->map_fd,&zero,&t->obs);
}
static int sample(struct session *s)
{
 s->stats=(struct xdev_ext_mech_stats){.session_id=s->create.session_id};
 return mech(s->ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&s->stats) ||
        ioctl(s->fd,DMA_FIXTURE_STATS,&s->device) ? -1 : 0;
}
static int snapshot(struct test *t,struct session *s,const char *phase,int query)
{
 if(query && sample(s))return -1;
 if(!s->created && ioctl(s->fd,DMA_FIXTURE_STATS,&s->device))return -1;
 if(observe(t))return -1;
 if(pread(t->ce,t->ce_bytes,DMA_FIXTURE_WINDOW_BYTES,0)!=DMA_FIXTURE_WINDOW_BYTES)return -1;
 if(blob(t,phase,"device.bin",s->window,DMA_FIXTURE_MAP_BYTES) ||
    blob(t,phase,"pool.bin",s->pool,POOL_BYTES) ||
    blob(t,phase,"ce.bin",t->ce_bytes,DMA_FIXTURE_WINDOW_BYTES) ||
    blob(t,phase,"session-stats.bin",&s->stats,sizeof(s->stats)) ||
    blob(t,phase,"provider-stats.bin",&s->device,sizeof(s->device)) ||
    blob(t,phase,"observations.bin",&t->obs,sizeof(t->obs)))return -1;
 int dma_refs=module_refs("xdev_ext_dma_provider_sim");
 int ce_refs=module_refs("xdev_ext_ce_sim");
 int ret=dprintf(t->receipt,
  "{\"phase\":\"%s\",\"scenario\":\"%s\",\"session\":%llu,\"state\":%u,"
  "\"done\":%llu,\"abort\":%llu,\"sequestered\":%llu,\"inflight\":%llu,\"last_err\":%d,"
  "\"submitted\":[%llu,%llu,%llu,%llu],\"stage_completed\":[%llu,%llu,%llu,%llu],"
  "\"accepted\":%llu,\"completed\":%llu,\"pending\":%llu,\"from\":%llu,\"to\":%llu,\"bytes\":%llu,"
  "\"region_binds\":%llu,\"host_binds\":%llu,\"region_unbinds\":%llu,\"host_unbinds\":%llu,"
  "\"dma_build\":%llu,\"dma_complete\":%llu,\"ce_build\":%llu,\"ce_complete\":%llu,"
  "\"wrong_base\":%llu,\"slot_mask\":%llu,\"source_slot0\":%u,\"sink_slot0\":%u,"
  "\"dma_refs\":%d,\"ce_refs\":%d,\"dma_refs_before_create\":%d,\"ce_refs_before_create\":%d,"
  "\"ce_refs_delta_from_create_baseline\":%d,"
  "\"stop_observed\":%d,\"stop_ret\":%d,\"session_stats_saved_before_stop\":%d}\n",
  phase,t->scenario,(unsigned long long)s->create.session_id,s->stats.state,
  (unsigned long long)s->stats.batches_done,(unsigned long long)s->stats.batches_abort,
  (unsigned long long)s->stats.sequestered,(unsigned long long)s->stats.inflight,s->stats.last_err,
  (unsigned long long)s->stats.submitted[0],(unsigned long long)s->stats.submitted[1],
  (unsigned long long)s->stats.submitted[2],(unsigned long long)s->stats.submitted[3],
  (unsigned long long)s->stats.completed[0],(unsigned long long)s->stats.completed[1],
  (unsigned long long)s->stats.completed[2],(unsigned long long)s->stats.completed[3],
  (unsigned long long)s->device.accepted,(unsigned long long)s->device.completed,
  (unsigned long long)s->device.pending,(unsigned long long)s->device.from_device,
  (unsigned long long)s->device.to_device,(unsigned long long)s->device.bytes,
  (unsigned long long)s->device.region_binds,(unsigned long long)s->device.host_binds,
  (unsigned long long)s->device.region_unbinds,(unsigned long long)s->device.host_unbinds,
  (unsigned long long)t->obs.dma_build,(unsigned long long)t->obs.dma_complete,
  (unsigned long long)t->obs.ce_build,(unsigned long long)t->obs.ce_complete,
  (unsigned long long)t->obs.wrong_base,(unsigned long long)t->obs.slot_mask,
  t->obs.source_slot[0],t->obs.sink_slot[0],dma_refs,ce_refs,s->dma_refs,s->ce_refs,ce_refs-s->ce_refs,
  s->stopped,s->stop_ret,s->stopped);
 printf("DMA_SCOPE phase=%s session=%llu done=%llu abort=%llu sequestered=%llu last_err=%d "
        "accepted=%llu completed=%llu pending=%llu dma_build=%llu dma_complete=%llu "
        "ce_build=%llu ce_complete=%llu dma_refs=%d ce_refs=%d\n",
        phase,(unsigned long long)s->create.session_id,(unsigned long long)s->stats.batches_done,
        (unsigned long long)s->stats.batches_abort,(unsigned long long)s->stats.sequestered,
        s->stats.last_err,(unsigned long long)s->device.accepted,
        (unsigned long long)s->device.completed,(unsigned long long)s->device.pending,
        (unsigned long long)t->obs.dma_build,(unsigned long long)t->obs.dma_complete,
        (unsigned long long)t->obs.ce_build,(unsigned long long)t->obs.ce_complete,dma_refs,ce_refs);
 return ret<0 || fsync(t->receipt) ? -1 : 0;
}
static void init_session(struct session *s)
{
 *s=(struct session){.fd=-1,.ring=-1,.window=MAP_FAILED,.pool=MAP_FAILED};
}
static int setup_session(struct test *t,struct session *s,int alias,int normal)
{
 struct io_uring_params params={0};
 struct io_uring_xdev_ext_umem_reg reg={.size=POOL_BYTES,.frame_size=FRAME};
 const char *label=alias ? "second" : s==&t->first ? "first" : "second";
 s->fd=alias ? fcntl(t->first.fd,F_DUPFD_CLOEXEC,0) :
              open("/dev/xdev_ext_dma_provider_sim",O_RDWR|O_CLOEXEC);
 if(s->fd<0)return -1;
 s->window=mmap(NULL,DMA_FIXTURE_MAP_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,s->fd,0);
 if(s->window==MAP_FAILED)return -1;
 s->initial=malloc(DMA_FIXTURE_MAP_BYTES);
 s->expected=malloc(DMA_FIXTURE_MAP_BYTES);
 s->pool_expected=malloc(POOL_BYTES);
 if(!s->initial || !s->expected || !s->pool_expected)return -1;
 memset(s->initial,0xa6,DMA_FIXTURE_MAP_BYTES);
 for(unsigned i=0;i<PAYLOAD;i++)s->initial[DMA_FIXTURE_INPUT_OFF+i]=campaign_pattern(0,i);
 memcpy(s->expected,s->initial,DMA_FIXTURE_MAP_BYTES);
 if(normal)for(unsigned i=0;i<PAYLOAD;i++)
  s->expected[DMA_FIXTURE_OUTPUT_OFF+i]=campaign_pattern(0,i);
 /* An alias must never reseed a quarantined backing. */
 if(!alias)memcpy(s->window,s->initial,DMA_FIXTURE_MAP_BYTES);
 if(memcmp(s->window,s->initial,DMA_FIXTURE_MAP_BYTES))return -1;
 s->pool=mmap(NULL,POOL_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 if(s->pool==MAP_FAILED)return -1;
 memset(s->pool,0x97,POOL_BYTES);
 memset(s->pool_expected,0x97,POOL_BYTES);
 if(s==&t->first || (strcmp(t->scenario,"dup-blocked") && strcmp(t->scenario,"legacy-blocked")))
  for(unsigned frame=0;frame<2;frame++)for(unsigned i=0;i<SEG;i++)
   s->pool_expected[(2*frame+1)*FRAME+HEAD+i]=campaign_pattern(0,frame*SEG+i);
 if(blob(t,label,"fixed-input.bin",s->initial,DMA_FIXTURE_MAP_BYTES) ||
    blob(t,label,"expected-device.bin",s->expected,DMA_FIXTURE_MAP_BYTES) ||
    blob(t,label,"expected-pool.bin",s->pool_expected,POOL_BYTES))return -1;
 s->ring=syscall(__NR_io_uring_setup,8,&params);
 if(s->ring<0)return -1;
 reg.addr=(uintptr_t)s->pool;
 if(syscall(__NR_io_uring_register,s->ring,IORING_REGISTER_XDEV_EXT_UMEM,&reg,1))return -1;
 s->create=(struct xdev_ext_mech_create){.abi_version=XDEV_EXT_MECH_ABI_VERSION,.nr_stages=4,
  .pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM,.pool_fd=-1,.depth=1,.eventfd=-1,
  .layout={.frame_size=FRAME,.hdr_room=HEAD,.seg_len=SEG,.group_bytes=PAYLOAD}};
 s->create.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_DMA,
  .direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=s->fd,
  .arg0=DMA_FIXTURE_INPUT_OFF,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 s->create.st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_CE,
  .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=t->ce,.arg0=0,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 s->create.st[2]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_CE,
  .direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=t->ce,.arg0=0,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 s->create.st[3]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_DMA,
  .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=s->fd,
  .arg0=DMA_FIXTURE_OUTPUT_OFF,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 s->dma_refs=module_refs("xdev_ext_dma_provider_sim");
 /* The one shared CE file stays open across both sessions and their STOPs. */
 s->ce_refs=module_refs("xdev_ext_ce_sim");
 if(s->dma_refs<1 || s->ce_refs<1)return -1;
 int ret=mech(s->ring,XDEV_EXT_MECH_OP_CREATE,(uintptr_t)&s->create);
 if(ret) { fprintf(stderr,"CREATE returned %d\n",ret);return -1; }
 s->created=1;
 if(module_refs("xdev_ext_dma_provider_sim")<s->dma_refs+2)return -1;
 errno=0;
 if(syscall(__NR_delete_module,"xdev_ext_dma_provider_sim",O_NONBLOCK)>=0 ||
    (errno!=EWOULDBLOCK && errno!=EBUSY))return -1;
 if(module_refs("xdev_ext_dma_provider_sim")<s->dma_refs+2)return -1;
 if(ioctl(s->fd,DMA_FIXTURE_STATS,&s->device))return -1;
 unsigned binds=alias ? 4 : 2;
 if(s->device.region_binds!=binds || s->device.host_binds!=binds ||
    s->device.accepted!=(alias ? 1U : 0U))return -1;
 return 0;
}
static int start_session(struct session *s)
{
 __u32 frames[2]={1,3};
 struct xdev_ext_mech_start start={.session_id=s->create.session_id,.nr_batches=1,
  .first_seq=0,.flags=XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_RECYCLE,
  .nr_user_frames=2,.user_frames=(uintptr_t)frames};
 return mech(s->ring,XDEV_EXT_MECH_OP_START,(uintptr_t)&start);
}
static int wait_terminal(struct session *s)
{
 uint64_t deadline=now_ms()+WAIT_MS;
 do {
  if(sample(s))return -1;
  if(s->stats.batches_abort || s->stats.sequestered ||
     (s->stats.batches_done==1 && !s->stats.inflight && !s->device.pending))return 0;
  usleep(1000);
 }while(now_ms()<deadline);
 return 0; /* The behavior assertions below diagnose the exact timeout. */
}
static int fault_before_stop(struct session *s)
{
 return s->stats.batches_done || !s->stats.last_err ||
  (!s->stats.batches_abort && !s->stats.sequestered) ||
  s->stats.sequestered!=2 || s->device.accepted!=1 || s->device.completed!=1 ||
  s->device.from_device!=1 || s->device.bytes!=PAYLOAD ||
  s->device.pending || s->device.to_device || s->device.region_unbinds || s->device.host_unbinds ||
  memcmp(s->window,s->initial,DMA_FIXTURE_MAP_BYTES) ||
  module_refs("xdev_ext_dma_provider_sim")<s->dma_refs+2 ? -1 : 0;
}
static int stop_fault(struct session *s)
{
 int ret=mech(s->ring,XDEV_EXT_MECH_OP_STOP,s->create.session_id);
 s->stop_ret=ret;
 printf("DMA_SCOPE fault_stop session=%llu ret=%d\n",(unsigned long long)s->create.session_id,ret);
 if(ret!=-EBUSY)return -1;
 s->stopped=1;
 if(ioctl(s->fd,DMA_FIXTURE_STATS,&s->device))return -1;
 return s->device.region_unbinds || s->device.host_unbinds ||
  module_refs("xdev_ext_dma_provider_sim")<s->dma_refs+2 ||
  module_refs("xdev_ext_ce_sim")<s->ce_refs+2 ? -1 : 0;
}
static int retained_first(struct test *t,int alias)
{
 struct session *s=&t->first;
 if(ioctl(s->fd,DMA_FIXTURE_STATS,&s->device))return -1;
 return s->device.accepted!=1 || s->device.completed!=1 || s->device.pending ||
  s->device.from_device!=1 || s->device.to_device || s->device.bytes!=PAYLOAD ||
  s->device.region_binds!=(alias ? 4U : 2U) || s->device.host_binds!=(alias ? 4U : 2U) ||
  s->device.region_unbinds || s->device.host_unbinds ||
  memcmp(s->window,s->initial,DMA_FIXTURE_MAP_BYTES) ||
  module_refs("xdev_ext_dma_provider_sim")<s->dma_refs+2 ||
  module_refs("xdev_ext_ce_sim")<s->ce_refs+2 ? -1 : 0;
}
static int normal_result(struct test *t,const struct dma_fixture_observation *base)
{
 struct session *s=&t->second;
 if(s->stats.batches_done!=1 || s->stats.batches_abort || s->stats.rejects ||
    s->stats.sequestered || s->stats.protocol_err || s->stats.inflight || s->stats.last_err)return -1;
 for(unsigned i=0;i<4;i++)if(s->stats.submitted[i]!=1 || s->stats.completed[i]!=1)return -1;
 if(memcmp(s->window,s->expected,DMA_FIXTURE_MAP_BYTES) ||
    memcmp(s->pool,s->pool_expected,POOL_BYTES))return -1;
 if(s->device.accepted!=2 || s->device.completed!=2 || s->device.pending ||
    s->device.from_device!=1 || s->device.to_device!=1 || s->device.bytes!=2U*PAYLOAD ||
    s->device.stale_callbacks)return -1;
 if(pread(t->ce,t->ce_bytes,DMA_FIXTURE_WINDOW_BYTES,0)!=DMA_FIXTURE_WINDOW_BYTES ||
    memcmp(t->ce_bytes,t->ce_expected,DMA_FIXTURE_WINDOW_BYTES))return -1;
 if(observe(t))return -1;
 return t->obs.dma_build-base->dma_build!=2 || t->obs.dma_complete-base->dma_complete!=2 ||
  t->obs.ce_build-base->ce_build!=2 || t->obs.ce_complete-base->ce_complete!=2 ||
  t->obs.wrong_base!=base->wrong_base || t->obs.slot_mask!=1 ||
  t->obs.source_slot[0] || t->obs.sink_slot[0] ? -1 : 0;
}
static int blocked_sample(struct test *t,const struct dma_fixture_stats *base,
                          const struct dma_fixture_observation *obs_base)
{
 struct session *s=&t->second;
 if(sample(s) || observe(t))return -1;
 if(s->device.accepted!=base->accepted || s->device.completed!=base->completed ||
    s->device.from_device!=base->from_device || s->device.to_device!=base->to_device ||
    s->device.bytes!=base->bytes || s->device.pending || s->device.region_unbinds || s->device.host_unbinds ||
    s->stats.batches_done || s->stats.batches_abort || s->stats.sequestered ||
    s->stats.last_err || s->stats.rejects || s->stats.protocol_err)return -1;
 for(unsigned i=0;i<4;i++)if(s->stats.completed[i])return -1;
 if(t->obs.dma_complete!=obs_base->dma_complete || t->obs.ce_build!=obs_base->ce_build ||
    t->obs.ce_complete!=obs_base->ce_complete || t->obs.wrong_base!=obs_base->wrong_base)return -1;
 return memcmp(s->window,s->initial,DMA_FIXTURE_MAP_BYTES) ? -1 : 0;
}
static void close_session(struct session *s)
{
 if(s->created && !s->stopped && s->ring>=0) {
  int ret=mech(s->ring,XDEV_EXT_MECH_OP_STOP,s->create.session_id);
  fprintf(stderr,"DMA_SCOPE cleanup_stop session=%llu ret=%d\n",(unsigned long long)s->create.session_id,ret);
 }
 if(s->ring>=0)close(s->ring);
 if(s->pool!=MAP_FAILED)munmap(s->pool,POOL_BYTES);
 if(s->window!=MAP_FAILED)munmap(s->window,DMA_FIXTURE_MAP_BYTES);
 if(s->fd>=0)close(s->fd);
 free(s->pool_expected);free(s->expected);free(s->initial);
}

int main(int argc,char **argv)
{
 if(argc!=4 || (strcmp(argv[2],"independent-normal") && strcmp(argv[2],"independent-ambiguous") &&
    strcmp(argv[2],"dup-blocked") && strcmp(argv[2],"legacy-blocked"))) {
  fprintf(stderr,"usage: %s PAIR.bpf.o {independent-normal|independent-ambiguous|dup-blocked|legacy-blocked} NEW_EVIDENCE_DIR\n",argv[0]);
  return 2;
 }
 struct test t={.scenario=argv[2],.dir=argv[3],.ce=-1,.map_fd=-1,.receipt=-1};
 struct dma_fixture_observation obs_base;
 struct dma_fixture_stats second_base;
 struct rlimit lim={RLIM_INFINITY,RLIM_INFINITY};
 const char *failure_kind="SETUP";
 char path[4096];
 int bad=1,alias=!strcmp(t.scenario,"dup-blocked");
 int normal=!strcmp(t.scenario,"independent-normal");
 int blocked=alias || !strcmp(t.scenario,"legacy-blocked");
 init_session(&t.first);init_session(&t.second);
 setvbuf(stdout,NULL,_IOLBF,0);
 setrlimit(RLIMIT_MEMLOCK,&lim);
 CHECK(!mkdir(t.dir,0700)); /* Refuse to overwrite evidence from any prior run. */
 CHECK(snprintf(path,sizeof(path),"%s/receipt.jsonl",t.dir)>0);
 t.receipt=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);CHECK(t.receipt>=0);
 CHECK(dprintf(t.receipt,"{\"scenario\":\"%s\",\"frame\":%u,\"pool_bytes\":%u,\"head\":%u,\"seg\":%u,\"payload\":%u,\"frames\":[1,3],\"sequence\":0,\"groups\":1,\"depth\":1,\"wait_ms\":%u,\"pattern\":\"campaign_pattern(0,byte)\",\"guard\":166,\"pool_guard\":151,\"ce_guard\":56}\n",
  t.scenario,FRAME,POOL_BYTES,HEAD,SEG,PAYLOAD,WAIT_MS)>0);
 CHECK(!fixture_param("fail_mode",2));
 CHECK(!fixture_param("delay_us",0));
 CHECK(!fixture_param("stale_replays",0));
 t.ce=open("/dev/xdev_ext_ce_sim",O_RDWR|O_CLOEXEC);CHECK(t.ce>=0);
 t.ce_bytes=malloc(DMA_FIXTURE_WINDOW_BYTES);CHECK(t.ce_bytes);
 t.ce_expected=malloc(DMA_FIXTURE_WINDOW_BYTES);CHECK(t.ce_expected);
 memset(t.ce_expected,0x38,DMA_FIXTURE_WINDOW_BYTES);
 CHECK(pwrite(t.ce,t.ce_expected,DMA_FIXTURE_WINDOW_BYTES,0)==DMA_FIXTURE_WINDOW_BYTES);
 CHECK(!blob(&t,"initial","ce.bin",t.ce_expected,DMA_FIXTURE_WINDOW_BYTES));
 if(normal)for(unsigned i=0;i<PAYLOAD;i++)t.ce_expected[i]=campaign_pattern(0,i);
 CHECK(!blob(&t,"final","expected-ce.bin",t.ce_expected,DMA_FIXTURE_WINDOW_BYTES));
 t.object=bpf_object__open_file(argv[1],NULL);
 CHECK(t.object && !libbpf_get_error(t.object));
 CHECK(!bpf_object__load(t.object));
 struct bpf_map *map=bpf_object__find_map_by_name(t.object,"dma_pair");CHECK(map);
 t.dma_link=bpf_map__attach_struct_ops(map);CHECK(t.dma_link && !libbpf_get_error(t.dma_link));
 map=bpf_object__find_map_by_name(t.object,"ce_pair");CHECK(map);
 t.ce_link=bpf_map__attach_struct_ops(map);CHECK(t.ce_link && !libbpf_get_error(t.ce_link));
 map=bpf_object__find_map_by_name(t.object,"observations");CHECK(map);
 CHECK(bpf_map__value_size(map)==sizeof(t.obs));
 t.map_fd=bpf_map__fd(map);CHECK(t.map_fd>=0);
 CHECK(!observe(&t));
 CHECK(!t.obs.dma_build && !t.obs.dma_complete && !t.obs.ce_build &&
       !t.obs.ce_complete && !t.obs.wrong_base && !t.obs.slot_mask);
 CHECK(!setup_session(&t,&t.first,0,0));
 CHECK(!snapshot(&t,&t.first,"first-created",1));
 failure_kind="BEHAVIOR";
 CHECK(!start_session(&t.first));
 CHECK(!wait_terminal(&t.first));
 CHECK(!snapshot(&t,&t.first,"first-short",0));
 CHECK(!fault_before_stop(&t.first));
 CHECK(t.obs.dma_build==1 && t.obs.dma_complete==1 && !t.obs.ce_build && !t.obs.ce_complete &&
       !t.obs.wrong_base && !t.obs.slot_mask);
 CHECK(!stop_fault(&t.first));
 CHECK(!snapshot(&t,&t.first,"first-stopped",0));
 CHECK(!retained_first(&t,0));
 /* Both callback accounting and the retained terminal state are known before
  * the global fault control is changed for the second request. */
 CHECK(!fixture_param("fail_mode",normal || blocked ? 0 : 3));
 CHECK(!setup_session(&t,&t.second,alias,normal));
 CHECK(!snapshot(&t,&t.second,"second-created",1));
 second_base=t.second.device;obs_base=t.obs;
 CHECK(!start_session(&t.second));
 if(blocked) {
  uint64_t deadline=now_ms()+WAIT_MS;
  do {
   CHECK(!blocked_sample(&t,&second_base,&obs_base));
   usleep(1000);
  }while(now_ms()<deadline);
  CHECK(t.obs.dma_build>obs_base.dma_build);
  CHECK(!snapshot(&t,&t.second,"second-blocked",0));
  for(unsigned i=0;i<POOL_BYTES;i++)CHECK(t.second.pool[i]==0x97);
 }else {
  CHECK(!wait_terminal(&t.second));
  CHECK(!snapshot(&t,&t.second,"second-terminal",0));
  /* This is a native-acceptance assertion, independent of the BPF build count. */
  CHECK(t.second.device.accepted>0);
  if(normal) {
   CHECK(!normal_result(&t,&obs_base));
   CHECK(!mech(t.second.ring,XDEV_EXT_MECH_OP_STOP,t.second.create.session_id));
   t.second.stopped=1;
   CHECK(!ioctl(t.second.fd,DMA_FIXTURE_STATS,&t.second.device));
   CHECK(t.second.device.region_unbinds==2 && t.second.device.host_unbinds==2);
   CHECK(module_refs("xdev_ext_dma_provider_sim")==t.second.dma_refs);
   CHECK(module_refs("xdev_ext_ce_sim")==t.second.ce_refs);
   CHECK(!snapshot(&t,&t.second,"second-stopped",0));
  }else {
   CHECK(!fault_before_stop(&t.second));
   CHECK(t.obs.dma_build-obs_base.dma_build==1 && t.obs.dma_complete-obs_base.dma_complete==1 &&
         t.obs.ce_build==obs_base.ce_build && t.obs.ce_complete==obs_base.ce_complete &&
         t.obs.wrong_base==obs_base.wrong_base && t.obs.slot_mask==obs_base.slot_mask);
   CHECK(!stop_fault(&t.second));
   CHECK(!snapshot(&t,&t.second,"second-stopped",0));
  }
 }
 CHECK(!retained_first(&t,alias));
 CHECK(!snapshot(&t,&t.first,"first-retained-after-second",0));
 CHECK(!memcmp(t.first.pool,t.first.pool_expected,POOL_BYTES));
 CHECK(!memcmp(t.second.pool,t.second.pool_expected,POOL_BYTES));
 if(!normal) {
  CHECK(pread(t.ce,t.ce_bytes,DMA_FIXTURE_WINDOW_BYTES,0)==DMA_FIXTURE_WINDOW_BYTES);
  CHECK(!memcmp(t.ce_bytes,t.ce_expected,DMA_FIXTURE_WINDOW_BYTES));
 }
 printf("PASS DMA_SCOPE scenario=%s first_short_accepted=1 first_sequestered=2 first_stop=-16 "
        "first_refs_retained=1 second_new_accepted=%llu fixed_byte_oracles=1 CPU_simulation=1\n",
        t.scenario,(unsigned long long)(t.second.device.accepted-second_base.accepted));
 printf("NOT_RUN cross_struct_file_alias UNKNOWN_mixed shifted_canonical_alias foreign_scope_owner\n");
 CHECK(dprintf(t.receipt,"{\"verdict\":\"PASS\",\"first_retained\":true,\"dedicated_guest_shutdown_required\":true}\n")>0);
 CHECK(!fsync(t.receipt));
 bad=0;
out:
 if(bad && t.receipt>=0) {
  if(t.first.created && t.first.window!=MAP_FAILED && t.first.pool!=MAP_FAILED && t.map_fd>=0)
   snapshot(&t,&t.first,"failure-first",0);
  if(t.second.created && t.second.window!=MAP_FAILED && t.second.pool!=MAP_FAILED && t.map_fd>=0)
   snapshot(&t,&t.second,"failure-second",0);
  dprintf(t.receipt,"{\"verdict\":\"%s\",\"failure_line\":%d}\n",
          !strcmp(failure_kind,"SETUP") ? "SETUP" : "FAIL",failure_line);
  fsync(t.receipt);
 }
 /* Closing userspace handles never force-releases a retained kernel session.
  * The original short owns its backing/pool/program pins until guest shutdown. */
 close_session(&t.second);close_session(&t.first);
 if(t.ce_link && !libbpf_get_error(t.ce_link))bpf_link__destroy(t.ce_link);
 if(t.dma_link && !libbpf_get_error(t.dma_link))bpf_link__destroy(t.dma_link);
 if(t.object && !libbpf_get_error(t.object))bpf_object__close(t.object);
 if(t.ce>=0)close(t.ce);
 if(t.receipt>=0)close(t.receipt);
 if(t.first.created || t.second.created) {
  fixture_param("fail_mode",0);fixture_param("delay_us",0);fixture_param("stale_replays",0);
 }
 free(t.ce_expected);free(t.ce_bytes);
 return bad && !strcmp(failure_kind,"SETUP") ? 77 : bad;
}

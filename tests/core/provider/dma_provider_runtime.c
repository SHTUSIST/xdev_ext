// SPDX-License-Identifier: GPL-2.0
/* KVM fixture runs production io_uring + BPF + independently loaded provider. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
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
#define POOL_BYTES (32U*FRAME)
#define STRIDE FRAME
#define MAX_DEPTH 8U
#define HEAD 256U
#define SEG 1024U
#define PAYLOAD (2U*SEG)
struct observation { __u64 dma_build,dma_complete,ce_build,ce_complete,wrong_base,slot_mask; };
static int bad;
#define REQUIRE(v) do { if (!(v)) { fprintf(stderr,"FAIL line %d: %s (errno=%d)\n",__LINE__,#v,errno); bad=1; goto out; } } while(0)
static int mech(int ring,__u32 op,__u64 arg)
{
 struct io_uring_xdev_ext_mech req={.op=op,.arg=arg};
 int ret=syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_MECH,&req,1);
 return ret<0 ? -errno : ret;
}
static __u64 now_ms(void)
{
 struct timespec t;
 clock_gettime(CLOCK_MONOTONIC,&t); return (__u64)t.tv_sec*1000+t.tv_nsec/1000000;
}
static int named_module_refs(const char *name)
{
 char path[160];snprintf(path,sizeof(path),"/sys/module/%s/refcnt",name);
 FILE *f=fopen(path,"r");
 int refs=-1;
 if(f) { if(fscanf(f,"%d",&refs)!=1) refs=-1; fclose(f); }
 return refs;
}
static int module_refs(void) { return named_module_refs("xdev_ext_dma_provider_sim"); }
static int fixture_param(const char *name,unsigned value)
{
 char path[160],text[32];int fd,n,ret;
 snprintf(path,sizeof(path),"/sys/module/xdev_ext_dma_provider_sim/parameters/%s",name);
 fd=open(path,O_WRONLY|O_CLOEXEC);if(fd<0)return -1;
 n=snprintf(text,sizeof(text),"%u\n",value);ret=write(fd,text,n)==n?0:-1;close(fd);return ret;
}
struct stop_watch { int fd; atomic_int done; int violation; unsigned checks; };
static void *watch_stop(void *arg)
{
 struct stop_watch *w=arg;
 while(!atomic_load(&w->done)) {
  struct dma_fixture_stats d={0};
  if(ioctl(w->fd,DMA_FIXTURE_STATS,&d)) { w->violation=1;break; }
  if(d.pending && (d.host_unbinds || d.region_unbinds)) { w->violation=1;break; }
  w->checks++;usleep(1000);
 }
 return NULL;
}
int main(int argc,char **argv)
{
 const char *objfile=argc>1 ? argv[1] : "dma_provider_pair.bpf.o";
 const char *mode=argc>2 ? argv[2] : "normal";
 unsigned int groups=argc>3 ? (unsigned int)strtoul(argv[3],NULL,10) : 257;
 unsigned int depth=argc>4 ? (unsigned int)strtoul(argv[4],NULL,10) : 8;
 int pending_stop=!strcmp(mode,"stop"),quarantine=!strcmp(mode,"short")||!strcmp(mode,"ambiguous");
 int reject=!strcmp(mode,"reject"),replay=!strcmp(mode,"stale")||!strcmp(mode,"duplicate");
 unsigned int fault=!strcmp(mode,"reject")?1:!strcmp(mode,"short")?2:!strcmp(mode,"ambiguous")?3:0;
 uint64_t end_offset;
 if((strcmp(mode,"normal") && strcmp(mode,"delay") && !pending_stop && !quarantine && !reject && !replay) ||
    !groups || !depth || depth>MAX_DEPTH || groups<depth ||
    !campaign_offset(groups-1,STRIDE,PAYLOAD,DMA_FIXTURE_WINDOW_BYTES,&end_offset) ||
    ((quarantine||reject) && (groups!=1 || depth!=1))) {
  fprintf(stderr,"FAIL usage: OBJECT {normal|delay|stale|duplicate|stop} GROUPS DEPTH (max 8), or {reject|short|ambiguous} 1 1\n");return 1;
 }
 struct bpf_object *object=NULL;
 struct bpf_link *dma_link=NULL,*ce_link=NULL;
 struct bpf_map *map;
 struct observation obs={0};
 struct io_uring_params params={0};
 struct io_uring_xdev_ext_umem_reg reg={.size=POOL_BYTES,.frame_size=FRAME};
 struct xdev_ext_mech_create c={.abi_version=XDEV_EXT_MECH_ABI_VERSION,.nr_stages=4,
   .pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM,.pool_fd=-1,.depth=1,.eventfd=-1,
   .layout={.frame_size=FRAME,.hdr_room=HEAD,.seg_len=SEG,.group_bytes=PAYLOAD}};
 __u32 frame_index[2*MAX_DEPTH],zero=0;
 struct xdev_ext_mech_start start={.nr_batches=1,.first_seq=0,
   .flags=XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_RECYCLE,.nr_user_frames=2,
   .user_frames=(uintptr_t)frame_index};
 struct xdev_ext_mech_stats stats={0};
 struct dma_fixture_stats device={0};
 unsigned char *window=MAP_FAILED,*pool=MAP_FAILED,*before=NULL;
 unsigned char *ce_bytes=NULL;
 struct stop_watch watcher={0};pthread_t watcher_thread;int watching=0;
 struct rlimit lim={RLIM_INFINITY,RLIM_INFINITY};
 int dma=-1,ce=-1,ring=-1,refs=-1,ce_refs=-1,created=0,stopped=0;
 __u64 deadline;
 unsigned int i,j,g;
 setrlimit(RLIMIT_MEMLOCK,&lim);
 c.depth=depth;start.nr_batches=groups;start.nr_user_frames=2*depth;
 for(i=0;i<2*depth;i++)frame_index[i]=2*i+1;
 REQUIRE(!fixture_param("fail_mode",fault));
 REQUIRE(!fixture_param("delay_us",pending_stop?500000:!strcmp(mode,"delay")?2000:0));
 REQUIRE(!fixture_param("stale_replays",!strcmp(mode,"duplicate")?2:replay?1:0));
 /* mmap occurs exactly once; the input/output windows are separate regions. */
 dma=open("/dev/xdev_ext_dma_provider_sim",O_RDWR|O_CLOEXEC); REQUIRE(dma>=0);
 window=mmap(NULL,DMA_FIXTURE_MAP_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,dma,0);
 REQUIRE(window!=MAP_FAILED);
 memset(window,0xa6,DMA_FIXTURE_MAP_BYTES);
 for(g=0;g<groups;g++)for(i=0;i<PAYLOAD;i++)
  window[DMA_FIXTURE_INPUT_OFF+g*STRIDE+i]=campaign_pattern(g,i);
 before=malloc(DMA_FIXTURE_MAP_BYTES); REQUIRE(before);
 memcpy(before,window,DMA_FIXTURE_MAP_BYTES);
 refs=module_refs(); REQUIRE(refs>=1);
 ce=open("/dev/xdev_ext_ce_sim",O_RDWR|O_CLOEXEC); REQUIRE(ce>=0);
 ce_refs=named_module_refs("xdev_ext_ce_sim");REQUIRE(ce_refs>=1);
 ce_bytes=malloc(DMA_FIXTURE_WINDOW_BYTES);REQUIRE(ce_bytes);
 memset(ce_bytes,0x38,DMA_FIXTURE_WINDOW_BYTES);
 REQUIRE(pwrite(ce,ce_bytes,DMA_FIXTURE_WINDOW_BYTES,0)==DMA_FIXTURE_WINDOW_BYTES);
 object=bpf_object__open_file(objfile,NULL);
 REQUIRE(object && !libbpf_get_error(object));
 REQUIRE(!bpf_object__load(object));
 map=bpf_object__find_map_by_name(object,"dma_pair"); REQUIRE(map);
 dma_link=bpf_map__attach_struct_ops(map); REQUIRE(!libbpf_get_error(dma_link));
 map=bpf_object__find_map_by_name(object,"ce_pair"); REQUIRE(map);
 ce_link=bpf_map__attach_struct_ops(map); REQUIRE(!libbpf_get_error(ce_link));
 ring=syscall(__NR_io_uring_setup,8,&params); REQUIRE(ring>=0);
 pool=mmap(NULL,POOL_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 REQUIRE(pool!=MAP_FAILED); memset(pool,0x97,POOL_BYTES);
 reg.addr=(uintptr_t)pool;
 REQUIRE(!syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_UMEM,&reg,1));
 c.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_DMA,
   .direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=dma,
   .arg0=DMA_FIXTURE_INPUT_OFF,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 c.st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_CE,
   .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=ce,.arg0=0,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 c.st[2]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_CE,
   .direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=ce,.arg0=0,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 c.st[3]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_DMA,
   .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=dma,
   .arg0=DMA_FIXTURE_OUTPUT_OFF,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_CREATE,(uintptr_t)&c)); created=1;
 REQUIRE(module_refs()>=refs+2); /* Both bound stages independently pin owner. */
 errno=0;
 REQUIRE(syscall(__NR_delete_module,"xdev_ext_dma_provider_sim",O_NONBLOCK)<0 &&
         (errno==EWOULDBLOCK || errno==EBUSY));
 REQUIRE(module_refs()>=refs+2);
 REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
 REQUIRE(device.region_binds==2 && device.host_binds==2 && !device.accepted);
 start.session_id=c.session_id;
 REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_START,(uintptr_t)&start));
 deadline=now_ms()+10000;
 do {
  memset(&stats,0,sizeof(stats)); stats.session_id=c.session_id;
  REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&stats));
  if(pending_stop) {
   REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
   if(device.pending)break;
  } else if(stats.batches_done==groups || stats.batches_abort || stats.sequestered) break;
  usleep(1000);
 } while(now_ms()<deadline);
 if(pending_stop) {
  REQUIRE(device.pending && !device.host_unbinds && !device.region_unbinds);
  REQUIRE(module_refs()>=refs+2);
  watcher.fd=dma;REQUIRE(!pthread_create(&watcher_thread,NULL,watch_stop,&watcher));watching=1;
  REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_STOP,c.session_id));stopped=1;
  atomic_store(&watcher.done,1);REQUIRE(!pthread_join(watcher_thread,NULL));watching=0;
  REQUIRE(!watcher.violation && watcher.checks);
  REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
  REQUIRE(device.accepted && device.accepted==device.completed && !device.pending);
  REQUIRE(device.region_unbinds==2 && device.host_unbinds==2 && module_refs()==refs);
  REQUIRE(!memcmp(window,before,DMA_FIXTURE_MAP_BYTES));
  printf("PASS provider case=stop groups=%u depth=%u accepted=%llu completed=%llu pending=0 watcher_checks=%u unbinds=2 owner_refs_released=1 source_and_guards=unchanged\n",
   groups,depth,(unsigned long long)device.accepted,(unsigned long long)device.completed,watcher.checks);
  goto out;
 }
 if(quarantine || reject) {
  int actual_stop_ret;
  REQUIRE(!stats.batches_done && stats.last_err && (stats.batches_abort || stats.sequestered));
  REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
  REQUIRE(!device.pending && !device.to_device && !device.region_unbinds && !device.host_unbinds);
  REQUIRE(!memcmp(window,before,DMA_FIXTURE_MAP_BYTES));
  if(quarantine) {
   REQUIRE(stats.sequestered==start.nr_user_frames && device.accepted==1 && device.completed==1);
   REQUIRE(module_refs()>=refs+2);
   actual_stop_ret=mech(ring,XDEV_EXT_MECH_OP_STOP,c.session_id);
   REQUIRE(actual_stop_ret==-EBUSY);stopped=1;
   REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
   REQUIRE(!device.region_unbinds && !device.host_unbinds && module_refs()>=refs+2);
   REQUIRE(named_module_refs("xdev_ext_ce_sim")>=ce_refs+2);
  } else {
   REQUIRE(!stats.sequestered && !device.accepted && !device.completed);
   actual_stop_ret=mech(ring,XDEV_EXT_MECH_OP_STOP,c.session_id);
   REQUIRE(!actual_stop_ret || actual_stop_ret==stats.last_err);stopped=1;
   REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
   REQUIRE(device.region_unbinds==2 && device.host_unbinds==2 && module_refs()==refs);
  }
  printf("PASS provider case=%s groups=1 depth=1 success=0 accepted=%llu completed=%llu sequestered=%llu source_and_guards=unchanged owner_refs_retained=%d stop_ret=%d region_unbinds=%llu host_unbinds=%llu ce_refs_retained=%d\n",
   mode,(unsigned long long)device.accepted,(unsigned long long)device.completed,
   (unsigned long long)stats.sequestered,quarantine,actual_stop_ret,
   (unsigned long long)device.region_unbinds,(unsigned long long)device.host_unbinds,quarantine);
  goto out;
 }
 REQUIRE(stats.batches_done==groups && !stats.batches_abort && !stats.rejects &&
         !stats.sequestered && !stats.protocol_err && !stats.inflight && !stats.last_err);
 for(i=0;i<4;i++) REQUIRE(stats.submitted[i]==groups && stats.completed[i]==groups);
 REQUIRE(!campaign_verify(window,before,DMA_FIXTURE_MAP_BYTES,DMA_FIXTURE_OUTPUT_OFF,groups,STRIDE,PAYLOAD));
 for(i=0;i<POOL_BYTES;i++) {
  int payload=0;
  for(j=0;j<2*depth;j++) if(i>=frame_index[j]*FRAME+HEAD &&
                            i<frame_index[j]*FRAME+HEAD+SEG) payload=1;
  if(!payload) REQUIRE(pool[i]==0x97);
 }
 REQUIRE(pread(ce,ce_bytes,DMA_FIXTURE_WINDOW_BYTES,0)==DMA_FIXTURE_WINDOW_BYTES);
 for(j=0;j<depth;j++) {
  uint64_t group=0;
  for(i=0;i<8;i++)group|=(uint64_t)ce_bytes[j*PAYLOAD+i]<<(i*8);
  REQUIRE(group<groups);
  for(i=0;i<PAYLOAD;i++)REQUIRE(ce_bytes[j*PAYLOAD+i]==campaign_pattern(group,i));
 }
 for(i=depth*PAYLOAD;i<DMA_FIXTURE_WINDOW_BYTES;i++)REQUIRE(ce_bytes[i]==0x38);
 REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
 REQUIRE(device.accepted==2ULL*groups && device.completed==2ULL*groups && !device.pending &&
         device.from_device==groups && device.to_device==groups && device.bytes==2ULL*groups*PAYLOAD);
 if(!strcmp(mode,"delay"))REQUIRE(device.peak_pending>=2);
 if(replay)REQUIRE(device.stale_callbacks>0);
 else REQUIRE(!device.stale_callbacks);
 map=bpf_object__find_map_by_name(object,"observations"); REQUIRE(map);
 REQUIRE(!bpf_map_lookup_elem(bpf_map__fd(map),&zero,&obs));
 REQUIRE(obs.dma_build==2ULL*groups && obs.dma_complete==2ULL*groups && obs.ce_build==2ULL*groups &&
         obs.ce_complete==2ULL*groups && !obs.wrong_base && obs.slot_mask==((1ULL<<depth)-1));
 REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_STOP,c.session_id)); stopped=1;
 REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
 REQUIRE(device.region_unbinds==2 && device.host_unbinds==2);
 REQUIRE(module_refs()==refs);
 printf("PASS provider case=%s groups=%u depth=%u slots=%u distinct_patterns=1 full_output=1 source_unchanged=1 all_guards=1 stage_counts=%u,%u,%u,%u accepted=%llu completed=%llu pending=0 stale_callbacks=%llu owner_refs_released=1 CPU_simulation=1\n",
  mode,groups,depth,depth,groups,groups,groups,groups,
  (unsigned long long)device.accepted,(unsigned long long)device.completed,(unsigned long long)device.stale_callbacks);
out:
 if(watching) { atomic_store(&watcher.done,1);pthread_join(watcher_thread,NULL); }
 if(created && !stopped && ring>=0) mech(ring,XDEV_EXT_MECH_OP_STOP,c.session_id);
 if(ring>=0) close(ring);
 if(pool!=MAP_FAILED) munmap(pool,POOL_BYTES);
 if(ce_link && !libbpf_get_error(ce_link)) bpf_link__destroy(ce_link);
 if(dma_link && !libbpf_get_error(dma_link)) bpf_link__destroy(dma_link);
 if(object && !libbpf_get_error(object)) bpf_object__close(object);
 if(ce>=0) close(ce);
 if(window!=MAP_FAILED) munmap(window,DMA_FIXTURE_MAP_BYTES);
 if(dma>=0) close(dma);
 fixture_param("fail_mode",0);fixture_param("delay_us",0);fixture_param("stale_replays",0);
 free(ce_bytes);free(before); return bad ? 1 : 0;
}

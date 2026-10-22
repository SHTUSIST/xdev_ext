// SPDX-License-Identifier: GPL-2.0
/* Independent software guest E2E. DMA provider is CPU simulation; compression
 * and decompression execute production CryptoAPI deflate-generic requests. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
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
#include "campaign.h"
#include "observations.h"
static int bad;
#define REQUIRE(c) do {if(!(c)){fprintf(stderr,"FAIL IAA line=%d expr=%s errno=%d\n",__LINE__,#c,errno);bad=1;goto out;}}while(0)
static int mech(int ring,__u32 op,__u64 arg) {
 struct io_uring_xdev_ext_mech r={.op=op,.arg=arg};
 int n=syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_MECH,&r,1);return n<0?-errno:n;
}
static uint64_t now_ms(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static int set_param(const char *name,unsigned value) {
 char path[160],text[32];snprintf(path,sizeof(path),"/sys/module/xdev_ext_dma_provider_sim/parameters/%s",name);
 int fd=open(path,O_WRONLY|O_CLOEXEC);if(fd<0)return -1;
 int n=snprintf(text,sizeof(text),"%u\n",value);int ret=write(fd,text,n)==n?0:-1;close(fd);return ret;
}
static int owner_refs(void) {FILE *f=fopen("/sys/module/xdev_ext_dma_provider_sim/refcnt","r");int n=-1;if(f){if(fscanf(f,"%d",&n)!=1)n=-1;fclose(f);}return n;}
static int full_source_guard_check(const unsigned char *image,const unsigned char *before) {
 return memcmp(image,before,DMA_FIXTURE_MAP_BYTES);
}
int main(int argc,char **argv) {
 const char *object_path=argc>1?argv[1]:"iaa_pair.bpf.o";
 const char *mode=argc>2?argv[2]:"normal";
 int stopping=!strcmp(mode,"stop"),replay=!strcmp(mode,"stale")||!strcmp(mode,"duplicate");
 if(strcmp(mode,"normal")&&strcmp(mode,"delay")&&!stopping&&!replay){fprintf(stderr,"FAIL invalid IAA case\n");return 1;}
 struct bpf_object *object=NULL;struct bpf_link *dma_link=NULL,*iaa_link=NULL;struct bpf_map *map;
 struct iaa_observation *obs=NULL;
 struct io_uring_params p={0};int ring=-1,dma=-1,created=0,stopped=0,refs=-1;
 unsigned char *window=MAP_FAILED,*pool=MAP_FAILED,*before=NULL;
 struct io_uring_xdev_ext_umem_reg reg={.size=IAA_POOL_BYTES,.frame_size=IAA_FRAME};
 struct xdev_ext_mech_create c={.abi_version=XDEV_EXT_MECH_ABI_VERSION,.nr_stages=4,
  .pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM,.pool_fd=-1,.depth=IAA_DEPTH,.eventfd=-1,
  .layout={.frame_size=IAA_FRAME,.hdr_room=IAA_HEAD,.seg_len=IAA_PAYLOAD,.group_bytes=IAA_PAYLOAD}};
 __u32 indices[IAA_DEPTH],zero=0;
 struct xdev_ext_mech_start start={.nr_batches=IAA_GROUPS,.first_seq=0,
  .flags=XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_RECYCLE,
  .nr_user_frames=IAA_DEPTH,.user_frames=(uintptr_t)indices};
 struct xdev_ext_mech_stats stats={0};struct dma_fixture_stats device={0};
 unsigned highwater[IAA_POOL_FRAMES]={0},last_source[IAA_DEPTH]={0};unsigned min_comp=UINT32_MAX,max_comp=0;
 struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};setrlimit(RLIMIT_MEMLOCK,&limit);
 REQUIRE(!set_param("fail_mode",0));REQUIRE(!set_param("delay_us",stopping?500000:!strcmp(mode,"delay")?2000:0));
 REQUIRE(!set_param("stale_replays",!strcmp(mode,"duplicate")?2:replay?1:0));
 dma=open("/dev/xdev_ext_dma_provider_sim",O_RDWR|O_CLOEXEC);REQUIRE(dma>=0);
 window=mmap(NULL,DMA_FIXTURE_MAP_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,dma,0);REQUIRE(window!=MAP_FAILED);
 memset(window,0xa6,DMA_FIXTURE_MAP_BYTES);
 for(unsigned g=0;g<IAA_GROUPS;g++)for(unsigned i=0;i<IAA_PAYLOAD;i++)window[DMA_FIXTURE_INPUT_OFF+g*IAA_PAYLOAD+i]=iaa_pattern(g,i);
 before=malloc(DMA_FIXTURE_MAP_BYTES);REQUIRE(before);memcpy(before,window,DMA_FIXTURE_MAP_BYTES);
 refs=owner_refs();REQUIRE(refs>=1);
 object=bpf_object__open_file(object_path,NULL);REQUIRE(object&&!libbpf_get_error(object));REQUIRE(!bpf_object__load(object));
 map=bpf_object__find_map_by_name(object,"dma_pair");REQUIRE(map);dma_link=bpf_map__attach_struct_ops(map);REQUIRE(!libbpf_get_error(dma_link));
 map=bpf_object__find_map_by_name(object,"iaa_pair");REQUIRE(map);iaa_link=bpf_map__attach_struct_ops(map);REQUIRE(!libbpf_get_error(iaa_link));
 ring=syscall(__NR_io_uring_setup,8,&p);REQUIRE(ring>=0);
 pool=mmap(NULL,IAA_POOL_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);REQUIRE(pool!=MAP_FAILED);memset(pool,0x97,IAA_POOL_BYTES);
 reg.addr=(uintptr_t)pool;REQUIRE(!syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_UMEM,&reg,1));
 c.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_DMA,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=dma,.arg0=DMA_FIXTURE_INPUT_OFF,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 c.st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_IAA,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=dma,.flags=XDEV_EXT_IAA_F_SOFTWARE,.arg0=IAA_COMP_FIRST,.arg1=2*IAA_PAYLOAD};
 c.st[2]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_IAA,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=dma,.flags=XDEV_EXT_IAA_F_SOFTWARE,.arg0=IAA_DECOMP_FIRST,.arg1=IAA_PAYLOAD};
 c.st[3]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_DMA,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=dma,.arg0=DMA_FIXTURE_OUTPUT_OFF,.arg1=DMA_FIXTURE_WINDOW_BYTES};
 REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_CREATE,(uintptr_t)&c));created=1;REQUIRE(owner_refs()>=refs+2);
 for(unsigned i=0;i<IAA_DEPTH;i++)indices[i]=i;
 start.session_id=c.session_id;REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_START,(uintptr_t)&start));
 uint64_t deadline=now_ms()+30000;
 do {
  stats=(struct xdev_ext_mech_stats){.session_id=c.session_id};REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_STATS,(uintptr_t)&stats));
  if(stopping){REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));if(device.pending)break;}
  else if(stats.batches_done==IAA_GROUPS||stats.batches_abort||stats.sequestered)break;
  usleep(1000);
 }while(now_ms()<deadline);
 if(stopping) {
  REQUIRE(device.pending&&!device.host_unbinds&&!device.region_unbinds&&owner_refs()>=refs+2);
  REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_STOP,c.session_id));stopped=1;
  REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
  REQUIRE(device.accepted&&device.accepted==device.completed&&!device.pending&&device.region_unbinds==2&&device.host_unbinds==2&&owner_refs()==refs);
  REQUIRE(!full_source_guard_check(window,before));
  printf("PASS IAA case=stop groups=257 depth=8 pending_drained=1 owners_released=1 full_source_and_guards=1 software=deflate-generic dma_cpu_simulation=1 stopped_stage=DMA native_accepted=%llu native_completed=%llu pending=0 region_unbinds=2 host_unbinds=2\n", (unsigned long long)device.accepted,(unsigned long long)device.completed);goto out;
 }
 REQUIRE(stats.batches_done==IAA_GROUPS&&!stats.batches_abort&&!stats.rejects&&!stats.sequestered&&!stats.protocol_err&&!stats.inflight&&!stats.last_err);
 for(unsigned i=0;i<4;i++)REQUIRE(stats.submitted[i]==IAA_GROUPS&&stats.completed[i]==IAA_GROUPS);
 REQUIRE(!iaa_verify_window(window,before,DMA_FIXTURE_MAP_BYTES,DMA_FIXTURE_OUTPUT_OFF,IAA_GROUPS,IAA_PAYLOAD));
 obs=calloc(1,sizeof(*obs));REQUIRE(obs);map=bpf_object__find_map_by_name(object,"observations");REQUIRE(map);
 REQUIRE(!bpf_map_lookup_elem(bpf_map__fd(map),&zero,obs));
 REQUIRE(obs->dma_build==2*IAA_GROUPS&&obs->dma_complete==2*IAA_GROUPS&&obs->iaa_build==2*IAA_GROUPS&&obs->iaa_complete==2*IAA_GROUPS&&!obs->errors);
 for(unsigned i=0;i<IAA_DEPTH;i++)highwater[i]=IAA_PAYLOAD;
 for(unsigned g=0;g<IAA_GROUPS;g++) {
  unsigned n=obs->compressed[g],f=obs->comp_frame[g],d=obs->sink_frame[g],src=obs->source_frame[g];
  REQUIRE(src<IAA_DEPTH);last_source[src]=g;
  REQUIRE(n&&n<=2*IAA_PAYLOAD&&n==obs->decomp_input[g]&&obs->decompressed[g]==IAA_PAYLOAD);
  REQUIRE(f>=IAA_COMP_FIRST&&f<IAA_COMP_FIRST+2*IAA_DEPTH&&(f-IAA_COMP_FIRST)%2==0);
  REQUIRE(d>=IAA_DECOMP_FIRST&&d<IAA_DECOMP_FIRST+IAA_DEPTH);
  if(n<min_comp)min_comp=n;
  if(n>max_comp)max_comp=n;
  unsigned first=n>IAA_PAYLOAD?IAA_PAYLOAD:n;
  if(first>highwater[f])highwater[f]=first;
  if(n>IAA_PAYLOAD&&n-IAA_PAYLOAD>highwater[f+1])highwater[f+1]=n-IAA_PAYLOAD;
  highwater[d]=IAA_PAYLOAD;
 }
 REQUIRE(min_comp<IAA_PAYLOAD&&max_comp>IAA_PAYLOAD); /* Expansion uses the second destination frame. */
 for(unsigned src=0;src<IAA_DEPTH;src++)for(unsigned byte=0;byte<IAA_PAYLOAD;byte++)
  REQUIRE(pool[src*IAA_FRAME+IAA_HEAD+byte]==iaa_pattern(last_source[src],byte));
 REQUIRE(!iaa_verify_pool_guards(pool,highwater));
 /* Mutation checks exercise the very validator that judged the real bytes. */
 window[DMA_FIXTURE_OUTPUT_OFF+IAA_PAYLOAD+77]^=1;
 REQUIRE(iaa_verify_window(window,before,DMA_FIXTURE_MAP_BYTES,DMA_FIXTURE_OUTPUT_OFF,IAA_GROUPS,IAA_PAYLOAD));window[DMA_FIXTURE_OUTPUT_OFF+IAA_PAYLOAD+77]^=1;
 window[DMA_FIXTURE_INPUT_OFF+17]^=1;
 REQUIRE(iaa_verify_window(window,before,DMA_FIXTURE_MAP_BYTES,DMA_FIXTURE_OUTPUT_OFF,IAA_GROUPS,IAA_PAYLOAD));window[DMA_FIXTURE_INPUT_OFF+17]^=1;
 window[DMA_FIXTURE_OUTPUT_OFF-1]^=1;
 REQUIRE(iaa_verify_window(window,before,DMA_FIXTURE_MAP_BYTES,DMA_FIXTURE_OUTPUT_OFF,IAA_GROUPS,IAA_PAYLOAD));window[DMA_FIXTURE_OUTPUT_OFF-1]^=1;
 pool[IAA_COMP_FIRST*IAA_FRAME+IAA_HEAD-1]^=1;REQUIRE(iaa_verify_pool_guards(pool,highwater));pool[IAA_COMP_FIRST*IAA_FRAME+IAA_HEAD-1]^=1;
 REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));
 REQUIRE(device.accepted==2*IAA_GROUPS&&device.completed==2*IAA_GROUPS&&!device.pending&&device.from_device==IAA_GROUPS&&device.to_device==IAA_GROUPS&&device.bytes==2ULL*IAA_GROUPS*IAA_PAYLOAD);
 if(!strcmp(mode,"delay"))REQUIRE(device.peak_pending>=2);
 if(replay)REQUIRE(device.stale_callbacks>0);else REQUIRE(!device.stale_callbacks);
 REQUIRE(!mech(ring,XDEV_EXT_MECH_OP_STOP,c.session_id));stopped=1;
 REQUIRE(!ioctl(dma,DMA_FIXTURE_STATS,&device));REQUIRE(device.region_unbinds==2&&device.host_unbinds==2&&owner_refs()==refs);
 printf("PASS IAA case=%s groups=257 depth=8 software=deflate-generic compressed_min=%u compressed_max=%u actual_lengths=257 restored_bytes=%u full_source=1 all_window_guards=1 all_pool_guards=1 mutation_rejects=4 stage_counts=257,257,257,257 native_accepted=514 native_completed=514 pending=0 owners_released=1 dma_cpu_simulation=1\n",mode,min_comp,max_comp,IAA_GROUPS*IAA_PAYLOAD);
out:
 if(created&&!stopped&&ring>=0)mech(ring,XDEV_EXT_MECH_OP_STOP,c.session_id);
 if(ring>=0)close(ring);
 if(pool!=MAP_FAILED)munmap(pool,IAA_POOL_BYTES);
 if(iaa_link&&!libbpf_get_error(iaa_link))bpf_link__destroy(iaa_link);
 if(dma_link&&!libbpf_get_error(dma_link))bpf_link__destroy(dma_link);
 if(object&&!libbpf_get_error(object))bpf_object__close(object);
 if(window!=MAP_FAILED)munmap(window,DMA_FIXTURE_MAP_BYTES);
 if(dma>=0)close(dma);
 set_param("fail_mode",0);set_param("delay_us",0);set_param("stale_replays",0);free(obs);free(before);return bad?1:0;
}

// SPDX-License-Identifier: GPL-2.0-only
/* Actual native completion FIFO helpers: capacity/holes operation bounds and
 * a separate uninstrumented host CPU cycle. Not NIC, DMA, IRQ or lock timing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
static volatile unsigned long long metadata_lookups;
#include "native_count.h"
#define CHECK(c) do {if (!(c)) {fprintf(stderr,"COST_CONTRACT_FAIL line=%d condition=%s\n",__LINE__,#c);return 1;}} while(0)
static unsigned long long ns(clockid_t c) {struct timespec t;if(clock_gettime(c,&t))abort();return (unsigned long long)t.tv_sec*1000000000ULL+t.tv_nsec;}
/* Separate API-like callers prevent the compiler folding an entire successful
 * reserve/take/retire cycle into its final state across an artificial loop. */
__attribute__((noinline,noclone)) static int enqueue(struct xdev_ext_net_count_ring *r,struct xdev_ext_net_count_entry *s) {
 __u32 at;int e=xdev_ext_net_count_reserve(r,1,&at);if(e)return e;
 s[at&(r->capacity-1)]=(struct xdev_ext_net_count_entry){.state=XDEV_EXT_NET_COUNT_PENDING};return 0;
}
__attribute__((noinline,noclone)) static int take(struct xdev_ext_net_count_ring *r,struct xdev_ext_net_count_view v) {return xdev_ext_net_count_peek(r,v);}
__attribute__((noinline,noclone)) static void finish(struct xdev_ext_net_count_ring *r,struct xdev_ext_net_count_view v,__u32 at) {xdev_ext_net_count_mark_done(r,v,at);xdev_ext_net_count_reclaim(r,v);}
static int contracts(unsigned cap) {
 struct xdev_ext_net_count_entry *s=calloc(cap,sizeof(*s));CHECK(s);
 struct xdev_ext_net_count_ring r={.capacity=cap};
 struct xdev_ext_net_count_view v={.first=s,.stride=sizeof(*s)};
 /* Produce the state by real helpers: DONE holes coexist with NATIVE entries.
  * This is helper-state stress; driver-path reachability is not asserted. */
 for(unsigned i=0;i<cap;i++){CHECK(!enqueue(&r,s));CHECK(take(&r,v)==(int)i);}
 for(unsigned i=1;i<cap;i+=2)xdev_ext_net_count_mark_done(&r,v,i);
 metadata_lookups=0;
 CHECK(xdev_ext_net_count_native(&r)==cap/2);
 CHECK(xdev_ext_net_count_head(&r)==0);
 CHECK(xdev_ext_net_count_tail(&r,v,0)==(int)cap-2);
 finish(&r,v,0);
 CHECK(r.cons==2 && xdev_ext_net_count_head(&r)==2);
 unsigned long long count=metadata_lookups;
 CHECK(count<=8); /* fixed one descriptor retirement, independent of capacity */
 printf("NIC_FIFO_COST capacity=%u pattern=alternating_done_holes retired=1 accessor_calls=%llu bound=8\n",cap,count);
 /* A blocked old native owner can leave a DONE suffix; reclaim is allowed
  * to consume that suffix once, not a constant-latency operation. */
 for(unsigned i=2;i<cap;i+=2)xdev_ext_net_count_mark_done(&r,v,i);
 metadata_lookups=0;xdev_ext_net_count_reclaim(&r,v);
 CHECK(r.cons==r.prod && metadata_lookups<=cap);
 unsigned long long reclaim=metadata_lookups;xdev_ext_net_count_reclaim(&r,v);CHECK(metadata_lookups==reclaim);
 printf("NIC_FIFO_COST capacity=%u pattern=done_suffix accessor_calls=%llu bound=capacity amortized_only=1\n",cap,reclaim);
 free(s);return 0;
}
static int timing(unsigned cap) {
 struct xdev_ext_net_count_entry *s=calloc(cap,sizeof(*s));CHECK(s);
 struct xdev_ext_net_count_view v={.first=s,.stride=sizeof(*s)};
 for(unsigned i=0;i<cap;i++)s[i].state=XDEV_EXT_NET_COUNT_DONE; /* prefault */
 for(unsigned rep=0;rep<7;rep++) {
  struct xdev_ext_net_count_ring r={.capacity=cap};
  for(unsigned i=0;i<4096;i++){CHECK(!enqueue(&r,s));int at=take(&r,v);CHECK(at>=0);finish(&r,v,(unsigned)at);}
  unsigned long long cpu=ns(CLOCK_PROCESS_CPUTIME_ID),wall=ns(CLOCK_MONOTONIC),sum=0;
  const unsigned cycles=262144;
  for(unsigned i=0;i<cycles;i++){if(enqueue(&r,s))abort();int at=take(&r,v);if(at<0)abort();sum+=(unsigned)at;finish(&r,v,(unsigned)at);}
  wall=ns(CLOCK_MONOTONIC)-wall;cpu=ns(CLOCK_PROCESS_CPUTIME_ID)-cpu;
  CHECK(r.prod==r.cons && !r.native_count);
  printf("NIC_FIFO_CPU capacity=%u rep=%u cycles=%u wall_ns=%llu process_ns=%llu checksum=%llu scope=host_helpers_no_locks_no_device\n",cap,rep,cycles,wall,cpu,sum);
 }
 free(s);return 0;
}
int main(int argc,char **argv) {
 if(argc!=2 || (strcmp(argv[1],"contract") && strcmp(argv[1],"timing")))return 2;
#ifdef COST_INSTRUMENTED
 if(strcmp(argv[1],"contract"))return 2;
#else
 if(strcmp(argv[1],"timing"))return 2;
#endif
 for(unsigned i=0;i<3;i++){unsigned cap=(unsigned[]){64,1024,65536}[i];if(!strcmp(argv[1],"contract")?contracts(cap):timing(cap))return 1;}
 return 0;
}

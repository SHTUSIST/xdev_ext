/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#ifdef BLOCK_NEW
#include "xdev_ext_storfam_core.h"
#define CAPS xdev_ext_stor_queue_caps
#define WALK xdev_ext_stor_seg_walk
#define INIT xdev_ext_stor_seg_walk_init
#define ADD xdev_ext_stor_seg_add
#define DONE xdev_ext_stor_seg_done
#else
#include "nvme_xdev_ext_passthru.h"
#define CAPS nvme_xdev_ext_queue_caps
#define WALK nvme_xdev_ext_seg_walk
#define INIT nvme_xdev_ext_seg_walk_init
#define ADD nvme_xdev_ext_seg_add
#define DONE nvme_xdev_ext_seg_done
#endif
static unsigned checks,failures;
static const char *label;
static void eq(const char *field,long long got,long long want){checks++;if(got!=want){failures++;fprintf(stderr,"FAIL %s %s got=%lld want=%lld\n",label,field,got,want);}}
#define EQ(n,g,w) eq(n,(long long)(g),(long long)(w))
static struct CAPS defaults(void){return (struct CAPS){.virt_boundary_mask=0,.page_size=4096,.dma_align_mask=3,.max_segments=4,.max_segment_size=4096,.max_bytes=8192,.lba_size=512};}
static void state(struct WALK *w,unsigned seg,unsigned len,unsigned bytes,unsigned end){EQ("segs",w->segs,seg);EQ("seg_len",w->seg_len,len);EQ("bytes",w->bytes,bytes);EQ("end",w->end,end);}
static void add(struct WALK *w,unsigned off,unsigned len,int same,int want){struct WALK old=*w;EQ("errno",ADD(w,off,len,same),want);if(want)EQ("failure-state-unchanged",memcmp(w,&old,sizeof(old)),0);}
int main(void){
 struct CAPS c=defaults();struct WALK w;
 label="init";memset(&w,0xa5,sizeof(w));INIT(&w,&c);state(&w,0,0,0,0);EQ("caps-copy",memcmp(&w.caps,&c,sizeof(c)),0);EQ("empty-done",DONE(&w),-EINVAL);
 label="literal-three-pieces";add(&w,0,512,0,0);state(&w,1,512,512,512);add(&w,512,512,1,0);state(&w,1,1024,1024,1024);add(&w,0,512,0,0);state(&w,2,512,1536,512);EQ("done",DONE(&w),0);
 label="geometry-before-alignment";add(&w,0,0,0,-EINVAL);add(&w,4096,512,0,-EINVAL);add(&w,4095,512,0,-EINVAL);add(&w,1,512,0,-EREMOTEIO);add(&w,0,513,0,-EREMOTEIO);
 label="alignment-before-bytes";c.max_bytes=512;INIT(&w,&c);add(&w,1,1024,0,-EREMOTEIO);
 label="bytes-before-segment";c.max_segment_size=512;c.max_segments=1;INIT(&w,&c);add(&w,0,512,0,0);add(&w,512,512,1,-EMSGSIZE);add(&w,0,512,0,-EMSGSIZE);
 label="same-page-segment-size";c=defaults();c.max_segment_size=512;INIT(&w,&c);add(&w,0,512,0,0);add(&w,512,512,1,-EREMOTEIO);
 label="new-segment-size";INIT(&w,&c);add(&w,0,1024,0,-EREMOTEIO);
 label="segment-count";c=defaults();c.max_segments=1;INIT(&w,&c);add(&w,0,512,0,0);add(&w,0,512,0,-EREMOTEIO);
 label="gap-boundary";c=defaults();c.virt_boundary_mask=4095;INIT(&w,&c);add(&w,0,512,0,0);add(&w,0,512,0,-EREMOTEIO);
 label="full-page-boundary";INIT(&w,&c);add(&w,0,4096,0,0);add(&w,0,512,0,0);state(&w,2,512,4608,512);
 label="LBA-terminal";c=defaults();c.dma_align_mask=0;INIT(&w,&c);add(&w,0,513,0,0);EQ("done-unaligned",DONE(&w),-EMSGSIZE);
 // Literal boundary table catches off-by-one range/alignment errors without
 // using production helpers to calculate an expected result.
 static const struct {unsigned off,len;int want;} cases[]={{0,512,0},{3584,512,0},{3585,512,-EINVAL},{4096,4,-EINVAL},{4092,4,0},{4093,3,-EREMOTEIO},{4095,2,-EINVAL},{0,4096,0},{0,4097,-EINVAL},{4,508,0},{2,512,-EREMOTEIO}};
 c=defaults();label="piece-boundaries";
 for(unsigned i=0;i<sizeof(cases)/sizeof(*cases);i++){INIT(&w,&c);add(&w,cases[i].off,cases[i].len,0,cases[i].want);}
 printf("storage_block_seg assertions=%u failures=%u\n",checks,failures);return failures?1:0;
}

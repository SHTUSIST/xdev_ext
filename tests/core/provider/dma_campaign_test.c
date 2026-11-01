// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dma_campaign.h"
#include "dma_wave.h"
static unsigned char wave_pattern(unsigned g,unsigned b){return campaign_pattern(g,b);}
static void wave_oracle(void)
{
 unsigned char image[512],before[512],unchanged[512];
 __u32 source[8],sink[8];bool seen[264]={0};unsigned distinct=0;
 struct xdev_ext_mech_stats s={.state=XDEV_EXT_MECH_SESSION_ACTIVE};
 struct dma_fixture_stats d={0};
 memset(image,0xa6,sizeof(image));memcpy(before,image,sizeof(image));
 for(unsigned base=0;base<257;) {
  unsigned count=257-base<8?257-base:8;
  memcpy(unchanged,image,sizeof(image));d.pending=1;
  assert(dma_wave_seed(image,before,512,0,8,16,base,wave_pattern,&s,&d,2)==-EAGAIN);
  assert(!memcmp(image,unchanged,sizeof(image)));d.pending=0;
  s.inflight=1;assert(dma_wave_seed(image,before,512,0,8,16,base,wave_pattern,&s,&d,2)==-EAGAIN);s.inflight=0;
  assert(!dma_wave_seed(image,before,512,0,8,16,base,wave_pattern,&s,&d,2));
  for(unsigned g=0;g<count;g++) {
   unsigned slot=(g*3+5)%8;source[g]=sink[g]=slot;
   assert(!seen[base+slot]);seen[base+slot]=true;distinct++;
   memcpy(image+256+slot*16,image+slot*16,16);
  }
  s.batches_done=base+count;s.submitted[0]=s.completed[0]=s.submitted[1]=s.completed[1]=base+count;
  d.accepted=d.completed=2ULL*(base+count);d.bytes=2ULL*(base+count)*16;
  assert(!dma_wave_check(image,before,512,256,8,16,base,count,source,sink,wave_pattern,&s,&d,2));
  image[256+source[0]*16]^=1;
  assert(dma_wave_check(image,before,512,256,8,16,base,count,source,sink,wave_pattern,&s,&d,2)==-EBADMSG);
  image[256+source[0]*16]^=1;
  sink[0]=(source[0]+1)%8;assert(dma_wave_check(image,before,512,256,8,16,base,count,source,sink,wave_pattern,&s,&d,2)==-EPROTO);sink[0]=source[0];
  base+=count;
 }
 assert(distinct==257);
 puts("PASS wave oracle: 257 distinct sequence patterns in reused depth8 slots, partial final wave, pending/inflight blocks refresh, stale payload and slot mismatch rejected");
}
int main(void)
{
 wave_oracle();
 uint64_t off=99;
 assert(campaign_offset(256,4096,2048,2U<<20,&off) && off==256*4096);
 off=99;assert(!campaign_offset(UINT64_MAX,4096,2048,2U<<20,&off)&&off==99);
 assert(!campaign_offset(0,0,2048,2U<<20,&off));
 assert(!campaign_offset(512,4096,2048,2U<<20,&off));
 assert(!campaign_offset(0,4096,4097,2U<<20,&off));
 unsigned char *image=malloc(8U<<20),*before=malloc(8U<<20);assert(image&&before);
 memset(image,0xa6,8U<<20);
 for(unsigned g=0;g<257;g++) for(unsigned b=0;b<2048;b++)image[(2U<<20)+g*4096+b]=campaign_pattern(g,b);
 memcpy(before,image,8U<<20);
 for(unsigned g=0;g<257;g++)memcpy(image+(6U<<20)+g*4096,image+(2U<<20)+g*4096,2048);
 assert(campaign_verify(image,before,8U<<20,6U<<20,257,4096,2048)==0);
 image[(6U<<20)+256*4096+2047]^=1;
 assert(campaign_verify(image,before,8U<<20,6U<<20,257,4096,2048)!=0);
 image[(6U<<20)+256*4096+2047]^=1;
 image[(6U<<20)+17*4096+2048]^=1;
 assert(campaign_verify(image,before,8U<<20,6U<<20,257,4096,2048)!=0);
 image[(6U<<20)+17*4096+2048]^=1;
 image[(2U<<20)+255*4096]^=1;
 assert(campaign_verify(image,before,8U<<20,6U<<20,257,4096,2048)!=0);
 for(unsigned a=0;a<257;a++)for(unsigned b=0;b<a;b++)assert(memcmp(before+(2U<<20)+a*4096,before+(2U<<20)+b*4096,2048));
 free(image);free(before);puts("PASS 257 distinct groups, zero/ones/alternating/mixed bodies, output/source/all guards, offset overflow");
 return 0;
}

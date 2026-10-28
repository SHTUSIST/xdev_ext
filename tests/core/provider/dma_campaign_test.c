// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dma_campaign.h"
int main(void)
{
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

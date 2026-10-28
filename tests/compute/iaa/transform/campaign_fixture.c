/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "campaign.h"
#define UNIT (2U*1024U*1024U)
int main(void) {
 unsigned char *before=malloc(4*UNIT),*window=malloc(4*UNIT),*pool=malloc(IAA_POOL_BYTES);
 assert(before&&window&&pool);memset(before,0xa6,4*UNIT);memcpy(window,before,4*UNIT);memset(pool,0x97,IAA_POOL_BYTES);
 unsigned highwater[IAA_POOL_FRAMES]={0};
 for(unsigned g=0;g<IAA_GROUPS;g++)for(unsigned b=0;b<IAA_PAYLOAD;b++)window[3*UNIT+g*IAA_PAYLOAD+b]=iaa_pattern(g,b);
 assert(!iaa_verify_window(window,before,4*UNIT,3*UNIT,IAA_GROUPS,IAA_PAYLOAD));
 const unsigned offsets[]={3*UNIT+77,UNIT+17,3*UNIT-1,4*UNIT-1};
 for(unsigned i=0;i<4;i++){window[offsets[i]]^=1;assert(iaa_verify_window(window,before,4*UNIT,3*UNIT,IAA_GROUPS,IAA_PAYLOAD));window[offsets[i]]^=1;}
 highwater[IAA_COMP_FIRST]=173;memset(pool+IAA_COMP_FIRST*IAA_FRAME+IAA_HEAD,0x3c,173);
 assert(!iaa_verify_pool_guards(pool,highwater));
 const unsigned guards[]={IAA_COMP_FIRST*IAA_FRAME+IAA_HEAD-1,IAA_COMP_FIRST*IAA_FRAME+IAA_HEAD+173,(IAA_COMP_FIRST+1)*IAA_FRAME+IAA_HEAD};
 for(unsigned i=0;i<3;i++){pool[guards[i]]^=1;assert(iaa_verify_pool_guards(pool,highwater));pool[guards[i]]^=1;}
 unsigned min=~0U,max=0;
 for(unsigned g=0;g<IAA_GROUPS;g++) {
  unsigned char input[IAA_PAYLOAD],compressed[2*IAA_PAYLOAD],restored[IAA_PAYLOAD];
  for(unsigned b=0;b<IAA_PAYLOAD;b++)input[b]=iaa_pattern(g,b);
  z_stream z={0};assert(deflateInit2(&z,Z_DEFAULT_COMPRESSION,Z_DEFLATED,-MAX_WBITS,8,Z_DEFAULT_STRATEGY)==Z_OK);
  z.next_in=input;z.avail_in=sizeof(input);z.next_out=compressed;z.avail_out=sizeof(compressed);
  assert(deflate(&z,Z_FINISH)==Z_STREAM_END);unsigned produced=z.total_out;deflateEnd(&z);
  if(produced<min)min=produced;
  if(produced>max)max=produced;
  z=(z_stream){0};assert(inflateInit2(&z,-MAX_WBITS)==Z_OK);z.next_in=compressed;z.avail_in=produced;z.next_out=restored;z.avail_out=sizeof(restored);
  assert(inflate(&z,Z_FINISH)==Z_STREAM_END);assert(z.total_out==IAA_PAYLOAD&&!memcmp(restored,input,IAA_PAYLOAD));inflateEnd(&z);
 }
 assert(min<IAA_PAYLOAD&&max>IAA_PAYLOAD);
 printf("PASS oracle mutations=7 raw_deflate_groups=257 min=%u max=%u full_window_bytes=%u pool_bytes=%u\n",min,max,4*UNIT,IAA_POOL_BYTES);
 free(before);free(window);free(pool);return 0;
}

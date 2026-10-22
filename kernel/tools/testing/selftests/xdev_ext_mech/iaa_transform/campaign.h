/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IAA_TRANSFORM_CAMPAIGN_H
#define IAA_TRANSFORM_CAMPAIGN_H
#include <stdint.h>
#include <stddef.h>
#define IAA_GROUPS 257U
#define IAA_DEPTH 8U
#define IAA_FRAME 8192U
#define IAA_HEAD 64U
#define IAA_PAYLOAD 4096U
#define IAA_POOL_FRAMES 64U
#define IAA_POOL_BYTES (IAA_POOL_FRAMES * IAA_FRAME)
#define IAA_COMP_FIRST 16U
#define IAA_DECOMP_FIRST 40U
/* The random branch forces DEFLATE expansion beyond the first output frame. */
static inline unsigned char iaa_pattern(unsigned group,unsigned byte)
{
 uint32_t x;
 if(byte<4)return (unsigned char)(group>>(byte*8));
 if(group%4==0)return 0;
 if(group%4==1)return (unsigned char)(byte&1?0x55:0xaa);
 if(group%4==2)return (unsigned char)(byte+group*29);
 x=(uint32_t)(group+1)*0x9e3779b9U+(uint32_t)(byte/4+1)*0x85ebca6bU;
 x^=x>>16;x*=0x7feb352dU;x^=x>>15;x*=0x846ca68bU;x^=x>>16;
 return (unsigned char)(x>>((byte%4)*8));
}
static inline int iaa_verify_window(const unsigned char *image,const unsigned char *before,
 size_t bytes,size_t output,unsigned groups,unsigned stride)
{
 if(output>bytes||stride<IAA_PAYLOAD||groups>(bytes-output)/stride)return -1;
 for(size_t i=0;i<bytes;i++) {
  unsigned char want=before[i];
  if(i>=output) {size_t rel=i-output;if(rel/stride<groups&&rel%stride<IAA_PAYLOAD)want=iaa_pattern(rel/stride,rel%stride);}
  if(image[i]!=want)return -1;
 }
 return 0;
}
static inline int iaa_verify_pool_guards(const unsigned char *pool,const unsigned *highwater)
{
 for(unsigned f=0;f<IAA_POOL_FRAMES;f++) {
  if(highwater[f]>IAA_PAYLOAD)return -1;
  for(unsigned p=0;p<IAA_FRAME;p++)
   if((p<IAA_HEAD||p>=IAA_HEAD+highwater[f])&&pool[f*IAA_FRAME+p]!=0x97)return -1;
 }
 return 0;
}
#endif

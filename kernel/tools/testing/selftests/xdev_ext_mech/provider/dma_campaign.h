/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DMA_CAMPAIGN_H
#define DMA_CAMPAIGN_H
#include <stdint.h>
#include <stddef.h>
static inline int campaign_offset(uint64_t group,uint64_t stride,uint64_t payload,
                                  uint64_t window,uint64_t *out)
{
 uint64_t offset;
 if(!stride || !payload || payload>stride || payload>window || group>(window-payload)/stride)
  return 0;
 offset=group*stride; /* Previous division proves multiplication cannot wrap. */
 *out=offset;return 1;
}
static inline unsigned char campaign_pattern(uint64_t group,unsigned int byte)
{
 if(byte<8) return (unsigned char)(group>>(byte*8));
 if(byte<16) return (unsigned char)~(group>>((byte-8)*8));
 switch(group%5) {
 case 0:return 0;
 case 1:return 255;
 case 2:return byte&1 ? 0x55 : 0xaa;
 case 3:return (unsigned char)(byte+group*29+(group>>8)*71);
 default:return (unsigned char)((byte*71+(byte>>3)*13+group*37+(group>>8)*19)^group);
 }
}
static inline int campaign_verify(const unsigned char *image,const unsigned char *before,
 size_t bytes,size_t output,uint64_t groups,unsigned stride,unsigned payload)
{
 size_t i;
 if(output>bytes || !stride || !payload || payload>stride ||
    !groups || groups>(bytes-output)/stride) return -1;
 for(i=0;i<bytes;i++) {
  unsigned char expected=before[i];
  if(i>=output) {
   size_t relative=i-output;
   if(relative/stride<groups && relative%stride<payload)
    expected=campaign_pattern(relative/stride,relative%stride);
  }
  if(image[i]!=expected) return -1;
 }
 return 0;
}
#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DMA_WAVE_H
#define DMA_WAVE_H
/* Correctness campaign only: never refresh a slot while any accepted native
 * work or frame lease from the preceding START remains in flight. */
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "dma_provider_fixture.h"

typedef unsigned char (*dma_wave_pattern_fn)(unsigned, unsigned);

static inline bool dma_wave_quiescent(const struct xdev_ext_mech_stats *s,
 const struct dma_fixture_stats *d, unsigned stages, unsigned done, unsigned payload)
{
 if (!stages || stages>XDEV_EXT_MECH_MAX_STAGES ||
     s->state!=XDEV_EXT_MECH_SESSION_ACTIVE || s->batches_done!=done ||
     s->batches_abort || s->rejects || s->sequestered || s->protocol_err ||
     s->last_err || s->inflight || d->pending || d->accepted!=d->completed ||
     d->completed!=2ULL*done || d->bytes!=2ULL*done*payload)
  return false;
 for(unsigned i=0;i<stages;i++)
  if(s->submitted[i]!=done || s->completed[i]!=done)return false;
 return true;
}

static inline int dma_wave_bounds(size_t bytes,size_t offset,unsigned depth,unsigned payload)
{
 return !depth || depth>8 || !payload || offset>bytes ||
        (size_t)depth>(bytes-offset)/payload ? -EINVAL : 0;
}

/* expected is an independent whole-image expectation, never copied back from
 * observed output. Every wave uses a disjoint pattern-id range base..base+depth. */
static inline int dma_wave_seed(unsigned char *image,unsigned char *expected,size_t bytes,
 size_t input,unsigned depth,unsigned payload,unsigned base,dma_wave_pattern_fn pattern,
 const struct xdev_ext_mech_stats *s,const struct dma_fixture_stats *d,unsigned stages)
{
 if(!dma_wave_quiescent(s,d,stages,base,payload))return -EAGAIN;
 if(dma_wave_bounds(bytes,input,depth,payload) || !pattern)return -EINVAL;
 if(memcmp(image,expected,bytes))return -EBADMSG;
 for(unsigned slot=0;slot<depth;slot++)for(unsigned b=0;b<payload;b++)
  image[input+(size_t)slot*payload+b]=expected[input+(size_t)slot*payload+b]=pattern(base+slot,b);
 return 0;
}

/* source/sink slots are per-business-sequence observations of C-issued leases.
 * Every sequence of the wave must use a different slot and round-trip to that
 * same slot. Old data from any preceding wave has a different literal pattern. */
static inline int dma_wave_check(const unsigned char *image,unsigned char *expected,size_t bytes,
 size_t output,unsigned depth,unsigned payload,unsigned base,unsigned count,
 const __u32 *source,const __u32 *sink,dma_wave_pattern_fn pattern,
 const struct xdev_ext_mech_stats *s,const struct dma_fixture_stats *d,unsigned stages)
{
 unsigned mask=0;
 if(!dma_wave_quiescent(s,d,stages,base+count,payload))return -EAGAIN;
 if(!count || count>depth || dma_wave_bounds(bytes,output,depth,payload) || !pattern)
  return -EINVAL;
 for(unsigned g=0;g<count;g++) {
  unsigned slot=source[g];
  if(slot>=depth || sink[g]!=slot || (mask&(1U<<slot)))return -EPROTO;
  mask|=1U<<slot;
 }
 for(unsigned g=0;g<count;g++)for(unsigned b=0;b<payload;b++) {
  unsigned slot=source[g];
  expected[output+(size_t)slot*payload+b]=pattern(base+slot,b);
 }
 return memcmp(image,expected,bytes) ? -EBADMSG : 0;
}
#endif

/* SPDX-License-Identifier: GPL-2.0 */
/* Extend only the existing native recorder, never production transport code.
 * Data in independently tracked coherent allocations is internal scratch.
 * Business PEER addresses are never dereferenced by this boundary. */
static int probe_startup_native_post(struct tb_ring *ring, struct ring_frame *frame)
{
 if (ring_info(ring)->control ||
     !probe_coherent_address(frame->buffer_phy, frame->size ? frame->size : 4096))
  return native_post(ring, frame);
 assert(ring->running && !ring_info(ring)->freed && world->nn < STACK_NATIVE);
 struct native *n = &world->n[world->nn++];
 *n = (struct native){.r=ring, .f=frame, .live=true,
                     .len=frame->size ? frame->size : 4096};
 stack_record((struct stack_event){
  .kind=STACK_EV_DATA_POST, .endpoint=ring_info(ring)->endpoint,
  .direction=ring->is_tx ? 1 : 2, .channel=ring_info(ring)->channel,
  .owner=(uintptr_t)frame, .address=frame->buffer_phy, .length=n->len,
  .pdf=frame->sof | (frame->eof << 8),
 });
 n->id = world->logs;
 return 0;
}

#define native_post probe_startup_native_post
#define one_native probe_existing_one_native
#define native_ready probe_existing_native_ready
#include "stack_nhi_boundary.h"
#undef native_ready
#undef one_native
#undef native_post

static bool held_tx[2][3];
static struct {unsigned type, offset; bool active, repair, repeat;} corrupt_data[2];
static struct native *filtered_native[STACK_NATIVE];
static unsigned nr_filtered;

static void filter_native(bool apply)
{
 if (!apply) {
  while (nr_filtered) filtered_native[--nr_filtered]->lost=false;
  return;
 }
 assert(!nr_filtered);
 for(unsigned i=0;i<world->nn;i++) {
  struct native *n=&world->n[i];
  struct stack_ring_info *info=ring_info(n->r);
  if(n->live && !n->lost && !n->completed && n->delivered && info->is_tx &&
     !info->control && probe_coherent_address(n->f->buffer_phy,n->len)) {
   unsigned type=((unsigned char *)(uintptr_t)n->f->buffer_phy)[5];
   if(type<3 && held_tx[info->endpoint][type]) {
    n->lost=true; filtered_native[nr_filtered++]=n;
   }
  }
 }
}

static struct native *native_ready(void)
{
 filter_native(true);
 struct native *n=probe_existing_native_ready();
 filter_native(false);
 return n;
}

static bool one_native(void)
{
 filter_native(true);
 struct native *tx = probe_existing_native_ready();
 if (tx && ring_info(tx->r)->is_tx && !ring_info(tx->r)->control &&
     !tx->delivered && probe_coherent_address(tx->f->buffer_phy, tx->len)) {
  struct native *rx = matching_rx(tx);
  assert(rx && tx->len <= 4096 &&
         probe_coherent_address(rx->f->buffer_phy, 4096));
  /* Only the external link boundary transfers scratch bytes; the actual
   * native descriptor and actual ring_work still deliver every callback. */
  memcpy((void *)(uintptr_t)rx->f->buffer_phy,
         (const void *)(uintptr_t)tx->f->buffer_phy, tx->len);
  unsigned endpoint=ring_info(tx->r)->endpoint;
  unsigned char *received=(void *)(uintptr_t)rx->f->buffer_phy;
  if(corrupt_data[endpoint].active && received[5]==corrupt_data[endpoint].type) {
   assert(corrupt_data[endpoint].offset<tx->len);
   received[corrupt_data[endpoint].offset]^=1;
   if(corrupt_data[endpoint].repair) {
    u32 checksum=~crc32c(~0U,received,tx->len-4);
    for(unsigned byte=0;byte<4;byte++)received[tx->len-4+byte]=checksum>>(8*byte);
   }
   corrupt_data[endpoint].active=corrupt_data[endpoint].repeat;
  }
 }
 bool result=probe_existing_one_native();
 filter_native(false);
 return result;
}

/* SPDX-License-Identifier: GPL-2.0 */
#include "probe_extra_compat.h"
static bool probe_coherent_address(dma_addr_t, size_t);
#define dma_alloc_coherent probe_existing_dma_alloc_coherent
#define dma_free_coherent probe_existing_dma_free_coherent
#define xdev_ext_requester_bind probe_recorded_requester_bind
#include "probe_stack_boundary.inc"
#undef xdev_ext_requester_bind
#undef dma_alloc_coherent
#undef dma_free_coherent
#include "probe_observation.h"

struct probe_allocation { void *pointer; size_t bytes; unsigned endpoint; bool freed; };
static struct probe_allocation allocations[1024];
static unsigned nr_allocations;
static unsigned requester_binds[2];

int xdev_ext_requester_bind(struct xdev_ext_requester *requester,
 struct xdev_ext_mech_stage *stage,struct pci_dev *pdev,u32 flags)
{
 requester_binds[stack_endpoint_stage(stage)]++;
 return probe_recorded_requester_bind(requester,stage,pdev,flags);
}

static bool probe_coherent_address(dma_addr_t address, size_t bytes)
{
 for (unsigned i = 0; i < nr_allocations; i++) {
  struct probe_allocation *a = &allocations[i];
  uintptr_t base = (uintptr_t)a->pointer;
  if (!a->freed && address >= base && address - base <= a->bytes &&
      bytes <= a->bytes - (address - base)) return true;
 }
 return false;
}

void *dma_alloc_coherent(struct device *dev, size_t bytes, dma_addr_t *dma, int flags)
{
 void *pointer = probe_existing_dma_alloc_coherent(dev, bytes, dma, flags);
 assert(nr_allocations < ARRAY_SIZE(allocations));
 if (pointer) allocations[nr_allocations++] = (struct probe_allocation){
  .pointer=pointer, .bytes=bytes, .endpoint=dev->endpoint};
 return pointer;
}

void dma_free_coherent(struct device *dev, size_t bytes, void *pointer, dma_addr_t dma)
{
 unsigned matches = 0;
 for (unsigned i = 0; i < nr_allocations; i++) {
  struct probe_allocation *a = &allocations[i];
  if (a->pointer == pointer && !a->freed) {
   assert(a->bytes == bytes && a->endpoint == dev->endpoint);
   a->freed = true; matches++;
  }
 }
 assert(matches == 1);
 probe_existing_dma_free_coherent(dev, bytes, pointer, dma);
}

void get_random_bytes(void *out, size_t length)
{
 unsigned char *bytes = out;
 while (length) {
  u64 value = get_random_u64();
  unsigned take = length < sizeof(value) ? length : sizeof(value);
  memcpy(bytes, &value, take); bytes += take; length -= take;
 }
}

bool cancel_delayed_work(struct delayed_work *work)
{
 return cancel_work_sync(&work->work); /* deterministic scheduler has no active peer worker */
}

int sysfs_emit_at(char *buffer, int offset, const char *format, ...)
{
 va_list args;
 va_start(args, format);
 int result = vsnprintf(buffer + offset, 4096 - offset, format, args);
 va_end(args);
 return result;
}

int probe_observe(struct stack_world *w, unsigned endpoint,
                  struct probe_observation *out)
{
 if (w != world || endpoint > 1 || !out || !w->side[endpoint].probed ||
     w->side[endpoint].removed) return -EINVAL;
 memset(out, 0, sizeof(*out));
 struct xdev_ext_xd_link *xl = link(endpoint);
 unsigned long flags;
 mutex_lock(&xl->ep_mutex);
 spin_lock_irqsave(&xl->lock, flags);
 out->up = xl->up; out->receive_ready = xl->receive_ready;
 out->logged_in = xl->logged_in; out->remote_logged_in = xl->remote_logged_in;
 out->local_inc = xl->local_inc; out->remote_inc = xl->remote_inc;
 out->accepted_inc = xl->accepted_inc; out->response_inc = xl->response_inc;
 out->retry_failures=xl->retry_failures; out->retries_exhausted=xl->retries_exhausted;
 out->link_ups=xl->link_ups;
 out->requester_binds=requester_binds[endpoint];
 for (unsigned c = 0; c < xl->channels; c++) {
  out->endpoints += !!xl->chan[c].ep[0] + !!xl->chan[c].ep[1];
  out->announced += xl->chan[c].announced; out->consumed += xl->chan[c].consumed;
  out->native_data_running += !!xl->chan[c].rx->running + !!xl->chan[c].tx->running;
 }
 spin_unlock_irqrestore(&xl->lock, flags);
 mutex_unlock(&xl->ep_mutex);
 for (size_t i = 0; i < w->logs; i++) {
  struct stack_event *e = &w->log[i];
  if (e->endpoint != endpoint || e->control) continue;
  out->data_posts += e->kind == STACK_EV_DATA_POST;
  out->data_callbacks += e->kind == STACK_EV_DATA_CALLBACK;
  out->native_data_callbacks += e->kind == STACK_EV_NHI_CALLBACK;
 }
 return 0;
}

int probe_native_facts(struct stack_world *w, unsigned endpoint,
                       struct probe_native_facts *out)
{
 if (w != world || endpoint > 1 || !out) return -EINVAL;
 memset(out, 0, sizeof(*out));
 for (unsigned i = 0; i < world->nn; i++) {
  struct native *n = &world->n[i];
  struct stack_ring_info *info = ring_info(n->r);
  if (info->endpoint != endpoint || info->control) continue;
  out->accepted++; out->pending += n->live; out->retired += !n->live;
  /* Frame storage stays owned by live transport; never read pending RX. */
  if (!n->live && n->completed && !info->freed) {
   unsigned length = n->f->size ? n->f->size : 4096;
   if (info->is_tx) { out->tx128 += n->len == 128; out->tx4096 += n->len == 4096; }
   else { out->rx128 += length == 128; out->rx4096 += length == 4096; }
  }
 }
 return 0;
}

size_t probe_live_allocations(unsigned endpoint, size_t bytes)
{
 size_t count = 0;
 for (unsigned i = 0; i < nr_allocations; i++)
  count += !allocations[i].freed && allocations[i].endpoint == endpoint &&
           allocations[i].bytes == bytes;
 return count;
}

void probe_hold_tx(unsigned endpoint,unsigned type,bool hold)
{
 assert(endpoint<2 && type>0 && type<3);
 held_tx[endpoint][type]=hold;
}

void probe_corrupt_data(unsigned endpoint,unsigned type,unsigned offset,bool repair)
{
 assert(endpoint<2 && type>0 && type<3);
 corrupt_data[endpoint].type=type; corrupt_data[endpoint].offset=offset;
 corrupt_data[endpoint].repair=repair; corrupt_data[endpoint].active=true;
}

void probe_corrupt_repeated(unsigned endpoint,unsigned type,unsigned offset)
{
 probe_corrupt_data(endpoint,type,offset,true);
 corrupt_data[endpoint].repeat=true;
}

void probe_stop_link(unsigned endpoint)
{
 assert(endpoint<2 && !world->side[endpoint].removed);
 xdev_ext_xd_link_down(link(endpoint),-ENOLINK);
}

void probe_retention_facts(unsigned endpoint,struct probe_retention_facts *out)
{
 assert(endpoint<2 && out);
 struct xdev_ext_requester_retention_stats stats;
 xdev_ext_requester_retention_snapshot(&world->side[endpoint].pci,&stats);
 *out=(struct probe_retention_facts){.generations=stats.generations,
   .retained_generations=stats.retained_generations,.retained_bytes=stats.retained_bytes};
 for(unsigned i=0;i<nr_allocations;i++)
  if(!allocations[i].freed && allocations[i].endpoint==endpoint)
   out->live_coherent_bytes+=allocations[i].bytes;
}

int probe_show_snapshot(unsigned endpoint,char *buffer)
{
 assert(endpoint<2 && !world->side[endpoint].removed && buffer);
 struct xdev_ext_xd_link *xl=link(endpoint);
 mutex_lock(&xl->ctl_mutex);
 int bytes=xdev_ext_xd_probe_show(xl,buffer);
 mutex_unlock(&xl->ctl_mutex);
 return bytes;
}

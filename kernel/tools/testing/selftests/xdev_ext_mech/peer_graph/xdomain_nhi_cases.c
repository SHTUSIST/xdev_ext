/* SPDX-License-Identifier: GPL-2.0 */
/* Observable software retirement; these tests never infer hardware DMA idle. */
static struct pci_dev pdev={.dev={.id=31}};
static struct tb_ring *tx[8],*rx[8];
static struct tb_nhi nhi;
static struct ring_frame frames[4];
static unsigned callbacks,normal_callbacks,canceled_callbacks;
static bool context_dead,block_normal_callback;
static unsigned frame_returns[4];
static void callback(struct tb_ring *r,struct ring_frame *f,bool canceled)
{
 assert(!held_locks&&!context_dead);unsigned i=(unsigned)(f-frames);assert(i<4);
 if(block_normal_callback&&!canceled){atomic_store(&callback_entered,true);while(!atomic_load(&callback_release))sched_yield();assert(!context_dead);}
 assert(!frame_returns[i]++);callbacks++;if(canceled)canceled_callbacks++;else normal_callbacks++;
}
static void setup(bool msix)
{
 pdev.msix_enabled=msix;
 nhi=(struct tb_nhi){.pdev=&pdev,.iobase=mmio,.tx_rings=tx,.rx_rings=rx,.hop_count=8};
 spin_lock_init(&nhi.lock);INIT_WORK(&nhi.interrupt_work,nhi_interrupt_work);
 for(unsigned i=0;i<4;i++) {frames[i]=(struct ring_frame){.buffer_phy=0x80000+i*4096,.callback=callback,.size=128};INIT_LIST_HEAD(&frames[i].list);}
}
static struct tb_ring *allocated(bool msix,bool started)
{
 setup(msix);struct tb_ring *r=tb_ring_alloc_tx(&nhi,-1,8,RING_FLAG_FRAME);
 assert(r&&tx[r->hop]==r&&!r->start_poll);if(started)tb_ring_start(r);return r;
}
static void post(struct tb_ring *r,unsigned n)
{for(unsigned i=0;i<n;i++)assert(!__tb_ring_enqueue(r,&frames[i]));}
static bool was_freed(void *p)
{for(unsigned i=0;i<allocation_nr;i++)if(allocations[i].p==p)return allocations[i].freed;assert(!"allocation not recorded");return false;}
static void retire(struct tb_ring *r)
{retiring=true;tb_ring_free_quarantined(r);retiring=false;}
static void inert(struct tb_ring *r,void *desc,dma_addr_t dma)
{
 assert(!tx[1]&&!r->running&&!r->nhi&&!r->irq&&!r->start_poll&&!r->poll_data);
 assert(!r->work.pending&&!r->work.func);
 assert(list_empty(&r->queue)&&list_empty(&r->in_flight));
 assert(!was_freed(desc)&&!was_freed(r));
 /* Metadata may remain in tb_ring or migrate inside its private wrapper.
  * Require an actual retained owner record to keep the backing address. */
 bool recorded=false;
 for(unsigned i=0;i<allocation_nr;i++)if(!allocations[i].freed&&allocations[i].p!=desc)
  for(size_t off=0;off+sizeof(void *)<=allocations[i].n;off+=sizeof(void *)) {
   void *value;memcpy(&value,(u8 *)allocations[i].p+off,sizeof(value));if(value==desc)recorded=true;
  }
 assert(recorded);(void)dma;
 assert(pdev.refs==1&&pdev_gets==1&&!pdev_puts);
}
static void descriptor_is_retained_but_callback_released(void)
{
 struct tb_ring *r=allocated(false,true);void *desc=r->descriptors;dma_addr_t dma=r->descriptors_dma;
 post(r,3);nhi.going_away=true;retire(r);
 assert(callbacks==3&&canceled_callbacks==3&&!normal_callbacks&&!dma_frees);
 inert(r,desc,dma);assert(!held_locks);
}
static void going_away_retirement_never_mmio(void)
{
 struct tb_ring *r=allocated(true,true);post(r,1);nhi.going_away=true;
 unsigned rd=mmio_reads,wr=mmio_writes;retire(r);
 assert(mmio_reads==rd&&mmio_writes==wr&&irq_frees==1&&callbacks==1);
 assert(last_flush_event>irq_free_event&&!dma_frees);
}
static void dedicated_irq_is_synchronized_before_final_flush(void)
{
 struct tb_ring *r=allocated(true,true);post(r,2);
 /* An IRQ already dispatched may still enter the real handler while free_irq
  * synchronizes. It must finish before the final work/callback barrier. */
 inject_irq_at_free=true;ring_msix(r->irq,r);assert(r->work.pending);
 retire(r);assert(irq_frees==1&&last_flush_event>irq_free_event&&callbacks==2);
 context_dead=true;mmio_dead=true;unsigned old=callbacks;
 for(unsigned i=0;i<irq_nr;i++)if(irqs[i].active)irqs[i].fn(irqs[i].irq,irqs[i].data);
 assert(callbacks==old&&!r->work.pending&&!r->work.func&&!r->nhi);
}
static void shared_irq_unlink_preserves_other_ring(void)
{
 struct tb_ring *r=allocated(false,true);
 struct tb_ring *other=tb_ring_alloc_tx(&nhi,-1,8,RING_FLAG_FRAME);assert(other&&other->hop==2);
 tb_ring_start(other);post(r,1);assert(!__tb_ring_enqueue(other,&frames[1]));
 /* Shared lookup's actual source holds NHI lock until schedule_work. */
 *(u32 *)(mmio+REG_RING_NOTIFY_BASE)=BIT(r->hop)|BIT(other->hop);
 nhi_interrupt_work(&nhi.interrupt_work);assert(r->work.pending&&other->work.pending);
 retire(r);assert(!tx[1]&&tx[2]==other&&!global_irq_disables&&!global_work_cancels&&!irq_frees);
 unsigned r_schedules=r->work.schedules;
 other->descriptors[other->tail].flags|=RING_DESC_COMPLETED;
 nhi_interrupt_work(&nhi.interrupt_work);flush_work(&other->work);
 assert(r->work.schedules==r_schedules&&callbacks==2&&normal_callbacks==1&&canceled_callbacks==1);
 assert(other->running&&tx[2]==other);
}
static void normal_done_is_not_recanceled(void)
{
 struct tb_ring *r=allocated(true,true);post(r,3);
 r->descriptors[r->tail].flags|=RING_DESC_COMPLETED;
 ring_msix(r->irq,r);flush_work(&r->work);assert(callbacks==1&&normal_callbacks==1);
 nhi.going_away=true;retire(r);
 assert(callbacks==3&&normal_callbacks==1&&canceled_callbacks==2);
 for(unsigned i=0;i<3;i++)assert(frame_returns[i]==1);
}
static void normal_stopped_descriptor_is_freed(void)
{
 struct tb_ring *r=allocated(true,true);void *desc=r->descriptors;post(r,2);
 tb_ring_stop(r);assert(!r->running&&callbacks==2&&canceled_callbacks==2);
 tb_ring_free(r);assert(dma_frees==1&&was_freed(desc)&&was_freed(r));
 assert(pdev_gets==1&&pdev_puts==1&&!pdev.refs&&irq_frees==1&&!warnings);
}
static void unused_descriptor_is_freed(void)
{
 struct tb_ring *r=allocated(false,false);void *desc=r->descriptors;
 tb_ring_free(r);assert(!callbacks&&dma_frees==1&&was_freed(desc));
 assert(pdev_gets==1&&pdev_puts==1&&!pdev.refs);
}
static void allocation_failure_balances_pci_reference(void)
{
 setup(true);alloc_fail_at=2; /* coherent descriptor allocation fails */
 assert(!tb_ring_alloc_tx(&nhi,-1,8,RING_FLAG_FRAME));
 assert(!pdev.refs&&pdev_gets==pdev_puts&&!irq_nr&&!tx[1]);
}
static void hop_failure_balances_pci_reference(void)
{
 setup(true);assert(!tb_ring_alloc_tx(&nhi,99,8,RING_FLAG_FRAME));
 assert(pdev_gets==1&&pdev_puts==1&&!pdev.refs&&irq_frees==1&&dma_frees==1&&!tx[1]);
}
static void retire_performs_no_allocation(void)
{
 struct tb_ring *r=allocated(true,true);post(r,1);nhi.going_away=true;
 unsigned attempts=allocation_calls;retire(r);
 assert(allocation_calls==attempts&&!dma_frees&&pdev.refs==1);
}
static void already_stopped_retirement_does_not_disable_twice(void)
{
 struct tb_ring *r=allocated(false,true);post(r,1);tb_ring_stop(r);
 unsigned rd=mmio_reads,wr=mmio_writes,warn=warnings;
 retire(r);assert(mmio_reads==rd&&mmio_writes==wr&&warnings==warn);
 assert(callbacks==1&&canceled_callbacks==1&&!dma_frees);
}
static void in_progress_normal_callback_is_drained_before_context_release(void)
{
 struct tb_ring *r=allocated(true,true);post(r,3);
 r->descriptors[r->tail].flags|=RING_DESC_COMPLETED;
 block_normal_callback=true;run_async_once=true;ring_msix(r->irq,r);
 while(!atomic_load(&callback_entered))sched_yield();
 /* A real ring_work invocation has already built its local normal-done list
  * and entered its callback. Retirement must wait for that worker, preserve
  * its normal classification, then cancel remaining accepted frames once. */
 nhi.going_away=true;retire(r);
 assert(callbacks==3&&normal_callbacks==1&&canceled_callbacks==2);
 assert(!r->work.asynchronous&&!atomic_load(&r->work.active)&&!r->work.pending);
 context_dead=true;mmio_dead=true;assert(!r->work.func&&!r->nhi);
}
static struct tb_ring *lookup_retire_ring;
static void *retire_while_lookup_holds_lock(void *unused)
{retire(lookup_retire_ring);return NULL;}
static void shared_lookup_interleave(void)
{
 assert(nhi.lock.held);gate_nhi_lock=&nhi.lock;
 assert(!pthread_create(&gate_retire_thread,NULL,retire_while_lookup_holds_lock,NULL));
 /* Wait until retirement actually attempts the same real pthread lock. The
  * old lookup then finishes its lookup->ring-lock->schedule section before
  * retirement can unlink; no timing sleeps or fictitious kth-submit failure. */
 while(!atomic_load(&retire_lock_attempted))sched_yield();
 shared_lookup_gate=false;
}
static void shared_lookup_and_unlink_are_serialized(void)
{
 struct tb_ring *r=allocated(false,true);post(r,1);
 struct tb_ring *other=tb_ring_alloc_tx(&nhi,-1,8,RING_FLAG_FRAME);assert(other);
 tb_ring_start(other);assert(!__tb_ring_enqueue(other,&frames[1]));
 lookup_retire_ring=r;shared_lookup_address=mmio+REG_RING_NOTIFY_BASE;shared_lookup_gate=true;
 *(u32 *)shared_lookup_address=BIT(r->hop)|BIT(other->hop);
 nhi_interrupt_work(&nhi.interrupt_work);
 assert(!pthread_join(gate_retire_thread,NULL));gate_nhi_lock=NULL;
 assert(!tx[1]&&tx[2]==other&&callbacks==1&&canceled_callbacks==1);
 unsigned before=r->work.schedules;
 other->descriptors[other->tail].flags|=RING_DESC_COMPLETED;
 nhi_interrupt_work(&nhi.interrupt_work);flush_work(&other->work);
 assert(r->work.schedules==before&&callbacks==2&&normal_callbacks==1);
 assert(!global_irq_disables&&!global_work_cancels&&!r->nhi&&!r->work.func);
}
static struct {const char *name;void (*run)(void);} cases[]={
 {"retirement keeps descriptor DMA and returns accepted frames UNKNOWN",descriptor_is_retained_but_callback_released},
 {"going-away retirement performs no MMIO",going_away_retirement_never_mmio},
 {"dedicated MSI-X free_irq precedes final real ring_work barrier",dedicated_irq_is_synchronized_before_final_flush},
 {"shared MSI lookup cannot find retired ring and unrelated ring progresses",shared_irq_unlink_preserves_other_ring},
 {"real normal completion stays normal; remaining cancellation happens once",normal_done_is_not_recanceled},
 {"normal STOPPED descriptor is freed with balanced PCI reference",normal_stopped_descriptor_is_freed},
 {"UNUSED descriptor is freed with balanced PCI reference",unused_descriptor_is_freed},
 {"descriptor allocation failure balances reserved PCI reference",allocation_failure_balances_pci_reference},
 {"HopID failure releases IRQ descriptor and reserved PCI reference",hop_failure_balances_pci_reference},
 {"retirement performs no GFP allocation after begin",retire_performs_no_allocation},
 {"already stopped retirement avoids duplicate MMIO disable",already_stopped_retirement_does_not_disable_twice},
 {"in-progress normal callback drains before callback parent release",in_progress_normal_callback_is_drained_before_context_release},
 {"concurrent actual shared lookup and NHI unlink use same lock",shared_lookup_and_unlink_are_serialized},
};
int main(int argc,char **argv) {
 if(argc==2&&!strcmp(argv[1],"--count")){printf("%zu\n",ARRAY_SIZE(cases));return 0;}
 if(argc!=2)return 2;unsigned i=(unsigned)strtoul(argv[1],NULL,10);if(!i||i>ARRAY_SIZE(cases))return 2;
 cases[i-1].run();printf("ok %u - %s\n",i,cases[i-1].name);return 0;
}

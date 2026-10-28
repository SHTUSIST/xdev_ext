/* SPDX-License-Identifier: GPL-2.0 */
/* Production NHI list transitions, independent list-walk oracle. */
static unsigned callbacks,canceled_callbacks,failures,samples;
static struct tb_ring *stop_probe;
static bool stop_probe_seen;
static void shared_lookup_interleave(void) { assert(!"unexpected shared IRQ gate"); }
static unsigned membership(struct list_head *head)
{
 unsigned n=0;
 for(struct list_head *p=head->next;p!=head;p=p->next){assert(n<1000);n++;}
 return n;
}
static void checked(bool condition,const char *message)
{ if(!condition){failures++;fprintf(stderr,"DIAG_NATIVE_ASSERT: %s\n",message);} }
static bool sample(struct tb_ring *r,unsigned inflight,unsigned queued,bool running)
{
 checked(membership(&r->in_flight)==inflight,"hand-derived native membership precondition");
 checked(membership(&r->queue)==queued,"hand-derived software membership precondition");
 if(!tb_ring_snapshot){fprintf(stderr,"DIAG_NATIVE_MISSING_FEATURE: tb_ring_snapshot runtime capability absent; transition assertions not certified\n");failures++;return false;}
 struct tb_ring_snapshot d={0};
 unsigned alloc=allocation_calls,rd=mmio_reads,wr=mmio_writes;
 unsigned cb=callbacks,scheduled=r->work.schedules;
 tb_ring_snapshot(r,&d);samples++;
 checked(d.in_flight==membership(&r->in_flight),"snapshot native count equals actual in_flight list");
 checked(d.software_pending==membership(&r->queue),"snapshot software count equals actual queue list");
 checked(d.in_flight==inflight && d.software_pending==queued,"snapshot equals literal transition state");
 checked(d.running==running && d.notify_pending==r->notify_pending,"snapshot copies running/notify facts");
 checked(alloc==allocation_calls && rd==mmio_reads && wr==mmio_writes && cb==callbacks && scheduled==r->work.schedules,"snapshot does not allocate, touch MMIO, drain callbacks or schedule work");
 checked(!held_locks,"snapshot releases its ring lock");
 return true;
}
static void diag_before_flush(struct work_struct *w)
{
 if(!stop_probe || w!=&stop_probe->work)return;
 checked(!stop_probe->running && stop_probe->head==0 && stop_probe->tail==0,"real stop resets head/tail before callback drain");
 sample(stop_probe,2,3,false);stop_probe_seen=true;stop_probe=NULL;
}
static struct pci_dev pdev={.dev={.id=29},.msix_enabled=true};
static struct tb_ring *tx[8],*rx[8];
static struct tb_nhi nhi;
static struct ring_frame frames[5];
static void completed(struct tb_ring *r,struct ring_frame *f,bool canceled)
{ (void)r;(void)f;checked(!held_locks,"callbacks run outside ring lock");callbacks++;if(canceled)canceled_callbacks++; }
static struct tb_ring *setup(bool receive,bool poll)
{
 nhi=(struct tb_nhi){.pdev=&pdev,.iobase=mmio,.tx_rings=tx,.rx_rings=rx,.hop_count=8};
 spin_lock_init(&nhi.lock);INIT_WORK(&nhi.interrupt_work,nhi_interrupt_work);
 unsigned flags=RING_FLAG_FRAME|(poll?RING_FLAG_NO_INTERRUPT:0);
 struct tb_ring *r=receive?tb_ring_alloc_rx(&nhi,-1,3,flags,0,0,0,NULL,NULL):tb_ring_alloc_tx(&nhi,-1,3,flags);
 assert(r);for(unsigned i=0;i<5;i++){
  frames[i]=(struct ring_frame){.buffer_phy=0x80000+i*4096,.callback=completed,.size=128};
  INIT_LIST_HEAD(&frames[i].list);
 }
 return r;
}
static void post(struct tb_ring *r,unsigned begin,unsigned n,bool more)
{ for(unsigned i=begin;i<begin+n;i++)checked(!__tb_ring_enqueue(r,&frames[i],more),"real enqueue accepted existing bounded frame"); }
int main(int argc,char **argv)
{
 assert(argc==2);const char *name=argv[1];bool poll=!strcmp(name,"poll-refill");
 bool receive=!strcmp(name,"rx-posted-membership");struct tb_ring *r=setup(receive,poll);
 if(!sample(r,0,0,false))goto done;
 tb_ring_start(r);sample(r,0,0,true);
 if(!strcmp(name,"enqueue-refill-irq")){
  post(r,0,5,true);sample(r,2,3,true);
  checked(r->notify_pending,"deferred enqueue retains notify_pending");
  r->descriptors[r->tail].flags|=RING_DESC_COMPLETED;
  ring_msix(r->irq,r);flush_work(&r->work);
  sample(r,2,2,true);checked(callbacks==1 && !canceled_callbacks,"IRQ completion returns exactly one frame and refills one");
  tb_ring_stop(r);sample(r,0,0,false);checked(callbacks==5 && canceled_callbacks==4,"stop cancels exact remaining membership");
 }else if(poll){
  post(r,0,5,false);sample(r,2,3,true);
  r->descriptors[r->tail].flags|=RING_DESC_COMPLETED;
  struct ring_frame *f=tb_ring_poll(r);checked(f==&frames[0],"real poll returns first completed frame");
  sample(r,2,2,true);checked(!callbacks,"poll return excludes the returned frame before caller callback");
  completed(r,f,false);tb_ring_stop(r);sample(r,0,0,false);
 }else if(!strcmp(name,"stopped-undrained")){
  post(r,0,5,false);sample(r,2,3,true);stop_probe=r;tb_ring_stop(r);
  checked(stop_probe_seen,"stop sampled its actual pre-drain window");sample(r,0,0,false);
 }else if(!strcmp(name,"restart")){
  post(r,0,5,false);tb_ring_stop(r);sample(r,0,0,false);
  tb_ring_start(r);sample(r,0,0,true);post(r,0,1,false);sample(r,1,0,true);
  tb_ring_stop(r);sample(r,0,0,false);checked(callbacks==6,"second start accepts returned frame once");
 }else if(receive){
  post(r,0,5,false);sample(r,2,3,true);
  r->descriptors[r->tail].flags|=RING_DESC_COMPLETED;
  ring_msix(r->irq,r);flush_work(&r->work);sample(r,2,2,true);
  checked(callbacks==1,"RX completion/refill uses actual descriptors");tb_ring_stop(r);sample(r,0,0,false);
 }else{
  assert(!strcmp(name,"quarantined-allocation"));
  post(r,0,5,false);sample(r,2,3,true);nhi.going_away=true;
  retiring=true;tb_ring_free_quarantined(r);retiring=false;
  sample(r,0,0,false);checked(!r->nhi && callbacks==5 && canceled_callbacks==5,"quarantined storage is inert after all callback custody returns");
  checked(!dma_frees && pdev.refs==1,"quarantine retains descriptor backing and owner reference");
 }
done:
 printf("DIAG_NATIVE %s samples=%u failures=%u\n",name,samples,failures);return !!failures;
}

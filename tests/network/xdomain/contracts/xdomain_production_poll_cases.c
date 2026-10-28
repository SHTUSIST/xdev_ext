/* SPDX-License-Identifier: GPL-2.0 */
/* Requirement-driven production-mode completion tests. No test dispatcher. */
#define main original_stack_main
#include "stack_cases.c"
#undef main
int production_poll_select(bool);
void production_poll_external_enable(bool);
void production_poll_once(unsigned);
unsigned production_poll_rings(unsigned,unsigned *,unsigned *);
unsigned production_poll_complete_tx(unsigned,unsigned);
unsigned production_poll_pending(void);
void production_poll_counts(unsigned,unsigned *,unsigned *);
void production_poll_worker_gone(unsigned);
int production_poll_race(unsigned,bool);
void production_poll_fail_allocation(unsigned);
void production_poll_delay_control_ack(void);
static size_t native_callbacks(struct stack_world *w,unsigned endpoint,bool data)
{
 size_t n=0;for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
 if(e.kind==STACK_EV_NHI_CALLBACK&&e.endpoint==endpoint&&(!data||!e.control)&&!e.status)n++;}return n;
}
static struct stack_world *production_world(struct stack_config *c)
{
 CHECK(!c->nhi_poll&&!c->nhi_batch,"production mode forbids adapter flag injection and notify injection");
 CHECK(production_poll_select(true)==0,"mode-selection missing feature: real readonly default-false poll_completions bool must exist");
 production_poll_external_enable(false);return create(c);
}
static void startup(struct stack_world *w)
{
 CHECK(stack_probe(w,0)==0&&stack_probe(w,1)==0,"real probes allocate production mode before CREATE");
 for(unsigned i=0;i<100;i++)pump(w,1000000);
 CHECK(count(w,STACK_EV_STARTUP_CONTROL_RX,-1,-1)>0&&count(w,STACK_EV_STARTUP_CALLBACK,-1,-1)>0,
       "startup challenge completes through bounded production fallback before CREATE");
 for(unsigned endpoint=0;endpoint<2;endpoint++){
  unsigned noirq,startpoll;unsigned rings=production_poll_rings(endpoint,&noirq,&startpoll);
  CHECK(rings==4&&noirq==4&&!startpoll,"all four production NHI rings have NO_INTERRUPT and NULL start_poll");
 }
 CHECK(count(w,STACK_EV_NHI_IRQ_ALLOC,-1,-1)==0,"production NO_INTERRUPT allocates no IRQ");
}
static void assert_sources(struct stack_world *w)
{
 bool session=false,fallback=false;unsigned kinds=0;
 for(size_t i=0;i<stack_log_count(w);i++){
  struct stack_event e=ev(w,i);
  if(e.kind==STACK_EV_SCHED_STEP)CHECK(e.flags!=STACK_STEP_NHI_POLL,"external adapter dispatcher never retires a production frame");
  if(e.kind==STACK_EV_NHI_POST)CHECK(!(e.flags&8U),"actual descriptor has no INTERRUPT bit");
  if(e.kind==1000&&e.address){session|=e.flags==1;fallback|=e.flags==2;}
  if(e.kind==STACK_EV_NHI_CALLBACK&&!e.status){
   CHECK(e.flags==2,"production completion callback originates in real native poll");
   kinds|=1U<<((e.control?0:2)+(e.direction==2));
  }
 }
 CHECK(session,"actual session progress collects a completed native frame");
 CHECK(fallback,"fallback returns are recorded separately from session progress");
 CHECK(kinds==15,"control TX/RX and data TX/RX callbacks all execute through production polling");
}
static void legacy_irq(void)
{
 (void)production_poll_select(false);production_poll_external_enable(false);
 struct stack_config c=geometry();struct stack_world *w=create(&c);
 login(w);sessions(w,1,0);start(w,c.first_seq,0);pump(w,1000000);release_group(w,c.first_seq);
 CHECK(count(w,STACK_EV_NHI_IRQ_ALLOC,-1,-1)>0,"default IRQ mode keeps real IRQ allocation");
 for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_NHI_CALLBACK&&!e.status)CHECK(e.flags==1,"default callbacks remain real ring_work");}
 addresses(w,&c);safety(w);stack_destroy(w);
}
static void mode_selection(void)
{
 struct stack_config c=geometry();struct stack_world *w=production_world(&c);startup(w);
 safety(w);stack_destroy(w);
}
static void startup_before_create(void)
{
 struct stack_config c=geometry();struct stack_world *w=production_world(&c);startup(w);
 CHECK(count(w,STACK_EV_BUILD,-1,-1)==0&&count(w,STACK_EV_PUBLISH,-1,-1)==0,"startup fallback requires no session work");
 size_t before=count(w,STACK_EV_NHI_CALLBACK,-1,-1);
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(count(w,STACK_EV_NHI_CALLBACK,-1,-1)==before,"idle posted RX produces no fabricated completion");
 safety(w);stack_destroy(w);
}
static void four_ring_progress(void)
{
 struct stack_config c=geometry();c.nhi_ring_size=3;
 struct stack_world *w=production_world(&c);startup(w);sessions(w,9,0);
 for(unsigned g=0;g<9;g++){
  start(w,c.first_seq+g,0);for(unsigned i=0;i<10;i++)pump(w,1000000);
  CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==g,"consumer release gates ACK in production polling mode");
  release_group(w,c.first_seq+g);for(unsigned i=0;i<10;i++)pump(w,1000000);
 }
 CHECK(count(w,STACK_EV_PUBLISH,0,-1)==9&&count(w,STACK_EV_PUBLISH,1,-1)==9,"finite rings refill and publish every native group once");
 CHECK(native_callbacks(w,0,true)==36&&native_callbacks(w,1,true)==36,"tiny-ring refill returns every accepted data owner exactly once");
 addresses(w,&c);assert_sources(w);safety(w);stack_destroy(w);
}
static struct stack_config sixteen(void)
{
 struct stack_config c=geometry();c.depth=16;c.nr_frames=8;c.native_elems=16;
 for(unsigned i=0;i<8;i++)c.span[i]=(struct stack_span){65536ULL*(i+1),4096,8192};return c;
}
static struct stack_world *backlog(struct stack_config *c)
{
 struct stack_world *w=production_world(c);startup(w);sessions(w,16,0);
 fault(w,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);
 for(unsigned g=0;g<16;g++){
  start(w,c->first_seq+g,0);for(unsigned i=0;i<5;i++)pump(w,1000000);
  /* The final accepted TX frame is software-pending until a native
   * completion is collected. Its matching RX cannot be released yet. */
  if(g<15){release_group(w,c->first_seq+g);for(unsigned i=0;i<5;i++)pump(w,1000000);}
 }
 CHECK(native_callbacks(w,1,true)==255,"withheld TX collection leaves the256th RX frame genuinely undelivered");
 CHECK(count(w,STACK_EV_PUBLISH,1,-1)==15,"only fifteen complete RX groups publish before real TX refill");
 CHECK(stack_release(w,1,c->first_seq+15)==-EAGAIN,"incomplete final RX group cannot enter CHAIN_END before actual refill");
 CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==15,"incomplete final RX group cannot produce an early sixteenth ACK");
 unsigned inflight,queued;production_poll_counts(0,&inflight,&queued);
 CHECK(inflight==255&&queued==1,"256 accepted frames retain 255 descriptors and one software pending owner");
 CHECK(native_callbacks(w,0,true)==0,"withheld TX descriptor completions cannot synthesize callbacks");return w;
}
static void budget_64_65(void)
{
 struct stack_config c=sixteen();struct stack_world *w=backlog(&c);
 CHECK(production_poll_complete_tx(0,65)==65,"hardware marks exactly65 delivered native descriptors complete");
 size_t before=stack_log_count(w);production_poll_once(0);
 CHECK(native_callbacks(w,0,true)==64,"one production session progress pass dispatches exactly64 of65 completed frames");
 unsigned inflight,queued;production_poll_counts(0,&inflight,&queued);
 CHECK(queued==0,"poll return refills the pending256th frame through actual NHI notify");
 /* Every eight successful pulls must offer another real ring before the
  * current ring receives its next successful pull; NULL offers count too. */
 unsigned run=0;uint64_t ring=0;
 for(size_t i=before;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind!=1000)continue;
  if(e.owner!=ring){ring=e.owner;run=0;}if(e.address)run++;CHECK(run<=8,"round-robin offers another ring after at most8 successful pulls");}
 production_poll_once(0);CHECK(native_callbacks(w,0,true)==65,"65th completion survives budget edge for next bounded pass");
 for(unsigned i=0;i<5;i++)pump(w,1000000);
 CHECK(native_callbacks(w,1,true)==256,"actual poll collection/refill delivers and completes the final native RX frame");
 CHECK(count(w,STACK_EV_PUBLISH,1,-1)==16,"last RX group publishes only after actual refill delivery");
 CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==15,"final RX completion still cannot ACK before consumer release");
 release_group(w,c.first_seq+15);
 CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==16,"sixteenth ACK follows actual final RX consumer release");
 fault(w,STACK_FAULT_RELEASE_CALLBACKS,0,0,0,0,0);for(unsigned i=0;i<20;i++)pump(w,1000000);
 CHECK(native_callbacks(w,0,true)==256,"all256 accepted owners return exactly once after refill");
 addresses(w,&c);safety(w);stack_destroy(w);
}
static void pending_256(void){budget_64_65();}
static void worker_gone(void)
{
 struct stack_config c=geometry();struct stack_world *w=production_world(&c);startup(w);sessions(w,1,0);
 start(w,c.first_seq,0);for(unsigned i=0;i<10;i++)pump(w,1000000);release_group(w,c.first_seq);
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(stack_stop(w,0)==0&&stack_stop(w,1)==0,"completed sessions STOP before external core worker retirement");
 production_poll_worker_gone(0);production_poll_worker_gone(1);
 CHECK(stack_suspend(w,0)==0&&stack_suspend(w,1)==0,"suspend shared links after worker_gone");
 CHECK(stack_resume(w,0)==0&&stack_resume(w,1)==0,"resume retains independent shared link poller lifecycle");
 size_t after=stack_log_count(w);for(unsigned i=0;i<100;i++)pump(w,1000000);
 bool fallback=false;for(size_t i=after;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==1000&&e.address&&e.flags==2)fallback=true;
 if(e.kind==STACK_EV_SCHED_STEP)CHECK(e.flags!=STACK_STEP_PROGRESS,"worker_gone suppresses all old session progress");}
 CHECK(fallback,"shared link startup/control still progresses after actual class unbind without stale stage worker");
 safety(w);stack_destroy(w);
}
static void stop_remove_unknown(void)
{
 for(unsigned unavailable=0;unavailable<2;unavailable++){
  struct stack_config c=geometry();c.nhi_ring_size=3;struct stack_world *w=production_world(&c);startup(w);sessions(w,1,0);
  fault(w,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);start(w,c.first_seq,0);for(unsigned i=0;i<10;i++)pump(w,1000000);
  if(unavailable)fault(w,STACK_FAULT_GOING_AWAY,0,0,0,1,0);
  CHECK(stack_remove(w,0)==0,"remove excludes production poll callbacks before stopping/freeing rings");
  size_t callbacks=count(w,STACK_EV_NHI_CALLBACK,0,-1);for(unsigned i=0;i<10;i++)pump(w,1000000);
  CHECK(count(w,STACK_EV_NHI_CALLBACK,0,-1)==callbacks,"no stale production callback follows ring retirement");
  CHECK(count(w,STACK_EV_LEASE_RELEASE,0,-1)==0,"STOP/unknown cannot falsely release accepted TX lease before quiescence");
  if(unavailable){bool retained=false;for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_NHI_RETIRE&&e.endpoint==0&&e.status==-ENOLINK){retained=true;CHECK(e.address&&e.bytes==0,"unknown native descriptor backing is retained with no DMA free");}}CHECK(retained,"unavailable NHI produces explicit unknown retirement");}
  safety(w);stack_destroy(w);
 }
}
static void partial_allocation(void)
{
 for(unsigned ordinal=1;ordinal<=4;ordinal++){
  struct stack_config c=geometry();struct stack_world *w=production_world(&c);
  production_poll_fail_allocation(ordinal);
  int result=stack_probe(w,0);
  if(!result){CHECK(stack_probe(w,1)==0,"peer probe for asynchronous data-ring allocation");for(unsigned i=0;i<10;i++)pump(w,1000000);}
  bool rejected=false;for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_REJECT&&e.endpoint==0&&e.status==-ENOMEM)rejected=true;}
  CHECK(rejected,"fail each of four native ring allocations at its actual allocation boundary");
  if(!result)CHECK(stack_remove(w,0)==0,"partial connected link removes its accepted resources");
  CHECK(count(w,STACK_EV_RING_ALLOC,0,-1)==count(w,STACK_EV_RING_FREE,0,-1),"partial allocation retires every accepted ring exactly once");
  size_t callbacks=count(w,STACK_EV_NHI_CALLBACK,0,-1);for(unsigned i=0;i<10;i++)pump(w,1000000);
  CHECK(count(w,STACK_EV_NHI_CALLBACK,0,-1)==callbacks,"failed/retired partial allocation leaves no callback producer");
  safety(w);stack_destroy(w);
 }
 production_poll_fail_allocation(0);
}
static void poll_return_race(bool suspend)
{
 struct stack_config c=geometry();struct stack_world *w=production_world(&c);startup(w);sessions(w,1,0);
 fault(w,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);start(w,c.first_seq,0);for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(production_poll_complete_tx(0,1)==1,"race stimulus completes one actual native TX descriptor");
 size_t before=native_callbacks(w,0,true);CHECK(production_poll_race(0,suspend)==0,"remove finishes after returned callback barrier opens");
 CHECK(native_callbacks(w,0,true)==before+1,"poll-returned frame callback executes exactly once before storage retirement");
 CHECK(count(w,STACK_EV_LEASE_RELEASE,0,-1)==0,"concurrent STOP does not falsely free TX ownership");safety(w);stack_destroy(w);
}
static void poll_return_stop_race(void){poll_return_race(true);}
static void poll_return_remove_race(void){poll_return_race(false);}
static void control_tx_tail_progress(void)
{
 struct stack_config c=geometry();struct stack_world *w=production_world(&c);startup(w);sessions(w,1,0);
 start(w,c.first_seq,0);for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(count(w,STACK_EV_PUBLISH,1,-1)==1,"real receiver completes native group before consumer release");
 CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==0,"final ACK has not been posted before actual consumer release");
 size_t begin=stack_log_count(w);production_poll_delay_control_ack();
 CHECK(stack_release(w,1,c.first_seq)==0,"consumer release creates actual CHAIN_END event");
 /* No time advance: the one-jiffy transport fallback is not due. The only
  * allowed callback path is a real queued session progress request. */
 pump(w,0);
 uint64_t ack=0;bool tail=false,dispatch=false;unsigned requests=0;
 for(size_t i=begin;i<stack_log_count(w);i++){
  struct stack_event e=ev(w,i);
  if(e.kind==STACK_EV_SCHED_STEP)CHECK(e.flags!=STACK_STEP_NHI_POLL,"control-tail regression forbids adapter polling");
  if(e.kind==STACK_EV_CONTROL_TX&&e.endpoint==1&&e.control_type==3)ack=e.owner;
  if(e.kind==1001&&e.endpoint==1&&e.control_type==3)fprintf(stderr,"ACK_TAIL_OBSERVE outstanding=%u slot_busy=%u reply_used_closed=%u queued=%u completed=%llu\n",e.control,e.length,e.pdf,e.flags,(unsigned long long)e.address);
  if(e.kind==1001&&e.endpoint==1&&e.control_type==3&&!e.length&&(!(e.pdf&1U)||(e.pdf&2U))){
   tail=true;requests++;
   fprintf(stderr,"CONTROL_TX_TAIL outstanding=%u completed=%llu slot_busy=%u reply_used_closed=%u queued=%u delay_ms=%d\n",
    e.control,(unsigned long long)e.address,e.length,e.pdf,e.flags,e.status);
   CHECK(e.flags,"slot cleared with terminal reply while real final-ACK control TX outstanding must request immediate queued progress");
  }
  if(e.kind==1000&&e.endpoint==1&&e.address&&e.flags==1)dispatch=true;
  if(e.kind==1000&&e.endpoint==1&&e.address&&e.flags==2)
   CHECK(false,"one-jiffy fallback must not mask missing final-ACK stage progress request");
 }
 CHECK(ack&&tail&&requests>=2,"real ACK remains outstanding across multiple progress passes after reply/slot clear");
 bool completed=false;for(size_t i=begin;i<stack_log_count(w);i++){
  struct stack_event e=ev(w,i);if(e.kind==STACK_EV_NHI_CALLBACK&&e.endpoint==1&&e.owner==ack&&!e.status)completed=true;
 }
 CHECK(completed&&dispatch,"actual final-ACK native completion dispatches through queued session progress before fallback");
 addresses(w,&c);safety(w);stack_destroy(w);
}
static void idle_control_rx_no_spin(void)
{
 struct stack_config c=geometry();struct stack_world *w=production_world(&c);startup(w);sessions(w,1,0);
 size_t begin=stack_log_count(w);pump(w,0);
 unsigned tails=0;
 for(size_t i=begin;i<stack_log_count(w);i++){
  struct stack_event e=ev(w,i);if(e.kind!=1001)continue;tails++;
  CHECK(!e.control&&!e.length&&!e.pdf,"idle stage has only preposted control RX and no actual TX/reply/slot commitment");
  CHECK(!e.flags,"idle preposted control RX must not request immediate repeated stage progress");
 }
 CHECK(tails>0&&tails<=2,"two idle bound stages execute at most one initial progress pass each");
 safety(w);stack_destroy(w);
}
static void diagnostic_progress_gap(void)
{
 /* Baseline-only dispatcher isolation: explicitly NOT a production-mode PASS.
  * Existing adapter establishes NO_IRQ and temporary startup dispatcher only. */
 struct stack_config c=geometry();c.nhi_poll=true;(void)production_poll_select(false);
 production_poll_external_enable(true);struct stack_world *w=create(&c);login(w);sessions(w,1,0);
 production_poll_external_enable(false);size_t completed=count(w,STACK_EV_NHI_COMPLETE,-1,-1);
 start(w,c.first_seq,0);pump(w,1000000);
 CHECK(count(w,STACK_EV_NHI_COMPLETE,-1,-1)>completed&&production_poll_pending()>0,
       "diagnostic reaches new actual descriptor COMPLETED and native pending without external dispatcher");
 size_t before=native_callbacks(w,0,false)+native_callbacks(w,1,false);
 production_poll_once(0);production_poll_once(1);
 fprintf(stderr,"PRODUCTION_POLL_GAP completed_before=%zu completed_after=%zu rings_pending=%u callbacks_before=%zu callbacks_after=%zu\n",
  completed,count(w,STACK_EV_NHI_COMPLETE,-1,-1),production_poll_pending(),before,
  native_callbacks(w,0,false)+native_callbacks(w,1,false));
 CHECK(native_callbacks(w,0,false)+native_callbacks(w,1,false)>before,
       "actual gap: session progress must dispatch already-completed native frames without external adapter poll");
 stack_destroy(w);
}
static const struct named poll_cases[]={
 {"legacy-irq",legacy_irq},{"mode-selection",mode_selection},{"startup-before-create",startup_before_create},
 {"four-ring-progress",four_ring_progress},{"budget-64-65",budget_64_65},{"pending-256",pending_256},
 {"worker-gone",worker_gone},{"stop-remove-unknown",stop_remove_unknown},{"partial-allocation",partial_allocation},
 {"control-tx-tail-progress",control_tx_tail_progress},{"idle-control-rx-no-spin",idle_control_rx_no_spin},
 {"poll-return-stop-race",poll_return_stop_race},{"poll-return-remove-race",poll_return_remove_race},{"diagnostic-progress-gap",diagnostic_progress_gap},
};
int main(int argc,char **argv)
{
 if(argc!=3)return 2;case_name=argv[1];budget=(unsigned)strtoul(argv[2],NULL,10);
 for(size_t i=0;i<sizeof(poll_cases)/sizeof(poll_cases[0]);i++)if(!strcmp(case_name,poll_cases[i].name)){
  poll_cases[i].run();printf("PRODUCTION_POLL_ASSERTIONS %s %u\n",case_name,assertions);return 0;}return 2;
}

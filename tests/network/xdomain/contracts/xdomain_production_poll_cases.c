/* SPDX-License-Identifier: GPL-2.0 */
/* Requirement-driven production-mode completion tests. No test dispatcher. */
#define main original_stack_main
#include "stack_cases.c"
#undef main
int production_poll_select(bool);
void production_poll_external_enable(bool);
void production_poll_once(unsigned);
unsigned production_poll_work_queued(unsigned);
unsigned production_poll_rings(unsigned,unsigned *,unsigned *);
unsigned production_poll_complete_tx(unsigned,unsigned);
unsigned production_poll_pending(void);
void production_poll_counts(unsigned,unsigned *,unsigned *);
void production_poll_worker_gone(unsigned);
int production_poll_race(unsigned,bool);
void production_poll_fail_allocation(unsigned);
void production_poll_delay_control_ack(void);
int production_poll_select_irq(bool);
unsigned production_poll_complete_rx(unsigned,unsigned);
unsigned production_poll_deliver_control(unsigned);
int production_poll_rx_irq(unsigned,bool);
bool production_poll_rx_pending(unsigned,bool);
unsigned production_poll_rx_dropped(unsigned,bool);
unsigned production_poll_ring_modes(unsigned,unsigned *,unsigned *,unsigned *);
void production_poll_irq_latching(bool);
unsigned production_poll_nhi_warns(void);
void production_poll_inject_before_unmask(unsigned);
unsigned production_poll_injected(void);
void production_poll_irq_at_stop(unsigned);
unsigned production_poll_late_injected(void);
int production_poll_lock_order(unsigned);
void production_poll_irq_before_gate(unsigned);
unsigned production_poll_prestart_injected(void);
static void no_link_activity(struct stack_world *,size_t,unsigned);
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
/* Interrupt-started polling (poll_on_interrupt). Private ledger kinds:
 * 1000 X4 native poll return, 1002 production start_poll entered from the real
 * __ring_interrupt (owner=ring), 1003 X4 re-enable just before the real
 * tb_ring_poll_complete (flags=interrupt already enabled, length=completion
 * waiting), 1004 X4/X5 mod_delayed_work on a link poll work (length=jiffies),
 * 1005/1006 test device actions in the lost-wakeup and teardown windows. */
static struct stack_world *irq_world(struct stack_config *c)
{
 CHECK(!c->nhi_poll&&!c->nhi_batch,"interrupt-started mode forbids adapter flag and notify injection");
 CHECK(production_poll_select(false)==0,"pure polling stays at its default");
 CHECK(production_poll_select_irq(true)==0,"irq-mode missing feature: real readonly default-false poll_on_interrupt bool must exist");
 production_poll_external_enable(false);return create(c);
}
static void irq_startup(struct stack_world *w)
{
 CHECK(stack_probe(w,0)==0&&stack_probe(w,1)==0,"real probes allocate interrupt-started rings before CREATE");
 for(unsigned i=0;i<100;i++)pump(w,1000000);
 CHECK(count(w,STACK_EV_STARTUP_CONTROL_RX,-1,-1)>0&&count(w,STACK_EV_STARTUP_CALLBACK,-1,-1)>0,
       "startup challenge completes through interrupt-started drains before CREATE");
 for(unsigned endpoint=0;endpoint<2;endpoint++){
  unsigned txirq,rxpoll,noirq,rings=production_poll_ring_modes(endpoint,&txirq,&rxpoll,&noirq);
  CHECK(rings==4&&txirq==2&&rxpoll==2&&!noirq,"TX rings keep IRQ ring_work, RX rings have start_poll, none NO_INTERRUPT");
 }
}
static void no_delayed_poll(struct stack_world *w,size_t begin)
{
 for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.kind==1004)CHECK(!e.length,"interrupt-started mode never arms a delayed link poll");
  if(e.kind==1000)CHECK(e.direction==2,"interrupt-started drains never poll a transmit ring");}
}
static uint64_t first_irq_ring(struct stack_world *w,size_t begin,unsigned endpoint,bool control)
{
 for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.kind==1002&&e.endpoint==endpoint&&!!e.control==control)return e.owner;}
 return 0;
}
/* One RX ring: start_poll masks and re-enables alternate, each re-enable
 * follows an empty poll of that ring, and no mask is left open. */
static unsigned irq_episodes(struct stack_world *w,size_t begin,uint64_t ring,bool allow_waiting)
{
 bool masked=false,empty=false;unsigned episodes=0;
 for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.owner!=ring)continue;
  if(e.kind==1002){CHECK(!masked,"a masked ring interrupt cannot start polling twice");masked=true;empty=false;}
  if(e.kind==1000&&masked&&!e.address)empty=true;
  if(e.kind==1003){
   CHECK(masked,"tb_ring_poll_complete re-enables only an interrupt start_poll masked");
   CHECK(!e.flags,"the re-enabled interrupt was disabled until then");
   CHECK(empty,"the drain polls the ring empty before re-enabling its interrupt");
   if(!allow_waiting)CHECK(!e.length,"no completion waits at the re-enable");
   masked=false;episodes++;
  }
 }
 CHECK(!masked,"every interrupt start_poll masked is re-enabled exactly once");
 return episodes;
}
static void irq_mode_selection(void)
{
 struct stack_config c=geometry();struct stack_world *w=irq_world(&c);irq_startup(w);
 CHECK(count(w,STACK_EV_NHI_IRQ_ALLOC,-1,-1)>=8,"every ring of both endpoints has a real IRQ");
 sessions(w,1,0);for(unsigned i=0;i<10;i++)pump(w,1000000);
 size_t begin=stack_log_count(w);production_poll_once(0);production_poll_once(1);
 for(size_t i=begin;i<stack_log_count(w);i++)CHECK(ev(w,i).kind!=1000,"session progress itself never polls native rings in this mode");
 safety(w);stack_destroy(w);
 CHECK(production_poll_select(true)==0,"select pure polling as well");
 struct stack_world *both=NULL;
 CHECK(stack_new(&c,&both)==-EINVAL&&!both,"module init refuses both completion modes at once");
 CHECK(production_poll_select(false)==0&&production_poll_select_irq(false)==0,"restore default modes");
}
static void irq_no_timer_group(void)
{
 struct stack_config c=geometry();struct stack_world *w=irq_world(&c);irq_startup(w);sessions(w,1,0);
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(stack_start(w,1,c.first_seq,0)==0,"receiver arms actual RX slots, which make no commitment");
 pump(w,0);
 size_t begin=stack_log_count(w);
 CHECK(stack_start(w,0,c.first_seq,0)==0,"sender starts the actual group");
 for(unsigned i=0;i<10;i++)pump(w,0);
 uint64_t t0=ev(w,begin).now_ns;bool ctl_irq=false,rts=false,data=false;
 for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  CHECK(e.now_ns==t0,"no simulated time passes in this window");
  if(e.kind==1002&&e.endpoint==1&&e.control)ctl_irq=true;
  if(e.kind==STACK_EV_CONTROL_RX&&e.endpoint==1&&e.control_type==1){CHECK(ctl_irq,"RTS discovery follows the receiver control RX interrupt");rts=true;}
  if(e.kind==STACK_EV_NHI_CALLBACK&&e.endpoint==1&&!e.control&&!e.status){CHECK(e.flags==2,"armed data RX completes through the interrupt-started drain");data=true;}
  if(e.kind==STACK_EV_NHI_CALLBACK&&e.direction==1&&!e.status)CHECK(e.flags==1,"TX completion stays on real ring_work");
 }
 CHECK(rts&&data,"control RX and armed data RX are discovered without a timer");
 CHECK(count(w,STACK_EV_PUBLISH,1,-1)==1,"receiver publishes the group with no simulated time");
 no_delayed_poll(w,begin);
 CHECK(stack_release(w,1,c.first_seq)==0,"actual receiver consumer release");
 for(unsigned i=0;i<10;i++)pump(w,0);
 CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==1,"one final ACK after consumer release");
 CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1,"sender publishes after the ACK with no simulated time");
 no_delayed_poll(w,begin);
 addresses(w,&c);safety(w);stack_destroy(w);
}
static struct stack_world *irq_held_group(struct stack_config *c)
{
 struct stack_world *w=irq_world(c);irq_startup(w);sessions(w,1,0);
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 fault(w,STACK_FAULT_HOLD_CALLBACK,1,0,0,1,0);
 start(w,c->first_seq,0);for(unsigned i=0;i<10;i++)pump(w,0);
 CHECK(native_callbacks(w,1,true)==0,"held receiver data RX descriptors have not completed");
 return w;
}
static void finish_held_group(struct stack_world *w,struct stack_config *c)
{
 fault(w,STACK_FAULT_RELEASE_CALLBACKS,1,0,0,0,0);for(unsigned i=0;i<10;i++)pump(w,0);
 CHECK(count(w,STACK_EV_PUBLISH,1,-1)==1,"receiver publishes the group");
 release_group(w,c->first_seq);
 CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==1,"one final ACK after consumer release");
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1,"sender publishes after the ACK");
 addresses(w,c);safety(w);stack_destroy(w);
}
static void poll_callbacks_only(struct stack_world *w,size_t begin,unsigned endpoint)
{
 for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.kind==STACK_EV_NHI_CALLBACK&&e.endpoint==endpoint&&!e.control&&!e.status)
   CHECK(e.flags==2,"data RX callback runs from the interrupt-started drain");}
}
static void irq_drain_rearm_once(void)
{
 struct stack_config c=geometry();struct stack_world *w=irq_held_group(&c);
 size_t begin=stack_log_count(w);
 CHECK(production_poll_complete_rx(1,4)==4,"hardware completes the four delivered data RX descriptors");
 CHECK(production_poll_rx_irq(1,false)==0,"the first completion's interrupt masked the data RX interrupt");
 pump(w,0);
 uint64_t ring=first_irq_ring(w,begin,1,false);
 CHECK(ring,"the data RX interrupt entered production start_poll");
 CHECK(irq_episodes(w,begin,ring,false)>=1,"at least one complete drain episode");
 CHECK(native_callbacks(w,1,true)==4,"each completed data RX frame returns exactly once");
 poll_callbacks_only(w,begin,1);
 CHECK(production_poll_rx_irq(1,false)==1,"the data RX interrupt ends enabled");
 no_delayed_poll(w,begin);
 finish_held_group(w,&c);
}
/* One legal group has64 native elements:32 registered frames, two4096-byte
 * chunks each. A group cannot have65 elements, and RX_POST forbids another
 * native group until this one is locally complete. The65-completion stimulus
 * therefore adds a real next-group RTS on the other (control) RX ring. */
static struct stack_config irq_budget_geometry(void)
{
 struct stack_config c=geometry();c.nr_frames=32;c.native_elems=64;
 for(unsigned i=0;i<32;i++)c.span[i]=(struct stack_span){65536ULL*(i+1),4096,8192};
 return c;
}
static struct stack_world *irq_budget_backlog(struct stack_config *c,bool control)
{
 struct stack_world *w=irq_world(c);irq_startup(w);sessions(w,control?2:1,0);
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 fault(w,STACK_FAULT_HOLD_CALLBACK,1,0,0,1,0);
 start(w,c->first_seq,0);for(unsigned i=0;i<10;i++)pump(w,0);
 if(control){
  fault(w,STACK_FAULT_HOLD_CONTROL,0,1,0,0,0);
  /* No second receiver ARM: only an announcement, not a second RX post. */
  CHECK(stack_start(w,0,c->first_seq+1,0)==0,"sender legally announces the next group within real credit");
  for(unsigned i=0;i<10;i++)pump(w,0);
 }
 CHECK(count(w,STACK_EV_DATA_POST,0,-1)==64&&count(w,STACK_EV_DATA_POST,1,-1)==64,
       "one legal real RTS/CTS group posts exactly64 data elements on both endpoints");
 CHECK(count(w,STACK_EV_CONTROL_TX,0,1)==(control?2U:1U)&&count(w,STACK_EV_CONTROL_RX,1,1)==1,
       "only the optional next-group RTS is held before control RX delivery");
 CHECK(native_callbacks(w,1,true)==0&&!production_poll_rx_pending(1,false),
       "held RX descriptors have neither completed nor returned callbacks");
 CHECK(!production_poll_work_queued(1),"no old receiver drain precedes the budget stimulus");
 return w;
}
struct irq_budget_window {
 size_t begin;
 unsigned completed;
 uint64_t owner[65];
 bool control[65],returned[65];
};
static struct irq_budget_window irq_budget_first_pass(struct stack_world *w,unsigned completed)
{
 struct irq_budget_window window={.begin=stack_log_count(w),.completed=completed};
 CHECK(production_poll_complete_rx(1,64)==64,"hardware completes the legal group's64 delivered data RX descriptors");
 if(completed==65)CHECK(production_poll_deliver_control(0)==1,"hardware delivers the real next-group RTS into control RX");
 unsigned data=0,control=0,n=0;
 for(size_t i=window.begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.kind!=STACK_EV_NHI_COMPLETE||e.endpoint!=1)continue;
  CHECK(e.direction==2&&e.control<=1&&n<completed,"budget stimulus consists only of actual data/control RX completions");
  for(unsigned j=0;j<n;j++)CHECK(window.owner[j]!=e.owner,"each marked descriptor has a distinct native owner");
  window.owner[n]=e.owner;window.control[n++]=!!e.control;
  if(e.control)control++;else data++;
 }
 CHECK(data==64&&control==completed-64&&n==completed,"stimulus is64 data plus zero or one real control RX completion");
 CHECK(first_irq_ring(w,window.begin,1,false)&&production_poll_rx_irq(1,false)==0,
       "the actual first completion interrupts and masks data RX");
 if(completed==65)CHECK(first_irq_ring(w,window.begin,1,true)&&production_poll_rx_irq(1,true)==0,
                       "the real control completion interrupts and masks control RX");
 CHECK(production_poll_work_queued(1)==1,"actual start_poll queues exactly one receiver drain");
 CHECK(stack_pump(w,1,0)==-ELOOP,"one real work invocation leaves immediately eligible work");
 unsigned returned=0;
 for(size_t i=window.begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.kind!=1000||e.endpoint!=1||!e.address)continue;
  unsigned j=0;while(j<completed&&window.owner[j]!=e.address)j++;
  CHECK(j<completed&&!window.returned[j],"each successful native pull returns a unique marked owner");
  window.returned[j]=true;returned++;
 }
 CHECK(returned==64,"one IRQ worker invocation dispatches exactly64 total RX completions");
 CHECK((unsigned)production_poll_rx_pending(1,false)+(unsigned)production_poll_rx_pending(1,true)==completed-64,
       "only the65-total-completion stimulus leaves one completed RX tail across both rings");
 CHECK(production_poll_rx_irq(1,false)==0,"full IRQ budget keeps the RX interrupt masked");
 if(completed==65)CHECK(production_poll_rx_irq(1,true)==0,"full IRQ budget also keeps control RX masked");
 CHECK(production_poll_work_queued(1)==1,"full IRQ budget immediately requeues exactly one drain");
 unsigned requeues=0;
 for(size_t i=window.begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.endpoint==1&&e.kind==1003)CHECK(false,"full-budget pass never rearms an RX interrupt");
  if(e.endpoint==1&&e.kind==1004&&e.flags==2){CHECK(!e.length,"budget continuation has zero delay");requeues++;}
 }
 CHECK(requeues==1,"the full-budget worker itself queues one immediate continuation");
 no_delayed_poll(w,window.begin);poll_callbacks_only(w,window.begin,1);
 return window;
}
/* First callback after this descriptor completion determines its fate. A
 * successful control callback may repost the same frame: its later STOP
 * cancellation belongs to that new post, not to this completed ownership. */
static void irq_budget_fates(struct stack_world *w,const struct irq_budget_window *window,bool stopped)
{
 unsigned successes=0,canceled=0;
 for(unsigned j=0;j<window->completed;j++){
  bool found=false;
  for(size_t i=window->begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
   if(e.kind!=STACK_EV_NHI_CALLBACK||e.endpoint!=1||e.owner!=window->owner[j])continue;
   bool cancel=stopped&&!window->returned[j];
   CHECK(e.direction==2&&!!e.control==window->control[j],"callback retains its marked RX owner and ring type");
   CHECK(e.status==(cancel?-ECANCELED:0),"returned owners succeed and only unreturned marked owners cancel at STOP");
   CHECK(e.flags==(cancel?1U:2U),"marked owner callback comes from actual native ring_work or IRQ polling");
   if(cancel)canceled++;else successes++;
   found=true;break;
  }
  CHECK(found,"every marked completed owner reaches its actual native callback");
 }
 CHECK(successes==(stopped?64U:window->completed)&&canceled==(stopped?window->completed-64:0U),
       "public64 budget leaves zero or one marked owner for native STOP cancellation");
}
static void irq_budget_64_65(void)
{
 for(unsigned completed=64;completed<=65;completed++){
  struct stack_config c=irq_budget_geometry();struct stack_world *w=irq_budget_backlog(&c,completed==65);
  struct irq_budget_window window=irq_budget_first_pass(w,completed);size_t begin=window.begin;
  uint64_t now=ev(w,begin).now_ns;
  pump(w,0);
  irq_budget_fates(w,&window,false);
  CHECK(native_callbacks(w,1,true)==64,"same-time continuation completes exactly the single64-element data group");
  CHECK(!production_poll_rx_pending(1,false)&&!production_poll_rx_pending(1,true)&&
        production_poll_rx_irq(1,false)==1&&production_poll_rx_irq(1,true)==1,
        "continuation observes both RX rings empty then rearms even at exact64 total");
  CHECK(!production_poll_work_queued(1),"empty continuation leaves no recurring IRQ poll work");
  uint64_t pass=0;unsigned pulls=0,passes=0;
  for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
   CHECK(e.now_ns==now,"budget drain and rearm require no timer advance");
   if(e.kind!=1000||e.endpoint!=1||!e.address)continue;
   CHECK(e.flags==2,"budget completions come from actual queued work, never session progress");
   if(e.seq!=pass){CHECK(pulls<=64,"each real IRQ work pass respects the64-frame budget");pass=e.seq;pulls=0;passes++;}
   pulls++;CHECK(pulls<=64,"each real IRQ work pass respects the64-frame budget");
  }
  CHECK(passes==(completed==65?2U:1U),"the65th successful native pull belongs to a second work pass");
  CHECK(irq_episodes(w,begin,first_irq_ring(w,begin,1,false),false)>=1,
        "budget continuation pairs every mask with an empty-poll rearm");
  if(completed==65)CHECK(irq_episodes(w,begin,first_irq_ring(w,begin,1,true),false)>=1,
                        "control RX mask is also paired with its empty-poll rearm");
  no_delayed_poll(w,begin);poll_callbacks_only(w,begin,1);
  CHECK(count(w,STACK_EV_DATA_POST,1,-1)==64&&count(w,STACK_EV_PUBLISH,1,-1)==1,
        "the next RTS cannot native-post another RX group without a receiver ARM");
  release_group(w,c.first_seq);
  fault(w,STACK_FAULT_RELEASE_CALLBACKS,1,0,0,0,0);
  if(completed==65){
   CHECK(stack_start(w,1,c.first_seq+1,0)==0,"arm the announced second RX only after first consumer release");
   fault(w,STACK_FAULT_RELEASE_CONTROLS,0,0,0,0,0);
   for(unsigned i=0;i<10;i++)pump(w,1000000);
   release_group(w,c.first_seq+1);
  }
  unsigned groups=completed==65?2U:1U;
  CHECK(native_callbacks(w,0,true)==64*groups&&native_callbacks(w,1,true)==64*groups&&
        count(w,STACK_EV_PUBLISH,0,-1)==groups&&count(w,STACK_EV_PUBLISH,1,-1)==groups,
        "actual consumer releases and ACKs finish every legally posted group and native owner");
  addresses(w,&c);safety(w);stack_destroy(w);
 }
}
static void irq_budget_stop(void)
{
 for(unsigned completed=64;completed<=65;completed++){
  struct stack_config c=irq_budget_geometry();struct stack_world *w=irq_budget_backlog(&c,completed==65);
  struct irq_budget_window window=irq_budget_first_pass(w,completed);
  unsigned warns=production_poll_nhi_warns();
  CHECK(stack_suspend(w,1)==0,"suspend executes real rings_stop with a full-budget continuation queued");
  /* The link survives suspend. Check before pumping: a broken cancel must
   * fail by this assertion, not by executing stale work after ring retirement. */
  CHECK(!production_poll_work_queued(1),"STOP removes the budget continuation from the actual work queue");
  irq_budget_fates(w,&window,true);
  unsigned data_tail=0;
  for(unsigned j=0;j<window.completed;j++)data_tail+=!window.returned[j]&&!window.control[j];
  struct stack_stage_facts facts=stage_facts(w,1,0);
  CHECK(facts.slot_local_known&&facts.slot_local_quiesced==!data_tail,
        "data custody follows whether any actual unreturned data owner canceled, independent of ring order");
  size_t stopped=stack_log_count(w);
  if(completed==65)fault(w,STACK_FAULT_RELEASE_CONTROLS,0,0,0,0,0);
  for(unsigned i=0;i<10;i++)pump(w,1000000);
  no_link_activity(w,stopped,1);
  CHECK(production_poll_nhi_warns()==warns,"full-budget masked RX STOP raises no NHI warning");
  if(data_tail)CHECK(count(w,STACK_EV_LEASE_RELEASE,1,-1)==0,"canceled data RX custody cannot falsely release payload leases");
  addresses(w,&c);safety(w);stack_destroy(w);
 }
}
static void irq_lost_wakeup(bool latching)
{
 struct stack_config c=geometry();struct stack_world *w=irq_held_group(&c);
 production_poll_irq_latching(latching);
 size_t begin=stack_log_count(w);unsigned dropped=production_poll_rx_dropped(1,false);
 CHECK(production_poll_complete_rx(1,1)==1,"one held data RX descriptor completes and interrupts");
 production_poll_inject_before_unmask(1);
 pump(w,0);
 CHECK(production_poll_injected()==1,"a completion lands after the final empty poll, before the re-enable");
 CHECK(native_callbacks(w,1,true)==2,"the completion in the lost-wakeup window is delivered without a timer");
 poll_callbacks_only(w,begin,1);
 uint64_t ring=first_irq_ring(w,begin,1,false);
 CHECK(ring&&irq_episodes(w,begin,ring,true)>=1,"masks and re-enables stay paired around the window");
 CHECK(production_poll_rx_irq(1,false)==1,"the data RX interrupt ends enabled");
 if(!latching)CHECK(production_poll_rx_dropped(1,false)==dropped+1,"a non-latching controller dropped the window completion's interrupt");
 no_delayed_poll(w,begin);
 production_poll_irq_latching(true);
 finish_held_group(w,&c);
}
static void irq_lost_wakeup_latching(void){irq_lost_wakeup(true);}
static void irq_lost_wakeup_nonlatching(void){irq_lost_wakeup(false);}
static void pure_rts_waits_fallback(void)
{
 struct stack_config c=geometry();struct stack_world *w=production_world(&c);startup(w);sessions(w,1,0);
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(stack_start(w,1,c.first_seq,0)==0,"receiver arms actual RX slots, which make no commitment");
 pump(w,0);
 CHECK(stack_start(w,0,c.first_seq,0)==0,"sender starts the actual group");
 for(unsigned i=0;i<10;i++)pump(w,0);
 CHECK(count(w,STACK_EV_CONTROL_RX,1,1)==0,"pure polling: the receiver does not see the RTS while no time passes");
 CHECK(production_poll_rx_pending(1,true),"the RTS is complete in the receiver control RX ring");
 pump(w,1000000);
 CHECK(count(w,STACK_EV_CONTROL_RX,1,1)==1,"the one-jiffy link fallback discovers the RTS");
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 release_group(w,c.first_seq);for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1&&count(w,STACK_EV_PUBLISH,1,-1)==1,"pure mode still completes the group");
 addresses(w,&c);assert_sources(w);safety(w);stack_destroy(w);
}
static struct stack_world *irq_held_rts(struct stack_config *c)
{
 struct stack_world *w=irq_world(c);irq_startup(w);sessions(w,1,0);
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 fault(w,STACK_FAULT_HOLD_CONTROL,0,1,0,0,0);
 start(w,c->first_seq,0);for(unsigned i=0;i<10;i++)pump(w,0);
 CHECK(count(w,STACK_EV_CONTROL_RX,1,1)==0,"the held RTS has not reached the receiver");
 return w;
}
static void no_link_activity(struct stack_world *w,size_t begin,unsigned endpoint)
{
 for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.endpoint!=endpoint)continue;
  CHECK(e.kind!=1000&&e.kind!=1002&&e.kind!=1004,"no drain, start_poll or poll work after the link stopped");
  if(e.kind==STACK_EV_NHI_CALLBACK)CHECK(e.flags!=2,"no poll-returned callback after the link stopped");
 }
}
static void irq_stop_pending_drain(void)
{
 for(unsigned mode=0;mode<2;mode++){
  struct stack_config c=geometry();struct stack_world *w=irq_held_rts(&c);
  size_t begin=stack_log_count(w);unsigned warns=production_poll_nhi_warns();
  CHECK(production_poll_deliver_control(0)==1,"hardware delivers the RTS into the receiver control RX");
  bool queued=false;
  for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==1004&&e.endpoint==1)queued=true;}
  CHECK(queued,"the receiver control RX interrupt queued its drain");
  CHECK(count(w,STACK_EV_CONTROL_RX,1,1)==0&&production_poll_rx_irq(1,true)==0,"drain pending, interrupt masked");
  if(!mode){
   size_t dispatches=count(w,STACK_EV_DISPATCH,1,-1);
   production_poll_worker_gone(1);
   pump(w,0);
   CHECK(count(w,STACK_EV_CONTROL_RX,1,1)==1,"the pending drain still collects the RTS after unbind");
   CHECK(count(w,STACK_EV_DISPATCH,1,-1)==dispatches,"no dispatch reaches the unbound and freed receiver endpoint");
  }
  size_t removed=stack_log_count(w);
  CHECK(stack_remove(w,1)==0,"remove the receiver link with its drain state");
  for(unsigned i=0;i<10;i++)pump(w,1000000);
  no_link_activity(w,removed,1);
  CHECK(production_poll_nhi_warns()==warns,"stopping a ring start_poll left masked raises no NHI WARN");
  fault(w,STACK_FAULT_RELEASE_CONTROLS,0,0,0,0,0);for(unsigned i=0;i<10;i++)pump(w,1000000);
  safety(w);stack_destroy(w);
 }
}
static void irq_stop_late_interrupt(void)
{
 for(unsigned mode=0;mode<2;mode++){
  struct stack_config c=geometry();struct stack_world *w=irq_held_rts(&c);
  size_t begin=stack_log_count(w);unsigned warns=production_poll_nhi_warns();
  production_poll_irq_at_stop(1);
  CHECK((mode?stack_suspend(w,1):stack_remove(w,1))==0,"teardown with a late receiver interrupt");
  for(unsigned i=0;i<10;i++)pump(w,1000000);
  CHECK(production_poll_late_injected()==1,"the RTS completes into the running control RX after the poll gate closed");
  bool late=false,masked=false;size_t after=begin;
  for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
   if(e.kind==1006&&e.endpoint==1){late=true;continue;}
   if(!late||e.endpoint!=1)continue;
   if(e.kind==1002&&e.control&&!masked){masked=true;after=i+1;continue;}
   CHECK(e.kind!=1004&&e.kind!=1000,"a late interrupt queues no drain and polls nothing after the poll gate closed");
  }
  CHECK(late&&masked,"the late interrupt reached production start_poll");
  no_link_activity(w,after,1);
  CHECK(production_poll_nhi_warns()==warns,"stopping the ring start_poll just masked raises no NHI WARN");
  fault(w,STACK_FAULT_RELEASE_CONTROLS,0,0,0,0,0);for(unsigned i=0;i<10;i++)pump(w,1000000);
  safety(w);stack_destroy(w);
 }
}
static void irq_interrupt_before_gate(void)
{
 struct stack_config c=geometry();struct stack_world *w=irq_world(&c);irq_startup(w);sessions(w,1,0);
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(stack_suspend(w,1)==0,"receiver link suspends and stops its rings");
 for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(stack_start(w,0,c.first_seq,0)==0,"sender announces while the receiver rings are stopped");
 for(unsigned i=0;i<10;i++)pump(w,0);
 size_t begin=stack_log_count(w);
 production_poll_irq_before_gate(1);
 CHECK(stack_resume(w,1)==0,"receiver link resumes and starts its rings again");
 for(unsigned i=0;i<100;i++)pump(w,1000000);
 CHECK(production_poll_prestart_injected()==1,"a peer control message completes into the receiver control RX before its interrupt gate opens");
 uint64_t ring=0;bool marked=false,queued=false,enabled=false;
 for(size_t i=begin;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);
  if(e.kind==1007&&e.endpoint==1)ring=e.owner;
  if(!ring||e.endpoint!=1)continue;
  if(e.kind==1002&&e.owner==ring&&!marked){marked=true;continue;}
  if(marked&&!queued&&e.kind==1004){CHECK(!e.length,"the gate opening queues the drain without delay");queued=true;}
  if(queued&&e.kind==1003&&e.owner==ring)enabled=true;
 }
 CHECK(marked&&queued&&enabled,"an interrupt before the gate is drained and re-enabled once the gate opens");
 CHECK(production_poll_rx_irq(1,true)==1,"the receiver control RX interrupt ends enabled");
 safety(w);stack_destroy(w);
}
static void irq_start_poll_lock_order(void)
{
 struct stack_config c=geometry();struct stack_world *w=irq_held_rts(&c);
 size_t begin=stack_log_count(w);
 CHECK(production_poll_lock_order(1)==0,"start_poll returns while another context holds xl->lock");
 CHECK(first_irq_ring(w,begin,1,true),"the control RX interrupt entered production start_poll");
 for(unsigned i=0;i<10;i++)pump(w,0);
 CHECK(count(w,STACK_EV_CONTROL_RX,1,1)==1,"the queued drain collects the RTS once the lock is free");
 no_delayed_poll(w,begin);
 fault(w,STACK_FAULT_RELEASE_CONTROLS,0,0,0,0,0);for(unsigned i=0;i<10;i++)pump(w,0);
 CHECK(count(w,STACK_EV_PUBLISH,1,-1)==1,"receiver publishes the group");
 release_group(w,c.first_seq);for(unsigned i=0;i<10;i++)pump(w,1000000);
 CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1,"sender publishes after the ACK");
 addresses(w,&c);safety(w);stack_destroy(w);
}
static const struct named poll_cases[]={
 {"legacy-irq",legacy_irq},{"mode-selection",mode_selection},{"startup-before-create",startup_before_create},
 {"four-ring-progress",four_ring_progress},{"budget-64-65",budget_64_65},{"pending-256",pending_256},
 {"worker-gone",worker_gone},{"stop-remove-unknown",stop_remove_unknown},{"partial-allocation",partial_allocation},
 {"control-tx-tail-progress",control_tx_tail_progress},{"idle-control-rx-no-spin",idle_control_rx_no_spin},
 {"poll-return-stop-race",poll_return_stop_race},{"poll-return-remove-race",poll_return_remove_race},{"diagnostic-progress-gap",diagnostic_progress_gap},
 {"irq-mode-selection",irq_mode_selection},{"irq-no-timer-group",irq_no_timer_group},
 {"irq-drain-rearm-once",irq_drain_rearm_once},{"irq-lost-wakeup-latching",irq_lost_wakeup_latching},
 {"irq-budget-64-65",irq_budget_64_65},{"irq-budget-stop",irq_budget_stop},
 {"irq-lost-wakeup-nonlatching",irq_lost_wakeup_nonlatching},{"pure-rts-waits-fallback",pure_rts_waits_fallback},
 {"irq-stop-pending-drain",irq_stop_pending_drain},{"irq-stop-late-interrupt",irq_stop_late_interrupt},
 {"irq-start-poll-lock-order",irq_start_poll_lock_order},{"irq-interrupt-before-gate",irq_interrupt_before_gate},
};
int main(int argc,char **argv)
{
 if(argc!=3)return 2;case_name=argv[1];budget=(unsigned)strtoul(argv[2],NULL,10);
 for(size_t i=0;i<sizeof(poll_cases)/sizeof(poll_cases[0]);i++)if(!strcmp(case_name,poll_cases[i].name)){
  poll_cases[i].run();printf("PRODUCTION_POLL_ASSERTIONS %s %u\n",case_name,assertions);return 0;}return 2;
}

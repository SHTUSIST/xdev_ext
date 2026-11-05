/* SPDX-License-Identifier: GPL-2.0 */
/* Test-only OS/device observations around the unchanged composition. */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>
static bool production_poll_external;
static bool production_poll_after_progress;
static bool production_poll_delay_ack;
static unsigned production_poll_ack_tails;
void production_poll_delay_control_ack(void){production_poll_delay_ack=true;production_poll_ack_tails=0;}
static uint64_t production_poll_device_serial;
void production_poll_tail(unsigned,struct xdev_ext_mech_session *,u64);
static _Thread_local unsigned production_poll_context;
static _Thread_local uint64_t production_poll_pass;
#define stack_ring_alloc_tx shared_poll_alloc_tx
#define stack_ring_alloc_rx shared_poll_alloc_rx
#define stack_ring_stop shared_poll_ring_stop
#define stack_ring_rx shared_poll_ring_rx
#include "stack_boundary.c"
#undef stack_ring_alloc_tx
#undef stack_ring_alloc_rx
#undef stack_ring_stop
#undef stack_ring_rx
static unsigned allocation_fail,allocation_seen;
void production_poll_fail_allocation(unsigned ordinal){allocation_fail=ordinal;allocation_seen=0;}
static void production_poll_allocation(struct tb_nhi *nhi)
{if(endpoint_pci(nhi->pdev)==0&&++allocation_seen==allocation_fail)world->ring_refuse[0]=true;}
struct tb_ring *stack_ring_alloc_tx(struct tb_nhi *nhi,int hop,int size,unsigned flags)
{production_poll_allocation(nhi);return shared_poll_alloc_tx(nhi,hop,size,flags);}
/* Observation of the production start_poll callback. The real NHI calls this
 * trampoline from __ring_interrupt() after masking the ring interrupt; it
 * forwards to the production callback with the production argument. */
struct production_irq_record{void(*poll)(void *);void *arg;struct tb_ring *ring;unsigned endpoint;};
static struct production_irq_record irq_records[64];
static unsigned irq_record_count;
static _Thread_local bool production_poll_in_interrupt;
/* X4 is about to call tb_ring_poll(): never from the interrupt itself. */
void production_poll_before_poll(struct tb_ring *ring)
{
 (void)ring;
 if(production_poll_in_interrupt){
  fprintf(stderr,"STACK_ASSERT start_poll: native poll runs inside the ring interrupt\n");exit(1);}
}
static void production_poll_start_trampoline(void *data)
{
 struct production_irq_record *r=data;
 unsigned spins=stack_spins,mutexes=stack_mutexes;
 size_t before=world->logs;
 /* Real __ring_interrupt context: NHI and ring spinlocks, interrupt masked. */
 assert(r->ring&&spins>=2&&!stack_nhi_irq_enabled(r->ring));
 stack_record((struct stack_event){.kind=1002,.endpoint=r->endpoint,.owner=(uintptr_t)r->ring,
  .control=ring_info(r->ring)->control,.direction=2,.seq=world->pump_serial,.flags=production_poll_context});
 production_poll_in_interrupt=true;
 r->poll(r->arg);
 production_poll_in_interrupt=false;
 if(stack_spins!=spins||stack_mutexes!=mutexes){
  fprintf(stderr,"STACK_ASSERT start_poll: interrupt-context callback changed the held lock set\n");exit(1);}
 for(size_t i=before;i<world->logs;i++)
  if(world->log[i].kind==STACK_EV_NHI_CALLBACK||world->log[i].kind==STACK_EV_PROTOCOL||
     world->log[i].kind==STACK_EV_DISPATCH){
   fprintf(stderr,"STACK_ASSERT start_poll: frame callback, dispatch or BPF ran in interrupt context\n");exit(1);}
}
struct tb_ring *stack_ring_alloc_rx(struct tb_nhi *nhi,int hop,int size,unsigned flags,int tx,u16 sof,u16 eof,void(*poll)(void *),void *arg)
{
 production_poll_allocation(nhi);
 if(!poll)return shared_poll_alloc_rx(nhi,hop,size,flags,tx,sof,eof,poll,arg);
 assert(irq_record_count<ARRAY_SIZE(irq_records));
 struct production_irq_record *r=&irq_records[irq_record_count++];
 *r=(struct production_irq_record){.poll=poll,.arg=arg,.endpoint=endpoint_pci(nhi->pdev)};
 r->ring=shared_poll_alloc_rx(nhi,hop,size,flags,tx,sof,eof,production_poll_start_trampoline,r);
 return r->ring;
}

static bool *poll_parameter,*irq_parameter;
static unsigned poll_permission,irq_permission;
static bool poll_initial,irq_initial;
void production_poll_parameter(const char *name,bool *value,unsigned permission)
{
 if(!strcmp(name,"poll_on_interrupt")){
  assert(!irq_parameter);
  irq_parameter=value;irq_permission=permission;irq_initial=*value;return;
 }
 if(strcmp(name,"poll_completions"))return;
 assert(!poll_parameter);
 poll_parameter=value;poll_permission=permission;poll_initial=*value;
}
int production_poll_select(bool value)
{
 if(!poll_parameter)return -ENOENT;
 if(poll_permission!=0444||poll_initial)return -EPROTO;
 *poll_parameter=value;return 0;
}
int production_poll_select_irq(bool value)
{
 if(!irq_parameter)return -ENOENT;
 if(irq_permission!=0444||irq_initial)return -EPROTO;
 *irq_parameter=value;return 0;
}
void production_poll_external_enable(bool value){production_poll_external=value;}

static pthread_mutex_t race_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t race_cond=PTHREAD_COND_INITIALIZER;
static bool race_arm,race_returned,race_release,race_attempted,race_finished;
static unsigned race_endpoint;
static bool race_suspend;
static struct tb_ring *race_ring;
static struct ring_frame *race_frame;
static int race_remove_result;
static pthread_t progress_thread,remove_thread;
static void race_deadline(struct timespec *deadline)
{assert(!clock_gettime(CLOCK_REALTIME,deadline));deadline->tv_sec+=3;}
static void race_wait(bool *condition)
{
 struct timespec deadline;race_deadline(&deadline);
 while(!*condition){int rc=pthread_cond_timedwait(&race_cond,&race_lock,&deadline);assert(!rc);}
}
/* X4/X5 calls of mod_delayed_work() on a link poll work; delay in jiffies. */
bool production_poll_mod_delayed_work(void *queue,struct delayed_work *work,unsigned long delay)
{
 for(unsigned e=0;e<2;e++)
  if(world->side[e].probed&&!world->side[e].removed&&link(e)&&work==&link(e)->poll_work){
   stack_record((struct stack_event){.kind=1004,.endpoint=e,.length=(u32)delay,
    .seq=world->pump_serial,.flags=production_poll_context});
   break;
  }
 return mod_delayed_work(queue,work,delay);
}
static struct native *pending_rx(unsigned endpoint,bool control)
{
 for(unsigned i=0;i<world->nn;i++){
  struct native *n=&world->n[i];struct stack_ring_info *info=ring_info(n->r);
  if(info->endpoint==endpoint&&!info->is_tx&&!!info->control==control&&native_live(n)&&n->delivered)return n;
 }
 return NULL;
}
/* Device action only: complete delivered data RX descriptors held by HOLD_CALLBACK. */
unsigned production_poll_complete_rx(unsigned endpoint,unsigned limit)
{
 unsigned done=0;struct native *n;
 while(done<limit&&(n=pending_rx(endpoint,false))){native_complete(n);done++;}
 return done;
}
/* Device action only: deliver one live control TX of endpoint from (held or
 * not) into the peer's posted control RX and complete that RX descriptor. */
unsigned production_poll_deliver_control(unsigned from)
{
 for(unsigned i=0;i<world->nn;i++){
  struct native *n=&world->n[i];struct stack_ring_info *info=ring_info(n->r);
  if(info->endpoint!=from||!info->control||!info->is_tx||!native_live(n)||n->delivered||
     !stack_nhi_visible(n->r,n->f))continue;
  struct native *rx=matching_rx(n);
  if(!rx)return 0;
  n->delivered=rx->delivered=true;
  rx->completion_len=n->len;rx->completion_sof=n->f->sof;rx->completion_eof=n->f->eof;
  memcpy((void *)(uintptr_t)rx->f->buffer_phy,n->raw,n->raw_len);
  rx->startup=n->startup;memcpy(rx->raw,n->raw,n->raw_len);rx->raw_len=n->raw_len;
  native_complete(rx);
  return 1;
 }
 return 0;
}
static struct tb_ring *endpoint_ring(unsigned endpoint,bool control,bool tx)
{
 for(unsigned i=world->nrings;i;i--){
  struct stack_ring_info *info=&world->ring_info[i-1];
  if(info->endpoint==endpoint&&!info->freed&&!!info->control==control&&info->is_tx==tx)return info->ring;
 }
 return NULL;
}
int production_poll_rx_irq(unsigned endpoint,bool control)
{struct tb_ring *r=endpoint_ring(endpoint,control,false);return r?stack_nhi_irq_enabled(r):-1;}
bool production_poll_rx_pending(unsigned endpoint,bool control)
{struct tb_ring *r=endpoint_ring(endpoint,control,false);return r&&tb_ring_poll_pending(r);}
unsigned production_poll_rx_dropped(unsigned endpoint,bool control)
{
 struct tb_ring *r=endpoint_ring(endpoint,control,false);struct stack_nhi_stats s;
 if(!r)return 0;
 stack_nhi_ring_snapshot(r,&s);return (unsigned)s.irq_dropped;
}
unsigned production_poll_ring_modes(unsigned endpoint,unsigned *tx_irq,unsigned *rx_start_poll,unsigned *noirq)
{
 unsigned n=0;*tx_irq=*rx_start_poll=*noirq=0;
 for(unsigned i=0;i<world->nrings;i++){
  struct stack_ring_info *info=&world->ring_info[i];
  if(info->endpoint!=endpoint||info->freed)continue;
  n++;*noirq+=!!(info->ring->flags&RING_FLAG_NO_INTERRUPT);
  if(info->is_tx)*tx_irq+=!(info->ring->flags&RING_FLAG_NO_INTERRUPT)&&!info->ring->start_poll&&info->ring->irq>0;
  else *rx_start_poll+=info->ring->start_poll!=NULL&&info->ring->irq>0;
 }
 return n;
}
void production_poll_irq_latching(bool on){stack_nhi_irq_latching(on);}
unsigned production_poll_nhi_warns(void){return stack_nhi_warns();}
static unsigned inject_endpoint=2,injected;
void production_poll_inject_before_unmask(unsigned endpoint){inject_endpoint=endpoint;injected=0;}
unsigned production_poll_injected(void){return injected;}
/* Called by the poll_complete observer after the drain's final poll and
 * before the real unmask: the classic NAPI lost-wakeup window. */
void production_poll_before_unmask(struct tb_ring *ring)
{
 struct stack_ring_info *info=ring_info(ring);
 if(inject_endpoint==info->endpoint&&!info->control&&!info->is_tx){
  inject_endpoint=2;injected=production_poll_complete_rx(info->endpoint,1);
  stack_record((struct stack_event){.kind=1005,.endpoint=info->endpoint,.owner=(uintptr_t)ring,.length=injected});
 }
 /* flags: interrupt still enabled before this re-enable; length: completion waiting. */
 stack_record((struct stack_event){.kind=1003,.endpoint=info->endpoint,.owner=(uintptr_t)ring,
  .control=info->control,.direction=2,.seq=world->pump_serial,.flags=stack_nhi_irq_enabled(ring),
  .length=tb_ring_poll_pending(ring)});
}
/* Late interrupt during teardown: before the first ring of an endpoint is
 * stopped, deliver one held control message into its control RX. */
static unsigned late_endpoint=2,late_injected;
void production_poll_irq_at_stop(unsigned endpoint){late_endpoint=endpoint;late_injected=0;}
unsigned production_poll_late_injected(void){return late_injected;}
void stack_ring_stop(struct tb_ring *ring)
{
 struct stack_ring_info *info=ring_info(ring);
 if(late_endpoint==info->endpoint){
  late_endpoint=2;
  /* Marker first: the delivered completion raises its interrupt at once. */
  stack_record((struct stack_event){.kind=1006,.endpoint=info->endpoint,.owner=(uintptr_t)ring});
  late_injected=production_poll_deliver_control(1-info->endpoint);
 }
 shared_poll_ring_stop(ring);
}
/* Interrupt before the gate: while rings start, the first control RX post of
 * an endpoint whose interrupt gate is still closed receives one pending
 * control message of its peer, and its completion interrupts at once. */
static unsigned prestart_endpoint=2,prestart_injected;
void production_poll_irq_before_gate(unsigned endpoint){prestart_endpoint=endpoint;prestart_injected=0;}
unsigned production_poll_prestart_injected(void){return prestart_injected;}
int stack_ring_rx(struct tb_ring *ring,struct ring_frame *frame)
{
 int ret=shared_poll_ring_rx(ring,frame);
 struct stack_ring_info *info=ring_info(ring);
 if(!ret&&prestart_endpoint==info->endpoint&&info->control&&!link(info->endpoint)->poll_irq_live){
  stack_record((struct stack_event){.kind=1007,.endpoint=info->endpoint,.owner=(uintptr_t)ring});
  prestart_injected=production_poll_deliver_control(1-info->endpoint);
  if(prestart_injected)prestart_endpoint=2;
 }
 return ret;
}
/* start_poll lock order: return while another context holds this link lock. */
static pthread_t lock_thread;
static bool lock_done;
static unsigned lock_from;
static void *lock_deliver(void *unused)
{
 (void)unused;
 unsigned delivered=production_poll_deliver_control(lock_from);
 assert(!pthread_mutex_lock(&race_lock));lock_done=delivered;
 assert(!pthread_cond_broadcast(&race_cond));assert(!pthread_mutex_unlock(&race_lock));return NULL;
}
int production_poll_lock_order(unsigned endpoint)
{
 struct xdev_ext_xd_link *xl=link(endpoint);unsigned long flags;
 lock_from=1-endpoint;lock_done=false;
 spin_lock_irqsave(&xl->lock,flags);
 assert(!pthread_create(&lock_thread,NULL,lock_deliver,NULL));
 assert(!pthread_mutex_lock(&race_lock));
 struct timespec deadline;race_deadline(&deadline);deadline.tv_sec-=1;
 int waited=0;
 while(!lock_done&&!waited)waited=pthread_cond_timedwait(&race_cond,&race_lock,&deadline);
 bool done=lock_done;
 assert(!pthread_mutex_unlock(&race_lock));
 if(!done){fprintf(stderr,"STACK_ASSERT irq-start-poll-lock-order: start_poll waits for xl->lock under NHI ring locks\n");fflush(stderr);exit(1);}
 spin_unlock_irqrestore(&xl->lock,flags);
 assert(!pthread_join(lock_thread,NULL));
 return 0;
}
void production_poll_return(struct tb_ring *ring,struct ring_frame *frame)
{
 struct stack_ring_info *info=ring_info(ring);
 stack_record((struct stack_event){.kind=1000,.endpoint=info->endpoint,
  .control=info->control,.direction=info->is_tx?1:2,.owner=(uintptr_t)ring,
  .address=(uintptr_t)frame,.seq=production_poll_pass,.flags=production_poll_context});
 if(!frame)return;
 assert(!stack_spins);
 assert(!pthread_mutex_lock(&race_lock));
 if(race_arm&&info->endpoint==race_endpoint&&!info->control&&info->is_tx){
  race_arm=false;race_returned=true;race_ring=ring;race_frame=frame;
  assert(!pthread_cond_broadcast(&race_cond));race_wait(&race_release);
 }
 assert(!pthread_mutex_unlock(&race_lock));
}
void production_poll_once(unsigned endpoint)
{
 struct epoch *e=world->side[endpoint].current;assert(e&&e->bound);
 production_poll_context=1;production_poll_pass++;
 e->s.st.cls->progress(&e->s.st);
 production_poll_context=0;
}
unsigned production_poll_rings(unsigned endpoint,unsigned *noirq,unsigned *startpoll)
{
 unsigned n=0;*noirq=*startpoll=0;
 for(unsigned i=0;i<world->nrings;i++){
  struct stack_ring_info *info=&world->ring_info[i];
  if(info->endpoint!=endpoint||info->freed)continue;
  n++;*noirq+=!!(info->ring->flags&RING_FLAG_NO_INTERRUPT);
  *startpoll+=info->ring->start_poll!=NULL;
 }
 return n;
}
unsigned production_poll_pending(void)
{
 unsigned count=0;
 for(unsigned i=0;i<world->nrings;i++){
  struct stack_ring_info *info=&world->ring_info[i];
  if(!info->freed&&!info->retiring&&tb_ring_poll_pending(info->ring))count++;
 }
 return count;
}
unsigned production_poll_complete_tx(unsigned endpoint,unsigned limit)
{
 unsigned done=0;
 for(unsigned i=0;i<world->nn&&done<limit;i++){
  struct native *n=&world->n[i];struct stack_ring_info *info=ring_info(n->r);
  if(info->endpoint==endpoint&&!info->control&&info->is_tx&&native_live(n)&&n->delivered){native_complete(n);done++;}
 }
 return done;
}
void production_poll_counts(unsigned endpoint,unsigned *inflight,unsigned *queued)
{
 *inflight=*queued=0;
 for(unsigned i=0;i<world->nrings;i++){
  struct stack_ring_info *info=&world->ring_info[i];
  if(info->endpoint!=endpoint||info->control||!info->is_tx||info->freed)continue;
  struct ring_frame *f;
  list_for_each_entry(f,&info->ring->in_flight,list)(*inflight)++;
  list_for_each_entry(f,&info->ring->queue,list)(*queued)++;
 }
}
void production_poll_worker_gone(unsigned endpoint)
{
 struct epoch *epoch=world->side[endpoint].current;assert(epoch&&epoch->bound);
 /* Match the external core boundary: no more worker scheduling, then actual
  * class unbind. This fixture does not execute the complete core worker. */
 epoch->bound=false;epoch->s.kicked=false;
 epoch->s.st.cls->unbind(&epoch->s.st);
}
static void *race_progress(void *unused)
{(void)unused;production_poll_once(race_endpoint);return NULL;}
static void *race_remove(void *unused)
{
 (void)unused;
 assert(!pthread_mutex_lock(&race_lock));race_attempted=true;
 assert(!pthread_cond_broadcast(&race_cond));assert(!pthread_mutex_unlock(&race_lock));
 race_remove_result=race_suspend?stack_suspend(world,race_endpoint):stack_remove(world,race_endpoint);
 assert(!pthread_mutex_lock(&race_lock));race_finished=true;
 assert(!pthread_cond_broadcast(&race_cond));assert(!pthread_mutex_unlock(&race_lock));return NULL;
}
int production_poll_race(unsigned endpoint,bool suspend)
{
 race_endpoint=endpoint;race_suspend=suspend;race_arm=true;race_returned=race_release=race_attempted=race_finished=false;
 assert(!pthread_create(&progress_thread,NULL,race_progress,NULL));
 assert(!pthread_mutex_lock(&race_lock));race_wait(&race_returned);
 /* Returned frame is genuinely absent from NHI ownership lists now. */
 bool absent=true;struct ring_frame *f;
 list_for_each_entry(f,&race_ring->in_flight,list)if(f==race_frame)absent=false;
 assert(absent);
 assert(!pthread_create(&remove_thread,NULL,race_remove,NULL));race_wait(&race_attempted);
 struct timespec deadline;race_deadline(&deadline);deadline.tv_sec-=2;
 int waited=0;
 while(!race_finished&&!waited)waited=pthread_cond_timedwait(&race_cond,&race_lock,&deadline);
 bool waited_for_callback=!race_finished&&!ring_info(race_ring)->freed;
 /* If the barrier is broken, fail by a named assertion before permitting a
  * callback into freed storage. Do not count a crash as race detection. */
 if(!waited_for_callback){fprintf(stderr,"STACK_ASSERT poll-return-stop-race: storage lifetime: STOP/remove must wait for poll-returned callback\n");fflush(stderr);exit(1);}
 race_release=true;assert(!pthread_cond_broadcast(&race_cond));assert(!pthread_mutex_unlock(&race_lock));
 assert(!pthread_join(progress_thread,NULL));assert(!pthread_join(remove_thread,NULL));
 return race_remove_result;
}

/* Observation only: no xd_snapshot, no authority update, no completion or kick. */
void production_poll_tail(unsigned endpoint,struct xdev_ext_mech_session *session,u64 next)
{
 struct stack_stage_facts facts;memset(&facts,0,sizeof(facts));
 assert(!stack_x5_stage_facts(&session->st,0,&facts));
 struct stack_event event={.kind=1001,.endpoint=endpoint,.session_id=session->id,
  .seq=world->pump_serial,.flags=session->kicked,.length=facts.slot_busy,
  .pdf=(facts.reply_used?1U:0)|(facts.reply_closed?2U:0),.bytes=facts.native_controls,.status=(int)((next-world->now)/NSEC_PER_MSEC)};
 for(unsigned i=0;i<world->nn;i++){
  struct native *n=&world->n[i];struct stack_ring_info *info=ring_info(n->r);
  if(info->endpoint==endpoint&&info->control&&info->is_tx&&n->live&&!n->startup){
   event.control++;if(n->raw[5]==3){event.control_type=3;event.owner=(uintptr_t)n->f;event.address=n->completed;}
  }
 }
 if(event.control_type==3&&production_poll_delay_ack&&++production_poll_ack_tails>=2)production_poll_delay_ack=false;
 stack_record(event);
}

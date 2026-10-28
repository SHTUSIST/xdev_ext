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
#include "stack_boundary.c"
#undef stack_ring_alloc_tx
#undef stack_ring_alloc_rx
static unsigned allocation_fail,allocation_seen;
void production_poll_fail_allocation(unsigned ordinal){allocation_fail=ordinal;allocation_seen=0;}
static void production_poll_allocation(struct tb_nhi *nhi)
{if(endpoint_pci(nhi->pdev)==0&&++allocation_seen==allocation_fail)world->ring_refuse[0]=true;}
struct tb_ring *stack_ring_alloc_tx(struct tb_nhi *nhi,int hop,int size,unsigned flags)
{production_poll_allocation(nhi);return shared_poll_alloc_tx(nhi,hop,size,flags);}
struct tb_ring *stack_ring_alloc_rx(struct tb_nhi *nhi,int hop,int size,unsigned flags,int tx,u16 sof,u16 eof,void(*poll)(void *),void *arg)
{production_poll_allocation(nhi);return shared_poll_alloc_rx(nhi,hop,size,flags,tx,sof,eof,poll,arg);}

static bool *poll_parameter;
static unsigned poll_permission;
static bool poll_initial;
void production_poll_parameter(const char *name,bool *value,unsigned permission)
{
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

/* SPDX-License-Identifier: GPL-2.0 */
/* Included after qualified full OS boundary TU, exposing only owned objects. */
#include <pthread.h>
#include <stdatomic.h>
int stack_diag_class(struct xdev_ext_mech_stage *,struct xdev_ext_mech_stage_diag *);
static struct xdev_ext_xd_link *diag_link;
static unsigned diag_point,diag_endpoint,diag_operation;
static pthread_t diag_thread;
static bool diag_thread_started;
static _Thread_local bool diag_lifecycle_thread;
static atomic_uint diag_attempted,diag_finished;
static unsigned diag_samples,diag_native_calls,diag_retention_calls;
static void *diag_lifecycle(void *arg)
{
 diag_lifecycle_thread=true;
 struct xdev_ext_xd_link *xl=arg;
 int rc=pthread_mutex_trylock(&xl->ctl_mutex.native);
 assert(rc==EBUSY); /* true competing thread sees the protected mutex */
 atomic_store(&diag_attempted,1);
 if(diag_operation==1){assert(!stack_remove(world,diag_endpoint));}
 else {assert(!stack_suspend(world,diag_endpoint));assert(!stack_resume(world,diag_endpoint));}
 atomic_store(&diag_finished,1);
 return NULL;
}
/* Called only by private environmental mutex primitives. The lifecycle thread
 * must reach the actual main path's ctl_mutex acquire before sampling starts.
 * Starting at native_snapshot itself would merely block it on xl.lock first. */
void stack_diag_mutex_before(struct mutex *m)
{
 if(diag_lifecycle_thread&&diag_link&&m==&diag_link->ctl_mutex&&atomic_load(&diag_attempted)==1){
  assert(pthread_mutex_trylock(&m->native)==EBUSY);
  atomic_store(&diag_attempted,2);
 }
}
void stack_diag_mutex_after(struct mutex *m)
{
 if(!diag_link||diag_lifecycle_thread||diag_thread_started||m!=&diag_link->ctl_mutex)return;
 assert(!stack_spins);diag_thread_started=true;
 assert(!pthread_create(&diag_thread,NULL,diag_lifecycle,diag_link));
 while(atomic_load(&diag_attempted)!=2)sched_yield();
 assert(!atomic_load(&diag_finished));
}
static void stack_diag_sample(unsigned point)
{
 if(!diag_link||point!=diag_point)return;
 assert(diag_link->ctl_mutex.held&&diag_thread_started);
 if(point==2)assert(!stack_spins);
 assert(atomic_load(&diag_attempted)==2&&!atomic_load(&diag_finished));
 fprintf(stderr,"STACK_DIAG_BOUNDARY point=%u actual_main_ctl_wait=1 operation=%u spins=%u\n",point,diag_operation,stack_spins);
 diag_samples++;diag_point=0;
}
void stack_diag_native(struct tb_ring *r,struct tb_ring_snapshot *s)
{
 diag_native_calls++;
 stack_diag_sample(1);
 tb_ring_snapshot(r,s); /* complete actual NHI ring algorithm */
 unsigned in=0,q=0;struct ring_frame *f;
 spin_lock_irq(&r->lock);
 list_for_each_entry(f,&r->in_flight,list){in++;assert(f->buffer_phy);}
 list_for_each_entry(f,&r->queue,list){q++;assert(f->buffer_phy);}
 assert(s->in_flight==in&&s->software_pending==q);
 spin_unlock_irq(&r->lock);
}
void stack_diag_retention(struct pci_dev *p,struct xdev_ext_requester_retention_stats *s)
{
 assert(!stack_spins);diag_retention_calls++;stack_diag_sample(2);
 actual_stack_retention_snapshot(p,s);
}
void xdev_ext_requester_retention_snapshot(struct pci_dev *p,struct xdev_ext_requester_retention_stats *s)
{actual_stack_retention_snapshot(p,s);}
bool stack_diag_parallel(void){return diag_operation!=0;}
static struct xdev_ext_mech_stage *diag_stage(unsigned e)
{assert(e<2&&world->side[e].current);return &world->side[e].current->s.st;}
int stack_diag_query(struct stack_world *w,unsigned e,struct xdev_ext_mech_stage_diag *d)
{
 assert(w==world);size_t n=world->logs;unsigned calls=diag_native_calls,ledger=diag_retention_calls;
 int rc=stack_diag_class(diag_stage(e),d);
 if(!diag_operation)assert(n==world->logs); /* no policy/post/progress side effects */
 if(!rc){assert(diag_native_calls==calls+1);assert(diag_retention_calls==ledger+1);}
 return rc;
}
void stack_diag_arm(struct stack_world *w,unsigned e,unsigned point,unsigned operation)
{
 assert(w==world&&point>=1&&point<=2);diag_link=link(e);diag_endpoint=e;
 diag_thread_started=false;diag_operation=operation;diag_point=point;atomic_store(&diag_attempted,0);atomic_store(&diag_finished,0);
}
void stack_diag_join(void)
{
 assert(!pthread_join(diag_thread,NULL));assert(atomic_load(&diag_finished));
 assert(diag_samples);diag_link=NULL;diag_operation=0;
}
/* Independent live observations use actual ring lists, accepted frame lengths,
 * descriptor addresses, mappings, and requester ledger. No seeded facts. */
void stack_diag_observe(struct stack_world *w,unsigned e,unsigned *in,unsigned *queued,
                        struct xdev_ext_requester_retention_stats *ret)
{
 assert(w==world);struct xdev_ext_mech_stage *st=diag_stage(e);
 struct xdev_ext_xd_link *xl=link(e);
 struct tb_ring *r=st->direction==2?xl->chan[0].rx:xl->chan[0].tx;
 *in=*queued=0;struct ring_frame *f;
 mutex_lock(&xl->ctl_mutex);spin_lock_irq(&r->lock);
 unsigned index=r->tail;
 list_for_each_entry(f,&r->in_flight,list){
  (*in)++;assert(f->buffer_phy);
  assert(r->descriptors[index].phys==f->buffer_phy);
  index=(index+1)%r->size;
 }
 list_for_each_entry(f,&r->queue,list){(*queued)++;assert(f->buffer_phy);}
 spin_unlock_irq(&r->lock);
 actual_stack_retention_snapshot(xl->nhi_pdev,ret);mutex_unlock(&xl->ctl_mutex);
}
int stack_diag_fill_controls(struct stack_world *w,unsigned e)
{
 assert(w==world);struct xdev_ext_xd_msg m={.type=XDEV_EXT_XD_ACK,.channel=0,.group=9001,.stream=9001,.credit=3};
 int accepted=0;while(xdev_ext_xd_msg_send(link(e),NULL,0,&m)==0){assert(++accepted<=128);}
 return accepted;
}
void stack_diag_ledger(struct stack_world *w,unsigned e,struct xdev_ext_requester_retention_stats *s)
{assert(w==world&&e<2);actual_stack_retention_snapshot(&w->side[e].pci,s);}

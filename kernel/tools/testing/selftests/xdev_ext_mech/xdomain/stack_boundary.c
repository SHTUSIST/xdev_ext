/* SPDX-License-Identifier: GPL-2.0 */
/* External kernel/NHI/provider recorder. Payload is never CPU accessible. */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
/* Actual built-in requester budget, with only kernel OS facilities facaded. */
#include "../../../../../io_uring/family/xdev_ext_requester_retention.c"
#ifndef STACK_REAL_NHI
/* Actual NHI declaration and sizing body; never a copied byte formula. */
#include "stack_descriptor_source.inc"
#endif
unsigned long jiffies;
#define STACK_RECORDS 200000
#define STACK_NATIVE 40000
#define STACK_BATCHES 512
#define STACK_WORK 256
#define STACK_FAULTS 128
struct native {
#ifdef STACK_REAL_NHI
	ring_cb callback;
	bool completed;
	u32 completion_len, completion_flags;
	u8 completion_sof, completion_eof;
#endif
	struct tb_ring*r;
	struct ring_frame*f;
	u64 id,
	seq,
	group,
	generation,
	session_id, incarnation;
	u32 len;
	bool live,
	held,
	lost,
	delivered,
	replay;
	u8 raw[STACK_CTL_BYTES];
	u32 raw_len;
}
;
/* The authority, stage, mutexes and callback storage of an old generation
 * never move. A new registration creates a distinct heap object. */
struct epoch {
 struct xdev_ext_mech_session s;
 struct xdev_ext_mech_batch b[STACK_BATCHES];
 unsigned nb;
 u64 next_progress, allocation_bias;
 bool bound;
};
struct side {
 struct pci_dev pci;
 struct tb_nhi nhi;
 struct tb tb;
 struct tb_xdomain xd;
 struct tb_service svc;
 uuid_t uuid;
 struct epoch *epochs[STACK_SESSION_GENERATIONS], *current;
 unsigned nr_epochs, ring_allocs;
 u64 rand;
 bool probed, removed;
};
#ifdef STACK_REAL_NHI
/* Test metadata is separate from the unmodified production ring layout. */
struct stack_ring_info {
 struct tb_ring *ring;
 struct tb_nhi *nhi;
 unsigned endpoint, control, channel, size;
 bool is_tx, freed, unknown, retiring;
};
#endif
struct stack_world {
	struct stack_config cfg;
	struct side side[2];
	struct stack_event*log;
	size_t logs;
	struct native*n;
	unsigned nn;
	struct tb_ring*rings[64];
#ifdef STACK_REAL_NHI
 struct stack_ring_info ring_info[64];
#endif
	unsigned nrings;
	struct work_struct*work[STACK_WORK];
	unsigned nwork;
	struct stack_fault faults[STACK_FAULTS];
	unsigned nf;
	u64 now,
	next_lease, pump_serial;
	unsigned active;
	unsigned duplicate_callback[2],
	hold_control_type[2],
	drop_control_type[2];
	bool hold_callbacks[2],
	hold_controls[2],
	drop_callback[2],
	drop_control[2],
	ring_refuse[2],
	control_refuse[2];
	int stop_result[2],
	policy[2];
	u32 rx_flags[2],
	rx_length[2];
	bool rx_length_set[2];
	void*response;
	size_t response_size;
	struct tb_protocol_handler*handler;
	bool in_callback;
}
;
static struct stack_world*world;
struct stack_world*stack_retained_worlds[128];
static unsigned stack_retained_count;
#ifdef STACK_REAL_NHI
static struct stack_ring_info *ring_info(const struct tb_ring *r)
{
 /* A normal free may recycle its address. The newest allocation owns it. */
 for (unsigned i = world->nrings; i; i--)
  if (world->ring_info[i - 1].ring == r)
   return &world->ring_info[i - 1];
 assert(!"unrecorded NHI ring");
 return NULL;
}
#else
#define ring_info(r) (r)
#endif
unsigned stack_spins,stack_mutexes;
static unsigned endpoint_pci(const struct pci_dev*p){
	assert(world);
	for(unsigned e=0;e<2;e++)if(p==&world->side[e].pci)return e;
	assert(0);
	return 0;
}
static unsigned endpoint_xd(const struct tb_xdomain*x){
	return endpoint_pci(x->tb->nhi->pdev);
}
int stack_endpoint_stage(const struct xdev_ext_mech_stage *stage)
{
 for (unsigned e=0;e<2;e++)
  for (unsigned i=0;i<world->side[e].nr_epochs;i++)
   if (stage->s == &world->side[e].epochs[i]->s)
    return e;
 assert(!"foreign stage");
 return -1;
}
static struct epoch *epoch_for_session(const struct xdev_ext_mech_session *session)
{
 for (unsigned e=0;e<2;e++)
  for (unsigned i=0;i<world->side[e].nr_epochs;i++)
   if (session == &world->side[e].epochs[i]->s)
    return world->side[e].epochs[i];
 return NULL;
}
static struct xdev_ext_xd_link*link(unsigned e){
	return world->side[e].svc.drvdata;
}
void stack_record(struct stack_event e){
	assert(world&&world->logs<STACK_RECORDS);
	e.id=world->logs+1;
	e.now_ns=world->now;
	if(e.endpoint<2&&world->side[e.endpoint].probed&&!world->side[e.endpoint].removed){
		struct xdev_ext_xd_link*x=link(e.endpoint);
		e.token=x->token;
		e.local_inc=x->local_inc;
		e.remote_inc=x->remote_inc;
	}
	world->log[world->logs++]=e;
	if(getenv("STACK_TRACE"))fprintf(stderr,"EV id=%llu t=%llu ep=%u kind=%u ctl=%u type=%u owner=%llx seq=%llu group=%llu sid=%llu status=%d\n",(unsigned long long)e.id,(unsigned long long)e.now_ns,e.endpoint,e.kind,e.control,e.control_type,(unsigned long long)e.owner,(unsigned long long)e.seq,(unsigned long long)e.group,(unsigned long long)e.session_id,e.status);
}
void stack_lock_error(void){
	if(world)stack_record((struct stack_event){
		.kind=STACK_EV_LOCK_VIOLATION
	}
	);
}
static void worker_safe(void){
	if(stack_spins||stack_mutexes||world->in_callback){
		stack_lock_error();
		assert(!stack_spins&&!stack_mutexes&&!world->in_callback);
	}
}
u64 ktime_get_boottime_ns(void){
	return world->now;
}
void*kzalloc(size_t n,int g){
	(void)g;
	return calloc(1,n);
}
void*kcalloc(size_t n,size_t s,int g){
	(void)g;
	return calloc(n,s);
}
void*kvcalloc(size_t n,size_t s,int g){
	return kcalloc(n,s,g);
}
void kfree(void*p){
	free(p);
}
void kvfree(void*p){
	free(p);
}
static bool enqueue_work(struct work_struct*w,u64 due,bool replace){
	if(w->pending&&!replace)return false;
	w->pending=true;
	w->due=due;
	for(unsigned i=0;i<world->nwork;i++)if(world->work[i]==w)return true;
	assert(world->nwork<STACK_WORK);
	world->work[world->nwork++]=w;
	return true;
}
bool queue_work(void*q,struct work_struct*w){
	(void)q;
	return enqueue_work(w,world->now,false);
}
bool queue_delayed_work(void*q,struct delayed_work*w,unsigned long d){
	(void)q;
	return enqueue_work(&w->work,world->now+d*NSEC_PER_MSEC,false);
}
bool mod_delayed_work(void*q,struct delayed_work*w,unsigned long d){
	(void)q;
	return enqueue_work(&w->work,world->now+d*NSEC_PER_MSEC,true);
}
bool cancel_work_sync(struct work_struct*w){
	bool was=w->pending;
	w->pending=false;
	for(unsigned i=0;i<world->nwork;i++)if(world->work[i]==w){
		world->nwork--;
		memmove(&world->work[i],&world->work[i+1],
		        (world->nwork-i)*sizeof(world->work[0]));
		break;
	}
	return was;
}
bool cancel_delayed_work_sync(struct delayed_work*w){
	return cancel_work_sync(&w->work);
}
u64 get_random_u64(void){
	return ++world->side[world->active].rand;
}
struct pci_dev*pci_dev_get(struct pci_dev*p){
	p->refs++;
	return p;
}
void pci_dev_put(struct pci_dev*p){
	assert(p->refs);
	p->refs--;
}
void stack_x3_pci_put(struct pci_dev*p){
	pci_dev_put(p);
	stack_record((struct stack_event){
		.kind=STACK_EV_DEVICE_PUT,.endpoint=endpoint_pci(p),.address=(uintptr_t)p,.length=p->refs
	}
	);
}
struct tb_property_dir*tb_property_create_dir(const uuid_t*u){
	(void)u;
	return calloc(1,sizeof(struct tb_property_dir));
}
int tb_property_add_immediate(struct tb_property_dir*d,const char*k,u32 n){
	(void)d;
	(void)k;
	(void)n;
	return 0;
}
void tb_property_free_dir(struct tb_property_dir*d){
	free(d);
}
int tb_register_protocol_handler(struct tb_protocol_handler*h){
	world->handler=h;
	return 0;
}
void tb_unregister_protocol_handler(struct tb_protocol_handler*h){
	assert(world->handler==h);
	world->handler=NULL;
}
int tb_register_property_dir(const char*k,struct tb_property_dir*d){
	(void)k;
	(void)d;
	return 0;
}
void tb_unregister_property_dir(const char*k,struct tb_property_dir*d){
	(void)k;
	(void)d;
}
int tb_register_service_driver(struct tb_service_driver*d){
	(void)d;
	return 0;
}
void tb_unregister_service_driver(struct tb_service_driver*d){
	(void)d;
}
static void handler_record(unsigned e,const void*p,size_t n){
	struct stack_event v={
		.kind=STACK_EV_HANDLER,
		.endpoint=e,
		.length=n,
		.raw_len=n>STACK_CTL_BYTES?STACK_CTL_BYTES:n
	}
	;
	memcpy(v.raw,p,v.raw_len);
	stack_record(v);
}
int tb_xdomain_request(struct tb_xdomain*x,const void*p,size_t n,int pt,void*out,size_t cap,int rt,unsigned timeout){
	(void)pt;
	(void)rt;
	(void)timeout;
	unsigned e=endpoint_xd(x);
	stack_record((struct stack_event){
		.kind=STACK_EV_LOGIN,.endpoint=e,.length=n
	}
	);
	if(!world->side[1-e].probed||world->side[1-e].removed)return -ETIMEDOUT;
	world->response=out;
	world->response_size=cap;
	handler_record(1-e,p,n);
	int got=world->handler->callback(p,n,world->handler->data);
	world->response=NULL;
	world->response_size=0;
	return got?0:-ETIMEDOUT;
}
int tb_xdomain_response(struct tb_xdomain*x,const void*p,size_t n,int pt){
	(void)pt;
	if(world->response){
		if(n>world->response_size)return -EMSGSIZE;
		memcpy(world->response,p,n);
		return 0;
	}
	if(n>=offsetof(struct xdev_ext_xd_login,proto_version)&&((const struct xdev_ext_xd_login*)p)->type==XDEV_EXT_XD_LOGIN_RESPONSE)return 0;
	unsigned e=endpoint_xd(x);
	if(world->side[1-e].probed&&!world->side[1-e].removed&&world->handler){
		handler_record(1-e,p,n);
		return world->handler->callback(p,n,world->handler->data)?0:-ENODEV;
	}
	return -ENODEV;
}
void dev_info(const struct device*d,const char*f,...){
	(void)d;
	(void)f;
}
void dev_dbg(const struct device*d,const char*f,...){
	(void)d;
	(void)f;
}
void*dma_alloc_coherent(struct device*d,size_t n,dma_addr_t*a,int g){
	(void)d;
	(void)g;
	void*p=calloc(1,n);
	*a=(uintptr_t)p;
	return p;
}
void dma_free_coherent(struct device*d,size_t n,void*p,dma_addr_t a){
	(void)d;
	(void)n;
	assert((uintptr_t)p==a);
	free(p);
}
u32 crc32c(u32 c,const void*p,size_t n){
	const u8*s=p;
	while(n--){
		c^=*s++;
		for(unsigned b=0;b<8;b++)c=(c>>1)^(0x82f63b78U&-(c&1));
	}
	return c;
}
#ifndef STACK_REAL_NHI
static struct tb_ring*ring_alloc(struct tb_nhi*n,int size,unsigned flags,bool tx){
	unsigned e=endpoint_pci(n->pdev);
	if(world->ring_refuse[e]){
		world->ring_refuse[e]=false;
		stack_record((struct stack_event){
			.kind=STACK_EV_REJECT,.endpoint=e,.status=-ENOMEM
		}
		);
		return NULL;
	}
	struct tb_ring*r=calloc(1,sizeof(*r));
	assert(r&&world->nrings<64);
	unsigned ordinal=world->side[e].ring_allocs++;
	*r=(struct tb_ring){
		.nhi=n,
		.size=size,
		.hop=16+ordinal,
		.flags=flags,
		.is_tx=tx,
		.endpoint=e,
		.control=size==XDEV_EXT_XD_CTL_RING,
		.channel=ordinal<2?0:(ordinal-2)/2
	}
	;
	world->rings[world->nrings++]=r;
	stack_record((struct stack_event){
		.kind=STACK_EV_RING_ALLOC,.endpoint=e,.control=r->control,.direction=tx?1:2,.channel=r->channel,.owner=(uintptr_t)r,.address=(uintptr_t)n->pdev,.length=size
	}
	);
	return r;
}
struct tb_ring*tb_ring_alloc_tx(struct tb_nhi*n,int hop,int size,unsigned flags){
	(void)hop;
	return ring_alloc(n,size,flags,true);
}
struct tb_ring*tb_ring_alloc_rx(struct tb_nhi*n,int hop,int size,unsigned flags,int tx,u16 sof,u16 eof,void(*poll)(void*),void*arg){
	(void)hop;
	(void)tx;
	(void)sof;
	(void)eof;
	(void)poll;
	(void)arg;
	return ring_alloc(n,size,flags,false);
}
void tb_ring_start(struct tb_ring*r){
	r->running=!r->nhi->going_away;
	stack_record((struct stack_event){
		.kind=STACK_EV_RING_START,.endpoint=r->endpoint,.direction=r->is_tx?1:2,.control=r->control,.owner=(uintptr_t)r,.status=r->running?0:-ENODEV
	}
	);
}
static void invoke(struct native*n,bool canceled){
	if(!n->live||n->r->freed||(!canceled&&n->lost)||
	   (n->incarnation&&n->incarnation!=link(n->r->endpoint)->local_inc)){
		stack_record((struct stack_event){
			.kind=STACK_EV_REJECT,.endpoint=n->r->endpoint,.owner=(uintptr_t)n->f,.session_id=n->session_id,.generation=n->generation,.seq=n->seq,.status=-ESTALE
		}
		);
		return;
	}
	n->live=false;
	struct ring_frame*f=n->f;
	unsigned e=n->r->endpoint;
	world->in_callback=true;
	if(!n->r->control)stack_record((struct stack_event){
		.kind=STACK_EV_DATA_CALLBACK,.endpoint=e,.direction=n->r->is_tx?1:2,.owner=(uintptr_t)f,.group=n->group,.seq=n->seq,.generation=n->generation,.session_id=n->session_id,.address=f->buffer_phy,.length=canceled?0:n->len,.flags=f->flags,.pdf=f->sof|(f->eof<<8),.status=canceled?-ECANCELED:0
	}
	);
	f->callback(n->r,f,canceled);
	world->in_callback=false;
	if(n->r->control&&n->r->is_tx)stack_record((struct stack_event){
		.kind=canceled?STACK_EV_RETAIN:STACK_EV_CONTROL_DONE,.endpoint=e,.control=1,.owner=(uintptr_t)f,.status=canceled?-ECANCELED:0
	}
	);
	if(!n->r->control&&world->duplicate_callback[e]){
		world->duplicate_callback[e]--;
		stack_record((struct stack_event){
			.kind=STACK_EV_REJECT,.endpoint=e,.owner=(uintptr_t)f,.session_id=n->session_id,.generation=n->generation,.seq=n->seq,.status=-ESTALE
		}
		);
	}
}
void tb_ring_stop(struct tb_ring*r){
	unsigned e=r->endpoint;
	bool unknown=r->nhi->going_away||world->stop_result[e];
	r->running=unknown;
	stack_record((struct stack_event){
		.kind=STACK_EV_RING_STOP,.endpoint=e,.direction=r->is_tx?1:2,.control=r->control,.owner=(uintptr_t)r,.status=unknown?-ENODEV:0
	}
	);
	for(unsigned i=0;i<world->nn;i++){
		struct native*n=&world->n[i];
		if(n->r==r&&n->live&&!n->lost){
			if(n->replay)n->live=false;
			else invoke(n,true);
		}
	}
}
void tb_ring_free(struct tb_ring*r){
	assert(!r->running&&!r->freed);
	r->freed=true;
	stack_record((struct stack_event){
		.kind=STACK_EV_RING_FREE,.endpoint=r->endpoint,.control=r->control,.direction=r->is_tx?1:2,.owner=(uintptr_t)r
	}
	);
}
void tb_ring_free_quarantined(struct tb_ring*r){
	r->unknown=true;
	r->freed=true;
	for(unsigned i=0;i<world->nn;i++)if(world->n[i].r==r&&world->n[i].live&&!world->n[i].lost)invoke(&world->n[i],true);
	stack_record((struct stack_event){
		.kind=STACK_EV_RETAIN,.endpoint=r->endpoint,.control=r->control,.owner=(uintptr_t)r,.status=-ENODEV
	}
	);
}
struct device*tb_ring_dma_device(struct tb_ring*r){
	return &r->nhi->pdev->dev;
}
#endif /* !STACK_REAL_NHI: model ring implementation */
static int native_post(struct tb_ring*r,struct ring_frame*f){
	assert(r->running&&!ring_info(r)->freed&&world->nn<STACK_NATIVE);
	struct native*n=&world->n[world->nn++];
	*n=(struct native){
		.r=r,
		.f=f,
		.live=true,
		.len=f->size?f->size:4096
	}
	;
	if(ring_info(r)->control){
		if(r->is_tx){
			n->raw_len=n->len;
			assert(n->raw_len<=STACK_CTL_BYTES);
			memcpy(n->raw,(void*)(uintptr_t)f->buffer_phy,n->raw_len);
			struct stack_event e={
				.kind=STACK_EV_CONTROL_TX,
				.endpoint=ring_info(r)->endpoint,
				.direction=1,
				.control=1,
				.owner=(uintptr_t)f,
				.address=f->buffer_phy,
				.length=n->len,
				.raw_len=n->raw_len,
				.control_type=n->raw[5]
			}
			;
			memcpy(e.raw,n->raw,n->raw_len);
			stack_record(e);
			n->id=world->logs;
			n->held=world->hold_controls[ring_info(r)->endpoint]&&(!world->hold_control_type[ring_info(r)->endpoint]||world->hold_control_type[ring_info(r)->endpoint]==n->raw[5]);
			if(world->drop_control[ring_info(r)->endpoint]&&(!world->drop_control_type[ring_info(r)->endpoint]||world->drop_control_type[ring_info(r)->endpoint]==n->raw[5])){
				n->delivered=true;
				world->drop_control[ring_info(r)->endpoint]=false;
			}
		}
	}
	else{
		struct xdev_ext_net_elem*el=container_of((void*)f,struct xdev_ext_net_elem,dev);
		n->group=el->slot->group;
		n->incarnation=link(ring_info(r)->endpoint)->local_inc;
		n->generation=el->slot->ns->st->s->generation;
		n->session_id=el->slot->ns->st->s->id;
		for(unsigned i=0;i+1<world->nn;i++)if(world->n[i].r==r&&world->n[i].incarnation==n->incarnation)n->seq++;
		struct stack_event e={
			.kind=STACK_EV_DATA_POST,
			.endpoint=ring_info(r)->endpoint,
			.direction=r->is_tx?1:2,
			.channel=ring_info(r)->channel,
			.stage_index=el->slot->ns->st->index,
			.owner=(uintptr_t)f,
			.address=f->buffer_phy,
			.length=el->len,
			.seq=n->seq,
			.group=n->group,
			.generation=n->generation,
			.session_id=n->session_id,
			.pdf=f->sof|(f->eof<<8)
		}
		;
		stack_record(e);
		n->id=world->logs;
	}
	return 0;
}
#ifndef STACK_REAL_NHI
int tb_ring_tx(struct tb_ring*r,struct ring_frame*f){
	assert(r->is_tx);
	return native_post(r,f);
}
int tb_ring_rx(struct tb_ring*r,struct ring_frame*f){
	assert(!r->is_tx);
	return native_post(r,f);
}
#else
#include "stack_nhi_boundary.h"
#endif
static int hop_alloc(struct tb_xdomain*x,int id,bool in){
	unsigned e=endpoint_xd(x);
	int v=id>=0?id:100+(int)world->logs;
	stack_record((struct stack_event){
		.kind=STACK_EV_HOP_ALLOC,.endpoint=e,.direction=in?2:1,.owner=(u64)v
	}
	);
	return v;
}
int tb_xdomain_alloc_in_hopid(struct tb_xdomain*x,int id){
	return hop_alloc(x,id,true);
}
int tb_xdomain_alloc_out_hopid(struct tb_xdomain*x,int id){
	return hop_alloc(x,id,false);
}
void tb_xdomain_release_in_hopid(struct tb_xdomain*x,int id){
	stack_record((struct stack_event){
		.kind=STACK_EV_HOP_FREE,.endpoint=endpoint_xd(x),.direction=2,.owner=id
	}
	);
}
void tb_xdomain_release_out_hopid(struct tb_xdomain*x,int id){
	stack_record((struct stack_event){
		.kind=STACK_EV_HOP_FREE,.endpoint=endpoint_xd(x),.direction=1,.owner=id
	}
	);
}
int tb_xdomain_enable_paths(struct tb_xdomain*x,int tx,int out,int rx,int in){
	(void)out;
	(void)in;
	unsigned e=endpoint_xd(x);
	bool control=false;
	unsigned channel=0;
	for(unsigned i=0;i<world->nrings;i++){
		struct tb_ring*r=world->rings[i];
		if(!ring_info(r)->freed&&ring_info(r)->endpoint==e&&(r->hop==out||r->hop==in)){
			control=ring_info(r)->control;
			channel=ring_info(r)->channel;
			break;
		}
	}
	stack_record((struct stack_event){
		.kind=STACK_EV_PATH_ENABLE,.endpoint=e,.control=control,.channel=channel,.owner=tx,.address=(uintptr_t)x->tb->nhi->pdev
	}
	);
	return 0;
}
int tb_xdomain_disable_paths(struct tb_xdomain*x,int tx,int out,int rx,int in){
	(void)x;
	(void)tx;
	(void)out;
	(void)rx;
	(void)in;
	return 0;
}
struct lease_entry{
	struct xdev_ext_peer_fd_lease*p;
	u64 ticket,
	off, generation, session_id;
	unsigned endpoint;
	bool live,
	retained;
}
;
static struct lease_entry leases[STACK_NATIVE];
static unsigned nleases;
int xdev_ext_peer_file_acquire(struct file*f,struct pci_dev*p,u64 generation,u64 off,u32 len,enum dma_data_direction dir,struct xdev_ext_peer_fd_lease*l){
	unsigned e=f->endpoint;
	assert(p==&world->side[e].pci&&f->session&&generation==f->session->generation&&nleases<STACK_NATIVE);
	u64 address;
	if(__builtin_add_overflow(world->cfg.mapping_base[e],off,&address))return -EOVERFLOW;
	*l=(struct xdev_ext_peer_fd_lease){
		.file=f,
		.lease={
			.ticket=++world->next_lease,
			.dma_address=address,
			.len=len
		}
	}
	;
	leases[nleases++]=(struct lease_entry){
 .p=l,.ticket=l->lease.ticket,.off=off,.generation=generation,
 .session_id=f->session->id,.endpoint=e,.live=true
 };
	stack_record((struct stack_event){
		.kind=STACK_EV_LEASE_ACQUIRE,.endpoint=e,.address=address,.length=len,.generation=generation,.session_id=f->session->id,.owner=l->lease.ticket,.direction=dir==DMA_TO_DEVICE?1:2
	}
	);
	return 0;
}
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease*l,bool q){
	for(unsigned i=nleases;i;i--){
		struct lease_entry*h=&leases[i-1];
		if(h->p==l&&h->live){
			h->live=false;
			h->retained=!q;
			stack_record((struct stack_event){
				.kind=q?STACK_EV_LEASE_RELEASE:STACK_EV_RETAIN,.endpoint=h->endpoint,.address=l->lease.dma_address,.length=l->lease.len,.owner=h->ticket,.generation=h->generation,.session_id=h->session_id,.status=q?0:-ENOLINK
			}
			);
			if(q)memset(l,0,sizeof(*l));
			return;
		}
	}
	stack_record((struct stack_event){
		.kind=STACK_EV_FORBIDDEN,.status=-ESTALE
	}
	);
}
struct file*xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool*p){
	return &container_of(p,struct xdev_ext_mech_session,pool)->authority;
}
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool*p){
	return container_of(p,struct xdev_ext_mech_session,pool)->generation;
}
bool xdev_ext_peer_control_file(struct file *file)
{
 return file && file->session && epoch_for_session(file->session) &&
        file == &file->session->authority;
}
int xdev_ext_requester_bind(struct xdev_ext_requester*r,struct xdev_ext_mech_stage*st,struct pci_dev*p,u32 flags){
	(void)flags;
	unsigned e=stack_endpoint_stage(st);
	if(p!=&world->side[e].pci)return -EXDEV;
	r->pdev=pci_dev_get(p);
	r->authority=st->file;
	r->generation=st->s->generation;
	return 0;
}
void xdev_ext_requester_unbind(struct xdev_ext_requester*r){
	pci_dev_put(r->pdev);
	r->pdev=NULL;
}
struct xdev_ext_mech_pool*xdev_ext_mech_session_pool(struct xdev_ext_mech_session*s){
	return &s->pool;
}
const struct xdev_ext_mech_layout*xdev_ext_mech_session_layout(const struct xdev_ext_mech_session*s){
	return &s->l;
}
u32 xdev_ext_mech_session_depth(const struct xdev_ext_mech_session*s){
	return s->depth;
}
u64 xdev_ext_mech_session_id(const struct xdev_ext_mech_session*s){
	return s->id;
}
u32 xdev_ext_mech_session_state(const struct xdev_ext_mech_session*s){
	return s->ss.state;
}
bool xdev_ext_mech_session_admits(const struct xdev_ext_mech_session*s){
	return xdev_ext_mech_sess_admits(&s->ss);
}
u64 xdev_ext_mech_session_stop_started_ns(struct xdev_ext_mech_session*s){
	return s->stop_started_ns;
}
void xdev_ext_mech_stage_stop(struct xdev_ext_mech_stage *st,int err){
 /* Core session storage is an explicit host boundary. Preserve its real
  * STOP transition and first timestamp; this is not the actual-core gate. */
 (void)err;
 if(!xdev_ext_mech_sess_stop(&st->s->ss)){
  st->s->stop_started_ns=world->now;
  st->s->kicked=true;
 }
}
void*xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch*b){
	return b->priv;
}
void*xdev_ext_mech_batch_cookie(struct xdev_ext_mech_batch*b){
	return b->cookie;
}
u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch*b){
	return b->nr;
}
u64 xdev_ext_mech_batch_ticket(const struct xdev_ext_mech_batch*b){
	return b->ticket;
}
int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch*b,u32 i,struct xdev_ext_mech_frame*out){
	if(i>=b->nr)return -EINVAL;
	*out=b->f[i];
	return 0;
}
int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch*b,u64 ticket){
	if(ticket!=b->ticket||b->claims)return -ESTALE;
	b->claims++;
	return 0;
}
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch*b,u64 ticket,int status,bool q){
	assert(ticket==b->ticket&&b->claims==1&&!b->publishes);
	b->publishes++;
	b->status=status;
	b->sequester=q;
}
void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage*st){
	st->s->kicked=true;
}
void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage*st,int err){
	stack_record((struct stack_event){
		.kind=STACK_EV_FAILURE,.endpoint=stack_endpoint_stage(st),.session_id=st->s->id,.status=err
	}
	);
	st->cls->mark_dead(st);
	st->s->kicked=true;
}
int xdev_ext_mech_stage_native_get(struct xdev_ext_mech_stage*st){
	if(!xdev_ext_mech_session_admits(st->s))return -ESHUTDOWN;
	st->s->native_controls++;
	return 0;
}
void xdev_ext_mech_stage_native_put(struct xdev_ext_mech_stage*st){
	assert(st->s->native_controls);
	st->s->native_controls--;
}
void xdev_ext_mech_count(struct xdev_ext_mech_session*s,enum xdev_ext_mech_counter c,u64 n){
	(void)s;
	(void)c;
	(void)n;
}
int xdev_ext_mech_class_register(const struct xdev_ext_mech_class_ops*o){
	assert(o==stack_x5_ops());
	return 0;
}
void xdev_ext_mech_class_unregister(const struct xdev_ext_mech_class_ops*o){
	assert(o==stack_x5_ops());
}
void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch*b,u64 cookie,u64 lba,u32 bytes,u32 opcode){
	(void)b;
	(void)cookie;
	(void)lba;
	(void)bytes;
	(void)opcode;
}
void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch*b,u64 ticket,int status){
	assert(ticket==b->ticket);
	(void)status;
}
bool xdev_ext_mech_stage_has_member(const struct xdev_ext_mech_stage*st,u32 member){
	(void)st;
	return member==XDEV_EXT_MECH_MEMBER_COMPLETE||member==XDEV_EXT_MECH_MEMBER_BUILD;
}
int xdev_ext_mech_call(struct xdev_ext_mech_stage*st,const struct xdev_ext_mech_call_args*a,s32*ret,struct xdev_ext_mech_hold_intent*h){
	(void)h;
	worker_safe();
	return stack_x6_call(st,a,ret);
}
void stack_record_dispatch(struct xdev_ext_mech_stage*st,const struct xdev_ext_xd_msg*m){
	stack_record((struct stack_event){
		.kind=STACK_EV_DISPATCH,.endpoint=stack_endpoint_stage(st),.session_id=st->s->id,.group=m->group,.seq=m->data_seq,.control=1,.control_type=m->type,.length=m->total_len
	}
	);
	xdev_ext_xd_class_ctl(st,m);
}
int stack_policy_fault(unsigned e,u32 event){
	int p=world->policy[e];
	if(p==7&&event!=XDEV_EXT_XDP_EV_READY&&event!=XDEV_EXT_XDP_EV_TIMER)return 0;
	if(p==7)world->policy[e]=0;
	return p;
}
static struct xdev_ext_binding_ctx_v2 base_for(struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){
	return(struct xdev_ext_binding_ctx_v2){
		.current_stage=st->index,
		.direction=st->direction,
		.src_offset=b?b->key:0,
		.length=st->s->l.group_bytes
	}
	;
}
int stack_new(const struct stack_config*c,struct stack_world**out){
	if(!c||!out||world)return -EINVAL;
	struct stack_world*w=calloc(1,sizeof(*w));
	if(!w)return -ENOMEM;
	w->cfg=*c;
	w->log=calloc(STACK_RECORDS,sizeof(*w->log));
	w->n=calloc(STACK_NATIVE,sizeof(*w->n));
	if(!w->log||!w->n){
		free(w->log);
		free(w->n);
		free(w);
		return -ENOMEM;
	}
	world=w;
	w->now=1000000;
	nleases=0;
	stack_spins=stack_mutexes=0;
	for(unsigned e=0;e<2;e++){
		struct side*s=&w->side[e];
		s->pci.dev=(struct device){
			.name=e?"0000:02:00.0":"0000:01:00.0",
			.endpoint=e
		}
		;
		s->pci.refs=1;
		s->nhi.pdev=&s->pci;
#ifndef STACK_REAL_NHI
  s->nhi.hop_count=32;
#endif
#ifdef STACK_REAL_NHI
  stack_nhi_init(&s->nhi, &s->pci);
#endif
		s->tb.nhi=&s->nhi;
		memset(s->uuid.b,e+1,sizeof(s->uuid));
		s->rand=c->local_inc[e]?c->local_inc[e]-1:100+100*e;
		s->xd=(struct tb_xdomain){
			.route=1,
			.local_uuid=&s->uuid,
			.remote_uuid=&w->side[1-e].uuid,
			.tb=&s->tb,
			.dev={
				.name=e?"1-1":"0-1",
				.endpoint=e
			}
		}
		;
		s->svc=(struct tb_service){
			.dev={
				.owner=&s->svc,
				.name=e?"xdevext1":"xdevext0",
				.endpoint=e
			}
			,
			.parent=&s->xd,
			.prtcstns=XDEV_EXT_XD_CAP_E2E
		}
		;
	}
	int r=stack_x3_init();
	if(r){
		world=NULL;
		free(w->n);
		free(w->log);
		free(w);
		return r;
	}
	*out=w;
	return 0;
}
int stack_probe(struct stack_world*w,unsigned e){
	if(w!=world||e>1)return -EINVAL;
	struct side*s=&w->side[e];
	if(s->probed&&!s->removed)return -EALREADY;
	w->active=e;
	/* A re-probed service has no published link until the actual probe
	 * installs drvdata. Allocation events must not inspect the old link. */
	s->probed=false;
	s->svc.drvdata=NULL;
	s->removed=false;
	s->ring_allocs=0;
	int r=stack_x3_probe(&s->svc);
	s->probed=!r;
	stack_record((struct stack_event){
		.kind=STACK_EV_PROBE,.endpoint=e,.address=(uintptr_t)&s->pci,.status=r
	}
	);
	return r;
}
/* Provider qualification is over the registered frame intervals themselves.
 * Gaps remain available; the enclosing min/max envelope is not an allocation. */
static int disjoint_registration(const struct stack_world *w,const struct side *side,u64 bias)
{
 for(unsigned generation=0;generation<side->nr_epochs;generation++){
  u64 old_bias=side->epochs[generation]->allocation_bias;
  for(unsigned i=0;i<w->cfg.nr_frames&&i<STACK_MAX_FRAMES;i++){
   u64 next_begin,next_end;
   if(__builtin_add_overflow(w->cfg.span[i].allocation_off,bias,&next_begin)||
      __builtin_add_overflow(next_begin,(u64)w->cfg.frame_size,&next_end))return -EOVERFLOW;
   for(unsigned j=0;j<w->cfg.nr_frames&&j<STACK_MAX_FRAMES;j++){
    u64 old_begin,old_end;
    if(__builtin_add_overflow(w->cfg.span[j].allocation_off,old_bias,&old_begin)||
       __builtin_add_overflow(old_begin,(u64)w->cfg.frame_size,&old_end))return -EOVERFLOW;
    if(next_begin<old_end&&old_begin<next_end)return -EADDRINUSE;
   }
  }
 }
 return 0;
}
static int create_epoch(struct stack_world *w,unsigned endpoint,
                        const struct stack_session_config *config,bool next)
{
 if(w!=world||endpoint>1||!config||!w->side[endpoint].probed||
    w->side[endpoint].removed)return -EINVAL;
 struct side *side=&w->side[endpoint];
 if(!next&&side->current&&side->current->bound)return -EBUSY;
 if(next&&!side->current)return -EINVAL;
 if(side->nr_epochs==STACK_SESSION_GENERATIONS)return -ENOSPC;
 u64 generation=config->generation?config->generation:w->cfg.generation[endpoint];
 if(next){
  int qualification=disjoint_registration(w,side,config->allocation_bias);
  if(qualification)return qualification;
  for(unsigned i=0;i<side->nr_epochs;i++)
   if(generation==side->epochs[i]->s.generation||
      config->allocation_bias==side->epochs[i]->allocation_bias)return -EINVAL;
 }
 struct epoch *epoch=calloc(1,sizeof(*epoch));
 if(!epoch)return -ENOMEM;
 unsigned ordinal=side->nr_epochs++;
 side->epochs[ordinal]=epoch;
 epoch->allocation_bias=config->allocation_bias;
 struct xdev_ext_mech_session *session=&epoch->s;
 spin_lock_init(&session->lock);
 session->depth=w->cfg.depth;
 session->generation=generation;
 session->id=1000+endpoint+ordinal*2;
 session->authority=(struct file){.endpoint=endpoint,.session=session};
 session->pool=(struct xdev_ext_mech_pool){.kind=XDEV_EXT_MECH_POOL_PEER,
  .frame_size=w->cfg.frame_size,.nr_frames=w->cfg.nr_frames};
 u64 bytes=0;
 bool invalid=false;
 for(unsigned i=0;i<w->cfg.nr_frames&&i<STACK_MAX_FRAMES;i++){
  u64 end;
  if(__builtin_add_overflow(bytes,w->cfg.span[i].len,&bytes)||
     __builtin_add_overflow(w->cfg.span[i].allocation_off,epoch->allocation_bias,&end)||
     __builtin_add_overflow(end,w->cfg.span[i].data_off,&end)||
     __builtin_add_overflow(end,w->cfg.span[i].len,&end))invalid=true;
 }
 session->l=(struct xdev_ext_mech_layout){.frame_size=w->cfg.frame_size,
  .seg_len=w->cfg.nr_frames?w->cfg.span[0].len:0,
  .group_bytes=invalid||bytes>UINT32_MAX?0:bytes};
 xdev_ext_mech_sess_init(&session->ss);
 session->st=(struct xdev_ext_mech_stage){.s=session,.cls=stack_x5_ops(),
  .file=&session->authority,.index=config->stage_index,
  .class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.direction=config->direction};
 struct xdev_ext_mech_stage_uapi u={
  .arg0=config->token?config->token:link(endpoint)->token,.arg1=0};
 worker_safe();
 int result=session->st.cls->bind(&session->st,&u);
 epoch->bound=!result;
 if(!result)side->current=epoch;
 stack_record((struct stack_event){.kind=result?STACK_EV_REJECT:STACK_EV_START_RESULT,
  .endpoint=endpoint,.session_id=session->id,.stage_index=config->stage_index,
  .direction=config->direction,.status=result});
 return result;
}
int stack_session(struct stack_world *w,unsigned endpoint,const struct stack_session_config *config)
{
 return create_epoch(w,endpoint,config,false);
}
int stack_next_session(struct stack_world *w,unsigned endpoint,const struct stack_session_config *config)
{
 return create_epoch(w,endpoint,config,true);
}
int stack_stage_facts(struct stack_world *w,unsigned endpoint,uint64_t session_id,
                      unsigned slot,struct stack_stage_facts *out)
{
 if(w!=world||endpoint>1||!out)return -EINVAL;
 struct epoch *epoch=world->side[endpoint].current;
 if(session_id){
  epoch=NULL;
  for(unsigned i=0;i<world->side[endpoint].nr_epochs;i++)
   if(world->side[endpoint].epochs[i]->s.id==session_id)
    epoch=world->side[endpoint].epochs[i];
 }
 if(!epoch||!epoch->bound)return -ENOENT;
 int result=stack_x5_stage_facts(&epoch->s.st,slot,out);
 if(!result&&getenv("STACK_TRACE"))fprintf(stderr,"FACT ep=%u sid=%llu controls=%u inflight=%u sequestered=%u state=%u known=%u quiesced=%u accepted=%u reply_adm=%u reply_sealed=%u reply_native=%u all_adm=%u dead=%u\n",endpoint,(unsigned long long)out->session_id,out->native_controls,out->inflight,out->sequestered,out->slot_state,out->slot_local_known,out->slot_local_quiesced,out->fact_accepted,out->reply_admission,out->reply_closed,out->reply_native_posted,out->reply_admissions,out->stage_dead);
 return result;
}
int stack_start(struct stack_world*w,unsigned e,uint64_t key,unsigned index){
	if(w!=world||e>1||(!w->side[e].current||!w->side[e].current->bound))return -EINVAL;
	struct epoch*side=w->side[e].current;
	struct xdev_ext_mech_stage*st=&side->s.st;
	if(index!=st->index||side->nb>=STACK_BATCHES||w->cfg.nr_frames>XDEV_EXT_MECH_MAX_FRAMES)return -EINVAL;
	struct xdev_ext_mech_batch*b=&side->b[side->nb];
	if(b->priv){
		free(b->priv);
		free(b->cookie);
	}
	memset(b,0,sizeof(*b));
	b->s=&side->s;
	b->key=key;
	b->ticket=key+1;
	b->nr=w->cfg.nr_frames;
	b->priv=calloc(1,st->cls->batch_priv_size);
	b->cookie=calloc(1,st->cls->batch_cookie_size);
	for(unsigned i=0;i<b->nr;i++)b->f[i]=(struct xdev_ext_mech_frame){
		.umem_addr=w->cfg.span[i].allocation_off+side->allocation_bias,
		.data_off=w->cfg.span[i].data_off,
		.data_len=w->cfg.span[i].len,
		.index=i
	}
	;
	void*info=calloc(1,st->cls->info_size);
	u8*scratch=calloc(st->cls->desc_cap,st->cls->desc_size);
	st->cls->fill_info(st,b,info);
	struct xdev_ext_binding_ctx_v2 base=base_for(st,b);
	struct xdev_ext_mech_call_args a={
		.member=XDEV_EXT_MECH_MEMBER_BUILD,
		.callsite=XDEV_EXT_MECH_SITE_WORKER,
		.base=&base,
		.b=b,
		.info=info,
		.info_size=st->cls->info_size,
		.scratch=scratch,
		.desc_size=st->cls->desc_size,
		.desc_cap=st->cls->desc_cap
	}
	;
	s32 ret;
	worker_safe();
	int r=stack_x6_call(st,&a,&ret);
	if(!r&&ret!=XDEV_EXT_MECH_BUILD_SUBMIT)r=-EPROTO;
	stack_record((struct stack_event){
		.kind=STACK_EV_BUILD,.endpoint=e,.session_id=side->s.id,.stage_index=index,.group=key,.status=r
	}
	);
	if(!r)r=st->cls->validate(st,b,scratch,b->nr);
	if(r)fprintf(stderr,"STACK_DIAG build endpoint=%u ret=%d bpf=%d nr=%u frame=%u seg=%u bytes=%u off=%u len=%u\n",e,r,ret,b->nr,st->s->pool.frame_size,st->s->l.seg_len,st->s->l.group_bytes,b->f[0].data_off,b->f[0].data_len);
	if(!r){
		r=xdev_ext_mech_sess_batch_begin(&side->s.ss);
		if(!r){
			r=st->cls->submit(st,b);
			if(r)xdev_ext_mech_sess_batch_end(&side->s.ss,false);
		}
	}
	free(info);
	free(scratch);
	stack_record((struct stack_event){
		.kind=STACK_EV_START_RESULT,.endpoint=e,.session_id=side->s.id,.stage_index=index,.group=key,.status=r
	}
	);
	if(!r)side->nb++;
	if(r)fprintf(stderr,"STACK_DIAG submit endpoint=%u result=%d\n",e,r);
	return r;
}
static bool finalize(unsigned e,struct epoch *s){
	for(unsigned i=0;i<s->nb;i++){
		struct xdev_ext_mech_batch*b=&s->b[i];
		if(b->publishes&&!b->cqe_filled){
			struct xdev_ext_xdomain_mech_cqe c={
			}
			;
			s->s.st.cls->fill_cqe(&s->s.st,b,&c);
			b->cqe_filled=true;
			b->group=c.group;
			if(c.status)stack_record((struct stack_event){
				.kind=STACK_EV_FAILURE,.endpoint=e,.session_id=s->s.id,.group=c.group,.status=c.status,.flags=c.outcome
			}
			);
			struct xdev_ext_binding_ctx_v2 base=base_for(&s->s.st,b);
			struct xdev_ext_mech_call_args a={
				.member=XDEV_EXT_MECH_MEMBER_COMPLETE,
				.callsite=XDEV_EXT_MECH_SITE_WORKER,
				.base=&base,
				.b=b,
				.cqe=&c,
				.cqe_size=sizeof(c),
				.cqe_cap=1
			}
			;
			s32 ret;
			stack_x6_call(&s->s.st,&a,&ret);
			stack_record((struct stack_event){
				.kind=STACK_EV_PUBLISH,.endpoint=e,.session_id=s->s.id,.stage_index=s->s.st.index,.group=c.group,.seq=b->key,.length=c.bytes,.bytes=c.bytes,.elems_done=c.elems_done,.status=c.status,.flags=c.outcome,.control_type=c.remote
			}
			);
			return true;
		}
	}
	return false;
}
#ifndef STACK_REAL_NHI
static struct native*matching_rx(struct native*t){
	for(unsigned i=0;i<world->nn;i++){
		struct native*r=&world->n[i];
		if(r->live&&!r->lost&&!r->delivered&&!r->r->is_tx&&r->r->endpoint!=t->r->endpoint&&r->r->control==t->r->control&&r->r->channel==t->r->channel&&!r->r->freed&&r->r->running)return r;
	}
	return NULL;
}
static bool one_native(void){
	for(unsigned j=0;j<world->nn;j++){
		struct native*r=&world->n[j];
		unsigned e=r->r->endpoint;
		if(r->live&&!r->r->is_tx&&!r->r->control&&r->delivered&&!r->lost&&!world->hold_callbacks[e]){
			invoke(r,false);
			return true;
		}
	}
	for(unsigned i=0;i<world->nn;i++){
		struct native*t=&world->n[i];
		if(!t->live||!t->r->is_tx||t->r->freed||t->held||t->lost)continue;
		unsigned e=t->r->endpoint;
		if(t->r->control){
			if(world->hold_controls[e]&&(!world->hold_control_type[e]||world->hold_control_type[e]==t->raw[5]))continue;
			if(t->delivered){
				if(t->replay)t->live=false;
				else invoke(t,false);
				return true;
			}
			struct native*r=matching_rx(t);
			if(!r)continue;
			for(unsigned k=0;k<world->nf;k++){
				struct stack_fault*f=&world->faults[k];
				if(f->kind==STACK_FAULT_CORRUPT_CONTROL&&f->endpoint==e&&(!f->control_type||f->control_type==t->raw[5])&&(!f->ordinal||f->ordinal==t->id)){
					if(f->arg0<t->raw_len)t->raw[f->arg0]^=1;
					if(f->arg1==2){
						u32 c=~crc32c(~0U,t->raw,124);
						for(unsigned b=0;b<4;b++)t->raw[124+b]=c>>(8*b);
					}
					f->kind=0;
				}
			}
			memcpy((void*)(uintptr_t)r->f->buffer_phy,t->raw,t->raw_len);
			r->f->size=t->raw_len;
			r->f->flags=0;
			struct stack_event ev={
				.kind=STACK_EV_CONTROL_RX,
				.endpoint=1-e,
				.control=1,
				.direction=2,
				.owner=(uintptr_t)r->f,
				.length=t->raw_len,
				.raw_len=t->raw_len,
				.control_type=t->raw[5]
			}
			;
			memcpy(ev.raw,t->raw,t->raw_len);
			stack_record(ev);
			t->delivered=true;
			u64 dropped=link(1-e)->ctl_dropped;
			invoke(r,false);
			if(link(1-e)->ctl_dropped!=dropped)stack_record((struct stack_event){
				.kind=STACK_EV_REJECT,.endpoint=1-e,.control=1,.control_type=t->raw[5],.length=link(1-e)->ctl_dropped-dropped
			}
			);
			if(t->replay)t->live=false;
			else invoke(t,false);
			for(unsigned k=0;k<world->nf;k++){
				struct stack_fault*f=&world->faults[k];
				if(f->kind==STACK_FAULT_DUP_CONTROL&&f->endpoint==e&&(!f->control_type||f->control_type==t->raw[5])){
					assert(world->nn<STACK_NATIVE);
					struct native*dup=&world->n[world->nn++];
					*dup=*t;
					dup->live=true;
					dup->delivered=false;
					dup->replay=true;
					dup->held=false;
					f->kind=0;
				}
			}
			return true;
		}
		if(!t->delivered){
			struct native*r=matching_rx(t);
			if(!r)continue;
			unsigned re=r->r->endpoint;
			r->f->size=world->rx_length_set[re]?world->rx_length[re]:(r->len==4096?0:r->len);
			r->f->flags=world->rx_flags[re];
			world->rx_length_set[re]=false;
			world->rx_flags[re]=0;
			t->delivered=true;
			r->delivered=true;
			if(world->drop_callback[re]){
				r->lost=true;
				world->drop_callback[re]=false;
			}
			else if(!world->hold_callbacks[re])invoke(r,false);
			return true;
		}
		if(world->drop_callback[e]){
			t->lost=true;
			world->drop_callback[e]=false;
			return true;
		}
		if(world->hold_callbacks[e])continue;
		invoke(t,false);
		return true;
	}
	return false;
}
/* The readiness scan is observational: idle posted RX storage, deliberately
 * held work and lost callbacks do not consume a budget or masquerade as work.
 * Every selected action reserves a step before any production callback runs. */
static struct native *native_ready(void)
{
 for(unsigned i=0;i<world->nn;i++){
  struct native *r=&world->n[i];
  if(r->live&&!r->r->is_tx&&!r->r->control&&r->delivered&&!r->lost&&
     !r->r->freed&&!world->hold_callbacks[r->r->endpoint])return r;
 }
 for(unsigned i=0;i<world->nn;i++){
  struct native *t=&world->n[i];
  if(!t->live||!t->r->is_tx||t->r->freed||t->held||t->lost)continue;
  unsigned endpoint=t->r->endpoint;
  if(t->r->control){
   if(world->hold_controls[endpoint]&&(!world->hold_control_type[endpoint]||
      world->hold_control_type[endpoint]==t->raw[5]))continue;
   if(t->delivered||matching_rx(t))return t;
  }else if(!t->delivered){
   if(matching_rx(t))return t;
  }else if(world->drop_callback[endpoint]||!world->hold_callbacks[endpoint])return t;
 }
 return NULL;
}
#endif /* !STACK_REAL_NHI: model native delivery */
static bool finalize_ready(const struct epoch *epoch)
{
 for(unsigned i=0;i<epoch->nb;i++)
  if(epoch->b[i].publishes&&!epoch->b[i].cqe_filled)return true;
 return false;
}
static void scheduler_step(struct stack_world *w,unsigned budget,unsigned *used,
                           unsigned kind,unsigned endpoint,u64 session_id)
{
 assert(*used<budget);
 (*used)++;
 stack_record((struct stack_event){.kind=STACK_EV_SCHED_STEP,.endpoint=endpoint,
  .session_id=session_id,.seq=w->pump_serial,.bytes=*used,.length=budget,.flags=kind});
}
int stack_pump(struct stack_world *w,unsigned budget,uint64_t advance)
{
 if(w!=world)return -EINVAL;
 worker_safe();
 if(__builtin_add_overflow(w->now,advance,&w->now))return -EOVERFLOW;
 jiffies=nsecs_to_jiffies(w->now);
 w->pump_serial++;
 unsigned used=0;
 for(;;){
  struct work_struct *work=NULL;
  unsigned work_index=0;
  for(unsigned i=0;i<w->nwork;i++)
   if(w->work[i]->pending&&w->work[i]->due<=w->now){work=w->work[i];work_index=i;break;}
  if(work){
   if(used==budget)return -ELOOP;
   for(unsigned endpoint=0;endpoint<2;endpoint++){
    if(!w->side[endpoint].probed||w->side[endpoint].removed)continue;
    struct xdev_ext_xd_link *xl=link(endpoint);
    if(work==&xl->login_work.work||work==&xl->connect_work||work==&xl->down_work)
     w->active=endpoint;
   }
   scheduler_step(w,budget,&used,STACK_STEP_WORK,w->active,0);
   work->pending=false;
   /* Keep the deterministic workqueue FIFO. Swapping the newest entry here
    * can run a later LOGIN before already queued receive-path setup. */
   w->nwork--;
   memmove(&w->work[work_index],&w->work[work_index+1],
           (w->nwork-work_index)*sizeof(w->work[0]));
   work->fn(work);
   continue;
  }
  struct epoch *selected=NULL;
  unsigned selected_endpoint=0;
  for(unsigned endpoint=0;endpoint<2&&!selected;endpoint++)
   for(unsigned i=0;i<w->side[endpoint].nr_epochs;i++){
    struct epoch *epoch=w->side[endpoint].epochs[i];
    if(epoch->bound&&(epoch->s.kicked||epoch->next_progress<=w->now)){
     selected=epoch;selected_endpoint=endpoint;break;
    }
   }
  if(selected){
   if(used==budget)return -ELOOP;
   scheduler_step(w,budget,&used,STACK_STEP_PROGRESS,selected_endpoint,selected->s.id);
   selected->s.kicked=false;
   selected->next_progress=w->now+
    selected->s.st.cls->progress(&selected->s.st)*NSEC_PER_MSEC;
   continue;
  }
  for(unsigned endpoint=0;endpoint<2&&!selected;endpoint++)
   for(unsigned i=0;i<w->side[endpoint].nr_epochs;i++){
    struct epoch *epoch=w->side[endpoint].epochs[i];
    if(epoch->bound&&finalize_ready(epoch)){selected=epoch;selected_endpoint=endpoint;break;}
   }
  if(selected){
   if(used==budget)return -ELOOP;
   scheduler_step(w,budget,&used,STACK_STEP_FINALIZE,selected_endpoint,selected->s.id);
   assert(finalize(selected_endpoint,selected));
   continue;
  }
#ifdef STACK_REAL_NHI
  struct tb_ring *notify = native_notify_ready();
  if (notify) {
   if (used == budget) return -ELOOP;
   scheduler_step(w, budget, &used, STACK_STEP_NHI_NOTIFY,
                  ring_info(notify)->endpoint, 0);
   tb_ring_notify(notify);
   continue;
  }
  struct tb_ring *poll = native_poll_ready();
  if (poll) {
   if (used == budget) return -ELOOP;
   scheduler_step(w, budget, &used, STACK_STEP_NHI_POLL,
                  ring_info(poll)->endpoint, 0);
   assert(stack_nhi_poll_one(poll));
   continue;
  }
#endif
  struct native *native=native_ready();
  if(native){
   if(used==budget)return -ELOOP;
   scheduler_step(w,budget,&used,STACK_STEP_NATIVE,ring_info(native->r)->endpoint,native->session_id);
   assert(one_native());
   continue;
  }
  return 0;
 }
}
int stack_release(struct stack_world*w,unsigned e,uint64_t key){
	if(w!=world||e>1||(!w->side[e].current||!w->side[e].current->bound))return -EINVAL;
	struct epoch*s=w->side[e].current;
	for(unsigned i=0;i<s->nb;i++){
		struct xdev_ext_mech_batch*b=&s->b[i];
		if(b->key!=key)continue;
		if(b->released)return -EALREADY;
		if(!b->cqe_filled)return -EAGAIN;
		s->s.st.cls->batch_end(&s->s.st,b,b->status);
		/* External core disposition must precede the actual CHAIN_END callback. */xdev_ext_mech_sess_batch_end(&s->s.ss,b->sequester);
		b->released=true;
		stack_record((struct stack_event){
			.kind=STACK_EV_BATCH_RELEASE,.endpoint=e,.session_id=s->s.id,.group=b->group,.seq=key,.status=b->status,.flags=b->sequester
		}
		);
		s->s.st.cls->batch_release(&s->s.st,b,b->sequester);
		return 0;
	}
	return -ENOENT;
}
int stack_stop(struct stack_world*w,unsigned e){
	if(w!=world||e>1||(!w->side[e].current||!w->side[e].current->bound))return -EINVAL;
	struct xdev_ext_mech_session*s=&w->side[e].current->s;
	if(!xdev_ext_mech_sess_stop(&s->ss))s->stop_started_ns=w->now;
	s->kicked=true;
	worker_safe();
	s->st.cls->progress(&s->st);
	for(unsigned i=0;i<w->side[e].current->nb;i++){
		struct xdev_ext_mech_batch*b=&w->side[e].current->b[i];
		if(b->cqe_filled&&!b->released)stack_release(w,e,b->key);
	}
	u32 pending=0,
	uncertain=0;
	s->st.cls->transport_stats(&s->st,&pending,&uncertain);
	int r=s->ss.inflight||s->ss.sequestered||s->native_controls||pending||uncertain?-EAGAIN:0;
	if(!r)xdev_ext_mech_sess_drain(&s->ss,false);
	stack_record((struct stack_event){
		.kind=STACK_EV_STOP_RESULT,.endpoint=e,.session_id=s->id,.status=r,.flags=s->native_controls,.length=pending
	}
	);
	return r;
}
int stack_remove(struct stack_world*w,unsigned e){
	if(w!=world||e>1||!w->side[e].probed||w->side[e].removed)return -EINVAL;
	w->active=e;
	stack_x3_remove(&w->side[e].svc);
	w->side[e].removed=true;
	stack_x4_quarantine_records();
	fprintf(stderr,"STACK_DIAG remove endpoint=%u pci_refs=%u\n",e,w->side[e].pci.refs);
	return 0;
}
int stack_suspend(struct stack_world*w,unsigned e){
	if(w!=world||e>1||!w->side[e].probed||w->side[e].removed)return -EINVAL;
	w->active=e;
	return stack_x3_suspend(&w->side[e].svc);
}
int stack_resume(struct stack_world*w,unsigned e){
	if(w!=world||e>1||!w->side[e].probed||w->side[e].removed)return -EINVAL;
	w->active=e;
	return stack_x3_resume(&w->side[e].svc);
}
size_t stack_log_count(const struct stack_world*w){
	return w->logs;
}
int stack_log_get(const struct stack_world*w,size_t i,struct stack_event*out){
	if(!out||i>=w->logs)return -ERANGE;
	*out=w->log[i];
	return 0;
}
static struct native*native_id(u64 id){
	for(unsigned i=0;i<world->nn;i++)if(world->n[i].id==id)return &world->n[i];
	if(id&&id<=world->logs){
		struct stack_event*e=&world->log[id-1];
		for(unsigned i=0;i<world->nn;i++)if((uintptr_t)world->n[i].f==e->owner&&world->n[i].seq==e->seq)return &world->n[i];
	}
	return NULL;
}
int stack_fault(struct stack_world*w,const struct stack_fault*f){
	if(w!=world||!f||f->endpoint>1)return -EINVAL;
#ifdef STACK_REAL_NHI
	/* These old model injections bypass descriptor ownership. Refuse them
	 * explicitly rather than accepting an event the NHI backend cannot run. */
	if (f->kind == STACK_FAULT_CORRUPT_CONTROL ||
	    f->kind == STACK_FAULT_DUP_CONTROL ||
	    f->kind == STACK_FAULT_REPLAY_CONTROL)
		return -EOPNOTSUPP;
#endif
	unsigned e=f->endpoint;
	struct native*n=f->ordinal?native_id(f->ordinal):NULL;
	switch(f->kind){
		case STACK_FAULT_HOLD_CALLBACK:w->hold_callbacks[e]=true;
		break;
		case STACK_FAULT_DROP_CALLBACK:w->drop_callback[e]=true;
		break;
		case STACK_FAULT_RELEASE_CALLBACKS:w->hold_callbacks[e]=false;
		for(unsigned i=0;i<w->nn;i++)if(ring_info(w->n[i].r)->endpoint==e)w->n[i].held=false;
		break;
		case STACK_FAULT_HOLD_CONTROL:w->hold_controls[e]=true;
		w->hold_control_type[e]=f->control_type;
		break;
		case STACK_FAULT_DROP_CONTROL:w->drop_control[e]=true;
		w->drop_control_type[e]=f->control_type;
		break;
		case STACK_FAULT_RELEASE_CONTROLS:w->hold_controls[e]=false;
		w->control_refuse[e]=false;
		if(w->side[e].probed&&!w->side[e].removed)stack_x4_control_pressure(link(e),false);
		for(unsigned i=0;i<w->nn;i++)if(ring_info(w->n[i].r)->endpoint==e&&ring_info(w->n[i].r)->control)w->n[i].held=false;
		break;
		case STACK_FAULT_RING_REFUSE:w->ring_refuse[e]=true;
		break;
		case STACK_FAULT_CONTROL_REFUSE:w->control_refuse[e]=!!f->arg0;
		stack_x4_control_pressure(link(e),!!f->arg0);
		break;
		case STACK_FAULT_RX_FLAGS:w->rx_flags[e]=f->arg0;
		break;
		case STACK_FAULT_RX_LENGTH:w->rx_length[e]=f->arg0;
		w->rx_length_set[e]=true;
		break;
		case STACK_FAULT_GOING_AWAY:w->side[e].nhi.going_away=true;
		break;
		case STACK_FAULT_STOP_RESULT:w->stop_result[e]=f->arg0;
		break;
		case STACK_FAULT_BPF_INTENT:w->policy[e]=f->arg0;
		if(w->side[e].current)w->side[e].current->s.kicked=true;
		break;
		case STACK_FAULT_SHIFT_OFFSET:if(w->cfg.nr_frames)w->cfg.span[0].data_off+=f->arg0?f->arg0:4096;
		break;
		case STACK_FAULT_DUP_CALLBACK:case STACK_FAULT_REPLAY_CALLBACK:
#ifdef STACK_REAL_NHI
   (void)n;
   return -EOPNOTSUPP;
#else
   if(n){
			invoke(n,false);
			if(f->kind==STACK_FAULT_DUP_CALLBACK)invoke(n,false);
		}
		else if(!f->ordinal)w->duplicate_callback[e]++;
		else return -ENOENT;
		break;
#endif
		case STACK_FAULT_REPLAY_HANDLER:if(!f->ordinal||f->ordinal>w->logs)return -ENOENT;
		{
			struct stack_event old=w->log[f->ordinal-1];
			handler_record(e,old.raw,old.raw_len);
			w->handler->callback(old.raw,old.raw_len,w->handler->data);
		}
		break;
		case STACK_FAULT_REPLAY_CONTROL:if(!f->ordinal||f->ordinal>w->logs)return -ENOENT;
		{
			struct stack_event old=w->log[f->ordinal-1];
			if(!old.raw_len||old.raw_len>STACK_CTL_BYTES)return -EINVAL;
			assert(w->nn<STACK_NATIVE);
			struct native*r=&w->n[w->nn++];
			*r=(struct native){
				.r=link(1-e)->ctl_tx,
				.live=true,
				.replay=true,
				.raw_len=old.raw_len
			}
			;
			memcpy(r->raw,old.raw,old.raw_len);
		}
		break;
		case STACK_FAULT_CORRUPT_CONTROL:case STACK_FAULT_DUP_CONTROL:if(w->nf>=STACK_FAULTS)return -ENOSPC;
		w->faults[w->nf++]=*f;
		break;
		default:return -EINVAL;
	}
	return 0;
}
void stack_destroy(struct stack_world *w)
{
 if(!w||w!=world)return;
 for(unsigned endpoint=0;endpoint<2;endpoint++)
  if(w->side[endpoint].probed&&!w->side[endpoint].removed)stack_remove(w,endpoint);
 bool retain_world=false;
 for(unsigned endpoint=0;endpoint<2;endpoint++){
  struct side *side=&w->side[endpoint];
  for(unsigned i=0;i<side->nr_epochs;i++){
   struct epoch *epoch=side->epochs[i];
   bool held=epoch->s.native_controls||epoch->s.ss.inflight||epoch->s.ss.sequestered;
   for(unsigned k=0;k<nleases;k++)
    if(leases[k].session_id==epoch->s.id&&(leases[k].live||leases[k].retained))held=true;
   if(held){retain_world=true;continue;}
   if(epoch->bound){epoch->s.st.cls->unbind(&epoch->s.st);epoch->bound=false;}
   for(unsigned k=0;k<STACK_BATCHES;k++){
    free(epoch->b[k].priv);free(epoch->b[k].cookie);
   }
   free(epoch);side->epochs[i]=NULL;
  }
 }
 stack_x3_exit();
#ifdef STACK_REAL_NHI
 for (unsigned endpoint = 0; endpoint < 2; endpoint++)
  stack_nhi_destroy(&w->side[endpoint].nhi);
#else
 for(unsigned i=0;i<w->nrings;i++)if(!w->rings[i]->unknown)free(w->rings[i]);
#endif
 for(unsigned endpoint=0;endpoint<2;endpoint++)retain_world|=w->side[endpoint].pci.refs>1;
 if(retain_world){
  assert(stack_retained_count<ARRAY_SIZE(stack_retained_worlds));
  stack_retained_worlds[stack_retained_count++]=w;
 }else{free(w->n);free(w->log);free(w);}
 world=NULL;
}

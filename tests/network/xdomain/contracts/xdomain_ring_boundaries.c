/* SPDX-License-Identifier: GPL-2.0 */
/* Only upstream/environment/family sinks. X4 ownership stays production. */
static struct xdev_ext_xd_link *fixture_xl;
static struct pci_dev fixture_pdev = {.dev={.id=71,.name="0000:2d:00.0"}};
static struct tb_nhi fixture_nhi = {.pdev=&fixture_pdev,.hop_count=256};
static struct tb fixture_tb = {.nhi=&fixture_nhi};
static struct tb_xdomain fixture_xd = {.tb=&fixture_tb,.dev={.name="7-1234ab"}};
static struct tb_ring *all_rings[16];
static unsigned ring_nr,acquire_step,fail_acquire_step,ring_frees,ring_dma_reads;
static unsigned starts,fail_start_at,stops,stop_hop[32],stop_nr;
static bool going_late_normal,stop_complete_normal,stop_rx_normal;
static struct tb_ring *late_normal_ring;
static unsigned fault_countdown;
static bool fail_fresh(void) { return fault_countdown && !--fault_countdown; }
static bool stop_nhi_gone,down_on_first_data_enqueue,down_requested,in_unlock;
static unsigned data_native_calls,duplicate_native_calls;
static struct ring_frame *native_seen[256];
static unsigned native_seen_nr;
static unsigned dma_allocs,dma_frees;
static bool callback_reads_buffer,require_ctl_rx_lock;
static struct { void *p; size_t bytes; dma_addr_t dma; bool freed; } dma_records[64];
static bool alloc_failed(void) { return ++acquire_step==fail_acquire_step; }
static unsigned heap_allocs,heap_frees,heap_attempts,heap_fail_at;
static bool heap_fail;
static void *kzalloc(size_t n,int flags)
{ if(heap_fail || ++heap_attempts==heap_fail_at || fail_fresh()) return NULL; void *p=calloc(1,n); assert(p); heap_allocs++; return p; }
static void kfree(void *p) { if(p) { heap_frees++; free(p); } }

static bool spawn_close_worker,spawn_early_ctl_worker,close_worker_pending,early_worker_pending;
static pthread_t close_thread,early_thread;
static atomic_bool worker_started;
static void invoke_frame(struct tb_ring *,struct ring_frame *,bool);
static struct ring_frame *take_frame(struct tb_ring *,unsigned);
static struct {struct tb_ring *r;struct ring_frame *f;} early_arg;
static void *close_worker(void *unused)
{
    atomic_store(&worker_started,true);
    spin_lock_irq(&fixture_xl->lock);fixture_xl->up=false;spin_unlock_irq(&fixture_xl->lock);
    mutex_lock(&fixture_xl->ctl_mutex);xdev_ext_xd_rings_stop(fixture_xl);mutex_unlock(&fixture_xl->ctl_mutex);
    return NULL;
}
static void *early_ctl_worker(void *unused)
{
    atomic_store(&worker_started,true);
    invoke_frame(early_arg.r,early_arg.f,false);return NULL;
}
static void fixture_unlock(spinlock_t *s)
{
    if(fixture_xl && s==&fixture_xl->lock) {
        if(close_worker_pending && !pthread_equal(pthread_self(),close_thread)) {
            assert(!pthread_join(close_thread,NULL));close_worker_pending=false;
        }
        if(early_worker_pending && !pthread_equal(pthread_self(),early_thread)) {
            assert(!pthread_join(early_thread,NULL));early_worker_pending=false;
        }
    }
    if(!fixture_xl || s!=&fixture_xl->lock || !down_requested || in_unlock) return;
    in_unlock=true;
    down_requested=false;
    /* A competing link-down acquires the same lock only after the post drops it. */
    spin_lock_irq(s); fixture_xl->up=false; spin_unlock_irq(s);
    mutex_lock(&fixture_xl->ctl_mutex);
    xdev_ext_xd_rings_stop(fixture_xl);
    mutex_unlock(&fixture_xl->ctl_mutex);
    in_unlock=false;
}
static struct tb_ring *ring_alloc(struct tb_nhi *nhi,int size,unsigned flags,bool tx)
{
    assert(!active_spins);
    if(alloc_failed()) return NULL;
    assert(ring_nr<ARRAY_SIZE(all_rings));
    struct tb_ring *r=calloc(1,sizeof(*r)); assert(r);
    *r=(struct tb_ring){.nhi=nhi,.size=size,.hop=(int)ring_nr+40,.flags=flags,.is_tx=tx};
    all_rings[ring_nr++]=r;
    return r;
}
static struct tb_ring *tb_ring_alloc_tx(struct tb_nhi *n,int hop,int size,unsigned flags)
{ assert(hop==-1); return ring_alloc(n,size,flags,true); }
static struct tb_ring *tb_ring_alloc_rx(struct tb_nhi *n,int hop,int size,unsigned flags,
                                      int e2e,u16 sof,u16 eof,void (*poll)(void *),void *arg)
{ assert(hop==-1 && sof==2 && eof==4 && !poll && !arg); assert(e2e>=40); return ring_alloc(n,size,flags,false); }
static void tb_ring_start(struct tb_ring *r)
{
    assert(!active_spins && !inside_callback && fixture_xl->ctl_mutex.held);
    assert(r && !r->freed && !r->running);
    if(++starts!=fail_start_at && !r->nhi->going_away) r->running=true;
}
static struct ring_frame *take_frame(struct tb_ring *r,unsigned k)
{
    assert(k<r->queued_nr);
    struct ring_frame *f=r->queued[k];
    memmove(r->queued+k,r->queued+k+1,(r->queued_nr-k-1)*sizeof(r->queued[0]));
    r->queued_nr--; return f;
}
static void invoke_frame(struct tb_ring *r,struct ring_frame *f,bool canceled)
{
    bool control=(r==fixture_xl->ctl_rx || r==fixture_xl->ctl_tx);
    if(control) {
        /* The NHI callback may still read the coherent bytes until its barrier.
         * Even normal completion does not permit free before callback returns. */
        void *buf=(void *)(uintptr_t)f->buffer_phy;
        for(unsigned i=0;i<dma_allocs;i++) if((u8 *)buf>=(u8 *)dma_records[i].p &&
                (u8 *)buf<(u8 *)dma_records[i].p+dma_records[i].bytes) assert(!dma_records[i].freed);
        callback_reads_buffer=true;
        volatile u8 sentinel=*(u8 *)buf; (void)sentinel;
    }
    inside_callback++; f->callback(r,f,canceled); inside_callback--;
    callback_reads_buffer=false;
}
static void complete_frame(struct tb_ring *r,unsigned k,u32 size,u32 flags)
{ struct ring_frame *f=take_frame(r,k); f->size=size; f->flags=flags; invoke_frame(r,f,false); }
static void tb_ring_stop(struct tb_ring *r)
{
    assert(!active_spins && !inside_callback && !fixture_xl->ep_mutex.held);
    assert(fixture_xl->ctl_mutex.held && r && !r->freed && r->running);
    stops++; stop_hop[stop_nr++]=r->hop;
    if(stop_nhi_gone || r->nhi->going_away) {
        /* Upstream stop still schedules/flushes ring_work; completed entries
         * can return normally even though running remains true. */
        if(going_late_normal && (!late_normal_ring || r==late_normal_ring) && r->queued_nr) {
            going_late_normal=false; complete_frame(r,0,128,0);
        }
        return;
    }
    r->running=false;
    while(r->queued_nr) invoke_frame(r,take_frame(r,0),!(stop_complete_normal || (stop_rx_normal && r==fixture_xl->ctl_rx)));
}
static unsigned descriptor_quarantines;
static void tb_ring_free(struct tb_ring *r)
{ assert(!active_spins && !inside_callback && !r->freed && !r->running); r->freed=true; ring_frees++; }
/* Ring-glue environment only. The NHI fixture separately executes the real
 * helper and proves IRQ/work/descriptor retirement; this stub makes no NHI claim. */
static void tb_ring_free_quarantined(struct tb_ring *r)
{
    assert(!active_spins && !inside_callback && !r->freed);
    r->running=false;
    while(r->queued_nr) invoke_frame(r,take_frame(r,0),true);
    r->freed=true; descriptor_quarantines++;
}
static int enqueue(struct tb_ring *r,struct ring_frame *f,bool tx)
{
    assert(r && !r->freed && r->is_tx==tx);
    r->enqueue_calls++;
    if(!r->running) return -ESHUTDOWN;
    /* Data/control TX must serialize the *real* decision with link down. */
    bool data=(r==fixture_xl->chan[0].tx || r==fixture_xl->chan[0].rx);
    if(data || tx || (require_ctl_rx_lock && inside_callback)) assert(fixture_xl->lock.held);
    if(data) {
        data_native_calls++;
        if(spawn_close_worker) {
            spawn_close_worker=false;atomic_store(&worker_started,false);
            assert(!pthread_create(&close_thread,NULL,close_worker,NULL));close_worker_pending=true;
            while(!atomic_load(&worker_started)) sched_yield();
        }
        for(unsigned i=0;i<native_seen_nr;i++) if(native_seen[i]==f) duplicate_native_calls++;
        assert(native_seen_nr<ARRAY_SIZE(native_seen)); native_seen[native_seen_nr++]=f;
        if(down_on_first_data_enqueue) { down_requested=true; down_on_first_data_enqueue=false; }
    }
    for(unsigned i=0;i<r->queued_nr;i++) assert(r->queued[i]!=f);
    assert(r->queued_nr<ARRAY_SIZE(r->queued)); r->queued[r->queued_nr++]=f;
    if(tx && r==fixture_xl->ctl_tx && spawn_early_ctl_worker) {
        spawn_early_ctl_worker=false;
        early_arg=(typeof(early_arg)){r,take_frame(r,r->queued_nr-1)};
        atomic_store(&worker_started,false);
        assert(!pthread_create(&early_thread,NULL,early_ctl_worker,NULL));early_worker_pending=true;
        while(!atomic_load(&worker_started)) sched_yield();
    }
    return 0;
}
static int tb_ring_tx(struct tb_ring *r,struct ring_frame *f) { return enqueue(r,f,true); }
static int tb_ring_rx(struct tb_ring *r,struct ring_frame *f) { return enqueue(r,f,false); }
/* Ring-glue recorder only. Real *_more descriptor publication and notify are
 * verified by xdomain_native_progress_test.py with actual nhi.c, not here. */
static int tb_ring_tx_more(struct tb_ring *r,struct ring_frame *f) { return enqueue(r,f,true); }
static int tb_ring_rx_more(struct tb_ring *r,struct ring_frame *f) { return enqueue(r,f,false); }
static void tb_ring_notify(struct tb_ring *r)
{
    assert(r && !r->freed && r->running && fixture_xl->lock.held);
    r->notify_calls++;
}
static struct device *tb_ring_dma_device(struct tb_ring *r)
{ ring_dma_reads++; assert(r && !r->freed && r->nhi); return &r->nhi->pdev->dev; }
static void *dma_alloc_coherent(struct device *dev,size_t n,dma_addr_t *dma,int flags)
{
    assert(!active_spins && dev==&fixture_pdev.dev);
    if(alloc_failed() || fail_fresh()) return NULL;
    assert(dma_allocs<ARRAY_SIZE(dma_records));
    void *p=calloc(1,n); assert(p); *dma=(dma_addr_t)p;
    dma_records[dma_allocs++]=(typeof(dma_records[0])){p,n,*dma,false}; return p;
}
static void dma_free_coherent(struct device *dev,size_t n,void *p,dma_addr_t dma)
{
    assert(!active_spins && !callback_reads_buffer && dev==&fixture_pdev.dev);
    for(unsigned i=0;i<dma_allocs;i++) if(dma_records[i].p==p) {
        assert(!dma_records[i].freed && dma_records[i].bytes==n && dma_records[i].dma==dma);
        dma_records[i].freed=true; dma_frees++; return;
    }
    assert(!"foreign DMA free");
}
static struct { int id; bool in,released; } hops[16];
static unsigned hop_nr,hop_releases,in_alloc_calls,in_mismatch_at,in_negative_at;
static int hop_alloc(bool in,int requested)
{
    if(!in && alloc_failed()) return -ENOMEM;
    if(in) {
        in_alloc_calls++;
        if(in_alloc_calls==in_negative_at) return -ENOMEM;
        if(in_alloc_calls==in_mismatch_at) requested+=1;
    }
    int id=in?requested:80+(int)hop_nr;
    assert(hop_nr<ARRAY_SIZE(hops)); hops[hop_nr++]=(typeof(hops[0])){id,in,false}; return id;
}
static int tb_xdomain_alloc_in_hopid(struct tb_xdomain *xd,int id)
{ assert(xd==&fixture_xd); return hop_alloc(true,id); }
static int tb_xdomain_alloc_out_hopid(struct tb_xdomain *xd,int id)
{ assert(xd==&fixture_xd && id==-1); return hop_alloc(false,id); }
static void hop_release(bool in,int id)
{
    assert(id>=0);
    for(unsigned i=0;i<hop_nr;i++) if(hops[i].id==id && hops[i].in==in && !hops[i].released) {
        hops[i].released=true; hop_releases++; return;
    }
    assert(!"unowned/double HopID release");
}
static void tb_xdomain_release_in_hopid(struct tb_xdomain *xd,int id) { hop_release(true,id); }
static void tb_xdomain_release_out_hopid(struct tb_xdomain *xd,int id) { hop_release(false,id); }
static struct { int tx_path,tx_ring,rx_path,rx_ring; bool disabled; } paths[8];
static unsigned path_nr,path_attempts,fail_path_at,path_disables;
static int tb_xdomain_enable_paths(struct tb_xdomain *xd,int tp,int tr,int rp,int rr)
{
    assert(!active_spins && fixture_xl->ctl_mutex.held && xd==&fixture_xd);
    if(++path_attempts==fail_path_at) return -EIO;
    paths[path_nr++]=(typeof(paths[0])){tp,tr,rp,rr,false}; return 0;
}
static int tb_xdomain_disable_paths(struct tb_xdomain *xd,int tp,int tr,int rp,int rr)
{
    assert(!active_spins && fixture_xl->ctl_mutex.held && xd==&fixture_xd);
    /* A later retry may re-enable the same native tuple. Retire its newest
     * ACTIVE acquisition; historical disabled records remain in the ledger. */
    for(unsigned k=path_nr;k>0;k--) {
        unsigned i=k-1;
        if(!paths[i].disabled && paths[i].tx_path==tp && paths[i].tx_ring==tr &&
           paths[i].rx_path==rp && paths[i].rx_ring==rr) {
            paths[i].disabled=true; path_disables++; return 0;
        }
    }
    assert(!"disable unacquired tunnel"); return -EINVAL;
}
static u32 crc32c(u32 crc,const void *p,size_t n)
{ const u8 *b=p; while(n--) { crc^=*b++; for(unsigned bit=0;bit<8;bit++) crc=(crc>>1)^((crc&1)?0x82f63b78U:0); } return crc; }

static struct { struct xdev_ext_net_elem *elem; int status; u32 len,hdr; bool quiesced; } done[256];
static unsigned done_nr;
void xdev_ext_net_elem_done(struct xdev_ext_net_elem *e,int status,u32 len,u32 hdr,bool q)
{
    for(unsigned i=0;i<done_nr;i++) assert(done[i].elem!=e);
    assert(done_nr<ARRAY_SIZE(done)); done[done_nr++]=(typeof(done[0])){e,status,len,hdr,q};
}
static unsigned class_calls,fail_calls;
static bool class_context_dead;
static struct xdev_ext_mech_stage *class_stage;
static struct xdev_ext_xd_msg class_msg;
static int fail_error;
void xdev_ext_xd_class_ctl(struct xdev_ext_mech_stage *st,const struct xdev_ext_xd_msg *msg)
{ assert(!class_context_dead && fixture_xl->ep_mutex.held); class_calls++; class_stage=st; class_msg=*msg; }
/* X5 is not linked into this ring-only recording boundary. */
void xdev_ext_xd_class_detach(struct xdev_ext_mech_stage *st)
{ (void)st; assert(fixture_xl->ep_mutex.held); }
void xdev_ext_xd_link_fail(struct xdev_ext_xd_link *xl,const struct xdev_ext_xd_ep *ep,int err)
{ assert(xl==fixture_xl); fail_calls++; fail_error=err; }
static unsigned link_gets,link_puts;
struct xdev_ext_xd_link *xdev_ext_xd_link_get(u64 token)
{ if(!fixture_xl || token!=fixture_xl->token) return NULL; link_gets++; return fixture_xl; }
void xdev_ext_xd_link_put(struct xdev_ext_xd_link *xl)
{ assert(xl==fixture_xl && link_puts<link_gets); link_puts++; }

static struct pci_dev *pci_dev_get(struct pci_dev *p) { if(p) p->refs++; return p; }
static void pci_dev_put(struct pci_dev *p) { if(p) { assert(p->refs>0); p->refs--; } }

static bool dma_is_freed(void *p)
{ for(unsigned i=0;i<dma_allocs;i++) if(dma_records[i].p==p) return dma_records[i].freed; assert(!"missing coherent allocation"); return false; }

/* Preserve actual printk body, associated device and the real external path
 * invocation count observed at that point. No BEGIN/END is generated here. */
static struct { const struct device *dev;char text[512];unsigned calls; } path_logs[32];
static unsigned path_log_nr;
static void dev_info(const struct device *dev,const char *fmt,...)
{
    char text[512];va_list args;va_start(args,fmt);int n=vsnprintf(text,sizeof(text),fmt,args);va_end(args);
    assert(n>=0 && (size_t)n<sizeof(text));
    if(strncmp(text,"XDEV_EXT_XDOMAIN_PATH ",21))return;
    assert(path_log_nr<ARRAY_SIZE(path_logs));
    path_logs[path_log_nr].dev=dev;path_logs[path_log_nr].calls=path_attempts;
    memcpy(path_logs[path_log_nr++].text,text,(size_t)n+1);
}

static void tb_ring_snapshot(struct tb_ring *r,struct tb_ring_snapshot *out){
 *out=(struct tb_ring_snapshot){.in_flight=r->queued_nr,.running=r->running};
}

/* Unit OS precondition: this ring-only fixture begins after startup verified
 * the data paths. No probe allocation/callback is supplied or certified here.
 * Full startup is exercised by probe_transport_test and the NHI composition. */
void xdev_ext_xd_probe_ctl_complete_locked(struct xdev_ext_xd_link *xl,bool canceled){(void)canceled;assert(!xl->probe);}
void xdev_ext_xd_probe_ctl_error_locked(struct xdev_ext_xd_link *xl,int error){(void)error;assert(!xl->probe);}
bool xdev_ext_xd_probe_ctl_rx(struct xdev_ext_xd_link *xl,const u8 *p,u32 n){
 assert(!xl->probe);assert(n<4||xdev_ext_xd_get(p,4)!=XD_PROBE_CTL_MAGIC);return false;
}
void xdev_ext_xd_probe_close(struct xdev_ext_xd_link *xl){assert(!xl->probe);xl->data_verified_mask=0;}
u64 xdev_ext_xd_probe_retire(struct xdev_ext_xd_link *xl,u32 rx,u32 tx,bool gone){(void)rx;(void)tx;(void)gone;assert(!xl->probe);return 0;}
void xdev_ext_xd_probe_free(struct xdev_ext_xd_link *xl){assert(!xl->probe);}

void xdev_ext_xd_class_ctl_v2(struct xdev_ext_mech_stage *stage,const struct xdev_ext_xd_msg_v2 *msg)
{ (void)stage;(void)msg;assert(!"v2 dispatch outside original v1 ring fixture");abort(); }

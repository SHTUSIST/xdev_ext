/* Each case executes in a fresh process. */
static unsigned parameter;
/* SPDX-License-Identifier: GPL-2.0 */
static struct xdev_ext_xd_link xl;
static struct xdev_ext_xd_ep ep;
static struct xdev_ext_mech_stage tx_stage={.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.id=1};
static struct xdev_ext_mech_stage rx_stage={.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.id=2};
static struct xdev_ext_net_elem elems[8];
static void bare(void)
{
    memset(&xl,0,sizeof(xl)); fixture_xl=&xl;
    xl.xd=&fixture_xd; xl.nhi_pdev=&fixture_pdev;
    xl.channels=1; xl.local_inc=0x1111; xl.remote_inc=0x2222; xl.token=123;
    spin_lock_init(&xl.lock); mutex_init(&xl.ctl_mutex); mutex_init(&xl.ep_mutex);
    ep=(struct xdev_ext_xd_ep){.xl=&xl,.st=&tx_stage,.chan=0};
    for(unsigned i=0;i<ARRAY_SIZE(elems);i++) {
        elems[i]=(struct xdev_ext_net_elem){.len=4096,.buf_len=4096};
        elems[i].lease.lease.dma_address=0x90000000ULL+0x10000*i;
        elems[i].lease.lease.len=4096;
    }
}
static void allocate(void)
{ bare(); assert(xdev_ext_xd_rings_alloc(&xl)==0); }
static void fresh(void)
{
    allocate(); mutex_lock(&xl.ctl_mutex);
    assert(xdev_ext_xd_rings_start(&xl)==0); mutex_unlock(&xl.ctl_mutex);
    xl.up=true; /* X3 already established this device prerequisite. */
}
static void stop_link(void)
{
    spin_lock_irq(&xl.lock); xl.up=false; spin_unlock_irq(&xl.lock);
    mutex_lock(&xl.ctl_mutex); xdev_ext_xd_rings_stop(&xl); mutex_unlock(&xl.ctl_mutex);
}
static unsigned free_ctl(void)
{ unsigned n=0; for(unsigned i=0;i<128;i++) n+=test_bit(i,xl.ctl_tx_free); return n; }
static unsigned running(void)
{ unsigned n=0; for(unsigned i=0;i<ring_nr;i++) n+=all_rings[i]->running; return n; }
static void raw_message(u8 *out,u8 value) { memset(out,value,128); }
static void fill_ctl(void)
{ u8 raw[128]; raw_message(raw,0x31); while(free_ctl()) assert(xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128)==0); }
static struct xdev_ext_xd_msg rts(u64 group,u16 count)
{ return (struct xdev_ext_xd_msg){.type=XDEV_EXT_XD_RTS,.stream=7,.group=group,.count=count,.total_len=4096U*count}; }
static struct xdev_ext_xd_msg incoming(u8 type,u64 group)
{
    struct xdev_ext_xd_msg m={.src_inc=0x2222,.dst_inc=0x1111,.stream=7,.group=group,.type=type};
    if(type==XDEV_EXT_XD_RTS) { m.count=4; m.total_len=16384; }
    if(type==XDEV_EXT_XD_CTS || type==XDEV_EXT_XD_ACK || type==XDEV_EXT_XD_HELD) m.credit=17;
    if(type==XDEV_EXT_XD_FAIL) m.status=EIO;
    return m;
}
static void deliver(struct xdev_ext_xd_msg m)
{
    u8 wire[128]; assert(xdev_ext_xd_msg_encode(wire,&m,crc32c)==0);
    xdev_ext_xd_ctl_dispatch(&xl,wire,128);
}
static struct xdev_ext_xd_login peer_login(void)
{ return (struct xdev_ext_xd_login){.channels=1,.ctl_tx_path=9,.data_tx_path={10}}; }
static void paths_on(void)
{ struct xdev_ext_xd_login p=peer_login(); mutex_lock(&xl.ctl_mutex); assert(!xdev_ext_xd_paths_enable(&xl,&p)); mutex_unlock(&xl.ctl_mutex); }

static void tx_frames_and_once(void)
{
    fresh(); elems[2].len=elems[2].buf_len=904;
    assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems,3)==0);
    struct tb_ring *r=xl.chan[0].tx;
    assert(r->queued_nr==3 && data_native_calls==3 && done_nr==0);
    for(unsigned i=0;i<3;i++) {
        assert(r->queued[i]==(struct ring_frame *)elems[i].dev.bytes);
        assert(r->queued[i]->buffer_phy==0x90000000ULL+0x10000*i);
        assert(r->queued[i]->sof==1 && r->queued[i]->eof==2);
    }
    assert(r->queued[0]->size==0 && r->queued[2]->size==904);
    complete_frame(r,0,0,0); complete_frame(r,0,0,0); complete_frame(r,0,0,0);
    assert(done_nr==3 && done[0].len==4096 && done[2].len==904);
    for(unsigned i=0;i<3;i++) assert(done[i].elem==&elems[i] && !done[i].status && done[i].quiesced && !done[i].hdr);
    stop_link(); assert(done_nr==3 && data_native_calls==3 && !duplicate_native_calls);
}
static void rx_frame_classification(void)
{
    fresh(); ep.rx=true; elems[1].len=904; elems[2].len=1000;
    assert(!xdev_ext_xd_dev_ops.post_rx(&ep,elems,4));
    struct tb_ring *r=xl.chan[0].rx;
    assert(r->queued_nr==4 && r->queued[0]->size==0);
    for(unsigned i=0;i<4;i++) assert(r->queued[i]->buffer_phy==0x90000000ULL+0x10000*i);
    complete_frame(r,0,0,0); complete_frame(r,0,904,1);
    complete_frame(r,0,1000,4); complete_frame(r,0,1234,0);
    assert(done_nr==4 && done[0].status==0 && done[0].len==4096);
    assert(done[1].status==-EBADMSG && done[1].len==0 && (elems[1].dev_flags&1));
    assert(done[2].status==-EOVERFLOW && done[2].len==0);
    assert(done[3].status==-EMSGSIZE && done[3].len==0);
    for(unsigned i=0;i<4;i++) assert(done[i].quiesced);
}
static void stop_cancellation_unknown(void)
{
    fresh(); assert(!xdev_ext_xd_dev_ops.post_rx(&ep,elems,4)); fill_ctl();
    assert(free_ctl()==0); int rxhop=xl.chan[0].rx->hop,txhop=xl.chan[0].tx->hop;
    stop_link(); assert(done_nr==4 && free_ctl()==0 && !running());
    for(unsigned i=0;i<4;i++) assert(done[i].status==-ECANCELED && !done[i].len && !done[i].quiesced);
    assert(stop_nr==4 && stop_hop[0]==(unsigned)rxhop && stop_hop[1]==(unsigned)txhop);
    assert(stop_hop[2]==(unsigned)xl.ctl_rx->hop && stop_hop[3]==(unsigned)xl.ctl_tx->hop);
    stop_link(); assert(done_nr==4 && stop_nr==4 && !duplicate_native_calls);
}
static void going_away_has_no_completion(void)
{
    fresh(); assert(!xdev_ext_xd_dev_ops.post_tx(&ep,elems,2)); fill_ctl();
    stop_nhi_gone=true; stop_link();
    assert(xl.nhi_gone && free_ctl()==0);
    /* Upstream stop generated no completion. The production glue may run its
     * separate software-retirement helper now or at rings_free; either way,
     * accepted backing must stay UNKNOWN and every callback occurs once. */
    assert(done_nr==0 || done_nr==2);
    for(unsigned i=0;i<done_nr;i++)assert(done[i].status==-ECANCELED&&!done[i].quiesced);
    assert(!dma_is_freed(xl.ctl_rx_buf)&&!dma_is_freed(xl.ctl_tx_buf));
    assert(data_native_calls==2 && !duplicate_native_calls);
    /* Family deadline quarantine is X5/F5, never fabricated by this ring shim. */
}
static void post_rejections_are_empty(void)
{
    fresh(); struct tb_ring *r=xl.chan[0].tx;
    xl.up=false; assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems,3)==-ENOLINK);
    xl.up=true; xl.gone=true; assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems,3)==-ENOLINK);
    xl.gone=false; ep.detached=true; assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems,3)==-ENOLINK);
    ep.detached=false; elems[2].len=0;
    assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems,3)==-EINVAL);
    elems[2].len=4097; assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems,3)==-EINVAL);
    assert(!r->queued_nr && !r->enqueue_calls && !data_native_calls && !done_nr);
}
static void rx_full_lease_prevalidation(void)
{
    fresh(); elems[2].buf_len=1000;
    assert(xdev_ext_xd_dev_ops.post_rx(&ep,elems,3)==-EINVAL);
    assert(!xl.chan[0].rx->queued_nr && !xl.chan[0].rx->enqueue_calls && !done_nr);
}
static void post_holds_gate_for_entire_batch(void)
{
    fresh(); down_on_first_data_enqueue=true;
    assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems,3)==0);
    assert(!xl.up && data_native_calls==3 && done_nr==3 && !duplicate_native_calls);
    for(unsigned i=0;i<3;i++) assert(done[i].status==-ECANCELED && !done[i].quiesced);
    assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems+3,1)==-ENOLINK);
    assert(data_native_calls==3 && done_nr==3);
}
static void control_copy_backpressure_and_return(void)
{
    fresh(); u8 raw[128];
    for(unsigned i=0;i<128;i++) {
        raw_message(raw,(u8)i); assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
        memset(raw,0xfe,128); /* accepted record must not borrow caller storage */
    }
    assert(free_ctl()==0 && xl.ctl_tx->queued_nr==128);
    for(unsigned i=0;i<128;i++) {
        struct ring_frame *f=xl.ctl_tx->queued[i]; assert(f->size==128 && f->sof==1 && f->eof==2);
        for(unsigned j=0;j<128;j++) assert(((u8 *)(uintptr_t)f->buffer_phy)[j]==(u8)i);
    }
    assert(xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128)==-EAGAIN);
    assert(xl.ctl_tx->queued_nr==128 && free_ctl()==0);
    complete_frame(xl.ctl_tx,13,0,0); assert(free_ctl()==1);
    raw_message(raw,0xd4); assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    assert(free_ctl()==0 && xl.ctl_tx->queued_nr==128);
    for(unsigned i=0;i<127;i++) { unsigned original=i<13?i:i+1;
        assert(*(u8 *)(uintptr_t)xl.ctl_tx->queued[i]->buffer_phy==(u8)original); }
    assert(*(u8 *)(uintptr_t)xl.ctl_tx->queued[127]->buffer_phy==0xd4);
}
static void control_invalid_and_dead_rollback(void)
{
    fresh(); u8 raw[128]={0};
    assert(xdev_ext_xd_dev_ops.ctl_send(&ep,raw,127)==-EINVAL);
    assert(xdev_ext_xd_dev_ops.ctl_send(&ep,raw,129)==-EINVAL);
    ep.detached=true; assert(xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128)==-ENOLINK);
    ep.detached=false; xl.gone=true; assert(xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128)==-ENOLINK);
    xl.gone=false; xl.up=false; assert(xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128)==-ENOLINK);
    assert(free_ctl()==128 && !xl.ctl_tx->enqueue_calls && !xl.ctl_tx->queued_nr);
}
static void announcement_commit_only_after_queue(void)
{
    fresh(); struct xdev_ext_xd_msg m=rts(5,3);
    assert(!xdev_ext_xd_msg_send(&xl,&ep,0,&m));
    assert(m.src_inc==0x1111 && m.dst_inc==0x2222 && m.data_seq==0 && m.channel==0);
    assert(xl.chan[0].announced==3 && xl.ctl_tx->queued_nr==1);
    struct xdev_ext_xd_msg queued;
    assert(!xdev_ext_xd_msg_decode(xl.ctl_tx_frames[0].buf,128,crc32c,&queued));
    assert(queued.group==5 && queued.count==3 && queued.data_seq==0);
    fill_ctl(); m=rts(6,2);
    assert(xdev_ext_xd_msg_send(&xl,&ep,0,&m)==-EAGAIN && xl.chan[0].announced==3);
    complete_frame(xl.ctl_tx,0,0,0);
    assert(!xdev_ext_xd_msg_send(&xl,&ep,0,&m) && m.data_seq==3 && xl.chan[0].announced==5);
}
static void announcement_error_rollback(void)
{
    fresh(); struct xdev_ext_xd_msg m=rts(1,3); m.credit=2;
    assert(xdev_ext_xd_msg_send(&xl,&ep,0,&m)==-EINVAL);
    m=rts(1,3); assert(xdev_ext_xd_msg_send(&xl,&ep,1,&m)==-EINVAL);
    ep.detached=true; assert(xdev_ext_xd_msg_send(&xl,&ep,0,&m)==-ENOLINK);
    ep.detached=false; xl.up=false; assert(xdev_ext_xd_msg_send(&xl,&ep,0,&m)==-ENOLINK);
    assert(!xl.chan[0].announced && free_ctl()==128 && !xl.ctl_tx->queued_nr);
}
static void consume_exact_sequence_once(void)
{
    fresh(); assert(!xdev_ext_xd_seq_consume(&xl,0,0,3));
    assert(xdev_ext_xd_seq_consume(&xl,0,0,3)==-EPROTO && xl.chan[0].consumed==3);
    assert(xdev_ext_xd_seq_consume(&xl,0,4,2)==-EPROTO && xl.chan[0].consumed==3);
    assert(!xdev_ext_xd_seq_consume(&xl,0,3,2) && xl.chan[0].consumed==5);
    assert(xdev_ext_xd_seq_consume(&xl,1,0,2)==-EINVAL);
    xl.up=false; assert(xdev_ext_xd_seq_consume(&xl,0,5,2)==-ENOLINK && xl.chan[0].consumed==5);
}
static void dispatch_routes_and_rejects_stale(void)
{
    fresh(); struct xdev_ext_xd_ep rx={.xl=&xl,.st=&rx_stage,.rx=true};
    xl.chan[0].ep[0]=&ep; xl.chan[0].ep[1]=&rx;
    deliver(incoming(XDEV_EXT_XD_CTS,2)); assert(class_calls==1 && class_stage==&tx_stage);
    struct xdev_ext_xd_msg stale=incoming(XDEV_EXT_XD_CTS,2); stale.src_inc++;
    deliver(stale); assert(class_calls==1 && xl.ctl_dropped==1);
    deliver(incoming(XDEV_EXT_XD_RTS,3)); assert(class_calls==2 && class_stage==&rx_stage && class_msg.count==4);
    deliver(incoming(XDEV_EXT_XD_CANCEL,3)); assert(class_calls==3 && class_stage==&rx_stage);
    u8 bad[128]={0}; xdev_ext_xd_ctl_dispatch(&xl,bad,128);
    assert(class_calls==3 && xl.ctl_dropped==2 && !fail_calls);
    assert(!xl.chan[0].consumed && !xl.chan[0].announced && !xl.ctl_tx->queued_nr);
}
static void no_receiver_refuses_and_consumes(void)
{
    fresh(); deliver(incoming(XDEV_EXT_XD_RTS,7));
    assert(!class_calls && xl.chan[0].consumed==4 && xl.ctl_tx->queued_nr==1);
    struct xdev_ext_xd_msg reply;
    assert(!xdev_ext_xd_msg_decode(xl.ctl_tx_frames[0].buf,128,crc32c,&reply));
    assert(reply.type==XDEV_EXT_XD_FAIL && reply.status==ENODEV && reply.group==7 && reply.stream==7);
    assert(reply.src_inc==0x1111 && reply.dst_inc==0x2222 && !fail_calls);
}
static void no_receiver_sequence_gap_ends_link(void)
{
    fresh(); struct xdev_ext_xd_msg m=incoming(XDEV_EXT_XD_RTS,8); m.data_seq=9;
    deliver(m); assert(fail_calls==1 && fail_error==-EPROTO && !xl.chan[0].consumed && !class_calls);
}
static void control_rx_callback_reposts_only_live_frame(void)
{
    fresh(); xl.chan[0].ep[0]=&ep;
    struct ring_frame *f=xl.ctl_rx->queued[0];
    struct xdev_ext_xd_ctl_frame *cf=container_of(f,struct xdev_ext_xd_ctl_frame,frame);
    struct xdev_ext_xd_msg m=incoming(XDEV_EXT_XD_CTS,1);
    assert(!xdev_ext_xd_msg_encode(cf->buf,&m,crc32c));
    assert(xl.ctl_rx->queued_nr==127); complete_frame(xl.ctl_rx,0,128,0);
    assert(class_calls==1 && xl.ctl_rx->queued_nr==127);
    complete_frame(xl.ctl_rx,0,128,1); assert(class_calls==1 && xl.ctl_rx->queued_nr==127);
    stop_link(); assert(class_calls==1 && !xl.ctl_rx->queued_nr);
}
static void requester_survives_ring_free(void)
{
    fresh(); stop_link(); xl.gone=true;
    mutex_lock(&xl.ctl_mutex); xdev_ext_xd_rings_free(&xl); mutex_unlock(&xl.ctl_mutex);
    unsigned reads=ring_dma_reads;
    for(unsigned i=0;i<ring_nr;i++) { assert(all_rings[i]->freed); all_rings[i]->nhi=NULL; }
    xl.xd=NULL;
    assert(xdev_ext_xd_dev_ops.requester(&ep)==&fixture_pdev && ring_dma_reads==reads);
    assert(xdev_ext_xd_dev_ops.max_payload(&ep)==0);
}
static void partial_start_rolls_back(void)
{
    allocate(); fail_start_at=parameter;
    mutex_lock(&xl.ctl_mutex); int ret=xdev_ext_xd_rings_start(&xl); mutex_unlock(&xl.ctl_mutex);
    assert(ret==-ENODEV && xl.nhi_gone && !running() && stops==parameter-1 && !done_nr);
}
static void paths_data_before_control(void)
{
    allocate(); paths_on();
    assert(path_nr==2 && paths[0].tx_path==xl.chan[0].out_hopid && paths[0].rx_path==10);
    assert(paths[0].tx_ring==xl.chan[0].tx->hop && paths[0].rx_ring==xl.chan[0].rx->hop);
    assert(paths[1].tx_path==xl.ctl_out_hopid && paths[1].rx_path==9);
    mutex_lock(&xl.ctl_mutex); xdev_ext_xd_paths_disable(&xl); xdev_ext_xd_paths_disable(&xl); mutex_unlock(&xl.ctl_mutex);
    assert(path_disables==2 && hop_releases==2 && !xl.ctl_paths && !xl.chan[0].paths);
    assert(xl.ctl_in_hopid==-1 && xl.chan[0].in_hopid==-1);
}
static void rings_allocation_unwinds(void)
{
    bare(); fail_acquire_step=parameter;
    assert(xdev_ext_xd_rings_alloc(&xl)==-ENOMEM);
    assert(ring_frees==ring_nr && dma_frees==dma_allocs && hop_releases==hop_nr);
    assert(!xl.ctl_tx && !xl.ctl_rx && !xl.chan[0].tx && !xl.chan[0].rx);
    assert(!xl.ctl_tx_buf && !xl.ctl_rx_buf && xl.ctl_out_hopid==-1 && xl.chan[0].out_hopid==-1);
    unsigned frees=ring_frees,dfs=dma_frees,hrs=hop_releases;
    xdev_ext_xd_rings_free(&xl); assert(ring_frees==frees && dma_frees==dfs && hop_releases==hrs);
}
static void path_enable_error_unwinds(void)
{
    allocate(); fail_path_at=parameter; struct xdev_ext_xd_login p=peer_login();
    mutex_lock(&xl.ctl_mutex); assert(xdev_ext_xd_paths_enable(&xl,&p)==-EIO); mutex_unlock(&xl.ctl_mutex);
    assert(path_disables==path_nr && hop_releases==parameter);
    assert(!xl.ctl_paths && !xl.chan[0].paths && xl.ctl_in_hopid==-1 && xl.chan[0].in_hopid==-1);
}
static void in_hop_error_unwinds(void)
{
    allocate(); if(parameter<=2) in_negative_at=parameter; else in_mismatch_at=parameter-2;
    struct xdev_ext_xd_login p=peer_login();
    mutex_lock(&xl.ctl_mutex); assert(xdev_ext_xd_paths_enable(&xl,&p)==-EIO); mutex_unlock(&xl.ctl_mutex);
    unsigned acquired_in=0; for(unsigned i=0;i<hop_nr;i++) if(hops[i].in) { acquired_in++; assert(hops[i].released); }
    assert(hop_releases==acquired_in && path_disables==path_nr);
    assert(xl.ctl_in_hopid==-1 && xl.chan[0].in_hopid==-1);
}
static void bind_errors_and_detached_unbind(void)
{
    fresh(); struct xdev_ext_mech_stage_uapi u={.arg0=123,.arg1=0};
    void *first=xdev_ext_xd_dev_ops.bind(&tx_stage,&u,NULL,NULL);
    assert(!IS_ERR(first) && xl.chan[0].ep[0]==first && link_gets==1 && !link_puts);
    void *busy=xdev_ext_xd_dev_ops.bind(&tx_stage,&u,NULL,NULL);
    assert(IS_ERR(busy) && PTR_ERR(busy)==-EBUSY && link_gets==2 && link_puts==1);
    struct xdev_ext_xd_ep successor={.xl=&xl,.st=&tx_stage};
    ((struct xdev_ext_xd_ep *)first)->detached=true; xl.chan[0].ep[0]=&successor;
    xdev_ext_xd_dev_ops.unbind(first);
    assert(xl.chan[0].ep[0]==&successor && link_puts==2 );
    u.arg1=1; void *bad=xdev_ext_xd_dev_ops.bind(&tx_stage,&u,NULL,NULL);
    assert(IS_ERR(bad) && PTR_ERR(bad)==-EINVAL && link_gets==3 && link_puts==3);
    u.arg1=0; heap_fail=true; bad=xdev_ext_xd_dev_ops.bind(&tx_stage,&u,NULL,NULL);
    assert(IS_ERR(bad) && PTR_ERR(bad)==-ENOMEM && link_gets==4 && link_puts==4);
    heap_fail=false; xl.up=false; bad=xdev_ext_xd_dev_ops.bind(&rx_stage,&u,NULL,NULL);
    assert(IS_ERR(bad) && PTR_ERR(bad)==-ENOLINK && link_gets==5 && link_puts==5);
    xl.up=true; xl.gone=true; bad=xdev_ext_xd_dev_ops.bind(&rx_stage,&u,NULL,NULL);
    assert(IS_ERR(bad) && PTR_ERR(bad)==-ENOLINK && link_gets==6 && link_puts==6);
    xl.gone=false; void *receiver=xdev_ext_xd_dev_ops.bind(&rx_stage,&u,NULL,NULL);
    assert(!IS_ERR(receiver) && xl.chan[0].ep[1]==receiver && xl.chan[0].ep[0]==&successor);
    xdev_ext_xd_dev_ops.unbind(receiver);
    assert(!xl.chan[0].ep[1] && xl.chan[0].ep[0]==&successor && link_gets==7 && link_puts==7);
    u.arg0=124; bad=xdev_ext_xd_dev_ops.bind(&tx_stage,&u,NULL,NULL);
    assert(IS_ERR(bad) && PTR_ERR(bad)==-ENODEV && link_gets==7);
    assert(xdev_ext_xd_dev_ops.hdr_policy==XDEV_EXT_NET_HDR_CHANNEL && xdev_ext_xd_dev_ops.max_elems==64);
    assert(!xdev_ext_xd_dev_ops.rx_flush);
}
/* Odin1: going-away stop runs real callback semantics, including late normal. */
static void going_away_late_normal_completion(void)
{
    fresh();xl.chan[0].ep[0]=&ep;
    struct tb_ring *r=xl.ctl_rx;
    struct xdev_ext_xd_ctl_frame *cf=container_of(r->queued[0],struct xdev_ext_xd_ctl_frame,frame);
    struct xdev_ext_xd_msg m=incoming(XDEV_EXT_XD_CTS,1);
    assert(!xdev_ext_xd_msg_encode(cf->buf,&m,crc32c));
    unsigned enqueues=r->enqueue_calls;
    stop_nhi_gone=true;going_late_normal=true;late_normal_ring=r;stop_link();
    assert(!class_calls&&r->enqueue_calls==enqueues&&xl.nhi_gone);
    assert(r->queued_nr<=126); /* remaining frames may already be software retired */
}
static void unposted_allocations_are_freed(void)
{
    allocate();void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;
    mutex_lock(&xl.ctl_mutex);xdev_ext_xd_rings_free(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(dma_is_freed(a)&&dma_is_freed(b)&&dma_frees==2&&!descriptor_quarantines);
    assert(ring_frees==4&&!fixture_pdev.refs);
}
static void normal_completions_allow_control_free(void)
{
    fresh();u8 raw[128]={0};assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;
    stop_complete_normal=true;stop_link();
    mutex_lock(&xl.ctl_mutex);xdev_ext_xd_rings_free(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(dma_is_freed(a)&&dma_is_freed(b)&&!descriptor_quarantines&&ring_frees==4);
    assert(!callback_reads_buffer&&!fixture_pdev.refs);
}
static void unknown_accepted_control_retained(void)
{
    fresh();u8 raw[128]={0};
    assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    complete_frame(xl.ctl_tx,0,0,0);
    void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;
    stop_link();
    mutex_lock(&xl.ctl_mutex);xdev_ext_xd_rings_free(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(!dma_is_freed(a)&&!dma_is_freed(b)&&dma_frees==0);
    assert(!descriptor_quarantines&&ring_frees==4); /* normal STOPPED descriptors */
    assert(fixture_pdev.refs>=2); /* unknown direction allocations own refs */
}
static void unknown_rx_does_not_leak_unposted_tx(void)
{
    fresh();void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;
    stop_link();mutex_lock(&xl.ctl_mutex);xdev_ext_xd_rings_free(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(!dma_is_freed(a)&&dma_is_freed(b)&&dma_frees==1&&fixture_pdev.refs>=1);
}
static void unknown_native_retirement_precedes_context_free(void)
{
    fresh();assert(!xdev_ext_xd_dev_ops.post_tx(&ep,elems,2));
    u8 raw[128]={0};assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    stop_nhi_gone=true;stop_link();void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;
    mutex_lock(&xl.ctl_mutex);xdev_ext_xd_rings_free(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(descriptor_quarantines==4&&!ring_frees&&done_nr==2);
    assert(!dma_is_freed(a)&&!dma_is_freed(b));
    for(unsigned i=0;i<2;i++)assert(done[i].status==-ECANCELED&&!done[i].quiesced);
    class_context_dead=true;
    for(unsigned i=0;i<ring_nr;i++){assert(all_rings[i]->freed&&!all_rings[i]->queued_nr);all_rings[i]->nhi=NULL;}
    fixture_tb.nhi=NULL;xl.xd=NULL;
    assert(xdev_ext_xd_dev_ops.requester(&ep)==&fixture_pdev);
}
static void healthy_relogin_replaces_unknown_rx_tx(void)
{
    fresh();u8 raw[128]={0};
    if(parameter&2)assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;dma_addr_t ad=xl.ctl_rx_dma,bd=xl.ctl_tx_dma;
    if(!(parameter&1))stop_rx_normal=true;
    stop_link();assert(!xl.nhi_gone);
    mutex_lock(&xl.ctl_mutex);int ret=xdev_ext_xd_rings_start(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(!ret&&!xl.nhi_gone&&running()==4);
    if(parameter&1)assert(xl.ctl_rx_buf!=a&&xl.ctl_rx_dma!=ad&&!dma_is_freed(a));
    if(parameter&2)assert(xl.ctl_tx_buf!=b&&xl.ctl_tx_dma!=bd&&!dma_is_freed(b));
    assert(xl.ctl_rx->queued_nr==127&&free_ctl()==128);
    xl.up=true;
    assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    assert((void *)(uintptr_t)xl.ctl_tx->queued[0]->buffer_phy>= (void *)xl.ctl_tx_buf);
}
static void fresh_control_allocation_failure_stays_down(void)
{
    fresh();u8 raw[128]={0};assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;stop_link();fault_countdown=parameter;
    mutex_lock(&xl.ctl_mutex);int ret=xdev_ext_xd_rings_start(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(ret<0&&!xl.up&&!running()&&!path_nr&&!dma_is_freed(a)&&!dma_is_freed(b));
    fault_countdown=0;
    mutex_lock(&xl.ctl_mutex);ret=xdev_ext_xd_rings_start(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(!ret&&running()==4&&xl.ctl_rx_buf!=a&&xl.ctl_tx_buf!=b);
}
static void idle_suspend_resume_refreshes_controls(void)
{
    fresh();assert(!xl.chan[0].ep[0]&&!xl.chan[0].ep[1]);
    void *old=xl.ctl_rx_buf;xl.suspended=true;stop_link();
    assert(!dma_is_freed(old));xl.suspended=false;
    mutex_lock(&xl.ctl_mutex);int ret=xdev_ext_xd_rings_start(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(!ret&&xl.ctl_rx_buf!=old&&xl.ctl_rx->queued_nr==127&&!xl.nhi_gone);
}
static void going_away_never_restarts_native_ring(void)
{
    fresh();stop_nhi_gone=true;fixture_nhi.going_away=true;stop_link();
    unsigned native_starts=starts;
    mutex_lock(&xl.ctl_mutex);int ret=xdev_ext_xd_rings_start(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(ret<0&&starts==native_starts&&!xl.up&&xl.nhi_gone);
}
static void starting_control_rx_reposts_before_up(void)
{
    allocate();mutex_lock(&xl.ctl_mutex);assert(!xdev_ext_xd_rings_start(&xl));mutex_unlock(&xl.ctl_mutex);
    assert(!xl.up);struct tb_ring *r=xl.ctl_rx;unsigned posts=r->enqueue_calls;
    complete_frame(r,0,128,1);assert(r->queued_nr==127&&r->enqueue_calls==posts+1&&!class_calls);
}
static void closed_control_rx_does_not_repost(void)
{
    fresh();struct tb_ring *r=xl.ctl_rx;unsigned posts=r->enqueue_calls;
    stop_complete_normal=true;stop_link();
    assert(r->enqueue_calls==posts&&!r->queued_nr&&!class_calls);
}
static void fresh_record_allocation_failure_unwinds(void)
{
    bare();heap_fail_at=parameter;
    assert(xdev_ext_xd_rings_alloc(&xl)<0);
    assert(dma_frees==dma_allocs&&!descriptor_quarantines&&ring_frees==ring_nr);
    assert(!fixture_pdev.refs&&!xl.ctl_rx_buf&&!xl.ctl_tx_buf);
}

static void actual_post_close_lock_boundary(void)
{
    fresh();spawn_close_worker=true;
    assert(!xdev_ext_xd_dev_ops.post_tx(&ep,elems,3));
    assert(!close_worker_pending&&!xl.up&&data_native_calls==3&&done_nr==3);
    for(unsigned i=0;i<3;i++)assert(done[i].status==-ECANCELED&&!done[i].quiesced);
    assert(xdev_ext_xd_dev_ops.post_tx(&ep,elems+3,1)==-ENOLINK);
    assert(data_native_calls==3&&!duplicate_native_calls);
}
static void other_cpu_early_control_callback_returns_slot_once(void)
{
    fresh();u8 raw[128];memset(raw,0x7b,sizeof(raw));spawn_early_ctl_worker=true;
    assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,sizeof(raw)));
    assert(!early_worker_pending&&free_ctl()==128&&!xl.ctl_tx->queued_nr);
    void *txbuf=xl.ctl_tx_buf;stop_link();
    mutex_lock(&xl.ctl_mutex);xdev_ext_xd_rings_free(&xl);mutex_unlock(&xl.ctl_mutex);
    /* The one accepted TX completed normally before close, unlike RX primes. */
    assert(dma_is_freed(txbuf));
}
static void rx_repost_close_serialized(void)
{
    fresh();require_ctl_rx_lock=true;struct tb_ring *r=xl.ctl_rx;
    /* At the actual repost call, the real link lock must still cover the
     * callback's close decision. Close-first behavior is checked by cases
     * 38 and 53; STARTING without up is checked by case 52. */
    complete_frame(r,0,128,1);assert(r->queued_nr==127);
    stop_complete_normal=true;unsigned posts=r->enqueue_calls;stop_link();
    assert(r->enqueue_calls==posts&&!r->queued_nr);
}
static void unknown_tx_does_not_leak_normal_rx(void)
{
    fresh();u8 raw[128]={0};assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,128));
    void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;stop_rx_normal=true;stop_link();
    mutex_lock(&xl.ctl_mutex);xdev_ext_xd_rings_free(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(dma_is_freed(a)&&!dma_is_freed(b)&&dma_frees==1);
}
static void started_path_failure_retains_only_accepted_direction(void)
{
    fresh();struct xdev_ext_xd_login p=peer_login();
    if(parameter<=2)fail_path_at=parameter;else in_mismatch_at=parameter-2;
    mutex_lock(&xl.ctl_mutex);assert(xdev_ext_xd_paths_enable(&xl,&p)<0);mutex_unlock(&xl.ctl_mutex);
    void *a=xl.ctl_rx_buf,*b=xl.ctl_tx_buf;stop_link();
    mutex_lock(&xl.ctl_mutex);xdev_ext_xd_rings_free(&xl);mutex_unlock(&xl.ctl_mutex);
    assert(!dma_is_freed(a)&&dma_is_freed(b)&&path_disables==path_nr);
    for(unsigned i=0;i<hop_nr;i++)assert(hops[i].released);
}
static struct { const char *name; void (*run)(void); unsigned parameter; } cases[]={
    {"TX physical frame construction and native completion once",tx_frames_and_once,0},
    {"RX full buffers and CRC/overrun/length classification",rx_frame_classification,0},
    {"normal stop cancels unknown DMA once before control teardown",stop_cancellation_unknown,0},
    {"NHI going away retains outstanding frames and control custody",going_away_has_no_completion,0},
    {"down/gone/detached and invalid late TX element accept nothing",post_rejections_are_empty,0},
    {"short late RX lease rejects whole batch",rx_full_lease_prevalidation,0},
    {"link down waits for entire native batch acceptance",post_holds_gate_for_entire_batch,0},
    {"control buffers preserve accepted bytes until callback under pressure",control_copy_backpressure_and_return,0},
    {"invalid/dead control submission changes no pool ownership",control_invalid_and_dead_rollback,0},
    {"RTS announced sequence commits only after control acceptance",announcement_commit_only_after_queue,0},
    {"RTS encode/channel/endpoint failure rolls back counter and pool",announcement_error_rollback,0},
    {"RX sequence consumed once with exact contiguous cursor",consume_exact_sequence_once,0},
    {"valid control routes to stage; stale/corrupt input drops without progress",dispatch_routes_and_rejects_stale,0},
    {"unbound RX device refusal consumes announced elements",no_receiver_refuses_and_consumes,0},
    {"unbound RX sequence gap schedules mandatory link failure",no_receiver_sequence_gap_ends_link,0},
    {"control RX repost and canceled callback boundary",control_rx_callback_reposts_only_live_frame,0},
    {"cached requester survives freed rings and removed service",requester_survives_ring_free,0},
    {"first ring not starting leaves no started ring",partial_start_rolls_back,1},
    {"second ring not starting stops only first ring",partial_start_rolls_back,2},
    {"third ring not starting stops only first two rings",partial_start_rolls_back,3},
    {"fourth ring not starting stops only first three rings",partial_start_rolls_back,4},
    {"data paths precede control; disable is paired and idempotent",paths_data_before_control,0},
    {"ring allocation failure step 1 unwinds exact ownership",rings_allocation_unwinds,1},
    {"ring allocation failure step 2 unwinds exact ownership",rings_allocation_unwinds,2},
    {"ring allocation failure step 3 unwinds exact ownership",rings_allocation_unwinds,3},
    {"ring allocation failure step 4 unwinds exact ownership",rings_allocation_unwinds,4},
    {"ring allocation failure step 5 unwinds exact ownership",rings_allocation_unwinds,5},
    {"ring allocation failure step 6 unwinds exact ownership",rings_allocation_unwinds,6},
    {"ring allocation failure step 7 unwinds exact ownership",rings_allocation_unwinds,7},
    {"ring allocation failure step 8 unwinds exact ownership",rings_allocation_unwinds,8},
    {"data tunnel enable failure releases allocated in-HopID",path_enable_error_unwinds,1},
    {"control tunnel enable failure disables data and releases both HopIDs",path_enable_error_unwinds,2},
    {"negative data in-HopID is never released",in_hop_error_unwinds,1},
    {"negative control in-HopID unwinds data",in_hop_error_unwinds,2},
    {"positive mismatched data in-HopID is released",in_hop_error_unwinds,3},
    {"positive mismatched control in-HopID is released",in_hop_error_unwinds,4},
    {"bind errors balance custody; detached unbind preserves successor",bind_errors_and_detached_unbind,0},
    {"going_away_late_normal_completion 0",going_away_late_normal_completion,0},
    {"unposted_allocations_are_freed 0",unposted_allocations_are_freed,0},
    {"normal_completions_allow_control_free 0",normal_completions_allow_control_free,0},
    {"unknown_accepted_control_retained 0",unknown_accepted_control_retained,0},
    {"unknown_rx_does_not_leak_unposted_tx 0",unknown_rx_does_not_leak_unposted_tx,0},
    {"unknown_native_retirement_precedes_context_free 0",unknown_native_retirement_precedes_context_free,0},
    {"healthy_relogin_replaces_unknown_rx_tx 1",healthy_relogin_replaces_unknown_rx_tx,1},
    {"healthy_relogin_replaces_unknown_rx_tx 3",healthy_relogin_replaces_unknown_rx_tx,3},
    {"fresh_control_allocation_failure_stays_down 1",fresh_control_allocation_failure_stays_down,1},
    {"fresh_control_allocation_failure_stays_down 2",fresh_control_allocation_failure_stays_down,2},
    {"fresh_control_allocation_failure_stays_down 3",fresh_control_allocation_failure_stays_down,3},
    {"fresh_control_allocation_failure_stays_down 4",fresh_control_allocation_failure_stays_down,4},
    {"idle_suspend_resume_refreshes_controls 0",idle_suspend_resume_refreshes_controls,0},
    {"going_away_never_restarts_native_ring 0",going_away_never_restarts_native_ring,0},
    {"starting_control_rx_reposts_before_up 0",starting_control_rx_reposts_before_up,0},
    {"closed_control_rx_does_not_repost 0",closed_control_rx_does_not_repost,0},
    {"fresh_record_allocation_failure_unwinds 1",fresh_record_allocation_failure_unwinds,1},
    {"fresh_record_allocation_failure_unwinds 2",fresh_record_allocation_failure_unwinds,2},
    {"actual pthread post/close serialization accepts whole batch or zero",actual_post_close_lock_boundary,0},
    {"other CPU callback before post return retires control slot once",other_cpu_early_control_callback_returns_slot_once,0},
    {"RX close decision and actual repost share link lock",rx_repost_close_serialized,0},
    {"normal RX allocation freed independently of unknown TX",unknown_tx_does_not_leak_normal_rx,0},
    {"healthy relogin refreshes TX-only unknown allocation",healthy_relogin_replaces_unknown_rx_tx,2},
    {"started data path failure retains accepted RX only",started_path_failure_retains_only_accepted_direction,1},
    {"started control path failure retains accepted RX only",started_path_failure_retains_only_accepted_direction,2},
    {"started mismatched data HopID rollback preserves control custody",started_path_failure_retains_only_accepted_direction,3},
    {"started mismatched control HopID rollback preserves control custody",started_path_failure_retains_only_accepted_direction,4},
};
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--count")) { printf("%zu\n",ARRAY_SIZE(cases)); return 0; }
    if(argc!=2) return 2;
    unsigned number=(unsigned)strtoul(argv[1],NULL,10);
    if(!number || number>ARRAY_SIZE(cases)) return 2;
    parameter=cases[number-1].parameter; cases[number-1].run();
    printf("ok %u - %s\n",number,cases[number-1].name); return 0;
}

#include "os_boundary.h"
static void boundary_raw(struct xsk_buff_pool *,u64);
static dma_addr_t xp_raw_get_dma(struct xsk_buff_pool *,u64);
static void xp_dma_sync_for_device(struct xsk_buff_pool *,dma_addr_t,size_t);
#include "production.c.inc"

static struct xsk_xdev_ext_mech_provider p;
static struct xsk_xdev_ext_mech_stage xst;
static struct xsk_xdev_ext_mech_tx_batch tb;
static struct xdev_ext_mech_stage st;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_pool pool;
static struct xdev_ext_mech_batch batch;
static struct xdp_sock xs;
static struct xdp_umem umem;
static struct xsk_buff_pool xp;
static struct xsk_mech_zc_slot slots[8];
static struct xdp_desc descs[8];
static struct xdp_buff_xsk heads[3];
static struct xsk_dma_map shared_map;
static struct device nic={17};
static void *pages[3];
static dma_addr_t maps[3]={0x100000,0x300000,0x500000};
static u8 chunks[3][4096];
static u64 tags[3];
static int wakeup(struct net_device *dev,u32 q,u32 flags)
{
    struct xdp_desc d;
    (void)dev;
    REQUIRE("wakeup_socket_lock",mutex_depth==1 && lock_depth==0 && q==7 && flags==2);
    wakeup_n++;ev("W ");
    for(int i=0;i<peek_on_wakeup;i++) REQUIRE("wakeup_native_peek",xsk_tx_peek_desc(&xp,&d));
    return wakeup_result;
}
static const struct net_device_ops nops={wakeup};
static struct net_device netdev={&nops};
static const u8 packet_prefix[42]={
  0,1,2,3,4,5,6,7,8,9,10,11,8,0,
  0x45,0,0,0x2c,0x12,0x34,0,0,0x40,0x11,0xaa,0xbb,0xc0,0,2,1,0xc6,0x33,0x64,2,
  0x12,0x34,0x56,0x78,0,0x18,0xcc,0xdd};
static const u8 finished_prefix[42]={
  0,1,2,3,4,5,6,7,8,9,10,11,8,0,
  0x45,0,0,0x2c,0x12,0x34,0,0,0x40,0x11,0x7c,0x56,0xc0,0,2,1,0xc6,0x33,0x64,2,
  0x12,0x34,0x56,0x78,0,0x18,0,0};
static void reset(const char *name)
{
    case_name=name;lock_depth=mutex_depth=lock_epoch=0;event_n=0;events[0]=0;
    callbacks=complete_status=dead_status=count_ops=count_bytes=seq_callbacks=cancel_callbacks=0;
    sync_dev_n=sync_cpu_n=raw_n=trace_n=wakeup_n=peek_on_wakeup=wakeup_result=0;memset(check_epoch,0,sizeof(check_epoch));
    memset(&p,0,sizeof(p));memset(&xst,0,sizeof(xst));memset(&tb,0,sizeof(tb));
    memset(&xs,0,sizeof(xs));memset(&xp,0,sizeof(xp));memset(&pool,0,sizeof(pool));memset(&batch,0,sizeof(batch));
    memset(slots,0,sizeof(slots));memset(tags,0,sizeof(tags));
    xp.dev=&nic;xp.dma_pages=malloc(sizeof(maps));memcpy(xp.dma_pages,maps,sizeof(maps));xp.dma_pages_cnt=3;xp.chunk_size=4096;xp.heads_cnt=3;xp.umem=&umem;xp.heads=heads;xp.addrs=&chunks[0][0];
    umem.npgs=umem.chunks=3;umem.size=12288;umem.pgs=pages;INIT_LIST_HEAD(&umem.xsk_dma_list);INIT_LIST_HEAD(&shared_map.list);shared_map.netdev=&netdev;shared_map.users=2;xp.netdev=&netdev;list_add_tail(&shared_map.list,&umem.xsk_dma_list);
    xp.tx_descs_capacity=8;xp.tx_descs=descs;xp.xdev_ext_mech_tx=&p;INIT_LIST_HEAD(&xp.xsk_tx_list);
    xs.pool=&xp;xs.umem=&umem;xs.dev=&netdev;xs.queue_id=7;xs.state=XSK_BOUND;xs.zc=true;xs.xdev_ext_mech_tx=&st;
    p.xs=&xs;p.xp=&xp;p.zc=true;p.slots=slots;p.ring.capacity=8;
    p.ring.native_head=p.ring.native_tail=XSK_MECH_ZC_NONE;
    pool.ops=&xsk_xdev_ext_mech_pool_ops;pool.priv=&p;pool.pages=pages;pool.frame_size=4096;pool.nr_frames=3;
    session.pool=&pool;st.s=&session;st.priv=&xst;
    xst.xs=&xs;xst.tx_staged=&batch;xst.tx_staged_id=77;xst.tx_n=3;
    batch.s=&session;batch.nr_frames=3;batch.id=77;batch.ticket=91;batch.priv=&tb;tb.ticket=91;
    for(u32 i=0;i<3;i++){
        memset(chunks[i],0x31+i,sizeof(chunks[i]));memcpy(chunks[i]+22,packet_prefix,42);
        batch.f[i]=(struct xdev_ext_mech_frame){.kaddr=chunks[i],.umem_addr=(u64)i*4096,.index=i,.data_off=64,.data_len=16,.pool_priv=&heads[i]};
        xst.tx_desc[i]=(struct xdp_desc){(u64)i*4096+22,58,0};
        xst.tx_pkt[i]=chunks[i]+22;xst.tx_tag[i]=&tags[i];
    }
    observed_provider=&p;observed_stage=&xst;
}
static void record_case(void)
{
    printf("TRACE %s prod=%u issued=%u cons=%u native=%u fatal=%d pending=%u status=%d raw_native=%d callbacks=%d cq=%d ops=%d bytes=%d sync_dev=%d sync_cpu=%d tags=%llu,%llu,%llu events=%s\n",case_name,p.ring.prod,p.ring.issued,p.ring.cons,p.ring.native_count,p.ring.fatal,tb.completion.pending,tb.completion.status,tb.native_error,callbacks,complete_status,count_ops,count_bytes,sync_dev_n,sync_cpu_n,(unsigned long long)tags[0],(unsigned long long)tags[1],(unsigned long long)tags[2],events);
}
static void test_all_unsent(void)
{
    reset("all_unsent");CHECK("submit",xsk_xdev_ext_mech_submit(&st,&batch)==0);
    CHECK("publish_count",p.ring.prod==3 && p.ring.issued==0 && p.ring.cons==0 && p.ring.native_count==0);
    CHECK("publish_effects",sync_dev_n==3 && trace_n==3 && raw_n==3 && wakeup_n==1 && callbacks==0);
    CHECK("sync_span",sync_addr[0]==0x100016 && sync_addr[1]==0x300016 && sync_addr[2]==0x500016 && sync_len[0]==58 && sync_len[1]==58 && sync_len[2]==58);
    CHECK("single_lock_interval",sync_epoch[0]==sync_epoch[1] && sync_epoch[1]==sync_epoch[2]);
    const struct xdp_desc golden_desc[3]={{22,58,0},{4118,58,0},{8214,58,0}};
    for(u32 i=0;i<3;i++){
        CHECK("golden_checksum_header",!memcmp(chunks[i]+22,finished_prefix,42));
        CHECK("payload_unchanged",chunks[i][64]==0x31+i && chunks[i][79]==0x31+i);
        CHECK("descriptor_bytes",!memcmp(&slots[i].desc,&golden_desc[i],sizeof(struct xdp_desc)) && slots[i].slot==i && tags[i]==77);
        for(u32 j=0;j<4096;j++)CHECK("whole_chunk_bytes",chunks[i][j]==(j>=22 && j<64?finished_prefix[j-22]:0x31+i));
    }
    CHECK("public_batch_peek",xsk_tx_peek_release_desc_batch(&xp,8)==3);
    CHECK("native_fifo",p.ring.native_head==0 && p.ring.native_tail==2 && slots[0].native_next==1 && slots[1].native_next==2);
    xsk_tx_completed(&xp,3);
    CHECK("complete",callbacks==1 && complete_status==0 && count_ops==3 && count_bytes==48 && p.ring.cons==3 && p.ring.native_count==0);
    struct xdev_ext_afxdp_tx_cqe c[3]={{123},{123},{123}};
    xsk_xdev_ext_mech_fill_cqe(&st,&batch,c);CHECK("cqe",c[0].err==0 && c[1].err==0 && c[2].err==0);
#if HAVE_POOL
    CHECK("definite_lease_clear",tb.pool_lease[0].kind==0 && tb.pool_lease[1].kind==0 && tb.pool_lease[2].kind==0);
#endif
    CHECK("golden_full_trace",!strcmp(events,"M L R S T R S T R S T U W m L U N H L O B O B O B U C "));
    record_case();
}
static void test_partial_and_none(void)
{
    reset("partial_sent");tags[1]=77;
    CHECK("partial_submit_original_frame",xsk_xdev_ext_mech_submit(&st,&batch)==0);
    CHECK("partial_original_index",p.ring.prod==2 && slots[0].slot==0 && slots[1].slot==2 && slots[1].desc.addr==8214);
    CHECK("partial_sync_span",sync_dev_n==2 && sync_addr[0]==0x100016 && sync_addr[1]==0x500016 && sync_len[1]==58);
    CHECK("sent_header_preserved",!memcmp(chunks[1]+22,packet_prefix,42));
#if HAVE_POOL
    CHECK("partial_lease_frame",tb.pool_lease[0].u.pool.frame_index==0 && tb.pool_lease[1].kind==0 && tb.pool_lease[2].u.pool.frame_index==2);
#endif
    CHECK("partial_trace",!strcmp(events,"M L R S T R S T U W m "));
    record_case();
    reset("none_unsent");tags[0]=tags[1]=tags[2]=77;
    CHECK("submit",xsk_xdev_ext_mech_submit(&st,&batch)==0);
    CHECK("none_no_native_effect",sync_dev_n==0 && trace_n==0 && wakeup_n==0 && p.ring.prod==0 && callbacks==1 && complete_status==0);
    CHECK("none_trace",!strcmp(events,"C "));record_case();
}
static void test_preflight(void)
{
    for(int which=0;which<5;which++){
        reset("preflight_priority");p.ring.prod=8;p.ring.fatal=-EPIPE;xp.dma_pages_cnt=2;
        if(which==0)p.stopped=true;
        if(which==1)xst.dead=true;
        if(which==2)xs.state=0;
        if(which==4)p.ring.fatal=0;
        int want=which<3?-ENXIO:which==3?-EPIPE:-EAGAIN;
        CHECK("preflight_error_priority",xsk_xdev_ext_mech_submit(&st,&batch)==want);
        CHECK("preflight_no_effect",p.ring.prod==8 && sync_dev_n==0 && trace_n==0 && wakeup_n==0 && callbacks==0 && tags[0]==0);
        CHECK("preflight_header_unchanged",!memcmp(chunks[0]+22,packet_prefix,42));
        CHECK("preflight_lock_trace",!strcmp(events,"M L U m "));record_case();
    }
    reset("staged_identity");xst.tx_staged_id=76;CHECK("staged_identity",xsk_xdev_ext_mech_submit(&st,&batch)==-EPROTO && !xst.tx_staged && !event_n);record_case();
}
static void test_wakeup(void)
{
    const int peeks[3]={0,1,3};
    for(int k=0;k<3;k++){
        reset("wakeup_error");peek_on_wakeup=peeks[k];wakeup_result=-ENETDOWN;
        CHECK("accepted_wakeup",xsk_xdev_ext_mech_submit(&st,&batch)==0);
        CHECK("wakeup_suffix",p.stopped && p.ring.native_count==(u32)peeks[k] && tb.completion.pending==(u32)peeks[k] && sync_cpu_n==3-peeks[k] && dead_status==-ENETDOWN);
        CHECK("wakeup_no_premature_callback",callbacks==(peeks[k]==0));
        if(peeks[k])xsk_tx_completed(&xp,peeks[k]);
        CHECK("wakeup_final_once",callbacks==1 && complete_status==(peeks[k]==3?0:-ENETDOWN) && p.ring.native_count==0);
        CHECK("wakeup_counter",count_ops==peeks[k] && count_bytes==16*peeks[k]);record_case();
    }
}
static void test_tail_hole(void)
{
    reset("tail_done_hole");CHECK("submit",xsk_xdev_ext_mech_submit(&st,&batch)==0);
    CHECK("peek",xsk_tx_peek_release_desc_batch(&xp,3)==3);
    xsk_tx_cancel_tail(&xp,1,0);
    CHECK("done_hole",slots[2].state==XSK_MECH_ZC_DONE && p.ring.cons==0 && p.ring.native_count==2 && p.ring.native_tail==1 && tb.completion.pending==2);
    xsk_tx_completed(&xp,1);
    CHECK("remaining_fifo",p.ring.native_head==1 && p.ring.native_tail==1 && p.ring.native_count==1 && p.ring.cons==1 && callbacks==0);
    xsk_tx_completed(&xp,1);
    CHECK("hole_reclaimed",p.ring.cons==3 && callbacks==1 && complete_status==0 && count_ops==3 && count_bytes==48);record_case();
    /* Remove a native head without reclaim, then ask actual FIFO head. */
    reset("fifo_independent_cons");CHECK("submit",xsk_xdev_ext_mech_submit(&st,&batch)==0);
    CHECK("peek",xsk_tx_peek_release_desc_batch(&xp,3)==3);
    xsk_mech_zc_mark_done(&p.ring,p.slots,0);
    CHECK("fifo_head_not_cons",xsk_mech_zc_complete(&p.ring,p.slots)==1 && p.ring.cons==0);record_case();
}
static void test_setonly_and_eagain(void)
{
    reset("set_only_first_error");CHECK("submit",xsk_xdev_ext_mech_submit(&st,&batch)==0);CHECK("peek",xsk_tx_peek_release_desc_batch(&xp,3)==3);
    xsk_tx_set_tail_result(&xp,1,-EAGAIN);
    CHECK("set_only_retains",p.ring.native_count==3 && tb.completion.pending==3 && callbacks==0 && slots[2].result==-EAGAIN && p.ring.fatal==-EIO && tb.native_error==-EAGAIN);
#if HAVE_POOL
    CHECK("set_only_lease",tb.pool_lease[2].kind==3);
#endif
    xsk_tx_set_tail_result(&xp,1,-EPIPE);CHECK("first_error_retained",slots[2].result==-EAGAIN && tb.native_error==-EAGAIN && p.ring.fatal==-EIO);
    xsk_tx_completed(&xp,3);
    CHECK("accepted_eagain_terminal",tb.err[2]==-EIO && tb.completion.status==-EIO && p.ring.fatal==-EIO && callbacks==1 && complete_status==-EAGAIN && count_ops==2 && count_bytes==32);
    struct xdp_desc d; CHECK("no_readmission_after_error",p.stopped && !xsk_tx_peek_desc(&xp,&d) && p.ring.prod==3 && callbacks==1);
    record_case();
}
static void test_excess(void)
{
    reset("excess_count");CHECK("submit",xsk_xdev_ext_mech_submit(&st,&batch)==0);CHECK("peek",xsk_tx_peek_release_desc_batch(&xp,1)==1);
    CHECK("excess_protocol",xsk_xdev_ext_mech_tx_complete(&xp,2,0,false,false)==-EPROTO);
    CHECK("excess_quarantine",p.stopped && p.ring.fatal==-EPROTO && callbacks==1 && seq_callbacks==1 && tb.completion.uncertain && complete_status==-EPROTO && count_ops==0 && sync_cpu_n==2);
#if HAVE_POOL
    CHECK("excess_unknown_lease",tb.pool_lease[0].kind==3 && tb.pool_lease[1].kind==0 && tb.pool_lease[2].kind==0);
#endif
    record_case();
}
static void test_stop_unmap(void)
{
    reset("mixed_stop_unmap_late");CHECK("submit",xsk_xdev_ext_mech_submit(&st,&batch)==0);CHECK("peek",xsk_tx_peek_release_desc_batch(&xp,2)==2);
    xsk_tx_cancel_tail(&xp,1,0);CHECK("mixed_done",slots[1].state==XSK_MECH_ZC_DONE && slots[0].state==XSK_MECH_ZC_NATIVE && slots[2].state==XSK_MECH_ZC_PENDING);
    xsk_xdev_ext_mech_pool_dead(&xp);
    CHECK("mixed_stop",p.stopped && callbacks==1 && seq_callbacks==1 && tb.completion.uncertain && p.ring.native_count==0 && p.ring.prod==p.ring.cons && sync_cpu_n==1);
#if HAVE_POOL
    CHECK("unknown_metadata_retained",tb.pool_lease[0].kind==3 && tb.pool_lease[1].kind==0 && tb.pool_lease[2].kind==0);
#endif
    xp_dma_unmap(&xp,0);
    CHECK("actual_unmap_shared_mapping",!xp.dev && !xp.dma_pages && !xp.dma_pages_cnt && shared_map.users==1);
    int before_raw=raw_n,before_cpu=sync_cpu_n,before_callbacks=callbacks;
    xsk_tx_completed(&xp,1);
    CHECK("late_no_map_access",raw_n==before_raw && sync_cpu_n==before_cpu && callbacks==before_callbacks);
#if HAVE_POOL
    CHECK("late_unknown_metadata_retained",tb.pool_lease[0].kind==3);
#endif
    record_case();
}
static void test_actual_family_host(void)
{
    reset("existing_family_host");
    struct xdev_ext_net_elem e[1]={0};struct xdev_ext_net_member m={XDEV_EXT_NET_LEASE_HOST_CPU};
    struct xdev_ext_net_slot slot={.batch=&batch,.elem=e,.busy=true};
    struct xdev_ext_netfam_stage ns={.st=&st,.m=&m,.max_elems=1};
    CHECK("host_existing_acquire",xdev_ext_netfam_lease_host(&ns,&slot,0,2,64,16)==0);
    CHECK("host_authority",e[0].lease.kind==2 && e[0].lease.u.host.addr==chunks[2]+64 && e[0].lease.u.host.len==16);
    struct xdev_ext_net_lease saved=e[0].lease;
    xdev_ext_netfam_release(&slot,false);CHECK("host_unknown",!memcmp(&saved,&e[0].lease,sizeof(saved)) && slot.busy);
    xdev_ext_netfam_release(&slot,true);CHECK("host_definite",e[0].lease.kind==0 && !slot.busy);record_case();
}
#if HAVE_POOL
static int provider_calls,provider_error;
static int scripted_check(void*o,struct xdev_ext_mech_pool*pl,const struct xdev_ext_mech_frame*f,u32 off,u32 len){(void)o;(void)pl;(void)f;(void)off;(void)len;provider_calls++;return provider_error;}
static const struct xdev_ext_net_pool_dma_ops scripted_ops={scripted_check};
static void test_family_pool(void)
{
    struct xdev_ext_net_lease l,saved;int ret;
    for(int v=0;v<18;v++){
        reset("family_pool_guard");memset(&l,0xa5,sizeof(l));l.kind=0;saved=l;provider_calls=provider_error=0;
        struct xdev_ext_net_pool_dma_ops ops=scripted_ops;
        struct xdev_ext_net_lease *lp=&l;struct xdev_ext_mech_batch*bp=&batch;void*owner=&p;u32 pos=0,off=22,len=58;int want=-EINVAL;
        if(v==0)lp=NULL;
        if(v==1)bp=NULL;
        if(v==2)owner=NULL;
        if(v==3)ops.check_locked=NULL;
        if(v==4){len=0;pos=9;want=-EPROTO;}
        if(v==5){pos=9;want=-ERANGE;}
        if(v==6)session.pool=NULL;
        if(v==7)batch.f[0].index=3;
        if(v==8)batch.f[0].data_off=4097;
        if(v==9)batch.f[0].data_len=4096;
        if(v==10){off=65;len=15;want=-ERANGE;}
        if(v==11){len=57;want=-ERANGE;}
        if(v==12){l.kind=1;saved=l;want=-EBUSY;}
        if(v==13){provider_error=-ESTALE;want=-ESTALE;}
        if(v==14){len=0;l.kind=1;saved=l;want=-EPROTO;}
        if(v==15){pos=9;l.kind=1;saved=l;want=-ERANGE;}
        if(v==16){l.kind=3;len=57;saved=l;want=-ERANGE;}
        ret=xdev_ext_net_lease_pool(lp,bp,pos,off,len,v==17?NULL:&ops,owner);
        CHECK("family_guard_priority",ret==want);CHECK("family_no_write_error",!memcmp(&l,&saved,sizeof(l)));
        CHECK("family_callback_priority",provider_calls==(v==13));
    }
    reset("family_pool_success");memset(&l,0xa5,sizeof(l));l.kind=0;provider_calls=provider_error=0;
    CHECK("pool_acquire",xdev_ext_net_lease_pool(&l,&batch,2,22,58,&scripted_ops,&p)==0);
    CHECK("pool_exact_metadata",l.kind==3 && l.u.pool.owner==&p && l.u.pool.umem_addr==8192 && l.u.pool.frame_index==2 && l.u.pool.frame_off==22 && l.u.pool.len==58 && provider_calls==1);
    saved=l;xdev_ext_net_lease_pool_release(&l,false);CHECK("unknown_full_bytes",!memcmp(&l,&saved,sizeof(l)));
    struct xdev_ext_net_lease expected=saved;expected.kind=0;memset(&expected.u.pool,0,sizeof(expected.u.pool));
    xdev_ext_net_lease_pool_release(&l,true);CHECK("true_only_pool_metadata",!memcmp(&l,&expected,sizeof(l)));CHECK("true_clear_kind",l.kind==0);
    struct xdev_ext_net_pool_dma zero={0};CHECK("true_clear_metadata",!memcmp(&l.u.pool,&zero,sizeof(zero)));
    memset(&l,0xb6,sizeof(l));l.kind=2;saved=l;xdev_ext_net_lease_pool_release(&l,true);CHECK("other_kind_untouched",!memcmp(&l,&saved,sizeof(l)));record_case();
}
static void test_provider_guards(void)
{
    for(int v=0;v<24;v++){
        reset("provider_mapping_guard");struct xsk_buff_pool other=xp;struct xdp_umem other_umem=umem;
        u32 off=22,len=58;int want;
        if(v==0){pool.ops=NULL;want=-EINVAL;}
        else if(v==1){pool.priv=NULL;want=-EINVAL;}
        else if(v==2){p.zc=false;want=-EINVAL;}
        else if(v==3){p.stopped=true;want=-ENXIO;}
        else if(v==4){p.xp=NULL;want=-ENXIO;}
        else if(v==5){xp.umem=NULL;want=-ENXIO;}
        else if(v==6){xp.dev=NULL;want=-ENXIO;}
        else if(v==7){xp.dma_pages=NULL;want=-ENXIO;}
        else if(v==8){xp.dma_pages_cnt=2;want=-ENXIO;}
        else if(v==9){xs.pool=&other;want=-EXDEV;}
        else if(v==10){xs.umem=&other_umem;want=-EXDEV;}
        else if(v==11){pool.pages=NULL;want=-EXDEV;}
        else if(v==12){pool.frame_size=2048;want=-EXDEV;}
        else if(v==13){pool.nr_frames=2;want=-EXDEV;}
        else if(v==14){xp.heads_cnt=2;want=-EXDEV;}
        else if(v==15){xp.unaligned=true;want=-ERANGE;}
        else if(v==16){batch.f[0].umem_addr=1;want=-ERANGE;}
        else if(v==17){batch.f[0].pool_priv=&heads[1];want=-ERANGE;}
        else if(v==18){umem.size=79;want=-ERANGE;}
        else if(v==19){umem.size=22;want=-ERANGE;}
        else if(v==20){umem.size=21;want=-ERANGE;}
        else if(v==21){batch.f[0].umem_addr=UINT64_MAX;want=-ERANGE;}
        else if(v==22){off=UINT32_MAX;len=UINT32_MAX;want=-ERANGE;}
        else {p.stopped=true;xp.dev=&nic;xp.dma_pages=malloc(sizeof(maps));memcpy(xp.dma_pages,maps,sizeof(maps));want=-ENXIO;}
        struct xdev_ext_mech_frame saved=batch.f[0];int before=event_n;unsigned long flags;
        spin_lock_irqsave(&p.tx_lock,flags);
        int ret=xsk_mech_pool_dma_check_locked(&p,&pool,&batch.f[0],off,len);
        spin_unlock_irqrestore(&p.tx_lock,flags);
        CHECK("provider_guard_priority",ret==want);
        CHECK("provider_no_effect",!memcmp(&saved,&batch.f[0],sizeof(saved)) && !raw_n && !sync_dev_n && !trace_n && !callbacks && event_n>=before);
    }
    reset("provider_mapped_array_bound");umem.npgs=xp.dma_pages_cnt=1;umem.size=12288;
    unsigned long flags;spin_lock_irqsave(&p.tx_lock,flags);
    int ret=xsk_mech_pool_dma_check_locked(&p,&pool,&batch.f[1],22,58);
    spin_unlock_irqrestore(&p.tx_lock,flags);CHECK("mapped_page_array_bound",ret==-ERANGE);record_case();
}
static void test_transactional_prefix(void)
{
    reset("transactional_prefix_failure");tags[1]=77;tb.pool_lease[1].kind=3;tb.pool_lease[1].u.pool.owner=(void*)0x1234;
    struct xdev_ext_net_lease saved=tb.pool_lease[1];batch.f[2].pool_priv=&heads[0];
    CHECK("prefix_refusal",xsk_xdev_ext_mech_submit(&st,&batch)==-ERANGE);
    CHECK("prefix_prod_restore",p.ring.prod==0 && p.ring.issued==0 && p.ring.cons==0 && p.ring.native_count==0);
    CHECK("prefix_no_effect",!raw_n && !sync_dev_n && !trace_n && !wakeup_n && !callbacks && tags[0]==0 && tags[1]==77 && tags[2]==0);
    CHECK("prefix_no_checksum",!memcmp(chunks[0]+22,packet_prefix,42) && !memcmp(chunks[2]+22,packet_prefix,42));
    struct xdev_ext_net_pool_dma empty_pool={0};
    CHECK("prefix_metadata_zero",!memcmp(&tb.pool_lease[0].u.pool,&empty_pool,sizeof(empty_pool)));
    struct xsk_mech_zc_slot empty_slots[8]={0};CHECK("prefix_slots_unchanged",!memcmp(slots,empty_slots,sizeof(slots)));
    CHECK("prefix_metadata_cleanup",tb.pool_lease[0].kind==0 && tb.pool_lease[2].kind==0 && !memcmp(&saved,&tb.pool_lease[1],sizeof(saved)));record_case();
    for(int v=0;v<3;v++){
        reset("prepare_frame_error_rollback");
        if(v==0)batch.nr_frames=2;
        if(v==1)xst.tx_desc[2].addr=8191;
        if(v==2)xst.tx_desc[2].addr=8192+((u64)UINT32_MAX)+1;
        CHECK("prepare_frame_precise_error",xsk_xdev_ext_mech_submit(&st,&batch)==-ERANGE);
        CHECK("prepare_frame_atomic",p.ring.prod==0 && !sync_dev_n && !trace_n && !callbacks && !tags[0] && !tags[1] && !tags[2] && tb.pool_lease[0].kind==0 && tb.pool_lease[1].kind==0);
        CHECK("prepare_frame_header_unchanged",!memcmp(chunks[0]+22,packet_prefix,42));record_case();
    }
    reset("occupied_unsent_lease");tb.pool_lease[1].kind=3;tb.pool_lease[1].u.pool.owner=(void*)0x1234;saved=tb.pool_lease[1];
    CHECK("occupied_refusal",xsk_xdev_ext_mech_submit(&st,&batch)==-EBUSY);
    CHECK("occupied_not_zeroed",!memcmp(&saved,&tb.pool_lease[1],sizeof(saved)) && tb.pool_lease[0].kind==0 && p.ring.prod==0 && !sync_dev_n && !trace_n && !callbacks);record_case();
}
#endif
static void invalid_mapping_red(void)
{
    reset("invalid_mapping_refusal");xp.dma_pages_cnt=2;
    int ret=xsk_xdev_ext_mech_submit(&st,&batch);
    printf("OBSERVED invalid_mapping return=%d sync=%d trace=%d prod=%u\n",ret,sync_dev_n,trace_n,p.ring.prod);
    CHECK("invalid_mapping_refusal",ret==-ENXIO);
    CHECK("invalid_mapping_no_effect",sync_dev_n==0 && trace_n==0 && tags[0]==0 && p.ring.prod==0);
    record_case();
}
int main(int argc,char**argv)
{
    if(argc>1 && !strcmp(argv[1],"invalid")){invalid_mapping_red();return failures?1:0;}
    test_all_unsent();test_partial_and_none();test_preflight();test_wakeup();test_tail_hole();test_setonly_and_eagain();test_excess();test_stop_unmap();test_actual_family_host();
#if HAVE_POOL
    test_family_pool();test_provider_guards();test_transactional_prefix();
#else
    puts("SETUP candidate POOL_DMA API/provider/metadata absent; new API tests not executed");
#endif
    printf("RESULT assertions_failed=%d pool_api=%d\n",failures,HAVE_POOL);return failures?1:0;
}

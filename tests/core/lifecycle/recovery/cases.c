/* SPDX-License-Identifier: GPL-2.0 */
#define EXPECT(c,msg) do {if (!(c)) {fprintf(stderr,"RECOVERY_ASSERT %s\n",msg);failures++;}}while(0)
int main(int argc, char **argv)
{
    struct io_uring_xdev_ext_umem_reg reg = reg_at(0x910000);
    struct io_ring_ctx ctx = {};
    struct task_struct task = {};
    struct mm_struct mm;
    struct xdev_ext_mech_pool borrower;
    struct xdev_ext_mech_session s = {};
    struct xdev_ext_mech_batch batch = {};
    u8 transform_owner[NR_FRAMES] = {};
    struct xdev_ext_mech_life retained[NR_FRAMES], borrower_life;
    u8 retained_custody[NR_FRAMES];
    unsigned char payload[NR_FRAMES * PAGE_SIZE];
    __u64 bclaim, producer, retry;
    u32 old_active;
    bool payload_ok = true;
    const char *mode;
    bool positive, consumer;
    int claim_ret;

    assert(argc == 2); mode = argv[1];
    positive = !strcmp(mode,"producer") || !strcmp(mode,"consumer");
    consumer = !strcmp(mode,"consumer") || !strcmp(mode,"foreign-consumer") ||
               !strcmp(mode,"stale-consumer");
    use_mm(&task,&mm,91);
    assert(!io_xdev_ext_umem_register(&ctx,&reg));
    assert(!io_xdev_ext_umem_mech_pool_bind(&s.pool,&ctx,&layout));
    assert(!io_xdev_ext_umem_mech_pool_bind(&borrower,&ctx,&layout));
    s.life=s.pool.life; s.batches=&batch; s.depth=1;
    s.transform_owner=transform_owner; s.nr_stages=s.nr_bound=1; s.st[0].cls=&ops; s.st[0].priv=&requester;
    spin_lock_init(&s.lock); atomic_init(&s.native_controls.refs,0);
    s.ss.state=XDEV_EXT_MECH_SESSION_ZOMBIE; s.ss.sequestered=1;
    s.ss.q.evidence=1; s.ss.q.stages=1; s.ss.q.settled=true;
    s.last_err=-EIO; s.id=91;
    batch.s=&s; batch.bs.state=XDEV_EXT_MECH_B_SEQUESTERED;
    batch.bs.native_sequester=true; batch.sequester=true;
    batch.present=batch.life_active=1; batch.nr_frames=1; batch.producing=!consumer;
    batch.f[0].index=0;
    assert(!xdev_ext_mech_frame_move(&s.pool.state[0],XDEV_EXT_MECH_F_USER,XDEV_EXT_MECH_F_HELD));
    assert(!xdev_ext_mech_life_claim(&s.life[0],0,&producer));
    if (consumer) {
        assert(!xdev_ext_mech_life_publish(&s.life[0],producer,
                    !strcmp(mode,"foreign-consumer")?2:1,PAGE_SIZE));
        assert(!xdev_ext_mech_life_acquire(&s.life[0],0,XDEV_EXT_MECH_L_ACQ_FANOUT,&batch.life_token[0]));
        if (!strcmp(mode,"foreign-consumer"))
            assert(!xdev_ext_mech_life_acquire(&s.life[0],1,XDEV_EXT_MECH_L_ACQ_FANOUT,&retry));
    } else batch.life_token[0]=producer;
    assert(!xdev_ext_mech_frame_move(&s.pool.state[0],XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_INFLIGHT));
    assert(!xdev_ext_mech_frame_move(&s.pool.state[0],XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_SEQUESTERED));
    assert(!xdev_ext_mech_frame_move(&borrower.state[1],XDEV_EXT_MECH_F_USER,XDEV_EXT_MECH_F_HELD));
    assert(!xdev_ext_mech_life_claim(&borrower.life[1],1,&bclaim));
    /* Keep a published active borrower, including meaningful valid_len. */
    assert(!xdev_ext_mech_life_publish(&borrower.life[1],bclaim,1,PAGE_SIZE-17));
    assert(!xdev_ext_mech_life_acquire(&borrower.life[1],1,
                XDEV_EXT_MECH_L_ACQ_EXCLUSIVE,&bclaim));
    borrower_life=borrower.life[1];
    for (u32 i=0;i<sizeof(payload);i++) payload[i]=(unsigned char)(i*37+0xa7);
    memcpy(borrower.vaddr,payload,sizeof(payload));
    requester.proven=5;
    if (!strcmp(mode,"no-proof")) requester.proven=0;
    if (!strcmp(mode,"wrong-requester")) {
        requester.proven=0;
        other_requester.proven=5;
        assert(xdev_ext_peer_requester_evidence(&other_requester,submitted_epoch)==
               XDEV_EXT_PEER_EVIDENCE_COVERED);
    }
    if (!strcmp(mode,"same-epoch")) requester.proven=4;
    if (!strcmp(mode,"unsettled")) s.ss.q.settled=false;
    if (!strcmp(mode,"inflight")) s.ss.inflight=1;
    if (!strcmp(mode,"references")) s.ss.refs=1;
    if (!strcmp(mode,"native-control")) atomic_store(&s.native_controls.refs,1);
    if (!strcmp(mode,"unbind-fails")) unbind_error=-EIO;
    if (!strcmp(mode,"release-fails")) release_error=-EBUSY;
    if (!strcmp(mode,"stale-generation")) {
        assert(!xdev_ext_mech_life_fail_produce(&s.life[0],producer));
        assert(!xdev_ext_mech_life_claim(&s.life[0],0,&retry));
    }
    if (!strcmp(mode,"stale-consumer")) {
        assert(xdev_ext_mech_life_fail_put(&s.life[0],batch.life_token[0])>=0);
        assert(!xdev_ext_mech_life_claim(&s.life[0],0,&retry));
        assert(!xdev_ext_mech_life_publish(&s.life[0],retry,1,PAGE_SIZE-31));
        assert(!xdev_ext_mech_life_acquire(&s.life[0],0,
                    XDEV_EXT_MECH_L_ACQ_FANOUT,&retry));
    }
    if (!strcmp(mode,"multi-frame-invalid")) {
        batch.nr_frames=2; batch.present=batch.life_active=3; batch.f[1].index=2;
        assert(!xdev_ext_mech_frame_move(&s.pool.state[2],XDEV_EXT_MECH_F_USER,XDEV_EXT_MECH_F_HELD));
        assert(!xdev_ext_mech_life_claim(&s.life[2],0,&batch.life_token[1]));
        assert(!xdev_ext_mech_frame_move(&s.pool.state[2],XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_INFLIGHT));
        assert(!xdev_ext_mech_frame_move(&s.pool.state[2],XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_SEQUESTERED));
        assert(!xdev_ext_mech_life_fail_produce(&s.life[2],batch.life_token[1]));
        assert(!xdev_ext_mech_life_claim(&s.life[2],0,&retry));
    }
    if (!strcmp(mode,"foreign-frame")) batch.f[0].index=1;
    if (!strcmp(mode,"active-transform")) batch.transform.active=true;
    memcpy(retained,s.life,sizeof(retained));
    memcpy(retained_custody,s.pool.state,sizeof(retained_custody));
    old_active=batch.life_active;
    /* This scoped check stops before final class unreserve. Recovery must
     * preserve the transform reservation while retiring its failed claim. */
    if (!strcmp(mode,"reserved-output")) {
        transform_owner[0]=1;
        EXPECT(!xdev_ext_mech_recover_frames(&s),"reserved frame recovery failed");
        EXPECT(borrower.state[0]==XDEV_EXT_MECH_F_HELD,"reserved frame escaped reservation");
        EXPECT(xdev_ext_mech_life_phase(&borrower.life[0])==XDEV_EXT_MECH_L_FREE,
               "reserved frame retained failed lifecycle claim");
        EXPECT(!batch.life_active,"reserved frame active claim was not retired");
        goto check_borrower;
    }
    INIT_LIST_HEAD(&s.quarantine_node);
    list_add_tail(&s.quarantine_node,&xdev_ext_mech_quarantined);
    xdev_ext_mech_recovery_fn(NULL);
    EXPECT(s.last_err==-EIO,"recovery changed failed I/O into success");
    if (positive) {
        EXPECT(released_sessions==1,"covered settled session not released");
        EXPECT(borrower.state[0]==XDEV_EXT_MECH_F_USER,"covered original frame did not return to USER");
        claim_ret=xdev_ext_mech_life_claim(&borrower.life[0],0,&retry);
        EXPECT(claim_ret==0,"covered original frame cannot acquire a fresh generation");
        if (!claim_ret) {
            EXPECT(xdev_ext_mech_life_claim_gen(retry)>xdev_ext_mech_life_claim_gen(batch.life_token[0]),
                   "original generation was reused");
            EXPECT((consumer ? xdev_ext_mech_life_fail_put(&borrower.life[0],batch.life_token[0]) :
                    xdev_ext_mech_life_fail_produce(&borrower.life[0],batch.life_token[0]))==-ESTALE,
                   "late old token changed the new claim");
            memset(borrower.vaddr,0x5c,PAGE_SIZE);

        }
        xdev_ext_mech_recovery_fn(NULL);
        EXPECT(released_sessions==1,"repeated recovery released the same session twice");
    } else {
        EXPECT(!released_sessions,"negative recovery condition released session resources");
        EXPECT(s.ss.state==XDEV_EXT_MECH_SESSION_ZOMBIE && !list_empty(&xdev_ext_mech_quarantined),
               "negative recovery condition lost the quarantined session");
        EXPECT(!memcmp(retained,s.life,sizeof(retained)) &&
               !memcmp(retained_custody,s.pool.state,sizeof(retained_custody)),
               "negative recovery condition changed a frame before full validation");
        EXPECT(batch.life_active==old_active,"failed prevalidation retired an earlier claim");
        EXPECT(!memcmp(borrower.vaddr,payload,sizeof(payload)),"negative recovery changed UMEM payload");
    }
check_borrower:
    EXPECT(borrower.life[1].ctrl==borrower_life.ctrl &&
           borrower.life[1].valid_len==borrower_life.valid_len &&
           borrower.state[1]==XDEV_EXT_MECH_F_HELD,
           "recovery changed live borrower's claim, length or custody");
    for (u32 i=PAGE_SIZE;i<2*PAGE_SIZE;i++)
        if (((unsigned char *)borrower.vaddr)[i]!=payload[i]) payload_ok=false;
    EXPECT(payload_ok,"recovery changed a byte of live borrower payload");
    if (!failures) printf("RECOVERY_CASE PASS %s\n",mode);
    return !!failures;
}

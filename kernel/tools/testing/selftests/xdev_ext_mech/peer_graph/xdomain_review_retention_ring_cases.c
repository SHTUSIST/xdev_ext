/* SPDX-License-Identifier: GPL-2.0 */
/* Requirement: real ring lifecycle and real built-in core must agree on
 * descriptor+coherent bytes, preserve UNKNOWN across recreated link objects,
 * and refuse new DMA allocation at the requester/global limits. */
static struct xdev_ext_requester_retention_stats joint_snapshot(void)
{
    struct xdev_ext_requester_retention_stats s;
    xdev_ext_requester_retention_snapshot(&fixture_pdev,&s);
    return s;
}
static void joint_full_unknown(void)
{
    review_start();
    struct xdev_ext_xd_ep ep={.xl=&review_link,.chan=0};u8 msg[128]={0};
    assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,msg,sizeof(msg)));
    stop_nhi_gone=true;review_stop();review_free();stop_nhi_gone=false;
}
static void joint_healthy(void)
{
    review_init();
    struct xdev_ext_requester_retention_stats s=joint_snapshot();
    /* 2*128*16 control descriptors + 2*256*16 data descriptors,
     * plus 128*4096 RX and 128*128 TX coherent bytes. */
    assert(s.generations==1 && s.reserved_bytes==552960);
    assert(!s.retained_generations && !s.retained_bytes);
    for(unsigned i=0;i<4;i++) {review_start();review_stop();s=joint_snapshot();
        assert(s.reserved_bytes==552960 && !s.retained_bytes && dma_allocs==2);}
    review_free();s=joint_snapshot();
    assert(!s.generations && !s.reserved_bytes && !s.retained_bytes);
    assert(!s.global_reserved_bytes && !s.global_retained_bytes);
    assert(dma_frees==2 && fixture_pdev.refs==0);
}
static void joint_unknown(void)
{
    review_init();void *rx=review_link.ctl_rx_buf,*tx=review_link.ctl_tx_buf;
    joint_full_unknown();struct xdev_ext_requester_retention_stats s=joint_snapshot();
    assert(s.generations==1 && s.retained_generations==1);
    assert(s.reserved_bytes==552960 && s.retained_bytes==552960);
    assert(s.global_reserved_bytes==552960 && s.global_retained_bytes==552960);
    assert(!dma_is_freed(rx) && !dma_is_freed(tx) && !dma_frees);
    assert(descriptor_quarantines==4 && fixture_pdev.refs==3);
    /* New subclass/link lifetime, same requester. Healthy allocation/free must
     * release only its own reservation, never erase prior retained charges. */
    review_init();s=joint_snapshot();assert(s.generations==2 && s.reserved_bytes==1105920);
    review_free();s=joint_snapshot();
    assert(s.generations==1 && s.reserved_bytes==552960 && s.retained_bytes==552960);
    assert(fixture_pdev.refs==3);
}
static void joint_partial_native(void)
{
    review_init();fail_start_at=4;stop_nhi_gone=true;
    mutex_lock(&review_link.ctl_mutex);
    assert(xdev_ext_xd_rings_start(&review_link)==-ENODEV);
    mutex_unlock(&review_link.ctl_mutex);
    assert(!review_link.ctl_rx_alloc->accepted && !review_link.ctl_tx_alloc->accepted);
    review_free();
    struct xdev_ext_requester_retention_stats s=joint_snapshot();
    /* Two started control descriptors (2048 each) and one data TX (4096),
     * while all never-submitted coherent control backing was truly freed. */
    assert(s.generations==1 && s.retained_generations==1);
    assert(s.reserved_bytes==552960 && s.retained_bytes==8192);
    assert(dma_frees==2 && descriptor_quarantines==3 && fixture_pdev.refs==1);
}
static void joint_limits(bool global)
{
    fixture_nhi.hop_count=global?1023:5;
    unsigned expected=global?121:2;
    for(unsigned i=0;i<expected;i++) {review_init();joint_full_unknown();}
    unsigned before=dma_allocs;
    memset(&review_link,0,sizeof(review_link));fixture_xl=&review_link;
    review_link.xd=&fixture_xd;review_link.nhi_pdev=&fixture_pdev;review_link.channels=1;
    spin_lock_init(&review_link.lock);mutex_init(&review_link.ctl_mutex);mutex_init(&review_link.ep_mutex);
    assert(xdev_ext_xd_rings_alloc(&review_link)==-ENOSPC);
    assert(dma_allocs==before && !review_link.rings && !dma_frees);
    struct xdev_ext_requester_retention_stats s=joint_snapshot();
    assert(s.generations==expected && s.retained_generations==expected);
    assert(s.global_limit==67108864 && s.reserved_bytes==552960ULL*expected);
    assert(s.retained_bytes==s.reserved_bytes && s.global_reserved_bytes==s.reserved_bytes);
    fprintf(stderr,"# actual ring->built-in ledger %s generations=%u reserved=%llu retained=%llu limit=%llu\n",global?"global":"requester",s.generations,(unsigned long long)s.reserved_bytes,(unsigned long long)s.retained_bytes,(unsigned long long)s.global_limit);
}
int main(int argc,char **argv)
{
    assert(argc==2);switch(atoi(argv[1])) {
    case 1:joint_healthy();break;case 2:joint_unknown();break;
    case 3:joint_partial_native();break;case 4:joint_limits(false);break;
    case 5:joint_limits(true);break;default:abort();}
    return 0;
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Independent requirements: healthy stop reuses control allocation; UNKNOWN
 * never releases accepted bytes. No replacement production decision here. */
static struct xdev_ext_xd_link review_link;
static void review_init(void)
{
    memset(&review_link,0,sizeof(review_link)); fixture_xl=&review_link;
    review_link.xd=&fixture_xd; review_link.nhi_pdev=&fixture_pdev;
    review_link.channels=1; review_link.local_inc=0x1111;
    spin_lock_init(&review_link.lock); mutex_init(&review_link.ctl_mutex); mutex_init(&review_link.ep_mutex);
    assert(!xdev_ext_xd_rings_alloc(&review_link));
}
static void review_start(void)
{
    mutex_lock(&review_link.ctl_mutex);
    assert(!xdev_ext_xd_rings_start(&review_link));
    mutex_unlock(&review_link.ctl_mutex);
    review_link.up=true;
}
static void review_stop(void)
{
    mutex_lock(&review_link.ctl_mutex);
    xdev_ext_xd_rings_stop(&review_link);
    mutex_unlock(&review_link.ctl_mutex);
}
static void review_free(void)
{
    mutex_lock(&review_link.ctl_mutex);
    xdev_ext_xd_rings_free(&review_link);
    mutex_unlock(&review_link.ctl_mutex);
}
static void healthy_reuse(bool with_tx)
{
    review_init();
    void *rx=review_link.ctl_rx_buf,*tx=review_link.ctl_tx_buf;
    unsigned initial=dma_allocs;
    struct xdev_ext_xd_ep ep={.xl=&review_link,.chan=0};
    u8 raw[128]={0};
    for(unsigned i=0;i<100;i++) {
        review_start();
        if(with_tx) assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,sizeof(raw)));
        review_stop();
        fprintf(stderr,"# healthy iteration=%u allocations=%u frees=%u rx_retained=%d tx_retained=%d\n",i,dma_allocs,dma_frees,review_link.ctl_rx_buf==rx,review_link.ctl_tx_buf==tx);
        assert(review_link.ctl_rx_buf==rx && review_link.ctl_tx_buf==tx);
        assert(dma_allocs==initial && !dma_frees);
        assert(list_empty(&xdev_ext_xd_ctl_quarantine));
        assert(review_link.ctl_rx_alloc->accepted==review_link.ctl_rx_alloc->retired);
        assert(review_link.ctl_tx_alloc->accepted==review_link.ctl_tx_alloc->retired);
        for(unsigned n=0;n<XDEV_EXT_XD_CTL_RING;n++) {
            assert(!review_link.ctl_rx_alloc->pending[n]);
            assert(!review_link.ctl_tx_alloc->pending[n]);
        }
    }
    review_free(); assert(dma_frees==dma_allocs && fixture_pdev.refs==0);
}
static void unknown_preservation(void)
{
    review_init(); review_start();
    void *rx=review_link.ctl_rx_buf,*tx=review_link.ctl_tx_buf;
    struct xdev_ext_xd_ep ep={.xl=&review_link,.chan=0};u8 raw[128]={0};
    assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,sizeof(raw)));
    going_late_normal=true; late_normal_ring=review_link.ctl_rx;
    stop_nhi_gone=true; review_stop();
    assert(review_link.nhi_gone);
    assert(!dma_is_freed(rx)&&!dma_is_freed(tx));
    unsigned before=dma_allocs;
    assert(xdev_ext_xd_rings_start(&review_link)<0);
    assert(dma_allocs==before);
    review_free();
    assert(!dma_is_freed(rx)&&!dma_is_freed(tx));
    assert(!dma_frees && descriptor_quarantines==4);
    struct xdev_ext_requester_retention_stats retained;
    xdev_ext_requester_retention_snapshot(&fixture_pdev,&retained);
    assert(retained.generations==1 && retained.retained_generations==1);
    /* This recorder has no native-ring PCI get (covered by actual NHI suite).
     * The two retained coherent mappings and actual built-in ledger each own one. */
    assert(fixture_pdev.refs==3);
}
static void quarantine_admission(void)
{
    /* Safety bound for this regression: 64 MiB on ONE NHI across reprobes.
     * An implementation may reject sooner; exhausting the recorder is not
     * counted as safe admission. Unknown records are never made free. */
    const size_t ceiling=64UL*1024*1024;
    bool refused=false; size_t retained=0; bool accepted[1024]={0};
    for(unsigned i=0;i<160;i++) {
        memset(&review_link,0,sizeof(review_link)); fixture_xl=&review_link;
        review_link.xd=&fixture_xd; review_link.nhi_pdev=&fixture_pdev; review_link.channels=1;
        spin_lock_init(&review_link.lock);mutex_init(&review_link.ctl_mutex);mutex_init(&review_link.ep_mutex);
        unsigned allocation_begin=dma_allocs;
        int ret=xdev_ext_xd_rings_alloc(&review_link);
        if(ret) { refused=true; break; }
        mutex_lock(&review_link.ctl_mutex);ret=xdev_ext_xd_rings_start(&review_link);mutex_unlock(&review_link.ctl_mutex);
        if(ret) { review_free(); refused=true;break; }
        review_link.up=true;u8 raw[128]={0};struct xdev_ext_xd_ep ep={.xl=&review_link};
        assert(!xdev_ext_xd_dev_ops.ctl_send(&ep,raw,sizeof(raw)));
        for(unsigned k=allocation_begin;k<dma_allocs;k++)accepted[k]=true;
        stop_nhi_gone=true;review_stop();review_free();stop_nhi_gone=false;
        retained=0;for(unsigned k=0;k<dma_allocs;k++) if(!dma_records[k].freed) retained+=dma_records[k].bytes;
        for(unsigned k=0;k<dma_allocs;k++)if(accepted[k])assert(!dma_records[k].freed);
        if(retained>ceiling) break;
    }
    for(unsigned k=0;k<dma_allocs;k++)if(accepted[k])assert(!dma_records[k].freed);
    fprintf(stderr,"# reprobe retained=%zu ceiling=%zu refused=%d allocations=%u\n",retained,ceiling,refused,dma_allocs);
    assert(refused && retained<=ceiling);
}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned n=(unsigned)atoi(argv[1]);
    if(n==1)healthy_reuse(false);else if(n==2)healthy_reuse(true);
    else if(n==3)unknown_preservation();else if(n==4)quarantine_admission();else abort();
    return 0;
}

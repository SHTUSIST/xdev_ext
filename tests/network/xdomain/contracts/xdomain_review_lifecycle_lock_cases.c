/* SPDX-License-Identifier: GPL-2.0 */
/* Two real pthreads; no scheduler timing assumptions. Main owns TB lock,
 * worker reaches production lock acquisition, main publishes unplugged and
 * synchronously runs actual service remove while retaining the TB lock. */
static struct pci_dev review_pdev;
static struct nhi review_nhi={.pdev=&review_pdev};
static struct tb_switch review_root,review_remote;
static struct tb_cm review_cm;
static struct tb review_tb={.nhi=&review_nhi,.root_switch=&review_root,.priv=&review_cm};
static uuid_t review_local={{0x10}},review_remote_uuid={{0x20}};
static struct device review_parent={.owner=&review_remote};
static struct tb_xdomain review_domain={.dev={.parent=&review_parent},.tb=&review_tb,.route=1,.local_uuid=&review_local,.remote_uuid=&review_remote_uuid};
static struct tb_service review_service={.parent=&review_domain};
static struct xdev_ext_xd_link *review_xl;
static unsigned review_case;
static void *review_worker(void *unused)
{
    (void)unused;review_is_worker=true;
    if(review_case==1)xdev_ext_xd_connect_work(&review_xl->connect_work);
    else xdev_ext_xd_link_down(review_xl,-ENOLINK);
    assert(!pthread_mutex_lock(&review_gate));review_done=true;
    pthread_cond_broadcast(&review_condition);assert(!pthread_mutex_unlock(&review_gate));
    return NULL;
}
static void review_remove(struct tb_xdomain *xd)
{
    /* Same publication->synchronous service-unbind ordering as CM hotplug.
     * CM owns tunnel cleanup after unplugged publication. */
    fprintf(stderr,"# main owns TB lock; publishing unplugged then entering production service remove\n");fflush(stderr);
    WRITE_ONCE(xd->is_unplugged,true);
    __tb_disconnect_xdomain_paths(xd->tb,xd,21,22,23,24);
    xdev_ext_xd_remove(&review_service);
}
int main(int argc,char **argv)
{
    assert(argc==2);review_case=atoi(argv[1]);
    mutex_init(&review_tb.lock);review_tb_mutex=&review_tb.lock;
    review_remote.port.xdomain=&review_domain;
    review_cm.tunnel_list.next=review_cm.tunnel_list.prev=&review_cm.tunnel_list;
    assert(!xdev_ext_xd_init());review_service.dev.owner=&review_service;
    assert(!xdev_ext_xd_probe(&review_service,NULL));review_xl=review_service.drvdata;
    /* Keep one independent reference across remove so postconditions can
     * inspect real gone/work state before dropping the final link reference. */
    kref_get(&review_xl->ref);
    review_xl->remote_login=(struct xdev_ext_xd_login){.length_sn=27,.type=XDEV_EXT_XD_LOGIN,.proto_version=3,.channels=1,.ctl_tx_path=37,.data_tx_path={41},.incarnation=0x1111,.caps=3};
    if(review_case==2) {
        assert(!tb_approve_xdomain_paths(&review_tb,&review_domain,21,22,23,24));
        rings_running=true;review_xl->up=true;review_xl->remote_logged_in=true;
    }
    mutex_lock(&review_tb.lock);
    pthread_t thread;review_worker_started=true;
    assert(!pthread_create(&thread,NULL,review_worker,NULL));
    assert(!pthread_mutex_lock(&review_gate));
    while(!review_entered&&!review_done)assert(!pthread_cond_wait(&review_condition,&review_gate));
    assert(review_entered);review_continue=true;pthread_cond_broadcast(&review_condition);
    assert(!pthread_mutex_unlock(&review_gate));
    review_remove(&review_domain);
    mutex_unlock(&review_tb.lock);
    assert(!pthread_join(thread,NULL));
    assert(review_done&&review_xl->gone&&!review_xl->xd&&!review_xl->svc);
    assert(!review_xl->login_work.work.pending&&!review_xl->connect_work.pending&&!review_xl->down_work.pending);
    assert(list_empty(&review_cm.tunnel_list));
    assert(review_tunnels==review_tunnels_freed);
    if(review_case==1)assert(!review_activations);else assert(review_activations==1);
    xdev_ext_xd_link_put(review_xl);assert(!review_pdev.refs);
    fprintf(stderr,"# remove and worker exited; tunnels=%u freed=%u activations=%u\n",review_tunnels,review_tunnels_freed,review_activations);
    return 0;
}

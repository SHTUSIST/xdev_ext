/* SPDX-License-Identifier: GPL-2.0 */
/* Both peers execute actual production handler/connect/login. The synchronous
 * request/response boundary routes bytes into the other real packet handler. */
static struct pci_dev ready_pdev[2];
static struct nhi ready_nhi[2];
static struct tb ready_tb[2];
static uuid_t ready_uuid[2]={{{0x11}},{{0x22}}};
static struct tb_xdomain ready_domain[2];
static struct tb_service ready_service[2];
static struct xdev_ext_xd_link *ready_link[2];
static void ready_fresh(void)
{
    assert(!xdev_ext_xd_init());
    for(unsigned i=0;i<2;i++) {
        ready_nhi[i].pdev=&ready_pdev[i];ready_tb[i].nhi=&ready_nhi[i];
        ready_domain[i]=(struct tb_xdomain){.route=1,.tb=&ready_tb[i],.local_uuid=&ready_uuid[i],.remote_uuid=&ready_uuid[1-i]};
        ready_service[i]=(struct tb_service){.parent=&ready_domain[i],.prtcstns=XDEV_EXT_XD_CAP_E2E};
        ready_service[i].dev.owner=&ready_service[i];
        assert(!xdev_ext_xd_probe(&ready_service[i],NULL));ready_link[i]=ready_service[i].drvdata;
    }
}
static void ready_login(unsigned i)
{
    live_link=ready_link[i];jiffies+=ready_link[i]->login_work.work.delay;
    ready_link[i]->login_work.work.pending=false;
    xdev_ext_xd_login_work(&ready_link[i]->login_work.work);
}
static void ready_connect(unsigned i)
{
    assert(ready_link[i]->connect_work.pending);ready_link[i]->connect_work.pending=false;
    live_link=ready_link[i];xdev_ext_xd_connect_work(&ready_link[i]->connect_work);
}
static void initially_not_ready(void)
{
    ready_fresh();ready_login(0);
    fprintf(stderr,"# peer initially ready=%d paths_calls=%u response=%u\n",review_ready_native(ready_link[1])->paths,review_ready_native(ready_link[1])->path_calls,last_response.status);
    assert(last_response.status==EAGAIN);
    assert(ready_link[1]->connect_work.pending&&!review_ready_native(ready_link[1])->paths);
}
static void failed_setup_never_positive(void)
{
    ready_fresh();ready_login(0);review_ready_failed=ready_link[1];ready_connect(1);
    assert(!review_ready_native(ready_link[1])->paths&&review_ready_native(ready_link[1])->path_calls==1);
    /* Retransmit same real initial advertisement after failed setup. */
    struct xdev_ext_xd_login advertisement=last_request;
    assert(xdev_ext_xd_handle_packet(&advertisement,sizeof(advertisement),NULL)==1);
    fprintf(stderr,"# failed peer setup attempts=%u response=%u\n",review_ready_native(ready_link[1])->path_calls,last_response.status);
    assert(last_response.status==EAGAIN&&!ready_link[1]->up);
}
static void simultaneous_peers_progress_without_up_precondition(void)
{
    ready_fresh();ready_login(0);assert(last_response.status==EAGAIN);
    ready_login(1);assert(last_response.status==EAGAIN);
    assert(!ready_link[0]->up&&!ready_link[1]->up);
    ready_connect(0);ready_connect(1);
    for(unsigned i=0;i<2;i++) {
        assert(review_ready_native(ready_link[i])->running&&review_ready_native(ready_link[i])->paths);
        assert(ready_link[i]->remote_logged_in&&ready_link[i]->accepted_inc==ready_link[1-i]->local_inc);
    }
    assert(!ready_link[0]->up&&!ready_link[1]->up);
    /* The responder is still !up here: requiring up would deadlock startup. */
    ready_login(0);assert(last_response.status==0&&ready_link[0]->up);
    ready_login(1);assert(last_response.status==0&&ready_link[1]->up);
    assert(ready_link[0]->remote_inc==ready_link[1]->local_inc&&ready_link[1]->remote_inc==ready_link[0]->local_inc);
    fprintf(stderr,"# both actual peers up after ready responses; path calls A=%u B=%u\n",review_ready_native(ready_link[0])->path_calls,review_ready_native(ready_link[1])->path_calls);
}
int main(int argc,char **argv)
{
    assert(argc==2);switch(atoi(argv[1])) {
    case 1:initially_not_ready();break;case 2:failed_setup_never_positive();break;
    case 3:simultaneous_peers_progress_without_up_precondition();break;default:abort();}
    return 0;
}

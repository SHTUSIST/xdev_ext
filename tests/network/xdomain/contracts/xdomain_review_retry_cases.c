/* SPDX-License-Identifier: GPL-2.0 */
/* Independent public behavior checks; no private retry/counter field names. */
static struct pci_dev review_retry_pdev;
static struct nhi review_retry_nhi={.pdev=&review_retry_pdev};
static struct tb review_retry_tb={.nhi=&review_retry_nhi};
static uuid_t review_retry_local={{0x11}},review_retry_remote={{0x22}};
static struct tb_xdomain review_retry_domain={.tb=&review_retry_tb,.route=1,.local_uuid=&review_retry_local,.remote_uuid=&review_retry_remote};
static struct tb_service review_retry_service={.parent=&review_retry_domain,.prtcstns=XDEV_EXT_XD_CAP_E2E};
static struct xdev_ext_xd_link *review_retry_xl;
static void review_retry_fresh(void)
{
    assert(!xdev_ext_xd_init());review_retry_service.dev.owner=&review_retry_service;
    assert(!xdev_ext_xd_probe(&review_retry_service,NULL));review_retry_xl=review_retry_service.drvdata;
}
static struct xdev_ext_xd_login review_retry_peer(u64 nonce)
{
    struct xdev_ext_xd_login l={.route_lo=1,.length_sn=27,.type=XDEV_EXT_XD_LOGIN,.command_id=0x76543210,.proto_version=2,.channels=1,.ctl_tx_path=37,.data_tx_path={41},.incarnation=nonce,.caps=1};
    memcpy(l.uuid,&xdev_ext_xd_proto_uuid,16);memcpy(l.initiator_uuid,&review_retry_remote,16);memcpy(l.target_uuid,&review_retry_local,16);return l;
}
static unsigned long review_retry_delay(void)
{
    assert(review_retry_xl->login_work.work.pending);
    return review_retry_xl->login_work.work.delay;
}
static void review_retry_advance(void)
{
    unsigned long delay=review_retry_delay();jiffies+=delay;
    review_retry_xl->login_work.work.pending=false;
    xdev_ext_xd_login_work(&review_retry_xl->login_work.work);
    /* Run newly queued immediate work, as the real workqueue does at this deadline. */
    if(review_retry_xl->connect_work.pending)run_work(&review_retry_xl->connect_work);
}
static void review_retry_connect(u64 nonce)
{
    struct xdev_ext_xd_login l=review_retry_peer(nonce);assert(xdev_ext_xd_handle_packet(&l,sizeof(l),NULL)==1);
    if(review_retry_xl->connect_work.pending) {review_retry_xl->connect_work.pending=false;xdev_ext_xd_connect_work(&review_retry_xl->connect_work);}
}
static ssize_t review_attr(const char *name,char *buf)
{
    for(unsigned i=0;xdev_ext_xd_attrs[i];i++)if(!strcmp(xdev_ext_xd_attrs[i]->name,name)) {
        struct device_attribute *a=container_of(xdev_ext_xd_attrs[i],struct device_attribute,attr);
        assert((a->attr.mode&0222)==0&&a->show);
        return a->show(&review_retry_service.dev,a,buf);
    }
    fprintf(stderr,"# required public read-only attr missing: %s\n",name);assert(!"missing public diagnostic behavior");return -1;
}
static long long review_value(const char *text,const char *name)
{
    char pattern[96];snprintf(pattern,sizeof(pattern),"%s=",name);const char *p=text;
    while((p=strstr(p,pattern))) {if(p==text||p[-1]==' '||p[-1]=='\n'){char *end;long long value=strtoll(p+strlen(pattern),&end,10);assert(end!=p+strlen(pattern));return value;}p++;}
    fprintf(stderr,"# required stats field missing: %s; output=%s\n",name,text);assert(!"missing public stats key");return -1;
}
static void review_stats(char *buf)
{
    assert(review_attr("xdev_ext_link_stats",buf)>0);
    const char *keys[]={"version","token","login_attempts","login_errors","version_errors","crc_errors","connect_errors","retries_exhausted","link_ups","last_error","retry_delay_ms","e2e_rx","e2e_tx"};
    for(unsigned i=0;i<ARRAY_SIZE(keys);i++)(void)review_value(buf,keys[i]);
    assert(review_value(buf,"version")>=1&&review_value(buf,"token")==review_retry_xl->token);
}
static void retry_backoff(void)
{
    review_retry_fresh();paths_result=-EIO;
    /* Initial successful request waits for peer; setup then fails. */
    review_retry_advance();review_retry_connect(0x1111);request_result=-EIO;
    for(unsigned i=0;i<9;i++) {
        unsigned long expected=i<6?(1000UL<<i):60000;
        unsigned long actual=review_retry_delay();
        fprintf(stderr,"# retry failure=%u delay=%lu expected=%lu\n",i,actual,expected);
        assert(actual==expected);
        review_retry_advance();
    }
}
static void candidate_budget(void)
{
    review_retry_fresh();paths_result=-EIO;review_retry_advance();
    review_retry_connect(0x999);request_result=-EIO;
    unsigned admitted=(unsigned)ring_starts;
    for(unsigned i=0;i<160;i++) {
        unsigned before=ring_starts;review_retry_connect(0x1000+i);
        if(ring_starts>before)admitted++;
        /* Any pending retry is advanced to its scheduler deadline. */
        if(review_retry_xl->login_work.work.pending)review_retry_advance();
    }
    fprintf(stderr,"# changed-candidate admitted setups=%u across160 nonce changes\n",admitted);
    assert(admitted>0&&admitted<=60);
    char text[4096];review_stats(text);assert(review_value(text,"retries_exhausted")>0);
}
static void candidate_cooldown(void)
{
    review_retry_fresh();paths_result=-EIO;review_retry_advance();
    review_retry_connect(0x1000);request_result=-EIO;unsigned before=ring_starts;
    review_retry_connect(0x2000);
    fprintf(stderr,"# native starts before deadline: before=%u after=%d\n",before,ring_starts);
    assert((unsigned)ring_starts==before);
}
static void stats_schema_and_old_state(void)
{
    review_retry_fresh();char text[4096];review_stats(text);
    const char *zeros[]={"login_attempts","login_errors","version_errors","crc_errors","connect_errors","retries_exhausted","link_ups"};
    for(unsigned i=0;i<ARRAY_SIZE(zeros);i++)assert(review_value(text,zeros[i])==0);
    assert(review_value(text,"e2e_tx")==0);
    assert(review_attr("xdev_ext_link_state",text)>0);
    assert(review_value(text,"version")==1);
    const char *old[]={"token","local_inc","remote_inc","up","closing","nhi_gone","channels"};
    for(unsigned i=0;i<ARRAY_SIZE(old);i++)(void)review_value(text,old[i]);
}
static void stats_actual_events(void)
{
    review_retry_fresh();char text[4096];request_result=-ETIMEDOUT;review_retry_advance();
    review_stats(text);assert(review_value(text,"login_attempts")==1&&review_value(text,"login_errors")==1&&review_value(text,"last_error")==-ETIMEDOUT);
    struct xdev_ext_xd_login l=review_retry_peer(0x1234);l.proto_version=99;
    assert(xdev_ext_xd_handle_packet(&l,sizeof(l),NULL)==1);review_stats(text);assert(review_value(text,"version_errors")==1);
    jiffies+=review_retry_delay();paths_result=-EIO;review_retry_connect(0x1234);review_stats(text);assert(review_value(text,"connect_errors")>=1);
}
static void stats_real_up_and_e2e(void)
{
    review_retry_fresh();review_retry_connect(0x1111);reply_inc=0x1111;
    if(review_retry_xl->login_work.work.pending)review_retry_advance();
    assert(review_retry_xl->up);
    char text[4096];review_stats(text);assert(review_value(text,"link_ups")==1);
    assert(review_value(text,"e2e_rx")==1&&review_value(text,"e2e_tx")==0);
    mutex_lock(&review_retry_xl->ctl_mutex);xdev_ext_xd_maybe_up(review_retry_xl);mutex_unlock(&review_retry_xl->ctl_mutex);
    review_stats(text);assert(review_value(text,"link_ups")==1);
}
int main(int argc,char **argv)
{
    assert(argc==2);switch(atoi(argv[1])) {
    case 1:retry_backoff();break;case 2:candidate_budget();break;case 3:candidate_cooldown();break;
    case 4:stats_schema_and_old_state();break;case 5:stats_actual_events();break;case 6:stats_real_up_and_e2e();break;default:abort();}
    return 0;
}

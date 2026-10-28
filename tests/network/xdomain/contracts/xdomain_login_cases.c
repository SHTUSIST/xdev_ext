/* SPDX-License-Identifier: GPL-2.0 */
/* Inputs and expected effects derive from X3 requirements, not its sample. */
static struct pci_dev pdev;
static struct nhi test_nhi={.pdev=&pdev};
static struct tb test_tb={.nhi=&test_nhi};
static uuid_t local_uuid={{0x10,0x21}}, remote_uuid={{0x30,0x41}};
static struct tb_xdomain domain={.route=0x12345678000000a5ULL,
    .local_uuid=&local_uuid,.remote_uuid=&remote_uuid,.tb=&test_tb};
static struct tb_service service={.parent=&domain,.prtcstns=XDEV_EXT_XD_CAP_E2E};
static struct xdev_ext_xd_link *xl;
static struct xdev_ext_xd_ep endpoint;
static struct xdev_ext_mech_stage stage={.id=71};
static int current_case;
static const char *current_name;
#define CHECK(x) do { if (!(x)) { \
    fprintf(stdout,"not ok %d - %s\n# failed: %s (%s:%d)\n",current_case,current_name,#x,__FILE__,__LINE__); \
    fflush(stdout); exit(1); } } while (0)

static void fresh_link(void)
{
    CHECK(!xdev_ext_xd_init());
    service.dev.owner=&service;
    CHECK(!xdev_ext_xd_probe(&service,NULL));
    xl=service.drvdata;
    CHECK(xl && xl->local_inc && xl->login_work.work.pending);
}
static struct xdev_ext_xd_login peer_login(u64 incarnation)
{
    struct xdev_ext_xd_login packet={
        .route_hi=0x12345678,.route_lo=0x000000a5,.length_sn=27,
        .type=XDEV_EXT_XD_LOGIN,.command_id=0x76543210,
        .proto_version=2,.channels=1,.ctl_tx_path=37,
        .data_tx_path={41},.incarnation=incarnation,.caps=1,
    };
    memcpy(packet.uuid,&xdev_ext_xd_proto_uuid,16);
    memcpy(packet.initiator_uuid,&remote_uuid,16);
    memcpy(packet.target_uuid,&local_uuid,16);
    return packet;
}
static int deliver(struct xdev_ext_xd_login *packet)
{ return registered_handler->callback(packet,sizeof(*packet),NULL); }
static void login_run(void) { run_work(&xl->login_work.work); }
static void connect_run(void) { run_work(&xl->connect_work); }
static void down_run(void) { run_work(&xl->down_work); }
static void establish(u64 incarnation)
{
    struct xdev_ext_xd_login packet=peer_login(incarnation);
    CHECK(deliver(&packet)==1);
    connect_run(); reply_inc=incarnation; login_run();
    CHECK(xl->up && xl->remote_inc==incarnation && rings_running);
}
static void up_link(void) { fresh_link(); establish(0x1111); }
static void bind_ep(bool rx)
{
    endpoint=(struct xdev_ext_xd_ep){.xl=xl,.st=&stage,.chan=0,.rx=rx};
    CHECK(!xl->chan[0].ep[rx]);
    xl->chan[0].ep[rx]=&endpoint;
    kref_get(&xl->ref); /* Existing stage owns a link reference. */
}
static void remove_link(void)
{ xdev_ext_xd_remove(&service); removed=true; }
static void put_ep(void) { xdev_ext_xd_link_put(endpoint.xl); }
static void check_no_pending(void)
{ CHECK(!xl->login_work.work.pending && !xl->connect_work.pending && !xl->down_work.pending); }

/* A wrong advertised HopID cannot hide behind equal local/peer values. */
static void login_bytes(void)
{
    fresh_link(); login_run();
    CHECK(requests==1 && last_request.type==1 && last_request.proto_version==2);
    CHECK(last_request.route_hi==0x12345678 && last_request.route_lo==0xa5);
    CHECK(last_request.length_sn==27 && last_request.command_id==1);
    CHECK(last_request.channels==1 && last_request.ctl_tx_path==21 && last_request.data_tx_path[0]==23);
    CHECK(last_request.incarnation==xl->local_inc && last_request.caps==1);
    CHECK(!memcmp(last_request.initiator_uuid,&local_uuid,16));
    CHECK(!memcmp(last_request.target_uuid,&remote_uuid,16));
    CHECK(!memcmp(last_request.uuid,&xdev_ext_xd_proto_uuid,16));
    CHECK(!last_request.reserved[0] && !last_request.reserved[1] && !last_request.reserved[2]);
    for (unsigned int i=1;i<4;i++) CHECK(!last_request.data_tx_path[i]);
    CHECK(!xdev_ext_xd_login_check(&last_request,120,1));
}
static void one_direction_is_not_up(void)
{ fresh_link(); login_run(); CHECK(xl->logged_in && !xl->up && !rings_running && !xl->remote_inc); }
static void distinct_peer_hopids(void)
{
    up_link(); CHECK(ring_starts==1 && paths_peer.ctl_tx_path==37 && paths_peer.data_tx_path[0]==41);
    CHECK(last_request.ctl_tx_path==21 && last_request.data_tx_path[0]==23);
}
static void epoch_mismatch_never_up(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x2222);
    CHECK(deliver(&packet)==1); connect_run(); reply_inc=0x1111; login_run();
    CHECK(xl->logged_in && xl->remote_logged_in && xl->response_inc==0x1111);
    CHECK(xl->accepted_inc==0x2222 && !xl->up && !xl->remote_inc);
}
static void control_command_sequence(void)
{
    fresh_link(); login_run(); CHECK(last_request.command_id==1);
    struct xdev_ext_xd_login packet=peer_login(0x1111);
    CHECK(deliver(&packet)==1 && last_response.status==EAGAIN);
    connect_run();
    CHECK(deliver(&packet)==1); CHECK(last_response.command_id==packet.command_id);
    CHECK(last_request.command_id==1 && atomic_read(&xl->command_id)==1);
    CHECK(last_response.length_sn==21 && last_response.type==2 && !last_response.status);
    CHECK(last_response.incarnation==xl->local_inc);
    CHECK(!memcmp(last_response.initiator_uuid,&local_uuid,16) &&
          !memcmp(last_response.target_uuid,&remote_uuid,16));
    CHECK(!last_response.rsvd0 && !last_response.rsvd1 &&
          last_response.requester_incarnation==packet.incarnation);
    connect_run(); login_run(); CHECK(last_request.command_id==2);
}
static void foreign_route(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x1111); packet.route_lo++;
    CHECK(deliver(&packet)==0 && !responses && !xl->connect_work.pending);
}
static void foreign_initiator(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x1111); packet.initiator_uuid[0]^=1;
    CHECK(deliver(&packet)==0 && !responses && !xl->connect_work.pending);
}
static void foreign_target(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x1111); packet.target_uuid[0]^=1;
    CHECK(deliver(&packet)==0 && !responses && !xl->connect_work.pending);
}
static void new_peer_epoch_detaches_old_stage(void)
{
    up_link(); bind_ep(false); struct xdev_ext_xd_login packet=peer_login(0x2222);
    u64 old_local=xl->local_inc;
    int requests_before=requests;
    CHECK(deliver(&packet)==1); clear_trace(); connect_run();
    CHECK(xl->up && xl->remote_inc==0x1111 && xl->accepted_inc==0x1111);
    CHECK(!endpoint.detached && !dead_calls && xl->chan[0].ep[0]==&endpoint);
    CHECK(rings_running && !ring_stops && !events("paths_enable"));
    CHECK(xl->login_work.work.pending);
    reply_inc=0x2222; login_run();
    CHECK(requests==requests_before+1 && xl->connect_work.pending);
    CHECK(xl->up && !endpoint.detached && !dead_calls && !ring_stops);
    connect_run();
    CHECK(xl->local_inc==old_local);
    CHECK(dead_calls==1 && dead_error==-ENOLINK && dead_stage==&stage && endpoint.detached);
    CHECK(!xl->chan[0].ep[0] && xl->accepted_inc==0x2222 && !xl->up);
    CHECK(event_index("stage_dead")<event_index("rings_stop"));
    CHECK(event_index("rings_stop")<event_index("paths_enable"));
}
static void bad_version_refused(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x1111); packet.proto_version=1;
    CHECK(deliver(&packet)==1 && responses==1 && last_response.status==EPROTO);
    CHECK(!xl->connect_work.pending && !xl->remote_logged_in && !ring_starts);
}
static void repeated_login_before_up(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x3333);
    CHECK(deliver(&packet)==1); connect_run(); CHECK(!xl->up);
    CHECK(deliver(&packet)==1); connect_run();
    CHECK(!xl->up && ring_starts==1 && !ring_stops && !ring_warn);
}
static void paths_failure_unwinds_and_retries(void)
{
    fresh_link(); login_run(); struct xdev_ext_xd_login packet=peer_login(0x4444); paths_result=-EIO;
    CHECK(deliver(&packet)==1); connect_run();
    CHECK(ring_starts==1 && ring_stops==1 && !rings_running && !xl->remote_logged_in && !xl->up);
    CHECK(xl->login_work.work.pending && xl->login_work.work.delay==1000);
    paths_result=0; jiffies+=xl->login_work.work.delay; CHECK(deliver(&packet)==1); connect_run();
    CHECK(ring_starts==2 && !ring_warn && rings_running);
}
static void rings_failure_does_not_enable_paths(void)
{
    fresh_link(); login_run(); struct xdev_ext_xd_login packet=peer_login(0x4444); start_result=-ENOMEM;
    CHECK(deliver(&packet)==1); clear_trace(); connect_run();
    CHECK(!events("paths_enable") && !rings_running && !xl->remote_logged_in && !xl->up);
    CHECK(xl->login_work.work.pending && xl->login_work.work.delay==1000);
}
static void down_starts_new_local_epoch(void)
{
    up_link(); u64 old=xl->local_inc; xdev_ext_xd_link_down(xl,-EPROTO);
    CHECK(!xl->up && !xl->remote_inc && !xl->logged_in && !xl->remote_logged_in);
    CHECK(xl->local_inc && xl->local_inc!=old && xl->login_work.work.pending);
    CHECK(xl->login_work.work.delay==1000 && !rings_running);
}
static void stale_logout_cannot_down(void)
{
    up_link(); struct xdev_ext_xd_login packet=peer_login(0x2222); packet.type=3;
    CHECK(deliver(&packet)==1 && !xl->down_work.pending && xl->up);
    packet.incarnation=0x1111; CHECK(deliver(&packet)==1 && xl->down_work.pending);
    down_run(); CHECK(!xl->up && !rings_running);
}
static void remove_releases_native_before_last_ref(void)
{
    up_link(); bind_ep(false); clear_trace(); remove_link();
    CHECK(list_empty(&xdev_ext_xd_links) && logouts==1 && ring_frees==1 && events("cancel")==4);
    CHECK(endpoint.detached && dead_calls==1 && dead_error==-ENOLINK);
    CHECK(xl->gone && xl->going_away && !xl->xd && !xl->svc);
    CHECK(!link_freed && !pci_puts && pdev.refs==1); check_no_pending();
    CHECK(event_index("list_del")<event_index("cancel"));
    CHECK(event_index("cancel")<event_index("logout"));
    CHECK(event_index("logout")<event_index("stage_dead"));
    CHECK(event_index("stage_dead")<event_index("rings_stop"));
    CHECK(event_index("rings_stop")<event_index("rings_free"));
    CHECK(event_index("paths_disable")<event_index("rings_free"));
    struct xdev_ext_xd_login packet=peer_login(0x5555);
    int before=responses; CHECK(deliver(&packet)==0 && responses==before);
    xdev_ext_xd_link_fail(xl,&endpoint,-EPROTO); check_no_pending();
    CHECK(!xdev_ext_xd_link_get(xl->token)); put_ep();
    CHECK(link_freed && pci_puts==1 && !pdev.refs && !ring_calls_after_remove);
}
static void remove_without_stage_frees_once(void)
{ up_link(); clear_trace(); remove_link(); CHECK(link_freed && pci_puts==1 && ring_frees==1);
  CHECK(event_index("rings_free")<event_index("pci_put") && event_index("pci_put")<event_index("link_free")); }
static void suspend_then_resume_login(void)
{
    up_link(); bind_ep(true); u64 old=xl->local_inc; clear_trace();
    CHECK(!xdev_ext_xd_suspend(&service.dev));
    CHECK(xl->suspended && !xl->up && dead_error==-ESHUTDOWN && endpoint.detached && !rings_running);
    CHECK(!ring_frees && !pci_puts && !link_freed); check_no_pending();
    CHECK(events("cancel")==4 && event_index("cancel")<event_index("stage_dead"));
    CHECK(!xdev_ext_xd_resume(&service.dev));
    CHECK(!xl->suspended && xl->local_inc && xl->local_inc!=old && xl->login_work.work.pending);
    CHECK(xl->login_work.work.delay==0); reply_inc=0x2222; login_run();
    CHECK(!xl->up && last_request.incarnation==xl->local_inc);
    establish(0x2222); CHECK(!xl->chan[0].ep[1]);
}
static void old_endpoint_cannot_fail_new_epoch(void)
{
    up_link(); bind_ep(true); xdev_ext_xd_link_down(xl,-ENOLINK); establish(0x2222);
    CHECK(endpoint.detached); xdev_ext_xd_link_fail(xl,&endpoint,-EPROTO);
    CHECK(!xl->down_work.pending && xl->up && xl->remote_inc==0x2222);
}
static void registry_token_reference(void)
{
    fresh_link(); u64 token=xl->token; CHECK(token);
    CHECK(!xdev_ext_xd_link_get(token+1));
    struct xdev_ext_xd_link *held=xdev_ext_xd_link_get(token); CHECK(held==xl);
    remove_link(); CHECK(!link_freed && !pci_puts && !xdev_ext_xd_link_get(token));
    xdev_ext_xd_link_put(held); CHECK(link_freed && pci_puts==1);
    /* Probe a new object through real registry code: old token stays absent. */
    removed=false; link_freed=false; CHECK(!xdev_ext_xd_probe(&service,NULL)); xl=service.drvdata;
    CHECK(xl->token>token && !xdev_ext_xd_link_get(token));
}
static void handler_registered_once_for_devices(void)
{
    fresh_link(); struct tb_xdomain second_domain=domain; second_domain.route++;
    struct tb_service second={.parent=&second_domain,.prtcstns=1}; second.dev.owner=&second;
    CHECK(!xdev_ext_xd_probe(&second,NULL));
    CHECK(handler_regs==1 && handler_live==1 && driver_regs==1);
    CHECK(event_index("handler_register")<event_index("property_register"));
    CHECK(event_index("property_register")<event_index("driver_register"));
    CHECK(event_index("driver_register")<event_index("rings_alloc"));
}
static void late_packet_during_cancel_is_unfindable(struct work_struct *work)
{
    (void)work; struct xdev_ext_xd_login packet=peer_login(0x5555);
    CHECK(deliver(&packet)==0);
}
static void remove_barrier_hides_link_before_cancel(void)
{
    up_link(); bind_ep(false); during_cancel=late_packet_during_cancel_is_unfindable;
    remove_link(); CHECK(events("cancel")==4 && responses==1); put_ep();
}
static void suspended_packets_do_not_queue(void)
{
    up_link(); CHECK(!xdev_ext_xd_suspend(&service.dev));
    struct xdev_ext_xd_login packet=peer_login(0x2222); int before=responses;
    CHECK(deliver(&packet)==1 && responses==before); check_no_pending();
    packet.type=3; packet.incarnation=0x1111; CHECK(deliver(&packet)==1); check_no_pending();
}
static void queued_objects_canceled_on_remove(void)
{
    up_link(); bind_ep(false);
    struct xdev_ext_xd_login packet=peer_login(0x2222); CHECK(deliver(&packet)==1);
    queue_delayed_work(system_long_wq,&xl->login_work,1000);
    xdev_ext_xd_link_fail(xl,&endpoint,-EPROTO);
    CHECK(xl->login_work.work.pending && xl->connect_work.pending && xl->down_work.pending);
    remove_link(); check_no_pending(); CHECK(ring_frees==1 && dead_calls==1); put_ep();
}
static void in_flight_login_observes_remove_flag(void)
{
    fresh_link(); kref_get(&xl->ref); int before=requests;
    running_at_cancel=&xl->login_work.work; remove_link();
    CHECK(!running_at_cancel && requests==before); xdev_ext_xd_link_put(xl);
}
static void in_flight_connect_observes_suspend_flag(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x3333);
    CHECK(deliver(&packet)==1); int before=ring_starts;
    running_at_cancel=&xl->connect_work; CHECK(!xdev_ext_xd_suspend(&service.dev));
    CHECK(!running_at_cancel && ring_starts==before); check_no_pending();
}
static void failed_response_not_logged_in(void)
{
    fresh_link(); reply_status=EPROTO; login_run(); CHECK(!xl->logged_in && !xl->up);
    CHECK(xl->login_work.work.pending && xl->login_work.work.delay==1000);
}
static void zero_peer_response_epoch_not_logged_in(void)
{
    fresh_link(); reply_inc=0; login_run(); CHECK(!xl->logged_in && !xl->up);
    CHECK(xl->login_work.work.pending && xl->login_work.work.delay==1000);
}
static void module_failure_unwind(void)
{
    fail_registration=4; CHECK(xdev_ext_xd_init()==-EIO);
    CHECK(!handler_live && !class_live && events("handler_unregister")==1 && events("property_free")==1);
    CHECK(event_index("property_unregister")<event_index("handler_unregister"));
    CHECK(event_index("handler_unregister")<event_index("class_unregister"));
    CHECK(event_index("class_unregister")<event_index("property_free"));
}
static void module_unregister_order(void)
{
    CHECK(!xdev_ext_xd_init()); clear_trace(); xdev_ext_xd_exit();
    CHECK(event_index("driver_unregister")<event_index("handler_unregister"));
    CHECK(event_index("handler_unregister")<event_index("class_unregister"));
    CHECK(!handler_live && !class_live);
}
static void in_flight_down_observes_remove_flag(void)
{
    up_link(); bind_ep(false); xdev_ext_xd_link_fail(xl,&endpoint,-EPROTO);
    CHECK(xl->down_work.pending); running_at_cancel=&xl->down_work;
    remove_link(); CHECK(!running_at_cancel && ring_stops==1 && logouts==1);
    CHECK(dead_calls==1 && ring_frees==1); check_no_pending(); put_ep();
}
static void login_retry_is_bounded(void)
{
    fresh_link(); request_result=-ETIMEDOUT;
    for (int i=0;i<60;i++) {
        CHECK(xl->login_work.work.pending); login_run();
        CHECK(!xl->logged_in && !xl->up);
        if (i<59) CHECK(xl->login_work.work.delay==1000);
    }
    CHECK(requests==60 && !xl->login_work.work.pending);
}
static void handler_registration_failure_unwinds_class(void)
{
    fail_registration=2; CHECK(xdev_ext_xd_init()==-EIO);
    CHECK(!handler_live && !class_live && !events("driver_register") && !events("property_register"));
    CHECK(!events("handler_unregister") && events("class_unregister")==1 && events("property_free")==1);
}
static void property_registration_failure_unwinds_handler(void)
{
    fail_registration=3; CHECK(xdev_ext_xd_init()==-EIO);
    CHECK(!handler_live && !class_live && !events("driver_register"));
    CHECK(!events("property_unregister") && events("handler_unregister")==1 && events("class_unregister")==1);
}
static void class_registration_failure_frees_property(void)
{
    fail_registration=1; CHECK(xdev_ext_xd_init()==-EIO);
    CHECK(!handler_live && !class_live && !events("handler_register"));
    CHECK(!events("class_unregister") && events("property_free")==1);
}
static void probe_allocation_failure_balances_owners(void)
{
    CHECK(!xdev_ext_xd_init()); service.dev.owner=&service; alloc_result=-ENOMEM;
    CHECK(xdev_ext_xd_probe(&service,NULL)==-ENOMEM);
    CHECK(list_empty(&xdev_ext_xd_links) && !service.drvdata && pci_gets==1 && pci_puts==1 && link_freed);
    CHECK(!events("queue_delayed") && !events("list_add"));
}
static void sequence_counters_reset_only_at_up(void)
{
    fresh_link(); xl->chan[0].announced=81; xl->chan[0].consumed=93;
    struct xdev_ext_xd_login packet=peer_login(0x1111); CHECK(deliver(&packet)==1); connect_run();
    CHECK(!xl->up && xl->chan[0].announced==81 && xl->chan[0].consumed==93);
    login_run(); CHECK(xl->up && !xl->chan[0].announced && !xl->chan[0].consumed);
}
static void zero_random_incarnation_is_retried(void)
{
    random_values[0]=0; random_values[1]=0; random_values[2]=0xaaaa;
    random_values[3]=0xbbbb; random_nr=4;
    fresh_link(); CHECK(xl->local_inc==0xaaaa && random_index==3);
    xdev_ext_xd_link_down(xl,-ENOLINK); CHECK(xl->local_inc==0xbbbb && random_index==4);
}
/* X3 observation supplement. These invoke production-registered sysfs shows;
 * no parser or formatter under test is reimplemented in a boundary stub. */
static struct device_attribute *registered_attribute(const char *name)
{
    const struct attribute_group **groups=registered_driver->driver.dev_groups;
    CHECK(groups);
    for (unsigned int i=0;groups[i];i++)
        for (unsigned int j=0;groups[i]->attrs[j];j++) {
            struct attribute *attr=groups[i]->attrs[j];
            if (!strcmp(attr->name,name))
                return container_of(attr,struct device_attribute,attr);
        }
    CHECK(false); return NULL;
}
static void read_attribute(const char *name,char *out)
{
    struct device_attribute *attr=registered_attribute(name);
    CHECK(attr->attr.mode==0444 && attr->show && !attr->store);
    memset(out,0xa5,512);
    ssize_t n=attr->show(&service.dev,attr,out);
    CHECK(n>0 && n<512 && out[n]=='\0' && (size_t)n==strlen(out));
}
static void expect_observation(u64 token,u64 local,u64 remote,unsigned int up,
                               unsigned int closing,unsigned int gone,unsigned int channels)
{
    char actual[512],expected[512];
    int n=snprintf(expected,sizeof(expected),
        "version=1 token=%llu local_inc=%llu remote_inc=%llu up=%u closing=%u nhi_gone=%u channels=%u\n",
        token,local,remote,up,closing,gone,channels);
    CHECK(n>0 && (size_t)n<sizeof(expected));
    read_attribute("xdev_ext_link_state",actual);
    CHECK(!strcmp(actual,expected));
}
static void token_attribute_stays_token_only_and_readonly(void)
{
    up_link(); char actual[512],expected[512];
    snprintf(expected,sizeof(expected),"%llu\n",xl->token);
    read_attribute("xdev_ext_link",actual);
    CHECK(!strcmp(actual,expected));
    /* Looking up the state attribute through the actual registered groups also
     * checks it was exported, rather than only defining an unused static show. */
    struct device_attribute *attr=registered_attribute("xdev_ext_link_state");
    CHECK(attr->attr.mode==0444 && attr->show && !attr->store);
}
static void fresh_observation_does_not_invent_peer_epoch(void)
{
    fresh_link(); CHECK(!xl->nhi_gone && !xl->up && !xl->remote_inc);
    expect_observation(xl->token,xl->local_inc,0,0,0,0,1);
}
static void matched_login_observation_reports_real_nonzero_incarnations(void)
{
    up_link(); CHECK(xl->local_inc && xl->remote_inc==0x1111);
    CHECK(xl->accepted_inc==0x1111 && xl->response_inc==0x1111);
    expect_observation(xl->token,xl->local_inc,0x1111,1,0,0,1);
}
static void mismatched_login_observation_never_invents_up(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x2222);
    CHECK(deliver(&packet)==1); connect_run(); reply_inc=0x1111; login_run();
    CHECK(!xl->up && !xl->remote_inc);
    expect_observation(xl->token,xl->local_inc,0,0,0,0,1);
}
static void suspended_observation_is_closing_without_peer_epoch(void)
{
    up_link(); CHECK(!xdev_ext_xd_suspend(&service.dev));
    expect_observation(xl->token,xl->local_inc,0,0,1,0,1);
}
static void each_closing_flag_is_visible_without_fabricating_nhi_loss(void)
{
    fresh_link();
    xl->going_away=true;
    expect_observation(xl->token,xl->local_inc,0,0,1,0,1);
    xl->going_away=false; xl->suspended=true;
    expect_observation(xl->token,xl->local_inc,0,0,1,0,1);
    xl->suspended=false; xl->gone=true;
    expect_observation(xl->token,xl->local_inc,0,0,1,0,1);
    xl->gone=false;
    expect_observation(xl->token,xl->local_inc,0,0,0,0,1);
}
static void known_nhi_gone_observation_is_separate_from_closing(void)
{
    fresh_link();
    /* X4 owns actual stop classification. This case checks only observation
     * of an already-known scalar fact; it does not prove that classification. */
    xl->nhi_gone=true;
    expect_observation(xl->token,xl->local_inc,0,0,0,1,1);
}
static int observation_lock_step;
static void competing_state_update_after_snapshot(const void *object,bool locked,bool spin)
{
    if (object==&xl->ctl_mutex) {
        CHECK(!spin);
        if (locked) { CHECK(observation_lock_step==0 && !xl->lock.held); observation_lock_step=1; }
        else {
            CHECK(observation_lock_step==3 && !xl->lock.held); observation_lock_step=4;
            /* A competing writer becomes runnable after the snapshot releases
             * both guards. A subsequent unlocked read would mix these facts. */
            xl->local_inc+=123; xl->remote_inc=0; xl->up=false;
            xl->suspended=true;
        }
    } else if (object==&xl->lock) {
        CHECK(spin && xl->ctl_mutex.held);
        if (locked) { CHECK(observation_lock_step==1); observation_lock_step=2; }
        else { CHECK(observation_lock_step==2); observation_lock_step=3; }
    } else CHECK(false);
}
static void state_observation_is_one_ctl_then_spin_snapshot(void)
{
    up_link(); u64 token=xl->token,local=xl->local_inc;
    observation_lock_step=0; lock_observer=competing_state_update_after_snapshot;
    expect_observation(token,local,0x1111,1,0,0,1);
    lock_observer=NULL;
    CHECK(observation_lock_step==4 && !xl->ctl_mutex.held && !xl->lock.held);
    CHECK(xl->local_inc==local+123 && !xl->remote_inc && !xl->up && xl->suspended);
}
/* Actual tb_property_add_immediate() may fail allocating any property.
 * Reject incomplete discovery publication and release every acquired owner. */
static void property_allocation_failure(unsigned int position)
{
    property_fail_index=position;
    CHECK(xdev_ext_xd_init()==-ENOMEM);
    CHECK(property_add_calls==position);
    CHECK(!property_dir_live && !property_entries && !property_registered);
    CHECK(!handler_live && !driver_live && !class_live);
    CHECK(events("property_create")==1 && events("property_free")==1);
    CHECK(list_empty(&xdev_ext_xd_links) && !pci_gets && !pci_puts);
}
static void first_property_allocation_failure(void) { property_allocation_failure(1); }
static void second_property_allocation_failure(void) { property_allocation_failure(2); }
static void third_property_allocation_failure(void) { property_allocation_failure(3); }
static void fourth_property_allocation_failure(void) { property_allocation_failure(4); }
/* Deterministic scheduler order, actual workers: a fault queued by a live
 * old endpoint loses authority when connect accepts the next incarnation. */
static void queued_old_fault_cannot_down_new_peer_incarnation(void)
{
    up_link(); bind_ep(false); u64 old_local=xl->local_inc;
    xdev_ext_xd_link_fail(xl,&endpoint,-EPROTO);
    CHECK(xl->down_work.pending && xl->up && !endpoint.detached && !dead_calls);
    struct xdev_ext_xd_login packet=peer_login(0x2222);
    CHECK(deliver(&packet)==1 && xl->connect_work.pending);
    connect_run();
    CHECK(xl->up && xl->remote_inc==0x1111 && xl->accepted_inc==0x1111);
    CHECK(!endpoint.detached && !dead_calls && xl->chan[0].ep[0]==&endpoint);
    CHECK(rings_running && !ring_stops && xl->down_work.pending);
    CHECK(xl->login_work.work.pending);
    int requests_before=requests;
    reply_inc=0x2222; login_run();
    CHECK(requests==requests_before+1 && xl->connect_work.pending);
    CHECK(xl->up && !endpoint.detached && !dead_calls && !ring_stops);
    connect_run();
    CHECK(endpoint.detached && dead_calls==1 && !xl->chan[0].ep[0]);
    CHECK(xl->accepted_inc==0x2222 && xl->local_inc && xl->local_inc==old_local);
    reply_inc=0x2222; login_run();
    CHECK(xl->up && xl->remote_inc==0x2222 && xl->down_work.pending && rings_running);
    u64 fresh_local=xl->local_inc;
    int stops_before=ring_stops,starts_before=ring_starts,dead_before=dead_calls;
    down_run();
    CHECK(xl->up && xl->local_inc==fresh_local && xl->remote_inc==0x2222);
    CHECK(xl->accepted_inc==0x2222 && xl->response_inc==0x2222);
    CHECK(rings_running && ring_stops==stops_before && ring_starts==starts_before);
    CHECK(dead_calls==dead_before && !xl->down_work.pending && !xl->login_work.work.pending);
}
static void queued_current_fault_still_enforces_link_down(void)
{
    up_link(); bind_ep(false); u64 old_local=xl->local_inc;
    xdev_ext_xd_link_fail(xl,&endpoint,-EPROTO);
    CHECK(xl->down_work.pending && xl->up && !endpoint.detached && !dead_calls);
    down_run();
    CHECK(!xl->up && !xl->remote_inc && !xl->logged_in && !xl->remote_logged_in);
    CHECK(endpoint.detached && !xl->chan[0].ep[0]);
    CHECK(dead_calls==1 && dead_error==-EPROTO && dead_stage==&stage);
    CHECK(!rings_running && ring_stops==1 && !xl->down_work.pending);
    CHECK(xl->local_inc && xl->local_inc!=old_local);
    CHECK(xl->login_work.work.pending && xl->login_work.work.delay==1000);
}
/* Peer LOGIN is a discovery input, not a clock that must rescue a stalled
 * successful-but-mismatched response. Actual login work must keep bounded
 * autonomous progress until a matching response arrives or retries expire. */
static void mismatched_response_recovers_without_more_peer_login(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x2222);
    CHECK(deliver(&packet)==1); connect_run();
    reply_inc=0x1111; login_run();
    CHECK(!xl->up && !xl->remote_inc && requests==1);
    CHECK(xl->login_work.work.pending);
    int responses_before=responses;
    reply_inc=0x2222; login_run();
    CHECK(requests==2 && responses==responses_before);
    CHECK(xl->up && xl->remote_inc==0x2222 && xl->local_inc);
    CHECK(!xl->login_work.work.pending && !xl->connect_work.pending);
    CHECK(rings_running && ring_starts==1 && !ring_stops && !ring_warn);
}
static void persistent_successful_mismatch_has_finite_retry_budget(void)
{
    fresh_link(); struct xdev_ext_xd_login packet=peer_login(0x2222);
    CHECK(deliver(&packet)==1); connect_run(); reply_inc=0x1111;
    unsigned int attempts=0;
    while (xl->login_work.work.pending && attempts<61) {
        login_run(); attempts++;
        CHECK(!xl->up && !xl->remote_inc);
    }
    CHECK(attempts>1 && attempts<=60 && requests==(int)attempts);
    CHECK(!xl->login_work.work.pending && !xl->connect_work.pending);
    CHECK(rings_running && ring_starts==1 && !ring_stops && !ring_warn);
}
/* A stale unsolicited candidate cannot replace a live peer when the actual
 * response to our fresh LOGIN still confirms the current incarnation. */
static void stale_candidate_current_response_preserves_live_stage(void)
{
    up_link(); bind_ep(false);
    u64 old_local=xl->local_inc;
    int starts_before=ring_starts,requests_before=requests;
    struct xdev_ext_xd_login packet=peer_login(0x2222);
    CHECK(deliver(&packet)==1);
    connect_run();
    CHECK(xl->up && xl->remote_inc==0x1111 && xl->accepted_inc==0x1111);
    CHECK(!endpoint.detached && !dead_calls && xl->chan[0].ep[0]==&endpoint);
    CHECK(rings_running && !ring_stops && xl->login_work.work.pending);
    reply_inc=0x1111; login_run();
    CHECK(requests==requests_before+1);
    if (xl->connect_work.pending) connect_run();
    CHECK(xl->up && xl->local_inc==old_local && xl->remote_inc==0x1111);
    CHECK(xl->accepted_inc==0x1111 && xl->response_inc==0x1111);
    CHECK(!endpoint.detached && !dead_calls && xl->chan[0].ep[0]==&endpoint);
    CHECK(rings_running && ring_starts==starts_before && !ring_stops);
    CHECK(!xl->down_work.pending && !xl->connect_work.pending);
}
/* A confirmed peer restart must complete without another inbound LOGIN.
 * Delayed packets may not erase either its incarnation or its advertised paths. */
static void finish_confirmed_peer_recovery(u64 old_local)
{
    unsigned int turns=0;
    while ((xl->connect_work.pending || xl->login_work.work.pending) && turns<120) {
        if (xl->connect_work.pending) connect_run();
        else login_run();
        turns++;
    }
    CHECK(xl->up && xl->remote_inc==0x2222 && xl->local_inc==old_local);
    CHECK(xl->accepted_inc==0x2222 && xl->response_inc==0x2222);
    CHECK(endpoint.detached && dead_calls==1 && dead_error==-ENOLINK);
    CHECK(!xl->chan[0].ep[0] && rings_running && ring_starts==2 && ring_stops==1);
    CHECK(paths_peer.incarnation==0x2222 && paths_peer.ctl_tx_path==53);
    CHECK(paths_peer.data_tx_path[0]==59);
    CHECK(!xl->login_work.work.pending && !xl->connect_work.pending && !xl->down_work.pending);
}
static void confirmed_peer_survives_stale_login_before_connect(void)
{
    up_link(); bind_ep(false); u64 old_local=xl->local_inc;
    struct xdev_ext_xd_login changed=peer_login(0x2222),stale=peer_login(0x1111);
    changed.ctl_tx_path=53; changed.data_tx_path[0]=59;
    CHECK(deliver(&changed)==1); connect_run();
    CHECK(xl->up && !endpoint.detached && !dead_calls && !ring_stops);
    reply_inc=0x2222; login_run();
    CHECK(xl->connect_work.pending && !endpoint.detached && !dead_calls);
    CHECK(deliver(&stale)==1);
    finish_confirmed_peer_recovery(old_local);
}
static int request_interleavings;
static void stale_login_during_fresh_request(void)
{
    CHECK(xl->ctl_mutex.held && !xl->lock.held && !active_spins);
    CHECK(last_request.incarnation==xl->local_inc);
    CHECK(xl->up && xl->remote_inc==0x1111 && !endpoint.detached && !dead_calls);
    struct xdev_ext_xd_login stale=peer_login(0x1111);
    CHECK(deliver(&stale)==1);
    CHECK(xl->up && !endpoint.detached && !dead_calls && !ring_stops);
    request_interleavings++;
}
static void confirmed_peer_survives_stale_login_during_request(void)
{
    up_link(); bind_ep(false); u64 old_local=xl->local_inc;
    struct xdev_ext_xd_login changed=peer_login(0x2222);
    changed.ctl_tx_path=53; changed.data_tx_path[0]=59;
    CHECK(deliver(&changed)==1); connect_run();
    CHECK(xl->up && !endpoint.detached && !dead_calls && !ring_stops);
    during_request=stale_login_during_fresh_request;
    reply_inc=0x2222; login_run();
    CHECK(request_interleavings==1 && !during_request);
    CHECK(xl->up && !endpoint.detached && !dead_calls && !ring_stops);
    finish_confirmed_peer_recovery(old_local);
}
/* Discovery must survive an old duplicate even before any worker has
 * sampled it. Both requests still receive their own protocol response. */
static void changed_peer_survives_stale_login_before_first_work(void)
{
    up_link(); bind_ep(false); u64 old_local=xl->local_inc;
    struct xdev_ext_xd_login changed=peer_login(0x2222),stale=peer_login(0x1111);
    changed.ctl_tx_path=53; changed.data_tx_path[0]=59;
    CHECK(deliver(&changed)==1 && last_response.status==EAGAIN);
    CHECK(deliver(&stale)==1 && !last_response.status);
    CHECK(xl->up && !endpoint.detached && !dead_calls && !ring_stops);
    reply_inc=0x2222;
    connect_run();
    finish_confirmed_peer_recovery(old_local);
    CHECK(deliver(&changed)==1 && !last_response.status);
}
static void finish_retried_third_peer_recovery(u64 old_local)
{
    unsigned int turns=0;
    while ((xl->connect_work.pending || xl->login_work.work.pending) && turns<120) {
        if (xl->connect_work.pending) connect_run();
        else login_run();
        turns++;
    }
    CHECK(xl->up && xl->remote_inc==0x3333 && xl->local_inc==old_local);
    CHECK(xl->accepted_inc==0x3333 && xl->response_inc==0x3333);
    CHECK(endpoint.detached && dead_calls==1 && dead_error==-ENOLINK);
    CHECK(!xl->chan[0].ep[0] && rings_running && ring_starts==2 && ring_stops==1);
    CHECK(paths_peer.incarnation==0x3333 && paths_peer.ctl_tx_path==61);
    CHECK(paths_peer.data_tx_path[0]==67);
    CHECK(!xl->login_work.work.pending && !xl->connect_work.pending && !xl->down_work.pending);
}
/* A single occupied candidate slot must reject a third incarnation rather
 * than positively acknowledging and losing its only discovery advertisement. */
static void conflicting_candidate_retries_after_fresh_rejection(void)
{
    up_link(); bind_ep(false); u64 old_local=xl->local_inc;
    struct xdev_ext_xd_login second=peer_login(0x2222),third=peer_login(0x3333);
    second.ctl_tx_path=53; second.data_tx_path[0]=59;
    third.ctl_tx_path=61; third.data_tx_path[0]=67;
    CHECK(deliver(&second)==1 && last_response.status==EAGAIN); connect_run();
    CHECK(deliver(&third)==1 && last_response.status==EAGAIN);
    CHECK(last_response.incarnation==old_local);
    CHECK(xl->up && xl->remote_inc==0x1111 && !endpoint.detached && !dead_calls && !ring_stops);
    /* Fresh native evidence rejects second; this must not kill the old stage. */
    reply_inc=0x3333; login_run();
    CHECK(xl->up && xl->remote_inc==0x1111 && !endpoint.detached && !dead_calls && !ring_stops);
    if (xl->connect_work.pending) connect_run();
    CHECK(xl->up && xl->remote_inc==0x1111 && !endpoint.detached && !dead_calls && !ring_stops);
    CHECK(deliver(&third)==1 && last_response.status==EAGAIN);
    int requests_before_retry_confirmation=requests;
    connect_run();
    CHECK(xl->up && xl->remote_inc==0x1111 && !endpoint.detached && !dead_calls && !ring_stops);
    CHECK(xl->login_work.work.pending);
    login_run();
    CHECK(requests==requests_before_retry_confirmation+1);
    CHECK(xl->up && xl->remote_inc==0x1111 && !endpoint.detached && !dead_calls && !ring_stops);
    finish_retried_third_peer_recovery(old_local);
    CHECK(deliver(&third)==1 && !last_response.status);
}
/* Duplicates of one unresolved candidate cannot refresh its finite native
 * request budget. Exhaustion frees admission for a newly retried candidate. */
static void exhausted_candidate_releases_slot_and_third_gets_fresh_budget(void)
{
    up_link(); bind_ep(false); u64 old_local=xl->local_inc;
    struct xdev_ext_xd_login second=peer_login(0x2222),third=peer_login(0x3333);
    second.ctl_tx_path=53; second.data_tx_path[0]=59;
    third.ctl_tx_path=61; third.data_tx_path[0]=67;
    CHECK(deliver(&second)==1 && last_response.status==EAGAIN); connect_run();
    int requests_before=requests;
    request_result=-ETIMEDOUT;
    unsigned int attempts=0;
    while (xl->login_work.work.pending && attempts<61) {
        login_run(); attempts++;
        CHECK(xl->up && xl->remote_inc==0x1111 && !endpoint.detached && !dead_calls && !ring_stops);
        if (xl->login_work.work.pending) {
            CHECK(deliver(&second)==1 && last_response.status==EAGAIN);
            if (xl->connect_work.pending) connect_run();
        }
    }
    CHECK(attempts==60 && requests==requests_before+60);
    CHECK(!xl->login_work.work.pending && !xl->connect_work.pending);
    request_result=0; reply_inc=0x3333;
    CHECK(deliver(&third)==1 && last_response.status==EAGAIN);
    int requests_after_exhaustion=requests;
    finish_retried_third_peer_recovery(old_local);
    CHECK(requests>requests_after_exhaustion && requests<=requests_after_exhaustion+60);
    CHECK(deliver(&third)==1 && !last_response.status);
}
struct test_case { const char *name; void (*run)(void); };
static const struct test_case cases[]={
    {"outgoing LOGIN has exact route, UUIDs, local HopIDs and incarnation",login_bytes},
    {"one successful login direction cannot bring link up",one_direction_is_not_up},
    {"peer HopIDs differ from local advertised HopIDs",distinct_peer_hopids},
    {"mismatched response/accepted peer epochs never publish up",epoch_mismatch_never_up},
    {"control requests and responses advance command IDs",control_command_sequence},
    {"foreign route has no reply or connect work",foreign_route},
    {"foreign initiator UUID has no reply or connect work",foreign_initiator},
    {"foreign target UUID has no reply or connect work",foreign_target},
    {"peer reincarnation detaches old stage before restarting native path",new_peer_epoch_detaches_old_stage},
    {"unsupported login version answers EPROTO without connect",bad_version_refused},
    {"repeated LOGIN before up does not restart running rings",repeated_login_before_up},
    {"failed path enable stops rings and schedules re-login",paths_failure_unwinds_and_retries},
    {"failed ring start cannot enable paths",rings_failure_does_not_enable_paths},
    {"link down invalidates peer and obtains fresh local epoch",down_starts_new_local_epoch},
    {"only accepted peer incarnation LOGOUT ends link",stale_logout_cannot_down},
    {"remove frees native objects before last stage reference",remove_releases_native_before_last_ref},
    {"remove with no stage frees link and PCI reference once",remove_without_stage_frees_once},
    {"suspend drains work and stages, resume performs fresh login",suspend_then_resume_login},
    {"detached old endpoint cannot fail a new incarnation",old_endpoint_cannot_fail_new_epoch},
    {"registry token lookup owns memory and tokens never reuse",registry_token_reference},
    {"one module protocol handler precedes property and device registration",handler_registered_once_for_devices},
    {"remove hides registry entry before every cancel barrier",remove_barrier_hides_link_before_cancel},
    {"suspended LOGIN and LOGOUT cannot queue new work",suspended_packets_do_not_queue},
    {"remove drops all three queued work objects",queued_objects_canceled_on_remove},
    {"in-flight login sees going-away before Thunderbolt request",in_flight_login_observes_remove_flag},
    {"in-flight connect sees suspend before native ring action",in_flight_connect_observes_suspend_flag},
    {"error response cannot establish login",failed_response_not_logged_in},
    {"zero response incarnation cannot establish login",zero_peer_response_epoch_not_logged_in},
    {"module registration failure unwinds property, handler and class",module_failure_unwind},
    {"module exit removes service driver before handler and class",module_unregister_order},
    {"in-flight down work sees remove before mandatory teardown",in_flight_down_observes_remove_flag},
    {"unanswered login retries stop at the declared bound",login_retry_is_bounded},
    {"handler registration failure releases class and property",handler_registration_failure_unwinds_class},
    {"property registration failure releases handler and class",property_registration_failure_unwinds_handler},
    {"class registration failure frees property only",class_registration_failure_frees_property},
    {"probe allocation failure leaves no registry or PCI owner",probe_allocation_failure_balances_owners},
    {"channel sequence counters reset only after matching handshake",sequence_counters_reset_only_at_up},
    {"zero random incarnation is retried before publication",zero_random_incarnation_is_retried},
    {"original token-only attribute and state attribute are registered read-only",token_attribute_stays_token_only_and_readonly},
    {"fresh state observation preserves unknown peer and initialized NHI facts",fresh_observation_does_not_invent_peer_epoch},
    {"UP state observation reports actual matched nonzero login incarnations",matched_login_observation_reports_real_nonzero_incarnations},
    {"mismatched login observation cannot synthesize UP or peer incarnation",mismatched_login_observation_never_invents_up},
    {"suspend state observation marks closing and invalidates peer incarnation",suspended_observation_is_closing_without_peer_epoch},
    {"each closing input is observed without inventing NHI loss",each_closing_flag_is_visible_without_fabricating_nhi_loss},
    {"known NHI-gone observation remains a separate scalar fact",known_nhi_gone_observation_is_separate_from_closing},
    {"state show snapshots under control then spin guards before competing update",state_observation_is_one_ctl_then_spin_snapshot},
    {"first property allocation failure rejects init and releases all owners",first_property_allocation_failure},
    {"second property allocation failure rejects init and releases all owners",second_property_allocation_failure},
    {"third property allocation failure rejects init and releases all owners",third_property_allocation_failure},
    {"fourth property allocation failure rejects init and releases all owners",fourth_property_allocation_failure},
    {"queued old endpoint fault cannot down fresh peer incarnation",queued_old_fault_cannot_down_new_peer_incarnation},
    {"queued current endpoint fault still enforces link down",queued_current_fault_still_enforces_link_down},
    {"mismatched response retries autonomously until a later match brings UP",mismatched_response_recovers_without_more_peer_login},
    {"persistent successful response mismatch stops within finite retry budget",persistent_successful_mismatch_has_finite_retry_budget},
    {"stale candidate LOGIN with current peer response preserves live stage",stale_candidate_current_response_preserves_live_stage},
    {"confirmed peer restart survives stale LOGIN before connect without new discovery",confirmed_peer_survives_stale_login_before_connect},
    {"confirmed peer restart survives stale LOGIN during own request with original paths",confirmed_peer_survives_stale_login_during_request},
    {"changed peer discovery survives old LOGIN before first worker",changed_peer_survives_stale_login_before_first_work},
    {"conflicting peer gets EAGAIN then retries after fresh rejection",conflicting_candidate_retries_after_fresh_rejection},
    {"duplicate candidate has finite budget and exhaustion admits fresh peer",exhausted_candidate_releases_slot_and_third_gets_fresh_budget},
};
int main(int argc,char **argv)
{
    if (argc==2 && !strcmp(argv[1],"--count")) { printf("%zu\n",ARRAY_SIZE(cases)); return 0; }
    CHECK(argc==2); current_case=atoi(argv[1]); CHECK(current_case>0 && (size_t)current_case<=ARRAY_SIZE(cases));
    current_name=cases[current_case-1].name;
    cases[current_case-1].run();
    printf("ok %d - %s\n",current_case,current_name); return 0;
}

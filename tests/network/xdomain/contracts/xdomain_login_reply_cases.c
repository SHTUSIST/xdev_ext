/* SPDX-License-Identifier: GPL-2.0 */
/* External transport controls the packet delivered to the real TB matcher. */
static int mutation, transport_mode;
static unsigned int wire_bytes=96;
static bool matcher_accepted;
static struct xdev_ext_xd_login saved_request;
static struct xdev_ext_xd_login_response wire_reply, saved_wire_reply;
static struct xdev_ext_xd_login_response well_formed_reply(const struct xdev_ext_xd_login *req)
{
    struct xdev_ext_xd_login_response res={
        .route_hi=req->route_hi, .route_lo=req->route_lo, .length_sn=21,
        .type=2, .command_id=req->command_id, .incarnation=0x1111,
    };
    memcpy(res.uuid,req->uuid,16);
    memcpy(res.initiator_uuid,req->target_uuid,16);
    memcpy(res.target_uuid,req->initiator_uuid,16);
    /* Wire contract fixes requester incarnation at the final eight bytes. */
    memcpy((unsigned char *)&res+88,&req->incarnation,8);
    return res;
}
static int tb_xdomain_request(struct tb_xdomain *xd,const void *request,size_t size,int req_type,
                              void *reply,size_t reply_size,int resp_type,unsigned int timeout)
{
    assert(xd && size==120 && reply_size==96 && req_type==1 && resp_type==1 && timeout==1000);
    assert(live_link->ctl_mutex.held);
    memcpy(&last_request,request,size); requests++;
    if (transport_mode==1) { saved_request=last_request; return -ETIMEDOUT; }
    struct xdev_ext_xd_login_response res;
    if (transport_mode==2) res=well_formed_reply(&saved_request);
    else res=well_formed_reply(&last_request);
    if (transport_mode==3) { res=well_formed_reply(&saved_request); res.incarnation=0x2222; }
    if (transport_mode==4) res=saved_wire_reply;
    switch(mutation) {
    case 1: res.command_id+=100; break;
    case 2: res.command_id=0; break;
    case 3: res.initiator_uuid[5]^=1; break;
    case 4: res.target_uuid[5]^=1; break;
    case 5: res.uuid[5]^=1; break;
    case 6: res.type=3; break;
    case 7: res.length_sn=20; break;
    case 8: res.route_lo^=1; break;
    }
    struct tb_cfg_request cfg={.request=request,.response_size=reply_size};
    struct ctl_pkg pkg={.frame={.eof=1,.size=wire_bytes/4},.buffer=&res};
    matcher_accepted=tb_xdomain_match(&cfg,&pkg);
    wire_reply=res;
    if (!matcher_accepted) return -ETIMEDOUT;
    memcpy(reply,&res,reply_size);
    return 0;
}
/* MAIN_TU_BEFORE_CASES */
static struct pci_dev pdev;
static struct nhi test_nhi={.pdev=&pdev};
static struct tb test_tb={.nhi=&test_nhi};
static uuid_t local_uuid={{0x10,0x21}}, remote_uuid={{0x30,0x41}};
static struct tb_xdomain domain={.route=0x12345678000000a5ULL,
    .local_uuid=&local_uuid,.remote_uuid=&remote_uuid,.tb=&test_tb};
static struct tb_service service={.parent=&domain,.prtcstns=1};
static struct xdev_ext_xd_link *xl;
static int current_case;
static const char *current_name;
#define CHECK(x) do { if (!(x)) { \
 printf("not ok %d - %s\n# failed: %s\n# observed: requests=%d id=%u logged_in=%d response_inc=%llu confirmed=%d up=%d matched=%d\n", \
 current_case,current_name,#x,requests,last_request.command_id,xl?xl->logged_in:0, \
 (unsigned long long)(xl?xl->response_inc:0),xl?xl->confirmed_pending:0,xl?xl->up:0,matcher_accepted); \
 fflush(stdout); exit(1); } } while(0)
static void fresh_link(void)
{
    CHECK(!xdev_ext_xd_init()); service.dev.owner=&service;
    CHECK(!xdev_ext_xd_probe(&service,NULL)); xl=service.drvdata;
    CHECK(xl && xl->login_work.work.pending);
}
static struct xdev_ext_xd_login peer_login(u64 inc)
{
    struct xdev_ext_xd_login l={.route_hi=0x12345678,.route_lo=0xa5,.length_sn=27,
        .type=1,.command_id=0x76543210,.proto_version=2,.channels=1,
        .ctl_tx_path=37,.data_tx_path={41},.incarnation=inc,.caps=1};
    memcpy(l.uuid,&xdev_ext_xd_proto_uuid,16);
    memcpy(l.initiator_uuid,&remote_uuid,16); memcpy(l.target_uuid,&local_uuid,16);
    return l;
}
static void login_run(void) { run_work(&xl->login_work.work); }
static void ready_peer(void)
{
    struct xdev_ext_xd_login l=peer_login(0x1111);
    CHECK(registered_handler->callback(&l,sizeof(l),NULL)==1);
    run_work(&xl->connect_work);
    CHECK(xl->remote_logged_in && xl->accepted_inc==0x1111 && !xl->logged_in && !xl->up);
}
static void unchanged_unconfirmed(void)
{ CHECK(!xl->logged_in && !xl->response_inc && !xl->confirmed_pending && !xl->up); }
static void correct_reply(void)
{ fresh_link(); ready_peer(); login_run(); CHECK(matcher_accepted && xl->logged_in && xl->response_inc==0x1111 && xl->up); }
static void invalid_reply(void)
{
    fresh_link(); ready_peer(); login_run(); unchanged_unconfirmed();
    mutation=0; wire_bytes=96; CHECK(xl->login_work.work.pending); login_run();
    CHECK(xl->logged_in && xl->response_inc==0x1111 && xl->up);
}
static void wrong_id(void) { mutation=1; invalid_reply(); }
static void zero_id(void) { mutation=2; invalid_reply(); }
static void wrong_initiator(void) { mutation=3; invalid_reply(); }
static void wrong_target(void) { mutation=4; invalid_reply(); }
static void wrong_protocol(void) { mutation=5; invalid_reply(); }
static void wrong_type(void) { mutation=6; invalid_reply(); }
static void wrong_wire_length(void) { mutation=7; invalid_reply(); }
static void wrong_route(void) { mutation=8; invalid_reply(); }
static void short_reply(void) { wire_bytes=92; invalid_reply(); }
static void late_reply(void)
{
    fresh_link(); ready_peer(); transport_mode=1; login_run(); unchanged_unconfirmed();
    CHECK(requests==1 && xl->login_work.work.pending);
    transport_mode=2; login_run(); CHECK(requests==2 && saved_request.command_id!=last_request.command_id);
    unchanged_unconfirmed();
    transport_mode=0; CHECK(xl->login_work.work.pending); login_run(); CHECK(xl->logged_in && xl->up);
}
static void late_reply_cannot_confirm_candidate(void)
{
    fresh_link(); ready_peer(); transport_mode=1; login_run();
    struct xdev_ext_xd_login l=peer_login(0x2222);
    CHECK(registered_handler->callback(&l,sizeof(l),NULL)==1 && xl->candidate_pending);
    transport_mode=3; login_run(); unchanged_unconfirmed();
}
static void response_echo(bool error)
{
    fresh_link(); struct xdev_ext_xd_login l=peer_login(0x1111);
    if (!error) {
        CHECK(registered_handler->callback(&l,sizeof(l),NULL)==1);
        run_work(&xl->connect_work);
    } else l.proto_version=1;
    l.command_id=0x1234abcd;
    CHECK(registered_handler->callback(&l,sizeof(l),NULL)==1);
    CHECK(last_response.command_id==0x1234abcd);
    CHECK(last_response.type==2 && last_response.length_sn==21);
    CHECK(!memcmp(last_response.uuid,l.uuid,16));
    CHECK(!memcmp(last_response.initiator_uuid,l.target_uuid,16));
    CHECK(!memcmp(last_response.target_uuid,l.initiator_uuid,16));
    CHECK(last_response.status==(error?EPROTO:0));
}
static void success_echo(void) { response_echo(false); }
static void error_echo(void) { response_echo(true); }
static void zero_request(void)
{
    fresh_link(); struct xdev_ext_xd_login l=peer_login(0x1111); l.command_id=0;
    registered_handler->callback(&l,sizeof(l),NULL);
    CHECK(!xl->candidate_pending && !xl->connect_work.pending && !xl->remote_logged_in && !xl->up);
}
static void command_exhaustion(void)
{
    fresh_link(); transport_mode=1; xl->command_id.n=-2;
    login_run();
    CHECK(!requests || last_request.command_id);
    u32 first_id=last_request.command_id;
    u64 first_inc=last_request.incarnation;
    if (xl->login_work.work.pending) login_run();
    CHECK(!requests || last_request.command_id);
    /* If a request reused low IDs, its incarnation must have changed first. */
    CHECK(requests<2 || last_request.command_id>first_id || last_request.incarnation!=first_inc);
}
static void incarnation_replay(bool recreate)
{
    fresh_link(); ready_peer(); login_run();
    CHECK(xl->up && last_request.command_id==1);
    saved_wire_reply=wire_reply;
    u64 old_inc=xl->local_inc;
    if (recreate) {
        xdev_ext_xd_remove(&service);
        CHECK(link_freed && !rings_running);
        link_freed=false;
        CHECK(!xdev_ext_xd_probe(&service,NULL));
        xl=service.drvdata;
    } else xdev_ext_xd_link_down(xl,-ENOLINK);
    CHECK(xl->local_inc && xl->local_inc!=old_inc);
    ready_peer(); transport_mode=4; login_run();
    CHECK(last_request.command_id==saved_wire_reply.command_id);
    CHECK(last_request.incarnation!=old_inc);
    unchanged_unconfirmed();
    transport_mode=0; CHECK(xl->login_work.work.pending); login_run();
    CHECK(xl->logged_in && xl->response_inc==0x1111 && xl->up);
}
static void same_link_incarnation_replay(void) { incarnation_replay(false); }
static void recreated_link_incarnation_replay(void) { incarnation_replay(true); }
static void responder_echoes_requester_incarnation(void)
{
    fresh_link(); struct xdev_ext_xd_login l=peer_login(0x123456789abcdef0ULL);
    CHECK(registered_handler->callback(&l,sizeof(l),NULL)==1);
    u64 echoed; memcpy(&echoed,(unsigned char *)&last_response+88,8);
    CHECK(last_response.status==EAGAIN && echoed==l.incarnation);
    run_work(&xl->connect_work);
    CHECK(registered_handler->callback(&l,sizeof(l),NULL)==1);
    memcpy(&echoed,(unsigned char *)&last_response+88,8);
    CHECK(last_response.status==0 && echoed==l.incarnation);
    l.proto_version=1;
    CHECK(registered_handler->callback(&l,sizeof(l),NULL)==1);
    memcpy(&echoed,(unsigned char *)&last_response+88,8);
    CHECK(last_response.status==EPROTO && echoed==l.incarnation);
}
static struct { const char *name; void (*run)(void); } cases[]={
    {"correct reply still establishes UP",correct_reply},
    {"timed-out N reply cannot confirm active N+1",late_reply},
    {"timed-out N reply cannot confirm changed candidate",late_reply_cannot_confirm_candidate},
    {"wrong command ID preserves confirmation state",wrong_id},
    {"zero response ID preserves confirmation state",zero_id},
    {"wrong initiator UUID preserves confirmation state",wrong_initiator},
    {"wrong target UUID preserves confirmation state",wrong_target},
    {"foreign protocol preserves state and valid retry works",wrong_protocol},
    {"wrong response type preserves state and valid retry works",wrong_type},
    {"short response preserves state and valid retry works",short_reply},
    {"wrong encoded length preserves confirmation state",wrong_wire_length},
    {"wrong route preserves state and valid retry works",wrong_route},
    {"real responder success echoes request identity",success_echo},
    {"real responder error echoes request identity",error_echo},
    {"zero request ID creates no candidate",zero_request},
    {"command exhaustion never sends zero or reuses within incarnation",command_exhaustion},
    {"same link fresh incarnation rejects prior ID1 response",same_link_incarnation_replay},
    {"recreated link rejects prior same route UUID ID1 response",recreated_link_incarnation_replay},
    {"real responder echoes requester incarnation",responder_echoes_requester_incarnation},
};
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--count")) { printf("%zu\n",ARRAY_SIZE(cases)); return 0; }
    CHECK(argc==2); current_case=atoi(argv[1]); CHECK(current_case>0 && (size_t)current_case<=ARRAY_SIZE(cases));
    current_name=cases[current_case-1].name; cases[current_case-1].run();
    printf("ok %d - %s\n",current_case,current_name); return 0;
}

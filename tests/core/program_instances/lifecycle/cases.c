/* SPDX-License-Identifier: GPL-2.0 */
/* Reuse the existing native provider; add PRIVATE reference assertions only. */
static struct host_selected_program private_program={.ops={.abi_version=1,.flags=1}};
static struct host_selected_program default_program={.ops={.abi_version=1,.flags=0}};
static struct bpf_link private_link={.type=91,.refs=1,.class_id=XDEV_EXT_MECH_CLASS_DMA,.ops=&private_program.ops};
static struct bpf_link default_link={.type=91,.refs=1,.class_id=XDEV_EXT_MECH_CLASS_DMA,.ops=&default_program.ops};
static const struct xdev_ext_mech_class_ops *xdev_ext_mech_class_get(u32 id){return id==XDEV_EXT_MECH_CLASS_DMA?&xdev_ext_dma_class:NULL;}
/* ACTUAL_SELECTION_PREFIX */
static struct xdev_ext_mech_session *selected_session(int selector){
 struct xdev_ext_mech_session *s=session_new();struct xdev_ext_mech_create c={.nr_stages=1};
 c.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_DMA,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.arg1=4096};
 s32 selectors[4]={selector,-1,-1,-1};assert(!selected_prefix(s,&c,selectors));
 /* Restore existing qualified FD boundary: selection prefix stops before the
  * original CREATE fget stage, which would restore this same device file. */
 s->st[0].file=&device;assert(!bind_session(s));
 list_add_tail(&s->all_node,&xdev_ext_mech_all);return s;
}
static void retire_private(void){assert(!private_link.detached);private_link.detached=true;assert(xdev_ext_mech_instance_unregister(XDEV_EXT_MECH_CLASS_DMA,private_link.ops,&private_link));}
/* Same qualified accounting observer as runtime/teardown_test.py: actual
 * completion consumption/frame movement/leave, no invented completion result. */
static bool retire_accepted(struct xdev_ext_mech_batch *b){
 struct xdev_ext_mech_session *s=b->s;int result;
 assert(!xdev_ext_mech_completion_consume(&b->completion,b->ticket,&result));b->status=result;
 assert(!xdev_ext_mech_frames_move(s,b,XDEV_EXT_MECH_F_INFLIGHT,b->sequester?XDEV_EXT_MECH_F_SEQUESTERED:XDEV_EXT_MECH_F_HELD));
 b->queued=0;s->inbox.first=NULL;return xdev_ext_mech_leave_locked(s,b->sequester);
}
static int native_lifetime(const char *mode){
 assert(!xdev_ext_dma_provider_register(&provider));program_fds[41]=&private_link;
 assert(!xdev_ext_mech_instance_register(XDEV_EXT_MECH_CLASS_DMA,private_link.ops,&private_link));
 struct xdev_ext_mech_session *s=selected_session(41);u8 *states=s->pool.state;
 EQ(private_program.pins,1,"actual selection owns one program pin");CHECK(!s->ops[XDEV_EXT_MECH_CLASS_DMA],"PRIVATE never borrows default slot");
 struct xdev_ext_mech_batch *b=batch_new(s);
 s->plan[0]=(struct xdev_ext_mech_stage_uapi){.class_id=s->st[0].class_id,.direction=s->st[0].direction};b->producing=true;
 assert(!xdev_ext_mech_life_claim(&s->life[b->f[0].index],s->st[0].index,&b->life_token[0]));b->life_active=BIT(0);
 EQ(submit(b),0,"existing actual adapter accepts native command");EQ(accepts,1,"exactly one native acceptance");EQ(states[1],XDEV_EXT_MECH_F_INFLIGHT,"accepted frame stays native-owned");
 retire_private();CHECK(!xdev_ext_mech_session_admits(s),"withdrawal closes selected admission");EQ(s->ss.inflight,1,"withdrawal retains accepted work");EQ(private_program.pins,1,"withdrawal retains selected program");
 if(!strcmp(mode,"native-control"))atomic_inc(&s->native_controls);
 EQ(xdev_ext_mech_session_destroy(s),-EBUSY,"drain expiry keeps accepted native custody");
 EQ(private_program.pins,1,"drain expiry never puts PRIVATE program");EQ(owner.refs,1,"native provider module stays pinned");EQ(region_unbinds+host_unbinds+pool_releases+file_puts,0,"pending work retains every native resource");EQ(destroyed_workers,0,"worker remains for late completion");EQ(states[1],XDEV_EXT_MECH_F_INFLIGHT,"drain expiry never recycles native frame");
 bool control=!strcmp(mode,"native-control"),exact=!strcmp(mode,"late-exact")||control;
 u64 life_ctrl=s->life[b->f[0].index].ctrl,claim=b->life_token[0];
 if(control)EQ(s->ss.state,XDEV_EXT_MECH_SESSION_ZOMBIE,"outstanding native control quarantines before completion");
 xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,exact?128:127);
 EQ(b->sequester,!exact||control,"actual completion decides definite versus UNKNOWN custody");
 if(control){
  EQ(s->ss.state,XDEV_EXT_MECH_SESSION_ZOMBIE,"exact bytes never revive a quarantined session");
  EQ(s->life[b->f[0].index].ctrl,life_ctrl,"UNKNOWN retains lifecycle ownership word");
  EQ(b->life_active,BIT(0),"UNKNOWN keeps native lifecycle claim active");
  EQ(b->life_token[0],claim,"UNKNOWN keeps native lifecycle token");
  EQ(xdev_ext_mech_life_phase(&s->life[b->f[0].index]),XDEV_EXT_MECH_L_IO_PENDING,"UNKNOWN cannot recycle IO_PENDING lifecycle");
 }EQ(private_program.pins,1,"callback retains pin until safe final teardown");
 EQ(retire_accepted(b),true,"actual accepted-batch accounting drops last session reference");EQ(private_program.pins,1,"last reference accounting cannot bypass release gate");
 xdev_ext_mech_reap(&s->reap_work);EQ(accepts,1,"accepted work never replays");EQ(destroyed_workers,1,"late last reference destroys worker exactly once");
 if(!strcmp(mode,"late-exact")){
  EQ(private_program.pins,0,"definite late teardown releases PRIVATE exactly once");EQ(selected_gets,selected_puts,"safe PRIVATE refs balance");EQ(owner.refs,0,"safe teardown drops provider module");EQ(region_unbinds,1,"region released once");EQ(host_unbinds,1,"host mapping released once");EQ(pool_releases,1,"pool released once");EQ(file_puts,1,"device file released once");free(states);
 }else{
  EQ(private_program.pins,1,"UNKNOWN/native-control quarantine retains selected program");EQ(selected_puts,0,"UNKNOWN never puts selected instance");EQ(owner.refs,1,"UNKNOWN retains provider module");EQ(region_unbinds+host_unbinds+pool_releases+file_puts,0,"UNKNOWN retains all native resources");EQ(s->ss.state,XDEV_EXT_MECH_SESSION_ZOMBIE,"UNKNOWN stays quarantined");
  if(!control)EQ(states[1],XDEV_EXT_MECH_F_SEQUESTERED,"ambiguous late frame remains sequestered");
 }
 printf("PRIVATE_NATIVE_LIFETIME mode=%s checks=%u pins=%u/%u\n",mode,checks,selected_gets,selected_puts);return 0;
}
static s32 cref_callback(const struct xdev_ext_mech_ctx *ctx){(void)ctx;return 0;}
static int reference_coexistence(void){
 struct xdev_ext_mech_c_ops reference={.abi_version=1,.build=cref_callback,.complete=cref_callback};struct module reference_owner={0};
 assert(!xdev_ext_dma_provider_register(&provider));EQ(xdev_ext_ops_publish(&xdev_ext_mech_registry,XDEV_EXT_MECH_CLASS_DMA,&default_program.ops,&default_link),0,"actual BPF default registers");
 EQ(__xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_DMA,&reference,&reference_owner),0,"actual C-reference install accepts known class");
 program_fds[41]=&private_link;assert(!xdev_ext_mech_instance_register(XDEV_EXT_MECH_CLASS_DMA,private_link.ops,&private_link));
 struct xdev_ext_mech_session *legacy=selected_session(-1),*selected=selected_session(41);u8 *ls=legacy->pool.state,*ps=selected->pool.state;
 CHECK(legacy->ops[XDEV_EXT_MECH_CLASS_DMA]==&reference&&!legacy->pinned[XDEV_EXT_MECH_CLASS_DMA],"selector-1 retains actual C-reference priority");EQ(reference_owner.refs,1,"C-reference module owned until safe release");EQ(default_program.pins,0,"C priority never pins BPF default");
 CHECK(selected->instances[0]&&!selected->ops[XDEV_EXT_MECH_CLASS_DMA]&&!selected->c_owner[XDEV_EXT_MECH_CLASS_DMA],"explicit PRIVATE bypasses installed C default");EQ(private_program.pins,1,"PRIVATE owns independent BPF pin");
 EQ(__xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_DMA,NULL,NULL),0,"actual C-reference uninstall");CHECK(!xdev_ext_mech_session_admits(legacy)&&xdev_ext_mech_session_admits(selected),"default withdrawal cancels only its default session");EQ(reference_owner.refs,1,"cached C module stays pinned after withdrawal");
 EQ(xdev_ext_mech_session_destroy(legacy),-ECANCELED,"safe default release preserves withdrawal cause");EQ(reference_owner.refs,0,"safe default release balances module ref");free(ls);
 EQ(xdev_ext_mech_session_destroy(selected),0,"independent PRIVATE releases safely");EQ(private_program.pins,0,"safe PRIVATE balances selected pin");free(ps);retire_private();EQ(owner.refs,0,"both native class bindings released");EQ(selected_gets,selected_puts,"PRIVATE refs balance independently");
 printf("C_REFERENCE_PRIVATE_COEXIST checks=%u pins=%u/%u\n",checks,selected_gets,selected_puts);return 0;
}
int main(int argc,char **argv){if(argc!=2)return 2;return !strcmp(argv[1],"c-reference")?reference_coexistence():native_lifetime(argv[1]);}

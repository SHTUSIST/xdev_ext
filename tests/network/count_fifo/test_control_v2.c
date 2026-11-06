/* Independent literal assertions for the public v2 COUNT/CONTROL contract.
 * No producer output populates these expected outcomes.
 */
struct v2_refusal_image {
 struct xsk_xdev_ext_mech_provider provider;
 struct xsk_mech_reliable rel;
 struct xsk_xdev_ext_mech_tx_batch target;
 struct xdev_ext_mech_pool pool;struct xdev_ext_mech_session session;
 struct xsk_xdev_ext_mech_stage stage;struct xdev_ext_mech_stage st;
 struct xsk_buff_pool xp;struct xdp_sock xs;struct xdp_umem umem;
 struct xdev_ext_mech_batch batch;dma_addr_t mappings[64];
 struct xsk_mech_zc_slot slots[64];struct xdp_desc desc[64];
 u8 state[64],backing[64][4096],raw_backing[3][4096];u64 tag[3];
 int refs,moves,kicks,dev,cpu,raw,ops,bytes,callbacks,dead;
 int refs_by_owner[2],puts_by_owner[2];
 u32 cas;size_t events;
};
static struct v2_refusal_image v2_before;
static void v2_fresh(const char *name)
{
 memset(public_chunks,0,sizeof(public_chunks));
 good_reset(name);v2_prepare_rel(&v2_rel,3);xst.rel=&v2_rel;
 v2_reserve_control(&v2_rel,0);v2_reserve_control(&v2_rel,1);
 observed_control=&v2_rel.control[0];observed_provider=NULL;
}
static void v2_capture(struct xsk_xdev_ext_mech_tx_batch *target)
{
 memcpy(&v2_before.provider,&p,sizeof(p));memcpy(&v2_before.rel,&v2_rel,sizeof(v2_rel));memcpy(&v2_before.target,target,sizeof(*target));
 memcpy(&v2_before.pool,&pool,sizeof(pool));memcpy(&v2_before.session,&session,sizeof(session));
 memcpy(&v2_before.stage,&xst,sizeof(xst));memcpy(&v2_before.st,&st,sizeof(st));
 memcpy(&v2_before.xp,&xp,sizeof(xp));memcpy(&v2_before.xs,&xs,sizeof(xs));memcpy(&v2_before.umem,&umem,sizeof(umem));
 memcpy(&v2_before.batch,&batch,sizeof(batch));memcpy(v2_before.mappings,xp.dma_pages,sizeof(v2_before.mappings));
 memcpy(v2_before.slots,public_slots,sizeof(public_slots));memcpy(v2_before.desc,public_descs,sizeof(public_descs));
 memcpy(v2_before.state,v2_words,sizeof(v2_words));memcpy(v2_before.backing,public_chunks,sizeof(public_chunks));memcpy(v2_before.raw_backing,chunks,sizeof(chunks));memcpy(v2_before.tag,tags,sizeof(tags));
 v2_before.refs=native_refs;v2_before.moves=frame_moves;v2_before.kicks=stage_kicks;
 memcpy(v2_before.refs_by_owner,v2_refs,sizeof(v2_refs));memcpy(v2_before.puts_by_owner,v2_puts,sizeof(v2_puts));
 v2_before.dev=sync_dev_n;v2_before.cpu=sync_cpu_n;v2_before.raw=raw_n;
 v2_before.ops=count_ops;v2_before.bytes=count_bytes;v2_before.callbacks=callbacks;v2_before.dead=dead_status;
 v2_before.cas=v2_cas_count;v2_before.events=event_n;
}
static void v2_assert_preserved(struct xsk_xdev_ext_mech_tx_batch *target)
{
 REQUIRE("v2_refusal_provider",!memcmp(&v2_before.provider,&p,sizeof(p)));
 REQUIRE("v2_refusal_owner",!memcmp(&v2_before.rel,&v2_rel,sizeof(v2_rel))&&!memcmp(&v2_before.target,target,sizeof(*target)));
 REQUIRE("v2_refusal_pool_session",!memcmp(&v2_before.pool,&pool,sizeof(pool))&&!memcmp(&v2_before.session,&session,sizeof(session)));
 REQUIRE("v2_refusal_stage",!memcmp(&v2_before.stage,&xst,sizeof(xst))&&!memcmp(&v2_before.st,&st,sizeof(st)));
 REQUIRE("v2_refusal_mapping_objects",!memcmp(&v2_before.xp,&xp,sizeof(xp))&&!memcmp(&v2_before.xs,&xs,sizeof(xs))&&!memcmp(&v2_before.umem,&umem,sizeof(umem))&&!memcmp(&v2_before.batch,&batch,sizeof(batch))&&!memcmp(v2_before.mappings,xp.dma_pages,sizeof(v2_before.mappings)));
 REQUIRE("v2_refusal_slots",!memcmp(v2_before.slots,public_slots,sizeof(public_slots))&&!memcmp(v2_before.desc,public_descs,sizeof(public_descs)));
 REQUIRE("v2_refusal_bytes",!memcmp(v2_before.state,v2_words,sizeof(v2_words))&&!memcmp(v2_before.backing,public_chunks,sizeof(public_chunks))&&!memcmp(v2_before.raw_backing,chunks,sizeof(chunks))&&!memcmp(v2_before.tag,tags,sizeof(tags)));
 REQUIRE("v2_refusal_effects",native_refs==v2_before.refs&&frame_moves==v2_before.moves&&stage_kicks==v2_before.kicks&&sync_dev_n==v2_before.dev&&sync_cpu_n==v2_before.cpu&&raw_n==v2_before.raw&&count_ops==v2_before.ops&&count_bytes==v2_before.bytes&&callbacks==v2_before.callbacks&&dead_status==v2_before.dead);
 REQUIRE("v2_refusal_individual_refs",!memcmp(v2_before.refs_by_owner,v2_refs,sizeof(v2_refs))&&!memcmp(v2_before.puts_by_owner,v2_puts,sizeof(v2_puts)));
}
static void v2_refusal(struct xsk_xdev_ext_mech_tx_batch *target,struct xdp_desc *d,u32 n,int error,bool helper,bool cas_attempt)
{
 struct xdp_desc original[32];memcpy(original,d,sizeof(original));v2_capture(target);
 int result=helper?v2_helper(target,d,n):v2_enqueue(target,d,n);
 v2_last_ret=result;
 REQUIRE("v2_refusal_error",result==error);v2_assert_preserved(target);
 REQUIRE("v2_refusal_descriptor_input",!memcmp(original,d,sizeof(original)));
 REQUIRE("v2_refusal_interval",event_n==v2_before.events+4&&!memcmp(events+v2_before.events,"L U ",4));
 REQUIRE("v2_refusal_cas_count",v2_cas_count==v2_before.cas+(cas_attempt?1:0));
 v2_preserved=true;
 if(cas_attempt){
  struct v2_cas_record *o=&v2_cas[v2_before.cas];
  REQUIRE("control_cas_busy_word",o->index==63&&o->from==XDEV_EXT_MECH_F_HELD&&o->to==XDEV_EXT_MECH_F_INFLIGHT&&o->result==-EBUSY&&o->nr==64&&!memcmp(o->before,o->after,64));
 }
}
static void v2_refusals(void)
{
 static const char *names[]={
  "control_count2_refused","control_count32_refused","control_count0_reserve_priority",
  "control_wrong_instance","control_free_standing_tb","control_wrong_stage","control_nonnull_batch","control_false_private_helper",
  "control_busy","control_uncertain","control_occupied_lease",
  "control_missing_state","control_wrong_reserved_index","control_wrong_source_partition","control_window_gt_frames",
  "control_payload_present","control_header58","control_layout_mismatch","control_header_room105","control_header_room4097",
  "control_options","control_short_header","control_long_header","control_addr_below_base","control_offset_u32_overflow","control_wrong_offset","control_other_frame_span",
  "control_map_unavailable","control_other_socket_pool","control_bad_head",
  "control_cpu_identity_vaddr","control_cpu_identity_size","control_cpu_identity_kaddr",
  "control_cas_busy_word","control_cas_free_word","control_cas_sequestered_word",
  "control_priority_full_bad_owner","control_priority_fatal_bad_count","control_priority_stopped_bad_header"
 };
 static const char *ids[]={"C10/count2","C10/count32","C10/count0","C11/foreign","C11/detached","C12/stage","C12/batch","C12/false-helper","C13/busy","C13/uncertain","C13/lease","C14/state","C14/index","C14/partition","C14/window","C15/payload","C15/header58","C16/layout","C16/105","C16/4097","C17/options","C17/105","C17/107","C17/below","C17/u32","C17/offset","C17/other-span","C18/device","C18/socket","C18/head","C19/vaddr","C19/size","C19/kaddr","C20/inflight","C20/free","C20/sequestered","C21/full","C21/fatal","C21/stopped"};
 REQUIRE("v2_refusal_id_inventory",sizeof(ids)/sizeof(ids[0])==sizeof(names)/sizeof(names[0]));
 for(u32 vector=0;vector<sizeof(names)/sizeof(names[0]);vector++){
  v2_fresh(names[vector]);struct xsk_mech_reliable foreign=v2_rel;
  struct xdev_ext_mech_stage other_stage=st;struct xsk_buff_pool other_pool=xp;
  struct xsk_xdev_ext_mech_tx_batch detached={.control=true,.reliable_stage=&st};
  struct xsk_rel_control *c=&v2_rel.control[0];struct xsk_xdev_ext_mech_tx_batch *target=&c->tb;
  struct xdp_desc d[32];for(u32 i=0;i<32;i++)d[i]=v2_control_desc(0);
  u32 count=1;int error=0;bool helper=false,cas_attempt=false;
  switch(vector){
  case 0:count=2;error=-EINVAL;break;
  case 1:count=32;error=-EINVAL;break;
  case 2:count=0;error=-EAGAIN;break;
  case 3:target=&foreign.control[0].tb;error=-EXDEV;break;
  case 4:target=&detached;error=-EXDEV;break;
  case 5:c->tb.reliable_stage=&other_stage;error=-EXDEV;break;
  case 6:c->tb.batch=&batch;error=-EXDEV;break;
  case 7:c->tb.control=false;helper=true;error=-EXDEV;break;
  case 8:c->busy=true;error=-EBUSY;break;
  case 9:c->uncertain=true;error=-EBUSY;break;
  case 10:memset(&c->tb.pool_lease[0],0xa5,sizeof(c->tb.pool_lease[0]));c->tb.pool_lease[0].kind=XDEV_EXT_NET_LEASE_POOL_DMA;error=-EBUSY;break;
  case 11:pool.state=NULL;error=-ERANGE;break;
  case 12:c->frame.index=62;error=-ERANGE;break;
  case 13:p.source_first=64;error=-ERANGE;break;
  case 14:v2_rel.rx.cfg.window=65;error=-ERANGE;break;
  case 15:c->frame.data_len=16;error=-EPROTO;break;
  case 16:d[0].len=58;error=-EPROTO;break;
  case 17:session.layout.hdr_room=129;error=-ERANGE;break;
  case 18:session.layout.hdr_room=c->frame.data_off=105;error=-ERANGE;break;
  case 19:session.layout.hdr_room=c->frame.data_off=4097;error=-ERANGE;break;
  case 20:d[0].options=1;error=-EINVAL;break;
  case 21:d[0].len=105;error=-EPROTO;break;
  case 22:d[0].len=107;error=-EPROTO;break;
  case 23:d[0].addr=258047;error=-ERANGE;break;
  case 24:d[0].addr=258048ULL+UINT32_MAX+1ULL;error=-ERANGE;break;
  case 25:d[0].addr++;error=-ERANGE;break;
  case 26:d[0].addr=253974;error=-ERANGE;break;
  case 27:xp.dev=NULL;error=-ENXIO;break;
  case 28:xs.pool=&other_pool;error=-EXDEV;break;
  case 29:c->frame.pool_priv=&public_heads[62];error=-ERANGE;break;
  case 30:pool.vaddr=chunks;error=-EXDEV;break;
  case 31:pool.size--;error=-EXDEV;break;
  case 32:c->frame.kaddr=public_chunks[62];error=-EXDEV;break;
  case 33:v2_words[63]=XDEV_EXT_MECH_F_INFLIGHT;error=-EBUSY;cas_attempt=true;break;
  case 34:v2_words[63]=XDEV_EXT_MECH_F_K_FREE;error=-EBUSY;cas_attempt=true;break;
  case 35:v2_words[63]=XDEV_EXT_MECH_F_SEQUESTERED;error=-EBUSY;cas_attempt=true;break;
  case 36:p.ring.prod=64;target=&foreign.control[0].tb;error=-EAGAIN;break;
  case 37:p.ring.fatal=-EPIPE;count=32;error=-EPIPE;break;
  case 38:p.stopped=true;d[0].len=58;error=-ENXIO;break;
  default:REQUIRE("v2_refusal_inventory",false);
  }
  v2_refusal(target,d,count,error,helper,cas_attempt);
  v2_semantic(ids[vector]);
 }
}
static void v2_accept(u32 j)
{
 struct xdp_desc d=v2_control_desc(j);v2_hold_ref(j);
 REQUIRE("v2_accept",!v2_enqueue(&v2_rel.control[j].tb,&d,1));v2_metadata(&v2_rel.control[j],j);
 struct v2_cas_record *o=&v2_cas[v2_cas_count-1];
 REQUIRE("v2_publish_real_cas",!o->result&&o->nr==64&&o->index==63-j&&o->from==XDEV_EXT_MECH_F_HELD&&o->to==XDEV_EXT_MECH_F_INFLIGHT);
 for(u32 k=0;k<64;k++)REQUIRE("v2_all_frame_words",o->after[k]==(k==63-j?XDEV_EXT_MECH_F_INFLIGHT:o->before[k]));
 REQUIRE("v2_exact_device_span",sync_addr[sync_dev_n-1]==(j?131072022:133169174)&&sync_len[sync_dev_n-1]==106&&sync_epoch[sync_dev_n-1]==lock_epoch);
 REQUIRE("reliable_control_tag",p.slots[(p.ring.prod-1)&63].owner==XSK_MECH_ZC_CONTROL);
}
static void v2_custody(bool unknown,int refs,int moves)
{
 struct xsk_rel_control *c=&v2_rel.control[0];
 REQUIRE("control_custody",c->busy==unknown&&c->uncertain==unknown&&native_refs==refs&&frame_moves==moves&&!c->tb.completion.pending&&!p.ring.native_count&&v2_words[63]==(unknown?XDEV_EXT_MECH_F_INFLIGHT:XDEV_EXT_MECH_F_HELD));
 REQUIRE("v2_terminal_lease",c->tb.pool_lease[0].kind==(unknown?XDEV_EXT_NET_LEASE_POOL_DMA:XDEV_EXT_NET_LEASE_NONE));
 if(unknown){
  const struct xdev_ext_net_pool_dma *l=&c->tb.pool_lease[0].u.pool;
  REQUIRE("v2_unknown_full_metadata",l->owner==&p&&l->frame_index==63&&l->umem_addr==258048&&l->frame_off==22&&l->len==106);
 }
 REQUIRE("v2_terminal_no_data",!count_ops&&!count_bytes&&!callbacks);
}
static void v2_lifecycle(void)
{
 v2_fresh("control_refusal_preserves_other_pending");v2_accept(0);
 struct xdp_desc d[32];for(u32 i=0;i<32;i++)d[i]=v2_control_desc(1);d[0].len=58;
 v2_refusal(&v2_rel.control[1].tb,d,1,-EPROTO,false,false);
 REQUIRE("v2_prior_pending",native_refs==1&&v2_rel.control[0].busy&&v2_rel.control[0].tb.completion.pending==1);
 v2_semantic("C22/refused");
 for(int mode=0;mode<8;mode++){
  const char *names[]={"control_definite_once","control_tail_definite_error","control_unknown_stop","control_overcount","control_set_only_zero","control_set_only_eagain_reentrant","control_direct_eagain","control_stopped_map"};
  const char *ids[]={"C24/complete","C25/error","C26/stop","C27/overcount","C28/complete","C29/single","C30/direct","C32/stopped"};
  const char *late[]={"C24/late","C25/late","C26/late","C27/late","C28/late","C29/late","C30/late","C32/late"};
  v2_fresh(names[mode]);v2_accept(0);REQUIRE("v2_public_peek",v2_public_peek(1)==1);
  struct xsk_rel_control *c=&v2_rel.control[0];
  if(mode==0)v2_public_complete(1);
  if(mode==1)v2_public_cancel(1,-EIO);
  if(mode==2)v2_stop(-ENXIO);
  if(mode==7)v2_pool_dead();
  if(mode==3){v2_last_ret=xsk_xdev_ext_mech_tx_complete(&xp,2,0,false,false);REQUIRE("v2_overcount",v2_last_ret==-EPROTO);}
  if(mode==4){
   v2_public_set(1,0);
   REQUIRE("v2_set_only_retained",p.slots[0].state==XSK_MECH_ZC_NATIVE&&c->tb.completion.pending==1&&c->busy&&!c->uncertain&&native_refs==1&&!frame_moves&&!sync_cpu_n&&c->tb.pool_lease[0].kind==XDEV_EXT_NET_LEASE_POOL_DMA&&v2_words[63]==XDEV_EXT_MECH_F_INFLIGHT);
   v2_semantic("C28/set-only");
   v2_public_complete(1);
  }
  if(mode==5){nested_dead=nested_stop;v2_public_set(1,-EAGAIN);}
  if(mode==6){v2_last_ret=xsk_xdev_ext_mech_tx_complete(&xp,1,-EAGAIN,false,false);v2_ret_null=false;REQUIRE("v2_direct_eagain",!v2_last_ret);}
  bool unknown=mode==2||mode==3||mode==5||mode==7;v2_custody(unknown,unknown,unknown?0:1);
  if(mode==1)REQUIRE("v2_tail_error_channels",c->tb.native_error==-EIO&&c->tb.completion.status==-EIO&&p.ring.fatal==-EIO&&dead_status==-EIO&&!sync_cpu_n);
  if(mode==5)REQUIRE("v2_reentrant_channels",p.slots[0].result==-EAGAIN&&c->tb.native_error==-EAGAIN&&c->tb.completion.status==-ENXIO&&p.ring.fatal==-EIO&&dead_status==-EAGAIN&&!sync_cpu_n);
  if(mode==6)REQUIRE("v2_direct_channels",p.slots[0].result==-EAGAIN&&c->tb.native_error==-EAGAIN&&c->tb.completion.status==-EIO&&p.ring.fatal==-EIO&&dead_status==-EAGAIN&&!sync_cpu_n&&!build_calls);
  if(mode==0||mode==4)REQUIRE("v2_definite_return_span",sync_cpu_n==1&&cpu_sync_addr[0]==133169174&&cpu_sync_len[0]==106);
  v2_semantic(ids[mode]);
  if(mode==2){
   case_name="control_refusal_preserves_other_unknown";for(u32 i=0;i<32;i++)d[i]=v2_control_desc(0);
   v2_refusal(&c->tb,d,1,-EBUSY,true,false);v2_semantic("C23/helper");
   v2_refusal(&c->tb,d,1,-ENXIO,false,false);v2_semantic("C23/enqueue");
  }
  int raw_before=raw_n,cpu_before=sync_cpu_n,refs_before=native_refs,moves_before=frame_moves;
  xsk_mech_zc_stop(&p,-ENXIO);REQUIRE("v2_repeat_no_put",native_refs==refs_before&&frame_moves==moves_before);
  v2_last_ret=xsk_xdev_ext_mech_tx_complete(&xp,1,0,false,false);v2_ret_null=false;REQUIRE("v2_unmatched_late",v2_last_ret==-EPROTO);
  REQUIRE("v2_stopped_no_map",native_refs==refs_before&&frame_moves==moves_before&&raw_n==raw_before&&sync_cpu_n==cpu_before);
  v2_semantic(late[mode]);
 }
}
static void v2_companion_stop(void)
{
 v2_fresh("control_set_only_eagain_pending_companion");v2_accept(0);v2_accept(1);
 REQUIRE("v2_companion_native",v2_public_peek(1)==1);
 nested_dead=nested_stop;v2_public_set(1,-EAGAIN);
 struct xsk_rel_control *c0=&v2_rel.control[0],*c1=&v2_rel.control[1];
 REQUIRE("v2_companion_individual",c0->uncertain&&c0->busy&&c0->tb.pool_lease[0].kind==XDEV_EXT_NET_LEASE_POOL_DMA&&v2_words[63]==XDEV_EXT_MECH_F_INFLIGHT&&!c1->uncertain&&!c1->busy&&!c1->tb.pool_lease[0].kind&&v2_words[62]==XDEV_EXT_MECH_F_HELD);
 REQUIRE("v2_companion_channels",c0->tb.native_error==-EAGAIN&&c0->tb.completion.status==-ENXIO&&c1->tb.completion.status==-ENXIO&&!c1->tb.cancelled_before_native&&p.ring.fatal==-EIO&&dead_status==-ENXIO&&native_refs==1&&frame_moves==1);
 v2_semantic("C29/companion");
 /* This full-call observation precedes the separately tested late EPROTO. */
}
static void v2_mixed_stop(void)
{
 memset(public_chunks,0,sizeof(public_chunks));good_reset("control_mixed_stop_first_pass");
 /* This added case follows ordinary32; restore its explicitly frozen input. */
 memset(public_chunks+3,0,sizeof(public_chunks)-3*4096);
 v2_mixed_input(&v2_rel,false);
 REQUIRE("v2_ordinary_dispatch",!xst.rel);REQUIRE("v2_mixed_submit",!xsk_xdev_ext_mech_submit(&st,&batch));v2_mixed_bytes(false);
 xst.rel=&v2_rel;v2_reserve_control(&v2_rel,0);v2_reserve_control(&v2_rel,1);v2_accept(0);v2_accept(1);
 REQUIRE("v2_mixed_peek3",v2_public_peek(3)==3);v2_public_cancel(1,0);
 REQUIRE("v2_mixed_peek_control",v2_public_peek(1)==1);
 REQUIRE("v2_mixed_before_stop",p.ring.prod==5&&p.ring.issued==4&&!p.ring.cons&&p.ring.native_count==3&&p.slots[2].state==XSK_MECH_ZC_DONE);
 v2_stop(-ENXIO);
 struct xsk_rel_control *c0=&v2_rel.control[0],*c1=&v2_rel.control[1];
 REQUIRE("control_custody",c0->uncertain&&c0->busy&&v2_words[63]==XDEV_EXT_MECH_F_INFLIGHT&&c0->tb.pool_lease[0].kind==XDEV_EXT_NET_LEASE_POOL_DMA&&!c1->uncertain&&!c1->busy&&v2_words[62]==XDEV_EXT_MECH_F_HELD&&!c1->tb.pool_lease[0].kind&&native_refs==1&&frame_moves==1);
 REQUIRE("v2_mixed_stop_channels",seq_callbacks==1&&callbacks==1&&tb.completion.uncertain&&count_ops==1&&count_bytes==16&&sync_cpu_n==1&&cpu_sync_addr[0]==131072022&&cpu_sync_len[0]==106&&dead_status==-ENXIO&&!p.ring.native_count&&p.ring.cons==5);
 const char *suffix="L R s U Q L U D L U D ";size_t n=strlen(suffix);
 REQUIRE("v2_mixed_stop_events",event_n>=n&&!memcmp(events+event_n-n,suffix,n));
 v2_semantic("C31/stopped");
}
static void v2_bad_mixed_layout(void)
{
 memset(public_chunks,0,sizeof(public_chunks));good_reset("control_mixed_bad_data_layout");v2_mixed_input(&v2_rel,false);
 v2_reserve_control(&v2_rel,0);v2_reserve_control(&v2_rel,1);
 v2_prefinish=true;memcpy(v2_input_backing,public_chunks,sizeof(public_chunks));
 struct xsk_xdev_ext_mech_tx_bounds bounds={.hdr_room=128,.mtu=108,.peer=session.peer};
 struct xdev_ext_mech_frame_info bad=xst.tx_fi[0];bad.data_off=64;
 struct xdev_ext_mech_frame_info saved_bad;struct xsk_xdev_ext_mech_tx_bounds saved_bounds;
 memcpy(&saved_bad,&bad,sizeof(bad));memcpy(&saved_bounds,&bounds,sizeof(bounds));
 v2_capture(&v2_rel.control[0].tb);
 v2_last_ret=xsk_xdev_ext_mech_tx_check(&xst.tx_desc[0],&bad,public_chunks[0],&bounds);
 REQUIRE("v2_one_field_data_layout",v2_last_ret==-EINVAL&&!p.ring.prod&&!sync_dev_n);
 v2_assert_preserved(&v2_rel.control[0].tb);
 REQUIRE("v2_tx_check_full_input_preserved",!memcmp(&saved_bad,&bad,sizeof(bad))&&!memcmp(&saved_bounds,&bounds,sizeof(bounds))&&event_n==v2_before.events&&v2_cas_count==v2_before.cas);
 v2_preserved=true;v2_semantic("C33/one-field");
 case_name="control_mixed_historical_geometry";struct xdp_desc d={22,58,0};
 struct xdp_desc saved_d;memcpy(&saved_d,&d,sizeof(d));v2_capture(&v2_rel.control[0].tb);
 v2_last_ret=xsk_xdev_ext_mech_tx_check(&d,&bad,chunks[0],&bounds);
 REQUIRE("v2_historical_geometry",v2_last_ret==-EINVAL&&!p.ring.prod&&!sync_dev_n);
 v2_assert_preserved(&v2_rel.control[0].tb);
 REQUIRE("v2_tx_historical_full_input_preserved",!memcmp(&saved_d,&d,sizeof(d))&&!memcmp(&saved_bad,&bad,sizeof(bad))&&!memcmp(&saved_bounds,&bounds,sizeof(bounds))&&event_n==v2_before.events&&v2_cas_count==v2_before.cas);
 v2_preserved=true;v2_semantic("C33/historical");
}
static void control_v2_cases(void)
{
 v2_refusals();v2_lifecycle();v2_companion_stop();v2_mixed_stop();v2_bad_mixed_layout();
}

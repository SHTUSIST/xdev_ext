/* typed-control-v2: equivalent input facts and observations, no policy stubs.
 * control_vectors.h is an independently authored, root-frozen SOURCE artifact.
 */
#include "control_vectors.h"
static u8 v2_words[64];
static struct xsk_mech_reliable v2_rel;
static struct xsk_mech_reliable *v2_watch;
static int v2_owner=-1,v2_refs[2],v2_puts[2],v2_dead[32];static u32 v2_dead_n;
static bool v2_packet_ok,v2_preserved,v2_ret_null,v2_prefinish;static int v2_last_ret;
static u8 v2_input_backing[64][4096];
static const char *v2_hidden_id;
static FILE *v2_semantic_file;static u32 v2_semantic_rows;
/* Observation only: tokens distinguish a callback from older equal-status
 * notifications, and a stack retains identity across synchronous STOP reentry. */
struct v2_invocation {
 struct xsk_xdev_ext_mech_tx_batch *tb;u32 token,notify_seq,put_seq;
 int owner,status;bool requires_dead,notified,put;
};
struct v2_joint_event {u32 token,sequence;int owner,status,refs;bool put;};
static struct v2_invocation v2_invocations[128];
static struct v2_joint_event v2_joint[256];
static u32 v2_stack[16],v2_depth,v2_invocation_n,v2_joint_n,v2_sequence;
static void v2_refusal(struct xsk_xdev_ext_mech_tx_batch *,struct xdp_desc *,u32,int,bool,bool);
static void v2_hold_ref(u32 j)
{
 REQUIRE("v2_reference_index",j<2);native_refs++;v2_refs[j]++;
}
static int v2_native_enter(struct xsk_xdev_ext_mech_tx_batch *t)
{
 int previous=v2_depth;v2_owner=-1;
 if(v2_watch && t->control){for(u32 j=0;j<2;j++)if(t==&v2_watch->control[j].tb)v2_owner=j;}
 REQUIRE("v2_native_invocation_bound",v2_depth<16&&v2_invocation_n<128);
 REQUIRE("v2_native_control_membership",!v2_watch||!t->control||v2_owner>=0);
 struct v2_invocation *call=&v2_invocations[v2_invocation_n];
 *call=(struct v2_invocation){.tb=t,.token=v2_invocation_n+1,.owner=v2_owner,
  .status=t->native_error?t->native_error:t->completion.status,
  .requires_dead=(t->native_error||t->completion.status)&&!(t->cancelled_before_native&&!t->native_error)};
 v2_stack[v2_depth++]=v2_invocation_n++;
 return previous;
}
static void v2_native_leave(int previous)
{
 REQUIRE("v2_native_invocation_balance",previous>=0&&v2_depth==(u32)previous+1);
 struct v2_invocation *call=&v2_invocations[v2_stack[v2_depth-1]];
 if(call->owner>=0&&call->requires_dead)REQUIRE("v2_native_required_notification",call->notified&&call->notify_seq>0);
 v2_depth=previous;v2_owner=v2_depth?v2_invocations[v2_stack[v2_depth-1]].owner:-1;
}
static void v2_joint_observe(struct v2_invocation *call,int status,bool put)
{
 REQUIRE("v2_joint_bound",v2_joint_n<256);
 v2_joint[v2_joint_n++]=(struct v2_joint_event){.token=call?call->token:0,
  .sequence=++v2_sequence,.owner=call?call->owner:-1,.status=status,
  .refs=call&&call->owner>=0?v2_refs[call->owner]:0,.put=put};
}
static void v2_note_put(void)
{
 REQUIRE("v2_put_identity",v2_depth&&v2_owner>=0&&v2_owner<2&&v2_refs[v2_owner]>0);
 struct v2_invocation *call=&v2_invocations[v2_stack[v2_depth-1]];
 REQUIRE("v2_put_same_invocation_owner",call->owner==v2_owner&&v2_watch&&call->tb==&v2_watch->control[v2_owner].tb&&!call->put);
 if(call->requires_dead)REQUIRE("v2_dead_before_put_same_invocation",call->notified&&call->notify_seq>0&&call->notify_seq<=v2_sequence);
 v2_joint_observe(call,call->status,true);call->put=true;call->put_seq=v2_sequence;
 if(call->requires_dead)REQUIRE("v2_dead_before_put_sequence",call->notify_seq<call->put_seq);
 v2_refs[v2_owner]--;v2_puts[v2_owner]++;
}
static void v2_note_dead(struct xdev_ext_mech_stage *stage,int status)
{
 if(!v2_watch)return;
 REQUIRE("v2_dead_actual_stage",stage==&st);
 struct v2_invocation *call=v2_depth?&v2_invocations[v2_stack[v2_depth-1]]:NULL;
 if(call&&call->owner>=0){
  REQUIRE("v2_dead_same_invocation_owner",call->tb==&v2_watch->control[call->owner].tb&&call->tb->reliable_stage==stage);
  REQUIRE("v2_dead_required_status",call->requires_dead&&status==call->status&&!call->notified&&!call->put&&v2_refs[call->owner]>0);
 }
 v2_joint_observe(call,status,false);
 if(call&&call->owner>=0){call->notified=true;call->notify_seq=v2_sequence;}
 REQUIRE("v2_dead_capacity",v2_dead_n<32);v2_dead[v2_dead_n++]=status;
}
static void v2_notification_owner_order(int owner,int status,u32 count,bool put)
{
 u32 found=0;
 for(u32 i=0;i<v2_joint_n;i++){
  struct v2_joint_event *event=&v2_joint[i];
  if(!event->put&&event->owner==owner){
   REQUIRE("v2_notification_owner_status",event->status==status&&event->token>0&&event->refs>0);
   struct v2_invocation *call=&v2_invocations[event->token-1];
   REQUIRE("v2_notification_owner_token",call->token==event->token&&call->owner==owner&&call->notified&&call->notify_seq==event->sequence);
   REQUIRE("v2_notification_individual_put",call->put==put&&(!put||call->put_seq>call->notify_seq));found++;
  }
 }
 REQUIRE("v2_notification_owner_count",found==count);
}
static void v2_notification_pair_order(bool outer_error)
{
 u32 found=0,previous=0,previous_token=0;
 if(outer_error)REQUIRE("v2_notification_outer_identity",v2_joint_n&&v2_joint[0].token==0&&v2_joint[0].owner==-1&&!v2_joint[0].put&&v2_joint[0].status==-EIO);
 for(u32 i=0;i<v2_joint_n;i++){
  struct v2_joint_event *event=&v2_joint[i];
  if(!event->put&&event->owner>=0){
   REQUIRE("v2_notification_pair_owner_order",found<2&&event->owner==(int)found&&event->sequence>previous&&event->token!=previous_token);
   if(outer_error)REQUIRE("v2_notification_outer_precedes_control",event->sequence>v2_joint[0].sequence);
   previous=event->sequence;previous_token=event->token;found++;
  }
 }
 REQUIRE("v2_notification_pair_complete",found==2);
}
static void snapshot(const char *);
static unsigned long long hash_bytes(const void *,size_t);
static void v2_reset_facts(void)
{
 v2_mixed_ordinary=v2_mixed_reliable=false;v2_cas_count=0;
 v2_watch=NULL;v2_owner=-1;memset(v2_refs,0,sizeof(v2_refs));memset(v2_puts,0,sizeof(v2_puts));v2_dead_n=0;
 v2_depth=v2_invocation_n=v2_joint_n=v2_sequence=0;
 v2_packet_ok=v2_preserved=false;v2_last_ret=0;
 v2_ret_null=v2_prefinish=false;memcpy(v2_input_backing,public_chunks,sizeof(public_chunks));
 v2_hidden_id=NULL;
 memset(v2_words,XDEV_EXT_MECH_F_K_FREE,sizeof(v2_words));
 pool.state=v2_words;pool.vaddr=public_chunks;pool.size=sizeof(public_chunks);
 umem.addrs=public_chunks;
 session.layout=(struct xdev_ext_mech_layout){4096,64,16,48};
 memset(&session.peer,0,sizeof(session.peer));
 memcpy(session.peer.peer_mac,packet_prefix,6);memcpy(session.peer.local_mac,packet_prefix+6,6);
 memcpy(&session.peer.local_ip,packet_prefix+26,4);memcpy(&session.peer.peer_ip,packet_prefix+30,4);
 memcpy(&session.peer.local_port,packet_prefix+34,2);memcpy(&session.peer.peer_port,packet_prefix+36,2);
 xst.mtu=108;
}
static void v2_prepare_rel(struct xsk_mech_reliable *r,u32 frames)
{
 memset(r,0,sizeof(*r));
 v2_watch=r;
 struct xdev_ext_rel_cfg cfg={.session=9,.first_group=77,.timeout_ns=10,.window=2,.max_attempts=4,.group_bytes=16*frames,.seg_len=16};
 REQUIRE("v2_tx_init",!xdev_ext_rel_tx_init(&r->tx,&cfg));
 REQUIRE("v2_rx_init",!xdev_ext_rel_rx_init(&r->rx,&cfg));
 session.layout=(struct xdev_ext_mech_layout){4096,128,16,16*frames};
 struct xsk_xdev_ext_mech_sock_facts facts={.bound=true,.zero_copy=true,.pool_users=1,.umem_users=1,.chunk_size=4096,.chunks=64};
 REQUIRE("v2_layout_admit",!xsk_xdev_ext_mech_pool_admit(&facts,&session.layout));
 REQUIRE("v2_layout_frames",xdev_ext_mech_layout_frames(&session.layout)==(int)frames);
 rel_now=100;
}
static void v2_reserve_control(struct xsk_mech_reliable *r,u32 j)
{
 REQUIRE("v2_control_index",j<2);
 struct xsk_rel_control *c=&r->control[j];
 c->frame.index=63-j;
 REQUIRE("v2_reservation_resolve",!xsk_xdev_ext_mech_pool_resolve(&pool,&c->frame));
 REQUIRE("v2_reservation_cas",!xdev_ext_mech_pool_frame_move(&pool,c->frame.index,XDEV_EXT_MECH_F_K_FREE,XDEV_EXT_MECH_F_HELD));
 c->frame.data_off=128;c->frame.data_len=0;c->tb.reliable_stage=&st;c->tb.control=true;
}
static struct xdp_desc v2_control_desc(u32 j)
{
 REQUIRE("v2_control_descriptor_index",j<2);
 return (struct xdp_desc){j?253974:258070,106,0};
}
static int v2_enqueue(struct xsk_xdev_ext_mech_tx_batch *t,const struct xdp_desc *d,u32 n)
{
 unsigned long flags;spin_lock_irqsave(&p.tx_lock,flags);
 int result=xsk_rel_enqueue(&st,t,d,n);
 spin_unlock_irqrestore(&p.tx_lock,flags);v2_last_ret=result;v2_ret_null=false;return result;
}
static int v2_helper(struct xsk_xdev_ext_mech_tx_batch *t,const struct xdp_desc *d,u32 n)
{
 unsigned long flags;spin_lock_irqsave(&p.tx_lock,flags);
 int result=xsk_rel_control_acquire_locked(&st,t,d,n);
 spin_unlock_irqrestore(&p.tx_lock,flags);v2_last_ret=result;v2_ret_null=false;return result;
}
static u32 v2_public_peek(u32 n){u32 result=xsk_tx_peek_release_desc_batch(&xp,n);v2_last_ret=result;v2_ret_null=false;return result;}
static void v2_public_complete(u32 n){xsk_tx_completed(&xp,n);v2_ret_null=true;}
static void v2_public_cancel(u32 n,int result){xsk_tx_cancel_tail(&xp,n,result);v2_ret_null=true;}
static void v2_public_set(u32 n,int result){xsk_tx_set_tail_result(&xp,n,result);v2_ret_null=true;}
static void v2_stop(int result){xsk_mech_zc_stop(&p,result);v2_ret_null=true;}
static void v2_pool_dead(void){xsk_xdev_ext_mech_pool_dead(&xp);v2_ret_null=true;}
static void v2_semantic_open(void)
{
 const char *path=getenv("COUNT_CONTROL_V2_SEMANTIC_OUT");
 REQUIRE("v2_semantic_path",path&&*path);
 v2_semantic_file=fopen(path,"wb");REQUIRE("v2_semantic_open",v2_semantic_file!=NULL);v2_semantic_rows=0;
}
static void v2_semantic(const char *id)
{
 REQUIRE("v2_semantic_bounded",v2_semantic_file&&id&&v2_watch&&++v2_semantic_rows<=128);
 FILE *f=v2_semantic_file;u32 tries=0,success=0,returns=0;
 REQUIRE("v2_semantic_no_live_invocation",!v2_depth);
 if(!strcmp(id,"C08/stopped"))v2_notification_owner_order(0,-ENXIO,1,true);
 if(!strcmp(id,"C29/single"))v2_notification_owner_order(0,-EAGAIN,1,false);
 if(!strcmp(id,"C29/companion")){v2_notification_owner_order(0,-EAGAIN,1,false);v2_notification_owner_order(1,-ENXIO,1,true);v2_notification_pair_order(true);}
 if(!strcmp(id,"C31/stopped")){v2_notification_owner_order(0,-ENXIO,1,false);v2_notification_owner_order(1,-ENXIO,1,true);v2_notification_pair_order(false);}
 for(u32 i=0;i<v2_cas_count;i++){
  struct v2_cas_record *o=&v2_cas[i];
  if(o->from==XDEV_EXT_MECH_F_HELD&&o->to==XDEV_EXT_MECH_F_INFLIGHT){tries++;if(!o->result)success++;}
  if(o->from==XDEV_EXT_MECH_F_INFLIGHT&&o->to==XDEV_EXT_MECH_F_HELD&&!o->result)returns++;
 }
 if(v2_mixed_ordinary||v2_mixed_reliable){
  const void *expected;
  if(v2_prefinish)expected=v2_input_backing;
  else if(v2_mixed_reliable)expected=count_control_v2_reliable_expected_backing;
  else expected=count_control_v2_ordinary_expected_backing;
  v2_packet_ok=!memcmp(public_chunks,expected,sizeof(public_chunks));
 }else v2_packet_ok=!memcmp(public_chunks,v2_input_backing,sizeof(public_chunks));
 REQUIRE("v2_semantic_full_backing",v2_packet_ok);
 fprintf(f,"{\"id\":\"%s\",\"ret\":",id);
 if(v2_ret_null)fputs("null",f);else fprintf(f,"%d",v2_last_ret);
 fprintf(f,",\"preserved\":%d,\"packet_ok\":%u,\"ring\":[%u,%u,%u,%u,%d,%u],\"state\":[%u,%u],\"busy\":[%u,%u],\"uncertain\":[%u,%u],\"meta\":[",v2_preserved?1:-1,v2_packet_ok,p.ring.prod,p.ring.issued,p.ring.cons,p.ring.native_count,p.ring.fatal,p.stopped,xdev_ext_mech_pool_frame_state(&pool,63),xdev_ext_mech_pool_frame_state(&pool,62),v2_watch->control[0].busy,v2_watch->control[1].busy,v2_watch->control[0].uncertain,v2_watch->control[1].uncertain);
 for(u32 j=0;j<2;j++){
  struct xdev_ext_net_lease *l=&v2_watch->control[j].tb.pool_lease[0];
  fprintf(f,"%s[%u,%u,%llu,%u,%u,%u]",j?",":"",l->kind,l->u.pool.owner==&p?1:l->u.pool.owner?2:0,(unsigned long long)l->u.pool.umem_addr,l->u.pool.frame_index,l->u.pool.frame_off,l->u.pool.len);
 }
 fprintf(f,"],\"refs\":[%d,%d],\"completion\":[",v2_refs[0],v2_refs[1]);
 for(u32 j=0;j<2;j++){
  struct xsk_xdev_ext_mech_tx_batch *t=&v2_watch->control[j].tb;int slot_result=0;
  for(u32 k=0;k<64;k++)if(public_slots[k].batch==t)slot_result=public_slots[k].result;
  fprintf(f,"%s[%u,%d,%u,%d,%u,%d,%d]",j?",":"",t->completion.pending,t->completion.status,t->completion.uncertain,t->native_error,t->cancelled_before_native,t->err[0],slot_result);
 }
 fprintf(f,"],\"cas_try\":%u,\"cas_ok\":%u,\"return_ok\":%u,\"puts\":[%d,%d],\"dev\":[",tries,success,returns,v2_puts[0],v2_puts[1]);
 for(int i=0;i<sync_dev_n;i++){fprintf(f,"%s[%llu,%zu,%d]",i?",":"",(unsigned long long)sync_addr[i],sync_len[i],sync_epoch[i]);}
 fputs("],\"cpu\":[",f);
 for(int i=0;i<sync_cpu_n;i++){fprintf(f,"%s[%llu,%zu,%d]",i?",":"",(unsigned long long)cpu_sync_addr[i],cpu_sync_len[i],cpu_sync_epoch[i]);}
 fprintf(f,"],\"ops\":%d,\"payload_bytes\":%d,\"dead\":[",count_ops,count_bytes);
 for(u32 i=0;i<v2_dead_n;i++){fprintf(f,"%s%d",i?",":"",v2_dead[i]);}
 fputs("]}\n",f);REQUIRE("v2_semantic_write",!ferror(f)&&ftell(f)>=0&&ftell(f)<=262144);
 v2_preserved=false;
}
static void v2_semantic_close(void)
{
 REQUIRE("v2_semantic_close",v2_semantic_file&&fclose(v2_semantic_file)==0);v2_semantic_file=NULL;
}
static void v2_snapshot_semantic(const char *event)
{
 const char *id=NULL;
 if(!strcmp(case_name,"control_enqueue"))id="C01/complete";
 else if(!strcmp(case_name,"control_enqueue_count32"))id="C02/refused";
 else if(v2_hidden_id)id=v2_hidden_id;
 else if(!strcmp(case_name,"public_three_native_plus_pending")){
  if(!strcmp(event,"peek3pending1"))id="C06/peek3pending1";
  else if(!strcmp(event,"tail"))id="C06/tail";
  else if(!strcmp(event,"head2"))id="C06/head2";
  else if(!strcmp(event,"control"))id="C06/control";
 }else if(!strcmp(case_name,"public_physical_wrap_interleave")){
  if(!strcmp(event,"wrapped3"))id="C07/wrapped3";
  else if(!strcmp(event,"across_hole"))id="C07/across_hole";
  else if(!strcmp(event,"done"))id="C07/done";
 }else if(!strcmp(case_name,"public_mixed_batches_stop")){
  if(!strcmp(event,"before_stop"))id="C08/before_stop";
  else if(!strcmp(event,"stopped"))id="C08/stopped";
 }
 if(id)v2_semantic(id);
}
static void v2_metadata(struct xsk_rel_control *c,u32 j)
{
 const struct xdev_ext_net_lease *l=&c->tb.pool_lease[0];
 REQUIRE("v2_exact_metadata",l->kind==XDEV_EXT_NET_LEASE_POOL_DMA&&l->u.pool.owner==&p&&l->u.pool.frame_index==63-j&&l->u.pool.umem_addr==(j?253952:258048)&&l->u.pool.frame_off==22&&l->u.pool.len==106);
 REQUIRE("v2_publication_custody",c->busy&&!c->uncertain&&pool.state[63-j]==XDEV_EXT_MECH_F_INFLIGHT);
 REQUIRE("v2_control_no_data",!count_ops&&!count_bytes);
}
/* Checks every backing byte against independently frozen literal arrays. */
static void v2_mixed_bytes(bool reliable)
{
 const unsigned char (*expected)[4096]=reliable?count_control_v2_reliable_expected_backing:count_control_v2_ordinary_expected_backing;
 REQUIRE("v2_full_mixed_bytes",!memcmp(public_chunks,expected,sizeof(public_chunks)));
 REQUIRE("v2_mixed_fnv",hash_bytes(public_chunks,sizeof(public_chunks))==(reliable?count_control_v2_reliable_expected_fnv:count_control_v2_ordinary_expected_fnv));
 v2_packet_ok=true;
}
static void v2_mixed_input(struct xsk_mech_reliable *r,bool reliable)
{
 v2_prepare_rel(r,reliable?2:3);
 /* Ordinary submit must still select its original dispatch branch. */
 xst.rel=reliable?r:NULL;v2_mixed_ordinary=!reliable;v2_mixed_reliable=reliable;
 batch.nr_frames=xst.tx_n=reliable?2:3;
 struct xdp_desc proposed[3];const u8 *chunks_in[3];
 for(u32 i=0;i<batch.nr_frames;i++){
  u32 off,len;REQUIRE("v2_actual_layout_span",!xdev_ext_mech_layout_span(&session.layout,i,&off,&len)&&off==128&&len==16);
  for(u32 k=64;k<80;k++)REQUIRE("v2_saved_payload_seed",public_chunks[i][k]==0x31+i);
  memcpy(public_chunks[i],reliable?count_control_v2_reliable_input_frames[i]:count_control_v2_ordinary_input_frames[i],4096);
  batch.f[i]=(struct xdev_ext_mech_frame){.kaddr=public_chunks[i],.umem_addr=(u64)i*4096,.index=i,.data_off=off,.data_len=len,.pool_priv=&public_heads[i]};
  xst.tx_fi[i]=(struct xdev_ext_mech_frame_info){(u64)i*4096,i,off,len};
  xst.tx_kaddr[i]=public_chunks[i];xst.tx_tag[i]=&tags[i];chunks_in[i]=public_chunks[i];
  proposed[i]=(struct xdp_desc){(u64)i*4096+(reliable?22:86),reliable?122:58,0};
 }
 struct xsk_xdev_ext_mech_tx_bounds bounds={.hdr_room=128,.mtu=108,.peer=session.peer};
 REQUIRE("v2_actual_tx_validate",!xsk_xdev_ext_mech_tx_validate((const u8 *)proposed,batch.nr_frames,xst.tx_fi,chunks_in,batch.nr_frames,&bounds,xst.tx_desc));
 REQUIRE("v2_crc_empty",(crc32c(~0U,"",0)^~0U)==0);
 REQUIRE("v2_crc_standard",(crc32c(~0U,"123456789",9)^~0U)==0xe3069283U);
 for(u32 i=0;i<batch.nr_frames;i++){
  xst.tx_pkt[i]=public_chunks[i]+(xst.tx_desc[i].addr-batch.f[i].umem_addr);
  if(reliable){
   REQUIRE("v2_actual_packet_check",!xsk_rel_packet_check(&st,&xst.tx_desc[i],&xst.tx_fi[i],public_chunks[i],77,1,0,XDEV_EXT_REL_DATA,i));
   REQUIRE("v2_independent_packet_crc",xdev_ext_rel_be(xst.tx_pkt[i]+98,4)==count_control_v2_reliable_crc32c[i]);
   xsk_xdev_ext_mech_tx_finish(xst.tx_pkt[i]);
  }
 }
 if(reliable)v2_mixed_bytes(true);
}
static void v2_control_enqueue_case(int count)
{
 v2_prepare_rel(&v2_rel,3);xst.rel=&v2_rel;v2_reserve_control(&v2_rel,0);v2_reserve_control(&v2_rel,1);
 struct xsk_rel_control *c=&v2_rel.control[0];struct xdp_desc d[32];
 for(u32 i=0;i<32;i++)d[i]=v2_control_desc(0);
 observed_provider=NULL;observed_control=c;
 if(count==32){
  case_name="control_enqueue_count32";v2_refusal(&c->tb,d,32,-EINVAL,false,false);
  REQUIRE("control_count32_preservation",!p.ring.prod&&!sync_dev_n&&!native_refs&&!c->busy&&pool.state[63]==XDEV_EXT_MECH_F_HELD);
  snapshot("refused");return;
 }
 v2_hold_ref(0);REQUIRE("reliable_enqueue",!v2_enqueue(&c->tb,d,1));v2_metadata(c,0);
 v2_semantic("publication.control0");
 REQUIRE("reliable_countdown",c->tb.completion.pending==1&&c->tb.reliable_stage==&st&&c->tb.n==1);
 REQUIRE("reliable_control_tag",p.slots[0].owner==XSK_MECH_ZC_CONTROL&&p.slots[0].state==XSK_MECH_ZC_PENDING&&p.slots[0].slot==0&&!memcmp(&p.slots[0].desc,d,sizeof(*d)));
 REQUIRE("reliable_public_peek",v2_public_peek(64)==1);v2_public_complete(1);
 REQUIRE("reliable_terminal_once",!native_refs&&!c->busy&&!callbacks&&!count_ops&&!count_bytes&&p.ring.cons==1&&pool.state[63]==XDEV_EXT_MECH_F_HELD);snapshot("complete");
}

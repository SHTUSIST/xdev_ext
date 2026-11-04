/* Every predecessor assertion and packet/TRACE literal is included verbatim. */
#define main frozen_pool_main
#include "frozen_pool_test.c"
#undef main
static struct xsk_mech_zc_slot public_slots[64];
static struct xdp_desc public_descs[64];
static struct xsk_mech_reliable *observed_rel;static struct xsk_rel_control *observed_control;
static u8 public_chunks[64][4096];static void *public_pages[64];static struct xdp_buff_xsk public_heads[64];
static void good_reset(const char *n)
{
 reset(n); observed_rel=NULL;observed_control=NULL;nested_dead=NULL;policy_calls=upstream_calls=0;policy_result=-EOPNOTSUPP;reliable_done_count=0;reliable_unknown=false;native_refs=frame_moves=build_calls=stage_kicks=0;
 memset(public_slots,0,sizeof(public_slots));memset(public_descs,0,sizeof(public_descs));
 p.slots=public_slots;p.ring.capacity=64;p.ring.native_head=p.ring.native_tail=0;p.source_first=p.source_next=32;
 xp.tx_descs=public_descs;xp.tx_descs_capacity=64;
 umem.chunks=umem.npgs=64;umem.size=64*4096;umem.pgs=public_pages;pool.pages=public_pages;pool.nr_frames=64;xp.heads_cnt=xp.dma_pages_cnt=64;xp.heads=public_heads;xp.addrs=&public_chunks[0][0];
 free(xp.dma_pages);xp.dma_pages=malloc(64*sizeof(dma_addr_t));
 for(u32 i=0;i<64;i++){public_pages[i]=public_chunks[i];xp.dma_pages[i]=0x100000+(u64)i*0x200000;}
 for(u32 i=0;i<3;i++){memcpy(public_chunks[i],chunks[i],4096);batch.f[i].kaddr=public_chunks[i];batch.f[i].pool_priv=&public_heads[i];xst.tx_pkt[i]=public_chunks[i]+22;}
 struct xdev_ext_mech_layout l={.frame_size=4096,.hdr_room=64,.seg_len=16,.group_bytes=48};
 struct xsk_xdev_ext_mech_sock_facts facts={.bound=true,.zero_copy=true,.pool_users=1,.umem_users=1,.chunk_size=4096,.chunks=64};
 REQUIRE("actual_bind_layout_admit",!xsk_xdev_ext_mech_pool_admit(&facts,&l)&&facts.chunks-p.source_first>=(u32)xdev_ext_mech_layout_frames(&l));
}
static unsigned long long hash_bytes(const void *,size_t);
static void snapshot(const char *event)
{
 printf("COUNT %s/%s present=%d stopped=%d p=%u i=%u c=%u cap=%u h=%u t=%u n=%u fatal=%d pending=%u status=%d uncertain=%d raw=%d cancel=%d callbacks=%d complete=%d dead=%d ops=%d bytes=%d cpu=%d dev=%d policy=%d upstream=%d reliable=%d events=%s\n",case_name,event,xp.xdev_ext_mech_tx!=NULL,p.stopped,p.ring.prod,p.ring.issued,p.ring.cons,p.ring.capacity,p.ring.native_head,p.ring.native_tail,p.ring.native_count,p.ring.fatal,tb.completion.pending,tb.completion.status,tb.completion.uncertain,tb.native_error,tb.cancelled_before_native,callbacks,complete_status,dead_status,count_ops,count_bytes,sync_cpu_n,sync_dev_n,policy_calls,upstream_calls,reliable_done_count,events);
 for(u32 i=0;i<64;i++)if(p.slots[i].batch){
  struct xsk_xdev_ext_mech_tx_batch *t=p.slots[i].batch;struct xdev_ext_net_lease *l=&t->pool_lease[p.slots[i].slot];
  printf("S %u d=%llu,%u,%u frame=%u state=%u tag=%u result=%d prev=%u next=%u owner_batch=%llu control=%d pending=%u status=%d uncertain=%d raw=%d cancel=%d lease=%d err=%d",i,(unsigned long long)p.slots[i].desc.addr,p.slots[i].desc.len,p.slots[i].desc.options,p.slots[i].slot,p.slots[i].state,p.slots[i].owner,p.slots[i].result,p.slots[i].native_prev,p.slots[i].native_next,t->batch?(unsigned long long)t->batch->id:0,t->control,t->completion.pending,t->completion.status,t->completion.uncertain,t->native_error,t->cancelled_before_native,l->kind,t->err[p.slots[i].slot]);
  printf(" pool_owner=%d umem=%llu index=%u off=%u len=%u",l->u.pool.owner==&p?1:l->u.pool.owner?2:0,(unsigned long long)l->u.pool.umem_addr,l->u.pool.frame_index,l->u.pool.frame_off,l->u.pool.len);
  putchar('\n');
 }
 printf("BYTES %llu tags=%llu,%llu,%llu\n",hash_bytes(public_chunks,sizeof(public_chunks)),(unsigned long long)tags[0],(unsigned long long)tags[1],(unsigned long long)tags[2]);
 printf("CUSTODY refs=%d moves=%d control_busy=%d control_unknown=%d\n",native_refs,frame_moves,observed_control?observed_control->busy:0,observed_control?observed_control->uncertain:0);
 if(observed_rel){printf("REL_TX next=%llu base=%llu credit=%llu retransmits=%llu\n",(unsigned long long)observed_rel->tx.next_group,(unsigned long long)observed_rel->tx.base_group,(unsigned long long)observed_rel->tx.credit,(unsigned long long)observed_rel->tx.retransmits);for(u32 i=0;i<observed_rel->tx.cfg.window;i++){struct xdev_ext_rel_tx_entry *e=&observed_rel->tx.entry[i];printf("REL_ENTRY %u group=%llu attempt=%u deadline=%llu native=%u terminal=%u live=%u acked=%u count=%u declined=%u held=%u\n",i,(unsigned long long)e->group,e->attempt,(unsigned long long)e->deadline_ns,e->native_pending,e->terminal,e->live,e->acked,e->count,e->declined,e->held_attempt);}}
 for(int i=0;i<sync_cpu_n;i++)printf("CPU_DMA %d addr=%llu len=%zu epoch=%d dev=17 dir=0\n",i,(unsigned long long)cpu_sync_addr[i],cpu_sync_len[i],cpu_sync_epoch[i]);
 for(int i=0;i<sync_dev_n;i++)printf("DMA %d addr=%llu len=%zu epoch=%d\n",i,(unsigned long long)sync_addr[i],sync_len[i],sync_epoch[i]);
}
static void public_three_native_pending(void)
{
 good_reset("public_three_native_pending");CHECK("submit",!xsk_xdev_ext_mech_submit(&st,&batch));snapshot("submit");
 CHECK("public_three_native_pending",xsk_tx_peek_release_desc_batch(&xp,2)==2);snapshot("peek2");
 xsk_tx_cancel_tail(&xp,1,0);CHECK("public_tail_hole",p.slots[1].state==2&&p.ring.cons==0&&p.ring.native_count==1);snapshot("tail");
 xsk_tx_completed(&xp,1);CHECK("public_head_cross_hole",p.ring.cons==2&&tb.completion.pending==1&&!callbacks);snapshot("head");
 CHECK("public_single_pending",xsk_tx_peek_desc(&xp,&descs[0]));xsk_tx_completed(&xp,1);CHECK("public_done",p.ring.cons==3&&callbacks==1&&count_ops==3);snapshot("done");
}
static void nested_stop(void){nested_dead=NULL;xsk_mech_zc_stop(&p,-ENXIO);}
static void public_errors(void)
{
 const int results[]={0,-EAGAIN,-EIO,-ECANCELED,-ENXIO,-EPROTO,1};
 for(u32 j=0;j<sizeof(results)/sizeof(results[0]);j++){
  good_reset("public_raw_result");CHECK("submit",!xsk_xdev_ext_mech_submit(&st,&batch));CHECK("peek",xsk_tx_peek_release_desc_batch(&xp,64)==3);
  int r=results[j];CHECK("matched_return",xsk_xdev_ext_mech_tx_complete(&xp,3,r,false,false)==0);
  CHECK("raw_error_separate",tb.native_error==r&&tb.err[0]==(r==-EAGAIN?-EIO:r)&&tb.completion.status==(r==-EAGAIN?-EIO:r));
  CHECK("fatal_normalization",p.ring.fatal==(r==-EAGAIN||r>0?-EIO:r));snapshot("complete");
 }
 good_reset("nested_set_only");CHECK("submit",!xsk_xdev_ext_mech_submit(&st,&batch));CHECK("peek",xsk_tx_peek_release_desc_batch(&xp,2)==2);
 nested_dead=nested_stop;xsk_tx_set_tail_result(&xp,1,-EAGAIN);
 CHECK("nested_unknown",callbacks==1&&seq_callbacks==1&&tb.completion.uncertain&&tb.pool_lease[0].kind==3&&tb.pool_lease[1].kind==3&&tb.pool_lease[2].kind==0&&p.ring.native_count==0);
 CHECK("nested_error_channels",tb.native_error==-EAGAIN&&tb.completion.status==-ENXIO&&p.ring.fatal==-EIO);snapshot("reentry");
 int before=callbacks;xsk_mech_zc_stop(&p,-EPIPE);CHECK("repeat_stop_once",callbacks==before&&p.ring.fatal==-EIO);CHECK("late_count_protocol",xsk_xdev_ext_mech_tx_complete(&xp,1,0,false,false)==-EPROTO&&callbacks==before);snapshot("late");
}
static void public_fallback(void)
{
 for(int mode=0;mode<3;mode++){
  good_reset("public_fallback");struct xdp_desc d={0};if(mode==0)xp.xdev_ext_mech_tx=NULL;if(mode==2)p.stopped=true;
  CHECK("empty_peek",!xsk_tx_peek_desc(&xp,&d));CHECK("empty_batch",!xsk_tx_peek_release_desc_batch(&xp,2));
  xsk_tx_completed(&xp,0);xsk_tx_cancel_tail(&xp,0,0);xsk_tx_set_tail_result(&xp,0,0);
  CHECK("provider_fallback_separation",policy_calls==(mode==0?6:0)&&upstream_calls==(mode==0?2:0));snapshot("all");
 }
 good_reset("public_excess_no_fallback");CHECK("submit",!xsk_xdev_ext_mech_submit(&st,&batch));CHECK("peek",xsk_tx_peek_release_desc_batch(&xp,1)==1);
 xsk_tx_completed(&xp,UINT32_MAX);CHECK("excess_not_fallback",!policy_calls&&!upstream_calls&&seq_callbacks==1);snapshot("u32max");
 good_reset("public_zero_clamp");CHECK("submit",!xsk_xdev_ext_mech_submit(&st,&batch));xp.tx_descs_capacity=1;
 CHECK("batch_clamp",xsk_tx_peek_release_desc_batch(&xp,UINT32_MAX)==1&&p.ring.issued==1);CHECK("zero_count",!xsk_xdev_ext_mech_tx_complete(&xp,0,1,true,true)&&p.ring.native_count==1&&!tb.native_error&&!p.ring.fatal);snapshot("clampzero");
}
static void reliable_enqueue_cases(void)
{
 for(int control=0;control<2;control++)for(int count=1;count<=32;count+=31){
  good_reset(control?"control_enqueue":"reliable_enqueue");struct xdp_desc d[32];
  for(int i=0;i<count;i++){d[i]=(struct xdp_desc){22,58,0};}
  tb.control=control;observed_provider=NULL;
  unsigned long flags;spin_lock_irqsave(&p.tx_lock,flags);CHECK("reliable_enqueue",!xsk_rel_enqueue(&st,&tb,d,count));spin_unlock_irqrestore(&p.tx_lock,flags);
  CHECK("reliable_countdown",tb.completion.pending==(u32)count&&tb.reliable_stage==&st&&tb.n==(u32)count);
  for(int i=0;i<count;i++)CHECK("reliable_control_tag",p.slots[i].owner==control&&p.slots[i].state==0&&p.slots[i].slot==(u32)i&&!memcmp(&p.slots[i].desc,&d[i],sizeof(d[i])));
  CHECK("reliable_public_peek",xsk_tx_peek_release_desc_batch(&xp,64)==(u32)count);xsk_tx_completed(&xp,count);
  CHECK("reliable_terminal_once",reliable_done_count==1&&!callbacks&&!count_ops&&p.ring.cons==(u32)count);snapshot("complete");
 }
}
static void reliable_real_callers(void)
{
 good_reset("actual_reliable_initial_resend");struct xsk_mech_reliable rel={0};
 struct xdev_ext_rel_cfg cfg={.session=9,.first_group=77,.timeout_ns=10,.window=2,.max_attempts=4,.group_bytes=48,.seg_len=16};
 CHECK("reliable_cfg",!xdev_ext_rel_tx_init(&rel.tx,&cfg));xst.rel=&rel;observed_rel=&rel;observed_provider=NULL;rel_now=100;build_calls=stage_kicks=0;
 CHECK("actual_initial_submit",!xsk_xdev_ext_mech_submit(&st,&batch));
 CHECK("actual_initial_authority",rel.data[1].batch==&batch&&rel.tx.entry[1].attempt==1&&rel.tx.entry[1].native_pending&&tb.attempt==1&&p.ring.prod==3);snapshot("initial");
 CHECK("actual_initial_public",xsk_tx_peek_release_desc_batch(&xp,64)==3);xsk_tx_completed(&xp,3);
 CHECK("actual_native_done",!rel.tx.entry[1].native_pending&&rel.tx.entry[1].deadline_ns==110&&sync_cpu_n==3&&!callbacks);snapshot("initial_done");
 for(int i=0;i<3;i++){rel.scratch[i]=xst.tx_desc[i];}
 rel_now=110;bool wake=false;
 CHECK("actual_resend",!xsk_rel_resend(&st,1,77,110,&wake));
 CHECK("actual_resend_authority",wake&&build_calls==1&&build_group==77&&build_attempt==2&&tb.attempt==2&&rel.tx.entry[1].native_pending&&rel.tx.retransmits==1&&p.ring.prod==6);snapshot("resend");
 CHECK("actual_resend_public",xsk_tx_peek_release_desc_batch(&xp,64)==3);xsk_tx_completed(&xp,3);
 CHECK("actual_resend_done",!rel.tx.entry[1].native_pending&&sync_cpu_n==6&&!callbacks&&count_ops==6);snapshot("resend_done");
 for(int phase=0;phase<3;phase++){
  bool unknown=phase==1;
  good_reset(unknown?"actual_control_unknown":"actual_control_definite");memset(&rel,0,sizeof(rel));xst.rel=&rel;observed_provider=NULL;
  struct xsk_rel_control c={0};c.tb.control=true;c.frame=(struct xdev_ext_mech_frame){.index=0,.umem_addr=0,.data_off=128,.data_len=16};c.busy=true;observed_control=&c;
  struct xdp_desc d={22,106,0};native_refs=1;frame_moves=0;unsigned long flags;
  spin_lock_irqsave(&p.tx_lock,flags);CHECK("control_actual_enqueue",!xsk_rel_enqueue(&st,&c.tb,&d,1));spin_unlock_irqrestore(&p.tx_lock,flags);
  CHECK("control_public_peek",xsk_tx_peek_release_desc_batch(&xp,64)==1);
  if(unknown)xsk_mech_zc_stop(&p,-ENXIO);else if(phase==2)xsk_tx_cancel_tail(&xp,1,-EIO);else xsk_tx_completed(&xp,1);
  CHECK("control_custody",c.uncertain==unknown&&c.busy==unknown&&native_refs==unknown&&frame_moves==!unknown&&p.ring.native_count==0&&c.tb.completion.pending==0);CHECK("control_mapped_return",sync_cpu_n==(phase==0));snapshot("control_done");
  xsk_mech_zc_stop(&p,-ENXIO);CHECK("control_no_double_put",native_refs==unknown&&frame_moves==!unknown);
 }
}
static void public_wrap_mixed(void)
{
 good_reset("public_three_native_plus_pending");CHECK("submit",!xsk_xdev_ext_mech_submit(&st,&batch));
 struct xsk_xdev_ext_mech_tx_batch other={0};struct xdp_desc d={22,58,0};other.control=true;observed_provider=NULL;unsigned long flags;
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("shared_control_enqueue",!xsk_rel_enqueue(&st,&other,&d,1));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("three_native_pending",xsk_tx_peek_release_desc_batch(&xp,3)==3&&p.ring.prod==4&&p.ring.issued==3);snapshot("peek3pending1");
 xsk_tx_cancel_tail(&xp,1,0);CHECK("three_tail_hole",p.ring.native_count==2&&p.ring.cons==0&&p.slots[2].state==2);snapshot("tail");
 xsk_tx_completed(&xp,2);CHECK("three_head_cross_hole",p.ring.cons==3&&callbacks==1&&other.completion.pending==1);snapshot("head2");
 CHECK("pending_control_peek",xsk_tx_peek_release_desc_batch(&xp,1)==1);xsk_tx_completed(&xp,1);CHECK("pending_control_done",reliable_done_count==1&&p.ring.cons==4);snapshot("control");
 good_reset("public_physical_wrap_interleave");observed_provider=NULL;p.ring.prod=p.ring.issued=p.ring.cons=62;
 struct xsk_xdev_ext_mech_tx_batch a={0},b={.control=true};struct xdp_desc pair[2]={{22,58,0},{4118,58,0}};
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("wrap_a",!xsk_rel_enqueue(&st,&a,pair,2));CHECK("wrap_b",!xsk_rel_enqueue(&st,&b,pair,2));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("wrap_peek3",xsk_tx_peek_release_desc_batch(&xp,3)==3&&p.ring.native_head==62&&p.ring.native_tail==0&&p.slots[63].native_next==0);snapshot("wrapped3");
 xsk_tx_cancel_tail(&xp,1,0);CHECK("wrap_tail_hole",p.slots[0].state==2&&p.ring.cons==62);xsk_tx_completed(&xp,2);
 CHECK("wrap_reclaim",p.ring.cons==65&&a.completion.pending==0&&b.completion.pending==1);snapshot("across_hole");
 CHECK("wrap_last",xsk_tx_peek_release_desc_batch(&xp,1)==1);xsk_tx_completed(&xp,1);CHECK("wrap_b_done",p.ring.cons==66&&reliable_done_count==2);snapshot("done");
 good_reset("public_mixed_batches_stop");CHECK("mixed_batches_submit",!xsk_xdev_ext_mech_submit(&st,&batch));observed_provider=NULL;other=(struct xsk_xdev_ext_mech_tx_batch){.control=true};
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("mixed_batches_control",!xsk_rel_enqueue(&st,&other,&d,1));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("mixed_batches_peek",xsk_tx_peek_release_desc_batch(&xp,3)==3);xsk_tx_cancel_tail(&xp,1,0);snapshot("before_stop");xsk_mech_zc_stop(&p,-ENXIO);
 CHECK("mixed_batches_unknown",seq_callbacks==1&&callbacks==1&&reliable_done_count==1&&tb.completion.uncertain&&!other.completion.uncertain&&tb.pool_lease[0].kind==3&&tb.pool_lease[1].kind==3&&tb.pool_lease[2].kind==0&&p.ring.native_count==0&&p.ring.cons==4&&sync_cpu_n==1);snapshot("stopped");
 good_reset("public_u32_origin_translation");observed_provider=NULL;p.ring.prod=p.ring.issued=p.ring.cons=UINT32_MAX-1;a=(struct xsk_xdev_ext_mech_tx_batch){0};
 spin_lock_irqsave(&p.tx_lock,flags);CHECK("origin_reserve",!xsk_rel_enqueue(&st,&a,pair,2));spin_unlock_irqrestore(&p.tx_lock,flags);
 CHECK("origin_wrap",p.ring.prod==0&&xsk_tx_peek_release_desc_batch(&xp,2)==2);xsk_tx_completed(&xp,2);CHECK("origin_done",p.ring.cons==0&&reliable_done_count==1);snapshot("done");
}
static void valid_public_wakeup_prefix(void)
{
 for(int k=0;k<3;k++){
  const int peeks[3]={0,1,3};good_reset("public_wakeup_error");peek_on_wakeup=peeks[k];wakeup_result=-ENETDOWN;
  CHECK("public_wakeup_accept",!xsk_xdev_ext_mech_submit(&st,&batch));
  CHECK("public_wakeup_suffix",p.stopped&&p.ring.native_count==(u32)peeks[k]&&tb.completion.pending==(u32)peeks[k]&&sync_cpu_n==3-peeks[k]);snapshot("wakeup");
  if(peeks[k]){xsk_tx_completed(&xp,peeks[k]);}
  CHECK("public_wakeup_final",callbacks==1&&p.ring.native_count==0&&count_ops==peeks[k]);snapshot("done");
 }
 good_reset("public_pool_prefix");tags[1]=77;tb.pool_lease[1].kind=3;tb.pool_lease[1].u.pool.owner=(void*)0x1234;
 struct xdev_ext_net_lease saved=tb.pool_lease[1];batch.f[2].pool_priv=&public_heads[0];
 CHECK("public_prefix_refusal",xsk_xdev_ext_mech_submit(&st,&batch)==-ERANGE);
 CHECK("public_prefix_exact",p.ring.prod==0&&!p.ring.issued&&!p.ring.cons&&!sync_dev_n&&!trace_n&&!callbacks&&!memcmp(&saved,&tb.pool_lease[1],sizeof(saved))&&tb.pool_lease[0].kind==0&&tb.pool_lease[2].kind==0);
 CHECK("public_prefix_bytes",!memcmp(public_chunks[0]+22,packet_prefix,42)&&!memcmp(public_chunks[2]+22,packet_prefix,42));snapshot("refused");
}
static void ordinary_32_frames(void)
{
 good_reset("public_ordinary_32");u64 full_tags[32]={0};batch.nr_frames=xst.tx_n=32;
 struct xdev_ext_mech_layout layout={.frame_size=4096,.hdr_room=64,.seg_len=16,.group_bytes=512};
 struct xsk_xdev_ext_mech_sock_facts facts={.bound=true,.zero_copy=true,.pool_users=1,.umem_users=1,.chunk_size=4096,.chunks=64};
 CHECK("boundary32_layout",!xsk_xdev_ext_mech_pool_admit(&facts,&layout)&&xdev_ext_mech_layout_frames(&layout)==32&&64-p.source_first>=32);
 for(u32 i=0;i<32;i++){
  memset(public_chunks[i],0x31+i,4096);memcpy(public_chunks[i]+22,packet_prefix,42);
  batch.f[i]=(struct xdev_ext_mech_frame){.kaddr=public_chunks[i],.umem_addr=(u64)i*4096,.index=i,.data_off=64,.data_len=16,.pool_priv=&public_heads[i]};
  xst.tx_desc[i]=(struct xdp_desc){(u64)i*4096+22,58,0};xst.tx_pkt[i]=public_chunks[i]+22;xst.tx_tag[i]=&full_tags[i];
 }
 CHECK("ordinary32_submit",!xsk_xdev_ext_mech_submit(&st,&batch));CHECK("ordinary32_full_prepare",tb.completion.pending==32&&p.ring.prod==32&&sync_dev_n==32&&trace_n==32);
 for(u32 i=0;i<32;i++)CHECK("ordinary32_authority",tb.pool_lease[i].kind==3&&tb.pool_lease[i].u.pool.frame_index==i&&full_tags[i]==77&&p.slots[i].slot==i&&!memcmp(public_chunks[i]+22,finished_prefix,42));
 snapshot("submit");
 CHECK("ordinary32_peek",xsk_tx_peek_release_desc_batch(&xp,64)==32);xsk_tx_completed(&xp,32);
 CHECK("ordinary32_complete",callbacks==1&&count_ops==32&&count_bytes==512&&p.ring.cons==32&&!tb.completion.pending);snapshot("done");
}
struct pure_state {struct xsk_mech_zc_ring r;struct xsk_mech_zc_slot s[8];struct xsk_mech_zc_batch b;s32 err[8];int native_error;bool cancelled;};
static unsigned long long hash_bytes(const void *v,size_t n){const unsigned char*p=v;unsigned long long h=1469598103934665603ULL;while(n--){h^=*p++;h*=1099511628211ULL;}return h;}
static unsigned long long pure_digest(const struct pure_state *q)
{
 unsigned long long h=1469598103934665603ULL;
 #define MIX(x) do{unsigned long long v=(unsigned long long)(x);h^=v;h*=1099511628211ULL;}while(0)
 MIX(q->r.prod);MIX(q->r.issued);MIX(q->r.cons);MIX(q->r.capacity);MIX(q->r.native_head);MIX(q->r.native_tail);MIX(q->r.native_count);MIX(q->r.fatal);MIX(q->b.pending);MIX(q->b.status);MIX(q->b.uncertain);MIX(q->native_error);MIX(q->cancelled);for(u32 i=0;i<8;i++){MIX(q->err[i]);}
 for(u32 i=0;i<q->r.capacity;i++){MIX(q->s[i].desc.addr);MIX(q->s[i].desc.len);MIX(q->s[i].desc.options);MIX(q->s[i].slot);MIX(q->s[i].result);MIX(q->s[i].native_prev);MIX(q->s[i].native_next);MIX(q->s[i].state);MIX(q->s[i].owner);}
 #undef MIX
 return h;
}
static void pure_check(struct pure_state *q)
{
 u32 n=0,at=q->r.native_head,prev=XSK_MECH_ZC_NONE;
 for(u32 i=0;i<q->r.capacity;i++)if(q->s[i].state==1)n++;
 REQUIRE("pure_native_state_count",n==q->r.native_count);
 for(u32 i=0;i<n;i++){REQUIRE("pure_fifo_link",at<q->r.capacity&&q->s[at].state==1&&q->s[at].native_prev==prev);prev=at;at=q->s[at].native_next;}
 REQUIRE("pure_fifo_end",!n||at==XSK_MECH_ZC_NONE);REQUIRE("pure_fifo_tail",!n||prev==q->r.native_tail);
 REQUIRE("pure_cursor_bound",q->r.prod-q->r.cons<=q->r.capacity&&q->r.issued-q->r.cons<=q->r.prod-q->r.cons);
}
static void pure_event(struct pure_state*q,u32 action)
{
 struct xsk_mech_zc_slot previous[8];memcpy(previous,q->s,sizeof(previous));u32 start=0xdeadbeef;int at;
 switch(action%18){
 case 0:case 1:case 2:case 14:case 15:case 16:{u32 op=action%18;u32 free_slots=q->r.capacity-(q->r.prod-q->r.cons);u32 n=op==14?free_slots:op==15?free_slots+1:op==16?q->r.capacity:op;u32 before=q->r.prod;int ret=xsk_mech_zc_reserve(&q->r,n,&start);if(!ret){REQUIRE("pure_reserve_success_cursors",start==before&&q->r.prod==before+n);for(u32 j=0;j<n;j++)q->s[(start+j)&(q->r.capacity-1)]=(struct xsk_mech_zc_slot){.desc={0x123400+j,58,0},.slot=j,.owner=j&1};q->b.pending+=n;}else REQUIRE("pure_refusal_unchanged",q->r.prod==before&&start==0xdeadbeef);break;}
 case 3:xsk_mech_zc_peek(&q->r,q->s);break;
 case 4:case 5:at=action%18==4?xsk_mech_zc_complete(&q->r,q->s):xsk_mech_zc_tail(&q->r,q->s,0);if(at>=0){xsk_mech_zc_mark_done(&q->r,q->s,at);xsk_mech_zc_retire_result(&q->b,q->s[at].result,&q->err[at]);}break;
 case 6:case 7:at=xsk_mech_zc_tail(&q->r,q->s,0);if(at>=0){int result=action%18==6?-EAGAIN:-EPIPE;if(!q->native_error)q->native_error=result;xsk_mech_zc_set_result(&q->r,q->s,at,result);}break;
 case 8:xsk_mech_zc_reclaim(&q->r,q->s);break;
 case 9:q->cancelled=true;for(u32 i=q->r.issued;i!=q->r.prod;i++){q->s[i&(q->r.capacity-1)].state=2;xsk_mech_zc_retire_result(&q->b,-ECANCELED,&q->err[i&(q->r.capacity-1)]);}q->r.issued=q->r.prod;xsk_mech_zc_reclaim(&q->r,q->s);break;
 case 10:xsk_mech_zc_fail(&q->r,1);break;
 case 11:at=xsk_mech_zc_tail(&q->r,q->s,q->r.native_count);REQUIRE("pure_tail_bounds",at==-ENOENT);break;
 case 12:xsk_mech_zc_fail(&q->r,-ENXIO);q->b.uncertain|=q->r.native_count!=0;while((at=xsk_mech_zc_complete(&q->r,q->s))>=0){xsk_mech_zc_mark_done(&q->r,q->s,at);xsk_mech_zc_retire_result(&q->b,-ENXIO,&q->err[at]);}for(u32 i=q->r.issued;i!=q->r.prod;i++){q->s[i&(q->r.capacity-1)].state=2;xsk_mech_zc_retire_result(&q->b,-ENXIO,&q->err[i&(q->r.capacity-1)]);}q->r.cons=q->r.issued=q->r.prod;break;
 case 17:at=xsk_mech_zc_tail(&q->r,q->s,0);if(at>=0)xsk_mech_zc_set_result(&q->r,q->s,at,0);break;
 case 13:{u32 before=q->r.prod;int ret=xsk_mech_zc_reserve(&q->r,1,&start);if(!ret)q->r.prod=start;REQUIRE("pure_rollback_prod_only",q->r.prod==before);break;}
 }
 if(action%18>2&&(action%18<14||action%18>16)){for(u32 i=0;i<q->r.capacity;i++){REQUIRE("pure_payload_untouched",!memcmp(&q->s[i].desc,&previous[i].desc,sizeof(q->s[i].desc))&&q->s[i].batch==previous[i].batch&&q->s[i].slot==previous[i].slot&&q->s[i].owner==previous[i].owner);}}
 pure_check(q);
}
static void pure_literal_edges(void)
{
 case_name="pure_literal_edges";struct xsk_mech_zc_ring r={.capacity=4};struct xsk_mech_zc_slot a[4]={0};u32 start=0x1234;
 CHECK("reserve_zero_no_write",xsk_mech_zc_reserve(&r,0,&start)==-EAGAIN&&start==0x1234&&!r.prod);
 CHECK("reserve_excess_no_write",xsk_mech_zc_reserve(&r,5,&start)==-EAGAIN&&start==0x1234&&!r.prod);
 CHECK("reserve_exact",!xsk_mech_zc_reserve(&r,4,&start)&&!start&&r.prod==4);
 start=0x1234;CHECK("reserve_full_retry",xsk_mech_zc_reserve(&r,1,&start)==-EAGAIN&&start==0x1234&&!r.fatal);
 r.fatal=-EPIPE;CHECK("reserve_fatal_priority",xsk_mech_zc_reserve(&r,0,&start)==-EPIPE&&start==0x1234);r.fatal=0;
 struct xsk_mech_zc_slot before=a[0];xsk_mech_zc_set_result(&r,a,0,-EIO);xsk_mech_zc_mark_done(&r,a,0);CHECK("pending_metadata_noop",!memcmp(&before,&a[0],sizeof(before))&&!r.fatal&&!r.native_count);
 struct xsk_mech_zc_batch b={0};s32 out=123;CHECK("empty_countdown_no_write",!xsk_mech_zc_retire_result(&b,-EIO,&out)&&out==123&&!b.status);b.pending=2;b.uncertain=true;
 CHECK("countdown_first",!xsk_mech_zc_retire_result(&b,-EAGAIN,&out)&&b.pending==1&&b.status==-EIO&&out==-EIO&&b.uncertain);
 CHECK("countdown_last",xsk_mech_zc_retire_result(&b,-EPIPE,&out)&&!b.pending&&b.status==-EIO&&out==-EPIPE&&b.uncertain);
#if HAVE_COUNT
 CHECK("overlay_offsets",offsetof(struct xsk_mech_zc_slot,count.result)==offsetof(struct xsk_mech_zc_slot,result)&&offsetof(struct xsk_mech_zc_slot,count.tag)==offsetof(struct xsk_mech_zc_slot,owner));
 struct xdev_ext_net_count_view v=xsk_mech_zc_view(a);CHECK("view_stride",v.first==&a[0].count&&v.stride==sizeof(a[0])&&xdev_ext_net_count_entry(v,3)==&a[3].count);
 r=(struct xsk_mech_zc_ring){.capacity=4,.prod=3,.issued=1,.cons=0};xdev_ext_net_count_rollback(&r,2);CHECK("rollback_issued_unchanged",r.prod==2&&r.issued==1&&r.cons==0);
#endif
}
static u32 replay_mode,replay_cap,replay_seed,replay_step,replay_parent,replay_action;
static void dump_replay(void);
static void pure_sequences(void)
{
 const u32 seeds[8]={1,7,17,101,2026,0x12345678,0xc0ffee,0xdeadbeef};
 for(u32 c=1;c<=8;c*=2)for(int seed=0;seed<8;seed++){
  struct pure_state q={0};q.r.capacity=c;u32 rng=seeds[seed];case_name="pure_seed";
  replay_mode=1;replay_cap=c;replay_seed=seeds[seed];assert_context=dump_replay;
  for(int i=0;i<256;i++){replay_step=i;rng=rng*1664525u+1013904223u;pure_event(&q,rng>>16);}
  printf("PURE cap=%u seed=%u steps=256 digest=%llu\n",c,seeds[seed],pure_digest(&q));assert_context=NULL;
 }
}
#define STATE_BOUND 100000u
#define HASH_BOUND 262144u
struct explored {struct pure_state q;u32 parent;u8 action,depth;};
static struct explored *explored;
static u32 *visited,total_states;
static void dump_replay(void)
{
 if(replay_mode==1){fprintf(stderr,"REPLAY pure capacity=%u seed=%u failing_step=%u generator=1664525*x+1013904223 action=(x>>16)%%18\n",replay_cap,replay_seed,replay_step);return;}
 u32 actions[16],n=0,at=replay_parent;while(at!=UINT32_MAX&&explored[at].parent!=UINT32_MAX&&n<15){actions[n++]=explored[at].action;at=explored[at].parent;}
 fprintf(stderr,"REPLAY bfs capacity=%u actions=",replay_cap);while(n)fprintf(stderr,"%u,",actions[--n]);fprintf(stderr,"%u\n",replay_action);
}
static bool pure_equal(const struct pure_state *a,const struct pure_state *b)
{
 if(memcmp(&a->r,&b->r,sizeof(a->r))||a->b.pending!=b->b.pending||a->b.status!=b->b.status||a->b.uncertain!=b->b.uncertain||a->native_error!=b->native_error||a->cancelled!=b->cancelled||memcmp(a->err,b->err,sizeof(a->err)))return false;
 for(u32 i=0;i<a->r.capacity;i++){const struct xsk_mech_zc_slot *x=&a->s[i],*y=&b->s[i];if(x->desc.addr!=y->desc.addr||x->desc.len!=y->desc.len||x->desc.options!=y->desc.options||x->slot!=y->slot||x->result!=y->result||x->native_prev!=y->native_prev||x->native_next!=y->native_next||x->state!=y->state||x->owner!=y->owner)return false;}
 return true;
}
static void pure_explore(void)
{
 explored=calloc(STATE_BOUND,sizeof(*explored));visited=calloc(HASH_BOUND,sizeof(*visited));REQUIRE("exploration_memory",explored&&visited);u32 cursor=0;bool hit=false;
 for(u32 cap=1;cap<=8;cap*=2){
  u32 begin=total_states;struct pure_state init={0};init.r.capacity=cap;u32 bucket=pure_digest(&init)&(HASH_BOUND-1);while(visited[bucket])bucket=(bucket+1)&(HASH_BOUND-1);
  REQUIRE("initial_state_bound",total_states<STATE_BOUND);explored[total_states]=(struct explored){.q=init,.parent=UINT32_MAX};visited[bucket]=++total_states;cursor=begin;u32 depth=cap<=2?8:4;unsigned long long digest=0;
  while(cursor<total_states){
   struct explored *cur=&explored[cursor];if(cur->depth>=depth){cursor++;continue;}
   for(u32 action=0;action<18;action++){
    struct pure_state next=cur->q;case_name="pure_bfs";replay_mode=2;replay_cap=cap;replay_parent=cursor;replay_action=action;assert_context=dump_replay;pure_event(&next,action);assert_context=NULL;u32 b=pure_digest(&next)&(HASH_BOUND-1);bool found=false;
    while(visited[b]){if(pure_equal(&explored[visited[b]-1].q,&next)){found=true;break;}b=(b+1)&(HASH_BOUND-1);}
    if(found)continue;
    if(total_states==STATE_BOUND){hit=true;break;}
    explored[total_states]=(struct explored){.q=next,.parent=cursor,.action=action,.depth=cur->depth+1};visited[b]=++total_states;digest^=pure_digest(&next);
   }
   cursor++;if(hit)break;
  }
  printf("EXPLORE capacity=%u depth=%u unique=%u total=%u bound=%u hit=%d digest=%llu\n",cap,depth,total_states-begin,total_states,STATE_BOUND,hit,digest);if(hit)break;
 }
 free(explored);free(visited);
}
int main(int argc,char **argv)
{
 fail_fast=getenv("COUNT_FAIL_FAST")!=NULL;
 int result=frozen_pool_main(argc,argv);if(result||argc>1)return result;
 public_three_native_pending();public_errors();public_fallback();reliable_enqueue_cases();reliable_real_callers();public_wrap_mixed();valid_public_wakeup_prefix();ordinary_32_frames();pure_literal_edges();pure_sequences();pure_explore();
 printf("COUNT_RESULT failures=%d\n",failures);return failures?1:0;
}

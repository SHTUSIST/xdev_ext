/* SPDX-License-Identifier: GPL-2.0 */
/* Literal oracles from the stated traces; production helpers never compute
 * an expected result. Boundary counters observe effects of actual class code. */
static unsigned tap_number;
static void ok(const char *name) { printf("ok %u - %s\n",++tap_number,name); }
static void done_success(struct side *side,unsigned batch,u64 group) {
 assert(side->batches[batch].publishes==1&&side->batches[batch].status==0&&!side->batches[batch].sequester);
 assert(side->cqe[batch].status==0&&side->cqe[batch].group==group);
}
static void announced(void) { pair(0,2,8192);assert(!submit(&sides[0],0));drain_worker(4);assert(wire_count(&sides[0],XDEV_EXT_XD_RTS)==1&&!total_posts()); }
static void posted(void) { pair(0,2,8192);assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(12);assert(sides[0].posts==1&&sides[1].posts==1&&!total_published()); }
static void local_success(void) { posted();complete_group(&sides[1],0,0,true);complete_group(&sides[0],0,0,true);drain_worker(8);assert(sides[1].batches[0].publishes==1&&!sides[0].batches[0].publishes); }
static void inject_message(struct side *receiver,unsigned type,u64 group,u64 credit,unsigned status) {
 struct side *sender=other(receiver);
 struct xdev_ext_xd_msg msg={.type=type,.stream=receiver->session.id,.group=group,.credit=credit,.status=status};
 assert(!xdev_ext_xd_msg_send(&sender->link,NULL,0,&msg));deliver_wire_once(sender);
}
static void check_admission_record(struct side *side,int expected_error,unsigned expected_mapped) {
 unsigned stage,reachability,backing,refused,mapped;int error,distance,consumed=0;
 unsigned long long session;char bdf[32];
 int fields=sscanf(side->diagnostic,"XDEV_EXT_XDOMAIN_ADMIT session=%llu stage=%u requester=%31s errno=%d reachability=%u distance=%d backing=0x%x refused=0x%x mapped=%u\n%n",
  &session,&stage,bdf,&error,&reachability,&distance,&backing,&refused,&mapped,&consumed);
 assert(fields==9&&side->diagnostic[consumed]=='\0');
 assert(session==side->session.id&&stage==stage_of(side)->index&&!strcmp(bdf,"0000:06:00.0"));
 assert(error==expected_error&&mapped==expected_mapped&&backing==XDEV_EXT_PEER_BACKING_MMIO_BAR);
 assert(reachability==(expected_error?XDEV_EXT_CAP_TOPOLOGY_FAILED:XDEV_EXT_CAP_TOPOLOGY_PASSED));
 assert(distance==(expected_error?-1:2)&&refused==(expected_error?XDEV_EXT_PEER_REFUSE_NO_P2P_PATH:0));
}
/* External diagnosis only: no state mutation or expected-value computation. */
static void debug_p04(unsigned phase,const char *point) {
 fprintf(stderr,"P04 phase=%u point=%s now=%llu last_snapshot{event=%u group=%llu now=%llu hard=%llu policy=%llu state=%u facts=%u}\n",phase,point,(unsigned long long)host_ns,last_snapshot.event,(unsigned long long)last_snapshot.group,(unsigned long long)last_snapshot.now_ns,(unsigned long long)last_snapshot.hard_deadline_ns,(unsigned long long)last_snapshot.policy_deadline_ns,last_snapshot.state,last_snapshot.facts);
 for(unsigned i=0;i<2;i++) {
  struct xdev_ext_xd_stage *xs=stage_of(&sides[i])->priv;
  fprintf(stderr,"P04 side=%u sess_state=%u stop_latched=%u stop_ns=%llu link_fail=%u down_latched=%u posted_groups=%u\n",i,sides[i].session.ss.state,xs->stop_latched,(unsigned long long)xs->stop_ns,sides[i].link_failures,xs->down_latched,xs->posted_groups);
  for(unsigned k=0;k<xs->ns.depth;k++)if(xs->ns.slots[k].busy) {
   struct xdev_ext_net_slot *slot=&xs->ns.slots[k];struct xdev_ext_xd_fact *f=&xs->facts[k];
   fprintf(stderr,"P04 side=%u slot=%u group=%llu state=%u born=%llu posted=%llu withdrawal=%llu wake=%llu event=%u known=%u quiesced=%u accepted=%u\n",i,k,(unsigned long long)slot->group,slot->state,(unsigned long long)f->born,(unsigned long long)f->posted,(unsigned long long)f->withdrawal,(unsigned long long)f->wake,f->event,slot->local_known,slot->local_quiesced,f->accepted);
  }
 }
}
static void original_traces(void) {
 /* T01 catches publishing/ACK on local RX rather than final chain disposition. */
 pair(0,2,8192);
 assert(!submit(&sides[1],0)&&!submit(&sides[1],1));
 assert(!submit(&sides[0],0)&&!submit(&sides[0],1));drain_worker(16);
 assert(sides[1].posts==1&&sides[0].posts==1);
 assert(sides[1].post[0].count==2&&sides[1].post[0].elements[0].buf_len==4096&&sides[1].post[0].elements[1].buf_len==4096);
 finish_element(&sides[1],0,0,0,4096,true);drain_worker(4);assert(sides[1].posts==1);
 finish_element(&sides[1],0,1,0,4096,true);complete_group(&sides[0],0,0,true);drain_worker(12);
 assert(sides[1].posts==2&&sides[0].posts==2&&!wire_count(&sides[1],XDEV_EXT_XD_ACK));
 consume(&sides[1],0);assert(!memcmp(sides[1].cqe[0].tag,test_tag,24));
 end_batch(&sides[1],0,0,false);drain_worker(8);consume(&sides[0],0);end_batch(&sides[0],0,0,false);
 complete_group(&sides[1],1,0,true);complete_group(&sides[0],1,0,true);drain_worker(8);consume(&sides[1],1);end_batch(&sides[1],1,0,false);drain_worker(8);consume(&sides[0],1);end_batch(&sides[0],1,0,false);
 done_success(&sides[0],0,1);done_success(&sides[0],1,2);done_success(&sides[1],0,1);done_success(&sides[1],1,2);
 assert(sides[0].cqe[0].remote==XDEV_EXT_NET_REMOTE_ACKED&&sides[0].cqe[1].remote==XDEV_EXT_NET_REMOTE_ACKED);
 assert(!sides[0].live&&!sides[1].live&&!sides[0].released_q0&&!sides[1].released_q0&&!sides[0].link_failures&&!sides[1].link_failures);
 assert(sides[0].native_submits==2&&sides[1].native_submits==2&&sides[0].native_completes==2&&sides[1].native_completes==2);
 for(unsigned side=0;side<2;side++)for(unsigned i=0;i<2;i++)assert(sides[side].native[i].cookie==(u64)i+1&&sides[side].native[i].bytes==8192&&sides[side].native[i].complete_order>sides[side].native[i].submit_order);
 ok("T01 two groups, one posted RX group, final-disposition ACK, exact tags and quiesced leases");

 posted();complete_group(&sides[1],0,0,true);drain_worker(4);consume(&sides[1],0);end_batch(&sides[1],0,0,false);drain_worker(8);
 assert(!sides[0].batches[0].publishes&&!sides[0].native_completes);finish_element(&sides[0],0,0,0,4096,true);drain_worker(4);assert(!sides[0].batches[0].publishes&&!sides[0].native_completes);
 finish_element(&sides[0],0,1,0,4096,true);drain_worker(4);assert(sides[0].batches[0].publishes==1&&sides[0].native_completes==1);consume(&sides[0],0);assert(!sides[0].cqe[0].status);
 ok("T02 early remote ACK waits for last actual TX completion");

 posted();finish_element(&sides[1],0,0,-EBADMSG,4096,true);finish_element(&sides[1],0,1,0,4096,true);complete_group(&sides[0],0,0,true);drain_worker(8);
 assert(sides[1].batches[0].status==-EBADMSG&&!sides[1].batches[0].sequester);consume(&sides[1],0);assert(sides[1].cqe[0].crc_errors==1);
 end_batch(&sides[1],0,-EBADMSG,false);drain_worker(8);assert(sides[0].batches[0].status==-EREMOTEIO);consume(&sides[0],0);end_batch(&sides[0],0,-EREMOTEIO,false);
 happy_group(1);done_success(&sides[0],1,2);ok("T03 CRC error sends FAIL, closes failed receive window and permits later group");

 posted();down_run(true);for(unsigned s=0;s<2;s++){assert(sides[s].batches[0].publishes==1&&sides[s].batches[0].sequester);consume(&sides[s],0);assert(sides[s].released_q0==2&&!sides[s].released_q1);}
 ok("T04 canceled nonquiescent owners at link down sequester both batches and leases");

 announced();advance_ms(15000);drain_worker(12);
 assert(wire_count(&sides[0],XDEV_EXT_XD_CANCEL)==1&&wire_count(&sides[1],XDEV_EXT_XD_FAIL)==1);
 assert(sides[0].batches[0].status==-EREMOTEIO&&!sides[0].live&&!sides[1].live&&!total_posts()&&!sides[0].link_failures&&!sides[1].link_failures);
 consume(&sides[0],0);end_batch(&sides[0],0,-EREMOTEIO,false);happy_group(1);assert(last_wire(&sides[0],XDEV_EXT_XD_RTS)->msg.data_seq==2);
 ok("T05 unarmed withdrawal FAIL consumes announcement once and preserves next channel sequence");

 announced();sides[1].drop_type=XDEV_EXT_XD_FAIL;advance_ms(15000);drain_worker(12);advance_ms(1000);drain_worker(8);
 assert(sides[0].link_failures&&sides[0].last_link_error==-ETIMEDOUT);down_run(false);drain_worker(8);
 assert(sides[0].batches[0].status==-ENOLINK&&!total_posts()&&!sides[0].live&&!sides[1].live);consume(&sides[0],0);assert(sides[0].cqe[0].remote==XDEV_EXT_NET_REMOTE_LOST);
 ok("T06 unanswered CANCEL ends incarnation at one second with LOST and no native leases");

 pair(0,2,8192);sides[1].drop_type=XDEV_EXT_XD_CTS;assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(12);assert(sides[1].posts==1&&!sides[0].posts);
 advance_ms(15000);drain_worker(12);assert(sides[1].posts==1&&sides[0].posts==1&&wire_count(&sides[1],XDEV_EXT_XD_CTS)==2);
 complete_group(&sides[0],0,0,true);complete_group(&sides[1],0,0,true);drain_worker(8);consume(&sides[1],0);end_batch(&sides[1],0,0,false);drain_worker(8);consume(&sides[0],0);done_success(&sides[0],0,1);assert(!sides[0].link_failures&&!sides[1].link_failures);
 ok("T07 lost CTS is replayed after CANCEL without second post or DATA retransmission");

 pair(0,2,8192);assert(!submit(&sides[1],0));sides[0].full_type=XDEV_EXT_XD_RTS;assert(submit(&sides[0],0)==-EAGAIN);sides[0].full_type=0;
 /* Deliver RTS record while stop already closed admission, before worker selection. */
 request_stop(&sides[1]);assert(!submit(&sides[0],1));deliver_wire_once(&sides[0]);drain_worker(12);
 assert(sides[1].batches[0].status==-ECANCELED&&!total_posts()&&!sides[0].live&&!sides[1].live);
 assert(last_wire(&sides[1],XDEV_EXT_XD_FAIL)->msg.status==ESHUTDOWN&&sides[1].link.chan[0].consumed==2);
 assert(sides[0].batches[1].status==-EREMOTEIO);ok("T08 STOP cancels ARMED and explicitly refuses queued RTS without native work");

 pair(0,2,8192);assert(!submit(&sides[1],0));sides[0].drop_type=XDEV_EXT_XD_RTS;assert(!submit(&sides[0],0));drain_worker(4);assert(!submit(&sides[0],1));drain_worker(8);
 assert(sides[1].link_failures&&sides[1].last_link_error==-EPROTO&&!total_posts());ok("T09 channel sequence gap fails link before posting any receiver");

 pair(0,2,8192);assert(!submit(&sides[1],0)&&!submit(&sides[0],0));sides[0].wire[0].msg.count=1;drain_worker(8);
 fprintf(stderr,"T10 observations: FAIL=%u consumed=%llu posts=%u stage_err=%d link_err=%d\n",wire_count(&sides[1],XDEV_EXT_XD_FAIL),(unsigned long long)sides[1].link.chan[0].consumed,total_posts(),sides[1].session.last_err,sides[1].last_link_error);
 assert(wire_count(&sides[1],XDEV_EXT_XD_FAIL)==1&&sides[1].link.chan[0].consumed==1&&!total_posts()&&sides[1].session.last_err==-EPROTO);
 ok("T10 contradictory announced count is consumed/refused and kills stage");

 pair(0,2,8192);sides[1].drop_type=XDEV_EXT_XD_CTS;assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(8);advance_ms(30000);drain_worker(12);
 assert(sides[1].link_failures);down_run(false);advance_ms(30000);drain_worker(8);assert(sides[1].batches[0].sequester);consume(&sides[1],0);assert(sides[1].released_q0==2);
 ok("T11 abandoned posted receiver ends incarnation and quarantines untouched buffers");

 pair(0,2,8192);sides[0].lease_error=-ENOMEM;assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(12);
 assert(sides[0].link_failures&&!sides[0].posts&&sides[0].batches[0].status==-ENOMEM&&!sides[0].batches[0].sequester);
 ok("T12 TX lease refusal after CTS fails link and returns proved unposted local frames");

 announced();xdev_ext_mech_stage_dead(stage_of(&sides[0]),-ENODEV);inject_message(&sides[0],XDEV_EXT_XD_CTS,1,4,0);drain_worker(8);
 assert(!sides[0].posts&&sides[0].link_failures);down_run(false);drain_worker(4);assert(sides[0].batches[0].status==-ENOLINK);
 ok("T13 CTS at dead sender performs no post and ends incarnation");

 fresh(0,0,2,65536,8192);sides[0].admission_error=-EXDEV;assert(bind_side(&sides[0])==-EXDEV);
 assert(sides[0].endpoint_attaches==1&&sides[0].endpoint_detaches==1&&sides[0].admitted_unbind_priv&&!stage_of(&sides[0])->priv);
 assert(sides[0].admission_order<sides[0].debug_order&&sides[0].debug_order<sides[0].unbind_order);
 check_admission_record(&sides[0],-EXDEV,0);
 fresh(0,0,2,65536,8192);assert(!bind_side(&sides[0]));check_admission_record(&sides[0],0,1);
 assert(sides[0].admission_order<sides[0].debug_order&&!sides[0].unbind_order);
 ok("T14 refused admission diagnostic precedes unbind and private stage cleanup");

 fresh(0,0,4,262144,262144);assert(bind_side(&sides[0])==-EINVAL);ok("T15 four batches of sixty-four elements exceed ring budget");

 pair(0,2,8192);struct xdev_ext_mech_batch *b=prepare(&sides[0],0);struct xdev_ext_xdomain_desc descriptor={.frame_pos=0,.frame_off=2048,.len=8192,.group=1};
 assert(registered->validate(stage_of(&sides[0]),b,(u8*)&descriptor,1)==-EINVAL);
 descriptor.frame_off=0;descriptor.group=2;assert(registered->validate(stage_of(&sides[0]),b,(u8*)&descriptor,1)==-EINVAL);
 b=prepare(&sides[1],0);descriptor=(struct xdev_ext_xdomain_desc){.len=8192};descriptor.tag[0]=1;assert(registered->validate(stage_of(&sides[1]),b,(u8*)&descriptor,1)==-EINVAL);
 descriptor.tag[0]=0;b->f[0].data_off=61440;b->f[0].data_len=4097;descriptor.frame_off=61440;descriptor.len=4097;assert(registered->validate(stage_of(&sides[1]),b,(u8*)&descriptor,1)==-ERANGE);
 /* CREATE rejects an oversized native geometry in its own right. */
 fresh(0,0,1,524288,266240);assert(bind_side(&sides[0])==-EINVAL);
 /* Unit defense precondition after legal CREATE: oversized batch metadata
  * plus one exact-cover span isolates validator's 65-native-element bound.
  * This does not claim BPF can bypass the core batch-length invariants. */
 fresh(0,0,1,524288,262144);assert(!bind_side(&sides[0]));b=prepare_raw(&sides[0],0);b->f[0].data_len=266240;
 descriptor=(struct xdev_ext_xdomain_desc){.len=266240,.group=1};assert(registered->validate(stage_of(&sides[0]),b,(u8*)&descriptor,1)==-E2BIG);
 ok("T16 descriptor offset, full RX room, element bound, exact TX group and RX tag are enforced");

 posted();inject_message(&sides[0],XDEV_EXT_XD_ACK,1,UINT64_MAX,0);drain_worker(6);
 assert(family_of(&sides[0])->tx.credit<=family_of(&sides[0])->tx.next_group+family_of(&sides[0])->tx.cfg.window);
 assert(!sides[0].link_failures&&!sides[0].batches[0].publishes);ok("T17 huge wire ACK credit is normalized before BPF acceptance and waits for native custody");

 pair(0,2,8192);struct xdev_ext_netfam_stage *ns=family_of(&sides[0]);ns->tx.credit=ns->tx.next_group;u64 sequence=sides[0].link.chan[0].announced;
 assert(submit(&sides[0],0)==-EAGAIN&&!sides[0].wires&&sides[0].link.chan[0].announced==sequence&&!sides[0].live);
 for(unsigned i=0;i<ns->depth;i++) { assert(!ns->slots[i].busy); }
 ok("T18 credit-limit refusal frees slot and advances no announcement counter");

 fresh(0,0,2,65536,8192);assert(!bind_side(&sides[0]));
 for(unsigned i=0;i<3;i++){int rc=submit(&sides[0],i);if(rc){fprintf(stderr,"T19 submit index=%u rc=%d\n",i,rc);debug_stage_scalars("T19-submit",&sides[0]);}assert(!rc);drain_worker(8);assert(last_wire(&sides[1],XDEV_EXT_XD_FAIL)->msg.status==ENODEV);consume(&sides[0],i);end_batch(&sides[0],i,-EREMOTEIO,false);}
 assert(!bind_side(&sides[1]));happy_group(3);done_success(&sides[1],3,4);ok("T19 late-bound receiver starts its receive window at group four");
}

static void stop_after_record(struct xdev_ext_mech_stage *st) { request_stop(side_of_stage(st));xdev_ext_mech_stage_dead(st,-ESHUTDOWN); }
static void reincarnate_after_record(struct xdev_ext_mech_stage *st) { struct side *s=side_of_stage(st);s->link.local_inc+=100;s->link.remote_inc+=100; }
static void generation_after_record(struct xdev_ext_mech_stage *st) { st->s->pool.generation++; }
static void ticket_after_record(struct xdev_ext_mech_stage *st) { side_of_stage(st)->batches[0].ticket++; }
static void stop_while_leasing(struct side *side) { request_stop(side);xdev_ext_mech_stage_dead(stage_of(side),-ESHUTDOWN); }
static void nested_rx_reservation(struct side *side) {
 side->lease_blocked++;unsigned before=side->posts;
 /* Timer/control ingress can queue a second candidate while first lease sleeps,
  * but may not run a nested worker. Subsequent pass must see reserved_groups=1. */
 struct xdev_ext_xd_msg second={.type=XDEV_EXT_XD_RTS,.src_inc=side->link.remote_inc,.dst_inc=side->link.local_inc,.stream=101,.group=2,.credit=0,.data_seq=2,.total_len=8192,.count=2};
 xdev_ext_xd_class_ctl(stage_of(side),&second);assert(side->posts==before);
}
static void pressure_case(void) {
 posted();unsigned before=protocol_calls;
 struct pressure_observation full={0},overflowed={0},terminal={0};struct xdev_ext_xd_msg one_more={0};
 pressure_seed_full(&sides[0],&one_more);pressure_capture(&sides[0],&full);
 assert(full.used==4*XDEV_EXT_REL_MAX_WINDOW&&full.bytes&&full.bytes<=sizeof(full.queue));
 /* This is the REAL ingress/capacity check. Dedup is not required to overflow:
  * the reviewed storage adapter supplies a valid distinct scalar candidate. */
 xdev_ext_xd_class_ctl(stage_of(&sides[0]),&one_more);pressure_capture(&sides[0],&overflowed);
 assert(overflowed.used==full.used&&overflowed.bytes==full.bytes&&!memcmp(full.queue,overflowed.queue,full.bytes));
 request_stop(&sides[0]);xdev_ext_mech_stage_dead(stage_of(&sides[0]),-ENOLINK);
 pressure_capture(&sides[0],&terminal);assert(terminal.stop_pending&&terminal.link_down_pending);
 sides[0].session.queued=1;run_worker_once(&sides[0]);
 pressure_capture(&sides[0],&terminal);assert(terminal.stop_observed);
 assert(sides[0].link_failures&&protocol_calls-before<=4*XDEV_EXT_REL_MAX_WINDOW);
 down_run(false);advance_ms(30000);drain_worker(8);assert(sides[0].batches[0].sequester);ok("P19 actual bounded enqueue overflow preserves queue, terminal latches and finite invocation budget");

}
static void policy_safety(void) {
 /* P01 catches any default C success policy on absent/invalid callbacks. */
 const enum injection invalid[]={ABSENT_CALLBACK,NO_VERDICT,RAW_HOLD,RAW_RETRY,RAW_UNKNOWN,SWALLOWED_ERROR,DUPLICATE_RECORD,INVALID_ACTION,BAD_VERSION,BAD_FLAGS,BAD_RESERVED};
 for(unsigned i=0;i<ARRAY_SIZE(invalid);i++){
  pair(0,2,8192);malicious(invalid[i],XDEV_EXT_XDP_EV_TX_SUBMIT,1);int rc=submit(&sides[0],0);
  assert(rc<0&&!total_posts()&&!total_wire());assert_protocol_failure(0,0,0);
 }
 posted();malicious(NO_VERDICT,XDEV_EXT_XDP_EV_LOCAL,1);complete_group(&sides[0],0,0,true);drain_worker(4);assert(sides[0].link_failures);assert(!sides[0].released_q1&&!sides[0].released_q0);
 ok("P01 missing/zero/raw-return/duplicate/malformed/error policy has no C fallback, including native owners");

 void(*races[])(struct xdev_ext_mech_stage*)={stop_after_record,reincarnate_after_record,generation_after_record,ticket_after_record};
 for(unsigned i=0;i<ARRAY_SIZE(races);i++){
  pair(0,2,8192);after_record=races[i];int rc=submit(&sides[0],0);(void)rc;
  assert(!total_posts()&&!total_wire()&&!total_published());
 }
 ok("P02 concurrent STOP/incarnation/generation/ticket invalidation discards unapplied old intent");

 for(unsigned mode=ID_FOREIGN;mode<=EPOCH_FORGED;mode++){
  pair(0,2,8192);malicious(mode,XDEV_EXT_XDP_EV_TX_SUBMIT,1);assert(submit(&sides[0],0)<0);assert_protocol_failure(0,0,0);
 }
 ok("P03 intentionally forged event identity or epoch is policy error, not benign stale retry");

 const u64 phase_ms[]={15000,1000,30000,1000};
 for(unsigned phase=0;phase<4;phase++){
  if(phase==0||phase==1)announced();else posted();
  if(phase==1){sides[1].drop_type=XDEV_EXT_XD_FAIL;advance_ms(15000);drain_worker(8);}
  if(phase==3)request_stop(&sides[0]);
  unsigned cancel_before=wire_count(&sides[0],XDEV_EXT_XD_CANCEL),ack_before=wire_count(&sides[1],XDEV_EXT_XD_ACK);
  malicious(WAIT_FOREVER,0,0);debug_p04(phase,"before-advance");advance_ms(phase_ms[phase]);debug_p04(phase,"at-boundary-before-worker");drain_worker(12);debug_p04(phase,"after-worker");
  assert(sides[0].link_failures+sides[1].link_failures);
  assert(wire_count(&sides[0],XDEV_EXT_XD_CANCEL)==cancel_before&&wire_count(&sides[1],XDEV_EXT_XD_ACK)==ack_before);
 }
 ok("P04 WAIT cannot move immutable announce/withdraw/post/STOP hard boundaries or trigger implicit CANCEL/ACK");

 const enum injection wakes[]={WAIT_ZERO,WAIT_PAST,WAIT_LATE,WAIT_HARD};
 for(unsigned i=0;i<ARRAY_SIZE(wakes);i++){
  announced();unsigned w=total_wire();
  /* announced() already recorded WAIT. Observe its actual wake so this test
   * reaches the malicious verdict rather than merely re-kicking a paused slot. */
  u64 wake=((struct xdev_ext_xd_stage*)stage_of(&sides[0])->priv)->facts[0].wake;
  assert(wake>host_ns);malicious(wakes[i],XDEV_EXT_XDP_EV_TIMER,1);
  advance_ms((wake-host_ns+NSEC_PER_MSEC-1)/NSEC_PER_MSEC);assert_protocol_failure(0,w,0);
 }
 pair(0,2,8192);host_ns=UINT64_MAX-100;malicious(WAIT_LATE,XDEV_EXT_XDP_EV_TX_SUBMIT,1);assert(submit(&sides[0],0)<0);assert_protocol_failure(0,0,0);
 ok("P05 invalid zero/past/late/hard-crossing/wrapped WAIT is refused");

 pair(0,2,8192);malicious(TX_POST_FORBIDDEN,XDEV_EXT_XDP_EV_TX_SUBMIT,1);assert(submit(&sides[0],0)<0);assert_protocol_failure(0,0,0);
 pair(0,2,8192);malicious(TX_POST_FORBIDDEN,XDEV_EXT_XDP_EV_RX_SUBMIT,1);assert(submit(&sides[1],0)<0);assert_protocol_failure(0,0,0);
 posted();unsigned w=total_wire();malicious(TX_POST_FORBIDDEN,XDEV_EXT_XDP_EV_DUPLICATE,1);inject_message(&sides[0],XDEV_EXT_XD_CTS,1,4,0);assert_protocol_failure(2,w+1,0);
 ok("P06 TX_POST requires matching CTS/direction and is never repeated after native_begin");

 pair(0,2,8192);assert(!submit(&sides[1],0)&&!submit(&sides[1],1));lease_schedule=nested_rx_reservation;assert(!submit(&sides[0],0));drain_worker(12);
 fprintf(stderr,"P07 lease_blocked=%u lease_calls=%u posts=%u\n",sides[1].lease_blocked,sides[1].lease_calls,sides[1].posts);debug_stage_scalars("P07-after-lease-race",&sides[1]);
 assert(sides[1].lease_blocked==1&&sides[1].posts==1);
 /* The retained second RTS is paused by a previous WAIT. Installing a new
  * malicious program is not a protocol fact; reach the actual retry first. */
 worker_depth=1;unsigned long rts_retry_ms=registered->progress(stage_of(&sides[1]));worker_depth=0;
 assert(rts_retry_ms>0&&rts_retry_ms*NSEC_PER_MSEC<=XD_TICK_NS);
 malicious(RX_POST_FORBIDDEN,XDEV_EXT_XDP_EV_RTS,1);advance_ms(rts_retry_ms);sides[1].session.queued=1;drain_worker(4);assert(sides[1].posts==1&&sides[1].link_failures);
 ok("P07 second RX candidate cannot post during first lease reservation or native owner");

 pair(0,2,8192);sides[0].complete_inline=sides[1].complete_inline=1;assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(12);
 assert(sides[0].posts==1&&sides[1].posts==1&&sides[1].batches[0].publishes==1&&!sides[0].batches[0].publishes);
 pair(0,2,8192);lease_schedule=stop_while_leasing;assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(12);
 assert(!sides[1].posts&&sides[1].link_failures);ok("P08 inline callbacks only record; STOP during sleeping lease blocks final post gate");

 const unsigned bad_contexts[]={0,1,2,3,4};
 for(unsigned i=0;i<ARRAY_SIZE(bad_contexts);i++){
  if(i==0)announced();else posted();
  if(i==1)complete_group(&sides[0],0,-ECANCELED,false);
  if(i==2)complete_group(&sides[1],0,-EBADMSG,true);
  if(i==3){finish_element(&sides[1],0,0,0,1,true);finish_element(&sides[1],0,1,0,4096,true);}
  if(i==4)complete_group(&sides[1],0,-EOVERFLOW,true);
  /* announced() has already produced WAIT without any completion fact.
   * Let its actual scheduled retry arrive before attacking the verdict. */
  if(i==0){worker_depth=1;unsigned long retry_ms=registered->progress(stage_of(&sides[0]));worker_depth=0;
   assert(retry_ms>0&&retry_ms*NSEC_PER_MSEC<=XD_TICK_NS);advance_ms(retry_ms);}
  malicious(PUBLISH_SUCCESS,0,1);sides[i>=2?1:0].session.queued=1;drain_worker(8);
  assert(sides[0].link_failures+sides[1].link_failures);
  for(unsigned s=0;s<2;s++)assert(!sides[s].batches[0].publishes||sides[s].batches[0].status!=0);
 }
 ok("P09 false success without ACK/local proof or after unknown/CRC/short/overrun is refused");

 pair(0,2,8192);assert(!submit(&sides[1],0));malicious(IGNORE_OBLIGATION,XDEV_EXT_XDP_EV_RTS,1);assert(!submit(&sides[0],0));drain_worker(8);assert(sides[1].link_failures&&!total_posts());
 posted();malicious(REJECT_POSTED,XDEV_EXT_XDP_EV_CANCEL,1);
 /* This attacks rejection of the accepted current stream. A stale stream is
  * correctly dropped before it can reach the injected BPF verdict. */
 struct xdev_ext_xd_msg accepted_cancel={.type=XDEV_EXT_XD_CANCEL,
  .stream=((struct xdev_ext_xd_stage*)stage_of(&sides[1])->priv)->stream,.group=1};
 assert(!xdev_ext_xd_msg_send(&sides[0].link,NULL,0,&accepted_cancel));deliver_wire_once(&sides[0]);
 drain_worker(6);assert(sides[1].link_failures&&sides[1].posts==1);
 for(unsigned event=XDEV_EXT_XDP_EV_CTS;event<=XDEV_EXT_XDP_EV_CHAIN_END;event++){
  if(event!=XDEV_EXT_XDP_EV_CTS&&event!=XDEV_EXT_XDP_EV_CHAIN_END)continue;
  if(event==XDEV_EXT_XDP_EV_CTS){announced();malicious(IGNORE_OBLIGATION,event,1);inject_message(&sides[0],XDEV_EXT_XD_CTS,1,4,0);}
  else{local_success();consume(&sides[1],0);malicious(IGNORE_OBLIGATION,event,1);end_batch(&sides[1],0,0,false);}
  drain_worker(8);assert(sides[0].link_failures+sides[1].link_failures);
 }
 ok("P10 IGNORE cannot consume live RTS/CTS/CHAIN_END and REJECT_RTS cannot escape posted RX");

 pair(0,2,8192);sides[1].drop_type=XDEV_EXT_XD_CTS;assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(8);advance_ms(15000);drain_worker(12);
 assert(sides[0].posts==1&&sides[1].posts==1&&wire_count(&sides[0],XDEV_EXT_XD_CANCEL)==1&&wire_count(&sides[1],XDEV_EXT_XD_CTS)==2);
 ok("P11 default BPF replays CTS after withdrawal and selects one native TX post");

 announced();assert(!sides[1].batches[0].priv);advance_ms(15000);drain_worker(12);
 assert(wire_count(&sides[1],XDEV_EXT_XD_FAIL)==1&&sides[1].link.chan[0].consumed==2&&!sides[1].posts);
 assert(last_snapshot.group==0||last_snapshot.group==1);ok("P12 pre-batch CANCEL uses real empty-backing stage call and consumes RTS once");

 pair(0,2,8192);sides[0].post_error=-EAGAIN;assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(10);
 assert(!sides[0].posts&&!sides[0].native_submits&&!sides[0].native_completes&&sides[0].link_failures);
 pair(0,2,8192);sides[0].full_type=XDEV_EXT_XD_RTS;assert(submit(&sides[0],0)==-EAGAIN&&!sides[0].wires&&!sides[0].link.chan[0].announced);
 const unsigned replies[]={XDEV_EXT_XD_CTS,XDEV_EXT_XD_ACK,XDEV_EXT_XD_FAIL};
 for(unsigned i=0;i<3;i++){
  if(i==0){pair(0,2,8192);sides[1].full_type=replies[i];assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(8);assert(sides[1].posts==1&&!sides[0].posts);}
  else{local_success();consume(&sides[1],0);sides[1].full_type=replies[i];end_batch(&sides[1],0,i==2?-EIO:0,false);drain_worker(8);}
  assert(!wire_count(&sides[1],replies[i]));unsigned calls=protocol_calls;sides[1].full_type=0;advance_ms(20);drain_worker(12);
  assert(wire_count(&sides[1],replies[i])==1&&protocol_calls>calls);
 }
 ok("P13 preaccept RTS has no sequence change; full CTS/ACK/FAIL queues retain owed BPF events");

 posted();u64 posted_at=family_of(&sides[0])->slots[0].posted_ms;
 /* Legal remote credit for group 1 in the actual public protocol window;
  * payload slot depth does not define the announced-RTS window. */
 u64 replay_credit=1+family_of(&sides[0])->tx.cfg.window;
 inject_message(&sides[0],XDEV_EXT_XD_ACK,1,replay_credit,0);inject_message(&sides[0],XDEV_EXT_XD_ACK,1,replay_credit,0);inject_message(&sides[0],XDEV_EXT_XD_CTS,1,replay_credit,0);drain_worker(10);
 assert(sides[0].posts==1&&!sides[0].batches[0].publishes&&family_of(&sides[0])->slots[0].posted_ms==posted_at);
 complete_group(&sides[0],0,0,true);drain_worker(6);assert(sides[0].batches[0].publishes==1);ok("P14 early/duplicate ACK and CTS neither repost nor publish early nor reset deadline");

 for(unsigned q=0;q<2;q++){
  local_success();consume(&sides[1],0);unsigned before=wire_count(&sides[1],XDEV_EXT_XD_ACK);
  frame_release_fail=q;end_batch(&sides[1],0,q?0:-EIO,false);
  assert(wire_count(&sides[1],XDEV_EXT_XD_ACK)==before);drain_worker(8);
  assert(!wire_count(&sides[1],XDEV_EXT_XD_ACK)&&wire_count(&sides[1],XDEV_EXT_XD_FAIL)==1&&sides[1].batches[0].disposed);
 }
 ok("P15 downstream error/final frame sequester queues failure only after actual core release ordering");

 pair(1,2,8192);unsigned window=family_of(&sides[0])->tx.cfg.window;
 for(unsigned i=0;i<2*window+3;i++){happy_group(i);assert(sides[0].cqe[i].group==(u64)i+1);}
 assert(family_of(&sides[0])->tx.base_group==2*window+4&&family_of(&sides[0])->tx.next_group==2*window+4);
 /* Stage 0 is a source-class sentinel; real core cannot call consumer batch_end. */
 assert(sides[0].session.st[0].cls==&source_class);
 pair(1,2,8192);assert(!submit(&sides[0],0));drain_worker(4);inject_message(&sides[0],XDEV_EXT_XD_FAIL,1,0,ECANCELED);drain_worker(8);consume(&sides[0],0);
 assert(family_of(&sides[0])->tx.base_group==2&&!sides[0].live&&!sides[0].posts);
 ok("P16 index-one TX fill_cqe retires over two windows and never-posted FAIL without source batch_end");

 pair(1,2,8192);assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(10);down_run(false);advance_ms(30000);drain_worker(8);consume(&sides[0],0);
 assert(family_of(&sides[0])->tx.base_group==1&&sides[0].released_q0==2&&!sides[0].released_q1);
 assert(family_of(&sides[0])->tx.entry[1%window].native_pending);ok("P17 index-one TX unknown owner remains pending, unretired and quarantined");

 fresh(0,1,2,65536,8192);assert(bind_side(&sides[1])==-EOPNOTSUPP&&!sides[1].endpoint_attaches);
 /* Distinct index cookies are exercised on the same batch via actual class
  * callbacks. RX0 receives group1; TX1 uses an independently chosen group9. */
 pair(0,2,8192);struct side *rx=&sides[1];struct xdev_ext_mech_stage *rxst=&rx->session.st[0];
 assert(!submit(rx,0)&&!submit(&sides[0],0));drain_worker(10);complete_group(rx,0,0,true);drain_worker(4);consume(rx,0);
 rx->session.nr_stages=2;rx->session.st[1]=(struct xdev_ext_mech_stage){.s=&rx->session,.cls=registered,.file=&authority,.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.index=1,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 assert(!bind_side(rx));family_of(rx)->tx.next_group=9;family_of(rx)->tx.base_group=9;
 u64 relay_credit=9+family_of(rx)->tx.cfg.window;family_of(rx)->tx.credit=relay_credit;
 struct xdev_ext_mech_batch *shared=&rx->batches[0];memset(shared->priv,0,registered->batch_priv_size);
 u8 plan[32*64]={0};registered->default_build(stage_of(rx),shared,plan);assert(!registered->validate(stage_of(rx),shared,plan,1));
 shared->claims=shared->publishes=0;shared->ticket++;rx->drop_type=XDEV_EXT_XD_RTS;
 worker_depth=1;assert(!registered->submit(stage_of(rx),shared));worker_depth=0;drain_worker(8);
 /* Explicit external peer control inputs isolate the indexed-cookie boundary.
  * ACK alone supplies no local custody; actual accepted TX elements complete. */
 inject_message(rx,XDEV_EXT_XD_CTS,9,relay_credit,0);drain_worker(8);debug_stage_scalars("P18-before-secondpost",rx);assert(rx->posts==2);
 complete_group(rx,1,0,true);inject_message(rx,XDEV_EXT_XD_ACK,9,relay_credit,0);drain_worker(8);
 assert(shared->publishes==1&&!shared->status);registered->fill_cqe(stage_of(rx),shared,&rx->cqe[0]);assert(rx->cqe[0].group==9);
 end_batch(rx,0,0,false);drain_worker(8);
 assert(rxst->index==0&&last_wire(rx,XDEV_EXT_XD_ACK)->msg.group==1);
 assert(wire_count(rx,XDEV_EXT_XD_ACK)==1);ok("P18 RX later-stage bind rejected; RX0 and TX1 preserve distinct same-batch group cookies");

 pressure_case();

 posted();unsigned before=protocol_calls;complete_group(&sides[1],0,0,true);
 assert(protocol_calls==before&&sides[1].session.queued&&sides[1].batches[0].publishes==0);
 run_worker_once(&sides[1]);assert(protocol_calls>before&&sides[1].batches[0].publishes==1);
 ok("P20 family callback under ns.lock queues kick; only later unlocked worker invokes BPF");

 const enum injection credits[]={BAD_CREDIT_HIGH,BAD_CREDIT_LOW,BAD_CREDIT_OVERFLOW,BAD_CREDIT_FOREIGN};
 for(unsigned i=0;i<4;i++){
  local_success();consume(&sides[1],0);malicious(credits[i],XDEV_EXT_XDP_EV_CHAIN_END,1);u64 safe=family_of(&sides[1])->rx_rel.base_group;
  end_batch(&sides[1],0,0,false);drain_worker(6);assert(sides[1].link_failures&&!wire_count(&sides[1],XDEV_EXT_XD_ACK)&&family_of(&sides[1])->rx_rel.base_group==safe);
 }
 local_success();consume(&sides[1],0);u64 advertised_floor=last_wire(&sides[1],XDEV_EXT_XD_CTS)->msg.credit;
 malicious(ALLOW_UNDERCREDIT,XDEV_EXT_XDP_EV_CHAIN_END,1);end_batch(&sides[1],0,0,false);drain_worker(6);
 assert(wire_count(&sides[1],XDEV_EXT_XD_ACK)==1&&!sides[1].link_failures);
 assert(last_wire(&sides[1],XDEV_EXT_XD_ACK)->msg.credit>=advertised_floor);
 ok("P21 illegal high/floor/overflow/foreign credit refused; proved bounded underadvertisement accepted");

 const enum injection unknowns[]={PUBLISH_SUCCESS,IGNORE_OBLIGATION,WAIT_FOREVER};
 for(unsigned i=0;i<3;i++){
  posted();malicious(unknowns[i],0,1);down_run(false);advance_ms(30000);drain_worker(8);
  for(unsigned s=0;s<2;s++){assert(sides[s].batches[0].publishes==1);consume(&sides[s],0);assert(sides[s].batches[0].sequester&&!sides[s].released_q1&&sides[s].released_q0==2);}
  assert(sides[0].posts==1&&sides[1].posts==1&&!wire_count(&sides[1],XDEV_EXT_XD_ACK));
 }
 ok("P22 skipped native stop callbacks never manufacture quiescence/success, even under hostile policy");

 pair(1,2,8192);happy_group(0);u64 base=family_of(&sides[0])->tx.base_group;unsigned released=sides[0].released_q1;
 registered->fill_cqe(stage_of(&sides[0]),&sides[0].batches[0],&sides[0].cqe[0]);
 registered->batch_release(stage_of(&sides[0]),&sides[0].batches[0],false);drain_worker(4);
 assert(sides[0].batches[0].publishes==1&&family_of(&sides[0])->tx.base_group==base&&sides[0].released_q1==released);
 happy_group(1);assert(sides[0].batches[0].publishes==1&&sides[0].cqe[1].group==2);ok("P23 duplicate final callbacks cannot retire/release twice or affect recycled ticket");

 local_success();consume(&sides[1],0);delayed_ack_ns=host_ns+60000000ULL;early_withdraw_ns=host_ns+1000000000ULL;
 malicious(ALTERNATE_POLICY,0,0);end_batch(&sides[1],0,0,false);drain_worker(4);assert(!wire_count(&sides[1],XDEV_EXT_XD_ACK));
 advance_ms(40);drain_worker(4);assert(!wire_count(&sides[1],XDEV_EXT_XD_ACK));advance_ms(20);drain_worker(8);assert(wire_count(&sides[1],XDEV_EXT_XD_ACK)==1);
 announced();early_withdraw_ns=host_ns+1000000000ULL;delayed_ack_ns=0;malicious(ALTERNATE_POLICY,0,0);advance_ms(1000);drain_worker(10);
 assert(wire_count(&sides[0],XDEV_EXT_XD_CANCEL)==1&&host_ns<15001000000ULL&&!sides[0].link_failures&&!sides[1].link_failures);
 ok("P24 alternate valid callback delays ACK and withdraws at one second; C follows selected legal choices");

 local_success();consume(&sides[1],0);unsigned admissions=sides[1].session.gets;assert(sides[1].session.native_controls==1);
 sides[1].full_type=XDEV_EXT_XD_ACK;request_stop(&sides[1]);end_batch(&sides[1],0,0,false);drain_worker(6);
 assert(!sides[1].session.ss.inflight&&sides[1].session.native_controls==1&&!xdev_ext_mech_settled(&sides[1].session));
 assert(sides[1].session.gets==admissions&&!sides[1].session.worker_gone);
 sides[1].full_type=0;advance_ms(20);drain_worker(8);
 assert(sides[1].session.native_controls==0&&sides[1].session.puts==1&&sides[1].session.gets==admissions&&xdev_ext_mech_settled(&sides[1].session));
 assert(wire_count(&sides[1],XDEV_EXT_XD_ACK)==1);ok("P25 admitted final reply pins STOP through real last-reference/settle order, no post-STOP native_get");

 pair(0,2,8192);sides[0].complete_inline=sides[1].complete_inline=1;assert(!submit(&sides[1],0)&&!submit(&sides[0],0));drain_worker(12);
 assert(sides[0].posts==1&&sides[1].posts==1&&sides[1].batches[0].publishes==1);
 consume(&sides[1],0);end_batch(&sides[1],0,0,false);drain_worker(8);consume(&sides[0],0);done_success(&sides[0],0,1);
 assert(sides[0].batches[0].publishes==1&&sides[0].released_q1==2&&sides[1].released_q1==2&&!sides[0].released_q0&&!sides[1].released_q0);
 assert(sides[0].native_submits==1&&sides[1].native_submits==1&&sides[0].native_completes==1&&sides[1].native_completes==1);
 ok("P26 accepted post merges synchronous completion epoch, one post/publication and no unposted rollback");
}
/* U01/U02 independently derive from 4.7b unknown custody and 4.7c reply pins.
 * No link-down worker is delivered between unknown aggregate and assertions. */
static void uncertain_rx_reservation(void) {
 pair(0,2,8192);
 assert(!submit(&sides[1],0)&&!submit(&sides[1],1));
 assert(!submit(&sides[0],0)&&!submit(&sides[0],1));drain_worker(16);
 assert(sides[1].posts==1&&sides[1].session.native_controls==2);
 unsigned calls=protocol_calls;
 complete_group(&sides[1],0,-ECANCELED,false);
 assert(protocol_calls==calls&&sides[1].posts==1);
 run_worker_once(&sides[1]);
 fprintf(stderr,"U01 observations: RXposts=%u linkfail=%u admitted=%d puts=%u\n",sides[1].posts,sides[1].link_failures,sides[1].session.native_controls,sides[1].session.puts);
 assert(sides[1].posts==1);
 assert(sides[1].link_failures>0);
 assert(!sides[1].released_q1&&sides[1].session.native_controls>0);
 ok("U01 unknown RX aggregate retains posted-ring custody before down work and forbids a second RX post");
}
static void uncertain_rx_reply_pin(void) {
 posted();unsigned gets=sides[1].session.gets;
 assert(sides[1].session.native_controls==1&&!sides[1].session.puts);
 complete_group(&sides[1],0,-ECANCELED,false);drain_worker(8);
 assert(sides[1].batches[0].publishes==1&&sides[1].batches[0].sequester);
 consume(&sides[1],0);request_stop(&sides[1]);
 end_batch(&sides[1],0,sides[1].batches[0].status,true);drain_worker(8);
 fprintf(stderr,"U02 observations: admitted=%d puts=%u gets=%u FAIL=%u q0=%u q1=%u settled=%u\n",sides[1].session.native_controls,sides[1].session.puts,sides[1].session.gets,wire_count(&sides[1],XDEV_EXT_XD_FAIL),sides[1].released_q0,sides[1].released_q1,xdev_ext_mech_settled(&sides[1].session));
 assert(sides[1].session.gets==gets&&sides[1].session.native_controls==1&&!sides[1].session.puts);
 assert(!sides[1].released_q1&&sides[1].released_q0==2&&!xdev_ext_mech_settled(&sides[1].session));
 assert(sides[1].link_failures>0);
 ok("U02 unknown RX owner retains its original native-control pin through failed/sequestered chain and STOP");
}
/* The announced-RTS protocol window is separate from legal payload depth. */
static void bind_depth33(void) {
 fresh(0,0,33,65536,4096);int rc=bind_side(&sides[0]);
 fprintf(stderr,"B01 bind depth33/one4K: rc=%d attached=%u admitted=%u live=%u\n",rc,sides[0].endpoint_attaches,sides[0].admission_calls,sides[0].live);
 assert(rc==0&&stage_of(&sides[0])->priv);
 assert(sides[0].endpoint_attaches==1&&sides[0].admission_calls==1&&!sides[0].live&&!sides[0].posts&&!sides[0].wires&&!sides[0].session.native_controls);
 registered->unbind(stage_of(&sides[0]));
 assert(!stage_of(&sides[0])->priv&&sides[0].endpoint_detaches==1&&sides[0].admitted_unbind_priv&&!sides[0].live&&!sides[0].released_q0&&!sides[0].released_q1);
 ok("B01 depth33 one-element batches bind independently of the protocol window and unbind without leases");
}
static void bind_depth256(void) {
 fresh(0,0,256,65536,4096);int rc=bind_side(&sides[0]);
 fprintf(stderr,"B02 bind depth256/one4K: rc=%d attached=%u admitted=%u live=%u\n",rc,sides[0].endpoint_attaches,sides[0].admission_calls,sides[0].live);
 assert(rc==-EINVAL&&!stage_of(&sides[0])->priv);
 assert(!sides[0].endpoint_attaches&&!sides[0].endpoint_detaches&&!sides[0].admission_calls&&!sides[0].live&&!sides[0].posts&&!sides[0].wires&&!sides[0].session.native_controls);
 ok("B02 depth256 one-element batches fail the real ring budget before attaching or acquiring leases");
}
/* Root-owned regressions after independent author stopped; actual callbacks
 * and class operations, with no replacement transition algorithm. */
static void bind_progress_before_attachment(void) {
 fresh(0,0,2,65536,8192);early_bind_progress=true;
 int rc=bind_side(&sides[0]);early_bind_progress=false;
 assert(rc<=0&&!sides[0].posts&&!sides[0].live);
 assert(!xdev_ext_mech_session_admits(&sides[0].session));
 if(!rc)registered->unbind(stage_of(&sides[0]));
 assert(!stage_of(&sides[0])->priv);
 ok("B03 queued worker during endpoint bind cannot access an unpublished family link");
}
static void final_ack_is_monotone(void) {
 posted();struct xdev_ext_net_slot *slot=&family_of(&sides[0])->slots[0];
 u64 credit=family_of(&sides[0])->tx.credit;
 inject_message(&sides[0],XDEV_EXT_XD_ACK,slot->group,credit,0);drain_worker(8);
 assert(slot->remote==XDEV_EXT_NET_REMOTE_ACKED&&!sides[0].batches[0].publishes);
 inject_message(&sides[0],XDEV_EXT_XD_HELD,slot->group,credit,0);drain_worker(8);
 assert(slot->remote==XDEV_EXT_NET_REMOTE_ACKED);
 complete_batch(&sides[0],0,0,true);drain_worker(8);
 assert(sides[0].batches[0].publishes==1&&sides[0].batches[0].status==0);
 ok("U03 terminal remote ACK cannot regress to HELD before local completion");
}
static void final_refusal_forbids_repost(void) {
 for(unsigned kind=0;kind<2;kind++) {
  announced();u64 credit=family_of(&sides[0])->tx.credit;
  inject_message(&sides[0],XDEV_EXT_XD_FAIL,1,0,ECANCELED);
  inject_message(&sides[0],kind?XDEV_EXT_XD_ACK:XDEV_EXT_XD_CTS,1,credit,0);
  drain_worker(12);
  fprintf(stderr,"U04 kind=%u posts=%u submits=%u live=%u published=%u status=%d\n",kind,sides[0].posts,sides[0].native_submits,sides[0].live,sides[0].batches[0].publishes,sides[0].batches[0].status);
  assert(!sides[0].posts&&!sides[0].native_submits&&!sides[0].live);
  assert(!sides[0].batches[0].publishes||sides[0].batches[0].status<0);
 }
 ok("U04 final refusal cannot turn a queued CTS or ACK into native acceptance or success");
}
int main(void) {
 setvbuf(stdout,NULL,_IONBF,0);puts("TAP version 13");
 const char *selected=getenv("X5_CASE");
 if(selected){
  if(!strcmp(selected,"P19"))pressure_case();
  else if(!strcmp(selected,"U01"))uncertain_rx_reservation();
  else if(!strcmp(selected,"U02"))uncertain_rx_reply_pin();
  else if(!strcmp(selected,"B01"))bind_depth33();
  else if(!strcmp(selected,"B02"))bind_depth256();
  else if(!strcmp(selected,"B03"))bind_progress_before_attachment();
  else if(!strcmp(selected,"U03"))final_ack_is_monotone();
  else {assert(!strcmp(selected,"U04"));final_refusal_forbids_repost();}
  printf("1..%u\n",tap_number);assert(tap_number==1);return 0;
 }
 original_traces();policy_safety();uncertain_rx_reservation();uncertain_rx_reply_pin();bind_depth33();bind_depth256();bind_progress_before_attachment();final_ack_is_monotone();final_refusal_forbids_repost();printf("1..%u\n",tap_number);assert(tap_number==52);return 0;
}

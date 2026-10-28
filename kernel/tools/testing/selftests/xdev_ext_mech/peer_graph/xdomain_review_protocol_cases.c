/* SPDX-License-Identifier: GPL-2.0 */
/* Independent literal review-P oracles. Original tests remain unchanged. */
static void review_require(bool truth, const char *message)
{
 if (!truth) { fprintf(stderr, "REVIEW-P ASSERTION: %s\n", message); exit(1); }
}
static void review_current_window(void)
{
 pair(0,3,8192);happy_group(0);
 review_require(sides[1].posts==1&&family_of(&sides[1])->rx_rel_ready,"setup creates a real accepted and closed RX group");
}
static void review_withdraw(unsigned batch)
{
 review_require(!submit(&sides[0],batch),"later TX request must be admitted after previous refusal");
 drain_worker(6);advance_ms(15000);drain_worker(12);
}
static void review_reject_credit(void)
{
 review_current_window();
 u64 before=family_of(&sides[1])->rx_rel.credit;
 review_withdraw(1);
 struct wire_record *fail=last_wire(&sides[1],XDEV_EXT_XD_FAIL);
 fprintf(stderr,"reject_credit group=%llu before=%llu fail_credit=%llu rx_credit=%llu base=%llu tx_status=%d\n",
  (unsigned long long)fail->msg.group,(unsigned long long)before,(unsigned long long)fail->msg.credit,
  (unsigned long long)family_of(&sides[1])->rx_rel.credit,(unsigned long long)family_of(&sides[1])->rx_rel.base_group,sides[0].batches[1].status);
 review_require(fail->msg.credit==before+1,"REJECT_RTS FAIL advertises checked close of current in-window group");
 review_require(family_of(&sides[1])->rx_rel.credit==before+1,"successful rejection commits RX window close");
 review_require(sides[0].batches[1].publishes==1&&sides[0].batches[1].status<0,"refused TX reaches explicit group terminal error");
}
static void review_reject_ring_full(void)
{
 review_current_window();review_require(!submit(&sides[0],1),"setup admits group 2");drain_worker(6);
 u64 sequence=sides[1].link.chan[0].consumed,credit=family_of(&sides[1])->rx_rel.credit;
 sides[1].full_type=XDEV_EXT_XD_FAIL;advance_ms(15000);drain_worker(8);
 struct xdev_ext_xd_stage *rx=stage_of(&sides[1])->priv;
 fprintf(stderr,"ring_full seq_before=%llu seq_after=%llu pending=%u native_controls=%d\n",
  (unsigned long long)sequence,(unsigned long long)sides[1].link.chan[0].consumed,rx->rts_count,sides[1].session.native_controls);
 review_require(sides[1].link.chan[0].consumed==sequence,"failed FAIL enqueue must not consume request sequence");
 review_require(family_of(&sides[1])->rx_rel.credit==credit&&rx->rts_count==1&&sides[1].session.native_controls>0,"full control ring preserves input, window and native-control retry responsibility");
 sides[1].full_type=0;
 /* Clearing the external recorder's flag is not a native callback/new fact.
  * Reach the actual retained request wake before expecting a retry. */
 worker_depth=1;unsigned long retry_ms=registered->progress(stage_of(&sides[1]));worker_depth=0;
 review_require(retry_ms>0&&retry_ms*NSEC_PER_MSEC<=XD_TICK_NS,"full-ring refusal records a future bounded retry wake");
 advance_ms(retry_ms);drain_worker(12);
 review_require(sides[1].link.chan[0].consumed==sequence+2&&rx->rts_count==0,"retry consumes once after successful FAIL enqueue");
 review_require(!sides[1].session.native_controls&&!sides[0].link_failures&&!sides[1].link_failures,"successful retry discharges responsibility without shared link failure");
}
static void review_reject_33(void)
{
 review_current_window();
 for(unsigned n=1;n<=35;n++) {
  review_withdraw(n);
  review_require(sides[0].batches[n].publishes==1&&sides[0].batches[n].status<0,"each of 35 consecutive withdrawals terminalizes");
  consume(&sides[0],n);end_batch(&sides[0],n,sides[0].batches[n].status,false);drain_worker(4);
 }
 happy_group(36);
 review_require(!sides[0].link_failures&&!sides[1].link_failures,"35 rejected groups preserve live session for next native group");
}

/* A genuine core work item. The queue shim preserves pending immediate kicks;
 * it does not reinterpret any class return as a mandatory 20ms delay. */
static void review_core_once(struct side *side)
{
 review_require(!held_spinlocks&&!held_mutexes&&!callback_depth&&!worker_depth,"core worker starts outside callbacks/locks");
 side->session.progress_ready=true;side->session.progress_work.work.queued=0;side->session.queued=0;
 unsigned before=protocol_calls;worker_depth=1;
 xdev_ext_mech_progress_work(&side->session.progress_work.work);
 worker_depth=0;
 fprintf(stderr,"core_pass side=%td calls=%u pending=%u due=%llu now=%llu\n",side-sides,protocol_calls-before,
  side->session.progress_work.work.queued,(unsigned long long)side->session.progress_work.work.due,(unsigned long long)host_ns);
 review_require(protocol_calls-before<=XD_EVENTS,"one stage pass has bounded policy budget");
}
static void review_rx_end(unsigned batch,bool drop_ack)
{
 complete_batch(&sides[1],batch,0,true);drain_worker(8);consume(&sides[1],batch);
 if(drop_ack)sides[1].drop_type=XDEV_EXT_XD_ACK;
 end_batch(&sides[1],batch,0,false);drain_worker(8);
}
static void review_wait_three(void)
{
 pair(0,3,8192);
 review_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"setup accepts first native group");drain_worker(12);
 review_rx_end(0,true);
 review_require(!submit(&sides[1],1)&&!submit(&sides[0],1),"setup accepts second native group");drain_worker(12);
 review_rx_end(1,false);
 review_require(!submit(&sides[0],2),"third depth slot has an announced request");drain_worker(6);
 complete_batch(&sides[0],0,0,true);complete_batch(&sides[0],1,0,true);
 unsigned first_calls=protocol_calls;review_core_once(&sides[0]);
 review_require(protocol_calls-first_calls<=3,"one pass must not spend policy budget repeatedly on the same unchanged WAIT candidate");
 fprintf(stderr,"wait_three waiting_publish=%u runnable_publish=%u total_calls=%u\n",sides[0].batches[0].publishes,sides[0].batches[1].publishes,protocol_calls);
 review_require(!sides[0].batches[0].publishes,"local completion alone does not discharge missing remote ACK");
 review_require(sides[0].batches[1].publishes==1&&sides[0].batches[1].status==0,"WAIT on slot0 does not postpone runnable slot1 in the same bounded pass at depth3");
 /* With only waiting candidates left, another work item must not repeatedly
  * spend its full budget on unchanged WAIT before wake. */
 unsigned before=protocol_calls;review_core_once(&sides[0]);
 review_require(protocol_calls-before<=3,"unchanged WAIT candidates are each visited at most once per pass");
 inject_message(&sides[0],XDEV_EXT_XD_ACK,1,family_of(&sides[1])->rx_rel.credit,0);
 review_core_once(&sides[0]);
 review_require(sides[0].batches[0].publishes==1&&!sides[0].batches[0].status,"new remote ACK overrides prior WAIT wake immediately");

}
static void review_timer_local(void)
{
 pair(0,3,8192);review_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"setup native group");drain_worker(12);
 review_rx_end(0,true);
 review_require(!submit(&sides[0],1)&&!submit(&sides[0],2),"two nonaccepted TX announcements share depth3");drain_worker(6);
 complete_batch(&sides[0],0,0,true);advance_ms(15000);
 review_core_once(&sides[0]);
 fprintf(stderr,"timer_local cancel=%u local_pending=%u now=%llu\n",wire_count(&sides[0],XDEV_EXT_XD_CANCEL),!sides[0].batches[0].publishes,(unsigned long long)host_ns);
 review_require(wire_count(&sides[0],XDEV_EXT_XD_CANCEL)==2,"15s policy TIMER for other slots cannot be starved by persistent LOCAL WAIT");
 review_require(!sides[0].batches[0].publishes&&!sides[0].released_q0&&!sides[0].link_failures,"withdrawal of unrelated slots preserves native commitment");
}

static void review_timer_posted(void)
{
 pair(0,3,8192);review_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"setup native post without local callback");drain_worker(12);
 review_require(!submit(&sides[0],1)&&!submit(&sides[0],2),"two other announced slots");drain_worker(6);
 advance_ms(15000);review_core_once(&sides[0]);
 fprintf(stderr,"timer_posted cancel=%u posts=%u local_known=%u\n",wire_count(&sides[0],XDEV_EXT_XD_CANCEL),sides[0].posts,
  family_of(&sides[0])->slots[0].local_known);
 review_require(wire_count(&sides[0],XDEV_EXT_XD_CANCEL)==2,"15s policy TIMER cannot be starved by persistent native POST_RESULT WAIT");
 review_require(sides[0].posts==1&&!sides[0].batches[0].publishes&&!sides[0].released_q1,"posted native owner remains outstanding while unrelated requests withdraw");
}
static void review_preaccept_lease(void)
{
 pair(0,3,8192);sides[1].lease_error=-ENOMEM;
 review_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"real RX leases are acquired only after RTS");drain_worker(16);
 fprintf(stderr,"preaccept_lease fail=%u posts=%u rx_failures=%u rx_status=%d\n",wire_count(&sides[1],XDEV_EXT_XD_FAIL),total_posts(),sides[1].link_failures,sides[1].batches[0].status);
 review_require(!sides[0].link_failures&&!sides[1].link_failures,"lease refusal before native post remains a group error");
 review_require(wire_count(&sides[1],XDEV_EXT_XD_FAIL)==1&&!total_posts()&&!sides[1].live&&!sides[1].released_q0,"preaccept lease refusal owes FAIL without UNKNOWN/native owner");
 review_require(sides[1].batches[0].publishes==1&&sides[1].batches[0].status==-ENOMEM&&!sides[1].batches[0].sequester,"lease refusal terminalizes RX truthfully");
}

static void review_preaccept_rx(void)
{
 pair(1,3,8192);
 /* Real reverse-direction endpoints use the same links. They have no native
  * work here, so no fabricated opposite-direction completion is introduced. */
 struct xdev_ext_mech_stage *reverse_rx=&sides[0].session.st[0],*reverse_tx=&sides[1].session.st[1];
 *reverse_rx=(struct xdev_ext_mech_stage){.s=&sides[0].session,.cls=registered,.file=&authority,.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.index=0,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE};
 *reverse_tx=(struct xdev_ext_mech_stage){.s=&sides[1].session,.cls=registered,.file=&authority,.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.index=1,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_stage_uapi rx={.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.direction=reverse_rx->direction,.arg0=sides[0].link.token};
 struct xdev_ext_mech_stage_uapi tx={.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.direction=reverse_tx->direction,.arg0=sides[1].link.token};
 review_require(!registered->bind(reverse_rx,&rx)&&!registered->bind(reverse_tx,&tx),"reverse sessions attach to the real shared endpoints");
 sides[1].post_error=-ENOMEM;
 review_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"setup sends a real RTS to an armed RX");drain_worker(16);
 fprintf(stderr,"preaccept_rx fail=%u posts=%u failures=%u/%u rx_status=%d tx_status=%d\n",wire_count(&sides[1],XDEV_EXT_XD_FAIL),total_posts(),sides[0].link_failures,sides[1].link_failures,sides[1].batches[0].status,sides[0].batches[0].status);
 review_require(!sides[0].link_failures&&!sides[1].link_failures,"all-or-none RX post refusal before native acceptance must not fail shared link");
 review_require(wire_count(&sides[1],XDEV_EXT_XD_FAIL)==1&&!total_posts(),"preaccept refusal sends group FAIL without native acceptance");
 review_require(sides[1].batches[0].publishes==1&&sides[1].batches[0].status==-ENOMEM&&!sides[1].batches[0].sequester,"preaccept RX gets truthful nonsequestered group error");
 review_require(sides[0].batches[0].publishes==1&&sides[0].batches[0].status<0&&!sides[0].batches[0].sequester,"preaccept FAIL terminalizes peer TX");
 review_require(!((struct xdev_ext_xd_stage*)reverse_rx->priv)->ns.dead&&!((struct xdev_ext_xd_stage*)reverse_tx->priv)->ns.dead,
  "other direction stages stay live after preaccept refusal");
 review_require(!((struct xdev_ext_xd_ep*)((struct xdev_ext_xd_stage*)reverse_rx->priv)->ns.lk)->detached&&
  !((struct xdev_ext_xd_ep*)((struct xdev_ext_xd_stage*)reverse_tx->priv)->ns.lk)->detached,"reverse endpoints remain attached");
 /* Finish the refused pair before selecting the already-bound reverse pair as
  * each host's active fixture view. Endpoint/stage/session objects stay intact;
  * only the fixture's direction-dependent external lease recorder view changes.
  * Both subsequent native posts and all completions are real class functions. */
 consume(&sides[1],0);end_batch(&sides[1],0,sides[1].batches[0].status,false);
 consume(&sides[0],0);end_batch(&sides[0],0,sides[0].batches[0].status,false);
 sides[1].post_error=0;sides[0].session.nr_stages=1;sides[1].session.nr_stages=2;
 review_require(!submit(&sides[0],1)&&!submit(&sides[1],1),"reverse direction admits batches after failed RX group");drain_worker(16);
 review_require(sides[0].posts==1&&sides[1].posts==1,"reverse direction reaches actual native acceptance on same shared links");
 complete_batch(&sides[0],1,0,true);complete_batch(&sides[1],1,0,true);drain_worker(12);
 consume(&sides[0],1);end_batch(&sides[0],1,0,false);drain_worker(12);
 consume(&sides[1],1);end_batch(&sides[1],1,0,false);drain_worker(8);
 review_require(sides[0].batches[1].publishes==1&&!sides[0].batches[1].status&&sides[1].batches[1].publishes==1&&!sides[1].batches[1].status,
  "reverse direction completes successfully after original preaccept refusal");
 review_require(!sides[0].link_failures&&!sides[1].link_failures,"preaccept failure and reverse success share the original live links");

}
static void review_old_cancel(void)
{
 pair(0,3,8192);review_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"setup posted group");drain_worker(12);
 struct xdev_ext_xd_stage *rx=stage_of(&sides[1])->priv;
 struct xdev_ext_xd_msg stale={.type=XDEV_EXT_XD_CANCEL,.stream=rx->stream+999,.group=1,
  .src_inc=sides[0].link.local_inc,.dst_inc=sides[1].link.local_inc};
 u64 epoch=rx->epoch,credit=rx->ns.rx_rel.credit;unsigned puts=sides[1].session.puts,wires=sides[1].wires;
 xdev_ext_xd_class_ctl(stage_of(&sides[1]),&stale);
 review_require(rx->epoch==epoch&&rx->ctl_count==0,"old-stream CANCEL must be rejected before it mutates the current group reply");
 drain_worker(8);
 review_require(rx->ns.rx_rel.credit==credit&&sides[1].session.puts==puts&&sides[1].wires==wires,"old CANCEL cannot advertise/release current native group");
}
static void review_accepted_cancel(void)
{
 pair(0,3,8192);review_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"setup accepted RX/TX");drain_worker(12);
 unsigned rx_posts=sides[1].posts,rx_puts=sides[1].session.puts,released=sides[1].released_q1;
 u64 credit=family_of(&sides[1])->rx_rel.credit;
 inject_message(&sides[1],XDEV_EXT_XD_CANCEL,1,0,0);drain_worker(10);
 inject_message(&sides[1],XDEV_EXT_XD_CANCEL,1,0,0);drain_worker(10);
 review_require(sides[1].posts==rx_posts&&!wire_count(&sides[1],XDEV_EXT_XD_FAIL),"accepted CANCEL replays CTS without a second native post or pre-CTS FAIL");
 review_require(family_of(&sides[1])->rx_rel.credit==credit&&sides[1].session.puts==rx_puts&&sides[1].released_q1==released,"duplicate accepted CANCEL does not close credit or release native owner");
 complete_batch(&sides[1],0,-ECANCELED,false);drain_worker(10);
 review_require(sides[1].batches[0].publishes==1&&sides[1].batches[0].sequester&&sides[1].released_q1==released&&sides[1].session.native_controls>0,
  "UNKNOWN accepted RX retains quarantine and native-control obligation");
}




static void review_reverse_shared(void)
{
 pair(1,3,8192);
 struct xdev_ext_mech_stage *rx=&sides[0].session.st[0],*tx=&sides[1].session.st[1];
 *rx=(struct xdev_ext_mech_stage){.s=&sides[0].session,.cls=registered,.file=&authority,.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.index=0,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE};
 *tx=(struct xdev_ext_mech_stage){.s=&sides[1].session,.cls=registered,.file=&authority,.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.index=1,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_stage_uapi ru={.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.direction=rx->direction,.arg0=sides[0].link.token};
 struct xdev_ext_mech_stage_uapi tu={.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.direction=tx->direction,.arg0=sides[1].link.token};
 review_require(!registered->bind(rx,&ru)&&!registered->bind(tx,&tu),"reverse setup binds real shared-link endpoints");
 sides[0].session.nr_stages=1;sides[1].session.nr_stages=2;
 review_require(!submit(&sides[0],1)&&!submit(&sides[1],1),"reverse direction batches admit");drain_worker(16);
 review_require(sides[0].posts==1&&sides[1].posts==1,"real reverse native posts recorded");
 complete_batch(&sides[0],1,0,true);complete_batch(&sides[1],1,0,true);drain_worker(12);
 consume(&sides[0],1);end_batch(&sides[0],1,0,false);drain_worker(12);
 consume(&sides[1],1);end_batch(&sides[1],1,0,false);drain_worker(8);
 review_require(sides[0].batches[1].publishes==1&&!sides[0].batches[1].status&&sides[1].batches[1].publishes==1&&!sides[1].batches[1].status,
  "reverse shared-link fixture reaches genuine success without rewriting protocol decisions");
}

static void review_reject_duplicate(void)
{
 review_current_window();review_withdraw(1);
 struct xdev_ext_xd_stage *rx=stage_of(&sides[1])->priv;
 struct xdev_ext_xd_msg replay=sides[0].wire[1].msg;
 review_require(replay.type==XDEV_EXT_XD_RTS&&replay.group==2,"replay is exact prior RTS, not fabricated sequence");
 u64 sequence=sides[1].link.chan[0].consumed,credit=rx->ns.rx_rel.credit;
 unsigned puts=sides[1].session.puts,posts=sides[1].posts;
 xdev_ext_xd_class_ctl(stage_of(&sides[1]),&replay);
 struct xdev_ext_xd_msg cancel=replay;cancel.type=XDEV_EXT_XD_CANCEL;
 xdev_ext_xd_class_ctl(stage_of(&sides[1]),&cancel);drain_worker(10);
 fprintf(stderr,"reject_duplicate seq=%llu credit=%llu fails=%u puts=%u/%u\n",(unsigned long long)sides[1].link.chan[0].consumed,
  (unsigned long long)rx->ns.rx_rel.credit,sides[1].link_failures,puts,sides[1].session.puts);
 review_require(!sides[1].link_failures,"duplicate rejected RTS/CANCEL cannot turn closed group into link failure");
 review_require(sides[1].link.chan[0].consumed==sequence&&rx->ns.rx_rel.credit==credit,"duplicate rejected group cannot consume or return credit twice");
 review_require(sides[1].posts==posts&&sides[1].session.native_controls==0,"duplicate rejection neither native-posts nor leaks control admission");
}

static void review_core_self_kick(void)
{
 pair(0,2,8192);review_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"setup posted native group");drain_worker(10);
 complete_batch(&sides[1],0,0,true);review_core_once(&sides[1]);
 review_require(sides[1].batches[0].publishes==1,"real worker publishes completed RX");
 review_require(sides[1].session.progress_work.work.queued&&sides[1].session.progress_work.work.due==host_ns,
  "actual core queue preserves immediate self-kick caused by publication");
 review_core_once(&sides[1]);
 review_require(sides[1].session.progress_work.work.due>host_ns,"without new facts the next work item is delayed");
}

int main(int argc,char **argv)
{
 review_require(argc==2,"select one case");
 if(!strcmp(argv[1],"reject_credit"))review_reject_credit();
 else if(!strcmp(argv[1],"reject_ring_full"))review_reject_ring_full();
 else if(!strcmp(argv[1],"reject_33"))review_reject_33();
 else if(!strcmp(argv[1],"wait_three"))review_wait_three();
 else if(!strcmp(argv[1],"timer_local"))review_timer_local();
 else if(!strcmp(argv[1],"timer_posted"))review_timer_posted();
 else if(!strcmp(argv[1],"preaccept_lease"))review_preaccept_lease();
 else if(!strcmp(argv[1],"preaccept_rx"))review_preaccept_rx();
 else if(!strcmp(argv[1],"old_cancel"))review_old_cancel();
 else if(!strcmp(argv[1],"accepted_cancel"))review_accepted_cancel();
 else if(!strcmp(argv[1],"core_self_kick"))review_core_self_kick();
 else if(!strcmp(argv[1],"reject_duplicate"))review_reject_duplicate();
 else if(!strcmp(argv[1],"reverse_shared"))review_reverse_shared();
 else {fprintf(stderr,"unknown case: %s\n",argv[1]);return 2;}
 return 0;
}

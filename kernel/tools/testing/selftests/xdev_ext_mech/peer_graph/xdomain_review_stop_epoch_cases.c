/* SPDX-License-Identifier: GPL-2.0 */
/* Registry pointer updates and all key admission/STOP/worker/class bodies are
 * actual production source. The RCU grace-period boundary gives a deterministic
 * schedule to a worker that is legal on another CPU after publication removal. */
static void stop_epoch_require(bool yes,const char *why)
{if(!yes){fprintf(stderr,"STOP EPOCH ASSERTION: %s\n",why);exit(1);}}
static u64 first_closed;
static void stop_epoch_setup(void)
{
 pair(0,3,8192);host_ns=100000000000ULL;
 stop_epoch_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"real pair admits before registry retraction");drain_worker(16);
 stop_epoch_require(sides[0].posts==1&&sides[1].posts==1,"both endpoints hold native ownership");
 struct xdev_ext_mech_session *s=&sides[1].session;
 s->ops[XDEV_EXT_MECH_CLASS_XDOMAIN]=registered;s->pinned[XDEV_EXT_MECH_CLASS_XDOMAIN]=true;
 stop_epoch_registry_slots[XDEV_EXT_MECH_CLASS_XDOMAIN]=registered;xdev_ext_mech_registry.nr_active=1;
 xdev_ext_mech_all.next=xdev_ext_mech_all.prev=&s->all_node;
 s->all_node.next=s->all_node.prev=&xdev_ext_mech_all;
 stop_epoch_require(xdev_ext_mech_session_admits(s)&&xdev_ext_mech_session_stop_started_ns(s)==0,"actual accessors report registered ACTIVE and no STOP publication");
}
static void stop_epoch_observe_gap(void)
{
 struct xdev_ext_mech_session *s=&sides[1].session;
 stop_epoch_require(s->ss.state==XDEV_EXT_MECH_SESSION_ACTIVE&&!xdev_ext_mech_session_admits(s),"actual retract closes admission while core state is still ACTIVE");
 stop_epoch_require(xdev_ext_mech_session_stop_started_ns(s)==0,"actual locked accessor has no STOP timestamp during grace period");
 first_closed=host_ns;review_core_once(&sides[1]);
 struct xdev_ext_xd_stage *xs=stage_of(&sides[1])->priv;
 fprintf(stderr,"STOP gap observed=%llu actual_stop=%llu class_stop=%llu latched=%u failures=%u publications=%u\n",(unsigned long long)first_closed,(unsigned long long)xdev_ext_mech_session_stop_started_ns(s),(unsigned long long)xs->stop_ns,xs->stop_latched,sides[1].link_failures,sides[1].batches[0].publishes);
 stop_epoch_require(!sides[1].link_failures&&!sides[1].batches[0].publishes&&!sides[1].released_q1,"registry withdrawal must not use unpublished zero to instantly timeout/abandon native owner");
 stop_epoch_require(host_ns==first_closed,"observation does not move test time");
}
static void stop_epoch_gap_only(void)
{
 stop_epoch_setup();host_ns+=500000000ULL;stop_epoch_rcu_hook=stop_epoch_observe_gap;
 xdev_ext_mech_unreg(XDEV_EXT_MECH_CLASS_XDOMAIN,(void *)registered);
 stop_epoch_require(stop_epoch_rcu_calls==1&&!held_spinlocks&&!held_mutexes,"actual retract grace period and generation notifier complete");
 stop_epoch_require(sides[1].session.ss.state==XDEV_EXT_MECH_SESSION_STOPPING&&xdev_ext_mech_session_stop_started_ns(&sides[1].session)==first_closed,"actual generation_gone publishes real STOP at the observed time");
}
static bool near_native_hard;
static void stop_epoch_late_hook(void)
{
 stop_epoch_observe_gap();host_ns+=200000000ULL;
}
static void stop_epoch_late(void)
{
 stop_epoch_setup();host_ns=near_native_hard?129500000000ULL:100500000000ULL;
 stop_epoch_rcu_hook=stop_epoch_late_hook;xdev_ext_mech_unreg(XDEV_EXT_MECH_CLASS_XDOMAIN,(void *)registered);
 u64 published=xdev_ext_mech_session_stop_started_ns(&sides[1].session);
 stop_epoch_require(published==first_closed,"class publishes real STOP at first observed closure; delayed generation notification cannot move its timestamp");
 u64 deadline=near_native_hard?130000000000ULL:101500000000ULL;
 host_ns=deadline-1000000ULL;review_core_once(&sides[1]);
 stop_epoch_require(!sides[1].link_failures&&!sides[1].batches[0].publishes,"native owner keeps its bounded grace before the earlier immutable deadline");
 host_ns=deadline;review_core_once(&sides[1]);
 stop_epoch_require(sides[1].link_failures&&sides[1].batches[0].publishes==1&&sides[1].batches[0].status<0&&sides[1].batches[0].sequester,"later real STOP cannot extend first-observed grace or original native deadline");
 stop_epoch_require(!sides[1].released_q1,"deadline does not prove UNKNOWN native owner quiescent");
}
static void stop_epoch_zero(void)
{
 pair(0,3,8192);host_ns=0;
 stop_epoch_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"boot-time pair submits");drain_worker(16);
 xdev_ext_mech_session_stop(&sides[1].session,0);
 stop_epoch_require(sides[1].session.ss.state==XDEV_EXT_MECH_SESSION_STOPPING&&xdev_ext_mech_session_stop_started_ns(&sides[1].session)==0,"actual zero timestamp is a published STOP, distinguished by session state");
 host_ns=500000000ULL;review_core_once(&sides[1]);
 stop_epoch_require(!sides[1].link_failures&&!sides[1].batches[0].publishes,"real boot-time STOP keeps its first half-second grace");
 host_ns=1000000000ULL;review_core_once(&sides[1]);
 stop_epoch_require(sides[1].link_failures&&sides[1].batches[0].publishes==1&&sides[1].batches[0].sequester&&!sides[1].released_q1,"valid zero STOP retains its real one-second bound and UNKNOWN custody");
}
static void stop_epoch_overdue_armed(void)
{
 pair(0,3,8192);stop_epoch_require(!submit(&sides[1],0),"RX arms before RTS");advance_ms(30000);
 stop_epoch_require(!submit(&sides[0],0),"new RTS arrives exactly at old ARMED hard deadline");deliver_wire_once(&sides[0]);
 u64 seq=sides[1].link.chan[0].consumed;review_core_once(&sides[1]);
 struct xdev_ext_xd_stage *xs=stage_of(&sides[1])->priv;
 stop_epoch_require(sides[1].batches[0].publishes==1&&sides[1].batches[0].status==-ETIMEDOUT&&!sides[1].batches[0].sequester,"overdue ARMED ends truthfully without native ownership");
 stop_epoch_require(!sides[1].link_failures&&!sides[1].posts&&xs->rts_count==1&&sides[1].link.chan[0].consumed==seq,"deadline selection preserves independent queued RTS and healthy link");
 stop_epoch_require(!submit(&sides[1],1),"fresh RX can arm for retained RTS");drain_worker(16);
 stop_epoch_require(sides[1].posts==1&&sides[0].posts==1&&!sides[1].link_failures,"retained RTS reaches exactly one native pair on fresh ARMED slot");
}
static void stop_epoch_normal_reason(void)
{
 pair(0,3,8192);host_ns=0;
 stop_epoch_require(!submit(&sides[1],0)&&!submit(&sides[0],0),"zero-time pair submits before normal STOP");drain_worker(16);
 xdev_ext_mech_session_stop(&sides[1].session,0);
 stop_epoch_require(sides[1].session.ss.state==XDEV_EXT_MECH_SESSION_STOPPING&&xdev_ext_mech_session_stop_started_ns(&sides[1].session)==0,"real normal STOP publishes genuine zero timestamp");
 for(unsigned n=1;n<=3;n++) {
  host_ns=n*100000000ULL;review_core_once(&sides[1]);
  stop_epoch_require(!sides[1].session.stop_err&&!sides[1].session.last_err,"repeated class progress must not turn normal STOP into ECANCELED error");
  stop_epoch_require(xdev_ext_mech_session_stop_started_ns(&sides[1].session)==0&&!sides[1].link_failures&&!sides[1].batches[0].publishes,"progress preserves real STOP0 timestamp and native grace");
  if(n>1)stop_epoch_require(!sides[1].session.stop_work.queued,"latched class STOP cannot requeue core stop_work on every progress pass");
  sides[1].session.stop_work.queued=0;
 }
 xdev_ext_mech_session_stop(&sides[1].session,-ECANCELED);
 stop_epoch_require(sides[1].session.stop_err==-ECANCELED&&sides[1].session.last_err==-ECANCELED&&xdev_ext_mech_session_stop_started_ns(&sides[1].session)==0,"subsequent real cancellation records its error without moving first STOP timestamp");
}
int main(int argc,char **argv)
{
 stop_epoch_require(argc==2,"one case required");
 if(!strcmp(argv[1],"withdrawal_gap"))stop_epoch_gap_only();
 else if(!strcmp(argv[1],"late_stop"))stop_epoch_late();
 else if(!strcmp(argv[1],"near_hard")){near_native_hard=true;stop_epoch_late();}
 else if(!strcmp(argv[1],"stop_zero"))stop_epoch_zero();
 else if(!strcmp(argv[1],"overdue_armed"))stop_epoch_overdue_armed();
 else if(!strcmp(argv[1],"normal_stop_reason"))stop_epoch_normal_reason();
 else return 2;
 printf("ok - STOP epoch %s\n",argv[1]);return 0;
}

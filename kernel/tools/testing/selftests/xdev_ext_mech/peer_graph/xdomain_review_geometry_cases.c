/* SPDX-License-Identifier: GPL-2.0 */
/* Requirements come from the author's P0 short-tail and elapsed-WAIT report.
 * All policy/class/family bodies are actual source. External time/native memory
 * boundaries are the existing fixture. No previous case/oracle is modified. */
static void p0_require(bool yes, const char *why)
{ if (!yes) { fprintf(stderr,"P0 ASSERTION: %s\n",why); exit(1); } }
static int p0_submit_layout(struct side *side, unsigned bytes)
{
 struct xdev_ext_mech_batch *b=prepare_raw(side,0);
 b->nr=bytes>65536?2:1;
 for(unsigned n=0;n<b->nr;n++) {
  unsigned len=n?bytes-65536:(bytes<65536?bytes:65536);
  b->f[n]=(struct xdev_ext_mech_frame){.umem_addr=(u64)n*65536,.index=n,.data_len=len};
 }
 u8 scratch[32*64]={0};
 p0_require(!registered->default_build(stage_of(side),b,scratch),"real descriptor builder accepts legal tail");
 p0_require(!registered->validate(stage_of(side),b,scratch,b->nr),"real descriptor validator accepts legal tail");
 worker_depth=1;int ret=registered->submit(stage_of(side),b);worker_depth=0;
 if(!ret)side->session.ss.inflight++;
 return ret;
}
static void p0_tail(unsigned bytes, unsigned elements)
{
 fresh(0,0,3,65536,bytes);
 sides[0].session.l.seg_len=sides[1].session.l.seg_len=65536;
 p0_require(!bind_side(&sides[0])&&!bind_side(&sides[1]),"short-tail layout passes real class bind");
 p0_require(!p0_submit_layout(&sides[1],bytes)&&!p0_submit_layout(&sides[0],bytes),"legal short-tail pair submits");
 struct wire_record *rts=last_wire(&sides[0],XDEV_EXT_XD_RTS);
 p0_require(rts->msg.total_len==bytes&&rts->msg.count==elements,"wire count is literal exact tail count, not ring upper bound");
 drain_worker(16);
 fprintf(stderr,"P0 tail bytes=%u seg=65536 RTS_count=%u RX_posts=%u TX_posts=%u failures=%u/%u last_want_count=%u\n",bytes,rts->msg.count,sides[1].posts,sides[0].posts,sides[0].link_failures,sides[1].link_failures,last_snapshot.want_count);
 p0_require(!sides[0].link_failures&&!sides[1].link_failures&&sides[0].posts==1&&sides[1].posts==1,"valid short tail must reach native acceptance on both endpoints");
 p0_require(sides[0].post[0].count==elements&&sides[1].post[0].count==elements,"native descriptor arrays preserve exact count");
 complete_batch(&sides[1],0,0,true);complete_batch(&sides[0],0,0,true);drain_worker(12);
 consume(&sides[1],0);end_batch(&sides[1],0,0,false);drain_worker(12);
 consume(&sides[0],0);end_batch(&sides[0],0,0,false);drain_worker(8);
 p0_require(sides[0].batches[0].publishes==1&&!sides[0].batches[0].status&&sides[1].batches[0].publishes==1&&!sides[1].batches[0].status,"legal short tail ends with exact successful CQEs");
 p0_require(!sides[0].live&&!sides[1].live&&!sides[0].released_q0&&!sides[1].released_q0,"all accepted tail elements retire proven quiescent");
}
static void p0_snapshot_wait(struct xdev_ext_xd_stage **out,struct xdev_ext_xdomain_proto_info *i,struct xdev_ext_xdomain_proto_result *v)
{
 pair(0,3,8192);p0_require(!submit(&sides[0],0),"announced sender starts before remote response");
 struct xdev_ext_xd_stage *xs=stage_of(&sides[0])->priv;unsigned long flags;
 spin_lock_irqsave(&xs->ns.lock,flags);xd_snapshot(xs,&xs->ns.slots[0],NULL,XDEV_EXT_XDP_EV_TIMER,false,false,i);spin_unlock_irqrestore(&xs->ns.lock,flags);
 worker_depth=1;int ret=xdev_ext_xd_protocol_call(xs,i,v);worker_depth=0;
 p0_require(!ret&&i->now_ns==1000000&&v->verdict.action==XDEV_EXT_XDP_ACT_WAIT&&v->verdict.wake_ns==21000000,"actual reference policy generates snapshot-valid 1ms to 21ms WAIT");
 p0_require(i->policy_deadline_ns==15001000000ULL,"ordinary withdrawal deadline remains far beyond elapsed tick wake");
 *out=xs;
}
static void p0_elapsed_wait(void)
{
 struct xdev_ext_xd_stage *xs;struct xdev_ext_xdomain_proto_info i;struct xdev_ext_xdomain_proto_result v;
 p0_snapshot_wait(&xs,&i,&v);host_ns=22000000;
 int ret=xdev_ext_xd_apply(xs,&i,&v.verdict);
 fprintf(stderr,"P0 elapsed WAIT snapshot=%llu wake=%llu apply=%llu hard=%llu policy=%llu ret=%d\n",(unsigned long long)i.now_ns,(unsigned long long)v.verdict.wake_ns,(unsigned long long)host_ns,(unsigned long long)i.hard_deadline_ns,(unsigned long long)i.policy_deadline_ns,ret);
 p0_require(ret==-ESTALE,"snapshot-valid WAIT whose wake elapsed before apply requires ESTALE and re-snapshot");
 unsigned long flags;spin_lock_irqsave(&xs->ns.lock,flags);xd_snapshot(xs,&xs->ns.slots[0],NULL,XDEV_EXT_XDP_EV_TIMER,false,false,&i);spin_unlock_irqrestore(&xs->ns.lock,flags);
 worker_depth=1;ret=xdev_ext_xd_protocol_call(xs,&i,&v);worker_depth=0;
 p0_require(!ret&&!xdev_ext_xd_apply(xs,&i,&v.verdict),"fresh actual BPF snapshot can WAIT normally without lost announcement");
 p0_require(sides[0].wires==1&&!sides[0].posts&&!sides[0].batches[0].publishes&&!sides[0].link_failures,"stale WAIT has no payload/sequence/publication/link side effect");
}
static void p0_invalid_wait(void)
{
 /* Each value is illegal at the snapshot, even if apply happens later. */
 for(unsigned n=0;n<5;n++) {
  struct xdev_ext_xd_stage *xs;struct xdev_ext_xdomain_proto_info i;struct xdev_ext_xdomain_proto_result v;
  p0_snapshot_wait(&xs,&i,&v);
  v.verdict.wake_ns=n==0?0:n==1?i.now_ns:n==2?i.now_ns-1:n==3?21000001ULL:i.hard_deadline_ns+1;
  host_ns=22000000;
  int ret=xdev_ext_xd_apply(xs,&i,&v.verdict);
  fprintf(stderr,"P0 invalid WAIT variant=%u snapshot=%llu wake=%llu apply=%llu ret=%d\n",n,(unsigned long long)i.now_ns,(unsigned long long)v.verdict.wake_ns,(unsigned long long)host_ns,ret);
  p0_require(ret==-EPROTO,"WAIT illegal when produced must remain EPROTO after elapsed apply time");
 }
}
static void p0_hard_timeout(void)
{
 posted();unsigned released=sides[1].released_q1;advance_ms(30000);drain_worker(16);
 p0_require(sides[0].link_failures+sides[1].link_failures>0,"real native hard deadline still terminates link");
 p0_require(sides[1].batches[0].publishes==1&&sides[1].batches[0].status<0&&sides[1].batches[0].sequester,"hard timeout cannot turn UNKNOWN into success or quiescence");
 p0_require(sides[1].released_q1==released,"unknown native tail ownership is not released at timeout");
}
int main(int argc,char **argv)
{
 p0_require(argc==2,"one independent P0 case required");
 if(!strcmp(argv[1],"tail8192"))p0_tail(8192,2);
 else if(!strcmp(argv[1],"tail69632"))p0_tail(69632,17);
 else if(!strcmp(argv[1],"elapsed_wait"))p0_elapsed_wait();
 else if(!strcmp(argv[1],"invalid_wait"))p0_invalid_wait();
 else if(!strcmp(argv[1],"hard_timeout"))p0_hard_timeout();
 else return 2;
 printf("ok - P0 %s\n",argv[1]);return 0;
}

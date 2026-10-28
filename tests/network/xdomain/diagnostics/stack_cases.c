/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_nhi_cases.c"
#include <linux/xdev_ext_requester_retention.h>
int stack_diag_query(struct stack_world *,unsigned,struct xdev_ext_mech_stage_diag *);
void stack_diag_arm(struct stack_world *,unsigned,unsigned,unsigned);
void stack_diag_join(void);
void stack_diag_observe(struct stack_world *,unsigned,unsigned *,unsigned *,struct xdev_ext_requester_retention_stats *);
int stack_diag_fill_controls(struct stack_world *,unsigned);
static struct xdev_ext_mech_stage_diag query(struct stack_world*w,unsigned e)
{
 struct xdev_ext_mech_stage_diag d={0};
 CHECK(!stack_diag_query(w,e,&d),"actual class to link to NHI to ledger query");
 unsigned in,q;struct xdev_ext_requester_retention_stats r;
 stack_diag_observe(w,e,&in,&q,&r);
 CHECK(d.native_inflight==in&&d.software_pending==q,"native snapshot equals actual accepted lists/descriptors");
 CHECK(d.retention.reserved_bytes==r.reserved_bytes&&d.retention.retained_bytes==r.retained_bytes&&d.retention.generations==r.generations,"actual requester mapping/generation reservations");
 CHECK((d.valid&63)==(e?63:59),"all six diagnostic families explicitly valid");
 return d;
}
static void cts_capacity(void)
{
 struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
 fault(w,STACK_FAULT_HOLD_CONTROL,1,3,0,1,0);
 CHECK(stack_diag_fill_controls(w,1)==128,"real accepted ACK frames fill receiver control capacity");
 start(w,c.first_seq,0);pump(w,1000000);
 struct xdev_ext_mech_stage_diag posted=query(w,1);
 CHECK(posted.cts_owed==1&&posted.rx_native_posted==4&&!posted.ctl_tx_free,"real preposted RX retains CTS obligation while control storage exhausted");
 CHECK(count(w,STACK_EV_DATA_POST,0,-1)==0,"sender cannot post data before actual CTS accepted");
 fault(w,STACK_FAULT_RELEASE_CONTROLS,1,3,0,0,0);
 pump(w,0);pump(w,20000000);
 posted=query(w,1);CHECK(!posted.cts_owed&&!posted.rx_native_posted&&posted.ctl_tx_free==128,"real callbacks restore control capacity and discharge CTS");
 release_group(w,c.first_seq);addresses(w,&c);nhi_descriptors(w,&c,1);wire(w,1);wire(w,2);wire(w,3);safety(w);stack_destroy(w);
}
static void pending_release(void)
{
 struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
 start(w,c.first_seq,0);pump(w,1000000);
 struct xdev_ext_mech_stage_diag before=query(w,1);
 struct stack_stage_facts facts=stage_facts(w,1,0);
 fprintf(stderr,"DIAG before release rx=%u cts=%u wait=%u down=%u slot_busy=%u known=%u quiesced=%u reply_native=%u final=%u chain=%u pub=%zu release=%zu\n",before.rx_native_posted,before.cts_owed,before.final_waiting_chain,before.downstream_release_pending,facts.slot_busy,facts.slot_local_known,facts.slot_local_quiesced,facts.reply_native_posted,facts.reply_final,facts.reply_chain_done,count(w,STACK_EV_PUBLISH,1,-1),count(w,STACK_EV_BATCH_RELEASE,1,-1));
 CHECK(!before.native_inflight&&!before.software_pending,"real data descriptors all complete");
 CHECK(before.downstream_release_pending==1&&before.final_waiting_chain==1&&before.ack_owed==0,"successful RX retains downstream responsibility after CQE and before real release");
 CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==0,"no ACK before chain release");
 CHECK(!stack_release(w,1,c.first_seq),"real downstream chain release without pumping");
 struct xdev_ext_mech_stage_diag owed=query(w,1);
 CHECK(owed.ack_owed==1&&!owed.downstream_release_pending&&!owed.final_waiting_chain,"release moves responsibility to real owed ACK before send");
 pump(w,1000000);
 struct xdev_ext_mech_stage_diag after=query(w,1);
 CHECK(!after.final_waiting_chain&&!after.downstream_release_pending&&!after.ack_owed&&!after.fail_owed&&!after.cts_owed,"real release and control callbacks discharge protocol responsibility");
 CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1&&count(w,STACK_EV_PUBLISH,1,-1)==1,"both actual CQEs exactly once");
 addresses(w,&c);nhi_descriptors(w,&c,1);wire(w,1);wire(w,2);wire(w,3);safety(w);stack_destroy(w);
}
static void ack_decrement(void)
{
 struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
 start(w,c.first_seq,0);pump(w,1000000);
 CHECK(!stack_release(w,1,c.first_seq),"actual chain release after successful native completion");
 struct xdev_ext_mech_stage_diag d=query(w,1);
 CHECK(d.ack_owed==1&&!d.downstream_release_pending,"real release creates one owed ACK before any control send");
 pump(w,1000000);d=query(w,1);
 CHECK(!d.ack_owed&&!d.cts_owed&&!d.fail_owed&&!d.final_waiting_chain&&!d.downstream_release_pending,"actual SEND_ACK discharges all reply responsibilities");
 CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==1,"one real ACK accepted by native ring");
 uint64_t id=first(w,STACK_EV_CONTROL_TX,1,3);struct stack_event ack=ev(w,id-1);unsigned done=0;
 for(size_t i=id;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_CONTROL_DONE&&e.endpoint==1&&e.owner==ack.owner)done++;}
 CHECK(done==1,"actual accepted ACK owner completed once by native ring");
 addresses(w,&c);nhi_descriptors(w,&c,1);wire(w,3);safety(w);stack_destroy(w);
}
static void slot_reuse(void)
{
 struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,2,0);
 start(w,c.first_seq,0);pump(w,1000000);
 struct stack_stage_facts old=stage_facts(w,1,0);
 CHECK(!old.slot_busy&&old.slot_local_known&&old.slot_local_quiesced,"first actual RX CQE retired its slot before downstream release");
 CHECK(!stack_start(w,1,c.first_seq+1,0),"real next RX arm reuses released family slot");
 struct stack_stage_facts current=stage_facts(w,1,0);
 CHECK(current.slot_owner==old.slot_owner&&current.slot_busy&&!current.slot_local_known&&!current.fact_accepted,"same slot now owns fresh uncompleted RX reservation");
 struct xdev_ext_mech_stage_diag d=query(w,1);
 CHECK(d.downstream_release_pending==1&&d.final_waiting_chain==1&&!d.ack_owed,"old reply responsibility survives next group slot reuse without reading new local facts");
 CHECK(!stack_release(w,1,c.first_seq),"release prior group while next RX slot is live");
 d=query(w,1);CHECK(!d.downstream_release_pending&&d.ack_owed==1,"only old reply moves to owed ACK while new armed slot stays uncounted");
 pump(w,1000000);d=query(w,1);CHECK(!d.downstream_release_pending&&!d.ack_owed,"old real ACK sent while new uncompleted slot stays uncounted");
 CHECK(!stack_start(w,0,c.first_seq+1,0),"actual sender starts matching fresh RX");pump(w,1000000);
 d=query(w,1);CHECK(d.downstream_release_pending==1&&!d.ack_owed,"next real completion creates exactly its own downstream responsibility");
 release_group(w,c.first_seq+1);d=query(w,1);CHECK(!d.downstream_release_pending&&!d.ack_owed,"second real release and ACK retire only second responsibility");
 CHECK(count(w,STACK_EV_PUBLISH,0,-1)==2&&count(w,STACK_EV_PUBLISH,1,-1)==2,"both groups actual exactly-once CQEs");
 addresses(w,&c);nhi_descriptors(w,&c,2);wire(w,1);wire(w,2);wire(w,3);safety(w);stack_destroy(w);
}
void stack_diag_ledger(struct stack_world *,unsigned,struct xdev_ext_requester_retention_stats *);
static void error_unknown(void)
{
 for(unsigned unknown=0;unknown<2;unknown++){
  struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
  fault(w,unknown?STACK_FAULT_HOLD_CALLBACK:STACK_FAULT_RX_FLAGS,1,0,0,1,0);
  start(w,c.first_seq,0);
  if(!unknown){
   bool saw_fail=false;
   for(unsigned step=0;step<1000;step++){
    int rc=stack_pump(w,1,0);CHECK(rc==0||rc==-ELOOP,"single actual step at failed native completion");
    struct xdev_ext_mech_stage_diag d=query(w,1);
    CHECK(!d.downstream_release_pending&&!d.final_waiting_chain&&!d.ack_owed,"native error cannot become successful downstream or ACK responsibility");
    if(d.fail_owed)saw_fail=true;
    if(!rc)break;
   }
   CHECK(saw_fail,"actual malformed native completion creates observed owed FAIL");
   pump(w,1000000);struct xdev_ext_mech_stage_diag d=query(w,1);
   CHECK(!d.fail_owed,"actual accepted FAIL discharges error obligation");
   CHECK(count(w,STACK_EV_CONTROL_TX,1,5)>0,"real wire FAIL sent for actual native error");
   for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_PUBLISH)CHECK(e.status<0,"malformed native result never publishes success");}
  }else{
   pump(w,1000000);struct xdev_ext_mech_stage_diag d=query(w,1);
   CHECK(d.native_inflight==4&&!d.downstream_release_pending&&!d.final_waiting_chain&&!d.ack_owed,"uncompleted native frames never appear successful or locally quiesced");
   size_t released=count(w,STACK_EV_LEASE_RELEASE,1,-1);
   fault(w,STACK_FAULT_GOING_AWAY,1,0,0,1,0);CHECK(!stack_remove(w,1),"actual UNKNOWN native retirement from lost controller");
   memset(&d,0xa5,sizeof(d));struct xdev_ext_mech_stage_diag saved=d;
   CHECK(stack_diag_query(w,1,&d)==-ESTALE&&!memcmp(&d,&saved,sizeof(d)),"retired old endpoint cannot return zero-safe success");
   struct xdev_ext_requester_retention_stats r;stack_diag_ledger(w,1,&r);
   CHECK(r.retained_generations&&r.retained_bytes,"actual requester ledger retains UNKNOWN native backing");
   CHECK(count(w,STACK_EV_LEASE_RELEASE,1,-1)==released&&count(w,STACK_EV_RETAIN,1,-1)>0,"UNKNOWN never falsely releases actual payload lease");
  }
  safety(w);stack_destroy(w);
 }
}
static void ack_orders(void)
{
 for(unsigned order=0;order<2;order++){
  struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
  fault(w,order?STACK_FAULT_HOLD_CONTROL:STACK_FAULT_HOLD_CALLBACK,order?1:0,order?3:0,0,1,0);
  start(w,c.first_seq,0);pump(w,1000000);release_group(w,c.first_seq);
  struct xdev_ext_mech_stage_diag d=query(w,0);
  fprintf(stderr,"DIAG order=%u inflight=%u pending=%u ack=%u wait=%u\n",order,d.native_inflight,d.software_pending,d.ack_owed,d.final_waiting_chain);
  CHECK(d.native_inflight==(order?0:4)&&!d.software_pending,"ACK and local-done order preserves actual pending descriptor custody");
  CHECK(count(w,STACK_EV_PUBLISH,0,-1)==0&&count(w,STACK_EV_LEASE_RELEASE,0,-1)==0,"query never releases sender before both witnesses");
  fault(w,order?STACK_FAULT_RELEASE_CONTROLS:STACK_FAULT_RELEASE_CALLBACKS,order?1:0,order?3:0,0,0,0);pump(w,1000000);
  d=query(w,0);CHECK(!d.native_inflight&&!d.software_pending&&!d.ack_owed&&!d.final_waiting_chain,"both witness orders drain diagnostic counts");
  CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1,"actual sender exactly once after both");
  addresses(w,&c);nhi_descriptors(w,&c,1);wire(w,3);safety(w);stack_destroy(w);
 }
}
static void lifecycle(void)
{
 for(unsigned operation=1;operation<=2;operation++)for(unsigned point=1;point<=2;point++){
  struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
  struct xdev_ext_mech_stage_diag old=query(w,0),d={0};
  stack_diag_arm(w,0,point,operation);
  CHECK(!stack_diag_query(w,0,&d),"query completes old epoch while actual lifecycle waits ctl_mutex");
  stack_diag_join();
  CHECK(d.local_inc==old.local_inc&&d.remote_inc==old.remote_inc&&d.token==old.token&&d.retention.reserved_bytes==old.retention.reserved_bytes,"no mixed old identity/native/retention snapshot");
  memset(&d,0x5a,sizeof(d));struct xdev_ext_mech_stage_diag saved=d;
  CHECK(stack_diag_query(w,0,&d)==-ESTALE&&!memcmp(&d,&saved,sizeof(d)),"old endpoint stale with untouched output after actual remove/reconnect");
  if(operation==1){CHECK(!stack_remove(w,1),"remove peer before actual two-end reprobe");CHECK(!stack_probe(w,0)&&!stack_probe(w,1),"actual main reprobe both ends");}
  else {CHECK(!stack_suspend(w,1)&&!stack_resume(w,1),"actual peer reconnect");}
  pump(w,1000000001);pump(w,1000000);
  struct stack_session_config rx={.direction=2,.groups=1,.generation=129,.allocation_bias=524288};
  struct stack_session_config tx={.direction=1,.groups=1,.generation=117,.allocation_bias=524288};
  CHECK(!stack_next_session(w,1,&rx)&&!stack_next_session(w,0,&tx),"fresh real bind after actual main reconnect");
  d=query(w,0);CHECK(d.local_inc!=old.local_inc&&d.remote_inc!=old.remote_inc,"fresh query reports actual successor incarnation pair");
  safety(w);stack_destroy(w);
 }
}
static void control_capacity(void)
{
 struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
 struct xdev_ext_mech_stage_diag d=query(w,0);CHECK(d.ctl_tx_free==128,"all real control frames initially returned");
 int n=stack_diag_fill_controls(w,0);CHECK(n==128,"128 accepted real control frames exhaust capacity");
 d=query(w,0);CHECK(!d.ctl_tx_free,"query sees actual exhausted control bitmap");
 pump(w,1000000);d=query(w,0);fprintf(stderr,"DIAG restored=%u\n",d.ctl_tx_free);CHECK(d.ctl_tx_free==128,"real NHI callbacks return entire control capacity");
 safety(w);stack_destroy(w);
}
int main(int argc,char**argv)
{
 if(argc!=2)return 2;
 case_name=argv[1];budget=30000;
 if(!strcmp(case_name,"pending-release"))pending_release();
 else if(!strcmp(case_name,"cts-capacity"))cts_capacity();
 else if(!strcmp(case_name,"ack-orders"))ack_orders();
 else if(!strcmp(case_name,"slot-reuse"))slot_reuse();
 else if(!strcmp(case_name,"error-unknown"))error_unknown();
 else if(!strcmp(case_name,"ack-decrement"))ack_decrement();
 else if(!strcmp(case_name,"lifecycle"))lifecycle();
 else if(!strcmp(case_name,"control-capacity"))control_capacity();else return 2;
 printf("STACK_DIAG %s assertions=%u PASS\n",case_name,assertions);return 0;
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Independent §8.2 assertions. No production policy or segmentation helpers. */
#include "stack_kernel_compat.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static unsigned assertions, budget;
static const char *case_name;
#define CHECK(c, why) do { assertions++; if (!(c)) { \
 fprintf(stderr,"STACK_ASSERT %s: %s (%s:%d)\n",case_name,why,__FILE__,__LINE__); exit(1); } } while (0)
static struct stack_event ev(struct stack_world *w, size_t i)
{ struct stack_event e; memset(&e,0,sizeof(e)); CHECK(stack_log_get(w,i,&e)==0,"read actual boundary event"); return e; }
static size_t count(struct stack_world *w,unsigned kind,int end,int ctl)
{ size_t n=0; for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i); if(e.kind==kind&&(end<0||e.endpoint==(unsigned)end)&&(ctl<0||e.control_type==(unsigned)ctl))n++;}return n; }
static uint64_t first(struct stack_world *w,unsigned kind,int end,int ctl)
{ for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==kind&&(end<0||e.endpoint==(unsigned)end)&&(ctl<0||e.control_type==(unsigned)ctl))return e.id;}return 0; }
static void pump(struct stack_world *w,uint64_t ns)
{CHECK(stack_pump(w,budget,ns)==0,"bounded scheduler: no unhandled work or budget exhaustion");}
static void fault(struct stack_world *w,unsigned kind,unsigned endpoint,unsigned ctl,uint64_t ordinal,uint64_t a,uint64_t b)
{struct stack_fault f={.kind=kind,.endpoint=endpoint,.control_type=ctl,.ordinal=ordinal,.arg0=a,.arg1=b};CHECK(stack_fault(w,&f)==0,"install boundary fault without direct X5 injection");}
static struct stack_config geometry(void)
{struct stack_config c;memset(&c,0,sizeof(c));c.mapping_base[0]=UINT64_C(0x1100000000);c.mapping_base[1]=UINT64_C(0x2200000000);c.local_inc[0]=101;c.local_inc[1]=203;c.generation[0]=17;c.generation[1]=29;c.first_seq=37;c.depth=3;c.nr_frames=2;c.frame_size=65536;c.native_elems=4;c.channels=1;c.span[0]=(struct stack_span){65536,4096,8192};c.span[1]=(struct stack_span){196608,8192,8192};return c;}
static struct stack_world *create(struct stack_config *c)
{struct stack_world*w=NULL;CHECK(stack_new(c,&w)==0&&w,"create recording environment");return w;}
static void login(struct stack_world*w)
{CHECK(stack_probe(w,0)==0,"actual endpoint0 X3 probe");CHECK(stack_probe(w,1)==0,"actual endpoint1 X3 probe");pump(w,1000000);CHECK(count(w,STACK_EV_LOGIN,0,-1)>0&&count(w,STACK_EV_LOGIN,1,-1)>0,"both actual login handlers executed");}
static void sessions(struct stack_world*w,unsigned groups,unsigned stage)
{struct stack_session_config rx={.direction=2,.stage_index=0,.groups=groups};struct stack_session_config tx={.direction=1,.stage_index=stage,.groups=groups};CHECK(stack_session(w,1,&rx)==0,"actual receiver X5 bind");CHECK(stack_session(w,0,&tx)==0,"actual sender X5 bind");}
static void start(struct stack_world*w,uint64_t group,unsigned stage)
{CHECK(stack_start(w,1,group,0)==0,"receiver arm actual class");CHECK(stack_start(w,0,group,stage)==0,"sender start actual class");}
static size_t count_sid(struct stack_world*w,unsigned kind,unsigned end,uint64_t sid)
{size_t n=0;for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==kind&&e.endpoint==end&&e.session_id==sid)n++;}return n;}
static struct stack_stage_facts stage_facts(struct stack_world*w,unsigned e,uint64_t sid)
{struct stack_stage_facts f;memset(&f,0,sizeof(f));CHECK(stack_stage_facts(w,e,sid,0,&f)==0,"read raw actual stage/session facts without changing authority");CHECK(f.session_id&&f.stage_owner&&f.slot_owner,"actual stable session/stage/slot identity");return f;}
static void native_control_balance(const struct stack_stage_facts*f)
{CHECK(f->native_controls==f->reply_admissions+f->rts_admissions,"actual native-control counter equals actual outstanding reply/RTS admissions");}
static void lease_balance(struct stack_world*w)
{for(size_t i=0;i<stack_log_count(w);i++){struct stack_event a=ev(w,i);if(a.kind!=STACK_EV_LEASE_ACQUIRE)continue;unsigned n=0;for(size_t j=i+1;j<stack_log_count(w);j++){struct stack_event d=ev(w,j);if((d.kind==STACK_EV_LEASE_RELEASE||d.kind==STACK_EV_RETAIN)&&!d.control&&d.endpoint==a.endpoint&&d.owner==a.owner&&d.generation==a.generation&&d.session_id==a.session_id)n++;}CHECK(n==1,"each actual acquired native lease ends in one quiesced release or retained custody");}}
static void control_balance(struct stack_world*w)
{
 for(size_t i=0;i<stack_log_count(w);i++) {
  struct stack_event tx=ev(w,i);
  if(tx.kind!=STACK_EV_CONTROL_TX)continue;
  CHECK(tx.owner!=0,"accepted control TX has actual ctl_frame owner");
  unsigned done=0,retained=0;
  for(size_t j=i+1;j<stack_log_count(w);j++) {
   struct stack_event e=ev(w,j);
   if(e.owner!=tx.owner||e.endpoint!=tx.endpoint)continue;
   if(e.kind==STACK_EV_CONTROL_TX)break;
   if(e.kind==STACK_EV_CONTROL_DONE)done++;
   if(e.kind==STACK_EV_RETAIN)retained++;
  }
  if(!(done==1||(done==0&&retained>0))) {
   fprintf(stderr,"STACK_CONTROL_BALANCE txid=%" PRIu64 " owner=%" PRIu64 " endpoint=%u type=%u done=%u retained=%u\n",tx.id,tx.owner,tx.endpoint,tx.control_type,done,retained);
  }
  CHECK(done==1||(done==0&&retained>0),"accepted control owner has one actual completion or explicit retained custody");
  for(size_t j=i+1;j<stack_log_count(w);j++) {
   struct stack_event e=ev(w,j);
   if(e.owner!=tx.owner||e.endpoint!=tx.endpoint)continue;
   if(e.kind==STACK_EV_CONTROL_DONE)break;
   CHECK(e.kind!=STACK_EV_CONTROL_TX,"control slot cannot be reused before actual native callback");
  }
 }
}
static void safety(struct stack_world*w)
{control_balance(w);uint64_t last=0;for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);CHECK(e.id>last,"strictly ordered raw boundary ledger");last=e.id;CHECK(e.endpoint<2,"event belongs to actual endpoint");CHECK(e.kind!=STACK_EV_FORBIDDEN,"no payload copy/direct X5 message/synthetic CQE/policy fallback");CHECK(e.kind!=STACK_EV_LOCK_VIOLATION,"no BPF/progress while production link/family lock held");CHECK(e.kind!=STACK_EV_UNHANDLED,"every scheduled event handled");if(e.kind==STACK_EV_PUBLISH){CHECK(e.session_id!=0,"actual published CQE has nonzero owning session identity");CHECK(e.status<=0,"actual CQE status");for(size_t j=0;j<i;j++){struct stack_event p=ev(w,j);CHECK(!(p.kind==e.kind&&p.endpoint==e.endpoint&&p.session_id==e.session_id&&p.group==e.group&&p.stage_index==e.stage_index),"at most one publication per actual session/group/stage");}}}}
static void addresses(struct stack_world*w,const struct stack_config*c)
{size_t n=0;unsigned seen[2]={0,0};uint64_t previous[2]={0,0};for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind!=STACK_EV_DATA_POST)continue;n++;CHECK(e.owner!=0,"accepted native frame has immutable callback owner");CHECK(e.generation==c->generation[e.endpoint],"native lease generation is actual registration generation");CHECK(e.length>0&&e.length<=4096,"native transfer length bounded independently");CHECK(e.seq<UINT64_C(1000000),"native sequence remains in independent bounded test stream");CHECK(e.seq>=previous[e.endpoint],"native sequence monotonic per endpoint");if(!seen[e.endpoint]++)CHECK(e.seq==0,"actual native channel data_seq starts0 independently of core batch key37");previous[e.endpoint]=e.seq;CHECK(e.group==e.seq/c->native_elems+1,"actual wire group1+ordinal independently of core batch key37");size_t ordinal=e.seq%c->native_elems;size_t frame=ordinal/2,chunk=ordinal%2;CHECK(frame<c->nr_frames,"independent fixed two-chunk frame fixture");uint64_t want=c->mapping_base[e.endpoint]+c->span[frame].allocation_off+c->span[frame].data_off+chunk*4096;CHECK(e.address==want,"independent mapping_base+allocation_off+data_off+chunk_off oracle");CHECK(e.length==4096,"each independent fixture chunk is exactly 4096 bytes");CHECK(e.pdf==0x201,"literal actual SOF1/EOF2 preserved without collapsing the two PDF fields");size_t callbacks=0;for(size_t j=i+1;j<stack_log_count(w);j++){struct stack_event cb=ev(w,j);if(cb.kind==STACK_EV_DATA_CALLBACK&&cb.endpoint==e.endpoint&&cb.owner==e.owner&&cb.seq==e.seq){CHECK(cb.generation==e.generation,"callback retains accepted lease generation");callbacks++;}}CHECK(callbacks==1,"every accepted native frame has exactly one actual callback");}CHECK(n>0,"real X4 vtable posted native frames");}
static void wire(struct stack_world*w,unsigned type)
{size_t tx=0,rx=0,dispatch=0;for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.control_type!=type)continue;if(e.kind==STACK_EV_CONTROL_TX||e.kind==STACK_EV_CONTROL_RX){CHECK(e.raw_len==128,"actual X4 128-byte control buffer");CHECK(e.raw[0]=='N'&&e.raw[1]=='X'&&e.raw[2]=='D'&&e.raw[3]=='1',"independent literal wire magic");CHECK(e.raw[4]==1&&e.raw[5]==type,"literal wire version/type");if(e.kind==STACK_EV_CONTROL_TX)tx++;else{int matched=0;rx++;for(size_t j=0;j<i;j++){struct stack_event prior=ev(w,j);if(prior.kind==STACK_EV_CONTROL_TX&&prior.endpoint!=e.endpoint&&prior.raw_len==e.raw_len&&!memcmp(prior.raw,e.raw,e.raw_len))matched=1;}CHECK(matched,"actual receive buffer bytes equal a preceding opposite endpoint TX buffer");}}if(e.kind==STACK_EV_DISPATCH)dispatch++;}CHECK(tx&&rx&&dispatch,"control crosses actual TX buffer RX callback and dispatch");}
static void release_group(struct stack_world*w,uint64_t group)
{CHECK(stack_release(w,1,group)==0,"actual receiver batch_release/CHAIN_END");pump(w,1000000);}
static void happy(unsigned stage)
{struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,9,stage);for(unsigned g=0;g<9;g++){start(w,c.first_seq+g,stage);pump(w,1000000);size_t ack=count(w,STACK_EV_CONTROL_TX,1,3);CHECK(ack==g,"RX has no final ACK before real batch release");release_group(w,c.first_seq+g);CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==g+1,"one final RX ACK after release");}addresses(w,&c);CHECK(count(w,STACK_EV_PUBLISH,0,-1)==9,"sender own-stage retires all nine groups");CHECK(count(w,STACK_EV_PUBLISH,1,-1)==9,"receiver publishes all nine groups");for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_PUBLISH){CHECK(e.status==0,"happy actual CQE status is success");CHECK(e.bytes==16384&&e.elems_done==4,"happy actual CQE bytes16384 and elems_done4 from actual fill");CHECK(e.stage_index==(e.endpoint==0?stage:0),"actual CQE belongs to its own stage (TX0/1 RX0)");}}CHECK(count(w,STACK_EV_BUILD,0,-1)>=9&&count(w,STACK_EV_PROTOCOL,0,-1)>0,"actual X6 BUILD and protocol invoked");CHECK(count(w,STACK_EV_BATCH_RELEASE,1,-1)==9,"all nine actual receive releases");wire(w,1);wire(w,2);wire(w,3);safety(w);CHECK(stack_stop(w,0)==0&&stack_stop(w,1)==0,"clean final STOP");stack_destroy(w);}
/* Exact-limit regression uses only observable production work: a successful
 * zero-advance pump must leave no immediately executable callback/final CQE. */
static void scheduler_exact_budget(void)
{
 for(unsigned limit=0;limit<24;limit++) {
  struct stack_config c=geometry();struct stack_world*w=create(&c);
  login(w);sessions(w,1,0);start(w,c.first_seq,0);
  size_t at=stack_log_count(w);int rc=stack_pump(w,limit,0);
  unsigned steps=0;uint64_t serial=0;
  for(size_t i=at;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind!=STACK_EV_SCHED_STEP)continue;steps++;if(!serial)serial=e.seq;CHECK(e.seq==serial&&e.bytes==steps&&e.length==limit,"raw scheduler execution ordinal/budget tied to exact pump");CHECK(e.flags>=1&&e.flags<=4,"scheduler step identifies actual work/progress/finalize/native dispatch");}
  CHECK(steps<=limit,"no scheduler execution beyond exact budget including finalization/native callbacks");
  CHECK(limit==0||steps>0,"eligible fixture executes observed real steps when budget allows");
  CHECK(rc==0||rc==-40,"bounded scheduler returns success or ELOOP only");
  if(rc==0) {
   size_t before=stack_log_count(w);
   CHECK(stack_pump(w,budget,0)==0,"large bounded followup drains same-time work");
   if(stack_log_count(w)!=before)fprintf(stderr,"STACK_BUDGET limit=%u first_return=0 followup_events=%zu\n",limit,stack_log_count(w)-before);
   CHECK(stack_log_count(w)==before,"exact-limit pump cannot return success with eligible native/finalize work left");
  }
  stack_destroy(w);
 }
 struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);
 CHECK(stack_pump(w,0,0)==0,"idle preposted RX storage is not eligible work or budget exhaustion");
 stack_destroy(w);
 for(unsigned lost=0;lost<2;lost++) {
  w=create(&c);login(w);sessions(w,1,0);
  fault(w,lost?STACK_FAULT_DROP_CALLBACK:STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);
  start(w,c.first_seq,0);pump(w,1000000);
  size_t before=stack_log_count(w);
  CHECK(stack_pump(w,0,0)==0,"deliberately held/lost native work is not immediately executable scheduler work");
  CHECK(stack_log_count(w)==before,"idle zero-budget pump executes no scheduler step");
  stack_destroy(w);
 }
}
static void probe_login_identity(void)
{scheduler_exact_budget();struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);CHECK(count(w,STACK_EV_PROBE,-1,-1)==2,"exactly two actual probes");uint64_t requester[2]={0},data[2]={0},ctl[2]={0};for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_PROBE){CHECK(e.token&&e.local_inc,"actual nonzero token/incarnation");requester[e.endpoint]=e.address;}if(e.kind==STACK_EV_PATH_ENABLE&&e.status==0){if(e.control)ctl[e.endpoint]=e.id;else if(!data[e.endpoint])data[e.endpoint]=e.id;}}CHECK(requester[0]&&requester[1]&&requester[0]!=requester[1],"actual distinct endpoint NHI requester identities");for(unsigned p=0;p<2;p++)CHECK(data[p]&&ctl[p]&&data[p]<ctl[p],"data paths enabled before control path");CHECK(stack_remove(w,0)==0&&stack_remove(w,1)==0,"actual X3 remove");pump(w,1000000);CHECK(count(w,STACK_EV_HOP_ALLOC,-1,-1)==count(w,STACK_EV_HOP_FREE,-1,-1),"HopIDs released exactly once");CHECK(count(w,STACK_EV_RING_ALLOC,-1,-1)==count(w,STACK_EV_RING_FREE,-1,-1),"all rings released exactly once");CHECK(count(w,STACK_EV_DEVICE_PUT,-1,-1)==2,"actual X3 own-link NHI requester reference released once per endpoint");unsigned retained[2]={0,0};for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_RETAIN&&e.control){CHECK(e.owner&&e.address==requester[e.endpoint]&&e.length>0,"actual UNKNOWN control allocation retains its own NHI PCI reference and storage");retained[e.endpoint]++;}}CHECK(!retained[0]&&!retained[1],"healthy STOPPED control allocations are released after real callback balance");for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_DEVICE_PUT)CHECK(e.length==1,"healthy endpoint retains only its initial NHI PCI reference");}safety(w);stack_destroy(w);}
static void multiwindow_happy_path(void){happy(0);happy(1);}
static void ack_before_tx_callback(void)
{struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);fault(w,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);start(w,c.first_seq,0);pump(w,1000000);release_group(w,c.first_seq);CHECK(count(w,STACK_EV_CONTROL_RX,0,3)>0,"ACK reached sender before held TX completion");CHECK(count(w,STACK_EV_PUBLISH,0,-1)==0,"no early TX publish before native callback");CHECK(count(w,STACK_EV_LEASE_RELEASE,0,-1)==0,"no early TX lease recycle/release");fault(w,STACK_FAULT_RELEASE_CALLBACKS,0,0,0,0,0);pump(w,1000000);CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1,"last native callback publishes exactly once");CHECK(first(w,STACK_EV_CONTROL_RX,0,3)<first(w,STACK_EV_DATA_CALLBACK,0,-1),"observed ACK/native callback ordering");addresses(w,&c);safety(w);stack_destroy(w);}
static void wire_rts_cts_ack_faults(void)
{
 for(unsigned type=1;type<=3;type++)for(unsigned mode=0;mode<3;mode++) {
  fprintf(stderr,"STACK_SUBCASE wire type=%u mode=%u\n",type,mode);
  struct stack_config c=geometry();struct stack_world*w=create(&c);
  login(w);sessions(w,1,0);
  unsigned end=type==1?0:1,receiver=1-end;
  unsigned kinds[]={STACK_FAULT_HOLD_CONTROL,STACK_FAULT_DROP_CONTROL,STACK_FAULT_DUP_CONTROL};
  fault(w,kinds[mode],end,type,0,1,0);start(w,c.first_seq,0);pump(w,1000000);
  if(type==3)release_group(w,c.first_seq);
  if(mode==1) {
   CHECK(count(w,STACK_EV_CONTROL_TX,end,type)>0,"dropped control was actually accepted by real X4 TX buffer");
   CHECK(count(w,STACK_EV_CONTROL_RX,receiver,type)==0,"dropped control copy never reaches actual RX callback");
   CHECK(count(w,STACK_EV_DISPATCH,receiver,type)==0,"dropped control copy never dispatches to X5");
   if(type!=3)CHECK(count(w,STACK_EV_DATA_POST,0,-1)==0,"dropped RTS/CTS cannot invent sender data admission");
   pump(w,UINT64_C(31000000000));
   pump(w,UINT64_C(1100000000));
   for(unsigned turn=0;turn<4;turn++)pump(w,1000000);
   CHECK(count(w,STACK_EV_FAILURE,-1,-1)+count(w,STACK_EV_RETAIN,-1,-1)>0,
         "one-attempt protocol reaches real bounded failure/cautious custody after actual30s deadline");
   CHECK(count(w,STACK_EV_CONTROL_TX,end,type)==1,"no invented retransmission fallback for one-attempt protocol");
  } else {
   if(mode==0){fault(w,STACK_FAULT_RELEASE_CONTROLS,end,type,0,0,0);pump(w,1000000);}
   if(type!=3&&count(w,STACK_EV_PUBLISH,1,-1))release_group(w,c.first_seq);
   pump(w,1000000);wire(w,type);
  }
  CHECK(count(w,STACK_EV_PUBLISH,0,-1)<=1,"wire fault/duplicate never double publishes");
  safety(w);stack_destroy(w);
 }
}
static void preaccept_refusal_rollback(void)
{for(unsigned mode=0;mode<2;mode++){struct stack_config c=geometry();struct stack_world*w=create(&c);if(mode==0){fault(w,STACK_FAULT_RING_REFUSE,0,0,0,1,0);CHECK(stack_probe(w,0)<0,"ring allocation refusal propagates before acceptance");pump(w,0);CHECK(count(w,STACK_EV_DATA_POST,0,-1)==0,"ring refusal causes no partial native post");CHECK(count(w,STACK_EV_HOP_ALLOC,0,-1)==count(w,STACK_EV_HOP_FREE,0,-1),"ring refusal exact HopID rollback");CHECK(count(w,STACK_EV_RING_ALLOC,0,-1)==count(w,STACK_EV_RING_FREE,0,-1),"ring refusal exact allocated ring rollback");}else{login(w);sessions(w,1,0);fault(w,STACK_FAULT_CONTROL_REFUSE,0,1,0,1,0);CHECK(stack_start(w,1,c.first_seq,0)==0,"receiver arm before preaccept refusal");CHECK(stack_start(w,0,c.first_seq,0)==-11,"actual class returns EAGAIN for preaccept full control storage");pump(w,1000);CHECK(count(w,STACK_EV_CONTROL_TX,0,1)==0,"full control storage accepts no early RTS scalar");CHECK(count(w,STACK_EV_DATA_POST,0,-1)==0,"no native data before accepted control");fault(w,STACK_FAULT_CONTROL_REFUSE,0,1,0,0,0);CHECK(stack_start(w,0,c.first_seq,0)==0,"one retry after actual preaccept capacity restored");pump(w,10000000);CHECK(count(w,STACK_EV_CONTROL_TX,0,1)==1,"accepted announcement not replayed after capacity restored");}safety(w);stack_destroy(w);}}
static void callback_lifetime(void)
{for(unsigned mode=0;mode<2;mode++){struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);if(!mode)fault(w,STACK_FAULT_DUP_CALLBACK,0,0,0,1,0);start(w,c.first_seq,0);pump(w,1000000);release_group(w,c.first_seq);size_t pubs=count(w,STACK_EV_PUBLISH,0,-1),releases=count(w,STACK_EV_LEASE_RELEASE,0,-1);CHECK(pubs==1,"native callback path produces real completion");if(mode){uint64_t id=first(w,STACK_EV_DATA_CALLBACK,0,-1);CHECK(stack_remove(w,0)==0,"actual callback owner removal barrier");releases=count(w,STACK_EV_LEASE_RELEASE,0,-1);fault(w,STACK_FAULT_REPLAY_CALLBACK,0,0,id,0,0);pump(w,1000);}CHECK(count(w,STACK_EV_REJECT,0,-1)>0,"duplicate/after-free native callback invocation rejected");CHECK(count(w,STACK_EV_PUBLISH,0,-1)==pubs,"duplicate callback cannot double publish");CHECK(count(w,STACK_EV_LEASE_RELEASE,0,-1)==releases,"duplicate callback cannot double release lease");for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind!=STACK_EV_LEASE_RELEASE)continue;for(size_t j=0;j<i;j++){struct stack_event p=ev(w,j);CHECK(!(p.kind==STACK_EV_LEASE_RELEASE&&p.owner==e.owner&&p.generation==e.generation),"lease ticket released exactly once despite callback replay");}}safety(w);stack_destroy(w);}}
static void native_and_wire_errors(void)
{for(unsigned mode=0;mode<6;mode++){fprintf(stderr,"STACK_SUBCASE native_error mode=%u\n",mode);struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);if(mode==0)fault(w,STACK_FAULT_RX_FLAGS,1,0,0,1,0);if(mode==1)fault(w,STACK_FAULT_RX_LENGTH,1,0,0,4095,0);if(mode==2)fault(w,STACK_FAULT_RX_FLAGS,1,0,0,4,0);if(mode>=3)fault(w,STACK_FAULT_CORRUPT_CONTROL,0,1,0,mode==3?124:mode==4?8:52,mode==3?1:2);start(w,c.first_seq,0);pump(w,100000000);CHECK(count(w,STACK_EV_FAILURE,-1,-1)+count(w,STACK_EV_REJECT,-1,-1)>0,"native/wire error reaches real custody failure or decoder rejection");for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_PUBLISH)CHECK(e.status<0,"malformed native/wire input cannot publish success");}safety(w);stack_destroy(w);}}
static void stop_all_commitment_phases(void)
{
 const char*names[]={"ARMED","ANNOUNCED","CTS-committed","POSTED","local-done-ACK-owed"};
 for(unsigned phase=0;phase<5;phase++) {
  fprintf(stderr,"STACK_STOP_PHASE %s\n",names[phase]);
  struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
  if(phase==1)fault(w,STACK_FAULT_HOLD_CONTROL,0,1,0,1,0);
  if(phase==2)fault(w,STACK_FAULT_HOLD_CONTROL,1,2,0,1,0);
  if(phase==3)fault(w,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);
  CHECK(stack_start(w,1,c.first_seq,0)==0,"receiver actual ARMED admission");
  if(phase){CHECK(stack_start(w,0,c.first_seq,0)==0,"sender admitted selected phase");pump(w,1000000);}
  struct stack_stage_facts tx=stage_facts(w,0,0),rx=stage_facts(w,1,0);
  native_control_balance(&tx);native_control_balance(&rx);
  CHECK(tx.native_controls==0,"sender has no receiver reply admission");
  if(phase==0){CHECK(rx.slot_state==1&&rx.slot_busy,"ARMED positive raw state witness");CHECK(count(w,STACK_EV_CONTROL_TX,0,1)==0&&count(w,STACK_EV_DATA_POST,-1,-1)==0,"ARMED precedes announcement/native post");}
  if(phase==1){CHECK(tx.slot_state==2&&rx.slot_state==1,"ANNOUNCED TX and still-ARMED RX raw states");CHECK(count(w,STACK_EV_CONTROL_TX,0,1)==1&&count(w,STACK_EV_CONTROL_RX,1,1)==0,"ANNOUNCED RTS accepted and held before real RX");CHECK(count(w,STACK_EV_DATA_POST,-1,-1)==0,"ANNOUNCED has no native payload post");}
  if(phase==2){CHECK(tx.slot_state==2&&rx.slot_state==3,"CTS-committed receiverPOSTED and senderANNOUNCED");CHECK(count(w,STACK_EV_CONTROL_TX,1,2)==1&&count(w,STACK_EV_CONTROL_RX,0,2)==0,"CTS committed in actual control storage before sender delivery");CHECK(count(w,STACK_EV_DATA_POST,1,-1)==4&&count(w,STACK_EV_DATA_POST,0,-1)==0,"CTS commitment owns actual RX native frames only");}
  if(phase==3){CHECK(tx.slot_state==3&&tx.fact_accepted&&!tx.slot_local_known,"POSTED positive actual accepted/unknown-native witness");CHECK(count(w,STACK_EV_DATA_POST,0,-1)==4&&count(w,STACK_EV_DATA_CALLBACK,0,-1)==0,"POSTED actual TX frames await native callbacks");}
  if(phase==4){CHECK(tx.slot_state==3&&tx.slot_local_known&&tx.slot_local_quiesced&&count(w,STACK_EV_DATA_CALLBACK,0,-1)==4,"local-done positive CHANNEL POSTED state plus all actual quiesced native completions");CHECK(count(w,STACK_EV_PUBLISH,1,-1)==1&&count(w,STACK_EV_BATCH_RELEASE,1,-1)==0,"receiver local publication precedes actual CHAIN_END");CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==0&&!rx.reply_chain_done,"final ACK remains owed until real receiver chain release");}
  CHECK(rx.native_controls==1&&rx.reply_admissions==1,"actual receive control reservation tracked from ARMED through every named phase");
  if(phase<2)CHECK(!rx.fact_accepted&&!rx.reply_native_posted&&count(w,STACK_EV_CONTROL_TX,1,2)==0&&count(w,STACK_EV_DATA_POST,1,-1)==0,"ARMED/ANNOUNCED reservation is not irreversible CTS/native DMA commitment");
  if(phase==2)CHECK(rx.fact_accepted&&rx.reply_native_posted,"CTS commitment has actual accepted native RX ownership beyond reservation");
  size_t posts=count(w,STACK_EV_DATA_POST,-1,-1);
  (void)stack_stop(w,0);(void)stack_stop(w,1);pump(w,1000000);pump(w,2000000000);pump(w,1000000);
  CHECK(count(w,STACK_EV_DATA_POST,-1,-1)==posts,"STOP admits no new native posts");
  tx=stage_facts(w,0,tx.session_id);rx=stage_facts(w,1,rx.session_id);
  native_control_balance(&tx);native_control_balance(&rx);
  if(tx.native_controls||rx.native_controls)fprintf(stderr,"STACK_STOP_CUSTODY phase=%s txcontrols=%u rxcontrols=%u rxreply=%u rxrts=%u rxknown=%u rxquiesced=%u rxaccepted=%u rxsequestered=%u rxpending=%u rxuncertain=%u\n",names[phase],tx.native_controls,rx.native_controls,rx.reply_admissions,rx.rts_admissions,rx.slot_local_known,rx.slot_local_quiesced,rx.fact_accepted,rx.sequestered,rx.pending,rx.uncertain);
  CHECK(tx.native_controls==0,"sender has no leaked receive reply control admission after STOP");
  if(rx.fact_accepted&&!rx.slot_local_quiesced){CHECK(rx.native_controls==1&&rx.reply_admissions==1&&rx.rts_admissions==0,"accepted UNKNOWN receive owner retains its exact actual reply/control admission");CHECK(rx.pending||rx.uncertain||rx.sequestered,"UNKNOWN retained control remains tied to actual native custody");}else CHECK(rx.native_controls==0,"safe/quiesced withdrawal releases all control reservations");
  int a=stack_stop(w,0),b=stack_stop(w,1);
  tx=stage_facts(w,0,tx.session_id);rx=stage_facts(w,1,rx.session_id);
  CHECK(a==(tx.inflight||tx.sequestered||tx.pending||tx.uncertain?-11:0),"sender STOP status matches actual remaining custody");
  CHECK(b==(rx.inflight||rx.sequestered||rx.pending||rx.uncertain?-11:0),"receiver STOP status matches actual remaining custody");
  if(phase==0)CHECK(count(w,STACK_EV_CONTROL_TX,1,3)==0,"ARMED cancellation cannot invent ACK");
  if(phase==4){CHECK(count(w,STACK_EV_BATCH_RELEASE,1,-1)==1&&count(w,STACK_EV_CONTROL_TX,1,3)==1,"local-done STOP performs actual release then exactly one final ACK");CHECK(first(w,STACK_EV_BATCH_RELEASE,1,-1)<first(w,STACK_EV_CONTROL_TX,1,3),"actual CHAIN_END release precedes final ACK at STOP");}
  if(phase==1||phase==2)CHECK(count(w,STACK_EV_CONTROL_TX,0,6)+count(w,STACK_EV_RING_STOP,0,-1)>0,"announced commitment has actual withdrawal or link teardown");
  lease_balance(w);safety(w);stack_destroy(w);
 }
}
static void loss_and_teardown(void)
{for(unsigned mode=0;mode<4;mode++){struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);fault(w,STACK_FAULT_DROP_CALLBACK,0,0,0,1,0);start(w,c.first_seq,0);pump(w,1000000);size_t released=count(w,STACK_EV_LEASE_RELEASE,0,-1);if(mode==0)CHECK(stack_remove(w,0)==0,"actual X3 remove path");if(mode==1)CHECK(stack_suspend(w,0)==0,"actual X3 suspend path");if(mode==2)fault(w,STACK_FAULT_GOING_AWAY,0,0,0,1,0);if(mode==3)fault(w,STACK_FAULT_STOP_RESULT,0,0,0,(uint64_t)(int64_t)-5,0);(void)stack_stop(w,0);pump(w,2000000000);CHECK(count(w,STACK_EV_RING_STOP,0,-1)>0,"actual X3 teardown reached X4 ring stop");CHECK(count(w,STACK_EV_RETAIN,0,-1)>0,"unknown callback ownership explicitly retained");CHECK(count(w,STACK_EV_LEASE_RELEASE,0,-1)==released,"lost callback cannot falsely unmap/unpin/free");safety(w);stack_destroy(w);}}
static void assert_session_unchanged(struct stack_world*w,const struct stack_stage_facts before[2],const size_t events[2][5])
{
 const unsigned kinds[]={STACK_EV_PUBLISH,STACK_EV_LEASE_ACQUIRE,STACK_EV_LEASE_RELEASE,STACK_EV_RETAIN,STACK_EV_DATA_POST};
 for(unsigned e=0;e<2;e++) {
  struct stack_stage_facts now=stage_facts(w,e,before[e].session_id);
  CHECK(!memcmp(&now,&before[e],sizeof(now)),"stale input cannot alter actual new-session slot/control/custody facts");
  for(unsigned k=0;k<5;k++)CHECK(count_sid(w,kinds[k],e,before[e].session_id)==events[e][k],"stale input cannot publish/post/release/reacquire/retain on new session");
 }
}
static void remember_session(struct stack_world*w,struct stack_stage_facts before[2],size_t events[2][5])
{
 const unsigned kinds[]={STACK_EV_PUBLISH,STACK_EV_LEASE_ACQUIRE,STACK_EV_LEASE_RELEASE,STACK_EV_RETAIN,STACK_EV_DATA_POST};
 for(unsigned e=0;e<2;e++){before[e]=stage_facts(w,e,0);CHECK(!before[e].stage_dead,"new session is live before stale traffic");for(unsigned k=0;k<5;k++)events[e][k]=count_sid(w,kinds[k],e,before[e].session_id);}
}
static void new_transfer_oracle(struct stack_world*w,const struct stack_config*c,const struct stack_stage_facts f[2],uint64_t bias)
{
 for(unsigned ep=0;ep<2;ep++) {
  unsigned posts=0,pubs=0;
  for(size_t i=0;i<stack_log_count(w);i++) {
   struct stack_event e=ev(w,i);if(e.endpoint!=ep||e.session_id!=f[ep].session_id)continue;
   if(e.kind==STACK_EV_DATA_POST){CHECK(e.seq<4&&e.group==1&&e.generation==f[ep].generation,"fresh native identities belong to new generation and wiregroup1");unsigned frame=e.seq/2,chunk=e.seq%2;CHECK(e.address==c->mapping_base[ep]+bias+c->span[frame].allocation_off+c->span[frame].data_off+chunk*4096,"fresh disjoint allocation independently maps every native address");CHECK(e.length==4096&&e.pdf==0x201,"fresh actual native frame length and PDF");posts++;}
   if(e.kind==STACK_EV_PUBLISH){CHECK(e.status==0&&e.bytes==16384&&e.elems_done==4&&e.stage_index==0,"fresh actual both-end CQE success and complete payload geometry");pubs++;}
  }
  CHECK(posts==4&&pubs==1,"each fresh session posts four frames and publishes exactly once");
 }
}
static void recover_both(struct stack_world*w)
{CHECK(stack_suspend(w,0)==0&&stack_suspend(w,1)==0,"actual both-end suspend detaches old endpoints");CHECK(stack_resume(w,0)==0&&stack_resume(w,1)==0,"actual both-end resume starts confirmed re-login");pump(w,10000000);}
static void relogin_stale_identity(void)
{
 for(unsigned unknown=0;unknown<2;unknown++) {
  fprintf(stderr,"STACK_NEW_SESSION old_unknown=%u\n",unknown);
  struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);
  struct stack_stage_facts old[2]={stage_facts(w,0,0),stage_facts(w,1,0)};
  if(unknown)fault(w,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);
  start(w,c.first_seq,0);pump(w,1000000);release_group(w,c.first_seq);
  uint64_t ack=first(w,STACK_EV_CONTROL_TX,1,3),handler=first(w,STACK_EV_HANDLER,0,-1),callback=first(w,STACK_EV_DATA_CALLBACK,0,-1);
  CHECK(ack&&handler,"capture actual old peer-TX ACK and old endpoint0 handler bytes");
  struct stack_event oldack=ev(w,ack-1),oldhandler=ev(w,handler-1);
  CHECK(oldack.endpoint==1&&oldack.raw_len==128,"stale ACK source is actual peer TX control buffer");
  if(!unknown)CHECK(stack_stop(w,0)==0&&stack_stop(w,1)==0,"known old session drains before recovery");
  recover_both(w);
  if(unknown){callback=first(w,STACK_EV_DATA_CALLBACK,0,-1);CHECK(count_sid(w,STACK_EV_RETAIN,0,old[0].session_id)>0,"old UNKNOWN native allocation remains retained after actual suspend");}
  CHECK(callback,"old native callback has actual immutable captured owner");
  struct stack_event oldcb=ev(w,callback-1);
  uint64_t bias=UINT64_C(1048576);
  struct stack_session_config rx={.direction=2,.stage_index=0,.groups=1,.allocation_bias=bias,.generation=c.generation[1]+100};
  struct stack_session_config tx={.direction=1,.stage_index=0,.groups=1,.allocation_bias=bias,.generation=c.generation[0]+100};
  if(unknown){struct stack_session_config overlap=tx;overlap.allocation_bias=131072;overlap.generation=c.generation[0]+99;CHECK(c.span[0].allocation_off+overlap.allocation_bias==c.span[1].allocation_off,"independent overlap fixture aliases old retained second frame");CHECK(stack_next_session(w,0,&overlap)<0,"external provider rejects genuinely overlapping retained UNKNOWN frame before fresh bind");struct stack_stage_facts same=stage_facts(w,0,0);CHECK(same.session_id==old[0].session_id&&same.stage_owner==old[0].stage_owner,"rejected overlapping registration cannot move current session or consume its storage");}
  CHECK(stack_next_session(w,1,&rx)==0&&stack_next_session(w,0,&tx)==0,"fresh both-end actual X5 bind after old endpoint detach");
  struct stack_stage_facts current[2]={stage_facts(w,0,0),stage_facts(w,1,0)};
  for(unsigned e=0;e<2;e++){CHECK(current[e].session_id!=old[e].session_id&&current[e].stage_owner!=old[e].stage_owner&&current[e].slot_owner!=old[e].slot_owner,"new session has distinct stable objects and actual identity");CHECK(current[e].generation==c.generation[e]+100,"fresh provider registration generation is actual configured value");struct stack_stage_facts retained=stage_facts(w,e,old[e].session_id);CHECK(retained.stage_owner==old[e].stage_owner&&retained.slot_owner==old[e].slot_owner,"old session/batch/class storage remains stable rather than overwritten");}
  fault(w,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);
  uint64_t key=c.first_seq+100;start(w,key,0);pump(w,1000000);release_group(w,key);
  CHECK(count_sid(w,STACK_EV_PUBLISH,1,current[1].session_id)==1&&count_sid(w,STACK_EV_PUBLISH,0,current[0].session_id)==0,"new actual session operational while final TX callback is held");
  struct stack_stage_facts before[2];size_t events[2][5];remember_session(w,before,events);
  size_t at=stack_log_count(w),rx0=count(w,STACK_EV_CONTROL_RX,0,3),rx1=count(w,STACK_EV_CONTROL_RX,1,3),dispatch=count(w,STACK_EV_DISPATCH,0,3);
  fault(w,STACK_FAULT_REPLAY_CONTROL,0,3,ack,0,0);pump(w,1000000);
  CHECK(count(w,STACK_EV_CONTROL_RX,0,3)==rx0+1&&count(w,STACK_EV_CONTROL_RX,1,3)==rx1,"stale peer ACK reaches requested actual recovered endpoint0 X4 RX only");
  int exact=0,rejected=0;for(size_t i=at;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_CONTROL_RX&&e.endpoint==0&&e.raw_len==oldack.raw_len&&!memcmp(e.raw,oldack.raw,e.raw_len))exact=1;if(e.kind==STACK_EV_REJECT&&e.endpoint==0&&e.control_type==3)rejected=1;}
  CHECK(exact&&rejected,"actual old ACK bytes rejected at exact target, independently of other reject counters");CHECK(count(w,STACK_EV_DISPATCH,0,3)==dispatch,"old incarnation ACK cannot dispatch to new X5 session");assert_session_unchanged(w,before,events);
  at=stack_log_count(w);fault(w,STACK_FAULT_REPLAY_CALLBACK,0,0,callback,0,0);pump(w,1000000);
  rejected=0;for(size_t i=at;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_REJECT&&e.endpoint==0&&e.owner==oldcb.owner&&e.session_id==old[0].session_id)rejected=1;}
  CHECK(rejected,"old native callback rejected by exact owner/target/captured old session");assert_session_unchanged(w,before,events);
  at=stack_log_count(w);fault(w,STACK_FAULT_REPLAY_HANDLER,0,0,handler,0,0);pump(w,100000000);
  exact=0;for(size_t i=at;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_HANDLER&&e.endpoint==0&&e.raw_len==oldhandler.raw_len&&!memcmp(e.raw,oldhandler.raw,e.raw_len))exact=1;}
  CHECK(exact,"actual stale handler bytes invoked at exact recovered endpoint0");assert_session_unchanged(w,before,events);
  if(unknown)CHECK(count_sid(w,STACK_EV_LEASE_RELEASE,0,old[0].session_id)==0,"retained old UNKNOWN backing cannot be freed or reused by new session");
  fault(w,STACK_FAULT_RELEASE_CALLBACKS,0,0,0,0,0);pump(w,1000000);new_transfer_oracle(w,&c,current,bias);
  CHECK(stack_stop(w,0)==0&&stack_stop(w,1)==0,"new session drains after stale traffic without corruption");
  {recover_both(w);bias=unknown?65536:bias*2;rx.allocation_bias=tx.allocation_bias=bias;rx.generation+=100;tx.generation+=100;CHECK(stack_next_session(w,1,&rx)==0&&stack_next_session(w,0,&tx)==0,"third bounded session binds (gap-disjoint registration accepted for retained UNKNOWN)");current[0]=stage_facts(w,0,0);current[1]=stage_facts(w,1,0);start(w,key+100,0);pump(w,1000000);release_group(w,key+100);new_transfer_oracle(w,&c,current,bias);CHECK(stack_stop(w,0)==0&&stack_stop(w,1)==0,"third bounded session actually drains");recover_both(w);CHECK(stack_next_session(w,0,&tx)==-28&&stack_next_session(w,1,&rx)==-28,"fixture rejects fourth session generation at explicit cap3");}
  for(unsigned e=0;e<2;e++){struct stack_stage_facts retained=stage_facts(w,e,old[e].session_id);CHECK(retained.stage_owner==old[e].stage_owner&&retained.slot_owner==old[e].slot_owner,"third generation/cap refusal preserves original stable old session and callback storage");}if(unknown)CHECK(count_sid(w,STACK_EV_LEASE_RELEASE,0,old[0].session_id)==0,"gap-disjoint third registration still cannot release old UNKNOWN backing");
  safety(w);stack_destroy(w);
 }
 /* Old-token refusal must reach actual bind, not short-circuit on old bound. */
 struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);
 uint64_t token=0;for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind==STACK_EV_PROBE&&e.endpoint==0)token=e.token;}
 CHECK(token&&stack_remove(w,0)==0&&stack_probe(w,0)==0,"actual remove/reprobe replaces X3 identity before token test");pump(w,10000000);
 struct stack_session_config stale={.direction=1,.stage_index=0,.groups=1,.token=token};size_t rejects=count(w,STACK_EV_REJECT,0,-1);
 CHECK(stack_session(w,0,&stale)<0&&count(w,STACK_EV_REJECT,0,-1)==rejects+1,"removed old token fails actual fresh X5 bind");stale.token=0;CHECK(stack_session(w,0,&stale)==0,"current token actually binds after old-token refusal");safety(w);stack_destroy(w);
}
static void sealed_bpf_boundary(void)
{for(unsigned mode=1;mode<=7;mode++){fprintf(stderr,"STACK_SUBCASE sealed mode=%u\n",mode);struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);sessions(w,1,0);fault(w,STACK_FAULT_BPF_INTENT,0,0,0,mode,0);CHECK(stack_start(w,1,c.first_seq,0)==0,"receiver arm for sealed intent test");int submit=stack_start(w,0,c.first_seq,0);if(mode<7)CHECK(submit==0||submit==-71,"actual class may synchronously reject invalid BPF intent with EPROTO");else CHECK(submit==0,"compatible WAIT intent accepted by actual class");pump(w,1000000);CHECK(count(w,STACK_EV_PROTOCOL,0,-1)>0,"actual reference BPF invoked with actual protocol info");if(mode<7){CHECK(count(w,STACK_EV_REJECT,0,-1)+count(w,STACK_EV_FAILURE,0,-1)>0,"C sealed apply rejects invalid/duplicate/stale/unsafe intent");CHECK(count(w,STACK_EV_DATA_POST,0,-1)==0,"no C policy fallback to post after rejected/no verdict");}else{pump(w,10000000);CHECK(count(w,STACK_EV_DATA_POST,0,-1)>0,"compatible replacement WAIT resumes through actual progress");release_group(w,c.first_seq);CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1,"WAIT/resume completes normally");}safety(w);stack_destroy(w);}}
static void geometry_and_offset_oracle(void)
{
 for(unsigned mode=0;mode<7;mode++) {
  struct stack_config c=geometry();
  c.nr_frames=1;c.frame_size=524288;
  c.span[0]=(struct stack_span){524288,0,262144};
  c.native_elems=64;c.depth=mode==0?4:3;
  if(mode==2)c.span[0].len=0;
  if(mode==3)c.span[0].allocation_off=UINT64_MAX-4095;
  if(mode==4){c.native_elems=65;c.span[0].len=65U*4096U;}
  if(mode==5){c=geometry();c.span[0].data_off=128;}
  if(mode==6)c.depth=65;
  struct stack_world*w=create(&c);login(w);
  struct stack_session_config rx={.direction=2,.stage_index=0,.groups=1};
  struct stack_session_config tx={.direction=1,.stage_index=0,.groups=1};
  int rrx=stack_session(w,1,&rx),rtx=stack_session(w,0,&tx);
  if(mode==6) {
   CHECK(rrx==-22&&rtx==-22,"depth65 with legal64-element payload fails actual class EINVAL admission");
   CHECK(count(w,STACK_EV_BUILD,-1,-1)==0&&count(w,STACK_EV_LEASE_ACQUIRE,-1,-1)==0,
         "depth65 rejected before BUILD, payload array access or native leases");
  }
  int started=0,failed=rrx<0||rtx<0;
  if(!failed) {
   int a=stack_start(w,1,c.first_seq,0),b=stack_start(w,0,c.first_seq,0);
   started=1;failed=a<0||b<0;pump(w,1000000);
  }
  if(mode==0||mode==1) {
   CHECK(!failed,"depth3-or4/64 actual class geometry accepted");
   CHECK(count(w,STACK_EV_DATA_POST,0,-1)==64&&count(w,STACK_EV_DATA_POST,1,-1)==64,
         "depth3-or4/64 actual X4 accepts exactly64 native frames per endpoint");
   release_group(w,c.first_seq);
   for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind!=STACK_EV_DATA_POST)continue;CHECK(e.seq<64&&e.group==1,"depth3-or4/64 independent native sequence0..63 and wire group1");CHECK(e.address==c.mapping_base[e.endpoint]+524288+4096*e.seq&&e.length==4096,"depth3-or4/64 literal independent address/length oracle");CHECK(e.pdf==0x201,"depth3-or4/64 actual SOF1/EOF2");}
   CHECK(count(w,STACK_EV_PUBLISH,0,-1)==1&&count(w,STACK_EV_PUBLISH,1,-1)==1,"depth3-or4/64 both endpoints actually complete");
   for(size_t i=0;i<stack_log_count(w);i++){struct stack_event e=ev(w,i);if(e.kind!=STACK_EV_PUBLISH)continue;CHECK(e.status==0&&e.bytes==262144&&e.elems_done==64,"depth3-or4/64 actual CQE success bytes262144 elems_done64");CHECK(e.stage_index==0,"depth3-or4/64 actual ownstage index0");}
  } else {
   CHECK(failed||count(w,STACK_EV_REJECT,-1,-1)+count(w,STACK_EV_FAILURE,-1,-1)>0,
         "zero length, address overflow, element65 and depth65 rejected by actual class/BUILD admission");
   CHECK(count(w,STACK_EV_DATA_POST,-1,-1)==0,"invalid geometry never partially posts");
   if(started)CHECK(count(w,STACK_EV_BUILD,-1,-1)+count(w,STACK_EV_REJECT,-1,-1)+count(w,STACK_EV_FAILURE,-1,-1)>0,
                    "invalid span reaches actual production admission, not environment-only filtering");
  }
  safety(w);stack_destroy(w);
 }
 /* A real source mutation shifts accepted offsets with unchanged status/count;
  * the same independent address oracle must fail multiwindow_happy_path. */
 struct stack_config c=geometry();
 CHECK(c.mapping_base[0]+c.span[0].allocation_off+c.span[0].data_off==UINT64_C(0x1100011000),
       "literal independent offset oracle fixture");
}
struct named {const char*name;void(*run)(void);};
static const struct named cases[]={
 {"probe_login_identity",probe_login_identity},{"multiwindow_happy_path",multiwindow_happy_path},{"ack_before_tx_callback",ack_before_tx_callback},{"wire_rts_cts_ack_faults",wire_rts_cts_ack_faults},{"preaccept_refusal_rollback",preaccept_refusal_rollback},{"callback_lifetime",callback_lifetime},{"native_and_wire_errors",native_and_wire_errors},{"stop_all_commitment_phases",stop_all_commitment_phases},{"loss_and_teardown",loss_and_teardown},{"relogin_stale_identity",relogin_stale_identity},{"sealed_bpf_boundary",sealed_bpf_boundary},{"geometry_and_offset_oracle",geometry_and_offset_oracle}};
int main(int argc,char**argv)
{if(argc!=3){fprintf(stderr,"usage: stack-cases NAME EVENT_BUDGET\n");return 2;}case_name=argv[1];budget=(unsigned)strtoul(argv[2],NULL,10);if(!budget)return 2;for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++)if(!strcmp(case_name,cases[i].name)){cases[i].run();printf("STACK_CASE_ASSERTIONS %s %u\n",case_name,assertions);return 0;}fprintf(stderr,"unknown frozen case %s\n",case_name);return 2;}

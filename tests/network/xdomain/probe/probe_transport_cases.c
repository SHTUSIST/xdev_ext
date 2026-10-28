/* SPDX-License-Identifier: GPL-2.0 */
/* Independent accepted-design oracles. Never set a production gate or invoke
 * private advancement directly; use real LOGIN/control/NHI callbacks. */
#include "probe_observation.h"
static unsigned assertions, failures;
#define CHECK(c, why) do { assertions++; if (!(c)) { \
 fprintf(stderr,"PROBE_TRANSPORT_ASSERT: %s\n",why); failures++; } } while (0)
#define SETUP(c, why) do { if (!(c)) { \
 fprintf(stderr,"PROBE_TRANSPORT_SETUP_FAILURE: %s\n",why); return 2; } } while (0)

static struct stack_config geometry(void)
{
 struct stack_config c = {0};
 c.mapping_base[0]=0x1100000000ULL; c.mapping_base[1]=0x2200000000ULL;
 c.local_inc[0]=101; c.local_inc[1]=203; c.generation[0]=17; c.generation[1]=29;
 c.first_seq=37; c.depth=3; c.nr_frames=2; c.frame_size=65536;
 c.native_elems=4; c.channels=1;
 c.span[0]=(struct stack_span){65536,4096,8192};
 c.span[1]=(struct stack_span){196608,8192,8192};
 return c;
}

static size_t events(struct stack_world *w, unsigned kind, int endpoint, int control)
{
 size_t count=0;
 for (size_t i=0;i<stack_log_count(w);i++) {
  struct stack_event event;
  if (stack_log_get(w,i,&event)) exit(2);
  count += event.kind==kind && (endpoint<0 || event.endpoint==(unsigned)endpoint) &&
           (control<0 || event.control==(unsigned)control);
 }
 return count;
}

static int install(struct stack_world *w, unsigned kind, unsigned endpoint,
                    unsigned control_type, uint64_t value)
{
 struct stack_fault fault={.kind=kind,.endpoint=endpoint,
                           .control_type=control_type,.arg0=value};
 return stack_fault(w,&fault);
}

static void prepost_before_ready(struct stack_world *w,unsigned endpoint)
{
 unsigned rx=0,ready=0;
 for(size_t i=0;i<stack_log_count(w);i++) {
  struct stack_event event;
  if(stack_log_get(w,i,&event))exit(2);
  if(event.endpoint!=endpoint)continue;
  if(event.kind==STACK_EV_DATA_POST && event.direction==2 && !event.control)rx++;
  if(event.kind==STACK_EV_CONTROL_TX && event.raw_len==128 &&
     !memcmp(event.raw,"XSB1",4) && event.raw[5]==1) {
   ready++;
   CHECK(rx==2,"both actual generic scratch RX are accepted before READY");
  }
 }
 CHECK(ready==1,"one accepted READY per endpoint");
}

int main(int argc, char **argv)
{
 SETUP(argc==2,"one named case required");
 const char *name=argv[1];
 bool held=!strcmp(name,"held_callbacks"), done=!strcmp(name,"held_done");
 bool length=!strcmp(name,"short_rx"), overrun=!strcmp(name,"overrun_rx");
 bool remove=!strcmp(name,"early_remove"), unknown=!strcmp(name,"unknown_remove");
 bool pingtx=!strcmp(name,"held_ping_tx"),pongtx=!strcmp(name,"held_pong_tx");
 bool pattern=!strcmp(name,"pattern_valid_crc"),nonce=!strcmp(name,"nonce_valid_crc");
 bool budget=!strcmp(name,"failure_budget");
 bool repeated=!strcmp(name,"unknown_repeated_stop");
 bool canceled_diag=!strcmp(name,"canceled_rx_diagnostic");
 SETUP(held||done||length||overrun||remove||unknown||pingtx||pongtx||pattern||nonce||
       budget||repeated||canceled_diag||!strcmp(name,"happy"),"known case");
 struct stack_config c=geometry(); struct stack_world *w=NULL;
 SETUP(stack_new(&c,&w)==0 && w,"existing stack environment");
 if(pingtx||pongtx)probe_hold_tx(0,pingtx?1:2,true);
 if(pattern||nonce)probe_corrupt_data(0,1,pattern?64:24,true);
 if(budget) {
  probe_corrupt_repeated(0,1,64);
  probe_corrupt_repeated(1,1,64);
 }
 if (held||remove||unknown||repeated||canceled_diag) {
  SETUP(install(w,STACK_FAULT_HOLD_CALLBACK,0,0,1)==0,"hold endpoint0 data callbacks");
  SETUP(install(w,STACK_FAULT_HOLD_CALLBACK,1,0,1)==0,"hold endpoint1 data callbacks");
 }
 if (done) SETUP(install(w,STACK_FAULT_HOLD_CONTROL,1,2,1)==0,"hold peer DONE at control boundary");
 if (length) SETUP(install(w,STACK_FAULT_RX_LENGTH,1,0,127)==0,"native actual length127");
 if (overrun) SETUP(install(w,STACK_FAULT_RX_FLAGS,1,0,4)==0,"native overrun flag");
 SETUP(stack_probe(w,0)==0 && stack_probe(w,1)==0,"actual main probes");
 SETUP(stack_pump(w,30000,1000000)==0,"bounded production startup convergence");
 struct probe_observation obs[2]; struct probe_native_facts native[2];
 for(unsigned e=0;e<2;e++) {
  SETUP(probe_observe(w,e,&obs[e])==0,"raw production link facts");
  SETUP(probe_native_facts(w,e,&native[e])==0,"raw native frame facts");
  printf("PROBE_TRANSPORT_OBS ep=%u up=%u accepted=%u retired=%u pending=%u "
         "rx128=%u rx4096=%u tx128=%u tx4096=%u\n",e,obs[e].up,
         native[e].accepted,native[e].retired,native[e].pending,
         native[e].rx128,native[e].rx4096,native[e].tx128,native[e].tx4096);
  CHECK(obs[e].announced==0 && obs[e].consumed==0,"startup preserves business sequence zero");
  CHECK(obs[e].endpoints==0,"startup creates no business endpoint");
  if(!length&&!overrun&&!pattern&&!nonce&&!budget)prepost_before_ready(w,e);
 }
 CHECK(events(w,STACK_EV_PUBLISH,-1,-1)==0 && events(w,STACK_EV_LEASE_ACQUIRE,-1,-1)==0,
       "startup produces no business completion or PEER lease");
 struct stack_session_config tx={.direction=1,.stage_index=0,.groups=1};
 if(canceled_diag) {
  CHECK(native[0].pending>=2 && native[0].retired==0,
        "diagnostic input owns two uncompleted native RX frames");
  probe_stop_link(0);
  char state[4096]={0};
  SETUP(probe_show_snapshot(0,state)>0,"actual readonly data state snapshot after cancellation");
  printf("PROBE_DATA_STATE %s",state);
  const char *rx0=strstr(state,"rx0_actual_len="),*rx1=strstr(state,"rx1_actual_len=");
  SETUP(rx0&&rx1,"existing actual RX diagnostic fields");
  CHECK(strtoul(rx0+strlen("rx0_actual_len="),NULL,10)==0 &&
        strtoul(rx1+strlen("rx1_actual_len="),NULL,10)==0,
        "native cancellation supplies no actual RX length; capacity0 must not report4096");
  CHECK(strstr(state,"rx0_canceled=1") && strstr(state,"rx1_canceled=1"),
        "canceled native RX is diagnosed separately from actual byte length");
 } else if(budget) {
  unsigned prior[2]={obs[0].retry_failures,obs[1].retry_failures};
  for(unsigned attempt=0;attempt<1024;attempt++) {
   SETUP(stack_pump(w,30000,30000000000ULL)==0,"bounded real repeated reconnect/data failure");
   for(unsigned e=0;e<2;e++) {
    SETUP(probe_observe(w,e,&obs[e])==0,"retry budget raw facts");
    CHECK(obs[e].retry_failures>=prior[e],"successful LOGIN cannot clear failed data budget");
    prior[e]=obs[e].retry_failures;
   }
   if(obs[0].retry_failures>=60 && obs[1].retry_failures>=60)break;
  }
  for(unsigned e=0;e<2;e++) {
   printf("PROBE_BUDGET_OBS ep=%u failures=%u exhausted=%u link_ups=%llu\n",e,
          obs[e].retry_failures,obs[e].retries_exhausted,(unsigned long long)obs[e].link_ups);
   CHECK(obs[e].retry_failures==60,"existing setup budget is exhausted exactly at60");
   CHECK(obs[e].link_ups>1,"multiple actual control UPs occurred while data repeatedly failed");
  }
  size_t logins=events(w,STACK_EV_LOGIN,-1,-1);
  SETUP(stack_pump(w,30000,120000000000ULL)==0,"advance after setup budget exhaustion");
  CHECK(events(w,STACK_EV_LOGIN,-1,-1)==logins,"budget exhaustion stops automatic LOGIN retry");
 } else if (remove||unknown||repeated) {
  CHECK(native[0].accepted>=2 && native[0].pending>=2,"STOP occurs after real RX acceptance");
  if(unknown||repeated) SETUP(install(w,STACK_FAULT_GOING_AWAY,0,0,1)==0,"NHI going away");
  if(repeated) {
   probe_stop_link(0);
   struct probe_retention_facts first,second;
   probe_retention_facts(0,&first);
   printf("PROBE_RETENTION_OBS generations=%u retained_generations=%u retained_bytes=%llu live_coherent_bytes=%llu\n",
          first.generations,first.retained_generations,(unsigned long long)first.retained_bytes,
          (unsigned long long)first.live_coherent_bytes);
   /* Independent one-channel byte oracle: data descriptors 2*256*16,
    * control descriptors 2*128*16, control RX 128*4096, scratch 16384.
    * Completed healthy control TX stays link-owned until remove, so mere
    * live allocation does not imply its 16384 bytes belong in retained ledger. */
   CHECK(first.retained_generations==1 && first.retained_bytes==552960,
         "UNKNOWN ledger exactly charges descriptors/control RX/scratch once");
   CHECK(probe_live_allocations(0,16384)>=1,"scratch coherent allocation remains retained");
   probe_stop_link(0);
   probe_retention_facts(0,&second);
   CHECK(second.retained_bytes==first.retained_bytes &&
         second.retained_generations==first.retained_generations,
         "repeated stop does not double-charge UNKNOWN bytes or generations");
  }
  CHECK(stack_remove(w,0)==0,"actual remove crosses production native stop/free");
  if(repeated) {
   struct probe_retention_facts removed;
   probe_retention_facts(0,&removed);
   printf("PROBE_REMOVED_RETENTION_OBS retained_bytes=%llu live_coherent_bytes=%llu\n",
          (unsigned long long)removed.retained_bytes,(unsigned long long)removed.live_coherent_bytes);
   CHECK(removed.retained_bytes==removed.live_coherent_bytes,
         "after remove ledger exactly accounts all surviving coherent backing");
  }
  if(unknown||repeated) CHECK(probe_live_allocations(0,16384)>=1,"UNKNOWN retains internal coherent scratch");
  else CHECK(probe_live_allocations(0,16384)==0,"healthy actual stop and callback barrier release scratch");
 } else if (held||done||length||overrun||pingtx||pongtx||pattern||nonce) {
  int result=stack_session(w,0,&tx);
  CHECK(result<0,"incomplete or failed data challenge refuses business bind");
  if(held||done||pingtx||pongtx) CHECK(result==-11,"control UP with incomplete challenge returns EAGAIN");
  if(held) CHECK(native[0].retired==0 && native[1].retired==0,
                 "successful data submission alone never implies native completion");
  if(done) CHECK(native[0].retired==4 && native[1].retired==4,
                 "own data completion remains insufficient without peer DONE");
  if(pingtx||pongtx) {
   /* Native TX callback retirement follows descriptor order: withholding the
    * first PING completion also blocks the later PONG callback at ring_work.
    * Withholding PONG alone leaves precisely that final callback pending. */
   CHECK(native[0].retired==(pingtx?2U:3U) &&
         native[0].pending==(pingtx?2U:1U) && native[1].retired==4,
         "peer receives both frames while selected own TX completion remains withheld");
   probe_hold_tx(0,pingtx?1:2,false);
   SETUP(stack_pump(w,30000,1000000)==0,"release only the withheld native TX completion");
   CHECK(stack_session(w,0,&tx)==0,"last own TX retirement permits validated DONE convergence");
  }
 } else {
  for(unsigned e=0;e<2;e++) {
   CHECK(obs[e].up==1,"real bidirectional LOGIN remains UP");
   CHECK(native[e].accepted==4 && native[e].retired==4 && native[e].pending==0,
         "two actual RX and two actual TX retire before handoff");
   CHECK(native[e].rx128==1 && native[e].rx4096==1 &&
         native[e].tx128==1 && native[e].tx4096==1,
         "PING128/PONG4096 cross actual native descriptors in both directions");
   CHECK(events(w,STACK_EV_RING_START,e,0)==2 && events(w,STACK_EV_RING_STOP,e,0)==0,
         "successful startup does not stop or restart either native data ring");
   char state[4096]={0};
   SETUP(probe_show_snapshot(e,state)>0,"readonly state after actual challenge");
   CHECK(strstr(state,"control_ready=1") && strstr(state,"data_verified_mask=1"),
         "readonly diagnostic separates control UP and actual data validation");
   CHECK(strstr(state,"backing_qualified=not_queried"),
         "host scratch success never upgrades target backing qualification");
   CHECK(strstr(state,"tx_ping_submitted_len=128") &&
         strstr(state,"tx_pong_submitted_len=4096") &&
         !strstr(state,"actual_tx_bytes"),
         "TX submitted lengths never become unsupported actual TX bytes");
   CHECK(!strstr(state,"nonce"),"readonly public diagnostic does not expose nonce");
  }
  CHECK(stack_session(w,0,&tx)==0,"actual successful challenge opens ordinary bind");
  SETUP(stack_pump(w,30000,11000000000ULL)==0,"advance beyond startup absolute deadline");
  SETUP(probe_observe(w,0,&obs[0])==0,"facts after old deadline");
  CHECK(obs[0].up && obs[0].endpoints==1,"completed startup deadline cannot end healthy link");
 }
 CHECK(events(w,STACK_EV_LOCK_VIOLATION,-1,-1)==0,"no observed transport lock-order violation");
 stack_destroy(w);
 printf("PROBE_TRANSPORT_ASSERTIONS %u failures=%u\n",assertions,failures);
 return failures?1:0;
}

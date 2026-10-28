/* SPDX-License-Identifier: GPL-2.0 */
/* Derived from frozen early-cts-contract/API.md; no production policy model.
 * Existing v1 oracle is included verbatim. Device injections only write real
 * posted control RX backing, then complete the actual NHI descriptor. */
#define main early_original_main
#include "stack_cases.c"
#undef main

static u64 early_le(const u8 *p,unsigned n)
{u64 v=0;for(unsigned i=0;i<n;i++)v|=(u64)p[i]<<(8*i);return v;}
static void early_put(u8 *p,u64 v,unsigned n)
{for(unsigned i=0;i<n;i++)p[i]=v>>(8*i);}
static u32 early_crc(const u8 *p,unsigned n)
{u32 v=~0U;while(n--){v^=*p++;for(unsigned b=0;b<8;b++)v=(v>>1)^((v&1)?0x82f63b78U:0);}return ~v;}
static void early_recrc(u8 p[128]) {early_put(p+124,early_crc(p,124),4);}
static size_t early_data(unsigned e)
{size_t n=0;for(size_t i=0;i<world->logs;i++)n+=world->log[i].kind==STACK_EV_DATA_POST&&world->log[i].endpoint==e;return n;}
static struct stack_event early_control(unsigned endpoint,unsigned type,unsigned ordinal)
{
 for(size_t i=0;i<world->logs;i++){
  struct stack_event e=world->log[i];
  if(e.kind==STACK_EV_CONTROL_TX&&e.endpoint==endpoint&&e.control_type==type&&!--ordinal)return e;
 }
 CHECK(false,"required real control message exists");return (struct stack_event){0};
}
static void early_wire(struct stack_event e,unsigned type)
{
 CHECK(e.raw_len==128,"strict v2 control length128");
 CHECK(!memcmp(e.raw,"NXD2",4)&&e.raw[4]==2&&e.raw[5]==type,"independent v2 magic version type");
 CHECK(e.raw[6]==0&&!e.raw[7],"channel0 and reserved byte zero");
 CHECK(early_le(e.raw+8,8)&&early_le(e.raw+16,8)&&early_le(e.raw+24,8),"wire carries current nonzero endpoint scope");
 CHECK(!early_le(e.raw+84,4)&&!early_le(e.raw+88,8)&&!early_le(e.raw+120,4),"all v2 flags/padding zero");
 CHECK(early_le(e.raw+124,4)==early_crc(e.raw,124),"independent bitwise CRC covers exact124 bytes");
}
static void early_inject(unsigned endpoint,const u8 raw[128])
{
 struct native *rx=NULL;
 for(unsigned i=0;i<world->nn;i++){
  struct native *n=&world->n[i];struct stack_ring_info *r=ring_info(n->r);
  if(r->endpoint==endpoint&&r->control&&!r->is_tx&&native_live(n)&&
     !n->delivered&&stack_nhi_visible(n->r,n->f)){rx=n;break;}
 }
 CHECK(rx!=NULL,"injected control uses actual posted NHI RX descriptor");
 CHECK(stack_scratch_dma(rx->f->buffer_phy,128),"injected control writes actual allocated coherent backing");
 memcpy((void *)(uintptr_t)rx->f->buffer_phy,raw,128);
 rx->completion_len=128;rx->completion_flags=0;rx->completion_sof=1;rx->completion_eof=2;
 rx->delivered=true;native_complete(rx);pump(world,1000000);
}
static void early_bind(bool tx_first,bool short_tail)
{
 struct stack_config c=geometry();
 if(short_tail){c.span[1].len=1024;c.native_elems=3;}
 struct stack_world *w=create(&c);login(w);early_flags=2;
 struct stack_session_config rx={.direction=2,.groups=3},tx={.direction=1,.groups=3};
 unsigned first_endpoint=tx_first?0:1;
 CHECK(stack_session(w,first_endpoint,tx_first?&tx:&rx)==0,"EARLY bit1 admits actual first endpoint");
 CHECK(count(w,STACK_EV_CONTROL_TX,-1,-1)==0,"bind itself never sends handshake");
 if(tx_first){pump(w,1000000);pump(w,25000000);}
 CHECK(stack_session(w,1-first_endpoint,tx_first?&rx:&tx)==0,"EARLY bit1 admits actual second endpoint");
 for(unsigned i=0;i<8;i++)pump(w,25000000);
 CHECK(count(w,STACK_EV_CONTROL_TX,0,1)==0,"pair does not send v1 RTS");
 CHECK(early_data(0)==0&&early_data(1)==0,"pair handshake alone cannot post payload storage");
 CHECK(count(w,STACK_EV_CONTROL_TX,0,7)>=1&&count(w,STACK_EV_CONTROL_TX,1,8)>=1&&
       count(w,STACK_EV_CONTROL_TX,0,9)>=1,"real HELLO challenge confirm complete without TX batch");
 struct stack_event hello=early_control(0,7,1),challenge=early_control(1,8,1),confirm=early_control(0,9,1);
 early_wire(hello,7);early_wire(challenge,8);early_wire(confirm,9);
 CHECK(!early_le(hello.raw+32,8)&&early_le(challenge.raw+32,8),"fresh RX bind appears only after challenge");
 CHECK(early_le(hello.raw+24,8)==early_le(challenge.raw+24,8)&&
       early_le(confirm.raw+24,8)==early_le(challenge.raw+24,8)&&
       early_le(confirm.raw+32,8)==early_le(challenge.raw+32,8),"challenge round trip freezes exact pair");
 CHECK(hello.id<challenge.id&&challenge.id<confirm.id,"wire handshake ordered before any grant");
}
static void early_grant(u64 key,unsigned group,bool short_tail)
{
 CHECK(stack_start(world,1,key,0)==0,"real RX batch arms independently of TX");pump(world,1000000);
 CHECK(early_data(0)==(group-1)*(short_tail?3:4),"CTS exists before matching TX native work");
 struct stack_event cts=early_control(1,2,group);early_wire(cts,2);
 CHECK(early_le(cts.raw+40,8)==group&&early_le(cts.raw+64,8)==key,"CTS binds exact actual nonconsecutive key and next group");
 CHECK(early_le(cts.raw+56,8)==(group-1)*(short_tail?3:4),"whole-group native FIFO sequence reserved exactly once");
 CHECK(early_le(cts.raw+72,4)==(short_tail?9216:16384)&&early_le(cts.raw+76,2)==(short_tail?3:4)&&
       early_le(cts.raw+80,4)==8192,"CTS exact canonical short-tail count and geometry");
 CHECK(early_le(cts.raw+48,8)>group,"CTS reliable credit is cumulative bound above actual group");
 u8 expected_tag[24]={0};for(unsigned i=0;i<8;i++)expected_tag[i]=key>>(56-8*i);
 CHECK(!memcmp(cts.raw+96,expected_tag,24),"CTS tag independent BE8 key and sixteen zero bytes");
 size_t rx=0;for(size_t i=0;i<world->logs;i++){
  struct stack_event e=world->log[i];
  if(e.kind==STACK_EV_DATA_POST&&e.endpoint==1&&e.group==group){rx++;CHECK(e.id<cts.id,"every actual RX native post precedes grant advertisement");}
 }
 CHECK(rx==(short_tail?3:4),"one whole real RX group posted before CTS");
}
static void early_addresses(bool short_tail,unsigned groups)
{
 unsigned expected_per=short_tail?3:4,seen[2]={0,0};
 for(size_t i=0;i<world->logs;i++){
  struct stack_event e=world->log[i];if(e.kind!=STACK_EV_DATA_POST)continue;
  unsigned ordinal=e.seq%expected_per,frame=ordinal<2?0:1,chunk=ordinal<2?ordinal:ordinal-2;
  u64 off=(frame?196608:65536)+(frame?8192:4096)+4096*chunk+(e.group-1)*524288;
  u32 len=short_tail&&ordinal==2?1024:4096;
  CHECK(e.address==(e.endpoint?0x2200000000ULL:0x1100000000ULL)+off,
        "independent actual frame address includes distinct second-batch storage");
  CHECK(e.length==len&&e.pdf==0x201,"independent canonical native short-tail length and PDFs");
  unsigned descriptor=0,callback=0;
  for(size_t j=i+1;j<world->logs;j++){
   struct stack_event n=world->log[j];
   if(n.owner!=e.owner||n.endpoint!=e.endpoint||n.group!=e.group||n.control)continue;
   if(n.kind==STACK_EV_NHI_POST){descriptor++;CHECK(n.address==e.address,"real NHI descriptor owns exact accepted local mapping");}
   if(n.kind==STACK_EV_DATA_CALLBACK)callback++;
  }
  CHECK(descriptor==1&&callback==1,"actual NHI post and real callback each occur once per accepted frame");seen[e.endpoint]++;
 }
 CHECK(seen[0]==groups*expected_per&&seen[1]==groups*expected_per,"both actual native rings carry all exact granted elements");
}
static void early_happy(bool short_tail,bool ack_first)
{
 early_bind(false,short_tail);
 if(ack_first)fault(world,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);
 early_grant(37,1,short_tail);
 CHECK(count(world,STACK_EV_BUILD,0,-1)==0,"grant mailbox accepts CTS with no TX BUILD/slot");
 CHECK(stack_start(world,0,37,0)==0,"exact later TX consumes its actual grant");pump(world,1000000);
 CHECK(!count(world,STACK_EV_CONTROL_TX,-1,1),"early TX never sends RTS");
 CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"CQE and local RX completion cannot authorize ACK");
 CHECK(!count(world,STACK_EV_PUBLISH,0,-1),"local TX completion alone cannot retire remote custody");
 if(ack_first){CHECK(stack_release(world,1,37)==0,"real consumer releases first batch");pump(world,1000000);
  CHECK(count(world,STACK_EV_CONTROL_TX,1,3)==1,"one ACK after real release");
  CHECK(!count(world,STACK_EV_PUBLISH,0,-1),"ACK before local completion retains TX custody");
  fault(world,STACK_FAULT_RELEASE_CALLBACKS,0,0,0,0,0);pump(world,1000000);
  CHECK(count(world,STACK_EV_PUBLISH,0,-1)==1,"both ACK and local completion retire TX exactly once");
 }else{
  /* Different registered frame span for a different actual batch; preserve
   * first consumer custody while the second RX reservation proceeds. */
  world->cfg.span[0].allocation_off+=524288;world->cfg.span[1].allocation_off+=524288;
  early_grant(901,2,short_tail);
  CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"next grant does not release prior consumer chain");
  CHECK(stack_start(world,0,901,0)==0,"nonconsecutive future key consumes second exact grant");pump(world,1000000);
  CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"both completed RX batches still await consumer release");
  CHECK(stack_release(world,1,37)==0,"release first actual consumer");pump(world,1000000);
  CHECK(count(world,STACK_EV_CONTROL_TX,1,3)==1,"only first consumer receives ACK");
  CHECK(stack_release(world,1,901)==0,"release second actual consumer");pump(world,1000000);
  CHECK(count(world,STACK_EV_CONTROL_TX,1,3)==2,"second ACK follows second real consumer release");
 }
 early_addresses(short_tail,ack_first?1:2);safety(world);lease_balance(world);
 CHECK(stack_stop(world,0)==0&&stack_stop(world,1)==0,"all actual custody drains cleanly");
}
static void early_first_invalid_cts(bool shape)
{
 early_bind(false,false);fault(world,STACK_FAULT_HOLD_CONTROL,1,2,0,0,0);
 CHECK(stack_start(world,1,37,0)==0,"real RX reserves/posts while its exact CTS held in native transport");pump(world,1000000);
 struct stack_event message=early_control(1,2,1);u8 bad[128];memcpy(bad,message.raw,128);
 if(shape)early_put(bad+80,4096,4);else bad[32]^=0x40;
 early_recrc(bad);early_inject(0,bad);
 CHECK(stack_start(world,0,37,0)==-EAGAIN,"first invalid pair/immutable-shape CTS cannot authorize any actual TX batch");
 CHECK(!early_data(0)&&early_data(1)==4,"invalid first CTS preserves sole posted RX without new TX native custody");
}
static void early_invalid(const char *name)
{
 early_bind(false,false);early_grant(37,1,false);
 size_t tx=early_data(0),rx=early_data(1),cts=count(world,STACK_EV_CONTROL_TX,1,2);
 struct stack_event msg=early_control(1,2,1);u8 raw[128];memcpy(raw,msg.raw,128);
 if(!strcmp(name,"wrong_key")){
  CHECK(stack_start(world,0,38,0)==-EPROTO,"wrong actual TX key fails early session closed");
  struct epoch *e=world->side[0].current;
  CHECK(e->b[e->nb].claims==0&&e->b[e->nb].publishes==0,"rejected wrong-key temporary batch owns no accepted completion claim or publication");
 }else if(!strcmp(name,"wrong_shape")){
  world->cfg.span[1].len=4096;
  CHECK(stack_start(world,0,37,0)<0,"same layout rejects actual noncanonical frame shape");
 }else if(!strcmp(name,"pool_generation")){
  world->side[1].current->s.generation++;
  CHECK(stack_start(world,0,37,0)==0,"matching TX submits before stale RX is diagnosed");pump(world,1000000);
 }else if(!strcmp(name,"duplicate_cts")){
  early_inject(0,raw);CHECK(early_data(0)==tx,"duplicate AVAILABLE grant cannot post TX");
  CHECK(stack_start(world,0,37,0)==0,"one matching TX consumes grant after duplicate");pump(world,1000000);
  tx=early_data(0);early_inject(0,raw);
  CHECK(early_data(0)==tx,"duplicate CONSUMED grant cannot post TX again");
  CHECK(stack_release(world,1,37)==0,"consumer release after duplicate");pump(world,1000000);return;
 }else if(!strcmp(name,"stop_available")){
  CHECK(stack_stop(world,0)<=0,"STOP closes available grant");
  CHECK(stack_start(world,0,37,0)==-ESHUTDOWN,"STOP rejects later matching TX");
 }else{
  if(!strcmp(name,"wrong_bind"))raw[32]^=0x40;
  else if(!strcmp(name,"old_inc"))raw[8]^=0x40;
  else if(!strcmp(name,"skip_group"))early_put(raw+40,2,8);
  else if(!strcmp(name,"same_count_shape"))early_put(raw+80,4096,4);
  else if(!strcmp(name,"wrong_seq"))early_put(raw+56,4,8);
  else if(!strcmp(name,"bad_reserved"))raw[88]=1;
  else if(!strcmp(name,"bad_crc"))raw[124]^=1;
  else CHECK(false,"known invalid scenario");
  if(strcmp(name,"bad_crc"))early_recrc(raw);
  early_inject(0,raw);
  CHECK(early_data(0)==tx&&early_data(1)==rx,"invalid wire cannot acquire payload custody or replace posted RX");
  CHECK(count(world,STACK_EV_CONTROL_TX,1,2)==cts,"invalid wire cannot create grant credit");
  CHECK(stack_start(world,0,37,0)==0,"invalid input cannot replace previously valid exact mailbox");pump(world,1000000);
  CHECK(stack_release(world,1,37)==0,"real release after invalid control drop");pump(world,1000000);return;
 }
 CHECK(early_data(0)==tx,"invalid submit cannot create extra native TX");
 CHECK(early_data(1)==rx&&count(world,STACK_EV_CONTROL_TX,1,2)==cts,"invalid submit cannot replace posted RX or advertise another grant");
}
static void early_missing_confirm(void)
{
 struct stack_config c=geometry();struct stack_world *w=create(&c);login(w);early_flags=2;
 struct stack_session_config rx={.direction=2,.groups=1},tx={.direction=1,.groups=1};
 CHECK(stack_session(w,1,&rx)==0&&stack_session(w,0,&tx)==0,"real early sessions bind");
 fault(w,STACK_FAULT_HOLD_CONTROL,0,9,0,0,0);
 CHECK(stack_start(w,1,37,0)==0,"actual RX arms before pair bound");
 for(unsigned i=0;i<4;i++)pump(w,25000000);
 CHECK(count(w,STACK_EV_CONTROL_TX,0,9)>=1,"real confirm was enqueued but held at device transport");
 CHECK(!early_data(1)&&!count(w,STACK_EV_CONTROL_TX,1,2),"missing received confirm prevents RX post and grant");
 fault(w,STACK_FAULT_RELEASE_CONTROLS,0,0,0,0,0);pump(w,25000000);
 CHECK(early_data(1)==4&&count(w,STACK_EV_CONTROL_TX,1,2)==1,"received exact confirm releases one actual ARMED RX batch");
}
static void early_armed_invalidation(const char *name)
{
 struct stack_config c=geometry();struct stack_world *w=create(&c);login(w);early_flags=2;
 struct stack_session_config rx={.direction=2,.groups=1},tx={.direction=1,.groups=1};
 CHECK(stack_session(w,1,&rx)==0&&stack_session(w,0,&tx)==0,"real early sessions bind before invalidation");
 fault(w,STACK_FAULT_HOLD_CONTROL,0,9,0,0,0);
 CHECK(stack_start(w,1,37,0)==0,"real actual batch has ARMED lease custody");
 for(unsigned i=0;i<4;i++)pump(w,25000000);
 CHECK(!early_data(1)&&!count(w,STACK_EV_CONTROL_TX,1,2),"unconfirmed batch owns no native payload grant");
 if(!strcmp(name,"armed_ticket"))world->side[1].current->b[0].ticket++;
 else if(!strcmp(name,"armed_pool"))world->side[1].current->s.generation++;
 else if(!strcmp(name,"stop_before_post"))CHECK(stack_stop(w,1)<=0,"STOP transitions real RX before post");
 else CHECK(false,"known arm invalidation");
 fault(w,STACK_FAULT_RELEASE_CONTROLS,0,0,0,0,0);pump(w,25000000);
 CHECK(!early_data(1)&&!count(w,STACK_EV_CONTROL_TX,1,2),"stale ticket/pool or STOP cannot create native RX acceptance or grant");
}
static void early_old_bind(void)
{
 early_bind(false,false);early_grant(37,1,false);
 struct stack_event old_cts=early_control(1,2,1),old_confirm=early_control(0,9,1);
 CHECK(stack_start(world,0,37,0)==0,"old pair actual TX completes");pump(world,1000000);
 CHECK(stack_release(world,1,37)==0,"old pair actual consumer release");pump(world,1000000);
 CHECK(stack_stop(world,0)==0&&stack_stop(world,1)==0,"old pair is quiescent before same-incarnation rebuild");
 u64 inc0=link(0)->local_inc,inc1=link(1)->local_inc;
 for(unsigned e=0;e<2;e++){
  struct epoch *ep=world->side[e].current;
  ep->s.st.cls->unbind(&ep->s.st);ep->bound=false;
 }
 struct stack_session_config rx={.direction=2,.groups=1,.allocation_bias=524288,.generation=129};
 struct stack_session_config tx={.direction=1,.groups=1,.allocation_bias=524288,.generation=117};
 CHECK(stack_next_session(world,1,&rx)==0&&stack_next_session(world,0,&tx)==0,"fresh actual same-incarnation endpoints rebind disjoint storage");
 CHECK(link(0)->local_inc==inc0&&link(1)->local_inc==inc1,"same-incarnation rebuild does not rely on link token reset");
 for(unsigned i=0;i<4;i++)pump(world,25000000);
 struct stack_event fresh_confirm=early_control(0,9,2);
 CHECK(early_le(fresh_confirm.raw+24,8)>early_le(old_confirm.raw+24,8)&&
       early_le(fresh_confirm.raw+32,8)>early_le(old_confirm.raw+32,8),"C monotonically allocates fresh bind IDs on same link");
 size_t tx_before=early_data(0),rx_before=early_data(1),cts_before=count(world,STACK_EV_CONTROL_TX,1,2);
 early_inject(0,old_cts.raw);early_inject(1,old_confirm.raw);
 CHECK(early_data(0)==tx_before&&early_data(1)==rx_before&&count(world,STACK_EV_CONTROL_TX,1,2)==cts_before,
       "old grant and old confirm cannot authorize fresh endpoint storage");
 CHECK(stack_start(world,0,37,0)==-EAGAIN,"old CTS never populates fresh TX mailbox");
}
static void early_tx_wait(bool zero_key)
{
 early_bind(false,false);u64 key=zero_key?0:37;
 CHECK(stack_start(world,0,key,0)==-EAGAIN,"actual TX before exact grant uses preadmission retry");
 CHECK(!early_data(0)&&!count(world,STACK_EV_CONTROL_TX,0,1),"pregrant retry creates neither RTS nor native TX");
 early_grant(key,1,false);
 CHECK(stack_start(world,0,key,0)==0,"same actual key retry consumes available grant");pump(world,1000000);
 CHECK(stack_release(world,1,key)==0,"matching consumer real release");pump(world,1000000);
 CHECK(count(world,STACK_EV_CONTROL_TX,1,3)==1,"key0 and normal key retain ordinary ACK chain contract");
 early_addresses(false,1);safety(world);
}
static void early_mixed(bool receive_early)
{
 struct stack_config c=geometry();struct stack_world *w=create(&c);login(w);
 struct stack_session_config rx={.direction=2,.groups=1},tx={.direction=1,.groups=1};
 early_flags=receive_early?2:0;CHECK(stack_session(w,1,&rx)==0,"mixed receiver binds explicit requested mode");
 early_flags=receive_early?0:2;CHECK(stack_session(w,0,&tx)==0,"mixed sender binds explicit requested mode");
 CHECK(stack_start(w,1,37,0)==0,"mixed receiver arms actual batch");
 int ret=stack_start(w,0,37,0);
 CHECK(receive_early?ret==0:ret==-EAGAIN,"normal submit starts RTS; early submit waits for exact grant");
 for(unsigned i=0;i<4;i++)pump(w,25000000);
 CHECK(!early_data(0)&&!early_data(1)&&!count(w,STACK_EV_CONTROL_TX,1,2),
       "mode mismatch cannot authorize payload DMA or silently fallback");
}
static void *early_stop_thread(void *arg)
{
 struct xdev_ext_mech_session *s=arg;
 pthread_barrier_wait(&early_race_barrier);
 if(!xdev_ext_mech_sess_stop(&s->ss))s->stop_started_ns=world->now;
 s->kicked=true;
 pthread_barrier_wait(&early_race_barrier);return NULL;
}
static void early_stop_after_lease(void)
{
 early_bind(false,false);early_grant(37,1,false);early_race_mode=1;
 pthread_t thread;CHECK(pthread_barrier_init(&early_race_barrier,NULL,2)==0,"initialize deterministic native lease STOP boundary");
 CHECK(pthread_create(&thread,NULL,early_stop_thread,&world->side[0].current->s)==0,"independent STOP thread waits for final successful lease");
 int ret=stack_start(world,0,37,0);
 CHECK(pthread_join(thread,NULL)==0,"STOP thread completed before submission result is inspected");
 pthread_barrier_destroy(&early_race_barrier);
 CHECK(early_race_hits==1,"real final TX lease was acquired before admission closed");
 CHECK(!early_data(0),"STOP after lease and before native_begin forbids all native TX posts");
 pump(world,1000000);
 CHECK(count(world,STACK_EV_LEASE_ACQUIRE,0,-1)==4&&count(world,STACK_EV_LEASE_RELEASE,0,-1)==4,
       "STOP after final lease releases each proven idle TX lease exactly once");
 unsigned errors=0,success=0;
 for(size_t j=0;j<world->logs;j++){
  struct stack_event e=world->log[j];if(e.kind!=STACK_EV_PUBLISH||e.endpoint!=0)continue;
  if(e.status<0)errors++;else success++;
 }
 CHECK(!success&&((ret==0&&errors==1)||(ret<0&&errors==0)),"closed admission ends in exactly one direct error or asynchronous negative completion ownership");
 CHECK(!link(0)->up,"STOP after consumed peer grant tears down its native commitment");
}
static void early_ack_before_post_return(void)
{
 early_bind(false,false);early_grant(37,1,false);
 fault(world,STACK_FAULT_HOLD_CALLBACK,0,0,0,1,0);early_race_mode=2;
 CHECK(stack_start(world,0,37,0)==0,"actual TX post accepts native group with early remote completion");
 CHECK(early_race_hits==1&&early_ack_during_post==1,"real RX consumer release sends ACK through NHI before TX post caller returns");
 CHECK(!count(world,STACK_EV_PUBLISH,0,-1),"early ACK cannot release active local native lease");
 fault(world,STACK_FAULT_RELEASE_CALLBACKS,0,0,0,0,0);pump(world,1000000);
 CHECK(count(world,STACK_EV_PUBLISH,0,-1)==1,"ACK arriving before post return survives acceptance merge and retires after local completion");
 CHECK(count(world,STACK_EV_CONTROL_TX,1,3)==1,"early ACK receipt does not require duplicate remote disposition");
}
static void early_local_before_post_return(void)
{
 early_bind(false,false);early_grant(37,1,false);early_race_mode=3;
 CHECK(stack_start(world,0,37,0)==0,"native TX accepts despite real callback before post caller return");
 CHECK(early_race_hits==1&&early_callbacks_during_post==4,"all four actual NHI TX callbacks precede native post acceptance merge");
 CHECK(!count(world,STACK_EV_PUBLISH,0,-1)&&!count(world,STACK_EV_CONTROL_TX,1,3),"early local completion alone retains remote disposition custody");
 CHECK(stack_release(world,1,37)==0,"real consumer releases after early local callbacks");pump(world,1000000);
 CHECK(count(world,STACK_EV_PUBLISH,0,-1)==1,"early local completion survives acceptance merge and retires exactly once after ACK");
}
static void early_partial_tx_lease(void)
{
 early_bind(false,false);early_grant(37,1,false);
 early_lease_fail_after=2;early_lease_fail_endpoint=0;early_lease_attempts=0;
 int ret=stack_start(world,0,37,0);early_lease_fail_after=0;
 fprintf(stderr,"EARLY_PARTIAL_SUBMIT result=%d attempts=%d acquired=%zu\n",ret,early_lease_attempts,count(world,STACK_EV_LEASE_ACQUIRE,0,-1));
 CHECK(!early_data(0),"failure after two actual leases cannot post any native TX element");
 CHECK(count(world,STACK_EV_LEASE_ACQUIRE,0,-1)==2,"exactly two actual TX leases were acquired before allocator refused");
 CHECK(count(world,STACK_EV_LEASE_RELEASE,0,-1)==2,"only proven idle partial TX leases release exactly once");
 pump(world,1000000);
 CHECK(count(world,STACK_EV_FAILURE,0,-1)>0,"partial mapping failure becomes terminal through actual stage/CQE path");
 CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"partial allocation failure fabricates no remote successful ACK");
 CHECK(stack_start(world,0,37,0)<0&&!early_data(0),"consumed reservation failure never retries same exact grant");
}
static void early_facts(bool ack_key)
{
 early_bind(false,false);early_grant(37,1,false);
 CHECK(stack_start(world,0,37,0)==0,"first exact TX native group remains active awaiting real consumer");pump(world,1000000);
 size_t after=world->logs;
 if(ack_key){CHECK(stack_release(world,1,37)==0,"real consumer creates ACK with wire key0");pump(world,1000000);}
 else{
  world->cfg.span[0].allocation_off+=524288;world->cfg.span[1].allocation_off+=524288;
  early_grant(901,2,false);pump(world,25000000);
 }
 unsigned selected=0;
 for(size_t j=after;j<world->logs;j++){
  struct stack_event e=world->log[j];
  if(e.kind!=STACK_EV_PROTOCOL||e.endpoint!=0||e.raw_len!=320)continue;
  struct xdev_ext_xdomain_proto_info_v2 i;memcpy(&i,e.raw,sizeof(i));
  if(!(i.early_facts&8))continue;
  if(ack_key?i.base.event!=6:(i.base.event!=9&&i.base.event!=16))continue;
  selected++;
  CHECK(i.key==37&&i.base.group==1,"HAS_BATCH facts retain selected actual batch key/group despite future grant or ACK key0");
 }
 CHECK(selected>0,"actual policy observes selected-slot LOCAL/READY or ACK facts");
}
static void early_window_reuse(void)
{
 early_bind(false,false);
 for(unsigned g=1;g<=66;g++){
  if(g>1){world->cfg.span[0].allocation_off+=524288;world->cfg.span[1].allocation_off+=524288;}
  u64 key=37+(g-1)*19;
  fprintf(stderr,"EARLY_WINDOW_BOUNDARY requested=%u\n",g);
  early_grant(key,g,false);
  CHECK(stack_start(world,0,key,0)==0,"each canonical actual TX consumes its own grant across reliable window reuse");pump(world,1000000);
  CHECK(stack_release(world,1,key)==0,"each actual consumer releases before next window group");pump(world,1000000);
  CHECK(count(world,STACK_EV_CONTROL_TX,1,3)==g,"every released group has one ACK across reliable window reuse");
 }
 CHECK(count(world,STACK_EV_PUBLISH,0,-1)==66&&count(world,STACK_EV_PUBLISH,1,-1)==66,
       "all66 actual batches publish through reliable window wrap");
 CHECK(!count(world,STACK_EV_CONTROL_TX,-1,1),"reliable reuse retains early noRTS path");
}
static void early_receipt_deadline(void)
{
 early_bind(false,false);early_wait_grant=true;
 CHECK(stack_start(world,1,37,0)==0,"real RX batch posts while TX policy defers ACCEPT_GRANT");pump(world,1000000);
 CHECK(count(world,STACK_EV_CONTROL_RX,0,2)==1,"actual CTS reaches native TX control receive before acceptance");
 CHECK(early_grant_waits>0&&!early_data(0),"replacement BPF policy issued bounded WAIT for actual GRANT");
 /* Deliberately delay the independent receiver worker, so its own RX phase
  * timeout cannot masquerade as TX receipt-time enforcement. Native frames
  * remain owned by the actual rings, with no fabricated completion. */
 world->side[1].current->next_progress=UINT64_MAX;
 world->side[1].current->s.kicked=false;
 pump(world,29000000000ULL);
 CHECK(!count(world,STACK_EV_FAILURE,0,-1),"receipt deadline has not expired at29s");
 early_wait_grant=false;pump(world,1000000);
 CHECK(!early_data(0),"policy acceptance without actual TX still creates no native TX");
 pump(world,1100000000ULL);
 CHECK(count(world,STACK_EV_FAILURE,0,-1)>0,"grant expires at actually received+30s despite later policy acceptance");
 CHECK(!early_data(0),"receipt deadline cannot fabricate local payload work");
}
static void early_expired_submit(bool lease_boundary)
{
 early_bind(false,false);early_grant(37,1,false);
 if(lease_boundary)early_race_mode=4;
 else{world->now+=31000000000ULL;jiffies=nsecs_to_jiffies(world->now);}
 int ret=stack_start(world,0,37,0);
 fprintf(stderr,"EARLY_EXPIRED_SUBMIT result=%d native=%zu\n",ret,early_data(0));
 if(lease_boundary)CHECK(early_race_hits==1,"real final lease crosses immutable available-grant deadline after policy snapshot");
 CHECK(!early_data(0),"expired available grant cannot create new native TX even without a worker safety pass");
}
static void early_pending_commit(bool stopping)
{
 early_bind(false,false);early_wait_grant=true;
 CHECK(stack_start(world,1,37,0)==0,"real RX posts before uncooperative TX grant acceptance");pump(world,1000000);
 CHECK(count(world,STACK_EV_CONTROL_RX,0,2)==1&&early_grant_waits>0,"actual valid CTS arrived while policy repeatedly WAITs");
 world->side[1].current->next_progress=UINT64_MAX;world->side[1].current->s.kicked=false;
 size_t stops=count(world,STACK_EV_RING_STOP,0,-1);
 if(stopping){CHECK(stack_stop(world,0)<=0,"STOP closes core with pending peer grant");pump(world,1100000000ULL);}
 else pump(world,31000000000ULL);
 CHECK(count(world,STACK_EV_FAILURE,0,-1)>0,"pending CTS reaches existing terminal stage path");
 CHECK(!link(0)->up&&count(world,STACK_EV_RING_STOP,0,-1)>stops,
       "valid pending CTS is peer native commitment and expiry/STOP tears down actual local link/rings");
 CHECK(!early_data(0)&&early_data(1)==4,"pending grant failure neither posts TX nor repeats remote reservation");
 CHECK(!count(world,STACK_EV_LEASE_RELEASE,1,-1),"unnotified peer RX backing remains held until real quiescence");
 CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"pending grant teardown cannot manufacture successful ACK");
}
static void early_control_full(void)
{
 early_bind(false,false);fault(world,STACK_FAULT_CONTROL_REFUSE,1,0,0,1,0);
 CHECK(stack_start(world,1,37,0)==0,"RX arms while control TX allocation is full");pump(world,1000000);
 CHECK(early_data(1)==4&&!count(world,STACK_EV_CONTROL_TX,1,2),"real RX posts once before blocked CTS enqueue");
 pump(world,25000000);
 CHECK(early_data(1)==4&&!count(world,STACK_EV_CONTROL_TX,1,2),"blocked control retry cannot repost native RX");
 fault(world,STACK_FAULT_RELEASE_CONTROLS,1,0,0,0,0);pump(world,25000000);
 CHECK(early_data(1)==4&&count(world,STACK_EV_CONTROL_TX,1,2)==1,"control recovery advertises same immutable accepted RX once");
 struct stack_event grant=early_control(1,2,1);
 CHECK(early_le(grant.raw+40,8)==1&&!early_le(grant.raw+56,8)&&early_le(grant.raw+64,8)==37,
       "control retry preserves original group sequence and exact key");
 CHECK(stack_start(world,0,37,0)==0,"exact original grant remains consumable after control retry");pump(world,1000000);
 CHECK(stack_release(world,1,37)==0,"actual consumer releases control-pressure batch");pump(world,1000000);
}
static void early_bind_exhaustion(void)
{
 struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);early_flags=2;
 link(0)->early_bind_next=UINT64_MAX;
 struct stack_session_config tx={.direction=1,.groups=1};
 CHECK(stack_session(w,0,&tx)==0,"last nonzero bind ID can be issued");
 CHECK(link(0)->early_bind_next==0,"last ID saturates link counter to exhausted0");
 struct epoch *ep=w->side[0].current;ep->s.st.cls->unbind(&ep->s.st);ep->bound=false;
 tx.allocation_bias=524288;tx.generation=117;
 CHECK(stack_next_session(w,0,&tx)==-EOVERFLOW,"exhausted same link never wraps bind ID on new CREATE");
 CHECK(!early_data(0)&&!count(w,STACK_EV_CONTROL_TX,0,7),"failed bind never publishes handshake/native progress");
}
static void early_seq_overflow(void)
{
 early_bind(false,false);link(0)->chan[0].announced=UINT64_MAX-2;link(1)->chan[0].consumed=UINT64_MAX-2;
 CHECK(stack_start(world,1,37,0)==0,"actual RX ARMs before checked sequence admission");pump(world,1000000);
 CHECK(!early_data(0)&&!early_data(1)&&!count(world,STACK_EV_CONTROL_TX,1,2),"whole-group sequence overflow cannot accept native work or advertise grant");
 CHECK(link(0)->chan[0].announced==UINT64_MAX-2&&link(1)->chan[0].consumed==UINT64_MAX-2,
       "overflow rejection never wraps cumulative native sequence");
}
static void early_consumer(const char *name)
{
 early_bind(false,false);early_grant(37,1,false);
 CHECK(stack_start(world,0,37,0)==0,"exact granted TX feeds real downstream consumer");pump(world,1000000);
 CHECK(count(world,STACK_EV_PUBLISH,1,-1)==1&&!count(world,STACK_EV_CONTROL_TX,1,3),"RX CQE exists but no successful ACK before consumer result");
 struct epoch *epoch=world->side[1].current;struct xdev_ext_mech_batch *b=&epoch->b[0];
 if(!strcmp(name,"batch_end_only")){
  epoch->s.st.cls->batch_end(&epoch->s.st,b,0);pump(world,1000000);
  CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"batch_end alone never authorizes successful ACK");
 }else{
  if(!strcmp(name,"consumer_error"))b->status=-EIO;
  else if(!strcmp(name,"consumer_sequester"))b->sequester=true;
  else CHECK(false,"known downstream consumer disposition");
  CHECK(stack_release(world,1,37)==0,"actual consumer release reports error or sequester");pump(world,1000000);
  CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"failed or sequestered consumer never authorizes successful ACK");
  CHECK(count(world,STACK_EV_CONTROL_TX,1,2)==1,"consumer failure creates no next credit/grant");
 }
}
static void early_unknown_stop(void)
{
 early_bind(false,false);early_grant(37,1,false);size_t posted=early_data(1);
 fault(world,STACK_FAULT_GOING_AWAY,1,0,0,0,0);
 int stop=stack_stop(world,1);CHECK(stop<0,"unknown native RX cannot falsely drain on STOP");
 pump(world,1000000);
 CHECK(early_data(1)==posted&&!early_data(0),"unknown advertised RX never reposts storage or fabricates TX");
 CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"unknown RX disposition creates no successful ACK");
 for(size_t i=0;i<world->logs;i++){
  struct stack_event e=world->log[i];
  CHECK(e.kind!=STACK_EV_LEASE_RELEASE||e.endpoint!=1,"unknown RX native backing remains in custody");
 }
}
static void early_single_posted(void)
{
 early_bind(false,false);early_grant(37,1,false);
 world->cfg.span[0].allocation_off+=524288;world->cfg.span[1].allocation_off+=524288;
 CHECK(stack_start(world,1,901,0)==0,"second distinct actual batch ARMs while first native RX outstanding");
 pump(world,1000000);
 CHECK(early_data(1)==4&&count(world,STACK_EV_CONTROL_TX,1,2)==1,"single posted-group occupancy blocks second actual RX/grant");
 /* Restore only the caller's next TX input geometry to first group's storage. */
 world->cfg.span[0].allocation_off-=524288;world->cfg.span[1].allocation_off-=524288;
 CHECK(stack_start(world,0,37,0)==0,"first exact grant TX makes first local RX quiescent");pump(world,1000000);
 CHECK(early_data(1)==8&&count(world,STACK_EV_CONTROL_TX,1,2)==2,"second own ARMED storage receives grant after first local quiescence");
 CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"retiring RX occupancy does not impersonate consumer release");
 struct stack_event second=early_control(1,2,2);CHECK(early_le(second.raw+64,8)==901,"second grant retains second actual batch exact key");
}
static void early_grant_timeout(void)
{
 early_bind(false,false);early_grant(37,1,false);
 size_t posted=early_data(1);fault(world,STACK_FAULT_BPF_INTENT,0,0,0,7,0);
 pump(world,31000000000ULL);
 CHECK(count(world,STACK_EV_FAILURE,-1,-1)>0,"C expires available grant without local TX despite WAIT");
 CHECK(!early_data(0)&&early_data(1)==posted,"grant expiry never retries native group or fabricates TX");
 CHECK(!count(world,STACK_EV_CONTROL_TX,1,3),"unwritten granted RX cannot fabricate successful ACK");
 safety(world);
}
static void early_timeout(void)
{
 struct stack_config c=geometry();struct stack_world *w=create(&c);login(w);early_flags=2;
 struct stack_session_config tx={.direction=1,.groups=1};CHECK(stack_session(w,0,&tx)==0,"unpaired actual TX binds");
 fault(w,STACK_FAULT_BPF_INTENT,0,0,0,7,0);
 pump(w,1000000);pump(w,31000000000ULL);
 CHECK(count(w,STACK_EV_FAILURE,0,-1)>0,"C deadline ends unbound pair even if BPF always WAITs");
 CHECK(!early_data(0)&&!early_data(1),"unbound timeout never creates payload custody");
}
int main(int argc,char **argv)
{
 if(argc!=2)return 2;
 case_name=argv[1];budget=12000;
 if(!strcmp(case_name,"opt_in")){struct stack_config c=geometry();struct stack_world*w=create(&c);login(w);early_flags=2;
  struct stack_session_config rx={.direction=2,.groups=1};int got=stack_session(w,1,&rx);
  fprintf(stderr,"EARLY_BIND_RESULT %d\n",got);CHECK(got==0,"EARLY bit1 admits a real receive endpoint");}
 else if(!strcmp(case_name,"default_v1")){early_flags=0;happy(0);}
 else if(!strcmp(case_name,"early_happy"))early_happy(false,false);
 else if(!strcmp(case_name,"short_tail"))early_happy(true,false);
 else if(!strcmp(case_name,"ack_before_local"))early_happy(false,true);
 else if(!strcmp(case_name,"delayed_peer_create"))early_bind(true,false);
 else if(!strcmp(case_name,"missing_confirm"))early_missing_confirm();
 else if(!strcmp(case_name,"unbound_wait_deadline"))early_timeout();
 else if(!strcmp(case_name,"armed_ticket")||!strcmp(case_name,"armed_pool")||!strcmp(case_name,"stop_before_post"))early_armed_invalidation(case_name);
 else if(!strcmp(case_name,"old_bind"))early_old_bind();
 else if(!strcmp(case_name,"tx_before_grant")||!strcmp(case_name,"zero_key"))early_tx_wait(!strcmp(case_name,"zero_key"));
 else if(!strcmp(case_name,"mixed_v1_tx")||!strcmp(case_name,"mixed_v1_rx"))early_mixed(!strcmp(case_name,"mixed_v1_tx"));
 else if(!strcmp(case_name,"available_deadline"))early_grant_timeout();
 else if(!strcmp(case_name,"single_posted"))early_single_posted();
 else if(!strcmp(case_name,"batch_end_only")||!strcmp(case_name,"consumer_error")||!strcmp(case_name,"consumer_sequester"))early_consumer(case_name);
 else if(!strcmp(case_name,"unknown_stop"))early_unknown_stop();
 else if(!strcmp(case_name,"control_full"))early_control_full();
 else if(!strcmp(case_name,"bind_exhaustion"))early_bind_exhaustion();
 else if(!strcmp(case_name,"seq_overflow"))early_seq_overflow();
 else if(!strcmp(case_name,"window_reuse66"))early_window_reuse();
 else if(!strcmp(case_name,"receipt_deadline"))early_receipt_deadline();
 else if(!strcmp(case_name,"stop_after_lease"))early_stop_after_lease();
 else if(!strcmp(case_name,"ack_before_post_return"))early_ack_before_post_return();
 else if(!strcmp(case_name,"local_before_post_return"))early_local_before_post_return();
 else if(!strcmp(case_name,"partial_tx_lease"))early_partial_tx_lease();
 else if(!strcmp(case_name,"facts_selected_slot")||!strcmp(case_name,"facts_ack_key"))early_facts(!strcmp(case_name,"facts_ack_key"));
 else if(!strcmp(case_name,"pending_deadline")||!strcmp(case_name,"stop_pending_grant"))early_pending_commit(!strcmp(case_name,"stop_pending_grant"));
 else if(!strcmp(case_name,"first_cts_pair")||!strcmp(case_name,"first_cts_shape"))early_first_invalid_cts(!strcmp(case_name,"first_cts_shape"));
 else if(!strcmp(case_name,"expired_submit")||!strcmp(case_name,"expired_after_lease"))early_expired_submit(!strcmp(case_name,"expired_after_lease"));
 else early_invalid(case_name);
 printf("EARLY_ASSERTIONS %s %u\n",case_name,assertions);return 0;
}

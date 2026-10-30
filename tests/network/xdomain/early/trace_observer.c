/* SPDX-License-Identifier: GPL-2.0 */
/* Independent observation oracle. Only records production hook calls.
 * The existing composition still owns every protocol/action assertion. */
#ifndef STACK_HAS_XDOMAIN_TRACE
/* Allows pre-feature sources to compile: missing calls are semantic RED. */
struct xdev_ext_xdomain_trace {
 const char *phase;
 u64 local_inc, remote_inc, tx_bind, rx_bind, group, key, ticket, pool_generation;
 u32 early;
 int status;
 bool quiesced;
};
#endif

struct early_trace_row {
 struct xdev_ext_xdomain_trace value;
 u64 session, now, boundary;
 u32 stage, direction, endpoint;
 bool control_observed;
};
static struct early_trace_row early_trace_rows[8192];
static unsigned early_trace_count;

bool xdev_ext_mech_trace_xdomain_enabled(void) { return true; }

void xdev_ext_mech_trace_xdomain(struct xdev_ext_mech_stage *st,
                               const struct xdev_ext_xdomain_trace *event)
{
 CHECK(st && st->s && event && event->phase, "trace requires real stage/session");
 CHECK(early_trace_count < 8192, "observation capacity cannot silently lose records");
 struct early_trace_row *r=&early_trace_rows[early_trace_count++];
 r->value=*event;
 r->session=st->s->id;
 r->stage=st->index;
 r->direction=st->direction;
 r->endpoint=stack_endpoint_stage(st);
 r->now=world->now;
 r->boundary=world->logs;
 if(!strcmp(event->phase,"cts_sent") || !strcmp(event->phase,"ack_sent") ||
    !strcmp(event->phase,"fail_sent")) {
  unsigned type=!strcmp(event->phase,"cts_sent")?2U:
                !strcmp(event->phase,"ack_sent")?3U:5U;
  for(size_t i=0;i<world->logs;i++) {
   const struct stack_event *b=&world->log[i];
   r->control_observed |= b->kind==STACK_EV_CONTROL_TX && b->endpoint==r->endpoint &&
     b->control_type==type && b->raw_len>=64 &&
     early_le(b->raw+(b->raw[4]==2?40:32),8)==event->group;
  }
 }
 /* ts_ns is the deterministic Host clock, not a hardware measurement. */
 printf("EARLY_TRACE abi=xdev-xdomain-v1 phase=%s session_id=%llu stage=%u direction=%u early=%u local_inc=%llu remote_inc=%llu tx_bind=%llu rx_bind=%llu group=%llu key=%llu ticket=%llu pool_generation=%llu status=%d quiesced=%u ts_ns=%llu\n",
   event->phase,(unsigned long long)r->session,r->stage,r->direction,event->early,
   (unsigned long long)event->local_inc,(unsigned long long)event->remote_inc,
   (unsigned long long)event->tx_bind,(unsigned long long)event->rx_bind,
   (unsigned long long)event->group,(unsigned long long)event->key,
   (unsigned long long)event->ticket,(unsigned long long)event->pool_generation,
   event->status,event->quiesced,(unsigned long long)r->now);
}

static size_t trace_count(const char *phase,int endpoint)
{
 size_t n=0;
 for(unsigned i=0;i<early_trace_count;i++)
  n+=!strcmp(early_trace_rows[i].value.phase,phase) &&
      (endpoint<0 || early_trace_rows[i].endpoint==(unsigned)endpoint);
 return n;
}

static int trace_first(const char *phase,unsigned endpoint,u64 key)
{
 for(unsigned i=0;i<early_trace_count;i++)
  if(!strcmp(early_trace_rows[i].value.phase,phase) &&
     early_trace_rows[i].endpoint==endpoint && early_trace_rows[i].value.key==key)
   return (int)i;
 return -1;
}

static int trace_required(const char *phase,unsigned endpoint,u64 key)
{
 int i=trace_first(phase,endpoint,key);
 CHECK(i>=0,"required production phase/key is observed");
 return i;
}

static void trace_successful_group(u64 key,u64 group)
{
 int rx=trace_required("native_accepted",1,key);
 int tx=trace_required("native_accepted",0,key);
 int rc=trace_required("native_complete",1,key);
 int tc=trace_required("native_complete",0,key);
 int cs=trace_required("cts_sent",1,key);
 int cr=trace_required("cts_received",0,key);
 int ga=trace_required("grant_accepted",0,key);
 int release=trace_required("consumer_release",1,key);
 int ack=trace_required("ack_sent",1,key);
 CHECK(rx<cs && cr<=ga && ga<tx,"native RX, CTS and authorized TX order");
 CHECK(rc<release && release<ack,"native RX completion and actual consumer release precede ACK");
 /* Completion may race with the posting function's return. */
 CHECK(early_trace_rows[rc].value.quiesced && !early_trace_rows[rc].value.status &&
       early_trace_rows[tc].value.quiesced && !early_trace_rows[tc].value.status,
       "successful native completion needs known quiescent disposition");
 int indices[]={rx,tx,rc,tc,cs,cr,ga,release,ack};
 for(unsigned i=0;i<sizeof(indices)/sizeof(indices[0]);i++){
  const struct early_trace_row *r=&early_trace_rows[indices[i]];
  CHECK(r->value.group==group,"trace preserves immutable transport group");
  CHECK(r->value.early==1 && r->value.local_inc && r->value.remote_inc &&
        r->value.tx_bind && r->value.rx_bind,
        "EARLY payload observation retains exact pair scope");
 }
 CHECK(early_trace_rows[rx].value.ticket && early_trace_rows[rx].value.pool_generation &&
       early_trace_rows[tx].value.ticket && early_trace_rows[tx].value.pool_generation,
       "accepted local work retains ticket and pool generation");
 CHECK(early_trace_rows[rc].value.ticket==early_trace_rows[rx].value.ticket &&
       early_trace_rows[tc].value.ticket==early_trace_rows[tx].value.ticket,
       "native completion refers to the same accepted lifetime");
}

static void early_trace_validate(const char *name)
{
 CHECK(early_trace_count>0,"production observation hooks must execute");
 CHECK(trace_count("stage_bound",-1)>0,"successful endpoint bind must be observable");
 for(unsigned i=0;i<early_trace_count;i++){
  const struct early_trace_row *r=&early_trace_rows[i];
  CHECK(r->session && r->direction==(r->endpoint?2U:1U),
        "observation comes from actual session and direction");
  CHECK(r->value.early==(!strcmp(name,"default_v1")?0U:1U),
        "request mode cannot be confused with the opposite admitted mode");
  if(!strcmp(r->value.phase,"cts_sent") || !strcmp(r->value.phase,"ack_sent") ||
     !strcmp(r->value.phase,"fail_sent")){
   unsigned type=!strcmp(r->value.phase,"cts_sent")?2U:
                 !strcmp(r->value.phase,"ack_sent")?3U:5U;
   CHECK(r->control_observed && (type==5U ? r->value.status<0 : r->value.status==0),
         "control observation requires native acceptance and the exact success/error disposition");
  }
 }
 if(strcmp(name,"default_v1")) {
  CHECK(trace_count("cts_sent",1)==count(world,STACK_EV_CONTROL_TX,1,2),
        "failed CTS enqueue cannot increase successful CTS observations");
  CHECK(trace_count("ack_sent",1)==count(world,STACK_EV_CONTROL_TX,1,3),
        "ACK observation exactly matches accepted control sends");
 }
 if(!strcmp(name,"opt_in")){
  CHECK(trace_count("stage_bound",1)==1 && !trace_count("cts_sent",-1) &&
        !trace_count("native_accepted",-1),
        "request/admission alone proves no grant or native execution");
 }else if(!strcmp(name,"default_v1")){
  CHECK(trace_count("tx_attempt",0)>0 && trace_count("native_accepted",0)>0,
        "ordinary path has the same observation boundaries");
 }else if(!strcmp(name,"early_happy") || !strcmp(name,"short_tail")){
  trace_successful_group(37,1);trace_successful_group(901,2);
  int second=trace_required("cts_sent",1,901),first_release=trace_required("consumer_release",1,37);
  CHECK(second<first_release,"disjoint second grant precedes prior consumer release");
  CHECK(trace_required("grant_accepted",0,37)<trace_required("tx_attempt",0,37) &&
        trace_required("grant_accepted",0,901)<trace_required("tx_attempt",0,901),
        "pregrant classification uses actual first TX attempt");
  CHECK(trace_count("native_accepted",0)==2 && trace_count("native_complete",0)==2 &&
        trace_count("native_accepted",1)==2 && trace_count("native_complete",1)==2,
        "two groups generate exactly two native observations per direction");
 }else if(!strcmp(name,"tx_before_grant") || !strcmp(name,"zero_key")){
  u64 key=!strcmp(name,"zero_key")?0:37;
  trace_successful_group(key,1);
  CHECK(trace_count("tx_attempt",0)==2 &&
        trace_required("tx_attempt",0,key)<trace_required("grant_accepted",0,key),
        "the initial EAGAIN submit is retained and cannot masquerade as a pregrant");
 }else if(!strcmp(name,"duplicate_cts")){
  trace_successful_group(37,1);
  CHECK(trace_count("cts_received",0)>1 && trace_count("grant_accepted",0)==1 &&
        trace_count("native_accepted",0)==1 && trace_count("native_complete",0)==1,
        "duplicate receipt cannot manufacture another grant or accepted native group");
 }else if(!strcmp(name,"batch_end_only")){
  CHECK(!trace_count("consumer_release",1) && !trace_count("ack_sent",1),
        "batch_end is not consumer release or ACK authority");
 }else if(!strcmp(name,"consumer_error") || !strcmp(name,"consumer_sequester")){
  int release=trace_required("consumer_release",1,37);
  CHECK((early_trace_rows[release].value.status<0 || !early_trace_rows[release].value.quiesced) &&
        !trace_count("ack_sent",1),
        "failed or sequestered release cannot be reported as successful ACK");
 }else if(!strcmp(name,"unknown_stop")){
  CHECK(!trace_count("ack_sent",1) && !trace_count("consumer_release",1),
        "unknown native STOP grants no successful disposition or consumer release");
  for(unsigned i=0;i<early_trace_count;i++)
   CHECK(strcmp(early_trace_rows[i].value.phase,"native_complete") ||
         early_trace_rows[i].endpoint!=1 || early_trace_rows[i].value.status ||
         !early_trace_rows[i].value.quiesced,
         "unknown STOP cannot appear as reusable successful native completion");
 }else if(!strcmp(name,"control_full")){
  trace_successful_group(37,1);
  CHECK(trace_count("cts_sent",1)==1 && trace_count("native_accepted",1)==1,
        "control-pressure retries preserve one native post and one successful CTS");
 }else if(!strcmp(name,"single_posted")){
  CHECK(trace_count("native_accepted",1)==2 && trace_count("native_complete",1)==1 &&
        !trace_count("consumer_release",1) && !trace_count("ack_sent",1),
        "second disjoint native post does not invent prior consumer release");
 }else{
  trace_successful_group(37,1);
 }
 printf("EARLY_TRACE_ASSERTIONS %s observations=%u\n",name,early_trace_count);
}

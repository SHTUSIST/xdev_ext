/* SPDX-License-Identifier: GPL-2.0 */
/* Included after the existing stack environment, never in production code. */
static unsigned checks, destroyed, queued_at_destroy;
static bool inject_at_destroy;
static struct xdev_ext_mech_session *receiving;
unsigned b4_raw_queued(struct xdev_ext_mech_stage *);
#define B4_CHECK(c, why) do { checks++; if(!(c)) { \
 fprintf(stderr,"B4_ASSERT: %s\n",why); exit(1); } } while(0)

static unsigned events(unsigned kind,unsigned endpoint,unsigned type)
{
 unsigned count=0;
 for(size_t i=0;i<world->logs;i++) {
  const struct stack_event *event=&world->log[i];
  if(event->kind==kind&&event->endpoint==endpoint&&
     (!type||event->control_type==type))count++;
 }
 return count;
}
static void send_rts(void)
{
 B4_CHECK(stack_start(world,0,37,0)==0,"real sender admits the late group");
 B4_CHECK(stack_pump(world,4096,1000000)==0,"bounded real control-ring delivery");
 B4_CHECK(events(STACK_EV_CONTROL_TX,0,1)==1,"sender actually announced one RTS");
 /* Two 8192-byte source spans split into four TB_FRAME_SIZE=4096 frames.
  * This literal is independent of the production layout-count helper. */
 for(size_t i=0;i<world->logs;i++) {
  const struct stack_event *event=&world->log[i];
  if(event->kind==STACK_EV_CONTROL_TX&&event->endpoint==0&&event->control_type==1)
   B4_CHECK(event->raw_len>=54&&event->raw[52]==4&&event->raw[53]==0,
            "actual announced wire count is the four independent native frames");
 }
 B4_CHECK(events(STACK_EV_CONTROL_RX,1,1)==1,"receiver actually decoded native RTS");
 B4_CHECK(events(STACK_EV_DATA_POST,0,0)==0&&events(STACK_EV_DATA_POST,1,0)==0,
          "late RTS cannot create native payload ownership after STOP");
}
/* These are kernel OS/resource facilities, not protocol decisions. */
int kthread_mod_delayed_work(void *worker,struct delayed_work *work,unsigned long delay)
{
 (void)work;(void)delay;
 struct xdev_ext_mech_session *s=worker;
 B4_CHECK(s&&!s->worker_gone,"core must never queue a destroyed worker");
 s->kicked=true;
 return 0;
}
static bool kthread_cancel_delayed_work_sync(struct delayed_work *work)
{ (void)work;return false; }
static void synchronize_rcu(void) { }
static void kthread_flush_worker(void *worker) { (void)worker;abort(); }
static void kthread_destroy_worker(void *worker)
{
 B4_CHECK(worker==receiving&&receiving->worker_gone,
          "actual release marked worker_gone before destroying worker");
 B4_CHECK(!xdev_ext_mech_session_admits(receiving),"admission is already closed");
 B4_CHECK(link(1)->chan[0].ep[1]!=NULL,"actual receive endpoint still published");
 B4_CHECK(!receiving->native_controls&&!receiving->ss.inflight&&
          !receiving->ss.sequestered,"release precondition has no accepted or UNKNOWN payload");
 destroyed++;
 if(inject_at_destroy) {
  send_rts();
  queued_at_destroy=b4_raw_queued(&receiving->st[0]);
  fprintf(stderr,"B4_WINDOW worker_gone=%u endpoint_published=%u raw_rts=%u native_controls=%u consumed=%llu fail_tx=%u link_up=%u\n",
   receiving->worker_gone,link(1)->chan[0].ep[1]!=NULL,queued_at_destroy,
   receiving->native_controls,(unsigned long long)link(1)->chan[0].consumed,
   events(STACK_EV_CONTROL_TX,1,5),link(1)->up);
 }
}
static void timer_shutdown_sync(int *timer) { (void)timer; }
static DEFINE_MUTEX(xdev_ext_mech_live_lock);
static void xdev_ext_mech_stats_fill(struct xdev_ext_mech_session *s,
                                    struct xdev_ext_mech_stats *stats)
{ (void)s;(void)stats;abort(); }
static void xdev_ext_mech_transport_stats_fill(struct xdev_ext_mech_session *s,
 struct xdev_ext_mech_transport_stats_v4 *stats,u32 version)
{ (void)s;(void)stats;(void)version;abort(); }
static void xdev_ext_mech_quarantine(struct xdev_ext_mech_session *s)
{ (void)s;abort(); }
#define atomic64_add(delta, p) ((p)->n+=(delta))
static void fput(void *file) { (void)file; }
static void xdev_ext_mech_class_put(const struct xdev_ext_mech_class_ops *cls)
{ B4_CHECK(cls==stack_x5_ops(),"release puts the actual class"); }
static void eventfd_ctx_put(void *ctx) { (void)ctx;abort(); }
static void xdev_ext_mech_ops_put(void *ops,bool pinned,void *owner)
{ (void)ops;(void)pinned;(void)owner;abort(); }
static void xdev_ext_mech_start_queue_free(void *queue)
{ B4_CHECK(!queue,"no unrelated start queue in teardown fixture"); }

/* ACTUAL_CORE_RELEASE */

int main(int argc,char **argv)
{
 if(argc!=2)return 2;
 inject_at_destroy=!strcmp(argv[1],"worker_gone_before_detach");
 B4_CHECK(inject_at_destroy||!strcmp(argv[1],"after_detach"),"known scenario");
 struct stack_config config={.mapping_base={0x1100000000ULL,0x2200000000ULL},
  .local_inc={101,203},.generation={17,29},.first_seq=37,.depth=3,
  .nr_frames=2,.frame_size=65536,.native_elems=4,.channels=1,
  .span={{65536,4096,8192},{196608,8192,8192}}};
 struct stack_world *w=NULL;
 B4_CHECK(stack_new(&config,&w)==0,"create established stack environment");
 B4_CHECK(stack_probe(w,0)==0&&stack_probe(w,1)==0,"real X3 endpoint probes");
 B4_CHECK(stack_pump(w,4096,1000000)==0,"real bilateral login");
 struct stack_session_config rx={.direction=2,.groups=1},tx={.direction=1,.groups=1};
 B4_CHECK(stack_session(w,1,&rx)==0&&stack_session(w,0,&tx)==0,"real X5/family/ring binds");
 for(unsigned e=0;e<2;e++) {
  struct xdev_ext_mech_session *s=&w->side[e].current->s;
  s->worker=s;s->nr_bound=s->nr_stages=1;INIT_LIST_HEAD(&s->live_node);
 }
 receiving=&w->side[1].current->s;
 B4_CHECK(stack_stop(w,1)==0,"idle STOP drains before final release");
 B4_CHECK(link(1)->chan[0].consumed==0,"initial receive sequence is zero");
 b4_embedded_session=receiving;
 B4_CHECK(xdev_ext_mech_session_release_report(receiving,NULL)==0,"actual core release succeeds");
 w->side[1].current->bound=false;
 B4_CHECK(destroyed==1&&receiving->worker_gone,"actual worker destruction executed once");
 B4_CHECK(!receiving->st[0].priv&&!link(1)->chan[0].ep[1],
          "actual class unbind/family fini/ring endpoint detach executed");
 if(!inject_at_destroy)send_rts();
 unsigned replies=events(STACK_EV_CONTROL_TX,1,5);
 u64 consumed=link(1)->chan[0].consumed;
 bool terminal=!link(1)->up;
 fprintf(stderr,"B4_OUTCOME case=%s fail_tx=%u consumed=%llu terminal=%u queued_before_detach=%u\n",
  argv[1],replies,(unsigned long long)consumed,terminal,queued_at_destroy);
 if(!inject_at_destroy)
  B4_CHECK(replies==1&&consumed==4&&!terminal,
           "detached-endpoint control gets exactly one FAIL and consumes exactly four frames without link failure");
 if(inject_at_destroy&&!replies&&!consumed&&!terminal) {
  /* Preserve the primary outcome before provoking the downstream symptom.
   * A later sequence-gap failure must not retroactively satisfy its owner. */
  B4_CHECK(stack_start(w,0,38,0)==0,"sender admits a later group after dropped RTS");
  B4_CHECK(stack_pump(w,4096,1000000)==0,"later actual RTS reaches detached receiver");
  fprintf(stderr,"B4_SEQUENCE_GAP later_rts=%u receiver_consumed=%llu link_up=%u failures=%u\n",
   events(STACK_EV_CONTROL_TX,0,1),(unsigned long long)link(1)->chan[0].consumed,
   link(1)->up,events(STACK_EV_FAILURE,0,0)+events(STACK_EV_FAILURE,1,0));
 }
 B4_CHECK((replies==1&&consumed==4)||terminal,
  "late RTS retains a live reply owner or ends in FAIL+exact sequence consumption or terminal link; teardown must not silently discard it");
 B4_CHECK(events(STACK_EV_DATA_POST,0,0)==0&&events(STACK_EV_DATA_POST,1,0)==0,
          "refusal cannot acquire or release accepted DMA/UNKNOWN ownership");
 printf("B4_ASSERTIONS %s %u\n",argv[1],checks);
 return 0;
}

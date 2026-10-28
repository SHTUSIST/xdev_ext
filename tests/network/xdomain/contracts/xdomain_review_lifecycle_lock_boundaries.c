/* SPDX-License-Identifier: GPL-2.0 */
/* Hardware/kernel API recordings only; production owns all link decisions. */
/* Optional scheduler instrumentation, inactive for the original 38 cases. */
static void (*lock_observer)(const void *,bool,bool);
static void fixture_lock_event(const void *object,bool locked,bool spin)
{ if (lock_observer) lock_observer(object,locked,spin); }
struct observation { const char *name; const void *object; unsigned long value; };
static struct observation trace[512];
static unsigned int nr_trace;
static struct xdev_ext_xd_link *live_link;
static bool removed, link_freed, rings_running, ring_warn;
static int ring_calls_after_remove, ring_starts, ring_stops, ring_frees;
static int paths_result, start_result, alloc_result, request_result;
static int requests, responses, logouts, dead_calls, dead_error, pci_gets, pci_puts;
/* One scheduler event while the native request is active, before its reply. */
static void (*during_request)(void);
static int handler_regs, handler_live, driver_regs, class_live;
static int fail_registration;
static unsigned int property_fail_index, property_add_calls, property_entries;
static bool property_dir_live, property_registered, driver_live;
static u64 reply_inc=0x1111, random_counter=0x9000;
static u64 random_values[8];
static unsigned int random_nr,random_index;
static u32 reply_type=XDEV_EXT_XD_LOGIN_RESPONSE, reply_status;
static struct xdev_ext_xd_login last_request, paths_peer;
static struct xdev_ext_xd_login_response last_response;
static struct xdev_ext_mech_stage *dead_stage;
static struct tb_protocol_handler *registered_handler;
static struct tb_service_driver *registered_driver;
static struct tb_property_dir property;
static struct work_struct *running_at_cancel;
static void (*during_cancel)(struct work_struct *);
static void observe(const char *name,const void *object,unsigned long value)
{ assert(nr_trace<ARRAY_SIZE(trace)); trace[nr_trace++]=(struct observation){name,object,value}; }
static void event(const char *name) { observe(name,NULL,0); }
static int event_index(const char *name)
{ for (unsigned int i=0;i<nr_trace;i++) if (!strcmp(trace[i].name,name)) return (int)i; return -1; }
static int events(const char *name)
{ int n=0; for (unsigned int i=0;i<nr_trace;i++) n+=!strcmp(trace[i].name,name); return n; }
static void clear_trace(void) { nr_trace=0; }
static void native_call(const char *name,struct xdev_ext_xd_link *xl)
{ if (removed) ring_calls_after_remove++; assert(xl); event(name); }
static struct pci_dev *pci_dev_get(struct pci_dev *p)
{ assert(p); p->refs++; pci_gets++; event("pci_get"); return p; }
static void pci_dev_put(struct pci_dev *p)
{ assert(p && p->refs>0); p->refs--; pci_puts++; event("pci_put"); }
static void kfree(void *p)
{ assert(p); if (p==live_link) { link_freed=true; event("link_free"); } free(p); }
static u64 get_random_u64(void)
{ event("random"); if (random_index<random_nr) return random_values[random_index++]; return ++random_counter; }
static bool queue_work(void *q,struct work_struct *w)
{ (void)q; bool old=w->pending; w->pending=true; observe("queue_work",w,0); return !old; }
static bool queue_delayed_work(void *q,struct delayed_work *w,unsigned long delay)
{ (void)q; bool old=w->work.pending; if (!old) { w->work.pending=true; w->work.delay=delay; }
  observe("queue_delayed",&w->work,delay); return !old; }
static bool mod_delayed_work(void *q,struct delayed_work *w,unsigned long delay)
{ (void)q; bool old=w->work.pending; w->work.pending=true; w->work.delay=delay;
  observe("mod_delayed",&w->work,delay); return old; }
static void cancel_barrier(struct work_struct *w)
{ review_cancel_wait(w); assert(live_link && !live_link->ctl_mutex.held);
  assert(live_link->going_away || live_link->suspended);
  observe("cancel",w,0);
  if (during_cancel) during_cancel(w);
  if (running_at_cancel==w) { running_at_cancel=NULL; w->fn(w); }
}
static bool cancel_work_sync(struct work_struct *w)
{ bool was=w->pending; w->pending=false; cancel_barrier(w); return was; }
static bool cancel_delayed_work_sync(struct delayed_work *w)
{ return cancel_work_sync(&w->work); }
static void run_work(struct work_struct *w)
{ assert(w->pending && w->fn); w->pending=false; w->fn(w); }

static int tb_xdomain_request(struct tb_xdomain *xd,const void *request,size_t size,int req_type,
                              void *reply,size_t reply_size,int resp_type,unsigned int timeout)
{ assert(xd && size==120 && reply_size==96 && req_type==TB_CFG_PKG_XDOMAIN_RESP &&
         resp_type==TB_CFG_PKG_XDOMAIN_RESP && timeout==1000);
  assert(live_link->ctl_mutex.held && !live_link->going_away && !live_link->suspended);
  memcpy(&last_request,request,size); requests++; event("request");
  if (during_request) { void (*callback)(void)=during_request; during_request=NULL; callback(); }
  const struct xdev_ext_xd_login *sent=request;
  struct xdev_ext_xd_login_response response={.type=reply_type,.status=reply_status,.incarnation=reply_inc,
      .route_hi=sent->route_hi,.route_lo=sent->route_lo,.length_sn=21,.command_id=sent->command_id,
      .requester_incarnation=sent->incarnation};
  memcpy(response.uuid,sent->uuid,16);
  memcpy(response.initiator_uuid,sent->target_uuid,16);
  memcpy(response.target_uuid,sent->initiator_uuid,16);
  memcpy(reply,&response,sizeof(response)); return request_result; }
static int tb_xdomain_response(struct tb_xdomain *xd,const void *packet,size_t size,int type)
{ assert(xd && type==TB_CFG_PKG_XDOMAIN_RESP); const struct xdev_ext_xd_login *h=packet;
  if (h->type==XDEV_EXT_XD_LOGOUT) { assert(size==120); logouts++; event("logout"); }
  else { assert(h->type==XDEV_EXT_XD_LOGIN_RESPONSE && size==96);
         memcpy(&last_response,packet,size); responses++; event("response"); }
  return 0; }
int xdev_ext_xd_rings_alloc(struct xdev_ext_xd_link *xl)
{ live_link=xl; native_call("rings_alloc",xl); xl->ctl_out_hopid=21; xl->chan[0].out_hopid=23;
  return alloc_result; }
int xdev_ext_xd_rings_start(struct xdev_ext_xd_link *xl)
{ native_call("rings_start",xl); assert(xl->ctl_mutex.held); ring_starts++;
  if (rings_running) { ring_warn=true; return -EALREADY; }
  if (start_result) return start_result;
  rings_running=true; return 0; }
void xdev_ext_xd_rings_stop(struct xdev_ext_xd_link *xl)
{ native_call("rings_stop",xl); assert(xl->ctl_mutex.held && !xl->ep_mutex.held && !active_spins);
  assert(!xl->up); rings_running=false; ring_stops++; }
void xdev_ext_xd_rings_free(struct xdev_ext_xd_link *xl)
{ native_call("rings_free",xl); assert(!rings_running && !xl->ep_mutex.held && !active_spins);
  ring_frees++; }
int xdev_ext_xd_paths_enable(struct xdev_ext_xd_link *xl,const struct xdev_ext_xd_login *peer)
{ native_call("paths_enable",xl); paths_peer=*peer;
  return tb_approve_xdomain_paths(xl->xd->tb,xl->xd,21,22,23,24); }
void xdev_ext_xd_paths_disable(struct xdev_ext_xd_link *xl)
{ native_call("paths_disable",xl);tb_disconnect_xdomain_paths(xl->xd->tb,xl->xd,21,22,23,24); }
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int error)
{ assert(st && live_link->ep_mutex.held); dead_calls++; dead_error=error; dead_stage=st; event("stage_dead"); }
int xdev_ext_xd_class_register(void)
{ event("class_register"); if (fail_registration==1) return -EIO; assert(!class_live); class_live++; return 0; }
void xdev_ext_xd_class_unregister(void)
{ assert(class_live==1); class_live--; event("class_unregister"); }
static struct tb_property_dir *tb_property_create_dir(const uuid_t *u)
{ assert(u && !property_dir_live); property_dir_live=true; property_entries=0;
  event("property_create"); return &property; }
static int tb_property_add_immediate(struct tb_property_dir *p,const char *key,u32 value)
{ assert(p==&property && property_dir_live && key); (void)value;
  property_add_calls++; observe("property_add",key,property_add_calls);
  if (property_add_calls==property_fail_index) return -ENOMEM;
  property_entries++; return 0; }
static void tb_property_free_dir(struct tb_property_dir *p)
{ assert(p==&property && property_dir_live && !property_registered);
  property_entries=0; property_dir_live=false; event("property_free"); }
static int tb_register_protocol_handler(struct tb_protocol_handler *h)
{ assert(h && h->callback && h->uuid); event("handler_register"); handler_regs++;
  if (fail_registration==2) return -EIO; assert(!handler_live); registered_handler=h; handler_live++; return 0; }
static void tb_unregister_protocol_handler(struct tb_protocol_handler *h)
{ assert(handler_live==1 && registered_handler==h); handler_live--; event("handler_unregister"); }
static int tb_register_property_dir(const char *key,struct tb_property_dir *p)
{ assert(key && p==&property && handler_live==1); event("property_register");
  if (fail_registration==3) return -EIO;
  assert(!property_registered); property_registered=true; return 0; }
static void tb_unregister_property_dir(const char *key,struct tb_property_dir *p)
{ assert(key && p==&property && property_registered); property_registered=false; event("property_unregister"); }
static int tb_register_service_driver(struct tb_service_driver *driver)
{ assert(driver && driver->probe && driver->remove && handler_live==1);
  event("driver_register"); driver_regs++; if (fail_registration==4) return -EIO;
  assert(!driver_live); driver_live=true; registered_driver=driver; return 0; }
static void tb_unregister_service_driver(struct tb_service_driver *driver)
{ assert(registered_driver==driver && driver_live); driver_live=false; event("driver_unregister"); }

/* LOGIN unit scope: the external data-path OS boundary is preverified. These
 * tests observe LOGIN, epochs and teardown, never startup challenge progress.
 * No probe object exists and executing its worker is a scope violation. */
int xdev_ext_xd_probe_prepare(struct xdev_ext_xd_link *xl,const struct xdev_ext_xd_login *peer){(void)peer;assert(!xl->probe);return 0;}
void xdev_ext_xd_probe_control_ready(struct xdev_ext_xd_link *xl){assert(!xl->probe);xl->data_verified_mask=(1U<<xl->channels)-1;xl->probe_phase=XD_PROBE_VERIFIED;}
void xdev_ext_xd_probe_login_exhausted(struct xdev_ext_xd_link *xl){assert(!xl->probe);}
void xdev_ext_xd_probe_close(struct xdev_ext_xd_link *xl){assert(!xl->probe);xl->data_verified_mask=0;}
void xdev_ext_xd_probe_work(struct work_struct *work){(void)work;assert(!"LOGIN unit cannot execute startup challenge");abort();}
ssize_t xdev_ext_xd_probe_show(struct xdev_ext_xd_link *xl,char *out){(void)out;assert(!xl->probe);return 0;}

/* SPDX-License-Identifier: GPL-2.0 */
/* All orchestration expectations come from frozen ASSERTIONS.md. This
 * includes the whole production DMA translation unit, without editing it. */
#include "kernel_boundary.h"
#include XDEV_DMA_SOURCE

static int failures;
static void check(bool ok,const char *name)
{printf("%s - %s\n",ok?"ok":"not ok",name);fflush(stdout);failures+=!ok;}
static void require(bool ok,const char *name)
{check(ok,name);if(!ok)exit(1);}
static struct module provider_module={.name="provider-A"};
static struct module scope_module __maybe_unused={.name="scope-B"};
static const struct file_operations operations={.tag=1};
static bool legacy_mode;
struct scope_record {
 struct xdev_ext_dma_scope *scope;struct module *owner;
 unsigned int released,locks_at_release;int owner_pins_at_release,provider_pins_at_release,resurrection;
 bool probe_resurrection;
};
struct provider_record {
 struct scope_record *identity;u32 kind,reserved;u64 canonical_start;
 int acquire_error,bind_error,host_error,unbind_host_error,unbind_region_error;
 bool fail_lease_alloc,bad_length,region_bad_length,bad_polled,wrong_direction,short_completion,pending;
 unsigned int acquire,bind,host,unhost,unregion,accepted;
 u64 requested_off,requested_len;
 struct xdev_ext_dma_cookie *saved_cookie;u64 saved_ticket,total;
};
static struct page pages[4];
static struct page *page_list[]={&pages[0],&pages[1],&pages[2],&pages[3]};
static const struct xdev_ext_dma_provider_ops provider_ops;
#ifndef DMA_SCOPE_LEGACY_CONTROL
static void released(void *private_data)
{
 struct scope_record *r=private_data;r->released++;r->locks_at_release=held_locks;
 r->owner_pins_at_release=r->owner?r->owner->refs:0;r->provider_pins_at_release=provider_module.refs;
 event("scope_release",r);
 if(r->probe_resurrection)r->resurrection=xdev_ext_dma_scope_get(r->scope);
}
static void identity_create(struct scope_record *r,struct module *owner)
{
 memset(r,0,sizeof(*r));r->owner=owner;r->resurrection=777;
 r->scope=xdev_ext_dma_scope_create(owner,r,released);
 require(!IS_ERR_OR_NULL(r->scope),"provider creates opaque backing identity");
}
static int scope_acquire(struct file *file,u64 off,u64 len,struct xdev_ext_dma_scope_info *out)
{
 struct provider_record *r=file->private_data;int ret;
 r->acquire++;event("acquire",r);
 check(held_locks==0,"scope acquire runs outside registry and lease locks");
 check(out->kind==XDEV_EXT_DMA_SCOPE_UNKNOWN && !out->reserved && !out->scope && !out->canonical_start && !out->canonical_len,"core initializes acquire output to clean UNKNOWN");
 r->requested_off=off;r->requested_len=len;
 out->kind=r->kind;out->reserved=r->reserved;
 if(r->identity) {
  ret=xdev_ext_dma_scope_get(r->identity->scope);if(ret)return ret;
  out->scope=r->identity->scope;
 }
 if(r->kind==XDEV_EXT_DMA_SCOPE_KNOWN || r->bad_length) {
  out->canonical_start=r->canonical_start;out->canonical_len=r->bad_length?len-1:len;
 }
 if(r->fail_lease_alloc)fail_next_allocation=1;
 return r->acquire_error;
}
static const struct xdev_ext_dma_scope_ops scope_ops={.size=sizeof(scope_ops),.version=1,.acquire=scope_acquire};
#endif
static int bind_region(struct file *file,u64 off,u64 len,struct xdev_ext_dma_region *out)
{
 struct provider_record *r=file->private_data;bool polled=out->polled;
 r->bind++;event("bind_region",r);
#ifndef DMA_SCOPE_LEGACY_CONTROL
 if(!legacy_mode)check(r->acquire==1 && r->requested_off==off && r->requested_len==len,"native bind uses the acquired backing selector and exact window");
#endif
 memset(out,0,sizeof(*out));out->ops=&provider_ops;out->priv=r;
 out->len=r->region_bad_length?len-1:len;out->alignment=1;
 out->directions=r->wrong_direction?(1U<<XDEV_EXT_MECH_DIR_FROM_DEVICE):((1U<<XDEV_EXT_MECH_DIR_FROM_DEVICE)|(1U<<XDEV_EXT_MECH_DIR_TO_DEVICE));
 out->polled=r->bad_polled?!polled:polled;
 return r->bind_error;
}
static int unbind_region(struct xdev_ext_dma_region *region)
{
 struct provider_record *r=region->priv;r->unregion++;event("unbind_region",r);
 if(r->unbind_region_error)return r->unbind_region_error;
 return 0;
}
static int bind_host(struct xdev_ext_dma_region *region,struct page **supplied,u32 nr,void **out)
{
 struct provider_record *r=region->priv;r->host++;event("bind_host",r);
 check(supplied==page_list && nr==4,"provider receives the actual registered host pool");
 *out=r;return r->host_error;
}
static int unbind_host(void *host)
{
 struct provider_record *r=host;r->unhost++;event("unbind_host",r);
 return r->unbind_host_error;
}
static int native_submit(struct xdev_ext_dma_region *region,void *host,u32 direction,
 const struct xdev_ext_dma_xfer *x,u32 n,struct xdev_ext_dma_cookie *cookie,u64 ticket)
{
 struct provider_record *r=region->priv;u32 i;u64 total=0;(void)direction;
 check(host==r && n==1,"native submit uses the same bound backing and host handle");
 for(i=0;i<n;i++)total+=x[i].len;
 r->accepted++;r->saved_cookie=cookie;r->saved_ticket=ticket;r->total=total;event("native_accept",r);
 if(!r->pending)xdev_ext_dma_complete(cookie,ticket,0,true,r->short_completion?total-1:total);
 return 0;
}
static const struct xdev_ext_dma_provider_ops provider_ops={.owner=&provider_module,.fops=&operations,
 .bind_region=bind_region,.unbind_region=unbind_region,.bind_host=bind_host,.unbind_host=unbind_host,.submit=native_submit};
static int __maybe_unused register_provider(void)
{
#ifdef DMA_SCOPE_LEGACY_CONTROL
 return xdev_ext_dma_provider_register(&provider_ops);
#else
 return xdev_ext_dma_provider_register_scoped(&provider_ops,&scope_ops);
#endif
}
static void session_init(struct xdev_ext_mech_session *s)
{
 memset(s,0,sizeof(*s));s->depth=2;s->layout.group_bytes=1024;
 s->pool.pages=page_list;s->pool.nr_pages=4;s->pool.nr_frames=4;s->pool.frame_size=4096;
}
static int bind_stage(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_session *s,
 struct file *file,struct provider_record *r,u64 requested_off,u64 requested_len,u32 direction)
{
 struct xdev_ext_mech_stage_uapi u={.class_id=XDEV_EXT_MECH_CLASS_DMA,.direction=direction,.arg0=requested_off,.arg1=requested_len};
 memset(st,0,sizeof(*st));file->f_op=&operations;file->private_data=r;
 st->s=s;st->file=file;st->direction=direction;st->cls=registered_class;
 return registered_class->bind(st,&u);
}
static void batch_init(struct xdev_ext_mech_batch *b,u32 slot,u64 generation)
{
 memset(b,0,sizeof(*b));b->slot=slot;b->id=generation;b->ticket=1000+generation;b->nr_frames=1;b->owners_valid=true;
 b->frame=(struct xdev_ext_mech_frame){.index=slot,.umem_addr=(u64)slot*4096,.data_len=1024};
 b->priv=calloc(1,registered_class->batch_priv_size);b->cookie=calloc(1,registered_class->batch_cookie_size);
 assert(b->priv&&b->cookie);
}
static int submit_stage(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b)
{
 static u64 native_ticket=10000;
 struct xdev_ext_dma_copy_desc descriptor={.frame_pos=0,.frame_off=0,.device_off=(u64)b->slot*1024,.len=1024};
 int ret=registered_class->validate(st,b,(const u8 *)&descriptor,1);
 if(ret)return ret;
 /* Mechanism boundary: each native stage invocation owns a fresh ticket;
  * lease generation remains b->id across same-batch stage transitions. */
 b->ticket=++native_ticket;b->claimed=false;
 return registered_class->submit(st,b);
}
static void finish_stage(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,bool unknown)
{registered_class->batch_release(st,b,unknown);}
static int cleanup(struct xdev_ext_mech_stage *st){return registered_class->unbind_checked(st);}
static void batch_free(struct xdev_ext_mech_batch *b){free(b->priv);free(b->cookie);}
static int __maybe_unused event_index(const char *what,const void *who,unsigned int from)
{unsigned int i;for(i=from;i<nr_events;i++)if(!strcmp(events[i].what,what)&&(!who||events[i].who==who))return (int)i;return -1;}

static void legacy_control(bool unknown)
{
 struct xdev_ext_mech_session a,b;struct xdev_ext_mech_stage sa,sb;struct file fa,fb;
 struct provider_record ra={.short_completion=unknown},rb={0};struct xdev_ext_mech_batch ba,bb;int ret;
 legacy_mode=true;require(xdev_ext_dma_provider_register(&provider_ops)==0,"legacy provider registers through unchanged API");session_init(&a);session_init(&b);
 require(bind_stage(&sa,&a,&fa,&ra,0,8192,XDEV_EXT_MECH_DIR_TO_DEVICE)==0,"legacy first stage binds");
 require(bind_stage(&sb,&b,&fb,&rb,0,8192,XDEV_EXT_MECH_DIR_FROM_DEVICE)==0,"legacy second stage binds same numeric window");
 batch_init(&ba,0,1);batch_init(&bb,0,2);
 require(submit_stage(&sa,&ba)==0 && ra.accepted==1,"legacy first group reaches real production submit");
 if(unknown) {
  check(ba.uncertain,"short native completion remains UNKNOWN");finish_stage(&sa,&ba,true);
  ret=submit_stage(&sb,&bb);check(ret==-EAGAIN && rb.accepted==0,"legacy UNKNOWN still blocks equal numeric window before native accept");
  check(cleanup(&sa)==-EBUSY && provider_module.refs==2,"quarantined legacy stage retains provider pin");
  check(cleanup(&sb)==0,"inactive conflicting legacy stage can clean its own binding");
 } else {
  check(!ba.uncertain && ba.published==1,"exact native completion is published normally");finish_stage(&sa,&ba,false);
  check(submit_stage(&sb,&bb)==0 && rb.accepted==1,"legacy window becomes available after normal batch release");finish_stage(&sb,&bb,false);
  check(cleanup(&sa)==0 && cleanup(&sb)==0 && provider_module.refs==0,"legacy cleanup balances original provider pins");
  xdev_ext_dma_provider_unregister(&provider_ops);batch_free(&ba);batch_free(&bb);
 }
}

#ifndef DMA_SCOPE_LEGACY_CONTROL
static void lifetime(void)
{
 struct scope_record r,builtin;struct xdev_ext_dma_scope *invalid;
 invalid=xdev_ext_dma_scope_create(NULL,NULL,NULL);check(IS_ERR(invalid)&&PTR_ERR(invalid)==-EINVAL,"scope requires a release callback");
 fail_next_allocation=1;invalid=xdev_ext_dma_scope_create(NULL,NULL,released);check(IS_ERR(invalid)&&PTR_ERR(invalid)==-ENOMEM,"scope allocation failure is explicit");
 identity_create(&r,&scope_module);check(scope_module.refs==0,"creator reference does not self-pin owner module");
 check(xdev_ext_dma_scope_get(NULL)==-EINVAL,"NULL scope get returns -EINVAL");
 scope_module.going=true;check(xdev_ext_dma_scope_get(r.scope)==-ENODEV && scope_module.refs==0,"unavailable scope owner cannot gain a reference");scope_module.going=false;
 check(xdev_ext_dma_scope_get(r.scope)==0 && xdev_ext_dma_scope_get(r.scope)==0 && scope_module.refs==2,"each external reference independently pins scope owner");
 xdev_ext_dma_scope_owner_put(r.scope);check(!r.released && scope_module.refs==2,"creator put preserves external references without module_put");
 xdev_ext_dma_scope_put(r.scope);check(!r.released && scope_module.refs==1,"non-final external put releases exactly one module pin");
 xdev_ext_dma_scope_put(r.scope);check(r.released==1 && r.owner_pins_at_release==1 && scope_module.refs==0 && !r.locks_at_release,"final release precedes final module_put outside locks");
 identity_create(&builtin,NULL);builtin.probe_resurrection=true;xdev_ext_dma_scope_owner_put(builtin.scope);
 check(builtin.released==1 && builtin.resurrection==-ESTALE,"protected final callback cannot resurrect zero-ref builtin scope");
}
static void registration(void)
{
 struct xdev_ext_dma_scope_ops side=scope_ops;struct xdev_ext_dma_provider_ops ops=provider_ops;unsigned int i;
 check(xdev_ext_dma_provider_register_scoped(NULL,NULL)==-EINVAL,"mandatory ops validation precedes missing sidecar");
 for(i=0;i<6;i++) {
  ops=provider_ops;side=scope_ops;side.version=99;
  if(i==0)ops.fops=NULL;else if(i==1)ops.bind_region=NULL;else if(i==2)ops.unbind_region=NULL;else if(i==3)ops.bind_host=NULL;else if(i==4)ops.unbind_host=NULL;else ops.submit=NULL;
  check(xdev_ext_dma_provider_register_scoped(&ops,&side)==-EINVAL,"every original mandatory callback/fops error precedes unknown sidecar version");
 }
 ops=provider_ops;
 check(xdev_ext_dma_provider_register_scoped(&ops,NULL)==-EINVAL,"scoped registration requires sidecar");
 side=scope_ops;side.size--;check(xdev_ext_dma_provider_register_scoped(&ops,&side)==-EINVAL,"scoped registration requires exact sidecar size");
 side.version=99;side.flags=1;check(xdev_ext_dma_provider_register_scoped(&ops,&side)==-EINVAL,"sidecar size validation precedes version and flags");
 side=scope_ops;side.version=99;check(xdev_ext_dma_provider_register_scoped(&ops,&side)==-EOPNOTSUPP,"unknown sidecar version returns -EOPNOTSUPP");
 side.flags=1;side.acquire=NULL;check(xdev_ext_dma_provider_register_scoped(&ops,&side)==-EOPNOTSUPP,"version rejection precedes flags and callback rejection");
 side=scope_ops;side.flags=1;fail_next_allocation=1;check(xdev_ext_dma_provider_register_scoped(&ops,&side)==-EINVAL && fail_next_allocation==1,"sidecar validation precedes registry allocation");fail_next_allocation=0;
 side=scope_ops;side.reserved=1;check(xdev_ext_dma_provider_register_scoped(&ops,&side)==-EINVAL,"sidecar reserved must be zero");
 side=scope_ops;side.acquire=NULL;check(xdev_ext_dma_provider_register_scoped(&ops,&side)==-EINVAL,"sidecar acquire is mandatory");
 fail_next_allocation=1;check(register_provider()==-ENOMEM,"registry entry allocation failure does not publish");
 require(register_provider()==0,"valid scoped provider publishes after prior rejections");
 fail_next_allocation=1;check(register_provider()==-ENOMEM,"entry allocation precedes duplicate-fops check");
 check(register_provider()==-EBUSY,"duplicate fops fails with -EBUSY");
 check(xdev_ext_dma_provider_register(&provider_ops)==-EBUSY,"legacy and scoped registration share the one fops registry");
 xdev_ext_dma_provider_unregister(&provider_ops);
 require(xdev_ext_dma_provider_register(&provider_ops)==0,"unregister withdraws both ops and sidecar from same entry");xdev_ext_dma_provider_unregister(&provider_ops);
}
static void bind_lifetime(bool same_owner)
{
 struct scope_record identity;struct provider_record r={.kind=XDEV_EXT_DMA_SCOPE_KNOWN,.canonical_start=500};
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage stage;struct file file;struct xdev_ext_mech_batch b;unsigned int at;
 identity_create(&identity,same_owner?&provider_module:&scope_module);r.identity=&identity;
 require(register_provider()==0,"scoped provider registers");session_init(&s);
 require(bind_stage(&stage,&s,&file,&r,100,8192,XDEV_EXT_MECH_DIR_TO_DEVICE)==0,"known stage binds acquired canonical backing");
 check(provider_module.refs==(same_owner?2:1) && scope_module.refs==(same_owner?0:1),"provider and scope pins are independent even for identical owners");
 xdev_ext_dma_scope_owner_put(identity.scope);check(!identity.released,"creator exit cannot release a bound stage's scope");
 batch_init(&b,0,1);check(submit_stage(&stage,&b)==0 && r.accepted==1,"known stage accepts one native command");finish_stage(&stage,&b,false);
 check(!identity.released && provider_module.refs==(same_owner?2:1),"normal batch release does not put per-stage scope");
 xdev_ext_dma_provider_unregister(&provider_ops);at=nr_events;
 check(cleanup(&stage)==0,"bound stage remains cleanable after provider unregister");
 check(identity.released==1 && !identity.locks_at_release && identity.provider_pins_at_release>0 && provider_module.refs==0 && scope_module.refs==0,"successful cleanup releases scope before provider pin");
 {int host=event_index("unbind_host",&r,at),region=event_index("unbind_region",&r,at),node=event_index("list_del",NULL,at),release=event_index("scope_release",&identity,at),put=event_index("module_put",&provider_module,(unsigned int)(release+1));
  check(host>=0 && region>host && node>region && release>node && put>release,"checked cleanup orders host, region, lease node, scope release and provider put");}
 check(cleanup(&stage)==0 && identity.released==1,"repeated cleanup cannot double-put scope");batch_free(&b);
}
static void acquire_errors(void)
{
 struct {int error;u32 kind,reserved;bool identity,bad_length;u64 start;int want;} table[]={
  {-EACCES,2,0,true,false,100,-EACCES},{1,2,0,true,false,100,-EPROTO},
  {-EIO,99,1,true,true,UINT64_MAX,-EIO},
  {0,0,0,false,false,0,-EPROTO},{0,99,0,true,false,100,-EPROTO},
  {0,2,1,true,false,100,-EPROTO},{0,2,0,false,false,100,-EPROTO},
  {0,2,0,true,true,100,-EPROTO},{0,2,0,true,false,UINT64_MAX,-EPROTO},
  {0,1,0,true,false,0,-EPROTO},{0,1,0,false,true,100,-EPROTO}
 };unsigned int i;
 require(register_provider()==0,"scope error cohort registers provider");
 for(i=0;i<ARRAY_SIZE(table);i++) {
  struct scope_record identity;struct provider_record r={.kind=table[i].kind,.reserved=table[i].reserved,.canonical_start=table[i].start,.acquire_error=table[i].error,.bad_length=table[i].bad_length};
  struct xdev_ext_mech_session s;struct xdev_ext_mech_stage stage;struct file file;
  identity_create(&identity,&scope_module);if(table[i].identity)r.identity=&identity;
  session_init(&s);check(bind_stage(&stage,&s,&file,&r,0,8192,XDEV_EXT_MECH_DIR_TO_DEVICE)==table[i].want,"malformed or failed scope declaration has frozen errno");
  check(r.acquire==1 && !r.bind && !r.host && !r.accepted,"scope failure precedes native bind and acceptance");
  check(cleanup(&stage)==0 && scope_module.refs==0 && provider_module.refs==0,"scope error rollback consumes every transferred pin once");
  check(!r.unhost && !r.unregion,"scope error rollback never unbinds absent native handles");
  xdev_ext_dma_scope_owner_put(identity.scope);check(identity.released==1,"creator remains valid after error rollback");
 }
 xdev_ext_dma_provider_unregister(&provider_ops);
}
static void bind_errors(const char *which)
{
 struct scope_record identity;struct provider_record r={.kind=2,.canonical_start=500};
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage stage;struct file file;int want;u64 length=8192;
 identity_create(&identity,&scope_module);r.identity=&identity;session_init(&s);require(register_provider()==0,"bind error cohort registers provider");
 if(!strcmp(which,"lease-alloc")){r.fail_lease_alloc=true;want=-ENOMEM;}
 else if(!strcmp(which,"region-error")){r.bind_error=-ENXIO;want=-ENXIO;}
 else if(!strcmp(which,"host-error")){r.host_error=-EIO;want=-EIO;}
 else if(!strcmp(which,"polled-error")){r.bad_polled=true;want=-EPROTO;}
 else if(!strcmp(which,"geometry-error")){r.region_bad_length=true;want=-EINVAL;}
 else if(!strcmp(which,"depth-window")){length=1024;want=-ENOSPC;}
 else {r.wrong_direction=true;want=-EOPNOTSUPP;}
 check(bind_stage(&stage,&s,&file,&r,0,length,XDEV_EXT_MECH_DIR_TO_DEVICE)==want,"original bind or lease failure keeps its specified errno");
 check(!r.accepted,"failed CREATE never submits native payload");
 if(r.fail_lease_alloc)check(!r.bind&&!r.host,"lease allocation failure precedes native mapping");
 xdev_ext_dma_scope_owner_put(identity.scope);check(!identity.released,"failed CREATE still owns its pin until checked rollback");
 check(cleanup(&stage)==0 && identity.released==1 && provider_module.refs==0 && scope_module.refs==0,"checked failed-bind rollback balances scope and provider refs");
 if(r.fail_lease_alloc)check(!r.unhost&&!r.unregion,"lease allocation failure does not invent unbind handles");
 xdev_ext_dma_provider_unregister(&provider_ops);
}
static void admission_order(void)
{
 struct scope_record identity;struct provider_record r={.kind=2,.canonical_start=100};
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;struct file file={.f_op=&operations,.private_data=&r};
 struct xdev_ext_mech_stage_uapi u={.arg1=8192};unsigned int i;
 identity_create(&identity,&scope_module);r.identity=&identity;session_init(&s);require(register_provider()==0,"admission provider registers");
 for(i=0;i<4;i++) {
  memset(&st,0,sizeof(st));st.s=&s;st.file=&file;st.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;u.flags=0;u.arg0=0;u.arg1=8192;
  if(i==0)u.flags=1;else if(i==1)st.direction=99;else if(i==2)u.arg1=0;else {u.arg0=UINT64_MAX;u.arg1=2;}
  fail_next_allocation=1;
  check(registered_class->bind(&st,&u)==-EINVAL && fail_next_allocation==1,"initial flags/direction/length checks precede stage allocation and scope acquire");fail_next_allocation=0;
  check(!r.acquire && !r.bind && !provider_module.refs && !scope_module.refs,"invalid initial request publishes no scope or provider reference");
 }
 memset(&st,0,sizeof(st));st.s=&s;st.file=&file;st.direction=1;st.poll=true;u.arg0=0;u.arg1=8192;
 check(registered_class->bind(&st,&u)==-EOPNOTSUPP && !r.acquire,"missing POLL callback is refused before scope acquire");
 check(cleanup(&st)==0 && !provider_module.refs && !scope_module.refs,"POLL refusal leaves no retained native or module resource");
 xdev_ext_dma_scope_owner_put(identity.scope);xdev_ext_dma_provider_unregister(&provider_ops);
}
static void scope_error_precedence(void)
{
 struct scope_record identity;struct provider_record r={.kind=2,.canonical_start=100,.acquire_error=-EACCES,.fail_lease_alloc=true,.bind_error=-ENXIO};
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;struct file file;
 identity_create(&identity,&scope_module);r.identity=&identity;session_init(&s);require(register_provider()==0,"precedence provider registers");
 require(bind_stage(&st,&s,&file,&r,0,8192,1)==-EACCES && fail_next_allocation==1 && !r.bind,"scope error precedes pending lease allocation and native bind errors");
 fail_next_allocation=0;xdev_ext_dma_scope_owner_put(identity.scope);
 check(cleanup(&st)==0 && identity.released==1 && !provider_module.refs && !scope_module.refs,"scope error with transferred pin uses checked rollback exactly once");
 xdev_ext_dma_provider_unregister(&provider_ops);
}
static void same_group(const char *which)
{
 struct scope_record s,t;struct provider_record a={.kind=2,.canonical_start=10000},b={.kind=2,.canonical_start=10000};
 struct xdev_ext_mech_session session;struct xdev_ext_mech_stage sa,sb;struct file fa,fb;struct xdev_ext_mech_batch ba,bb;
 bool serial=!strcmp(which,"group-shifted");unsigned int prior;int second;
 identity_create(&s,&scope_module);identity_create(&t,&scope_module);a.identity=&s;b.identity=!strcmp(which,"group-distinct")?&t:&s;
 if(serial)b.canonical_start=10512;else if(!strcmp(which,"group-disjoint"))b.canonical_start=18192;
 session_init(&session);require(register_provider()==0,"same-group provider registers");
 require(bind_stage(&sa,&session,&fa,&a,0,8192,1)==0 && bind_stage(&sb,&session,&fb,&b,1000000,8192,2)==0,"same group binds literal canonical windows independently of numeric aliases");
 xdev_ext_dma_scope_owner_put(s.scope);xdev_ext_dma_scope_owner_put(t.scope);
 batch_init(&ba,0,1);batch_init(&bb,1,2);
 check(submit_stage(&sa,&ba)==0,"first batch activates one same-group slot");
 second=submit_stage(&sb,&bb);
 check(second==(serial?-EAGAIN:0) && b.accepted==(serial?0U:1U),"only shifted overlapping canonical windows serialize a second batch");
 prior=b.accepted;check(submit_stage(&sb,&ba)==0 && b.accepted==prior+1,"same-batch next-stage acquire remains idempotent");
 finish_stage(&sa,&ba,false);finish_stage(&sb,&ba,false);if(!serial)finish_stage(&sb,&bb,false);
 check(scope_module.refs==2,"slot release retains both per-stage scope references");
 check(cleanup(&sa)==0 && cleanup(&sb)==0 && !provider_module.refs && !scope_module.refs && s.released==1 && t.released==1,"group cleanup returns each stage pin exactly once");
 xdev_ext_dma_provider_unregister(&provider_ops);batch_free(&ba);batch_free(&bb);
}
static void foreign_cleanup_hold(void)
{
 struct scope_record scope;struct provider_record active_a={.kind=2,.canonical_start=10000},active_b={.kind=2,.canonical_start=10000},foreign={.kind=2,.canonical_start=10000};
 struct xdev_ext_mech_session own_session,other_session;struct xdev_ext_mech_stage a,b,f;struct file fa,fb,ff;struct xdev_ext_mech_batch batch,other;
 identity_create(&scope,&scope_module);active_a.identity=active_b.identity=foreign.identity=&scope;session_init(&own_session);session_init(&other_session);require(register_provider()==0,"cleanup hold provider registers");
 require(bind_stage(&a,&own_session,&fa,&active_a,0,8192,1)==0 && bind_stage(&b,&own_session,&fb,&active_b,0,8192,2)==0 && bind_stage(&f,&other_session,&ff,&foreign,0,8192,1)==0,"active and foreign groups bind same protected backing");
 xdev_ext_dma_scope_owner_put(scope.scope);batch_init(&batch,0,1);batch_init(&other,0,2);
 check(submit_stage(&a,&batch)==0,"own group activates before foreign cleanup begins");
 foreign.unbind_host_error=-EIO;check(cleanup(&f)==-EIO,"foreign unmap failure retains cleanup_hold");
 check(submit_stage(&b,&batch)==-EAGAIN && !active_b.accepted,"foreign cleanup_hold blocks idempotent next stage of an already active group");
 check(submit_stage(&f,&other)==-EBUSY && !foreign.accepted,"own cleanup_hold retains -EBUSY admission priority");
 check(scope_module.refs==3 && provider_module.refs==3 && !scope.released,"failed cleanup and blocked submits retain all per-stage pins");
 foreign.unbind_host_error=0;check(cleanup(&f)==0,"foreign cleanup can safely retry and remove its hold");
 check(submit_stage(&b,&batch)==0 && active_b.accepted==1,"same-batch progress resumes only after foreign hold is removed");
 finish_stage(&a,&batch,false);finish_stage(&b,&batch,false);
 check(cleanup(&a)==0 && cleanup(&b)==0 && scope.released==1 && !provider_module.refs && !scope_module.refs,"cleanup_hold recovery has no double-put or early release");
 xdev_ext_dma_provider_unregister(&provider_ops);batch_free(&batch);batch_free(&other);
}
static void partial_cleanup(void)
{
 struct scope_record s,t;struct provider_record a={.kind=2,.canonical_start=10000},b={.kind=2,.canonical_start=10000};
 struct xdev_ext_mech_session session;struct xdev_ext_mech_stage sa,sb;struct file fa,fb;
 identity_create(&s,&scope_module);identity_create(&t,&scope_module);a.identity=&s;b.identity=&t;session_init(&session);require(register_provider()==0,"partial cleanup provider registers");
 require(bind_stage(&sa,&session,&fa,&a,0,8192,1)==0 && bind_stage(&sb,&session,&fb,&b,0,8192,2)==0,"partial cleanup binds two independent stage scopes");
 xdev_ext_dma_scope_owner_put(s.scope);xdev_ext_dma_scope_owner_put(t.scope);
 check(cleanup(&sa)==0 && s.released==1 && !t.released,"safe first stage returns only its own scope reference");
 b.unbind_region_error=-ENXIO;check(cleanup(&sb)==-ENXIO && scope_module.refs==1 && provider_module.refs==1 && !t.released,"later stage failure retains only remaining stage pins");
 check(cleanup(&sa)==0 && s.released==1 && scope_module.refs==1 && provider_module.refs==1,"retry never re-releases previously cleaned stage");
 b.unbind_region_error=0;check(cleanup(&sb)==0 && t.released==1 && !scope_module.refs && !provider_module.refs,"final partial cleanup retry balances remaining scope exactly once");xdev_ext_dma_provider_unregister(&provider_ops);
}
static void retained_unbind(bool host_failure)
{
 struct scope_record identity;struct provider_record r={.kind=2,.canonical_start=500};
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage stage;struct file file;
 identity_create(&identity,&scope_module);r.identity=&identity;session_init(&s);require(register_provider()==0,"retained cleanup provider registers");
 require(bind_stage(&stage,&s,&file,&r,0,8192,XDEV_EXT_MECH_DIR_TO_DEVICE)==0,"retained cleanup stage binds");xdev_ext_dma_scope_owner_put(identity.scope);
 if(host_failure)r.unbind_host_error=-EIO;else r.unbind_region_error=-ENXIO;
 check(cleanup(&stage)==(host_failure?-EIO:-ENXIO),"checked unbind preserves provider failure");
 check(!identity.released && provider_module.refs==1 && scope_module.refs==1 && stage.priv,"failed unbind retains scope, provider and native handle");
 if(host_failure)check(r.unhost==1 && r.unregion==0,"failed host unbind does not advance to region unbind");
 else check(r.unhost==1 && r.unregion==1,"region failure occurs only after successful host unbind");
 r.unbind_host_error=r.unbind_region_error=0;
 check(cleanup(&stage)==0 && identity.released==1 && !provider_module.refs && !scope_module.refs,"retry releases only safely unbound stage references");
 check(r.unhost==(host_failure?2U:1U),"already successful host unbind is not repeated after region retry");
 check(cleanup(&stage)==0 && identity.released==1,"subsequent cleanup remains idempotent");xdev_ext_dma_provider_unregister(&provider_ops);
}
static void independent_alias(bool unknown_scope)
{
 struct scope_record old,new;struct provider_record a={.kind=2,.canonical_start=10000,.short_completion=true},b={.kind=2,.canonical_start=10000},alias={.kind=2,.canonical_start=10000},disjoint={.kind=2,.canonical_start=18192};
 struct xdev_ext_mech_session s1,s2,s3,s4;struct xdev_ext_mech_stage st1,st2,st3,st4;struct file f1,f2,f3,f4;struct xdev_ext_mech_batch ba,bb,bc,bd;
 identity_create(&old,&scope_module);identity_create(&new,&scope_module);a.identity=&old;b.identity=&new;alias.identity=disjoint.identity=&old;
 if(unknown_scope){a.kind=1;a.identity=NULL;}
 require(register_provider()==0,"independence cohort provider registers");session_init(&s1);session_init(&s2);session_init(&s3);session_init(&s4);
 require(bind_stage(&st1,&s1,&f1,&a,0,8192,1)==0 && bind_stage(&st2,&s2,&f2,&b,0,8192,2)==0 && bind_stage(&st3,&s3,&f3,&alias,1000000,8192,1)==0 && bind_stage(&st4,&s4,&f4,&disjoint,0,8192,2)==0,"windows bind with literal independent, alias and disjoint canonical metadata");
 xdev_ext_dma_scope_owner_put(old.scope);xdev_ext_dma_scope_owner_put(new.scope);
 batch_init(&ba,0,1);batch_init(&bb,0,2);batch_init(&bc,0,3);batch_init(&bd,0,4);
 require(submit_stage(&st1,&ba)==0 && ba.uncertain,"first native short completion is UNKNOWN");finish_stage(&st1,&ba,true);
 if(unknown_scope) {
  check(submit_stage(&st2,&bb)==-EAGAIN && !b.accepted,"scope UNKNOWN blocks a distinct known scope ops-wide");
  check(cleanup(&st2)==0,"inactive known stage can release its own references");
 } else {
  check(submit_stage(&st2,&bb)==0 && b.accepted==1,"retained first scope does not block proven independent equal numeric window");finish_stage(&st2,&bb,false);
  check(cleanup(&st2)==0 && new.released==1,"independent stage cleans despite foreign quarantine");
 }
 if(unknown_scope)check(submit_stage(&st4,&bd)==-EAGAIN && !disjoint.accepted,"scope UNKNOWN also blocks a numerically and canonically disjoint-looking known window");
 else {check(submit_stage(&st4,&bd)==0 && disjoint.accepted==1,"same-scope disjoint canonical window remains independent despite equal numeric request");finish_stage(&st4,&bd,false);}
 check(cleanup(&st4)==0,"safe disjoint stage releases only its own pin");
 check(submit_stage(&st3,&bc)==-EAGAIN && !alias.accepted,"different numeric alias with overlapping canonical bytes cannot reach native accept");
 check(cleanup(&st3)==0,"inactive alias can safely clean its own binding");
 check(cleanup(&st1)==-EBUSY && a.unhost==0 && a.unregion==0,"UNKNOWN retains native mapping instead of invoking unbind");
 {int pins=scope_module.refs,refs=provider_module.refs;unsigned int released_before=old.released,published=ba.published;
  xdev_ext_dma_complete(a.saved_cookie,a.saved_ticket,0,true,a.total);
  check(scope_module.refs==pins && provider_module.refs==refs && old.released==released_before && ba.uncertain && ba.published==published && cleanup(&st1)==-EBUSY,"late completion cannot change UNKNOWN or release quarantined scope/provider pins");}
 if(!unknown_scope)check(old.released==0 && scope_module.refs==1 && provider_module.refs==1,"retained stage keeps backing identity and both module sources");
}
static void legacy_known_mixed(void)
{
 struct scope_record scope;struct provider_record old={.short_completion=true},known={.kind=2,.canonical_start=500000};
 struct xdev_ext_mech_session a,b;struct xdev_ext_mech_stage sa,sb;struct file fa,fb;struct xdev_ext_mech_batch ba,bb;
 identity_create(&scope,&scope_module);known.identity=&scope;session_init(&a);session_init(&b);legacy_mode=true;
 check(xdev_ext_dma_provider_register(&provider_ops)==0 && bind_stage(&sa,&a,&fa,&old,0,8192,1)==0,"old legacy binding captures legacy key in shared registry");
 xdev_ext_dma_provider_unregister(&provider_ops);legacy_mode=false;
 check(register_provider()==0 && bind_stage(&sb,&b,&fb,&known,1000000,8192,2)==0,"same ops may later provide scoped metadata without changing old bound key");
 xdev_ext_dma_scope_owner_put(scope.scope);batch_init(&ba,0,1);batch_init(&bb,0,2);
 check(submit_stage(&sa,&ba)==0 && ba.uncertain,"old legacy binding reaches UNKNOWN through production completion");finish_stage(&sa,&ba,true);
 check(submit_stage(&sb,&bb)==-EAGAIN && !known.accepted,"legacy/known mixture blocks ops-wide despite unrelated numeric and canonical coordinates");
 check(cleanup(&sb)==0 && scope.released==1 && !scope_module.refs,"inactive scoped binding releases its own reference safely");
 check(cleanup(&sa)==-EBUSY && provider_module.refs==1,"legacy quarantine is not weakened by later scoped registration");
}
#endif
int main(int argc,char **argv)
{
 const char *which=argc>1?argv[1]:"legacy-clean";
 check(registered_class!=NULL,"actual production class init registered callbacks");
 if(!strcmp(which,"legacy-clean"))legacy_control(false);
 else if(!strcmp(which,"legacy-unknown"))legacy_control(true);
#ifndef DMA_SCOPE_LEGACY_CONTROL
 else if(!strcmp(which,"lifetime"))lifetime();
 else if(!strcmp(which,"registration"))registration();
 else if(!strcmp(which,"bind-lifetime"))bind_lifetime(false);
 else if(!strcmp(which,"same-owner"))bind_lifetime(true);
 else if(!strcmp(which,"acquire-errors"))acquire_errors();
 else if(!strcmp(which,"admission-order"))admission_order();
 else if(!strcmp(which,"scope-precedence"))scope_error_precedence();
 else if(!strcmp(which,"lease-alloc")||!strcmp(which,"region-error")||!strcmp(which,"host-error")||!strcmp(which,"polled-error")||!strcmp(which,"direction-error")||!strcmp(which,"geometry-error")||!strcmp(which,"depth-window"))bind_errors(which);
 else if(!strcmp(which,"host-retain"))retained_unbind(true);
 else if(!strcmp(which,"region-retain"))retained_unbind(false);
 else if(!strcmp(which,"independent-alias"))independent_alias(false);
 else if(!strcmp(which,"unknown-mixed"))independent_alias(true);
 else if(!strcmp(which,"legacy-known-mixed"))legacy_known_mixed();
 else if(!strncmp(which,"group-",6))same_group(which);
 else if(!strcmp(which,"cleanup-hold"))foreign_cleanup_hold();
 else if(!strcmp(which,"partial-cleanup"))partial_cleanup();
#endif
 else return 2;
 printf("RESULT failures=%d warnings=%u\n",failures,warnings);return failures||warnings?1:0;
}

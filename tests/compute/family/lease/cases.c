/* Expectations come from compute-copy-lease-v1; no generated/model oracle. */
#ifdef LEASE_SHARED
#define CG(c) ((c)->lease.group)
#define CE_HEAD (&ce_domain->groups)
#define DM_HEAD (&dm_domain->groups)
#define RN(c) (&(c)->lease.node)
#define CH(c) ((c)->lease.cleanup_held)
#else
#define CG(c) ((c)->lease_group)
#define CE_HEAD (&xdev_ext_ce_lease_groups)
#define DM_HEAD (&xdev_ext_dma_lease_groups)
#define RN(c) (&(c)->lease_node)
#define CH(c) ((c)->cleanup_held)
#endif
#ifdef LEASE_SHARED
static struct xdev_ext_comp_copy_lease_domain *ce_domain,*dm_domain;
static unsigned shared_hits[7],shared_depth,predicate_depth;
static int ce_bind_adapter(struct xdev_ext_mech_stage*st,struct xdev_ext_ce_stage*c,u64 start,u64 len){c->window_start=start;c->window_len=len;return xdev_ext_comp_copy_lease_bind(ce_domain,&c->lease,st->s,st->s->depth,c,true);}
#define xdev_ext_ce_lease_bind ce_bind_adapter
#define xdev_ext_ce_lease_bind_ready(c) xdev_ext_comp_copy_lease_hold(&(c)->lease,false)
#define xdev_ext_ce_lease_get(c,b) xdev_ext_comp_copy_lease_get(&(c)->lease,(b)->slot,(b)->id)
#define xdev_ext_ce_lease_cleanup_begin(c) xdev_ext_comp_copy_lease_cleanup_begin(&(c)->lease)
#define xdev_ext_ce_lease_unbind(c) xdev_ext_comp_copy_lease_unbind(&(c)->lease,true)
#define xdev_ext_dma_lease_bind(st,c) xdev_ext_comp_copy_lease_bind(dm_domain,&(c)->lease,(st)->s,(st)->s->depth,&(c)->key,false)
#define xdev_ext_dma_lease_get(c,b) xdev_ext_comp_copy_lease_get(&(c)->lease,(b)->slot,(b)->id)
#define xdev_ext_dma_lease_cleanup(c,h) xdev_ext_comp_copy_lease_hold(&(c)->lease,h)
#define xdev_ext_dma_lease_busy(c) xdev_ext_comp_copy_lease_busy(&(c)->lease)
#define xdev_ext_dma_lease_unbind(c) xdev_ext_comp_copy_lease_unbind(&(c)->lease,false)
#endif
static struct module native_mod,scope_mod;
static struct file_operations fop={1},fop2={2};
static unsigned binds,hosts,unhosts,unregions,submits,scope_released;
static int fail_region,fail_host,fail_uh,fail_ur,scope_err;
static void *watch_stage;static bool watch_dma,watch_end;static unsigned clear_linked,detached_unlock,group_freed;
static u32 scope_kind=XDEV_EXT_DMA_SCOPE_KNOWN;
static u64 canonical=1000;
static struct xdev_ext_dma_scope *provided_scope;
static unsigned char device_payload[96];static unsigned char *host_payload;
static char events[256];static unsigned evn;
static void ev(char c){OK(evn<sizeof(events)-1);events[evn++]=c;events[evn]=0;}
static void native_boundary(void){EQ(held,0);OK(native_mod.refs>0);}
static int ce_br(struct file*f,u64 start,u64 len,struct xdev_ext_ce_region*r){native_boundary();binds++;ev('R');r->priv=r;r->len=len;r->seg_size=4096;r->max_entry_len=4096;return fail_region;}
static int ce_bh(struct xdev_ext_ce_region*r,struct page**p,u32 n,void**h){native_boundary();hosts++;ev('H');*h=r;return fail_host;}
static int ce_uh(void*h){native_boundary();unhosts++;ev('h');return fail_uh;}
static int ce_ur(struct xdev_ext_ce_region*r){native_boundary();unregions++;ev('r');if(!fail_ur && watch_stage)watch_end=true;return fail_ur;}
static int ce_sub(struct xdev_ext_ce_region*r,void*h,u32 dir,const struct xdev_ext_ce_xfer*x,u32 n,struct xdev_ext_ce_cookie*ck,u64 ticket){native_boundary();ev('S');submits++;EQ(n,1);EQ(x[0].owner,17);EQ(x[0].generation,23);EQ(x[0].host_byte_off,0);EQ(x[0].gpu_off,0);EQ(x[0].len,64);EQ(ticket,9001);memcpy(device_payload+x[0].gpu_off,host_payload+x[0].host_byte_off,x[0].len);xdev_ext_ce_complete(ck,ticket,0,true,64);return 0;}
static struct xdev_ext_ce_backend_ops ceops={.fops=&fop,.owner=&native_mod,.bind_region=ce_br,.unbind_region=ce_ur,.bind_host=ce_bh,.unbind_host=ce_uh,.submit=ce_sub};
static struct xdev_ext_ce_backend_ops ceops2={.fops=&fop2,.owner=&native_mod,.bind_region=ce_br,.unbind_region=ce_ur,.bind_host=ce_bh,.unbind_host=ce_uh,.submit=ce_sub};
static int dm_br(struct file*f,u64 start,u64 len,struct xdev_ext_dma_region*r){native_boundary();binds++;ev('R');r->priv=r;r->len=len;r->segment_size=4096;r->max_entry_len=4096;r->alignment=1;r->directions=1U<<XDEV_EXT_MECH_DIR_TO_DEVICE;return fail_region;}
static int dm_bh(struct xdev_ext_dma_region*r,struct page**p,u32 n,void**h){native_boundary();hosts++;ev('H');*h=r;return fail_host;}
static int dm_ur(struct xdev_ext_dma_region*r){return ce_ur((void*)r);}
static int dm_sub(struct xdev_ext_dma_region*r,void*h,u32 dir,const struct xdev_ext_dma_xfer*x,u32 n,struct xdev_ext_dma_cookie*ck,u64 ticket){native_boundary();ev('S');submits++;EQ(n,1);EQ(x[0].owner,17);EQ(x[0].generation,23);EQ(x[0].host_byte_off,0);EQ(x[0].device_off,0);EQ(x[0].len,64);EQ(ticket,9001);memcpy(device_payload+x[0].device_off,host_payload+x[0].host_byte_off,x[0].len);xdev_ext_dma_complete(ck,ticket,0,true,64);return 0;}
static struct xdev_ext_dma_provider_ops dmops={.fops=&fop,.owner=&native_mod,.bind_region=dm_br,.unbind_region=dm_ur,.bind_host=dm_bh,.unbind_host=ce_uh,.submit=dm_sub};
static int acquire_scope(struct file*f,u64 start,u64 len,struct xdev_ext_dma_scope_info*i){EQ(held,0);ev('A');if(provided_scope){EQ(xdev_ext_dma_scope_get(provided_scope),0);i->scope=provided_scope;}i->kind=scope_kind;i->canonical_start=canonical;i->canonical_len=scope_kind==XDEV_EXT_DMA_SCOPE_KNOWN?len:0;return scope_err;}
static struct xdev_ext_dma_scope_ops scopeops={.size=sizeof(scopeops),.version=XDEV_EXT_DMA_SCOPE_OPS_VERSION,.acquire=acquire_scope};
static void release_scope(void*p){EQ(held,0);OK(list_empty(DM_HEAD));scope_released++;ev('P');}
static struct page page_storage[4];static struct page *pages[]={page_storage,page_storage+1,page_storage+2,page_storage+3};
static void session(struct xdev_ext_mech_session*s,u32 depth){memset(s,0,sizeof(*s));s->depth=depth;s->pool.pages=pages;s->pool.nr_pages=4;s->pool.frame_size=4096;s->pool.nr_frames=4;s->layout.group_bytes=4096;}
static struct file file={&fop};
static void stage(struct xdev_ext_mech_stage*st,struct xdev_ext_mech_session*s){memset(st,0,sizeof(*st));st->s=s;st->file=&file;st->direction=XDEV_EXT_MECH_DIR_TO_DEVICE;}
static struct xdev_ext_mech_stage_uapi u={.arg0=0x10000,.arg1=8192};
static void clear_events(void){evn=0;events[0]=0;}
static void event_expect(const char*s){checks++;if(strcmp(events,s)){fprintf(stderr,"ASSERT %s events got=%s want=%s\n",test_name,events,s);exit(70);}}
static void ce_direct_bind(struct xdev_ext_ce_stage*c,struct xdev_ext_mech_stage*st,u64 start,u64 len,const struct xdev_ext_ce_backend_ops*ops){memset(c,0,sizeof(*c));c->ops=ops;c->copy.ops=&xdev_ext_ce_copy_ops;
EQ(xdev_ext_ce_lease_bind(st,c,start,len),0);
}

static void ce_detach(struct xdev_ext_ce_stage*c){OK(xdev_ext_ce_lease_unbind(c));EQ(CG(c),NULL);}
static void dma_direct_bind(struct xdev_ext_dma_stage*c,struct xdev_ext_mech_stage*st,struct xdev_ext_dma_scope_key key){memset(c,0,sizeof(*c));c->ops=&dmops;c->copy.ops=&xdev_ext_dma_copy_ops;c->key=key;EQ(xdev_ext_dma_lease_bind(st,c),0);}
static void dma_detach(struct xdev_ext_dma_stage*c){xdev_ext_dma_lease_cleanup(c,false);OK(xdev_ext_dma_lease_unbind(c));CG(c)=NULL;}
static void ce_state_cases(void){
 struct xdev_ext_mech_session s,t;struct xdev_ext_mech_stage st,tt;struct xdev_ext_ce_stage a,b,c;struct xdev_ext_mech_batch x={.id=41,.ticket=901,.slot=0};
 session(&s,3);session(&t,3);stage(&st,&s);stage(&tt,&t);test_name="CE allocation/reuse/hold/depth/generation";
 unsigned before=allocs;ce_direct_bind(&a,&st,100,100,&ceops);EQ(allocs,before+1);EQ(CG(&a)->cleanup_holds,1);EQ(CH(&a),true);EQ(xdev_ext_ce_lease_get(&a,&x),-EBUSY);
 before=allocs;fail_alloc=allocs+1;s.depth=7;ce_direct_bind(&b,&st,100,100,&ceops);s.depth=3;EQ(CG(&a)->depth,3);EQ(allocs,before);EQ(CG(&a)->regions.next,RN(&a));EQ(RN(&a)->next,RN(&b));EQ(RN(&b)->next,&CG(&a)->regions);EQ(CG(&a),CG(&b));EQ(CG(&a)->cleanup_holds,2);fail_alloc=0;
 memset(&c,0,sizeof(c));c.ops=&ceops;before=allocs;fail_alloc=allocs+1;EQ(xdev_ext_ce_lease_bind(&tt,&c,100,100),-ENOMEM);EQ(allocs,before+1);EQ(CG(&c),NULL);
#ifndef LEASE_SHARED
EQ(c.window_len,0);
#else
EQ(c.lease.key,NULL);EQ(c.lease.domain,NULL);
#endif
EQ(CH(&c),0);fail_alloc=0;
 xdev_ext_ce_lease_bind_ready(&a);xdev_ext_ce_lease_bind_ready(&b);xdev_ext_ce_lease_bind_ready(&a);EQ(CG(&a)->cleanup_holds,0);
 x.slot=3;x.id=0;EQ(xdev_ext_ce_lease_get(&a,&x),-ERANGE);st.priv=&a;unsigned warn_before=warnings;xdev_ext_ce_batch_release(&st,&x,true);EQ(warnings,warn_before+1);EQ(CG(&a)->state.active_batches,0);EQ(CG(&a)->state.quarantined,false);x.slot=0;EQ(xdev_ext_ce_lease_get(&a,&x),-EINVAL);x.id=41;EQ(xdev_ext_ce_lease_get(&a,&x),0);EQ(CG(&a)->slots[0].generation,41);EQ(xdev_ext_ce_lease_get(&b,&x),0);EQ(CG(&a)->state.active_batches,1);
 x.id=901;EQ(xdev_ext_ce_lease_get(&a,&x),-EBUSY);st.priv=&a;xdev_ext_ce_batch_release(&st,&x,false);EQ(CG(&a)->state.active_batches,1);x.id=41;xdev_ext_ce_batch_release(&st,&x,false);EQ(CG(&a)->state.active_batches,0);xdev_ext_ce_batch_release(&st,&x,true);EQ(CG(&a)->state.quarantined,0);
 x.slot=2;x.id=42;EQ(xdev_ext_ce_lease_get(&a,&x),0);EQ(CG(&a)->slots[2].generation,42);xdev_ext_ce_batch_release(&st,&x,false);EQ(CG(&a)->state.active_batches,0);
 CG(&a)->state.active_batches=UINT32_MAX;x.slot=1;EQ(xdev_ext_ce_lease_get(&a,&x),-EOVERFLOW);EQ(CG(&a)->slots[1].active,0);CG(&a)->state.active_batches=0;
 EQ(xdev_ext_ce_lease_cleanup_begin(&a),0);EQ(xdev_ext_ce_lease_cleanup_begin(&a),0);EQ(CG(&a)->cleanup_holds,1);EQ(xdev_ext_ce_lease_cleanup_begin(&b),0);EQ(CG(&a)->cleanup_holds,2);ce_detach(&a);EQ(CG(&b)->cleanup_holds,1);EQ(CH(&b),true);ce_detach(&b);
 session(&s,0);stage(&st,&s);ce_direct_bind(&a,&st,100,100,&ceops);xdev_ext_ce_lease_bind_ready(&a);x.slot=0;EQ(xdev_ext_ce_lease_get(&a,&x),-ERANGE);ce_detach(&a);
}
static void ce_serial_cases(void){
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;struct xdev_ext_ce_stage a,b;struct xdev_ext_mech_batch x={.id=1},y={.id=2,.slot=1};
 static const struct{u64 base;bool sameops;int want;}rows[]={{100,true,0},{150,true,-EAGAIN},{200,true,0},{150,false,0}};
 test_name="CE shifted/equal/disjoint/backend/sticky serial";
 for(unsigned i=0;i<ARRAY_SIZE(rows);i++){session(&s,2);stage(&st,&s);ce_direct_bind(&a,&st,100,100,&ceops);ce_direct_bind(&b,&st,rows[i].base,100,rows[i].sameops?&ceops:&ceops2);xdev_ext_ce_lease_bind_ready(&a);xdev_ext_ce_lease_bind_ready(&b);EQ(CG(&a)->state.serial_batches,rows[i].want!=0);ce_detach(&b);EQ(xdev_ext_ce_lease_get(&a,&x),0);EQ(xdev_ext_ce_lease_get(&a,&y),rows[i].want);st.priv=&a;xdev_ext_ce_batch_release(&st,&x,false);xdev_ext_ce_batch_release(&st,&y,false);ce_detach(&a);}
}
static void ce_scan_cases(void){
 struct xdev_ext_mech_session s[3];struct xdev_ext_mech_stage st[3];struct xdev_ext_ce_stage c[3];struct xdev_ext_mech_batch b[3]={{.id=1},{.id=2},{.id=3}};
 test_name="CE insertion first-hit ordinary before cleanup / active cleanup precedence";
 for(int i=0;i<3;i++){session(&s[i],2);stage(&st[i],&s[i]);ce_direct_bind(&c[i],&st[i],100,100,&ceops);xdev_ext_ce_lease_bind_ready(&c[i]);st[i].priv=&c[i];}
 EQ(CE_HEAD->next,&CG(&c[0])->node);EQ(CG(&c[0])->node.next,&CG(&c[1])->node);EQ(CG(&c[1])->node.next,&CG(&c[2])->node);EQ(xdev_ext_ce_lease_get(&c[0],&b[0]),0);EQ(xdev_ext_ce_lease_cleanup_begin(&c[2]),0);
 /* Foreign ordinary match comes first: own hold outranks ordinary conflict. */
 EQ(xdev_ext_ce_lease_cleanup_begin(&c[1]),0);EQ(xdev_ext_ce_lease_get(&c[1],&b[1]),-EBUSY);xdev_ext_ce_lease_bind_ready(&c[1]);EQ(xdev_ext_ce_lease_get(&c[1],&b[1]),-EAGAIN);
 /* Own-active skips ordinary groups but must still see foreign cleanup before same-id success. */
 EQ(xdev_ext_ce_lease_get(&c[0],&b[0]),-EAGAIN);xdev_ext_ce_lease_bind_ready(&c[2]);EQ(xdev_ext_ce_lease_get(&c[0],&b[0]),0);
 xdev_ext_ce_batch_release(&st[0],&b[0],false);for(int i=0;i<3;i++)ce_detach(&c[i]);
}
static void ce_quarantine_cases(void){
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;struct xdev_ext_ce_stage a;struct xdev_ext_mech_batch b={.id=33};session(&s,2);stage(&st,&s);ce_direct_bind(&a,&st,100,100,&ceops);xdev_ext_ce_lease_bind_ready(&a);st.priv=&a;test_name="CE wrong generation/sequester retention";
 EQ(xdev_ext_ce_lease_get(&a,&b),0);b.id=34;xdev_ext_ce_batch_release(&st,&b,true);EQ(CG(&a)->state.quarantined,0);EQ(CG(&a)->state.active_batches,1);b.id=33;xdev_ext_ce_batch_release(&st,&b,true);EQ(CG(&a)->state.quarantined,1);EQ(CG(&a)->state.active_batches,1);EQ(CG(&a)->slots[0].active,1);EQ(xdev_ext_ce_lease_cleanup_begin(&a),-EBUSY);OK(!xdev_ext_ce_lease_unbind(&a));b.slot=1;EQ(xdev_ext_ce_lease_get(&a,&b),-EBUSY);
 /* Deliberate fixture retirement only after retention assertions. */CG(&a)->state.quarantined=false;CG(&a)->slots[0].active=false;CG(&a)->state.active_batches=0;ce_detach(&a);
}
static void dma_keys_cases(void){
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;struct xdev_ext_dma_stage a,b;struct xdev_ext_mech_batch x={.id=11},y={.id=12,.slot=1};
 int token1,token2; const struct{u32 ak,bk;u64 start;bool alias;int want;bool other_provider;} rows[]={
 {0,0,100,true,0},{0,0,150,true,-EAGAIN},{0,0,200,true,0},{2,2,100,true,0},{2,2,150,true,-EAGAIN},{2,2,150,false,0},{1,1,0,true,-EAGAIN},{0,1,0,true,-EAGAIN},{2,0,100,true,-EAGAIN},{1,1,0,true,0,true}};
 test_name="DMA canonical LEGACY KNOWN UNKNOWN mixed scope aliases";
 for(unsigned i=0;i<ARRAY_SIZE(rows);i++){session(&s,2);stage(&st,&s);struct xdev_ext_dma_scope_key ka={.provider=&dmops,.kind=rows[i].ak,.start=100,.len=100},kb={.provider=&dmops,.kind=rows[i].bk,.start=rows[i].start,.len=100};if(rows[i].other_provider)kb.provider=&ceops;if(ka.kind==2)ka.scope=(void*)&token1;if(kb.kind==2)kb.scope=(void*)(rows[i].alias?&token1:&token2);if(ka.kind==1)ka.start=ka.len=0;if(kb.kind==1)kb.start=kb.len=0;dma_direct_bind(&a,&st,ka);dma_direct_bind(&b,&st,kb);EQ(CG(&a),CG(&b));EQ(CG(&a)->cleanup_holds,0);EQ(xdev_ext_dma_lease_get(&a,&x),0);EQ(xdev_ext_dma_lease_get(&b,&y),rows[i].want);st.priv=&a;xdev_ext_dma_batch_release(&st,&x,false);xdev_ext_dma_batch_release(&st,&y,false);dma_detach(&a);dma_detach(&b);}
}
static void live_cases(bool dma){
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;session(&s,2);stage(&st,&s);test_name=dma?"DMA actual class/executor native/CQE/ref cleanup":"CE actual class/executor native/CQE/ref cleanup";clear_events();

#ifdef LEASE_SHARED
unsigned before_hits[7];memcpy(before_hits,shared_hits,sizeof(before_hits));
#endif
 host_payload=(unsigned char*)page_storage;for(unsigned i=0;i<96;i++){host_payload[i]=(unsigned char)(i*3+1);device_payload[i]=0x5A;}
 int r=dma?xdev_ext_dma_bind(&st,&u):xdev_ext_ce_bind(&st,&u);EQ(r,0);event_expect("RH");EQ(native_mod.refs,1);
 struct xdev_ext_comp_copy_cookie ck={0}; union{struct xdev_ext_ce_batch ce;struct xdev_ext_dma_batch dm;}priv;memset(&priv,0,sizeof(priv));struct xdev_ext_mech_batch b={.id=77,.ticket=9001,.priv=&priv,.cookie=&ck,.nr=1,.frames={{.index=0,.umem_addr=0,.data_off=0,.data_len=64}}};
 struct xdev_ext_ce_copy_desc d={.frame_pos=0,.frame_off=0,.len=64,.gpu_off=0};
 EQ(dma?xdev_ext_dma_validate(&st,&b,(void*)&d,1):xdev_ext_ce_validate(&st,&b,(void*)&d,1),0);
 EQ(dma?xdev_ext_dma_submit(&st,&b):xdev_ext_ce_submit(&st,&b),0);EQ(b.published,1);EQ(b.status,0);EQ(b.sequestered,false);EQ(ck.bytes_done,64);for(unsigned i=0;i<64;i++)EQ(device_payload[i],(unsigned char)(i*3+1));for(unsigned i=64;i<96;i++)EQ(device_payload[i],0x5A);
 if(dma){struct xdev_ext_dma_stage*c=st.priv;EQ(CG(c)->slots[0].generation,77);}else{struct xdev_ext_ce_stage*c=st.priv;EQ(CG(c)->slots[0].generation,77);}
 unsigned char cqe[128];memset(cqe,0xAA,sizeof(cqe));if(dma)xdev_ext_dma_fill_cqe(&st,&b,cqe);else xdev_ext_ce_fill_cqe(&st,&b,cqe);
 struct xdev_ext_ce_mech_cqe *q=(void*)cqe;EQ(q->backend_status,0);EQ(q->bytes_done,64);EQ(q->entries_done,1);static const unsigned char cqewant[24]={[8]=64,[16]=1};EQ(sizeof(struct xdev_ext_ce_mech_cqe),24);EQ(sizeof(struct xdev_ext_dma_mech_cqe),24);for(unsigned i=0;i<24;i++)EQ(cqe[i],cqewant[i]);for(unsigned i=24;i<128;i++)EQ(cqe[i],0xAA);
 EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),-EBUSY);event_expect("RHS");
 if(dma)xdev_ext_dma_batch_release(&st,&b,false);else xdev_ext_ce_batch_release(&st,&b,false);
 fail_uh=-EIO;EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),-EIO);EQ(native_mod.refs,1);fail_uh=0;
 if(dma){struct xdev_ext_dma_stage*c=st.priv;EQ(CH(c),1);EQ(CG(c)->cleanup_holds,1);}else{struct xdev_ext_ce_stage*c=st.priv;EQ(CH(c),1);EQ(CG(c)->cleanup_holds,1);}
 fail_ur=-EAGAIN;EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),-EAGAIN);fail_ur=0;
 watch_stage=st.priv;watch_dma=dma;watch_end=false;clear_linked=detached_unlock=group_freed=0;EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),0);EQ(clear_linked,dma?1:0);EQ(detached_unlock,1);EQ(group_freed,1);watch_stage=NULL;watch_end=false;EQ(st.priv,NULL);EQ(native_mod.refs,0);event_expect("RHShhrr");
#ifdef LEASE_SHARED
OK(shared_hits[0]>before_hits[0]);OK(shared_hits[1]>before_hits[1]);OK(shared_hits[2]>before_hits[2]);OK(shared_hits[3]>before_hits[3]);OK(shared_hits[6]>before_hits[6]);OK(shared_hits[dma?4:5]>before_hits[dma?4:5]);
#endif
EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),0);
}
static void rollback_cases(bool dma){
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;session(&s,2);stage(&st,&s);test_name=dma?"DMA no-group and residual rollback":"CE early initial hold and no-group rollback";clear_events();
 fail_alloc=allocs+2;EQ(dma?xdev_ext_dma_bind(&st,&u):xdev_ext_ce_bind(&st,&u),-ENOMEM);fail_alloc=0;OK(st.priv);event_expect("");EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),0);EQ(native_mod.refs,0);
 stage(&st,&s);clear_events();fail_region=-EIO;EQ(dma?xdev_ext_dma_bind(&st,&u):xdev_ext_ce_bind(&st,&u),-EIO);fail_region=0;event_expect("R");if(dma){struct xdev_ext_dma_stage*c=st.priv;EQ(CH(c),0);EQ(CG(c)->cleanup_holds,0);}else{struct xdev_ext_ce_stage*c=st.priv;EQ(CH(c),1);EQ(CG(c)->cleanup_holds,1);}
 fail_ur=-EAGAIN;EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),-EAGAIN);EQ(native_mod.refs,1);fail_ur=0;EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),0);event_expect("Rrr");EQ(native_mod.refs,0);
 stage(&st,&s);clear_events();fail_host=-EIO;EQ(dma?xdev_ext_dma_bind(&st,&u):xdev_ext_ce_bind(&st,&u),-EIO);fail_host=0;event_expect("RH");if(dma){struct xdev_ext_dma_stage*c=st.priv;EQ(CH(c),false);}else{struct xdev_ext_ce_stage*c=st.priv;EQ(CH(c),true);}EQ(dma?xdev_ext_dma_unbind(&st):xdev_ext_ce_unbind(&st),0);event_expect("RHhr");EQ(native_mod.refs,0);
}
static void scoped_lifetime(void){
 test_name="DMA real scope retained until detach incl error output";xdev_ext_dma_provider_unregister(&dmops);EQ(xdev_ext_dma_provider_register_scoped(&dmops,&scopeops),0);provided_scope=xdev_ext_dma_scope_create(&scope_mod,NULL,release_scope);OK(!IS_ERR(provided_scope));
 struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;session(&s,2);stage(&st,&s);clear_events();EQ(xdev_ext_dma_bind(&st,&u),0);EQ(provided_scope->refs.refs,2);EQ(scope_mod.refs,1);event_expect("ARH");fail_ur=-EIO;EQ(xdev_ext_dma_unbind(&st),-EIO);EQ(provided_scope->refs.refs,2);EQ(scope_mod.refs,1);fail_ur=0;EQ(xdev_ext_dma_unbind(&st),0);EQ(provided_scope->refs.refs,1);EQ(scope_mod.refs,0);event_expect("ARHhrr");
 stage(&st,&s);clear_events();scope_err=-EIO;EQ(xdev_ext_dma_bind(&st,&u),-EIO);scope_err=0;EQ(provided_scope->refs.refs,2);EQ(xdev_ext_dma_unbind(&st),0);EQ(provided_scope->refs.refs,1);event_expect("A");xdev_ext_dma_scope_owner_put(provided_scope);provided_scope=NULL;EQ(scope_released,1);EQ(native_mod.refs,0);
}
static bool node_in(struct list_head*h,struct list_head*n){for(struct list_head*p=h->next;p!=h;p=p->next)if(p==n)return true;return false;}
static void observe_unlock(void){if(!watch_end)return;if(watch_dma){struct xdev_ext_dma_stage*c=watch_stage;if(CG(c)&&node_in(&CG(c)->regions,
#ifdef LEASE_SHARED
&c->lease.node
#else
&c->lease_node
#endif
)){if(!CH(c))clear_linked++;}else detached_unlock++;}else{struct xdev_ext_ce_stage*c=watch_stage;if(CG(c)&&node_in(&CG(c)->regions,
#ifdef LEASE_SHARED
&c->lease.node
#else
&c->lease_node
#endif
)){EQ(CH(c),true);}else detached_unlock++;}}
static void observe_free(void*p){if(!watch_stage)return;if(p==watch_stage){if(watch_dma){struct xdev_ext_dma_stage*c=p;EQ(CG(c),NULL);EQ(c->scope,NULL);}else{struct xdev_ext_ce_stage*c=p;EQ(CG(c),NULL);}return;}
/* Group frees are intercepted only after the last observed detach. */
if(watch_end){struct list_head*n=p;OK(n->next==NULL||n->next==n);OK(n->prev==NULL||n->prev==n);group_freed++;}}
static void dma_order_state(void){
 struct xdev_ext_mech_session s[3];struct xdev_ext_mech_stage st[3];struct xdev_ext_dma_stage c[3];struct xdev_ext_mech_batch b[3]={{.id=1},{.id=2},{.id=3}};struct xdev_ext_dma_scope_key k={.provider=&dmops,.kind=0,.start=100,.len=100};
 test_name="DMA first match depth generation hold overflow quarantine";
 for(int i=0;i<3;i++){session(&s[i],2);stage(&st[i],&s[i]);dma_direct_bind(&c[i],&st[i],k);st[i].priv=&c[i];}
 unsigned before=allocs;fail_alloc=allocs+1;struct xdev_ext_dma_stage extra;dma_direct_bind(&extra,&st[0],k);EQ(allocs,before);fail_alloc=0;EQ(CG(&extra),CG(&c[0]));dma_detach(&extra);
 b[0].slot=2;b[0].id=0;EQ(xdev_ext_dma_lease_get(&c[0],&b[0]),-ERANGE);b[0].slot=0;EQ(xdev_ext_dma_lease_get(&c[0],&b[0]),-EINVAL);b[0].id=1;
 EQ(xdev_ext_dma_lease_get(&c[0],&b[0]),0);xdev_ext_dma_lease_cleanup(&c[2],true);xdev_ext_dma_lease_cleanup(&c[2],true);EQ(CG(&c[2])->cleanup_holds,1);xdev_ext_dma_lease_cleanup(&c[1],true);EQ(xdev_ext_dma_lease_get(&c[1],&b[1]),-EBUSY);EQ(xdev_ext_dma_lease_get(&c[0],&b[0]),-EAGAIN);xdev_ext_dma_lease_cleanup(&c[1],false);xdev_ext_dma_lease_cleanup(&c[2],false);EQ(xdev_ext_dma_lease_get(&c[0],&b[0]),0);
 b[0].id=9001;EQ(xdev_ext_dma_lease_get(&c[0],&b[0]),-EBUSY);xdev_ext_dma_batch_release(&st[0],&b[0],true);EQ(CG(&c[0])->state.quarantined,false);b[0].id=1;xdev_ext_dma_batch_release(&st[0],&b[0],false);xdev_ext_dma_batch_release(&st[0],&b[0],true);EQ(CG(&c[0])->state.quarantined,false);
 CG(&c[0])->state.active_batches=UINT32_MAX;b[0].slot=1;EQ(xdev_ext_dma_lease_get(&c[0],&b[0]),-EOVERFLOW);CG(&c[0])->state.active_batches=0;EQ(xdev_ext_dma_lease_get(&c[0],&b[0]),0);xdev_ext_dma_batch_release(&st[0],&b[0],true);EQ(CG(&c[0])->state.active_batches,1);OK(xdev_ext_dma_lease_busy(&c[0]));OK(!xdev_ext_dma_lease_unbind(&c[0]));CG(&c[0])->state.quarantined=false;CG(&c[0])->state.active_batches=0;CG(&c[0])->slots[1].active=false;
 for(int i=0;i<3;i++)dma_detach(&c[i]);
}
static void invalid_finish(void){test_name="pure finish internal count/generation precedence";struct xdev_ext_ce_lease_state s={0};struct xdev_ext_ce_lease_slot l={.generation=8,.active=true};EQ(xdev_ext_ce_lease_finish(&s,&l,7,true),-ESTALE);EQ(s.quarantined,false);EQ(xdev_ext_ce_lease_finish(&s,&l,8,false),-EPROTO);EQ(l.active,true);EQ(xdev_ext_ce_lease_finish(&s,&l,8,true),-EBUSY);EQ(s.quarantined,true);EQ(l.active,true);}
static void separate_domains(void){struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;struct xdev_ext_ce_stage ce;struct xdev_ext_dma_stage dm;struct xdev_ext_mech_batch b={.id=88};struct xdev_ext_dma_scope_key key={.provider=&dmops,.kind=0,.start=100,.len=100};session(&s,2);stage(&st,&s);test_name="same session separate domains";ce_direct_bind(&ce,&st,100,100,&ceops);xdev_ext_ce_lease_bind_ready(&ce);dma_direct_bind(&dm,&st,key);OK((void*)CG(&ce)!=(void*)CG(&dm));EQ(xdev_ext_ce_lease_get(&ce,&b),0);EQ(xdev_ext_dma_lease_get(&dm,&b),0);EQ(CG(&ce)->state.active_batches,1);EQ(CG(&dm)->state.active_batches,1);st.priv=&ce;xdev_ext_ce_batch_release(&st,&b,false);EQ(CG(&dm)->state.active_batches,1);st.priv=&dm;xdev_ext_dma_batch_release(&st,&b,false);ce_detach(&ce);dma_detach(&dm);}
#ifdef LEASE_SHARED
/* Compiler instrumentation observes actual functions, including live adapter paths. */
static bool __attribute__((no_instrument_function)) policy_target(void*fn){return (ce_domain&&(fn==(void*)ce_domain->policy->overlap||fn==(void*)ce_domain->policy->serial))||(dm_domain&&(fn==(void*)dm_domain->policy->overlap||fn==(void*)dm_domain->policy->serial));}
void __attribute__((no_instrument_function)) __cyg_profile_func_enter(void *fn,void*site){
 const void*targets[]={xdev_ext_comp_copy_lease_bind,xdev_ext_comp_copy_lease_get,xdev_ext_comp_copy_lease_finish,xdev_ext_comp_copy_lease_hold,xdev_ext_comp_copy_lease_busy,xdev_ext_comp_copy_lease_cleanup_begin,xdev_ext_comp_copy_lease_unbind};
 if(predicate_depth && (fn==(void*)mutex_lock||fn==(void*)kalloc||fn==(void*)kfree||fn==(void*)list_add_tail||fn==(void*)list_del||fn==(void*)xdev_ext_ce_lease_acquire||fn==(void*)xdev_ext_ce_lease_finish||fn==(void*)try_module_get||fn==(void*)module_put)){fprintf(stderr,"ASSERT policy callback retained lease/ref/native authority\n");exit(70);}
 if(policy_target(fn))predicate_depth++;
 for(unsigned i=0;i<7;i++)if(fn==targets[i]){shared_hits[i]++;shared_depth++;}
}
void __attribute__((no_instrument_function)) __cyg_profile_func_exit(void *fn,void*site){
 const void*targets[]={xdev_ext_comp_copy_lease_bind,xdev_ext_comp_copy_lease_get,xdev_ext_comp_copy_lease_finish,xdev_ext_comp_copy_lease_hold,xdev_ext_comp_copy_lease_busy,xdev_ext_comp_copy_lease_cleanup_begin,xdev_ext_comp_copy_lease_unbind};
 if(policy_target(fn))predicate_depth--;
 for(unsigned i=0;i<7;i++)if(fn==targets[i])shared_depth--;
}
static void observe_common_lock(struct mutex*m){if(m==&xdev_ext_ce_registry.lock||m==&xdev_ext_dma_registry.lock)return;OK(shared_depth>0);OK(m==&ce_domain->lock||m==&dm_domain->lock);EQ(predicate_depth,0);}
static void bootstrap_domains(void){struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;session(&s,2);stage(&st,&s);EQ(xdev_ext_ce_bind(&st,&u),0);ce_domain=((struct xdev_ext_ce_stage*)st.priv)->lease.domain;EQ(xdev_ext_ce_unbind(&st),0);stage(&st,&s);EQ(xdev_ext_dma_bind(&st,&u),0);dm_domain=((struct xdev_ext_dma_stage*)st.priv)->lease.domain;EQ(xdev_ext_dma_unbind(&st),0);OK(ce_domain!=dm_domain);OK(&ce_domain->lock!=&dm_domain->lock);OK(ce_domain->policy!=dm_domain->policy);}
#endif
int main(void){test_name="registry";EQ(xdev_ext_ce_backend_register(&ceops),0);EQ(xdev_ext_ce_backend_register(&ceops2),0);EQ(xdev_ext_dma_provider_register(&dmops),0);
#ifdef LEASE_SHARED
bootstrap_domains();lock_observer=observe_common_lock;
#endif
unlock_observer=observe_unlock;free_observer=observe_free;ce_state_cases();ce_serial_cases();ce_scan_cases();ce_quarantine_cases();dma_keys_cases();dma_order_state();separate_domains();invalid_finish();live_cases(false);live_cases(true);rollback_cases(false);rollback_cases(true);scoped_lifetime();xdev_ext_ce_backend_unregister(&ceops);xdev_ext_ce_backend_unregister(&ceops2);xdev_ext_dma_provider_unregister(&dmops);EQ(held,0);EQ(native_mod.refs,0);
#ifdef LEASE_SHARED
for(unsigned i=0;i<7;i++)OK(shared_hits[i]>0);
#endif
printf("PASS independent lease assertions=%u allocations=%u frees=%u warnings=%u\n",checks,allocs,frees,warnings);return 0;}

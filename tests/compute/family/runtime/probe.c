/* Literal behavioral vectors frozen from the runtime contract. */
#ifdef IO_URING_XDEV_EXT_COMPFAM_COPY_LEASE_H
/* This file follows all actual production bodies: project fixture fields only. */
#define lease_group lease.group
#define cleanup_held lease.cleanup_held
#endif
#ifdef RUNTIME_AVAILABLE
#define STATE(cs) (&(cs)->copy)
#else
#define STATE(cs) (cs)
#endif
static unsigned runtime_consumer;
#ifdef RUNTIME_AVAILABLE
static unsigned long runtime_hits[2][10];
void __attribute__((no_instrument_function)) __cyg_profile_func_enter(void *fn,void *site) {
    void *operations[10]={
        (void*)xdev_ext_comp_copy_registry_register,(void*)xdev_ext_comp_copy_registry_unregister,(void*)xdev_ext_comp_copy_registry_get,(void*)xdev_ext_comp_copy_collect,(void*)xdev_ext_comp_copy_stage_validate,(void*)xdev_ext_comp_copy_stage_submit,(void*)xdev_ext_comp_copy_complete,(void*)xdev_ext_comp_copy_mark_dead,(void*)xdev_ext_comp_copy_poll,(void*)xdev_ext_comp_copy_unbind
    }
    ;
    for(int i=0;i<10;i++)if(fn==operations[i])runtime_hits[runtime_consumer][i]++;
}
void __attribute__((no_instrument_function)) __cyg_profile_func_exit(void *fn,void *site) {
}
static void common_operations_observed(void) {
    for(int consumer=0;consumer<2;consumer++)for(int i=0;i<10;i++)if(consumer||i!=8)CHECK(runtime_hits[consumer][i]>0);
    puts("PASS all ten real common operation entries observed");
}
#else
static void common_operations_observed(void) {
}
#endif
static struct module native_module,scope_module;
static struct file_operations fops[12];
static struct xdev_ext_ce_backend_ops ce_ops[7];
static struct xdev_ext_dma_provider_ops dma_ops[7];
static struct xdev_ext_mech_stage *active_stage;
static bool active_dma,region_zero_output,clear_polled,inline_complete,check_hold;
static int bind_region_errno,bind_host_errno,unbind_host_errno,unbind_region_errno,native_submit_errno,poll_errno;
static int native_calls,poll_calls,scope_releases;
static struct xdev_ext_mech_batch *native_batch;
static const void *saved_xfers;
static void *pending_cookie;
static u64 pending_ticket;
static int scope_acquire_errno;
static u32 scope_kind=2;
static u64 scope_start;
static struct xdev_ext_dma_scope *scope_object;
static struct xdev_ext_mech_stage *conflict_stage;
static struct xdev_ext_mech_batch *conflict_batch;
static struct xdev_ext_mech_stage_uapi bind_u;
static bool ce_check_exclusion,ce_zero_length,ce_short_region;
static struct module poisoned_module;
static int ce_expected_foreign=-EAGAIN,ce_expected_own=-EBUSY;
static void ce_configured_observer(bool binding) {
    struct xdev_ext_ce_stage *cs=active_stage->priv;
    CHECK(cs->ops && cs->ops->fops==active_stage->file->f_op);
    CHECK(cs->window_start==bind_u.arg0&&cs->window_len==bind_u.arg1);
    CHECK(cs->lease_group&&cs->cleanup_held&&cs->lease_group->cleanup_holds>0);
    struct xdev_ext_mech_batch held_probe={.slot=1,.id=91};
    CHECK(xdev_ext_ce_lease_get(cs,&held_probe)==ce_expected_own);
    if(ce_check_exclusion&&conflict_stage) {
        int calls=native_calls;
        CHECK(xdev_ext_ce_lease_get(conflict_stage->priv,conflict_batch)==ce_expected_foreign);
        CHECK(native_calls==calls);
    }
}

static int ce_bind_region(struct file*f,u64 start,u64 len,struct xdev_ext_ce_region*r){
    CHECK(!lock_depth&&active_stage->priv);
    event("region+");
    ce_configured_observer(true);
    if(region_zero_output)memset(r,0,sizeof(*r));
    r->priv=(void*)0x100;
    r->len=ce_zero_length?0:(ce_short_region?128:len);
    r->seg_size=0;
    r->max_entry_len=256;
    return bind_region_errno;
}
static int dma_bind_region(struct file*f,u64 start,u64 len,struct xdev_ext_dma_region*r){
    bool polled=r->polled;
    CHECK(!lock_depth&&active_stage->priv);
    event("region+");
    if(region_zero_output)memset(r,0,sizeof(*r));
    r->priv=(void*)0x100;
    r->len=len;
    r->alignment=1;
    r->max_entry_len=256;
    r->directions=XDEV_EXT_DMA_DIR_KNOWN_MASK;
    r->polled=clear_polled?false:polled;
    return bind_region_errno;
}
static void observe_cleanup(void){
    CHECK(!lock_depth);
    if(!active_dma)ce_configured_observer(false);
    if(active_dma&&check_hold){
        struct xdev_ext_dma_stage*cs=active_stage->priv;
        CHECK(cs->cleanup_held&&cs->lease_group->cleanup_holds==1);
        if(scope_object)CHECK(cs->scope==scope_object&&scope_module.refs==2);
        if(conflict_stage)CHECK(xdev_ext_dma_lease_get(conflict_stage->priv,conflict_batch)==-EAGAIN);
    }
}
static int ce_unbind_region(struct xdev_ext_ce_region*r){
    CHECK(!lock_depth&&r->priv);
    ce_configured_observer(false);
    event("region-");
    return unbind_region_errno;
}
static int dma_unbind_region(struct xdev_ext_dma_region*r){
    observe_cleanup();
    CHECK(r->priv);
    event("region-");
    return unbind_region_errno;
}
static int ce_bind_host(struct xdev_ext_ce_region*r,struct page**p,u32 n,void**h){
    CHECK(!lock_depth&&active_stage->priv);
    ce_configured_observer(true);
    CHECK(r->ops==((struct xdev_ext_ce_stage*)active_stage->priv)->ops);
    *h=(void*)0x200;
    event("host+");
    return bind_host_errno;
}
static int dma_bind_host(struct xdev_ext_dma_region*r,struct page**p,u32 n,void**h){
    CHECK(!lock_depth&&active_stage->priv);
    *h=(void*)0x200;
    event("host+");
    return bind_host_errno;
}
static int native_unbind_host(void*h){
    observe_cleanup();
    CHECK(h==(void*)0x200);
    event("host-");
    return unbind_host_errno;
}
static void native_xfer(u64 owner,u64 generation,u64 host,u64 dev,u32 len,u32 flags){
    CHECK(owner==21&&generation==55&&host==272&&dev==256&&len==128&&flags==3);
    printf("XFER owner=%llu gen=%llu host=%llu device=%llu len=%u flags=%u\n",(unsigned long long)owner,(unsigned long long)generation,(unsigned long long)host,(unsigned long long)dev,len,flags);
}
static int ce_native_submit(struct xdev_ext_ce_region*r,void*h,u32 dir,const struct xdev_ext_ce_xfer*x,u32 n,struct xdev_ext_ce_cookie*ck,u64 ticket){
    CHECK(!lock_depth&&n==1&&x==((struct xdev_ext_ce_batch*)native_batch->priv)->x);
    native_xfer(x->owner,x->generation,x->host_byte_off,x->gpu_off,x->len,x->flags);
    saved_xfers=x;
    native_calls++;
    pending_cookie=ck;
    pending_ticket=ticket;
    event("submit");
    if(inline_complete)xdev_ext_ce_complete(ck,ticket,0,true,128);
    return native_submit_errno;
}
static int dma_native_submit(struct xdev_ext_dma_region*r,void*h,u32 dir,const struct xdev_ext_dma_xfer*x,u32 n,struct xdev_ext_dma_cookie*ck,u64 ticket){
    CHECK(!lock_depth&&n==1&&x==((struct xdev_ext_dma_batch*)native_batch->priv)->x);
    native_xfer(x->owner,x->generation,x->host_byte_off,x->device_off,x->len,x->flags);
    saved_xfers=x;
    native_calls++;
    pending_cookie=ck;
    pending_ticket=ticket;
    event("submit");
    if(inline_complete)xdev_ext_dma_complete(ck,ticket,0,true,128);
    return native_submit_errno;
}
static int native_poll(struct xdev_ext_dma_region*r){
    CHECK(!lock_depth);
    poll_calls++;
    event("poll");
    if(pending_cookie){
        xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,128);
        pending_cookie=NULL;
    }
    return poll_errno;
}
static void scope_release(void*p){
    CHECK(!lock_depth);
    scope_releases++;
    event("scope-");
}
static int scope_acquire(struct file*f,u64 start,u64 len,struct xdev_ext_dma_scope_info*out){
    CHECK(!lock_depth&&active_stage->priv);
    event("scope+");
    out->kind=scope_kind;
    if(scope_kind==2){
        CHECK(!xdev_ext_dma_scope_get(scope_object));
        out->scope=scope_object;
        out->canonical_start=scope_start;
        out->canonical_len=len;
    }
    return scope_acquire_errno;
}
static struct xdev_ext_dma_scope_ops scope_ops={
    sizeof(scope_ops),1,0,0,scope_acquire
}
;
static void defaults(void){
    bind_region_errno=bind_host_errno=unbind_host_errno=unbind_region_errno=native_submit_errno=scope_acquire_errno=poll_errno=0;
    region_zero_output=clear_polled=inline_complete=check_hold=ce_check_exclusion=ce_zero_length=ce_short_region=false;
    ce_expected_foreign=-EAGAIN;ce_expected_own=-EBUSY;
    conflict_stage=NULL;
    conflict_batch=NULL;
    pending_cookie=NULL;
    clear_trace();
}
static int poisoned_ce_submit(struct xdev_ext_ce_region*r,void*h,u32 dir,const struct xdev_ext_ce_xfer*x,u32 n,struct xdev_ext_ce_cookie*ck,u64 ticket){
    CHECK(false);return -EUCLEAN;
}
static void setup_ops(void){
    for(int i=0;i<7;i++){
        fops[i].id=i;
        ce_ops[i]=(struct xdev_ext_ce_backend_ops){
            &native_module,&fops[i],ce_bind_region,ce_unbind_region,ce_bind_host,native_unbind_host,ce_native_submit
        }
        ;
        dma_ops[i]=(struct xdev_ext_dma_provider_ops){
            &native_module,&fops[i],dma_bind_region,dma_unbind_region,dma_bind_host,native_unbind_host,dma_native_submit,native_poll
        }
        ;
    }
    ce_ops[6].submit=poisoned_ce_submit;
    ce_ops[6].owner=&poisoned_module;
}
static void registry(void){
    runtime_consumer=0;
    int a=allocations;
    CHECK(xdev_ext_ce_backend_register(NULL)==-EINVAL);
    for(int i=0;i<4;i++)CHECK(!xdev_ext_ce_backend_register(&ce_ops[i]));
    CHECK(xdev_ext_ce_backend_register(&ce_ops[0])==-EBUSY);
    CHECK(xdev_ext_ce_backend_register(&ce_ops[4])==-ENOSPC);
    CHECK(allocations==a);
    struct file f={
        &fops[0]
    }
    ;
    expect_registry_pin=true;
    CHECK(xdev_ext_ce_backend_get(&f)==&ce_ops[0]);
    expect_registry_pin=false;
    CHECK(native_module.refs==1);
    xdev_ext_ce_backend_unregister(&ce_ops[0]);
    CHECK(native_module.refs==1);
    CHECK(!xdev_ext_ce_backend_register(&ce_ops[4]));
    module_put(&native_module);
    for(int i=1;i<5;i++)xdev_ext_ce_backend_unregister(&ce_ops[i]);
    runtime_consumer=1;
    for(int i=0;i<6;i++)CHECK(!xdev_ext_dma_provider_register(&dma_ops[i]));
    allocation_fail=1;
    CHECK(xdev_ext_dma_provider_register(&dma_ops[0])==-ENOMEM);
    CHECK(xdev_ext_dma_provider_register(&dma_ops[0])==-EBUSY);
    const struct xdev_ext_dma_scope_ops*side=(void*)1;
    expect_registry_pin=true;
    CHECK(xdev_ext_dma_provider_get(&f,&side)==&dma_ops[0]);
    expect_registry_pin=false;
    CHECK(side==NULL&&native_module.refs==1);
    xdev_ext_dma_provider_unregister(&dma_ops[0]);
    CHECK(native_module.refs==1);
    module_put(&native_module);
    for(int i=1;i<6;i++)xdev_ext_dma_provider_unregister(&dma_ops[i]);
    struct xdev_ext_dma_scope_ops bad=scope_ops;
    bad.size=0;
    bad.version=9;
    CHECK(xdev_ext_dma_provider_register_scoped(&dma_ops[0],&bad)==-EINVAL);
    bad.size=sizeof(bad);
    CHECK(xdev_ext_dma_provider_register_scoped(&dma_ops[0],&bad)==-EOPNOTSUPP);
    bad.version=1;
    bad.flags=1;
    CHECK(xdev_ext_dma_provider_register_scoped(&dma_ops[0],&bad)==-EINVAL);
    bad.flags=0;
    bad.reserved=1;
    CHECK(xdev_ext_dma_provider_register_scoped(&dma_ops[0],&bad)==-EINVAL);
    bad.reserved=0;
    bad.acquire=NULL;
    CHECK(xdev_ext_dma_provider_register_scoped(&dma_ops[0],&bad)==-EINVAL);
    CHECK(!xdev_ext_dma_provider_register_scoped(&dma_ops[0],&scope_ops));
    CHECK(xdev_ext_dma_provider_get(&f,&side)==&dma_ops[0]&&side==&scope_ops);
    xdev_ext_dma_provider_unregister(&dma_ops[0]);
    CHECK(native_module.refs==1);
    module_put(&native_module);
    f.f_op=&fops[11];
    side=(void*)1;
    CHECK(!xdev_ext_dma_provider_get(&f,&side)&&!side);
    CHECK(!native_module.refs);
    puts("PASS registry capacity/duplicate/ENOMEM/pin/sidecar");
}
struct fixture {
    struct xdev_ext_mech_session session;
    struct xdev_ext_mech_stage st;
    struct file file;
    struct page *pages[1];
    struct xdev_ext_mech_batch batch;
    union {
        max_align_t align;
        unsigned char bytes[16384];
    }
    priv;
    union {
        max_align_t align;
        unsigned char bytes[64];
    }
    cookie;
}
;
static struct xdev_ext_mech_stage_uapi bind_u={
    .arg0=4096,.arg1=512
}
;
static void init_fixture(struct fixture*f,bool dma){
    memset(f,0,sizeof(*f));
    f->session.depth=2;
    f->session.layout.group_bytes=256;
    f->session.pool.pages=f->pages;
    f->session.pool.nr_pages=1;
    f->session.pool.frame_size=256;
    f->session.pool.nr_frames=4;
    f->file.f_op=&fops[0];
    f->st=(struct xdev_ext_mech_stage){
        .s=&f->session,.file=&f->file,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.cls=dma?&xdev_ext_dma_class:&xdev_ext_ce_class
    }
    ;
    f->batch=(struct xdev_ext_mech_batch){
        .priv=f->priv.bytes,.cookie=f->cookie.bytes,.id=91,.ticket=17,.slot=1,.nr=1,.owners_valid=true,.phase=1,.completion={
            .ctrl=(17ULL<<3)|1
        }
    }
    ;
    f->batch.frames[0]=(struct xdev_ext_mech_frame){
        .umem_addr=1024,.index=1,.data_off=16,.data_len=128
    }
    ;
}
static void observe_stage(struct fixture*f,bool dma,const char*op,int ret){
    bool host=false,region=false,lease=false,cleanup=false,scope=false;
    if(f->st.priv){
        if(dma){
            struct xdev_ext_dma_stage*cs=f->st.priv;
            host=STATE(cs)->host!=NULL;
            region=cs->region.priv!=NULL;
            lease=cs->lease_group!=NULL;
            cleanup=cs->cleanup_held;
            scope=cs->scope!=NULL;
        }
        else{
            struct xdev_ext_ce_stage*cs=f->st.priv;
            host=STATE(cs)->host!=NULL;
            region=cs->region.priv!=NULL;
            lease=cs->lease_group!=NULL;
            cleanup=cs->cleanup_held;
        }
    }
    printf("OBS %s %s ret=%d stage=%d host=%d region=%d lease=%d cleanup=%d scope=%d native_pin=%d scope_pin=%d trace=[%s]\n",dma?"DMA":"CE",op,ret,f->st.priv!=NULL,host,region,lease,cleanup,scope,native_module.refs,scope_module.refs,trace);
}
static int bind_fixture(struct fixture*f,bool dma){
    active_stage=&f->st;
    active_dma=dma;
    runtime_consumer=dma;
    int ret=f->st.cls->bind(&f->st,&bind_u);
    observe_stage(f,dma,"bind",ret);
    return ret;
}
static int unbind_fixture(struct fixture*f,bool dma){
    active_stage=&f->st;
    active_dma=dma;
    runtime_consumer=dma;
    int ret=f->st.cls->unbind_checked(&f->st);
    observe_stage(f,dma,"unbind",ret);
    return ret;
}
static void release_fixture(struct fixture*f,bool dma){
    if(f->st.priv)f->st.cls->batch_release(&f->st,&f->batch,false);
    CHECK(!unbind_fixture(f,dma));
}
static struct xdev_ext_window_copy_desc desc={
    0,16,256,128,3
}
;
static int validate_fixture(struct fixture*f){
    return f->st.cls->validate(&f->st,&f->batch,(const u8*)&desc,1);
}
static int submit_fixture(struct fixture*f){
    native_batch=&f->batch;
    active_stage=&f->st;
    active_dma=f->st.cls==&xdev_ext_dma_class;
    int ret=f->st.cls->submit(&f->st,&f->batch);
    observe_stage(f,active_dma,"submit",ret);
    return ret;
}
static void complete_fixture(struct fixture*f,bool dma,int e,bool hw,u64 bytes){
    if(dma)xdev_ext_dma_complete((void*)f->cookie.bytes,f->batch.ticket,e,hw,bytes);
    else xdev_ext_ce_complete((void*)f->cookie.bytes,f->batch.ticket,e,hw,bytes);
    printf("OBS %s complete input=%d/%d/%llu publish=%d/%d/%d trace=[%s]\n",dma?"DMA":"CE",e,hw,(unsigned long long)bytes,f->batch.publishes,f->batch.publish_errno,f->batch.sequestered,trace);
}
static void binds(void){
    for(int dma=0;dma<2;dma++){
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        struct xdev_ext_mech_stage_uapi u=bind_u;
        u.flags=2;
        int before=allocations;
        CHECK(f.st.cls->bind(&f.st,&u)==-EINVAL&&allocations==before&&!f.st.priv);
        bind_region_errno=-ENXIO;
        CHECK(bind_fixture(&f,dma)==-ENXIO&&f.st.priv&&native_module.refs==1);
        expect_trace("region+ ");
        CHECK(!unbind_fixture(&f,dma));
        CHECK(!native_module.refs);
        defaults();
        init_fixture(&f,dma);
        bind_host_errno=-ENOSPC;
        CHECK(bind_fixture(&f,dma)==-ENOSPC&&f.st.priv);
        expect_trace("region+ host+ ");
        unbind_host_errno=-EAGAIN;
        CHECK(unbind_fixture(&f,dma)==-EAGAIN&&f.st.priv&&native_module.refs==1);
        unbind_host_errno=0;
        CHECK(!unbind_fixture(&f,dma));
        CHECK(!native_module.refs);
    }
    struct fixture f;
    defaults();
    init_fixture(&f,true);
    f.st.poll=true;
    dma_ops[0].poll=NULL;
    CHECK(bind_fixture(&f,true)==-EOPNOTSUPP&&!f.st.priv&&!native_module.refs);
    dma_ops[0].poll=native_poll;
    clear_polled=true;
    CHECK(bind_fixture(&f,true)==-EPROTO&&f.st.priv);
    CHECK(!unbind_fixture(&f,true));
    CHECK(xdev_ext_ce_class.poll==NULL);
    defaults();
    init_fixture(&f,true);
    region_zero_output=true;
    CHECK(!bind_fixture(&f,true));
    CHECK(((struct xdev_ext_dma_stage*)f.st.priv)->ops==&dma_ops[0]);
    CHECK(((struct xdev_ext_dma_stage*)f.st.priv)->region.ops==&dma_ops[0]);
    CHECK(!unbind_fixture(&f,true));
    puts("PASS bind residual/errno/poll/output identity");
}
static void bind_error_order(void) {
    for(int dma=0;dma<2;dma++) {
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        struct xdev_ext_mech_stage_uapi u=bind_u;
        int before=allocations;
        u.arg1=0;
        CHECK(f.st.cls->bind(&f.st,&u)==-EINVAL);
        u=bind_u;
        u.arg0=UINT64_MAX;
        CHECK(f.st.cls->bind(&f.st,&u)==-EINVAL);
        u=bind_u;
        f.st.direction=99;
        CHECK(f.st.cls->bind(&f.st,&u)==-EINVAL);
        f.st.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;
        f.session.pool.pages=NULL;
        CHECK(f.st.cls->bind(&f.st,&u)==-EINVAL&&allocations==before&&!f.st.priv);
        f.session.pool.pages=f.pages;
        allocation_fail=1;
        CHECK(bind_fixture(&f,dma)==-ENOMEM&&!f.st.priv&&!native_module.refs);
        native_module.unavailable=true;
        CHECK(bind_fixture(&f,dma)==-ENODEV&&!f.st.priv&&!native_module.refs);
        native_module.unavailable=false;
    }
    puts("PASS flags/direction/pool/window/allocation/module bind errno order");
}
static void preparation(void){
    for(int dma=0;dma<2;dma++){
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        int n=frame_reads;
        CHECK(f.st.cls->validate(&f.st,NULL,NULL,33)==-EINVAL&&frame_reads==n);
        CHECK(f.st.cls->validate(&f.st,&f.batch,NULL,33)==-E2BIG&&frame_reads==n);
        f.batch.frame_error=-EFAULT;
        CHECK(validate_fixture(&f)==-EFAULT);
        f.batch.frame_error=0;
        f.batch.nr=XDEV_EXT_MECH_MAX_FRAMES+1;
        CHECK(validate_fixture(&f)==-E2BIG);
        f.batch.nr=1;
        struct xdev_ext_window_copy_desc d=desc;
        d.flags=8;
        CHECK(f.st.cls->validate(&f.st,&f.batch,(u8*)&d,1)==-EOPNOTSUPP);
        d=desc;
        d.len=127;
        CHECK(f.st.cls->validate(&f.st,&f.batch,(u8*)&d,1)==-ENODATA);
        d=desc;
        d.dev_off=0;
        CHECK(f.st.cls->validate(&f.st,&f.batch,(u8*)&d,1)==-ERANGE);
        CHECK(!validate_fixture(&f));
        if(dma){
            struct xdev_ext_dma_stage*cs=f.st.priv;
            CHECK(STATE(cs)->index[0]==1&&STATE(cs)->fi[0].umem_addr==1024&&STATE(cs)->fi[0].data_off==16&&STATE(cs)->fi[0].data_len==128);
        }
        else{
            struct xdev_ext_ce_stage*cs=f.st.priv;
            CHECK(STATE(cs)->index[0]==1&&STATE(cs)->fi[0].umem_addr==1024);
        }
        if(dma){
            struct xdev_ext_dma_mech_info i;
            memset(&i,0xff,sizeof(i));
            f.st.cls->fill_info(&f.st,NULL,&i);
            CHECK(!i.nr_frames&&i.window_slot==UINT32_MAX&&!i.window_depth&&!i.lease_generation);
            for(int j=0;j<XDEV_EXT_MECH_MAX_FRAMES;j++)CHECK(!i.f[j].data_len&&!i.f[j].umem_addr);
            f.st.cls->fill_info(&f.st,&f.batch,&i);
            CHECK(i.nr_frames==1&&i.window_slot==1&&i.window_depth==2&&i.lease_generation==91);
            f.batch.frame_error=-EFAULT;
            f.st.cls->fill_info(&f.st,&f.batch,&i);
            CHECK(!i.nr_frames&&!i.f[0].data_len);
        }
        else{
            struct xdev_ext_ce_mech_info i;
            memset(&i,0xff,sizeof(i));
            f.st.cls->fill_info(&f.st,NULL,&i);
            CHECK(!i.nr_frames&&i.window_slot==UINT32_MAX&&!i.window_depth&&!i.lease_generation);
            f.st.cls->fill_info(&f.st,&f.batch,&i);
            CHECK(i.nr_frames==1&&i.window_slot==1&&i.window_depth==2&&i.lease_generation==91);
            f.batch.frame_error=-EFAULT;
            f.st.cls->fill_info(&f.st,&f.batch,&i);
            CHECK(!i.nr_frames&&!i.f[0].data_len);
        }
        f.batch.frame_error=0;
        CHECK(!unbind_fixture(&f,dma));
    }
    puts("PASS collect/validate/info count/flags/coverage/slot");
}
static void submit_paths(void){
    for(int dma=0;dma<2;dma++){
        for(int ret=-1;ret<=1;ret++){
            struct fixture f;
            defaults();
            init_fixture(&f,dma);
            CHECK(!bind_fixture(&f,dma));
            CHECK(!validate_fixture(&f));
            native_submit_errno=ret<0?-ENOSPC:ret;
            CHECK(submit_fixture(&f)==(ret<0?-ENOSPC:0));
            struct xdev_ext_native_cookie_layout*ck=(void*)f.cookie.bytes;
            CHECK(ck->b==&f.batch);
            CHECK(ck->state==(ret<0?0:1));
            CHECK(ck->status==(ret<0?-ENOSPC:0));
            release_fixture(&f,dma);
        }
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        CHECK(!validate_fixture(&f));
        f.batch.claim_error=-ESTALE;
        int calls=native_calls;
        CHECK(submit_fixture(&f)==-ESTALE&&native_calls==calls);
        f.batch.claim_error=0;
        CHECK(!validate_fixture(&f));
        if(dma)STATE((struct xdev_ext_dma_stage*)f.st.priv)->plan.batch_id++;
        else STATE((struct xdev_ext_ce_stage*)f.st.priv)->plan.batch_id++;
        CHECK(submit_fixture(&f)==-EPROTO);
        CHECK(!validate_fixture(&f));
        struct xdev_ext_native_cookie_layout*ck=(void*)f.cookie.bytes;
        ck->state=1;
        CHECK(submit_fixture(&f)==-EBUSY);
        ck->state=0;
        CHECK(!validate_fixture(&f));
        f.st.cls->mark_dead(&f.st);
        if(dma)STATE((struct xdev_ext_dma_stage*)f.st.priv)->staged=NULL;
        else STATE((struct xdev_ext_ce_stage*)f.st.priv)->staged=NULL;
        calls=native_calls;
        CHECK(submit_fixture(&f)==-ENODEV&&native_calls==calls);
        release_fixture(&f,dma);
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        CHECK(!validate_fixture(&f));
        inline_complete=true;
        native_submit_errno=-ENOSPC;
        CHECK(!submit_fixture(&f));
        CHECK(f.batch.publishes==1&&!f.batch.sequestered&&f.batch.publish_errno==0);
        release_fixture(&f,dma);
    }
    puts("PASS submit stable typed transfers/refusal/positive/inline/dead");
}
static void transfer_transaction(void) {
    for (int dma=0;dma<2;dma++) {
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        struct xdev_ext_window_copy_desc pieces[2]={
            {
                0,16,256,64,0
            }
            ,{
                0,80,320,64,3
            }
        }
        ;
        CHECK(!f.st.cls->validate(&f.st,&f.batch,(u8*)pieces,2));
        void *scratch=dma?(void*)STATE((struct xdev_ext_dma_stage*)f.st.priv)->transfer:(void*)STATE((struct xdev_ext_ce_stage*)f.st.priv)->transfer;
        unsigned char want[sizeof(struct xdev_ext_comp_copy_transfer)*32];
        memset(want,0x6b,sizeof(want));
        memcpy(scratch,want,sizeof(want));
        memset(f.priv.bytes,0x4c,sizeof(f.priv.bytes));
        claim_attempts=0;
        fail_claim_call=2;
        CHECK(submit_fixture(&f)==-ESTALE&&claim_attempts==2);
        CHECK(!memcmp(scratch,want,sizeof(want)));
        for(unsigned i=0;i<sizeof(f.priv.bytes);i++)CHECK(f.priv.bytes[i]==0x4c);
        fail_claim_call=0;
        CHECK(!validate_fixture(&f));
        if(dma)STATE((struct xdev_ext_dma_stage*)f.st.priv)->plan.slot=0;
        else STATE((struct xdev_ext_ce_stage*)f.st.priv)->plan.slot=0;
        CHECK(submit_fixture(&f)==-EPROTO);
        CHECK(!validate_fixture(&f));
        CHECK(!submit_fixture(&f));
        memset(scratch,0,sizeof(want));
        if(dma){
            const struct xdev_ext_dma_xfer*x=saved_xfers;
            native_xfer(x->owner,x->generation,x->host_byte_off,x->device_off,x->len,x->flags);
        }
        else {
            const struct xdev_ext_ce_xfer*x=saved_xfers;
            native_xfer(x->owner,x->generation,x->host_byte_off,x->gpu_off,x->len,x->flags);
        }
        release_fixture(&f,dma);
    }
    puts("PASS transactional second-claim failure/stale plan slot/native storage lifetime");
}
static void lease_refusal(void){
    for(int dma=0;dma<2;dma++){
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        CHECK(!validate_fixture(&f));
        unsigned char cookie[64];
        memcpy(cookie,f.cookie.bytes,64);
        if(dma)((struct xdev_ext_dma_stage*)f.st.priv)->lease_group->state.quarantined=true;
        else ((struct xdev_ext_ce_stage*)f.st.priv)->lease_group->state.quarantined=true;
        CHECK(submit_fixture(&f)==-EBUSY&&!memcmp(cookie,f.cookie.bytes,64));
        if(dma){
            struct xdev_ext_dma_stage*cs=f.st.priv;
            CHECK(STATE(cs)->staged==&f.batch);
            cs->lease_group->state.quarantined=false;
        }
        else{
            struct xdev_ext_ce_stage*cs=f.st.priv;
            CHECK(STATE(cs)->staged==&f.batch);
            cs->lease_group->state.quarantined=false;
        }
        CHECK(!unbind_fixture(&f,dma));
    }
    puts("PASS lease refusal before cookie/staged consumption");
}
static void cqe_bytes(struct fixture*f,u32 outcome,int status,u64 bytes,u32 entries){
    unsigned char got[24],want[24]={
        0
    }
    ;
    /* Little-endian ABI bytes are literal independent fields. */CHECK(sizeof(struct xdev_ext_ce_mech_cqe)==24&&sizeof(struct xdev_ext_dma_mech_cqe)==24);
    for(int i=0;i<4;i++){
        want[i]=(outcome>>(8*i))&255;
        want[4+i]=((u32)status>>(8*i))&255;
        want[16+i]=(entries>>(8*i))&255;
    }
    for(int i=0;i<8;i++)want[8+i]=(bytes>>(8*i))&255;
    memset(got,0xa5,sizeof(got));
    f->st.cls->fill_cqe(&f->st,&f->batch,got);
    CHECK(!memcmp(got,want,24));
    printf("CQE %s ",f->st.cls==&xdev_ext_dma_class?"DMA":"CE");
    for(int i=0;i<24;i++)printf("%02x",got[i]);
    puts("");
}
static void completions(void){
    struct vector{
        int status;
        bool hw;
        u64 bytes;
        u32 outcome;
        int ce_status,dma_status,publish;
        bool seq;
        u32 entries;
    }
    v[]={
        {
            0,true,128,0,0,0,0,false,1
        }
        ,{
            0,true,127,2,-EIO,0,-EIO,true,0
        }
        ,{
            0,false,128,1,-EIO,-EIO,1,false,0
        }
        ,{
            0,true,129,2,-EIO,0,-EIO,true,0
        }
        ,{
            1,true,128,2,1,1,-EIO,true,0
        }
        ,{
            -ENOSPC,false,17,1,-ENOSPC,-ENOSPC,1,false,0
        }
        ,{
            -ENXIO,true,17,2,-ENXIO,-ENXIO,-ENXIO,true,0
        }
    }
    ;
    for(int dma=0;dma<2;dma++)for(unsigned i=0;i<ARRAY_SIZE(v);i++){
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        CHECK(!validate_fixture(&f));
        CHECK(!submit_fixture(&f));
        clear_trace();
        complete_fixture(&f,dma,v[i].status,v[i].hw,v[i].bytes);
        expect_trace("claim publish ");
        CHECK(f.batch.publishes==1&&f.batch.publish_errno==v[i].publish&&f.batch.sequestered==v[i].seq);
        cqe_bytes(&f,v[i].outcome,dma?v[i].dma_status:v[i].ce_status,v[i].bytes>128?128:v[i].bytes,v[i].entries);
        complete_fixture(&f,dma,99,true,1);
        CHECK(f.batch.publishes==1);
        /* Controlled final disposition for isolated cleanup, never acceptance of UNKNOWN release. */if(dma)atomic_set(&STATE((struct xdev_ext_dma_stage*)f.st.priv)->ambiguous,0);
        else atomic_set(&STATE((struct xdev_ext_ce_stage*)f.st.priv)->ambiguous,0);
        release_fixture(&f,dma);
    }
    for(int dma=0;dma<2;dma++){
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        CHECK(!validate_fixture(&f));
        CHECK(!submit_fixture(&f));
        struct xdev_ext_native_cookie_layout*ck=(void*)f.cookie.bytes;
        ck->state=0;
        ck->status=123;
        ck->bytes_done=7;
        ck->outcome=9;
        complete_fixture(&f,dma,0,true,128);
        CHECK(f.batch.publish_errno==-EPROTO&&f.batch.sequestered&&ck->status==123&&ck->bytes_done==7&&ck->outcome==9);
        cqe_bytes(&f,1,123,0,0);
        if(dma)atomic_set(&STATE((struct xdev_ext_dma_stage*)f.st.priv)->ambiguous,0);
        else atomic_set(&STATE((struct xdev_ext_ce_stage*)f.st.priv)->ambiguous,0);
        release_fixture(&f,dma);
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        CHECK(!validate_fixture(&f));
        CHECK(!submit_fixture(&f));
        f.batch.owners_valid=false;
        complete_fixture(&f,dma,-ENOSPC,false,128);
        CHECK(f.batch.sequestered==(bool)dma);
        cqe_bytes(&f,dma?2:1,dma?-ESTALE:-ENOSPC,128,0);
        if(dma)atomic_set(&STATE((struct xdev_ext_dma_stage*)f.st.priv)->ambiguous,0);
        release_fixture(&f,dma);
    }
    puts("PASS completion matrix/owner/unarmed/full CQE bytes");
}
static void stale_reuse(void){
    for(int old_dma=0;old_dma<2;old_dma++){
        struct fixture f,next;
        defaults();
        init_fixture(&f,old_dma);
        CHECK(!bind_fixture(&f,old_dma));
        CHECK(!validate_fixture(&f));
        CHECK(!submit_fixture(&f));
        complete_fixture(&f,old_dma,0,true,128);
        release_fixture(&f,old_dma);
        /* Core keeps b/cookie stable and zeroes only typed batch private storage on stage rebuild. */  init_fixture(&next,!old_dma);
        CHECK(!bind_fixture(&next,!old_dma));
        f.st=next.st;
        memset(f.priv.bytes,0,sizeof(f.priv.bytes));
        f.batch.ticket=18;
        f.batch.claimed=false;
        f.batch.publishes=0;
        f.batch.completion.ctrl=(18ULL<<3)|1;
        CHECK(!validate_fixture(&f));
        CHECK(!submit_fixture(&f));
        struct xdev_ext_native_cookie_layout*ck=(void*)f.cookie.bytes;
        CHECK(ck->b==&f.batch&&ck->state==1);
        void*saved=ck->cs;
        void*guard=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        CHECK(guard!=MAP_FAILED);
        ck->cs=guard;
        f.batch.priv=guard;
        clear_trace();
        pid_t pid=fork();
        CHECK(pid>=0);
        if(!pid){
            if(old_dma)xdev_ext_dma_complete((void*)ck,17,0,true,128);
            else xdev_ext_ce_complete((void*)ck,17,0,true,128);
            _exit(0);
        }
        int status;
        CHECK(waitpid(pid,&status,0)==pid);
        CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
        CHECK(!f.batch.publishes&&!trace[0]);
        ck->cs=saved;
        f.batch.priv=f.priv.bytes;
        munmap(guard,4096);
        complete_fixture(&f,!old_dma,0,true,128);
        CHECK(f.batch.publishes==1);
        release_fixture(&f,!old_dma);
    }
    puts("PASS CE-to-DMA and DMA-to-CE same-batch cookie reuse, protected stale stage/batch");
}
static void owner_phases(void){
    for(int dma=0;dma<2;dma++){
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        CHECK(!validate_fixture(&f));
        CHECK(!submit_fixture(&f));
        if(dma){
            struct xdev_ext_dma_batch*cb=f.batch.priv;
            CHECK(xdev_ext_dma_owners_valid((void*)f.cookie.bytes,17,cb->x,1));
            f.batch.completion.ctrl=(17ULL<<3)|2;
            CHECK(xdev_ext_dma_owners_valid((void*)f.cookie.bytes,17,cb->x,1));
            CHECK(!xdev_ext_dma_owners_valid((void*)f.cookie.bytes,16,(void*)1,1));
        }
        else{
            struct xdev_ext_ce_batch*cb=f.batch.priv;
            CHECK(xdev_ext_ce_owners_valid((void*)f.cookie.bytes,17,cb->x,1));
            f.batch.completion.ctrl=(17ULL<<3)|2;
            CHECK(!xdev_ext_ce_owners_valid((void*)f.cookie.bytes,17,cb->x,1));
            CHECK(!xdev_ext_ce_owners_valid((void*)f.cookie.bytes,16,(void*)1,1));
        }
        release_fixture(&f,dma);
    }
    puts("PASS actual core CE SUBMITTED versus DMA COMPLETING owner admission");
}
static void poll_case(void){
    struct fixture f;
    defaults();
    init_fixture(&f,true);
    f.st.poll=true;
    CHECK(!bind_fixture(&f,true));
    CHECK(!validate_fixture(&f));
    CHECK(!submit_fixture(&f));
    poll_errno=-EIO;
    int n=poll_calls;
    clear_trace();
    CHECK(f.st.cls->poll(&f.st)==-EIO&&poll_calls==n+1&&f.batch.publishes==1&&!f.batch.sequestered);
    expect_trace("poll claim publish ");
    release_fixture(&f,true);
    puts("PASS DMA one-pass poll inline completion/informational errno");
}
static void cleanup(void){
    for(int dma=0;dma<2;dma++){
        struct fixture f;
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        if(dma)atomic_set(&STATE((struct xdev_ext_dma_stage*)f.st.priv)->ambiguous,1);
        else atomic_set(&STATE((struct xdev_ext_ce_stage*)f.st.priv)->ambiguous,1);
        clear_trace();
        CHECK(unbind_fixture(&f,dma)==-EBUSY&&!trace[0]);
        if(dma)atomic_set(&STATE((struct xdev_ext_dma_stage*)f.st.priv)->ambiguous,0);
        else atomic_set(&STATE((struct xdev_ext_ce_stage*)f.st.priv)->ambiguous,0);
        unbind_region_errno=-EXDEV;
        check_hold=dma;
        CHECK(unbind_fixture(&f,dma)==-EXDEV&&f.st.priv&&native_module.refs==1);
        expect_trace("host- region- ");
        clear_trace();
        unbind_region_errno=0;
        CHECK(!unbind_fixture(&f,dma));
        expect_trace("region- ");
        CHECK(!native_module.refs);
        defaults();
        init_fixture(&f,dma);
        CHECK(!bind_fixture(&f,dma));
        CHECK(!validate_fixture(&f));
        CHECK(!submit_fixture(&f));
        f.st.cls->batch_release(&f.st,&f.batch,true);
        clear_trace();
        CHECK(unbind_fixture(&f,dma)==-EBUSY&&!trace[0]);
        if(dma){
            struct xdev_ext_dma_stage*cs=f.st.priv;
            CHECK(cs->lease_group->state.quarantined&&cs->lease_group->state.active_batches==1);
            cs->lease_group->state.quarantined=false;
        }
        else{
            struct xdev_ext_ce_stage*cs=f.st.priv;
            CHECK(cs->lease_group->state.quarantined&&cs->lease_group->state.active_batches==1);
            cs->lease_group->state.quarantined=false;
        }
        release_fixture(&f,dma);
    }
    puts("PASS cleanup refusal/retry/handle order/quarantine retention");
}
static void namespace_domains(void){
    struct fixture a,b;
    defaults();
    init_fixture(&a,true);
    init_fixture(&b,true);
    CHECK(!bind_fixture(&a,true));
    CHECK(!xdev_ext_dma_provider_register(&dma_ops[1]));
    b.file.f_op=&fops[1];
    CHECK(!bind_fixture(&b,true));
    CHECK(!xdev_ext_dma_lease_get(a.st.priv,&a.batch));
    CHECK(!xdev_ext_dma_lease_get(b.st.priv,&b.batch));
    release_fixture(&a,true);
    release_fixture(&b,true);
    xdev_ext_dma_provider_unregister(&dma_ops[1]);
    defaults();
    init_fixture(&a,false);
    init_fixture(&b,true);
    CHECK(!bind_fixture(&a,false));
    CHECK(!bind_fixture(&b,true));
    CHECK(!xdev_ext_ce_lease_get(a.st.priv,&a.batch));
    CHECK(!xdev_ext_dma_lease_get(b.st.priv,&b.batch));
    release_fixture(&a,false);
    release_fixture(&b,true);
    puts("PASS distinct provider and CE/DMA lease namespaces");
}
static void scoped_lifetimes(void){
    xdev_ext_dma_provider_unregister(&dma_ops[0]);
    CHECK(!xdev_ext_dma_provider_register_scoped(&dma_ops[0],&scope_ops));
    scope_object=xdev_ext_dma_scope_create(&scope_module,NULL,scope_release);
    CHECK(!IS_ERR(scope_object)&&!scope_module.refs);
    CHECK(PTR_ERR(xdev_ext_dma_scope_create(&scope_module,NULL,NULL))==-EINVAL);
    CHECK(xdev_ext_dma_scope_get(NULL)==-EINVAL);
    scope_module.unavailable=true;
    CHECK(xdev_ext_dma_scope_get(scope_object)==-ENODEV&&!scope_module.refs);
    scope_module.unavailable=false;
    struct fixture a,b;
    defaults();
    init_fixture(&a,true);
    scope_start=1000;
    region_zero_output=true;
    CHECK(!bind_fixture(&a,true));
    CHECK(scope_module.refs==1);
    struct xdev_ext_dma_stage*cs=a.st.priv;
    CHECK(cs->key.provider==&dma_ops[0]&&cs->key.scope==scope_object&&cs->key.start==1000&&cs->scope==scope_object);
    init_fixture(&b,true);
    scope_start=1000;
    CHECK(!bind_fixture(&b,true));
    CHECK(!validate_fixture(&b));
    CHECK(!submit_fixture(&b));
    /* An active alias excludes a new batch in the first group. */CHECK(xdev_ext_dma_lease_get(a.st.priv,&a.batch)==-EAGAIN);
    b.st.cls->batch_release(&b.st,&b.batch,false);
    /* Keep b's same-batch lease active while a's cleanup hold is introduced. */CHECK(!xdev_ext_dma_lease_get(b.st.priv,&b.batch));
    active_stage=&a.st;
    active_dma=true;
    check_hold=true;
    conflict_stage=&b.st;
    conflict_batch=&b.batch;
    unbind_host_errno=-EAGAIN;
    CHECK(unbind_fixture(&a,true)==-EAGAIN);
    CHECK(cs->cleanup_held&&cs->scope==scope_object&&scope_module.refs==2);
    CHECK(xdev_ext_dma_lease_get(b.st.priv,&b.batch)==-EAGAIN);
    CHECK(xdev_ext_dma_lease_get(a.st.priv,&a.batch)==-EBUSY);
    conflict_stage=NULL;
    check_hold=false;
    unbind_host_errno=0;
    CHECK(!unbind_fixture(&a,true));
    CHECK(scope_module.refs==1);
    release_fixture(&b,true);
    CHECK(!scope_module.refs);
    defaults();
    init_fixture(&a,true);
    scope_acquire_errno=-EACCES;
    scope_start=2000;
    CHECK(bind_fixture(&a,true)==-EACCES&&a.st.priv&&scope_module.refs==1);
    expect_trace("scope+ ");
    CHECK(!unbind_fixture(&a,true)&&!scope_module.refs);
    defaults();
    init_fixture(&a,true);
    scope_acquire_errno=1;
    CHECK(bind_fixture(&a,true)==-EPROTO&&scope_module.refs==1);
    CHECK(!unbind_fixture(&a,true));
    defaults();
    init_fixture(&a,true);
    scope_kind=1;
    CHECK(!bind_fixture(&a,true));
    init_fixture(&b,true);
    scope_kind=2;
    scope_start=9000;
    CHECK(!bind_fixture(&b,true));
    CHECK(!xdev_ext_dma_lease_get(a.st.priv,&a.batch));
    CHECK(xdev_ext_dma_lease_get(b.st.priv,&b.batch)==-EAGAIN);
    release_fixture(&a,true);
    CHECK(!xdev_ext_dma_lease_get(b.st.priv,&b.batch));
    release_fixture(&b,true);
    defaults();
    init_fixture(&a,true);
    scope_start=0;
    CHECK(!bind_fixture(&a,true));
    init_fixture(&b,true);
    scope_start=4096;
    CHECK(!bind_fixture(&b,true));
    CHECK(!xdev_ext_dma_lease_get(a.st.priv,&a.batch));
    CHECK(!xdev_ext_dma_lease_get(b.st.priv,&b.batch));
    release_fixture(&a,true);
    release_fixture(&b,true);
    CHECK(!scope_module.refs);
    /* UNKNOWN completion retains every class-owned handle and both reference domains. */     defaults();
    init_fixture(&a,true);
    scope_kind=2;
    scope_start=1000;
    CHECK(!bind_fixture(&a,true));
    CHECK(!validate_fixture(&a));
    CHECK(!submit_fixture(&a));
    complete_fixture(&a,true,-EIO,true,64);
    a.st.cls->batch_release(&a.st,&a.batch,true);
    cs=a.st.priv;
    CHECK(STATE(cs)->host&&cs->region.priv&&cs->lease_group&&cs->scope==scope_object&&native_module.refs==1&&scope_module.refs==1);
    CHECK(unbind_fixture(&a,true)==-EBUSY&&cs->lease_group->state.quarantined);
    /* Test-only final disposal after retained-state observation; no quiescence is inferred. */     atomic_set(&STATE(cs)->ambiguous,0);
    cs->lease_group->state.quarantined=false;
    release_fixture(&a,true);
    CHECK(!scope_module.refs);
    /* Re-register the same pinned provider with a scope sidecar: old legacy identity stays conservative. */  xdev_ext_dma_provider_unregister(&dma_ops[0]);
    CHECK(!xdev_ext_dma_provider_register(&dma_ops[0]));
    defaults();
    init_fixture(&a,true);
    CHECK(!bind_fixture(&a,true));
    xdev_ext_dma_provider_unregister(&dma_ops[0]);
    CHECK(!xdev_ext_dma_provider_register_scoped(&dma_ops[0],&scope_ops));
    init_fixture(&b,true);
    scope_start=100000;
    CHECK(!bind_fixture(&b,true));
    CHECK(!xdev_ext_dma_lease_get(a.st.priv,&a.batch));
    CHECK(xdev_ext_dma_lease_get(b.st.priv,&b.batch)==-EAGAIN);
    release_fixture(&a,true);
    CHECK(!xdev_ext_dma_lease_get(b.st.priv,&b.batch));
    release_fixture(&b,true);
    CHECK(!scope_module.refs);
    xdev_ext_dma_scope_owner_put(scope_object);
    CHECK(scope_releases==1);
    scope_object=NULL;
    xdev_ext_dma_provider_unregister(&dma_ops[0]);
    CHECK(!xdev_ext_dma_provider_register(&dma_ops[0]));
    puts("PASS scope error refs/canonical alias/disjoint/UNKNOWN/cleanup same-batch");
}
static void ce_v2_bind_and_identity(void) {
    struct fixture a,b;defaults();init_fixture(&a,false);
    allocation_fail_after=2;
    CHECK(bind_fixture(&a,false)==-ENOMEM&&a.st.priv&&native_module.refs==1);
    struct xdev_ext_ce_stage *cs=a.st.priv;
    CHECK(cs->ops==&ce_ops[0]&&!cs->lease_group&&!STATE(cs)->host&&!cs->region.priv&&!trace[0]);
    CHECK(!unbind_fixture(&a,false)&&!native_module.refs);
    printf("CEV2 D6.1 lease allocation refusal precedes native hooks; rollback balances pin\n");
    for(int failure=0;failure<2;failure++) {
        defaults();init_fixture(&a,false);region_zero_output=true;ce_zero_length=failure;
        bind_region_errno=failure?-ENXIO:0;
        CHECK(bind_fixture(&a,false)==(failure?-ENXIO:0));
        cs=a.st.priv;CHECK(cs->ops==&ce_ops[0]&&cs->region.ops==cs->ops&&cs->window_start==4096&&cs->window_len==512);
        CHECK(cs->lease_group&&cs->cleanup_held==(bool)failure);
        if(!failure){cs->region.ops=&ce_ops[6];CHECK(!validate_fixture(&a));CHECK(!submit_fixture(&a));complete_fixture(&a,false,0,true,128);a.st.cls->batch_release(&a.st,&a.batch,false);}
        CHECK(!unbind_fixture(&a,false)&&!native_module.refs);
    }
    defaults();init_fixture(&a,false);ce_short_region=true;bind_region_errno=-ENXIO;
    CHECK(bind_fixture(&a,false)==-ENXIO&&((struct xdev_ext_ce_stage*)a.st.priv)->region.len==128);
    init_fixture(&b,false);ce_short_region=false;bind_region_errno=0;bind_u.arg0=4500;ce_expected_own=-EAGAIN;
    CHECK(!bind_fixture(&b,false));CHECK(xdev_ext_ce_lease_get(b.st.priv,&b.batch)==-EAGAIN);
    bind_u.arg0=4096;ce_expected_own=-EBUSY;CHECK(!unbind_fixture(&a,false));bind_u.arg0=4500;CHECK(!unbind_fixture(&b,false));bind_u.arg0=4096;
    printf("CEV2 D6.2 rewritten region output preserves selected ops/requested interval/module identity\n");
    /* An already active foreign group must still honor an overlapping bind's transient hold. */
    defaults();init_fixture(&b,false);CHECK(!bind_fixture(&b,false));CHECK(!xdev_ext_ce_lease_get(b.st.priv,&b.batch));
    init_fixture(&a,false);conflict_stage=&b.st;conflict_batch=&b.batch;ce_check_exclusion=true;
    CHECK(!bind_fixture(&a,false));conflict_stage=NULL;ce_check_exclusion=false;
    CHECK(!xdev_ext_ce_lease_get(b.st.priv,&b.batch));
    release_fixture(&b,false);CHECK(!unbind_fixture(&a,false));
    printf("CEV2 D6.3 foreign same-batch admission during initial bind hold is EAGAIN\n");
}
static void ce_v2_cleanup_exclusion(void) {
    struct fixture a,b;defaults();init_fixture(&a,false);init_fixture(&b,false);
    CHECK(!bind_fixture(&a,false));CHECK(!bind_fixture(&b,false));
    CHECK(!xdev_ext_ce_lease_get(b.st.priv,&b.batch));
    conflict_stage=&b.st;conflict_batch=&b.batch;ce_check_exclusion=true;
    unbind_host_errno=-EAGAIN;clear_trace();
    CHECK(unbind_fixture(&a,false)==-EAGAIN);
    struct xdev_ext_ce_stage *cs=a.st.priv;
    CHECK(cs->cleanup_held&&cs->lease_group&&cs->lease_group->cleanup_holds==1&&STATE(cs)->host&&cs->region.priv&&native_module.refs==2);
    CHECK(xdev_ext_ce_lease_get(b.st.priv,&b.batch)==-EAGAIN);
    CHECK(xdev_ext_ce_lease_get(cs,&a.batch)==-EBUSY);
    int calls=native_calls;unsigned char oldcookie[64];memcpy(oldcookie,b.cookie.bytes,64);
    CHECK(!validate_fixture(&b));native_batch=&b.batch;
    CHECK(b.st.cls->submit(&b.st,&b.batch)==-EAGAIN&&native_calls==calls&&!memcmp(oldcookie,b.cookie.bytes,64));
    CHECK(STATE((struct xdev_ext_ce_stage*)b.st.priv)->staged==&b.batch);
    a.st.cls->mark_dead(&a.st);CHECK(cs->cleanup_held&&cs->lease_group->cleanup_holds==1);
    unbind_host_errno=0;unbind_region_errno=-EXDEV;clear_trace();
    CHECK(unbind_fixture(&a,false)==-EXDEV);expect_trace("host- region- ");
    CHECK(!STATE(cs)->host&&cs->region.priv&&cs->cleanup_held&&cs->lease_group);
    unbind_region_errno=0;clear_trace();CHECK(!unbind_fixture(&a,false));expect_trace("region- ");
    conflict_stage=NULL;ce_check_exclusion=false;CHECK(!xdev_ext_ce_lease_get(b.st.priv,&b.batch));release_fixture(&b,false);CHECK(!native_module.refs);
    printf("CEV2 D6.3/D6.4 cleanup holds exclude same-batch submit before arm; refusal/retry preserves handles and record\n");
    /* A disjoint requested interval and a different native backend remain independent. */
    CHECK(!xdev_ext_ce_backend_register(&ce_ops[1]));
    for(int different_ops=0;different_ops<2;different_ops++) {
        defaults();init_fixture(&a,false);init_fixture(&b,false);CHECK(!bind_fixture(&a,false));
        if(different_ops)b.file.f_op=&fops[1];else bind_u.arg0=8192;
        CHECK(!bind_fixture(&b,false));
        bind_u.arg0=4096;unbind_host_errno=-EAGAIN;CHECK(unbind_fixture(&a,false)==-EAGAIN);
        CHECK(!xdev_ext_ce_lease_get(b.st.priv,&b.batch));
        b.st.cls->batch_release(&b.st,&b.batch,false);
        unbind_host_errno=0;CHECK(!unbind_fixture(&a,false));
        if(!different_ops)bind_u.arg0=8192;
        CHECK(!unbind_fixture(&b,false));bind_u.arg0=4096;
    }
    xdev_ext_ce_backend_unregister(&ce_ops[1]);
    printf("CEV2 D6.3 disjoint requested intervals and distinct selected native ops stay independent\n");
}
/* Supplement derived from the old executable registry, separate from frozen330. */
static void null_unregister_supplement(void) {
    int before=warnings;runtime_consumer=0;
    xdev_ext_ce_backend_unregister(NULL);CHECK(warnings==before);
    puts("SUPP NULL CE empty warning_condition=0 pins=0");
    for(int i=0;i<4;i++)CHECK(!xdev_ext_ce_backend_register(&ce_ops[i]));
    before=warnings;xdev_ext_ce_backend_unregister(NULL);CHECK(warnings==before+1);
    for(int i=0;i<4;i++){struct file f={&fops[i]};CHECK(xdev_ext_ce_backend_get(&f)==&ce_ops[i]);module_put(&native_module);}
    puts("SUPP NULL CE full warning_condition=1 registered=4 pins=0");
    xdev_ext_ce_backend_unregister(&ce_ops[0]);before=warnings;
    xdev_ext_ce_backend_unregister(NULL);CHECK(warnings==before);
    CHECK(!xdev_ext_ce_backend_register(&ce_ops[4]));
    puts("SUPP NULL CE freed_slot warning_condition=0 reusable=1");
    for(int i=1;i<5;i++)xdev_ext_ce_backend_unregister(&ce_ops[i]);
    runtime_consumer=1;before=warnings;xdev_ext_dma_provider_unregister(NULL);CHECK(warnings==before+1);
    puts("SUPP NULL DMA empty warning_condition=1 pins=0");
    for(int i=0;i<5;i++)CHECK(!xdev_ext_dma_provider_register(&dma_ops[i]));
    before=warnings;xdev_ext_dma_provider_unregister(NULL);CHECK(warnings==before+1);
    for(int i=0;i<5;i++){struct file f={&fops[i]};const struct xdev_ext_dma_scope_ops *side=(void*)1;CHECK(xdev_ext_dma_provider_get(&f,&side)==&dma_ops[i]&&!side);module_put(&native_module);}
    puts("SUPP NULL DMA populated warning_condition=1 registered=5 pins=0");
    for(int i=0;i<5;i++)xdev_ext_dma_provider_unregister(&dma_ops[i]);
    CHECK(!native_module.refs);
}
int main(void){
    printf("ABI CE cookie=%zu batch=%zu desc=%zu info=%zu cqe=%zu ops=%zu; DMA cookie=%zu batch=%zu desc=%zu info=%zu cqe=%zu ops=%zu\n",xdev_ext_ce_class.batch_cookie_size+0UL,xdev_ext_ce_class.batch_priv_size+0UL,xdev_ext_ce_class.desc_size+0UL,xdev_ext_ce_class.info_size+0UL,xdev_ext_ce_class.cqe_size+0UL,sizeof(struct xdev_ext_ce_backend_ops),xdev_ext_dma_class.batch_cookie_size+0UL,xdev_ext_dma_class.batch_priv_size+0UL,xdev_ext_dma_class.desc_size+0UL,xdev_ext_dma_class.info_size+0UL,xdev_ext_dma_class.cqe_size+0UL,sizeof(struct xdev_ext_dma_provider_ops));
    setup_ops();
    registry();
    CHECK(!xdev_ext_ce_backend_register(&ce_ops[0]));
    CHECK(!xdev_ext_dma_provider_register(&dma_ops[0]));
    binds();
    bind_error_order();
    preparation();
    submit_paths();
    transfer_transaction();
    lease_refusal();
    completions();
    stale_reuse();
    owner_phases();
    poll_case();
    cleanup();
    namespace_domains();
    scoped_lifetimes();
    puts("V2-ADDITIONAL-BEGIN");
    ce_v2_bind_and_identity();
    ce_v2_cleanup_exclusion();
    xdev_ext_ce_backend_unregister(&ce_ops[0]);
    xdev_ext_dma_provider_unregister(&dma_ops[0]);
    null_unregister_supplement();
    CHECK(!native_module.refs&&!scope_module.refs&&!lock_depth&&allocations==frees+failed_allocations);
    common_operations_observed();
    printf("PASS actual CE/DMA runtime contract; %d assertions; allocations=%d frees=%d\n",assertions,allocations,frees);
    return 0;
}

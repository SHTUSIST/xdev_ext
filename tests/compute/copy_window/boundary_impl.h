/* OS/native boundaries for exercising real bind admission and transfer consumers.
 * Shared-runtime fixtures execute actual lease helpers; tracing records their
 * call boundary without replacing an admission or cleanup decision. */
static int events[16], nevents;
static u32 native_alignment=1, native_directions=XDEV_EXT_WINDOW_COPY_DIRS;
static int region_error, host_error;
static bool native_clear_polled;
static void event(int n) { assert(nevents<16); events[nevents++]=n; }
static int ce_region(struct file *f,u64 off,u64 len,struct xdev_ext_ce_region *r) { event(1); r->len=len; r->seg_size=0; r->max_entry_len=4096; return region_error; }
static int dma_region(struct file *f,u64 off,u64 len,struct xdev_ext_dma_region *r) { event(1); r->len=len; r->segment_size=0; r->max_entry_len=4096; r->alignment=native_alignment; r->directions=native_directions; if(native_clear_polled)r->polled=false; return region_error; }
static int ce_host(struct xdev_ext_ce_region *r,struct page **p,u32 n,void **out) { event(2); *out=(void *)1; return host_error; }
static int dma_host(struct xdev_ext_dma_region *r,struct page **p,u32 n,void **out) { event(2); *out=(void *)1; return host_error; }
#ifdef HAVE_RUNTIME
static int native_unbind_host(void *host) { (void)host; return 0; }
static int ce_unbind_region(struct xdev_ext_ce_region *r) { r->priv=NULL; return 0; }
static int dma_unbind_region(struct xdev_ext_dma_region *r) { r->priv=NULL; return 0; }
/* Synchronous native boundary: observes adaptation, retains no command/cookie. */
static int ce_submit(struct xdev_ext_ce_region *r,void *host,u32 direction,const struct xdev_ext_ce_xfer *x,u32 n,struct xdev_ext_ce_cookie *cookie,u64 ticket) {
 (void)r;(void)host;(void)direction;(void)x;(void)n;(void)cookie;(void)ticket; return 0;
}
static int dma_submit(struct xdev_ext_dma_region *r,void *host,u32 direction,const struct xdev_ext_dma_xfer *x,u32 n,struct xdev_ext_dma_cookie *cookie,u64 ticket) {
 (void)r;(void)host;(void)direction;(void)x;(void)n;(void)cookie;(void)ticket; return 0;
}
static const struct xdev_ext_ce_backend_ops ce_ops={.bind_region=ce_region,.bind_host=ce_host,.unbind_region=ce_unbind_region,.unbind_host=native_unbind_host,.submit=ce_submit};
static const struct xdev_ext_dma_provider_ops dma_ops={.bind_region=dma_region,.bind_host=dma_host,.unbind_region=dma_unbind_region,.unbind_host=native_unbind_host,.submit=dma_submit};
#else
static const struct xdev_ext_ce_backend_ops ce_ops={.bind_region=ce_region,.bind_host=ce_host};
static const struct xdev_ext_dma_provider_ops dma_ops={.bind_region=dma_region,.bind_host=dma_host};
#endif
static const struct xdev_ext_ce_backend_ops *xdev_ext_ce_backend_get(struct file *f) { event(0); return &ce_ops; }
static const struct xdev_ext_dma_provider_ops *xdev_ext_dma_provider_get(struct file *f,const struct xdev_ext_dma_scope_ops **s) { event(0); *s=NULL; return &dma_ops; }
#ifdef HAVE_RUNTIME
static int traced_ce_lease_bind(struct xdev_ext_mech_stage *s,struct xdev_ext_ce_stage *c,u64 off,u64 len) { event(3); return xdev_ext_ce_lease_bind(s,c,off,len); }
#ifdef HAVE_COMMON_LEASE
static int traced_common_bind(struct xdev_ext_comp_copy_lease_domain *d,struct xdev_ext_comp_copy_lease_region *r,struct xdev_ext_mech_session *s,u32 depth,const void *key,bool held) { if(d==&xdev_ext_dma_lease_domain)event(3);return xdev_ext_comp_copy_lease_bind(d,r,s,depth,key,held); }
static void traced_common_hold(struct xdev_ext_comp_copy_lease_region *r,bool hold) { if(r->domain==&xdev_ext_ce_lease_domain&&!hold)event(5);xdev_ext_comp_copy_lease_hold(r,hold); }
#define xdev_ext_comp_copy_lease_bind(...) traced_common_bind(__VA_ARGS__)
#define xdev_ext_comp_copy_lease_hold(...) traced_common_hold(__VA_ARGS__)
#else
static void traced_ce_lease_ready(struct xdev_ext_ce_stage *c) { event(5); xdev_ext_ce_lease_bind_ready(c); }
#endif
#ifndef HAVE_COMMON_LEASE
static int traced_dma_lease_bind(struct xdev_ext_mech_stage *s,struct xdev_ext_dma_stage *c) { event(3); return xdev_ext_dma_lease_bind(s,c); }
#endif
static int traced_dma_stage_scope(struct xdev_ext_dma_stage *c,const struct xdev_ext_dma_scope_ops *s,struct file *f,u64 off,u64 len) { event(4); return xdev_ext_dma_stage_scope(c,s,f,off,len); }
#define xdev_ext_ce_lease_bind(...) traced_ce_lease_bind(__VA_ARGS__)
#define xdev_ext_ce_lease_bind_ready(...) traced_ce_lease_ready(__VA_ARGS__)
#define xdev_ext_dma_lease_bind(...) traced_dma_lease_bind(__VA_ARGS__)
#define xdev_ext_dma_stage_scope(...) traced_dma_stage_scope(__VA_ARGS__)
#else
static int xdev_ext_ce_lease_bind(struct xdev_ext_mech_stage *s,struct xdev_ext_ce_stage *c,u64 off,u64 len) { event(3); return 0; }
static void xdev_ext_ce_lease_bind_ready(struct xdev_ext_ce_stage *c) { event(5); }
static int xdev_ext_dma_lease_bind(struct xdev_ext_mech_stage *s,struct xdev_ext_dma_stage *c) { event(3); return 0; }
static int xdev_ext_dma_stage_scope(struct xdev_ext_dma_stage *c,const struct xdev_ext_dma_scope_ops *s,struct file *f,u64 off,u64 len) { event(4); return 0; }
#endif
#ifdef HAVE_TYPED
/* Trace only the immutable interface. No translation or policy is mocked. */
static struct {
 unsigned prepare_calls,validate_calls,transfer_calls;
 struct xdev_ext_comp_copy_window *prepared;
 const struct xdev_ext_comp_copy_window *validated_window;
 struct xdev_ext_comp_copy_plan *admitted;
 const struct xdev_ext_comp_copy_plan *consumed;
} trace;
static int traced_prepare(struct xdev_ext_comp_copy_window *out,int kind,const struct xdev_ext_window_copy_geom *g,u32 dir,u32 depth,u32 bytes) {
 trace.prepare_calls++; trace.prepared=out;
 return xdev_ext_comp_copy_prepare(out,kind,g,dir,depth,bytes);
}
static int traced_validate(const struct xdev_ext_comp_copy_window *w,const struct xdev_ext_mech_frame_info *f,const u32 *ix,u32 nr,const void *d,u32 n,u32 max,u32 mask,u32 slot,u64 id,struct xdev_ext_comp_copy_plan *out) {
 trace.validate_calls++; trace.validated_window=w; trace.admitted=out;
 return xdev_ext_comp_copy_validate(w,f,ix,nr,d,n,max,mask,slot,id,out);
}
static int traced_transfer(const struct xdev_ext_comp_copy_plan *p,u64 id,u32 slot,void *batch,xdev_ext_comp_claim_fn fn,struct xdev_ext_comp_copy_transfer *out) {
 trace.transfer_calls++; trace.consumed=p;
 return xdev_ext_comp_copy_transfer(p,id,slot,batch,fn,out);
}
#define xdev_ext_comp_copy_prepare(...) traced_prepare(__VA_ARGS__)
#define xdev_ext_comp_copy_validate(...) traced_validate(__VA_ARGS__)
#define xdev_ext_comp_copy_transfer(...) traced_transfer(__VA_ARGS__)
#endif

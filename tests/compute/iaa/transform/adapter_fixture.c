/* SPDX-License-Identifier: GPL-2.0 */
/* L11: adapter result reaches native lifecycle handoff before worker custody transfer. */
/* Boundary structs/helpers and actual core bodies are inserted unchanged. */
/* LEASE_BOUNDARY */

#define XDEV_EXT_IAA_SG_MAX 128
#define CRYPTO_TFM_REQ_MAY_BACKLOG 0x400U
struct scatterlist {struct page *page;u32 offset,length;bool end;};
struct crypto_acomp {int unused;};
struct acomp_req {
 struct scatterlist *src,*dst;
 u32 slen,dlen,flags;
 void (*callback)(void *,int);
 void *opaque;
};
/* CREATE-time boundary: allocation shims count, never decide admission. */
#define GFP_KERNEL 0
#define U32_MAX 0xffffffffU
#define CRYPTO_ACOMP_DST_MAX 131072U
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
static struct crypto_acomp fixture_tfm;
static char alloc_name[64];
static int tfm_allocs,tfm_frees,req_allocs,req_frees;
static struct crypto_acomp *crypto_alloc_acomp(const char *name,u32 type,u32 mask) {
 (void)type;(void)mask;snprintf(alloc_name,sizeof(alloc_name),"%s",name);tfm_allocs++;return &fixture_tfm;
}
static void crypto_free_acomp(struct crypto_acomp *t) {(void)t;tfm_frees++;}
static struct acomp_req *acomp_request_alloc(struct crypto_acomp *t,int gfp) {(void)t;(void)gfp;req_allocs++;return calloc(1,sizeof(struct acomp_req));}
static void acomp_request_free(struct acomp_req *r) {if(r){req_frees++;free(r);}}
static void *kzalloc(size_t n,int gfp) {(void)gfp;return calloc(1,n);}
static void kfree(void *p) {free(p);}
static void *kvcalloc(size_t n,size_t size,int gfp) {(void)gfp;return calloc(n,size);}
static void kvfree(void *p) {free(p);}
/* Physical placement of each fixture page; adjacency is decided per test. */
static u64 phys_map[2*N];
static u64 page_to_phys(const struct page *p) {return phys_map[p->id];}
/* ADAPTER_STRUCTS */
/* Actual production accessors keep slot selection and frame identity honest. */
/* xdev_ext_mech_session_layout */
/* xdev_ext_mech_session_pool */
/* xdev_ext_mech_batch_slot */
/* xdev_ext_mech_batch_nr_frames */
/* xdev_ext_mech_batch_bytes */
/* xdev_ext_mech_batch_frame */
/* xdev_ext_mech_batch_ticket */
static void sg_init_table(struct scatterlist *sg,u32 n) {memset(sg,0,n*sizeof(*sg));}
static void sg_set_page(struct scatterlist *sg,struct page *p,u32 len,u32 off) {*sg=(struct scatterlist){.page=p,.offset=off,.length=len};}
static void sg_mark_end(struct scatterlist *sg) {sg->end=true;}
static u64 sg_phys(struct scatterlist *sg) {return page_to_phys(sg->page)+sg->offset;}
/* xdev_ext_mech_session_depth */
/* CryptoAPI boundary setters contain no scheduling/acceptance policy. */
static void acomp_request_set_params(struct acomp_req *r,struct scatterlist *src,struct scatterlist *dst,u32 slen,u32 dlen) {
 r->src=src;r->dst=dst;r->slen=slen;r->dlen=dlen;
}
static void acomp_request_set_callback(struct acomp_req *r,u32 flags,void (*cb)(void *,int),void *opaque) {
 r->flags=flags;r->callback=cb;r->opaque=opaque;
}
static int api_return,inline_status;
static u32 api_dlen,compress_calls,decompress_calls,inline_dlen,submitted_capacity;
static bool inline_complete;
static struct acomp_req *issued;
static int crypto_boundary(struct acomp_req *r) {
 issued=r;submitted_capacity=r->dlen;
 /* An actual terminal callback may run before the API submit returns. */
 if(inline_complete){r->dlen=inline_dlen;r->callback(r->opaque,inline_status);}
 r->dlen=api_dlen;
 return api_return;
}
static int crypto_acomp_compress(struct acomp_req *r) {compress_calls++;return crypto_boundary(r);}
static int crypto_acomp_decompress(struct acomp_req *r) {decompress_calls++;return crypto_boundary(r);}
/* xdev_ext_iaa_crypto_done */
/* xdev_ext_iaa_sg */
/* xdev_ext_iaa_output */
/* xdev_ext_iaa_hw_admit */
/* xdev_ext_iaa_bind */
/* xdev_ext_iaa_unbind */
/* xdev_ext_iaa_submit */
/* xdev_ext_iaa_mark_dead */

static const struct xdev_ext_mech_class_ops adapter_ops={.flags=XDEV_EXT_MECH_CLASS_F_TRANSFORM,.submit=xdev_ext_iaa_submit};
static void prepare(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,
                    struct xdev_ext_iaa_stage *stage,struct xdev_ext_iaa_request *storage,struct acomp_req *request) {
 setup(s);source(s,b,0);s->batches=b;
 s->layout=(struct xdev_ext_mech_layout){.frame_size=FS,.hdr_room=16,.seg_len=768,.group_bytes=700};
 s->st[0].cls=&adapter_ops;s->st[0].direction=XDEV_EXT_MECH_DIR_TO_DEVICE;s->st[0].priv=stage;
 /* Scheduling cases use the explicit software flag; hardware admission is separate. */
 s->st[0].flags=XDEV_EXT_IAA_F_SOFTWARE;
 for(u32 i=0;i<2*N;i++)phys_map[i]=(u64)i*4*FS;
 *request=(struct acomp_req){0};*storage=(struct xdev_ext_iaa_request){.req=request};
 *stage=(struct xdev_ext_iaa_stage){.requests=storage,.first=10,.nr=2,.capacity=1536,.depth=1};
 assert(!xdev_ext_mech_transform_reserve(&s->st[0],10,2));
 assert(!xdev_ext_mech_completion_cancel(&b->completion,b->ticket));
 s->pool.state[0]=XDEV_EXT_MECH_F_HELD;
 xdev_ext_mech_bstate_init(&b->bs,1);assert(!xdev_ext_mech_batch_step(&b->bs,XDEV_EXT_MECH_EV_READY,0));
 api_return=0;api_dlen=173;compress_calls=decompress_calls=0;inline_complete=false;issued=NULL;submitted_capacity=0;
}
static void emit(struct acomp_req *r,int status,u32 dlen) {r->dlen=dlen;r->callback(r->opaque,status);}
static void expect_pending(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,const char *why) {
 CHECK(!queues,why);
 CHECK(b->transform.active&&s->pool.state[0]==XDEV_EXT_MECH_F_INFLIGHT&&s->pool.state[10]==XDEV_EXT_MECH_F_INFLIGHT,"pending adapter request lost custody");
 CHECK(xdev_ext_mech_life_phase(&s->life[0])==XDEV_EXT_MECH_L_OUT_PENDING&&xdev_ext_mech_life_phase(&s->life[10])==XDEV_EXT_MECH_L_IO_PENDING,"pending adapter request retired lifecycle");
 CHECK(xdev_ext_mech_completion_consume(&b->completion,b->ticket,&b->status)==-ESTALE,"pending completion became consumable");
}
/* CREATE through the actual bind/unbind: admission, transform name and leases. */
static int bind_case(const char *mode) {
 struct xdev_ext_mech_session s;
 bool hardware=strncmp(mode,"bind_sw",7)!=0;
 bool admit=!strcmp(mode,"bind_hw_single")||!strcmp(mode,"bind_sw_multi");
 struct xdev_ext_mech_stage_uapi u={.class_id=XDEV_EXT_MECH_CLASS_IAA,.flags=hardware?0:XDEV_EXT_IAA_F_SOFTWARE,.arg0=10,.arg1=768};
 setup(&s);
 for(u32 i=0;i<2*N;i++)phys_map[i]=(u64)i*4*FS;
 s.layout=(struct xdev_ext_mech_layout){.frame_size=FS,.hdr_room=16,.seg_len=768,.group_bytes=700};
 s.depth=2;s.st[0].cls=&adapter_ops;s.st[0].flags=u.flags;s.st[0].priv=NULL;
 tfm_allocs=tfm_frees=req_allocs=req_frees=0;alloc_name[0]=0;
 if(!strcmp(mode,"bind_hw_multi_dst")||!strcmp(mode,"bind_sw_multi"))u.arg1=1536;
 if(!strcmp(mode,"bind_hw_multi_src"))s.layout.group_bytes=1400;
 if(!strcmp(mode,"bind_hw_split_window"))page_split=600;
 int ret=xdev_ext_iaa_bind(&s.st[0],&u);
 CHECK(!strcmp(alloc_name,hardware?"deflate-iaa":"deflate-generic"),"bind requested the wrong CryptoAPI driver");
 if(!admit) {
  CHECK(ret==-EOPNOTSUPP,"hardware CREATE admitted a window deflate-iaa maps to several DMA segments");
  CHECK(!s.st[0].priv&&tfm_allocs==tfm_frees&&req_allocs==req_frees,"refused CREATE leaked transform/request state");
  for(u32 i=0;i<N;i++)CHECK(s.pool.state[i]==XDEV_EXT_MECH_F_USER&&!s.transform_owner[i],"refused CREATE reserved output frames");
  return !!failures;
 }
 CHECK(!ret&&s.st[0].priv,"single-segment CREATE was refused");
 if(ret)return 1;
 struct xdev_ext_iaa_stage *cs=s.st[0].priv;
 u32 frames=cs->depth*cs->nr;
 CHECK(cs->depth==2&&cs->nr==(u.arg1>768?2U:1U)&&req_allocs==2,"bind sized requests/output frames wrongly");
 for(u32 i=0;i<frames;i++)CHECK(s.pool.state[10+i]==XDEV_EXT_MECH_F_HELD&&s.transform_owner[10+i]==1,"bind did not reserve each output frame");
 xdev_ext_iaa_unbind(&s.st[0]);
 CHECK(!s.st[0].priv&&tfm_allocs==1&&tfm_frees==1&&req_frees==2,"unbind leaked transform/request state");
 for(u32 i=0;i<frames;i++)CHECK(s.pool.state[10+i]==XDEV_EXT_MECH_F_USER&&!s.transform_owner[10+i],"unbind kept output reservation");
 return !!failures;
}
int main(int argc,char **argv) {
 assert(argc==2);const char *mode=argv[1];
 struct xdev_ext_mech_session s;struct xdev_ext_mech_batch b;
 struct xdev_ext_iaa_stage stage;struct xdev_ext_iaa_request storage;struct acomp_req request;
 if(!strncmp(mode,"bind_",5))return bind_case(mode);
 prepare(&s,&b,&stage,&storage,&request);
 if(!strcmp(mode,"eagain")) {
  /* A synchronous -EAGAIN returned before provider acceptance is backpressure. */
  api_return=-EAGAIN;
  CHECK(xdev_ext_mech_submit(&s,&s.st[0],&b)==-EAGAIN,"pre-acceptance -EAGAIN was not returned as backpressure");
  CHECK(compress_calls==1&&!queues&&!s.submitted[0]&&!s.last_err,"pre-acceptance -EAGAIN completed or counted the batch");
  CHECK(!b.transform.active&&s.pool.state[10]==XDEV_EXT_MECH_F_HELD&&xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_FREE,"backpressure kept the destination lease");
  CHECK(s.pool.state[0]==XDEV_EXT_MECH_F_HELD&&b.bs.state==XDEV_EXT_MECH_B_READY,"backpressure did not return the source batch to READY");
  if(failures)return 1;
  api_return=0;
  CHECK(!xdev_ext_mech_submit(&s,&s.st[0],&b),"retry after backpressure was refused");
  CHECK(compress_calls==2&&queues==1&&s.submitted[0]==1,"retry was not one new native operation");
  CHECK(!xdev_ext_mech_completion_consume(&b.completion,b.ticket,&b.status)&&!b.status&&b.transform.produced==173,"retry lost its terminal result");
  source_landed(&b,false);
  CHECK(!xdev_ext_mech_transform_landed(&s,&b,false)&&b.f[0].index==10&&b.bytes==173,"retry output was not published");
  return !!failures;
 }
 if(!strcmp(mode,"hw_multi_dst")||!strcmp(mode,"hw_multi_src")) {
  /* Hardware batches shaped outside CREATE admission never enter CryptoAPI. */
  s.st[0].flags=0;
  if(!strcmp(mode,"hw_multi_src")) {
   stage.nr=1;stage.capacity=768;
   b.f[1]=frame(1,100);b.nr_frames=2;b.present=3;b.bytes=800;s.pool.state[1]=XDEV_EXT_MECH_F_HELD;
  }
  CHECK(xdev_ext_mech_submit(&s,&s.st[0],&b)==-EOPNOTSUPP,"hardware stage submitted a multi-segment scatterlist");
  CHECK(!compress_calls&&!decompress_calls&&!queues&&!s.submitted[0]&&!b.transform.active,"multi-segment refusal entered CryptoAPI or kept a lease");
  CHECK(s.pool.state[0]==XDEV_EXT_MECH_F_HELD&&s.pool.state[10]==XDEV_EXT_MECH_F_HELD&&xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_FREE,"multi-segment refusal changed custody");
  return !!failures;
 }
 if(!strcmp(mode,"hw_single")) {
  s.st[0].flags=0;stage.nr=1;stage.capacity=768;
  CHECK(!xdev_ext_mech_submit(&s,&s.st[0],&b),"admitted single-segment hardware batch was refused");
  CHECK(compress_calls==1&&request.src[0].length==700&&request.src[0].end&&request.dst[0].page==&pages[10]&&request.dst[0].offset==16&&request.dst[0].length==768&&request.dst[0].end,"hardware batch did not submit one source and one destination segment");
  return !!failures;
 }
 if(!strcmp(mode,"contiguous")) {
  /* Physically adjacent output frames form one truthful scatterlist entry. */
  s.layout.hdr_room=0;s.layout.seg_len=FS;stage.capacity=2*FS;phys_map[11]=phys_map[10]+FS;
  CHECK(!xdev_ext_mech_submit(&s,&s.st[0],&b),"contiguous software batch was refused");
  CHECK(request.dst[0].page==&pages[10]&&request.dst[0].offset==0&&request.dst[0].length==2*FS&&request.dst[0].end,"physically contiguous destination was split into several entries");
  CHECK(request.src[0].length==700&&request.src[0].end,"source entry changed");
  return !!failures;
 }
 bool async=!strcmp(mode,"async")||!strcmp(mode,"backlog")||!strcmp(mode,"async_error")||!strcmp(mode,"late_stop")||!strcmp(mode,"late_stop_error");
 bool failure=!strcmp(mode,"sync_error")||!strcmp(mode,"async_error")||!strcmp(mode,"zero")||!strcmp(mode,"overcap")||!strcmp(mode,"positive_error")||!strcmp(mode,"invalid_errno")||!strcmp(mode,"late_stop_error");
 int expected_status=0;
 if(!strcmp(mode,"decompress"))s.st[0].direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;
 if(async)api_return=!strcmp(mode,"backlog")?-EBUSY:-EINPROGRESS;
 if(!strcmp(mode,"sync_error"))expected_status=api_return=-EIO;
 if(!strcmp(mode,"async_error"))expected_status=-ENOSPC;
 if(!strcmp(mode,"late_stop_error"))expected_status=-EIO;
 if(!strcmp(mode,"positive_error")){api_return=7;expected_status=-EIO;}
 if(!strcmp(mode,"invalid_errno")){api_return=-4096;expected_status=-EIO;}
 if(!strcmp(mode,"zero")){api_dlen=0;expected_status=-EOVERFLOW;}
 if(!strcmp(mode,"overcap")){api_dlen=1537;expected_status=-EOVERFLOW;}
 if(!strcmp(mode,"inline_callback")){inline_complete=true;inline_status=0;inline_dlen=173;api_return=-EIO;api_dlen=999;}
 if(!strcmp(mode,"dead")) {
  xdev_ext_iaa_mark_dead(&s.st[0]);
  CHECK(xdev_ext_mech_submit(&s,&s.st[0],&b)==-ENODEV,"dead stage submitted request");
  CHECK(!compress_calls&&!decompress_calls&&!queues&&!b.transform.active&&!s.submitted[0],"dead stage entered CryptoAPI or accepted a lease");
  CHECK(s.pool.state[0]==XDEV_EXT_MECH_F_HELD&&s.pool.state[10]==XDEV_EXT_MECH_F_HELD,"dead stage changed custody");return !!failures;
 }
 CHECK(!xdev_ext_mech_submit(&s,&s.st[0],&b),"entered CryptoAPI was treated as preaccept retry");
 CHECK(s.submitted[0]==1&&compress_calls+decompress_calls==1,"native operation was not submitted exactly once");
 CHECK(compress_calls==(!strcmp(mode,"decompress")?0U:1U)&&decompress_calls==(!strcmp(mode,"decompress")?1U:0U),"adapter dispatched wrong compression direction");
 CHECK(issued==&request&&request.flags==CRYPTO_TFM_REQ_MAY_BACKLOG,"adapter omitted MAY_BACKLOG or used wrong request");
 CHECK(submitted_capacity==1536&&request.slen==700&&request.src==storage.src&&request.dst==storage.dst,"CryptoAPI parameters did not use real source/destination SGs");
 CHECK(request.src[0].page==&pages[0]&&request.src[0].length==700&&request.src[0].end,"source scatterlist lost source identity/length/end");
 CHECK(request.dst[0].page==&pages[10]&&request.dst[0].offset==16&&request.dst[0].length==768&&!request.dst[0].end&&request.dst[1].page==&pages[11]&&request.dst[1].length==768&&request.dst[1].end,"destination scatterlist did not cover independent capacity");
 if(async) {
  expect_pending(&s,&b,"pending return was incorrectly completed");
  if(!strcmp(mode,"backlog")) {
   emit(&request,-EINPROGRESS,1536);
   expect_pending(&s,&b,"backlog promotion became a terminal completion");
   CHECK(!b.transform.produced&&!s.last_err,"promotion published output/error metadata");
   /* Avoid assertions below hiding a mutation's explicit failure message. */
   if(failures)return 1;
  }
  if(!strcmp(mode,"late_stop")||!strcmp(mode,"late_stop_error")) {
   s.admits=false;xdev_ext_iaa_mark_dead(&s.st[0]);
   expect_pending(&s,&b,"stage STOP released request before late terminal");
   CHECK(!released[0]&&s.transform_owner[10]==1,"stage STOP returned pending source/destination");
  }
  emit(&request,expected_status,expected_status?911:173);
 }
 CHECK(queues==1,"request produced zero or multiple terminal deliveries");
 CHECK(compress_calls+decompress_calls==1&&s.submitted[0]==1,"terminal result retried accepted CryptoAPI operation");
 CHECK(!xdev_ext_mech_completion_consume(&b.completion,b.ticket,&b.status),"terminal callback did not reach real core completion");
 CHECK(b.status==expected_status,"adapter changed synchronous/asynchronous terminal errno");
 CHECK(b.transform.produced==(failure?0U:173U),"adapter did not propagate actual terminal produced dlen");
 CHECK(s.last_err==expected_status,"real core native-error latch lost terminal result");
 source_landed(&b,false);
 CHECK(!xdev_ext_mech_transform_landed(&s,&b,false),"definitive adapter result was quarantined");
 if(failure) {
  CHECK(b.f[0].index==0&&b.bytes==700&&xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_FREE,"failed native output advanced or published batch");
 } else {
  CHECK(b.f[0].index==10&&b.bytes==173&&s.life[10].valid_len==173&&xdev_ext_mech_life_phase(&s.life[10])==XDEV_EXT_MECH_L_READY,"terminal dlen did not become downstream published payload");
 }
 if(!strcmp(mode,"sequential_reuse")) {
  /* Legal request reuse happens after its one terminal result was consumed.
   * No previous-operation callback is emitted after this point. */
  u64 old_ticket=b.ticket;
  assert(!xdev_ext_mech_life_release(&s.life[10],xdev_ext_mech_life_gen(&s.life[10])));
  b.f[0]=frame(1,700);b.nr_frames=1;b.present=1;b.bytes=700;
  s.pool.state[1]=XDEV_EXT_MECH_F_HELD;u64 token;
  assert(!xdev_ext_mech_life_claim(&s.life[1],0,&token));assert(!xdev_ext_mech_life_publish(&s.life[1],token,1,700));assert(!xdev_ext_mech_life_acquire(&s.life[1],0,0,&token));b.life_token[0]=token;b.life_active=1;
  xdev_ext_mech_bstate_init(&b.bs,1);assert(!xdev_ext_mech_batch_step(&b.bs,XDEV_EXT_MECH_EV_READY,0));
  api_dlen=251;
  CHECK(!xdev_ext_mech_submit(&s,&s.st[0],&b),"legal sequential request reuse refused");
  CHECK(b.ticket>old_ticket&&storage.ticket==b.ticket&&queues==2&&compress_calls==2,"reused operation retained old ticket or was not submitted once");
  CHECK(!xdev_ext_mech_completion_consume(&b.completion,b.ticket,&b.status)&&!b.status&&b.transform.produced==251,"reused request lost its independent terminal dlen");
 }
 return !!failures;
}

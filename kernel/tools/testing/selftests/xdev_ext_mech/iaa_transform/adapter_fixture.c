/* SPDX-License-Identifier: GPL-2.0 */
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
/* xdev_ext_iaa_submit */
/* xdev_ext_iaa_mark_dead */

static const struct xdev_ext_mech_class_ops adapter_ops={.flags=XDEV_EXT_MECH_CLASS_F_TRANSFORM,.submit=xdev_ext_iaa_submit};
static void prepare(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,
                    struct xdev_ext_iaa_stage *stage,struct xdev_ext_iaa_request *storage,struct acomp_req *request) {
 setup(s);source(s,b,0);s->batches=b;
 s->layout=(struct xdev_ext_mech_layout){.frame_size=FS,.hdr_room=16,.seg_len=768,.group_bytes=700};
 s->st[0].cls=&adapter_ops;s->st[0].direction=XDEV_EXT_MECH_DIR_TO_DEVICE;s->st[0].priv=stage;
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
int main(int argc,char **argv) {
 assert(argc==2);const char *mode=argv[1];
 struct xdev_ext_mech_session s;struct xdev_ext_mech_batch b;
 struct xdev_ext_iaa_stage stage;struct xdev_ext_iaa_request storage;struct acomp_req request;
 prepare(&s,&b,&stage,&storage,&request);
 bool async=!strcmp(mode,"async")||!strcmp(mode,"backlog")||!strcmp(mode,"async_error")||!strcmp(mode,"late_stop")||!strcmp(mode,"late_stop_error");
 bool failure=!strcmp(mode,"eagain")||!strcmp(mode,"sync_error")||!strcmp(mode,"async_error")||!strcmp(mode,"zero")||!strcmp(mode,"overcap")||!strcmp(mode,"positive_error")||!strcmp(mode,"invalid_errno")||!strcmp(mode,"late_stop_error");
 int expected_status=0;
 if(!strcmp(mode,"decompress"))s.st[0].direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;
 if(async)api_return=!strcmp(mode,"backlog")?-EBUSY:-EINPROGRESS;
 if(!strcmp(mode,"eagain"))expected_status=api_return=-EAGAIN;
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
  assert(!xdev_ext_mech_life_release(&s.life[10],xdev_ext_mech_life_token(&s.life[10])));
  b.f[0]=frame(1,700);b.nr_frames=1;b.present=1;b.bytes=700;
  s.pool.state[1]=XDEV_EXT_MECH_F_HELD;u64 token;
  assert(!xdev_ext_mech_life_begin_produce(&s.life[1],false,&token));assert(!xdev_ext_mech_life_publish(&s.life[1],token,700));assert(!xdev_ext_mech_life_begin_consume(&s.life[1],&token));
  xdev_ext_mech_bstate_init(&b.bs,1);assert(!xdev_ext_mech_batch_step(&b.bs,XDEV_EXT_MECH_EV_READY,0));
  api_dlen=251;
  CHECK(!xdev_ext_mech_submit(&s,&s.st[0],&b),"legal sequential request reuse refused");
  CHECK(b.ticket>old_ticket&&storage.ticket==b.ticket&&queues==2&&compress_calls==2,"reused operation retained old ticket or was not submitted once");
  CHECK(!xdev_ext_mech_completion_consume(&b.completion,b.ticket,&b.status)&&!b.status&&b.transform.produced==251,"reused request lost its independent terminal dlen");
 }
 return !!failures;
}

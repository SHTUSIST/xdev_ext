/* SPDX-License-Identifier: GPL-2.0 */
/* Linux boundary only. USER state decisions come from the complete real TU. */
#include <sys/ioctl.h>
#include <fcntl.h>
#include "io_uring/xdev_ext_mech_poll.h"
#ifndef XDEV_EXT_USER_F_STRICT_ASYNC
#define XDEV_EXT_USER_F_STRICT_ASYNC (1U << 1)
#endif
#ifndef XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL
#define XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL (1U << 0)
#endif
#ifndef XDEV_EXT_USER_K_DRAINING
#define XDEV_EXT_USER_K_DRAINING (1U << 2)
#endif
#ifndef XDEV_EXT_USER_IOC_CTL_ATTACH
#define XDEV_EXT_USER_IOC_CTL_ATTACH _IO('X', 0xe9)
#define XDEV_EXT_USER_IOC_CTL_DETACH _IO('X', 0xea)
#endif
#define __user
#define __init
#define late_initcall_sync(fn)
#define GFP_KERNEL_ACCOUNT 0
#define PAGE_SIZE 4096
#define struct_size(p,m,n) (sizeof(*(p)) + sizeof((p)->m[0])*(n))
#define msecs_to_jiffies(n) (n)
#define spin_lock_init(p) (*(p)=0)
#define copy_from_user(d,s,n) (memcpy(d,s,n),0)
#define copy_to_user(d,s,n) (memcpy(d,s,n),0)
#define put_user(v,p) (*(p)=(v),0)
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define PTR_ERR(p) ((long)(p))
#define compat_ptr_ioctl NULL
#define XDEV_EXT_COMP_INPLACE 0
#define XDEV_EXT_FAMILY_COMPUTE 0
#define XDEV_EXT_CAP_NOT_WIRED 0
struct xdev_ext_comp_hooks { struct { int family; } hdr; unsigned kinds; int producer_visibility; };
struct kref { unsigned count; };
static void kref_init(struct kref *r) { r->count=1; }
static void kref_get(struct kref *r) { assert(r->count); r->count++; }
static int kref_put(struct kref *r,void (*release)(struct kref *)) { assert(r->count); if(!--r->count){release(r);return 1;}return 0; }
static unsigned region_frees;
static void *vmalloc_user(size_t n) { return calloc(1,n); }
static void vfree(void *p) { if(p)region_frees++;free(p); }
static int remap_vmalloc_range(struct vm_area_struct *v,void *p,int n) {(void)v;(void)p;(void)n;return 0;}
static struct file *files[64];
static int get_unused_fd_flags(int flags) {(void)flags;for(int i=3;i<64;i++)if(!files[i])return i;return -EMFILE;}
static void put_unused_fd(int fd) {(void)fd;}
static struct file *anon_inode_getfile(const char *name,const struct file_operations *ops,void *p,int flags) {
 (void)name;(void)flags;struct file*f=calloc(1,sizeof(*f));f->f_op=ops;f->private_data=p;f->refs=1;return f;
}
static void fd_install(int fd,struct file *f) {files[fd]=f;}
static struct file *fget(int fd) {if(fd<0||fd>=64||!files[fd])return NULL;files[fd]->refs++;return files[fd];}
static struct eventfd_ctx *eventfd_ctx_fdget(int fd) {(void)fd;return NULL;}
struct xdev_ext_user_stage;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops;
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *,int);
static int xdev_ext_mech_class_register(const struct xdev_ext_mech_class_ops *c) {(void)c;return 0;}
/* STRICT CASES */
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err) {
 (void)err;st->cls->mark_dead(st);
}
static struct file *owner;
static struct xdev_ext_user_obj *object;
static int bind_err;
static u32 bind_extra;
static s64 bind_delta;
static int real_setup(bool strict,bool peer,bool external,bool polling) {
 setup(2,2,0,false);
 /* Drop the fabricated stage and replace it through actual CREATE/bind. */
 free(us);free(region);session.st[1].priv=NULL;
 struct xdev_ext_mech_user_stage req={.size=sizeof(req),.entries=2,.eventfd=-1,
  .flags=external?XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL:0};
 int err=xdev_ext_mech_user_stage_create(&req);
 if(err){fprintf(stderr,"CREATE returned %d\n",err);return err;}
 owner=files[req.fd];object=owner->private_data;
 session.pool.vaddr=peer?NULL:(void*)0x10000;
 session.pool.kind=peer?XDEV_EXT_MECH_POOL_PEER:XDEV_EXT_MECH_POOL_IOU_UMEM;
 session.st[1].cls=&xdev_ext_user_class;
 session.plan[1].fd=req.fd;session.plan[1].arg0=TIMEOUT;
 session.plan[1].arg1=bind_delta;session.plan[1].flags=(strict?XDEV_EXT_USER_F_STRICT_ASYNC:0)|bind_extra;
 if(polling){
  struct xdev_ext_mech_stage_uapi clean;
  session.plan[1].flags|=XDEV_EXT_MECH_STAGE_F_POLL;
  err=xdev_ext_mech_poll_split(&session.plan[1],xdev_ext_user_class.poll,&clean,&session.st[1].poll);
  if(err){fprintf(stderr,"POLL split returned %d\n",err);return err;}
  session.plan[1]=clean;
 }
 session.st[1].flags=session.plan[1].flags;
 bind_err=xdev_ext_user_bind(&session.st[1],&session.plan[1]);
 if(bind_err){fprintf(stderr,"bind returned %d\n",bind_err);return bind_err;}
 us=session.st[1].priv;region=object->region;
 return 0;
}
static bool quarantined(struct xdev_ext_mech_batch*b) {
 for(u32 i=0;i<FRAMES;i++)if(custody[b->f[i].index]!=XDEV_EXT_MECH_F_SEQUESTERED)return false;
 return b->bs.state==XDEV_EXT_MECH_B_SEQUESTERED;
}
static int attach_cases(const char *mode) {
 struct xdev_ext_mech_user_stage req={.size=sizeof(req),.entries=2,.eventfd=-1,
   .flags=strcmp(mode,"attach-legacy")?XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL:0};
 REQUIRE(!xdev_ext_mech_user_stage_create(&req),"external control CREATE accepts bit0");
 owner=files[req.fd];object=owner->private_data;
 unsigned freed=region_frees;
 if(!strcmp(mode,"attach-legacy")){
  CHECK(xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_ATTACH,0)==-EOPNOTSUPP,"non-external attach rejected");return failures!=0;
 }
 if(!strcmp(mode,"attach-args")){
  CHECK(xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_ATTACH,1)==-EINVAL,"attach arg must be zero");
  CHECK(xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_DETACH,1)==-EINVAL,"detach arg must be zero");
  return failures!=0;
 }
 REQUIRE(!xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_ATTACH,0),"attach succeeds before bind");
 CHECK(object->ref.count==2,"attach holds an independent object ref");
 if(!strcmp(mode,"attach")){
  CHECK(xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_ATTACH,0)==-EALREADY,"duplicate attach rejected");
  CHECK(!xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_DETACH,0),"unbound detach succeeds");
  CHECK(xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_DETACH,0)==-ENOENT,"duplicate detach rejected");
  CHECK(object->ref.count==1,"detach drops exactly external ref");return failures!=0;
 }
 if(!strcmp(mode,"retain-owner-exit")){
  xdev_ext_user_release(NULL,owner);
  CHECK(region_frees==freed,"owner exit must not implicitly detach/free persistent control region");
  CHECK(object->ref.count==1,"external ref survives owner exit");return failures!=0;
 }
 /* Build only session boundaries; do not replace the real external object. */
 setup(2,2,0,false);free(us);free(region);session.st[1].priv=NULL;
 session.pool.vaddr=(void*)0x10000;session.plan[1].fd=req.fd;session.plan[1].arg1=0;
 session.plan[1].flags=!strcmp(mode,"attach-nonstrict")?0:XDEV_EXT_USER_F_STRICT_ASYNC;session.st[1].flags=session.plan[1].flags;session.st[1].cls=&xdev_ext_user_class;
 if(!strcmp(mode,"attach-nonstrict")){
  CHECK(xdev_ext_user_bind(&session.st[1],&session.plan[1])==-EOPNOTSUPP,"attached external control cannot bind nonstrict CPU USER");return failures!=0;
 }
 REQUIRE(!xdev_ext_user_bind(&session.st[1],&session.plan[1]),"attached object binds strict USER");
 us=session.st[1].priv;
 if(!strcmp(mode,"attach-owner-exit-pending")){
  struct xdev_ext_mech_batch*b=start(0,4092);REQUIRE(b&&us->nr_held==1,"attached pending external work");
  xdev_ext_user_release(NULL,owner);progress();drain();
  CHECK(quarantined(b),"owner loss isolates pending payload without claiming external work stopped");
  CHECK(region_frees==freed,"owner loss and payload isolation retain attached control region");return failures!=0;
 }
 if(!strcmp(mode,"attach-bound")){
  int attach_ret=xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_ATTACH,0);
  if(attach_ret!=-EBUSY)fprintf(stderr,"bound attach returned %d, expected %d\n",attach_ret,-EBUSY);
  CHECK(attach_ret==-EBUSY,"bound attach rejected");return failures!=0;
 }
 if(!strcmp(mode,"detach-bound")){
  CHECK(xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_DETACH,0)==-EBUSY,"bound detach rejected even nr_held zero");return failures!=0;
 }
 xdev_ext_mech_sess_stop(&session.ss);xdev_ext_user_unbind(&session.st[1]);
 CHECK(region_frees==freed,"unbind keeps attached region alive");
 if(!strcmp(mode,"detach-final")){
  CHECK(!xdev_ext_user_ioctl(owner,XDEV_EXT_USER_IOC_CTL_DETACH,0),"owner explicitly detaches after stop/unbind");
  xdev_ext_user_release(NULL,owner);
  CHECK(region_frees==freed+1,"explicit detach then last owner ref frees control region");
 }else{
  xdev_ext_user_release(NULL,owner);
  CHECK(region_frees==freed,"unbound object remains alive after owner loss without detach");
 }
 return failures!=0;
}
static int exercise(const char *mode) {
 if(strstr(mode,"attach")||strstr(mode,"detach")||strstr(mode,"retain"))return attach_cases(mode);
 if(!strncmp(mode,"peer-reject-",12)){
  bool strict=strcmp(mode,"peer-reject-nonstrict")!=0;
  if(!strcmp(mode,"peer-reject-varlen"))bind_extra=XDEV_EXT_USER_F_VARLEN;
  if(!strcmp(mode,"peer-reject-delta"))bind_delta=1;
  CHECK(real_setup(strict,true,false,false)==-EOPNOTSUPP,"PEER USER requires strict, fixed lengths and zero delta");return failures!=0;
 }
 bool legacy=!strcmp(mode,"legacy-stop")||!strcmp(mode,"external-nonstrict"),peer=!strcmp(mode,"strict-bind-peer");
 REQUIRE(!real_setup(!legacy,peer,false,!strcmp(mode,"poll")),"specified USER mode binds through production bind");
 if(!strncmp(mode,"strict-bind",11))return failures!=0;
 struct xdev_ext_mech_batch*b=start(0,4092);
 REQUIRE(b&&us->nr_held==1,"real producer completion publishes USER ready");
 struct xdev_ext_user_ready r=take();
 u64 gen=xdev_ext_mech_life_gen(&life[0]);
 CHECK(held_out_pending(b),"published USER ready retains INFLIGHT and OUT_PENDING");
 CHECK(!attempts[2]&&!ends,"downstream and batch end wait for final external completion");
 if(!strncmp(mode,"external-",9)){
#ifdef STRICT_HAS_EXTERNAL
  struct xdev_ext_mech_life saved_life=life[0];u64 ticket=us->held[0].ticket;
  struct xdev_ext_mech_completion saved=b->completion;
  int err=xdev_ext_mech_batch_external_complete(b,!strcmp(mode,"external-stale")?r.ticket+1:r.ticket,0,XDEV_EXT_MECH_EXTERNAL_QUIESCED);
  CHECK(err<0,"external completion rejects stale or nonstrict claim");
  CHECK(!memcmp(&saved,&b->completion,sizeof(saved))&&!memcmp(&saved_life,&life[0],sizeof(saved_life))&&us->held[0].ticket==ticket,"rejected external completion does not mutate claim/lifecycle/responsibility");
#else
  CHECK(false,"production external completion entry is required");
#endif
  return failures!=0;
 }
 if(legacy){
  xdev_ext_mech_sess_stop(&session.ss);progress();drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-ESHUTDOWN,"legacy CPU STOP cancels immediately");
  CHECK(custody[0]==XDEV_EXT_MECH_F_K_FREE,"legacy CPU cancelled custody is reusable");return failures!=0;
 }
 if(!strcmp(mode,"stop-late")||!strcmp(mode,"deadline-late")||strstr(mode,"noack")){
  bool deadline=!strncmp(mode,"deadline",8);
  if(deadline)jiffies+=TIMEOUT;else xdev_ext_mech_sess_stop(&session.ss);
  progress();drain();
  CHECK(us->nr_held==1&&us->held[0].b==b&&us->held[0].ticket==r.ticket,"drain keeps exact object/slot/ticket responsibility");
  CHECK(held_out_pending(b)&&xdev_ext_mech_life_gen(&life[0])==gen,"drain does not handoff or advance generation");
  CHECK(!ends&&!attempts[2],"STOP/deadline alone does not imply external completion");
  CHECK(us->hdr->kernel_flags&XDEV_EXT_USER_K_DRAINING,"drain publishes K_DRAINING");
  if(strstr(mode,"noack")){
   jiffies+=1000;progress();drain();
   CHECK(quarantined(b),"no matching completion after one second isolates every frame");
   CHECK(end_how==XDEV_EXT_MECH_END_SEQUESTER,"UNKNOWN retains batch authority");
   CHECK(end_err==-ETIMEDOUT,"unacknowledged grace expires with timeout");
   post(0,r.ticket,0);progress();drain();
   CHECK(quarantined(b),"grace-expired completion cannot revive isolated frames");
   CHECK(xdev_ext_mech_pool_frame_move(&session.pool,0,XDEV_EXT_MECH_F_K_FREE,XDEV_EXT_MECH_F_HELD)==-EBUSY,"isolated allocation cannot be claimed");
  }else{
   jiffies+=999;post(0,r.ticket,0);progress();drain();
   CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==(deadline?-ETIMEDOUT:-ESHUTDOWN),"late status0 safely ends failed batch with first drain error");
   CHECK(!attempts[2],"late acknowledgement never submits downstream");
  }
 }else if(!strcmp(mode,"negative")||!strcmp(mode,"positive")||!strcmp(mode,"dead")){
  if(!strcmp(mode,"dead"))xdev_ext_user_mark_dead(&session.st[1]);
  else post(0,r.ticket,!strcmp(mode,"negative")?-EIO:5);
  progress();drain();
  CHECK(quarantined(b)&&end_how==XDEV_EXT_MECH_END_SEQUESTER,"unknown external status or vanished owner isolates payload");
  CHECK(!attempts[2],"unknown completion cannot submit downstream");
  CHECK(end_err==(!strcmp(mode,"negative")?-EIO:!strcmp(mode,"positive")?-EPROTO:-EPIPE),"unknown completion preserves the specified error");
 }else if(!strcmp(mode,"badlen")){
  us->slots[0].f[1].out_len=4091;post(0,r.ticket,0);progress();drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-EPROTO,"status0 invalid length safely aborts");
  CHECK(!attempts[2]&&b->f[0].data_len==4092,"invalid lengths are not partially applied or forwarded");
  CHECK(custody[0]!=XDEV_EXT_MECH_F_SEQUESTERED,"status0 declares quiesced external use");
 }else if(!strcmp(mode,"overflow")||!strcmp(mode,"rewind")){
  if(!strcmp(mode,"overflow")){
   /* Oldest ring entry was overwritten; latest plausible ack must not free. */
   us->done[1]=(struct xdev_ext_user_done){.slot=0,.ticket=r.ticket,.status=0};us->hdr->done_prod=3;
  }else us->hdr->done_prod=UINT32_MAX;
  progress();drain();
  CHECK(held_out_pending(b)&&us->nr_held==1&&!attempts[2]&&!ends,"corrupt done window retains unmatched responsibility instead of skipping entries");
  CHECK(us->hdr->kernel_flags&XDEV_EXT_USER_K_DRAINING,"corrupt done window starts protocol drain");
  jiffies+=1000;progress();drain();CHECK(quarantined(b),"corrupt ring without matched ack isolates after grace");
 }else if(!strcmp(mode,"stale")){
  post(0,r.ticket+1,0);post(1,r.ticket,0);progress();drain();
  CHECK(held_out_pending(b)&&us->nr_held==1&&!ends&&!attempts[2],"wrong ticket and wrong slot cannot clear responsibility");
  post(0,r.ticket,0);progress();drain();
  CHECK(accepts[2]==1,"matching completion advances once");
  unsigned before=accepts[2];post(0,r.ticket,0);progress();drain();
  CHECK(accepts[2]==before,"duplicate done never advances twice");
 }else if(!strcmp(mode,"ticket-reuse")){
  post(0,r.ticket,0);progress();drain();REQUIRE(accepts[2]==1,"first matching completion advances");
  callback(2,0);drain();REQUIRE(ends==1,"first batch releases after native completion");
  struct xdev_ext_user_ready old=r;
  b=start(0,4092);REQUIRE(b&&us->nr_held==1,"same batch slot reused");r=take();
  CHECK(r.ticket>old.ticket,"completion ticket increases across slot reuse");
  unsigned before=accepts[2];post(0,old.ticket,0);progress();drain();
  CHECK(us->nr_held==1&&held_out_pending(b)&&accepts[2]==before,"previous message ticket cannot complete reused slot");
  post(0,r.ticket,0);progress();drain();CHECK(accepts[2]==before+1,"new matching ticket advances its message");
 }else if(!strcmp(mode,"poll")){
  /* Actual worker progress, no KICK ioctl. */
  post(0,r.ticket,0);xdev_ext_mech_poll_work(&session.poll_work.work);drain();
  CHECK(accepts[2]==1,"strict POLL consumes completion without KICK");
  callback(2,0);drain();
  struct xdev_ext_mech_batch*b2=start(1,4092);REQUIRE(b2,"second message");r=take();
  xdev_ext_mech_sess_stop(&session.ss);run_progress_work();
  post(1,r.ticket,0);xdev_ext_mech_poll_work(&session.poll_work.work);drain();
  CHECK(ends==2&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-ESHUTDOWN,"POLL continues consuming late done during STOP drain");
  CHECK(accepts[2]==1,"STOP drain does not publish second downstream message");
 }
 CHECK(!warnings,"production warning count is zero");return failures!=0;
}
int main(int argc,char **argv){return argc==2?exercise(argv[1]):2;}

/* SPDX-License-Identifier: GPL-2.0 */
/* Native calls are observation/injection boundaries, never a CE policy model. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
typedef __u64 u64; typedef __u32 u32; typedef __u8 u8;
#define PAGE_SHIFT 12
#define U64_MAX (~(u64)0)
#define GFP_KERNEL 0
#define EXPORT_SYMBOL_GPL(x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define WARN_ON_ONCE(x) test_warn(!!(x))
#define WARN_ON(x) test_warn(!!(x))
#define WARN_ONCE(x,...) test_warn(!!(x))
static int test_warn(int value){return value;}
#define struct_size(p,m,n) (sizeof(*(p))+sizeof((p)->m[0])*(n))
struct list_head { struct list_head *next,*prev; };
#define LIST_HEAD(n) struct list_head n={&n,&n}
#define INIT_LIST_HEAD(n) ((n)->next=(n),(n)->prev=(n))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry(p,h,m) for(p=list_entry((h)->next,typeof(*p),m); &(p)->m!=(h);p=list_entry((p)->m.next,typeof(*p),m))
static void list_add_tail(struct list_head*n,struct list_head*h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_del(struct list_head*n){n->prev->next=n->next;n->next->prev=n->prev;}
static bool list_empty(struct list_head*h){return h->next==h;}
struct mutex {int locked;};
#define DEFINE_MUTEX(n) struct mutex n
static void mutex_lock(struct mutex*m){if(m->locked){fprintf(stderr,"SETUP nested locked hook\n");exit(2);}m->locked=1;}
static void (*unlock_observer)(void);static int observing_unlock;
static void mutex_unlock(struct mutex*m){m->locked=0;if(unlock_observer&&!observing_unlock){observing_unlock=1;unlock_observer();observing_unlock=0;}}
typedef struct{int v;} atomic_t;
static int atomic_read(atomic_t*a){return a->v;}
static void atomic_inc(atomic_t*a){a->v++;}
static int alloc_calls,fail_alloc_at,native_entered,late_allocs;
static void *test_alloc(size_t n){alloc_calls++;if(native_entered)late_allocs++;if(alloc_calls==fail_alloc_at)return NULL;return calloc(1,n);}
#define kzalloc(n,f) test_alloc(n)
#define kvzalloc(n,f) test_alloc(n)
#define kfree(p) free(p)
#define kvfree(p) free(p)
struct module {int refs,puts;};
static bool try_module_get(struct module*m){m->refs++;return true;}
static void (*put_observer)(void);
static void module_put(struct module*m){if(put_observer)put_observer();m->refs--;m->puts++;}
struct file_operations{int id;};
struct file {const struct file_operations *f_op;int id;};
struct page{int unused;};
struct xdev_ext_ce_cookie;struct xdev_ext_ce_backend_ops;
#include "actual-api.h"
#include "xdev_ext_mech_ce_core.h"
#include "xdev_ext_compfam_copy_core.h"
struct xdev_ext_mech_frame {u64 umem_addr;u32 data_off,data_len,index;};
struct xdev_ext_mech_pool {struct page **pages;u32 nr_pages,first_page_off,frame_size,nr_frames;};
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops {int (*unbind_checked)(struct xdev_ext_mech_stage*);};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;u32 depth,nr_bound;struct xdev_ext_mech_stage *st;};
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;struct file *file;void *priv;u32 direction;const struct xdev_ext_mech_class_ops *cls;};
struct xdev_ext_mech_batch {u32 slot;u64 id,ticket;_Alignas(16) char priv[4096],cookie[128];};
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session*s){return &s->pool;}
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session*s){return s->depth;}
static struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session*s){return &s->layout;}
static u32 xdev_ext_mech_batch_slot(struct xdev_ext_mech_batch*b){return b->slot;}
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch*b){return b->id;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch*b){return b->ticket;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch*b){return b->priv;}
static void *xdev_ext_mech_batch_cookie(struct xdev_ext_mech_batch*b){return b->cookie;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch*b){return 1;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch*b,u32 i,struct xdev_ext_mech_frame*f){*f=(struct xdev_ext_mech_frame){.data_len=64};return 0;}
static int xdev_ext_mech_batch_frame_claim(const struct xdev_ext_mech_batch*b,u32 p,u64*o,u64*g){*o=91;*g=92;return 0;}
static bool xdev_ext_mech_batch_ce_owners_valid(const struct xdev_ext_mech_batch*b,u64 t,const struct xdev_ext_ce_xfer*x,u32 n){return t==b->ticket;}
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch*b,u64 t){return t==b->ticket?0:-ESTALE;}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch*b,u64 t,int e,bool q){}
#include "actual-ce.c"
#include "actual-checked.c"
static int checks,failures;static const char *case_name;
#define CHECK(c,msg) do{checks++;if(!(c)){failures++;printf("not ok %s: %s\n",case_name,msg);}}while(0)
struct fixture {struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st[4];struct file file[4];struct page page;struct page *pages[1];};
static const struct xdev_ext_ce_backend_ops ops_b;
static struct module module_a,module_b;static struct file_operations fops_a={1},fops_b={2};
static int bind_errno,host_errno,unhost_errno,unregion_errno,native_calls,bind_calls,host_calls,unhost_calls,unregion_calls;
static int forged,zero_len,hook_kind,hook_seen,hook_expected,hook_before_native;
static struct xdev_ext_mech_stage *hook_stage;static struct xdev_ext_mech_batch *hook_batch;
static void nested_hook(int kind){if(kind!=hook_kind)return;hook_seen++;int before=native_calls;int r=xdev_ext_ce_submit(hook_stage,hook_batch);printf("observe %s hook=%d B_errno=%d native_delta=%d\n",case_name,kind,r,native_calls-before);CHECK(r==hook_expected,"nested B admission errno");CHECK(native_calls==before,"nested B no native submit");hook_before_native=before;if(r==0)xdev_ext_ce_complete((void*)hook_batch->cookie,hook_batch->ticket,0,true,64);}
static int native_bind(struct file*f,u64 start,u64 len,struct xdev_ext_ce_region*r){CHECK(!xdev_ext_ce_lease_lock.locked&&!xdev_ext_ce_backend_lock.locked,"bind outside locks");bind_calls++;native_entered=1;r->priv=(void*)(uintptr_t)(f->id+1);r->len=zero_len?0:len;if(forged)r->ops=forged==2?NULL:&ops_b;nested_hook(1);return bind_errno;}
static int native_host(struct xdev_ext_ce_region*r,struct page**p,u32 n,void**h){host_calls++;*h=r->priv;return host_errno;}
static int native_unhost(void*h){CHECK(!xdev_ext_ce_lease_lock.locked&&!xdev_ext_ce_backend_lock.locked,"host unmap outside locks");CHECK(module_a.refs+module_b.refs>0,"host unmap with module pin");unhost_calls++;nested_hook(2);return unhost_errno;}
static int native_unregion(struct xdev_ext_ce_region*r){CHECK(!xdev_ext_ce_lease_lock.locked&&!xdev_ext_ce_backend_lock.locked,"region unmap outside locks");CHECK(module_a.refs+module_b.refs>0,"region unmap with module pin");CHECK(container_of(r,struct xdev_ext_ce_stage,region)->host==NULL,"host clears before region unmap");unregion_calls++;nested_hook(3);return unregion_errno;}
static int native_submit(struct xdev_ext_ce_region*r,void*h,u32 d,const struct xdev_ext_ce_xfer*x,u32 n,struct xdev_ext_ce_cookie*ck,u64 t){CHECK(n==1&&x[0].len==64&&x[0].owner==91&&x[0].generation==92,"literal typed native transfer");native_calls++;return 0;}
static const struct xdev_ext_ce_backend_ops ops_a={&module_a,&fops_a,native_bind,native_unregion,native_host,native_unhost,native_submit};
static const struct xdev_ext_ce_backend_ops ops_b={&module_b,&fops_b,native_bind,native_unregion,native_host,native_unhost,native_submit};
static const struct xdev_ext_mech_class_ops class_ops={xdev_ext_ce_unbind};
static void reset(void){INIT_LIST_HEAD(&xdev_ext_ce_lease_groups);memset(xdev_ext_ce_backends,0,sizeof(xdev_ext_ce_backends));module_a=(struct module){0};module_b=(struct module){0};bind_errno=host_errno=unhost_errno=unregion_errno=native_calls=bind_calls=host_calls=unhost_calls=unregion_calls=0;forged=zero_len=hook_kind=hook_seen=0;hook_stage=NULL;alloc_calls=fail_alloc_at=native_entered=late_allocs=0;CHECK(!xdev_ext_ce_backend_register(&ops_a),"register actual backend A");CHECK(!xdev_ext_ce_backend_register(&ops_b),"register actual backend B");}
static void init(struct fixture*f,int ops){memset(f,0,sizeof(*f));f->pages[0]=&f->page;f->s=(struct xdev_ext_mech_session){.pool={f->pages,1,0,64,1},.layout={.group_bytes=64},.depth=2,.st=f->st};for(int i=0;i<4;i++){f->file[i]=(struct file){ops?&fops_b:&fops_a,i};f->st[i]=(struct xdev_ext_mech_stage){&f->s,&f->file[i],NULL,XDEV_EXT_MECH_DIR_TO_DEVICE,&class_ops};}}
static int bind_stage(struct fixture*f,int i,u64 start){struct xdev_ext_mech_stage_uapi u={.arg0=start,.arg1=256};native_entered=0;int r=xdev_ext_ce_bind(&f->st[i],&u);native_entered=0;if(!r||f->st[i].priv)f->s.nr_bound++;return r;}
static void batch_init(struct xdev_ext_mech_batch*b,u64 id,u32 slot){memset(b,0,sizeof(*b));b->id=id;b->ticket=id+100;b->slot=slot;}
static int submit(struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){struct xdev_ext_ce_copy_desc d={.len=64,.gpu_off=b->slot*64};int r=xdev_ext_ce_validate(st,b,(u8*)&d,1);CHECK(r==0,"real typed validation before submit");return r?r:xdev_ext_ce_submit(st,b);}
static void prepare_hook(struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b,int kind){struct xdev_ext_ce_copy_desc d={.len=64,.gpu_off=b->slot*64};CHECK(!xdev_ext_ce_validate(st,b,(u8*)&d,1),"hook real typed validation");hook_stage=st;hook_batch=b;hook_kind=kind;hook_expected=-EAGAIN;}
static void after_block(struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b){int before=native_calls;int r=submit(st,b);printf("observe %s after B_errno=%d native_delta=%d\n",case_name,r,native_calls-before);CHECK(r==-EAGAIN,"retained A blocks B with EAGAIN");CHECK(native_calls==before,"retained A no native B submission");}
static void residual(void){case_name="failed-create-residual";reset();struct fixture a,b;struct xdev_ext_mech_batch batch;init(&a,0);init(&b,0);batch_init(&batch,1,0);CHECK(!bind_stage(&b,0,4096),"bind B");prepare_hook(&b.st[0],&batch,1);bind_errno=-EREMOTEIO;zero_len=1;CHECK(bind_stage(&a,0,4096)==-EREMOTEIO,"preserve bind errno");CHECK(hook_seen==1,"native bind interleaving executed");hook_kind=0;unregion_errno=-EIO;CHECK(xdev_ext_mech_unbind_checked(&a.s)==-EIO,"actual checked rollback native refusal");CHECK(a.st[0].priv&&((struct xdev_ext_ce_stage*)a.st[0].priv)->region.priv,"retain partial region");CHECK(a.s.pool.pages==a.pages&&module_a.refs==2&&module_a.puts==0,"pool and backend pins retained");after_block(&b.st[0],&batch);}
static void cleanup(int region,bool active){case_name=region?(active?"region-refusal-later-stage":"region-refusal"):(active?"host-refusal-later-stage":"host-refusal");reset();struct fixture a,b;struct xdev_ext_mech_batch batch;init(&a,0);init(&b,0);batch_init(&batch,1,0);CHECK(!bind_stage(&b,0,4096),"bind B");if(active){CHECK(!submit(&b.st[0],&batch),"earlier B accepted");xdev_ext_ce_complete((void*)batch.cookie,batch.ticket,0,true,64);}CHECK(!bind_stage(&a,0,4096),"bind A");prepare_hook(&b.st[0],&batch,region?3:2);if(region)unregion_errno=-EIO;else unhost_errno=-EBUSY;int r=xdev_ext_mech_unbind_checked(&a.s);CHECK(r==(region?-EIO:-EBUSY),"native unmap errno unchanged");CHECK(hook_seen==1,"unmap interleaving executed");hook_kind=0;CHECK(a.st[0].priv&&module_a.refs==2&&module_a.puts==0,"refusal retains stage and pins");after_block(&b.st[0],&batch);}

static void finish(struct xdev_ext_mech_stage*st,struct xdev_ext_mech_batch*b,bool quarantine){
 struct xdev_ext_ce_cookie*ck=(void*)b->cookie;
 if(ck->state==XDEV_EXT_CE_CK_ARMED)xdev_ext_ce_complete(ck,b->ticket,0,true,64);
 xdev_ext_ce_batch_release(st,b,quarantine);
}
static void expect_holds(struct xdev_ext_mech_stage*st,unsigned expected,const char*msg){
#if CE_REPAIRED
 struct xdev_ext_ce_stage*cs=st->priv;
 CHECK(cs&&cs->lease_group&&cs->lease_group->cleanup_holds==expected,msg);
#else
 (void)st;(void)expected;(void)msg;
#endif
}
static void positive(int different_ops,bool disjoint){
 case_name=different_ops?"different-ops-positive":disjoint?"disjoint-positive":"successful-bind-hold-release";reset();
 struct fixture a,b;struct xdev_ext_mech_batch ba,bb;init(&a,0);init(&b,different_ops);batch_init(&ba,1,0);batch_init(&bb,2,0);
 CHECK(!bind_stage(&a,0,4096),"A ordinary bind");CHECK(!bind_stage(&b,0,disjoint?4352:4096),"B ordinary bind");
 CHECK(late_allocs==0,"no allocation after entering native bind");expect_holds(&a.st[0],0,"successful bind releases hold");
 if(disjoint||different_ops)CHECK(!submit(&a.st[0],&ba),"A accepts before independent B");
 CHECK(!submit(&b.st[0],&bb),"unheld/disjoint/different ops B admitted");finish(&b.st[0],&bb,false);
 if(disjoint||different_ops)finish(&a.st[0],&ba,false);
 CHECK(!xdev_ext_mech_unbind_checked(&a.s),"A full cleanup");CHECK(!xdev_ext_mech_unbind_checked(&b.s),"B full cleanup");
 CHECK(!a.st[0].priv&&!b.st[0].priv,"successful cleanup clears stage");CHECK(module_a.refs==0&&module_b.refs==0,"all module pins released");CHECK(module_a.puts+module_b.puts==2,"one module_put per stage");CHECK(list_empty(&xdev_ext_ce_lease_groups),"successful cleanup removes groups");
}
static void retry_cleanup(bool region){
 case_name=region?"region-cleanup-retry":"host-cleanup-retry";reset();struct fixture a,b;struct xdev_ext_mech_batch bb;init(&a,0);init(&b,0);batch_init(&bb,1,0);
 CHECK(!bind_stage(&a,0,4096)&&!bind_stage(&b,0,4096),"ordinary bind both");
 if(region)unregion_errno=-EIO;else unhost_errno=-EBUSY;
 int err=region?-EIO:-EBUSY;CHECK(xdev_ext_mech_unbind_checked(&a.s)==err,"first refusal");expect_holds(&a.st[0],1,"first refusal owns one hold");
 CHECK(xdev_ext_mech_unbind_checked(&a.s)==err,"repeat refusal same errno");expect_holds(&a.st[0],1,"retry does not double hold");
 CHECK(unhost_calls==(region?1:2),"successful host cleanup not replayed");CHECK(unregion_calls==(region?2:0),"host refusal stops region cleanup");
 CHECK(module_a.puts==0&&module_a.refs==2,"no early module put");after_block(&b.st[0],&bb);
 if(((struct xdev_ext_ce_cookie*)bb.cookie)->state==XDEV_EXT_CE_CK_ARMED)finish(&b.st[0],&bb,false);
 unregion_errno=unhost_errno=0;CHECK(!xdev_ext_mech_unbind_checked(&a.s),"retry complete succeeds");CHECK(!a.st[0].priv&&module_a.puts==1,"final cleanup clears stage and puts once");
 CHECK(!submit(&b.st[0],&bb),"B released after all A handles clear");finish(&b.st[0],&bb,false);CHECK(!xdev_ext_mech_unbind_checked(&b.s),"B cleanup");
 CHECK(module_a.refs==0&&module_a.puts==2&&list_empty(&xdev_ext_ce_lease_groups),"all stages and pins detached once");
}
static void identity(int forge){
 case_name=forge==2?"provider-null-ops-residual":"provider-forged-ops-residual";reset();struct fixture a,b;struct xdev_ext_mech_batch bb;init(&a,0);init(&b,0);batch_init(&bb,1,0);CHECK(!bind_stage(&b,0,4096),"B bind");
 prepare_hook(&b.st[0],&bb,1);forged=forge;zero_len=1;bind_errno=-EREMOTEIO;CHECK(bind_stage(&a,0,4096)==-EREMOTEIO,"provider error preserved");hook_kind=0;CHECK(hook_seen==1,"forged fields callback interleaving");
 struct xdev_ext_ce_stage*cs=a.st[0].priv;CHECK(cs->region.ops==&ops_a,"region compatibility authority restored on error");if(!cs->region.ops)return;
 unregion_errno=-EIO;CHECK(xdev_ext_mech_unbind_checked(&a.s)==-EIO,"forged provider residual refused");after_block(&b.st[0],&bb);
 if(((struct xdev_ext_ce_cookie*)bb.cookie)->state==XDEV_EXT_CE_CK_ARMED)finish(&b.st[0],&bb,false);
 unregion_errno=0;CHECK(!xdev_ext_mech_unbind_checked(&a.s),"residual eventually releases");CHECK(module_a.puts==1&&module_a.refs==1&&module_b.puts==0,"C owned module authority");
}
static void multistage(void){
 case_name="multistage-retained-holds";reset();struct fixture a,b;struct xdev_ext_mech_batch bb;init(&a,0);init(&b,0);batch_init(&bb,1,0);CHECK(!bind_stage(&b,0,4096),"B bind");
 bind_errno=-EREMOTEIO;zero_len=1;CHECK(bind_stage(&a,0,4096)==-EREMOTEIO,"A residual stage0");CHECK(bind_stage(&a,1,4160)==-EREMOTEIO,"A residual stage1");
 unregion_errno=-EIO;CHECK(xdev_ext_ce_unbind(&a.st[0])==-EIO,"stage0 refuses");CHECK(xdev_ext_ce_unbind(&a.st[1])==-EIO,"stage1 refuses");expect_holds(&a.st[0],2,"two distinct holds");
 CHECK(xdev_ext_ce_unbind(&a.st[0])==-EIO,"stage0 retries refusal");expect_holds(&a.st[0],2,"retry does not double hold");
 unregion_errno=0;CHECK(!xdev_ext_ce_unbind(&a.st[0]),"stage0 final cleanup");expect_holds(&a.st[1],1,"stage0 cannot clear stage1 hold");if(((struct xdev_ext_ce_stage*)a.st[1].priv)->lease_group)xdev_ext_ce_batch_release(&a.st[1],&bb,false);expect_holds(&a.st[1],1,"batch release leaves cleanup hold");
 CHECK(module_a.refs==2&&module_a.puts==1,"only stage0 pin released");after_block(&b.st[0],&bb);
 if(((struct xdev_ext_ce_cookie*)bb.cookie)->state==XDEV_EXT_CE_CK_ARMED)finish(&b.st[0],&bb,false);
 xdev_ext_ce_mark_dead(&a.st[1]);expect_holds(&a.st[1],1,"mark dead leaves hold");after_block(&b.st[0],&bb);
 CHECK(!xdev_ext_ce_unbind(&a.st[1]),"last residual final cleanup");
}
static void refusals(void){
 case_name="ambiguous-active-quarantine-refusal";reset();struct fixture a;struct xdev_ext_mech_batch ba;init(&a,0);batch_init(&ba,1,0);CHECK(!bind_stage(&a,0,4096),"A bind");struct xdev_ext_ce_stage*cs=a.st[0].priv;
 cs->ambiguous.v=1;CHECK(xdev_ext_mech_unbind_checked(&a.s)==-EBUSY,"ambiguous refusal");CHECK(!unhost_calls&&!unregion_calls,"ambiguous never native unmap");cs->ambiguous.v=0;
 CHECK(!submit(&a.st[0],&ba),"A accepted batch");CHECK(xdev_ext_mech_unbind_checked(&a.s)==-EBUSY,"active refusal");CHECK(!unhost_calls&&!unregion_calls,"active never unmaps");finish(&a.st[0],&ba,true);
 CHECK(cs->lease_group->state.quarantined,"unknown batch group quarantine");CHECK(xdev_ext_mech_unbind_checked(&a.s)==-EBUSY,"quarantine refusal");CHECK(!unhost_calls&&!unregion_calls,"quarantine never native unmap");CHECK(module_a.refs==1&&module_a.puts==0,"unknown preserves module");
}
static void allocation(void){
 case_name="allocation-and-precheck-order";reset();struct fixture a;init(&a,0);struct xdev_ext_mech_stage_uapi u={.flags=1,.arg1=256};CHECK(xdev_ext_ce_bind(&a.st[0],&u)==-EINVAL&&alloc_calls==0,"flags reject before allocation");u.flags=0;u.arg1=0;CHECK(xdev_ext_ce_bind(&a.st[0],&u)==-EINVAL&&alloc_calls==0,"zero length rejects before allocation");u.arg0=U64_MAX;u.arg1=2;CHECK(xdev_ext_ce_bind(&a.st[0],&u)==-EINVAL&&alloc_calls==0,"overflow before allocation");
 fail_alloc_at=1;CHECK(bind_stage(&a,0,4096)==-ENOMEM&&bind_calls==0&&module_a.refs==0,"stage allocation failure no native or pin");
 fail_alloc_at=alloc_calls+2;CHECK(bind_stage(&a,0,4096)==-ENOMEM,"group allocation errno");CHECK(bind_calls==0&&host_calls==0,"group allocation before native entry");CHECK(a.st[0].priv&&module_a.refs==1,"unbound stage pin rollback ownership");CHECK(!xdev_ext_mech_unbind_checked(&a.s),"checked rollback before native");CHECK(module_a.refs==0&&module_a.puts==1&&!a.st[0].priv,"one put early group failure");CHECK(unhost_calls==0&&unregion_calls==0,"no cleanup for no native handles");
}
static void shifted(void){
 case_name="shifted-overlap-and-idempotence";reset();struct fixture a;struct xdev_ext_mech_batch b0,b1;init(&a,0);batch_init(&b0,1,0);batch_init(&b1,2,1);CHECK(!bind_stage(&a,0,4096)&&!bind_stage(&a,1,4160),"shifted session binds");
 CHECK(((struct xdev_ext_ce_stage*)a.st[0].priv)->lease_group->state.serial_batches,"shifted overlap serializes");CHECK(!submit(&a.st[0],&b0),"batch0 accepts");xdev_ext_ce_complete((void*)b0.cookie,b0.ticket,0,true,64);CHECK(!submit(&a.st[1],&b0),"same generation later stage idempotent");CHECK(submit(&a.st[1],&b1)==-EAGAIN,"second slot serialized");finish(&a.st[1],&b0,false);CHECK(!submit(&a.st[1],&b1),"next slot after release");finish(&a.st[1],&b1,false);CHECK(!xdev_ext_mech_unbind_checked(&a.s),"multistage final cleanup");CHECK(module_a.puts==2&&module_a.refs==0,"multistage pin accounting");
}

static struct xdev_ext_mech_stage *audit_a,*audit_b;static struct xdev_ext_mech_batch *audit_batch;static int audit_seen;
static void atomic_observer(void){
 struct xdev_ext_ce_stage *cs=audit_a->priv;if(!cs)return;
#if CE_REPAIRED
 if(cs->lease_group)CHECK(cs->cleanup_held&&cs->lease_group->cleanup_holds>0,"no linked cleanup range without its hold");
#endif
 if(!cs->host&&!cs->region.priv)return;
 audit_seen++;CHECK(cs->lease_group!=NULL,"native handles cannot detach early");
 int before=native_calls;int ret=submit(audit_b,audit_batch);CHECK(ret==-EAGAIN,"unlock observer B denied until handles clear");CHECK(native_calls==before,"unlock observer no native B");
 if(!ret)xdev_ext_ce_complete((void*)audit_batch->cookie,audit_batch->ticket,0,true,64);
}
static void put_check(void){CHECK(!audit_a->priv,"module put follows stage detach");}
static void atomic_cleanup(void){
 case_name="atomic-cleanup-detach";reset();struct fixture a,b;struct xdev_ext_mech_batch bb;init(&a,0);init(&b,0);batch_init(&bb,1,0);CHECK(!bind_stage(&a,0,4096)&&!bind_stage(&b,0,4096),"bind both for atomic observation");
 audit_a=&a.st[0];audit_b=&b.st[0];audit_batch=&bb;audit_seen=0;unlock_observer=atomic_observer;put_observer=put_check;
 CHECK(!xdev_ext_mech_unbind_checked(&a.s),"atomic observed cleanup succeeds");unlock_observer=NULL;put_observer=NULL;CHECK(audit_seen>0,"observer executed before native cleanup");CHECK(!a.st[0].priv&&module_a.puts==1,"detached only after native cleanup");
}
static void errors(void){
 case_name="native-error-and-geometry-order";reset();struct fixture a;init(&a,0);bind_errno=-ENOSPC;zero_len=1;CHECK(bind_stage(&a,0,4096)==-ENOSPC,"native bind error before geometry error");CHECK(host_calls==0,"bind error never host bind");CHECK(!xdev_ext_mech_unbind_checked(&a.s),"bind residual cleanup");
 reset();init(&a,0);zero_len=1;CHECK(bind_stage(&a,0,4096)==-EINVAL,"geometry error unchanged");CHECK(host_calls==0,"geometry error before host hook");CHECK(!xdev_ext_mech_unbind_checked(&a.s),"geometry residual cleanup");
 reset();init(&a,0);a.s.layout.group_bytes=512;CHECK(bind_stage(&a,0,4096)==-ENOSPC,"typed prepare error before host hook");CHECK(host_calls==0,"prepare failure never host bind");CHECK(!xdev_ext_mech_unbind_checked(&a.s),"prepare residual cleanup");
 reset();init(&a,0);host_errno=-ENOBUFS;CHECK(bind_stage(&a,0,4096)==-ENOBUFS,"native host bind errno unchanged");CHECK(host_calls==1,"host hook entered after geometry/prepare");unhost_errno=-EIO;CHECK(xdev_ext_mech_unbind_checked(&a.s)==-EIO,"partial host retains on cleanup failure");expect_holds(&a.st[0],1,"partial host hold survives");CHECK(!unregion_calls&&module_a.puts==0,"host failure stops region and put");
}
static void cqe_and_dead(void){
 case_name="cqe-ticket-and-dead-order";reset();struct fixture a;struct xdev_ext_mech_batch ba;init(&a,0);batch_init(&ba,1,0);CHECK(!bind_stage(&a,0,4096),"A bind");CHECK(!submit(&a.st[0],&ba),"accepted A");struct xdev_ext_ce_cookie*ck=(void*)ba.cookie;
 xdev_ext_ce_complete(ck,ba.ticket-1,0,true,64);CHECK(ck->state==XDEV_EXT_CE_CK_ARMED,"stale ticket cannot finish cookie");xdev_ext_ce_complete(ck,ba.ticket,0,true,64);
 struct xdev_ext_ce_mech_cqe got,expected={.outcome=XDEV_EXT_CE_OK,.bytes_done=64,.entries_done=1};memset(&got,0xa5,sizeof(got));xdev_ext_ce_fill_cqe(&a.st[0],&ba,&got);CHECK(!memcmp(&got,&expected,sizeof(got)),"exact successful CQE bytes");finish(&a.st[0],&ba,false);
 xdev_ext_ce_mark_dead(&a.st[0]);((struct xdev_ext_ce_stage*)a.st[0].priv)->staged=NULL;CHECK(xdev_ext_ce_submit(&a.st[0],&ba)==-ENODEV,"no-conflict dead error precedes staged error");
}
int main(int argc,char**argv){setvbuf(stdout,NULL,_IONBF,0);residual();cleanup(0,false);cleanup(1,false);cleanup(0,true);cleanup(1,true);positive(0,false);positive(0,true);positive(1,false);retry_cleanup(0);retry_cleanup(1);identity(1);identity(2);multistage();refusals();allocation();shifted();atomic_cleanup();errors();cqe_and_dead();printf("checks=%d failures=%d\n",checks,failures);return failures?1:0;}

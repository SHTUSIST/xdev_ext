/* SPDX-License-Identifier: GPL-2.0 */
/* Oracles: core-family/CONTRACT.md core-table-v1; block-v2 additionally uses
 * storage-second-member-next/CONTRACT.md section 2. Neither is production.
 * All calls below execute production static inline rules. No syscall or DMA. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "adapter.h"

static unsigned checks, failures;
static bool block_v2;
static char context[160];
static void eq(const char *name, long long got, long long want)
{
 checks++;
 if (got != want) {
  failures++;
  fprintf(stderr, "FAIL %s %s: got=%lld want=%lld\n", context, name, got, want);
 }
}
#define EQ(name, got, want) eq(name, (long long)(got), (long long)(want))
#define TO XDEV_EXT_MECH_DIR_TO_DEVICE
#define FROM XDEV_EXT_MECH_DIR_FROM_DEVICE
#define D struct xdev_ext_mech_class_desc
#define C struct xdev_ext_mech_create
#define S struct xdev_ext_mech_stage_uapi
#define SENTINEL 0xa55a1234U

static C fixture(unsigned id)
{
 C c = { .abi_version=1, .nr_stages=1, .pool_kind=2, .pool_fd=-1,
  .layout={.frame_size=4096,.hdr_room=0,.seg_len=4096,.group_bytes=8192},
  .depth=2, .eventfd=-1 };
 c.st[0]=(S){.class_id=id,.direction=TO,.fd=7};
 if (id==2) { c.pool_kind=1; c.pool_fd=6; }
 if (id==8 || id==11) { c.pool_kind=3; c.pool_fd=6; }
 if (id==9) { c.st[0].fd=-1; c.st[0].arg0=3; }
 if (id==10) c.st[0].arg0=1;
 return c;
}
static void rows_for(const C *c, const D **rows)
{
 unsigned i;
 for (i=0;i<4;i++) rows[i]=xdev_ext_mech_class_desc(c->st[i].class_id);
}
static void create_rows(const char *name, const C *c, const D *const *rows, int want)
{
 __u32 frames=SENTINEL;
 int ret=test_create(c,rows,&frames);
 EQ(name,ret,want);
 EQ("frames-write-only-on-success",frames,want ? SENTINEL:2);
}
static void create(const char *name, const C *c, int want)
{
 const D *rows[4]; rows_for(c,rows); create_rows(name,c,rows,want);
}
static void start(const char *name, const C *c, int want)
{
 const D *rows[4]; rows_for(c,rows);
 EQ(name,test_start(c->st,rows,c->nr_stages),want);
}

/* Removing a legal case, allowing an undocumented site, or widening a return
 * boundary must fail. Entries use literal masks/ranges from the prose. */
struct ret_case { unsigned classes, member, site; int min,max; unsigned values; };
static const struct ret_case legal_returns[]={
 {0xffc,1,4,-4095,0,0}, /* every known PREPARE/CREATE */
 {0xffc,2,0,1,0,0x7}, /* every known BUILD/WORKER */
 {0x008,2,3,1,0,0x7}, /* NVMe BUILD/URING */
 {0xffc,3,0,1,0,0xf}, /* every known COMPLETE/WORKER */
 {0x008,3,3,1,0,0xa}, /* NVMe COMPLETE/URING */
 {0x004,3,1,1,0,0x70}, /* AF_XDP RX_GENERIC */
 {0x004,3,2,1,0,0x70}, /* AF_XDP RX_NATIVE */
 {0x004,3,5,1,0,0x70}, /* AF_XDP RX_HOLD_RESULT */
 {0x200,4,0,-4095,0,0}, /* CPU COMPUTE/WORKER */
};
static bool golden_ret(unsigned id,unsigned member,unsigned site,int ret)
{
 size_t i;
 for (i=0;i<sizeof(legal_returns)/sizeof(*legal_returns);i++) {
  const struct ret_case *c=&legal_returns[i];
  if (id<32 && (c->classes&(1U<<id)) && c->member==member && c->site==site) {
   if (c->values) return ret>=0 && ret<32 && (c->values&(1U<<ret));
   return ret>=c->min && ret<=c->max;
  }
 }
 return false;
}
static void returns(void)
{
 static const int values[]={INT_MIN,-4096,-4095,-2,-1,0,1,2,3,4,5,6,7,31,32,INT_MAX};
 static const unsigned ids[]={0,1,2,3,4,5,6,7,8,9,10,11,12,77,UINT_MAX};
 static const unsigned ids_v2[]={0,1,2,3,4,5,6,7,8,9,10,11,13,77,UINT_MAX};
 size_t a,v; unsigned m,s;
 for(a=0;a<sizeof(ids)/sizeof(*ids);a++) for(m=0;m<=5;m++) for(s=0;s<=8;s++)
  for(v=0;v<sizeof(values)/sizeof(*values);v++) {
   unsigned id=block_v2?ids_v2[a]:ids[a]; int r=values[v], want; bool legal=golden_ret(id,m,s,r),illegal=legal;
   snprintf(context,sizeof(context),"ret id=%u member=%u site=%u ret=%d",id,m,s,r);
   EQ("legality",test_ret(xdev_ext_mech_class_desc(id),id,m,s,r),legal);
   if(legal) want=r;
   else if(m==2) want=2;
   else if(m==3 && s==5) want=6;
   else if(m==3 && (s==1 || s==2)) want=5;
   else if(m==3) want=3;
   else want=-EPROTO;
   EQ("replacement",test_resolve(xdev_ext_mech_class_desc(id),id,m,s,r,&illegal),want);
   EQ("illegal-indication",illegal,!legal);
  }
}
struct retry_case { unsigned id,retries; int status; bool want; };
static const struct retry_case retry_cases[]={
 {3,0,1,1},{3,2,1,1},{3,3,1,0},{3,UINT_MAX,1,0},
 {3,0,0,0},{3,0,-EAGAIN,0},{3,0,-EIO,0},{3,0,0x800,0},
 {3,0,0x7ff,1},{3,0,0x4001,0},{3,0,0x4801,0},{3,0,0x8001,1},
 {2,0,-EAGAIN,1},{2,3,-EAGAIN,1},{2,4,-EAGAIN,0},
 {2,0,0,0},{2,0,-EIO,0},{2,0,1,0},{2,0,2,0},
 {5,0,1,1},{5,2,1,1},{5,3,1,0},{5,0,0,0},{5,0,2,0},{5,0,-EIO,0},
 {6,0,1,1},{6,2,1,1},{6,3,1,0},{6,0,0,0},{6,0,2,0},{6,0,-EIO,0},
};
static void retries(void)
{
 size_t i; unsigned id,n; static const int statuses[]={INT_MIN,-EAGAIN,-EIO,0,1,2,3,0x4001,INT_MAX};
 for(i=0;i<sizeof(retry_cases)/sizeof(*retry_cases);i++) {
  const struct retry_case *c=&retry_cases[i];
  snprintf(context,sizeof(context),"retry id=%u count=%u status=%d",c->id,c->retries,c->status);
  EQ("bounded-retry",test_retry(xdev_ext_mech_class_desc(c->id),c->id,c->retries,c->status),c->want);
 }
 for(id=0;id<14;id++) if(id!=2 && id!=3 && id!=5 && id!=6)
  for(n=0;n<5;n++) for(i=0;i<sizeof(statuses)/sizeof(*statuses);i++) {
   snprintf(context,sizeof(context),"never-retry id=%u count=%u status=%d",id,n,statuses[i]);
   EQ("no-retry",test_retry(xdev_ext_mech_class_desc(id),id,n,statuses[i]),0);
  }
}
struct complete_case { unsigned id; int ret,status; bool sequestered,zombie; unsigned retries; int step,error; };
static const struct complete_case complete_cases[]={
 {3,0,0,0,0,0,2,0},{3,1,0,0,0,0,3,0},
 {3,0,-ENOENT,0,0,0,5,-ENOENT},{3,1,1,0,0,0,5,-EIO},
 {3,2,1,0,0,2,4,0},{3,2,1,0,0,3,5,-EIO},
 {2,2,-EAGAIN,0,0,3,4,0},{2,2,-EAGAIN,0,0,4,5,-EAGAIN},
 {5,2,1,0,0,2,4,0},{6,2,1,0,0,2,4,0},
 {5,2,2,0,0,0,5,-EIO},{6,2,2,0,0,0,5,-EIO},
 {6,2,0,0,0,0,5,-ECANCELED},{4,2,-EAGAIN,0,0,0,5,-EAGAIN},
 {3,3,0,0,0,0,5,-ECANCELED},{3,3,-ENOENT,0,0,0,5,-ENOENT},
 {3,3,1,0,0,0,5,-EIO},{3,99,0,0,0,0,5,-EPROTO},
 {3,0,0,1,0,0,6,-EIO},{3,0,-ENOENT,1,0,0,6,-ENOENT},
 {3,1,0,0,1,0,6,-ETIMEDOUT},{3,1,-ENOENT,1,1,0,6,-ETIMEDOUT},
};
static void completions(void)
{
 size_t i;
 for(i=0;i<sizeof(complete_cases)/sizeof(*complete_cases);i++) {
  const struct complete_case *c=&complete_cases[i]; int err=0;
  snprintf(context,sizeof(context),"complete case=%zu",i);
  EQ("step",xdev_ext_mech_complete_step(c->id,c->ret,c->status,c->sequestered,c->zombie,c->retries,&err),c->step);
  EQ("errno",err,c->error);
 }
}

static void per_class(void)
{
 unsigned id; C c; const D *d;
 static const unsigned family[]={0,0,1,2,3,3,3,1,1,3,3,1};
 for(id=2;id<=11;id++) {
  snprintf(context,sizeof(context),"class id=%u",id); c=fixture(id); d=xdev_ext_mech_class_desc(id);
  EQ("family",d->family,family[id]); create("valid",&c,0);
  EQ("TO-role",test_role(d,&c.st[0]),id==4?4:(id==9||id==10?3:2));
  c.st[0].direction=FROM;
  EQ("FROM-role",test_role(d,&c.st[0]),id==4?4:(id==9||id==10?-EINVAL:1));
  c=fixture(id); c.st[0].direction=0; create("invalid-direction",&c,-EINVAL);
  c=fixture(id); c.st[0].flags=1U<<24; create("unknown-flags",&c,-EINVAL);
  c=fixture(id); c.st[0].fd=-2; create("negative-fd",&c,id==9?-EINVAL:-EBADF);
  c=fixture(id); c.st[0].flags=XDEV_EXT_MECH_STAGE_F_POLL; create("POLL-stripped",&c,0);
 }
 c=fixture(2); c.pool_kind=2;c.pool_fd=-1;create("AFXDP-requires-XSK",&c,-EINVAL);
 c=fixture(2);c.st[0].flags=2;create("AFXDP-FINITE-requires-RELIABLE",&c,-EINVAL);
 c.st[0].flags=4;create("AFXDP-POLICY-requires-RELIABLE",&c,-EINVAL);
 c.st[0].flags=7;create("AFXDP-reliable-extensions",&c,0);
 c=fixture(2);c.st[0].direction=FROM;create("AFXDP-RX-needs-follower",&c,-EINVAL);
 c.nr_stages=2;c.st[1]=(S){.class_id=3,.direction=TO,.fd=7};create("AFXDP-RX-first",&c,0);
 c.st[0].direction=TO;c.st[1]=(S){.class_id=2,.direction=FROM,.fd=7};create("AFXDP-RX-not-first",&c,-EINVAL);
 c=fixture(4);c.st[0].flags=1;create("IAA-software",&c,0);
 c=fixture(7);c.st[0].flags=1;c.st[0].fd=-2;create("NXP-args-before-fd",&c,-EINVAL);
 c.st[0].arg0=1;c.st[0].arg1=68;create("NXP-min-excluded",&c,-EINVAL);
 c.st[0].arg1=69;create("NXP-valid-args-then-fd",&c,-EBADF);
 c.st[0].fd=7;create("NXP-min-valid",&c,0);
 c.st[0].arg1=UINT_MAX;create("NXP-max-valid",&c,0);
 c.st[0].arg1=(__u64)UINT_MAX+1;create("NXP-max-exceeded",&c,-EINVAL);
 c=fixture(7);c.st[0].direction=FROM;create("SOCKET-RX-needs-follower",&c,-EINVAL);
 c.nr_stages=2;c.st[1]=(S){.class_id=3,.direction=TO,.fd=7};create("SOCKET-RX-first",&c,0);
 c.st[0].direction=TO;c.st[1]=(S){.class_id=7,.direction=FROM,.fd=7};create("SOCKET-RX-not-first",&c,-EINVAL);
 for(id=8;id<=11;id+=3) {
  c=fixture(id);c.pool_kind=2;c.pool_fd=-1;c.st[0].flags=1U<<24;c.st[0].direction=0;
  create("peer-only-before-flags-direction",&c,-EOPNOTSUPP);
  c=fixture(id);c.st[0].direction=FROM;create("peer-both-directions",&c,0);
 }
 c=fixture(11);c.st[0].flags=3;create("XDOMAIN-known-flags",&c,0);
 c=fixture(9);c.st[0].fd=0;create("CPU-no-file",&c,-EINVAL);
 c=fixture(9);c.st[0].arg0=11;create("CPU-max-invalid",&c,-EINVAL);
 c=fixture(9);c.st[0].arg0=0;create("CPU-zero-invalid",&c,-EINVAL);
 c=fixture(10);c.st[0].arg0=0;create("USER-deadline-zero",&c,-EINVAL);
 c.st[0].arg0=600000;create("USER-deadline-max",&c,0);
 c.st[0].arg0=600001;create("USER-deadline-too-large",&c,-EINVAL);
 c=fixture(10);c.st[0].flags=2;create("USER-strict",&c,0);
 c.st[0].flags=3;create("USER-strict-varlen",&c,-EOPNOTSUPP);
 c.st[0].flags=2;c.st[0].arg1=1;create("USER-strict-delta",&c,-EOPNOTSUPP);
 c=fixture(10);c.pool_kind=3;c.pool_fd=6;create("USER-peer-needs-strict",&c,-EOPNOTSUPP);
 c.st[0].flags=2;create("USER-peer-strict",&c,0);
}

/* Each pair of invalid fields catches a misplaced validator. */
static void precedence(void)
{
 C c; unsigned id;
 snprintf(context,sizeof(context),"create-precedence");
 c=fixture(3);c.abi_version=2;c.pool_kind=0;create("ABI-before-pool",&c,-EINVAL);
 c=fixture(3);c.nr_stages=0;c.pool_fd=0;create("count-before-pool-fd",&c,-EINVAL);
 c=fixture(3);c.nr_stages=5;create("count-max",&c,-EINVAL);
 c=fixture(3);c.pool_kind=0;c.st[0].fd=-2;create("pool-before-stage-fd",&c,-EINVAL);
 c=fixture(3);c.pool_fd=6;c.st[0].fd=-2;create("IOU-pool-fd-before-stage-fd",&c,-EINVAL);
 c=fixture(3);c.pool_kind=1;c.pool_fd=-1;c.layout.frame_size=0;create("XSK-pool-fd-before-layout",&c,-EBADF);
 c=fixture(3);c.pool_kind=3;c.pool_fd=-1;c.layout.frame_size=0;create("PEER-pool-fd-before-layout",&c,-EBADF);
 c=fixture(3);c.depth=0;c.st[0].fd=-2;create("depth-before-stage-fd",&c,-EINVAL);
 c=fixture(3);c.eventfd=-2;c.st[0].fd=-2;create("eventfd-before-stage-fd",&c,-EINVAL);
 c=fixture(3);c.layout.frame_size=0;c.st[0].fd=-2;create("layout-before-stage-fd",&c,-EINVAL);
 c=fixture(3);c.st[1].fd=1;create("unused-slot-must-be-zero",&c,-EINVAL);
 c=fixture(3);c.st[0].flags=XDEV_EXT_MECH_STAGE_F_FANOUT;c.st[0].fd=-2;create("fanout-before-fd",&c,-EINVAL);
 c=fixture(3);c.nr_stages=2;c.st[1]=c.st[0];c.st[1].flags=XDEV_EXT_MECH_STAGE_F_FANOUT;create("consumer-fanout",&c,0);
 c.st[0].direction=FROM;create("fanout-previous-producer",&c,-EINVAL);
 for(id=2;id<=11;id++) {
  if(id==8 || id==11 || id==9 || id==10) continue;
  c=fixture(id);c.pool_kind=3;c.pool_fd=6;c.st[0].fd=-2;
  create("fd-before-final-peer-capability",&c,-EBADF);
  c.st[0].fd=7;create("peer-capability-last",&c,id==3?0:-EOPNOTSUPP);
 }
 for(id=0;id<=13;id++) if(id<2 || id>(block_v2?12U:11U)) {
  c=fixture(3);c.st[0].class_id=id;create("unknown-id",&c,-EINVAL);
  c.layout.frame_size=0;create("layout-before-unknown",&c,-EINVAL);
 }
}

struct length_case { unsigned xform; long long param; int want; bool template_ok; };
static const struct length_case lengths[]={
 {1,0,0,0},{1,1,-EINVAL,0},{2,0,0,0},{2,1,-EINVAL,0},
 {3,0,0,1},{3,1,-EINVAL,0},{4,0,0,1},{4,1,-EINVAL,0},
 {5,3,-EINVAL,0},{5,4,0,0},{5,256,0,0},{5,257,-EINVAL,0},
 {6,0,0,0},{6,-1,0,0},{7,0,0,0},{7,1,-EINVAL,0},
 {8,0,-EINVAL,0},{8,1,0,0},{8,131072,0,0},{8,131073,-EINVAL,0},
 {9,1,0,0},{9,131072,0,0},{10,-257,-EINVAL,0},{10,-256,0,0},
 {10,0,0,1},{10,256,0,0},{10,257,-EINVAL,0},
};
static void length_and_start(void)
{
 size_t i; C c; unsigned id;
 for(i=0;i<sizeof(lengths)/sizeof(*lengths);i++) {
  const struct length_case *l=&lengths[i];
  snprintf(context,sizeof(context),"CPU xform=%u param=%lld",l->xform,l->param);
  c=fixture(9);c.st[0].arg0=l->xform;c.st[0].arg1=(__u64)l->param;
  create("length-parameter",&c,l->want);
  start("template",&c,l->template_ok?0:-EOPNOTSUPP);
 }
 snprintf(context,sizeof(context),"length-and-start");
 for(id=2;id<=11;id++) {c=fixture(id);start("class-template",&c,id==4?-EOPNOTSUPP:0);}
 c=fixture(7);c.st[0].direction=FROM;start("SOCKET-RX-template",&c,-EOPNOTSUPP);
 c=fixture(10);c.st[0].arg1=4096;create("USER-positive-limit",&c,0);start("USER-delta-template",&c,-EOPNOTSUPP);
 c.st[0].arg1=(__u64)-4096LL;create("USER-negative-limit",&c,0);
 c.st[0].arg1=4097;create("USER-positive-overflow",&c,-EINVAL);
 c.st[0].arg1=(__u64)-4097LL;create("USER-negative-overflow",&c,-EINVAL);
 c.st[0].flags=1;c.st[0].arg1=0;create("USER-varlen",&c,0);start("USER-varlen-template",&c,-EOPNOTSUPP);
 c.st[0].arg1=1;create("USER-varlen-needs-zero-delta",&c,-EINVAL);
 for(id=9;id<=10;id++) {
  c=fixture(id);if(id==9)c.st[0].arg0=1;else c.st[0].arg1=1;
  c.nr_stages=2;c.st[1]=(S){.class_id=3,.direction=TO,.fd=7};
  create("length-change-before-fixed",&c,-EOPNOTSUPP);
  c.nr_stages=3;c.st[2]=c.st[1];c.st[1]=(S){.class_id=4,.direction=TO,.fd=7};
  create("transform-stops-fixed-scan",&c,0);
 }
 c=fixture(9);c.st[0].arg0=8;c.st[0].arg1=4096;c.nr_stages=2;
 c.st[1]=(S){.class_id=3,.direction=TO,.fd=7};create("CPU-variable-skips-static-fixed-scan",&c,0);
 c=fixture(10);c.st[0].flags=1;c.nr_stages=2;c.st[1]=(S){.class_id=3,.direction=TO,.fd=7};
 create("USER-variable-scans-fixed",&c,-EOPNOTSUPP);
}

static void extension(void)
{
 unsigned id; C c; D row; const D *rows[4];
 for(id=2;id<=11;id++) {
  snprintf(context,sizeof(context),"extension row=%u class_id=77",id);
  c=fixture(id);rows_for(&c,rows);row=*rows[0];rows[0]=&row;c.st[0].class_id=77;
  create_rows("explicit-row-CREATE",&c,rows,0);
  EQ("explicit-row-role",test_role(&row,&c.st[0]),id==4?4:(id==9||id==10?3:2));
  EQ("explicit-row-PREPARE",test_ret(&row,77,1,4,-1),1);
  EQ("explicit-row-BUILD",test_ret(&row,77,2,0,1),1);
  EQ("explicit-row-template",test_start(c.st,rows,c.nr_stages),id==4?-EOPNOTSUPP:0);
  c.st[0].fd=-2;create_rows("remapped-fd-rule",&c,rows,id==9?-EINVAL:-EBADF);
  c.st[0].fd=id==9?-1:7;c.st[0].flags=1U<<24;
  create_rows("remapped-flag-rule",&c,rows,-EINVAL);
 }
 /* Rebind both the length-changing stage and its follower. This catches a
  * hidden class-id scan after otherwise correct declaration dispatch. */
 c=fixture(9);c.st[0].arg0=1;c.nr_stages=2;c.st[0].class_id=77;
 c.st[1]=(S){.class_id=78,.direction=TO,.fd=7};
 rows[0]=xdev_ext_mech_class_desc(9);rows[1]=xdev_ext_mech_class_desc(3);
 snprintf(context,sizeof(context),"extension remapped-followers");
 create_rows("remapped-fixed-follower",&c,rows,-EOPNOTSUPP);
 c.nr_stages=3;c.st[2]=c.st[1];rows[2]=rows[1];
 c.st[1].class_id=79;rows[1]=xdev_ext_mech_class_desc(4);
 create_rows("remapped-transform-stops-scan",&c,rows,0);
 c=fixture(10);c.st[0].class_id=77;c.st[0].flags=1;c.nr_stages=2;
 c.st[1]=(S){.class_id=78,.direction=TO,.fd=7};
 rows[0]=xdev_ext_mech_class_desc(10);rows[1]=xdev_ext_mech_class_desc(2);
 create_rows("remapped-USER-varlen-fixed",&c,rows,-EOPNOTSUPP);
 EQ("remapped-USER-varlen-template",test_start(c.st,rows,2),-EOPNOTSUPP);
 snprintf(context,sizeof(context),"extension same-id different-row");
 c=fixture(3);c.st[0].class_id=77;rows_for(&c,rows);
 rows[0]=xdev_ext_mech_class_desc(3);create_rows("NVMe-row",&c,rows,0);
 rows[0]=xdev_ext_mech_class_desc(8);create_rows("NET-row-enforces-peer-only",&c,rows,-EOPNOTSUPP);
 c=fixture(3);c.st[0].class_id=77;c.st[0].direction=FROM;
 EQ("IAA-row-overrides-direction-role",test_role(xdev_ext_mech_class_desc(4),&c.st[0]),4);
 EQ("NVMe-row-direction-role",test_role(xdev_ext_mech_class_desc(3),&c.st[0]),1);
 EQ("NVMe-row-retry",test_retry(xdev_ext_mech_class_desc(3),77,0,1),1);
 EQ("IAA-row-no-retry",test_retry(xdev_ext_mech_class_desc(4),77,0,1),0);
}

#ifdef CLASS_DECLARATIONS_DESC
/* New row interface edge cases have no baseline entry and are not the RED
 * proof. Candidate-only tests exercise actual production _desc functions. */
static void descriptor_bases(void)
{
 unsigned id,dir,native;
 for(id=2;id<=11;id++) for(dir=1;dir<=2;dir++) for(native=0;native<=1;native++) {
  const D *d=xdev_ext_mech_class_desc(id);
  struct xdev_ext_binding_ctx_v2 b=xdev_ext_mech_base_desc(d,dir,native?16:0,12345);
  snprintf(context,sizeof(context),"base id=%u dir=%u native=%u",id,dir,native);
  EQ("base-ABI",b.abi_version,2);EQ("base-size",b.ctx_size,sizeof(b));
  EQ("base-direction",b.direction,dir);EQ("base-length",b.length,12345);
  EQ("base-request-id",b.request_id,0);EQ("base-chain-id",b.chain_id,0);
  EQ("base-source-offset",b.src_offset,0);EQ("base-destination-offset",b.dst_offset,0);
  EQ("base-logical-offset",b.logical_offset,0);EQ("base-bytes-done",b.bytes_done,0);
  if(id==2) { EQ("AFXDP-backend",b.backend,2); EQ("AFXDP-stage",b.current_stage,dir==1?9:12); }
  else if(id==3) {EQ("NVMe-backend",b.backend,3);EQ("NVMe-stage",b.current_stage,dir==1?8:7);}
  else if(id==5) {EQ("GPU-backend",b.backend,5);EQ("GPU-stage",b.current_stage,3);}
  else {
   struct xdev_ext_binding_ctx_v2 common={.abi_version=2,.ctx_size=sizeof(b),.direction=dir,.length=12345};
   EQ("COMMON-exact",memcmp(&b,&common,sizeof(b)),0);
  }
 }
}
static void descriptor_edges(void)
{
 C c=fixture(3); D none={0}; const D *rows[4]; unsigned i,id;
 snprintf(context,sizeof(context),"descriptor-null-none");
 for(i=0;i<2;i++) {
  const D *d=i?&none:NULL; bool illegal=false;
  EQ("ret-reject",test_ret(d,3,2,0,1),0);
  EQ("retry-reject",test_retry(d,3,0,1),0);
  EQ("role-reject",test_role(d,&c.st[0]),-EINVAL);
  EQ("resolve-reject",test_resolve(d,3,2,0,1,&illegal),2);EQ("resolve-illegal",illegal,1);
  EQ("info-even-equal-reject",xdev_ext_mech_info_view_ok_desc(d,32,32),0);
  rows_for(&c,rows);rows[0]=d;create_rows("CREATE-reject",&c,rows,-EINVAL);
  c.pool_kind=1;c.pool_fd=-1;create_rows("pool-error-before-null-row",&c,rows,-EBADF);c.pool_kind=2;
  c.st[0].flags=XDEV_EXT_MECH_STAGE_F_FANOUT;create_rows("fanout-before-null-row",&c,rows,-EINVAL);c.st[0].flags=0;
  struct xdev_ext_binding_ctx_v2 b=xdev_ext_mech_base_desc(d,TO,UINT_MAX,4096),zero={0};
  EQ("base-zero",memcmp(&b,&zero,sizeof(b)),0);
 }
 for(id=2;id<=11;id++) {
  const D *d=xdev_ext_mech_class_desc(id);
  snprintf(context,sizeof(context),"descriptor-metadata id=%u",id);
  EQ("mech-ABI",d->mech_abi_version,(id==5||id==6)?2:1);
  EQ("fixed-group",d->fixed_group,id==2||id==3);
  EQ("rx-source",d->rx_source,id==2);
  EQ("fifo-from-device",d->fifo_from_device,id==7);
  EQ("compute-worker",d->compute_worker,id==9);
  EQ("external-async-permission",d->external_async_flag,id==10?2:0);
  EQ("role-callback-present",d->role!=NULL,1);
  EQ("stage-callback-present",d->check_stage!=NULL,1);
  EQ("base-callback-present",d->base!=NULL,1);
  EQ("info-equal",xdev_ext_mech_info_view_ok_desc(d,117,117),1);
  EQ("info-no-arbitrary-prefix",xdev_ext_mech_info_view_ok_desc(d,117,116),0);
  EQ("AF-XDP-v1-prefix-only",xdev_ext_mech_info_view_ok_desc(d,
   sizeof(struct xdev_ext_afxdp_reliable_info),sizeof(struct xdev_ext_afxdp_mech_info)),id==2);
  EQ("AF-XDP-neighbor-prefix-reject",xdev_ext_mech_info_view_ok_desc(d,
   sizeof(struct xdev_ext_afxdp_reliable_info),sizeof(struct xdev_ext_afxdp_mech_info)-1),0);
 }
 rows_for(&c,rows);rows[1]=NULL;rows[2]=&none;rows[3]=NULL;
 create_rows("inactive-rows-ignored",&c,rows,0);
 /* Literal artificial policy rows test RANGE and SET interpretation. Callback
  * bodies remain production; these records are the interface's input data. */
 const struct xdev_ext_mech_ret_rule rr[]={
  {.member=2,.callsite=3,.kind=XDEV_EXT_MECH_RET_RANGE,.min=-2,.max=1},
  {.member=3,.callsite=5,.kind=XDEV_EXT_MECH_RET_SET,.values=(1U<<0)|(1U<<31)},
  {.member=4,.callsite=0,.kind=999,.min=INT_MIN,.max=INT_MAX,.values=UINT_MAX},
 };
 D custom=*xdev_ext_mech_class_desc(3);custom.ret_rules=rr;custom.nr_ret_rules=3;
 snprintf(context,sizeof(context),"descriptor-ret-rules");
 EQ("range-low",test_ret(&custom,77,2,3,-2),1);EQ("range-high",test_ret(&custom,77,2,3,1),1);
 EQ("range-below",test_ret(&custom,77,2,3,-3),0);EQ("range-above",test_ret(&custom,77,2,3,2),0);
 EQ("set-negative",test_ret(&custom,77,3,5,-1),0);EQ("set-zero",test_ret(&custom,77,3,5,0),1);
 EQ("set-gap",test_ret(&custom,77,3,5,1),0);EQ("set-high",test_ret(&custom,77,3,5,31),1);
 EQ("set-32",test_ret(&custom,77,3,5,32),0);EQ("set-min-int",test_ret(&custom,77,3,5,INT_MIN),0);
 EQ("wrong-site",test_ret(&custom,77,3,0,0),0);EQ("wrong-member",test_ret(&custom,77,1,5,0),0);
 EQ("bad-kind",test_ret(&custom,77,4,0,0),0);
 const struct xdev_ext_mech_info_view iv[]={{128,64},{200,80}};
 custom.info_views=iv;custom.nr_info_views=2;
 EQ("info-exact-pair",xdev_ext_mech_info_view_ok_desc(&custom,128,64),1);
 EQ("info-other-exact-pair",xdev_ext_mech_info_view_ok_desc(&custom,200,80),1);
 EQ("info-mixed-pair",xdev_ext_mech_info_view_ok_desc(&custom,128,80),0);
 EQ("info-short-prefix",xdev_ext_mech_info_view_ok_desc(&custom,128,63),0);
 EQ("info-allocated-mismatch",xdev_ext_mech_info_view_ok_desc(&custom,129,64),0);
 EQ("info-identity",xdev_ext_mech_info_view_ok_desc(&custom,63,63),1);
}
#endif

/* Independent block-v2 literals frozen before editing in maintenance PLAN.md.
 * Keep the historical masks above unchanged: bit12 is not a v1 known class. */
#ifdef CLASS_DECLARATIONS_BLOCK_V2
static const D block_expected={
 .family=2, .peer_dirs=0, .known_flags=0,
 .peer_only=0, .flags_later=0, .role_rule=1, .ctx_rule=4, .no_file=0,
 .mech_abi_version=1, .fixed_group=true, .rx_source=false,
 .fifo_from_device=false, .compute_worker=false, .external_async_flag=0,
};
static bool block_golden_ret(unsigned member,unsigned site,int ret)
{
 if(member==1 && site==4) return ret>=-4095 && ret<=0;
 if(member==2 && site==0) return ret>=0 && ret<=2;
 if(member==3 && site==0) return ret>=0 && ret<=3;
 return false;
}
static void block_returns(void)
{
 static const int values[]={INT_MIN,-4096,-4095,-2,-1,0,1,2,3,4,5,6,7,31,32,INT_MAX};
 const D *d=xdev_ext_mech_class_desc(12);
 size_t v; unsigned m,s;
 for(m=0;m<=5;m++) for(s=0;s<=8;s++) for(v=0;v<sizeof(values)/sizeof(*values);v++) {
  int r=values[v],want; bool legal=block_golden_ret(m,s,r),illegal=legal;
  snprintf(context,sizeof(context),"block-v2 ret id=12 member=%u site=%u ret=%d",m,s,r);
  EQ("legality",test_ret(d,12,m,s,r),legal);
  if(legal) want=r;
  else if(m==2) want=2;
  else if(m==3 && s==5) want=6;
  else if(m==3 && (s==1 || s==2)) want=5;
  else if(m==3) want=3;
  else want=-EPROTO;
  EQ("replacement",test_resolve(d,12,m,s,r,&illegal),want);
  EQ("illegal-indication",illegal,!legal);
 }
}
static void block_declaration(void)
{
 const D *d=xdev_ext_mech_class_desc(12);
 static const unsigned unknown[]={13,77,UINT_MAX};
 static const int statuses[]={INT_MIN,-EAGAIN,-EIO,0,1,2,3,0x4001,INT_MAX};
 static const unsigned counts[]={0,1,2,3,4,UINT_MAX};
 C c; size_t i,j; unsigned dir; int err;
 snprintf(context,sizeof(context),"block-v2 literal-row");
 EQ("BLOCK-id",XDEV_EXT_MECH_CLASS_BLOCK,12);
 EQ("MAX",XDEV_EXT_MECH_CLASS_MAX,13);
 EQ("family",d->family,block_expected.family);
 EQ("peer-dirs",d->peer_dirs,block_expected.peer_dirs);
 EQ("known-flags",d->known_flags,block_expected.known_flags);
 EQ("peer-only",d->peer_only,block_expected.peer_only);
 EQ("flags-later",d->flags_later,block_expected.flags_later);
 EQ("direction-rule",d->role_rule,block_expected.role_rule);
 EQ("COMMON-context",d->ctx_rule,block_expected.ctx_rule);
 EQ("requires-file",d->no_file,block_expected.no_file);
 EQ("mech-ABI",d->mech_abi_version,block_expected.mech_abi_version);
 EQ("fixed-group",d->fixed_group,block_expected.fixed_group);
 EQ("no-rx-source",d->rx_source,block_expected.rx_source);
 EQ("no-fifo-from-device",d->fifo_from_device,block_expected.fifo_from_device);
 EQ("no-compute-worker",d->compute_worker,block_expected.compute_worker);
 EQ("no-external-async",d->external_async_flag,block_expected.external_async_flag);
 EQ("role-callback",d->role!=NULL,1);
 EQ("file-check-callback",d->check_stage!=NULL,1);
 EQ("COMMON-base-callback",d->base!=NULL,1);
 EQ("no-retry-callback",d->retry_ok==NULL,1);
 for(dir=1;dir<=2;dir++) {
  snprintf(context,sizeof(context),"block-v2 CREATE direction=%u",dir);
  c=fixture(12);c.st[0].direction=dir;
  create("HOST-valid",&c,0);start("fixed-template",&c,0);
  EQ("direction-role",test_role(d,&c.st[0]),dir==1?2:1);
  c.st[0].fd=-1;create("requires-file",&c,-EBADF);
  c.st[0].fd=-2;create("negative-file",&c,-EBADF);
  c.st[0].fd=7;c.st[0].flags=1;create("no-class-flags",&c,-EINVAL);
  c.st[0].flags=1U<<24;create("unknown-class-flags",&c,-EINVAL);
  /* Pure CREATE strips the common flag. Native POLL capability is a separate
   * root-owned bind gate; this assertion does not grant it to BLOCK. */
  c.st[0].flags=XDEV_EXT_MECH_STAGE_F_POLL;create("common-POLL-stripping",&c,0);
  c.st[0].flags=0;c.pool_kind=3;c.pool_fd=6;
  create("no-PEER",&c,-EOPNOTSUPP);
  c.st[0].fd=-2;create("fd-before-final-PEER",&c,-EBADF);
 }
 c=fixture(12);c.st[0].direction=0;create("invalid-direction",&c,-EINVAL);
 for(i=0;i<sizeof(unknown)/sizeof(*unknown);i++) {
  snprintf(context,sizeof(context),"block-v2 unknown=%u",unknown[i]);
  EQ("NONE-family",xdev_ext_mech_class_desc(unknown[i])->family,0);
  c=fixture(unknown[i]);create("unknown-CREATE",&c,-EINVAL);
 }
 for(i=0;i<sizeof(counts)/sizeof(*counts);i++) for(j=0;j<sizeof(statuses)/sizeof(*statuses);j++) {
  snprintf(context,sizeof(context),"block-v2 no-retry count=%u status=%d",counts[i],statuses[j]);
  EQ("no-retry",test_retry(d,12,counts[i],statuses[j]),0);
 }
 for(i=0;i<2;i++) {
  c=fixture(i?10:9);c.st[0].arg0=1;if(i)c.st[0].flags=1;
  c.nr_stages=2;c.st[1]=(S){.class_id=12,.direction=TO,.fd=7};
  snprintf(context,sizeof(context),"block-v2 fixed-follower predecessor=%u",c.st[0].class_id);
  create("length-change-before-BLOCK",&c,-EOPNOTSUPP);
  c.nr_stages=3;c.st[2]=c.st[1];c.st[1]=(S){.class_id=4,.direction=TO,.fd=7};
  create("transform-stops-fixed-scan",&c,0);
 }
 for(i=0;i<3;i++) {
  static const int status[]={0,-EIO,-ENOENT};
  static const int error[]={-ECANCELED,-EIO,-ENOENT};
  err=0;snprintf(context,sizeof(context),"block-v2 COMPLETE RETRY status=%d",status[i]);
  EQ("ABORT-no-resubmit",xdev_ext_mech_complete_step(12,2,status[i],false,false,0,&err),5);
  EQ("original-errno",err,error[i]);
 }
#ifdef CLASS_DECLARATIONS_DESC
 unsigned native;
 for(dir=1;dir<=2;dir++) for(native=0;native<=1;native++) {
  struct xdev_ext_binding_ctx_v2 b=xdev_ext_mech_base_desc(d,dir,native?16:0,12345);
  struct xdev_ext_binding_ctx_v2 expected={.abi_version=2,.ctx_size=sizeof(b),.direction=dir,.length=12345};
  snprintf(context,sizeof(context),"block-v2 COMMON-base direction=%u native=%u",dir,native);
  EQ("COMMON-exact",memcmp(&b,&expected,sizeof(b)),0);
 }
 snprintf(context,sizeof(context),"block-v2 info-view");
 EQ("exact-size",xdev_ext_mech_info_view_ok_desc(d,117,117),1);
 EQ("no-arbitrary-prefix",xdev_ext_mech_info_view_ok_desc(d,117,116),0);
#endif
}
#endif /* CLASS_DECLARATIONS_BLOCK_V2 */
int main(int argc,char **argv)
{
 const char *contract=argc>2?argv[2]:"core-table-v1";
 block_v2=!strcmp(contract,"block-v2");
 if(argc>3 || (!block_v2 && strcmp(contract,"core-table-v1"))) return 2;
#ifndef CLASS_DECLARATIONS_BLOCK_V2
 if(block_v2) return 2;
#endif
 bool legacy=argc<2 || !strcmp(argv[1],"legacy") || !strcmp(argv[1],"all");
 bool ext=argc<2 || !strcmp(argv[1],"extension") || !strcmp(argv[1],"all");
 if(!legacy&&!ext) return 2;
 if(legacy) {returns();retries();completions();per_class();precedence();length_and_start();}
#ifdef CLASS_DECLARATIONS_BLOCK_V2
 if(legacy && block_v2) {block_returns();block_declaration();}
#endif
 if(ext) extension();
#ifdef CLASS_DECLARATIONS_DESC
 if(legacy) { descriptor_edges();descriptor_bases(); }
#endif
 printf("class_declarations assertions=%u failures=%u mode=%s contract=%s\n",checks,failures,argc>1?argv[1]:"all",contract);
 return failures?1:0;
}

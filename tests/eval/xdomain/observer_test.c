/* SPDX-License-Identifier: GPL-2.0 */
/* Independent D observer requirements. Included around the unmodified actual
 * BPF translation unit; only external maps and kfunc metadata are adapted. */
_Static_assert(sizeof(struct tb_xd_observer_cqe) == 64, "copied CQE size");
_Static_assert(sizeof(struct tb_xd_observer_cqe) == sizeof(struct xdev_ext_xdomain_mech_cqe), "public CQE size");
#define CQE_PIN(field, off) \
 _Static_assert(offsetof(struct tb_xd_observer_cqe, field) == off, "copied " #field); \
 _Static_assert(offsetof(struct xdev_ext_xdomain_mech_cqe, field) == off, "public " #field); \
 _Static_assert(sizeof(((struct tb_xd_observer_cqe *)0)->field) == \
                sizeof(((struct xdev_ext_xdomain_mech_cqe *)0)->field), "width " #field)
CQE_PIN(status, 0); CQE_PIN(outcome, 4); CQE_PIN(remote, 8); CQE_PIN(elems_done, 12);
CQE_PIN(group, 16); CQE_PIN(bytes, 24); CQE_PIN(crc_errors, 32);
CQE_PIN(rsvd, 36); CQE_PIN(tag, 40);
#undef CQE_PIN

static struct tb_xd_observer_config observer_cfg;
static struct tb_xd_observer_record observer_rec[TB_XD_OBSERVER_MAX_GROUPS];
static struct tb_xd_observer_errors observer_errors;
static const struct xdev_ext_mech_ctx *observer_active;
static unsigned observer_lookups;
static int observer_parity, missing_cfg, missing_rec, missing_err;
static unsigned noop_build_calls, noop_cqe_calls;
static int observer_noop_build(const struct xdev_ext_mech_ctx *c,
                               const struct xdev_ext_xdomain_mech_info *info)
{
 assert(c->callsite != XDEV_EXT_MECH_SITE_WORKER_PROTOCOL);
 assert(info == &build_info && info->nr_frames > 0);
 for(unsigned i=0;i<info->nr_frames;i++) {
  /* A hook in the descriptor loop, before later slots are built, fails. */
  assert(descriptors[i].frame_pos==i && descriptors[i].frame_off==info->f[i].data_off);
  assert(descriptors[i].len==info->f[i].data_len);
 }
 noop_build_calls++;
 return 0;
}
static int observer_noop_cqe(const struct xdev_ext_mech_ctx *c,
                             const struct xdev_ext_xdomain_mech_cqe *q)
{
 assert(c->callsite==XDEV_EXT_MECH_SITE_WORKER);
 assert(q==&final_cqe && !no_cqe && cqe_calls>0);
 noop_cqe_calls++;
 return 0;
}

#if OBS_WRAPPER && !OBS_SYNTAX
static int observer_interleave_armed;
static void observer_interleaved_failure(void);
/* Keep the real atomic operation and schedule a second actual observer after
 * ownership release, before this callback makes its final return decision.
 * This is a host scheduler seam, not a replacement observer implementation. */
#define __sync_val_compare_and_swap(p, old, val) ({ \
 __typeof__(*(p)) observer_previous=__sync_val_compare_and_swap((p),(old),(val)); \
 if(observer_interleave_armed && (void *)(p)==(void *)&observer_rec[0].cqe_seen && \
    (old)==0x80000000U && ((val)==0 || (val)==1)) { \
  observer_interleave_armed=0; observer_interleaved_failure(); \
 } observer_previous; })
#endif

/* @ACTUAL_SOURCE@ */

#if OBS_WRAPPER && !OBS_SYNTAX
#undef __sync_val_compare_and_swap
#endif

static void *bpf_map_lookup_elem(const void *map, const void *key)
{
 const __u32 index = *(const __u32 *)key;
 (void)map; (void)index;
 assert(observer_active);
 /* Every lookup is prohibited at the sealed protocol boundary, including
  * config/error maps and lookups before the private-info kfunc call. */
 assert(observer_active->callsite != XDEV_EXT_MECH_SITE_WORKER_PROTOCOL);
 observer_lookups++;
#if OBS_WRAPPER
 if (map == &xd_check_cfg) return !index && !missing_cfg ? &observer_cfg : NULL;
 if (map == &xd_check_rec)
  return index < TB_XD_OBSERVER_MAX_GROUPS && !missing_rec ? &observer_rec[index] : NULL;
 if (map == &xd_check_err) return !index && !missing_err ? &observer_errors : NULL;
#endif
 assert(!"unknown observer map");
 return NULL;
}

static void observer_seed_record(struct tb_xd_observer_record *r,
                                 const struct xdev_ext_mech_ctx *c)
{
 memset(r, 0, sizeof(*r));
 r->size=sizeof(*r); r->version=TB_XD_OBSERVER_VERSION;
 r->session_id=c->session_id; r->batch_id=c->batch_id; r->key=c->base.src_offset;
 r->epoch=observer_cfg.epoch; r->generation=build_info.generation;
 r->local_inc=build_info.local_inc; r->remote_inc=build_info.remote_inc;
 r->direction=c->base.direction; r->channel=build_info.channel;
 r->build_attempts=1;
}
static void observer_setup_config(const struct xdev_ext_mech_ctx *c)
{
 observer_cfg=(struct tb_xd_observer_config){.size=sizeof(observer_cfg),
  .version=TB_XD_OBSERVER_VERSION,.session_id=c->session_id,
  .first_seq=c->base.src_offset,.groups=3,.epoch=93,.allocation_bytes=1048576,
  .direction=c->base.direction,.stage=c->base.current_stage};
}
static int observer_call_build(void *unused, const struct xdev_ext_mech_ctx *c)
{
 struct xdev_ext_mech_ctx active=*c;
 (void)unused;
 if(observer_parity) {
  active.session_id=37; active.batch_id=91;
  observer_setup_config(&active); observer_cfg.allocation_bytes=UINT64_MAX;
  memset(observer_rec,0,sizeof(observer_rec)); memset(&observer_errors,0,sizeof(observer_errors));
 }
 observer_active=&active;
 unsigned hook_before=noop_build_calls;
 int ret=xdomain_peer_build(NULL,&active);
 if(OBS_NOOP && OBS_HAS_HOOKS)
  assert(noop_build_calls==hook_before+(ret==XDEV_EXT_MP_BUILD_SUBMIT));
 observer_active=NULL;
 return ret;
}
static int observer_call_complete(void *unused, const struct xdev_ext_mech_ctx *c)
{
 struct xdev_ext_mech_ctx active=*c;
 (void)unused;
 if(observer_parity && c->callsite != XDEV_EXT_MECH_SITE_WORKER_PROTOCOL) {
  active.session_id=37; active.batch_id=91;
  observer_setup_config(&active); observer_cfg.allocation_bytes=UINT64_MAX;
  memset(observer_rec,0,sizeof(observer_rec)); memset(&observer_errors,0,sizeof(observer_errors));
  /* The historical CQE-only cases have no BUILD step. Seed only external
   * ARRAY history to isolate final policy equivalence; dedicated cases below
   * execute real BUILD and assert the observer-created record. */
  observer_seed_record(&observer_rec[0],&active);
 }
 observer_active=&active;
 unsigned before=observer_lookups, hook_before=noop_cqe_calls;
 int ret=xdomain_peer_complete(NULL,&active);
 if(OBS_NOOP && OBS_HAS_HOOKS)
  assert(noop_cqe_calls==hook_before+
   (active.callsite==XDEV_EXT_MECH_SITE_WORKER && !no_cqe));
 if(c->callsite == XDEV_EXT_MECH_SITE_WORKER_PROTOCOL) assert(before==observer_lookups);
 observer_active=NULL;
 return ret;
}
#define xdomain_peer_build observer_call_build
#define xdomain_peer_complete observer_call_complete

/* @LEGACY_CASES@ */

#undef xdomain_peer_build
#undef xdomain_peer_complete
#define REQUIRE(test) do { if (!(test)) { \
 fprintf(stderr,"OBSERVER FAIL %s:%u: %s\n",__func__,__LINE__,#test); assert(test); } } while(0)
static struct xdev_ext_mech_ctx observer_context(void)
{
 struct xdev_ext_mech_ctx c={0};
 c.session_id=37; c.batch_id=71; c.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN;
 c.member=XDEV_EXT_MECH_MEMBER_BUILD; c.callsite=XDEV_EXT_MECH_SITE_WORKER;
 c.base.current_stage=1; c.base.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;
 c.base.src_offset=0x0102030405060708ULL; c.base.length=12288;
 c.nr_frames=2; c.desc_cap=2;
 return c;
}
static struct xdev_ext_mech_ctx observer_reset(void)
{
 struct xdev_ext_mech_ctx c=observer_context();
 observer_parity=0; missing_cfg=missing_rec=missing_err=0;
 observer_lookups=0; no_build_info=no_cqe=0; no_desc_at=-1;
 memset(observer_rec,0,sizeof(observer_rec)); memset(&observer_errors,0,sizeof(observer_errors));
 memset(descriptors,0,sizeof(descriptors)); memset(&build_info,0,sizeof(build_info));
 observer_setup_config(&c);
 build_info.generation=7; build_info.local_inc=11; build_info.remote_inc=13;
 build_info.direction=1; build_info.channel=5; build_info.nr_frames=2;
 build_info.next_group=19; build_info.max_frame=4096; build_info.max_elems=64;
 /* Deliberately noncontiguous, in reverse order in the allocation. */
 build_info.f[0]=(struct xdev_ext_mech_frame_info){.umem_addr=131072,.data_off=4096,.data_len=8192};
 build_info.f[1]=(struct xdev_ext_mech_frame_info){.umem_addr=16384,.data_off=8192,.data_len=4096};
 memset(&final_cqe,0,sizeof(final_cqe));
 final_cqe.group=19; final_cqe.bytes=12288; final_cqe.elems_done=3;
 final_cqe.remote=XDEV_EXT_NET_REMOTE_ACKED;
 for(unsigned i=0;i<24;i++) final_cqe.tag[i]=(unsigned char)(0xa0+i);
 return c;
}
static int build_call(struct xdev_ext_mech_ctx *c)
{ return observer_call_build(NULL,c); }
static int complete_call(struct xdev_ext_mech_ctx *c)
{ c->member=XDEV_EXT_MECH_MEMBER_COMPLETE; return observer_call_complete(NULL,c); }
static void error_expected(__u32 bit, int valid_index)
{
 REQUIRE((observer_errors.error_bits & bit)==bit);
 REQUIRE(observer_errors.observations_lost>=1);
 if(valid_index) REQUIRE((observer_rec[0].error_bits & bit)==bit);
}
static void observer_ok(const char *name)
{ printf("observer ok - %s\n",name); }

static void positive_records(void)
{
 struct xdev_ext_mech_ctx c=observer_reset();
 const unsigned char tag[24]={1,2,3,4,5,6,7,8};
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 struct tb_xd_observer_record *r=&observer_rec[0];
 REQUIRE(r->size==sizeof(*r) && r->version==1);
 REQUIRE(r->session_id==37 && r->batch_id==71 && r->key==c.base.src_offset && r->epoch==93);
 REQUIRE(r->generation==7 && r->local_inc==11 && r->remote_inc==13);
 REQUIRE(r->direction==1 && r->channel==5 && r->build_attempts==1 && !r->cqe_seen && !r->error_bits);
 REQUIRE(r->nr_spans==2);
 REQUIRE(r->spans[0].allocation_off==131072 && r->spans[0].data_off==4096 && r->spans[0].len==8192);
 REQUIRE(r->spans[1].allocation_off==16384 && r->spans[1].data_off==8192 && r->spans[1].len==4096);
 REQUIRE(!memcmp(r->tag,tag,24));
 REQUIRE(!memcmp(r->tag,descriptors[0].tag,24));
 REQUIRE(all_zero(&r->completion,sizeof(r->completion)));
 REQUIRE(!observer_errors.error_bits && !observer_errors.observations_lost);
 observer_ok("BUILD records full actual noncontiguous descriptor spans and BE8 zero16 tag");
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_NEXT);
 REQUIRE(r->cqe_seen==1 && r->build_attempts==1);
 REQUIRE(!memcmp(&r->completion,&final_cqe,sizeof(final_cqe)));
 REQUIRE(!observer_errors.error_bits && !observer_errors.observations_lost);
 observer_ok("ordinary final CQE exact public 64 bytes copied once");
 c=observer_reset(); c.base.direction=2; build_info.direction=2;
 observer_cfg.direction=2; final_cqe.remote=0;
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 REQUIRE(all_zero(observer_rec[0].tag,24));
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_NEXT);
 REQUIRE(!memcmp(&observer_rec[0].completion,&final_cqe,64));
 observer_ok("RX BUILD tag zero and actual final RX tag retained");
}
static void retry_records(void)
{
 struct xdev_ext_mech_ctx c=observer_reset();
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 build_info.f[0].umem_addr=262144; build_info.f[1].data_off=12288;
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 REQUIRE(observer_rec[0].build_attempts==2 && observer_rec[0].nr_spans==2);
 REQUIRE(observer_rec[0].spans[0].allocation_off==262144 && observer_rec[0].spans[1].data_off==12288);
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_NEXT);
 REQUIRE(observer_rec[0].build_attempts==2 && observer_rec[0].cqe_seen==1);
 observer_ok("preaccept retry increments attempts and replaces latest plan");
 c=observer_reset(); c.base.src_offset+=2;
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 REQUIRE(observer_rec[2].key==c.base.src_offset && observer_rec[2].build_attempts==1);
 REQUIRE(!observer_rec[0].build_attempts && !observer_rec[1].build_attempts && !observer_rec[3].build_attempts);
 observer_ok("ordinal is key minus first_seq with no extra records");
 c=observer_reset(); observer_cfg.groups=10000; c.base.src_offset+=9999;
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 REQUIRE(observer_rec[9999].key==c.base.src_offset && observer_rec[9999].build_attempts==1);
 REQUIRE(!observer_rec[0].build_attempts);
 observer_ok("last legal ARRAY ordinal 9999 is recorded without aliasing zero");
 c=observer_reset(); c.nr_frames=32; c.desc_cap=32; build_info.nr_frames=32;
 c.base.length=32*4096;
 for(unsigned i=0;i<32;i++)
  build_info.f[i]=(struct xdev_ext_mech_frame_info){.umem_addr=524288-i*8192,.data_off=4096,.data_len=4096};
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 REQUIRE(observer_rec[0].nr_spans==32);
 for(unsigned i=0;i<32;i++) {
  REQUIRE(observer_rec[0].spans[i].allocation_off==524288-i*8192);
  REQUIRE(observer_rec[0].spans[i].data_off==4096 && observer_rec[0].spans[i].len==4096);
 }
 REQUIRE(all_zero(&observer_rec[0].spans[32],32*sizeof(observer_rec[0].spans[0])));
 observer_ok("all 32 source-admissible spans retained and unused observer spans zero");
}
static void config_errors(void)
{
 for(unsigned n=0;n<12;n++) {
  struct xdev_ext_mech_ctx c=observer_reset();
  switch(n) {
  case 0: observer_cfg.size--; break;
  case 1: observer_cfg.version++; break;
  case 2: observer_cfg.session_id++; break;
  case 3: observer_cfg.stage=0; break;
  case 4: observer_cfg.direction=2; break;
  case 5: observer_cfg.groups=0; break;
  case 6: observer_cfg.groups=10001; break;
  case 7: observer_cfg.allocation_bytes=0; break;
  case 8: observer_cfg.first_seq=UINT64_MAX; observer_cfg.groups=2; break;
  case 9: missing_cfg=1; break;
  case 10: c.base.current_stage=2; break;
  case 11: c.session_id++; break;
  }
  REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
  error_expected(TB_XD_OBS_ERR_CONFIG,0);
 }
 observer_ok("config size version session stage current_stage direction groups allocation firstseq validated");
}
static void identity_and_order_errors(void)
{
 struct xdev_ext_mech_ctx c=observer_reset();
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT); c.batch_id++;
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
 error_expected(TB_XD_OBS_ERR_IDENTITY,1);
 observer_ok("changed batch identity cannot overwrite existing ordinal");
 c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_NEXT);
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
 error_expected(TB_XD_OBS_ERR_BUILD_AFTER_CQE,1);
 REQUIRE(observer_rec[0].cqe_seen==1);
 observer_ok("post-CQE BUILD aborts and latches durable error");
 c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_NEXT);
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_ABORT);
 error_expected(TB_XD_OBS_ERR_DUP_CQE,1);
 REQUIRE(observer_rec[0].cqe_seen==1);
 observer_ok("duplicate final CQE aborts without wrapping or replacing completion");
 c=observer_reset(); REQUIRE(complete_call(&c)==XDEV_EXT_MP_ABORT);
 error_expected(TB_XD_OBS_ERR_MISSING_BUILD,1);
 observer_ok("missing BUILD final observation is never accepted");
 c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT); c.batch_id++;
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_ABORT);
 error_expected(TB_XD_OBS_ERR_IDENTITY,1);
 observer_ok("CQE batch identity checked independently of successful status");
 for(unsigned n=0;n<3;n++) {
  c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
  if(n==0)observer_cfg.session_id++;
  if(n==1)observer_cfg.stage++;
  if(n==2)c.base.current_stage++;
  REQUIRE(complete_call(&c)==XDEV_EXT_MP_ABORT);
  error_expected(TB_XD_OBS_ERR_CONFIG,0);
 }
 observer_ok("final CQE independently validates config session and actual stage");
}
static void key_and_map_errors(void)
{
 for(unsigned n=0;n<4;n++) {
  struct xdev_ext_mech_ctx c=observer_reset();
  if(n==0)c.base.src_offset--;
  if(n==1)c.base.src_offset+=3;
  if(n==2)c.base.src_offset=UINT64_MAX;
  if(n==3)missing_rec=1;
  REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
  REQUIRE(observer_errors.error_bits && observer_errors.observations_lost==1);
  if(n<3)REQUIRE(observer_errors.error_bits & TB_XD_OBS_ERR_KEY);
  REQUIRE(!observer_rec[0].build_attempts && !observer_rec[1].build_attempts);
 }
 observer_ok("out-of-range key and absent ARRAY record preserve global lost/error truth");
 struct xdev_ext_mech_ctx invalid=observer_reset(); invalid.base.src_offset--;
 REQUIRE(build_call(&invalid)==XDEV_EXT_MP_BUILD_ABORT);
 REQUIRE(build_call(&invalid)==XDEV_EXT_MP_BUILD_ABORT);
 REQUIRE(complete_call(&invalid)==XDEV_EXT_MP_ABORT);
 REQUIRE(observer_errors.observations_lost==3 && (observer_errors.error_bits & TB_XD_OBS_ERR_KEY));
 observer_ok("each unaddressable BUILD or CQE attempt increments global loss exactly once");
 struct xdev_ext_mech_ctx c=observer_reset();
 missing_err=1;
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
 observer_ok("absent error ARRAY fails closed");
}
static void overflow_errors(void)
{
 struct xdev_ext_mech_ctx c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 observer_rec[0].build_attempts=UINT32_MAX;
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
 error_expected(TB_XD_OBS_ERR_OVERFLOW,1);
 REQUIRE(observer_rec[0].build_attempts==UINT32_MAX);
 observer_ok("BUILD attempt overflow aborts and saturates");
 c=observer_reset(); observer_errors.observations_lost=UINT64_MAX;
 observer_cfg.version++;
 REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
 REQUIRE(observer_errors.observations_lost==UINT64_MAX && observer_errors.error_bits);
 observer_ok("global lost attempts saturate rather than wrap to zero");
 c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 observer_rec[0].cqe_seen=UINT32_MAX;
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_ABORT);
 REQUIRE(observer_rec[0].cqe_seen==UINT32_MAX && observer_errors.error_bits);
 observer_ok("corrupt maximum CQE count cannot wrap or advance");
}
static void bad_plan_errors(void)
{
 for(unsigned n=0;n<4;n++) {
  struct xdev_ext_mech_ctx c=observer_reset();
  if(n==0)build_info.f[0].umem_addr=1048576;
  if(n==1)build_info.f[0].umem_addr=UINT64_MAX-4095;
  if(n==2)observer_cfg.allocation_bytes=131072+4096+8191;
  if(n==3)build_info.f[1].umem_addr=UINT64_MAX;
  REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
  error_expected(TB_XD_OBS_ERR_PLAN,1);
 }
 observer_ok("descriptor spans outside root allocation and addition overflow abort");
 for(unsigned n=0;n<4;n++) {
  struct xdev_ext_mech_ctx c=observer_reset();
  if(n==0)build_info.f[0].data_len=0;
  if(n==1)build_info.nr_frames=0;
  if(n==2)build_info.nr_frames=33;
  if(n==3)build_info.f[0].data_off=1;
  REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
  REQUIRE(!observer_rec[0].build_attempts && !observer_rec[0].cqe_seen);
 }
 observer_ok("source-rejected nonpositive/misaligned/malformed plan never observed as BUILD");
}
static void failed_cqe_records(void)
{
 for(unsigned n=0;n<5;n++) {
  struct xdev_ext_mech_ctx c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
  if(n==0)final_cqe.status=-EIO;
  if(n==1)final_cqe.status=1;
  if(n==2)final_cqe.outcome=2;
  if(n==3)final_cqe.bytes--;
  if(n==4)final_cqe.remote=XDEV_EXT_NET_REMOTE_FAILED;
  final_cqe.crc_errors=3; final_cqe.rsvd=0xface;
  REQUIRE(complete_call(&c)==XDEV_EXT_MP_ABORT);
  REQUIRE(observer_rec[0].cqe_seen==1);
  REQUIRE(!memcmp(&observer_rec[0].completion,&final_cqe,64));
 }
 observer_ok("failed CQE copied before status outcome bytes remote policy rejection");
 struct xdev_ext_mech_ctx c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 no_cqe=1; unsigned before=observer_lookups;
 REQUIRE(complete_call(&c)==XDEV_EXT_MP_ABORT);
 REQUIRE(!observer_rec[0].cqe_seen && before==observer_lookups);
 observer_ok("NULL CQE aborts without manufacturing observation");
}
static void latch_errors(void)
{
 struct xdev_ext_mech_ctx c=observer_reset(); REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
 c.batch_id++; REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_ABORT);
 __u64 bits=observer_errors.error_bits, lost=observer_errors.observations_lost;
 c.batch_id--; REQUIRE(complete_call(&c)==XDEV_EXT_MP_ABORT);
 REQUIRE((observer_errors.error_bits & bits)==bits && observer_errors.observations_lost>=lost);
 REQUIRE(observer_rec[0].error_bits & TB_XD_OBS_ERR_IDENTITY);
 observer_ok("latched record errors cannot be healed by later valid final CQE");
}
static void sticky_global_loss_records(void)
{
 struct sticky_result {
  int invalid_build, valid_build, valid_cqe;
  __u64 lost[3], global_bits[3], record_bits[2];
 } actual[2]={0};
 for(unsigned n=0;n<2;n++) {
  struct xdev_ext_mech_ctx c=observer_reset(), invalid=c;
  struct sticky_result *a=&actual[n];
  /* The first error has no record. Later inputs address a previously untouched
   * record, so an early return on the global latch must not hide their loss. */
  observer_errors.observations_lost=n ? UINT64_MAX-1 : 0;
  invalid.base.src_offset--;
  a->invalid_build=build_call(&invalid);
  a->lost[0]=observer_errors.observations_lost;
  a->global_bits[0]=observer_errors.error_bits;
  a->valid_build=build_call(&c);
  a->lost[1]=observer_errors.observations_lost;
  a->global_bits[1]=observer_errors.error_bits;
  a->record_bits[0]=observer_rec[0].error_bits;
  a->valid_cqe=complete_call(&c);
  a->lost[2]=observer_errors.observations_lost;
  a->global_bits[2]=observer_errors.error_bits;
  a->record_bits[1]=observer_rec[0].error_bits;
  printf("sticky diagnostic saturated=%u lost=%llu/%llu/%llu record_errors=%llu/%llu\n",
   n,(unsigned long long)a->lost[0],(unsigned long long)a->lost[1],
   (unsigned long long)a->lost[2],(unsigned long long)a->record_bits[0],
   (unsigned long long)a->record_bits[1]);
  REQUIRE(a->invalid_build==XDEV_EXT_MP_BUILD_ABORT);
  REQUIRE(a->valid_build==XDEV_EXT_MP_BUILD_ABORT && a->valid_cqe==XDEV_EXT_MP_ABORT);
  REQUIRE((a->global_bits[0] & TB_XD_OBS_ERR_KEY)!=0);
  REQUIRE((a->global_bits[1] & a->global_bits[0])==a->global_bits[0]);
  REQUIRE((a->global_bits[2] & a->global_bits[1])==a->global_bits[1]);
  REQUIRE(!observer_rec[0].build_attempts && !observer_rec[0].cqe_seen);
  REQUIRE(all_zero(&observer_rec[0].completion,sizeof(observer_rec[0].completion)));
 }
 /* Print both counter paths before failing, preserving evidence for the exact
  * counts and the independent addressable-record latch requirement. */
 fflush(stdout);
 REQUIRE(actual[0].lost[0]==1 && actual[0].lost[1]==2 && actual[0].lost[2]==3);
 REQUIRE(actual[0].record_bits[0]!=0 && actual[0].record_bits[1]!=0);
 REQUIRE((actual[0].record_bits[1] & actual[0].record_bits[0])==actual[0].record_bits[0]);
 observer_ok("sticky global error counts invalid BUILD then valid BUILD and CQE and latches record failure");
 REQUIRE(actual[1].lost[0]==UINT64_MAX && actual[1].lost[1]==UINT64_MAX && actual[1].lost[2]==UINT64_MAX);
 REQUIRE(actual[1].record_bits[0]!=0 && actual[1].record_bits[1]!=0);
 REQUIRE((actual[1].record_bits[1] & actual[1].record_bits[0])==actual[1].record_bits[0]);
 observer_ok("sticky global loss saturates while later addressable BUILD and CQE still latch failure");
}
/* Independent requirement: each failed hook owns one lost observation and
 * latches its own addressable record, even if a different callback caused
 * the global error after the initial check. */
#if OBS_WRAPPER && !OBS_SYNTAX
static void observer_interleaved_failure(void)
{
 struct xdev_ext_mech_ctx foreign=observer_context();
 foreign.session_id=observer_cfg.session_id+1;
 foreign.base.src_offset=observer_cfg.first_seq+1;
 REQUIRE(xd_obs_build(&foreign,&build_info)!=0);
}
static void final_interleaved_errors(void)
{
 struct interleaved_result {
  int ret, armed;
  __u64 lost, global_bits;
  __u32 own_bits, foreign_bits;
 } actual[2]={0};
 for(unsigned final=0;final<2;final++) {
  struct xdev_ext_mech_ctx c=observer_reset();
  struct interleaved_result *a=&actual[final];
  if(final) REQUIRE(build_call(&c)==XDEV_EXT_MP_BUILD_SUBMIT);
  observer_interleave_armed=1;
  a->ret=final ? complete_call(&c) : build_call(&c);
  a->armed=observer_interleave_armed;
  a->lost=observer_errors.observations_lost;
  a->global_bits=observer_errors.error_bits;
  a->own_bits=observer_rec[0].error_bits;
  a->foreign_bits=observer_rec[1].error_bits;
  printf("final interleave %s ret=%d lost=%llu own_error=%u foreign_error=%u global_error=%llu\n",
   final?"CQE":"BUILD",a->ret,(unsigned long long)a->lost,
   a->own_bits,a->foreign_bits,(unsigned long long)a->global_bits);
 }
 fflush(stdout);
 for(unsigned final=0;final<2;final++) {
  const struct interleaved_result *a=&actual[final];
  REQUIRE(!a->armed);
  REQUIRE(a->ret==(final ? XDEV_EXT_MP_ABORT : XDEV_EXT_MP_BUILD_ABORT));
  REQUIRE((a->global_bits & TB_XD_OBS_ERR_CONFIG)!=0);
  REQUIRE((a->foreign_bits & TB_XD_OBS_ERR_CONFIG)!=0);
  REQUIRE(a->lost==2);
  REQUIRE((a->own_bits & TB_XD_OBS_ERR_CONFIG)!=0);
  observer_ok(final ?
   "final CQE rejected by interleaved global error counts its own loss and record error" :
   "BUILD rejected by interleaved global error counts its own loss and record error");
 }
}
#endif
int main(void)
{
 observer_parity=1;
 int result=old_main();
 REQUIRE(tap==67);
 if(result)return result;
#if OBS_WRAPPER && !OBS_SYNTAX
 puts("OBSERVER CASES BEGIN");
 positive_records(); retry_records(); config_errors(); identity_and_order_errors();
 key_and_map_errors(); overflow_errors(); bad_plan_errors(); failed_cqe_records(); latch_errors();
 sticky_global_loss_records();
 final_interleaved_errors();
#endif
 return 0;
}

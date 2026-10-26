// SPDX-License-Identifier: GPL-2.0
/* Requirement: one row holds every class property, preserving main 713327e.
 * The frozen oracle bodies below come from that commit, not the new table.
 * No enum-macro feature guard: a missing descriptor API is an expected RED
 * compile failure; once it exists these checks execute the production rules.
 * Build with -I <kernel>. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "io_uring/xdev_ext_mech_step.h"
#include "include/linux/xdev_ext_family_core.h"

static unsigned int checks, failures;
#define EQ(a, b) do { \
 long long av = (long long)(a), bv = (long long)(b); \
 checks++; \
 if (av != bv) { \
  fprintf(stderr, "%s:%d %s got %lld expected %lld\n", __func__, __LINE__, #a, av, bv); \
  failures++; \
 } \
} while (0)

/* 713327e io_uring/xdev_ext_mech_core.h:658-665, body verbatim. */
static inline bool old_class_known(__u32 class_id)
{
	return class_id == XDEV_EXT_MECH_CLASS_AFXDP ||
	       class_id == XDEV_EXT_MECH_CLASS_NVME || class_id == XDEV_EXT_MECH_CLASS_CE ||
	       class_id == XDEV_EXT_MECH_CLASS_DMA || class_id == XDEV_EXT_MECH_CLASS_IAA ||
	       class_id == XDEV_EXT_MECH_CLASS_CPU || class_id == XDEV_EXT_MECH_CLASS_USER ||
	       class_id == XDEV_EXT_MECH_CLASS_SOCKET || class_id == XDEV_EXT_MECH_CLASS_NET;
}

/* 713327e io_uring/xdev_ext_mech_step.h:43-64, body verbatim.
 * Bind its class-known dependency to the frozen oracle, not production. */
#define xdev_ext_mech_class_known old_class_known
static inline int old_role(const struct xdev_ext_mech_stage_uapi *u)
{
 if (!xdev_ext_mech_class_known(u->class_id) ||
     (u->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE && u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE))
  return -EINVAL;
 if (u->class_id == XDEV_EXT_MECH_CLASS_IAA)
  return XDEV_EXT_MECH_ROLE_TRANSFORM;
 /* A user thread works in place on the batch's frames, like a fixed CPU
  * transform: exclusive OUT_PENDING claim, republished READY afterwards. */
 if (u->class_id == XDEV_EXT_MECH_CLASS_USER)
  return u->direction == XDEV_EXT_MECH_DIR_TO_DEVICE ? XDEV_EXT_MECH_ROLE_INPLACE : -EINVAL;
 if (u->class_id == XDEV_EXT_MECH_CLASS_CPU) {
  if (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE || u->arg0 >= XDEV_EXT_CPU_XFORM_MAX)
   return -EINVAL;
  /* A BPF compute program changes the frame in place, like a fixed one. */
  if (xdev_ext_mech_cpu_xform_fixed(u->arg0) || xdev_ext_mech_cpu_xform_bpf(u->arg0))
   return XDEV_EXT_MECH_ROLE_INPLACE;
  return xdev_ext_mech_cpu_xform_variable(u->arg0) ? XDEV_EXT_MECH_ROLE_TRANSFORM : -EINVAL;
 }
 return u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE ?
  XDEV_EXT_MECH_ROLE_PRODUCER : XDEV_EXT_MECH_ROLE_CONSUMER;
}
#undef xdev_ext_mech_class_known

/* 713327e io_uring/xdev_ext_mech_step.h:105-114, body verbatim. */
static inline __u32 old_peer_dirs(__u32 class_id)
{
 switch (class_id) {
 case XDEV_EXT_MECH_CLASS_NVME:
 case XDEV_EXT_MECH_CLASS_NET:
  return XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE;
 default:
  return 0; /* AF_XDP, socket, IAA, DMA, CE, CPU, USER: host-page classes */
 }
}

/* 713327e io_uring/xdev_ext_mech_step.h:197-199, clause verbatim. */
static bool old_peer_only(__u32 class_id, __u32 pool_kind)
{
 struct xdev_ext_mech_create req = { .pool_kind = pool_kind };
 struct xdev_ext_mech_stage_uapi stage = { .class_id = class_id };
 const struct xdev_ext_mech_create *c = &req;
 const struct xdev_ext_mech_stage_uapi *u = &stage;

  if (u->class_id == XDEV_EXT_MECH_CLASS_NET && c->pool_kind != XDEV_EXT_MECH_POOL_PEER)
   return true;
 return false;
}

/* 713327e io_uring/xdev_ext_mech_step.h:201-211, flag clauses verbatim. */
static bool old_flags_bad(__u32 class_id, __u32 flags)
{
 const struct xdev_ext_mech_stage_uapi stage = { .class_id = class_id, .flags = flags };
 const struct xdev_ext_mech_stage_uapi *u = &stage;

 return (u->flags && u->class_id == XDEV_EXT_MECH_CLASS_IAA &&
             (u->flags & ~XDEV_EXT_IAA_F_SOFTWARE)) ||
            (u->flags && u->class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
             (u->flags & ~XDEV_EXT_SOCKET_F_NXP)) ||
            (u->flags && u->class_id != XDEV_EXT_MECH_CLASS_SOCKET &&
             u->class_id != XDEV_EXT_MECH_CLASS_IAA && u->class_id != XDEV_EXT_MECH_CLASS_USER &&
             (u->class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
		     (u->flags & ~(XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) ||
		     ((u->flags & (XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) &&
		      !(u->flags & XDEV_EXT_AFXDP_F_RELIABLE))));
}

/* 713327e io_uring/xdev_ext_mech.c:262-288: frozen switch labels;
 * replace context constructors with their specified context-rule kind. */
static unsigned int old_ctx_rule(__u32 class_id)
{
 switch (class_id) {
	case XDEV_EXT_MECH_CLASS_NVME:
  return 2;
	case XDEV_EXT_MECH_CLASS_AFXDP:
  return 3;
	case XDEV_EXT_MECH_CLASS_CPU:
	case XDEV_EXT_MECH_CLASS_USER:
	case XDEV_EXT_MECH_CLASS_IAA:
	case XDEV_EXT_MECH_CLASS_SOCKET:
	case XDEV_EXT_MECH_CLASS_NET:
	case XDEV_EXT_MECH_CLASS_DMA:
  return 4;
	default:
  return 1;
 }
}

/* 713327e io_uring/xdev_ext_mech.c:2938-2939, predicate verbatim. */
static bool old_no_file(__u32 class_id)
{
 const struct xdev_ext_mech_stage_uapi stage = { .class_id = class_id };
 const struct xdev_ext_mech_stage_uapi *st = &stage;

 return !(st->class_id != XDEV_EXT_MECH_CLASS_CPU &&
		    st->class_id != XDEV_EXT_MECH_CLASS_USER);
}

/* Additional end-to-end admission oracle, 713327e
 * io_uring/xdev_ext_mech_step.h:152-286: body verbatim; the three refactored
 * dependencies resolve to frozen functions so production cannot bless itself. */
#define xdev_ext_mech_class_known old_class_known
#define xdev_ext_mech_stage_role old_role
#define xdev_ext_mech_peer_dirs old_peer_dirs
static inline int old_create_check(const struct xdev_ext_mech_create *c,
					__u32 *frames)
{
	__u32 i;
	int nr;

	if (c->abi_version != XDEV_EXT_MECH_ABI_VERSION || !c->nr_stages ||
	    c->nr_stages > XDEV_EXT_MECH_MAX_STAGES)
		return -EINVAL;
	switch (c->pool_kind) {
	case XDEV_EXT_MECH_POOL_PEER:
	case XDEV_EXT_MECH_POOL_XSK:
		if (c->pool_fd < 0)
			return -EBADF;
		break;
	case XDEV_EXT_MECH_POOL_IOU_UMEM:
		if (c->pool_fd != -1)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	if (!c->depth || c->depth > XDEV_EXT_MECH_MAX_DEPTH || c->eventfd < -1)
		return -EINVAL;
	nr = xdev_ext_mech_layout_frames(&c->layout);
	if (nr < 0)
		return nr;

	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++) {
		struct xdev_ext_mech_stage_uapi clean = c->st[i];
		const struct xdev_ext_mech_stage_uapi *u = &clean;

		if (i >= c->nr_stages) {
			if (!xdev_ext_mech_stage_zero(u))
				return -EINVAL;
			continue;
		}
		/* Generic, for every class; its capability is checked at bind. */
		clean.flags &= ~XDEV_EXT_MECH_STAGE_F_POLL;
  if (u->flags & XDEV_EXT_MECH_STAGE_F_FANOUT) {
   if (!i || xdev_ext_mech_stage_role(u) != XDEV_EXT_MECH_ROLE_CONSUMER ||
       xdev_ext_mech_stage_role(&c->st[i - 1]) != XDEV_EXT_MECH_ROLE_CONSUMER)
    return -EINVAL;
   clean.flags &= ~XDEV_EXT_MECH_STAGE_F_FANOUT;
  }
  /* NET DMAs device memory only. */
  if (u->class_id == XDEV_EXT_MECH_CLASS_NET && c->pool_kind != XDEV_EXT_MECH_POOL_PEER)
   return -EOPNOTSUPP;
		if (!xdev_ext_mech_class_known(u->class_id) ||
		    (u->flags && u->class_id == XDEV_EXT_MECH_CLASS_IAA &&
             (u->flags & ~XDEV_EXT_IAA_F_SOFTWARE)) ||
            (u->flags && u->class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
             (u->flags & ~XDEV_EXT_SOCKET_F_NXP)) ||
            (u->flags && u->class_id != XDEV_EXT_MECH_CLASS_SOCKET &&
             u->class_id != XDEV_EXT_MECH_CLASS_IAA && u->class_id != XDEV_EXT_MECH_CLASS_USER &&
             (u->class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
		     (u->flags & ~(XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) ||
		     ((u->flags & (XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) &&
		      !(u->flags & XDEV_EXT_AFXDP_F_RELIABLE)))) ||
		    (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
		     u->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
			return -EINVAL;
  if (u->class_id == XDEV_EXT_MECH_CLASS_CPU) {
   __s64 delta;
   __u32 j;

   if (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE || u->fd != -1 || u->flags ||
       u->arg0 >= XDEV_EXT_CPU_XFORM_MAX)
    return -EINVAL;
   if (xdev_ext_mech_cpu_xform_variable(u->arg0)) {
    if (!u->arg1 || u->arg1 > (__u64)XDEV_EXT_MECH_MAX_FRAMES * c->layout.seg_len)
     return -EINVAL;
   } else {
    if (xdev_ext_mech_cpu_len_delta(u->arg0, u->arg1, &delta))
     return -EINVAL;
    for (j = i + 1; delta && j < c->nr_stages; j++) {
     if (xdev_ext_mech_stage_role(&c->st[j]) == XDEV_EXT_MECH_ROLE_TRANSFORM)
      break;
     if (c->st[j].class_id == XDEV_EXT_MECH_CLASS_NVME ||
         c->st[j].class_id == XDEV_EXT_MECH_CLASS_AFXDP)
      return -EOPNOTSUPP;
    }
   }
   continue;
  }
  /* USER: its own fd, flag, deadline and length rule; a length change may
   * not reach a fixed-group NVMe or AF_XDP stage, as for the CPU class. */
  if (u->class_id == XDEV_EXT_MECH_CLASS_USER) {
   __s64 delta;
   bool varlen;
   __u32 j;
   int err = xdev_ext_user_stage_check(u, c->layout.frame_size, &delta, &varlen);

   if (err)
    return err;
   for (j = i + 1; (delta || varlen) && j < c->nr_stages; j++) {
    if (xdev_ext_mech_stage_role(&c->st[j]) == XDEV_EXT_MECH_ROLE_TRANSFORM)
     break;
    if (c->st[j].class_id == XDEV_EXT_MECH_CLASS_NVME ||
        c->st[j].class_id == XDEV_EXT_MECH_CLASS_AFXDP)
     return -EOPNOTSUPP;
   }
   continue;
  }
  if (u->class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
      (u->flags & XDEV_EXT_SOCKET_F_NXP) &&
      (!u->arg0 || u->arg1 <= 68 || u->arg1 > 0xffffffffULL))
   return -EINVAL;
		if (u->fd < 0)
			return -EBADF;
		if (u->class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
		    u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&
		    (i || c->nr_stages < 2))
			return -EINVAL;
		if (u->class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
      c->pool_kind == XDEV_EXT_MECH_POOL_PEER)
			continue;
		if (c->pool_kind != XDEV_EXT_MECH_POOL_XSK)
			return -EINVAL;
		if (u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&
		    (i || c->nr_stages < 2))
			return -EINVAL;
	}
 if (c->pool_kind == XDEV_EXT_MECH_POOL_PEER) {
  int ret = xdev_ext_mech_peer_layout_check(&c->layout);

  if (ret)
   return ret;
  for (i = 0; i < c->nr_stages; i++)
   if (!(xdev_ext_mech_peer_dirs(c->st[i].class_id) & (1U << c->st[i].direction)))
    return -EOPNOTSUPP;
 }
	*frames = (__u32)nr;
	return 0;
}
#undef xdev_ext_mech_class_known
#undef xdev_ext_mech_stage_role
#undef xdev_ext_mech_peer_dirs

static bool new_flags_bad(const struct xdev_ext_mech_class_desc *d, __u32 flags)
{
 return !d->flags_later && ((flags & ~d->known_flags) ||
                          (d->flags_ok && !d->flags_ok(flags)));
}

/* Run the actual CREATE function too: these valid base requests exercise the
 * generic properties in all three pools; downstream class restrictions must
 * retain their original errno and frame-count behavior. */
static void compare_create(__u32 class_id, __u32 dir, __u32 arg, __u32 flags)
{
 __u32 pool;

 for (pool = XDEV_EXT_MECH_POOL_XSK; pool <= XDEV_EXT_MECH_POOL_PEER; pool++) {
  struct xdev_ext_mech_create c = {
   .abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
   .pool_kind = pool, .pool_fd = pool == XDEV_EXT_MECH_POOL_IOU_UMEM ? -1 : 5,
   .depth = 1, .eventfd = -1,
   .layout = { .frame_size = 4096, .seg_len = 4096, .group_bytes = 4096 },
   .st = {
    { .class_id = class_id, .direction = dir, .fd = class_id == XDEV_EXT_MECH_CLASS_CPU ? -1 : 5,
      .flags = flags, .arg0 = arg, .arg1 = 4096 },
    { .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 6 },
   },
  };
  __u32 before = UINT32_MAX, after = UINT32_MAX;

  EQ(xdev_ext_mech_create_check(&c, &after), old_create_check(&c, &before));
  EQ(after, before);
 }
}

int main(void)
{
 static const struct {
  __u32 class_id, family, role, ctx, known_flags;
  bool peer_only, flags_later, no_file, flags_ok;
 } rows[] = {
  { XDEV_EXT_MECH_CLASS_AFXDP, 1, 1, 3, XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY, 0, 0, 0, 1 },
  { XDEV_EXT_MECH_CLASS_NVME, 2, 1, 2, 0, 0, 0, 0, 0 },
  { XDEV_EXT_MECH_CLASS_IAA, 3, 2, 4, XDEV_EXT_IAA_F_SOFTWARE, 0, 0, 0, 0 },
  { XDEV_EXT_MECH_CLASS_CE, 3, 1, 1, 0, 0, 0, 0, 0 },
  { XDEV_EXT_MECH_CLASS_DMA, 3, 1, 4, 0, 0, 0, 0, 0 },
  { XDEV_EXT_MECH_CLASS_SOCKET, 1, 1, 4, XDEV_EXT_SOCKET_F_NXP, 0, 0, 0, 0 },
  { XDEV_EXT_MECH_CLASS_NET, 1, 1, 4, 0, 1, 0, 0, 0 },
  { XDEV_EXT_MECH_CLASS_CPU, 3, 4, 4, 0, 0, 0, 1, 0 },
  { XDEV_EXT_MECH_CLASS_USER, 3, 3, 4, 0, 0, 1, 1, 0 },
 };
 static const __u32 afxdp[] = {
  0, XDEV_EXT_AFXDP_F_RELIABLE, XDEV_EXT_AFXDP_F_FINITE, XDEV_EXT_AFXDP_F_POLICY,
  XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE,
  XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_POLICY,
  XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY,
  XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY,
 };
 __u32 c, dir, bit, x, i, pool;

#define FIELD_TYPE(field, type) _Static_assert( \
 _Generic(((struct xdev_ext_mech_class_desc *)0)->field, type: 1, default: 0), \
 #field " keeps its frozen type")
 FIELD_TYPE(family, __u32);
 FIELD_TYPE(peer_dirs, __u32);
 FIELD_TYPE(known_flags, __u32);
 FIELD_TYPE(peer_only, __u8);
 FIELD_TYPE(flags_later, __u8);
 FIELD_TYPE(role_rule, __u8);
 FIELD_TYPE(ctx_rule, __u8);
 FIELD_TYPE(no_file, __u8);
 FIELD_TYPE(flags_ok, bool (*)(__u32));
#undef FIELD_TYPE
 EQ(XDEV_EXT_MECH_ABI_VERSION, 1);
 EQ(XDEV_EXT_MECH_CLASS_AFXDP, 2);
 EQ(XDEV_EXT_MECH_CLASS_NVME, 3);
 EQ(XDEV_EXT_MECH_CLASS_IAA, 4);
 EQ(XDEV_EXT_MECH_CLASS_CE, 5);
 EQ(XDEV_EXT_MECH_CLASS_DMA, 6);
 EQ(XDEV_EXT_MECH_CLASS_SOCKET, 7);
 EQ(XDEV_EXT_MECH_CLASS_NET, 8);
 EQ(XDEV_EXT_MECH_CLASS_CPU, 9);
 EQ(XDEV_EXT_MECH_CLASS_USER, 10);
 EQ(XDEV_EXT_MECH_CLASS_MAX, 11);
 EQ(XDEV_EXT_ROLE_RULE_DIRECTION, 1);
 EQ(XDEV_EXT_ROLE_RULE_TRANSFORM, 2);
 EQ(XDEV_EXT_ROLE_RULE_INPLACE_TX, 3);
 EQ(XDEV_EXT_ROLE_RULE_CPU_XFORM, 4);
 EQ(XDEV_EXT_CTX_RULE_GPU, 1);
 EQ(XDEV_EXT_CTX_RULE_NVME, 2);
 EQ(XDEV_EXT_CTX_RULE_AFXDP, 3);
 EQ(XDEV_EXT_CTX_RULE_COMMON, 4);
 for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
  const struct xdev_ext_mech_class_desc *d = xdev_ext_mech_class_desc(rows[i].class_id);

  EQ(d != NULL, true);
  if (!d)
   continue;
  EQ(d->family, rows[i].family);
  EQ(d->role_rule, rows[i].role);
  EQ(d->ctx_rule, rows[i].ctx);
  EQ(d->known_flags, rows[i].known_flags);
  EQ(d->peer_only, rows[i].peer_only);
  EQ(d->flags_later, rows[i].flags_later);
  EQ(d->no_file, rows[i].no_file);
  EQ(d->flags_ok != NULL, rows[i].flags_ok);
 }
 for (c = 0; c < 64; c++) {
  const struct xdev_ext_mech_class_desc *d = xdev_ext_mech_class_desc(c);

  EQ(d != NULL, true);
  if (!d)
   continue;
  EQ(xdev_ext_mech_class_known(c), old_class_known(c));
  EQ(xdev_ext_mech_peer_dirs(c), old_peer_dirs(c));
  EQ(d->peer_dirs, old_peer_dirs(c));
  EQ(d->family != XDEV_EXT_FAMILY_NONE, old_class_known(c));
  EQ(xdev_ext_mech_class_family(c), d->family);
  if (old_class_known(c)) {
   EQ(d->ctx_rule, old_ctx_rule(c));
   EQ(d->no_file, old_no_file(c));
  }
  for (pool = 0; pool <= 4; pool++)
   EQ(!!d->peer_only && pool != XDEV_EXT_MECH_POOL_PEER, old_peer_only(c, pool));
  for (bit = 0; bit < 32; bit++) {
   EQ(old_class_known(c) && new_flags_bad(d, 1U << bit), old_class_known(c) && old_flags_bad(c, 1U << bit));
   EQ(xdev_ext_afxdp_flags_ok(1U << bit),
      !((1U << bit) & (XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)));
   compare_create(c, XDEV_EXT_MECH_DIR_TO_DEVICE, 1, 1U << bit);
  }
  for (i = 0; i < sizeof(afxdp) / sizeof(afxdp[0]); i++) {
   EQ(old_class_known(c) && new_flags_bad(d, afxdp[i]), old_class_known(c) && old_flags_bad(c, afxdp[i]));
   EQ(xdev_ext_afxdp_flags_ok(afxdp[i]),
      !((afxdp[i] & (XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) && !(afxdp[i] & XDEV_EXT_AFXDP_F_RELIABLE)));
   compare_create(c, XDEV_EXT_MECH_DIR_TO_DEVICE, 1, afxdp[i]);
  }
  for (dir = 0; dir < 4; dir++)
   for (x = 0; x <= XDEV_EXT_CPU_XFORM_MAX; x++) {
    struct xdev_ext_mech_stage_uapi u = { .class_id = c, .direction = dir, .arg0 = x };

    EQ(xdev_ext_mech_stage_role(&u), old_role(&u));
    compare_create(c, dir, x, 0);
   }
 }
 {
  const struct xdev_ext_mech_class_desc *d = xdev_ext_mech_class_desc(UINT32_MAX);

  EQ(d != NULL, true);
  if (d)
   EQ(d->family, XDEV_EXT_FAMILY_NONE);
 }
 printf("%s 1 - one class table row gives every per-class answer of main (%u checks, %u failures)\n",
        failures ? "not ok" : "ok", checks, failures);
 return failures != 0;
}

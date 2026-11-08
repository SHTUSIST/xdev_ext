/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_FAMILY_CORE_H
#define _LINUX_XDEV_EXT_FAMILY_CORE_H

/* Immutable class declarations and pure admission rules, shared with host tests. */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/xdev_ext_binding_ctx.h>
#include <uapi/linux/xdev_ext_mech.h>
#else
#include <stdbool.h>
#include <errno.h>
#include <linux/types.h>
#include "xdev_ext_binding_ctx.h"
#include "../uapi/linux/xdev_ext_mech.h"
#endif

enum xdev_ext_mech_role_rule {
	XDEV_EXT_ROLE_RULE_DIRECTION	= 1,
	XDEV_EXT_ROLE_RULE_TRANSFORM	= 2,
	XDEV_EXT_ROLE_RULE_INPLACE_TX	= 3,
	XDEV_EXT_ROLE_RULE_CPU_XFORM	= 4,
};

enum xdev_ext_mech_ctx_rule {
	XDEV_EXT_CTX_RULE_GPU		= 1,
	XDEV_EXT_CTX_RULE_NVME		= 2,
	XDEV_EXT_CTX_RULE_AFXDP		= 3,
	XDEV_EXT_CTX_RULE_COMMON		= 4,
};

enum xdev_ext_mech_stage_role {
	XDEV_EXT_MECH_ROLE_PRODUCER = 1,
	XDEV_EXT_MECH_ROLE_CONSUMER = 2,
	XDEV_EXT_MECH_ROLE_INPLACE = 3,
	XDEV_EXT_MECH_ROLE_TRANSFORM = 4,
};

struct xdev_ext_mech_stage_facts {
	__s64 length_delta;
	bool variable_length;
	bool restrict_fixed_followers;
	bool template_safe;
};
typedef int (*xdev_ext_mech_stage_check_fn)(
	const struct xdev_ext_mech_create *, __u32,
	const struct xdev_ext_mech_stage_uapi *, struct xdev_ext_mech_stage_facts *);

enum xdev_ext_mech_ret_rule_kind {
	XDEV_EXT_MECH_RET_RANGE = 1,
	XDEV_EXT_MECH_RET_SET = 2,
};
struct xdev_ext_mech_ret_rule {
	__u32 member, callsite, kind;
	__s32 min, max;
	__u32 values;
};
struct xdev_ext_mech_info_view { __u32 allocated, requested; };

/* A FROM_DEVICE stage fills the whole group into host frames before CE; a
 * TO_DEVICE stage consumes it from host frames after CE; FILL_UMEM_ONLY: the
 * filled frames are host pages only on the ring's IOU_UMEM pool. */
enum {
	XDEV_EXT_CE_RANGE_FILLS_BEFORE = 1,
	XDEV_EXT_CE_RANGE_DRAINS_AFTER = 2,
	XDEV_EXT_CE_RANGE_FILL_UMEM_ONLY = 4,
};

struct xdev_ext_mech_class_desc {
	__u32 family, peer_dirs, known_flags;
	__u8 peer_only, flags_later, role_rule, ctx_rule, no_file;
	bool (*flags_ok)(__u32 flags);
	__u32 mech_abi_version;
	bool fixed_group, rx_source, fifo_from_device, compute_worker;
	__u8 ce_range_partner;	/* XDEV_EXT_CE_RANGE_* this class offers a CE range stage */
	__u32 external_async_flag;
	int (*role)(const struct xdev_ext_mech_stage_uapi *);
	xdev_ext_mech_stage_check_fn check_stage;
	bool (*retry_ok)(__u32 retries, __s32 status);
	const struct xdev_ext_mech_ret_rule *ret_rules;
	__u32 nr_ret_rules;
	const struct xdev_ext_mech_info_view *info_views;
	__u32 nr_info_views;
	struct xdev_ext_binding_ctx_v2 (*base)(__u32 direction, __u32 caps, __u64 bytes);
	bool (*protocol_info_ok)(const void *info, __u32 size);
	bool (*template_ok)(const struct xdev_ext_mech_stage_uapi *u);
};

static inline int xdev_ext_decl_direction_role(const struct xdev_ext_mech_stage_uapi *u)
{
	return u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE ?
		XDEV_EXT_MECH_ROLE_PRODUCER : XDEV_EXT_MECH_ROLE_CONSUMER;
}
static inline int xdev_ext_decl_transform_role(const struct xdev_ext_mech_stage_uapi *u)
{
	(void)u;
	return XDEV_EXT_MECH_ROLE_TRANSFORM;
}
static inline int xdev_ext_decl_inplace_role(const struct xdev_ext_mech_stage_uapi *u)
{
	return u->direction == XDEV_EXT_MECH_DIR_TO_DEVICE ? XDEV_EXT_MECH_ROLE_INPLACE : -EINVAL;
}
static inline bool xdev_ext_mech_cpu_xform_fixed(__u32 xform)
{
	return xform >= XDEV_EXT_CPU_XFORM_CRC32C_APPEND && xform <= XDEV_EXT_CPU_XFORM_SHA256_APPEND;
}
static inline bool xdev_ext_mech_cpu_xform_variable(__u32 xform)
{
	return xform == XDEV_EXT_CPU_XFORM_DEFLATE || xform == XDEV_EXT_CPU_XFORM_INFLATE;
}
static inline bool xdev_ext_mech_cpu_xform_bpf(__u32 xform)
{
	return xform == XDEV_EXT_CPU_XFORM_BPF;
}
static inline int xdev_ext_mech_cpu_len_delta(__u32 xform, __u64 param, __s64 *delta)
{
	__s64 d;

	switch (xform) {
	case XDEV_EXT_CPU_XFORM_CRC32C_APPEND: d = 4; break;
	case XDEV_EXT_CPU_XFORM_CRC32C_STRIP: d = -4; break;
	case XDEV_EXT_CPU_XFORM_CRC32C_SEAL:
	case XDEV_EXT_CPU_XFORM_CRC32C_CHECK: d = 0; break;
	case XDEV_EXT_CPU_XFORM_PARSE_STRIP:
		if (param < XDEV_EXT_CPU_PARSE_HDR_MIN || param > XDEV_EXT_CPU_PARSE_HDR_MAX)
			return -EINVAL;
		*delta = -(__s64)param;
		return 0;
	case XDEV_EXT_CPU_XFORM_XXH64_APPEND: *delta = 8; return 0;
	case XDEV_EXT_CPU_XFORM_SHA256_APPEND: d = 32; break;
	case XDEV_EXT_CPU_XFORM_BPF:
		/* param is the declared change itself, in two's complement. */
		if ((__s64)param < -(__s64)XDEV_EXT_CPU_BPF_DELTA_MAX ||
						(__s64)param > (__s64)XDEV_EXT_CPU_BPF_DELTA_MAX)
			return -EINVAL;
		*delta = (__s64)param;
		return 0;
	default: return -EINVAL;
	}
	if (param)
		return -EINVAL;
	*delta = d;
	return 0;
}


static inline int xdev_ext_decl_cpu_role(const struct xdev_ext_mech_stage_uapi *u)
{
	if (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE || u->arg0 >= XDEV_EXT_CPU_XFORM_MAX)
		return -EINVAL;
	if (xdev_ext_mech_cpu_xform_fixed(u->arg0) || xdev_ext_mech_cpu_xform_bpf(u->arg0))
		return XDEV_EXT_MECH_ROLE_INPLACE;
	return xdev_ext_mech_cpu_xform_variable(u->arg0) ? XDEV_EXT_MECH_ROLE_TRANSFORM : -EINVAL;
}
static inline int xdev_ext_decl_file_check(const struct xdev_ext_mech_create *c, __u32 i,
	const struct xdev_ext_mech_stage_uapi *u, struct xdev_ext_mech_stage_facts *f)
{
	(void)c; (void)i;
	*f = (struct xdev_ext_mech_stage_facts){ .template_safe = true };
	return u->fd < 0 ? -EBADF : 0;
}

/* Range targets have one CE stage and no later CE range acquisition: the
 * per-session range lease keeps one record per batch slot for one window,
 * taken at CE submit and released with the batch. The partner either fills
 * the whole group into host frames before CE (NVMe READ, XDOMAIN RX) or
 * consumes it after CE (NVMe WRITE). XDOMAIN RX must be on the ring's
 * IOU_UMEM host pages, which CE maps itself. Keep legacy compositions
 * unchanged; their configured-window lease is separate.
 */
static inline int xdev_ext_ce_range_partner_ok(const struct xdev_ext_mech_create *c,
	__u32 i, const struct xdev_ext_mech_stage_uapi *u, __u32 cap)
{
	const struct xdev_ext_mech_stage_uapi *peer = &c->st[i ^ 1];

	if (i == 1)
		return (cap & XDEV_EXT_CE_RANGE_FILLS_BEFORE) &&
		       u->direction == XDEV_EXT_MECH_DIR_TO_DEVICE &&
		       peer->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&
		       (!(cap & XDEV_EXT_CE_RANGE_FILL_UMEM_ONLY) ||
			c->pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM) ? 0 : -EOPNOTSUPP;
	return (cap & XDEV_EXT_CE_RANGE_DRAINS_AFTER) &&
	       u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&
	       peer->direction == XDEV_EXT_MECH_DIR_TO_DEVICE ? 0 : -EOPNOTSUPP;
}
static inline const struct xdev_ext_mech_class_desc *xdev_ext_mech_class_desc(__u32 class_id);
static inline int xdev_ext_decl_ce_check(const struct xdev_ext_mech_create *c, __u32 i,
	const struct xdev_ext_mech_stage_uapi *u, struct xdev_ext_mech_stage_facts *f)
{
	int err = xdev_ext_decl_file_check(c, i, u, f);

	if (err || !(u->flags & XDEV_EXT_CE_STAGE_F_TARGET_RANGE))
		return err;
	if (c->nr_stages != 2 || i > 1)
		return -EOPNOTSUPP;
	return xdev_ext_ce_range_partner_ok(c, i, u,
		xdev_ext_mech_class_desc(c->st[i ^ 1].class_id)->ce_range_partner);
}
/* XDOMAIN frames are PEER device memory or the ring's host-page UMEM, which
 * the class maps for its NHI; an AF_XDP UMEM belongs to its netdev driver. */
static inline int xdev_ext_decl_xdomain_check(const struct xdev_ext_mech_create *c, __u32 i,
	const struct xdev_ext_mech_stage_uapi *u, struct xdev_ext_mech_stage_facts *f)
{
	int err = xdev_ext_decl_file_check(c, i, u, f);

	if (err)
		return err;
	return c->pool_kind == XDEV_EXT_MECH_POOL_PEER ||
	       c->pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM ? 0 : -EOPNOTSUPP;
}
static inline int xdev_ext_decl_cpu_check(const struct xdev_ext_mech_create *c, __u32 i,
	const struct xdev_ext_mech_stage_uapi *u, struct xdev_ext_mech_stage_facts *f)
{
	(void)i;
	*f = (struct xdev_ext_mech_stage_facts){};
	if (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE || u->fd != -1 || u->flags ||
					u->arg0 >= XDEV_EXT_CPU_XFORM_MAX)
		return -EINVAL;
	if (xdev_ext_mech_cpu_xform_variable(u->arg0)) {
		f->variable_length = true;
		return !u->arg1 || u->arg1 > (__u64)XDEV_EXT_MECH_MAX_FRAMES * c->layout.seg_len ? -EINVAL : 0;
	}
	if (xdev_ext_mech_cpu_len_delta(u->arg0, u->arg1, &f->length_delta))
		return -EINVAL;
	f->restrict_fixed_followers = f->length_delta != 0;
	f->template_safe = !f->length_delta;
	return 0;
}
static inline int xdev_ext_decl_user_args(const struct xdev_ext_mech_stage_uapi *u,
	__u32 frame_size, __s64 *delta, bool *varlen)
{
	__s64 d = (__s64)u->arg1;

	if (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE ||
					(u->flags & ~(XDEV_EXT_USER_F_VARLEN | XDEV_EXT_USER_F_STRICT_ASYNC)))
		return -EINVAL;
	if ((u->flags & XDEV_EXT_USER_F_STRICT_ASYNC) && ((u->flags & XDEV_EXT_USER_F_VARLEN) || d))
		return -EOPNOTSUPP;
	if (u->fd < 0)
		return -EBADF;
	if (!u->arg0 || u->arg0 > XDEV_EXT_USER_DEADLINE_MAX_MS)
		return -EINVAL;
	if ((u->flags & XDEV_EXT_USER_F_VARLEN) ? d != 0 :
					(d < -(__s64)frame_size || d > (__s64)frame_size))
		return -EINVAL;
	*delta = d;
	*varlen = u->flags & XDEV_EXT_USER_F_VARLEN;
	return 0;
}
/* Named compatibility helper; generic CREATE invokes the row callback. */
static inline int xdev_ext_user_stage_check(const struct xdev_ext_mech_stage_uapi *u,
	__u32 frame_size, __s64 *delta, bool *varlen)
{
	if (u->class_id != XDEV_EXT_MECH_CLASS_USER)
		return -EINVAL;
	return xdev_ext_decl_user_args(u, frame_size, delta, varlen);
}
static inline int xdev_ext_decl_user_check(const struct xdev_ext_mech_create *c, __u32 i,
	const struct xdev_ext_mech_stage_uapi *u, struct xdev_ext_mech_stage_facts *f)
{
	int err;
	(void)i;
	*f = (struct xdev_ext_mech_stage_facts){};
	err = xdev_ext_decl_user_args(u, c->layout.frame_size, &f->length_delta, &f->variable_length);
	if (err)
		return err;
	f->restrict_fixed_followers = f->length_delta || f->variable_length;
	f->template_safe = !f->restrict_fixed_followers;
	if (c->pool_kind == XDEV_EXT_MECH_POOL_PEER && !(u->flags & XDEV_EXT_USER_F_STRICT_ASYNC))
		return -EOPNOTSUPP;
	return 0;
}
static inline int xdev_ext_decl_afxdp_check(const struct xdev_ext_mech_create *c, __u32 i,
	const struct xdev_ext_mech_stage_uapi *u, struct xdev_ext_mech_stage_facts *f)
{
	int err = xdev_ext_decl_file_check(c, i, u, f);
	if (err || c->pool_kind == XDEV_EXT_MECH_POOL_PEER)
		return err;
	if (c->pool_kind != XDEV_EXT_MECH_POOL_XSK)
		return -EINVAL;
	return u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE && (i || c->nr_stages < 2) ? -EINVAL : 0;
}
static inline int xdev_ext_decl_socket_check(const struct xdev_ext_mech_create *c, __u32 i,
	const struct xdev_ext_mech_stage_uapi *u, struct xdev_ext_mech_stage_facts *f)
{
	int err;
	if ((u->flags & XDEV_EXT_SOCKET_F_NXP) && (!u->arg0 || u->arg1 <= 68 || u->arg1 > 0xffffffffULL))
		return -EINVAL;
	err = xdev_ext_decl_file_check(c, i, u, f);
	if (err)
		return err;
	if (u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE) {
		f->template_safe = false;
		if (i || c->nr_stages < 2)
			return -EINVAL;
	}
	return 0;
}
/* START checks only template stability; CREATE already checked fd/args. */
static inline bool xdev_ext_decl_cpu_template(const struct xdev_ext_mech_stage_uapi *u)
{
	__s64 delta = 0;
	return !xdev_ext_mech_cpu_len_delta(u->arg0, u->arg1, &delta) && !delta;
}
static inline bool xdev_ext_decl_user_template(const struct xdev_ext_mech_stage_uapi *u)
{
	return !u->arg1 && !(u->flags & XDEV_EXT_USER_F_VARLEN);
}
static inline bool xdev_ext_decl_socket_template(const struct xdev_ext_mech_stage_uapi *u)
{
	return u->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE;
}
static inline bool xdev_ext_decl_nvme_retry(__u32 retries, __s32 status)
{
	return retries < 3 && status > 0 && (status & 0x07ff) && !(status & 0x4000);
}
static inline bool xdev_ext_decl_afxdp_retry(__u32 retries, __s32 status)
{
	return retries < 4 && status == -EAGAIN;
}
static inline bool xdev_ext_decl_copy_retry(__u32 retries, __s32 status)
{
	return retries < 3 && status == 1;
}
static inline struct xdev_ext_binding_ctx_v2 xdev_ext_decl_common_base(__u32 dir, __u32 caps, __u64 bytes)
{
	(void)caps;
	return (struct xdev_ext_binding_ctx_v2){ .abi_version = XDEV_EXT_BINDING_ABI_VERSION,
		.ctx_size = sizeof(struct xdev_ext_binding_ctx_v2), .backend = XDEV_EXT_BINDING_BACKEND_UNSPEC,
		.direction = dir, .length = bytes };
}
static inline struct xdev_ext_binding_ctx_v2 xdev_ext_decl_nvme_base(__u32 dir, __u32 caps, __u64 bytes)
{
	(void)caps;
	return xdev_ext_binding_make_nvme_ctx(dir == XDEV_EXT_MECH_DIR_TO_DEVICE, 0, bytes);
}
static inline struct xdev_ext_binding_ctx_v2 xdev_ext_decl_afxdp_base(__u32 dir, __u32 caps, __u64 bytes)
{
	bool native = caps & XDEV_EXT_BINDING_CAP_ZERO_COPY;
	if (dir == XDEV_EXT_MECH_DIR_TO_DEVICE)
		return native ? xdev_ext_binding_make_afxdp_native_tx_ctx(0, bytes, caps) : xdev_ext_binding_make_afxdp_tx_ctx(bytes);
	return xdev_ext_binding_make_afxdp_rx_ctx(0, bytes, native ? caps : 0);
}
static inline struct xdev_ext_binding_ctx_v2 xdev_ext_decl_gpu_base(__u32 dir, __u32 caps, __u64 bytes)
{
	(void)caps;
	return xdev_ext_binding_make_gpu_ctx(dir, 0, 0, bytes);
}
static inline bool xdev_ext_decl_protocol_info_ok(const void *p, __u32 size)
{
	const struct xdev_ext_xdomain_proto_info *info = (const struct xdev_ext_xdomain_proto_info *)p;
	if (!info || (size != sizeof(*info) && size != sizeof(struct xdev_ext_xdomain_proto_info_v2)))
		return false;
	return info->size == size &&
		((size == sizeof(*info) && info->version == XDEV_EXT_XDOMAIN_PROTO_VERSION) ||
			(size == sizeof(struct xdev_ext_xdomain_proto_info_v2) && info->version == XDEV_EXT_XDOMAIN_PROTO_V2_VERSION));
}

#define XDEV_EXT_DECL_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define XDEV_EXT_DECL_RET_RANGE(m, s, lo, hi) { .member = (m), .callsite = (s), .kind = XDEV_EXT_MECH_RET_RANGE, .min = (lo), .max = (hi) }
#define XDEV_EXT_DECL_COMMON_RETURNS \
	XDEV_EXT_DECL_RET_RANGE(XDEV_EXT_MECH_MEMBER_PREPARE, XDEV_EXT_MECH_SITE_CREATE, -4095, 0), \
	XDEV_EXT_DECL_RET_RANGE(XDEV_EXT_MECH_MEMBER_BUILD, XDEV_EXT_MECH_SITE_WORKER, 0, 2), \
	XDEV_EXT_DECL_RET_RANGE(XDEV_EXT_MECH_MEMBER_COMPLETE, XDEV_EXT_MECH_SITE_WORKER, 0, 3)
static const struct xdev_ext_mech_ret_rule xdev_ext_decl_common_returns[] = { XDEV_EXT_DECL_COMMON_RETURNS };
static const struct xdev_ext_mech_ret_rule xdev_ext_decl_nvme_returns[] = {
	XDEV_EXT_DECL_COMMON_RETURNS,
	XDEV_EXT_DECL_RET_RANGE(XDEV_EXT_MECH_MEMBER_BUILD, XDEV_EXT_MECH_SITE_URING_CMD, 0, 2),
	{ .member = XDEV_EXT_MECH_MEMBER_COMPLETE, .callsite = XDEV_EXT_MECH_SITE_URING_CMD,
			.kind = XDEV_EXT_MECH_RET_SET, .values = (1U << XDEV_EXT_MECH_DONE) | (1U << XDEV_EXT_MECH_ABORT) },
};
static const struct xdev_ext_mech_ret_rule xdev_ext_decl_afxdp_returns[] = {
	XDEV_EXT_DECL_COMMON_RETURNS,
	XDEV_EXT_DECL_RET_RANGE(XDEV_EXT_MECH_MEMBER_COMPLETE, XDEV_EXT_MECH_SITE_RX_GENERIC, 4, 6),
	XDEV_EXT_DECL_RET_RANGE(XDEV_EXT_MECH_MEMBER_COMPLETE, XDEV_EXT_MECH_SITE_RX_NATIVE, 4, 6),
	XDEV_EXT_DECL_RET_RANGE(XDEV_EXT_MECH_MEMBER_COMPLETE, XDEV_EXT_MECH_SITE_RX_HOLD_RESULT, 4, 6),
};
static const struct xdev_ext_mech_ret_rule xdev_ext_decl_cpu_returns[] = {
	XDEV_EXT_DECL_COMMON_RETURNS,
	XDEV_EXT_DECL_RET_RANGE(XDEV_EXT_MECH_MEMBER_COMPUTE, XDEV_EXT_MECH_SITE_WORKER, -4095, 0),
};
static const struct xdev_ext_mech_info_view xdev_ext_decl_afxdp_views[] = {
	{ sizeof(struct xdev_ext_afxdp_reliable_info), sizeof(struct xdev_ext_afxdp_mech_info) },
};
#undef XDEV_EXT_DECL_COMMON_RETURNS
#undef XDEV_EXT_DECL_RET_RANGE

/* AF_XDP: FINITE and POLICY extend a RELIABLE stage only. */
static inline bool xdev_ext_afxdp_flags_ok(__u32 flags)
{
	return !((flags & (XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) &&
		 !(flags & XDEV_EXT_AFXDP_F_RELIABLE));
}

/* Positional slots avoid array designators unsupported by C++ consumers. */
typedef char xdev_ext_mech_class_table_ids[
	(XDEV_EXT_MECH_CLASS_AFXDP == 2 && XDEV_EXT_MECH_CLASS_NVME == 3 &&
	 XDEV_EXT_MECH_CLASS_IAA == 4 && XDEV_EXT_MECH_CLASS_CE == 5 &&
	 XDEV_EXT_MECH_CLASS_DMA == 6 && XDEV_EXT_MECH_CLASS_SOCKET == 7 &&
	 XDEV_EXT_MECH_CLASS_NET == 8 && XDEV_EXT_MECH_CLASS_CPU == 9 &&
	 XDEV_EXT_MECH_CLASS_USER == 10 && XDEV_EXT_MECH_CLASS_XDOMAIN == 11 &&
	 XDEV_EXT_MECH_CLASS_BLOCK == 12 && XDEV_EXT_MECH_CLASS_MAX == 13) ? 1 : -1];

/* Class declarations are immutable; registration and pure wrappers share these rows. */
static const struct xdev_ext_mech_class_desc xdev_ext_mech_class_decls[XDEV_EXT_MECH_CLASS_MAX] = {
	{}, {},
	{ /* XDEV_EXT_MECH_CLASS_AFXDP */
		.family = XDEV_EXT_FAMILY_NETWORK,
		.known_flags = XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY,
		.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION,
		.ctx_rule = XDEV_EXT_CTX_RULE_AFXDP,
		.flags_ok = xdev_ext_afxdp_flags_ok,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.fixed_group = true,
		.rx_source = true,
		.role = xdev_ext_decl_direction_role,
		.check_stage = xdev_ext_decl_afxdp_check,
		.retry_ok = xdev_ext_decl_afxdp_retry,
		.ret_rules = xdev_ext_decl_afxdp_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_afxdp_returns),
		.info_views = xdev_ext_decl_afxdp_views, .nr_info_views = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_afxdp_views),
		.base = xdev_ext_decl_afxdp_base,
	},
	{ /* XDEV_EXT_MECH_CLASS_NVME */
		.family = XDEV_EXT_FAMILY_STORAGE,
		.peer_dirs = XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE,
		.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION,
		.ctx_rule = XDEV_EXT_CTX_RULE_NVME,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.fixed_group = true,
		.ce_range_partner = XDEV_EXT_CE_RANGE_FILLS_BEFORE | XDEV_EXT_CE_RANGE_DRAINS_AFTER,
		.role = xdev_ext_decl_direction_role,
		.check_stage = xdev_ext_decl_file_check,
		.retry_ok = xdev_ext_decl_nvme_retry,
		.ret_rules = xdev_ext_decl_nvme_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_nvme_returns),
		.base = xdev_ext_decl_nvme_base,
	},
	{ /* XDEV_EXT_MECH_CLASS_IAA */
		.family = XDEV_EXT_FAMILY_COMPUTE,
		.known_flags = XDEV_EXT_IAA_F_SOFTWARE,
		.role_rule = XDEV_EXT_ROLE_RULE_TRANSFORM,
		.ctx_rule = XDEV_EXT_CTX_RULE_COMMON,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.role = xdev_ext_decl_transform_role,
		.check_stage = xdev_ext_decl_file_check,
		.ret_rules = xdev_ext_decl_common_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_common_returns),
		.base = xdev_ext_decl_common_base,
	},
	{ /* XDEV_EXT_MECH_CLASS_CE */
		.family = XDEV_EXT_FAMILY_COMPUTE,
		.known_flags = XDEV_EXT_CE_STAGE_F_TARGET_RANGE,
		.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION,
		.ctx_rule = XDEV_EXT_CTX_RULE_GPU,
		.mech_abi_version = XDEV_EXT_CE_MECH_ABI_VERSION,
		.role = xdev_ext_decl_direction_role,
		.check_stage = xdev_ext_decl_ce_check,
		.retry_ok = xdev_ext_decl_copy_retry,
		.ret_rules = xdev_ext_decl_common_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_common_returns),
		.base = xdev_ext_decl_gpu_base,
	},
	{ /* XDEV_EXT_MECH_CLASS_DMA */
		.family = XDEV_EXT_FAMILY_COMPUTE,
		.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION,
		.ctx_rule = XDEV_EXT_CTX_RULE_COMMON,
		.mech_abi_version = XDEV_EXT_DMA_MECH_ABI_VERSION,
		.role = xdev_ext_decl_direction_role,
		.check_stage = xdev_ext_decl_file_check,
		.retry_ok = xdev_ext_decl_copy_retry,
		.ret_rules = xdev_ext_decl_common_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_common_returns),
		.base = xdev_ext_decl_common_base,
	},
	{ /* XDEV_EXT_MECH_CLASS_SOCKET */
		.family = XDEV_EXT_FAMILY_NETWORK,
		.known_flags = XDEV_EXT_SOCKET_F_NXP,
		.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION,
		.ctx_rule = XDEV_EXT_CTX_RULE_COMMON,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.fifo_from_device = true,
		.role = xdev_ext_decl_direction_role,
		.check_stage = xdev_ext_decl_socket_check,
		.ret_rules = xdev_ext_decl_common_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_common_returns),
		.base = xdev_ext_decl_common_base,
		.template_ok = xdev_ext_decl_socket_template,
	},
	{ /* XDEV_EXT_MECH_CLASS_NET */
		.family = XDEV_EXT_FAMILY_NETWORK,
		.peer_dirs = XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE,
		.peer_only = 1,
		.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION,
		.ctx_rule = XDEV_EXT_CTX_RULE_COMMON,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.role = xdev_ext_decl_direction_role,
		.check_stage = xdev_ext_decl_file_check,
		.ret_rules = xdev_ext_decl_common_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_common_returns),
		.base = xdev_ext_decl_common_base,
	},
	{ /* XDEV_EXT_MECH_CLASS_CPU */
		.family = XDEV_EXT_FAMILY_COMPUTE,
		.role_rule = XDEV_EXT_ROLE_RULE_CPU_XFORM,
		.ctx_rule = XDEV_EXT_CTX_RULE_COMMON,
		.no_file = 1,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.compute_worker = true,
		.role = xdev_ext_decl_cpu_role,
		.check_stage = xdev_ext_decl_cpu_check,
		.ret_rules = xdev_ext_decl_cpu_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_cpu_returns),
		.base = xdev_ext_decl_common_base,
		.template_ok = xdev_ext_decl_cpu_template,
	},
	{ /* XDEV_EXT_MECH_CLASS_USER */
		.family = XDEV_EXT_FAMILY_COMPUTE,
		.peer_dirs = XDEV_EXT_DMA_DIR_TO_DEVICE,
		.flags_later = 1,
		.role_rule = XDEV_EXT_ROLE_RULE_INPLACE_TX,
		.ctx_rule = XDEV_EXT_CTX_RULE_COMMON,
		.no_file = 1,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.external_async_flag = XDEV_EXT_USER_F_STRICT_ASYNC,
		.role = xdev_ext_decl_inplace_role,
		.check_stage = xdev_ext_decl_user_check,
		.ret_rules = xdev_ext_decl_common_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_common_returns),
		.base = xdev_ext_decl_common_base,
		.template_ok = xdev_ext_decl_user_template,
	},
	{ /* XDEV_EXT_MECH_CLASS_XDOMAIN */
		.family = XDEV_EXT_FAMILY_NETWORK,
		.peer_dirs = XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE,
		.known_flags = XDEV_EXT_XDOMAIN_KNOWN_FLAGS,
		.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION,
		.ctx_rule = XDEV_EXT_CTX_RULE_COMMON,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.ce_range_partner = XDEV_EXT_CE_RANGE_FILLS_BEFORE | XDEV_EXT_CE_RANGE_FILL_UMEM_ONLY,
		.role = xdev_ext_decl_direction_role,
		.check_stage = xdev_ext_decl_xdomain_check,
		.ret_rules = xdev_ext_decl_common_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_common_returns),
		.base = xdev_ext_decl_common_base,
		.protocol_info_ok = xdev_ext_decl_protocol_info_ok,
	},
	{ /* XDEV_EXT_MECH_CLASS_BLOCK */
		.family = XDEV_EXT_FAMILY_STORAGE,
		.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION,
		.ctx_rule = XDEV_EXT_CTX_RULE_COMMON,
		.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.fixed_group = true,
		.role = xdev_ext_decl_direction_role,
		.check_stage = xdev_ext_decl_file_check,
		.ret_rules = xdev_ext_decl_common_returns, .nr_ret_rules = XDEV_EXT_DECL_ARRAY_SIZE(xdev_ext_decl_common_returns),
		.base = xdev_ext_decl_common_base,
	},
};
#undef XDEV_EXT_DECL_ARRAY_SIZE

static inline const struct xdev_ext_mech_class_desc *
xdev_ext_mech_class_desc(__u32 class_id)
{
	static const struct xdev_ext_mech_class_desc none = {};
	if (class_id >= XDEV_EXT_MECH_CLASS_MAX || !xdev_ext_mech_class_decls[class_id].family)
		return &none;
	return &xdev_ext_mech_class_decls[class_id];
}

static inline bool xdev_ext_mech_info_view_ok_desc(const struct xdev_ext_mech_class_desc *d,
	__u32 allocated, __u32 requested)
{
	__u32 i;
	if (!d || !d->family)
		return false;
	if (allocated == requested)
		return true;
	for (i = 0; i < d->nr_info_views; i++)
		if (d->info_views[i].allocated == allocated && d->info_views[i].requested == requested)
			return true;
	return false;
}
static inline struct xdev_ext_binding_ctx_v2 xdev_ext_mech_base_desc(
	const struct xdev_ext_mech_class_desc *d, __u32 direction, __u32 caps, __u64 bytes)
{
	if (!d || !d->family || !d->base)
		return (struct xdev_ext_binding_ctx_v2){};
	return d->base(direction, caps, bytes);
}

static inline __u32 xdev_ext_mech_class_family(__u32 class_id)
{
	return xdev_ext_mech_class_desc(class_id)->family;
}

/* @hooks_family is &ops->fam.hdr->family, or NULL for optional hooks. */
static inline bool xdev_ext_family_hooks_ok(__u32 class_id,
					  const __u32 *hooks_family)
{
	__u32 family = xdev_ext_mech_class_family(class_id);

	return !hooks_family || (family != XDEV_EXT_FAMILY_NONE &&
				 *hooks_family == family);
}

#endif /* _LINUX_XDEV_EXT_FAMILY_CORE_H */

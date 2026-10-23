// SPDX-License-Identifier: GPL-2.0
/*
 * XDEV_EXT mechanism layer, eBPF side: the four struct_ops types (one per
 * device class), the shared kfuncs that hand a callback bounded views of
 * its class info, scratch descriptors, completion copies and frame bytes,
 * the call envelope, the class registry and, in measurement builds, the C
 * reference callbacks.  Sessions live in xdev_ext_mech.c.
 */

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/crc32.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/xdev_ext_binding.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_core.h"
#include "xdev_ext_mech_internal.h"
#include "xdev_ext_mech_step.h"
#include "xdev_ext_ops_core.h"

/* The four types share one layout; xdev_ext_nvme_mech_ops stands for all. */
#define XDEV_EXT_MECH_SAME_LAYOUT(type)					\
	static_assert(sizeof(struct type) ==				\
		      sizeof(struct xdev_ext_nvme_mech_ops) &&		\
		      offsetof(struct type, abi_version) ==		\
		      offsetof(struct xdev_ext_nvme_mech_ops, abi_version) &&	\
		      offsetof(struct type, flags) ==			\
		      offsetof(struct xdev_ext_nvme_mech_ops, flags) &&	\
		      offsetof(struct type, prepare) ==			\
		      offsetof(struct xdev_ext_nvme_mech_ops, prepare) &&	\
		      offsetof(struct type, build) ==			\
		      offsetof(struct xdev_ext_nvme_mech_ops, build) &&	\
		      offsetof(struct type, complete) ==		\
		      offsetof(struct xdev_ext_nvme_mech_ops, complete))

XDEV_EXT_MECH_SAME_LAYOUT(xdev_ext_afxdp_mech_ops);
XDEV_EXT_MECH_SAME_LAYOUT(xdev_ext_ce_mech_ops);
XDEV_EXT_MECH_SAME_LAYOUT(xdev_ext_dma_mech_ops);
XDEV_EXT_MECH_SAME_LAYOUT(xdev_ext_iaa_mech_ops);
XDEV_EXT_MECH_SAME_LAYOUT(xdev_ext_socket_mech_ops);
#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
XDEV_EXT_MECH_SAME_LAYOUT(xdev_ext_mech_c_ops);
#endif

typedef __s32 (*xdev_ext_mech_cb_t)(const struct xdev_ext_mech_ctx *ctx);

/* One published struct_ops generation per class, indexed by class id. */
DEFINE_XDEV_EXT_OPS_REGISTRY(xdev_ext_mech_registry, XDEV_EXT_MECH_CLASS_MAX, NULL);

static DEFINE_MUTEX(xdev_ext_mech_class_lock);
static const struct xdev_ext_mech_class_ops *xdev_ext_mech_classes[XDEV_EXT_MECH_CLASS_MAX];
#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
/*
 * Changed under xdev_ext_mech_class_lock, only NULL -> table -> NULL: the owner
 * is written before its table is published and rewritten only a grace
 * period after the table was cleared, so a reader under RCU that sees a
 * table sees its owner.
 */
static const struct xdev_ext_mech_c_ops *xdev_ext_mech_c_table[XDEV_EXT_MECH_CLASS_MAX];
static struct module *xdev_ext_mech_c_owner[XDEV_EXT_MECH_CLASS_MAX];
#endif
static bool xdev_ext_mech_types_ready;

static xdev_ext_mech_cb_t xdev_ext_mech_member_fn(const void *ops, u32 member)
{
	const struct xdev_ext_nvme_mech_ops *o = ops;

	switch (member) {
	case XDEV_EXT_MECH_MEMBER_PREPARE:
		return o->prepare;
	case XDEV_EXT_MECH_MEMBER_BUILD:
		return o->build;
	case XDEV_EXT_MECH_MEMBER_COMPLETE:
		return o->complete;
	default:
		return NULL;
	}
}

static bool xdev_ext_mech_args_ok(const struct xdev_ext_mech_call_args *a)
{
	if (!a || !a->base || a->nr_frames > XDEV_EXT_MECH_MAX_FRAMES ||
	    (a->nr_frames && !a->frames) || (a->info_size && !a->info))
		return false;
 if (a->callsite==XDEV_EXT_MECH_SITE_WORKER_SELECT)
  return a->member==XDEV_EXT_MECH_MEMBER_BUILD && !a->b && !a->frames && !a->nr_frames &&
         !a->scratch && !a->desc_size && !a->desc_cap && !a->cqe && !a->cqe_size && !a->cqe_cap;
	switch (a->member) {
	case XDEV_EXT_MECH_MEMBER_PREPARE:
		return a->callsite == XDEV_EXT_MECH_SITE_CREATE;
	case XDEV_EXT_MECH_MEMBER_BUILD:
		return a->callsite != XDEV_EXT_MECH_SITE_CREATE && a->scratch &&
		       a->desc_size && a->desc_cap;
	case XDEV_EXT_MECH_MEMBER_COMPLETE:
		return a->callsite != XDEV_EXT_MECH_SITE_CREATE &&
		       (a->cqe || (!a->cqe_size && !a->cqe_cap));
	default:
		return false;
	}
}

int xdev_ext_mech_invoke(const void *ops, const struct xdev_ext_mech_target *t,
		    const struct xdev_ext_mech_call_args *a, s32 *ret,
		    struct xdev_ext_mech_hold_intent *hold)
{
	struct xdev_ext_mech_call call;
	xdev_ext_mech_cb_t fn;

	if (!xdev_ext_mech_args_ok(a))
		return -EINVAL;
	fn = xdev_ext_mech_member_fn(ops, a->member);
	if (!fn)
		return -ENOENT;

	memset(&call, 0, sizeof(call));
	call.ctx.base = *a->base;
	call.ctx.base.event = a->member == XDEV_EXT_MECH_MEMBER_COMPLETE ?
			      XDEV_EXT_BINDING_EVENT_COMPLETE :
			      XDEV_EXT_BINDING_EVENT_DISPATCH;
	call.ctx.base.request_id = t->batch_id;
	call.ctx.base.chain_id = t->session_id;
	if (t->batch) {
		call.ctx.base.src_offset = t->key;
		call.ctx.base.length = t->bytes;
	}
	call.ctx.mech_abi_version = t->class_id == XDEV_EXT_MECH_CLASS_CE ?
		XDEV_EXT_CE_MECH_ABI_VERSION : XDEV_EXT_MECH_ABI_VERSION;
	call.ctx.member = a->member;
	call.ctx.class_id = t->class_id;
	call.ctx.callsite = a->callsite;
	call.ctx.nr_frames = a->nr_frames;
	call.ctx.session_id = t->session_id;
	call.ctx.batch_id = t->batch_id;

	call.member = a->member;
	call.callsite = a->callsite;
	call.s = t->s;
	call.st = t->st;
	call.b = a->b;
	call.frames = a->frames;
	call.nr_frames = a->nr_frames;
	call.frame_size = t->frame_size;
	call.hdr_room = t->hdr_room;
	call.batch_frames = t->batch_frames;
	call.info = a->info;
	call.info_size = a->info_size;
	if (a->member == XDEV_EXT_MECH_MEMBER_BUILD) {
		call.ctx.desc_cap = a->desc_cap;
		call.scratch = a->scratch;
		call.desc_size = a->desc_size;
		call.desc_cap = a->desc_cap;
	} else if (a->member == XDEV_EXT_MECH_MEMBER_COMPLETE) {
		call.cqe = a->cqe;
		call.cqe_size = a->cqe_size;
		call.cqe_cap = a->cqe_cap;
	}

	WRITE_ONCE(call.magic, XDEV_EXT_MECH_CALL_MAGIC);
	*ret = fn(&call.ctx);
	WRITE_ONCE(call.magic, 0);

	if (hold)
		*hold = call.hold;
	return call.protocol_error ? -EPROTO : 0;
}

/* Bytes [off, off + len) of frame @pos's chunk during build or complete. */
static u8 *xdev_ext_mech_frame_bytes(struct xdev_ext_mech_call *c, u32 pos, u32 off,
				u64 len)
{
	const struct xdev_ext_mech_frame *f;

	if ((c->member != XDEV_EXT_MECH_MEMBER_BUILD &&
	     c->member != XDEV_EXT_MECH_MEMBER_COMPLETE) ||
	    c->callsite == XDEV_EXT_MECH_SITE_RX_HOLD_RESULT || !c->frames ||
	    pos >= c->nr_frames || !len)
		return NULL;
	f = &c->frames[pos];
	if (!f->kaddr || !xdev_ext_mech_span_in(off, len, c->frame_size))
		return NULL;
	return (u8 *)f->kaddr + off;
}

__bpf_kfunc_start_defs();

__bpf_kfunc __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx,
			       const size_t rdonly_buf_size)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);

	if (!c || !c->info)
  return NULL;
 /* Keep the fixed v1 AF_XDP view readable when C allocates the v3
  * extension. No other prefix length or class is granted a view. */
 if (rdonly_buf_size != c->info_size &&
     !(c->ctx.class_id == XDEV_EXT_MECH_CLASS_AFXDP &&
       c->info_size == sizeof(struct xdev_ext_afxdp_reliable_info) &&
       rdonly_buf_size == sizeof(struct xdev_ext_afxdp_mech_info)))
  return NULL;
	return (__u8 *)c->info;
}

__bpf_kfunc __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
			       const size_t rdwr_buf_size)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);

	if (!c || c->member != XDEV_EXT_MECH_MEMBER_BUILD || !c->scratch ||
	    rdwr_buf_size != c->desc_size || slot >= c->desc_cap)
		return NULL;
	return c->scratch + (size_t)slot * c->desc_size;
}

__bpf_kfunc __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
			      const size_t rdonly_buf_size)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);

	if (!c || c->member != XDEV_EXT_MECH_MEMBER_COMPLETE || !c->cqe ||
	    rdonly_buf_size != c->cqe_size || slot >= c->cqe_cap)
		return NULL;
	return (__u8 *)c->cqe + (size_t)slot * c->cqe_size;
}

__bpf_kfunc __u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
				__u32 off, const size_t rdonly_buf_size)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);

	return c ? xdev_ext_mech_frame_bytes(c, pos, off, rdonly_buf_size) : NULL;
}

/* Out-of-bounds bytes latch a protocol error: the callback then fails. */
__bpf_kfunc __u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *ctx,
				       __u32 pos, __u32 off, __u32 len,
				       __u32 seed)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);
	const u8 *p;

	if (!c)
		return 0;
	if (!len)
		return seed;
	p = xdev_ext_mech_frame_bytes(c, pos, off, len);
	if (!p) {
		c->protocol_error = 1;
		return 0;
	}
	return crc32c(seed, p, len);
}

__bpf_kfunc __u32 bpf_xdev_ext_crc32c(const void *buf, __u32 buf__sz, __u32 seed)
{
	return crc32c(seed, buf, buf__sz);
}

__bpf_kfunc_end_defs();

EXPORT_SYMBOL_GPL(bpf_xdev_ext_info);
EXPORT_SYMBOL_GPL(bpf_xdev_ext_desc);
EXPORT_SYMBOL_GPL(bpf_xdev_ext_cqe);
EXPORT_SYMBOL_GPL(bpf_xdev_ext_frame);
EXPORT_SYMBOL_GPL(bpf_xdev_ext_frame_crc32c);
EXPORT_SYMBOL_GPL(bpf_xdev_ext_crc32c);

BTF_KFUNCS_START(xdev_ext_mech_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdev_ext_info, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdev_ext_desc, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdev_ext_cqe, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdev_ext_frame, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdev_ext_frame_crc32c, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_crc32c, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(xdev_ext_mech_kfunc_ids)

BTF_SET_START(xdev_ext_mech_prepare_kfuncs)
BTF_ID(func, bpf_xdev_ext_info)
BTF_ID(func, bpf_xdev_ext_crc32c)
BTF_SET_END(xdev_ext_mech_prepare_kfuncs)

BTF_SET_START(xdev_ext_mech_build_kfuncs)
BTF_ID(func, bpf_xdev_ext_info)
BTF_ID(func, bpf_xdev_ext_desc)
BTF_ID(func, bpf_xdev_ext_frame)
BTF_ID(func, bpf_xdev_ext_frame_crc32c)
BTF_ID(func, bpf_xdev_ext_crc32c)
BTF_SET_END(xdev_ext_mech_build_kfuncs)

BTF_SET_START(xdev_ext_mech_complete_kfuncs)
BTF_ID(func, bpf_xdev_ext_info)
BTF_ID(func, bpf_xdev_ext_cqe)
BTF_ID(func, bpf_xdev_ext_frame)
BTF_ID(func, bpf_xdev_ext_frame_crc32c)
BTF_ID(func, bpf_xdev_ext_crc32c)
BTF_SET_END(xdev_ext_mech_complete_kfuncs)

/* struct_ops plumbing shared by the three types. */

static bool xdev_ext_mech_abi_valid(u32 value)
{
	return value == XDEV_EXT_MECH_ABI_VERSION;
}

static bool xdev_ext_mech_flags_known(u32 value)
{
	return !(value & ~XDEV_EXT_MECH_OPS_KNOWN_FLAGS);
}

static const struct xdev_ext_ops_u32_field xdev_ext_mech_ops_fields[] = {
	{ offsetof(struct xdev_ext_nvme_mech_ops, abi_version), xdev_ext_mech_abi_valid },
	{ offsetof(struct xdev_ext_nvme_mech_ops, flags), xdev_ext_mech_flags_known },
};

static bool xdev_ext_ce_mech_abi_valid(u32 value)
{
	return value == XDEV_EXT_CE_MECH_ABI_VERSION;
}

static const struct xdev_ext_ops_u32_field xdev_ext_ce_mech_ops_fields[] = {
	{ offsetof(struct xdev_ext_ce_mech_ops, abi_version), xdev_ext_ce_mech_abi_valid },
	{ offsetof(struct xdev_ext_ce_mech_ops, flags), xdev_ext_mech_flags_known },
};

/* Only prepare, which runs at CREATE in process context, may sleep. */
static const struct xdev_ext_ops_member xdev_ext_mech_ops_members[] = {
	{ .off = offsetof(struct xdev_ext_nvme_mech_ops, prepare), .sleepable = true },
	{ .off = offsetof(struct xdev_ext_nvme_mech_ops, build), .required = true },
	{ .off = offsetof(struct xdev_ext_nvme_mech_ops, complete), .required = true },
};

static const struct xdev_ext_ops_desc xdev_ext_mech_ops_desc = {
	.fields = xdev_ext_mech_ops_fields,
	.nr_fields = ARRAY_SIZE(xdev_ext_mech_ops_fields),
	.members = xdev_ext_mech_ops_members,
	.nr_members = ARRAY_SIZE(xdev_ext_mech_ops_members),
};

static const struct xdev_ext_ops_desc xdev_ext_ce_mech_ops_desc = {
	.fields = xdev_ext_ce_mech_ops_fields,
	.nr_fields = ARRAY_SIZE(xdev_ext_ce_mech_ops_fields),
	.members = xdev_ext_mech_ops_members,
	.nr_members = ARRAY_SIZE(xdev_ext_mech_ops_members),
};

static int xdev_ext_ce_mech_ops_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	return xdev_ext_ops_init_member(&xdev_ext_ce_mech_ops_desc, t, member, kdata, udata);
}

static int xdev_ext_ce_mech_ops_validate(void *kdata)
{
	return xdev_ext_ops_validate(&xdev_ext_ce_mech_ops_desc, kdata);
}

static int xdev_ext_mech_ops_init_member(const struct btf_type *t,
				    const struct btf_member *member,
				    void *kdata, const void *udata)
{
	return xdev_ext_ops_init_member(&xdev_ext_mech_ops_desc, t, member, kdata, udata);
}

static int xdev_ext_mech_ops_check_member(const struct btf_type *t,
				     const struct btf_member *member,
				     const struct bpf_prog *prog)
{
	return xdev_ext_ops_check_member(&xdev_ext_mech_ops_desc, t, member, prog);
}

static int xdev_ext_mech_ops_validate(void *kdata)
{
	return xdev_ext_ops_validate(&xdev_ext_mech_ops_desc, kdata);
}

static int xdev_ext_mech_reg(u32 class_id, void *kdata, struct bpf_link *link)
{
	return xdev_ext_ops_publish(&xdev_ext_mech_registry, class_id, kdata, link);
}

/*
 * Retract and wait for RCU readers.  Sessions keep their pinned generation
 * for batches already in flight and stop admitting new ones.
 */
static void xdev_ext_mech_unreg(u32 class_id, void *kdata)
{
	if (xdev_ext_ops_retract(&xdev_ext_mech_registry, class_id, kdata))
		xdev_ext_mech_generation_gone(class_id, kdata);
}

static int xdev_ext_mech_btf_struct_access(struct bpf_verifier_log *log,
				      const struct bpf_reg_state *reg,
				      int off, int size)
{
	return xdev_ext_ops_deny_btf_write(log, reg, off, size, "xdev_ext_mech_ctx");
}

static const struct bpf_verifier_ops xdev_ext_mech_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = xdev_ext_ops_is_valid_access,
	.btf_struct_access = xdev_ext_mech_btf_struct_access,
};

XDEV_EXT_OPS_CFI_STUB(xdev_ext_mech_ops__prepare, struct xdev_ext_mech_ctx)
XDEV_EXT_OPS_CFI_STUB(xdev_ext_mech_ops__build, struct xdev_ext_mech_ctx)
XDEV_EXT_OPS_CFI_STUB(xdev_ext_mech_ops__complete, struct xdev_ext_mech_ctx)

/* One struct_ops type per class; reg/unreg know their registry slot. */
#define XDEV_EXT_MECH_STRUCT_OPS(cls, id, init_member_fn, validate_fn)				\
static int xdev_ext_##cls##_mech_reg(void *kdata, struct bpf_link *link)	\
{									\
	return xdev_ext_mech_reg(id, kdata, link);				\
}									\
static void xdev_ext_##cls##_mech_unreg(void *kdata, struct bpf_link *link)	\
{									\
	xdev_ext_mech_unreg(id, kdata);					\
}									\
static struct xdev_ext_##cls##_mech_ops xdev_ext_##cls##_mech_cfi_stubs = {	\
	.prepare = xdev_ext_mech_ops__prepare,				\
	.build = xdev_ext_mech_ops__build,					\
	.complete = xdev_ext_mech_ops__complete,				\
};									\
static struct bpf_struct_ops bpf_xdev_ext_##cls##_mech_ops = {		\
	.verifier_ops = &xdev_ext_mech_verifier_ops,				\
	.init = xdev_ext_ops_init,						\
	.check_member = xdev_ext_mech_ops_check_member,			\
	.init_member = init_member_fn,			\
	.reg = xdev_ext_##cls##_mech_reg,					\
	.unreg = xdev_ext_##cls##_mech_unreg,				\
	.validate = validate_fn,				\
	.cfi_stubs = &xdev_ext_##cls##_mech_cfi_stubs,			\
	.name = "xdev_ext_" #cls "_mech_ops",				\
	.owner = THIS_MODULE,						\
}

XDEV_EXT_MECH_STRUCT_OPS(nvme, XDEV_EXT_MECH_CLASS_NVME,
                    xdev_ext_mech_ops_init_member, xdev_ext_mech_ops_validate);
XDEV_EXT_MECH_STRUCT_OPS(afxdp, XDEV_EXT_MECH_CLASS_AFXDP,
                    xdev_ext_mech_ops_init_member, xdev_ext_mech_ops_validate);
XDEV_EXT_MECH_STRUCT_OPS(ce, XDEV_EXT_MECH_CLASS_CE,
                    xdev_ext_ce_mech_ops_init_member, xdev_ext_ce_mech_ops_validate);
XDEV_EXT_MECH_STRUCT_OPS(dma, XDEV_EXT_MECH_CLASS_DMA,
                    xdev_ext_mech_ops_init_member, xdev_ext_mech_ops_validate);

XDEV_EXT_MECH_STRUCT_OPS(iaa, XDEV_EXT_MECH_CLASS_IAA,
                    xdev_ext_mech_ops_init_member, xdev_ext_mech_ops_validate);

XDEV_EXT_MECH_STRUCT_OPS(socket, XDEV_EXT_MECH_CLASS_SOCKET,
                    xdev_ext_mech_ops_init_member, xdev_ext_mech_ops_validate);
XDEV_EXT_MECH_STRUCT_OPS(net, XDEV_EXT_MECH_CLASS_NET,
                    xdev_ext_mech_ops_init_member, xdev_ext_mech_ops_validate);

static const struct bpf_struct_ops *const xdev_ext_mech_st_ops[] = {
	&bpf_xdev_ext_nvme_mech_ops,
	&bpf_xdev_ext_afxdp_mech_ops,
	&bpf_xdev_ext_ce_mech_ops,
	&bpf_xdev_ext_dma_mech_ops,
	&bpf_xdev_ext_iaa_mech_ops,
	&bpf_xdev_ext_socket_mech_ops,
	&bpf_xdev_ext_net_mech_ops,
};

static const struct bpf_struct_ops *xdev_ext_mech_st_ops_of(u32 class_id)
{
	switch (class_id) {
	case XDEV_EXT_MECH_CLASS_NVME:
		return &bpf_xdev_ext_nvme_mech_ops;
	case XDEV_EXT_MECH_CLASS_AFXDP:
		return &bpf_xdev_ext_afxdp_mech_ops;
	case XDEV_EXT_MECH_CLASS_CE:
		return &bpf_xdev_ext_ce_mech_ops;
	case XDEV_EXT_MECH_CLASS_DMA:
		return &bpf_xdev_ext_dma_mech_ops;
	case XDEV_EXT_MECH_CLASS_IAA:
		return &bpf_xdev_ext_iaa_mech_ops;
	case XDEV_EXT_MECH_CLASS_SOCKET:
		return &bpf_xdev_ext_socket_mech_ops;
	case XDEV_EXT_MECH_CLASS_NET:
		return &bpf_xdev_ext_net_mech_ops;
	default:
		return NULL;
	}
}

static const struct xdev_ext_ops_kfunc_member xdev_ext_mech_kfunc_members[] = {
	{
		.off = offsetof(struct xdev_ext_nvme_mech_ops, prepare),
		.allowed = &xdev_ext_mech_prepare_kfuncs,
	},
	{
		.off = offsetof(struct xdev_ext_nvme_mech_ops, build),
		.allowed = &xdev_ext_mech_build_kfuncs,
	},
	{
		.off = offsetof(struct xdev_ext_nvme_mech_ops, complete),
		.allowed = &xdev_ext_mech_complete_kfuncs,
	},
};

static const struct xdev_ext_ops_kfunc_rule xdev_ext_mech_kfunc_rule = {
	.ids = &xdev_ext_mech_kfunc_ids,
	.st_ops = xdev_ext_mech_st_ops,
	.nr_st_ops = ARRAY_SIZE(xdev_ext_mech_st_ops),
	.members = xdev_ext_mech_kfunc_members,
	.nr_members = ARRAY_SIZE(xdev_ext_mech_kfunc_members),
};

static int xdev_ext_mech_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	return xdev_ext_ops_kfunc_filter(&xdev_ext_mech_kfunc_rule, prog, kfunc_id);
}

static const struct btf_kfunc_id_set xdev_ext_mech_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &xdev_ext_mech_kfunc_ids,
	.filter = xdev_ext_mech_kfunc_filter,
};

int xdev_ext_mech_class_kfunc_filter(u32 class_id, const struct bpf_prog *prog,
				u32 kfunc_id, const struct btf_id_set8 *ids,
				const struct btf_id_set *build,
				const struct btf_id_set *complete)
{
	const struct bpf_struct_ops *st_ops = xdev_ext_mech_st_ops_of(class_id);
	struct xdev_ext_ops_kfunc_member members[2];
	struct xdev_ext_ops_kfunc_rule rule = {
		.ids = ids,
		.st_ops = &st_ops,
		.nr_st_ops = st_ops ? 1 : 0,
		.members = members,
	};

	if (build)
		members[rule.nr_members++] = (struct xdev_ext_ops_kfunc_member) {
			.off = offsetof(struct xdev_ext_nvme_mech_ops, build),
			.allowed = build,
		};
	if (complete)
		members[rule.nr_members++] = (struct xdev_ext_ops_kfunc_member) {
			.off = offsetof(struct xdev_ext_nvme_mech_ops, complete),
			.allowed = complete,
		};
	return xdev_ext_ops_kfunc_filter(&rule, prog, kfunc_id);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_class_kfunc_filter);

/* Class registry. */

int xdev_ext_mech_class_register(const struct xdev_ext_mech_class_ops *ops)
{
	int ret = 0;

	if (!ops || !xdev_ext_mech_class_known(ops->class_id) || !ops->bind ||
	    !ops->validate || !ops->submit ||
	    (ops->info_size && !ops->fill_info) ||
	    (ops->cqe_size && !ops->fill_cqe) ||
	    !xdev_ext_mech_class_sizes_ok(ops->info_size, ops->desc_size,
				     ops->desc_cap, ops->cqe_size,
				     ops->cqe_cap, ops->batch_priv_size))
		return -EINVAL;

	mutex_lock(&xdev_ext_mech_class_lock);
	if (xdev_ext_mech_classes[ops->class_id])
		ret = -EBUSY;
	else
		xdev_ext_mech_classes[ops->class_id] = ops;
	mutex_unlock(&xdev_ext_mech_class_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_class_register);

void xdev_ext_mech_class_unregister(const struct xdev_ext_mech_class_ops *ops)
{
	mutex_lock(&xdev_ext_mech_class_lock);
	if (ops && xdev_ext_mech_class_known(ops->class_id) &&
	    xdev_ext_mech_classes[ops->class_id] == ops)
		xdev_ext_mech_classes[ops->class_id] = NULL;
	mutex_unlock(&xdev_ext_mech_class_lock);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_class_unregister);

const struct xdev_ext_mech_class_ops *xdev_ext_mech_class_get(u32 class_id)
{
	const struct xdev_ext_mech_class_ops *cls;

	if (!xdev_ext_mech_class_known(class_id))
		return NULL;
	mutex_lock(&xdev_ext_mech_class_lock);
	cls = xdev_ext_mech_classes[class_id];
	if (cls && !try_module_get(cls->owner))
		cls = NULL;
	mutex_unlock(&xdev_ext_mech_class_lock);
	return cls;
}

void xdev_ext_mech_class_put(const struct xdev_ext_mech_class_ops *cls)
{
	module_put(cls->owner);
}

const void *xdev_ext_mech_ops_get(u32 class_id, bool *pinned,
			     struct module **owner)
{
	const void *ops = NULL;
	bool c_set = false;

	*pinned = false;
	*owner = NULL;
	if (!xdev_ext_mech_class_known(class_id))
		return NULL;
#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
	rcu_read_lock();
	ops = smp_load_acquire(&xdev_ext_mech_c_table[class_id]);
	if (ops) {
		struct module *mod = READ_ONCE(xdev_ext_mech_c_owner[class_id]);

		c_set = true;
		/* A table whose module is going serves no new holder. */
		if (try_module_get(mod))
			*owner = mod;
		else
			ops = NULL;
	}
	rcu_read_unlock();
#endif
	if (c_set)
		return ops;
	ops = xdev_ext_ops_pin(&xdev_ext_mech_registry, class_id);
	*pinned = ops != NULL;
	return ops;
}

void xdev_ext_mech_ops_put(const void *ops, bool pinned, struct module *owner)
{
	if (pinned)
		xdev_ext_ops_unpin(ops);
	module_put(owner);
}

bool xdev_ext_mech_ops_current(u32 class_id, const void *ops, bool pinned)
{
	if (pinned)
		return xdev_ext_ops_is_current(&xdev_ext_mech_registry, class_id, ops);
#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
	return READ_ONCE(xdev_ext_mech_c_table[class_id]) == ops;
#else
	return false;
#endif
}

int xdev_ext_mech_call_active(u32 class_id, const struct xdev_ext_mech_call_args *a,
			 s32 *ret, struct xdev_ext_mech_hold_intent *hold)
{
	struct xdev_ext_mech_target t = { .class_id = class_id };
	struct module *owner;
	const void *ops;
	bool pinned;
	int rc;

	if (!a)
		return -EINVAL;
	/* RX owns mutable per-session state, frame custody and serialization.
	 * This stateless diagnostic entry cannot manufacture that owner. */
	if (a->callsite == XDEV_EXT_MECH_SITE_RX_GENERIC ||
	    a->callsite == XDEV_EXT_MECH_SITE_RX_NATIVE ||
	    a->callsite == XDEV_EXT_MECH_SITE_RX_HOLD_RESULT)
		return -EOPNOTSUPP;
	t.batch_id = a->batch_id;
	t.frame_size = a->frame_size;
	t.hdr_room = a->hdr_room;
	t.batch_frames = a->batch_frames;
	ops = xdev_ext_mech_ops_get(class_id, &pinned, &owner);
	if (!ops)
		return xdev_ext_mech_class_known(class_id) ? -ENOENT : -EINVAL;
	rc = xdev_ext_mech_invoke(ops, &t, a, ret, hold);
	xdev_ext_mech_ops_put(ops, pinned, owner);
	return rc;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_call_active);

#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
int __xdev_ext_mech_set_c_ops(u32 class_id, const struct xdev_ext_mech_c_ops *ops,
			 struct module *owner)
{
	const struct xdev_ext_mech_c_ops *old;

	if (!xdev_ext_mech_class_known(class_id) ||
	    (ops && (!ops->build || !ops->complete)))
		return -EINVAL;
	mutex_lock(&xdev_ext_mech_class_lock);
	old = xdev_ext_mech_c_table[class_id];
	if (old == ops) {
		mutex_unlock(&xdev_ext_mech_class_lock);
		return 0;
	}
	if (old) {
		/* After the grace period no reader takes @old's owner any more. */
		WRITE_ONCE(xdev_ext_mech_c_table[class_id], NULL);
		synchronize_rcu();
	}
	WRITE_ONCE(xdev_ext_mech_c_owner[class_id], ops ? owner : NULL);
	if (ops)
		smp_store_release(&xdev_ext_mech_c_table[class_id], ops);
	mutex_unlock(&xdev_ext_mech_class_lock);
	/* Sessions on @old stop admitting; what they hold keeps its module. */
	if (old)
		xdev_ext_mech_generation_gone(class_id, old);
	return 0;
}
EXPORT_SYMBOL_GPL(__xdev_ext_mech_set_c_ops);
#endif

bool xdev_ext_mech_ready(void)
{
	return READ_ONCE(xdev_ext_mech_types_ready);
}

/*
 * register_bpf_struct_ops() of built-in code returns 0 without registering
 * anything when vmlinux has no BTF; look the types up before trusting it.
 */
static bool __init xdev_ext_mech_types_findable(void)
{
	struct btf *btf = bpf_get_btf_vmlinux();
	u32 i;

	if (IS_ERR_OR_NULL(btf))
		return false;
	for (i = 0; i < ARRAY_SIZE(xdev_ext_mech_st_ops); i++) {
		const struct bpf_struct_ops_desc *desc;
		s32 id = btf_find_by_name_kind(btf, xdev_ext_mech_st_ops[i]->name,
					       BTF_KIND_STRUCT);

		if (id <= 0)
			return false;
		desc = bpf_struct_ops_find(btf, id);
		if (!desc || desc->st_ops != xdev_ext_mech_st_ops[i])
			return false;
	}
	return true;
}

/*
 * Mechanism programs read these views by their UAPI types (vmlinux.h), but
 * C only copies some of them by size, so pahole would leave them out.
 */
static void __init xdev_ext_mech_emit_btf_types(void)
{
	BTF_TYPE_EMIT(struct xdev_ext_mech_frame_info);
	BTF_TYPE_EMIT(struct xdev_ext_mech_layout);
	BTF_TYPE_EMIT(struct xdev_ext_mech_peer);
	BTF_TYPE_EMIT(struct xdev_ext_nvme_mech_info);
	BTF_TYPE_EMIT(struct xdev_ext_afxdp_mech_info);
	BTF_TYPE_EMIT(struct xdev_ext_ce_mech_info);
	BTF_TYPE_EMIT(struct xdev_ext_ce_copy_desc);
	BTF_TYPE_EMIT(struct xdev_ext_dma_copy_desc);
	BTF_TYPE_EMIT(struct xdev_ext_dma_mech_info);
 BTF_TYPE_EMIT(struct xdev_ext_iaa_mech_info);
 BTF_TYPE_EMIT(struct xdev_ext_iaa_desc);
 BTF_TYPE_EMIT(struct xdev_ext_socket_send_desc);
 BTF_TYPE_EMIT(struct xdev_ext_socket_mech_info);
 BTF_TYPE_EMIT(struct xdev_ext_socket_mech_cqe);
 BTF_TYPE_EMIT(struct xdev_ext_net_send_desc);
 BTF_TYPE_EMIT(struct xdev_ext_net_mech_info);
 BTF_TYPE_EMIT(struct xdev_ext_net_mech_cqe);
 BTF_TYPE_EMIT(struct xdev_ext_iaa_mech_cqe);
	BTF_TYPE_EMIT(struct xdev_ext_dma_mech_cqe);
	BTF_TYPE_EMIT(struct xdev_ext_nvme_mech_cqe);
	BTF_TYPE_EMIT(struct xdev_ext_afxdp_tx_cqe);
	BTF_TYPE_EMIT(struct xdev_ext_ce_mech_cqe);
}

static int __init xdev_ext_mech_ops_init(void)
{
	int ret;

	xdev_ext_mech_emit_btf_types();
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&xdev_ext_mech_kfunc_set);
	if (!ret)
		ret = register_bpf_struct_ops(&bpf_xdev_ext_nvme_mech_ops,
					      xdev_ext_nvme_mech_ops);
	if (!ret)
		ret = register_bpf_struct_ops(&bpf_xdev_ext_afxdp_mech_ops,
					      xdev_ext_afxdp_mech_ops);
	if (!ret)
		ret = register_bpf_struct_ops(&bpf_xdev_ext_ce_mech_ops,
					      xdev_ext_ce_mech_ops);
	if (!ret)
		ret = register_bpf_struct_ops(&bpf_xdev_ext_dma_mech_ops,
					      xdev_ext_dma_mech_ops);
 if (!ret)
  ret = register_bpf_struct_ops(&bpf_xdev_ext_iaa_mech_ops, xdev_ext_iaa_mech_ops);
 if (!ret)
  ret = register_bpf_struct_ops(&bpf_xdev_ext_socket_mech_ops, xdev_ext_socket_mech_ops);
 if (!ret)
  ret = register_bpf_struct_ops(&bpf_xdev_ext_net_mech_ops, xdev_ext_net_mech_ops);
	if (!ret && !xdev_ext_mech_types_findable())
		ret = -ENOENT;
	if (ret) {
		pr_err("xdev_ext_mech: struct_ops types unavailable (%d); CREATE fails with -EOPNOTSUPP\n",
		       ret);
		return ret;
	}
	WRITE_ONCE(xdev_ext_mech_types_ready, true);
	return 0;
}
late_initcall(xdev_ext_mech_ops_init);

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_OPS_CORE_H
#define IO_URING_XDEV_EXT_OPS_CORE_H

/*
 * Plumbing shared by every XDEV_EXT struct_ops type: the policy layer
 * (xdev_ext_binding_ops) and the mechanism layer (one type per device class).
 * Each user keeps its own ABI rules and passes them in as tables.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/compiler.h>
#include <linux/jump_label.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

struct bpf_insn_access_aux;
struct bpf_reg_state;
struct bpf_verifier_log;

/*
 * One active instance per slot, published with RCU.  @key, when set, is
 * enabled while any slot is published so call sites stay a patched-out
 * branch until the first registration.
 */
struct xdev_ext_ops_registry {
	struct mutex lock;
	struct static_key_false *key;
	const void __rcu **slots;
	u32 nr_slots;
	u32 nr_active;
};

#define DEFINE_XDEV_EXT_OPS_REGISTRY(name, nr, static_key)			\
	static const void __rcu *name##_slots[nr];			\
	static struct xdev_ext_ops_registry name = {				\
		.lock = __MUTEX_INITIALIZER(name.lock),			\
		.key = (static_key),					\
		.slots = name##_slots,					\
		.nr_slots = (nr),					\
	}

/* struct_ops ->reg/->unreg; process context, may sleep. */
int xdev_ext_ops_publish(struct xdev_ext_ops_registry *reg, u32 slot, const void *ops,
		    struct bpf_link *link);
/* Returns true when @ops was the published instance; waits for RCU readers. */
bool xdev_ext_ops_retract(struct xdev_ext_ops_registry *reg, u32 slot, const void *ops);

/*
 * Pin the generation published in @slot, or return NULL.  The pin keeps that
 * exact generation callable after a later retract; drop it with
 * xdev_ext_ops_unpin().  Any context.
 */
const void *xdev_ext_ops_pin(struct xdev_ext_ops_registry *reg, u32 slot);
void xdev_ext_ops_unpin(const void *ops);

/* True while @ops is still the published generation of @slot. */
static inline bool xdev_ext_ops_is_current(struct xdev_ext_ops_registry *reg, u32 slot,
				      const void *ops)
{
	return slot < reg->nr_slots &&
	       rcu_access_pointer(reg->slots[slot]) == ops;
}

/* A u32 scalar member checked at map update and again at ->validate. */
struct xdev_ext_ops_u32_field {
	u32 off;
	bool (*valid)(u32 value);
};

/* A callback member; ->validate refuses a NULL @required member. */
struct xdev_ext_ops_member {
	u32 off;
	bool required;
	bool sleepable;
};

struct xdev_ext_ops_desc {
	const struct xdev_ext_ops_u32_field *fields;
	u32 nr_fields;
	const struct xdev_ext_ops_member *members;
	u32 nr_members;
};

bool xdev_ext_ops_u32_zero(u32 value);

int xdev_ext_ops_init(struct btf *btf);
int xdev_ext_ops_init_member(const struct xdev_ext_ops_desc *desc,
			const struct btf_type *t,
			const struct btf_member *member, void *kdata,
			const void *udata);
int xdev_ext_ops_check_member(const struct xdev_ext_ops_desc *desc,
			 const struct btf_type *t,
			 const struct btf_member *member,
			 const struct bpf_prog *prog);
int xdev_ext_ops_validate(const struct xdev_ext_ops_desc *desc, const void *kdata);

bool xdev_ext_ops_is_valid_access(int off, int size, enum bpf_access_type type,
			     const struct bpf_prog *prog,
			     struct bpf_insn_access_aux *info);
/* Refuse every write through a kernel BTF pointer; @ctx_type gets its own text. */
int xdev_ext_ops_deny_btf_write(struct bpf_verifier_log *log,
			   const struct bpf_reg_state *reg, int off, int size,
			   const char *ctx_type);

/* The kfuncs of @ids a program attached at member offset @off may call. */
struct xdev_ext_ops_kfunc_member {
	u32 off;
	const struct btf_id_set *allowed;
};

struct xdev_ext_ops_kfunc_rule {
	const struct btf_id_set8 *ids;
	const struct bpf_struct_ops *const *st_ops;
	u32 nr_st_ops;
	const struct xdev_ext_ops_kfunc_member *members;
	u32 nr_members;
};

/*
 * Load-time filter body.  Returns 0 for a kfunc outside @rule->ids: the
 * verifier runs every filter registered on the hook and treats any non-zero
 * result as "no such kfunc", so a filter must not hide kfuncs it does not own.
 */
int xdev_ext_ops_kfunc_filter(const struct xdev_ext_ops_kfunc_rule *rule,
			 const struct bpf_prog *prog, u32 kfunc_id);

/* A stub for ->cfi_stubs; never called, its type is what kCFI checks. */
#define XDEV_EXT_OPS_CFI_STUB(fn, ctx_type)					\
	static __s32 fn(const ctx_type *ctx)				\
	{								\
		(void)ctx;						\
		return -EOPNOTSUPP;					\
	}

/*
 * Call envelope.  C copies the ctx a callback sees into a private envelope on
 * its own stack and seals it with a magic of its own.  A kfunc accepts only a
 * sealed envelope, counts itself against a per-callback limit and latches
 * misuse; the caller inspects the envelope once the callback has returned.
 */
struct xdev_ext_ops_call_state {
	u32 magic;
	u8 calls;
	u8 protocol_error;
};

static inline void xdev_ext_ops_call_seal(struct xdev_ext_ops_call_state *cs, u32 magic)
{
	*cs = (struct xdev_ext_ops_call_state) { .magic = magic };
}

/* Any context; latches a protocol error on an unsealed envelope. */
static inline bool xdev_ext_ops_call_sealed(struct xdev_ext_ops_call_state *cs,
				       u32 magic)
{
	if (likely(READ_ONCE(cs->magic) == magic))
		return true;
	cs->protocol_error = 1;
	return false;
}

/* Count one kfunc call; past @limit calls latch a protocol error. */
static inline bool xdev_ext_ops_call_take(struct xdev_ext_ops_call_state *cs, u8 limit)
{
	if (likely(cs->calls++ < limit))
		return true;
	cs->protocol_error = 1;
	return false;
}

/* After the callback: no misuse and exactly @calls counted kfunc calls. */
static inline bool xdev_ext_ops_call_clean(const struct xdev_ext_ops_call_state *cs,
				      u8 calls)
{
	return !cs->protocol_error && cs->calls == calls;
}

#endif /* IO_URING_XDEV_EXT_OPS_CORE_H */

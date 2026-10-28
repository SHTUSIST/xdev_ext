/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_MECH_H
#define _LINUX_XDEV_EXT_MECH_H

/*
 * Kernel contract of the XDEV_EXT mechanism layer.
 *
 * io_uring/xdev_ext_mech.c (the core) owns sessions, the control plane, one
 * kthread_worker per session, batches, frame ownership, generation pinning
 * and teardown; io_uring/xdev_ext_mech_ops.c owns the three struct_ops types,
 * the shared kfuncs and the class table.  Each device class supplies a
 * struct xdev_ext_mech_class_ops; the copy-engine class takes one struct
 * xdev_ext_ce_backend_ops per backend driver.  The pure rules every party
 * follows live in io_uring/xdev_ext_mech_core.h.
 *
 * The part above the kernel-only section is plain data, shared with
 * io_uring/xdev_ext_mech_core.h and its user-space tests.
 */

#ifdef __KERNEL__
#include <linux/compiler.h>
#include <linux/container_of.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <asm/page.h>
#include <uapi/linux/xdev_ext_mech.h>
#else
#include <stdbool.h>
#include <linux/types.h>
#include "../uapi/linux/xdev_ext_mech.h"
#endif

/*
 * One ownership word per UMEM chunk, stored with the UMEM (not the pool) so
 * every socket and session on it agrees; changed only by a compare-and-
 * exchange of a legal edge (xdev_ext_mech_frame_edge_ok()).  USER is zero: a
 * fresh UMEM belongs to user space.
 */
enum xdev_ext_mech_frame_state {
	XDEV_EXT_MECH_F_USER		= 0,	/* fill ring, RX ring or the application */
	XDEV_EXT_MECH_F_K_FREE	= 1,	/* kernel partition, free */
	XDEV_EXT_MECH_F_HELD		= 2,	/* in a batch, no native command on it */
	XDEV_EXT_MECH_F_INFLIGHT	= 3,	/* under one native command */
	XDEV_EXT_MECH_F_SEQUESTERED	= 4,	/* may still be in device use; never reused */
	XDEV_EXT_MECH_F_NIC_RX	= 5,	/* lent to native NIC RX; not on user FQ */
	XDEV_EXT_MECH_F_NR,
};

/*
 * AF_XDP RX hold intent: recorded by bpf_xdev_ext_afxdp_hold() in the call
 * envelope and applied by C only when the callback returns XDEV_EXT_MECH_HOLD.
 * count is the session layout's frames per batch; 0 means nothing was
 * recorded.
 */
struct xdev_ext_mech_hold_intent {
	__u64 key;
	__u32 pos;
	__u32 count;
	__u32 span_off;		/* payload span in the frame's chunk */
	__u32 span_len;
};

/* Session counters a caller adds to; they feed struct xdev_ext_mech_stats. */
enum xdev_ext_mech_counter {
	XDEV_EXT_MECH_CNT_REJECTS,
	XDEV_EXT_MECH_CNT_RECYCLED,
	XDEV_EXT_MECH_CNT_HELD,
	XDEV_EXT_MECH_CNT_SEQUESTERED,
	XDEV_EXT_MECH_CNT_TIMEOUTS,
	XDEV_EXT_MECH_CNT_NATIVE_PUBLISH,
	XDEV_EXT_MECH_CNT_PROTOCOL_ERR,
	XDEV_EXT_MECH_CNT_PUBLISHED,
	XDEV_EXT_MECH_CNT_NIC_COPY_OPS,
	XDEV_EXT_MECH_CNT_NIC_COPY_BYTES,
	XDEV_EXT_MECH_CNT_NIC_ZC_OPS,
	XDEV_EXT_MECH_CNT_NIC_ZC_BYTES,
	XDEV_EXT_MECH_CNT_NR,
};

static inline enum xdev_ext_mech_counter xdev_ext_mech_nic_ops_counter(bool zero_copy)
{
	return zero_copy ? XDEV_EXT_MECH_CNT_NIC_ZC_OPS : XDEV_EXT_MECH_CNT_NIC_COPY_OPS;
}
static inline enum xdev_ext_mech_counter xdev_ext_mech_nic_bytes_counter(bool zero_copy)
{
	return zero_copy ? XDEV_EXT_MECH_CNT_NIC_ZC_BYTES : XDEV_EXT_MECH_CNT_NIC_COPY_BYTES;
}

#define XDEV_EXT_MECH_POOL_CPU_BATCH	1

#ifdef __KERNEL__
/*
 * Everything a module (nvme-core, a CE backend, bpf_testmod) calls below is
 * EXPORT_SYMBOL_GPL; the io_uring entry points and the pool binders are
 * called by built-in code only.
 */

struct bpf_prog;
struct btf_id_set;
struct btf_id_set8;
struct file;
struct file_operations;
struct io_ring_ctx;
struct io_uring_cmd;
struct module;
struct page;

struct xdev_ext_mech_session;	/* io_uring/xdev_ext_mech.c */
struct xdev_ext_mech_batch;		/* io_uring/xdev_ext_mech.c */
struct xdev_ext_ce_cookie;		/* io_uring/xdev_ext_mech_ce.c */
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops;
struct xdev_ext_ce_backend_ops;

#define XDEV_EXT_MECH_OPS_KNOWN_FLAGS	0x00000000U

/*
 * One struct_ops type per class, registered by built-in code so neither
 * nvme-core nor a CE backend needs module BTF.  Separate types let the kfunc
 * filter tell classes apart at load time.  check_member accepts a sleepable
 * program only for prepare; no member requests a private stack, so a
 * softirq RX complete may nest inside a worker build of the same program.
 * CE requires XDEV_EXT_CE_MECH_ABI_VERSION; the other types use XDEV_EXT_MECH_ABI_VERSION.
 * Every type has the compute slot so the layouts stay identical; only the
 * CPU type accepts a program for it (Documentation/userspace-api/xdev_ext-compute.rst).
 */
#define XDEV_EXT_MECH_OPS_TYPE(name)						\
struct name {								\
	__u32 abi_version;	/* per-class version, see above */	\
	__u32 flags;		/* XDEV_EXT_MECH_OPS_KNOWN_FLAGS */		\
	/* optional, SEC("struct_ops.s/prepare"), CREATE */		\
	__s32 (*prepare)(const struct xdev_ext_mech_ctx *ctx);		\
	/* required, never sleeps */					\
	__s32 (*build)(const struct xdev_ext_mech_ctx *ctx);			\
	/* required, never sleeps */					\
	__s32 (*complete)(const struct xdev_ext_mech_ctx *ctx);		\
	/* optional, CPU class only, never sleeps, once per batch */	\
	__s32 (*compute)(const struct xdev_ext_mech_ctx *ctx);		\
}

XDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_afxdp_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_ce_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_dma_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_iaa_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_cpu_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_socket_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_net_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_user_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_xdomain_mech_ops);

/*
 * A frame resolved to kernel memory.  [kaddr, kaddr + frame_size) is one
 * kernel mapping of the chunk; the data span is [data_off, data_off +
 * data_len) of the chunk.
 */
struct xdev_ext_mech_frame {
	void *kaddr;
	u64 umem_addr;		/* chunk base as a UMEM offset */
	u32 index;		/* chunk index in the pool */
	u32 data_off;
	u32 data_len;
	void *pool_priv;	/* provider handle while held (xsk: struct xdp_buff_xsk *) */
};

/*
 * Call envelope, on the invoking C caller's stack for exactly one callback.
 * The program sees &ctx; kfuncs map it back with xdev_ext_mech_call_of() and read
 * only fields of this envelope.  Views a kfunc returns are valid for this
 * callback only, and C reads scratch and the hold intent after the callback
 * has returned, so nothing is checked and then changed.
 */
#define XDEV_EXT_MECH_CALL_MAGIC	0x55424d43U	/* "UBMC" */

/* Invocation-stack storage; the kfunc copies bytes and never retains BPF memory. */
struct xdev_ext_xdomain_proto_result {
	struct xdev_ext_xdomain_proto_verdict verdict;
	__u32 calls;
};

struct xdev_ext_mech_call {
	struct xdev_ext_mech_ctx ctx;
	u32 magic;
	u8 member;			/* enum xdev_ext_mech_member */
	u8 callsite;			/* enum xdev_ext_mech_callsite */
	u8 hold_calls;			/* bpf_xdev_ext_afxdp_hold() calls, at most 1 */
	u8 protocol_error;		/* latched by a kfunc on misuse */
	struct xdev_ext_mech_hold_intent hold;
	struct xdev_ext_mech_session *s;	/* NULL from xdev_ext_mech_call_active() */
	struct xdev_ext_mech_stage *st;	/* NULL from xdev_ext_mech_call_active() */
	struct xdev_ext_mech_batch *b;	/* NULL for prepare, RX and uring_cmd */
	const struct xdev_ext_mech_frame *frames;
	u32 nr_frames;
	u32 frame_size;			/* bpf_xdev_ext_frame() bound */
	u32 hdr_room;			/* bpf_xdev_ext_afxdp_hdr() bound */
	u32 batch_frames;		/* bpf_xdev_ext_afxdp_hold() count */
	u32 info_size;
	const void *info;
	u8 *scratch;			/* build only; zeroed by C before the call */
	u32 desc_size;
	u32 desc_cap;
	const void *cqe;		/* complete only */
	u32 cqe_size;
	u32 cqe_cap;
	u32 *out_len;			/* compute only: per-frame output lengths */
	s32 len_delta;			/* compute only: declared change D */
	struct xdev_ext_xdomain_proto_result *xdomain;
};

/* Any context, current callback only: check identity before reading the envelope.
 * A different ctx latches misuse on the real call, even if BPF ignores it.
 */
struct xdev_ext_mech_call *
xdev_ext_mech_call_of(const struct xdev_ext_mech_ctx *ctx);

/*
 * One callback invocation.  base is the class's xdev_ext_binding_make_*_ctx()
 * output and is copied into ctx.base.  xdev_ext_mech_call() takes frame_size,
 * hdr_room and batch_frames (the frames per batch, which an RX hold records
 * as its count) from the session layout and ctx.batch_id from @b when set,
 * else from batch_id; xdev_ext_mech_call_active() takes all four from these
 * fields.
 * The scratch area is caller-owned, at least desc_size * desc_cap bytes, and
 * zeroed by the caller.  compute takes out_len, nr_frames entries preset to
 * each frame's data_len, and the declared change len_delta.
 */
struct xdev_ext_mech_call_args {
	u32 member;			/* enum xdev_ext_mech_member */
	u32 callsite;			/* enum xdev_ext_mech_callsite */
	const struct xdev_ext_binding_ctx_v2 *base;
	struct xdev_ext_mech_batch *b;
	u64 batch_id;
	const struct xdev_ext_mech_frame *frames;
	u32 nr_frames;
	u32 frame_size;
	u32 hdr_room;
	u32 batch_frames;
	u32 info_size;
	const void *info;
	u8 *scratch;
	u32 desc_size;
	u32 desc_cap;
	const void *cqe;
	u32 cqe_size;
	u32 cqe_cap;
	u32 *out_len;
	s32 len_delta;
	struct xdev_ext_xdomain_proto_result *xdomain;
};

/*
 * Context of the member (prepare: process context; build and complete: any
 * context, never sleeps): run @a->member of the generation the session pinned
 * for @st's class.  0 with *@ret the program value (raw; resolve it with
 * xdev_ext_mech_ret_resolve()) and *@hold the recorded intent when @hold is set;
 * -EPROTO when a kfunc latched misuse; -ENOENT when that generation has no
 * program for the member (prepare only); -EINVAL for a bad @a.
 */
int xdev_ext_mech_call(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_call_args *a,
		  s32 *ret, struct xdev_ext_mech_hold_intent *hold);
/*
 * Same context rules as xdev_ext_mech_call() (prepare: process context; build and
 * complete: any context): run the generation published now for @class_id,
 * pinned for this call only, without a session.  For bpf_testmod and the C
 * reference measurement.  -ENOENT when nothing is published.
 */
int xdev_ext_mech_call_active(u32 class_id, const struct xdev_ext_mech_call_args *a,
			 s32 *ret, struct xdev_ext_mech_hold_intent *hold);

/*
 * A stage of a session chain.  The core fills every field except priv
 * before ->bind and keeps a reference on file until after ->unbind.
 */
struct xdev_ext_mech_stage {
	struct xdev_ext_mech_session *s;
	const struct xdev_ext_mech_class_ops *cls;
	struct file *file;
	void *priv;			/* class: set in ->bind, freed in ->unbind */
	u64 arg0;
	u64 arg1;
	u32 class_id;			/* enum xdev_ext_mech_class */
	u32 direction;			/* enum xdev_ext_mech_dir */
	u32 flags;			/* xdev_ext_mech_stage_uapi.flags without F_POLL */
	u32 index;			/* position in the chain */
	/* XDEV_EXT_MECH_STAGE_F_POLL accepted: set by the core before ->bind */
	bool poll;
	struct xdev_ext_mech_stage_caps caps;	/* CREATE record, OP_STAGE_CAPS */
};

/*
 * Class C.  The core runs every batch step in the session worker: fill_info,
 * the program's build (or default_build), the slot rule, ->validate, then
 * marks the batch and its frames IN_FLIGHT before ->submit.  ->submit
 * returns 0 once the native command is handed to the driver path, after
 * which exactly one xdev_ext_mech_batch_complete() or xdev_ext_mech_batch_sequester()
 * follows, possibly before ->submit returns and from any context; a negative
 * return means nothing reached the device and nothing will complete.
 */
/* Submit a session's batches in key order (a wire protocol needs it). */
#define XDEV_EXT_MECH_CLASS_F_ORDERED	(1U << 0)
/* Certified native-ZC submit preserves FIFO after accepted enqueue. */
#define XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE (1U << 1)
/* Read-only source plus an independent, bounded destination lease. */
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM (1U << 2)

/* First member of every family hooks structure. */
struct xdev_ext_family_hooks_hdr {
	u32 family;			/* enum xdev_ext_family */
};
struct xdev_ext_net_hooks;
struct xdev_ext_stor_hooks;
struct xdev_ext_comp_hooks;

struct xdev_ext_rel_policy;
struct xdev_ext_mech_class_ops {
	u32 class_id;			/* enum xdev_ext_mech_class */
	u32 flags;			/* XDEV_EXT_MECH_CLASS_F_* */
	u32 desc_size;			/* bytes per scratch slot */
	u32 desc_cap;			/* scratch slots per build */
	u32 info_size;			/* bytes of the class info structure */
	u32 cqe_size;			/* bytes per completion copy (worker complete) */
	u32 cqe_cap;
	u32 batch_priv_size;		/* bytes of xdev_ext_mech_batch_priv() */
	u32 batch_cookie_size;		/* stable callback storage; never stage-zeroed */
	struct module *owner;		/* pinned by each session with such a stage */
	/* CREATE, process context, may sleep */
	int  (*bind)(struct xdev_ext_mech_stage *st,
		     const struct xdev_ext_mech_stage_uapi *u);
	/* after drain, process context, may sleep; never for a quarantined stage */
	void (*unbind)(struct xdev_ext_mech_stage *st);
	/* Failure retains session/pool pins, including residual failed CREATE binds. */
	int (*unbind_checked)(struct xdev_ext_mech_stage *st);
	/* worker, or CREATE with b NULL; never sleeps */
	void (*fill_info)(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			  void *info);
	/* worker; NULL when the class has no C default; 0 or -errno */
	int  (*default_build)(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			      u8 *scratch);
	/* worker; 1 <= n <= desc_cap used slots; 0 or -errno, never partial */
	int  (*validate)(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			 const u8 *scratch, u32 n);
	/* worker, may sleep; the batch is already IN_FLIGHT */
	int  (*submit)(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b);
	/* worker, after the completion was queued back */
	void (*fill_cqe)(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			 void *cqe);
	/* any context, never blocks: start no new native work on this stage */
	void (*mark_dead)(struct xdev_ext_mech_stage *st);
 /* Same session worker, before final frame release; terminal chain outcome. */
 void (*batch_end)(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, int err);
 /* All stages, after final frame disposition; uncertainty must retain leases.
  * Multiple stages sharing a resource must make this callback idempotent.
  */
 void (*batch_release)(struct xdev_ext_mech_stage *st,
                       struct xdev_ext_mech_batch *b, bool sequestered);
 /* Same session worker, bounded transport progress; returns next poll delay. */
 unsigned long (*progress)(struct xdev_ext_mech_stage *st);
 /* Observational snapshot, provider lock only; both outputs start at zero. */
 void (*transport_stats)(struct xdev_ext_mech_stage *st, u32 *pending_acks,
                         u32 *uncertain_controls);
 /* Same snapshot rules; adds this stage's version 2 counters into @out. */
 void (*transport_counters)(struct xdev_ext_mech_stage *st,
                            struct xdev_ext_mech_transport_stats_v2 *out);
 void (*transport_policy)(struct xdev_ext_mech_stage *st, struct xdev_ext_rel_policy *out);
	/*
	 * Optional; only for a stage with st->poll, only from the session worker,
	 * no session lock held.  One bounded pass reaping native completions the
	 * device already produced; never sleeps, waits for the device or submits.
	 * Completions go through the usual claim and publish, possibly before it
	 * returns.  The number processed (>= 0, may include other users of a
	 * shared native queue) or -errno; informational only.  A class with this
	 * member refuses in ->bind (-EOPNOTSUPP) a device it cannot poll.
	 */
	int (*poll)(struct xdev_ext_mech_stage *st);
	/* Optional family hooks; checked at class registration. */
	union {
		const struct xdev_ext_family_hooks_hdr *hdr;
		const struct xdev_ext_net_hooks *net;
		const struct xdev_ext_stor_hooks *stor;
		const struct xdev_ext_comp_hooks *comp;
	} fam;
};

/* Initcall or module init, process context: -EBUSY if the class is taken. */
int xdev_ext_mech_class_register(const struct xdev_ext_mech_class_ops *ops);
/* Module exit, process context; sessions pin ops->owner, so none is left. */
void xdev_ext_mech_class_unregister(const struct xdev_ext_mech_class_ops *ops);

/*
 * Load time, from a class kfunc set's filter: 0 for kfuncs outside @ids;
 * otherwise only programs of @class_id's struct_ops type may call them, the
 * @build ones in build and the @complete ones in complete.
 */
int xdev_ext_mech_class_kfunc_filter(u32 class_id, const struct bpf_prog *prog,
				u32 kfunc_id, const struct btf_id_set8 *ids,
				const struct btf_id_set *build,
				const struct btf_id_set *complete);

/*
 * Load time, from a family kfunc set's filter: allow @family's struct_ops
 * types, with @build in build and @complete in complete; ignore other ids.
 */
int xdev_ext_mech_family_kfunc_filter(u32 family, const struct bpf_prog *prog,
				 u32 kfunc_id, const struct btf_id_set8 *ids,
				 const struct btf_id_set *build,
				 const struct btf_id_set *complete);

/*
 * Where batch frames live.  The provider fills it in its bind function and
 * keeps the UMEM, its pages and its state words alive until ->release.
 */
struct xdev_ext_mech_pool;

struct xdev_ext_mech_pool_ops {
	/* Worker, before CPU callbacks or another device maps these pages. */
	void (*sync_for_cpu)(struct xdev_ext_mech_pool *pool,
			     const struct xdev_ext_mech_frame *f);
	/* Preferred over sync_for_cpu; synchronizes all actual batch frames. */
	void (*sync_for_cpu_batch)(struct xdev_ext_mech_pool *pool,
				   const struct xdev_ext_mech_frame *f, u32 nr);
	/* worker: take @nr K_FREE frames, move them to HELD; -ENOSPC takes none */
	int  (*alloc)(struct xdev_ext_mech_pool *pool, struct xdev_ext_mech_frame *f,
		      u32 nr);
	/* worker: fill kaddr, umem_addr and pool_priv of chunk f->index */
	int  (*resolve)(struct xdev_ext_mech_pool *pool, struct xdev_ext_mech_frame *f);
	/* any context, never sleeps or takes rx_lock: a K_FREE frame goes back */
	void (*recycle)(struct xdev_ext_mech_pool *pool, struct xdev_ext_mech_frame *f);
	/* process context: drop the provider references; never if quarantined */
	void (*release)(struct xdev_ext_mech_pool *pool);
};

struct xdev_ext_mech_pool {
 struct xdev_ext_mech_life *life; /* optional provider-owned authoritative table */
	const struct xdev_ext_mech_pool_ops *ops;
	void *priv;			/* provider object */
	u8 *state;			/* nr_frames enum xdev_ext_mech_frame_state words */
	struct page **pages;
	void *vaddr;			/* kernel address of chunk 0 */
	u64 size;			/* bytes from chunk 0 */
	u32 kind;			/* enum xdev_ext_mech_pool_kind */
	u32 capabilities;		/* provider-certified XDEV_EXT_BINDING_CAP_* */
	u32 frame_size;			/* chunk size */
	u32 nr_frames;
	u32 nr_pages;
	u32 first_page_off;		/* offset of chunk 0 in pages[0] */
};

/*
 * Any context: the page holding byte @off of @f's chunk, the offset in it,
 * and the bytes left in that page; NULL past the chunk or the pool.
 */
static inline struct page *xdev_ext_mech_frame_page(const struct xdev_ext_mech_pool *pool,
					       const struct xdev_ext_mech_frame *f,
					       u32 off, u32 *page_off, u32 *len)
{
	u64 abs = pool->first_page_off + (u64)f->index * pool->frame_size + off;

	if (off >= pool->frame_size || f->index >= pool->nr_frames ||
	    abs >> PAGE_SHIFT >= pool->nr_pages)
		return NULL;
	*page_off = abs & ~PAGE_MASK;
	*len = PAGE_SIZE - *page_off;
	return pool->pages[abs >> PAGE_SHIFT];
}

/* CREATE, process context: an exclusive aligned AF_XDP UMEM behind @file. */
int xsk_xdev_ext_mech_pool_bind(struct xdev_ext_mech_pool *pool, struct file *file,
			   const struct xdev_ext_mech_layout *l);
/* CREATE, process context: the ring's IORING_REGISTER_XDEV_EXT_UMEM UMEM. */
int io_xdev_ext_umem_mech_pool_bind(struct xdev_ext_mech_pool *pool,
			       struct io_ring_ctx *ctx,
			       const struct xdev_ext_mech_layout *l);

/* CREATE, process context: device-memory frames have no CPU pages/address. */
int xdev_ext_peer_mech_pool_bind(struct xdev_ext_mech_pool *, struct file *,
                                const struct xdev_ext_mech_layout *);
/* Worker context: borrowed authority while the session retains its pool. */
struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *);
/* Worker context: generation captured by the exclusive CREATE claim. */
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *);

/* Any context: compare-and-exchange of chunk @index's ownership word. */
int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *pool, u32 index, u32 from,
			     u32 to);
/* Any context: current ownership word of chunk @index. */
u32 xdev_ext_mech_pool_frame_state(const struct xdev_ext_mech_pool *pool, u32 index);

/* Any context: a frame outside any batch (USER or K_FREE) goes to K_FREE. */
void xdev_ext_mech_frame_recycle(struct xdev_ext_mech_session *s,
			    struct xdev_ext_mech_frame *f);
/* Any context: a frame outside any batch goes to USER; -EBUSY if held. */
int xdev_ext_mech_frame_publish(struct xdev_ext_mech_session *s,
			   const struct xdev_ext_mech_frame *f);

/*
 * RX under receive serialization, or the session worker exclusively owning
 * a class-private pending NIC_RX frame: put @f into the OPEN batch of
 * @hold->key at @hold->pos with the hold span as its data, move it to HELD,
 * and queue the batch once complete. Batch mutation is protected internally
 * by the session lock and custody moves are atomic. A pending-queue owner
 * must not acquire pool->rx_lock while holding its queue lock.
 * -errno leaves @f untouched. The class reports its actual admission at
 * RX_HOLD_RESULT; a queued frame is committed here later by its sole owner.
 */
int xdev_ext_mech_hold_commit(struct xdev_ext_mech_stage *st,
			 const struct xdev_ext_mech_hold_intent *hold,
			 const struct xdev_ext_mech_frame *f);

/* Any context: queue bounded stage progress on the existing session worker. */
void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st);
/* Worker: atomically admit/pin native control through STOP/drain, or -ESHUTDOWN. */
int xdev_ext_mech_stage_native_get(struct xdev_ext_mech_stage *st);
/* Any context: release a definite native control completion; never on uncertainty. */
void xdev_ext_mech_stage_native_put(struct xdev_ext_mech_stage *st);

/* Any context. */
u64 xdev_ext_mech_session_id(const struct xdev_ext_mech_session *s);
/* Any context; stable for the session's life. */
const struct xdev_ext_mech_layout *
xdev_ext_mech_session_layout(const struct xdev_ext_mech_session *s);
/* Any context; stable for the session's life. */
const struct xdev_ext_mech_peer *
xdev_ext_mech_session_peer(const struct xdev_ext_mech_session *s);
/* Any context; stable for the session's life. */
struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s);
/* Any context. */
u32 xdev_ext_mech_session_depth(const struct xdev_ext_mech_session *s);
/* Any context: enum xdev_ext_mech_session_state. */
u32 xdev_ext_mech_session_state(const struct xdev_ext_mech_session *s);
/* Any context: first successful STOP time, under the session lock; zero is valid.
 * Read after observing admission closed. Repeated STOP never changes this clock. */
u64 xdev_ext_mech_session_stop_started_ns(struct xdev_ext_mech_session *s);
/* Any context: ACTIVE and every pinned generation still published. */
bool xdev_ext_mech_session_admits(const struct xdev_ext_mech_session *s);
/* Any context. */
void xdev_ext_mech_count(struct xdev_ext_mech_session *s, enum xdev_ext_mech_counter c,
		    u64 n);

/*
 * Process context (uring_cmd issue): the @class_id stage bound to this
 * command's ring and file, with a session reference; ERR_PTR(-EOPNOTSUPP)
 * when there is none.
 */
struct xdev_ext_mech_stage *xdev_ext_mech_stage_get_cmd(struct io_uring_cmd *ioucmd,
					      u32 class_id);
/* Any context; a final put frees the session from a worker. */
void xdev_ext_mech_stage_put(struct xdev_ext_mech_stage *st);
/*
 * Any context, never blocks, even with xs->mutex held: the stage's device
 * went away.  Records @err, stops admission, calls ->mark_dead and queues
 * the teardown.
 */
/* Close admission and drain, without declaring external users quiescent. */
void xdev_ext_mech_stage_stop(struct xdev_ext_mech_stage *st, int err);
int xdev_ext_mech_stage_stop_error(struct xdev_ext_mech_stage *st);
void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st, int err);

/* Any context. */
u64 xdev_ext_mech_batch_id(const struct xdev_ext_mech_batch *b);
/* Any context: RX hold key or START sequence. */
u64 xdev_ext_mech_batch_key(const struct xdev_ext_mech_batch *b);
/* Any context: fixed batch index, stable through all stages and retries. */
u32 xdev_ext_mech_batch_slot(const struct xdev_ext_mech_batch *b);
/* Any context. */
u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch *b);
/* Any context: sum of the frames' data_len. */
u32 xdev_ext_mech_batch_bytes(const struct xdev_ext_mech_batch *b);
/* Any context. */
struct xdev_ext_mech_session *xdev_ext_mech_batch_session(const struct xdev_ext_mech_batch *b);
/* Any context: the stage the batch is READY or IN_FLIGHT at. */
struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(const struct xdev_ext_mech_batch *b);
/* Any context: frame @pos of the batch; -ERANGE past nr_frames. */
int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch *b, u32 pos,
			 struct xdev_ext_mech_frame *f);
/* Process context, CREATE: reserve distinct IOU output frames for a transform stage. */
int xdev_ext_mech_transform_reserve(struct xdev_ext_mech_stage *st, u32 first, u32 nr);
/* Process context, unbind after drain: return an idle reserved lease. */
void xdev_ext_mech_transform_unreserve(struct xdev_ext_mech_stage *st, u32 first, u32 nr);
/* Worker context, submit: dst spans carry capacities; source spans remain read-only. */
int xdev_ext_mech_batch_transform_begin(struct xdev_ext_mech_batch *b,
                                      const struct xdev_ext_mech_frame *dst, u32 nr);
/* Any context, provider terminal callback: immutable ticket wins before result metadata. */
void xdev_ext_mech_batch_transform_complete(struct xdev_ext_mech_batch *b, u64 ticket,
                                          int err, u32 produced, bool sequester);
/* Any context: actual produced length, after terminal publication. */
u32 xdev_ext_mech_batch_transform_produced(const struct xdev_ext_mech_batch *b);
/* Worker context, fill_cqe: native terminal status consumed by the core. */
int xdev_ext_mech_batch_status(const struct xdev_ext_mech_batch *b);

/*
 * Any context: the class area of cls->batch_priv_size bytes.  The worker
 * zeroes it when a step starts, before ->validate; from there it stays
 * intact through ->submit and the completion to ->fill_cqe, so ->validate
 * can hand ->submit what it admitted.  A sequestered batch's area is never
 * reused or freed.
 */
void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b);
/* Any context: stable callback storage for the batch/session lifetime. */
void *xdev_ext_mech_batch_cookie(struct xdev_ext_mech_batch *b);
/* Any context: capture at submit and retain by value in the native request. */
u64 xdev_ext_mech_batch_ticket(const struct xdev_ext_mech_batch *b);
/*
 * Any context: claim before writing class completion metadata. A stale or
 * duplicate ticket fails without changing metadata. Success must be followed
 * by exactly one publish. This does not extend the native object's lifetime:
 * callbacks after native/session destruction remain invalid.
 */
int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b, u64 ticket);
/* Worker context: snapshot planned command and actual class validation result. */
void xdev_ext_mech_trace_plan(struct xdev_ext_mech_batch *b, u64 lba,
			    u32 bytes, u32 plan, int status);
/* Worker context, provider TX lock held: immutable frame/descriptor binding. */
void xdev_ext_mech_trace_descriptor_bind(struct xdev_ext_mech_batch *b,
		u32 pos, u64 pool, u64 address, u32 bytes);
/* Worker context: immediately before native accepted-request handoff. */
void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b, u64 cookie,
				     u64 lba, u32 bytes, u32 opcode);
/* Any context: winning native end_io claim, before completion publication. */
void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,
				       u64 ticket, int status);
/* Any context: matching claim winner only; publish metadata then enqueue. */
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b, u64 ticket,
				      int err, bool sequester);
/*
 * Any context (end_io, softirq, backend callback): claim and publish a native
 * completion. err is 0, a negative errno, or a positive native class status.
 * Accepted commands are never resent by BPF RETRY; preaccept queue refusal is
 * rolled back and scheduled separately by the core.
 */
void xdev_ext_mech_batch_complete_produced(struct xdev_ext_mech_batch *b,
                                         u64 ticket, int err, u32 produced);
/* Any context after native publication: valid bytes reported by this stage. */
u32 xdev_ext_mech_batch_produced(const struct xdev_ext_mech_batch *b);
/* Any context: publish one terminal native result using the immutable ticket. */
enum xdev_ext_mech_external_outcome {
 XDEV_EXT_MECH_EXTERNAL_QUIESCED = 0,
 XDEV_EXT_MECH_EXTERNAL_UNKNOWN = 1,
};
int xdev_ext_mech_batch_external_complete(
 struct xdev_ext_mech_batch *b, u64 ticket, int err,
 enum xdev_ext_mech_external_outcome outcome);

void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b, u64 ticket, int err);
/* Any context: explicit local cancellation after proving no native owner remains. This
 * cannot report a hardware error; native failures use batch_complete(). */
void xdev_ext_mech_batch_complete_cancelled(struct xdev_ext_mech_batch *b,
					 u64 ticket, int err);
/*
 * Any context: instead of xdev_ext_mech_batch_complete() when the device may
 * still use the frames.  The worker still runs complete for the record, then
 * the batch and its frames are SEQUESTERED whatever the program returned.
 */
void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch *b, u64 ticket, int err);

/* Device-side window bound for one CE stage. */
struct xdev_ext_ce_region {
	const struct xdev_ext_ce_backend_ops *ops;	/* set by the core */
	void *priv;			/* backend object */
	u64 len;			/* window bytes */
	u32 seg_size;			/* device-contiguous segment; 0: whole window */
	u32 max_entry_len;		/* largest entry; 0: seg_size */
};

/* One copy, translated by C from a validated struct xdev_ext_ce_copy_desc. */
struct xdev_ext_ce_xfer {
	u64 owner;		/* immutable per-frame claim owner */
	u64 generation;		/* immutable per-frame claim generation */
	u64 host_byte_off;		/* from the start of the bind_host() pages */
	u64 gpu_off;			/* in the window */
	u32 len;
	u32 flags;			/* XDEV_EXT_CE_F_* */
};

/* Worker context: record an exclusive in-place stage's (CPU, USER) bounded output length. */
int xdev_ext_mech_batch_cpu_length(struct xdev_ext_mech_batch *b, u32 pos, u32 len);
/*
 * Worker context, from a CPU stage's ->submit: run the compute program of the
 * generation the session pinned over @b, then give every frame exactly
 * data_len + @delta bytes.  0; -EBADMSG or -EMSGSIZE, before the program
 * runs, when a frame cannot take that length; the program's own -errno;
 * -EOPNOTSUPP without a compute program; -EPROTO for an illegal return, a
 * kfunc misuse or a frame left at another length.  Never retry on failure.
 */
int xdev_ext_mech_batch_compute(struct xdev_ext_mech_batch *b, s32 delta);
/* Process or worker context: the generation @st's session pinned has @member. */
bool xdev_ext_mech_stage_has_member(const struct xdev_ext_mech_stage *st, u32 member);
/* Worker context: snapshot the current immutable per-frame claim. */
int xdev_ext_mech_batch_frame_claim(const struct xdev_ext_mech_batch *b,
                                   u32 pos, u64 *owner, u64 *generation);
/* Any context: validate the ticket before reading reusable batch claims. */
bool xdev_ext_mech_batch_ce_owners_valid(const struct xdev_ext_mech_batch *b,
                                       u64 ticket, const struct xdev_ext_ce_xfer *x, u32 n);
/* Any context: validate saved CE transfers against their live native ticket. */
bool xdev_ext_ce_owners_valid(struct xdev_ext_ce_cookie *ck, u64 ticket,
                             const struct xdev_ext_ce_xfer *x, u32 n);

/*
 * A CE backend; a stage fd selects it by f_op.  ->submit returns 0 once it
 * accepted the transfers; exactly one xdev_ext_ce_complete() follows, possibly
 * before ->submit returns.  A negative return means nothing was submitted
 * and no xdev_ext_ce_complete() will come.
 */
struct xdev_ext_ce_backend_ops {
	struct module *owner;
	const struct file_operations *fops;
	/* CREATE caller's process context, may sleep */
	int  (*bind_region)(struct file *f, u64 gpu_va, u64 len,
			    struct xdev_ext_ce_region *out);
	/* process context, may sleep; never after an AMBIGUOUS outcome */
	int  (*unbind_region)(struct xdev_ext_ce_region *r);
	/* CREATE, process context: pool pages, already pinned by their UMEM */
	int  (*bind_host)(struct xdev_ext_ce_region *r, struct page **pages, u32 nr,
			  void **host);
	/* process context */
	int  (*unbind_host)(void *host);
	/* session worker, may sleep; dir is enum xdev_ext_mech_dir. Retain ticket
	 * by value for the callback, never recover it from a mutable cookie. */
	int  (*submit)(struct xdev_ext_ce_region *r, void *host, u32 dir,
		       const struct xdev_ext_ce_xfer *x, u32 n,
		       struct xdev_ext_ce_cookie *ck, u64 ticket);
};

/* Module init, process context: -EBUSY if ops->fops is already registered. */
int xdev_ext_ce_backend_register(const struct xdev_ext_ce_backend_ops *ops);
/* Module exit, process context; sessions pin ops->owner, so none is left. */
void xdev_ext_ce_backend_unregister(const struct xdev_ext_ce_backend_ops *ops);
/*
 * Any context, once per accepted submit.  hw_submitted: GPPut or a doorbell
 * was written.  status 0 is OK; a failure is PRE_SUBMIT_FAILED without
 * hw_submitted and AMBIGUOUS with it.
 */
void xdev_ext_ce_complete(struct xdev_ext_ce_cookie *ck, u64 ticket, int status,
		     bool hw_submitted, u64 bytes_done);

/* Generic provider: registered dynamically by fops, with owner pinned by C. */
struct xdev_ext_dma_cookie;
struct xdev_ext_dma_provider_ops;
struct xdev_ext_dma_region {
	const struct xdev_ext_dma_provider_ops *ops;
	void *priv;
	u64 len;
	u32 segment_size, max_entry_len, alignment, directions;
	/* Set by the class before ->bind_region for a polled stage; the
	 * provider must not clear it, and refuses (-EOPNOTSUPP) a device it
	 * cannot poll.  Normal completions then come from ->poll (or inline in
	 * ->submit), never from a device interrupt or a provider thread. */
	bool polled;
};
struct xdev_ext_dma_xfer {
	u64 host_byte_off, device_off;
	u32 len, flags;
};
/* Accepted submit returns 0, completes exactly once (possibly inline).
 * Negative return guarantees no submission and no callback. Provider owns
 * dma_map/sync, native queue/doorbell/completion, and reachability checks.
 */
struct xdev_ext_dma_provider_ops {
	struct module *owner;
	const struct file_operations *fops;
	int (*bind_region)(struct file *f, u64 device_off, u64 len,
			   struct xdev_ext_dma_region *out);
	void (*unbind_region)(struct xdev_ext_dma_region *r);
	int (*bind_host)(struct xdev_ext_dma_region *r, struct page **pages, u32 nr,
			 void **host);
	int  (*unbind_host)(void *host);
	int (*submit)(struct xdev_ext_dma_region *r, void *host, u32 dir,
		      const struct xdev_ext_dma_xfer *x, u32 n,
		      struct xdev_ext_dma_cookie *cookie, u64 ticket);
	/* Optional: a polled region's completion pass in the session worker;
	 * never sleeps.  Transfers it completed (>= 0) or -errno. */
	int (*poll)(struct xdev_ext_dma_region *r);
};
/* Module init, process context: duplicate fops fails with -EBUSY. */
int xdev_ext_dma_provider_register(const struct xdev_ext_dma_provider_ops *ops);
/* Module exit, process context; bound sessions hold owner references. */
void xdev_ext_dma_provider_unregister(const struct xdev_ext_dma_provider_ops *ops);
/* Any context, once per accepted submit, with its immutable ticket. */
void xdev_ext_dma_complete(struct xdev_ext_dma_cookie *cookie, u64 ticket,
		      int status, bool hw_submitted, u64 bytes_done);

/*
 * Shared kfuncs (io_uring/xdev_ext_mech_ops.c) and AF_XDP kfuncs
 * (net/xdp/xsk_xdev_ext_mech.c), all KF_TRUSTED_ARGS, views also KF_RET_NULL.
 * Declared for C callers of the same checks.
 */
/* Any context, during a callback: the class info, rdonly_buf_size == info_size. */
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, const size_t rdonly_buf_size);
/* Any context, during build: slot @slot of the scratch. */
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
		   const size_t rdwr_buf_size);
/* Any context, during complete: completion copy @slot. */
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
		  const size_t rdonly_buf_size);
/* Any context, during build, complete or compute: chunk bytes [off, off + size). */
__u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *ctx, __u32 pos, __u32 off,
		    const size_t rdonly_buf_size);
/* Any context, during build, complete or compute: crc32c() over chunk bytes. */
__u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
			   __u32 off, __u32 len, __u32 seed);
/* Any context: crc32c() over a program stack buffer. */
__u32 bpf_xdev_ext_crc32c(const void *buf, __u32 buf__sz, __u32 seed);
/* Worker context, during compute: valid length of frame @pos on entry. */
__u32 bpf_xdev_ext_frame_len(const struct xdev_ext_mech_ctx *ctx, __u32 pos);
/*
 * Worker context, during compute: writable bytes [off, off + size) counted
 * from frame @pos's first valid byte, inside frame_size - data_off.
 */
__u8 *bpf_xdev_ext_frame_rw(const struct xdev_ext_mech_ctx *ctx, __u32 pos, __u32 off,
		       const size_t rdwr_buf_size);
/* Worker context, during compute: record frame @pos's output length, L + D. */
int bpf_xdev_ext_frame_set_len(const struct xdev_ext_mech_ctx *ctx, __u32 pos, __u32 len);
/* AF_XDP RX complete, pool rx_lock held: writable stage protocol state. */
__u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *ctx,
			     const size_t rdwr_buf_size);
/* Any context, during AF_XDP TX build: header room bytes of frame @pos. */
__u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *ctx, __u32 pos, __u32 off,
			const size_t rdwr_buf_size);
/*
 * AF_XDP RX_GENERIC/RX_NATIVE complete, rx_lock held: record one hold intent.
 * RX_HOLD_RESULT cannot record another hold. A
 * kfunc takes at most five arguments (MAX_BPF_FUNC_REG_ARGS), so the frames
 * per batch come from the session layout, not from the program.
 */
int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *ctx, __u64 key, __u32 pos,
		       __u32 span_off, __u32 span_len);

#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
/* Same layout as the struct_ops types; plain C callbacks. */
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_mech_c_ops);
/*
 * Process context, measurement builds only: run @class_id's callbacks from
 * @ops, code of @owner, instead of BPF for sessions created afterwards;
 * NULL restores BPF.  A session or call on @ops holds @owner until it lets
 * go; sessions still on a cleared or replaced table stop admitting with
 * -ECANCELED, like a retracted generation.
 */
int __xdev_ext_mech_set_c_ops(u32 class_id, const struct xdev_ext_mech_c_ops *ops,
			 struct module *owner);
#define xdev_ext_mech_set_c_ops(class_id, ops)				\
	__xdev_ext_mech_set_c_ops(class_id, ops, THIS_MODULE)
#endif

#ifdef CONFIG_XDEV_EXT_MECH
/* Process context, uring_lock held: IORING_REGISTER_XDEV_EXT_MECH. */
int io_xdev_ext_mech_register(struct io_ring_ctx *ctx, void __user *arg,
			 unsigned int nr_args);
/* Process context (io_ring_exit_work): STOP and bounded drain of every session. */
void io_xdev_ext_mech_ring_exit(struct io_ring_ctx *ctx);
#else
static inline int io_xdev_ext_mech_register(struct io_ring_ctx *ctx,
				       void __user *arg, unsigned int nr_args)
{
	return -EINVAL;
}

static inline void io_xdev_ext_mech_ring_exit(struct io_ring_ctx *ctx)
{
}
#endif
#endif /* __KERNEL__ */

#ifdef CONFIG_XDEV_EXT_MECH
extern int bpf_xdev_ext_rel_rx_view(const struct xdev_ext_mech_ctx *ctx, __u64 group,
                                  void *view, __u32 view__sz);
extern int bpf_xdev_ext_rel_rx_data(const struct xdev_ext_mech_ctx *ctx, __u64 group,
                                  __u32 index, __u32 attempt, __u32 verdict);
extern int bpf_xdev_ext_rel_rx_control(const struct xdev_ext_mech_ctx *ctx, __u64 group,
                                     __u32 attempt, __u64 credit, __u32 type);
extern int bpf_xdev_ext_rel_policy(const struct xdev_ext_mech_ctx *ctx, void *policy,
                                 __u32 policy__sz);

extern __u8 *bpf_xdev_ext_rel_tx_view(const struct xdev_ext_mech_ctx *ctx,
                                    const size_t rdonly_buf_size);

#endif
#endif /* _LINUX_XDEV_EXT_MECH_H */

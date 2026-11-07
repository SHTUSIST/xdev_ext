/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_COMPFAM_COPY_RUNTIME_H
#define IO_URING_XDEV_EXT_COMPFAM_COPY_RUNTIME_H

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_compfam_copy_core.h"
#include "xdev_ext_mech_native_cookie.h"

struct xdev_ext_comp_copy_stage;
struct xdev_ext_dma_scope_ops;

struct xdev_ext_comp_copy_member {
	const void *identity;
	const struct file_operations *fops;
	struct module *owner;
	const struct xdev_ext_dma_scope_ops *scope_ops;
};

struct xdev_ext_comp_copy_registration {
	struct list_head node;
	struct xdev_ext_comp_copy_member member;
};

struct xdev_ext_comp_copy_registry {
	struct mutex lock;
	struct list_head members;
	struct xdev_ext_comp_copy_registration *fixed;
	u32 capacity; /* fixed != NULL: static slots; NULL: dynamic */
};

/* Stable per-batch allocation, shared across typed adapter transitions. */
struct xdev_ext_comp_copy_cookie {
	struct xdev_ext_mech_batch *b;
	struct xdev_ext_comp_copy_stage *cs;
	u64 bytes_done;
	int status;
	u32 outcome;
	u8 state;
};
XDEV_EXT_NATIVE_COOKIE_ASSERT(struct xdev_ext_comp_copy_cookie);

struct xdev_ext_comp_copy_legacy_ops {
	int (*lease_get)(struct xdev_ext_comp_copy_stage *,
			 struct xdev_ext_mech_batch *);
	int (*submit)(struct xdev_ext_comp_copy_stage *,
		      struct xdev_ext_mech_stage *, struct xdev_ext_mech_batch *,
		      const struct xdev_ext_comp_copy_transfer *, u32 n,
		      u64 total, struct xdev_ext_comp_copy_cookie *, u64 ticket);
	u32 (*classify)(struct xdev_ext_mech_batch *, u64 ticket,
			int *status, bool *hw_submitted, u64 bytes_done);
	int (*unbind_begin)(struct xdev_ext_comp_copy_stage *);
	int (*unbind_host)(struct xdev_ext_comp_copy_stage *);
	int (*unbind_region)(struct xdev_ext_comp_copy_stage *);
	int (*unbind_end)(struct xdev_ext_comp_copy_stage *);
	int (*poll)(struct xdev_ext_comp_copy_stage *);
	void (*warn)(bool refused_submit);
};

/* Scratch is worker-only; dead and ambiguous retain their atomic access. */
struct xdev_ext_comp_copy_stage {
	const struct xdev_ext_comp_copy_legacy_ops *ops;
	void *host;
	struct xdev_ext_comp_copy_window window;
	atomic_t ambiguous;
	bool dead;
	struct xdev_ext_mech_batch *staged;
	struct xdev_ext_comp_copy_plan plan;
	struct xdev_ext_comp_copy_transfer transfer[XDEV_EXT_COMP_COPY_MAX_ENTRIES];
	struct xdev_ext_mech_frame_info fi[XDEV_EXT_MECH_MAX_FRAMES];
	u32 index[XDEV_EXT_MECH_MAX_FRAMES];
};

int xdev_ext_comp_copy_registry_register(struct xdev_ext_comp_copy_registry *,
	const struct xdev_ext_comp_copy_member *);
bool xdev_ext_comp_copy_registry_unregister(struct xdev_ext_comp_copy_registry *,
	const void *identity);
bool xdev_ext_comp_copy_registry_get(struct xdev_ext_comp_copy_registry *,
	struct file *, struct xdev_ext_comp_copy_member *out);
int xdev_ext_comp_copy_collect(struct xdev_ext_comp_copy_stage *,
	struct xdev_ext_mech_batch *);
int xdev_ext_comp_copy_stage_validate(struct xdev_ext_comp_copy_stage *,
	struct xdev_ext_mech_batch *, const u8 *scratch, u32 n,
	u32 max_entries, u32 known_flags);
int xdev_ext_comp_copy_stage_submit(struct xdev_ext_comp_copy_stage *,
	struct xdev_ext_mech_stage *, struct xdev_ext_mech_batch *);
void xdev_ext_comp_copy_complete(struct xdev_ext_comp_copy_cookie *, u64 ticket,
	int status, bool hw_submitted, u64 bytes_done,
	const struct xdev_ext_comp_copy_legacy_ops *);
void xdev_ext_comp_copy_mark_dead(struct xdev_ext_comp_copy_stage *);
int xdev_ext_comp_copy_poll(struct xdev_ext_comp_copy_stage *);
int xdev_ext_comp_copy_unbind(struct xdev_ext_comp_copy_stage *);

#endif /* IO_URING_XDEV_EXT_COMPFAM_COPY_RUNTIME_H */

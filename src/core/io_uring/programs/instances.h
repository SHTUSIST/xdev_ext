/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_PROGRAMS_H
#define IO_URING_XDEV_EXT_MECH_PROGRAMS_H

#include <linux/types.h>

struct bpf_link;
struct xdev_ext_mech_instance;

/* Struct-ops registration context; no session or lasting link reference. */
int xdev_ext_mech_instance_register(u32 class_id, const void *ops,
				  struct bpf_link *link);
bool xdev_ext_mech_instance_unregister(u32 class_id, const void *ops,
				     struct bpf_link *link);

/*
 * Process context. Success owns one record ref plus one struct_ops pin.
 * The temporary fd lookup's link ref is released before this returns.
 * A concurrent withdrawal can make the returned held instance noncurrent.
 */
int xdev_ext_mech_instance_get_from_fd(u32 class_id, int fd,
				     struct xdev_ext_mech_instance **out);

/* Any context, with a selected handle held. Ops remain pinned after unreg. */
bool xdev_ext_mech_instance_current(const struct xdev_ext_mech_instance *instance);
const void *xdev_ext_mech_instance_ops(const struct xdev_ext_mech_instance *instance);

/*
 * Process context, after worker/native safety, outside registry/session locks.
 * Balances one selected handle, including its real struct_ops pin.
 */
void xdev_ext_mech_instance_put(struct xdev_ext_mech_instance *instance);

/* Core notifier. Retired record is still owned; no registry lock is held. */
void xdev_ext_mech_instance_gone(struct xdev_ext_mech_instance *instance);

#endif /* IO_URING_XDEV_EXT_MECH_PROGRAMS_H */

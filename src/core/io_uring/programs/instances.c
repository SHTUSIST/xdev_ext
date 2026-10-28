// SPDX-License-Identifier: GPL-2.0
/* Independent PRIVATE mechanism generations; default registry stays separate. */
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/xdev_ext_family_core.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_programs.h"

struct xdev_ext_mech_instance {
	struct hlist_node node;
	/*
	 * Lookup key only. No link ref is retained and cached readers never
	 * dereference it: selected handles can outlive the link allocation.
	 */
	struct bpf_link *link;
	const void *ops;
	refcount_t refs;
	u32 class_id;
	bool live;
};

static DEFINE_HASHTABLE(xdev_ext_mech_instances, 6);
static DEFINE_MUTEX(xdev_ext_mech_instances_lock);

static bool xdev_ext_mech_instance_class(u32 class_id)
{
	return xdev_ext_mech_class_desc(class_id)->family != XDEV_EXT_FAMILY_NONE;
}

static bool xdev_ext_mech_instance_private(const void *ops)
{
	const struct xdev_ext_nvme_mech_ops *common = ops;

	return common && common->flags == XDEV_EXT_MECH_OPS_F_PRIVATE;
}

/*
 * Caller owns the registry mutex; this function returns no unpinned pointer
 * to a caller outside that critical section.
 */
static struct xdev_ext_mech_instance *
xdev_ext_mech_instance_find(struct bpf_link *link)
{
	struct xdev_ext_mech_instance *instance;

	hash_for_each_possible(xdev_ext_mech_instances, instance, node,
			       (unsigned long)link)
		if (instance->link == link)
			return instance;
	return NULL;
}

/* Registration owns only a record ref, never a struct_ops or link pin. */
static void xdev_ext_mech_instance_record_put(struct xdev_ext_mech_instance *instance)
{
	if (refcount_dec_and_test(&instance->refs))
		kfree(instance);
}

int xdev_ext_mech_instance_register(u32 class_id, const void *ops,
				  struct bpf_link *link)
{
	struct xdev_ext_mech_instance *instance;
	int ret = 0;

	if (!link)
		return -EOPNOTSUPP;
	if (!xdev_ext_mech_instance_class(class_id) ||
	    link->type != BPF_LINK_TYPE_STRUCT_OPS ||
	    !xdev_ext_mech_instance_private(ops))
		return -EINVAL;
	instance = kzalloc(sizeof(*instance), GFP_KERNEL);
	if (!instance)
		return -ENOMEM;
	instance->link = link;
	instance->ops = ops;
	instance->class_id = class_id;
	refcount_set(&instance->refs, 1);
	instance->live = true;

	mutex_lock(&xdev_ext_mech_instances_lock);
	if (xdev_ext_mech_instance_find(link))
		ret = -EBUSY;
	else
		hash_add(xdev_ext_mech_instances, &instance->node, (unsigned long)link);
	mutex_unlock(&xdev_ext_mech_instances_lock);
	if (ret)
		xdev_ext_mech_instance_record_put(instance);
	return ret;
}

bool xdev_ext_mech_instance_unregister(u32 class_id, const void *ops,
				     struct bpf_link *link)
{
	struct xdev_ext_mech_instance *instance;

	mutex_lock(&xdev_ext_mech_instances_lock);
	instance = xdev_ext_mech_instance_find(link);
	if (!instance || instance->class_id != class_id || instance->ops != ops) {
		mutex_unlock(&xdev_ext_mech_instances_lock);
		return false;
	}
	/* Cached liveness closes before either notification or record release. */
	smp_store_release(&instance->live, false);
	hash_del(&instance->node);
	mutex_unlock(&xdev_ext_mech_instances_lock);

	/*
	 * All hash readers use the mutex and cached readers own record refs.
	 * No private RCU grace period or link retention is needed here.
	 */
	xdev_ext_mech_instance_gone(instance);
	xdev_ext_mech_instance_record_put(instance);
	return true;
}

int xdev_ext_mech_instance_get_from_fd(u32 class_id, int fd,
				     struct xdev_ext_mech_instance **out)
{
	struct xdev_ext_mech_instance *instance;
	struct bpf_link *link;
	int ret = 0;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!xdev_ext_mech_instance_class(class_id))
		return -EINVAL;
	link = bpf_link_get_from_fd(fd);
	if (IS_ERR(link))
		return PTR_ERR(link);
	if (link->type != BPF_LINK_TYPE_STRUCT_OPS) {
		ret = -EINVAL;
		goto put_link;
	}

	mutex_lock(&xdev_ext_mech_instances_lock);
	instance = xdev_ext_mech_instance_find(link);
	if (!instance || !instance->live ||
	    !xdev_ext_mech_instance_private(instance->ops)) {
		ret = -ENOENT;
	} else if (instance->class_id != class_id) {
		ret = -EINVAL;
	} else if (!bpf_struct_ops_get(instance->ops)) {
		ret = -ENOENT;
	} else {
		refcount_inc(&instance->refs);
		*out = instance;
	}
	mutex_unlock(&xdev_ext_mech_instances_lock);
 put_link:
	/* Final link put can reenter unregister; never hold our mutex here. */
	bpf_link_put(link);
	return ret;
}

bool xdev_ext_mech_instance_current(const struct xdev_ext_mech_instance *instance)
{
	return instance && smp_load_acquire(&instance->live);
}

const void *xdev_ext_mech_instance_ops(const struct xdev_ext_mech_instance *instance)
{
	return instance ? instance->ops : NULL;
}

void xdev_ext_mech_instance_put(struct xdev_ext_mech_instance *instance)
{
	if (!instance)
		return;
	bpf_struct_ops_put(instance->ops);
	xdev_ext_mech_instance_record_put(instance);
}

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __XDEV_EXT_BINDING_COMMON_H
#define __XDEV_EXT_BINDING_COMMON_H

/* Keep the test programs tied to the ABI exported by this source tree. */
#include "../../../../../include/uapi/linux/xdev_ext_binding.h"
#include <bpf/bpf_helpers.h>

/* This is the BTF-visible policy type.  The context itself comes from the
 * authoritative UAPI above rather than a test-local copy.
 */
struct xdev_ext_binding_ops {
	__u32 abi_version;
	__u32 backend;
	__u32 flags;
	__u32 reserved;
	__s32 (*dispatch)(const struct xdev_ext_binding_ctx_v2 *ctx);
	__s32 (*complete)(const struct xdev_ext_binding_ctx_v2 *ctx);
} __attribute__((preserve_access_index));

extern int bpf_xdev_ext_dispatch_action(const struct xdev_ext_binding_ctx_v2 *ctx,
				   __u32 action, __u32 recipe,
				   __u32 next_stage, __u32 profile) __ksym;
extern int bpf_xdev_ext_complete_action(const struct xdev_ext_binding_ctx_v2 *ctx,
				   __u32 action, __u32 recipe,
				   __u32 next_stage, __u32 profile) __ksym;

_Static_assert(sizeof(struct xdev_ext_binding_ctx_v2) == 136,
	       "struct xdev_ext_binding_ctx_v2 ABI size changed");

#endif /* __XDEV_EXT_BINDING_COMMON_H */

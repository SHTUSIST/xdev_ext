/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CLASS_DECLARATIONS_TEST_ADAPTER_H
#define CLASS_DECLARATIONS_TEST_ADAPTER_H
/* Entry selection only. Baseline runs existing production public wrappers.
 * It deliberately cannot use an explicit row: that is the missing behavior.
 * core-table-v1/block-v2 selects the independent oracle, not these entries. */
#include "xdev_ext_mech_start_queue.h"
static inline bool test_ret(const struct xdev_ext_mech_class_desc *d,
 __u32 id, __u32 member, __u32 site, __s32 ret)
{
#ifdef CLASS_DECLARATIONS_DESC
 (void)id; return xdev_ext_mech_ret_legal_desc(d, member, site, ret);
#else
 (void)d; return xdev_ext_mech_ret_legal(id, member, site, ret);
#endif
}
static inline __s32 test_resolve(const struct xdev_ext_mech_class_desc *d,
 __u32 id, __u32 member, __u32 site, __s32 ret, bool *illegal)
{
#ifdef CLASS_DECLARATIONS_DESC
 (void)id; return xdev_ext_mech_ret_resolve_desc(d, member, site, ret, illegal);
#else
 (void)d; return xdev_ext_mech_ret_resolve(id, member, site, ret, illegal);
#endif
}
static inline bool test_retry(const struct xdev_ext_mech_class_desc *d,
 __u32 id, __u32 retries, __s32 status)
{
#ifdef CLASS_DECLARATIONS_DESC
 (void)id; return xdev_ext_mech_retry_ok_desc(d, retries, status);
#else
 (void)d; return xdev_ext_mech_retry_ok(id, retries, status);
#endif
}
static inline int test_role(const struct xdev_ext_mech_class_desc *d,
 const struct xdev_ext_mech_stage_uapi *u)
{
#ifdef CLASS_DECLARATIONS_DESC
 return xdev_ext_mech_stage_role_desc(d, u);
#else
 (void)d; return xdev_ext_mech_stage_role(u);
#endif
}
static inline int test_create(const struct xdev_ext_mech_create *c,
 const struct xdev_ext_mech_class_desc *const rows[XDEV_EXT_MECH_MAX_STAGES],
 __u32 *frames)
{
#ifdef CLASS_DECLARATIONS_DESC
 return xdev_ext_mech_create_check_desc(c, rows, frames);
#else
 (void)rows; return xdev_ext_mech_create_check(c, frames);
#endif
}
static inline int test_start(const struct xdev_ext_mech_stage_uapi *st,
 const struct xdev_ext_mech_class_desc *const *rows, __u32 nr)
{
#ifdef CLASS_DECLARATIONS_DESC
 return xdev_ext_mech_start_queue_plan_check_desc(st, rows, nr);
#else
 (void)rows; return xdev_ext_mech_start_queue_plan_check(st, nr);
#endif
}
#endif

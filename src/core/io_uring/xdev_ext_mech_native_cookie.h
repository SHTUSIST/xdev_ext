/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_NATIVE_COOKIE_H
#define XDEV_EXT_MECH_NATIVE_COOKIE_H
#include <linux/types.h>
struct xdev_ext_mech_batch;
/* The same stable batch allocation serves CE and DMA. A late old-class
 * callback may read only b before claiming its immutable native ticket.
 * Keep every field's shape explicit so class-local changes fail the build. */
struct xdev_ext_native_cookie_layout {
 struct xdev_ext_mech_batch *b;
 void *cs;
 __u64 bytes_done;
 int status;
 __u32 outcome;
 __u8 state;
};
#define XDEV_EXT_NATIVE_COOKIE_FIELD_ASSERT(type,member) \
 _Static_assert(__builtin_offsetof(type,member)== \
                __builtin_offsetof(struct xdev_ext_native_cookie_layout,member), \
                "native cookie offset: " #member)
#define XDEV_EXT_NATIVE_COOKIE_ASSERT(type) \
 _Static_assert(sizeof(type)==sizeof(struct xdev_ext_native_cookie_layout),"native cookie size"); \
 _Static_assert(__alignof__(type)==__alignof__(struct xdev_ext_native_cookie_layout),"native cookie alignment"); \
 XDEV_EXT_NATIVE_COOKIE_FIELD_ASSERT(type,b); \
 XDEV_EXT_NATIVE_COOKIE_FIELD_ASSERT(type,cs); \
 XDEV_EXT_NATIVE_COOKIE_FIELD_ASSERT(type,bytes_done); \
 XDEV_EXT_NATIVE_COOKIE_FIELD_ASSERT(type,status); \
 XDEV_EXT_NATIVE_COOKIE_FIELD_ASSERT(type,outcome); \
 XDEV_EXT_NATIVE_COOKIE_FIELD_ASSERT(type,state)
#endif

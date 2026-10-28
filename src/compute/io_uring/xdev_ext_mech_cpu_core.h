/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CPU_CORE_H
#define XDEV_EXT_MECH_CPU_CORE_H
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#endif
#include "../include/uapi/linux/xdev_ext_mech.h"

struct xdev_ext_mech_cpu_prims {
 __u32 (*crc32c)(__u32 crc, const void *p, size_t len);
 __u64 (*xxh64)(const void *p, size_t len, __u64 seed);
 void (*sha256)(const void *p, size_t len, __u8 out[32]);
};

static inline bool xdev_ext_mech_cpu_xform_fixed(__u32 xform)
{
 return xform >= XDEV_EXT_CPU_XFORM_CRC32C_APPEND && xform <= XDEV_EXT_CPU_XFORM_SHA256_APPEND;
}

static inline bool xdev_ext_mech_cpu_xform_variable(__u32 xform)
{
 return xform == XDEV_EXT_CPU_XFORM_DEFLATE || xform == XDEV_EXT_CPU_XFORM_INFLATE;
}

/* Run by the CPU program's compute member, never by the code below. */
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

static inline int xdev_ext_mech_cpu_out_len(__u32 xform, __u64 param,
 __u32 valid_len, __u32 cap, __u32 *out_len)
{
 __s64 delta, out;
 int err = xdev_ext_mech_cpu_len_delta(xform, param, &delta);

 if (err || valid_len > cap)
  return -EINVAL;
 if (((xform == XDEV_EXT_CPU_XFORM_CRC32C_STRIP ||
       xform == XDEV_EXT_CPU_XFORM_CRC32C_SEAL ||
       xform == XDEV_EXT_CPU_XFORM_CRC32C_CHECK) && valid_len < 4) ||
     (xform == XDEV_EXT_CPU_XFORM_PARSE_STRIP && valid_len < param))
  return -EBADMSG;
 out = (__s64)valid_len + delta;
 if (out < 0)
  return -EBADMSG;
 if (out > cap)
  return -EMSGSIZE;
 *out_len = (__u32)out;
 return 0;
}

static inline __u32 xdev_ext_mech_cpu_le32(const __u8 *p)
{
 return (__u32)p[0] | ((__u32)p[1] << 8) | ((__u32)p[2] << 16) | ((__u32)p[3] << 24);
}

static inline int xdev_ext_mech_cpu_apply(const struct xdev_ext_mech_cpu_prims *p,
 __u32 xform, __u64 param, __u8 *span, __u32 valid_len, __u32 cap, __u32 *out_len)
{
 __u32 out, crc = 0, i;
 __u64 hash;
 int err;

 if (!xdev_ext_mech_cpu_xform_fixed(xform))
  return -EINVAL;
 err = xdev_ext_mech_cpu_out_len(xform, param, valid_len, cap, &out);
 if (err)
  return err;
 if (!p || !span)
  return -EINVAL;
 if (xform <= XDEV_EXT_CPU_XFORM_CRC32C_CHECK) {
  if (!p->crc32c)
   return -EINVAL;
  crc = ~p->crc32c(~0U, span, xform == XDEV_EXT_CPU_XFORM_CRC32C_APPEND ? valid_len : valid_len - 4);
  if ((xform == XDEV_EXT_CPU_XFORM_CRC32C_STRIP || xform == XDEV_EXT_CPU_XFORM_CRC32C_CHECK) &&
      xdev_ext_mech_cpu_le32(span + valid_len - 4) != crc)
   return -EBADMSG;
 }
 if (xform == XDEV_EXT_CPU_XFORM_PARSE_STRIP && xdev_ext_mech_cpu_le32(span) != out)
  return -EBADMSG;
 if (xform == XDEV_EXT_CPU_XFORM_XXH64_APPEND && !p->xxh64)
  return -EINVAL;
 if (xform == XDEV_EXT_CPU_XFORM_SHA256_APPEND && !p->sha256)
  return -EINVAL;
 /* All validation precedes the first byte write. */
 switch (xform) {
 case XDEV_EXT_CPU_XFORM_CRC32C_APPEND:
 case XDEV_EXT_CPU_XFORM_CRC32C_SEAL:
  for (i = 0; i < 4; i++)
   span[out - 4 + i] = (__u8)(crc >> (8 * i));
  break;
 case XDEV_EXT_CPU_XFORM_PARSE_STRIP:
  memmove(span, span + param, out);
  break;
 case XDEV_EXT_CPU_XFORM_XXH64_APPEND:
  hash = p->xxh64(span, valid_len, param);
  for (i = 0; i < 8; i++)
   span[valid_len + i] = (__u8)(hash >> (56 - 8 * i));
  break;
 case XDEV_EXT_CPU_XFORM_SHA256_APPEND:
  p->sha256(span, valid_len, span + valid_len);
  break;
 }
 *out_len = out;
 return 0;
}

static inline int xdev_ext_mech_cpu_var_result(int err, __u32 produced,
 __u32 dst_cap, __u32 *valid_len)
{
 if (err == -ENOSPC || err == -EOVERFLOW || produced > dst_cap)
  return -ENOSPC;
 if (err)
  return err;
 if (!produced)
  return -EPROTO;
 *valid_len = produced;
 return 0;
}

static inline int xdev_ext_mech_cpu_desc_check(const struct xdev_ext_cpu_desc *d,
 __u32 create_xform, __u64 create_param)
{
 __s64 expected, selected;

 if (d->flags)
  return -EINVAL;
 if (xdev_ext_mech_cpu_xform_variable(create_xform))
  return d->xform == create_xform && d->param == create_param ? 0 : -EINVAL;
 if (xdev_ext_mech_cpu_len_delta(create_xform, create_param, &expected) ||
     xdev_ext_mech_cpu_len_delta(d->xform, d->param, &selected) || expected != selected)
  return -EINVAL;
 return 0;
}

/*
 * BPF compute kfunc bounds (Documentation/userspace-api/xdev_ext-compute.rst).
 * A writable view [off, off + size) counts from the frame's first valid byte
 * and must lie inside the capacity, frame_size - data_off.
 */
static inline bool xdev_ext_mech_compute_view_ok(__u32 data_off, __u32 frame_size,
 __u32 off, __u64 size)
{
 __u64 cap;

 if (data_off >= frame_size || !size)
  return false;
 cap = (__u64)frame_size - data_off;
 return off < cap && size <= cap - off;
}

/* The only output length compute may record: valid_len + delta, within cap. */
static inline bool xdev_ext_mech_compute_len_ok(__u32 valid_len, __s64 delta,
 __u32 cap, __u32 len)
{
 __s64 want = (__s64)valid_len + delta;

 return valid_len <= cap && want >= 0 && want <= (__s64)cap && (__s64)len == want;
}
#endif

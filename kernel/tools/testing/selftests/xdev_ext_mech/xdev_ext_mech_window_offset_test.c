// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_window.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

static unsigned int checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; \
	fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

/* Appending this metadata must leave the existing frame array intact. */
_Static_assert(sizeof(((struct xdev_ext_ce_mech_info *)0)->window_slot) == 4,
	       "slot width");
_Static_assert(sizeof(((struct xdev_ext_ce_mech_info *)0)->window_depth) == 4,
	       "depth width");
_Static_assert(sizeof(((struct xdev_ext_ce_mech_info *)0)->lease_generation) == 8,
	       "lease generation width");
_Static_assert(offsetof(struct xdev_ext_ce_mech_info, window_slot) ==
	       offsetof(struct xdev_ext_ce_mech_info, f) +
	       sizeof(((struct xdev_ext_ce_mech_info *)0)->f), "append lease metadata");

static void offset_case(__u32 slot, __u32 depth, __u32 bytes, __u64 len,
			int expected, __u64 want)
{
	const __u64 sentinel = UINT64_C(0xdeadc0de12345678);
	__u64 out = sentinel;
	int ret = xdev_ext_mech_window_offset(slot, depth, bytes, len, &out);

	CHECK(ret == expected);
	CHECK(out == (expected ? sentinel : want));
}

int main(void)
{
	const __u64 huge = (__u64)UINT32_MAX * UINT32_MAX;

	for (__u32 depth = 1; depth <= 64; depth++) {
		for (__u32 slot = 0; slot < depth; slot++) {
			offset_case(slot, depth, 8192, (__u64)depth * 8192,
				    0, (__u64)slot * 8192);
			offset_case(slot, depth, 8192, (__u64)depth * 8192 + 17,
				    0, (__u64)slot * 8192);
			/* Even slot zero rejects an undersized total lease window. */
			offset_case(slot, depth, 8192, (__u64)depth * 8192 - 1,
				    -ENOSPC, 0);
		}
		offset_case(depth, depth, 8192, UINT64_MAX, -EINVAL, 0);
	}
	offset_case(0, 0, 8192, 65536, -EINVAL, 0);
	offset_case(0, 8, 0, 65536, -EINVAL, 0);
	offset_case(0, 8, 8192, 0, -ENOSPC, 0);
	offset_case(UINT32_MAX, 8, 8192, UINT64_MAX, -EINVAL, 0);
	offset_case(0, UINT32_MAX, UINT32_MAX, huge - 1, -ENOSPC, 0);
	offset_case(UINT32_MAX - 1, UINT32_MAX, UINT32_MAX, huge, 0,
		    (__u64)(UINT32_MAX - 1) * UINT32_MAX);
	offset_case(UINT32_MAX - 1, UINT32_MAX, UINT32_MAX, UINT64_MAX, 0,
		    (__u64)(UINT32_MAX - 1) * UINT32_MAX);

	/* Campaign has 256 groups but only 8 simultaneously owned batch slots. */
	CHECK(xdev_ext_mech_ctl_ce_window_ok(8, 8192, 65536));
	CHECK(!xdev_ext_mech_ctl_ce_window_ok(9, 8192, 65536));
	CHECK(!xdev_ext_mech_ctl_ce_window_ok(0, 8192, 65536));
	CHECK(!xdev_ext_mech_ctl_ce_window_ok(8, 0, 65536));
	CHECK(!xdev_ext_mech_ctl_ce_window_ok(UINT64_MAX, 8192, UINT64_MAX));
	printf("window offset: %u checks, %u failures\n", checks, failures);
	return !!failures;
}

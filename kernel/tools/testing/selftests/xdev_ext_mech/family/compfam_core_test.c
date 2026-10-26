// SPDX-License-Identifier: GPL-2.0
/* F9a requirement: compute kinds follow the independently specified stage
 * semantics; non-compute classes and invalid stages have no compute kind.
 * Breaks caught: wrong family gate, CE/DMA role handling, CPU BPF/variable
 * confusion, invalid-direction acceptance, and unchecked bit shifts.
 * Build after promotion with GCC -I <kernel>; this draft is not a run result.
 */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !__has_include("include/linux/xdev_ext_compfam_core.h")
int main(void)
{
	puts("not ok 1 - no compute family rules");
	return 1;
}
#else
#include "io_uring/xdev_ext_mech_step.h"
#include "include/linux/xdev_ext_compfam_core.h"

static unsigned int checks, failures;
#define EQ(got, want) do { \
	long long g_ = (got), w_ = (want); \
	checks++; \
	if (g_ != w_) { \
		fprintf(stderr, "line %u: %s = %lld, want %lld\n", \
			__LINE__, #got, g_, w_); \
		failures++; \
	} \
} while (0)

/* Handwritten class membership, independent of the production family table. */
static bool compute_class(__u32 c)
{
	return c == XDEV_EXT_MECH_CLASS_CE || c == XDEV_EXT_MECH_CLASS_DMA ||
	       c == XDEV_EXT_MECH_CLASS_IAA || c == XDEV_EXT_MECH_CLASS_CPU ||
	       c == XDEV_EXT_MECH_CLASS_USER;
}

/* Literal semantic cases from F9a and the CPU transform contract: fixed and
 * BPF transforms are in-place; DEFLATE/INFLATE use leased output. The oracle
 * deliberately calls neither stage_role nor any production CPU classifier.
 */
static int expected_kind(__u32 c, __u32 direction, __u64 xform)
{
	if (!compute_class(c) ||
	    (direction != XDEV_EXT_MECH_DIR_FROM_DEVICE &&
	     direction != XDEV_EXT_MECH_DIR_TO_DEVICE))
		return -EINVAL;
	if (c == XDEV_EXT_MECH_CLASS_CE || c == XDEV_EXT_MECH_CLASS_DMA)
		return XDEV_EXT_COMP_COPY_WINDOW;
	if (c == XDEV_EXT_MECH_CLASS_IAA)
		return XDEV_EXT_COMP_TRANSFORM;
	if (direction != XDEV_EXT_MECH_DIR_TO_DEVICE)
		return -EINVAL;
	if (c == XDEV_EXT_MECH_CLASS_USER)
		return XDEV_EXT_COMP_INPLACE;
	switch (xform) {
	case XDEV_EXT_CPU_XFORM_CRC32C_APPEND:
	case XDEV_EXT_CPU_XFORM_CRC32C_STRIP:
	case XDEV_EXT_CPU_XFORM_CRC32C_SEAL:
	case XDEV_EXT_CPU_XFORM_CRC32C_CHECK:
	case XDEV_EXT_CPU_XFORM_PARSE_STRIP:
	case XDEV_EXT_CPU_XFORM_XXH64_APPEND:
	case XDEV_EXT_CPU_XFORM_SHA256_APPEND:
	case XDEV_EXT_CPU_XFORM_BPF:
		return XDEV_EXT_COMP_INPLACE;
	case XDEV_EXT_CPU_XFORM_DEFLATE:
	case XDEV_EXT_CPU_XFORM_INFLATE:
		return XDEV_EXT_COMP_TRANSFORM;
	default:
		return -EINVAL;
	}
}

int main(void)
{
	const __u32 directions[] = {
		XDEV_EXT_MECH_DIR_FROM_DEVICE, XDEV_EXT_MECH_DIR_TO_DEVICE,
		0, 3, UINT32_MAX,
	};
	const struct { int role, kind; } roles[] = {
		{ XDEV_EXT_MECH_ROLE_PRODUCER, XDEV_EXT_COMP_COPY_WINDOW },
		{ XDEV_EXT_MECH_ROLE_CONSUMER, XDEV_EXT_COMP_COPY_WINDOW },
		{ XDEV_EXT_MECH_ROLE_INPLACE, XDEV_EXT_COMP_INPLACE },
		{ XDEV_EXT_MECH_ROLE_TRANSFORM, XDEV_EXT_COMP_TRANSFORM },
		{ -EINVAL, -EINVAL }, { -1, -EINVAL },
	};
	const int kinds[] = { XDEV_EXT_COMP_COPY_WINDOW, XDEV_EXT_COMP_INPLACE,
		XDEV_EXT_COMP_TRANSFORM };
	const int invalid_kinds[] = { INT_MIN, -EINVAL, -1, 0, 32, 33, INT_MAX };
	unsigned int c, d, x, i, j;

	for (c = 0; c < 64; c++) {
		for (d = 0; d < sizeof(directions) / sizeof(directions[0]); d++) {
			for (x = 0; x <= XDEV_EXT_CPU_XFORM_MAX; x++) {
				struct xdev_ext_mech_stage_uapi u = {
					.class_id = c, .direction = directions[d], .arg0 = x,
				};
				int got = xdev_ext_comp_kind_of(&u);
				int want = expected_kind(c, directions[d], x);
				if (got != want)
					fprintf(stderr, "class=%u direction=%u arg0=%u\n",
						c, directions[d], x);
				EQ(got, want);
			}
		}
		for (i = 0; i < sizeof(roles) / sizeof(roles[0]); i++)
			EQ(xdev_ext_comp_kind_of_role(c, roles[i].role),
			   compute_class(c) ? roles[i].kind : -EINVAL);
	}
	for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
		for (j = 0; j < sizeof(kinds) / sizeof(kinds[0]); j++)
			EQ(xdev_ext_comp_kind_ok(1U << kinds[i], kinds[j]), i == j);
		for (j = 0; j < sizeof(invalid_kinds) / sizeof(invalid_kinds[0]); j++)
			EQ(xdev_ext_comp_kind_ok(UINT32_MAX, invalid_kinds[j]), false);
		EQ(xdev_ext_comp_kind_ok(0, kinds[i]), false);
		EQ(xdev_ext_comp_kind_ok((1U << XDEV_EXT_COMP_COPY_WINDOW) |
			(1U << XDEV_EXT_COMP_INPLACE) | (1U << XDEV_EXT_COMP_TRANSFORM), kinds[i]), true);
	}
	if (failures) {
		printf("not ok 1 - compute family rules (%u/%u failed)\n", failures, checks);
		return 1;
	}
	printf("ok 1 - compute kinds follow class, direction and transform (%u checks)\n", checks);
	return 0;
}
#endif

// SPDX-License-Identifier: GPL-2.0
/* Requirement: every known class has one family; optional hooks, when present,
 * must match that family. Execute the production rules, not a test model.
 * Build with -I <kernel tree>. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !__has_include("include/linux/xdev_ext_family_core.h")
int main(void)
{
	puts("not ok 1 - no device-family table: classes have no parent family");
	return 1;
}
#else
#include "io_uring/xdev_ext_mech_step.h"
#include "include/linux/xdev_ext_family_core.h"

static unsigned int checks, failures;
#define EXPECT_EQ(actual, expected) do { \
	long long got = (long long)(actual), want = (long long)(expected); \
	checks++; \
	if (got != want) { \
		fprintf(stderr, "line %d: %s got %lld expected %lld\n", \
			__LINE__, #actual, got, want); \
		failures++; \
	} \
} while (0)

int main(void)
{
	static const struct { __u32 class_id, family; } required[] = {
		{ XDEV_EXT_MECH_CLASS_NET, 1 },
		{ XDEV_EXT_MECH_CLASS_AFXDP, 1 },
		{ XDEV_EXT_MECH_CLASS_SOCKET, 1 },
		{ XDEV_EXT_MECH_CLASS_XDOMAIN, 1 },
		{ XDEV_EXT_MECH_CLASS_NVME, 2 },
		{ XDEV_EXT_MECH_CLASS_CE, 3 },
		{ XDEV_EXT_MECH_CLASS_DMA, 3 },
		{ XDEV_EXT_MECH_CLASS_IAA, 3 },
		{ XDEV_EXT_MECH_CLASS_CPU, 3 },
		{ XDEV_EXT_MECH_CLASS_USER, 3 },
	};
	__u32 c, f, i, known = 0;

	EXPECT_EQ(XDEV_EXT_FAMILY_NONE, 0);
	EXPECT_EQ(XDEV_EXT_FAMILY_NETWORK, 1);
	EXPECT_EQ(XDEV_EXT_FAMILY_STORAGE, 2);
	EXPECT_EQ(XDEV_EXT_FAMILY_COMPUTE, 3);
	for (i = 0; i < sizeof(required) / sizeof(required[0]); i++)
		EXPECT_EQ(xdev_ext_mech_class_family(required[i].class_id),
			  required[i].family);
	for (c = 0; c < 64; c++) {
		__u32 expected = 0, actual = xdev_ext_mech_class_family(c);

		for (i = 0; i < sizeof(required) / sizeof(required[0]); i++)
			if (required[i].class_id == c)
				expected = required[i].family;
		EXPECT_EQ(actual, expected);
		EXPECT_EQ(actual != 0, xdev_ext_mech_class_known(c));
		known += xdev_ext_mech_class_known(c);
		if (xdev_ext_mech_peer_dirs(c))
			EXPECT_EQ(actual == 1 || actual == 2, true);
		/* NULL hooks impose no new requirement; class validity remains the
		 * registry's separate responsibility. All known classes must work. */
		if (expected)
			EXPECT_EQ(xdev_ext_family_hooks_ok(c, NULL), true);
		for (f = 0; f <= 4; f++)
			EXPECT_EQ(xdev_ext_family_hooks_ok(c, &f),
				  expected != 0 && f == expected);
	}
	EXPECT_EQ(known, 10);
	EXPECT_EQ(xdev_ext_mech_class_family(UINT32_MAX), 0);
	f = 1;
	EXPECT_EQ(xdev_ext_family_hooks_ok(UINT32_MAX, &f), false);
	printf("%s 1 - family mapping and hook compatibility (%u checks, %u failures)\n",
	       failures ? "not ok" : "ok", checks, failures);
	return failures != 0;
}
#endif

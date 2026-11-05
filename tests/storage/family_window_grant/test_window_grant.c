/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Independent oracle for the storage LBA window grant rules (prototype for
 * ASK.69), written from the stated requirement, not from the implementation:
 *
 *  - a holder of a namespace issues a grant naming one nonempty LBA range
 *    inside the namespace and its access (read, write or both);
 *  - a stage presenting the grant may bind a window only inside that range,
 *    and only in a granted direction (an ungranted direction is reported
 *    before the range, as an fd opened without that mode would be);
 *  - two grants of one namespace conflict when they share an LBA and either
 *    may write; read-only grants may overlap.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "xdev_ext_storfam_core.h"

static unsigned checks, failures;
static char label[160];

static void eq(const char *what, long long got, long long want)
{
	checks++;
	if (got != want) {
		failures++;
		fprintf(stderr, "FAIL %s %s got=%lld want=%lld\n", label, what, got, want);
	}
}
#define EQ(what, got, want) eq(what, (long long)(got), (long long)(want))

#define R XDEV_EXT_STOR_GRANT_READ
#define W XDEV_EXT_STOR_GRANT_WRITE
#define RW (XDEV_EXT_STOR_GRANT_READ | XDEV_EXT_STOR_GRANT_WRITE)
#define MAX64 (~(__u64)0)

static void make_case(const char *name, __u64 cap, __u64 slba, __u64 nlb,
		      __u32 access, int want)
{
	struct xdev_ext_stor_grant g, before;
	int ret;

	snprintf(label, sizeof(label), "make/%s", name);
	memset(&g, 0xa5, sizeof(g));
	before = g;
	ret = xdev_ext_stor_grant_make(&g, cap, slba, nlb, access);
	EQ("errno", ret, want);
	if (ret) {
		/* A refused grant publishes nothing. */
		EQ("unchanged-on-error", memcmp(&g, &before, sizeof(g)), 0);
		return;
	}
	EQ("slba", g.slba, slba);
	EQ("nlb", g.nlb, nlb);
	EQ("access", g.access, access);
}

static struct xdev_ext_stor_grant grant(__u64 slba, __u64 nlb, __u32 access)
{
	struct xdev_ext_stor_grant g;

	memset(&g, 0, sizeof(g));
	g.slba = slba;
	g.nlb = nlb;
	g.access = access;
	return g;
}

static void admit_case(const char *name, struct xdev_ext_stor_grant g, bool write,
		       __u64 slba, __u64 nlb, int want)
{
	snprintf(label, sizeof(label), "admit/%s", name);
	EQ("errno", xdev_ext_stor_grant_admit(&g, write, slba, nlb), want);
}

static void conflict_case(const char *name, struct xdev_ext_stor_grant a,
			  struct xdev_ext_stor_grant b, bool want)
{
	snprintf(label, sizeof(label), "conflict/%s", name);
	EQ("a-b", xdev_ext_stor_grant_conflict(&a, &b), want);
	/* Conflict is a property of the pair, not of the order of issue. */
	EQ("b-a", xdev_ext_stor_grant_conflict(&b, &a), want);
}

int main(void)
{
	/* Issue. */
	make_case("whole-namespace", 1024, 0, 1024, RW, 0);
	make_case("one-lba-at-end", 1024, 1023, 1, W, 0);
	make_case("read-only", 1024, 64, 64, R, 0);
	make_case("write-only", 1024, 64, 64, W, 0);
	make_case("no-access", 1024, 0, 64, 0, -EINVAL);
	make_case("unknown-access-bit", 1024, 0, 64, 4, -EINVAL);
	make_case("known-plus-unknown-bit", 1024, 0, 64, RW | 0x80000000U, -EINVAL);
	make_case("empty", 1024, 0, 0, RW, -EINVAL);
	make_case("past-end", 1024, 1000, 25, RW, -ERANGE);
	make_case("start-at-capacity", 1024, 1024, 1, RW, -ERANGE);
	make_case("start-past-capacity", 1024, 2048, 1, RW, -ERANGE);
	make_case("sum-wraps", MAX64, MAX64, 1, RW, -ERANGE);
	make_case("huge-count-wraps", 1024, 1, MAX64, RW, -ERANGE);
	make_case("max-capacity-tail", MAX64, MAX64 - 1, 1, RW, 0);
	snprintf(label, sizeof(label), "make/null-out");
	EQ("errno", xdev_ext_stor_grant_make(NULL, 1024, 0, 64, RW), -EINVAL);

	/* CREATE with a grant: direction first, then the range. */
	admit_case("equal-window-write", grant(64, 64, RW), true, 64, 64, 0);
	admit_case("equal-window-read", grant(64, 64, RW), false, 64, 64, 0);
	admit_case("inner-window", grant(64, 64, RW), true, 80, 16, 0);
	admit_case("at-start", grant(64, 64, RW), true, 64, 1, 0);
	admit_case("at-end", grant(64, 64, RW), true, 127, 1, 0);
	admit_case("next-window", grant(0, 64, RW), true, 64, 64, -EACCES);
	admit_case("previous-window", grant(64, 64, RW), true, 0, 64, -EACCES);
	admit_case("straddles-end", grant(0, 64, RW), true, 32, 64, -EACCES);
	admit_case("straddles-start", grant(64, 64, RW), true, 32, 64, -EACCES);
	admit_case("one-past-end", grant(0, 64, RW), true, 64, 1, -EACCES);
	admit_case("one-before-start", grant(64, 64, RW), false, 63, 1, -EACCES);
	admit_case("one-too-long", grant(64, 64, RW), true, 64, 65, -EACCES);
	admit_case("count-wraps", grant(64, 64, RW), true, 65, MAX64, -EACCES);
	admit_case("start-far-away", grant(64, 64, RW), true, MAX64, 1, -EACCES);
	admit_case("write-on-read-grant", grant(0, 64, R), true, 0, 64, -EBADF);
	admit_case("read-on-write-grant", grant(0, 64, W), false, 0, 64, -EBADF);
	admit_case("read-on-read-grant", grant(0, 64, R), false, 0, 64, 0);
	admit_case("write-on-write-grant", grant(0, 64, W), true, 0, 64, 0);
	admit_case("direction-before-range", grant(0, 64, R), true, 64, 64, -EBADF);
	admit_case("no-access-grant-read", grant(0, 64, 0), false, 0, 64, -EBADF);
	admit_case("no-access-grant-write", grant(0, 64, 0), true, 0, 64, -EBADF);
	snprintf(label, sizeof(label), "admit/null-grant");
	EQ("errno", xdev_ext_stor_grant_admit(NULL, true, 0, 64), -EINVAL);

	/* Overlap between grants of one namespace. */
	conflict_case("identical-rw", grant(64, 64, RW), grant(64, 64, RW), true);
	conflict_case("partial-rw", grant(64, 64, RW), grant(96, 64, RW), true);
	conflict_case("contained-rw", grant(0, 256, RW), grant(64, 1, RW), true);
	conflict_case("last-lba-shared", grant(0, 65, W), grant(64, 64, W), true);
	conflict_case("adjacent-rw", grant(0, 64, RW), grant(64, 64, RW), false);
	conflict_case("disjoint-rw", grant(0, 64, RW), grant(512, 64, RW), false);
	conflict_case("read-read-overlap", grant(0, 64, R), grant(32, 64, R), false);
	conflict_case("read-write-overlap", grant(0, 64, R), grant(32, 64, W), true);
	conflict_case("read-rw-overlap", grant(0, 64, R), grant(0, 64, RW), true);
	conflict_case("read-write-adjacent", grant(0, 64, R), grant(64, 64, W), false);
	conflict_case("max-tail", grant(MAX64 - 1, 1, RW), grant(MAX64 - 1, 1, RW), true);
	conflict_case("max-span-and-tail", grant(0, MAX64, RW), grant(MAX64 - 1, 1, W), true);
	conflict_case("max-span-adjacent", grant(0, MAX64 - 1, RW), grant(MAX64 - 1, 1, W), false);

	printf("%s window-grant checks=%u failures=%u\n",
	       failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}

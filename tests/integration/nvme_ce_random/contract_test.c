// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
#if __has_include("contract.h")
#include "contract.h"
#define HAVE_RANDOM_CONTRACT 1
#endif
static unsigned checks, failures;
#define EQ(label, got, want) do { long long a_ = (got), b_ = (want); checks++; if (a_ != b_) { fprintf(stderr,"FAIL %s: got %lld want %lld\n",label,a_,b_); failures++; } } while (0)
static void controls(void)
{
	unsigned save;
	for (save = 0; save < 2; save++) {
		struct xdev_ext_mech_create c = { .abi_version = 1,
			.nr_stages = 2, .pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM,
			.pool_fd = -1, .depth = 2, .eventfd = -1,
			.layout = {32768, 0, 32768, 1048576} };
		__u32 frames = 0;
		c.st[save] = (struct xdev_ext_mech_stage_uapi){
			.class_id = XDEV_EXT_MECH_CLASS_NVME, .fd = 7,
			.direction = save ? 1 : 2, .arg0 = 4096, .arg1 = 16384 };
		c.st[1 - save] = (struct xdev_ext_mech_stage_uapi){
			.class_id = XDEV_EXT_MECH_CLASS_CE, .fd = 8,
			.direction = save ? 2 : 1, .arg0 = 0x10000000,
			.arg1 = 4194304, .flags = XDEV_EXT_CE_STAGE_F_TARGET_RANGE };
		EQ("actual two-stage range topology", xdev_ext_mech_create_check(&c, &frames), 0);
		EQ("actual1MiB/32frame control", frames, 32);
	}
}
static void contract(void)
{
#ifndef HAVE_RANDOM_CONTRACT
	EQ("missing feature: native RANDOM request/window contract", 0, 1);
#else
	struct rr_geometry g = { .gpu_bytes = 4194304, .disk_bytes = 8388608,
		.guard_bytes = 65536, .depth = 2, .lba_bytes = 512 };
	const struct rr_request original[4] = {
		{100,2097152,1,1048576,0}, {101,0,1048577,1048576,0},
		{102,1048576,1,1048576,1}, {103,2097152,2097153,1048576,1} };
	struct rr_request rows[4];
	struct xdev_ext_mech_create c;
	int selectors[4];
	unsigned save;
	memcpy(rows, original, sizeof(rows));
	EQ("fixed1MiB/depth2 two phases", rr_validate(&g, rows, 4, false), 0);
	EQ("repeat source allowed for READ", rr_validate(&g, rows, 4, true), 0);
	for (save = 0; save < 2; save++) {
		__u32 frames = 0;
		EQ("actual helper stage assembly", rr_create(&c, &g, 7, 8, 0x10000000, 4096, 16384, save, -1), 0);
		EQ("actual assembled CREATE accepted", xdev_ext_mech_create_check(&c, &frames), 0);
		EQ("assembled fixed32 frames", frames, 32);
		EQ("CE explicit range flag both orders", c.st[1-save].flags, 1);
		EQ("NVMe flags remain0", c.st[save].flags, 0);
		rr_selectors(selectors, 21, 22, save);
		EQ("NVMe PRIVATE selector", selectors[save], 21);
		EQ("CE PRIVATE selector", selectors[1-save], 22);
		EQ("unused selector2", selectors[2], -1);
		EQ("unused selector3", selectors[3], -1);
	}
#define BAD(label, mutation, want) do { memcpy(rows, original, sizeof(rows)); mutation; EQ(label,rr_validate(&g,rows,4,false),want); } while (0)
	BAD("same phase GPU overlap", rows[1].gpu_offset=1048576, -EAGAIN);
	BAD("same phase duplicate target", rows[1].gpu_offset=1, -EAGAIN);
	BAD("unaligned source LBA", rows[0].nvme_offset=1, -EINVAL);
	BAD("GPU addition overflow", rows[0].gpu_offset=UINT64_MAX, -EOVERFLOW);
	BAD("source addition overflow", rows[0].nvme_offset=UINT64_MAX-511, -EOVERFLOW);
	BAD("GPU one byte out of window", rows[0].gpu_offset=3145729, -ERANGE);
	BAD("source beyond grant", rows[0].nvme_offset=8388608, -ERANGE);
	BAD("cannot shrink payload", rows[0].bytes=524288, -EINVAL);
	BAD("cannot skip map key", rows[1].key=102, -EINVAL);
	BAD("cannot duplicate map key", rows[1].key=100, -EINVAL);
	BAD("cannot skip phase", rows[2].phase=3, -EINVAL);
	BAD("cannot serialize phase", rows[1].phase=1, -EINVAL);
	memcpy(rows, original, sizeof(rows)); rows[1].nvme_offset=rows[0].nvme_offset;
	EQ("same source READ disjoint GPU permitted", rr_validate(&g,rows,4,false), 0);
	EQ("concurrent WRITE destination overlap refused", rr_validate(&g,rows,4,true), -EAGAIN);
	memcpy(rows, original, sizeof(rows)); rows[0].gpu_offset=3145728;
	EQ("whole payload exact GPU end", rr_validate(&g,rows,4,false), 0);
	g.depth=1; EQ("cannot lower depth1",rr_validate(&g,original,4,false),-EINVAL);
	g.depth=2; g.guard_bytes=UINT64_MAX;
	EQ("allocation plus both guards overflow",rr_validate(&g,original,4,false),-EOVERFLOW);
#endif
}
int main(int argc, char **argv)
{
	if (argc != 2) return 2;
	if (!strcmp(argv[1],"controls")) controls();
	else if (!strcmp(argv[1],"contract")) contract();
	else return 2;
	printf("%s: %u checks, %u failures\n",argv[1],checks,failures);
	return failures ? 1 : 0;
}

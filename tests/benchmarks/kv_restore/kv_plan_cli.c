// SPDX-License-Identifier: GPL-2.0
/*
 * kv_plan.h as a command, for the cross-check against kv_layout.py:
 *   kv_plan_cli plan --window-slba N --window-nlb N --lba-bytes N --object-slba N
 *       --bytes N --group-bytes N --frame-bytes N --depth N --window N --ordinal N
 *       [--dst-frame0 N] [--pool-frames N] [--early] [--host2-ring]
 *   kv_plan_cli pattern SEED OFFSET LENGTH
 * Prints one JSON object; a refused plan prints {"error": -errno} and exits 1.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"
#include "kv_plan.h"

static int u64(const char *s, uint64_t *v)
{
	char *end;
	unsigned long long n;

	if (!s || !*s || *s == '-')
		return -EINVAL;
	errno = 0;
	n = strtoull(s, &end, 0);
	if (errno || *end)
		return -EINVAL;
	*v = n;
	return 0;
}

static int u32(const char *s, uint32_t *v)
{
	uint64_t n;

	if (u64(s, &n) || n > UINT32_MAX)
		return -EINVAL;
	*v = (uint32_t)n;
	return 0;
}

static int plan(int argc, char **argv)
{
	struct kv_window w = { 0 };
	struct kv_geometry g = { 0 };
	struct kv_request r = { 0 };
	struct kv_plan p;
	int ret = 0;

	for (int i = 0; i < argc && !ret; i++) {
		const char *k = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;

		if (!strcmp(k, "--early")) { g.early = true; continue; }
		if (!strcmp(k, "--host2-ring")) { r.host2_ring = true; continue; }
		if (!v) return 2;
		if (!strcmp(k, "--window-slba")) ret = u64(v, &w.slba);
		else if (!strcmp(k, "--window-nlb")) ret = u64(v, &w.nlb);
		else if (!strcmp(k, "--lba-bytes")) ret = u32(v, &w.lba_bytes);
		else if (!strcmp(k, "--object-slba")) ret = u64(v, &r.object_slba);
		else if (!strcmp(k, "--bytes")) ret = u64(v, &r.bytes);
		else if (!strcmp(k, "--ordinal")) ret = u64(v, &r.ordinal);
		else if (!strcmp(k, "--dst-frame0")) ret = u32(v, &r.dst_frame0);
		else if (!strcmp(k, "--pool-frames")) ret = u64(v, &r.pool_frames);
		else if (!strcmp(k, "--group-bytes")) ret = u32(v, &g.group_bytes);
		else if (!strcmp(k, "--frame-bytes")) ret = u32(v, &g.frame_bytes);
		else if (!strcmp(k, "--depth")) ret = u32(v, &g.depth);
		else if (!strcmp(k, "--window")) ret = u32(v, &g.window);
		else return 2;
		i++;
	}
	if (ret)
		return 2;
	ret = kv_plan_make(&w, &g, &r, &p);
	if (ret) {
		printf("{\"error\": %d}\n", ret);
		return 1;
	}
	printf("{\"groups\": %" PRIu64 ", \"slots\": %" PRIu64 ", \"slot0\": %" PRIu64
	       ", \"first_seq\": %" PRIu64 ", \"frames_per_group\": %u"
	       ", \"host1_pool_frames\": %u, \"host1_recycle_frames\": %u"
	       ", \"host2_dst_frame0\": %u, \"host2_frames\": %" PRIu64
	       ", \"host2_pool_frames\": %" PRIu64 ", \"first_group_slba\": %" PRIu64
	       ", \"last_group_slba\": %" PRIu64 ", \"xdomain_arg1\": %llu"
	       ", \"host2_ring\": %s, \"host2_start_frames\": %u}\n",
	       p.groups, p.slots, p.slot0, p.first_seq, p.frames_per_group,
	       p.host1_pool_frames, p.host1_recycle_frames, p.host2_dst_frame0,
	       p.host2_frames, p.host2_pool_frames, kv_plan_group_slba(&p, &w, 0),
	       kv_plan_group_slba(&p, &w, p.groups - 1),
	       (unsigned long long)kv_plan_xdomain_arg1(&g), p.host2_ring ? "true" : "false",
	       p.host2_start_frames);
	return 0;
}

static int pattern(int argc, char **argv)
{
	uint64_t seed, offset, length, h = KV_FNV_OFFSET, b = UINT64_MAX;
	uint8_t block[KV_BLOCK];

	if (argc != 3 || u64(argv[0], &seed) || u64(argv[1], &offset) || u64(argv[2], &length) ||
	    length > (1ULL << 34) || offset > UINT64_MAX - length)
		return 2;
	for (uint64_t at = offset; at < offset + length; at++) {
		if (at / KV_BLOCK != b) {
			b = at / KV_BLOCK;
			kv_pattern_block(seed, b, block);
		}
		h = kv_fnv1a(h, &block[at % KV_BLOCK], 1);
	}
	printf("{\"fnv1a\": \"0x%016" PRIx64 "\"}\n", h);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 2 && !strcmp(argv[1], "plan"))
		return plan(argc - 2, argv + 2);
	if (argc >= 2 && !strcmp(argv[1], "pattern"))
		return pattern(argc - 2, argv + 2);
	fprintf(stderr, "usage: kv_plan_cli plan OPTIONS | pattern SEED OFFSET LENGTH\n");
	return 2;
}

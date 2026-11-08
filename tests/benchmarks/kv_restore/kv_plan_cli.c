// SPDX-License-Identifier: GPL-2.0
/*
 * kv_plan.h as a command, for the cross-check against kv_layout.py:
 *   kv_plan_cli plan --window-slba N --window-nlb N --lba-bytes N --object-slba N
 *       --bytes N --group-bytes N --frame-bytes N --depth N --window N --ordinal N
 *       [--dst-frame0 N] [--pool-frames N] [--early] [--host2-ring]
 *   kv_plan_cli pattern SEED OFFSET LENGTH
 *   kv_plan_cli pages BLOCK_SIZE LAYERS HEADS STATE_BYTES GROUP_BYTES GROUP
 *   kv_plan_cli index FILE
 *   kv_plan_cli fnv FILE LEN...   FNV-1a 64 of the first LEN bytes (ascending LENs)
 * Prints one JSON object; a refused plan prints {"error": -errno} and exits 1.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"
#include "kv_plan.h"
#include "kv_index.h"

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

static int pages(int argc, char **argv)
{
	struct kv_block_layout b;
	struct kv_page_piece pc[64];
	uint32_t group_bytes;
	uint64_t group;
	int n;

	if (argc != 6 || u32(argv[0], &b.block_size) || u32(argv[1], &b.layers) ||
	    u32(argv[2], &b.heads) || u32(argv[3], &b.state_bytes) || u32(argv[4], &group_bytes) ||
	    u64(argv[5], &group))
		return 2;
	if (kv_block_layout_check(&b, group_bytes)) {
		printf("{\"error\": %d}\n", -EINVAL);
		return 1;
	}
	n = kv_group_pages(&b, group, group_bytes, pc, 64);
	if (n < 0) {
		printf("{\"error\": %d}\n", n);
		return 1;
	}
	printf("{\"pieces\": [");
	for (int i = 0; i < n; i++)
		printf("%s[%" PRIu64 ", %u, %" PRIu64 ", %" PRIu64 ", %" PRIu64 "]", i ? ", " : "",
		       pc[i].block, pc[i].layer, pc[i].page_off, pc[i].len, pc[i].group_off);
	printf("]}\n");
	return 0;
}

static int index_cmd(int argc, char **argv)
{
	struct kv_index ix;
	FILE *f;
	int ret;

	if (argc != 1 || !(f = fopen(argv[0], "r")))
		return 2;
	ret = kv_index_load(f, &ix);
	fclose(f);
	if (ret) {
		printf("{\"error\": %d}\n", ret);
		return 1;
	}
	printf("{\"entries\": [");
	for (size_t i = 0; i < ix.n; i++) {
		const struct kv_index_entry *e = &ix.v[i];

		printf("%s{\"hash\": \"%s\", \"object\": \"%s\", \"slba\": %" PRIu64
		       ", \"offset\": %" PRIu64 ", \"bytes\": %" PRIu64 ", \"tokens\": %" PRIu64,
		       i ? ", " : "", e->hash, e->object, e->slba, e->offset, e->bytes, e->tokens);
		if (e->has_fnv1a)
			printf(", \"fnv1a\": \"0x%016" PRIx64 "\"}", e->fnv1a);
		else
			printf(", \"fnv1a\": null}");
	}
	printf("]}\n");
	kv_index_free(&ix);
	return 0;
}

static int fnv_cmd(int argc, char **argv)
{
	static uint8_t buf[1 << 20];
	uint64_t h = KV_FNV_OFFSET, pos = 0, want, prev = 0;
	FILE *f;
	int ret = 0;

	if (argc < 2 || !(f = fopen(argv[0], "rb")))
		return 2;
	printf("{\"fnv1a\": [");
	for (int i = 1; i < argc && !ret; i++) {
		if (u64(argv[i], &want) || want < prev) {
			ret = 2;
			break;
		}
		prev = want;
		while (pos < want) {
			size_t n = want - pos < sizeof(buf) ? (size_t)(want - pos) : sizeof(buf);

			if (fread(buf, 1, n, f) != n) {
				ret = 1;
				break;
			}
			h = kv_fnv1a(h, buf, n);
			pos += n;
		}
		if (!ret)
			printf("%s\"0x%016" PRIx64 "\"", i > 1 ? ", " : "", h);
	}
	printf("]}\n");
	fclose(f);
	return ret;
}

int main(int argc, char **argv)
{
	if (argc >= 2 && !strcmp(argv[1], "plan"))
		return plan(argc - 2, argv + 2);
	if (argc >= 2 && !strcmp(argv[1], "pattern"))
		return pattern(argc - 2, argv + 2);
	if (argc >= 2 && !strcmp(argv[1], "pages"))
		return pages(argc - 2, argv + 2);
	if (argc >= 2 && !strcmp(argv[1], "index"))
		return index_cmd(argc - 2, argv + 2);
	if (argc >= 2 && !strcmp(argv[1], "fnv"))
		return fnv_cmd(argc - 2, argv + 2);
	fprintf(stderr, "usage: kv_plan_cli plan OPTIONS | pattern SEED OFFSET LENGTH | pages B L H C G I | index FILE | fnv FILE LEN...\n");
	return 2;
}

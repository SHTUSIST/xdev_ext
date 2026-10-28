// SPDX-License-Identifier: GPL-2.0
/* Requirement: retaining NET's pinned Ethernet plan checker must not change
 * its accepted payload coverage or errno after family rule extraction.
 * Breaks caught: omitted range/frame checks, callback ordering/errno drift,
 * flags/reserved acceptance and changing Ethernet packet admission.
 * This is differential compatibility evidence, not a device fixture. */
#include <stdio.h>
#if !__has_include("include/linux/xdev_ext_netfam_core.h")
int main(void)
{
	puts("not ok 1 - no network family rules");
	return 1;
}
#else
#include <stdint.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_net_core.h"
#include "include/linux/xdev_ext_mech_reliable_core.h"
#include "include/linux/xdev_ext_netfam_core.h"

struct context {
	const struct xdev_ext_net_mech_info *info;
	const struct xdev_ext_net_send_desc *d;
};

static void span_of_send_desc(const void *arg, __u32 i, struct xdev_ext_net_span *out)
{
	const struct context *c = arg;
	*out = (struct xdev_ext_net_span){.frame_pos = c->d[i].frame_pos,
		.frame_off = c->d[i].frame_off, .len = c->d[i].len,
		.bad = c->d[i].flags | c->d[i].reserved};
}

static int ethernet_entry(const void *arg, __u32 i)
{
	const struct context *c = arg;
	return xdev_ext_peer_net_check(c->info->mtu, c->d[i].header_len, c->d[i].len, 0);
}

static uint32_t seed = UINT32_C(0x6a09e667);
static uint32_t random32(void)
{
	seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
	return seed;
}

int main(void)
{
	unsigned int trial, failures = 0, accepted = 0;
	for (trial = 0; trial < 200000; trial++) {
		struct xdev_ext_net_mech_info info = {0};
		struct xdev_ext_net_send_desc d[16] = {0};
		struct context c = {&info, d};
		unsigned int i, nr, frame = 0;
		__u32 covered = 0;
		int pinned, family;
		info.nr_frames = 1 + random32() % 4;
		info.mtu = 1000 + random32() % 8001;
		for (i = 0; i < info.nr_frames; i++) {
			info.f[i].data_off = random32() % 8193;
			info.f[i].data_len = random32() % 9001;
		}
		if (trial % 5 == 0) {
			/* Deliberately substantial valid coverage: fully uniform random
			 * plans mostly stop at entry zero and miss later comparisons. */
			nr = info.nr_frames;
			for (i = 0; i < nr; i++) {
				info.f[i].data_len = 60 + random32() % 841;
				d[i].frame_pos = i; d[i].frame_off = info.f[i].data_off;
				d[i].len = info.f[i].data_len; d[i].header_len = 42;
			}
		} else {
			nr = 1 + random32() % 16;
			for (i = 0; i < nr; i++) {
				__u32 remain = info.f[frame].data_len - covered;
				__u32 len = remain ? 1 + random32() % remain : 0;
				int delta = (int)(random32() % 5) - 2;
				d[i].frame_pos = frame;
				d[i].frame_off = info.f[frame].data_off + covered;
				d[i].len = len; d[i].header_len = random32() % 141;
				if (random32() % 3 == 0) d[i].frame_off += delta;
				if (random32() % 31 == 0) d[i].frame_pos = random32() % 5;
				if (random32() % 37 == 0) d[i].len = random32() % 9001;
				if (random32() % 61 == 0) d[i].flags = 1;
				if (random32() % 67 == 0) d[i].reserved = 1;
				covered += len;
				if (covered == info.f[frame].data_len && frame + 1 < info.nr_frames) {
					frame++; covered = 0;
				}
			}
		}
		/* Mutate a valid plan often enough to exercise every deep error. */
		if (trial % 10 == 5) {
			unsigned int last = nr - 1;
			switch ((trial / 10) % 6) {
			case 0: d[last].frame_off++; break;
			case 1: d[last].len++; break;
			case 2: d[last].flags = 1; break;
			case 3: d[last].reserved = 1; break;
			case 4: d[last].header_len = 129; break;
			default: d[last].frame_pos = info.nr_frames; break;
			}
		}
		pinned = xdev_ext_net_plan_check(&info, d, nr);
		family = xdev_ext_net_cover_check(info.f, info.nr_frames, nr,
			XDEV_EXT_NET_MAX_ENTRIES, span_of_send_desc, ethernet_entry, &c);
		accepted += pinned == 0;
		if (pinned != family) {
			if (failures < 10)
				fprintf(stderr, "trial %u nr=%u frames=%u: pinned=%d family=%d\n",
					trial, nr, info.nr_frames, pinned, family);
			failures++;
		}
	}
	if (accepted < 19000) {
		fprintf(stderr, "generator missed its known-valid population: %u\n", accepted);
		failures++;
	}
	if (failures) {
		printf("not ok 1 - NET/family plan differential: %u failures\n", failures);
		return 1;
	}
	puts("ok 1 - NET plan check equals family coverage plus the Ethernet header rule on 200000 plans");
	return 0;
}
#endif

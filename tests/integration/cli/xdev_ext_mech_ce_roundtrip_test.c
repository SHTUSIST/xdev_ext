// SPDX-License-Identifier: GPL-2.0
/*
 * Chain d (user frames -> CE H2D -> CE D2H) and chain a (NVMe -> frames ->
 * H2D -> D2H -> NVMe) move every batch out to the device window and back
 * into the same host frames.  A host-side compare alone is vacuous: if the
 * copy engine moves nothing the frames still hold their original bytes.
 * This models the round trip on the CPU, with mutants that skip copies, and
 * checks the device-window oracle the control tool runs after the session
 * (window filled with XDEV_EXT_MECH_CTL_CE_POISON before START).
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

static unsigned int checks, failures;
#define EXPECT(c, msg) do { checks++; if (!(c)) { failures++; \
	fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); } } while (0)

enum mutant { CORRECT, SKIP_BOTH, SKIP_H2D, SKIP_D2H, FIRST_PIECE_ONLY, STRAY_TAIL,
	      WRONG_SLOT_BYTES };

#define FRAME 4096U
#define HDR 256U
#define SEG 3000U
#define GROUP 8192U	/* three frames per group: 3000 + 3000 + 2192 */
#define DEPTH 4U
#define WINDOW (DEPTH * GROUP + 4096U)

static __u8 pattern(__u32 frame, __u32 off)
{
	return (__u8)(frame * 131U + off * 7U + 0x5aU);
}

struct model {
	__u8 *frames, *window, *expected;	/* expected: frames as filled */
	__u32 nr_frames, frames_per_group;
};

/* One batch: frames [first, first+frames_per_group) <-> window slot. */
static void batch(struct model *m, __u32 first, __u32 slot, enum mutant mut, bool to_dev)
{
	__u32 c, off = 0;

	for (c = 0; c < m->frames_per_group; c++) {
		__u32 len = GROUP - off < SEG ? GROUP - off : SEG;
		__u8 *host = m->frames + (size_t)(first + c) * FRAME + HDR;
		__u8 *dev = m->window + (size_t)slot * GROUP + off;

		off += len;
		if (mut == SKIP_BOTH || (mut == SKIP_H2D && to_dev) ||
		    (mut == SKIP_D2H && !to_dev) || (mut == FIRST_PIECE_ONLY && c))
			continue;
		if (to_dev)
			memcpy(dev, host, len);
		else
			memcpy(host, dev, len);
	}
	if (mut == WRONG_SLOT_BYTES && to_dev)
		m->window[(size_t)slot * GROUP + 5] ^= 0x40;
}

static void run(struct model *m, __u64 groups, enum mutant mut, bool user_pattern)
{
	__u32 pool = (__u32)(groups < DEPTH ? groups : DEPTH);
	__u64 g;

	memset(m->window, XDEV_EXT_MECH_CTL_CE_POISON, WINDOW);
	for (g = 0; g < groups; g++) {
		__u32 slot = (__u32)(g % pool), first = slot * m->frames_per_group;

		if (!user_pattern)	/* chain a: NVMe READ fills the frames */
			for (__u32 i = 0; i < GROUP; i++)
				m->frames[(size_t)(first + i / SEG) * FRAME + HDR + i % SEG] =
					(__u8)(rand() | 1);
		batch(m, first, slot, mut, true);
		batch(m, first, slot, mut, false);
	}
	if (mut == STRAY_TAIL)
		m->window[DEPTH * GROUP + 100] = 0;
}

static bool frames_hold_pattern(const struct model *m)
{
	for (__u32 i = 0; i < m->nr_frames; i++)
		for (__u32 j = 0; j < FRAME; j++)
			if (m->frames[(size_t)i * FRAME + j] != pattern(i, j))
				return false;
	return true;
}

static int oracle(const struct model *m, __u64 groups, bool reference, __u32 *written)
{
	struct xdev_ext_mech_ctl_ce_ref ref = {
		.base = reference ? m->expected : NULL, .count = m->nr_frames,
		.stride = FRAME, .off = HDR, .len = SEG,
	};

	return xdev_ext_mech_ctl_ce_window_check(m->window, WINDOW, DEPTH, GROUP, groups,
						 &ref, written);
}

static void chain_d(void)
{
	struct model m = { .frames_per_group = 3 };
	__u32 written;
	int ret;

	m.nr_frames = DEPTH * m.frames_per_group;
	m.frames = malloc((size_t)m.nr_frames * FRAME);
	m.expected = malloc((size_t)m.nr_frames * FRAME);
	m.window = malloc(WINDOW);
	for (__u32 i = 0; i < m.nr_frames; i++)
		for (__u32 j = 0; j < FRAME; j++)
			m.expected[(size_t)i * FRAME + j] = pattern(i, j);
	for (__u64 groups = 1; groups <= 9; groups += 4) {
		for (int mut = CORRECT; mut <= WRONG_SLOT_BYTES; mut++) {
			for (__u32 i = 0; i < m.nr_frames; i++)
				for (__u32 j = 0; j < FRAME; j++)
					m.frames[(size_t)i * FRAME + j] = pattern(i, j);
			run(&m, groups, mut, true);
			written = ~0U;
			ret = oracle(&m, groups, true, &written);
			switch (mut) {
			case CORRECT:
				EXPECT(frames_hold_pattern(&m), "correct round trip keeps frames");
				EXPECT(ret == 0, "correct round trip passes the window oracle");
				EXPECT(written == (groups < DEPTH ? groups : DEPTH),
				       "every used slot counted");
				break;
			case SKIP_BOTH:
				/* The vacuous case: frames are still equal. */
				EXPECT(frames_hold_pattern(&m), "no-op copy engine leaves frames equal");
				EXPECT(ret == -ENODATA, "no-op copy engine fails the window oracle");
				EXPECT(written == 0, "no slot written");
				break;
			case SKIP_H2D:
				EXPECT(!frames_hold_pattern(&m), "poison returns to frames when H2D is lost");
				EXPECT(ret != 0, "lost H2D fails the window oracle");
				break;
			case SKIP_D2H:
				/*
				 * Documented limit: D2H of bytes the frames already
				 * hold cannot be told apart from no D2H.
				 */
				EXPECT(frames_hold_pattern(&m) && ret == 0,
				       "lost D2H alone is outside what chain d can detect");
				break;
			case FIRST_PIECE_ONLY:
				EXPECT(ret == -EIO, "partially copied group fails");
				break;
			case STRAY_TAIL:
				EXPECT(ret == -EFAULT, "write past the used slots fails");
				break;
			case WRONG_SLOT_BYTES:
				EXPECT(ret == -EIO, "slot bytes that match no frame fail");
				break;
			}
		}
	}
	free(m.frames);
	free(m.expected);
	free(m.window);
}

static void chain_a(void)
{
	struct model m = { .frames_per_group = 3 };
	__u32 written;
	int ret;

	m.nr_frames = DEPTH * m.frames_per_group;
	m.frames = calloc(m.nr_frames, FRAME);
	m.window = malloc(WINDOW);
	srand(7);
	for (int mut = CORRECT; mut <= FIRST_PIECE_ONLY; mut++) {
		run(&m, 9, mut, false);
		ret = oracle(&m, 9, false, &written);
		if (mut == CORRECT)
			EXPECT(ret == 0 && written == DEPTH, "chain a round trip passes");
		else if (mut == SKIP_BOTH)
			EXPECT(ret == -ENODATA, "chain a no-op copy engine fails");
		else if (mut == FIRST_PIECE_ONLY)
			EXPECT(ret == -EIO, "chain a partial group fails");
	}
	free(m.frames);
	free(m.window);
}

static void geometry(void)
{
	__u8 window[GROUP];
	struct xdev_ext_mech_ctl_ce_ref ref = { .len = SEG };
	__u32 written;

	memset(window, XDEV_EXT_MECH_CTL_CE_POISON, sizeof(window));
	EXPECT(xdev_ext_mech_ctl_ce_window_check(window, sizeof(window), 2, GROUP, 2, &ref,
						 &written) == -ERANGE, "window shorter than slots");
	EXPECT(xdev_ext_mech_ctl_ce_window_check(window, sizeof(window), 1, GROUP, 1, NULL,
						 &written) == -EINVAL, "missing piece geometry");
	ref.len = 0;
	EXPECT(xdev_ext_mech_ctl_ce_window_check(window, sizeof(window), 1, GROUP, 1, &ref,
						 &written) == -EINVAL, "zero piece length");
}

static void report(void)
{
	char line[256];

	EXPECT(xdev_ext_mech_ctl_report_ce_window(line, sizeof(line), 0, 'd', 4, 8, true),
	       "window pass line");
	EXPECT(!strcmp(line, "XDEV_EXT_MECH_CE_WINDOW=PASS chain=d written=4 depth=8 "
		       "poison=0xc3 reference=frames error=0"), "window pass text");
	EXPECT(!xdev_ext_mech_ctl_report_ce_window(line, sizeof(line), -ENODATA, 'a', 0, 8, false),
	       "window fail line");
	EXPECT(!strcmp(line, "XDEV_EXT_MECH_CE_WINDOW=FAIL chain=a written=0 depth=8 "
		       "poison=0xc3 reference=none error=-61"), "window fail text");
}

int main(void)
{
	report();
	chain_d();
	chain_a();
	geometry();
	if (failures) {
		fprintf(stderr, "FAIL: %u of %u checks\n", failures, checks);
		return 1;
	}
	printf("PASS: %u CE round-trip oracle checks\n", checks);
	return 0;
}

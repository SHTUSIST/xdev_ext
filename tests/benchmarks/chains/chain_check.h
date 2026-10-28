/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_CHECK_H
#define CHAIN_CHECK_H

/*
 * Post-campaign judgements of chain_bench that need no device: the session
 * counter assertions and the CPU payload copy policy.  test_chain_spec.c
 * covers them on the host.
 */

#include <stdio.h>

#include "chain_spec.h"

#define CHAIN_MAX_COPY_SOURCES	6

#define CHAIN_COPY_XSK		"afxdp-copy-mode"
#define CHAIN_COPY_BOUNCE	"nvme-kvm-bounce"
#define CHAIN_COPY_CE_SIM	"ce-sim-cpu-standin"
#define CHAIN_COPY_IAA_SW	"iaa-deflate-generic-cpu"

/*
 * Every stage completed every native command it submitted, for every
 * batch; RX (stage 0 of a receiver) submits nothing and holds the frames.
 * "published" counts frames whose custody returned to user space, not
 * copies: a START with USER_FRAMES|RECYCLE on the io_uring UMEM gets every
 * lent frame back once it drains (xdev_ext_mech_frames_release and
 * xdev_ext_mech_return_idle count each one), so @lent_frames, the sum of
 * nr_user_frames over the campaign's STARTs, must equal it.  A socket UMEM
 * chain lends nothing and publishes nothing.
 */
static inline const char *chain_counters_bad(const struct chain_spec *s,
					     const struct xdev_ext_mech_stats *st,
					     uint64_t groups, uint32_t frames,
					     uint64_t lent_frames)
{
	unsigned int i;

	if (st->state != XDEV_EXT_MECH_SESSION_ACTIVE)
		return "session not ACTIVE";
	if (st->last_err || st->batches_abort || st->rejects || st->protocol_err ||
	    st->timeouts)
		return "errors, aborts, rejects, protocol errors or group timeouts";
	if (st->batches_done != groups)
		return "batches_done differs from the campaign";
	if (st->inflight || st->sequestered)
		return "batches left in flight or sequestered";
	if (st->published != lent_frames)
		return lent_frames ? "published frames differ from the frames START lent" :
				     "frames were handed to user space";
	for (i = 0; i < s->nr_stages; i++) {
		if (!i && chain_rx_first(s)) {
			if (st->submitted[0] || st->completed[0] != groups ||
			    st->held != groups * frames || st->recycled < st->held)
				return "RX stage counters";
			continue;
		}
		if (st->submitted[i] != st->completed[i] || st->completed[i] < groups)
			return "a stage did not complete every batch";
	}
	return NULL;
}

/*
 * The copy sources a timed session run of @s declares up front: only the
 * E7 AF_XDP copy-mode ablation.  The CE simulator and deflate-generic never
 * reach a timed run (chain_validate refuses them), and an NVMe bounce is
 * never expected.
 */
static inline unsigned int chain_declared_copies(const struct chain_spec *s,
						 const char **out)
{
	unsigned int n = 0;

	if (chain_has(s, CH_AFXDP) && s->xsk_mode == CH_XSK_COPY)
		out[n++] = CHAIN_COPY_XSK;
	return n;
}

/* The first of @seen that @s does not declare, or NULL. */
static inline const char *chain_undeclared_copy(const struct chain_spec *s,
						const char *const *seen,
						unsigned int nr_seen)
{
	const char *declared[CHAIN_MAX_COPY_SOURCES];
	unsigned int nd = chain_declared_copies(s, declared), i, k;

	for (i = 0; i < nr_seen; i++) {
		for (k = 0; k < nd && strcmp(seen[i], declared[k]); k++)
			;
		if (k == nd)
			return seen[i];
	}
	return NULL;
}

/*
 * Second line of defence behind hardware_gate.py, for a timed run started
 * without run.py: the hypervisor evidence the running kernel reports.
 * @root is "" for the running system (the tests use a fabricated tree).
 * True, with the reason in @why, when a hypervisor is visible.
 */
static inline bool chain_env_virtual(const char *root, char *why, size_t size)
{
	static char line[16384];
	char path[512];
	bool hit = false;
	FILE *f;

	snprintf(path, sizeof(path), "%s/sys/hypervisor/type", root);
	f = fopen(path, "r");
	if (f) {
		if (fgets(line, sizeof(line), f) && line[0] && line[0] != '\n') {
			line[strcspn(line, "\n")] = '\0';
			snprintf(why, size, "/sys/hypervisor/type reports %.32s", line);
			hit = true;
		}
		fclose(f);
	}
	snprintf(path, sizeof(path), "%s/proc/cpuinfo", root);
	f = hit ? NULL : fopen(path, "r");
	while (f && !hit && fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\n")] = '\0';
		if (strncmp(line, "flags", 5))
			continue;
		strcat(line, " ");
		if (strstr(line, " hypervisor ")) {
			snprintf(why, size, "the CPU flags in /proc/cpuinfo include hypervisor");
			hit = true;
		}
	}
	if (f)
		fclose(f);
	return hit;
}

#endif /* CHAIN_CHECK_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CE_VMM_PROBE_CHECK_H
#define CE_VMM_PROBE_CHECK_H

/* Decisions shared by the real probe and host corruption tests. No device model. */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
/* The consumer supplies the project xdev_ext_policy.h UAPI types. */

/*
 * One batch of @frames user frames (one group); stage counters count batches,
 * not copy entries.
 */
static inline int cvp_check_stats(const struct xdev_ext_mech_stats *s,
				 uint64_t session, unsigned int stages, uint32_t state,
				 unsigned int frames)
{
	unsigned int i;

	if (!s || !session || stages < 1 || stages > 2 ||
	    !frames || frames > XDEV_EXT_MECH_MAX_FRAMES ||
	    (state != XDEV_EXT_MECH_SESSION_ACTIVE && state != XDEV_EXT_MECH_SESSION_STOPPED) ||
	    s->session_id != session || s->state != state ||
	    s->batches_done != 1 || s->published != frames || s->batches_abort ||
	    s->rejects || s->recycled || s->held || s->sequestered || s->timeouts ||
	    s->inflight || s->native_publish || s->protocol_err || s->last_err)
		return -EIO;
	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++) {
		uint64_t expected = i < stages ? 1 : 0;

		if (s->submitted[i] != expected || s->completed[i] != expected)
			return -EIO;
	}
	return 0;
}

static inline int cvp_check_memory(const unsigned char *host,
				  const unsigned char *expected_host, size_t host_bytes,
				  const unsigned char *gpu,
				  const unsigned char *expected_gpu, size_t gpu_bytes)
{
	if (!host || !expected_host || !host_bytes || !gpu || !expected_gpu || !gpu_bytes)
		return -EINVAL;
	return memcmp(host, expected_host, host_bytes) ||
	       memcmp(gpu, expected_gpu, gpu_bytes) ? -EBADMSG : 0;
}

/* The caller must separately require STOP_REPORT's syscall to return zero. */
static inline int cvp_check_stop(const struct xdev_ext_mech_stop_report *report,
				uint64_t session, unsigned int stages, unsigned int frames)
{
	if (!report || report->size != sizeof(*report) ||
	    report->version != XDEV_EXT_MECH_STOP_REPORT_VERSION ||
	    report->session_id != session)
		return -EPROTO;
	return cvp_check_stats(&report->stats, session, stages, XDEV_EXT_MECH_SESSION_STOPPED,
			       frames);
}

/*
 * Runs of physically adjacent pages among @n /proc/self/pagemap entries of
 * consecutive virtual pages: a new run starts wherever a page frame number
 * is not the previous one plus one.  0 when any page is not present or its
 * frame number reads as zero (pagemap hides frame numbers without
 * CAP_SYS_ADMIN).  Bit 63 is "present", bits 0-54 the frame number.
 */
static inline unsigned int cvp_phys_runs(const uint64_t *entry, size_t n)
{
	const uint64_t present = UINT64_C(1) << 63, pfn = (UINT64_C(1) << 55) - 1;
	unsigned int runs = 0;
	size_t i;

	if (!entry || !n)
		return 0;
	for (i = 0; i < n; i++) {
		if (!(entry[i] & present) || !(entry[i] & pfn))
			return 0;
		if (!i || (entry[i] & pfn) != (entry[i - 1] & pfn) + 1)
			runs++;
	}
	return runs;
}
#endif

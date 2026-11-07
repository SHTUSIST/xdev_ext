/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CE_VMM_PROBE_CHECK_H
#define CE_VMM_PROBE_CHECK_H

/* Decisions shared by the real probe and host corruption tests. No device model. */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
/* The consumer supplies the project xdev_ext_policy.h UAPI types. */

/* One batch, two user frames; stage counters count batches, not copy entries. */
static inline int cvp_check_stats(const struct xdev_ext_mech_stats *s,
				 uint64_t session, unsigned int stages, uint32_t state)
{
	unsigned int i;

	if (!s || !session || stages < 1 || stages > 2 ||
	    (state != XDEV_EXT_MECH_SESSION_ACTIVE && state != XDEV_EXT_MECH_SESSION_STOPPED) ||
	    s->session_id != session || s->state != state ||
	    s->batches_done != 1 || s->published != 2 || s->batches_abort ||
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
				uint64_t session, unsigned int stages)
{
	if (!report || report->size != sizeof(*report) ||
	    report->version != XDEV_EXT_MECH_STOP_REPORT_VERSION ||
	    report->session_id != session)
		return -EPROTO;
	return cvp_check_stats(&report->stats, session, stages, XDEV_EXT_MECH_SESSION_STOPPED);
}
#endif

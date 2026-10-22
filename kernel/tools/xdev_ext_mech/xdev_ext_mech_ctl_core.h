/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CTL_CORE_H
#define XDEV_EXT_MECH_CTL_CORE_H

/*
 * Pure decisions of xdev_ext_mech_ctl: the frame layout it gives a session, CLI
 * value parsing, setting a BPF global in a section image, and the verdict
 * and text of every marker line.  The KVM harness greps those lines, so
 * their text is part of the contract;
 * tools/testing/selftests/xdev_ext_mech_tools/xdev_ext_mech_ctl_core_test.c pins it.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_xdp.h>
#include <linux/types.h>

#include "../../include/uapi/linux/xdev_ext_mech.h"
#include "../../io_uring/xdev_ext_mech_core.h"
#include "../../io_uring/xdev_ext_mech_notify.h"
#include "xdev_ext_mech_prog.h"

static inline bool xdev_ext_mech_ctl_transport_ok(
			const struct xdev_ext_mech_transport_stats *s)
{
	return s->size == sizeof(*s) &&
	       s->version == XDEV_EXT_MECH_TRANSPORT_STATS_VERSION &&
	       s->session_id && !s->rsvd && !s->native_controls &&
	       !s->pending_acks && !s->uncertain_controls;
}

/*
 * The frame of the user-space NXP pipeline (nvme_xdp_pipeline.c): 4 KiB
 * chunks, and an RX packet at XDP_PACKET_HEADROOM plus 22 bytes of UMEM
 * headroom, so the payload after the 82 header bytes starts 8-byte aligned
 * at 360 in both directions.
 */
#define XDEV_EXT_MECH_CTL_FRAME_SIZE		4096U
#define XDEV_EXT_MECH_CTL_XDP_HEADROOM	256U	/* XDP_PACKET_HEADROOM */
#define XDEV_EXT_MECH_CTL_HDR_ROOM		(XDEV_EXT_MECH_CTL_XDP_HEADROOM + 22U + \
					 XDEV_EXT_MP_PKT_HDR_LEN)

/* A normal campaign requests one wake for its entire absolute batch goal. */
static inline int
xdev_ext_mech_ctl_notify_request(struct xdev_ext_mech_notify_arm *arm, __u64 session,
			    __u64 groups)
{
	*arm = (struct xdev_ext_mech_notify_arm) {
		.session_id = session,
		.batches_target = groups,
	};
	return xdev_ext_mech_notify_validate(arm);
}

/* A wake can announce failure/STOPPING while accepted DMA remains live. */
static inline int
xdev_ext_mech_ctl_notify_result(const struct xdev_ext_mech_stats *s, __u64 groups)
{
	if (s->last_err)
		return s->last_err;
	if (s->state != XDEV_EXT_MECH_SESSION_ACTIVE)
		return -ESHUTDOWN;
	if (s->batches_done < groups || s->batches_abort ||
	    s->inflight || s->sequestered)
		return -EIO;
	return 0;
}

/* Force the requested mode: no implicit ZC-to-COPY downgrade. */
static inline __u16 xdev_ext_mech_ctl_xsk_flags(bool copy_mode)
{
	return copy_mode ? XDP_COPY : XDP_ZEROCOPY;
}

static inline int xdev_ext_mech_ctl_xsk_mode_check(bool copy_mode, __u32 options)
{
	bool zc = options & XDP_OPTIONS_ZEROCOPY;

	if (copy_mode)
		return zc ? -EPROTO : 0;
	return zc ? 0 : -EOPNOTSUPP;
}

/* Configure once: RX admission consumes stage 0, then core runs stages 1+. */
static inline int
xdev_ext_mech_ctl_rx_stages(struct xdev_ext_mech_stage_uapi *st, int xsk_fd, int nvme_fd,
		      int ce_to_fd, int ce_from_fd, __u64 slba, __u64 nlb,
		      __u64 ce_va, __u64 ce_len)
{
	unsigned int last = ce_len ? 3 : 1;

	if (!st || xsk_fd < 0 || nvme_fd < 0 || !nlb ||
	    (ce_len && (ce_to_fd < 0 || ce_from_fd < 0)))
		return -EINVAL;
	memset(st, 0, (last + 1) * sizeof(*st));
	st[0] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = xsk_fd,
	};
	if (ce_len) {
		st[1] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_CE,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = ce_to_fd,
			.arg0 = ce_va, .arg1 = ce_len,
		};
		st[2] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_CE,
			.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = ce_from_fd,
			.arg0 = ce_va, .arg1 = ce_len,
		};
	}
	st[last] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = nvme_fd,
		.arg0 = slba, .arg1 = nlb,
	};
	return last + 1;
}

/* Session layout for an L3 MTU: NXP-sized segments of a @group_bytes group. */
static inline int xdev_ext_mech_ctl_layout(__u32 mtu, __u32 group_bytes,
				      struct xdev_ext_mech_layout *l)
{
	__u32 seg_len;
	int ret;

	if (!group_bytes)
		return -EINVAL;
	ret = xdev_ext_mp_seg_limit(mtu, XDEV_EXT_MECH_CTL_FRAME_SIZE,
			       XDEV_EXT_MECH_CTL_HDR_ROOM, &seg_len);
	if (ret)
		return ret;
	*l = (struct xdev_ext_mech_layout) {
		.frame_size = XDEV_EXT_MECH_CTL_FRAME_SIZE,
		.hdr_room = XDEV_EXT_MECH_CTL_HDR_ROOM,
		.seg_len = seg_len,
		.group_bytes = group_bytes,
	};
	ret = xdev_ext_mech_layout_frames(l);
	return ret < 0 ? ret : 0;
}

/* UMEM headroom that puts a received payload at the layout's hdr_room. */
static inline int xdev_ext_mech_ctl_rx_headroom(const struct xdev_ext_mech_layout *l,
					   __u32 *headroom)
{
	if (l->hdr_room < XDEV_EXT_MECH_CTL_XDP_HEADROOM + XDEV_EXT_MP_PKT_HDR_LEN)
		return -EINVAL;
	*headroom = l->hdr_room - XDEV_EXT_MECH_CTL_XDP_HEADROOM -
		    XDEV_EXT_MP_PKT_HDR_LEN;
	return 0;
}

/* Decimal or 0x-prefixed hex, nothing else. */
static inline int xdev_ext_mech_ctl_parse_u64(const char *s, __u64 *v)
{
	unsigned long long value;
	char *end;

	if (!s || *s < '0' || *s > '9')
		return -EINVAL;
	errno = 0;
	value = strtoull(s, &end, 0);
	if (errno == ERANGE)
		return -ERANGE;
	if (errno || *end)
		return -EINVAL;
	*v = value;
	return 0;
}

static inline int xdev_ext_mech_ctl_hex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* xx:xx:xx:xx:xx:xx */
static inline int xdev_ext_mech_ctl_parse_mac(const char *s, __u8 mac[6])
{
	int i, hi, lo;

	if (!s || strlen(s) != 17)
		return -EINVAL;
	for (i = 0; i < 6; i++) {
		hi = xdev_ext_mech_ctl_hex(s[3 * i]);
		lo = xdev_ext_mech_ctl_hex(s[3 * i + 1]);
		if (hi < 0 || lo < 0 || (i < 5 && s[3 * i + 2] != ':'))
			return -EINVAL;
		mac[i] = (__u8)(hi << 4 | lo);
	}
	return 0;
}

/* --set <global>=<u64>: a C identifier and a value. */
static inline int xdev_ext_mech_ctl_parse_set(const char *arg, char *name,
					 size_t name_size, __u64 *value)
{
	const char *eq = arg ? strchr(arg, '=') : NULL;
	size_t len, i;

	if (!eq || eq == arg)
		return -EINVAL;
	len = (size_t)(eq - arg);
	for (i = 0; i < len; i++) {
		char c = arg[i];

		if (!(c == '_' || (c >= 'a' && c <= 'z') ||
		      (c >= 'A' && c <= 'Z') || (i && c >= '0' && c <= '9')))
			return -EINVAL;
	}
	if (len >= name_size)
		return -ENAMETOOLONG;
	memcpy(name, arg, len);
	name[len] = '\0';
	return xdev_ext_mech_ctl_parse_u64(eq + 1, value);
}

/*
 * Store @value as a host-order integer of @size bytes at @off of a section
 * image (the BPF target has the host's byte order).
 */
static inline int xdev_ext_mech_ctl_set_value(void *image, size_t image_size,
					 __u32 off, __u32 size, __u64 value)
{
	__u8 *p = (__u8 *)image + off;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		return -EINVAL;
	if (off > image_size || size > image_size - off ||
	    (size < 8 && value >> (8 * size)))
		return -ERANGE;
	switch (size) {
	case 1:
		*p = (__u8)value;
		break;
	case 2: {
		__u16 v = (__u16)value;

		memcpy(p, &v, sizeof(v));
		break;
	}
	case 4: {
		__u32 v = (__u32)value;

		memcpy(p, &v, sizeof(v));
		break;
	}
	default:
		memcpy(p, &value, sizeof(value));
		break;
	}
	return 0;
}

static inline const char *xdev_ext_mech_ctl_state_name(__u32 state)
{
	switch (state) {
	case XDEV_EXT_MECH_SESSION_NONE:
		return "NONE";
	case XDEV_EXT_MECH_SESSION_ACTIVE:
		return "ACTIVE";
	case XDEV_EXT_MECH_SESSION_ERROR:
		return "ERROR";
	case XDEV_EXT_MECH_SESSION_STOPPING:
		return "STOPPING";
	case XDEV_EXT_MECH_SESSION_STOPPED:
		return "STOPPED";
	case XDEV_EXT_MECH_SESSION_ZOMBIE:
		return "ZOMBIE";
	default:
		return "UNKNOWN";
	}
}

/* Symbolic -errno for the errors marker lines name; one call per line. */
static inline const char *xdev_ext_mech_ctl_errname(int err)
{
	static const struct {
		int err;
		const char *name;
	} names[] = {
		{ -EBUSY, "-EBUSY" }, { -ENXIO, "-ENXIO" },
		{ -ECANCELED, "-ECANCELED" }, { -EOPNOTSUPP, "-EOPNOTSUPP" },
		{ -ERANGE, "-ERANGE" }, { -EPERM, "-EPERM" },
		{ -EINVAL, "-EINVAL" }, { -ESHUTDOWN, "-ESHUTDOWN" },
		{ -ENOENT, "-ENOENT" }, { -ENOSPC, "-ENOSPC" },
		{ -EPROTO, "-EPROTO" }, { -EAGAIN, "-EAGAIN" },
		{ -EIO, "-EIO" }, { -ETIMEDOUT, "-ETIMEDOUT" },
		{ -ENODEV, "-ENODEV" }, { -EMSGSIZE, "-EMSGSIZE" },
		{ -EXDEV, "-EXDEV" }, { -EEXIST, "-EEXIST" },
		{ -ENODATA, "-ENODATA" }, { -E2BIG, "-E2BIG" },
		{ -ENETDOWN, "-ENETDOWN" }, { -ENOBUFS, "-ENOBUFS" },
		{ -EFAULT, "-EFAULT" }, { -ENOMEM, "-ENOMEM" },
	};
	static char other[16];
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		if (names[i].err == err)
			return names[i].name;
	snprintf(other, sizeof(other), "%d", err);
	return other;
}

/* Remote completion was not established before the configured retry budget. */
static inline int xdev_ext_mech_ctl_remote_outcome_line(char *buf,size_t size,
                                                  const struct xdev_ext_mech_stats *s)
{
 int n;
 if (s->last_err != -EREMOTEIO) return 0;
 n=snprintf(buf,size,"XDEV_EXT_MECH_REMOTE_OUTCOME outcome=UNKNOWN cause=remote-ack-unconfirmed batches_abort=%llu durable=unclaimed",
             (unsigned long long)s->batches_abort);
 return n<0 || (size_t)n>=size ? -ENOSPC : n;
}

/* One stats line; its length, or -ENOSPC when @size is too small. */
static inline int xdev_ext_mech_ctl_stats_line(char *buf, size_t size,
					  const struct xdev_ext_mech_stats *s)
{
	int n;

	n = snprintf(buf, size,
		     "XDEV_EXT_MECH_STATS session=%llu state=%s last_err=%s "
		     "batches_done=%llu batches_abort=%llu rejects=%llu "
		     "recycled=%llu held=%llu sequestered=%llu timeouts=%llu "
		     "inflight=%llu native_publish=%llu protocol_err=%llu "
		     "published=%llu submitted=%llu,%llu,%llu,%llu "
		     "completed=%llu,%llu,%llu,%llu",
		     (unsigned long long)s->session_id,
		     xdev_ext_mech_ctl_state_name(s->state),
		     xdev_ext_mech_ctl_errname(s->last_err),
		     (unsigned long long)s->batches_done,
		     (unsigned long long)s->batches_abort,
		     (unsigned long long)s->rejects,
		     (unsigned long long)s->recycled,
		     (unsigned long long)s->held,
		     (unsigned long long)s->sequestered,
		     (unsigned long long)s->timeouts,
		     (unsigned long long)s->inflight,
		     (unsigned long long)s->native_publish,
		     (unsigned long long)s->protocol_err,
		     (unsigned long long)s->published,
		     (unsigned long long)s->submitted[0],
		     (unsigned long long)s->submitted[1],
		     (unsigned long long)s->submitted[2],
		     (unsigned long long)s->submitted[3],
		     (unsigned long long)s->completed[0],
		     (unsigned long long)s->completed[1],
		     (unsigned long long)s->completed[2],
		     (unsigned long long)s->completed[3]);
	if (n < 0 || (size_t)n >= size)
		return -ENOSPC;
	return n;
}

/*
 * Marker lines.  Each report writes "<MARKER>=PASS|FAIL <fields>" and
 * returns the verdict; a line that did not fit is a FAIL.  "errors" is the
 * number of aborted batches.
 */
static inline bool xdev_ext_mech_ctl_line(char *buf, size_t size, bool pass,
				     const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

static inline bool xdev_ext_mech_ctl_line(char *buf, size_t size, bool pass,
				     const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	return pass && n >= 0 && (size_t)n < size;
}

#define XDEV_EXT_MECH_CTL_VERDICT(pass)	((pass) ? "PASS" : "FAIL")
#define XDEV_EXT_MECH_CTL_U(x)		((unsigned long long)(x))

/* Observed successful reads in one terminal wait, including timeout waits. */
static inline bool xdev_ext_mech_ctl_notify_line(char *buf, size_t size,
					  unsigned int eventfd_reads,
					  unsigned int stats_reads)
{
	return xdev_ext_mech_ctl_line(buf, size, true,
		"XDEV_EXT_MECH_NOTIFY mode=terminal eventfd_reads=%u stats_reads=%u",
		eventfd_reads, stats_reads);
}

/* Nothing left behind: no batch in flight, none sequestered. */
static inline bool xdev_ext_mech_ctl_settled(const struct xdev_ext_mech_stats *s)
{
	return !s->inflight && !s->sequestered;
}

/* Finite campaign: every group needs its own full CE window slot. */
static inline bool xdev_ext_mech_ctl_ce_window_ok(__u64 depth, __u64 group_bytes,
                                             __u64 ce_len)
{
	return depth && group_bytes && depth <= ce_len / group_bytes;
}

static inline bool xdev_ext_mech_ctl_report_nic_ce_nvme(char *buf, size_t size,
                          const struct xdev_ext_mech_stats *s,
                          __u64 groups, __u32 frames)
{
	bool pass = s->state == XDEV_EXT_MECH_SESSION_ACTIVE &&
		s->batches_done == groups && !s->batches_abort &&
		!s->last_err && !s->rejects && !s->protocol_err &&
		s->held == groups * frames && s->recycled >= s->held &&
		!s->published && xdev_ext_mech_ctl_settled(s);
	unsigned int i;

	for (i = 0; i < 4; i++)
		pass = pass && s->submitted[i] == (i ? groups : 0) &&
			s->completed[i] == groups;
	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_NIC_CE_NVME_E2E=%s groups=%llu",
		XDEV_EXT_MECH_CTL_VERDICT(pass), XDEV_EXT_MECH_CTL_U(groups));
}

/* S1: AF_XDP RX (stage 0) -> NVMe WRITE (stage 1), @frames per group. */
static inline bool xdev_ext_mech_ctl_nic_nvme_ok(const struct xdev_ext_mech_stats *s,
					    __u64 groups, __u32 frames)
{
	return s->state == XDEV_EXT_MECH_SESSION_ACTIVE && !s->last_err &&
	       s->batches_done == groups && !s->batches_abort &&
	       s->held == groups * frames && s->recycled >= s->held &&
	       s->submitted[1] == groups && s->completed[1] == groups &&
	       !s->published && !s->rejects && !s->protocol_err &&
	       xdev_ext_mech_ctl_settled(s);
}

static inline bool xdev_ext_mech_ctl_report_nic_nvme(char *buf, size_t size,
						const struct xdev_ext_mech_stats *s,
						__u64 groups, __u32 frames)
{
	bool pass = xdev_ext_mech_ctl_nic_nvme_ok(s, groups, frames);

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_NIC_NVME_E2E=%s groups=%llu held=%llu "
		"nvme_submitted=%llu nvme_completed=%llu recycled=%llu "
		"published=%llu errors=%llu sequestered=%llu inflight=%llu",
		XDEV_EXT_MECH_CTL_VERDICT(pass), XDEV_EXT_MECH_CTL_U(groups),
		XDEV_EXT_MECH_CTL_U(s->held), XDEV_EXT_MECH_CTL_U(s->submitted[1]),
		XDEV_EXT_MECH_CTL_U(s->completed[1]), XDEV_EXT_MECH_CTL_U(s->recycled),
		XDEV_EXT_MECH_CTL_U(s->published), XDEV_EXT_MECH_CTL_U(s->batches_abort),
		XDEV_EXT_MECH_CTL_U(s->sequestered), XDEV_EXT_MECH_CTL_U(s->inflight));
}

/*
 * --quiet-wait (measurement MK1, plan section 6.2): after READY the receiver
 * makes no system call per group.  It blocks once in sigtimedwait() until
 * the harness, which reads the session eventfd's count from
 * /proc/<pid>/fdinfo, sends SIGUSR1 once every group ended; then it reads
 * the eventfd once and takes one STATS.  Only a plain nic-nvme run, without
 * an arm or the shared-UMEM probe, has that shape.
 */
static inline int xdev_ext_mech_ctl_quiet_check(bool quiet, bool nic_nvme,
					   unsigned int arms, bool probe)
{
	if (!quiet)
		return 0;
	return nic_nvme && !arms && !probe ? 0 : -EINVAL;
}

/*
 * The one look after the wake-up suffices when the eventfd count read (one
 * per ended batch) and STATS both cover @groups; otherwise the receiver
 * falls back to the ordinary wait, and its syscalls are no longer quiet.
 */
static inline bool xdev_ext_mech_ctl_quiet_done(__u64 efd_count, __u64 groups,
					   const struct xdev_ext_mech_stats *s)
{
	return efd_count >= groups &&
	       s->batches_done + s->batches_abort >= groups;
}

/* Printed before READY: the process and eventfd the harness watches. */
static inline bool xdev_ext_mech_ctl_quiet_line(char *buf, size_t size, int pid,
					   int efd, __u64 groups)
{
	return xdev_ext_mech_ctl_line(buf, size, true,
		"XDEV_EXT_MECH_QUIET_WAIT pid=%d eventfd=%d signal=SIGUSR1 "
		"groups=%llu", pid, efd, (unsigned long long)groups);
}

/* Printed after the wake-up, before the run's marker line. */
static inline bool xdev_ext_mech_ctl_quiet_wake_line(char *buf, size_t size,
						bool signalled,
						__u64 efd_count, bool fallback)
{
	return xdev_ext_mech_ctl_line(buf, size, true,
		"XDEV_EXT_MECH_QUIET_WAKE by=%s eventfd_count=%llu fallback=%d",
		signalled ? "signal" : "timeout",
		(unsigned long long)efd_count, fallback);
}

/* A held frame address pushed into the fill ring changed nothing. */
static inline bool xdev_ext_mech_ctl_report_fq_dup(char *buf, size_t size,
					      const struct xdev_ext_mech_stats *s,
					      __u64 groups, __u32 frames,
					      __u32 pushed)
{
	bool pass = pushed && xdev_ext_mech_ctl_nic_nvme_ok(s, groups, frames);

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_FQ_DUP_REJECT=%s pushed=%u batches_done=%llu "
		"errors=%llu", XDEV_EXT_MECH_CTL_VERDICT(pass), pushed,
		XDEV_EXT_MECH_CTL_U(s->batches_done),
		XDEV_EXT_MECH_CTL_U(s->batches_abort));
}

/* The program put every SLBA past the window: C refused each group. */
static inline bool
xdev_ext_mech_ctl_report_window_reject(char *buf, size_t size,
				  const struct xdev_ext_mech_stats *s, __u64 groups)
{
	bool pass = s->batches_abort == groups && !s->batches_done &&
		    !s->submitted[1] && s->recycled == s->held &&
		    xdev_ext_mech_ctl_settled(s);

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_NVME_WINDOW_REJECT=%s errors=%llu nvme_submitted=%llu",
		XDEV_EXT_MECH_CTL_VERDICT(pass), XDEV_EXT_MECH_CTL_U(s->batches_abort),
		XDEV_EXT_MECH_CTL_U(s->submitted[1]));
}

/* DRV-mode copy delivery (RX_NATIVE): never held, always published. */
static inline bool
xdev_ext_mech_ctl_report_native_copy(char *buf, size_t size,
				const struct xdev_ext_mech_stats *s)
{
	bool pass = !s->held && s->native_publish && !s->batches_done;

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_NATIVE_COPY=%s held=%llu native_publish=%llu",
		XDEV_EXT_MECH_CTL_VERDICT(pass), XDEV_EXT_MECH_CTL_U(s->held),
		XDEV_EXT_MECH_CTL_U(s->native_publish));
}

/* An incomplete group expired and gave all its frames back. */
static inline bool
xdev_ext_mech_ctl_report_group_timeout(char *buf, size_t size,
				  const struct xdev_ext_mech_stats *s)
{
	bool pass = s->timeouts && s->recycled == s->held &&
		    xdev_ext_mech_ctl_settled(s);

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_GROUP_TIMEOUT=%s timeouts=%llu held=%llu recycled=%llu",
		XDEV_EXT_MECH_CTL_VERDICT(pass), XDEV_EXT_MECH_CTL_U(s->timeouts),
		XDEV_EXT_MECH_CTL_U(s->held), XDEV_EXT_MECH_CTL_U(s->recycled));
}

/* A second socket binding XDP_SHARED_UMEM onto the session socket. */
static inline bool xdev_ext_mech_ctl_report_shared_umem(char *buf, size_t size,
						   int err)
{
	bool pass = err == -EBUSY;

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_SHARED_UMEM_REJECT=%s err=%s",
		XDEV_EXT_MECH_CTL_VERDICT(pass), xdev_ext_mech_ctl_errname(err));
}

/* The program was detached mid-run: the session stopped with -ECANCELED. */
static inline bool
xdev_ext_mech_ctl_report_prog_detach(char *buf, size_t size,
				const struct xdev_ext_mech_stats *s)
{
	bool pass = s->state == XDEV_EXT_MECH_SESSION_STOPPED &&
		    s->last_err == -ECANCELED && xdev_ext_mech_ctl_settled(s);

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_PROG_DETACH=%s last_err=%s state=%s",
		XDEV_EXT_MECH_CTL_VERDICT(pass), xdev_ext_mech_ctl_errname(s->last_err),
		xdev_ext_mech_ctl_state_name(s->state));
}

/*
 * The ring closed with batches in flight.  @s is the session afterwards, or
 * NULL once it was freed, which needs every in-flight batch to have ended
 * since each holds a session reference.  A ZOMBIE that parked what it could
 * not drain also passes.
 */
static inline bool xdev_ext_mech_ctl_report_ring_exit(char *buf, size_t size,
						 const struct xdev_ext_mech_stats *s)
{
	bool pass = !s ||
		    (s->state == XDEV_EXT_MECH_SESSION_STOPPED && !s->inflight) ||
		    s->state == XDEV_EXT_MECH_SESSION_ZOMBIE;

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_RING_EXIT=%s inflight=%llu state=%s",
		XDEV_EXT_MECH_CTL_VERDICT(pass), XDEV_EXT_MECH_CTL_U(s ? s->inflight : 0),
		s ? xdev_ext_mech_ctl_state_name(s->state) : "FREED");
}

/* The TX device went away under the session: it stopped with -ENXIO. */
static inline bool xdev_ext_mech_ctl_report_unbind(char *buf, size_t size,
					      const struct xdev_ext_mech_stats *s)
{
	bool pass = s->state == XDEV_EXT_MECH_SESSION_STOPPED &&
		    s->last_err == -ENXIO && xdev_ext_mech_ctl_settled(s);

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_XSK_UNBIND_INFLIGHT=%s last_err=%s state=%s "
		"inflight=%llu", XDEV_EXT_MECH_CTL_VERDICT(pass),
		xdev_ext_mech_ctl_errname(s->last_err),
		xdev_ext_mech_ctl_state_name(s->state),
		XDEV_EXT_MECH_CTL_U(s->inflight));
}

/* S2: NVMe READ (stage 0) -> AF_XDP TX (stage 1). */
static inline bool xdev_ext_mech_ctl_report_nvme_nic(char *buf, size_t size,
						const struct xdev_ext_mech_stats *s,
						__u64 groups)
{
	bool pass = s->state == XDEV_EXT_MECH_SESSION_ACTIVE && !s->last_err &&
		    s->batches_done == groups && !s->batches_abort &&
		    s->submitted[0] == groups && s->completed[0] == groups &&
		    s->submitted[1] >= groups &&
		    s->completed[1] == s->submitted[1] &&
		    xdev_ext_mech_ctl_settled(s);

	return xdev_ext_mech_ctl_line(buf, size, pass,
		"XDEV_EXT_MECH_NVME_NIC_E2E=%s groups=%llu nvme_submitted=%llu "
		"nvme_completed=%llu tx_submitted=%llu tx_completed=%llu "
		"errors=%llu sequestered=%llu inflight=%llu",
		XDEV_EXT_MECH_CTL_VERDICT(pass), XDEV_EXT_MECH_CTL_U(groups),
		XDEV_EXT_MECH_CTL_U(s->submitted[0]),
		XDEV_EXT_MECH_CTL_U(s->completed[0]),
		XDEV_EXT_MECH_CTL_U(s->submitted[1]),
		XDEV_EXT_MECH_CTL_U(s->completed[1]),
		XDEV_EXT_MECH_CTL_U(s->batches_abort),
		XDEV_EXT_MECH_CTL_U(s->sequestered), XDEV_EXT_MECH_CTL_U(s->inflight));
}

/*
 * S3 chain @chain over @nr_stages stages, each of which completed every
 * native command it submitted for every group; @frames_ok is the user's
 * compare (chain d) and true otherwise.  @sim names the CE simulator.
 */
static inline bool xdev_ext_mech_ctl_report_ce_chain(char *buf, size_t size,
						const struct xdev_ext_mech_stats *s,
						char chain, __u64 groups,
						__u32 nr_stages, bool sim,
						bool frames_ok)
{
	bool pass = frames_ok && s->batches_done == groups &&
		    !s->batches_abort && xdev_ext_mech_ctl_settled(s) &&
		    nr_stages && nr_stages <= XDEV_EXT_MECH_MAX_STAGES;
	__u32 i;

	for (i = 0; pass && i < nr_stages; i++)
		pass = s->submitted[i] == s->completed[i] &&
		       s->completed[i] >= groups;
	return xdev_ext_mech_ctl_line(buf, size, pass, "XDEV_EXT_MECH_CE_%s=%s chain=%c",
				 sim ? "SIM" : "GPU",
				 XDEV_EXT_MECH_CTL_VERDICT(pass), chain);
}

#endif /* XDEV_EXT_MECH_CTL_CORE_H */

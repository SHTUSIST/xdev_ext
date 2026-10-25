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

/* --poll: ask every used stage for kernel-worker polling; CREATE refuses a
 * stage that cannot be polled (no interrupt fallback). Other flags are kept. */
static inline void xdev_ext_mech_ctl_poll_stages(struct xdev_ext_mech_create *c, bool poll)
{
	__u32 i;

	for (i = 0; poll && i < c->nr_stages && i < XDEV_EXT_MECH_MAX_STAGES; i++)
		c->st[i].flags |= XDEV_EXT_MECH_STAGE_F_POLL;
}

/* The marker of a --poll CREATE: how many stages asked for polling. */
static inline bool xdev_ext_mech_ctl_poll_line(char *buf, size_t size, __u32 stages)
{
	int n = snprintf(buf, size, "XDEV_EXT_MECH_POLL stages=%u\n", stages);

	return n > 0 && (size_t)n < size;
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


/* The control tool's oracle uses byte operations independently of kernel
 * crypto callbacks. This runs only after correctness workloads, never timed. */
#define XDEV_EXT_MECH_CTL_CHAINS_V2 1
static inline int xdev_ext_mech_ctl_xform_parse(const char *name, __u32 *xform)
{
 /* bpf-compute runs the attached CPU program's compute member; --xform-arg is
  * its declared length change. ctl's byte oracle cannot judge it. */
 static const char *const names[] = { "crc32c-append", "crc32c-strip", "crc32c-seal",
  "crc32c-check", "parse-strip", "xxh64-append", "sha256-append", "deflate", "inflate",
  "bpf-compute" };
 unsigned i;
 if (!name || !xform) return -EINVAL;
 for (i=0;i<sizeof(names)/sizeof(names[0]);i++)
  if (!strcmp(name,names[i])) { *xform=i+1; return 0; }
 return -EINVAL;
}
static inline int xdev_ext_mech_ctl_fanout_stages(struct xdev_ext_mech_stage_uapi *st,
 int src_fd,__u64 slba,__u64 nlb,int dst_fd,__u64 dst_slba,__u64 dst_nlb,int xsk_fd)
{
 if (!st || src_fd<0 || dst_fd<0 || xsk_fd<0 || !nlb || !dst_nlb) return -EINVAL;
 memset(st,0,sizeof(*st)*XDEV_EXT_MECH_MAX_STAGES);
 st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,
  .direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=src_fd,.arg0=slba,.arg1=nlb};
 st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,
  .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=dst_fd,.arg0=dst_slba,.arg1=dst_nlb};
 st[2]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_AFXDP,
  .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=xsk_fd,.flags=XDEV_EXT_MECH_STAGE_F_FANOUT};
 return 3;
}
static inline int xdev_ext_mech_ctl_cpu_stages(struct xdev_ext_mech_stage_uapi *st,
 int src_fd,__u64 slba,__u64 nlb,__u32 xform,__u64 param,
 __u32 sink_class,int sink_fd,__u64 sink_arg0,__u64 sink_arg1)
{
 if (!st || src_fd<0 || sink_fd<0 || !nlb || !xform || xform>=XDEV_EXT_CPU_XFORM_MAX ||
     (sink_class!=XDEV_EXT_MECH_CLASS_NVME && sink_class!=XDEV_EXT_MECH_CLASS_AFXDP)) return -EINVAL;
 memset(st,0,sizeof(*st)*XDEV_EXT_MECH_MAX_STAGES);
 st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,
  .direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=src_fd,.arg0=slba,.arg1=nlb};
 st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_CPU,
  .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=-1,.arg0=xform,.arg1=param};
 st[2]=(struct xdev_ext_mech_stage_uapi){.class_id=sink_class,
  .direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=sink_fd,.arg0=sink_arg0,.arg1=sink_arg1};
 return 3;
}
static inline __u64 ctl_oracle_load(const __u8 *p,unsigned n,bool big)
{
 __u64 v=0; unsigned i;
 for(i=0;i<n;i++) v|=(__u64)p[i]<<(8*(big?n-1-i:i));
 return v;
}
static inline void ctl_oracle_store(__u8 *p,__u64 v,unsigned n,bool big)
{
 unsigned i; for(i=0;i<n;i++)p[i]=v>>(8*(big?n-1-i:i));
}
static inline __u32 ctl_oracle_crc(const __u8 *p,size_t n)
{
 __u32 c=~0U; size_t i; unsigned bit;
 for(i=0;i<n;i++){c^=p[i];for(bit=0;bit<8;bit++)c=(c>>1)^((0U-(c&1))&0x82f63b78U);}
 return ~c;
}
static inline __u64 ctl_oracle_rot(__u64 v,unsigned n){return (v<<n)|(v>>(64-n));}
static inline __u64 ctl_oracle_xround(__u64 a,__u64 v)
{
 return ctl_oracle_rot(a+v*14029467366897019727ULL,31)*11400714785074694791ULL;
}
static inline __u64 ctl_oracle_xxh(const __u8 *p,size_t n,__u64 seed)
{
 const __u64 p1=11400714785074694791ULL,p2=14029467366897019727ULL;
 const __u64 p3=1609587929392839161ULL,p4=9650029242287828579ULL,p5=2870177450012600261ULL;
 size_t off=0;__u64 h;
 if(n>=32){
  __u64 lane[4]={seed+p1+p2,seed+p2,seed,seed-p1};unsigned j;
  do {for(j=0;j<4;j++)lane[j]=ctl_oracle_xround(lane[j],ctl_oracle_load(p+off+8*j,8,false));off+=32;}while(n-off>=32);
  h=ctl_oracle_rot(lane[0],1)+ctl_oracle_rot(lane[1],7)+ctl_oracle_rot(lane[2],12)+ctl_oracle_rot(lane[3],18);
  for(j=0;j<4;j++)h=(h^ctl_oracle_xround(0,lane[j]))*p1+p4;
 }else h=seed+p5;
 h+=n;
 while(n-off>=8){h=ctl_oracle_rot(h^ctl_oracle_xround(0,ctl_oracle_load(p+off,8,false)),27)*p1+p4;off+=8;}
 if(n-off>=4){h=ctl_oracle_rot(h^(ctl_oracle_load(p+off,4,false)*p1),23)*p2+p3;off+=4;}
 while(off<n)h=ctl_oracle_rot(h^((__u64)p[off++]*p5),11)*p1;
 h^=h>>33;h*=p2;h^=h>>29;h*=p3;return h^(h>>32);
}
static inline __u32 ctl_oracle_ror32(__u32 x,unsigned n){return (x>>n)|(x<<(32-n));}
static inline void ctl_oracle_sha256(const __u8 *p,size_t n,__u8 out[32])
{
 static const __u32 k[64]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 __u32 h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 size_t blocks=n/64+1+(n%64>=56),b;unsigned i;
 for(b=0;b<blocks;b++){
  __u8 bytes[64]={0};__u32 w[64],v[8];size_t off=b*64;
  for(i=0;i<64;i++)if(off+i<n)bytes[i]=p[off+i];else if(off+i==n)bytes[i]=0x80;
  if(b+1==blocks)ctl_oracle_store(bytes+56,(__u64)n*8,8,true);
  for(i=0;i<16;i++)w[i]=ctl_oracle_load(bytes+4*i,4,true);
  for(i=16;i<64;i++){
   __u32 a=w[i-15],z=w[i-2];
   w[i]=w[i-16]+(ctl_oracle_ror32(a,7)^ctl_oracle_ror32(a,18)^(a>>3))+w[i-7]+(ctl_oracle_ror32(z,17)^ctl_oracle_ror32(z,19)^(z>>10));
  }
  memcpy(v,h,sizeof(v));
  for(i=0;i<64;i++){
   __u32 t=v[7]+(ctl_oracle_ror32(v[4],6)^ctl_oracle_ror32(v[4],11)^ctl_oracle_ror32(v[4],25))+((v[4]&v[5])^(~v[4]&v[6]))+k[i]+w[i];
   __u32 u=(ctl_oracle_ror32(v[0],2)^ctl_oracle_ror32(v[0],13)^ctl_oracle_ror32(v[0],22))+((v[0]&v[1])^(v[0]&v[2])^(v[1]&v[2]));
   memmove(v+1,v,7*sizeof(*v));v[4]+=t;v[0]=t+u;
  }
  for(i=0;i<8;i++)h[i]+=v[i];
 }
 for(i=0;i<8;i++)ctl_oracle_store(out+4*i,h[i],4,true);
}
static inline int xdev_ext_mech_ctl_xform_expect(__u32 x,__u64 param,__u32 seg,
 const __u8 *src,__u32 len,__u8 *out,__u32 cap,__u32 *out_len)
{
 __u32 off,n,result=0;
 if(!src || !out || !out_len || !seg || x<1 || x>XDEV_EXT_CPU_XFORM_SHA256_APPEND ||
    (x!=XDEV_EXT_CPU_XFORM_PARSE_STRIP && x!=XDEV_EXT_CPU_XFORM_XXH64_APPEND && param) ||
    (x==XDEV_EXT_CPU_XFORM_PARSE_STRIP && (param<4 || param>256))) return -EINVAL;
 for(off=0;off<len;off+=n){
  __u32 size;const __u8 *in=src+off;
  n=len-off<seg?len-off:seg;size=n;
  if(x==XDEV_EXT_CPU_XFORM_PARSE_STRIP){
   if(n<param || ctl_oracle_load(in,4,false)!=n-param)return -EBADMSG;
   size-=param;in+=param;
  }else if(x==XDEV_EXT_CPU_XFORM_CRC32C_STRIP || x==XDEV_EXT_CPU_XFORM_CRC32C_CHECK){
   if(n<4 || ctl_oracle_load(in+n-4,4,false)!=ctl_oracle_crc(in,n-4))return -EBADMSG;
   if(x==XDEV_EXT_CPU_XFORM_CRC32C_STRIP)size-=4;
  }else if(x==XDEV_EXT_CPU_XFORM_CRC32C_SEAL){if(n<4)return -EBADMSG;
  }else{
   __u32 extra=x==XDEV_EXT_CPU_XFORM_CRC32C_APPEND?4:x==XDEV_EXT_CPU_XFORM_XXH64_APPEND?8:32;
   if(n>UINT32_MAX-extra)return -EMSGSIZE;
   size+=extra;
  }
  if(result>cap || size>cap-result)return -EMSGSIZE;
  memcpy(out+result,in,size<n?size:n);
  if(x==XDEV_EXT_CPU_XFORM_CRC32C_APPEND)ctl_oracle_store(out+result+n,ctl_oracle_crc(in,n),4,false);
  if(x==XDEV_EXT_CPU_XFORM_CRC32C_SEAL)ctl_oracle_store(out+result+n-4,ctl_oracle_crc(in,n-4),4,false);
  if(x==XDEV_EXT_CPU_XFORM_XXH64_APPEND)ctl_oracle_store(out+result+n,ctl_oracle_xxh(in,n,param),8,true);
  if(x==XDEV_EXT_CPU_XFORM_SHA256_APPEND)ctl_oracle_sha256(in,n,out+result+n);
  result+=size;
 }
 *out_len=result;return 0;
}


static inline void xdev_ext_mech_ctl_report_chain(char *line,size_t cap,bool pass,
 bool fanout,const char *xform,bool network)
{
 if(fanout)snprintf(line,cap,"XDEV_EXT_MECH_FANOUT=%s",pass?"PASS":"FAIL");
 else snprintf(line,cap,"XDEV_EXT_MECH_CPU_CHAIN=%s xform=%s sink=%s",
  pass?"PASS":"FAIL",xform,network?"afxdp":"nvme");
}
static inline void xdev_ext_mech_ctl_report_verify(char *line,size_t cap,bool pass,
 const char *xform,__u32 bytes,__u64 mismatches)
{
 snprintf(line,cap,"XDEV_EXT_MECH_VERIFY_XFORM=%s xform=%s bytes=%u mismatches=%llu",
  pass?"PASS":"FAIL",xform,bytes,(unsigned long long)mismatches);
}


/* Counter text follows the same marker ownership rule as the other reports. */
static inline void xdev_ext_mech_ctl_print_transport_counters(__u64 session,
 const struct xdev_ext_mech_transport_stats_v2 *counters)
{
 printf("XDEV_EXT_MECH_TRANSPORT_COUNTERS session=%llu retransmits=%llu dup_suppressed=%llu "
        "held_acks=%llu held_unacked=%u\n",(unsigned long long)session,
        (unsigned long long)counters->retransmits,(unsigned long long)counters->dup_suppressed,
        (unsigned long long)counters->held_acks,counters->held_unacked);
}

#endif /* XDEV_EXT_MECH_CTL_CORE_H */

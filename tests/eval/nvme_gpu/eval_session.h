/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_SESSION_H
#define XDEV_EVAL_SESSION_H

/*
 * Session control of the eval session arms (session_nvme_ce.c here,
 * ../gpu_nic/session_gpu_nic.c): one io_uring, one XDEV_EXT mechanism session,
 * one NOTIFY_ARM before START and one terminal eventfd wait, so the timed
 * region is the kernel-owned campaign alone.  The register calls follow
 * kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c (ctl_ring_open, ctl_create,
 * ctl_start, ctl_wait_coarse); marker decisions come from its
 * xdev_ext_mech_ctl_core.h.
 *
 * The copy-engine window is either the CPU stand-in /dev/xdev_ext_ce_sim
 * (correctness only, its window read and written through the device file) or
 * a real GPU allocation made once before CREATE with
 * kernel/tools/xdev_ext_mech/xdev_ext_mech_cuda.h.  Seeding and the oracle
 * readback of a GPU window use cuMemcpyHtoD/DtoH through the same driver
 * handle, before CREATE and after the session settled; never during the
 * campaign.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "../../../kernel/include/uapi/linux/io_uring.h"
#include "../../../kernel/tools/include/xdev_ext_gpu_identity.h"
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_cuda.h"
#include "nvme_gpu_core.h"

struct es_run {
	int ring;
	int efd;
	__u64 session;
};

static inline __u64 es_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static inline __u64 es_cpu_us(void)
{
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru))
		return 0;
	return xg_cpu_us(ru.ru_utime.tv_sec, ru.ru_utime.tv_usec,
			 ru.ru_stime.tv_sec, ru.ru_stime.tv_usec);
}

static inline int es_ring_open(struct es_run *r)
{
	struct io_uring_params p;

	memset(&p, 0, sizeof(p));
	r->session = 0;
	r->efd = -1;
	r->ring = (int)syscall(__NR_io_uring_setup, 8, &p);
	if (r->ring < 0)
		return -errno;
	r->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	return r->efd < 0 ? -errno : 0;
}

static inline int es_register(int ring, unsigned int opcode, void *arg)
{
	int ret = (int)syscall(__NR_io_uring_register, ring, opcode, arg, 1);

	return ret < 0 ? -errno : ret;
}

static inline int es_mech(int ring, __u32 op, __u64 arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };

	return es_register(ring, IORING_REGISTER_XDEV_EXT_MECH, &req);
}

static inline int es_stats(const struct es_run *r, struct xdev_ext_mech_stats *s)
{
	memset(s, 0, sizeof(*s));
	s->session_id = r->session;
	return es_mech(r->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)s);
}

/* CREATE, then arm the terminal notification for @batches. */
static inline int es_create(struct es_run *r, struct xdev_ext_mech_create *c,
			    __u64 batches)
{
	struct xdev_ext_mech_notify_arm arm;
	int ret;

	c->abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c->eventfd = r->efd;
	ret = es_mech(r->ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)c);
	if (ret)
		return ret;
	r->session = c->session_id;
	ret = xdev_ext_mech_ctl_notify_request(&arm, r->session, batches);
	return ret ? ret : es_mech(r->ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
}

/* START @batches from key 1; @user_frames (or NULL) recycled through a depth. */
static inline int es_start(const struct es_run *r, __u64 batches,
			   const __u32 *user_frames, __u32 nr_user_frames)
{
	struct xdev_ext_mech_start st = {
		.session_id = r->session,
		.nr_batches = batches,
		.first_seq = 1,
		.flags = user_frames ? XDEV_EXT_MECH_START_F_USER_FRAMES |
				      XDEV_EXT_MECH_START_F_RECYCLE : 0,
		.nr_user_frames = nr_user_frames,
		.user_frames = (uintptr_t)user_frames,
	};

	return es_mech(r->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st);
}

/* One terminal eventfd read, or -ETIMEDOUT at @deadline_ns. */
static inline int es_wait_terminal(const struct es_run *r, __u64 deadline_ns)
{
	for (;;) {
		struct pollfd pfd = { .fd = r->efd, .events = POLLIN };
		__u64 now = es_now_ns(), count, left_ms;
		ssize_t n;
		int ready;

		if (!now || now >= deadline_ns)
			return -ETIMEDOUT;
		left_ms = (deadline_ns - now) / 1000000 + 1;
		ready = poll(&pfd, 1, left_ms > INT_MAX ? INT_MAX : (int)left_ms);
		if (ready < 0 && errno == EINTR)
			continue;
		if (ready < 0)
			return -errno;
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			return -EIO;
		if (!(pfd.revents & POLLIN))
			continue;
		n = read(r->efd, &count, sizeof(count));
		if (n == sizeof(count))
			return 0;
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		return n < 0 ? -errno : -EIO;
	}
}

/*
 * After the terminal wake: STATS until nothing is in flight (a wake alone
 * does not certify a DMA drain), then the campaign verdict for @batches.
 */
static inline int es_settle(const struct es_run *r, __u64 batches,
			    __u64 deadline_ns, struct xdev_ext_mech_stats *s)
{
	int ret;

	for (;;) {
		ret = es_stats(r, s);
		if (ret)
			return ret;
		if (!s->inflight || es_now_ns() >= deadline_ns)
			break;
		usleep(1000);
	}
	return xdev_ext_mech_ctl_notify_result(s, batches);
}

/* STOP (when a session exists) and close the ring; 0 or the STOP error. */
static inline int es_close(struct es_run *r)
{
	int ret = 0;

	if (r->ring >= 0 && r->session) {
		ret = es_mech(r->ring, XDEV_EXT_MECH_OP_STOP, r->session);
		if (ret == -ENOENT)
			ret = 0;
	}
	if (r->ring >= 0)
		close(r->ring);
	if (r->efd >= 0)
		close(r->efd);
	r->ring = r->efd = -1;
	r->session = 0;
	return ret;
}

static inline void es_print_stats(const struct xdev_ext_mech_stats *s)
{
	char line[512];

	if (xdev_ext_mech_ctl_stats_line(line, sizeof(line), s) > 0)
		fprintf(stderr, "%s\n", line);
}

/* --- copy-engine window ------------------------------------------------ */

typedef int (*es_cu_copy_htod)(uint64_t dst, const void *src, size_t bytes);
typedef int (*es_cu_copy_dtoh)(void *dst, uint64_t src, size_t bytes);

struct es_ce {
	int fd[2];			/* one open per CE stage; fd[1] unused if one stage */
	bool sim;			/* /dev/xdev_ext_ce_sim: CPU stand-in */
	struct xdev_ext_mech_cuda cuda;
	es_cu_copy_htod htod;
	es_cu_copy_dtoh dtoh;
	__u64 va;			/* stage arg0: window base */
	__u64 len;			/* stage arg1: window length */
};

static inline bool es_ce_is_sim(const char *dev)
{
	const char *base = strrchr(dev, '/');

	return !strncmp(base ? base + 1 : dev, "xdev_ext_ce_sim", 15);
}

/*
 * Open @stages CE stage files on @dev.  A GPU device always gets a native
 * allocation of @len (@alloc required); the stand-in takes @va as an offset
 * into its window.  Exit-code style: 0, XG_EXIT_USAGE for a device/flag
 * mismatch, XG_EXIT_UNAVAILABLE when the device or driver is missing.
 */
static inline int es_ce_open(struct es_ce *ce, const char *dev, unsigned int stages,
			     bool alloc, __u64 va, __u64 len)
{
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE];
	unsigned int i;
	int ret;

	memset(ce, 0, sizeof(*ce));
	ce->fd[0] = ce->fd[1] = -1;
	ce->sim = es_ce_is_sim(dev);
	if (!len || stages < 1 || stages > 2)
		return XG_EXIT_USAGE;
	if (ce->sim == alloc) {
		fprintf(stderr, "%s\n", ce->sim ? "the CE stand-in takes --ce-va, not --ce-alloc" :
			"a GPU CE device requires --ce-alloc");
		return XG_EXIT_USAGE;
	}
	for (i = 0; i < stages; i++) {
		ce->fd[i] = open(dev, O_RDWR | O_CLOEXEC);
		if (ce->fd[i] < 0) {
			fprintf(stderr, "SKIP: CE device %s: %s\n", dev, strerror(errno));
			return XG_EXIT_UNAVAILABLE;
		}
	}
	ce->len = len;
	if (ce->sim) {
		ce->va = va;
		return XG_EXIT_PASS;
	}
	ret = xdev_ext_gpu_identity_from_opened(ce->fd[0], dev,
					 XDEV_EXT_GPU_IDENTITY_ANY_MINOR, bdf);
	if (ret) {
		fprintf(stderr, "SKIP: GPU identity of %s: %s\n", dev, strerror(-ret));
		return XG_EXIT_UNAVAILABLE;
	}
	ret = xdev_ext_mech_cuda_open(&ce->cuda, bdf, len);
	if (ret) {
		fprintf(stderr, "SKIP: CUDA allocation on %s: %s\n", bdf, strerror(-ret));
		return XG_EXIT_UNAVAILABLE;
	}
	ce->va = ce->cuda.va;
	*(void **)(&ce->htod) = dlsym(ce->cuda.lib, "cuMemcpyHtoD_v2");
	*(void **)(&ce->dtoh) = dlsym(ce->cuda.lib, "cuMemcpyDtoH_v2");
	if (!ce->htod || !ce->dtoh) {
		fprintf(stderr, "SKIP: CUDA driver lacks cuMemcpyHtoD_v2/DtoH_v2\n");
		return XG_EXIT_UNAVAILABLE;
	}
	return XG_EXIT_PASS;
}

/* Bytes [off, off + n) of the window, outside any timed region. */
static inline int es_ce_access(struct es_ce *ce, bool write, __u64 off, void *buf,
			       size_t n)
{
	void *previous = NULL;
	int ret, restore;

	if (off > ce->len || n > ce->len - off)
		return -ERANGE;
	if (ce->sim) {
		size_t done = 0;

		while (done < n) {
			ssize_t k = write ?
				pwrite(ce->fd[0], (char *)buf + done, n - done,
				       (off_t)(ce->va + off + done)) :
				pread(ce->fd[0], (char *)buf + done, n - done,
				      (off_t)(ce->va + off + done));

			if (k < 0 && errno == EINTR)
				continue;
			if (k <= 0)
				return k < 0 ? -errno : -EIO;
			done += (size_t)k;
		}
		return 0;
	}
	ret = xdev_ext_mech_cuda_result(ce->cuda.ctx_get(&previous), "cuCtxGetCurrent");
	if (ret)
		return ret;
	ret = xdev_ext_mech_cuda_result(ce->cuda.ctx_set(ce->cuda.ctx), "cuCtxSetCurrent");
	if (!ret)
		ret = write ? xdev_ext_mech_cuda_result(ce->htod(ce->va + off, buf, n),
						   "cuMemcpyHtoD_v2") :
			      xdev_ext_mech_cuda_result(ce->dtoh(buf, ce->va + off, n),
						   "cuMemcpyDtoH_v2");
	restore = xdev_ext_mech_cuda_result(ce->cuda.ctx_set(previous),
				       "cuCtxSetCurrent(restore)");
	return ret ? ret : restore;
}

/* Call after es_close(): the session no longer references the window. */
static inline int es_ce_close(struct es_ce *ce)
{
	int ret = 0;
	unsigned int i;

	for (i = 0; i < 2; i++)
		if (ce->fd[i] >= 0) {
			close(ce->fd[i]);
			ce->fd[i] = -1;
		}
	if (!ce->sim)
		ret = xdev_ext_mech_cuda_close(&ce->cuda);
	return ret;
}

#endif /* XDEV_EVAL_SESSION_H */

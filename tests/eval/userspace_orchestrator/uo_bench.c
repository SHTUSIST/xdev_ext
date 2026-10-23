// SPDX-License-Identifier: GPL-2.0
/*
 * uo_bench - the user-space shared-region baseline of reviewer E2.
 *
 *   uo_bench --spec FILE.json	run, print one JSON result line
 *   uo_bench --check FILE.json	parse and validate only
 *
 * One hugepage region is registered as the AF_XDP UMEM (XDP_UMEM_REG), as
 * io_uring fixed buffers (IORING_REGISTER_BUFFERS) and, in a UO_CUDA=1
 * build, with cuMemHostRegister.  The process sequences every stage itself:
 * NVMe I/O straight into the packet frames (vectored NVMe passthrough
 * uring_cmd, or READ_FIXED/WRITE_FIXED when the segment layout is LBA
 * aligned), optional GPU round trips over the same frames, and AF_XDP TX/RX
 * of NXP segments a session peer accepts.  --wait poll spins on the rings;
 * eventfd blocks on the ring's registered eventfd and the socket.  The
 * closed load drains each record before the next; the sustained load keeps
 * up to depth groups in flight for the whole campaign and times every
 * record's completion (../chains/chain_timing.h).
 *
 * Costs are counted outside the timed windows: every system call this
 * process issues during the campaign, and getrusage() context switches and
 * CPU time.  The NXP CRC32C is the wire protocol's (the session computes the
 * same one in its BPF plan), not a correctness oracle; it is the hardware
 * chain_crc32c_fast() of ../chains/chain_crc.h.  The receiver's oracle is
 * one full readback after the campaign.
 *
 * Exit: 0 pass, 1 run failed, 2 invalid spec, 4 not run.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "uo_core.h"
#include "../chains/chain_nxp.h"
#include "../chains/chain_check.h"
#include "../chains/chain_oracle.h"
#include "../chains/chain_timing.h"
#include "../chains/uring_min.h"
#include "../../../kernel/tools/include/xdev_ext_xsk_redirect.h"
#ifdef UO_CUDA
#include "../chains/chain_cuda.h"
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << 26)
#endif

#define UO_RING		2048U
#define UO_REGION	((size_t)CHAIN_XSK_FRAMES * UO_CHUNK)

enum { UO_PASS = 0, UO_FAIL = 1, UO_INVALID = 2, UO_NOT_RUN = 4 };
enum { SL_FREE, SL_NVME, SL_GPU, SL_READY, SL_TX, SL_RX };

struct uo_xring {
	__u32 *producer, *consumer;
	void *descs;
	__u32 mask;
	void *map;
	size_t len;
};

struct uo_slot {
	int state;
	uint64_t g;
	uint32_t segs_done, nvme_left, tx_left;
	uint64_t rx_chunk[UO_MAX_SEGS];		/* receiver: chunk of segment j */
	struct iovec iov[UO_MAX_SEGS];
	struct nvme_uring_cmd cmd;
};

struct uo {
	struct uo_spec s;
	struct uo_map m;
	struct chain_nxp nxp;
	struct xdev_ext_mp_rx_cfg cfg;
	uint8_t *region;
	int xsk, nvme, efd;
	uint32_t nsid, mtu;
	bool zero_copy;
	struct uo_xring fq, cq, rx, tx;
	struct ur ur;
	struct uo_slot *slot;
	struct xdev_ext_xsk_redirect redirect;
#ifdef UO_CUDA
	struct chain_cuda cuda;
#endif
	bool cuda_open;
	unsigned int inflight;
	/* accounting */
	uint64_t syscalls, wakeups, cpu_read_bytes, foreign;
	uint64_t *samples, nr_samples, windows_done, batches_done;
	struct chain_sustained sus;
	uint64_t *rec_ns;
	struct rusage ru0, ru1;
	int status;
	char failure[256];
	const char *oracle_verdict;
	uint64_t oracle_bytes;
};

static int uo_fail(struct uo *u, int status, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static int uo_fail(struct uo *u, int status, const char *fmt, ...)
{
	va_list ap;

	if (u->status)
		return u->status;
	u->status = status;
	va_start(ap, fmt);
	vsnprintf(u->failure, sizeof(u->failure), fmt, ap);
	va_end(ap);
	return status;
}

static uint64_t uo_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* --- AF_XDP over the shared region ------------------------------------------ */

static int uo_xring(int fd, const struct xdp_ring_offset *off, __u64 pgoff,
		    size_t esize, struct uo_xring *r)
{
	r->len = off->desc + UO_RING * esize;
	r->map = mmap(NULL, r->len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		      fd, (off_t)pgoff);
	if (r->map == MAP_FAILED) {
		r->map = NULL;
		return -errno;
	}
	r->producer = (__u32 *)((char *)r->map + off->producer);
	r->consumer = (__u32 *)((char *)r->map + off->consumer);
	r->descs = (char *)r->map + off->desc;
	r->mask = UO_RING - 1;
	return 0;
}

static int uo_xsk_open(struct uo *u)
{
	struct xdp_umem_reg reg = { .addr = (uintptr_t)u->region, .len = UO_REGION,
		.chunk_size = UO_CHUNK, .headroom = u->m.headroom };
	struct sockaddr_xdp sxdp = { .sxdp_family = AF_XDP };
	struct xdp_mmap_offsets off;
	struct xdp_options opt = { 0 };
	socklen_t len = sizeof(off);
	unsigned int ifindex = if_nametoindex(u->s.ifname);
	__u32 size = UO_RING;
	int ret;

	if (!ifindex)
		return -errno;
	u->xsk = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (u->xsk < 0)
		return -errno;
	if (setsockopt(u->xsk, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)) ||
	    setsockopt(u->xsk, SOL_XDP, XDP_UMEM_FILL_RING, &size, sizeof(size)) ||
	    setsockopt(u->xsk, SOL_XDP, XDP_UMEM_COMPLETION_RING, &size, sizeof(size)) ||
	    setsockopt(u->xsk, SOL_XDP, u->s.rx ? XDP_RX_RING : XDP_TX_RING, &size,
		       sizeof(size)) ||
	    getsockopt(u->xsk, SOL_XDP, XDP_MMAP_OFFSETS, &off, &len))
		return -errno;
	ret = uo_xring(u->xsk, &off.fr, XDP_UMEM_PGOFF_FILL_RING, sizeof(__u64), &u->fq);
	if (!ret)
		ret = uo_xring(u->xsk, &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING,
			       sizeof(__u64), &u->cq);
	if (!ret)
		ret = u->s.rx ? uo_xring(u->xsk, &off.rx, XDP_PGOFF_RX_RING,
					 sizeof(struct xdp_desc), &u->rx) :
				uo_xring(u->xsk, &off.tx, XDP_PGOFF_TX_RING,
					 sizeof(struct xdp_desc), &u->tx);
	if (ret)
		return ret;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = u->s.queue;
	sxdp.sxdp_flags = u->s.xsk_mode == CH_XSK_COPY ? XDP_COPY : XDP_ZEROCOPY;
	if (bind(u->xsk, (struct sockaddr *)&sxdp, sizeof(sxdp)))
		return -errno;
	len = sizeof(opt);
	if (getsockopt(u->xsk, SOL_XDP, XDP_OPTIONS, &opt, &len))
		return -errno;
	u->zero_copy = !!(opt.flags & XDP_OPTIONS_ZEROCOPY);
	return xdev_ext_mech_ctl_xsk_mode_check(u->s.xsk_mode == CH_XSK_COPY, opt.flags);
}

static void uo_fq_push(struct uo *u, uint64_t chunk)
{
	__u32 prod = *u->fq.producer;

	((__u64 *)u->fq.descs)[prod & u->fq.mask] = chunk;
	__atomic_store_n(u->fq.producer, prod + 1, __ATOMIC_RELEASE);
}

static void uo_kick(struct uo *u)
{
	u->syscalls++;
	sendto(u->xsk, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

/* --- stages ----------------------------------------------------------------- */

static int uo_nvme(struct uo *u, uint32_t k, bool write)
{
	struct uo_slot *sl = &u->slot[k];
	uint32_t nr = u->m.segs, j;

	/* A sender reads into its slot's chunks; a receiver's iov is set. */
	if (!u->s.rx)
		uo_iov(&u->m, u->region, k, sl->iov);
	if (u->s.nvme_io == UO_IO_PASSTHRU_VEC) {
		struct io_uring_sqe *sqe = ur_sqe(&u->ur);

		if (!sqe)
			return -EBUSY;
		uo_nvme_cmd(&u->s, u->nsid, write, sl->g, sl->iov, nr, &sl->cmd);
		sqe->opcode = IORING_OP_URING_CMD;
		sqe->fd = u->nvme;
		sqe->cmd_op = NVME_URING_CMD_IO_VEC;
		sqe->user_data = (uint64_t)k << 8 | 1;
		memcpy(sqe->cmd, &sl->cmd, sizeof(sl->cmd));
		sl->nvme_left = 1;
	} else {
		uint64_t base = (u->s.slba + sl->g * (u->s.group_bytes / u->s.lba_bytes)) *
				u->s.lba_bytes;
		uint64_t at = 0;

		if (ur_free_sqes(&u->ur) < nr)
			return -EBUSY;
		for (j = 0; j < nr; j++) {
			struct io_uring_sqe *sqe = ur_sqe(&u->ur);

			ur_prep_rw(sqe, write ? IORING_OP_WRITE_FIXED : IORING_OP_READ_FIXED,
				   u->nvme, sl->iov[j].iov_base, (uint32_t)sl->iov[j].iov_len,
				   base + at, (uint64_t)k << 8 | 1);
			sqe->buf_index = 0;
			at += sl->iov[j].iov_len;
		}
		sl->nvme_left = nr;
	}
	u->inflight += sl->nvme_left;
	sl->state = SL_NVME;
	return 0;
}

#ifdef UO_CUDA
/* H2D then D2H of every payload span on the slot's stream, in place. */
static int uo_gpu(struct uo *u, uint32_t k)
{
	struct uo_slot *sl = &u->slot[k];
	uint64_t dev = (uint64_t)k * u->s.group_bytes;
	uint32_t j;
	int ret = 0;

	for (j = 0; !ret && j < u->m.segs; j++)
		ret = chain_cuda_h2d(&u->cuda, k, dev + j * u->m.l.seg_len,
				     sl->iov[j].iov_base, sl->iov[j].iov_len);
	for (j = 0; !ret && j < u->m.segs; j++)
		ret = chain_cuda_d2h(&u->cuda, k, sl->iov[j].iov_base,
				     dev + j * u->m.l.seg_len, sl->iov[j].iov_len);
	if (!ret)
		sl->state = SL_GPU;
	return ret;
}

static int uo_gpu_poll(struct uo *u, bool *busy)
{
	uint32_t k;

	*busy = false;
	for (k = 0; k < u->s.depth; k++) {
		int q;

		if (u->slot[k].state != SL_GPU)
			continue;
		q = chain_cuda_query(&u->cuda, k);
		if (q < 0)
			return q;
		if (q)
			*busy = true;
		else
			u->slot[k].state = SL_READY;
	}
	return 0;
}
#else
static int uo_gpu(struct uo *u, uint32_t k)
{
	(void)u;
	(void)k;
	return -EOPNOTSUPP;
}

static int uo_gpu_poll(struct uo *u, bool *busy)
{
	(void)u;
	*busy = false;
	return 0;
}
#endif

/* Headers into each chunk's headroom, then every segment on the TX ring. */
static int uo_tx(struct uo *u, uint32_t k)
{
	struct uo_slot *sl = &u->slot[k];
	__u32 prod = *u->tx.producer;
	__u32 cons = __atomic_load_n(u->tx.consumer, __ATOMIC_ACQUIRE);
	uint32_t j, off, len;
	int ret;

	if (UO_RING - (prod - cons) < u->m.segs)
		return -EBUSY;
	for (j = 0; j < u->m.segs; j++) {
		uint64_t chunk = uo_chunk(&u->m, k, j);
		uint8_t *payload;
		struct xdp_desc *d = &((struct xdp_desc *)u->tx.descs)[(prod + j) & u->tx.mask];

		uo_span(&u->m, j, &off, &len);
		payload = u->region + chunk + off;
		ret = chain_nxp_build(&u->nxp, payload - XDEV_EXT_MP_PKT_HDR_LEN, sl->g, j,
				      payload);
		if (ret)
			return ret;
		u->cpu_read_bytes += len;
		xdev_ext_mp_tx_desc(d, chunk, off, len);
	}
	__atomic_store_n(u->tx.producer, prod + u->m.segs, __ATOMIC_RELEASE);
	sl->tx_left = u->m.segs;
	sl->state = SL_TX;
	uo_kick(u);
	return 0;
}

/* Completed TX chunks back to their slots; *@done counts finished groups. */
static int uo_tx_reap(struct uo *u, uint64_t *done)
{
	__u32 cons = *u->cq.consumer;
	__u32 prod = __atomic_load_n(u->cq.producer, __ATOMIC_ACQUIRE);

	for (; cons != prod; cons++) {
		uint64_t addr = ((__u64 *)u->cq.descs)[cons & u->cq.mask];
		uint32_t k = (uint32_t)(addr / UO_CHUNK / u->m.segs);

		if (k >= u->s.depth || u->slot[k].state != SL_TX || !u->slot[k].tx_left)
			return -EPROTO;
		if (!--u->slot[k].tx_left) {
			u->slot[k].state = SL_FREE;
			(*done)++;
		}
	}
	__atomic_store_n(u->cq.consumer, cons, __ATOMIC_RELEASE);
	return 0;
}

/*
 * Received packets: each must be the next segment of the group being
 * collected (the NXP receiver accepts segments strictly in order).
 * Foreign packets go straight back to the fill ring.
 */
static int uo_rx_reap(struct uo *u, uint64_t end, uint64_t *next)
{
	__u32 cons = *u->rx.consumer;
	__u32 prod = __atomic_load_n(u->rx.producer, __ATOMIC_ACQUIRE);
	int ret = 0;

	for (; cons != prod && *next < end && !ret; cons++) {
		const struct xdp_desc *d = &((struct xdp_desc *)u->rx.descs)[cons & u->rx.mask];
		uint64_t chunk = d->addr & ~(uint64_t)(UO_CHUNK - 1);
		uint32_t data_off = (uint32_t)(d->addr - chunk), k = *next % u->s.depth;
		struct uo_slot *sl = &u->slot[k];
		struct xdev_ext_mp_segment seg;
		uint8_t *pkt = u->region + d->addr;
		int cls;

		if (sl->state != SL_RX || sl->g != *next)
			break;		/* the slot is still writing its last group */
		cls = xdev_ext_mp_rx_parse(pkt, data_off, d->len, &u->s.peer, &u->cfg, &seg);
		if (cls == XDEV_EXT_MP_RX_FOREIGN) {
			u->foreign++;
			uo_fq_push(u, chunk);
			continue;
		}
		if (cls != XDEV_EXT_MP_RX_SEGMENT || seg.generation != sl->g + 1 ||
		    seg.index != sl->segs_done) {
			ret = -EPROTO;
			break;
		}
		ret = chain_nxp_check(&u->nxp, pkt + XDEV_EXT_MP_NXP_OFF, sl->g, seg.index,
				      u->region + chunk + seg.payload_off);
		u->cpu_read_bytes += seg.payload_len;
		if (ret)
			break;
		sl->rx_chunk[sl->segs_done] = chunk;
		sl->iov[sl->segs_done].iov_base = u->region + seg.payload_off + chunk;
		sl->iov[sl->segs_done].iov_len = seg.payload_len;
		if (++sl->segs_done == u->m.segs) {
			sl->state = SL_READY;
			if (u->s.gpu) {
				ret = uo_gpu(u, k);
				if (ret)
					break;
			}
			(*next)++;
			if (*next < end && u->slot[*next % u->s.depth].state == SL_FREE) {
				u->slot[*next % u->s.depth].state = SL_RX;
				u->slot[*next % u->s.depth].g = *next;
				u->slot[*next % u->s.depth].segs_done = 0;
			}
		}
	}
	__atomic_store_n(u->rx.consumer, cons, __ATOMIC_RELEASE);
	return ret;
}

/* Sleep until something may have completed (eventfd mode) or spin (poll). */
static int uo_block(struct uo *u, bool gpu_busy, uint64_t deadline)
{
	struct pollfd p[2] = { { .fd = u->efd, .events = POLLIN },
			       { .fd = u->xsk, .events = POLLIN } };
	uint64_t count;
	int n;

	/*
	 * AF_XDP has no wakeup for its completion ring, so a sender with only
	 * transmits outstanding spins on that ring even in eventfd mode; the
	 * 1 ms poll timeout is only a fallback for missed wakeups.
	 */
	if (u->s.wait == UO_WAIT_POLL || gpu_busy || (!u->s.rx && !u->inflight))
		return uo_now() > deadline ? -ETIMEDOUT : 0;
	n = poll(p, 2, 1);
	u->syscalls++;
	u->wakeups += n > 0;
	if (n < 0 && errno != EINTR)
		return -errno;
	if (n > 0 && (p[0].revents & POLLIN)) {
		u->syscalls++;
		if (read(u->efd, &count, sizeof(count)) < 0 && errno != EAGAIN)
			return -errno;
	}
	return uo_now() > deadline ? -ETIMEDOUT : 0;
}

static int uo_reap_ring(struct uo *u, uint64_t *done)
{
	struct io_uring_cqe *cqe;

	while ((cqe = ur_peek(&u->ur))) {
		uint32_t k = (uint32_t)(cqe->user_data >> 8);
		int res = cqe->res;
		struct uo_slot *sl;

		ur_seen(&u->ur);
		if (k >= u->s.depth)
			return -EPROTO;
		sl = &u->slot[k];
		u->inflight--;
		if (res < 0)
			return res;
		if (sl->state != SL_NVME || !sl->nvme_left)
			return -EPROTO;
		if (--sl->nvme_left)
			continue;
		if (u->s.rx) {
			uint32_t j;

			/* Written: the chunks go back to the fill ring. */
			for (j = 0; j < u->m.segs; j++)
				uo_fq_push(u, sl->rx_chunk[j]);
			sl->state = SL_FREE;
			(*done)++;
		} else if (u->s.gpu) {
			int ret = uo_gpu(u, k);

			if (ret)
				return ret;
		} else {
			sl->state = SL_READY;
		}
	}
	return 0;
}

/*
 * Groups [first, first + nb), up to depth in flight.  With @t (sustained
 * load) each record's completion is timed.  Gives up after timeout_ms
 * without a finished group.
 */
static int uo_window(struct uo *u, uint64_t first, uint64_t nb, struct chain_sustained *t)
{
	uint64_t end = first + nb, next = first, out = first, done = 0;
	uint64_t timeout = u->s.timeout_ms * 1000000ULL;
	uint64_t deadline = uo_now() + timeout;
	uint32_t depth = u->s.depth;

	if (u->s.rx && u->slot[first % depth].state == SL_FREE) {
		u->slot[first % depth] = (struct uo_slot){ .state = SL_RX, .g = first };
	}
	while (done < nb) {
		uint64_t was = done;
		bool busy;
		int ret;

		if (!u->s.rx) {
			while (next < end && u->slot[next % depth].state == SL_FREE) {
				u->slot[next % depth].g = next;
				ret = uo_nvme(u, next % depth, false);
				if (ret == -EBUSY)
					break;
				if (ret)
					return ret;
				next++;
			}
		} else {
			ret = uo_rx_reap(u, end, &next);
			if (ret)
				return ret;
			if (next < end && u->slot[next % depth].state == SL_FREE) {
				u->slot[next % depth].state = SL_RX;
				u->slot[next % depth].g = next;
				u->slot[next % depth].segs_done = 0;
			}
		}
		ret = uo_gpu_poll(u, &busy);
		if (ret)
			return ret;
		/* Ready groups leave in order: on the wire, or to NVMe. */
		while (out < next && u->slot[out % depth].state == SL_READY &&
		       u->slot[out % depth].g == out) {
			ret = u->s.rx ? uo_nvme(u, out % depth, true) : uo_tx(u, out % depth);
			if (ret == -EBUSY)
				break;
			if (ret)
				return ret;
			out++;
		}
		ret = ur_enter(&u->ur, 0);
		if (ret >= 0)
			ret = ur_taskrun(&u->ur);
		if (ret < 0)
			return ret;
		ret = uo_reap_ring(u, &done);
		if (!ret && !u->s.rx)
			ret = uo_tx_reap(u, &done);
		if (ret)
			return ret;
		if (done != was) {
			uint64_t now = uo_now();

			deadline = now + timeout;
			if (t)
				chain_sustained_note(t, first + done, now);
		}
		if (done < nb) {
			ret = uo_block(u, busy, deadline);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/* --- output ------------------------------------------------------------------ */

static uint64_t tv_us(const struct timeval *tv)
{
	return (uint64_t)tv->tv_sec * 1000000ULL + (uint64_t)tv->tv_usec;
}

static void uo_emit(FILE *f, const struct uo *u, bool have_cuda)
{
	const struct uo_spec *s = &u->s;
	uint64_t k;
	int first = 1;

	fprintf(f, "{\"schema\":\"xdev-uo-result-v1\",\"status\":\"%s\",\"chain\":",
		u->status == UO_PASS ? "pass" : u->status == UO_FAIL ? "fail" :
		u->status == UO_INVALID ? "invalid" : "not_run");
	cj_write_str(f, s->chain);
	fprintf(f, ",\"arm\":\"userspace-shared\",\"mode\":\"%s\",\"wait\":\"%s\","
		"\"nvme_io\":\"%s\",\"afxdp_mode\":\"%s\",\"group_bytes\":%u,"
		"\"batches\":%llu,\"warmup\":%llu,\"burst\":%u,\"depth\":%u,"
		"\"segments\":%u,\"seg_len\":%u,\"cuda_build\":%s,\"load\":\"%s\","
		"\"wire_crc\":\"%s\",",
		s->mode == CH_TIMING ? "timing" : "correctness",
		s->wait == UO_WAIT_POLL ? "poll" : "eventfd",
		s->nvme_io == UO_IO_PASSTHRU_VEC ? "passthru-vec" : "read-fixed",
		s->xsk_mode == CH_XSK_ZC ? "zc" : "copy", s->group_bytes,
		(unsigned long long)s->batches, (unsigned long long)s->warmup, s->burst,
		s->depth, u->m.segs, u->m.l.seg_len, have_cuda ? "true" : "false",
		s->load == CH_LOAD_SUSTAINED ? "sustained" : "closed", chain_crc32c_impl());
	fprintf(f, "\"windows_done\":%llu,\"batches_done\":%llu,",
		(unsigned long long)u->windows_done, (unsigned long long)u->batches_done);
	if (s->mode == CH_TIMING && !u->status && s->load == CH_LOAD_SUSTAINED) {
		uint64_t t0 = chain_sustained_t0(&u->sus);

		fprintf(f, "\"timing\":{\"load\":\"sustained\",\"clock\":\"CLOCK_MONOTONIC_RAW\","
			"\"unit\":\"ns\",\"observer\":\"in-process\",\"record_bytes\":%llu,"
			"\"records\":%llu,\"warmup_records\":%llu,\"t0_ns\":%llu,"
			"\"completions\":[", (unsigned long long)s->burst * s->group_bytes,
			(unsigned long long)(u->sus.records - u->sus.warm),
			(unsigned long long)u->sus.warm, (unsigned long long)t0);
		for (k = u->sus.warm; k < u->sus.next; k++)
			fprintf(f, "%s%llu", k > u->sus.warm ? "," : "",
				(unsigned long long)(u->sus.done_ns[k] - t0));
		fputs("]},", f);
	} else if (s->mode == CH_TIMING && !u->status) {
		fprintf(f, "\"timing\":{\"load\":\"closed\",\"clock\":\"CLOCK_MONOTONIC_RAW\","
			"\"unit\":\"ns\",\"window_batches\":%u,\"window_bytes\":%llu,\"samples\":[",
			s->burst, (unsigned long long)s->burst * s->group_bytes);
		for (k = 0; k < u->nr_samples; k++)
			fprintf(f, "%s%llu", k ? "," : "", (unsigned long long)u->samples[k]);
		fputs("]},", f);
	}
	fputs("\"copies\":{\"sources\":[", f);
	if (u->xsk >= 0 && !u->zero_copy) {
		fputs("\"afxdp-copy-mode\"", f);
		first = 0;
	}
	/* Only a completed run can claim it saw no CPU payload copy. */
	fprintf(f, "],\"zero_cpu_payload_copies\":%s,\"xsk_zero_copy\":%s,"
		"\"cpu_read_bytes\":%llu,\"foreign_packets\":%llu},",
		u->status ? "null" : first ? "true" : "false",
		u->xsk < 0 ? "null" : u->zero_copy ? "true" : "false",
		(unsigned long long)u->cpu_read_bytes, (unsigned long long)u->foreign);
	fprintf(f, "\"cost\":{\"syscalls\":%llu,\"wakeups\":%llu,\"voluntary_ctxsw\":%ld,"
		"\"involuntary_ctxsw\":%ld,\"user_us\":%llu,\"sys_us\":%llu},",
		(unsigned long long)u->syscalls, (unsigned long long)u->wakeups,
		u->ru1.ru_nvcsw - u->ru0.ru_nvcsw, u->ru1.ru_nivcsw - u->ru0.ru_nivcsw,
		(unsigned long long)(tv_us(&u->ru1.ru_utime) - tv_us(&u->ru0.ru_utime)),
		(unsigned long long)(tv_us(&u->ru1.ru_stime) - tv_us(&u->ru0.ru_stime)));
	fprintf(f, "\"oracle\":{\"kind\":\"%s\",\"verdict\":\"%s\",\"bytes\":%llu},",
		s->oracle == CH_ORACLE_FILE ? "file" : "none",
		u->oracle_verdict ? u->oracle_verdict : "not-checked",
		(unsigned long long)u->oracle_bytes);
	fputs("\"failure\":", f);
	cj_write_str(f, u->failure);
	fputs("}\n", f);
}

/* After the campaign: one O_DIRECT readback of the destination window. */
static void uo_oracle(struct uo *u)
{
	int ref = open(u->s.reference, O_RDONLY | O_CLOEXEC);
	int fd = open(u->s.oracle_path, O_RDONLY | O_CLOEXEC | O_DIRECT);
	size_t chunk = 1U << 20;
	uint8_t *a = NULL, *b = malloc(chunk);
	struct stat sb;
	uint64_t done = 0;

	if (fd < 0 && errno == EINVAL)
		fd = open(u->s.oracle_path, O_RDONLY | O_CLOEXEC);
	if (ref < 0 || fd < 0 || fstat(ref, &sb) || !b || posix_memalign((void **)&a, 4096, chunk)) {
		uo_fail(u, UO_FAIL, "oracle open: %s", strerror(errno));
		goto out;
	}
	while (done < (uint64_t)sb.st_size) {
		size_t want = (uint64_t)sb.st_size - done < chunk ?
			      (size_t)(sb.st_size - done) : chunk;
		ssize_t n = pread(fd, a, (want + 4095) & ~(size_t)4095,
				  (off_t)(u->s.oracle_offset + done));
		long long diff;

		if (n < (ssize_t)want || pread(ref, b, want, (off_t)done) != (ssize_t)want) {
			uo_fail(u, UO_FAIL, "oracle short read at %llu", (unsigned long long)done);
			goto out;
		}
		diff = chain_first_diff(a, b, want);
		if (diff >= 0) {
			uo_fail(u, UO_FAIL, "oracle: first differing byte at %llu",
				(unsigned long long)(done + (uint64_t)diff));
			goto out;
		}
		done += want;
	}
	u->oracle_bytes = done;
out:
	u->oracle_verdict = u->status ? "fail" : "pass";
	if (ref >= 0)
		close(ref);
	if (fd >= 0)
		close(fd);
	free(a);
	free(b);
}

static char *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *buf = NULL;
	long n;

	if (!f)
		return NULL;
	if (!fseek(f, 0, SEEK_END) && (n = ftell(f)) > 0 && n < (1 << 20) &&
	    !fseek(f, 0, SEEK_SET) && (buf = malloc((size_t)n + 1)) &&
	    fread(buf, 1, (size_t)n, f) == (size_t)n) {
		buf[n] = '\0';
		*len = (size_t)n;
	} else {
		free(buf);
		buf = NULL;
	}
	fclose(f);
	return buf;
}

static int uo_run(struct uo *u)
{
	const struct uo_spec *s = &u->s;
	struct chain_err e = { { 0 } };
	struct iovec reg;
	struct ifreq ifr = { 0 };
	uint64_t windows = s->batches / s->burst, warm = s->warmup / s->burst, w, first = 0;
	int fd, ret;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", s->ifname);
	ret = fd < 0 || ioctl(fd, SIOCGIFMTU, &ifr) ? -errno : 0;
	if (fd >= 0)
		close(fd);
	if (ret)
		return uo_fail(u, UO_NOT_RUN, "MTU of %s: %s", s->ifname, strerror(-ret));
	u->mtu = (uint32_t)ifr.ifr_mtu;
	if (uo_map(s, u->mtu, &u->m, &e))
		return uo_fail(u, strncmp(e.msg, "unsupported:", 12) ? UO_INVALID : UO_NOT_RUN,
			       "%s", e.msg);
	u->nxp = (struct chain_nxp){ .peer = &u->s.peer, .session = s->nxp_session,
		.group_bytes = s->group_bytes, .seg_len = u->m.l.seg_len, .nr_segs = u->m.segs };
	u->cfg = (struct xdev_ext_mp_rx_cfg){ .session_id = s->nxp_session, .mtu = u->mtu,
		.frame_size = u->m.l.frame_size, .hdr_room = u->m.l.hdr_room,
		.seg_len = u->m.l.seg_len, .group_bytes = s->group_bytes };
	u->slot = calloc(s->depth, sizeof(*u->slot));
	if (s->load == CH_LOAD_SUSTAINED)
		u->rec_ns = malloc((warm + windows) * sizeof(*u->rec_ns));
	else if (s->mode == CH_TIMING)
		u->samples = calloc(windows, sizeof(*u->samples));
	if (!u->slot || (s->load == CH_LOAD_SUSTAINED ? !u->rec_ns :
			 s->mode == CH_TIMING && !u->samples))
		return uo_fail(u, UO_NOT_RUN, "allocation failed");
	if (u->rec_ns)
		chain_sustained_init(&u->sus, warm + windows, warm, s->burst, u->rec_ns);
	chain_crc32c_init();		/* CRC tables built outside the campaign */
	u->region = mmap(NULL, UO_REGION, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE |
			 (s->hugepage ? MAP_HUGETLB | MAP_HUGE_2MB : 0), -1, 0);
	if (u->region == MAP_FAILED) {
		u->region = NULL;
		return uo_fail(u, UO_NOT_RUN, "region of %zu bytes%s: %s", UO_REGION,
			       s->hugepage ? " in 2 MiB hugepages (vm.nr_hugepages)" : "",
			       strerror(errno));
	}
	ret = uo_xsk_open(u);
	if (ret)
		return uo_fail(u, UO_NOT_RUN, "AF_XDP %s on %s: %s",
			       s->xsk_mode == CH_XSK_COPY ? "copy" : "zero-copy", s->ifname,
			       strerror(-ret));
	ret = ur_setup(&u->ur, 1024, true, s->wait == UO_WAIT_POLL);
	if (ret)
		return uo_fail(u, UO_NOT_RUN, "io_uring SQE128: %s", strerror(-ret));
	reg = (struct iovec){ u->region, UO_REGION };
	ret = ur_register(&u->ur, IORING_REGISTER_BUFFERS, &reg, 1);
	if (ret)
		return uo_fail(u, UO_NOT_RUN, "IORING_REGISTER_BUFFERS: %s", strerror(-ret));
	if (s->wait == UO_WAIT_EVENTFD) {
		u->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		ret = u->efd < 0 ? -errno :
		      ur_register(&u->ur, IORING_REGISTER_EVENTFD, &u->efd, 1);
		if (ret)
			return uo_fail(u, UO_NOT_RUN, "IORING_REGISTER_EVENTFD: %s",
				       strerror(-ret));
	}
	if (s->nvme_io == UO_IO_PASSTHRU_VEC) {
		u->nvme = open(s->ng, (s->rx ? O_RDWR : O_RDONLY) | O_CLOEXEC);
		ret = u->nvme < 0 ? -errno : ioctl(u->nvme, NVME_IOCTL_ID);
		if (ret <= 0)
			return uo_fail(u, UO_NOT_RUN, "NVMe generic device %s: %s", s->ng,
				       strerror(ret < 0 ? errno : ENODEV));
		u->nsid = (uint32_t)ret;
	} else {
		u->nvme = open(s->block, (s->rx ? O_RDWR : O_RDONLY) | O_DIRECT | O_CLOEXEC);
		if (u->nvme < 0)
			return uo_fail(u, UO_NOT_RUN, "NVMe block device %s: %s", s->block,
				       strerror(errno));
	}
#ifdef UO_CUDA
	if (s->gpu) {
		ret = chain_cuda_open(&u->cuda, s->gpu_bdf, (size_t)s->depth * s->group_bytes,
				      s->depth);
		if (!ret)
			ret = chain_cuda_register(&u->cuda, u->region, UO_REGION);
		if (ret)
			return uo_fail(u, UO_NOT_RUN, "CUDA on %s: %s", s->gpu_bdf,
				       strerror(-ret));
		u->cuda_open = true;
	}
#endif
	if (s->rx) {
		const struct xdev_ext_xsk_flow_filter filter = {
			.flags = XDEV_EXT_XSK_FILTER_F_ALL,
			.src_ipv4 = ntohl(s->peer.peer_ip), .dst_ipv4 = ntohl(s->peer.local_ip),
			.payload_magic = XDEV_EXT_MP_NXP_MAGIC,
			.src_port = ntohs(s->peer.peer_port), .dst_port = ntohs(s->peer.local_port),
		};
		uint32_t i;

		/* Receive chunks: the half of the region the slots never claim. */
		for (i = 0; i < CHAIN_XSK_FRAMES / 2; i++)
			uo_fq_push(u, (uint64_t)(CHAIN_XSK_FRAMES / 2 + i) * UO_CHUNK);
		ret = xdev_ext_xsk_redirect_attach(&u->redirect, &filter,
			(int)if_nametoindex(s->ifname), s->queue, u->xsk,
			s->xsk_mode == CH_XSK_COPY ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE);
		if (ret)
			return uo_fail(u, UO_NOT_RUN, "XDP redirect on %s: %s", s->ifname,
				       strerror(-ret));
	}
	fprintf(stderr, "CHAIN_READY chain=%s arm=userspace-shared segments=%u seg_len=%u "
		"xsk=%s\n", s->chain, u->m.segs, u->m.l.seg_len, u->zero_copy ? "zc" : "copy");
	fflush(stderr);
	u->syscalls = 0;
	u->ur.syscalls = 0;
	getrusage(RUSAGE_SELF, &u->ru0);
	if (s->load == CH_LOAD_SUSTAINED) {
		u->sus.t_begin = uo_now();
		ret = uo_window(u, 0, s->warmup + s->batches, &u->sus);
		getrusage(RUSAGE_SELF, &u->ru1);
		u->syscalls += u->ur.syscalls;
		u->batches_done = u->sus.next * s->burst;
		if (ret)
			return uo_fail(u, UO_FAIL, "sustained run after %llu of %llu records: %s",
				       (unsigned long long)u->sus.next,
				       (unsigned long long)u->sus.records, strerror(-ret));
		u->windows_done = 1;
		return 0;
	}
	for (w = 0; w < warm + windows; w++) {
		uint64_t t0 = uo_now(), t1;

		ret = uo_window(u, first, s->burst, NULL);
		t1 = uo_now();
		if (ret) {
			getrusage(RUSAGE_SELF, &u->ru1);
			return uo_fail(u, UO_FAIL, "window %llu: %s", (unsigned long long)w,
				       strerror(-ret));
		}
		if (w >= warm && u->samples)
			u->samples[u->nr_samples++] = t1 - t0;
		first += s->burst;
		u->windows_done++;
		u->batches_done = first;
	}
	getrusage(RUSAGE_SELF, &u->ru1);
	u->syscalls += u->ur.syscalls;
	return 0;
}

int main(int argc, char **argv)
{
#ifdef UO_CUDA
	const bool have_cuda = true;
#else
	const bool have_cuda = false;
#endif
	static struct uo u;
	struct chain_err e = { { 0 } };
	char why[128];
	bool check;
	size_t len = 0;
	char *text;

	if (argc != 3 || (strcmp(argv[1], "--spec") && strcmp(argv[1], "--check"))) {
		fprintf(stderr, "usage: %s --spec|--check FILE.json\n", argv[0]);
		return UO_INVALID;
	}
	check = !strcmp(argv[1], "--check");
	text = slurp(argv[2], &len);
	if (!text) {
		fprintf(stderr, "uo_bench: cannot read %s\n", argv[2]);
		return UO_INVALID;
	}
	u.xsk = u.nvme = u.efd = -1;
	u.ur.fd = -1;
	u.redirect = (struct xdev_ext_xsk_redirect)XDEV_EXT_XSK_REDIRECT_INIT;
	if (uo_parse(text, len, &u.s, &e) || uo_validate(&u.s, have_cuda, &e)) {
		int status = strncmp(e.msg, "unsupported:", 12) ? UO_INVALID : UO_NOT_RUN;

		free(text);
		uo_print_refusal(stdout, status == UO_INVALID, e.msg);
		fprintf(stderr, "uo_bench: %s\n", e.msg);
		return status;
	}
	free(text);
	if (check) {
		printf("{\"status\":\"ok\",\"chain\":\"%s\",\"rx\":%s,\"gpu\":%s,\"cuda_build\":%s}\n",
		       u.s.chain, u.s.rx ? "true" : "false", u.s.gpu ? "true" : "false",
		       have_cuda ? "true" : "false");
		return UO_PASS;
	}
	/* hardware_gate.py admits timed runs; this catches a direct start. */
	if (u.s.mode == CH_TIMING && chain_env_virtual("", why, sizeof(why)))
		uo_fail(&u, UO_NOT_RUN, "unsupported: timing refused: %s", why);
	else
		uo_run(&u);
	/* Teardown before the oracle: nothing may still own the region. */
	if (xdev_ext_xsk_redirect_is_active(&u.redirect))
		xdev_ext_xsk_redirect_detach(&u.redirect);
	if (u.ur.fd >= 0)
		ur_close(&u.ur);
#ifdef UO_CUDA
	if (u.cuda_open && chain_cuda_close(&u.cuda) && !u.status)
		uo_fail(&u, UO_FAIL, "CUDA cleanup failed");
#endif
	if (u.xsk >= 0)
		close(u.xsk);
	if (u.nvme >= 0)
		close(u.nvme);
	if (u.efd >= 0)
		close(u.efd);
	if (!u.status && u.s.oracle == CH_ORACLE_FILE)
		uo_oracle(&u);
	uo_emit(stdout, &u, have_cuda);
	if (u.s.out[0]) {
		FILE *f = fopen(u.s.out, "wx");

		if (f) {
			uo_emit(f, &u, have_cuda);
			fclose(f);
		} else if (!u.status) {
			u.status = UO_FAIL;
		}
	}
	if (u.failure[0])
		fprintf(stderr, "uo_bench: %s\n", u.failure);
	free(u.samples);
	free(u.rec_ns);
	free(u.slot);
	return u.status;
}

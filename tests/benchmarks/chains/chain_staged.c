// SPDX-License-Identifier: GPL-2.0
/*
 * Staged arm of chain_bench: the strongest per-pair Linux composition this
 * repository builds, with every buffer allocated and registered once.
 *
 *   NVMe		io_uring READ_FIXED / WRITE_FIXED, O_DIRECT block device,
 *			fixed buffers registered once (IORING_REGISTER_BUFFERS)
 *   GPU		CUDA: page-locked once (cuMemHostRegister), async H2D/D2H
 *			on one stream per slot; or, correctness only, the CE
 *			simulator's read()/write() window (CPU copies, counted)
 *   NIC TX		UDP socket, io_uring SENDMSG_ZC of [NXP header, payload]
 *   NIC RX		UDP socket, io_uring RECVMSG straight into the slot
 *			(the kernel's skb-to-user copy is counted)
 *   IAA (decompress)	none on hardware; correctness only, CPU zlib raw inflate
 *
 * Datagrams carry the NXP header of kernel/tools/xdev_ext_mech/
 * xdev_ext_mech_prog.h with the receiving session's segment size, so a
 * staged sender interoperates with a session receiver and the reverse.
 * Up to depth groups are in flight (reads, GPU copies and NVMe writes
 * overlap); a group's datagrams go out only after the previous group's,
 * because the NXP receiver accepts segments strictly in order.  The closed
 * load drains every record before the next; the sustained load runs the
 * whole campaign as one window and times each record's completion.  The
 * NXP CRC32C is chain_crc32c_fast() (chain_crc.h), the hardware CRC of
 * the session's kernel crc32c().
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <zlib.h>

#include "chain_bench.h"
#include "chain_cuda.h"
#include "chain_nxp.h"
#include "chain_oracle.h"
#include "uring_min.h"

#define SG_NXP		XDEV_EXT_MP_NXP_LEN
#define SG_MAX_SEGS	XDEV_EXT_MECH_MAX_FRAMES
#define SG_PRISTINE	0xa6

enum { OP_READ = 1, OP_WRITE, OP_SEND, OP_RECV };
enum { SL_FREE, SL_IO, SL_GPU, SL_READY, SL_SEND, SL_RECV };

struct sg_slot {
	int state;
	uint64_t g;
	unsigned int segs_done, sends_left, notifs_left;
	struct msghdr msg[SG_MAX_SEGS];
	struct iovec iov[SG_MAX_SEGS][3];
};

struct sg {
	const struct chain_spec *s;
	struct chain_result *r;
	struct ur ur;
	struct sg_slot *slot;
	uint8_t *a, *b, *hdr;		/* read/receive, GPU return, NXP headers */
	size_t stride, a_len, b_len;
	int nvme, sock, ce;
	uint32_t lba, seg_len, nr_segs;
	struct chain_nxp nxp;
	uint64_t nvme_base;		/* byte offset of the NVMe window */
	bool gpu, iaa, rx;
	uint32_t iaa_out;
	struct chain_cuda cuda;
	bool cuda_open, b_registered;
	bool recv_busy;			/* the one outstanding RECVMSG */
	unsigned int inflight;		/* ring operations without a final CQE */
	unsigned int notifs;		/* zero-copy notifications still due */
	uint8_t spill;			/* a datagram longer than expected lands here */
};

static uint64_t sg_ud(int op, unsigned int slot, unsigned int seg)
{
	return (uint64_t)op << 48 | (uint64_t)slot << 16 | seg;
}

/* --- GPU leg -------------------------------------------------------------- */

/* Source of the GPU copy and the buffer the result lands in, per slot. */
static uint8_t *sg_gpu_src(struct sg *x, unsigned int k)
{
	return (x->iaa ? x->b : x->a) + (size_t)k * x->stride;
}

static int sg_gpu_start(struct sg *x, unsigned int k)
{
	uint8_t *src = sg_gpu_src(x, k);
	size_t len = x->iaa ? x->iaa_out : x->s->group_bytes;
	uint64_t dev = (uint64_t)k * x->s->group_bytes;
	int ret;

	if (x->s->gpu == CH_GPU_CUDA) {
		ret = chain_cuda_h2d(&x->cuda, k, dev, src, len);
		if (!ret && !x->iaa)
			ret = chain_cuda_d2h(&x->cuda, k, x->b + (size_t)k * x->stride,
					     dev, len);
		if (!ret)
			x->slot[k].state = SL_GPU;
		return ret;
	}
	/* CE simulator: two synchronous CPU copies through its window. */
	if (pwrite(x->ce, src, len, (off_t)(x->s->ce_va + dev)) != (ssize_t)len)
		return -EIO;
	x->r->cpu_copies++;
	x->r->cpu_copy_bytes += len;
	if (!x->iaa) {
		if (pread(x->ce, x->b + (size_t)k * x->stride, len,
			  (off_t)(x->s->ce_va + dev)) != (ssize_t)len)
			return -EIO;
		x->r->cpu_copies++;
		x->r->cpu_copy_bytes += len;
	}
	x->slot[k].state = SL_READY;
	return 0;
}

/* Slots whose CUDA stream finished become READY. */
static int sg_gpu_poll(struct sg *x, bool *busy)
{
	unsigned int k;

	*busy = false;
	if (x->s->gpu != CH_GPU_CUDA)
		return 0;
	for (k = 0; k < x->s->depth; k++) {
		int q;

		if (x->slot[k].state != SL_GPU)
			continue;
		q = chain_cuda_query(&x->cuda, k);
		if (q < 0)
			return q;
		if (q)
			*busy = true;
		else
			x->slot[k].state = SL_READY;
	}
	return 0;
}

/* --- NXP datagrams -------------------------------------------------------- */

static void sg_seg(const struct sg *x, unsigned int j, uint32_t *off, uint32_t *len)
{
	chain_nxp_seg(&x->nxp, j, off, len);
}

/* The 40 NXP bytes of segment @j of group @g, CRC over @payload. */
static int sg_header(struct sg *x, uint8_t *nxp, uint64_t g, unsigned int j,
		     const uint8_t *payload)
{
	uint8_t pkt[XDEV_EXT_MP_PKT_HDR_LEN];
	uint32_t off, len;
	int ret;

	sg_seg(x, j, &off, &len);
	ret = chain_nxp_build(&x->nxp, pkt, g, j, payload);
	if (ret)
		return ret;
	memcpy(nxp, pkt + XDEV_EXT_MP_NXP_OFF, SG_NXP);
	x->r->cpu_read_bytes += len;
	return 0;
}

/* A received segment is exactly the one expected next. */
static int sg_header_ok(struct sg *x, const uint8_t *nxp, uint64_t g, unsigned int j,
			const uint8_t *payload)
{
	uint32_t off, len;

	sg_seg(x, j, &off, &len);
	x->r->cpu_read_bytes += len;
	return chain_nxp_check(&x->nxp, nxp, g, j, payload);
}

/* --- ring operations ------------------------------------------------------ */

static int sg_nvme(struct sg *x, unsigned int k, uint64_t g, bool write)
{
	struct io_uring_sqe *sqe = ur_sqe(&x->ur);
	uint8_t *buf = (write && x->gpu ? x->b : x->a) + (size_t)k * x->stride;

	if (!sqe)
		return -EBUSY;
	ur_prep_rw(sqe, write ? IORING_OP_WRITE_FIXED : IORING_OP_READ_FIXED, x->nvme,
		   buf, x->s->group_bytes, x->nvme_base + g * x->s->group_bytes,
		   sg_ud(write ? OP_WRITE : OP_READ, k, 0));
	sqe->buf_index = write && x->gpu ? 1 : 0;
	x->slot[k].state = SL_IO;
	x->slot[k].g = g;
	x->inflight++;
	return 0;
}

/* Every segment of slot @k's group, linked so they leave in order. */
static int sg_send(struct sg *x, unsigned int k)
{
	struct sg_slot *sl = &x->slot[k];
	uint8_t *payload = (x->gpu ? x->b : x->a) + (size_t)k * x->stride;
	unsigned int j;
	int ret;

	if (ur_free_sqes(&x->ur) < x->nr_segs)
		return -EBUSY;
	for (j = 0; j < x->nr_segs; j++) {
		uint8_t *h = x->hdr + ((size_t)k * SG_MAX_SEGS + j) * SG_NXP;
		struct io_uring_sqe *sqe = ur_sqe(&x->ur);
		uint32_t off, len;

		sg_seg(x, j, &off, &len);
		ret = sg_header(x, h, sl->g, j, payload + off);
		if (ret)
			return ret;
		sl->iov[j][0] = (struct iovec){ h, SG_NXP };
		sl->iov[j][1] = (struct iovec){ payload + off, len };
		sl->msg[j] = (struct msghdr){ .msg_iov = sl->iov[j], .msg_iovlen = 2 };
		ur_prep_rw(sqe, IORING_OP_SENDMSG_ZC, x->sock, &sl->msg[j], 1, 0,
			   sg_ud(OP_SEND, k, j));
		if (j + 1 < x->nr_segs)
			sqe->flags |= IOSQE_IO_LINK;
		x->inflight++;
		x->r->socket_bytes += len;
	}
	sl->state = SL_SEND;
	sl->sends_left = x->nr_segs;
	sl->notifs_left = 0;
	return 0;
}

static int sg_recv(struct sg *x, unsigned int k)
{
	struct sg_slot *sl = &x->slot[k];
	unsigned int j = sl->segs_done;
	struct io_uring_sqe *sqe = ur_sqe(&x->ur);
	uint32_t off, len;

	if (!sqe)
		return -EBUSY;
	sg_seg(x, j, &off, &len);
	sl->iov[0][0] = (struct iovec){ x->hdr + (size_t)k * SG_MAX_SEGS * SG_NXP, SG_NXP };
	sl->iov[0][1] = (struct iovec){ x->a + (size_t)k * x->stride + off, len };
	sl->iov[0][2] = (struct iovec){ &x->spill, 1 };
	sl->msg[0] = (struct msghdr){ .msg_iov = sl->iov[0], .msg_iovlen = 3 };
	ur_prep_rw(sqe, IORING_OP_RECVMSG, x->sock, &sl->msg[0], 1, 0,
		   sg_ud(OP_RECV, k, j));
	sl->state = SL_RECV;
	x->recv_busy = true;
	x->inflight++;
	return 0;
}

/* Decompress slot @k (CPU zlib raw inflate, correctness arm only). */
static int sg_inflate(struct sg *x, unsigned int k)
{
	z_stream z = { 0 };
	int ret;

	if (inflateInit2(&z, -15) != Z_OK)
		return -ENOMEM;
	z.next_in = x->a + (size_t)k * x->stride;
	z.avail_in = x->s->group_bytes;
	z.next_out = x->b + (size_t)k * x->stride;
	z.avail_out = x->iaa_out;
	ret = inflate(&z, Z_FINISH);
	inflateEnd(&z);
	if (ret != Z_STREAM_END || z.total_out != x->iaa_out)
		return -EBADMSG;
	x->r->cpu_copies++;
	x->r->cpu_copy_bytes += x->iaa_out;
	return 0;
}

/* --- the campaign ------------------------------------------------------- */

/* One completion; *@done counts groups that finished. */
static int sg_complete(struct sg *x, struct io_uring_cqe *cqe, uint64_t *done,
		       uint64_t *sending)
{
	int op = (int)(cqe->user_data >> 48), res = cqe->res;
	unsigned int k = (unsigned int)(cqe->user_data >> 16) & 0xffff;
	struct sg_slot *sl = &x->slot[k];
	uint32_t off, len;
	int ret;

	if (op == OP_SEND && (cqe->flags & IORING_CQE_F_NOTIF)) {
		if (!sl->notifs_left || !x->notifs)
			return -EPROTO;
		x->notifs--;
		if (!--sl->notifs_left && !sl->sends_left) {
			sl->state = SL_FREE;
			(*done)++;
		}
		return 0;
	}
	x->inflight--;
	switch (op) {
	case OP_READ:
		if (res != (int)x->s->group_bytes)
			return res < 0 ? res : -EIO;
		if (x->iaa) {
			ret = sg_inflate(x, k);
			if (!ret)
				ret = sg_gpu_start(x, k);
			return ret;
		}
		if (x->gpu)
			return sg_gpu_start(x, k);
		sl->state = SL_READY;
		return 0;
	case OP_WRITE:
		if (res != (int)x->s->group_bytes)
			return res < 0 ? res : -EIO;
		sl->state = SL_FREE;
		(*done)++;
		return 0;
	case OP_SEND:
		sg_seg(x, (unsigned int)(cqe->user_data & 0xffff), &off, &len);
		if (res != (int)(SG_NXP + len))
			return res < 0 ? res : -EIO;
		if (cqe->flags & IORING_CQE_F_MORE) {
			sl->notifs_left++;
			x->notifs++;
		}
		if (!--sl->sends_left) {
			(*sending) = UINT64_MAX;
			if (!sl->notifs_left) {
				sl->state = SL_FREE;
				(*done)++;
			}
		}
		return 0;
	case OP_RECV:
		x->recv_busy = false;
		sg_seg(x, sl->segs_done, &off, &len);
		/* A longer datagram would reach the spill byte. */
		if (res != (int)(SG_NXP + len))
			return res < 0 ? res : -EPROTO;
		x->r->cpu_copies++;
		x->r->cpu_copy_bytes += len;
		x->r->socket_bytes += len;
		ret = sg_header_ok(x, x->hdr + (size_t)k * SG_MAX_SEGS * SG_NXP, sl->g,
				   sl->segs_done, x->a + (size_t)k * x->stride + off);
		if (ret)
			return ret;
		if (++sl->segs_done < x->nr_segs)
			return sg_recv(x, k);
		if (x->gpu)
			return sg_gpu_start(x, k);
		sl->state = SL_READY;
		return 0;
	}
	return -EPROTO;
}

/*
 * Groups [first, first + nb): reads/receives, GPU, sends/writes, done.
 * With @t (sustained load) each record's completion is timed.  Gives up
 * after timeout_ms without a finished group.
 */
static int sg_window(struct sg *x, uint64_t first, uint64_t nb, struct chain_sustained *t)
{
	uint64_t next = first, done = 0, next_out = first, sending = UINT64_MAX;
	unsigned int depth = x->s->depth;
	uint64_t timeout = x->s->timeout_ms * 1000000ULL;
	uint64_t deadline = cb_now_ns() + timeout;

	while (done < nb) {
		struct io_uring_cqe *cqe;
		uint64_t was = done;
		bool busy;
		int ret;

		/* Admit new groups into free slots, in order. */
		while (next < first + nb && x->slot[next % depth].state == SL_FREE &&
		       !(x->rx && x->recv_busy)) {
			unsigned int k = next % depth;

			x->slot[k].g = next;
			x->slot[k].segs_done = 0;
			ret = x->rx ? sg_recv(x, k) : sg_nvme(x, k, next, false);
			if (ret == -EBUSY)
				break;
			if (ret)
				return ret;
			/* One receive at a time keeps datagrams in order. */
			next++;
		}
		ret = sg_gpu_poll(x, &busy);
		if (ret)
			return ret;
		/* Ready groups leave in order: datagrams or the NVMe write. */
		while (next_out < next && x->slot[next_out % depth].state == SL_READY &&
		       x->slot[next_out % depth].g == next_out) {
			unsigned int k = next_out % depth;

			if (x->rx) {
				ret = sg_nvme(x, k, next_out, true);
			} else if (x->iaa) {
				x->slot[k].state = SL_FREE;
				done++;
				ret = 0;
			} else {
				if (sending != UINT64_MAX)
					break;
				ret = sg_send(x, k);
				if (!ret)
					sending = next_out;
			}
			if (ret == -EBUSY)
				break;
			if (ret)
				return ret;
			next_out++;
		}
		{
			uint64_t now = cb_now_ns();

			if (now > deadline)
				return -ETIMEDOUT;
			ret = ur_enter_timeout(&x->ur, (x->inflight || x->notifs) && !busy,
					       deadline - now);
			/* Spinning on a GPU stream: still let ring completions in. */
			if (ret >= 0 && busy)
				ret = ur_taskrun(&x->ur);
		}
		if (ret < 0 && ret != -ETIME)
			return ret;
		while ((cqe = ur_peek(&x->ur))) {
			ret = sg_complete(x, cqe, &done, &sending);
			ur_seen(&x->ur);
			if (ret)
				return ret;
		}
		if (done != was) {
			uint64_t now = cb_now_ns();

			deadline = now + timeout;
			if (t)
				chain_sustained_note(t, first + done, now);
		}
	}
	return 0;
}

static int sg_udp(struct sg *x)
{
	struct sockaddr_in local = { .sin_family = AF_INET,
		.sin_port = x->s->peer.local_port, .sin_addr.s_addr = x->s->peer.local_ip };
	struct sockaddr_in peer = { .sin_family = AF_INET,
		.sin_port = x->s->peer.peer_port, .sin_addr.s_addr = x->s->peer.peer_ip };
	int big = 64 << 20;

	x->sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (x->sock < 0)
		return -errno;
	/* Best effort: the receiver must buffer while its slots are busy. */
	setsockopt(x->sock, SOL_SOCKET, x->rx ? SO_RCVBUFFORCE : SO_SNDBUFFORCE,
		   &big, sizeof(big));
	if (bind(x->sock, (struct sockaddr *)&local, sizeof(local)) ||
	    connect(x->sock, (struct sockaddr *)&peer, sizeof(peer)))
		return -errno;
	return 0;
}

/*
 * The GPU window after @end groups.  Slot k holds group g with g % depth ==
 * k and a slot is reused only after its group finished, so the last
 * min(depth, end) groups are all there.
 */
static int sg_oracle_gpu(struct sg *x, const uint8_t *ref, size_t ref_len,
			 uint64_t end)
{
	const struct chain_spec *s = x->s;
	size_t bytes = (size_t)s->depth * s->group_bytes;
	uint8_t *window = malloc(bytes);
	uint64_t found = 0, want[CHAIN_MAX_DEPTH];
	unsigned int nr = end < s->depth ? (unsigned int)end : s->depth, i;
	long long bad;
	int ret = 0;

	for (i = 0; i < nr; i++)
		want[i] = end - nr + i;
	if (!window)
		return -ENOMEM;
	if (s->gpu == CH_GPU_CUDA) {
		ret = chain_cuda_ok(x->cuda.d2h_sync(window, x->cuda.dbuf, bytes),
				    "cuMemcpyDtoH_v2");
	} else if (pread(x->ce, window, bytes, (off_t)s->ce_va) != (ssize_t)bytes) {
		ret = -EIO;
	}
	if (!ret) {
		bad = chain_check_window(window, s->depth, s->group_bytes, x->iaa_out,
					 ref, ref_len / x->iaa_out, SG_PRISTINE,
					 want, nr, &found);
		x->r->oracle_bytes = found * x->iaa_out;
		x->r->oracle_detail = bad;
		ret = bad ? -EBADMSG : 0;
	}
	free(window);
	return ret;
}

int chain_run_staged(const struct chain_spec *s, struct chain_result *r)
{
	struct sg x = { .s = s, .r = r, .nvme = -1, .sock = -1, .ce = -1,
			.ur = { .fd = -1 } };
	struct xdev_ext_mech_layout l;
	struct iovec bufs[2];
	uint64_t windows = chain_windows(s), wb = chain_window_batches(s);
	uint64_t warm = s->warmup ? (s->start_per == CH_START_RUN ? 1 :
				     s->warmup / s->burst) : 0;
	uint64_t first = 0, w;
	uint8_t *ref = NULL;
	size_t ref_len = 0;
	unsigned int i, nv = 0;
	int ret;

	x.rx = chain_rx_first(s);
	x.gpu = chain_has(s, CH_CE);
	x.iaa = chain_has(s, CH_IAA);
	r->ce_backend = !x.gpu ? "none" : s->gpu == CH_GPU_CUDA ? "staged-cuda" :
			"staged-ce-sim-cpu-standin";
	for (i = 0; i < s->nr_stages; i++) {
		if (s->st[i].cls == CH_NVME)
			nv = i;
		if (s->st[i].cls == CH_IAA)
			x.iaa_out = s->st[i].expect ? s->st[i].expect : s->st[i].capacity;
		if (s->st[i].cls == CH_AFXDP) {
			struct ifreq q = { 0 };
			int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

			snprintf(q.ifr_name, sizeof(q.ifr_name), "%s", s->st[i].ifname);
			ret = fd < 0 || ioctl(fd, SIOCGIFMTU, &q) ? -errno : 0;
			if (fd >= 0)
				close(fd);
			if (!ret)
				ret = xdev_ext_mech_ctl_layout((__u32)q.ifr_mtu, s->group_bytes, &l);
			if (ret)
				return cb_fail(r, CB_NOT_RUN, "NXP layout on %s: %s",
					       s->st[i].ifname, strerror(-ret));
			x.seg_len = l.seg_len;
			x.nr_segs = (s->group_bytes + l.seg_len - 1) / l.seg_len;
			x.nxp = (struct chain_nxp){ .peer = &s->peer,
				.session = s->nxp_session, .group_bytes = s->group_bytes,
				.seg_len = x.seg_len, .nr_segs = x.nr_segs };
		}
	}
	if (s->load == CH_LOAD_SUSTAINED) {
		r->rec_ns = malloc(chain_records(s) * sizeof(*r->rec_ns));
		if (!r->rec_ns)
			return cb_fail(r, CB_NOT_RUN, "record array: %s", strerror(ENOMEM));
		chain_sustained_init(&r->sus, chain_records(s), s->warmup / s->burst,
				     s->burst, r->rec_ns);
		r->observer = "in-process";
	} else if (s->mode == CH_TIMING) {
		r->samples = calloc(windows, sizeof(*r->samples));
		if (!r->samples)
			return cb_fail(r, CB_NOT_RUN, "sample array: %s", strerror(ENOMEM));
	}
	if (s->oracle == CH_ORACLE_CE) {
		ref = chain_read_reference(s, &ref_len, r);
		if (!ref)
			return r->status;
	}
	x.stride = ((size_t)s->group_bytes + 4095) & ~(size_t)4095;
	x.a_len = x.b_len = x.stride * s->depth;
	x.a = aligned_alloc(4096, x.a_len);
	x.b = aligned_alloc(4096, x.b_len);
	x.hdr = calloc((size_t)s->depth * SG_MAX_SEGS, SG_NXP);
	x.slot = calloc(s->depth, sizeof(*x.slot));
	if (!x.a || !x.b || !x.hdr || !x.slot) {
		cb_fail(r, CB_NOT_RUN, "buffers: %s", strerror(ENOMEM));
		goto out;
	}
	memset(x.a, 0, x.a_len);
	memset(x.b, 0, x.b_len);
	x.nvme = open(s->st[nv].block, (x.rx ? O_RDWR : O_RDONLY) | O_DIRECT | O_CLOEXEC);
	if (x.nvme < 0 || ioctl(x.nvme, BLKSSZGET, &x.lba) || !x.lba) {
		cb_fail(r, CB_NOT_RUN, "NVMe block device %s: %s", s->st[nv].block,
			strerror(errno));
		goto out;
	}
	if (chain_nvme_window_ok(&s->st[nv], x.lba, s->group_bytes,
				 s->warmup + s->batches)) {
		cb_fail(r, CB_INVALID, "NVMe window too small or group not LBA-aligned");
		goto out;
	}
	x.nvme_base = s->st[nv].slba * x.lba;
	ret = ur_setup(&x.ur, 4096, false, true);
	if (ret) {
		cb_fail(r, CB_NOT_RUN, "io_uring: %s", strerror(-ret));
		goto out;
	}
	bufs[0] = (struct iovec){ x.a, x.a_len };
	bufs[1] = (struct iovec){ x.b, x.b_len };
	ret = ur_register(&x.ur, IORING_REGISTER_BUFFERS, bufs, 2);
	if (ret) {
		cb_fail(r, CB_NOT_RUN, "IORING_REGISTER_BUFFERS: %s", strerror(-ret));
		goto out;
	}
	if (x.nr_segs) {
		if (x.nr_segs > SG_MAX_SEGS) {
			cb_fail(r, CB_INVALID, "group needs more than %u datagrams", SG_MAX_SEGS);
			goto out;
		}
		ret = sg_udp(&x);
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "UDP socket: %s", strerror(-ret));
			goto out;
		}
	}
	if (x.gpu && s->gpu == CH_GPU_CUDA) {
		ret = chain_cuda_open(&x.cuda, s->ce_bdf, (size_t)s->depth * s->group_bytes,
				      s->depth);
		if (!ret)
			ret = chain_cuda_register(&x.cuda, x.a, x.a_len);
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "CUDA on %s: %s", s->ce_bdf, strerror(-ret));
			goto out;
		}
		x.cuda_open = true;
		/* chain_cuda tracks one region; the return buffer is ours to undo. */
		ret = chain_cuda_ok(x.cuda.host_register(x.b, x.b_len,
				    CHAIN_CUDA_HOSTREGISTER_PORTABLE), "cuMemHostRegister_v2");
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "CUDA register: %s", strerror(-ret));
			goto out;
		}
		x.b_registered = true;
	} else if (x.gpu) {
		x.ce = open(s->ce_dev, O_RDWR | O_CLOEXEC);
		if (x.ce < 0) {
			cb_fail(r, CB_NOT_RUN, "%s: %s", s->ce_dev, strerror(errno));
			goto out;
		}
		cb_copy_source(r, "ce-sim-cpu-standin");
	}
	if (s->oracle == CH_ORACLE_CE) {
		size_t bytes = (size_t)s->depth * s->group_bytes;
		uint8_t *fill = malloc(bytes);

		ret = fill ? 0 : -ENOMEM;
		if (fill) {
			memset(fill, SG_PRISTINE, bytes);
			if (s->gpu == CH_GPU_CUDA)
				ret = chain_cuda_ok(x.cuda.h2d_sync(x.cuda.dbuf, fill, bytes),
						    "cuMemcpyHtoD_v2");
			else if (pwrite(x.ce, fill, bytes, (off_t)s->ce_va) != (ssize_t)bytes)
				ret = -EIO;
			free(fill);
		}
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "GPU window pristine fill: %s", strerror(-ret));
			goto out;
		}
	}
	if (x.rx)
		cb_copy_source(r, "socket-receive-copy");
	if (x.iaa)
		cb_copy_source(r, "staged-cpu-zlib");
	if (x.nr_segs) {
		chain_crc32c_init();		/* tables built outside the campaign */
		r->wire_crc = chain_crc32c_impl();
	}
	fprintf(stderr, "CHAIN_READY chain=%s arm=staged segments=%u seg_len=%u\n",
		s->chain, x.nr_segs, x.seg_len);
	fflush(stderr);
	/* Costs count the campaign only. */
	x.ur.syscalls = 0;
	getrusage(RUSAGE_SELF, &r->ru_before);
	if (s->load == CH_LOAD_SUSTAINED) {
		r->sus.t_begin = cb_now_ns();
		ret = sg_window(&x, 0, s->warmup + s->batches, &r->sus);
		r->batches_done = r->sus.next * s->burst;
		if (ret) {
			cb_fail(r, CB_FAIL, "sustained run after %llu of %llu records: %s",
				(unsigned long long)r->sus.next,
				(unsigned long long)r->sus.records, strerror(-ret));
			goto out;
		}
		first = s->warmup + s->batches;
		r->windows_done = 1;
		warm = windows = 0;		/* skip the closed-load loop */
	}
	for (w = 0; w < warm + windows; w++) {
		uint64_t nb = w < warm ? (s->start_per == CH_START_RUN ? s->warmup :
					  s->burst) : wb;
		uint64_t t0 = cb_now_ns(), t1;

		ret = sg_window(&x, first, nb, NULL);
		t1 = cb_now_ns();
		if (ret) {
			cb_fail(r, CB_FAIL, "window %llu: %s", (unsigned long long)w,
				strerror(-ret));
			goto out;
		}
		if (w >= warm && r->samples)
			r->samples[r->nr_samples++] = t1 - t0;
		first += nb;
		r->windows_done++;
		r->batches_done = first;
		if (s->oracle == CH_ORACLE_CE && s->every_window &&
		    sg_oracle_gpu(&x, ref, ref_len, first)) {
			r->oracle_verdict = "fail";
			cb_fail(r, CB_FAIL, "GPU window after window %llu: detail %lld",
				(unsigned long long)w, r->oracle_detail);
			goto out;
		}
	}
	getrusage(RUSAGE_SELF, &r->ru_after);
	r->syscalls = x.ur.syscalls;
	if (s->oracle == CH_ORACLE_CE) {
		ret = sg_oracle_gpu(&x, ref, ref_len, first);
		r->oracle_verdict = ret ? "fail" : "pass";
		if (ret)
			cb_fail(r, CB_FAIL, "final GPU window: detail %lld", r->oracle_detail);
	}
out:
	if (x.cuda_open) {
		if (x.b_registered && x.cuda.host_unregister(x.b) && !r->status)
			cb_fail(r, CB_FAIL, "cuMemHostUnregister failed");
		if (chain_cuda_close(&x.cuda) && !r->status)
			cb_fail(r, CB_FAIL, "CUDA cleanup failed");
	}
	if (x.ur.fd >= 0)
		ur_close(&x.ur);
	if (x.sock >= 0)
		close(x.sock);
	if (x.ce >= 0)
		close(x.ce);
	if (x.nvme >= 0)
		close(x.nvme);
	free(x.a);
	free(x.b);
	free(x.hdr);
	free(x.slot);
	free(ref);
	if (!r->status && s->oracle == CH_ORACLE_FILE)
		chain_oracle_file(s, r);
	return r->status;
}

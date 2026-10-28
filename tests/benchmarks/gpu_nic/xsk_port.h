/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_XSK_PORT_H
#define XDEV_EVAL_XSK_PORT_H

/*
 * One AF_XDP socket with its own aligned UMEM, for session_gpu_nic.c (whose
 * session takes the socket's UMEM as its pool) and afxdp_cuda.cu (which
 * registers the same kind of UMEM with cudaHostRegister).  Ported from
 * ctl_xsk_open(), ctl_xring_map(), ctl_fq_push() and ctl_xsk_close() of
 * kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c (product tree, main 8e0238a):
 * same ring size, the same explicit copy/zero-copy request without a silent
 * downgrade, and the same mode check from xdev_ext_mech_ctl_core.h.  C and C++.
 */
#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_xdp.h>

#include "gpu_nic_core.h"

#ifndef AF_XDP
#define AF_XDP			44
#endif
#ifndef SOL_XDP
#define SOL_XDP			283
#endif

#define XP_RING_SIZE		2048U

struct xp_ring {
	uint32_t *producer, *consumer;
	void *descs;
	uint32_t mask;
	void *map;
	size_t map_len;
};

struct xp_sock {
	int fd;
	bool zero_copy;
	unsigned char *umem;
	size_t umem_size;
	uint32_t frame_size, nr_frames;
	struct xp_ring fq, cq, rx, tx;
};

static inline int xp_ring_map(int fd, const struct xdp_ring_offset *off, uint64_t pgoff,
			      size_t esize, struct xp_ring *r)
{
	r->map_len = off->desc + XP_RING_SIZE * esize;
	r->map = mmap(NULL, r->map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		      fd, (off_t)pgoff);
	if (r->map == MAP_FAILED) {
		r->map = NULL;
		return -errno;
	}
	r->producer = (uint32_t *)((char *)r->map + off->producer);
	r->consumer = (uint32_t *)((char *)r->map + off->consumer);
	r->descs = (char *)r->map + off->desc;
	r->mask = XP_RING_SIZE - 1;
	return 0;
}

static inline int xp_setsockopt_u32(int fd, int opt, uint32_t v)
{
	return setsockopt(fd, SOL_XDP, opt, &v, sizeof(v)) ? -errno : 0;
}

static inline void xp_close(struct xp_sock *x)
{
	struct xp_ring *rings[4] = { &x->fq, &x->cq, &x->rx, &x->tx };
	unsigned int i;

	for (i = 0; i < 4; i++)
		if (rings[i]->map)
			munmap(rings[i]->map, rings[i]->map_len);
	if (x->fd >= 0)
		close(x->fd);
	if (x->umem)
		munmap(x->umem, x->umem_size);
	memset(x, 0, sizeof(*x));
	x->fd = -1;
}

/*
 * Socket on @ifname/@queue with @nr_frames 4 KiB chunks of UMEM, @headroom
 * bytes of UMEM headroom, and the RX and/or TX ring.  @copy_mode selects
 * XDP_COPY, otherwise XDP_ZEROCOPY is required.
 */
static inline int xp_open(struct xp_sock *x, const char *ifname, uint32_t queue,
			  uint32_t nr_frames, uint32_t headroom, bool rx, bool tx,
			  bool copy_mode)
{
	struct sockaddr_xdp sxdp;
	struct xdp_umem_reg reg;
	struct xdp_mmap_offsets off;
	struct xdp_options options;
	socklen_t optlen = sizeof(off);
	unsigned int ifindex = if_nametoindex(ifname);
	int ret;

	memset(x, 0, sizeof(*x));
	x->fd = -1;
	if (!ifindex)
		return -ENODEV;
	x->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (x->fd < 0)
		return -errno;
	x->frame_size = XDEV_EXT_MECH_CTL_FRAME_SIZE;
	x->nr_frames = nr_frames;
	x->umem_size = (size_t)nr_frames * x->frame_size;
	x->umem = (unsigned char *)mmap(NULL, x->umem_size, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (x->umem == MAP_FAILED) {
		x->umem = NULL;
		return -errno;
	}
	memset(&reg, 0, sizeof(reg));
	reg.addr = (uintptr_t)x->umem;
	reg.len = x->umem_size;
	reg.chunk_size = x->frame_size;
	reg.headroom = headroom;
	if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)))
		return -errno;
	ret = xp_setsockopt_u32(x->fd, XDP_UMEM_FILL_RING, XP_RING_SIZE);
	if (!ret)
		ret = xp_setsockopt_u32(x->fd, XDP_UMEM_COMPLETION_RING, XP_RING_SIZE);
	if (!ret && rx)
		ret = xp_setsockopt_u32(x->fd, XDP_RX_RING, XP_RING_SIZE);
	if (!ret && tx)
		ret = xp_setsockopt_u32(x->fd, XDP_TX_RING, XP_RING_SIZE);
	if (ret)
		return ret;
	if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen))
		return -errno;
	ret = xp_ring_map(x->fd, &off.fr, XDP_UMEM_PGOFF_FILL_RING, sizeof(uint64_t), &x->fq);
	if (!ret)
		ret = xp_ring_map(x->fd, &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING,
				  sizeof(uint64_t), &x->cq);
	if (!ret && rx)
		ret = xp_ring_map(x->fd, &off.rx, XDP_PGOFF_RX_RING, sizeof(struct xdp_desc), &x->rx);
	if (!ret && tx)
		ret = xp_ring_map(x->fd, &off.tx, XDP_PGOFF_TX_RING, sizeof(struct xdp_desc), &x->tx);
	if (ret)
		return ret;
	memset(&sxdp, 0, sizeof(sxdp));
	sxdp.sxdp_family = AF_XDP;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;
	sxdp.sxdp_flags = xdev_ext_mech_ctl_xsk_flags(copy_mode);
	if (bind(x->fd, (struct sockaddr *)&sxdp, sizeof(sxdp)))
		return -errno;
	memset(&options, 0, sizeof(options));
	optlen = sizeof(options);
	if (getsockopt(x->fd, SOL_XDP, XDP_OPTIONS, &options, &optlen))
		return -errno;
	x->zero_copy = !!(options.flags & XDP_OPTIONS_ZEROCOPY);
	return xdev_ext_mech_ctl_xsk_mode_check(copy_mode, options.flags);
}

/* Put chunk addresses on the fill ring; how many fit. */
static inline uint32_t xp_fq_push(struct xp_ring *fq, const uint64_t *addr, uint32_t n)
{
	uint32_t prod = *fq->producer;
	uint32_t cons = __atomic_load_n(fq->consumer, __ATOMIC_ACQUIRE);
	uint32_t room = fq->mask + 1 - (prod - cons), i;

	if (n > room)
		n = room;
	for (i = 0; i < n; i++)
		((uint64_t *)fq->descs)[(prod + i) & fq->mask] = addr[i];
	__atomic_store_n(fq->producer, prod + n, __ATOMIC_RELEASE);
	return n;
}

/* Chunks [first, first + n) onto the fill ring; 0 or -ENOSPC. */
static inline int xp_fq_fill(struct xp_sock *x, uint32_t first, uint32_t n)
{
	uint64_t addr[64];
	uint32_t done = 0;

	while (done < n) {
		uint32_t k = n - done < 64 ? n - done : 64, i;

		for (i = 0; i < k; i++)
			addr[i] = (uint64_t)(first + done + i) * x->frame_size;
		if (xp_fq_push(&x->fq, addr, k) != k)
			return -ENOSPC;
		done += k;
	}
	return 0;
}

#endif /* XDEV_EVAL_XSK_PORT_H */

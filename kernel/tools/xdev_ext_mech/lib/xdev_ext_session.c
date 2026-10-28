// SPDX-License-Identifier: GPL-2.0
/*
 * libxdev_ext session steps: SPEC.md sections 3, 5 and 7.  The pure
 * decisions (NXP layout, notify request and result, exact XSK mode) are
 * those of xdev_ext_mech_ctl, included from xdev_ext_mech_ctl_core.h.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_xdp.h>

#include "../../../include/uapi/linux/io_uring.h"
#include "../xdev_ext_mech_ctl_core.h"
#include "libxdev_ext.h"
#include "libxdev_ext_internal.h"

#ifndef AF_XDP
#define AF_XDP		44
#endif
#ifndef SOL_XDP
#define SOL_XDP		283
#endif

#define XRING_SIZE	2048U
#define IOU_MTU		1500U

/* --- system calls, replaceable by the host tests ----------------------- */

static const struct xdev_ext_sys *sys_hook;

void xdev_ext__set_sys(const struct xdev_ext_sys *sys)
{
	sys_hook = sys;
}

static int sys_uring_setup(unsigned int entries, struct io_uring_params *p)
{
	int fd;

	if (sys_hook && sys_hook->io_uring_setup)
		return sys_hook->io_uring_setup(entries, p);
	fd = (int)syscall(__NR_io_uring_setup, entries, p);
	return fd < 0 ? -errno : fd;
}

static int sys_uring_register(int fd, unsigned int opcode, void *arg)
{
	int ret;

	if (sys_hook && sys_hook->io_uring_register)
		return sys_hook->io_uring_register(fd, opcode, arg, 1);
	ret = (int)syscall(__NR_io_uring_register, fd, opcode, arg, 1);
	return ret < 0 ? -errno : ret;
}

int xdev_ext__uring_register(int fd, unsigned int opcode, void *arg)
{
	return sys_uring_register(fd, opcode, arg);
}

int xdev_ext__ioctl(int fd, unsigned long request, unsigned long arg)
{
	int ret;

	if (sys_hook && sys_hook->ioctl)
		return sys_hook->ioctl(fd, request, arg);
	ret = ioctl(fd, request, arg);
	return ret < 0 ? -errno : ret;
}

static void sys_usleep(unsigned int usec)
{
	if (sys_hook && sys_hook->usleep)
		sys_hook->usleep(usec);
	else
		usleep(usec);
}

/* --- the handle ------------------------------------------------------- */

struct xring {
	__u32 *producer, *consumer;
	void *descs, *map;
	size_t map_len;
	__u32 mask;
};

struct xdev_ext_session {
	int ring, efd, xsk;
	int allocation_fd;
	__u32 pool_kind, xsk_mode, nr_frames, depth, frames_per_batch;
	bool zero_copy, created, started, released, retained;
	void *umem;			/* XSK UMEM or IOU UMEM */
	size_t umem_size;
	struct xring fq, cq, tx;
	char ifname[IF_NAMESIZE];
	__u64 id, nr_batches, armed_batches;
	int owned_fd[XDEV_EXT_MECH_MAX_STAGES];
	__u32 nr_owned_fds;
	struct xdev_ext_prog *prog[XDEV_EXT_MAX_PROGS];
	__u32 nr_progs;
	int (*prog_detach)(struct xdev_ext_prog *p);
};

/* sz contract: version 1 is the smallest layout; a larger tail must be 0. */
int xdev_ext__opts_check(const void *o, size_t sz, size_t known)
{
	size_t i;

	if (sz < known)
		return -EINVAL;
	for (i = known; i < sz; i++)
		if (((const unsigned char *)o)[i])
			return -EOPNOTSUPP;
	return 0;
}

static int mech(struct xdev_ext_session *s, __u32 op, __u64 arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };

	return sys_uring_register(s->ring, IORING_REGISTER_XDEV_EXT_MECH, &req);
}

static int if_query(const char *ifname, unsigned long req, struct ifreq *ifr)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	int ret;

	if (fd < 0)
		return -errno;
	memset(ifr, 0, sizeof(*ifr));
	snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", ifname);
	ret = ioctl(fd, req, ifr) ? -errno : 0;
	close(fd);
	return ret;
}

/* --- AF_XDP pool -------------------------------------------------------- */

static int xring_map(int fd, const struct xdp_ring_offset *off, __u64 pgoff,
		     size_t esize, struct xring *r)
{
	r->map_len = off->desc + XRING_SIZE * esize;
	r->map = mmap(NULL, r->map_len, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, fd, (off_t)pgoff);
	if (r->map == MAP_FAILED) {
		r->map = NULL;
		return -errno;
	}
	r->producer = (__u32 *)((char *)r->map + off->producer);
	r->consumer = (__u32 *)((char *)r->map + off->consumer);
	r->descs = (char *)r->map + off->desc;
	r->mask = XRING_SIZE - 1;
	return 0;
}

static int xsk_u32(int fd, int opt, __u32 v)
{
	return setsockopt(fd, SOL_XDP, opt, &v, sizeof(v)) ? -errno : 0;
}

/* TX-capable socket with its own aligned UMEM, bound in exactly the mode. */
static int xsk_open(struct xdev_ext_session *s, unsigned int ifindex, __u32 queue)
{
	struct sockaddr_xdp sxdp = { .sxdp_family = AF_XDP };
	struct xdp_umem_reg reg = { .chunk_size = XDEV_EXT_FRAME_SIZE };
	struct xdp_options options = { 0 };
	struct xdp_mmap_offsets off;
	socklen_t len = sizeof(off);
	bool copy = s->xsk_mode == XDEV_EXT_XSK_COPY;
	int ret;

	s->xsk = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (s->xsk < 0)
		return -errno;
	s->umem_size = (size_t)s->nr_frames * XDEV_EXT_FRAME_SIZE;
	s->umem = mmap(NULL, s->umem_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (s->umem == MAP_FAILED) {
		s->umem = NULL;
		return -errno;
	}
	reg.addr = (uintptr_t)s->umem;
	reg.len = s->umem_size;
	if (setsockopt(s->xsk, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)))
		return -errno;
	if ((ret = xsk_u32(s->xsk, XDP_UMEM_FILL_RING, XRING_SIZE)) ||
	    (ret = xsk_u32(s->xsk, XDP_UMEM_COMPLETION_RING, XRING_SIZE)) ||
	    (ret = xsk_u32(s->xsk, XDP_TX_RING, XRING_SIZE)))
		return ret;
	if (getsockopt(s->xsk, SOL_XDP, XDP_MMAP_OFFSETS, &off, &len))
		return -errno;
	if ((ret = xring_map(s->xsk, &off.fr, XDP_UMEM_PGOFF_FILL_RING,
			     sizeof(__u64), &s->fq)) ||
	    (ret = xring_map(s->xsk, &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING,
			     sizeof(__u64), &s->cq)) ||
	    (ret = xring_map(s->xsk, &off.tx, XDP_PGOFF_TX_RING,
			     sizeof(struct xdp_desc), &s->tx)))
		return ret;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;
	sxdp.sxdp_flags = xdev_ext_mech_ctl_xsk_flags(copy);
	if (bind(s->xsk, (struct sockaddr *)&sxdp, sizeof(sxdp)))
		return -errno;
	len = sizeof(options);
	if (getsockopt(s->xsk, SOL_XDP, XDP_OPTIONS, &options, &len))
		return -errno;
	s->zero_copy = !!(options.flags & XDP_OPTIONS_ZEROCOPY);
	return xdev_ext_mech_ctl_xsk_mode_check(copy, options.flags);
}

/* Copy mode: the kernel source takes its frames from the fill ring. */
static int xsk_fill(struct xdev_ext_session *s)
{
	__u32 n = s->nr_frames < XRING_SIZE ? s->nr_frames : XRING_SIZE;
	__u32 prod = *s->fq.producer;
	__u32 cons = __atomic_load_n(s->fq.consumer, __ATOMIC_ACQUIRE);
	__u32 i;

	if (s->fq.mask + 1 - (prod - cons) < n)
		return -ENOSPC;
	for (i = 0; i < n; i++)
		((__u64 *)s->fq.descs)[(prod + i) & s->fq.mask] =
			(__u64)i * XDEV_EXT_FRAME_SIZE;
	__atomic_store_n(s->fq.producer, prod + n, __ATOMIC_RELEASE);
	return 0;
}

static void xring_unmap(struct xring *r)
{
	if (r->map)
		munmap(r->map, r->map_len);
	r->map = NULL;
}

/* --- release ------------------------------------------------------------ */

static void session_free(struct xdev_ext_session *s)
{
	__u32 i;

	if (s->ring >= 0)
		close(s->ring);
	xring_unmap(&s->fq);
	xring_unmap(&s->cq);
	xring_unmap(&s->tx);
	if (s->xsk >= 0)
		close(s->xsk);
	if (s->allocation_fd >= 0)
		close(s->allocation_fd);
	if (s->umem)
		munmap(s->umem, s->umem_size);
	for (i = 0; i < s->nr_owned_fds; i++)
		close(s->owned_fd[i]);
	if (s->efd >= 0)
		close(s->efd);
	for (i = s->nr_progs; i--;)
		s->prog_detach(s->prog[i]);
	free(s);
}

/* --- public steps -------------------------------------------------------- */

int xdev_ext_session_open(const struct xdev_ext_pool_opts *o,
			  struct xdev_ext_session **out)
{
	struct io_uring_params p;
	struct xdev_ext_session *s;
	unsigned int ifindex = 0;
	int ret;

	if (!o || !out)
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags)
		return -EOPNOTSUPP;
	if (o->pool_kind == XDEV_EXT_MECH_POOL_PEER)
		return -EOPNOTSUPP;
	if ((o->pool_kind != XDEV_EXT_MECH_POOL_XSK &&
	     o->pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM) ||
	    o->nr_frames > XDEV_EXT_MAX_FRAMES)
		return -EINVAL;
	if (o->pool_kind == XDEV_EXT_MECH_POOL_XSK) {
		if (!o->ifname || strlen(o->ifname) >= IF_NAMESIZE ||
		    (o->xsk_mode != XDEV_EXT_XSK_ZEROCOPY &&
		     o->xsk_mode != XDEV_EXT_XSK_COPY))
			return -EINVAL;
		ifindex = if_nametoindex(o->ifname);
		if (!ifindex)
			return -errno;
	}
	s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;
	s->ring = s->efd = s->xsk = s->allocation_fd = -1;
	s->pool_kind = o->pool_kind;
	s->xsk_mode = o->xsk_mode;
	s->nr_frames = o->nr_frames ? o->nr_frames : XDEV_EXT_DEFAULT_FRAMES;
	memset(&p, 0, sizeof(p));
	s->ring = sys_uring_setup(8, &p);
	if (s->ring < 0) {
		ret = s->ring;
		goto fail;
	}
	s->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (s->efd < 0) {
		ret = -errno;
		goto fail;
	}
	if (s->pool_kind == XDEV_EXT_MECH_POOL_XSK) {
		snprintf(s->ifname, sizeof(s->ifname), "%s", o->ifname);
		ret = xsk_open(s, ifindex, o->queue);
	} else {
		struct io_uring_xdev_ext_umem_reg reg = {
			.frame_size = XDEV_EXT_FRAME_SIZE,
		};

		s->umem_size = (size_t)s->nr_frames * XDEV_EXT_FRAME_SIZE;
		s->umem = mmap(NULL, s->umem_size, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		if (s->umem == MAP_FAILED) {
			s->umem = NULL;
			ret = -errno;
			goto fail;
		}
		reg.addr = (uintptr_t)s->umem;
		reg.size = s->umem_size;
		ret = sys_uring_register(s->ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg);
	}
	if (ret)
		goto fail;
	*out = s;
	return 0;
fail:
	session_free(s);
	return ret;
}

int xdev_ext_session_open_peer(const struct xdev_ext_peer_pool_opts *o,
			       struct xdev_ext_session **out)
{
	struct io_uring_params p = { 0 };
	struct xdev_ext_session *s;
	int ret;

	if (!o || !out || o->allocation_fd < 0)
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags)
		return -EOPNOTSUPP;
	s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;
	s->ring = s->efd = s->xsk = s->allocation_fd = -1;
	s->pool_kind = XDEV_EXT_MECH_POOL_PEER;
	s->allocation_fd = fcntl(o->allocation_fd, F_DUPFD_CLOEXEC, 0);
	if (s->allocation_fd < 0) {
		ret = -errno;
		goto peer_fail;
	}
	s->ring = sys_uring_setup(8, &p);
	if (s->ring < 0) {
		ret = s->ring;
		goto peer_fail;
	}
	s->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (s->efd < 0) {
		ret = -errno;
		goto peer_fail;
	}
	*out = s;
	return 0;
peer_fail:
	session_free(s);
	return ret;
}

int xdev_ext_session_create(struct xdev_ext_session *s,
			    const struct xdev_ext_create_opts *o)
{
	static const struct xdev_ext_mech_layout zero_layout;
	static const __u8 zero_mac[6];
	struct xdev_ext_mech_create c = { 0 };
	struct ifreq ifr;
	__u32 i;
	int ret;

	if (!s || !o)
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags)
		return -EOPNOTSUPP;
	if (!o->group_bytes || !o->depth || !o->nr_stages ||
	    o->nr_stages > XDEV_EXT_MECH_MAX_STAGES)
		return -EINVAL;
	if (s->created)
		return -EALREADY;
	c.layout = o->layout;
	if (!memcmp(&o->layout, &zero_layout, sizeof(zero_layout))) {
		__u32 mtu = o->mtu;

		if (!mtu && s->pool_kind == XDEV_EXT_MECH_POOL_XSK) {
			ret = if_query(s->ifname, SIOCGIFMTU, &ifr);
			if (ret)
				return ret;
			mtu = (__u32)ifr.ifr_mtu;
		}
		ret = xdev_ext_mech_ctl_layout(mtu ? mtu : IOU_MTU, o->group_bytes,
					       &c.layout);
		if (ret)
			return ret;
	}
	ret = xdev_ext_mech_layout_frames(&c.layout);
	if (ret <= 0)
		return ret ? ret : -EINVAL;
	s->frames_per_batch = (__u32)ret;
	c.peer = o->peer;
	if (s->pool_kind == XDEV_EXT_MECH_POOL_XSK &&
	    !memcmp(c.peer.local_mac, zero_mac, sizeof(zero_mac))) {
		ret = if_query(s->ifname, SIOCGIFHWADDR, &ifr);
		if (ret)
			return ret;
		memcpy(c.peer.local_mac, ifr.ifr_hwaddr.sa_data, 6);
	}
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = o->nr_stages;
	c.pool_kind = s->pool_kind;
	c.pool_fd = s->pool_kind == XDEV_EXT_MECH_POOL_XSK ? s->xsk :
		s->pool_kind == XDEV_EXT_MECH_POOL_PEER ? s->allocation_fd : -1;
	c.depth = o->depth;
	c.eventfd = s->efd;
	memcpy(c.st, o->st, sizeof(c.st));
	for (i = 0; i < c.nr_stages; i++)
		if (s->pool_kind == XDEV_EXT_MECH_POOL_XSK &&
		    c.st[i].class_id == XDEV_EXT_MECH_CLASS_AFXDP && c.st[i].fd < 0)
			c.st[i].fd = s->xsk;
	ret = mech(s, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&c);
	if (ret)
		return ret;
	s->id = c.session_id;
	s->depth = o->depth;
	s->created = true;
	return 0;
}

static bool live(const struct xdev_ext_session *s)
{
	return s->created && !s->released && !s->retained;
}

int xdev_ext_session_arm(struct xdev_ext_session *s, __u64 batches_target,
			 __u64 published_target)
{
	struct xdev_ext_mech_notify_arm arm;
	int ret;

	if (!s)
		return -EINVAL;
	if (!live(s))
		return -ENOTCONN;
	arm = (struct xdev_ext_mech_notify_arm) {
		.session_id = s->id,
		.batches_target = batches_target,
		.published_target = published_target,
	};
	ret = xdev_ext_mech_notify_validate(&arm);
	if (ret)
		return ret;
	ret = mech(s, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
	if (!ret)
		s->armed_batches = batches_target;
	return ret;
}

int xdev_ext_session_start(struct xdev_ext_session *s,
			   const struct xdev_ext_start_opts *o)
{
	struct xdev_ext_mech_start st = { 0 };
	__u32 *user = NULL;
	int ret;

	if (!s || !o)
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags)
		return -EOPNOTSUPP;
	if (!o->nr_batches)
		return -EINVAL;
	if (!live(s))
		return -ENOTCONN;
	if (s->started)
		return -EOPNOTSUPP;	/* appending batches: reserved */
	st.session_id = s->id;
	st.nr_batches = o->nr_batches;
	st.first_seq = o->first_seq ? o->first_seq : 1;
	if (s->pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM) {
		__u64 groups = o->nr_batches < s->depth ? o->nr_batches : s->depth;
		__u64 k = groups * s->frames_per_batch, i;

		if (k > s->nr_frames)
			return -E2BIG;
		user = calloc(k, sizeof(*user));
		if (!user)
			return -ENOMEM;
		for (i = 0; i < k; i++)
			user[i] = (__u32)i;
		st.flags = XDEV_EXT_MECH_START_F_USER_FRAMES |
			   XDEV_EXT_MECH_START_F_RECYCLE;
		st.nr_user_frames = (__u32)k;
		st.user_frames = (uintptr_t)user;
	} else if (!s->zero_copy) {
		ret = xsk_fill(s);
		if (ret)
			return ret;
	}
	ret = mech(s, XDEV_EXT_MECH_OP_START, (uintptr_t)&st);
	free(user);
	if (!ret) {
		s->started = true;
		s->nr_batches = o->nr_batches;
	}
	return ret;
}

static __u64 now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000ULL + (__u64)ts.tv_nsec / 1000000ULL;
}

static int raw_stats(struct xdev_ext_session *s, struct xdev_ext_mech_stats *out)
{
	memset(out, 0, sizeof(*out));
	out->session_id = s->id;
	return mech(s, XDEV_EXT_MECH_OP_STATS, (uintptr_t)out);
}

int xdev_ext_session_start_frames(struct xdev_ext_session *s,
				 const struct xdev_ext_start_frames_opts *o)
{
	struct xdev_ext_mech_start st = { 0 };
	struct xdev_ext_mech_stats snap;
	__u32 *indices;
	__u64 target;
	int ret;

	if (!s || !o)
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags & ~XDEV_EXT_MECH_START_F_RECYCLE)
		return -EOPNOTSUPP;
	if (!o->nr_batches || !o->nr_indices || !o->indices ||
	    o->nr_indices > XDEV_EXT_MAX_FRAMES ||
	    o->nr_batches - 1 > UINT64_MAX - (o->first_seq ? o->first_seq : 1))
		return -EINVAL;
	if (!live(s))
		return -ENOTCONN;
	if (s->pool_kind != XDEV_EXT_MECH_POOL_PEER &&
	    s->pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM)
		return -EOPNOTSUPP;
	if (s->started) {
		ret = raw_stats(s, &snap);
		if (ret)
			return ret;
		if (snap.last_err || snap.sequestered || snap.batches_abort ||
		    snap.state != XDEV_EXT_MECH_SESSION_ACTIVE)
			return snap.last_err < 0 ? snap.last_err : -EIO;
		if (snap.inflight || snap.batches_done < s->nr_batches)
			return -EBUSY;
	}
	if (o->nr_batches > UINT64_MAX - s->nr_batches)
		return -EOVERFLOW;
	target = s->nr_batches + o->nr_batches;
	indices = malloc((size_t)o->nr_indices * sizeof(*indices));
	if (!indices)
		return -ENOMEM;
	memcpy(indices, o->indices, (size_t)o->nr_indices * sizeof(*indices));
	st.session_id = s->id;
	st.nr_batches = o->nr_batches;
	st.first_seq = o->first_seq ? o->first_seq : 1;
	st.flags = o->flags | XDEV_EXT_MECH_START_F_USER_FRAMES |
		XDEV_EXT_MECH_START_F_ORDERED_FRAMES;
	st.nr_user_frames = o->nr_indices;
	st.user_frames = (uintptr_t)indices;
	ret = xdev_ext_session_arm(s, target, 0);
	if (ret) {
		free(indices);
		return ret;
	}
	ret = mech(s, XDEV_EXT_MECH_OP_START, (uintptr_t)&st);
	free(indices);
	if (!ret) {
		s->started = true;
		s->nr_batches = target;
	}
	return ret;
}

int xdev_ext_session_stage_caps(struct xdev_ext_session *s, __u32 stage,
			       struct xdev_ext_mech_stage_caps *out)
{
	struct xdev_ext_mech_stage_caps caps = {
		.size = sizeof(caps), .version = XDEV_EXT_MECH_STAGE_CAPS_VERSION,
		.stage = stage,
	};
	int ret;
	if (!s || !out)
		return -EINVAL;
	if (!live(s))
		return -ENOTCONN;
	caps.session_id = s->id;
	ret = mech(s, XDEV_EXT_MECH_OP_STAGE_CAPS, (uintptr_t)&caps);
	if (!ret)
		*out = caps;
	return ret;
}

int xdev_ext_stage_xdomain(struct xdev_ext_mech_stage_uapi *out, int control_fd,
			  __u64 link_token, __u32 direction, __u32 flags)
{
	if (!out || control_fd < 0 || !link_token ||
	    (direction != XDEV_EXT_MECH_DIR_TO_DEVICE && direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
		return -EINVAL;
	/* A public helper never silently enables the administrator override. */
	if (flags & ~(XDEV_EXT_MECH_STAGE_F_POLL))
		return -EOPNOTSUPP;
	*out = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_XDOMAIN, .direction = direction,
		.fd = control_fd, .flags = flags, .arg0 = link_token,
	};
	return 0;
}

int xdev_ext_session_wait(struct xdev_ext_session *s, int timeout_ms,
			  struct xdev_ext_mech_stats *out)
{
	__u64 deadline = timeout_ms >= 0 ? now_ms() + (__u64)timeout_ms : 0;
	__u64 target, count;
	int ret = 0, q;

	if (!s || !out)
		return -EINVAL;
	if (!live(s))
		return -ENOTCONN;
	for (;;) {
		struct pollfd pfd = { .fd = s->efd, .events = POLLIN };
		int wait_ms = -1, ready;

		if (timeout_ms >= 0) {
			__u64 now = now_ms();

			wait_ms = now >= deadline ? 0 :
				deadline - now > INT32_MAX ? INT32_MAX :
				(int)(deadline - now);
		}
		ready = poll(&pfd, 1, wait_ms);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			break;
		}
		if (!ready) {
			ret = -ETIMEDOUT;
			break;
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			ret = -EIO;
			break;
		}
		if (read(s->efd, &count, sizeof(count)) == sizeof(count))
			break;
		if (errno != EAGAIN && errno != EINTR) {
			ret = -errno;
			break;
		}
	}
	/* One final snapshot on every path, including the deadline. */
	q = raw_stats(s, out);
	if (q)
		return q;
	if (ret)
		return ret;
	target = s->armed_batches ? s->armed_batches : s->nr_batches;
	return xdev_ext_mech_ctl_notify_result(out, target);
}

int xdev_ext_session_stats(struct xdev_ext_session *s, struct xdev_ext_mech_stats *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!s->created || s->released)
		return -ENOTCONN;
	return raw_stats(s, out);
}

int xdev_ext_session_nic_accounting(struct xdev_ext_session *s,
				    struct xdev_ext_mech_transport_stats_v3 *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!live(s))
		return -ENOTCONN;
	*out = (struct xdev_ext_mech_transport_stats_v3) {
		.v2.v1 = { .size = sizeof(*out),
			.version = XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3,
			.session_id = s->id },
	};
	return mech(s, XDEV_EXT_MECH_OP_TRANSPORT_STATS, (uintptr_t)out);
}

int xdev_ext_session_stop(struct xdev_ext_session *s)
{
	unsigned int tries;
	int ret;

	if (!s)
		return -EINVAL;
	if (!s->created)
		return -ENOTCONN;
	if (s->released)
		return 0;
	if (s->retained)
		return -EBUSY;
	for (tries = 0;; tries++) {
		ret = mech(s, XDEV_EXT_MECH_OP_STOP, s->id);
		if (ret != -EAGAIN || tries == XDEV_EXT_STOP_RETRIES)
			break;
		/* Returning to user space lets this task's completions run. */
		sys_usleep(1000);
	}
	if (!ret) {
		s->released = true;
	} else if (ret == -EBUSY) {
		s->retained = true;
	} else if (ret != -EAGAIN) {
		struct xdev_ext_mech_stats snap;

		/*
		 * The kernel returns the session's final error after a full
		 * release, and an unbind error after quarantine.  Only STATS
		 * tells them apart: -ENOENT once released.
		 */
		if (raw_stats(s, &snap) == -ENOENT)
			s->released = true;
		else
			s->retained = true;
	}
	return ret;
}

int xdev_ext_session_close(struct xdev_ext_session *s)
{
	struct xdev_ext_mech_stats snap;
	int ret = 0;

	if (!s)
		return -EINVAL;
	if (s->created && !s->released) {
		if (!s->retained) {
			ret = xdev_ext_session_stop(s);
			if (ret == -EAGAIN)
				return ret;	/* still live and listed: close again */
		}
		/* Only the kernel's own -ENOENT proves a release STOP did not. */
		if (!s->released && raw_stats(s, &snap) != -ENOENT)
			return s->retained ? -EBUSY : ret;
	}
	session_free(s);
	return 0;
}

int xdev_ext_session_eventfd(const struct xdev_ext_session *s)
{
	return s ? s->efd : -EINVAL;
}

int xdev_ext_session_ring_fd(const struct xdev_ext_session *s)
{
	return s ? s->ring : -EINVAL;
}

int xdev_ext_session_xsk_fd(const struct xdev_ext_session *s)
{
	return s ? s->xsk : -EINVAL;
}

__u64 xdev_ext_session_id(const struct xdev_ext_session *s)
{
	return s ? s->id : 0;
}

bool xdev_ext_session_zero_copy(const struct xdev_ext_session *s)
{
	return s && s->zero_copy;
}

bool xdev_ext_session_retained(const struct xdev_ext_session *s)
{
	return s && s->retained;
}

/* --- library-internal, for the one-call runner ---------------------------- */

int xdev_ext__session_own_fd(struct xdev_ext_session *s, int fd)
{
	if (!s || fd < 0 || s->nr_owned_fds >= XDEV_EXT_MECH_MAX_STAGES)
		return -EINVAL;
	s->owned_fd[s->nr_owned_fds++] = fd;
	return 0;
}

int xdev_ext__session_adopt_prog(struct xdev_ext_session *s, struct xdev_ext_prog *p,
				 int (*detach)(struct xdev_ext_prog *p))
{
	if (!s || !p || !detach || s->nr_progs >= XDEV_EXT_MAX_PROGS)
		return -EINVAL;
	s->prog[s->nr_progs++] = p;
	s->prog_detach = detach;
	return 0;
}

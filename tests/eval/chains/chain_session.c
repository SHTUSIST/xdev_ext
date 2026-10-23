// SPDX-License-Identifier: GPL-2.0
/*
 * Session arm of chain_bench: the whole stage list is one mechanism
 * session (IORING_REGISTER_XDEV_EXT_MECH CREATE), configured once.  Closed
 * load: each window arms one terminal notification, issues one START
 * (source chains) and blocks once on the eventfd; the CLOCK_MONOTONIC_RAW
 * interval goes to a preallocated array.  Sustained load: one START for the
 * campaign keeps up to depth batches in flight and every record's
 * completion is timed (cs_sustained).  STATS, byte checks and STOP run
 * outside the measured part.
 *
 * AF_XDP socket helpers and the struct_ops loading are adapted from
 * kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c at 8e0238a (git blob
 * 3ccfcf58fb2b85c5eef73e025f15d576c2a9c96c); the RX setup follows its
 * cmd_nic_nvme(), the source setup its ctl_run_source().
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <net/if.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include "../../../kernel/include/uapi/linux/io_uring.h"
#include "../../../kernel/tools/include/xdev_ext_xsk_redirect.h"
#include "../../../kernel/tools/include/xdev_ext_gpu_identity.h"
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_cuda.h"
#include "chain_bench.h"
#include "chain_cuda.h"
#include "chain_oracle.h"

#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#define CS_RING_SIZE	2048U
#define CS_PRISTINE	0xa6

/* --- struct_ops plans --------------------------------------------------- */

struct cs_plans {
	unsigned int nr;
	struct bpf_object *obj[CHAIN_MAX_PLANS];
	struct bpf_link *link[CHAIN_MAX_PLANS];
	int iaa_counts_fd;
};

static struct bpf_map *cs_section_map(struct bpf_object *obj, const char *sec)
{
	size_t n = strlen(sec);
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);
		size_t len = strlen(name);

		if (bpf_map__is_internal(map) && len >= n &&
		    !strcmp(name + len - n, sec))
			return map;
	}
	return NULL;
}

/* Before load: global @name in the .bss/.data image, host byte order. */
static int cs_set_global(struct bpf_object *obj, const char *name, __u64 value)
{
	static const char *const sections[] = { ".bss", ".data" };
	struct btf *btf = bpf_object__btf(obj);
	unsigned int i;

	if (!btf)
		return -ENOENT;
	for (i = 0; i < 2; i++) {
		int id = btf__find_by_name_kind(btf, sections[i], BTF_KIND_DATASEC);
		const struct btf_var_secinfo *vsi;
		const struct btf_type *sec;
		__u16 v;

		if (id < 0)
			continue;
		sec = btf__type_by_id(btf, id);
		vsi = btf_var_secinfos(sec);
		for (v = 0; v < btf_vlen(sec); v++, vsi++) {
			const struct btf_type *var = btf__type_by_id(btf, vsi->type);
			struct bpf_map *map;
			const void *image;
			size_t size;
			void *copy;
			int ret;

			if (strcmp(btf__name_by_offset(btf, var->name_off), name))
				continue;
			map = cs_section_map(obj, sections[i]);
			image = map ? bpf_map__initial_value(map, &size) : NULL;
			if (!image)
				return -ENOENT;
			copy = malloc(size);
			if (!copy)
				return -ENOMEM;
			memcpy(copy, image, size);
			ret = xdev_ext_mech_ctl_set_value(copy, size, vsi->offset,
						     vsi->size, value);
			if (!ret)
				ret = bpf_map__set_initial_value(map, copy, size);
			free(copy);
			return ret;
		}
	}
	return -ENOENT;
}

static void cs_plans_close(struct cs_plans *p)
{
	unsigned int i;

	for (i = 0; i < p->nr; i++) {
		if (p->link[i])
			bpf_link__destroy(p->link[i]);
		if (p->obj[i])
			bpf_object__close(p->obj[i]);
	}
	memset(p, 0, sizeof(*p));
	p->iaa_counts_fd = -1;
}

/* Load and attach every plan; the links live until the run ends. */
static int cs_plans_open(const struct chain_spec *s, struct cs_plans *p,
			 struct chain_result *r)
{
	unsigned int i, k;

	memset(p, 0, sizeof(*p));
	p->iaa_counts_fd = -1;
	for (i = 0; i < s->nr_plans; i++) {
		const struct chain_plan *pl = &s->plans[i];
		struct bpf_object *obj = bpf_object__open_file(pl->obj, NULL);
		struct bpf_map *map;
		int ret = (int)libbpf_get_error(obj);

		if (ret)
			return cb_fail(r, CB_NOT_RUN, "plan %s: open: %s", pl->obj,
				       strerror(-ret));
		p->obj[p->nr++] = obj;
		/* Only this entry's struct_ops map decides whether it attaches. */
		bpf_object__for_each_map(map, obj)
			if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS &&
			    strcmp(bpf_map__name(map), pl->map))
				bpf_map__set_autocreate(map, false);
		for (k = 0; k < pl->nr_sets; k++) {
			ret = cs_set_global(obj, pl->set_name[k], pl->set_value[k]);
			if (ret)
				return cb_fail(r, CB_NOT_RUN, "plan %s: global %s: %s",
					       pl->obj, pl->set_name[k], strerror(-ret));
		}
		ret = bpf_object__load(obj);
		if (ret)
			return cb_fail(r, CB_NOT_RUN, "plan %s: load: %s", pl->obj,
				       strerror(-ret));
		map = bpf_object__find_map_by_name(obj, pl->map);
		if (!map || bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
			return cb_fail(r, CB_NOT_RUN, "plan %s: no struct_ops map %s",
				       pl->obj, pl->map);
		p->link[i] = bpf_map__attach_struct_ops(map);
		ret = (int)libbpf_get_error(p->link[i]);
		if (ret) {
			p->link[i] = NULL;
			return cb_fail(r, CB_NOT_RUN, "plan %s: attach %s: %s%s",
				       pl->obj, pl->map, strerror(-ret),
				       ret == -EBUSY ? " (the class already has an attached "
				       "plan; detach it or leave this entry out)" : "");
		}
		map = bpf_object__find_map_by_name(obj, "chain_counts");
		if (map && !strcmp(pl->map, "chain_iaa_ops"))
			p->iaa_counts_fd = bpf_map__fd(map);
	}
	return 0;
}

/* --- AF_XDP socket -------------------------------------------------------- */

struct cs_xring {
	__u32 *producer, *consumer;
	void *descs;
	__u32 mask;
	void *map;
	size_t map_len;
};

struct cs_xsk {
	int fd;
	bool zero_copy;
	void *umem;
	size_t umem_size;
	struct cs_xring fq, cq, rx, tx;
};

static int cs_xring_map(int fd, const struct xdp_ring_offset *off, __u64 pgoff,
			size_t esize, struct cs_xring *x)
{
	x->map_len = off->desc + CS_RING_SIZE * esize;
	x->map = mmap(NULL, x->map_len, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, fd, (off_t)pgoff);
	if (x->map == MAP_FAILED) {
		x->map = NULL;
		return -errno;
	}
	x->producer = (__u32 *)((char *)x->map + off->producer);
	x->consumer = (__u32 *)((char *)x->map + off->consumer);
	x->descs = (char *)x->map + off->desc;
	x->mask = CS_RING_SIZE - 1;
	return 0;
}

static int cs_sockopt(int fd, int opt, __u32 v)
{
	return setsockopt(fd, SOL_XDP, opt, &v, sizeof(v)) ? -errno : 0;
}

/* A UMEM-owning socket of CHAIN_XSK_FRAMES 4 KiB chunks, mode forced. */
static int cs_xsk_open(struct cs_xsk *x, const char *ifname, __u32 queue,
		       __u32 headroom, bool rx, bool copy_mode)
{
	struct sockaddr_xdp sxdp = { .sxdp_family = AF_XDP };
	struct xdp_umem_reg reg = {
		.len = (__u64)CHAIN_XSK_FRAMES * XDEV_EXT_MECH_CTL_FRAME_SIZE,
		.chunk_size = XDEV_EXT_MECH_CTL_FRAME_SIZE,
		.headroom = headroom,
	};
	struct xdp_mmap_offsets off;
	struct xdp_options options = { 0 };
	socklen_t len = sizeof(off);
	unsigned int ifindex = if_nametoindex(ifname);
	int ret;

	memset(x, 0, sizeof(*x));
	x->fd = -1;
	if (!ifindex)
		return -errno;
	x->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (x->fd < 0)
		return -errno;
	x->umem_size = reg.len;
	x->umem = mmap(NULL, x->umem_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (x->umem == MAP_FAILED) {
		x->umem = NULL;
		return -errno;
	}
	reg.addr = (uintptr_t)x->umem;
	if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)))
		return -errno;
	ret = cs_sockopt(x->fd, XDP_UMEM_FILL_RING, CS_RING_SIZE);
	if (!ret)
		ret = cs_sockopt(x->fd, XDP_UMEM_COMPLETION_RING, CS_RING_SIZE);
	if (!ret)
		ret = cs_sockopt(x->fd, rx ? XDP_RX_RING : XDP_TX_RING, CS_RING_SIZE);
	if (ret)
		return ret;
	if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &len))
		return -errno;
	ret = cs_xring_map(x->fd, &off.fr, XDP_UMEM_PGOFF_FILL_RING,
			   sizeof(__u64), &x->fq);
	if (!ret)
		ret = cs_xring_map(x->fd, &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING,
				   sizeof(__u64), &x->cq);
	if (!ret)
		ret = rx ? cs_xring_map(x->fd, &off.rx, XDP_PGOFF_RX_RING,
					sizeof(struct xdp_desc), &x->rx) :
			   cs_xring_map(x->fd, &off.tx, XDP_PGOFF_TX_RING,
					sizeof(struct xdp_desc), &x->tx);
	if (ret)
		return ret;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;
	sxdp.sxdp_flags = xdev_ext_mech_ctl_xsk_flags(copy_mode);
	if (bind(x->fd, (struct sockaddr *)&sxdp, sizeof(sxdp)))
		return -errno;
	len = sizeof(options);
	if (getsockopt(x->fd, SOL_XDP, XDP_OPTIONS, &options, &len))
		return -errno;
	x->zero_copy = !!(options.flags & XDP_OPTIONS_ZEROCOPY);
	return xdev_ext_mech_ctl_xsk_mode_check(copy_mode, options.flags);
}

static void cs_xring_unmap(struct cs_xring *x)
{
	if (x->map)
		munmap(x->map, x->map_len);
}

static void cs_xsk_close(struct cs_xsk *x)
{
	cs_xring_unmap(&x->fq);
	cs_xring_unmap(&x->cq);
	cs_xring_unmap(&x->rx);
	cs_xring_unmap(&x->tx);
	if (x->fd >= 0)
		close(x->fd);
	if (x->umem)
		munmap(x->umem, x->umem_size);
	memset(x, 0, sizeof(*x));
	x->fd = -1;
}

/* The first ring's worth of chunks to the kernel, as ctl_fq_fill(). */
static int cs_fq_fill(struct cs_xsk *x)
{
	__u32 prod = *x->fq.producer, i;

	for (i = 0; i < CS_RING_SIZE; i++)
		((__u64 *)x->fq.descs)[(prod + i) & x->fq.mask] =
			(__u64)i * XDEV_EXT_MECH_CTL_FRAME_SIZE;
	__atomic_store_n(x->fq.producer, prod + CS_RING_SIZE, __ATOMIC_RELEASE);
	return 0;
}

static int cs_mtu(const char *ifname, __u32 *mtu)
{
	struct ifreq ifr = { 0 };
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), ret;

	if (fd < 0)
		return -errno;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	ret = ioctl(fd, SIOCGIFMTU, &ifr) ? -errno : 0;
	close(fd);
	if (!ret)
		*mtu = (__u32)ifr.ifr_mtu;
	return ret;
}

/* --- the session ---------------------------------------------------------- */

static int cs_mech(int ring, __u32 op, __u64 arg, uint64_t *syscalls)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };
	int ret = (int)syscall(__NR_io_uring_register, ring,
			       IORING_REGISTER_XDEV_EXT_MECH, &req, 1);

	(*syscalls)++;
	return ret < 0 ? -errno : ret;
}

/*
 * The NVMe bounce counter of KVM_BOUNCE test kernels; -1 when the running
 * kernel has none (a ZEROCOPY build cannot bounce).
 */
static int64_t cs_bounces(void)
{
	glob_t g;
	int64_t v = -1;

	if (glob("/sys/module/*/parameters/xdev_ext_mech_bounces", 0, NULL, &g))
		return -1;
	if (g.gl_pathc == 1) {
		FILE *f = fopen(g.gl_pathv[0], "r");
		long long x;

		if (f && fscanf(f, "%lld", &x) == 1)
			v = x;
		if (f)
			fclose(f);
	}
	globfree(&g);
	return v;
}

/* One wake: 0, -ETIMEDOUT or -errno; *@count gets the eventfd count. */
static int cs_wait(int efd, uint64_t deadline_ns, uint64_t *syscalls, uint64_t *count)
{
	for (;;) {
		struct pollfd pfd = { .fd = efd, .events = POLLIN };
		uint64_t now = cb_now_ns();
		long long left;
		int n;

		if (now >= deadline_ns)
			return -ETIMEDOUT;
		left = (long long)((deadline_ns - now) / 1000000ULL) + 1;
		n = poll(&pfd, 1, left > 1000000 ? 1000000 : (int)left);
		(*syscalls)++;
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (!n)
			continue;
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			return -EIO;
		(*syscalls)++;
		if (read(efd, count, sizeof(*count)) == (ssize_t)sizeof(*count))
			return 0;
		if (errno != EAGAIN && errno != EINTR)
			return -errno;
	}
}

struct cs_ce {
	int fd[XDEV_EXT_MECH_MAX_STAGES];
	struct xdev_ext_mech_cuda cuda;
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE];
	uint64_t va;
};

/* CE window read or write outside every window (oracle, pristine fill). */
static int cs_ce_access(const struct chain_spec *s, struct cs_ce *ce, uint64_t off,
			void *buf, size_t len, bool write)
{
	int fd = -1, i;
	ssize_t n;

	if (s->ce_native)
		return write ? chain_cuda_fill(ce->bdf, ce->va + off, buf, len) :
			       chain_cuda_readback(ce->bdf, ce->va + off, buf, len);
	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES && fd < 0; i++)
		fd = ce->fd[i];
	if (fd < 0)
		return -EBADF;
	n = write ? pwrite(fd, buf, len, (off_t)(ce->va + off)) :
		    pread(fd, buf, len, (off_t)(ce->va + off));
	if (n < 0)
		return -errno;
	return (size_t)n == len ? 0 : -EIO;
}

/* The window slots against the reference; @required batches must be there. */
static int cs_ce_oracle(const struct chain_spec *s, struct cs_ce *ce,
			const uint8_t *ref, size_t ref_len, const uint64_t *required,
			unsigned int nr_required, struct chain_result *r)
{
	size_t bytes = (size_t)s->depth * s->group_bytes;
	uint32_t len = s->st[s->nr_stages - 1].cls == CH_CE &&
		       s->nr_stages > 1 && s->st[s->nr_stages - 2].cls == CH_IAA &&
		       s->st[s->nr_stages - 2].expect ?
		       s->st[s->nr_stages - 2].expect : s->group_bytes;
	uint64_t groups = ref_len / len, found = 0;
	uint8_t *window = malloc(bytes);
	long long bad;
	int ret;

	if (!window)
		return -ENOMEM;
	ret = cs_ce_access(s, ce, 0, window, bytes, false);
	if (ret) {
		free(window);
		return ret;
	}
	bad = chain_check_window(window, s->depth, s->group_bytes, len, ref, groups,
				 CS_PRISTINE, required, nr_required, &found);
	free(window);
	r->oracle_bytes += found * len;
	r->oracle_detail = bad;
	return bad ? -EBADMSG : 0;
}

/*
 * Sustained load: one START for the whole campaign (a receiver has none),
 * so the kernel keeps up to depth batches in flight.  No NOTIFY_ARM is
 * issued, so the eventfd keeps the legacy one count per finished batch
 * (xdev_ext_mech_notify_locked).  A RECYCLE START on the io_uring UMEM
 * holds every wake until it drains (start_return_pending), so there the
 * completions are seen by polling STATS; those calls are the observer's,
 * counted apart from the application's system calls.  A record's
 * completion is the moment its last batch was seen to finish.
 */
static int cs_sustained(const struct chain_spec *s, struct chain_result *r, int ring,
			int efd, __u64 session, const __u32 *user, __u32 frames,
			bool rx, uint64_t *lent, bool *started)
{
	uint64_t total = s->warmup + s->batches, finished = 0, timeout, last, now;
	int ret;

	timeout = s->timeout_ms * 1000000ULL;
	r->observer = user ? "stats-poll" : "eventfd-count";
	if (!rx) {
		struct xdev_ext_mech_start start = {
			.session_id = session, .nr_batches = total, .first_seq = 1,
		};

		if (user) {
			start.flags = XDEV_EXT_MECH_START_F_USER_FRAMES |
				      XDEV_EXT_MECH_START_F_RECYCLE;
			start.nr_user_frames = (__u32)((total < s->depth ? total : s->depth) *
						       frames);
			start.user_frames = (uintptr_t)user;
		}
		*started = true;
		r->sus.t_begin = cb_now_ns();
		ret = cs_mech(ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start, &r->syscalls);
		if (ret)
			return ret;
		*lent += start.nr_user_frames;
	} else {
		*started = true;
		r->sus.t_begin = cb_now_ns();
	}
	last = r->sus.t_begin;
	while (finished < total) {
		if (user) {
			struct xdev_ext_mech_stats st = { .session_id = session };

			ret = cs_mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st,
				      &r->observer_syscalls);
			now = cb_now_ns();
			if (ret)
				return ret;
			if (st.last_err)
				return st.last_err;
			if (st.state != XDEV_EXT_MECH_SESSION_ACTIVE)
				return -ESHUTDOWN;
			if (st.batches_done + st.batches_abort > finished) {
				finished = st.batches_done + st.batches_abort;
				last = now;
			}
		} else {
			uint64_t count = 0;

			ret = cs_wait(efd, last + timeout, &r->syscalls, &count);
			now = cb_now_ns();
			if (ret)
				return ret;
			finished += count;
			last = now;
		}
		chain_sustained_note(&r->sus, finished, now);
		/* No progress for timeout_ms: give up (STOP follows). */
		if (now - last > timeout)
			return -ETIMEDOUT;
	}
	r->windows_done = 1;
	return 0;
}

int chain_run_session(const struct chain_spec *s, struct chain_result *r)
{
	struct xdev_ext_xsk_redirect redirect = XDEV_EXT_XSK_REDIRECT_INIT;
	struct xdev_ext_mech_create c = { 0 };
	struct xdev_ext_mech_stats st;
	struct xdev_ext_mech_layout l;
	struct chain_iou_plan iou = { 0 };
	struct chain_err e = { { 0 } };
	struct cs_plans plans = { .iaa_counts_fd = -1 };
	struct cs_xsk x = { .fd = -1 };
	struct cs_ce ce = { .fd = { -1, -1, -1, -1 } };
	int fds[XDEV_EXT_MECH_MAX_STAGES] = { -1, -1, -1, -1 };
	__u32 *user = NULL, frames = 0, headroom = 0, mtu = 0, i;
	uint8_t *ref = NULL;
	size_t ref_len = 0;
	void *pool = NULL;
	size_t pool_bytes = 0;
	int ring = -1, efd = -1, ret, ax = -1;
	bool pinned_counts = false;
	bool rx = chain_rx_first(s), started = false, unsafe = false;
	uint64_t windows = chain_windows(s), wb = chain_window_batches(s);
	uint64_t warm = s->warmup ? (s->start_per == CH_START_RUN ? 1 :
				     s->warmup / s->burst) : 0;
	uint64_t seq = 1, target = 0, t_prev, w, campaign_syscalls = 0, lent = 0;
	bool sustained = s->load == CH_LOAD_SUSTAINED;
	int64_t bounces0 = cs_bounces();

	r->ce_backend = !chain_has(s, CH_CE) ? "none" :
			strstr(s->ce_dev, "xdev_ext_ce_sim") ? "ce-sim-cpu-standin" :
			s->ce_native ? "gpu-native-allocation" : "gpu-given-window";
	if (sustained) {
		r->rec_ns = malloc(chain_records(s) * sizeof(*r->rec_ns));
		if (!r->rec_ns)
			return cb_fail(r, CB_NOT_RUN, "record array: %s", strerror(ENOMEM));
		chain_sustained_init(&r->sus, chain_records(s), s->warmup / s->burst,
				     s->burst, r->rec_ns);
	} else if (s->mode == CH_TIMING) {
		r->samples = calloc(windows, sizeof(*r->samples));
		if (!r->samples)
			return cb_fail(r, CB_NOT_RUN, "sample array: %s", strerror(ENOMEM));
		for (w = 0; w < windows; w++)
			r->samples[w] = 0;	/* fault the array in before any window */
	}
	if (s->oracle != CH_ORACLE_NONE) {
		ref = chain_read_reference(s, &ref_len, r);
		if (!ref)
			return r->status;
	}
	if (cs_plans_open(s, &plans, r))
		goto out;
	ring = (int)syscall(__NR_io_uring_setup, 8, &(struct io_uring_params){ 0 });
	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ring < 0 || efd < 0) {
		cb_fail(r, CB_NOT_RUN, "io_uring/eventfd: %s", strerror(errno));
		goto out;
	}
	for (i = 0; i < s->nr_stages; i++)
		if (s->st[i].cls == CH_AFXDP)
			ax = (int)i;
	if (ax >= 0) {
		ret = cs_mtu(s->st[ax].ifname, &mtu);
		if (!ret)
			ret = xdev_ext_mech_ctl_layout(mtu, s->group_bytes, &l);
		if (!ret && rx)
			ret = xdev_ext_mech_ctl_rx_headroom(&l, &headroom);
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "NXP layout on %s: %s", s->st[ax].ifname,
				strerror(-ret));
			goto out;
		}
		frames = (__u32)xdev_ext_mech_layout_frames(&l);
		ret = cs_xsk_open(&x, s->st[ax].ifname, s->st[ax].queue, headroom, rx,
				  s->xsk_mode == CH_XSK_COPY);
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "AF_XDP %s mode on %s: %s",
				s->xsk_mode == CH_XSK_COPY ? "copy" : "zero-copy",
				s->st[ax].ifname, strerror(-ret));
			goto out;
		}
		r->xsk_zero_copy = x.zero_copy;
		c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
		c.pool_fd = x.fd;
	} else {
		struct io_uring_xdev_ext_umem_reg reg = { 0 };

		if (chain_iou_layout(s, &iou, &e)) {
			cb_fail(r, CB_INVALID, "%s", e.msg);
			goto out;
		}
		l = iou.l;
		frames = iou.src_frames;
		pool_bytes = (size_t)iou.pool_frames * s->frame_size;
		pool = mmap(NULL, pool_bytes, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE |
			    (s->hugepage ? MAP_HUGETLB : 0), -1, 0);
		if (pool == MAP_FAILED) {
			pool = NULL;
			cb_fail(r, CB_NOT_RUN, "pool of %zu bytes%s: %s", pool_bytes,
				s->hugepage ? " (hugetlb)" : "", strerror(errno));
			goto out;
		}
		reg = (struct io_uring_xdev_ext_umem_reg){
			.addr = (uintptr_t)pool, .size = pool_bytes,
			.frame_size = s->frame_size,
		};
		r->syscalls++;
		if (syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_UMEM,
			    &reg, 1) < 0) {
			cb_fail(r, CB_NOT_RUN, "IORING_REGISTER_XDEV_EXT_UMEM: %s",
				strerror(errno));
			goto out;
		}
		user = calloc(iou.lend_frames, sizeof(*user));
		if (!user) {
			cb_fail(r, CB_NOT_RUN, "user frames: %s", strerror(ENOMEM));
			goto out;
		}
		for (i = 0; i < iou.lend_frames; i++)
			user[i] = i;
		c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
		c.pool_fd = -1;
	}
	for (i = 0; i < s->nr_stages; i++) {
		const struct chain_stage *sg = &s->st[i];

		if (sg->cls == CH_NVME)
			fds[i] = open(sg->dev, (sg->dir == CH_FROM ? O_RDONLY : O_RDWR) |
				      O_CLOEXEC);
		else if (sg->cls == CH_CE)
			fds[i] = ce.fd[i] = open(s->ce_dev, O_RDWR | O_CLOEXEC);
		else if (sg->cls == CH_IAA)
			fds[i] = open(sg->dev, O_RDONLY | O_CLOEXEC);
		if (sg->cls != CH_AFXDP && fds[i] < 0) {
			cb_fail(r, CB_NOT_RUN, "stage %u device: %s", i, strerror(errno));
			goto out;
		}
	}
	ce.va = s->ce_va;
	if (s->ce_native) {
		int first = -1;

		for (i = 0; i < s->nr_stages; i++) {
			char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE];

			if (ce.fd[i] < 0)
				continue;
			ret = xdev_ext_gpu_identity_from_opened(ce.fd[i], s->ce_dev,
					XDEV_EXT_GPU_IDENTITY_ANY_MINOR, first < 0 ? ce.bdf : bdf);
			if (!ret && first >= 0 && strcasecmp(ce.bdf, bdf))
				ret = -EXDEV;
			if (ret) {
				cb_fail(r, CB_NOT_RUN, "GPU identity of %s: %s", s->ce_dev,
					strerror(-ret));
				goto out;
			}
			first = (int)i;
		}
		ret = xdev_ext_mech_cuda_open(&ce.cuda, ce.bdf, s->ce_len);
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "CUDA allocation on %s: %s", ce.bdf,
				strerror(-ret));
			goto out;
		}
		ce.va = ce.cuda.va;
	}
	if (s->oracle == CH_ORACLE_CE) {
		size_t bytes = (size_t)s->depth * s->group_bytes;
		uint8_t *fill = malloc(bytes);

		ret = fill ? 0 : -ENOMEM;
		if (fill) {
			memset(fill, CS_PRISTINE, bytes);
			ret = cs_ce_access(s, &ce, 0, fill, bytes, true);
			free(fill);
		}
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "CE window pristine fill: %s", strerror(-ret));
			goto out;
		}
	}
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = s->nr_stages;
	c.layout = l;
	c.depth = s->depth;
	c.eventfd = efd;
	c.peer = s->peer;
	chain_stage_uapi(s, fds, x.fd, ce.va, iou.iaa_first, c.st);
	ret = cs_mech(ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&c, &r->syscalls);
	if (ret) {
		cb_fail(r, CB_NOT_RUN, "CREATE: %s", xdev_ext_mech_ctl_errname(ret));
		goto out;
	}
	/* As ctl_run_source(): a copy-mode source socket gets the fill ring too. */
	if (!rx && ax >= 0 && !x.zero_copy)
		cs_fq_fill(&x);
	if (rx) {
		const struct xdev_ext_xsk_flow_filter filter = {
			.flags = XDEV_EXT_XSK_FILTER_F_ALL,
			.src_ipv4 = ntohl(s->peer.peer_ip),
			.dst_ipv4 = ntohl(s->peer.local_ip),
			.payload_magic = XDEV_EXT_MP_NXP_MAGIC,
			.src_port = ntohs(s->peer.peer_port),
			.dst_port = ntohs(s->peer.local_port),
		};
		struct xdev_ext_mech_notify_arm arm;

		/*
		 * The first arm precedes readiness, so no completion races it.
		 * A sustained receiver never arms: one eventfd count per batch.
		 */
		ret = sustained ? 0 :
		      xdev_ext_mech_ctl_notify_request(&arm, c.session_id, wb);
		if (!ret && !sustained)
			ret = cs_mech(ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm,
				      &r->syscalls);
		if (!ret)
			ret = cs_fq_fill(&x);
		if (!ret)
			ret = xdev_ext_xsk_redirect_attach(&redirect, &filter,
				(int)if_nametoindex(s->st[ax].ifname), s->st[ax].queue, x.fd,
				s->xsk_mode == CH_XSK_COPY ? XDP_FLAGS_SKB_MODE :
							     XDP_FLAGS_DRV_MODE);
		if (ret) {
			cb_fail(r, CB_NOT_RUN, "receiver arm/fill/redirect: %s",
				strerror(-ret));
			goto out;
		}
	}
	fprintf(stderr, "CHAIN_READY chain=%s arm=session session=%llu frames=%u "
		"seg_len=%u xsk=%s\n", s->chain, (unsigned long long)c.session_id,
		frames, l.seg_len, ax < 0 ? "none" : x.zero_copy ? "zc" : "copy");
	fflush(stderr);
	/* Costs count the campaign only: from here to the last window. */
	r->syscalls = 0;
	getrusage(RUSAGE_SELF, &r->ru_before);
	t_prev = cb_now_ns();
	if (sustained) {
		ret = cs_sustained(s, r, ring, efd, c.session_id, user, frames, rx, &lent,
				   &started);
		target = s->warmup + s->batches;
		r->batches_done = r->sus.next * s->burst;
		if (ret) {
			cb_fail(r, CB_FAIL, "sustained run after %llu of %llu records: %s",
				(unsigned long long)r->sus.next,
				(unsigned long long)r->sus.records,
				xdev_ext_mech_ctl_errname(ret));
			goto stop;
		}
		warm = windows = 0;		/* skip the closed-load loop */
	}
	for (w = 0; w < warm + windows; w++) {
		uint64_t nb = w < warm ? (s->start_per == CH_START_RUN ? s->warmup :
					  s->burst) : wb;
		uint64_t t0, t1;

		target += nb;
		if (!rx) {
			struct xdev_ext_mech_notify_arm arm;
			struct xdev_ext_mech_start start = {
				.session_id = c.session_id, .nr_batches = nb,
				.first_seq = seq,
			};

			if (user) {
				start.flags = XDEV_EXT_MECH_START_F_USER_FRAMES |
					      XDEV_EXT_MECH_START_F_RECYCLE;
				start.nr_user_frames = (__u32)((nb < s->depth ? nb : s->depth) *
							       frames);
				start.user_frames = (uintptr_t)user;
			}
			ret = xdev_ext_mech_ctl_notify_request(&arm, c.session_id, target);
			if (!ret)
				ret = cs_mech(ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm,
					      &r->syscalls);
			if (ret) {
				cb_fail(r, CB_FAIL, "NOTIFY_ARM window %llu: %s",
					(unsigned long long)w, xdev_ext_mech_ctl_errname(ret));
				goto stop;
			}
			/* An interrupted START cannot prove the batches were refused. */
			started = true;
			t0 = cb_now_ns();
			ret = cs_mech(ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start,
				      &r->syscalls);
			if (!ret) {
				uint64_t count;

				lent += start.nr_user_frames;
				ret = cs_wait(efd, t0 + s->timeout_ms * 1000000ULL,
					      &r->syscalls, &count);
			}
			t1 = cb_now_ns();
			seq += nb;
		} else {
			uint64_t count;

			started = true;
			t0 = t_prev;
			ret = cs_wait(efd, cb_now_ns() + s->timeout_ms * 1000000ULL,
				      &r->syscalls, &count);
			t1 = cb_now_ns();
		}
		t_prev = t1;
		if (ret) {
			cb_fail(r, CB_FAIL, "window %llu: %s", (unsigned long long)w,
				xdev_ext_mech_ctl_errname(ret));
			goto stop;
		}
		if (w >= warm && r->samples)
			r->samples[r->nr_samples++] = t1 - t0;
		/*
		 * Outside the window: did every batch of it end well?  A timed run
		 * leaves this to the final STATS, so its system calls are the
		 * application's (arm, START, one wake) and not the harness's.
		 */
		st = (struct xdev_ext_mech_stats){ .session_id = c.session_id };
		ret = s->mode == CH_TIMING ? 0 :
		      cs_mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st, &r->syscalls);
		if (!ret && s->mode != CH_TIMING)
			ret = xdev_ext_mech_ctl_notify_result(&st, target);
		if (ret) {
			r->stats = st;
			r->have_stats = true;
			cb_fail(r, CB_FAIL, "window %llu ended with %s",
				(unsigned long long)w, xdev_ext_mech_ctl_errname(ret));
			goto stop;
		}
		r->windows_done++;
		r->batches_done = target;
		if (rx && w + 1 < warm + windows) {
			struct xdev_ext_mech_notify_arm arm;

			ret = xdev_ext_mech_ctl_notify_request(&arm, c.session_id,
							  target + wb);
			if (!ret)
				ret = cs_mech(ring, XDEV_EXT_MECH_OP_NOTIFY_ARM,
					      (uintptr_t)&arm, &r->syscalls);
			if (ret) {
				cb_fail(r, CB_FAIL, "NOTIFY_ARM after window %llu: %s",
					(unsigned long long)w, xdev_ext_mech_ctl_errname(ret));
				goto stop;
			}
		}
		/* Only the newest group is sure to keep its slot (LIFO batches). */
		if (s->oracle == CH_ORACLE_CE && s->every_window) {
			uint64_t want = target - 1;

			if (cs_ce_oracle(s, &ce, ref, ref_len, &want, 1, r)) {
				r->oracle_verdict = "fail";
				cb_fail(r, CB_FAIL, "CE window after window %llu: detail %lld",
					(unsigned long long)w, r->oracle_detail);
				goto stop;
			}
		}
	}
	getrusage(RUSAGE_SELF, &r->ru_after);
	campaign_syscalls = r->syscalls;
	st = (struct xdev_ext_mech_stats){ .session_id = c.session_id };
	ret = cs_mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st, &r->syscalls);
	if (!ret) {
		const char *bad = chain_counters_bad(s, &st, target, frames, lent);

		r->stats = st;
		r->have_stats = true;
		if (bad)
			cb_fail(r, CB_FAIL, "final counters: %s (published %llu, lent %llu)",
				bad, (unsigned long long)st.published,
				(unsigned long long)lent);
	} else {
		cb_fail(r, CB_FAIL, "final STATS: %s", xdev_ext_mech_ctl_errname(ret));
	}
	if (!r->status && s->oracle == CH_ORACLE_CE) {
		uint64_t want = target - 1;

		ret = cs_ce_oracle(s, &ce, ref, ref_len, &want, 1, r);
		r->oracle_verdict = ret ? "fail" : "pass";
		if (ret)
			cb_fail(r, CB_FAIL, "final CE window: %s detail %lld",
				strerror(-ret), r->oracle_detail);
	}
stop:
	if (c.session_id) {
		ret = cs_mech(ring, XDEV_EXT_MECH_OP_STOP, c.session_id, &r->syscalls);
		if (ret) {
			/* Accepted DMA may still own pool pages: keep everything. */
			unsafe = true;
			cb_fail(r, CB_FAIL, "STOP: %s; native resources retained",
				xdev_ext_mech_ctl_errname(ret));
		}
	}
	/*
	 * chain_counts of this process's plan, or of the system-wide one
	 * pinned by whoever attached it (concurrent sessions share it, so the
	 * pinned counts cover every session of the campaign).
	 */
	if (plans.iaa_counts_fd < 0 && s->iaa_counts_pin[0]) {
		plans.iaa_counts_fd = bpf_obj_get(s->iaa_counts_pin);
		pinned_counts = plans.iaa_counts_fd >= 0;
		if (!pinned_counts && !r->status)
			cb_fail(r, CB_FAIL, "pinned IAA counters %s: %s", s->iaa_counts_pin,
				strerror(errno));
	}
	if (plans.iaa_counts_fd >= 0) {
		struct { __u64 builds, completes, errors, produced; } cnt = { 0 };
		__u32 key = 0;

		if (!bpf_map_lookup_elem(plans.iaa_counts_fd, &key, &cnt)) {
			r->iaa_completes = (int64_t)cnt.completes;
			r->iaa_errors = (int64_t)cnt.errors;
			r->iaa_scope = pinned_counts ? "system-wide-pin" : "this-process";
		}
		if (pinned_counts)
			close(plans.iaa_counts_fd);
		plans.iaa_counts_fd = -1;
	}
out:
	if (campaign_syscalls)
		r->syscalls = campaign_syscalls;
	if (bounces0 >= 0) {
		int64_t now = cs_bounces();

		r->nvme_bounces = now >= bounces0 ? now - bounces0 : -1;
		if (r->nvme_bounces)
			cb_copy_source(r, CHAIN_COPY_BOUNCE);
	}
	if (ax >= 0 && x.fd >= 0 && !x.zero_copy)
		cb_copy_source(r, CHAIN_COPY_XSK);
	if (!strcmp(r->ce_backend, "ce-sim-cpu-standin"))
		cb_copy_source(r, CHAIN_COPY_CE_SIM);
	for (i = 0; i < s->nr_stages; i++)
		if (s->st[i].cls == CH_IAA && s->st[i].software)
			cb_copy_source(r, CHAIN_COPY_IAA_SW);
	if (unsafe) {
		fprintf(stderr, "chain_bench: STOP failed; leaving the session's memory mapped\n");
		free(ref);
		return r->status;
	}
	if (xdev_ext_xsk_redirect_is_active(&redirect))
		xdev_ext_xsk_redirect_detach(&redirect);
	if (ring >= 0)
		close(ring);
	if (efd >= 0)
		close(efd);
	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++)
		if (fds[i] >= 0)
			close(fds[i]);
	if (s->ce_native && xdev_ext_mech_cuda_close(&ce.cuda) && !r->status)
		cb_fail(r, CB_FAIL, "CUDA allocation cleanup failed");
	cs_xsk_close(&x);
	if (pool)
		munmap(pool, pool_bytes);
	free(user);
	cs_plans_close(&plans);
	if (!r->status && started && s->oracle == CH_ORACLE_FILE)
		chain_oracle_file(s, r);
	free(ref);
	return r->status;
}

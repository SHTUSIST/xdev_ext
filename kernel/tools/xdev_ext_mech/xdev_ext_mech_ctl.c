// SPDX-License-Identifier: GPL-2.0
/*
 * xdev_ext_mech_ctl - control tool of the XDEV_EXT mechanism layer.
 *
 *   attach --obj F --map M --pin P [--set G=V ...]
 *	load F, set .bss/.data globals, attach struct_ops map M, pin its link
 *   detach --pin P
 *	detach the pinned struct_ops link and unpin it
 *   nic-nvme ...	S1 receiver: AF_XDP RX -> NVMe WRITE
 *			(--quiet-wait: no system call per group, MK1)
 *   nvme-nic ...	S2 source: START -> NVMe READ -> AF_XDP TX
 *   ce-chain --chain a|b|c|d ...	S3 chains through copy-engine stages
 *   stats --session ID
 *
 * A run subcommand opens its own io_uring, creates one session with
 * IORING_REGISTER_XDEV_EXT_MECH, prints XDEV_EXT_MECH_READY, waits on the session
 * eventfd (and services the AF_XDP RX ring) until the run ends or times
 * out, then prints its marker line and the stats line.  The marker text
 * and verdicts come from xdev_ext_mech_ctl_core.h.
 *
 * Exit status: 0 PASS, 1 FAIL, 2 usage error, 3 setup error.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include "../../include/uapi/linux/io_uring.h"
#include "../include/xdev_ext_xsk_redirect.h"
#include "../include/xdev_ext_gpu_identity.h"
#include "xdev_ext_mech_cuda.h"
#include "xdev_ext_mech_ctl_core.h"
#include "../../io_uring/xdev_ext_policy.h"
#include "xdev_ext_mech_ctl_fallback.h"

#ifndef AF_XDP
#define AF_XDP			44
#endif
#ifndef SOL_XDP
#define SOL_XDP			283
#endif

enum { CTL_PASS = 0, CTL_FAIL = 1, CTL_USAGE = 2, CTL_SETUP = 3 };

#define CTL_NUM_FRAMES		4096U
#define CTL_RING_SIZE		2048U
#define CTL_MAX_SETS		16U
#define CTL_POLL_MS		1000

#define ctl_err(...)	fprintf(stderr, "xdev_ext_mech_ctl: " __VA_ARGS__)

struct ctl_opts {
	const char *obj, *map, *pin, *detach_pin;
	const char *sets[CTL_MAX_SETS];
	unsigned int nr_sets;
	const char *ifname, *src_ng, *dst_ng, *ce_dev;
 const char *xform_name, *verify_src, *verify_dst;
 __u64 xform_arg, verify_src_off, verify_dst_off, verify_bytes, verify_seg;
	__u64 slba, nlb, dst_slba, dst_nlb, groups, timeout_ms, session;
	__u64 ce_va, ce_len, queue, depth, group_bytes, mtu;
	struct xdev_ext_mech_peer peer;
	char chain;
	__u32 nic_policy;
	bool copy_mode, drv_mode, expect_window_reject, fq_dup, shared_umem_probe;
	bool close_inflight, expect_unbind, expect_timeout, quiet_wait;
	bool have_slba, have_nlb, have_dst_slba, have_dst_nlb, have_session;
	bool have_local_mac, have_peer_mac, have_local_ip, have_peer_ip;
	bool have_local_port, have_peer_port;
	bool ce_alloc, have_ce_va, reliable;
 __u64 wire_session, first_group, remote_window, max_attempts, retry_timeout_ms;
 bool have_policy;
 unsigned int policy_fields;
 struct xdev_ext_rel_policy rel_policy;
};

/* --- struct_ops attach and detach ------------------------------------- */

/* The internal map holding section @sec (".bss" or ".data"). */
static struct bpf_map *ctl_section_map(struct bpf_object *obj, const char *sec)
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

/* Before load: patch global @name in the initial image of its section map. */
static int ctl_set_global(struct bpf_object *obj, const char *name,
			  __u64 value)
{
	static const char *const sections[] = { ".bss", ".data" };
	struct btf *btf = bpf_object__btf(obj);
	unsigned int i;

	if (!btf)
		return -ENOENT;
	for (i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
		const struct btf_var_secinfo *vsi;
		const struct btf_type *sec;
		int id = btf__find_by_name_kind(btf, sections[i],
						BTF_KIND_DATASEC);
		__u16 v;

		if (id < 0)
			continue;
		sec = btf__type_by_id(btf, id);
		vsi = btf_var_secinfos(sec);
		for (v = 0; v < btf_vlen(sec); v++, vsi++) {
			const struct btf_type *var = btf__type_by_id(btf,
								     vsi->type);
			struct bpf_map *map;
			const void *image;
			size_t size;
			void *copy;
			int ret;

			if (strcmp(btf__name_by_offset(btf, var->name_off),
				   name))
				continue;
			map = ctl_section_map(obj, sections[i]);
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
				ret = bpf_map__set_initial_value(map, copy,
								 size);
			free(copy);
			return ret;
		}
	}
	return -ENOENT;
}

static int cmd_attach(struct ctl_opts *o)
{
	struct bpf_object *obj;
	struct bpf_link *link;
	struct bpf_map *map;
	unsigned int i;
	int ret;

	if (!o->obj || !o->map || !o->pin)
		return -EINVAL;
	obj = bpf_object__open_file(o->obj, NULL);
	ret = (int)libbpf_get_error(obj);
	if (ret) {
		ctl_err("open %s: %s\n", o->obj, strerror(-ret));
		return CTL_SETUP;
	}
	/*
	 * Load only the programs of the map being attached: an object holds
	 * one struct_ops map per class, and a program of another class must
	 * not decide whether this one attaches.
	 */
	bpf_object__for_each_map(map, obj) {
		if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS &&
		    strcmp(bpf_map__name(map), o->map))
			bpf_map__set_autocreate(map, false);
	}
	for (i = 0; i < o->nr_sets; i++) {
		char name[64];
		__u64 value;

		ret = xdev_ext_mech_ctl_parse_set(o->sets[i], name, sizeof(name),
					     &value);
		if (!ret)
			ret = ctl_set_global(obj, name, value);
		if (ret) {
			ctl_err("--set %s: %s\n", o->sets[i], strerror(-ret));
			goto close;
		}
	}
	ret = bpf_object__load(obj);
	if (ret) {
		ctl_err("load %s: %s\n", o->obj, strerror(-ret));
		goto close;
	}
	map = bpf_object__find_map_by_name(obj, o->map);
	if (!map) {
		ret = -ENOENT;
		ctl_err("no struct_ops map %s in %s\n", o->map, o->obj);
		goto close;
	}
	link = bpf_map__attach_struct_ops(map);
	ret = (int)libbpf_get_error(link);
	if (ret) {
		ctl_err("attach %s: %s\n", o->map, strerror(-ret));
		goto close;
	}
	ret = bpf_link__pin(link, o->pin);
	if (ret)
		ctl_err("pin %s: %s\n", o->pin, strerror(-ret));
	/* The pin keeps the struct_ops registered after this process. */
	if (!ret)
		bpf_link__disconnect(link);
	bpf_link__destroy(link);
	if (!ret)
		printf("XDEV_EXT_MECH_ATTACH=PASS map=%s pin=%s\n", o->map, o->pin);
close:
	bpf_object__close(obj);
	return ret ? CTL_SETUP : CTL_PASS;
}

/* Detach the struct_ops behind a pinned link, then drop the pin. */
static int ctl_detach_pin(const char *pin)
{
	int fd = bpf_obj_get(pin);
	int ret = 0;

	if (fd < 0)
		return -errno;
	/* An unsupported detach still ends with the last reference below. */
	if (bpf_link_detach(fd) && errno != EOPNOTSUPP && errno != EINVAL)
		ret = -errno;
	if (unlink(pin) && !ret)
		ret = -errno;
	close(fd);
	return ret;
}

static int cmd_detach(struct ctl_opts *o)
{
	int ret;

	if (!o->pin)
		return -EINVAL;
	ret = ctl_detach_pin(o->pin);
	if (ret) {
		ctl_err("detach %s: %s\n", o->pin, strerror(-ret));
		return CTL_SETUP;
	}
	printf("XDEV_EXT_MECH_DETACH=PASS pin=%s\n", o->pin);
	return CTL_PASS;
}

/* --- io_uring and the session ----------------------------------------- */

static int ctl_ring_open(void)
{
	struct io_uring_params p;
	int fd;

	memset(&p, 0, sizeof(p));
	fd = (int)syscall(__NR_io_uring_setup, 8, &p);
	return fd < 0 ? -errno : fd;
}

static int ctl_register(int ring, unsigned int opcode, void *arg)
{
	int ret = (int)syscall(__NR_io_uring_register, ring, opcode, arg, 1);

	return ret < 0 ? -errno : ret;
}

static int ctl_mech(int ring, __u32 op, __u64 arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };

	return ctl_register(ring, IORING_REGISTER_XDEV_EXT_MECH, &req);
}

static int ctl_stats(int ring, __u64 session, struct xdev_ext_mech_stats *s)
{
	memset(s, 0, sizeof(*s));
	s->session_id = session;
	return ctl_mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)s);
}

static int ctl_transport_stats(int ring, __u64 session,
			       struct xdev_ext_mech_transport_stats *s)
{
	*s = (struct xdev_ext_mech_transport_stats) {
		.size = sizeof(*s),
		.version = XDEV_EXT_MECH_TRANSPORT_STATS_VERSION,
		.session_id = session,
	};
	return ctl_mech(ring, XDEV_EXT_MECH_OP_TRANSPORT_STATS, (uintptr_t)s);
}

/* Observational reliable-protocol counters; never part of a PASS decision. */
static int ctl_transport_counters(int ring, __u64 session,
				  struct xdev_ext_mech_transport_stats_v2 *s)
{
	*s = (struct xdev_ext_mech_transport_stats_v2) {
		.v1.size = sizeof(*s),
		.v1.version = XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_2,
		.v1.session_id = session,
	};
	return ctl_mech(ring, XDEV_EXT_MECH_OP_TRANSPORT_STATS, (uintptr_t)s);
}

static int ctl_create(int ring, struct xdev_ext_mech_create *c, __u64 *session)
{
	int ret;

	c->abi_version = XDEV_EXT_MECH_ABI_VERSION;
	ret = ctl_mech(ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)c);
	if (!ret)
		*session = c->session_id;
	return ret;
}

static int ctl_notify_arm(int ring, __u64 session, __u64 groups)
{
	struct xdev_ext_mech_notify_arm arm;
	int ret = xdev_ext_mech_ctl_notify_request(&arm, session, groups);

	if (ret)
		return ret;
	return ctl_mech(ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
}

static int ctl_start(int ring, __u64 session, __u64 groups,
		     const __u32 *user_frames, __u32 nr_user_frames, __u64 first_group)
{
	struct xdev_ext_mech_start st = {
		.session_id = session,
		.nr_batches = groups,
		.first_seq = first_group,
		.flags = user_frames ? XDEV_EXT_MECH_START_F_USER_FRAMES |
				      XDEV_EXT_MECH_START_F_RECYCLE : 0,
		.nr_user_frames = nr_user_frames,
		.user_frames = (uintptr_t)user_frames,
	};

	return ctl_mech(ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st);
}

static void ctl_print_stats(const struct xdev_ext_mech_stats *s)
{
	char line[512];

	if (xdev_ext_mech_ctl_stats_line(line, sizeof(line), s) > 0)
		printf("%s\n", line);
 if (xdev_ext_mech_ctl_remote_outcome_line(line,sizeof(line),s)>0)
  printf("%s\n",line);
}

static int ctl_report(bool pass, const char *line)
{
	printf("%s\n", line);
	return pass ? CTL_PASS : CTL_FAIL;
}

/* --- AF_XDP socket ----------------------------------------------------- */

struct ctl_xring {
	__u32 *producer;
	__u32 *consumer;
	void *descs;
	__u32 mask;
	void *map;
	size_t map_len;
};

struct ctl_xsk {
	int fd;
	bool zero_copy, zc_refused;
	void *umem;
	size_t umem_size;
	struct ctl_xring fq, cq, rx, tx;
};

static int ctl_xring_map(int fd, const struct xdp_ring_offset *off,
			 __u64 pgoff, size_t esize, struct ctl_xring *r)
{
	r->map_len = off->desc + CTL_RING_SIZE * esize;
	r->map = mmap(NULL, r->map_len, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, fd, (off_t)pgoff);
	if (r->map == MAP_FAILED) {
		r->map = NULL;
		return -errno;
	}
	r->producer = (__u32 *)((char *)r->map + off->producer);
	r->consumer = (__u32 *)((char *)r->map + off->consumer);
	r->descs = (char *)r->map + off->desc;
	r->mask = CTL_RING_SIZE - 1;
	return 0;
}

static int ctl_setsockopt_u32(int fd, int opt, __u32 v)
{
	return setsockopt(fd, SOL_XDP, opt, &v, sizeof(v)) ? -errno : 0;
}

/*
 * An explicitly selected AF_XDP socket mode on @ifname/@queue.  The UMEM owner registers an
 * aligned UMEM of 4 KiB chunks with @headroom and maps its fill and
 * completion rings; @rx and @tx add those rings.  With @shared_fd >= 0 the
 * socket binds XDP_SHARED_UMEM onto it instead, and the bind result is the
 * return value.
 */
static int ctl_xsk_open(struct ctl_xsk *x, const char *ifname, __u32 queue,
			__u32 headroom, bool rx, bool tx, int shared_fd,
			bool copy_mode, __u32 pool_frames)
{
	struct sockaddr_xdp sxdp = { .sxdp_family = AF_XDP };
	struct xdp_mmap_offsets off;
	socklen_t optlen = sizeof(off);
	unsigned int ifindex = if_nametoindex(ifname);
	int ret;

	memset(x, 0, sizeof(*x));
	x->fd = -1;
	if (!ifindex)
		return -errno;
	x->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (x->fd < 0)
		return -errno;
	if (shared_fd < 0) {
		struct xdp_umem_reg reg = {
			.len = (__u64)pool_frames * XDEV_EXT_MECH_CTL_FRAME_SIZE,
			.chunk_size = XDEV_EXT_MECH_CTL_FRAME_SIZE,
			.headroom = headroom,
		};

		x->umem_size = reg.len;
		x->umem = mmap(NULL, x->umem_size, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1,
			       0);
		if (x->umem == MAP_FAILED) {
			x->umem = NULL;
			return -errno;
		}
		reg.addr = (uintptr_t)x->umem;
		if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)))
			return -errno;
		ret = ctl_setsockopt_u32(x->fd, XDP_UMEM_FILL_RING,
					 CTL_RING_SIZE);
		if (!ret)
			ret = ctl_setsockopt_u32(x->fd,
						 XDP_UMEM_COMPLETION_RING,
						 CTL_RING_SIZE);
		if (ret)
			return ret;
	}
	if (rx && (ret = ctl_setsockopt_u32(x->fd, XDP_RX_RING, CTL_RING_SIZE)))
		return ret;
	if (tx && (ret = ctl_setsockopt_u32(x->fd, XDP_TX_RING, CTL_RING_SIZE)))
		return ret;
	if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen))
		return -errno;
	if (shared_fd < 0) {
		ret = ctl_xring_map(x->fd, &off.fr, XDP_UMEM_PGOFF_FILL_RING,
				    sizeof(__u64), &x->fq);
		if (!ret)
			ret = ctl_xring_map(x->fd, &off.cr,
					    XDP_UMEM_PGOFF_COMPLETION_RING,
					    sizeof(__u64), &x->cq);
		if (ret)
			return ret;
	}
	if (rx && (ret = ctl_xring_map(x->fd, &off.rx, XDP_PGOFF_RX_RING,
				       sizeof(struct xdp_desc), &x->rx)))
		return ret;
	if (tx && (ret = ctl_xring_map(x->fd, &off.tx, XDP_PGOFF_TX_RING,
				       sizeof(struct xdp_desc), &x->tx)))
		return ret;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;
	if (shared_fd < 0) {
		sxdp.sxdp_flags = xdev_ext_mech_ctl_xsk_flags(copy_mode);
	} else {
		sxdp.sxdp_flags = XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = (__u32)shared_fd;
	}
	if (bind(x->fd, (struct sockaddr *)&sxdp, sizeof(sxdp))) {
		x->zc_refused = !copy_mode && errno == EOPNOTSUPP;
		return -errno;
	}
	{
		struct xdp_options options = {};

		optlen = sizeof(options);
		if (getsockopt(x->fd, SOL_XDP, XDP_OPTIONS, &options, &optlen))
			return -errno;
		x->zero_copy = !!(options.flags & XDP_OPTIONS_ZEROCOPY);
		ret = xdev_ext_mech_ctl_xsk_mode_check(copy_mode, options.flags);
		x->zc_refused = !copy_mode && ret == -EOPNOTSUPP;
	}
	return ret;
}

static void ctl_xring_unmap(struct ctl_xring *r)
{
	if (r->map)
		munmap(r->map, r->map_len);
}

static void ctl_xsk_close(struct ctl_xsk *x)
{
	ctl_xring_unmap(&x->fq);
	ctl_xring_unmap(&x->cq);
	ctl_xring_unmap(&x->rx);
	ctl_xring_unmap(&x->tx);
	if (x->fd >= 0)
		close(x->fd);
	if (x->umem)
		munmap(x->umem, x->umem_size);
	memset(x, 0, sizeof(*x));
	x->fd = -1;
}

/* Put chunk addresses on the fill ring; how many fit. */
static __u32 ctl_fq_push(struct ctl_xring *fq, const __u64 *addr, __u32 n)
{
	__u32 prod = *fq->producer;
	__u32 cons = __atomic_load_n(fq->consumer, __ATOMIC_ACQUIRE);
	__u32 room = fq->mask + 1 - (prod - cons), i;

	if (n > room)
		n = room;
	for (i = 0; i < n; i++)
		((__u64 *)fq->descs)[(prod + i) & fq->mask] = addr[i];
	__atomic_store_n(fq->producer, prod + n, __ATOMIC_RELEASE);
	return n;
}

/* Hand the first ring's worth of chunks to the kernel. */
static int ctl_fq_fill(struct ctl_xsk *x)
{
	__u64 addr[CTL_RING_SIZE];
	__u32 i;

	for (i = 0; i < CTL_RING_SIZE; i++)
		addr[i] = (__u64)i * XDEV_EXT_MECH_CTL_FRAME_SIZE;
	return ctl_fq_push(&x->fq, addr, CTL_RING_SIZE) == CTL_RING_SIZE ?
	       0 : -ENOSPC;
}

/*
 * Published frames go straight back to the fill ring; how many were taken.
 * *@more: descriptors are left, because the batch or the fill ring is full.
 */
static __u32 ctl_rx_recycle(struct ctl_xsk *x, bool *more)
{
	__u32 cons, prod, n, i, done;
	__u64 addr[64];

	*more = false;
	if (!x->rx.map)
		return 0;
	cons = *x->rx.consumer;
	prod = __atomic_load_n(x->rx.producer, __ATOMIC_ACQUIRE);
	n = prod - cons < 64 ? prod - cons : 64;
	for (i = 0; i < n; i++) {
		const struct xdp_desc *d =
			&((struct xdp_desc *)x->rx.descs)[(cons + i) & x->rx.mask];

		addr[i] = d->addr & ~(__u64)(XDEV_EXT_MECH_CTL_FRAME_SIZE - 1);
	}
	done = ctl_fq_push(&x->fq, addr, n);
	__atomic_store_n(x->rx.consumer, cons + done, __ATOMIC_RELEASE);
	*more = prod - cons > done;
	return done;
}

static const char *ctl_nic_path_name(__u32 path)
{
	return path == XDEV_EXT_MECH_CTL_NIC_SOCKET ? "socket" :
		path == XDEV_EXT_MECH_CTL_NIC_AFXDP_ZC ? "zc" : "copy";
}

/* Only the zero-copy bind/mode refusal authorizes substitution. An unrelated
 * allocation, socket setup or permission error preserves its original errno. */
static int ctl_nic_open(struct ctl_xsk *x, const struct ctl_opts *o, __u32 headroom,
			bool rx, __u32 *path)
{
	int err = 0;

	if (xdev_ext_mech_ctl_nic_try_afxdp(o->nic_policy)) {
		err = ctl_xsk_open(x, o->ifname, (__u32)o->queue, headroom,
				   rx || o->reliable, !rx || o->reliable,
				   -1, o->copy_mode, CTL_NUM_FRAMES);
		if (err && !x->zc_refused)
			return err;
	}
	err = xdev_ext_mech_ctl_nic_path(o->nic_policy, o->copy_mode, err,
				       x->zero_copy ? XDP_OPTIONS_ZEROCOPY : 0, path);
	if (!err && *path == XDEV_EXT_MECH_CTL_NIC_SOCKET)
		ctl_xsk_close(x);
	return err;
}

static int ctl_socket_open(const struct ctl_opts *o, bool rx)
{
	struct sockaddr_in local = { .sin_family = AF_INET,
		.sin_addr.s_addr = o->peer.local_ip, .sin_port = o->peer.local_port };
	struct sockaddr_in peer = { .sin_family = AF_INET,
		.sin_addr.s_addr = o->peer.peer_ip, .sin_port = o->peer.peer_port };
	__u64 wanted = o->groups > (32U << 20) / o->group_bytes ?
		64U << 20 : 2 * o->groups * o->group_bytes;
	int fd, err, bytes = wanted < (4U << 20) ? 4 << 20 : (int)wanted;

	if (o->reliable)
		return -EOPNOTSUPP;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (rx && setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bytes, sizeof(bytes)) &&
	    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)))
		goto fail;
	if (bind(fd, (void *)&local, sizeof(local)) ||
	    connect(fd, (void *)&peer, sizeof(peer)))
		goto fail;
	return fd;
fail:
	err = -errno;
	close(fd);
	return err;
}

struct ctl_socket_pool {
	void *addr;
	size_t size;
	__u32 *frames, nr;
};
static int ctl_socket_pool_open(int ring, const struct ctl_opts *o, __u32 frames,
				struct ctl_socket_pool *pool)
{
	__u64 groups = o->groups < o->depth ? o->groups : o->depth;
	struct io_uring_xdev_ext_umem_reg reg = {};
	__u32 i;

	if (!frames || groups > CTL_NUM_FRAMES / frames)
		return -E2BIG;
	pool->nr = groups * frames;
	pool->size = (size_t)pool->nr * XDEV_EXT_MECH_CTL_FRAME_SIZE;
	pool->addr = mmap(NULL, pool->size, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (pool->addr == MAP_FAILED) {
		pool->addr = NULL;
		return -errno;
	}
	pool->frames = calloc(pool->nr, sizeof(*pool->frames));
	if (!pool->frames)
		return -ENOMEM;
	for (i = 0; i < pool->nr; i++)
		pool->frames[i] = i;
	reg.addr = (uintptr_t)pool->addr;
	reg.size = pool->size;
	reg.frame_size = XDEV_EXT_MECH_CTL_FRAME_SIZE;
	return ctl_register(ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg);
}
static void ctl_socket_pool_close(struct ctl_socket_pool *pool)
{
	free(pool->frames);
	if (pool->addr)
		munmap(pool->addr, pool->size);
}
static int ctl_nic_accounting(int ring, __u64 session,
			      struct xdev_ext_mech_transport_stats_v3 *stats)
{
	*stats = (struct xdev_ext_mech_transport_stats_v3) {
		.v2.v1 = { .size = sizeof(*stats),
			.version = XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3,
			.session_id = session },
	};
	return ctl_mech(ring, XDEV_EXT_MECH_OP_TRANSPORT_STATS, (uintptr_t)stats);
}
static void ctl_print_nic_accounting(__u32 path,
				     const struct xdev_ext_mech_transport_stats_v3 *s)
{
	printf("XDEV_EXT_MECH_NIC_ACCOUNTING session=%llu path=%s nic_copy_ops=%llu nic_copy_bytes=%llu nic_zc_ops=%llu nic_zc_bytes=%llu\n",
	       (unsigned long long)s->v2.v1.session_id, ctl_nic_path_name(path),
	       (unsigned long long)s->nic_copy_ops, (unsigned long long)s->nic_copy_bytes,
	       (unsigned long long)s->nic_zc_ops, (unsigned long long)s->nic_zc_bytes);
}

/* The START-driven socket producer uses IOU frame loans, not AF_XDP HOLDs.
 * Preserve the public result marker while checking the actual loan ledger. */
static bool ctl_socket_rx_report(char *line, size_t size,
		const struct xdev_ext_mech_stats *s, __u64 groups,
		__u32 frames, __u32 pool_frames, __u32 nr_stages)
{
	bool pass = s->state == XDEV_EXT_MECH_SESSION_ACTIVE &&
		s->batches_done == groups && !s->batches_abort && !s->last_err &&
		!s->rejects && !s->protocol_err && !s->held &&
		s->published == pool_frames && s->recycled == groups * frames - pool_frames &&
		xdev_ext_mech_ctl_settled(s);
	__u32 i;

	for (i = 0; i < nr_stages; i++)
		pass = pass && s->submitted[i] == groups && s->completed[i] == groups;
	if (nr_stages == 4)
		return xdev_ext_mech_ctl_line(line, size, pass,
			"XDEV_EXT_MECH_NIC_CE_NVME_E2E=%s groups=%llu",
			XDEV_EXT_MECH_CTL_VERDICT(pass), (unsigned long long)groups);
	return xdev_ext_mech_ctl_line(line, size, pass,
		"XDEV_EXT_MECH_NIC_NVME_E2E=%s groups=%llu held=%llu nvme_submitted=%llu nvme_completed=%llu recycled=%llu published=%llu errors=%llu sequestered=%llu inflight=%llu",
		XDEV_EXT_MECH_CTL_VERDICT(pass), (unsigned long long)groups,
		(unsigned long long)s->held, (unsigned long long)s->submitted[1],
		(unsigned long long)s->completed[1], (unsigned long long)s->recycled,
		(unsigned long long)s->published, (unsigned long long)s->batches_abort,
		(unsigned long long)s->sequestered, (unsigned long long)s->inflight);
}

/* --- device facts ------------------------------------------------------ */

static int ctl_if_query(const char *ifname, unsigned long req,
			struct ifreq *ifr)
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

/* The session peer from the options; the local MAC defaults to @ifname's. */
static int ctl_peer(struct ctl_opts *o)
{
	struct ifreq ifr;
	int ret;

	if (!o->have_peer_mac || !o->have_local_ip || !o->have_peer_ip ||
	    !o->have_local_port || !o->have_peer_port)
		return -EINVAL;
	if (o->have_local_mac)
		return 0;
	ret = ctl_if_query(o->ifname, SIOCGIFHWADDR, &ifr);
	if (!ret)
		memcpy(o->peer.local_mac, ifr.ifr_hwaddr.sa_data, 6);
	return ret;
}

/* The NXP layout on @ifname, or on --mtu (default 1500) without a NIC. */
static int ctl_layout(const struct ctl_opts *o, const char *ifname,
		      struct xdev_ext_mech_layout *l, __u32 *frames)
{
	__u32 mtu = (__u32)o->mtu;
	struct ifreq ifr;
	int ret;

	if (ifname) {
		ret = ctl_if_query(ifname, SIOCGIFMTU, &ifr);
		if (ret)
			return ret;
		mtu = (__u32)ifr.ifr_mtu;
	}
	ret = xdev_ext_mech_ctl_layout(mtu, (__u32)o->group_bytes, l);
	if (ret)
		return ret;
 if (o->reliable) {
  if (mtu < 100) return -EINVAL;
  l->hdr_room=384;
  l->seg_len=(mtu-20-8-64)&~7U;
  if (!l->seg_len || l->seg_len>l->frame_size-l->hdr_room ||
      (l->group_bytes-1)/l->seg_len>=32) return -EINVAL;
 }
	*frames = (__u32)xdev_ext_mech_layout_frames(l);
	return 0;
}

/* Preserve the AF_XDP wire contract when only its NIC boundary is replaced. */
static int ctl_nic_nxp_create(const struct ctl_opts *o,
 struct xdev_ext_mech_create *c, __u32 index, int fd)
{
 struct ifreq ifr;
 int err = ctl_if_query(o->ifname, SIOCGIFMTU, &ifr);
 if (err) return err;
 err = xdev_ext_mech_ctl_nic_fallback_create(c, index, fd);
 if (!err) {
  c->st[index].flags = XDEV_EXT_SOCKET_F_NXP;
  c->st[index].arg0 = o->wire_session;
  c->st[index].arg1 = (__u32)ifr.ifr_mtu;
 }
 return err;
}

static void ctl_reliable_config(const struct ctl_opts *o,struct xdev_ext_mech_create *c,
                                struct xdev_ext_afxdp_reliable_policy_config *cfg)
{
 unsigned int i;
 if (!o->reliable) return;
 cfg->finite=(struct xdev_ext_afxdp_reliable_finite_config){.base={.first_group=o->first_group,
  .timeout_ns=o->retry_timeout_ms*1000000ULL,.window=o->remote_window,
  .max_attempts=o->max_attempts},.nr_groups=o->groups};
 for(i=0;i<c->nr_stages;i++) if(c->st[i].class_id==XDEV_EXT_MECH_CLASS_AFXDP) {
  c->st[i].flags|=XDEV_EXT_AFXDP_F_RELIABLE|XDEV_EXT_AFXDP_F_FINITE;
  if (o->have_policy) {
   c->st[i].flags|=XDEV_EXT_AFXDP_F_POLICY;
   cfg->finite.base.window=cfg->finite.base.timeout_ns=cfg->finite.base.max_attempts=0;
   cfg->policy=o->rel_policy;
  }
  c->st[i].arg0=o->wire_session;c->st[i].arg1=(uintptr_t)cfg;
 }
}

static __u64 ctl_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

/* --- waiting ----------------------------------------------------------- */

struct ctl_run {
	int ring;
	int efd;
	__u64 session;
	struct ctl_xsk *xsk;		/* RX ring to service, or NULL */
	__u64 deadline_ns;
	__u64 published_seen;		/* frames taken off the RX ring */
	int poll_ms;			/* longest sleep between two STATS */
	bool defer_stats;		/* reliable finalizer prints the sole final snapshot */
};

/* One final snapshot and one synchronous STOP, for success and failure alike.
 * No PASS marker precedes this boundary. A failed query remains visibly unknown. */
static int ctl_finish_reliable(struct ctl_run *r,
                               const struct xdev_ext_mech_stats *s, int outcome)
{
 struct xdev_ext_mech_transport_stats transport;
 struct xdev_ext_mech_transport_stats_v2 counters;
 int query, stopped;
 __u64 session=r->session;

 ctl_print_stats(s);
 query=ctl_transport_stats(r->ring,session,&transport);
 if (query) {
  transport=(struct xdev_ext_mech_transport_stats){.session_id=session,
   .native_controls=UINT32_MAX,.pending_acks=UINT32_MAX,.uncertain_controls=UINT32_MAX};
  if (!outcome) outcome=query;
 }
 printf("XDEV_EXT_MECH_TRANSPORT session=%llu native_controls=%u pending_acks=%u uncertain_controls=%u\n",
        (unsigned long long)transport.session_id,transport.native_controls,
        transport.pending_acks,transport.uncertain_controls);
 /* A failed counter query is printed as unknown and changes no outcome. */
 if (ctl_transport_counters(r->ring,session,&counters))
  counters=(struct xdev_ext_mech_transport_stats_v2){.retransmits=UINT64_MAX,
   .dup_suppressed=UINT64_MAX,.held_acks=UINT64_MAX,.held_unacked=UINT32_MAX};
 xdev_ext_mech_ctl_print_transport_counters(session,&counters);
 if (!outcome && !xdev_ext_mech_ctl_transport_ok(&transport)) outcome=-EBUSY;
 stopped=ctl_mech(r->ring,XDEV_EXT_MECH_OP_STOP,session);
 printf("XDEV_EXT_MECH_FINALIZE session=%llu stop_ret=%d\n",
        (unsigned long long)session,stopped);
 if (stopped!=-EAGAIN) r->session=0;
 return outcome ?: stopped;
}

typedef bool (*ctl_done_fn)(const struct xdev_ext_mech_stats *s,
			    const struct ctl_run *r, const void *arg);

/*
 * Wait until @done holds, servicing the RX ring and the eventfd; STATS on
 * every wakeup and at least every poll_ms.  The RX ring is not polled while
 * the fill ring has no room for its frames.  0, -ETIMEDOUT or -errno; @s is
 * the last STATS.
 */
static int ctl_wait(struct ctl_run *r, ctl_done_fn done, const void *arg,
		    struct xdev_ext_mech_stats *s)
{
	for (;;) {
		struct pollfd pfd[2] = {
			{ .fd = r->efd, .events = POLLIN },
			{ .fd = r->xsk ? r->xsk->fd : -1, .events = POLLIN },
		};
		__u64 now, left_ms, count;
		bool more = false;
		int ret;

		if (r->xsk)
			r->published_seen += ctl_rx_recycle(r->xsk, &more);
		ret = ctl_stats(r->ring, r->session, s);
		if (ret)
			return ret;
		if (done(s, r, arg))
			return 0;
		now = ctl_now_ns();
		if (now >= r->deadline_ns)
			return -ETIMEDOUT;
		left_ms = (r->deadline_ns - now) / 1000000 + 1;
		if (poll(pfd, r->xsk && !more ? 2 : 1,
			 left_ms < (__u64)r->poll_ms ? (int)left_ms : r->poll_ms) < 0 &&
		    errno != EINTR)
			return -errno;
		if (pfd[0].revents & POLLIN &&
		    read(r->efd, &count, sizeof(count)) < 0 && errno != EAGAIN)
			return -errno;
	}
}

/*
 * The arm precedes admission/readiness, so the eventfd covers completions
 * that race entry into poll.  No intermediate STATS or RX-ring service is
 * needed for a normal kernel-owned campaign.  Always take a final snapshot,
 * including on timeout; a terminal wake alone does not certify a DMA drain.
 */
static int ctl_wait_coarse(struct ctl_run *r, __u64 groups,
			   struct xdev_ext_mech_stats *s)
{
	unsigned int eventfd_reads = 0, stats_reads = 0;
	char line[128];
	int ret = 0, stats_ret;

	for (;;) {
		struct pollfd pfd = { .fd = r->efd, .events = POLLIN };
		__u64 now = ctl_now_ns(), left_ms, count;
		int ready;

		if (now >= r->deadline_ns) {
			ret = -ETIMEDOUT;
			break;
		}
		left_ms = (r->deadline_ns - now) / 1000000 + 1;
		ready = poll(&pfd, 1, left_ms > INT_MAX ? INT_MAX : (int)left_ms);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			break;
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			ret = -EIO;
			break;
		}
		if (pfd.revents & POLLIN) {
			ssize_t n = read(r->efd, &count, sizeof(count));

			if (n == sizeof(count)) {
				eventfd_reads++;
				break;
			}
			if (n < 0 && (errno == EAGAIN || errno == EINTR))
				continue;
			ret = n < 0 ? -errno : -EIO;
			break;
		}
	}
	stats_ret = ctl_stats(r->ring, r->session, s);
	if (!stats_ret)
		stats_reads++;
	if (xdev_ext_mech_ctl_notify_line(line, sizeof(line), eventfd_reads, stats_reads))
		printf("%s\n", line);
	if (!r->defer_stats && !stats_ret &&
	    (ret || xdev_ext_mech_ctl_notify_result(s, groups)))
		ctl_print_stats(s);
	if (stats_ret || ret)
		return stats_ret ? stats_ret : ret;
	return xdev_ext_mech_ctl_notify_result(s, groups);
}

static bool ctl_stopped(const struct xdev_ext_mech_stats *s)
{
	return s->state != XDEV_EXT_MECH_SESSION_ACTIVE &&
	       s->state != XDEV_EXT_MECH_SESSION_ERROR;
}

/* @arg: the number of finished batches to wait for. */
static bool ctl_done_batches(const struct xdev_ext_mech_stats *s,
			     const struct ctl_run *r, const void *arg)
{
	(void)r;
	return s->batches_done + s->batches_abort >= *(const __u64 *)arg ||
	       ctl_stopped(s);
}

static bool ctl_done_timeout(const struct xdev_ext_mech_stats *s,
			     const struct ctl_run *r, const void *arg)
{
	return s->timeouts && !s->inflight && ctl_done_batches(s, r, arg);
}

/* @arg: the number of frames user space must have received. */
static bool ctl_done_published(const struct xdev_ext_mech_stats *s,
			       const struct ctl_run *r, const void *arg)
{
	(void)s;
	return r->published_seen >= *(const __u64 *)arg;
}

static bool ctl_done_stopped(const struct xdev_ext_mech_stats *s,
			     const struct ctl_run *r, const void *arg)
{
	(void)r;
	(void)arg;
	return ctl_stopped(s) && !s->inflight;
}

static bool ctl_done_holding(const struct xdev_ext_mech_stats *s,
			     const struct ctl_run *r, const void *arg)
{
	(void)r;
	(void)arg;
	return s->inflight || s->held > s->recycled;
}

/*
 * The ring of a session is gone: query it through a fresh ring until it
 * settled or was freed.  -ENOENT from STATS means freed.
 */
static int ctl_after_ring_exit(__u64 session, __u64 deadline_ns,
			       struct xdev_ext_mech_stats *s, bool *freed)
{
	int ring = ctl_ring_open();
	int ret;

	if (ring < 0)
		return ring;
	for (;;) {
		ret = ctl_stats(ring, session, s);
		*freed = ret == -ENOENT;
		if (*freed || (!ret && ctl_stopped(s) &&
			       s->state != XDEV_EXT_MECH_SESSION_STOPPING &&
			       (!s->inflight ||
				s->state == XDEV_EXT_MECH_SESSION_ZOMBIE)) ||
		    (ret && ret != -ENOENT) || ctl_now_ns() >= deadline_ns)
			break;
		usleep(10000);
	}
	close(ring);
	return *freed ? 0 : ret;
}

/*
 * --quiet-wait: block once in sigtimedwait() until the harness, which
 * watches this session's eventfd count in /proc/<pid>/fdinfo, sends
 * SIGUSR1 (blocked since before READY) once every group ended, or until the
 * deadline.  Then read the eventfd once and take one STATS.  Should the run
 * not be done, the ordinary wait takes over; the wake line says which.
 */
static int ctl_quiet_wait(struct ctl_run *r, const sigset_t *set,
			  __u64 groups, struct xdev_ext_mech_stats *s)
{
	__u64 now, left, count = 0;
	struct timespec ts;
	bool fallback;
	char line[160];
	int sig, ret;

	do {
		now = ctl_now_ns();
		left = now < r->deadline_ns ? r->deadline_ns - now : 0;
		ts.tv_sec = (time_t)(left / 1000000000ULL);
		ts.tv_nsec = (long)(left % 1000000000ULL);
		sig = sigtimedwait(set, NULL, &ts);
	} while (sig < 0 && errno == EINTR);
	if (sig < 0 && errno != EAGAIN)
		return -errno;
	if (read(r->efd, &count, sizeof(count)) < 0) {
		if (errno != EAGAIN)
			return -errno;
		count = 0;
	}
	ret = ctl_stats(r->ring, r->session, s);
	if (ret)
		return ret;
	fallback = !xdev_ext_mech_ctl_quiet_done(count, groups, s);
	if (xdev_ext_mech_ctl_quiet_wake_line(line, sizeof(line), sig == SIGUSR1,
					 count, fallback))
		printf("%s\n", line);
	if (!fallback)
		return 0;
	return ctl_wait(r, ctl_done_batches, &groups, s);
}

/* A second socket sharing the session socket's UMEM must be refused. */
static int ctl_shared_umem_probe(const struct ctl_opts *o, int session_fd)
{
	struct ctl_xsk probe;
	int ret = ctl_xsk_open(&probe, o->ifname, (__u32)o->queue, 0, true,
			       false, session_fd, o->copy_mode, CTL_NUM_FRAMES);

	ctl_xsk_close(&probe);
	return ret;
}

/* Resolve the opened device, never infer GPU identity from an ordinal. */
static int ctl_cuda_open(struct xdev_ext_mech_cuda *cuda, struct ctl_opts *o, int fd,
			 int other_fd)
{
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE], other_bdf[XDEV_EXT_GPU_PCI_BDF_SIZE];
	int ret;

	if (!o->ce_alloc)
		return 0;
	ret = xdev_ext_gpu_identity_from_opened(fd, o->ce_dev,
					 XDEV_EXT_GPU_IDENTITY_ANY_MINOR, bdf);
	if (ret) {
		ctl_err("GPU identity of %s: %s\n", o->ce_dev, strerror(-ret));
		return ret;
	}
	ret = xdev_ext_gpu_identity_from_opened(other_fd, o->ce_dev,
					 XDEV_EXT_GPU_IDENTITY_ANY_MINOR, other_bdf);
	if (ret || strcasecmp(bdf, other_bdf)) {
		ctl_err("CE stage GPU identities do not match: %s\n",
			ret ? strerror(-ret) : "different PCI BDFs");
		return ret ? ret : -EXDEV;
	}
	ret = xdev_ext_mech_cuda_open(cuda, bdf, o->ce_len);
	if (ret)
		return ret;
	o->ce_va = cuda->va;
	printf("CUDA allocation=native bdf=%s va=0x%llx bytes=%llu\n",
	       bdf, (unsigned long long)cuda->va,
	       (unsigned long long)o->ce_len);
	return 0;
}

static int ctl_cuda_close(struct xdev_ext_mech_cuda *cuda, const struct ctl_opts *o,
			  int verdict)
{
	int ret = xdev_ext_mech_cuda_close(cuda);

	if (o->ce_alloc)
		printf("CUDA allocation=native released=%s\n",
		       ret ? "no" : "yes");
	if (ret) {
		ctl_err("CUDA allocation cleanup: %s\n", strerror(-ret));
		return CTL_SETUP;
	}
	return verdict;
}

/* --- S1: NIC -> NVMe ---------------------------------------------------- */

static int cmd_nic_nvme(struct ctl_opts *o)
{
	struct xdev_ext_xsk_redirect redirect = XDEV_EXT_XSK_REDIRECT_INIT;
	struct xdev_ext_mech_cuda cuda = { 0 };
	struct xdev_ext_mech_create c = { 0 };
 struct xdev_ext_afxdp_reliable_policy_config reliable_config;
	struct xdev_ext_mech_stats s;
	struct xdev_ext_mech_layout l;
	struct ctl_run r = { .ring = -1, .efd = -1, .poll_ms = CTL_POLL_MS,
		.defer_stats = o->reliable };
	struct ctl_xsk x = { .fd = -1 };
	struct ctl_socket_pool pool = {};
	struct xdev_ext_mech_transport_stats_v3 accounting;
	__u32 path = 0;
	int socket_fd = -1;
	char line[512];
	__u32 frames, headroom, pushed = 0;
	__u64 target = o->groups;
	int ng = -1, ce_to = -1, ce_from = -1;
	int ret, verdict = CTL_SETUP, probe = 0;
	bool freed = false;
	unsigned int arms = o->expect_window_reject + o->drv_mode +
			    !!o->detach_pin + o->close_inflight +
			    o->expect_timeout + o->fq_dup;
	bool coarse = !o->quiet_wait && !arms;
	sigset_t quiet_set;

	if ((o->drv_mode && !o->copy_mode) ||
	    !o->ifname || !o->dst_ng || !o->have_slba || !o->have_nlb ||
	    !o->groups || arms > 1 || ctl_peer(o) ||
	    xdev_ext_mech_ctl_quiet_check(o->quiet_wait, true, arms,
				     o->shared_umem_probe))
		return -EINVAL;
	/* Queued, not fatal, whenever the harness sends it. */
	sigemptyset(&quiet_set);
	sigaddset(&quiet_set, SIGUSR1);
	if (o->quiet_wait && sigprocmask(SIG_BLOCK, &quiet_set, NULL)) {
		ctl_err("SIGUSR1: %s\n", strerror(errno));
		return CTL_SETUP;
	}
	ret = ctl_layout(o, o->ifname, &l, &frames);
	if (!ret)
		ret = xdev_ext_mech_ctl_rx_headroom(&l, &headroom);
 if (!ret && o->reliable) headroom=22;
	if (ret) {
		ctl_err("layout on %s: %s\n", o->ifname, strerror(-ret));
		return CTL_SETUP;
	}
	if (o->ce_len && !xdev_ext_mech_ctl_ce_window_ok(o->depth,
						    l.group_bytes, o->ce_len))
		return -ERANGE;
	r.ring = ctl_ring_open();
	r.efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	ng = open(o->dst_ng, O_RDWR | O_CLOEXEC);
	if (r.ring < 0 || r.efd < 0 || ng < 0) {
		ctl_err("ring/eventfd/%s: %s\n", o->dst_ng, strerror(errno));
		goto out;
	}
	ret = ctl_nic_open(&x, o, headroom, true, &path);
	if (ret) {
		ctl_err("AF_XDP socket on %s: %s\n", o->ifname, strerror(-ret));
		goto out;
	}

	if (path == XDEV_EXT_MECH_CTL_NIC_SOCKET) {
		/* AF_XDP fault/probe controls have no equivalent on a UDP socket. */
		if (arms || o->shared_umem_probe) {
			ret = -EOPNOTSUPP;
			goto out;
		}
		socket_fd = ctl_socket_open(o, true);
		if (socket_fd < 0) {
			ret = socket_fd;
			goto out;
		}
		ret = ctl_socket_pool_open(r.ring, o, frames, &pool);
		if (ret)
			goto out;
	}

	if (o->ce_len) {
		ce_to = open(o->ce_dev, O_RDWR | O_CLOEXEC);
		ce_from = open(o->ce_dev, O_RDWR | O_CLOEXEC);
		if (ce_to < 0 || ce_from < 0) {
			ctl_err("CE open: %s\n", strerror(errno));
			goto out;
		}
	}
	ret = ctl_cuda_open(&cuda, o, ce_to, ce_from);
	if (ret)
		goto out;
	ret = xdev_ext_mech_ctl_rx_stages(c.st, socket_fd >= 0 ? socket_fd : x.fd, ng, ce_to, ce_from,
				   o->slba, o->nlb, o->ce_va, o->ce_len);
	if (ret < 0)
		goto out;
	c.nr_stages = ret;
	c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	c.pool_fd = x.fd;
	c.layout = l;
	c.depth = (__u32)o->depth;
	c.eventfd = r.efd;
	c.peer = o->peer;
	ctl_reliable_config(o,&c,&reliable_config);
	if (path == XDEV_EXT_MECH_CTL_NIC_SOCKET) {
		ret = ctl_nic_nxp_create(o, &c, 0, socket_fd);
		if (ret)
			goto out;
	}
 ret = ctl_create(r.ring, &c, &r.session);
	if (ret) {
		ctl_err("CREATE: %s\n", strerror(-ret));
		goto out;
	}
	if (coarse) {
		ret = ctl_notify_arm(r.ring, r.session, o->groups);
		if (ret) {
			ctl_err("NOTIFY_ARM: %s\n", strerror(-ret));
			goto out;
		}
	}
	if (o->shared_umem_probe)
		probe = ctl_shared_umem_probe(o, x.fd);
	ret = path == XDEV_EXT_MECH_CTL_NIC_SOCKET ? 0 : ctl_fq_fill(&x);
	if (!ret && path != XDEV_EXT_MECH_CTL_NIC_SOCKET) {
		const struct xdev_ext_xsk_flow_filter filter = {
			.flags = XDEV_EXT_XSK_FILTER_F_ALL,
			.src_ipv4 = ntohl(o->peer.peer_ip),
			.dst_ipv4 = ntohl(o->peer.local_ip),
			.payload_magic = o->reliable ? 0x4e585033 : XDEV_EXT_MP_NXP_MAGIC,
			.src_port = ntohs(o->peer.peer_port),
			.dst_port = ntohs(o->peer.local_port),
		};

		ret = xdev_ext_xsk_redirect_attach(&redirect, &filter,
					      (int)if_nametoindex(o->ifname),
					      (__u32)o->queue, x.fd,
					      (!o->copy_mode || o->drv_mode) ? XDP_FLAGS_DRV_MODE :
							    XDP_FLAGS_SKB_MODE);
	}
	if (ret) {
		ctl_err("fill ring / XDP redirect on %s: %s\n", o->ifname,
			strerror(-ret));
		goto out;
	}
	if (path == XDEV_EXT_MECH_CTL_NIC_SOCKET) {
		ret = ctl_start(r.ring, r.session, o->groups, pool.frames, pool.nr, 1);
		if (ret)
			goto out;
	}
	if (o->quiet_wait &&
	    xdev_ext_mech_ctl_quiet_line(line, sizeof(line), (int)getpid(), r.efd,
				    o->groups))
		printf("%s\n", line);
	printf("XDEV_EXT_MECH_READY mode=nic-nvme session=%llu frames=%u seg_len=%u xsk=%s%s\n",
	       (unsigned long long)r.session, frames, l.seg_len,
	       ctl_nic_path_name(path),
	       o->ce_alloc ? " ce_allocation=native" : "");
	fflush(stdout);

	r.xsk = path == XDEV_EXT_MECH_CTL_NIC_SOCKET ? NULL : &x;
	r.deadline_ns = ctl_now_ns() + o->timeout_ms * 1000000ULL;
	if (o->quiet_wait) {
		ret = ctl_quiet_wait(&r, &quiet_set, o->groups, &s);
	} else if (coarse) {
		ret = ctl_wait_coarse(&r, o->groups, &s);
	} else if (o->drv_mode) {
		target = o->groups * frames;
		ret = ctl_wait(&r, ctl_done_published, &target, &s);
	} else if (o->detach_pin || o->fq_dup) {
		/* Halfway (or after the first batch) comes the disturbance. */
		__u64 first = o->fq_dup ? 1 : (o->groups + 1) / 2;
		__u64 dup = 0;	/* frame 0: the first fill-ring entry */

		ret = ctl_wait(&r, ctl_done_batches, &first, &s);
		if (!ret && o->fq_dup)
			pushed = ctl_fq_push(&x.fq, &dup, 1);
		if (!ret && o->detach_pin)
			ret = ctl_detach_pin(o->detach_pin);
		if (!ret)
			ret = ctl_wait(&r, o->detach_pin ? ctl_done_stopped :
						      ctl_done_batches,
				       &target, &s);
	} else if (o->close_inflight) {
		/* Catch the session while it holds frames: STATS every 1 ms. */
		r.poll_ms = 1;
		ret = ctl_wait(&r, ctl_done_holding, NULL, &s);
		if (!ret) {
			printf("XDEV_EXT_MECH_RING_EXIT_CLOSE inflight=%llu held=%llu recycled=%llu\n",
			       (unsigned long long)s.inflight,
			       (unsigned long long)s.held,
			       (unsigned long long)s.recycled);
			close(r.ring);
			r.ring = -1;
			ret = ctl_after_ring_exit(r.session, r.deadline_ns, &s,
						  &freed);
		}
	} else {
		ret = ctl_wait(&r, o->expect_timeout ? ctl_done_timeout :
						       ctl_done_batches,
			       &target, &s);
	}
 if (o->reliable) {
  int observed;
  if (!ret) {
   struct timespec linger={.tv_sec=(o->max_attempts*o->retry_timeout_ms)/1000,
      .tv_nsec=((o->max_attempts*o->retry_timeout_ms)%1000)*1000000ULL};
   while (nanosleep(&linger,&linger) && errno==EINTR) { }
  }
  observed=ctl_stats(r.ring,r.session,&s);
  if (!ret) ret=observed;
  if (!ret) ret=xdev_ext_mech_ctl_notify_result(&s,o->groups);
  ret=ctl_finish_reliable(&r,&s,ret);
 }

	if (ret && (coarse || ret != -ETIMEDOUT)) {
		ctl_err("wait: %s\n", strerror(-ret));
		/* Legacy terminal wakes may still precede native drain. */
		if (!o->reliable) {
			__u64 drain_until = ctl_now_ns() + 5000000000ULL;

			do {
				struct xdev_ext_mech_stats final;

				if (ctl_stats(r.ring, r.session, &final))
					break;
				s = final;
				if (!s.inflight)
					break;
				usleep(10000);
			} while (ctl_now_ns() < drain_until);
		}
		if (!o->reliable)
			ctl_print_stats(&s);
		/* Preserve the final snapshot before this releases the session. */
		if (r.session && !o->reliable) {
			int stopped = ctl_mech(r.ring, XDEV_EXT_MECH_OP_STOP, r.session);

			if (o->reliable)
				printf("XDEV_EXT_MECH_FINALIZE session=%llu stop_ret=%d\n",
				       (unsigned long long)r.session, stopped);
			if (stopped != -EAGAIN)
				r.session = 0;
		}
		verdict = CTL_FAIL;
		goto out;
	}
	if (ret)
		ctl_err("timed out after %llu ms\n",
			(unsigned long long)o->timeout_ms);

	if (o->expect_window_reject)
		verdict = ctl_report(xdev_ext_mech_ctl_report_window_reject(
			line, sizeof(line), &s, o->groups), line);
	else if (o->drv_mode)
		verdict = ctl_report(xdev_ext_mech_ctl_report_native_copy(
			line, sizeof(line), &s), line);
	else if (o->detach_pin)
		verdict = ctl_report(xdev_ext_mech_ctl_report_prog_detach(
			line, sizeof(line), &s), line);
	else if (o->close_inflight)
		verdict = ctl_report(xdev_ext_mech_ctl_report_ring_exit(
			line, sizeof(line), freed ? NULL : &s), line);
	else if (o->expect_timeout)
		verdict = ctl_report(xdev_ext_mech_ctl_report_group_timeout(
			line, sizeof(line), &s), line);
	else if (o->fq_dup)
		verdict = ctl_report(xdev_ext_mech_ctl_report_fq_dup(
			line, sizeof(line), &s, o->groups, frames, pushed),
			line);
	else if (path == XDEV_EXT_MECH_CTL_NIC_SOCKET)
		verdict = ctl_report(ctl_socket_rx_report(line, sizeof(line), &s,
			o->groups, frames, pool.nr, c.nr_stages), line);
	else if (o->ce_len)
		verdict = ctl_report(xdev_ext_mech_ctl_report_nic_ce_nvme(
			line, sizeof(line), &s, o->groups, frames), line);
	else
		verdict = ctl_report(xdev_ext_mech_ctl_report_nic_nvme(
			line, sizeof(line), &s, o->groups, frames), line);
	if (o->shared_umem_probe &&
	    ctl_report(xdev_ext_mech_ctl_report_shared_umem(line, sizeof(line),
						       probe), line))
		verdict = CTL_FAIL;
	if (!freed && !o->reliable)
		ctl_print_stats(&s);
	if (!freed) {
		if (ctl_nic_accounting(r.ring, r.session, &accounting))
			verdict = CTL_FAIL;
		else
			ctl_print_nic_accounting(path, &accounting);
	}
out:
	if (xdev_ext_xsk_redirect_is_active(&redirect))
		xdev_ext_xsk_redirect_detach(&redirect);
	if (r.ring >= 0) {
		if (o->ce_alloc && r.session)
			ctl_mech(r.ring, XDEV_EXT_MECH_OP_STOP, r.session);
		close(r.ring);
	}
	ctl_xsk_close(&x);
	if (socket_fd >= 0)
		close(socket_fd);
	ctl_socket_pool_close(&pool);
	if (ce_from >= 0)
		close(ce_from);
	if (ce_to >= 0)
		close(ce_to);
	if (ng >= 0)
		close(ng);
	if (r.efd >= 0)
		close(r.efd);
	return ctl_cuda_close(&cuda, o, verdict);
}

/* --- S2 and S3: source sessions ----------------------------------------- */

/*
 * Pattern of chain d: every byte of the user frames, so a stray write in
 * the header room shows as well as a lost one in a data span.
 */
static __u8 ctl_pattern(__u32 frame, __u32 off)
{
	return (__u8)(frame * 131U + off * 7U + 0x5aU);
}

struct ctl_source {
	const struct ctl_opts *o;
	const char *ifname;		/* AF_XDP TX stage, or NULL */
	struct xdev_ext_mech_stage_uapi st[XDEV_EXT_MECH_MAX_STAGES];
	__u32 nr_stages;
	bool iou_umem;			/* pool: the ring's XDEV_EXT UMEM */
	bool user_pattern;		/* chain d: user fills and compares */
	__u32 nic_path;
	struct xdev_ext_mech_transport_stats_v3 accounting;
};

/*
 * Run a source session: CREATE, hand frames over (fill ring or START user
 * frames), START @o->groups batches, wait for all of them.  *@frames_ok is
 * the compare of chain d.
 */
static int ctl_run_source(struct ctl_source *src, struct xdev_ext_mech_stats *s,
			  bool *frames_ok)
{
	const struct ctl_opts *o = src->o;
	struct xdev_ext_mech_create c = { 0 };
 struct xdev_ext_afxdp_reliable_policy_config reliable_config;
	struct xdev_ext_mech_layout l;
	struct ctl_run r = { .ring = -1, .efd = -1, .poll_ms = CTL_POLL_MS,
		.defer_stats = o->reliable };
	struct ctl_xsk x = { .fd = -1 };
 struct xdev_ext_xsk_redirect redirect = XDEV_EXT_XSK_REDIRECT_INIT;
	__u32 *user = NULL, frames, nr_user = 0, i, j;
	__u64 target = o->groups;
	void *umem = NULL;
	size_t umem_size;
	__u64 pool_groups = o->groups < o->depth ? o->groups : o->depth;
	int ret, socket_fd = -1;
	bool iou_umem = src->iou_umem;

	*frames_ok = true;
	ret = ctl_layout(o, src->ifname, &l, &frames);
	if (ret)
		return ret;
	if (pool_groups > CTL_NUM_FRAMES / frames)
		return -E2BIG;
	umem_size = (size_t)pool_groups * frames * XDEV_EXT_MECH_CTL_FRAME_SIZE;
	r.ring = ctl_ring_open();
	r.efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (r.ring < 0 || r.efd < 0) {
		ret = -errno;
		goto out;
	}
	if (src->ifname) {
		ret = ctl_nic_open(&x, o, 0, false, &src->nic_path);
		if (ret)
			goto out;
		if (src->nic_path == XDEV_EXT_MECH_CTL_NIC_SOCKET) {
			socket_fd = ctl_socket_open(o, false);
			if (socket_fd < 0) {
				ret = socket_fd;
				goto out;
			}
			iou_umem = true;
		}
	}
	if (iou_umem) {
		struct io_uring_xdev_ext_umem_reg reg = {
			.size = umem_size,
			.frame_size = XDEV_EXT_MECH_CTL_FRAME_SIZE,
		};

		umem = mmap(NULL, umem_size, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		if (umem == MAP_FAILED) {
			umem = NULL;
			ret = -errno;
			goto out;
		}
		reg.addr = (uintptr_t)umem;
		ret = ctl_register(r.ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg);
		if (ret)
			goto out;
		nr_user = (__u32)(pool_groups * frames);
		user = calloc(nr_user, sizeof(*user));
		if (!user) {
			ret = -ENOMEM;
			goto out;
		}
		for (i = 0; i < nr_user; i++) {
			user[i] = i;
			if (src->user_pattern)
				for (j = 0; j < XDEV_EXT_MECH_CTL_FRAME_SIZE; j++)
					((__u8 *)umem)[(size_t)i *
						XDEV_EXT_MECH_CTL_FRAME_SIZE + j] =
						ctl_pattern(i, j);
		}
		c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
		c.pool_fd = -1;
	} else {
		/* Fixed XSK pool includes RX, source and reliable control partitions. */
		c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
		c.pool_fd = x.fd;
		for (i = 0; i < src->nr_stages; i++)
			if (src->st[i].class_id == XDEV_EXT_MECH_CLASS_AFXDP)
				src->st[i].fd = x.fd;
	}
	c.nr_stages = src->nr_stages;
	c.layout = l;
	c.depth = (__u32)o->depth;
	c.eventfd = r.efd;
	c.peer = o->peer;
	memcpy(c.st, src->st, sizeof(c.st));
	ctl_reliable_config(o,&c,&reliable_config);
	if (src->nic_path == XDEV_EXT_MECH_CTL_NIC_SOCKET) {
		ret = ctl_nic_nxp_create(o, &c, c.nr_stages - 1, socket_fd);
		if (ret)
			goto out;
	}
 ret = ctl_create(r.ring, &c, &r.session);
	if (ret)
		goto out;
	if (!o->expect_unbind) {
		ret = ctl_notify_arm(r.ring, r.session, o->groups);
		if (ret)
			goto out;
	}
	if (!iou_umem) {
		ret = x.zero_copy && !o->reliable ? 0 : ctl_fq_fill(&x);
  if (!ret && o->reliable) {
   const struct xdev_ext_xsk_flow_filter filter={.flags=XDEV_EXT_XSK_FILTER_F_ALL,
    .src_ipv4=ntohl(o->peer.peer_ip),.dst_ipv4=ntohl(o->peer.local_ip),
    .payload_magic=0x4e585033,.src_port=ntohs(o->peer.peer_port),
    .dst_port=ntohs(o->peer.local_port)};
   ret=xdev_ext_xsk_redirect_attach(&redirect,&filter,(int)if_nametoindex(src->ifname),(__u32)o->queue,
                               x.fd,XDP_FLAGS_DRV_MODE);
  }
		if (ret)
			goto out;
	}
	printf("XDEV_EXT_MECH_READY mode=source session=%llu frames=%u seg_len=%u xsk=%s%s\n",
	       (unsigned long long)r.session, frames, l.seg_len,
	       src->nic_path ? ctl_nic_path_name(src->nic_path) : "none",
	       o->ce_alloc ? " ce_allocation=native" : "");
	fflush(stdout);
	ret = ctl_start(r.ring, r.session, o->groups, user, nr_user, o->reliable ? o->first_group : 1);
	if (ret)
		goto out;
	r.deadline_ns = ctl_now_ns() + o->timeout_ms * 1000000ULL;
	ret = o->expect_unbind ?
		ctl_wait(&r, ctl_done_stopped, &target, s) :
		ctl_wait_coarse(&r, o->groups, s);
	if (o->reliable) {
		int observed = ctl_stats(r.ring, r.session, s);

		if (!ret)
			ret = observed;
		if (!ret)
			ret = xdev_ext_mech_ctl_notify_result(s, o->groups);
		ret = ctl_finish_reliable(&r, s, ret);
	}

	if (ret == -ETIMEDOUT) {
		ctl_err("timed out after %llu ms\n",
			(unsigned long long)o->timeout_ms);
		if (o->expect_unbind)
			ret = 0;
	}
	for (i = 0; !ret && src->user_pattern && i < nr_user; i++)
		for (j = 0; *frames_ok && j < XDEV_EXT_MECH_CTL_FRAME_SIZE; j++)
			*frames_ok = ((__u8 *)umem)[(size_t)i *
				XDEV_EXT_MECH_CTL_FRAME_SIZE + j] == ctl_pattern(i, j);
	if (!ret && !o->expect_unbind && iou_umem)
		*frames_ok = *frames_ok && s->published == nr_user &&
			s->recycled >= (o->groups - pool_groups) * frames &&
			s->recycled < o->groups * frames;
	if (!ret && src->nic_path)
		ret = ctl_nic_accounting(r.ring, r.session, &src->accounting);
out:
	if (r.ring >= 0) {
		if (o->ce_alloc && r.session)
			ctl_mech(r.ring, XDEV_EXT_MECH_OP_STOP, r.session);
		close(r.ring);
	}
	if (r.efd >= 0)
		close(r.efd);
	if (xdev_ext_xsk_redirect_is_active(&redirect)) xdev_ext_xsk_redirect_detach(&redirect);
 ctl_xsk_close(&x);
	if (socket_fd >= 0)
		close(socket_fd);
	free(user);
	if (umem)
		munmap(umem, umem_size);
	return ret;
}

static int cmd_nvme_nic(struct ctl_opts *o)
{
	struct ctl_source src = { .o = o, .ifname = o->ifname, .nr_stages = 2 };
	struct xdev_ext_mech_stats s;
	char line[512];
	bool frames_ok;
	int src_ng, ret, verdict;

	if (!o->ifname || !o->src_ng || !o->have_slba || !o->have_nlb ||
	    !o->groups || ctl_peer(o))
		return -EINVAL;
	src_ng = open(o->src_ng, O_RDONLY | O_CLOEXEC);
	if (src_ng < 0) {
		ctl_err("%s: %s\n", o->src_ng, strerror(errno));
		return CTL_SETUP;
	}
	src.st[0] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = src_ng,
		.arg0 = o->slba, .arg1 = o->nlb,
	};
	src.st[1] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
	};
	ret = ctl_run_source(&src, &s, &frames_ok);
	close(src_ng);
	if (ret) {
		ctl_err("source session: %s\n", strerror(-ret));
		return CTL_SETUP;
	}
	if (o->expect_unbind)
		verdict = ctl_report(xdev_ext_mech_ctl_report_unbind(
			line, sizeof(line), &s), line);
	else
		verdict = ctl_report(xdev_ext_mech_ctl_report_nvme_nic(
			line, sizeof(line), &s, o->groups), line);
	if (!o->reliable)
		ctl_print_stats(&s);
	if (src.nic_path)
		ctl_print_nic_accounting(src.nic_path, &src.accounting);
	return verdict;
}


/* Both commands share the existing one-shot CREATE/START/wait path. */
static int ctl_new_chain(struct ctl_opts *o,bool fanout)
{
 struct ctl_source src={.o=o,.ifname=o->ifname,.nr_stages=3,.iou_umem=!o->ifname};
 struct xdev_ext_mech_stats stats={0};__u32 xform=0;bool frames_ok=false,ok;
 int source=-1,dest=-1,ret;
 char line[512];
 if(!o->src_ng || !o->have_slba || !o->have_nlb || !o->nlb || !o->groups ||
    (fanout && (!o->ifname || !o->dst_ng)) ||
    (!fanout && ((!o->ifname)==(!o->dst_ng))) ||
    (o->dst_ng && (!o->have_dst_slba || !o->have_dst_nlb || !o->dst_nlb)) ||
    (o->ifname && ctl_peer(o)) ||
    (!fanout && xdev_ext_mech_ctl_xform_parse(o->xform_name,&xform)))return -EINVAL;
 source=open(o->src_ng,O_RDONLY|O_CLOEXEC);
 if(source<0){ret=-errno;goto out;}
 if(o->dst_ng){dest=open(o->dst_ng,O_RDWR|O_CLOEXEC);if(dest<0){ret=-errno;goto out;}}
 if(fanout)
  ret=xdev_ext_mech_ctl_fanout_stages(src.st,source,o->slba,o->nlb,dest,o->dst_slba,o->dst_nlb,0);
 else
  ret=xdev_ext_mech_ctl_cpu_stages(src.st,source,o->slba,o->nlb,xform,o->xform_arg,
      o->ifname?XDEV_EXT_MECH_CLASS_AFXDP:XDEV_EXT_MECH_CLASS_NVME,
      o->ifname?0:dest,o->ifname?0:o->dst_slba,o->ifname?0:o->dst_nlb);
 if(ret<0)goto out;
 ret=ctl_run_source(&src,&stats,&frames_ok);
 ok=!ret && frames_ok && !xdev_ext_mech_ctl_notify_result(&stats,o->groups);
 xdev_ext_mech_ctl_report_chain(line,sizeof(line),ok,fanout,o->xform_name,!!o->ifname);
 puts(line);
 ctl_print_stats(&stats);
 if(!ret)ret=ok?CTL_PASS:CTL_FAIL;
 out:
 if(source>=0)close(source);
 if(dest>=0)close(dest);
 if(ret<0){ctl_err("chain: %s\n",strerror(-ret));return CTL_SETUP;}
 return ret;
}
static int cmd_fanout(struct ctl_opts *o){return ctl_new_chain(o,true);}
static int cmd_cpu_chain(struct ctl_opts *o){return ctl_new_chain(o,false);}

/* O_DIRECT reads must retain their block alignment after short reads. A short
 * result is a failed comparison, never an implicit buffered-I/O fallback. */
static int ctl_verify_read(int fd,void *buf,size_t size,__u64 off)
{
 ssize_t got;
 do {got=pread(fd,buf,size,(off_t)off);}while(got<0 && errno==EINTR);
 return got<0?-errno:(size_t)got==size?0:-EIO;
}
static int cmd_verify_xform(struct ctl_opts *o)
{
 __u8 *source=NULL,*actual=NULL,*expected=NULL;__u32 xform=0,length=0;
 __u64 cap,rounded,mismatches=0;int in=-1,out=-1,ret=CTL_SETUP,error;
 char line[512];
 bool identity=o->xform_name && !strcmp(o->xform_name,"none");
 if(!o->verify_src || !o->verify_dst || !o->verify_bytes || !o->verify_seg ||
    o->verify_seg>UINT32_MAX || o->verify_bytes>UINT32_MAX ||
    ((o->verify_src_off|o->verify_dst_off|o->verify_bytes)&511) ||
    o->verify_src_off>INT64_MAX-o->verify_bytes ||
    (!identity && xdev_ext_mech_ctl_xform_parse(o->xform_name,&xform)))return -EINVAL;
 cap=o->verify_bytes+((o->verify_bytes-1)/o->verify_seg+1+
     (o->group_bytes?(o->verify_bytes-1)/o->group_bytes:0))*32;
 if(cap>UINT32_MAX || o->verify_dst_off>INT64_MAX-cap-511)return -EINVAL;
 rounded=(cap+511)&~511ULL;
 if(posix_memalign((void**)&source,4096,o->verify_bytes) ||
    posix_memalign((void**)&actual,4096,rounded) || !(expected=malloc(cap))){error=-ENOMEM;goto done;}
 in=open(o->verify_src,O_RDONLY|O_CLOEXEC|O_DIRECT);
 out=open(o->verify_dst,O_RDONLY|O_CLOEXEC|O_DIRECT);
 if(in<0 || out<0){error=-errno;goto done;}
 error=ctl_verify_read(in,source,o->verify_bytes,o->verify_src_off);if(error)goto done;
 if(identity){memcpy(expected,source,o->verify_bytes);length=o->verify_bytes;}
 else {
  /* The final frame of each batch can be short: restart segmentation at
   * every group boundary, exactly as the pool layout does. */
  __u32 offset=0;
  if(!o->group_bytes){error=-EINVAL;goto done;}
  while(offset<o->verify_bytes){
   __u32 n=o->verify_bytes-offset<o->group_bytes?o->verify_bytes-offset:o->group_bytes,produced=0;
   error=xdev_ext_mech_ctl_xform_expect(xform,o->xform_arg,o->verify_seg,source+offset,n,expected+length,cap-length,&produced);
   if(error)goto done;
   offset+=n;length+=produced;
  }
 }
 error=ctl_verify_read(out,actual,((__u64)length+511)&~511ULL,o->verify_dst_off);if(error)goto done;
 for(__u32 i=0;i<length;i++)mismatches+=actual[i]!=expected[i];
 ret=mismatches?CTL_FAIL:CTL_PASS;error=0;
 done:
 xdev_ext_mech_ctl_report_verify(line,sizeof(line),ret==CTL_PASS,
  o->xform_name?o->xform_name:"invalid",length,mismatches);
 puts(line);
 if(error)ctl_err("verify: %s\n",strerror(-error));
 if(in>=0)close(in);
 if(out>=0)close(out);
 free(source);free(actual);free(expected);return ret;
}

static int cmd_ce_chain(struct ctl_opts *o)
{
	struct xdev_ext_mech_cuda cuda = { 0 };
	struct ctl_source src = { .o = o };
	const char *base = strrchr(o->ce_dev, '/');
	struct xdev_ext_mech_stats s;
	char line[512];
	int fds[4] = { -1, -1, -1, -1 };
	int ret, verdict = CTL_SETUP;
	bool frames_ok, nic = o->chain == 'b' || o->chain == 'c';
	__u32 n = 0, i;

	if (o->chain < 'a' || o->chain > 'd' || !o->groups || !o->ce_len ||
	    (nic && (!o->ifname || ctl_peer(o))) ||
	    (o->chain != 'd' && (!o->src_ng || !o->have_slba || !o->have_nlb)) ||
	    (o->chain == 'a' && (!o->dst_ng || !o->have_dst_slba ||
				 !o->have_dst_nlb)))
		return -EINVAL;
	if (!xdev_ext_mech_ctl_ce_window_ok(o->depth, o->group_bytes, o->ce_len))
		return -ERANGE;
	if (o->chain != 'd') {
		fds[0] = open(o->src_ng, O_RDONLY | O_CLOEXEC);
		src.st[n++] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_NVME,
			.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = fds[0],
			.arg0 = o->slba, .arg1 = o->nlb,
		};
	}
	/* One open per CE stage: each stage binds its own region. */
	fds[1] = open(o->ce_dev, O_RDWR | O_CLOEXEC);
	fds[2] = open(o->ce_dev, O_RDWR | O_CLOEXEC);
	if (fds[1] < 0 || fds[2] < 0) {
		ctl_err("CE open: %s\n", strerror(errno));
		goto out;
	}
	ret = ctl_cuda_open(&cuda, o, fds[1], fds[2]);
	if (ret)
		goto out;
	src.st[n++] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_CE,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = fds[1],
		.arg0 = o->ce_va, .arg1 = o->ce_len,
	};
	src.st[n++] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_CE,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = fds[2],
		.arg0 = o->ce_va, .arg1 = o->ce_len,
	};
	if (o->chain == 'a') {
		fds[3] = open(o->dst_ng, O_RDWR | O_CLOEXEC);
		src.st[n++] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_NVME,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = fds[3],
			.arg0 = o->dst_slba, .arg1 = o->dst_nlb,
		};
	} else if (nic) {
		src.st[n++] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_AFXDP,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
		};
		src.ifname = o->ifname;
	}
	for (i = 0; i < 4; i++) {
		if (fds[i] < 0 && (i == 1 || i == 2 ||
				   (i == 0 && o->chain != 'd') ||
				   (i == 3 && o->chain == 'a'))) {
			ctl_err("open: %s\n", strerror(errno));
			goto out;
		}
	}
	src.nr_stages = n;
	src.iou_umem = !nic;
	src.user_pattern = o->chain == 'd';
	ret = ctl_run_source(&src, &s, &frames_ok);
	if (ret) {
		ctl_err("chain %c: %s\n", o->chain, strerror(-ret));
		goto out;
	}
	verdict = ctl_report(xdev_ext_mech_ctl_report_ce_chain(
		line, sizeof(line), &s, o->chain, o->groups, n,
		!strncmp(base ? base + 1 : o->ce_dev, "xdev_ext_ce_sim", 10),
		frames_ok), line);
	if (!o->reliable)
		ctl_print_stats(&s);
	if (src.nic_path)
		ctl_print_nic_accounting(src.nic_path, &src.accounting);
out:
	for (i = 0; i < 4; i++)
		if (fds[i] >= 0)
			close(fds[i]);
	return ctl_cuda_close(&cuda, o, verdict);
}

static int cmd_stats(struct ctl_opts *o)
{
	struct xdev_ext_mech_stats s;
	int ring, ret;

	if (!o->have_session)
		return -EINVAL;
	ring = ctl_ring_open();
	if (ring < 0) {
		ctl_err("io_uring: %s\n", strerror(-ring));
		return CTL_SETUP;
	}
	ret = ctl_stats(ring, o->session, &s);
	close(ring);
	if (ret) {
		ctl_err("STATS %llu: %s\n", (unsigned long long)o->session,
			strerror(-ret));
		return CTL_SETUP;
	}
	ctl_print_stats(&s);
	return CTL_PASS;
}

/* --- command line ------------------------------------------------------- */

enum {
	OPT_OBJ = 256, OPT_MAP, OPT_PIN, OPT_SET, OPT_IFNAME, OPT_QUEUE,
	OPT_DRV_MODE, OPT_SRC_NG, OPT_DST_NG, OPT_SLBA, OPT_NLB, OPT_DST_SLBA,
	OPT_DST_NLB, OPT_GROUPS, OPT_DEPTH, OPT_GROUP_BYTES, OPT_MTU,
	OPT_TIMEOUT_MS, OPT_LOCAL_MAC, OPT_PEER_MAC, OPT_LOCAL_IP, OPT_PEER_IP,
	OPT_LOCAL_PORT, OPT_PEER_PORT, OPT_CE_DEV, OPT_CE_VA, OPT_CE_LEN,
	OPT_CHAIN, OPT_SESSION, OPT_WINDOW_REJECT, OPT_DETACH_MID_RUN,
	OPT_FQ_DUP, OPT_SHARED_UMEM, OPT_CLOSE_INFLIGHT, OPT_EXPECT_UNBIND,
	OPT_EXPECT_TIMEOUT, OPT_QUIET_WAIT, OPT_COPY, OPT_NIC_FALLBACK, OPT_CE_ALLOC,
 OPT_RELIABLE, OPT_WIRE_SESSION, OPT_FIRST_GROUP, OPT_REMOTE_WINDOW,
 OPT_MAX_ATTEMPTS, OPT_RETRY_TIMEOUT,
 OPT_XFORM, OPT_XFORM_ARG, OPT_VERIFY_SRC, OPT_VERIFY_DST, OPT_VERIFY_SRC_OFF,
 OPT_VERIFY_DST_OFF, OPT_VERIFY_BYTES, OPT_VERIFY_SEG,
 OPT_REL_WINDOW, OPT_REL_INITIAL_CREDIT, OPT_REL_RTO_US, OPT_REL_RTO_MAX_US,
 OPT_REL_BACKOFF, OPT_REL_MAX_ATTEMPTS, OPT_REL_ACK_EVERY, OPT_REL_ACK_DELAY_US,
 OPT_REL_ACK_RULE, OPT_REL_RESEND_ORDER,
};

static const struct option ctl_options[] = {
 { "xform", required_argument, NULL, OPT_XFORM },
 { "xform-arg", required_argument, NULL, OPT_XFORM_ARG },
 { "src", required_argument, NULL, OPT_VERIFY_SRC },
 { "dst", required_argument, NULL, OPT_VERIFY_DST },
 { "src-off", required_argument, NULL, OPT_VERIFY_SRC_OFF },
 { "dst-off", required_argument, NULL, OPT_VERIFY_DST_OFF },
 { "bytes", required_argument, NULL, OPT_VERIFY_BYTES },
 { "seg-len", required_argument, NULL, OPT_VERIFY_SEG },
 { "rel-window", required_argument, NULL, OPT_REL_WINDOW },
 { "rel-initial-credit", required_argument, NULL, OPT_REL_INITIAL_CREDIT },
 { "rel-rto-us", required_argument, NULL, OPT_REL_RTO_US },
 { "rel-rto-max-us", required_argument, NULL, OPT_REL_RTO_MAX_US },
 { "rel-backoff", required_argument, NULL, OPT_REL_BACKOFF },
 { "rel-max-attempts", required_argument, NULL, OPT_REL_MAX_ATTEMPTS },
 { "rel-ack-every", required_argument, NULL, OPT_REL_ACK_EVERY },
 { "rel-ack-delay-us", required_argument, NULL, OPT_REL_ACK_DELAY_US },
 { "rel-ack-rule", required_argument, NULL, OPT_REL_ACK_RULE },
 { "rel-resend-order", required_argument, NULL, OPT_REL_RESEND_ORDER },

 { "reliable", no_argument, NULL, OPT_RELIABLE },
 { "wire-session", required_argument, NULL, OPT_WIRE_SESSION },
 { "first-group", required_argument, NULL, OPT_FIRST_GROUP },
 { "remote-window", required_argument, NULL, OPT_REMOTE_WINDOW },
 { "max-attempts", required_argument, NULL, OPT_MAX_ATTEMPTS },
 { "retry-timeout-ms", required_argument, NULL, OPT_RETRY_TIMEOUT },
	{ "obj", required_argument, NULL, OPT_OBJ },
	{ "map", required_argument, NULL, OPT_MAP },
	{ "pin", required_argument, NULL, OPT_PIN },
	{ "set", required_argument, NULL, OPT_SET },
	{ "ifname", required_argument, NULL, OPT_IFNAME },
	{ "queue", required_argument, NULL, OPT_QUEUE },
	{ "drv-mode", no_argument, NULL, OPT_DRV_MODE },
	{ "copy", no_argument, NULL, OPT_COPY },
	{ "nic-fallback", required_argument, NULL, OPT_NIC_FALLBACK },
	{ "src-ng", required_argument, NULL, OPT_SRC_NG },
	{ "dst-ng", required_argument, NULL, OPT_DST_NG },
	{ "slba", required_argument, NULL, OPT_SLBA },
	{ "nlb", required_argument, NULL, OPT_NLB },
	{ "dst-slba", required_argument, NULL, OPT_DST_SLBA },
	{ "dst-nlb", required_argument, NULL, OPT_DST_NLB },
	{ "groups", required_argument, NULL, OPT_GROUPS },
	{ "depth", required_argument, NULL, OPT_DEPTH },
	{ "group-bytes", required_argument, NULL, OPT_GROUP_BYTES },
	{ "mtu", required_argument, NULL, OPT_MTU },
	{ "timeout-ms", required_argument, NULL, OPT_TIMEOUT_MS },
	{ "local-mac", required_argument, NULL, OPT_LOCAL_MAC },
	{ "peer-mac", required_argument, NULL, OPT_PEER_MAC },
	{ "local-ip", required_argument, NULL, OPT_LOCAL_IP },
	{ "peer-ip", required_argument, NULL, OPT_PEER_IP },
	{ "local-port", required_argument, NULL, OPT_LOCAL_PORT },
	{ "peer-port", required_argument, NULL, OPT_PEER_PORT },
	{ "ce-dev", required_argument, NULL, OPT_CE_DEV },
	{ "ce-va", required_argument, NULL, OPT_CE_VA },
	{ "ce-alloc", no_argument, NULL, OPT_CE_ALLOC },
	{ "ce-len", required_argument, NULL, OPT_CE_LEN },
	{ "chain", required_argument, NULL, OPT_CHAIN },
	{ "session", required_argument, NULL, OPT_SESSION },
	{ "expect-window-reject", no_argument, NULL, OPT_WINDOW_REJECT },
	{ "detach-mid-run", required_argument, NULL, OPT_DETACH_MID_RUN },
	{ "fq-dup", no_argument, NULL, OPT_FQ_DUP },
	{ "shared-umem-probe", no_argument, NULL, OPT_SHARED_UMEM },
	{ "close-inflight", no_argument, NULL, OPT_CLOSE_INFLIGHT },
	{ "expect-unbind", no_argument, NULL, OPT_EXPECT_UNBIND },
	{ "expect-timeout", no_argument, NULL, OPT_EXPECT_TIMEOUT },
	{ "quiet-wait", no_argument, NULL, OPT_QUIET_WAIT },
	{ "help", no_argument, NULL, 'h' },
	{ NULL, 0, NULL, 0 },
};

static void usage(FILE *f)
{
	fprintf(f,
"usage: xdev_ext_mech_ctl attach --obj FILE --map NAME --pin PATH [--set G=V]...\n"
"       xdev_ext_mech_ctl detach --pin PATH\n"
"       xdev_ext_mech_ctl nic-nvme --ifname IF --dst-ng NG --slba N --nlb N PEER\n"
"                [--expect-window-reject | --drv-mode | --fq-dup |\n"
"                 --detach-mid-run PIN | --close-inflight | --expect-timeout]\n"
"                [--shared-umem-probe | --quiet-wait] [COMMON]\n"
"                [--ce-dev DEV (--ce-va VA | --ce-alloc) --ce-len N] (RX -> CE -> CE -> NVMe)\n"
"       xdev_ext_mech_ctl nvme-nic --ifname IF --src-ng NG --slba N --nlb N PEER\n"
"                [--expect-unbind] [COMMON]\n"
"       xdev_ext_mech_ctl ce-chain --chain a|b|c|d [--ce-dev DEV] --ce-len N\n"
"                [--ce-va N | --ce-alloc] [--src-ng NG --slba N --nlb N]\n"
"                [--dst-ng NG --dst-slba N --dst-nlb N] [--ifname IF PEER]\n"
"                [COMMON]\n"
"       xdev_ext_mech_ctl fanout --src-ng NG --slba N --nlb N\n"
"                --dst-ng NG --dst-slba N --dst-nlb N --ifname IF PEER [COMMON]\n"
"       xdev_ext_mech_ctl cpu-chain --xform NAME [--xform-arg N]\n"
"                --src-ng NG --slba N --nlb N\n"
"                (--dst-ng NG --dst-slba N --dst-nlb N | --ifname IF PEER) [COMMON]\n"
"       xdev_ext_mech_ctl verify-xform --xform NAME|none [--xform-arg N]\n"
"                --seg-len N --src DEV --src-off N --dst DEV --dst-off N --bytes N\n"
"       xdev_ext_mech_ctl stats --session ID\n"
"PEER:   --peer-mac M --local-ip A --peer-ip A --local-port P --peer-port P\n"
"        [--local-mac M] [--queue Q]\n"
"RELIABLE: --reliable [--wire-session N] [--first-group N] [--remote-window N]\n"
" [--max-attempts N] [--retry-timeout-ms N] (ACK means chain completion)\n"
"POLICY: --rel-window N --rel-initial-credit N --rel-rto-us N --rel-rto-max-us N\n"
" --rel-backoff fixed|exponential --rel-max-attempts N --rel-ack-every N\n"
" --rel-ack-delay-us N --rel-ack-rule each|every-n|delayed\n"
" --rel-resend-order slot|oldest|round-robin (requires --reliable)\n"
"COMMON: [--groups N] [--depth N] [--group-bytes N] [--mtu N]\n"
"        [--timeout-ms N] [--copy] [--nic-fallback auto|off|force]\n"
"        auto: socket on ZC refusal; off: require ZC; force: socket (NXP2; reliable mode refused)\n"
"CUDA:   --ce-alloc requires a real GPU --ce-dev; allocates once before CREATE\n"
"chains: a NVMe READ -> CE H2D -> CE D2H -> NVMe WRITE (XDEV_EXT UMEM)\n"
"        b NVMe READ -> CE H2D -> CE D2H -> AF_XDP TX (AF_XDP UMEM)\n"
"        c as b, received by a nic-nvme session\n"
"        d user frames -> CE H2D -> CE D2H, compared by user space\n");
}

static int parse_u64_opt(const char *arg, __u64 *v, bool *have)
{
	if (xdev_ext_mech_ctl_parse_u64(arg, v))
		return -EINVAL;
	if (have)
		*have = true;
	return 0;
}

static int parse_ip(const char *arg, __be32 *ip, bool *have)
{
	if (inet_pton(AF_INET, arg, ip) != 1)
		return -EINVAL;
	*have = true;
	return 0;
}

static int parse_port(const char *arg, __be16 *port, bool *have)
{
	__u64 v;

	if (xdev_ext_mech_ctl_parse_u64(arg, &v) || !v || v > 0xffff)
		return -EINVAL;
	*port = htons((__u16)v);
	*have = true;
	return 0;
}

/* CLI only: remember explicitly supplied fields, resolve dependent defaults once. */
static int ctl_rel_policy_option(struct ctl_opts *o,int opt,const char *arg)
{
 struct xdev_ext_rel_policy *p=&o->rel_policy;
 __u64 value=0;
 unsigned bit;
 if (opt<OPT_REL_WINDOW || opt>OPT_REL_RESEND_ORDER) return -ENOENT;
 bit=opt-OPT_REL_WINDOW;
 if (!o->have_policy) xdev_ext_rel_policy_defaults(p);
 if (opt==OPT_REL_BACKOFF) {
  if (!strcmp(arg,"fixed")) value=XDEV_EXT_REL_BACKOFF_FIXED;
  else if (!strcmp(arg,"exponential")) value=XDEV_EXT_REL_BACKOFF_EXPONENTIAL;
  else return -EINVAL;
 } else if (opt==OPT_REL_ACK_RULE) {
  if (!strcmp(arg,"each")) value=XDEV_EXT_REL_ACK_EACH;
  else if (!strcmp(arg,"every-n")) value=XDEV_EXT_REL_ACK_EVERY_N;
  else if (!strcmp(arg,"delayed")) value=XDEV_EXT_REL_ACK_DELAYED;
  else return -EINVAL;
 } else if (opt==OPT_REL_RESEND_ORDER) {
  if (!strcmp(arg,"slot")) value=XDEV_EXT_REL_RESEND_SLOT;
  else if (!strcmp(arg,"oldest")) value=XDEV_EXT_REL_RESEND_OLDEST;
  else if (!strcmp(arg,"round-robin")) value=XDEV_EXT_REL_RESEND_ROUND_ROBIN;
  else return -EINVAL;
 } else if (parse_u64_opt(arg,&value,NULL)) return -EINVAL;
 if (opt==OPT_REL_RTO_US || opt==OPT_REL_RTO_MAX_US || opt==OPT_REL_ACK_DELAY_US) {
  if (value>UINT64_MAX/1000) return -EINVAL;
  value*=1000;
 } else if (value>UINT32_MAX) return -EINVAL;
 switch(opt) {
 case OPT_REL_WINDOW:p->window=value;break;
 case OPT_REL_INITIAL_CREDIT:p->initial_credit=value;break;
 case OPT_REL_RTO_US:p->rto_ns=value;break;
 case OPT_REL_RTO_MAX_US:p->rto_max_ns=value;break;
 case OPT_REL_BACKOFF:p->backoff=value;break;
 case OPT_REL_MAX_ATTEMPTS:p->max_attempts=value;break;
 case OPT_REL_ACK_EVERY:p->ack_every=value;break;
 case OPT_REL_ACK_DELAY_US:p->ack_delay_ns=value;break;
 case OPT_REL_ACK_RULE:p->ack_rule=value;break;
 case OPT_REL_RESEND_ORDER:p->resend_order=value;break;
 }
 o->have_policy=true; o->policy_fields |= 1U<<bit;
 return 0;
}
static int ctl_rel_policy_finish(struct ctl_opts *o)
{
 struct xdev_ext_rel_policy *p=&o->rel_policy;
 __u32 field;
 if (!o->have_policy) return 0;
 if (o->remote_window>UINT32_MAX || o->max_attempts>UINT32_MAX ||
     o->retry_timeout_ms>UINT64_MAX/1000000ULL) return -EINVAL;
#define CTL_POLICY_GIVEN(opt) (o->policy_fields & (1U<<((opt)-OPT_REL_WINDOW)))
 if (!CTL_POLICY_GIVEN(OPT_REL_WINDOW)) p->window=o->remote_window;
 if (!CTL_POLICY_GIVEN(OPT_REL_INITIAL_CREDIT)) p->initial_credit=p->window;
 if (!CTL_POLICY_GIVEN(OPT_REL_RTO_US)) p->rto_ns=o->retry_timeout_ms*1000000ULL;
 if (!CTL_POLICY_GIVEN(OPT_REL_MAX_ATTEMPTS)) p->max_attempts=o->max_attempts;
 if (!CTL_POLICY_GIVEN(OPT_REL_ACK_EVERY))
  p->ack_every=p->ack_rule==XDEV_EXT_REL_ACK_DELAYED ? 0 : 1;
#undef CTL_POLICY_GIVEN
 if (xdev_ext_rel_policy_validate(p,&field)) {
  ctl_err("invalid reliable policy field %u\n",field); return -EINVAL;
 }
 o->remote_window=p->window; o->max_attempts=p->max_attempts;
 o->retry_timeout_ms=(p->rto_ns+999999ULL)/1000000ULL;
 return 0;
}

static int parse_options(int argc, char **argv, struct ctl_opts *o)
{
	int opt, ret = 0;

	o->groups = 64;
	o->depth = XDEV_EXT_POLICY_DEFAULT_DEPTH;
 o->wire_session=270019;o->first_group=1;o->max_attempts=XDEV_EXT_REL_POLICY_DEFAULT_MAX_ATTEMPTS;
 o->retry_timeout_ms=XDEV_EXT_REL_POLICY_DEFAULT_RTO_NS/1000000ULL;
	o->group_bytes = 8192;
	o->mtu = 1500;
	o->timeout_ms = 60000;
	o->ce_dev = "/dev/xdev_ext_ce_sim";
	o->ce_len = !strcmp(argv[0], "nic-nvme") ? 0 : 1U << 20;
	optind = 1;
	while (!ret && (opt = getopt_long(argc, argv, "h", ctl_options,
					  NULL)) != -1) {
  if (opt>=OPT_REL_WINDOW && opt<=OPT_REL_RESEND_ORDER) {
   ret=ctl_rel_policy_option(o,opt,optarg); continue;
  }
		switch (opt) {
  case OPT_XFORM:o->xform_name=optarg;break;
  case OPT_XFORM_ARG:ret=parse_u64_opt(optarg,&o->xform_arg,NULL);break;
  case OPT_VERIFY_SRC:o->verify_src=optarg;break;
  case OPT_VERIFY_DST:o->verify_dst=optarg;break;
  case OPT_VERIFY_SRC_OFF:ret=parse_u64_opt(optarg,&o->verify_src_off,NULL);break;
  case OPT_VERIFY_DST_OFF:ret=parse_u64_opt(optarg,&o->verify_dst_off,NULL);break;
  case OPT_VERIFY_BYTES:ret=parse_u64_opt(optarg,&o->verify_bytes,NULL);break;
  case OPT_VERIFY_SEG:ret=parse_u64_opt(optarg,&o->verify_seg,NULL);break;
  case OPT_RELIABLE:o->reliable=true;break;
  case OPT_WIRE_SESSION:ret=parse_u64_opt(optarg,&o->wire_session,NULL);break;
  case OPT_FIRST_GROUP:ret=parse_u64_opt(optarg,&o->first_group,NULL);break;
  case OPT_REMOTE_WINDOW:ret=parse_u64_opt(optarg,&o->remote_window,NULL);break;
  case OPT_MAX_ATTEMPTS:ret=parse_u64_opt(optarg,&o->max_attempts,NULL);break;
  case OPT_RETRY_TIMEOUT:ret=parse_u64_opt(optarg,&o->retry_timeout_ms,NULL);break;
		case OPT_OBJ: o->obj = optarg; break;
		case OPT_MAP: o->map = optarg; break;
		case OPT_PIN: o->pin = optarg; break;
		case OPT_SET:
			if (o->nr_sets == CTL_MAX_SETS)
				ret = -E2BIG;
			else
				o->sets[o->nr_sets++] = optarg;
			break;
		case OPT_IFNAME: o->ifname = optarg; break;
		case OPT_QUEUE: ret = parse_u64_opt(optarg, &o->queue, NULL);
			break;
		case OPT_DRV_MODE: o->drv_mode = true; break;
		case OPT_COPY: o->copy_mode = true; break;
		case OPT_NIC_FALLBACK: ret = xdev_ext_mech_ctl_nic_policy_parse(optarg, &o->nic_policy); break;
		case OPT_SRC_NG: o->src_ng = optarg; break;
		case OPT_DST_NG: o->dst_ng = optarg; break;
		case OPT_SLBA:
			ret = parse_u64_opt(optarg, &o->slba, &o->have_slba);
			break;
		case OPT_NLB:
			ret = parse_u64_opt(optarg, &o->nlb, &o->have_nlb);
			break;
		case OPT_DST_SLBA:
			ret = parse_u64_opt(optarg, &o->dst_slba,
					    &o->have_dst_slba);
			break;
		case OPT_DST_NLB:
			ret = parse_u64_opt(optarg, &o->dst_nlb,
					    &o->have_dst_nlb);
			break;
		case OPT_GROUPS: ret = parse_u64_opt(optarg, &o->groups, NULL);
			break;
		case OPT_DEPTH: ret = parse_u64_opt(optarg, &o->depth, NULL);
			break;
		case OPT_GROUP_BYTES:
			ret = parse_u64_opt(optarg, &o->group_bytes, NULL);
			break;
		case OPT_MTU: ret = parse_u64_opt(optarg, &o->mtu, NULL); break;
		case OPT_TIMEOUT_MS:
			ret = parse_u64_opt(optarg, &o->timeout_ms, NULL);
			break;
		case OPT_LOCAL_MAC:
			ret = xdev_ext_mech_ctl_parse_mac(optarg, o->peer.local_mac);
			o->have_local_mac = !ret;
			break;
		case OPT_PEER_MAC:
			ret = xdev_ext_mech_ctl_parse_mac(optarg, o->peer.peer_mac);
			o->have_peer_mac = !ret;
			break;
		case OPT_LOCAL_IP:
			ret = parse_ip(optarg, &o->peer.local_ip,
				       &o->have_local_ip);
			break;
		case OPT_PEER_IP:
			ret = parse_ip(optarg, &o->peer.peer_ip,
				       &o->have_peer_ip);
			break;
		case OPT_LOCAL_PORT:
			ret = parse_port(optarg, &o->peer.local_port,
					 &o->have_local_port);
			break;
		case OPT_PEER_PORT:
			ret = parse_port(optarg, &o->peer.peer_port,
					 &o->have_peer_port);
			break;
		case OPT_CE_DEV: o->ce_dev = optarg; break;
		case OPT_CE_ALLOC: o->ce_alloc = true; break;
		case OPT_CE_VA: ret = parse_u64_opt(optarg, &o->ce_va, &o->have_ce_va);
			break;
		case OPT_CE_LEN: ret = parse_u64_opt(optarg, &o->ce_len, NULL);
			break;
		case OPT_CHAIN:
			o->chain = optarg[0];
			ret = optarg[0] && !optarg[1] ? 0 : -EINVAL;
			break;
		case OPT_SESSION:
			ret = parse_u64_opt(optarg, &o->session,
					    &o->have_session);
			break;
		case OPT_WINDOW_REJECT: o->expect_window_reject = true; break;
		case OPT_DETACH_MID_RUN: o->detach_pin = optarg; break;
		case OPT_FQ_DUP: o->fq_dup = true; break;
		case OPT_SHARED_UMEM: o->shared_umem_probe = true; break;
		case OPT_CLOSE_INFLIGHT: o->close_inflight = true; break;
		case OPT_EXPECT_UNBIND: o->expect_unbind = true; break;
		case OPT_EXPECT_TIMEOUT: o->expect_timeout = true; break;
		case OPT_QUIET_WAIT: o->quiet_wait = true; break;
		case 'h':
			usage(stdout);
			exit(CTL_PASS);
		default:
			ret = -EINVAL;
			break;
		}
	}
	if (!ret && (optind != argc || !o->depth || o->depth > 0xffffffffULL ||
		     o->queue > 0xffffffffULL || o->group_bytes > 0xffffffffULL ||
		     o->mtu > 0xffffffffULL || !o->timeout_ms ||
		     o->timeout_ms > 86400000ULL))
		ret = -EINVAL;
 if (o->have_policy && !o->reliable) ret=-EINVAL;
 if (o->reliable) {
  if (!o->remote_window) o->remote_window=o->depth;
  if (!ret) ret=ctl_rel_policy_finish(o);
  if (!o->wire_session || !o->first_group || !o->remote_window ||
      o->remote_window>32 || o->remote_window>o->depth || o->copy_mode ||
      !o->max_attempts || o->max_attempts>0xffffffffULL ||
      !o->retry_timeout_ms || o->retry_timeout_ms>86400000ULL ||
      (!o->have_policy && o->max_attempts*o->retry_timeout_ms>o->timeout_ms) ||
      o->first_group>~0ULL-o->remote_window ||
      o->groups>~0ULL-o->first_group-o->remote_window) ret=-EINVAL;
 }
	if (!ret && o->ce_alloc) {
		char canonical[PATH_MAX];
		const char *device;
		const char *minor_text;

		if (o->have_ce_va || !o->ce_len ||
		    (strcmp(argv[0], "ce-chain") && strcmp(argv[0], "nic-nvme")) ||
		    !xdev_ext_mech_ctl_ce_window_ok(o->depth, o->group_bytes, o->ce_len)) {
			ctl_err("--ce-alloc requires a CE chain, nonzero window, and no --ce-va\n");
			return -EINVAL;
		}
		/* Symlinks are accepted; opened-fd identity remains authoritative. */
		device = realpath(o->ce_dev, canonical);
		if (!device)
			device = o->ce_dev;
		if (strncmp(device, "/dev/nvidia", 11))
			return -EINVAL;
		minor_text = device + 11;
		if (!*minor_text)
			return -EINVAL;
		for (; *minor_text; minor_text++)
			if (*minor_text < '0' || *minor_text > '9')
				return -EINVAL;
	}
	return ret;
}

static const struct {
	const char *name;
	int (*run)(struct ctl_opts *o);
} ctl_commands[] = {
	{ "attach", cmd_attach },
	{ "detach", cmd_detach },
	{ "nic-nvme", cmd_nic_nvme },
	{ "nvme-nic", cmd_nvme_nic },
	{ "ce-chain", cmd_ce_chain },
 { "fanout", cmd_fanout },
 { "cpu-chain", cmd_cpu_chain },
 { "verify-xform", cmd_verify_xform },
	{ "stats", cmd_stats },
};

/*
 * libbpf warnings, with a rejected program's verifier log cut to its head
 * and tail: the guest console is a serial line, and a full log of a large
 * program takes long enough to print that the guest reports soft lockups.
 */
#define CTL_LOG_HEAD_LINES	8
#define CTL_LOG_TAIL_LINES	60

static int ctl_libbpf_print(enum libbpf_print_level level, const char *fmt,
			    va_list args)
{
	const char *p, *tail;
	unsigned int lines = 0, skip;
	char *text;
	int len;

	if (level == LIBBPF_DEBUG)
		return 0;
	len = vasprintf(&text, fmt, args);
	if (len < 0)
		return len;
	for (p = text; *p; p++)
		lines += *p == '\n';
	if (lines <= CTL_LOG_HEAD_LINES + CTL_LOG_TAIL_LINES) {
		fputs(text, stderr);
		free(text);
		return len;
	}
	for (p = text, skip = CTL_LOG_HEAD_LINES; skip; p++)
		skip -= *p == '\n';
	fwrite(text, 1, p - text, stderr);
	for (tail = text + len, skip = CTL_LOG_TAIL_LINES + 1; tail > p; tail--)
		if (tail[-1] == '\n' && !--skip)
			break;
	fprintf(stderr, "... %u log lines omitted ...\n",
		lines - CTL_LOG_HEAD_LINES - CTL_LOG_TAIL_LINES);
	fputs(tail, stderr);
	free(text);
	return len;
}

int main(int argc, char **argv)
{
	struct ctl_opts o;
	unsigned int i;
	int ret;

	libbpf_set_print(ctl_libbpf_print);
	memset(&o, 0, sizeof(o));
	if (argc < 2) {
		usage(stderr);
		return CTL_USAGE;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		usage(stdout);
		return CTL_PASS;
	}
	for (i = 0; i < sizeof(ctl_commands) / sizeof(ctl_commands[0]); i++) {
		if (strcmp(argv[1], ctl_commands[i].name))
			continue;
		if (parse_options(argc - 1, argv + 1, &o) ||
		    xdev_ext_mech_ctl_quiet_check(o.quiet_wait,
					     !strcmp(argv[1], "nic-nvme"), 0,
					     false)) {
			usage(stderr);
			return CTL_USAGE;
		}
		ret = ctl_commands[i].run(&o);
		if (ret < 0) {
			usage(stderr);
			return CTL_USAGE;
		}
		return ret;
	}
	usage(stderr);
	return CTL_USAGE;
}

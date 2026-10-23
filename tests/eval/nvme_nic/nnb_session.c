// SPDX-License-Identifier: GPL-2.0
/*
 * Session arm of the NVMe<->NIC eval: one xdev_ext mechanism session per
 * configuration on shared AF_XDP UMEM host pages, created once.
 *   forward  NVMe READ (stage 0, FROM_DEVICE) -> AF_XDP TX (stage 1), like
 *            `xdev_ext_mech_ctl nvme-nic`; START per trial, one eventfd wake.
 *   reverse  AF_XDP RX (stage 0) -> NVMe WRITE (stage 1), like
 *            `xdev_ext_mech_ctl nic-nvme`; the XDP redirect admits only the
 *            peer's NXP2 flow to this arm's port.  One wake per burst.
 * The policy is nnb_bench.bpf.c.  User space issues no per-group system
 * call; a trial ends at the eventfd wake followed by an exact STATS check.
 *
 * Setup helpers adapted from kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c
 * (ctl_section_map, ctl_set_global, ctl_xring_map, ctl_xsk_open,
 * ctl_xsk_close, ctl_fq_fill, ctl_rx_recycle) at product HEAD 8e0238a, and
 * from tests/eval/hft/hft_session.c (attach_maps, stats_ok).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "nnb.h"

#ifdef NNB_HAVE_SESSION
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include "../../../kernel/include/uapi/linux/io_uring.h"
#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"
#include "../../../kernel/tools/include/xdev_ext_xsk_redirect.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#define S_FRAMES	4096U	/* CTL_NUM_FRAMES */
#define S_RING		2048U	/* CTL_RING_SIZE */
#define S_RX_HEADROOM	22U	/* NNB_HDR_ROOM - XDP headroom 256 - 82 */

struct s_ring {
	uint32_t *producer, *consumer;
	void *descs, *map;
	uint32_t mask;
	size_t map_len;
};

struct s_xsk {
	int fd;
	bool zero_copy;
	void *umem;
	size_t umem_size;
	struct s_ring fq, cq, rx, tx;
};

struct spriv {
	struct bpf_object *obj;
	struct bpf_link *links[2];
	struct s_xsk x;
	struct xdev_ext_xsk_redirect redirect;
	int ring, efd, ng, unsafe;
	uint64_t session, done;		/* cumulative batches */
	struct xdev_ext_mech_stats stats;
};

static struct bpf_map *section_map(struct bpf_object *obj, const char *sec)
{
	size_t n = strlen(sec);
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);
		size_t len = strlen(name);

		if (bpf_map__is_internal(map) && len >= n && !strcmp(name + len - n, sec))
			return map;
	}
	return NULL;
}

/* Before load: patch global @name (4 or 8 bytes) in its section image. */
static int set_global(struct bpf_object *obj, const char *name, uint64_t value)
{
	static const char *const sections[] = { ".bss", ".data" };
	struct btf *btf = bpf_object__btf(obj);

	if (!btf)
		return -ENOENT;
	for (unsigned i = 0; i < 2; i++) {
		int id = btf__find_by_name_kind(btf, sections[i], BTF_KIND_DATASEC);
		const struct btf_var_secinfo *vsi;
		const struct btf_type *sec;

		if (id < 0)
			continue;
		sec = btf__type_by_id(btf, id);
		vsi = btf_var_secinfos(sec);
		for (unsigned v = 0; v < btf_vlen(sec); v++, vsi++) {
			const struct btf_type *var = btf__type_by_id(btf, vsi->type);
			struct bpf_map *map;
			const void *image;
			size_t size;
			unsigned char *copy;
			int ret;

			if (strcmp(btf__name_by_offset(btf, var->name_off), name))
				continue;
			map = section_map(obj, sections[i]);
			image = map ? bpf_map__initial_value(map, &size) : NULL;
			if (!image || vsi->offset > size || vsi->size > size - vsi->offset ||
			    (vsi->size != 4 && vsi->size != 8) || (vsi->size == 4 && value > UINT32_MAX))
				return -EINVAL;
			copy = malloc(size);
			if (!copy)
				return -ENOMEM;
			memcpy(copy, image, size);
			for (unsigned j = 0; j < vsi->size; j++)
				copy[vsi->offset + j] = (unsigned char)(value >> (8 * j));
			ret = bpf_map__set_initial_value(map, copy, size);
			free(copy);
			return ret;
		}
	}
	return -ENOENT;
}

static int ring_map(int fd, const struct xdp_ring_offset *off, uint64_t pgoff, size_t esize,
		    struct s_ring *r)
{
	r->map_len = off->desc + S_RING * esize;
	r->map = mmap(NULL, r->map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		      (off_t)pgoff);
	if (r->map == MAP_FAILED) {
		r->map = NULL;
		return -errno;
	}
	r->producer = (uint32_t *)((char *)r->map + off->producer);
	r->consumer = (uint32_t *)((char *)r->map + off->consumer);
	r->descs = (char *)r->map + off->desc;
	r->mask = S_RING - 1;
	return 0;
}

static int set_u32(int fd, int opt, uint32_t v)
{
	return setsockopt(fd, SOL_XDP, opt, &v, sizeof(v)) ? -errno : 0;
}

/* Zero-copy AF_XDP socket owning a UMEM of S_FRAMES 4 KiB chunks. */
static int xsk_open(struct s_xsk *x, const char *ifname, uint32_t queue, uint32_t headroom,
		    bool rx, bool tx)
{
	struct sockaddr_xdp sxdp = { .sxdp_family = AF_XDP, .sxdp_flags = XDP_ZEROCOPY };
	struct xdp_umem_reg reg = { .len = (uint64_t)S_FRAMES * NNB_FRAME_SIZE,
		.chunk_size = NNB_FRAME_SIZE, .headroom = headroom };
	struct xdp_mmap_offsets off;
	struct xdp_options options = { 0 };
	socklen_t optlen = sizeof(off);
	unsigned ifindex = if_nametoindex(ifname);
	int ret;

	memset(x, 0, sizeof(*x));
	x->fd = -1;
	if (!ifindex)
		return -ENODEV;
	x->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (x->fd < 0)
		return errno == EAFNOSUPPORT ? -EOPNOTSUPP : -errno;	/* no AF_XDP: capability */
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
	if ((ret = set_u32(x->fd, XDP_UMEM_FILL_RING, S_RING)) ||
	    (ret = set_u32(x->fd, XDP_UMEM_COMPLETION_RING, S_RING)) ||
	    (rx && (ret = set_u32(x->fd, XDP_RX_RING, S_RING))) ||
	    (tx && (ret = set_u32(x->fd, XDP_TX_RING, S_RING))))
		return ret;
	if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen))
		return -errno;
	if ((ret = ring_map(x->fd, &off.fr, XDP_UMEM_PGOFF_FILL_RING, sizeof(uint64_t), &x->fq)) ||
	    (ret = ring_map(x->fd, &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING, sizeof(uint64_t), &x->cq)) ||
	    (rx && (ret = ring_map(x->fd, &off.rx, XDP_PGOFF_RX_RING, sizeof(struct xdp_desc), &x->rx))) ||
	    (tx && (ret = ring_map(x->fd, &off.tx, XDP_PGOFF_TX_RING, sizeof(struct xdp_desc), &x->tx))))
		return ret;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;
	if (bind(x->fd, (struct sockaddr *)&sxdp, sizeof(sxdp)))
		return -errno;
	optlen = sizeof(options);
	if (getsockopt(x->fd, SOL_XDP, XDP_OPTIONS, &options, &optlen))
		return -errno;
	x->zero_copy = !!(options.flags & XDP_OPTIONS_ZEROCOPY);
	return x->zero_copy ? 0 : -EOPNOTSUPP;	/* no copy-mode substitute */
}

static void ring_unmap(struct s_ring *r)
{
	if (r->map)
		munmap(r->map, r->map_len);
}

static void xsk_close(struct s_xsk *x)
{
	ring_unmap(&x->fq), ring_unmap(&x->cq), ring_unmap(&x->rx), ring_unmap(&x->tx);
	if (x->fd >= 0)
		close(x->fd);
	if (x->umem)
		munmap(x->umem, x->umem_size);
	memset(x, 0, sizeof(*x));
	x->fd = -1;
}

static uint32_t fq_push(struct s_ring *fq, const uint64_t *addr, uint32_t n)
{
	uint32_t prod = *fq->producer, cons = __atomic_load_n(fq->consumer, __ATOMIC_ACQUIRE);
	uint32_t room = fq->mask + 1 - (prod - cons);

	if (n > room)
		n = room;
	for (uint32_t i = 0; i < n; i++)
		((uint64_t *)fq->descs)[(prod + i) & fq->mask] = addr[i];
	__atomic_store_n(fq->producer, prod + n, __ATOMIC_RELEASE);
	return n;
}

/* Foreign frames the program published go straight back to the fill ring. */
static void rx_recycle(struct s_xsk *x)
{
	uint32_t cons = *x->rx.consumer, prod = __atomic_load_n(x->rx.producer, __ATOMIC_ACQUIRE);
	uint32_t n = prod - cons < 64 ? prod - cons : 64, done;
	uint64_t addr[64];

	for (uint32_t i = 0; i < n; i++)
		addr[i] = ((struct xdp_desc *)x->rx.descs)[(cons + i) & x->rx.mask].addr &
			  ~(uint64_t)(NNB_FRAME_SIZE - 1);
	done = fq_push(&x->fq, addr, n);
	__atomic_store_n(x->rx.consumer, cons + done, __ATOMIC_RELEASE);
}

static int mech(int ring, unsigned op, uint64_t arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };
	int n = (int)syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);

	return n < 0 ? -errno : n;
}

static int parse_mac(const char *s, unsigned char *out)
{
	unsigned v[6];
	char extra;

	if (!s || sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5],
			 &extra) != 6)
		return -EINVAL;
	for (unsigned i = 0; i < 6; i++)
		out[i] = (unsigned char)v[i];
	return 0;
}

static int attach(struct nnb_arm *a, struct spriv *p)
{
	static const char *const names[2] = { "nnb_nvme_ops", "nnb_afxdp_ops" };
	int err;

	p->obj = bpf_object__open_file(a->c->bpf_object, NULL);
	err = (int)libbpf_get_error(p->obj);
	if (err) {
		p->obj = NULL;
		return err;
	}
	if (set_global(p->obj, "nnb_session", a->wire_session))
		return -EINVAL;
	if (bpf_object__load(p->obj))
		return -EOPNOTSUPP;
	for (unsigned i = 0; i < 2; i++) {
		struct bpf_map *map = bpf_object__find_map_by_name(p->obj, names[i]);

		if (!map || bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
			return -EPROTO;
		p->links[i] = bpf_map__attach_struct_ops(map);
		err = (int)libbpf_get_error(p->links[i]);
		if (err) {
			p->links[i] = NULL;
			return err;
		}
	}
	return 0;
}

static int session_setup(struct nnb_arm *a)
{
	const struct nnb_cfg *c = a->c;
	const struct nnb_geom *g = a->g;
	struct spriv *p = calloc(1, sizeof(*p));
	struct xdev_ext_mech_create create = { 0 };
	struct io_uring_params params = { 0 };
	uint64_t depth = (uint64_t)c->qd * g->groups_per_unit;
	int ret;

	if (!p)
		return -ENOMEM;
	a->priv = p;
	p->ring = p->efd = p->ng = -1;
	p->x.fd = -1;
	p->redirect = (struct xdev_ext_xsk_redirect)XDEV_EXT_XSK_REDIRECT_INIT;
	/* XDEV_EXT_MECH_MAX_DEPTH bounds live batches; recorded, never hidden. */
	a->session_depth = (uint32_t)(depth > NNB_SESSION_MAX_DEPTH ? NNB_SESSION_MAX_DEPTH : depth);
	a->effective_qd = (a->session_depth + g->groups_per_unit - 1) / g->groups_per_unit;
	/* Rounded-up units hide a shortfall (4 MiB, qd 1: 64 x 32 KiB): record the bytes. */
	a->inflight_bytes = (uint64_t)a->session_depth * g->group;
	if (!c->ifname || !c->ng || !c->bpf_object || !c->local_mac || !c->peer_mac) {
		nnb_diag(a, "session needs --ifname --ng --bpf-object --local-mac --peer-mac");
		return -EINVAL;
	}
	p->ng = open(c->ng, (c->reverse ? O_RDWR : O_RDONLY) | O_CLOEXEC);
	p->ring = (int)syscall(__NR_io_uring_setup, 8, &params);
	p->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (p->ng < 0 || p->ring < 0 || p->efd < 0) {
		nnb_diag(a, "ng/ring/eventfd: %s", strerror(errno));
		return -ENODEV;
	}
	ret = attach(a, p);
	if (ret) {
		nnb_diag(a, "load/attach %s: %s", c->bpf_object, strerror(-ret));
		return ret;
	}
	ret = xsk_open(&p->x, c->ifname, c->queue, c->reverse ? S_RX_HEADROOM : 0, c->reverse,
		       !c->reverse);
	a->xsk_zerocopy = p->x.fd >= 0 ? p->x.zero_copy : -1;
	if (ret) {
		nnb_diag(a, "AF_XDP zero-copy socket on %s queue %u: %s", c->ifname, c->queue,
			 strerror(-ret));
		return ret;
	}
	create.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	create.nr_stages = 2;
	create.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	create.pool_fd = p->x.fd;
	create.layout = (struct xdev_ext_mech_layout){ .frame_size = NNB_FRAME_SIZE,
		.hdr_room = NNB_HDR_ROOM, .seg_len = g->seg, .group_bytes = g->group };
	create.depth = a->session_depth;
	create.eventfd = p->efd;
	if (parse_mac(c->local_mac, create.peer.local_mac) ||
	    parse_mac(c->peer_mac, create.peer.peer_mac) ||
	    inet_pton(AF_INET, c->local_ip, &create.peer.local_ip) != 1 ||
	    inet_pton(AF_INET, c->peer_ip, &create.peer.peer_ip) != 1)
		return -EINVAL;
	create.peer.local_port = htons(a->port);
	create.peer.peer_port = htons(c->peer_port);
	if (!c->reverse) {
		create.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
			.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = p->ng,
			.arg0 = c->slba, .arg1 = c->nlb };
		create.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = p->x.fd };
	} else {
		create.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
			.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = p->x.fd };
		create.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = p->ng,
			.arg0 = c->slba, .arg1 = c->nlb };
	}
	/* Strict kernel admission checks native NVMe SGL and every NIC mapping. */
	ret = mech(p->ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&create);
	if (ret) {
		nnb_diag(a, "CREATE: %s", strerror(-ret));
		return ret;
	}
	p->session = create.session_id;
	a->registrations = 1;
	if (c->reverse) {
		const struct xdev_ext_xsk_flow_filter filter = {
			.flags = XDEV_EXT_XSK_FILTER_F_ALL,
			.src_ipv4 = ntohl(create.peer.peer_ip), .dst_ipv4 = ntohl(create.peer.local_ip),
			.payload_magic = NNB_MAGIC,
			.src_port = c->peer_port, .dst_port = a->port,
		};
		uint64_t addr[S_RING];

		for (uint32_t i = 0; i < S_RING; i++)
			addr[i] = (uint64_t)i * NNB_FRAME_SIZE;
		if (fq_push(&p->x.fq, addr, S_RING) != S_RING)
			return -ENOSPC;
		ret = xdev_ext_xsk_redirect_attach(&p->redirect, &filter, (int)if_nametoindex(c->ifname),
						   c->queue, p->x.fd, XDP_FLAGS_DRV_MODE);
		if (ret) {
			nnb_diag(a, "XDP redirect: %s", strerror(-ret));
			return ret;
		}
	}
	return 0;
}

static int stats_ok(struct nnb_arm *a, struct spriv *p, uint64_t target)
{
	const struct xdev_ext_mech_stats *s = &p->stats;
	unsigned nvme = a->c->reverse ? 1 : 0, net = 1 - nvme;

	p->stats = (struct xdev_ext_mech_stats){ .session_id = p->session };
	if (mech(p->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&p->stats))
		return -EIO;
	if (s->state != XDEV_EXT_MECH_SESSION_ACTIVE || s->batches_done != target ||
	    s->batches_abort || s->rejects || s->sequestered || s->timeouts || s->protocol_err ||
	    s->last_err || s->inflight || s->submitted[nvme] != target ||
	    s->completed[nvme] != target || s->submitted[net] != s->completed[net]) {
		nnb_diag(a, "STATS state=%u done=%llu/%llu abort=%llu rejects=%llu timeouts=%llu "
			 "proto=%llu err=%d inflight=%llu", s->state,
			 (unsigned long long)s->batches_done, (unsigned long long)target,
			 (unsigned long long)s->batches_abort, (unsigned long long)s->rejects,
			 (unsigned long long)s->timeouts, (unsigned long long)s->protocol_err,
			 s->last_err, (unsigned long long)s->inflight);
		return -EPROTO;
	}
	return 0;
}

/* One eventfd wake for an absolute batch target; the RX ring is serviced meanwhile. */
static int wait_target(struct nnb_arm *a, struct spriv *p, uint64_t target)
{
	uint64_t deadline = nnb_now() + 20000000000ULL, event;

	for (;;) {
		struct pollfd pfd[2] = { { .fd = p->efd, .events = POLLIN },
					 { .fd = p->x.fd, .events = POLLIN } };
		uint64_t now = nnb_now();
		int n;

		if (now >= deadline)
			return -ETIMEDOUT;
		n = poll(pfd, a->c->reverse ? 2 : 1, (int)((deadline - now) / 1000000 + 1));
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (a->c->reverse && (pfd[1].revents & POLLIN))
			rx_recycle(&p->x);
		if (pfd[0].revents & POLLIN) {
			if (read(p->efd, &event, sizeof(event)) == (ssize_t)sizeof(event))
				return stats_ok(a, p, target);
			if (errno != EAGAIN && errno != EINTR)
				return -errno;
		}
	}
}

static int session_run(struct nnb_arm *a, struct nnb_trial *t)
{
	struct spriv *p = a->priv;
	const struct nnb_geom *g = a->g;
	uint64_t before = p->done;
	int ret = 0;

	if (!a->c->reverse) {
		struct xdev_ext_mech_notify_arm arm = { .session_id = p->session,
			.batches_target = p->done + t->groups };
		struct xdev_ext_mech_start start = { .session_id = p->session,
			.nr_batches = t->groups, .first_seq = t->first_gen };

		ret = mech(p->ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
		/* A failed START cannot prove non-acceptance: treat resources as unknown. */
		if (!ret && (ret = mech(p->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start)))
			p->unsafe = 1;
		if (!ret)
			ret = wait_target(a, p, p->done + t->groups);
		if (!ret) {
			t->t_release = nnb_now();
			p->done += t->groups;
		}
	} else {
		for (uint32_t b = 0; b < t->bursts && !ret; b++) {
			uint64_t u0 = (uint64_t)b * t->burst_units;
			uint64_t n = t->units - u0 < t->burst_units ? t->units - u0 : t->burst_units;
			struct xdev_ext_mech_notify_arm arm = { .session_id = p->session,
				.batches_target = p->done + n * g->groups_per_unit };

			ret = mech(p->ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
			if (!ret)
				ret = nnb_rev_go(a, t, b);
			if (!ret)
				ret = wait_target(a, p, arm.batches_target);
			if (!ret)
				p->done = arm.batches_target;
			if (!ret && b + 1 == t->bursts)
				t->t_release = nnb_now();
			if (!ret)
				ret = nnb_rev_sent(a, t, b);
		}
	}
	t->counts.batches = p->done - before;
	if (a->c->reverse) {
		t->counts.write_ops = t->counts.batches, t->counts.write_bytes = t->counts.batches * g->group;
		t->counts.datagrams = t->counts.batches * g->dgrams;
	} else {
		t->counts.read_ops = t->counts.batches, t->counts.read_bytes = t->counts.batches * g->group;
		t->counts.datagrams = t->counts.batches * g->dgrams;
		t->counts.send_bytes = t->counts.datagrams * NNB_HDR_LEN + t->counts.read_bytes;
	}
	if (ret) {
		char stats[sizeof(a->diag)];

		memcpy(stats, a->diag, sizeof(stats));
		nnb_diag(a, "%.96s%strial %llu: %s", stats, stats[0] ? "; " : "",
			 (unsigned long long)t->trial, strerror(-ret));
	}
	return ret;
}

static void session_teardown(struct nnb_arm *a)
{
	struct spriv *p = a->priv;
	int stop = 0;

	if (!p)
		return;
	if (p->session) {
		stop = mech(p->ring, XDEV_EXT_MECH_OP_STOP, p->session);
		printf("{\"record\":\"teardown\",\"arm\":\"session\",\"stop_ret\":%d}\n", stop);
		fflush(stdout);
	}
	if (stop || p->unsafe) {
		/* UNKNOWN native ownership: keep UMEM, rings and links until exit. */
		fprintf(stderr, "nnb_producer: session STOP %d; native resources retained\n", stop);
		return;
	}
	if (xdev_ext_xsk_redirect_is_active(&p->redirect))
		xdev_ext_xsk_redirect_detach(&p->redirect);
	xsk_close(&p->x);
	if (p->ring >= 0)
		close(p->ring);
	if (p->efd >= 0)
		close(p->efd);
	if (p->ng >= 0)
		close(p->ng);
	for (unsigned i = 0; i < 2; i++)
		if (p->links[i])
			bpf_link__destroy(p->links[i]);
	if (p->obj)
		bpf_object__close(p->obj);
	free(p);
	a->priv = NULL;
}
#else
static int session_setup(struct nnb_arm *a)
{
	nnb_diag(a, "built without the session backend (make ENABLE_SESSION=1)");
	return -EOPNOTSUPP;
}
static int session_run(struct nnb_arm *a, struct nnb_trial *t) { (void)a; (void)t; return -EOPNOTSUPP; }
static void session_teardown(struct nnb_arm *a) { (void)a; }
#endif

const struct nnb_arm_ops nnb_session_ops = { "session", session_setup, session_run, session_teardown };

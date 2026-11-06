// SPDX-License-Identifier: GPL-2.0
/*
 * libxdev_ext gives a transmit-only zero-copy XSK session XDP mode before
 * CREATE, as xdev_ext_mech_ctl does, and owns what it attached until close.
 *
 * Real code: the library session steps, xdev_ext_xsk_redirect_zc_tx_xdp()
 * and the pass-program helper.  Simulated: the operating system boundary
 * only.  AF_XDP socket calls, sendto(), mmap() and libbpf's BPF and netlink
 * calls are link-time wrapped; io_uring goes through the library's own test
 * hook.  The simulated driver refuses a TX wakeup without XDP with the
 * scenario's errno (igb EINVAL, igc ENXIO, mlx5 ENETDOWN), and refuses every
 * wakeup with ENETDOWN while its link is down.  The simulated CREATE probes
 * as the kernel does: a zero-copy, non-reliable AF_XDP TX stage fails with
 * the wakeup error, except ENETDOWN on a down link, which is deferred.
 *
 * Output: "ok - ..." / "not ok - ..." lines, then RESULT failures=N.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#ifndef __has_include
#define __has_include(header_) 0
#endif
#if __has_include(<bpf/libbpf_version.h>)
#include <bpf/libbpf_version.h>
#endif
#ifndef LIBBPF_MAJOR_VERSION
#define LIBBPF_MAJOR_VERSION 0
#endif
#include "libxdev_ext.h"
#include "libxdev_ext_internal.h"
#include "include/uapi/linux/io_uring.h"

#define IFINDEX 7
#define QUEUE 3
#define FRAMES 8U
#define XSK_FD 10001
#define RING_FD 10002
#define EVENT_FD 10003
#define PROG_FD 10004
#define PROG_ID 77U
#define OTHER_ID 99U

static int failures;

static void check(int ok, const char *scenario, const char *what)
{
	printf("%s - %s: %s\n", ok ? "ok" : "not ok", scenario, what);
	if (!ok)
		failures++;
}

/* --- the simulated host -------------------------------------------------- */

struct mapping { void *base; size_t bytes; uint64_t offset; int active; };

static struct {
	/* scenario inputs */
	bool zero_copy;
	int needs_xdp;		/* wakeup errno without XDP; 0: no such precondition */
	bool link_down;		/* every wakeup fails with ENETDOWN */
	int attach_errno;	/* forced netlink attach failure */
	int create_ret;		/* CREATE result after the probe */
	int stop_ret;
	int stats_ret;
	/* observations */
	char log[64];
	unsigned int nlog;
	unsigned int kicks, bad_kicks, attaches, detaches, creates;
	uint32_t attached_id;	/* program on IFINDEX now, 0: none */
	uint32_t attach_flags;
	int prog_fds_open, open_fds;
	uint32_t fill_prod_at_create;
	struct mapping maps[8];
	unsigned int nr_maps;
} h;

static void note(char c)
{
	if (h.nlog < sizeof(h.log) - 1)
		h.log[h.nlog++] = c;
}

/* Position of the first @c in the event log, or -1. */
static int at(char c)
{
	const char *p = strchr(h.log, c);

	return p ? (int)(p - h.log) : -1;
}

static void host_reset(void)
{
	unsigned int i;

	for (i = 0; i < h.nr_maps; i++)
		if (h.maps[i].active)
			free(h.maps[i].base);
	memset(&h, 0, sizeof(h));
	h.stats_ret = -ENOENT;
}

static struct mapping *map_at(uint64_t offset)
{
	unsigned int i;

	for (i = 0; i < h.nr_maps; i++)
		if (h.maps[i].active && h.maps[i].offset == offset)
			return &h.maps[i];
	return NULL;
}

/* The fill ring the library mapped: producer at 24, descriptors at 256. */
static uint32_t fill_producer(void)
{
	struct mapping *m = map_at(XDP_UMEM_PGOFF_FILL_RING);

	return m ? *(uint32_t *)((char *)m->base + 24) : UINT32_MAX;
}

static uint64_t fill_desc(uint32_t i)
{
	struct mapping *m = map_at(XDP_UMEM_PGOFF_FILL_RING);

	return m ? ((uint64_t *)((char *)m->base + 256))[i & 2047] : UINT64_MAX;
}

/* ndo_xsk_wakeup(XDP_WAKEUP_TX) of the simulated driver. */
static int wakeup(void)
{
	if (h.link_down)
		return -ENETDOWN;
	return h.needs_xdp && !h.attached_id ? -h.needs_xdp : 0;
}

int __wrap_socket(int domain, int type, int protocol)
{
	(void)protocol;
	if (domain != AF_XDP || type != (SOCK_RAW | SOCK_CLOEXEC)) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	h.open_fds++;
	return XSK_FD;
}

unsigned int __wrap_if_nametoindex(const char *name)
{
	if (!strcmp(name, "fixture0"))
		return IFINDEX;
	errno = ENODEV;
	return 0;
}

int __wrap_eventfd(unsigned int initial, int flags)
{
	(void)initial;
	(void)flags;
	h.open_fds++;
	return EVENT_FD;
}

int __wrap_close(int fd)
{
	if (fd == XSK_FD || fd == RING_FD || fd == EVENT_FD) {
		h.open_fds--;
		return 0;
	}
	if (fd == PROG_FD) {
		h.prog_fds_open--;
		return 0;
	}
	errno = EBADF;
	return -1;
}

int __wrap_setsockopt(int fd, int level, int opt, const void *value, socklen_t bytes)
{
	(void)value;
	(void)bytes;
	if (fd != XSK_FD || level != SOL_XDP) {
		errno = EINVAL;
		return -1;
	}
	switch (opt) {
	case XDP_UMEM_REG: case XDP_RX_RING: case XDP_TX_RING:
	case XDP_UMEM_FILL_RING: case XDP_UMEM_COMPLETION_RING:
		return 0;
	}
	errno = ENOPROTOOPT;
	return -1;
}

int __wrap_getsockopt(int fd, int level, int opt, void *value, socklen_t *bytes)
{
	if (fd != XSK_FD || level != SOL_XDP) {
		errno = EINVAL;
		return -1;
	}
	if (opt == XDP_MMAP_OFFSETS && *bytes >= sizeof(struct xdp_mmap_offsets)) {
		struct xdp_mmap_offsets *o = value;

		memset(o, 0, sizeof(*o));
		o->rx = (struct xdp_ring_offset){ .producer = 16, .consumer = 32, .desc = 128 };
		o->tx = (struct xdp_ring_offset){ .producer = 20, .consumer = 36, .desc = 192 };
		o->fr = (struct xdp_ring_offset){ .producer = 24, .consumer = 40, .desc = 256 };
		o->cr = (struct xdp_ring_offset){ .producer = 28, .consumer = 44, .desc = 320 };
		*bytes = sizeof(*o);
		return 0;
	}
	if (opt == XDP_OPTIONS && *bytes >= sizeof(struct xdp_options)) {
		((struct xdp_options *)value)->flags = h.zero_copy ? XDP_OPTIONS_ZEROCOPY : 0;
		*bytes = sizeof(struct xdp_options);
		return 0;
	}
	errno = ENOPROTOOPT;
	return -1;
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t bytes)
{
	const struct sockaddr_xdp *a = (const void *)addr;

	if (fd != XSK_FD || bytes != sizeof(*a) || a->sxdp_ifindex != IFINDEX ||
	    a->sxdp_queue_id != QUEUE ||
	    !(a->sxdp_flags & (h.zero_copy ? XDP_ZEROCOPY : XDP_COPY))) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

void *__wrap_mmap(void *addr, size_t bytes, int prot, int flags, int fd, off_t offset)
{
	void *p;

	(void)addr;
	(void)prot;
	(void)flags;
	if (fd != -1 && fd != XSK_FD) {
		errno = EBADF;
		return MAP_FAILED;
	}
	p = calloc(1, bytes);
	if (!p || h.nr_maps == 8)
		abort();
	h.maps[h.nr_maps++] = (struct mapping){ p, bytes, fd == -1 ? UINT64_MAX : (uint64_t)offset, 1 };
	return p;
}

int __wrap_munmap(void *addr, size_t bytes)
{
	unsigned int i;

	for (i = 0; i < h.nr_maps; i++)
		if (h.maps[i].base == addr && h.maps[i].active && h.maps[i].bytes == bytes) {
			h.maps[i].active = 0;
			free(addr);
			return 0;
		}
	errno = EINVAL;
	return -1;
}

/* An AF_XDP TX kick on a zero-copy socket is the driver's wakeup result. */
ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
		      const struct sockaddr *dest, socklen_t dest_len)
{
	int err = wakeup();

	note('K');
	h.kicks++;
	if (fd != XSK_FD || buf || len || flags != MSG_DONTWAIT || dest || dest_len)
		h.bad_kicks++;
	if (err) {
		errno = -err;
		return -1;
	}
	return 0;
}

/* --- libbpf: program load, identity, netlink attach, query and detach ---- */

static int sim_load(void)
{
	h.prog_fds_open++;
	return PROG_FD;
}

static int sim_attach(int ifindex, int prog_fd, uint32_t flags)
{
	note('A');
	h.attaches++;
	h.attach_flags = flags & ~XDP_FLAGS_UPDATE_IF_NOEXIST;
	if (ifindex != IFINDEX || prog_fd != PROG_FD || !(flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
		return -EINVAL;
	if (h.attach_errno)
		return -h.attach_errno;
	if (h.attached_id)
		return -EBUSY;		/* XDP_FLAGS_UPDATE_IF_NOEXIST */
	h.attached_id = PROG_ID;
	return 0;
}

static int sim_query(int ifindex, uint32_t *id)
{
	if (ifindex != IFINDEX)
		return -EINVAL;
	*id = h.attached_id;
	return 0;
}

static int sim_detach(int ifindex, int old_prog_fd, uint32_t flags)
{
	note('D');
	h.detaches++;
	if (ifindex != IFINDEX || old_prog_fd != PROG_FD || !(flags & XDP_FLAGS_REPLACE) ||
	    h.attached_id != PROG_ID)
		return -EINVAL;
	h.attached_id = 0;
	return 0;
}

int __wrap_bpf_obj_get_info_by_fd(int fd, void *info, __u32 *len)
{
	if (fd != PROG_FD || *len < sizeof(struct bpf_prog_info)) {
		errno = EINVAL;
		return -1;
	}
	((struct bpf_prog_info *)info)->id = PROG_ID;
	return 0;
}

#if LIBBPF_MAJOR_VERSION >= 1
int __wrap_bpf_prog_load(enum bpf_prog_type type, const char *name, const char *license,
			 const struct bpf_insn *insns, size_t cnt,
			 const struct bpf_prog_load_opts *opts)
{
	(void)name;
	(void)license;
	(void)insns;
	(void)opts;
	if (type != BPF_PROG_TYPE_XDP || cnt != 2)
		return -EINVAL;
	return sim_load();
}

int __wrap_bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags,
			  const struct bpf_xdp_attach_opts *opts)
{
	(void)opts;
	return sim_attach(ifindex, prog_fd, flags);
}

int __wrap_bpf_xdp_query_id(int ifindex, int flags, __u32 *id)
{
	(void)flags;
	return sim_query(ifindex, id);
}

int __wrap_bpf_xdp_detach(int ifindex, __u32 flags, const struct bpf_xdp_attach_opts *opts)
{
	return sim_detach(ifindex, opts ? opts->old_prog_fd : -1, flags);
}
#else
int __wrap_bpf_load_program(enum bpf_prog_type type, const struct bpf_insn *insns,
			    size_t cnt, const char *license, __u32 kern_version,
			    char *log_buf, size_t log_size)
{
	(void)insns;
	(void)license;
	(void)kern_version;
	(void)log_buf;
	(void)log_size;
	if (type != BPF_PROG_TYPE_XDP || cnt != 2) {
		errno = EINVAL;
		return -1;
	}
	return sim_load();
}

int __wrap_bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags)
{
	return sim_attach(ifindex, fd, flags);
}

int __wrap_bpf_get_link_xdp_id(int ifindex, __u32 *id, __u32 flags)
{
	(void)flags;
	return sim_query(ifindex, id);
}

int __wrap_bpf_set_link_xdp_fd_opts(int ifindex, int fd, __u32 flags,
				    const struct bpf_xdp_set_link_opts *opts)
{
	if (fd != -1)
		return -EINVAL;
	return sim_detach(ifindex, opts ? opts->old_fd : -1, flags);
}
#endif

/* --- io_uring through the library hook ------------------------------------ */

static int sim_ring_setup(unsigned int entries, struct io_uring_params *p)
{
	(void)entries;
	(void)p;
	h.open_fds++;
	return RING_FD;
}

/* The kernel's CREATE probe of a transmit-only zero-copy queue, then CREATE. */
static int sim_create(struct xdev_ext_mech_create *c)
{
	uint32_t i;

	note('C');
	h.creates++;
	h.fill_prod_at_create = fill_producer();
	for (i = 0; i < c->nr_stages; i++) {
		const struct xdev_ext_mech_stage_uapi *st = &c->st[i];
		int err;

		if (c->pool_kind != XDEV_EXT_MECH_POOL_XSK || !h.zero_copy ||
		    st->class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
		    st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE ||
		    (st->flags & XDEV_EXT_AFXDP_F_RELIABLE))
			continue;
		err = wakeup();
		if (err && !(err == -ENETDOWN && h.link_down))
			return err;
	}
	if (h.create_ret)
		return h.create_ret;
	c->session_id = 77;
	return 0;
}

static int sim_register(int fd, unsigned int opcode, void *arg, unsigned int nr)
{
	struct io_uring_xdev_ext_mech *req = arg;

	(void)fd;
	(void)nr;
	if (opcode == IORING_REGISTER_XDEV_EXT_UMEM)
		return 0;
	if (opcode != IORING_REGISTER_XDEV_EXT_MECH)
		return -EINVAL;
	switch (req->op) {
	case XDEV_EXT_MECH_OP_CREATE:
		return sim_create((void *)(uintptr_t)req->arg);
	case XDEV_EXT_MECH_OP_STOP:
		note('S');
		return h.stop_ret;
	case XDEV_EXT_MECH_OP_STATS:
		return h.stats_ret;
	}
	return -EOPNOTSUPP;
}

static const struct xdev_ext_sys sys = {
	.io_uring_setup = sim_ring_setup,
	.io_uring_register = sim_register,
};

/* --- scenarios ------------------------------------------------------------- */

enum shape { TX_ONLY, WITH_RX, RELIABLE_TX };

static int open_session(struct xdev_ext_session **s, __u32 pool_kind)
{
	struct xdev_ext_pool_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
		.pool_kind = pool_kind,
		.xsk_mode = h.zero_copy ? XDEV_EXT_XSK_ZEROCOPY : XDEV_EXT_XSK_COPY,
		.ifname = "fixture0", .queue = QUEUE, .nr_frames = FRAMES);

	return xdev_ext_session_open(&o, s);
}

/* NVMe READ -> AF_XDP TX, a receiver, or a reliable sender. */
static int create(struct xdev_ext_session *s, enum shape shape)
{
	struct xdev_ext_create_opts c = XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
		.group_bytes = 1024, .depth = 1, .mtu = 1500, .nr_stages = 2,
		.peer = { .local_mac = { 2, 0, 0, 0, 0, 1 } });

	c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 99 };
	c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = -1,
		.flags = shape == RELIABLE_TX ? XDEV_EXT_AFXDP_F_RELIABLE : 0 };
	if (shape == WITH_RX)
		c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
			.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = -1 };
	return xdev_ext_session_create(s, &c);
}

static void expect_released(const char *n)
{
	unsigned int i;
	int active = 0;

	for (i = 0; i < h.nr_maps; i++)
		active += h.maps[i].active;
	check(h.open_fds == 0 && h.prog_fds_open == 0 && active == 0, n,
	      "close releases every fd, program fd and mapping");
}

static bool fill_lower_half(void)
{
	uint32_t i;

	if (fill_producer() != FRAMES / 2)
		return false;
	for (i = 0; i < FRAMES / 2; i++)
		if (fill_desc(i) != (uint64_t)i * 4096)
			return false;
	return true;
}

/*
 * A driver refusing the kick for want of XDP: an owned pass program before
 * CREATE, the lower half of the chunks on the fill ring after CREATE, and a
 * detach after STOP at close.  @stop_first: the caller stops explicitly.
 */
static void refused(const char *n, int needs_xdp, bool stop_first)
{
	struct xdev_ext_session *s = NULL;

	host_reset();
	h.zero_copy = true;
	h.needs_xdp = needs_xdp;
	check(open_session(&s, XDEV_EXT_MECH_POOL_XSK) == 0 && s, n, "zero-copy XSK session opens");
	if (!s)
		return;
	check(h.kicks == 0, n, "open does not kick");
	check(create(s, TX_ONLY) == 0, n, "CREATE succeeds once the queue has XDP mode");
	check(h.kicks == 1 && h.bad_kicks == 0, n,
	      "one kick: sendto(xsk, NULL, 0, MSG_DONTWAIT, NULL, 0)");
	check(h.attaches == 1 && h.attach_flags == XDP_FLAGS_DRV_MODE, n,
	      "the pass program is attached once, in driver mode");
	check(!strncmp(h.log, "KAC", 3), n, "kick, then attach, then CREATE");
	check(h.fill_prod_at_create == 0, n, "the fill ring is empty at CREATE");
	check(fill_lower_half(), n, "after CREATE the fill ring holds the lower half of the chunks");
	if (stop_first)
		check(xdev_ext_session_stop(s) == 0, n, "STOP succeeds");
	check(h.detaches == 0 && h.attached_id == PROG_ID, n,
	      "the program stays until close");
	check(xdev_ext_session_close(s) == 0, n, "close succeeds");
	check(h.detaches == 1 && h.attached_id == 0, n, "close detaches exactly the attached program");
	check(at('S') >= 0 && at('S') < at('D'), n, "the program is detached after STOP");
	expect_released(n);
}

static void accepted(void)
{
	const char *n = "kick-accepted";
	struct xdev_ext_session *s = NULL;

	host_reset();
	h.zero_copy = true;
	check(open_session(&s, XDEV_EXT_MECH_POOL_XSK) == 0 && s, n, "session opens");
	if (!s)
		return;
	check(create(s, TX_ONLY) == 0, n, "CREATE succeeds");
	check(h.kicks == 1 && h.bad_kicks == 0 && at('K') < at('C'), n,
	      "the TX queue is kicked once before CREATE");
	check(h.attaches == 0, n, "a queue that takes the kick gets no program");
	check(fill_lower_half(), n, "after CREATE the fill ring holds the lower half of the chunks");
	check(xdev_ext_session_close(s) == 0 && h.detaches == 0, n, "close detaches nothing");
	expect_released(n);
}

/* A down link refuses the kick; another owner's program is XDP mode. */
static void other_owner(void)
{
	const char *n = "other-owner";
	struct xdev_ext_session *s = NULL;

	host_reset();
	h.zero_copy = true;
	h.needs_xdp = EINVAL;
	h.link_down = true;
	h.attached_id = OTHER_ID;
	check(open_session(&s, XDEV_EXT_MECH_POOL_XSK) == 0 && s, n, "session opens");
	if (!s)
		return;
	check(create(s, TX_ONLY) == 0, n, "-EBUSY from the attach is accepted; CREATE succeeds");
	check(h.kicks == 1 && h.attaches == 1, n, "the refused kick tries the pass program once");
	check(xdev_ext_session_close(s) == 0, n, "close succeeds");
	check(h.detaches == 0 && h.attached_id == OTHER_ID, n,
	      "the other owner's program is never detached");
	expect_released(n);
}

static void attach_fails(void)
{
	const char *n = "attach-fails";
	struct xdev_ext_session *s = NULL;

	host_reset();
	h.zero_copy = true;
	h.needs_xdp = ENXIO;
	h.attach_errno = EPERM;
	check(open_session(&s, XDEV_EXT_MECH_POOL_XSK) == 0 && s, n, "session opens");
	if (!s)
		return;
	check(create(s, TX_ONLY) == -EPERM, n, "the attach error is the create step's error");
	check(h.creates == 0, n, "no CREATE is issued");
	check(xdev_ext_session_close(s) == 0 && h.detaches == 0, n, "close detaches nothing");
	expect_released(n);
}

static void create_fails(void)
{
	const char *n = "create-fails";
	struct xdev_ext_session *s = NULL;

	host_reset();
	h.zero_copy = true;
	h.needs_xdp = ENETDOWN;
	h.create_ret = -EIO;
	check(open_session(&s, XDEV_EXT_MECH_POOL_XSK) == 0 && s, n, "session opens");
	if (!s)
		return;
	check(create(s, TX_ONLY) == -EIO, n, "the CREATE error is returned");
	check(h.attaches == 1 && h.detaches == 1 && h.attached_id == 0, n,
	      "a failed CREATE drops the XDP mode this create attached");
	check(fill_producer() == 0, n, "a failed CREATE leaves the fill ring empty");
	check(xdev_ext_session_close(s) == 0 && h.detaches == 1, n, "close detaches nothing more");
	expect_released(n);
}

/* Unknown native ownership after STOP: the queue keeps its XDP mode. */
static void stop_retained(void)
{
	const char *n = "stop-retained";
	struct xdev_ext_session *s = NULL;

	host_reset();
	h.zero_copy = true;
	h.needs_xdp = EINVAL;
	check(open_session(&s, XDEV_EXT_MECH_POOL_XSK) == 0 && s, n, "session opens");
	if (!s)
		return;
	check(create(s, TX_ONLY) == 0 && h.attached_id == PROG_ID, n, "CREATE with the pass program");
	h.stop_ret = -EBUSY;
	h.stats_ret = 0;
	check(xdev_ext_session_close(s) == -EBUSY, n, "close reports the retained session");
	check(h.detaches == 0 && h.attached_id == PROG_ID, n,
	      "a retained session keeps the program it attached");
}

/* Only a zero-copy, transmit-only, non-reliable XSK session is kicked. */
static void not_kicked(const char *n, bool zero_copy, __u32 pool_kind, enum shape shape)
{
	struct xdev_ext_session *s = NULL;

	host_reset();
	h.zero_copy = zero_copy;
	h.needs_xdp = EINVAL;		/* would refuse, if asked */
	check(open_session(&s, pool_kind) == 0 && s, n, "session opens");
	if (!s)
		return;
	(void)create(s, shape);
	check(h.kicks == 0 && h.attaches == 0, n, "no kick and no program");
	check(fill_producer() == (pool_kind == XDEV_EXT_MECH_POOL_XSK ? 0 : UINT32_MAX), n,
	      "the fill ring is left as before");
	check(xdev_ext_session_close(s) == 0 && h.detaches == 0, n, "close detaches nothing");
	expect_released(n);
}

int main(void)
{
	xdev_ext__set_sys(&sys);
	refused("kick-einval", EINVAL, false);
	refused("kick-enxio", ENXIO, false);
	refused("kick-enetdown", ENETDOWN, false);
	refused("stop-then-close", EINVAL, true);
	accepted();
	other_owner();
	attach_fails();
	create_fails();
	stop_retained();
	not_kicked("copy-mode", false, XDEV_EXT_MECH_POOL_XSK, TX_ONLY);
	not_kicked("receive-stage", true, XDEV_EXT_MECH_POOL_XSK, WITH_RX);
	not_kicked("reliable-sender", true, XDEV_EXT_MECH_POOL_XSK, RELIABLE_TX);
	not_kicked("iou-pool", true, XDEV_EXT_MECH_POOL_IOU_UMEM, TX_ONLY);
	host_reset();
	printf("RESULT failures=%d\n", failures);
	return failures ? 1 : 0;
}

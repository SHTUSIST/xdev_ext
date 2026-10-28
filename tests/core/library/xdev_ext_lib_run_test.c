// SPDX-License-Identifier: GPL-2.0
/*
 * Host tests of libxdev_ext class-program options and of the one-call
 * NVMe -> NIC entry: every rejection happens before any side effect (no
 * file descriptor, no program, no io_uring_register call).  A successful
 * run needs the real kernel and is the guest test's job.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "include/uapi/linux/io_uring.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext_internal.h"

static unsigned int checks, failures, tests, before;

#define EXPECT_EQ(actual, expected) do { \
	long long a_ = (long long)(actual); \
	long long e_ = (long long)(expected); \
	checks++; \
	if (a_ != e_) { \
		fprintf(stderr, "# %s:%d: %s: got %lld, expected %lld\n", \
			__FILE__, __LINE__, #actual, a_, e_); \
		failures++; \
	} \
} while (0)

static unsigned int nr_register, nr_setup;

static int count_register(int fd, unsigned int opcode, void *arg, unsigned int nr)
{
	(void)fd; (void)opcode; (void)arg; (void)nr;
	nr_register++;
	return -ENOSYS;
}

static int count_setup(unsigned int entries, struct io_uring_params *p)
{
	(void)entries; (void)p;
	nr_setup++;
	return -ENOSYS;
}

static const struct xdev_ext_sys counting = {
	.io_uring_setup = count_setup,
	.io_uring_register = count_register,
};

static int open_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int n = 0;

	if (!d)
		return -1;
	while ((e = readdir(d)))
		n += e->d_name[0] != '.';
	closedir(d);
	return n - 1;
}

static void test_prog_validation(void)
{
	struct xdev_ext_prog_global g[XDEV_EXT_PROG_MAX_GLOBALS + 1] = {
		{ .name = "nxp_session", .value = 1 } };
	struct xdev_ext_prog_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_prog_opts,
		.obj_path = "/nonexistent/xdev_ext_lib_test.bpf.o",
		.map_name = "nxp_afxdp_ops");
	struct {
		struct xdev_ext_prog_opts o;
		__u64 tail;
	} big = { .o = o };
	struct xdev_ext_prog *p = (void *)1;
	int fds = open_fds();

	EXPECT_EQ(xdev_ext_prog_attach(NULL, &p), -EINVAL);
	EXPECT_EQ(xdev_ext_prog_attach(&o, NULL), -EINVAL);
	o.obj_path = NULL;
	EXPECT_EQ(xdev_ext_prog_attach(&o, &p), -EINVAL);
	o.obj_path = big.o.obj_path;
	o.map_name = NULL;
	EXPECT_EQ(xdev_ext_prog_attach(&o, &p), -EINVAL);
	o.map_name = big.o.map_name;
	o.nr_globals = 1;
	EXPECT_EQ(xdev_ext_prog_attach(&o, &p), -EINVAL);	/* globals NULL */
	o.globals = g;
	o.nr_globals = XDEV_EXT_PROG_MAX_GLOBALS + 1;
	EXPECT_EQ(xdev_ext_prog_attach(&o, &p), -EINVAL);
	o.nr_globals = 2;	/* second entry has no name */
	EXPECT_EQ(xdev_ext_prog_attach(&o, &p), -EINVAL);
	o.nr_globals = 1;
	o.flags = 4;
	EXPECT_EQ(xdev_ext_prog_attach(&o, &p), -EOPNOTSUPP);
	o.flags = 0;
	o.sz = offsetof(struct xdev_ext_prog_opts, flags);
	EXPECT_EQ(xdev_ext_prog_attach(&o, &p), -EINVAL);
	o.sz = sizeof(o);
	big.o.sz = sizeof(big);
	big.tail = 3;
	EXPECT_EQ(xdev_ext_prog_attach(&big.o, &p), -EOPNOTSUPP);
	/* A missing object is the open error, not a crash or a leak. */
	EXPECT_EQ(xdev_ext_prog_attach(&o, &p), -ENOENT);
	EXPECT_EQ((uintptr_t)p, 1);
	EXPECT_EQ(xdev_ext_prog_detach(NULL), -EINVAL);
	EXPECT_EQ(open_fds(), fds);
}

static struct xdev_ext_nvme_nic_opts good(void)
{
	return XDEV_EXT_OPTS_INIT(xdev_ext_nvme_nic_opts,
		.nvme_path = "/dev/null", .slba = 0, .nlb = 64,
		.ifname = "lo", .group_bytes = 8192, .depth = 4,
		.nr_batches = 4, .timeout_ms = 1000);
}

static void test_run_validation(void)
{
	struct xdev_ext_prog_opts prog = XDEV_EXT_OPTS_INIT(xdev_ext_prog_opts,
		.obj_path = "/nonexistent/x.bpf.o", .map_name = "m");
	struct xdev_ext_run_result r = { .sz = sizeof(r) };
	struct xdev_ext_nvme_nic_opts o = good();
	struct {
		struct xdev_ext_nvme_nic_opts o;
		__u64 tail;
	} big = { .o = o };
	int fds = open_fds();

	EXPECT_EQ(xdev_ext_nvme_to_nic(NULL, &r), -EINVAL);
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, NULL), -EINVAL);
	r.sz = offsetof(struct xdev_ext_run_result, session);
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	r.sz = sizeof(r);
	o.nvme_path = NULL;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	o = good();
	o.ifname = NULL;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	o = good();
	o.nr_batches = 0;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	o = good();
	o.group_bytes = 0;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	o = good();
	o.depth = 0;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	o = good();
	o.nlb = 0;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	o = good();
	o.xsk_mode = 7;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	o = good();
	o.nr_progs = 1;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);	/* progs NULL */
	o.progs = &prog;
	o.nr_progs = XDEV_EXT_MAX_PROGS + 1;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	o = good();
	o.flags = 1;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EOPNOTSUPP);
	o = good();
	o.sz = offsetof(struct xdev_ext_nvme_nic_opts, flags);
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -EINVAL);
	big.o = good();
	big.o.sz = sizeof(big);
	big.tail = 1;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&big.o, &r), -EOPNOTSUPP);
	EXPECT_EQ(nr_setup, 0);
	EXPECT_EQ(nr_register, 0);
	EXPECT_EQ(open_fds(), fds);
}

/* Failures after validation unwind everything they set up. */
static void test_run_unwind(void)
{
	struct xdev_ext_prog_opts prog = XDEV_EXT_OPTS_INIT(xdev_ext_prog_opts,
		.obj_path = "/nonexistent/x.bpf.o", .map_name = "m");
	struct xdev_ext_run_result r = { .sz = sizeof(r) };
	struct xdev_ext_nvme_nic_opts o = good();
	int fds = open_fds();

	/* The program attach fails first: nothing else is opened. */
	o.progs = &prog;
	o.nr_progs = 1;
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -ENOENT);
	EXPECT_EQ(nr_setup, 0);
	EXPECT_EQ(r.retained, 0);
	EXPECT_EQ((uintptr_t)r.session, 0);
	EXPECT_EQ(open_fds(), fds);
	/* The NVMe path is opened before the pool; a missing one stops there. */
	o = good();
	o.nvme_path = "/nonexistent/ng0n1";
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -ENOENT);
	EXPECT_EQ(nr_setup, 0);
	EXPECT_EQ(open_fds(), fds);
	/* A missing interface fails the pool open before any io_uring. */
	o = good();
	o.ifname = "xdevextnone0";
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -ENODEV);
	EXPECT_EQ(nr_setup, 0);
	EXPECT_EQ(open_fds(), fds);
	/* io_uring setup failure is returned and unwound. */
	o = good();
	EXPECT_EQ(xdev_ext_nvme_to_nic(&o, &r), -ENOSYS);
	EXPECT_EQ(nr_setup, 1);
	EXPECT_EQ(nr_register, 0);
	EXPECT_EQ(open_fds(), fds);
}

#define RUN(fn) do { \
	nr_register = nr_setup = 0; \
	xdev_ext__set_sys(&counting); \
	before = failures; \
	fn(); \
	xdev_ext__set_sys(NULL); \
	printf("%s %u - %s\n", failures == before ? "ok" : "not ok", ++tests, #fn); \
} while (0)

int main(void)
{
	printf("TAP version 13\n1..3\n");
	RUN(test_prog_validation);
	RUN(test_run_validation);
	RUN(test_run_unwind);
	printf("# checks=%u failures=%u\n", checks, failures);
	return failures ? 1 : 0;
}

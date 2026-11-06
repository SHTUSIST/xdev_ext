// SPDX-License-Identifier: GPL-2.0
/*
 * The XDP-mode rule for a transmit-only zero-copy AF_XDP socket, before
 * CREATE (xdev_ext_xsk_redirect_zc_tx_xdp): kick the TX queue as an AF_XDP
 * application does; only a kick the driver refuses for want of XDP mode
 * (EINVAL from igb, ice, i40e and ixgbe, ENXIO from igc, ENETDOWN from mlx5
 * or a down interface) attaches the pass program.  Another owner's native
 * program (-EBUSY) already selects XDP mode and leaves nothing owned.  Every
 * other kick result attaches nothing; CREATE then decides.
 *
 * The kick and the control-plane operations are injected, so no device and
 * no CAP_BPF are needed.  The production wrapper is exercised on a socket
 * pair, whose successful kick must attach nothing and send an empty datagram.
 */
#include <errno.h>
#include <linux/if_link.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "xdev_ext_xsk_redirect.h"

static unsigned int checks, failures;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	checks++;                                                            \
	if (actual_ != expected_) {                                         \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__FILE__, __LINE__, #actual_expr, actual_, expected_); \
		failures++;                                                   \
	}                                                                   \
} while (0)

#define XSK_FD 42
#define IFINDEX 9
#define PROG_FD 20
#define PROG_ID 77

/* One letter per event, in call order: K kick, L load, I id, A attach,
 * Q query, D detach, C close, M map create, U map update, X map delete. */
static struct {
	char order[32];
	unsigned int n;
	int kick_ret, load_ret, attach_ret, detach_ret;
	int kick_fd, attach_ifindex, detach_ifindex;
	uint32_t attach_flags, current_id;
	bool load_was_pass;
} f;

static void reset(int kick_ret)
{
	memset(&f, 0, sizeof(f));
	f.kick_ret = kick_ret;
	f.load_ret = PROG_FD;
	f.current_id = PROG_ID;
	f.kick_fd = f.attach_ifindex = f.detach_ifindex = -1;
}

static void note(char c)
{
	if (f.n < sizeof(f.order) - 1)
		f.order[f.n++] = c;
}

static unsigned int count(char c)
{
	unsigned int i, n = 0;

	for (i = 0; i < f.n; i++)
		n += f.order[i] == c;
	return n;
}

static int fake_kick(int fd)
{
	note('K');
	f.kick_fd = fd;
	return f.kick_ret;
}

static int fake_map_create(uint32_t max_entries)
{
	(void)max_entries;
	note('M');
	return 10;
}

static int fake_prog_load(int map_fd, const struct xdev_ext_xsk_flow_filter *filter)
{
	note('L');
	f.load_was_pass = map_fd == -1 && !filter;
	return f.load_ret;
}

static int fake_prog_id(int prog_fd, uint32_t *id)
{
	note('I');
	EXPECT_EQ(prog_fd, PROG_FD);
	*id = PROG_ID;
	return 0;
}

static int fake_attach(int ifindex, int prog_fd, uint32_t xdp_flags)
{
	note('A');
	EXPECT_EQ(prog_fd, PROG_FD);
	f.attach_ifindex = ifindex;
	f.attach_flags = xdp_flags;
	return f.attach_ret;
}

static int fake_query(int ifindex, uint32_t xdp_flags, uint32_t *id)
{
	(void)ifindex;
	(void)xdp_flags;
	note('Q');
	*id = f.current_id;
	return 0;
}

static int fake_update(int map_fd, uint32_t queue_id, int xsk_fd)
{
	(void)map_fd;
	(void)queue_id;
	(void)xsk_fd;
	note('U');
	return 0;
}

static int fake_delete(int map_fd, uint32_t queue_id)
{
	(void)map_fd;
	(void)queue_id;
	note('X');
	return 0;
}

static int fake_detach(int ifindex, int expected_prog_fd, uint32_t xdp_flags)
{
	(void)xdp_flags;
	note('D');
	EXPECT_EQ(expected_prog_fd, PROG_FD);
	f.detach_ifindex = ifindex;
	return f.detach_ret;
}

static int fake_close(int fd)
{
	(void)fd;
	note('C');
	return 0;
}

static const struct xdev_ext_xsk_redirect_ops ops = {
	.map_create = fake_map_create, .prog_load = fake_prog_load,
	.prog_id = fake_prog_id, .attach = fake_attach, .query_id = fake_query,
	.map_update = fake_update, .map_delete = fake_delete,
	.detach = fake_detach, .close_fd = fake_close,
};

static int rule(struct xdev_ext_xsk_redirect *r, uint32_t xdp_flags)
{
	return xdev_ext_xsk_redirect_zc_tx_xdp_with(r, &ops, fake_kick, XSK_FD,
						    IFINDEX, xdp_flags);
}

static void expect_nothing_owned(const struct xdev_ext_xsk_redirect *r)
{
	EXPECT_EQ(xdev_ext_xsk_redirect_is_active(r), 0);
	EXPECT_EQ(r->prog_fd, -1);
	EXPECT_EQ(r->map_fd, -1);
}

/* A queue that takes the kick needs nothing: no program, no BPF call. */
static void test_accepted_kick_attaches_nothing(void)
{
	struct xdev_ext_xsk_redirect r = XDEV_EXT_XSK_REDIRECT_INIT;

	reset(0);
	EXPECT_EQ(rule(&r, XDP_FLAGS_DRV_MODE), 0);
	EXPECT_EQ(strcmp(f.order, "K"), 0);
	EXPECT_EQ(f.kick_fd, XSK_FD);
	expect_nothing_owned(&r);
}

/* The three refusals that mean "no XDP program": the pass program, owned. */
static void test_refused_kick_attaches_owned_pass_program(void)
{
	static const int refusals[] = { -EINVAL, -ENXIO, -ENETDOWN };
	unsigned int i;

	for (i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++) {
		struct xdev_ext_xsk_redirect r = XDEV_EXT_XSK_REDIRECT_INIT;

		reset(refusals[i]);
		EXPECT_EQ(rule(&r, XDP_FLAGS_DRV_MODE), 0);
		EXPECT_EQ(f.order[0], 'K');		/* kick before any BPF call */
		EXPECT_EQ(count('K'), 1);
		EXPECT_EQ(count('L'), 1);
		EXPECT_EQ(f.load_was_pass, 1);		/* no filter, no XSKMAP */
		EXPECT_EQ(count('M') + count('U'), 0);
		EXPECT_EQ(count('A'), 1);
		EXPECT_EQ(f.attach_ifindex, IFINDEX);
		EXPECT_EQ(f.attach_flags, XDP_FLAGS_DRV_MODE);
		EXPECT_EQ(count('D'), 0);
		EXPECT_EQ(xdev_ext_xsk_redirect_is_active(&r), 1);
		EXPECT_EQ(r.attached, 1);
		EXPECT_EQ(r.mapped, 0);
		/* What the rule attached, the owner's detach removes exactly. */
		EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&r, &ops), 0);
		EXPECT_EQ(count('D'), 1);
		EXPECT_EQ(f.detach_ifindex, IFINDEX);
		expect_nothing_owned(&r);
	}
}

/* Other kick results are not the missing-XDP precondition: CREATE decides. */
static void test_other_kick_results_attach_nothing(void)
{
	static const int others[] = { -EAGAIN, -ENOBUFS, -EBUSY, -EOPNOTSUPP, -EPERM, -EBADF };
	unsigned int i;

	for (i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
		struct xdev_ext_xsk_redirect r = XDEV_EXT_XSK_REDIRECT_INIT;

		reset(others[i]);
		EXPECT_EQ(rule(&r, XDP_FLAGS_DRV_MODE), 0);
		EXPECT_EQ(strcmp(f.order, "K"), 0);
		expect_nothing_owned(&r);
	}
}

/* Another owner's native program is XDP mode already: accepted, not owned. */
static void test_other_owners_program_is_accepted_and_never_detached(void)
{
	struct xdev_ext_xsk_redirect r = XDEV_EXT_XSK_REDIRECT_INIT;

	reset(-EINVAL);
	f.attach_ret = -EBUSY;
	EXPECT_EQ(rule(&r, XDP_FLAGS_DRV_MODE), 0);
	EXPECT_EQ(count('A'), 1);
	EXPECT_EQ(count('D'), 0);
	EXPECT_EQ(count('C'), 1);	/* our unattached program fd only */
	expect_nothing_owned(&r);
}

/* Any other attach failure is the caller's setup failure, nothing owned. */
static void test_attach_failure_is_returned(void)
{
	struct xdev_ext_xsk_redirect r = XDEV_EXT_XSK_REDIRECT_INIT;

	reset(-ENXIO);
	f.attach_ret = -EPERM;
	EXPECT_EQ(rule(&r, XDP_FLAGS_DRV_MODE), -EPERM);
	EXPECT_EQ(count('D'), 0);
	expect_nothing_owned(&r);

	reset(-ENETDOWN);
	f.load_ret = -EPERM;		/* no CAP_BPF: the program never loads */
	EXPECT_EQ(rule(&r, XDP_FLAGS_DRV_MODE), -EPERM);
	EXPECT_EQ(count('A'), 0);
	expect_nothing_owned(&r);
}

/* The caller's XDP mode reaches the attach unchanged. */
static void test_mode_is_the_callers(void)
{
	struct xdev_ext_xsk_redirect r = XDEV_EXT_XSK_REDIRECT_INIT;

	reset(-EINVAL);
	EXPECT_EQ(rule(&r, XDP_FLAGS_SKB_MODE), 0);
	EXPECT_EQ(f.attach_flags, XDP_FLAGS_SKB_MODE);
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&r, &ops), 0);
}

static void test_invalid_arguments_never_kick(void)
{
	struct xdev_ext_xsk_redirect r = XDEV_EXT_XSK_REDIRECT_INIT;

	reset(-EINVAL);
	EXPECT_EQ(xdev_ext_xsk_redirect_zc_tx_xdp_with(NULL, &ops, fake_kick, XSK_FD, IFINDEX,
						       XDP_FLAGS_DRV_MODE), -EINVAL);
	EXPECT_EQ(xdev_ext_xsk_redirect_zc_tx_xdp_with(&r, &ops, NULL, XSK_FD, IFINDEX,
						       XDP_FLAGS_DRV_MODE), -EINVAL);
	EXPECT_EQ(xdev_ext_xsk_redirect_zc_tx_xdp_with(&r, &ops, fake_kick, -1, IFINDEX,
						       XDP_FLAGS_DRV_MODE), -EINVAL);
	EXPECT_EQ(f.n, 0);
	expect_nothing_owned(&r);
}

/*
 * The production kick is sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0): on a
 * socket pair it succeeds, so nothing is attached, and the peer sees one
 * empty datagram.
 */
static void test_production_kick_is_an_empty_send(void)
{
	struct xdev_ext_xsk_redirect r = XDEV_EXT_XSK_REDIRECT_INIT;
	char byte;
	int sv[2];

	EXPECT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv), 0);
	EXPECT_EQ(xdev_ext_xsk_redirect_zc_tx_xdp(&r, sv[0], IFINDEX, XDP_FLAGS_DRV_MODE), 0);
	expect_nothing_owned(&r);
	EXPECT_EQ(recv(sv[1], &byte, sizeof(byte), MSG_DONTWAIT), 0);
	EXPECT_EQ(recv(sv[1], &byte, sizeof(byte), MSG_DONTWAIT), -1);
	EXPECT_EQ(errno, EAGAIN);
	close(sv[0]);
	close(sv[1]);
}

int main(void)
{
	test_accepted_kick_attaches_nothing();
	test_refused_kick_attaches_owned_pass_program();
	test_other_kick_results_attach_nothing();
	test_other_owners_program_is_accepted_and_never_detached();
	test_attach_failure_is_returned();
	test_mode_is_the_callers();
	test_invalid_arguments_never_kick();
	test_production_kick_is_an_empty_send();
	printf("zc_tx_rule: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}

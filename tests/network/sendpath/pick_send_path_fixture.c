// SPDX-License-Identifier: GPL-2.0
/*
 * Truth table of the SEND path selector, run against the production code.
 *
 * pick_send_path_test.py pastes two production bodies in place of the
 * markers below and compiles this file:
 *
 *   PRODUCTION_SELECTOR    enum xdev_ext_send_path and xdev_ext_pick_send_path()
 *                          from io_uring/unified_ops.c;
 *   PRODUCTION_TX_CAPABLE  xsk_kernel_tx_capable() from net/xdp/xsk.c, the
 *                          probe the SEND dispatch in unified_ops.c actually
 *                          calls, over minimal socket/xdp_sock stand-ins.
 *
 * The expected column is derived from the contract prose, not from either
 * body: the in-kernel COPY-mode AF_XDP send is taken only when the feature
 * is compiled in AND the fd is a PF_XDP socket AND it is bound AND it has a
 * TX ring; everything else stays on the existing sock_sendmsg / UMEM path.
 * Every one of the 2^4 rows is checked for both bodies, plus the structural
 * checks of the original test: the enum encoding, exactly one COPY row (the
 * all-true row), and "not compiled in" forcing SOCK for all 8 sub-rows.
 *
 * Ported from the Plan Y QA unit test
 *   archive/conduit-legacy/afxdp_work/qa_y/test_pick_send_path_y.c
 *   (sha256 a0b5ebb93ad89b670bc4abeac92d27758cf123969a4fab2781d1b44e2e328842)
 * whose function under test was a verbatim spec copy.  Its five-input
 * predecessor
 *   archive/conduit-legacy/afxdp_work/qa/test_pick_send_path.c
 *   (sha256 6fef2d4c154955b99242edc3435f178c98f9d4b063967346e52eeb144859102d)
 * also selected a zero-copy arm on nic_zc; the current selector has no ZC
 * arm ("Plan Y has no ZC runtime arm", unified_ops.c), so its
 * dominance and single-missing-capability invariants (INV-1, INV-3) are kept
 * here and its ZC row (INV-2a) is not.
 *
 * Exit 0 when every check passes, 1 otherwise.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Stand-ins for what xsk_kernel_tx_capable() reads. */
#define PF_XDP 44
#define PF_INET 2
#define READ_ONCE(x) (*(const volatile __typeof__(x) *)&(x))

struct sock {
	int sk_family;
};

struct xsk_queue {
	int unused;
};

struct xsk_buff_pool {
	int unused;
};

/* struct sock comes first, as in the kernel, so xdp_sk() is a cast. */
struct xdp_sock {
	struct sock sk;
	struct xsk_queue *tx;
	struct xsk_buff_pool *pool;
	bool bound;
};

struct socket {
	struct sock *sk;
};

static struct xdp_sock *xdp_sk(struct sock *sk)
{
	return (struct xdp_sock *)sk;
}

static bool xsk_is_bound(struct xdp_sock *xs)
{
	return READ_ONCE(xs->bound);
}

/* PRODUCTION_SELECTOR */

/* PRODUCTION_TX_CAPABLE */

static unsigned int checks, failures;

static void check(bool ok, const char *what, int row)
{
	checks++;
	if (!ok) {
		failures++;
		printf("FAIL row %d: %s\n", row, what);
	}
}

/* From the contract prose; deliberately not shaped like either body. */
static enum xdev_ext_send_path expected_path(bool compiled, bool is_xdp_sock,
					bool xsk_bound, bool has_tx_ring)
{
	bool take_copy = false;

	if (compiled == true)
		if (is_xdp_sock == true)
			if (xsk_bound == true)
				if (has_tx_ring == true)
					take_copy = true;
	return take_copy ? XDEV_EXT_SEND_XDP_COPY : XDEV_EXT_SEND_SOCK;
}

/*
 * The SEND dispatch: afxdp = xsk_kernel_tx_capable(send_sock) only when the
 * feature is compiled in (#if XDEV_EXT_AFXDP_SEND && CONFIG_XDP_SOCKETS),
 * otherwise the compiled-out stub, which is false.  A bound socket has a
 * pool (bind installs it before publishing XSK_BOUND); an unbound one may or
 * may not (bind still running, or unbound after its device went away), and
 * both must give the same answer.  -1 marks such a disagreement.
 */
static int dispatch_path(bool compiled, bool is_xdp_sock, bool xsk_bound,
			 bool has_tx_ring)
{
	struct xsk_queue tx = { 0 };
	struct xsk_buff_pool pool = { 0 };
	int path = -1, with_pool;

	for (with_pool = xsk_bound; with_pool <= 1; with_pool++) {
		struct xdp_sock xs = {
			.sk = { .sk_family = is_xdp_sock ? PF_XDP : PF_INET },
			.tx = has_tx_ring ? &tx : NULL,
			.pool = with_pool ? &pool : NULL,
			.bound = xsk_bound,
		};
		struct socket sock = { .sk = &xs.sk };
		bool afxdp = compiled && xsk_kernel_tx_capable(&sock);
		int p = afxdp ? XDEV_EXT_SEND_XDP_COPY : XDEV_EXT_SEND_SOCK;

		if (path >= 0 && p != path)
			return -1;
		path = p;
	}
	return path;
}

static const char *name_of(enum xdev_ext_send_path p)
{
	switch (p) {
	case XDEV_EXT_SEND_SOCK:
		return "SOCK";
	case XDEV_EXT_SEND_XDP_COPY:
		return "XDP_COPY";
	default:
		return "INVALID";
	}
}

int main(void)
{
	struct socket no_sk = { .sk = NULL };
	int bits, copy_rows = 0;

	printf("row | comp xdpsk bound txring | selector | dispatch | expected\n");
	for (bits = 0; bits < 16; bits++) {
		bool compiled = (bits >> 3) & 1;
		bool is_xdp_sock = (bits >> 2) & 1;
		bool xsk_bound = (bits >> 1) & 1;
		bool has_tx_ring = bits & 1;
		enum xdev_ext_send_path want = expected_path(compiled, is_xdp_sock,
							xsk_bound, has_tx_ring);
		enum xdev_ext_send_path pick = xdev_ext_pick_send_path(compiled, is_xdp_sock,
								  xsk_bound, has_tx_ring);
		int live = dispatch_path(compiled, is_xdp_sock, xsk_bound, has_tx_ring);

		printf("%3d | %4d %5d %5d %6d | %-8s | %-8s | %s\n", bits, compiled,
		       is_xdp_sock, xsk_bound, has_tx_ring, name_of(pick),
		       live < 0 ? "SPLIT" : name_of((enum xdev_ext_send_path)live),
		       name_of(want));
		check(pick == XDEV_EXT_SEND_SOCK || pick == XDEV_EXT_SEND_XDP_COPY,
		      "selector returned an undefined path", bits);
		check(pick == want, "selector disagrees with the contract", bits);
		check(live == (int)want, "dispatch probe disagrees with the contract", bits);
		if (pick == XDEV_EXT_SEND_XDP_COPY)
			copy_rows++;
	}

	/* Structural checks, independent of the loop above. */
	check(XDEV_EXT_SEND_SOCK == 0 && XDEV_EXT_SEND_XDP_COPY == 1,
	      "enum encoding changed", -1);
	check(copy_rows == 1, "exactly one row may select XDP_COPY", -1);
	check(xdev_ext_pick_send_path(true, true, true, true) == XDEV_EXT_SEND_XDP_COPY,
	      "(1,1,1,1) must select XDP_COPY", -1);
	for (bits = 0; bits < 8; bits++)
		check(xdev_ext_pick_send_path(false, (bits >> 2) & 1, (bits >> 1) & 1,
					 bits & 1) == XDEV_EXT_SEND_SOCK,
		      "not compiled in must force SOCK", bits);
	/* Any single missing capability falls back (legacy INV-3). */
	check(xdev_ext_pick_send_path(true, false, true, true) == XDEV_EXT_SEND_SOCK,
	      "not a PF_XDP socket must be SOCK", -1);
	check(xdev_ext_pick_send_path(true, true, false, true) == XDEV_EXT_SEND_SOCK,
	      "an unbound socket must be SOCK", -1);
	check(xdev_ext_pick_send_path(true, true, true, false) == XDEV_EXT_SEND_SOCK,
	      "no TX ring must be SOCK", -1);
	/* The probe itself refuses a missing socket or sock. */
	check(!xsk_kernel_tx_capable(NULL), "NULL socket must not be TX-capable", -1);
	check(!xsk_kernel_tx_capable(&no_sk), "socket without sk must not be TX-capable",
	      -1);

	if (failures) {
		printf("RESULT: FAIL (%u of %u checks)\n", failures, checks);
		return 1;
	}
	printf("RESULT: PASS (%u checks, 16 rows, XDP_COPY rows = %d)\n", checks,
	       copy_rows);
	return 0;
}

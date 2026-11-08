// SPDX-License-Identifier: GPL-2.0
/*
 * Host test for the AF_XDP receive-steering location choice in
 * xdev_ext_xsk_steer.c.  No device, no root: socket/ioctl/close and
 * if_nametoindex are replaced by an in-process fake ethtool layer.
 *
 * Two driver models are exercised:
 *  - "fixed location" (ice, igb, mlx5 in Linux 6.16): ETHTOOL_GRXCLSRLCNT
 *    does not set RX_CLS_LOC_SPECIAL; the table size comes from the data
 *    field of ETHTOOL_GRXCLSRLALL (ice also reports it in GRXCLSRLCNT,
 *    igb/mlx5 leave it zero).  Insertion needs an explicit location below
 *    the table size; RX_CLS_LOC_ANY or a location >= size gives -ENOSPC
 *    (ice_add_fdir_ethtool), and an occupied location silently REPLACES
 *    the rule already there.
 *  - "driver allocates" (bnxt, sfc, ...): GRXCLSRLCNT sets
 *    RX_CLS_LOC_SPECIAL and insertion with RX_CLS_LOC_ANY picks a slot.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "include/xdev_ext_xsk_steer.h"

#define FAKE_FD 4242
#define FAKE_IFINDEX 7
#define FAKE_MAX 64

static struct fake_nic {
	bool loc_special;	/* driver allocates on RX_CLS_LOC_ANY */
	bool cnt_reports_size;	/* ice: size also in GRXCLSRLCNT data */
	uint32_t size;		/* advertised table size */
	uint32_t pool;		/* filters the hardware can still hold */
	bool used[FAKE_MAX];
	struct ethtool_rx_flow_spec rule[FAKE_MAX];
	unsigned int inserts, replaced, deletes, open_fds;
	uint32_t last_requested_location;
	int get_absent_errno;	/* GRXCLSRULE on an empty location: ice -EINVAL */
	int get_force_errno;	/* GRXCLSRULE fails even on a listed location */
	unsigned int rlall_calls;
} nic;

static int fake_socket(int domain, int type, int protocol)
{
	(void)domain;
	(void)type;
	(void)protocol;
	nic.open_fds++;
	return FAKE_FD;
}

static int fake_close(int fd)
{
	if (fd != FAKE_FD)
		abort();
	nic.open_fds--;
	return 0;
}

static unsigned int fake_if_nametoindex(const char *name)
{
	return strcmp(name, "eth0") ? 0 : FAKE_IFINDEX;
}

static unsigned int used_count(void)
{
	unsigned int i, n = 0;
	for (i = 0; i < FAKE_MAX; i++)
		n += nic.used[i];
	return n;
}

static int fail(int e)
{
	errno = e;
	return -1;
}

static int fake_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	struct ifreq *ifr;
	struct ethtool_rxnfc *c;
	uint32_t i, n, loc;
	va_start(ap, request);
	ifr = va_arg(ap, struct ifreq *);
	va_end(ap);
	if (fd != FAKE_FD || request != SIOCETHTOOL || !ifr->ifr_data)
		return fail(EINVAL);
	c = (void *)ifr->ifr_data;
	switch (c->cmd) {
	case ETHTOOL_GRXRINGS:
		c->data = 8;
		return 0;
	case ETHTOOL_GRXCLSRLCNT:
		c->rule_cnt = used_count();
		c->data = nic.loc_special ? (nic.size | RX_CLS_LOC_SPECIAL)
			  : nic.cnt_reports_size ? nic.size
						 : 0;
		return 0;
	case ETHTOOL_GRXCLSRLALL:
		nic.rlall_calls++;
		c->data = nic.size;
		n = 0;
		for (i = 0; i < FAKE_MAX; i++) {
			if (!nic.used[i])
				continue;
			if (n == c->rule_cnt)
				return fail(EMSGSIZE);
			c->rule_locs[n++] = i;
		}
		c->rule_cnt = n;
		return 0;
	case ETHTOOL_GRXCLSRULE:
		i = c->fs.location;
		if (nic.get_force_errno)
			return fail(nic.get_force_errno);
		if (i >= FAKE_MAX || !nic.used[i])
			/* ice_get_ethtool_fdir_entry: no rule at index -> -EINVAL */
			return fail(nic.get_absent_errno);
		c->fs = nic.rule[i];
		return 0;
	case ETHTOOL_SRXCLSRLINS:
		loc = c->fs.location;
		nic.last_requested_location = loc;
		if (nic.loc_special && loc == RX_CLS_LOC_ANY) {
			for (loc = 0; loc < nic.size && nic.used[loc]; loc++) {
			}
			if (loc == nic.size)
				return fail(ENOSPC);
		} else if (loc >= nic.size) {
			/* ice_add_fdir_ethtool: location >= max -> -ENOSPC */
			return fail(ENOSPC);
		}
		if (nic.used[loc])
			nic.replaced++; /* driver treats it as an update */
		else if (used_count() >= nic.pool)
			return fail(ENOSPC);
		c->fs.location = loc;
		nic.used[loc] = true;
		nic.rule[loc] = c->fs;
		nic.inserts++;
		return 0;
	case ETHTOOL_SRXCLSRLDEL:
		i = c->fs.location;
		if (i >= FAKE_MAX || !nic.used[i])
			return fail(ENOENT);
		nic.used[i] = false;
		nic.deletes++;
		return 0;
	default:
		return fail(EOPNOTSUPP);
	}
}

#define socket fake_socket
#define close fake_close
#define ioctl fake_ioctl
#define if_nametoindex fake_if_nametoindex
#include "xdev_ext_xsk_steer.c"
#undef socket
#undef close
#undef ioctl
#undef if_nametoindex

static unsigned int failures;
#define check(cond, msg)                                                      \
	do {                                                                  \
		if (cond)                                                     \
			printf("ok - %s\n", msg);                             \
		else {                                                        \
			printf("not ok - %s (line %d)\n", msg, __LINE__);     \
			failures++;                                           \
		}                                                             \
	} while (0)

static const struct xdev_ext_xsk_flow_filter flow = {
	.dst_ipv4 = 0x0a000002, .dst_port = 4791};

static void reset(bool special, bool cnt_size, uint32_t size)
{
	memset(&nic, 0, sizeof(nic));
	nic.loc_special = special;
	nic.cnt_reports_size = cnt_size;
	nic.size = size;
	nic.pool = size;
	nic.get_absent_errno = ENOENT;
}

/* A foreign rule that cannot overlap our UDP/IPv4 tuple. */
static void foreign(uint32_t loc)
{
	struct ethtool_rx_flow_spec fs = {0};
	fs.flow_type = TCP_V4_FLOW;
	fs.location = loc;
	fs.ring_cookie = 1;
	fs.h_u.tcp_ip4_spec.pdst = htons(80);
	fs.m_u.tcp_ip4_spec.pdst = UINT16_MAX;
	nic.used[loc] = true;
	nic.rule[loc] = fs;
}

static int add(struct ethtool_rx_flow_spec *owned, bool *uncertain,
	       struct xdev_ext_xsk_shared_error *err)
{
	memset(err, 0, sizeof(*err));
	return xdev_ext_xsk_steer_add("eth0", FAKE_IFINDEX, 3, &flow, owned,
				      uncertain, err);
}

static void fixed_location(const char *model, bool cnt_size, int absent)
{
	struct ethtool_rx_flow_spec owned, saved[4];
	struct xdev_ext_xsk_shared_error err;
	bool uncertain;
	char msg[160];
	int ret;

	printf("# %s: empty table\n", model);
	reset(false, cnt_size, 16);
	nic.get_absent_errno = absent;
	ret = add(&owned, &uncertain, &err);
	snprintf(msg, sizeof(msg),
		 "%s: insert succeeds without RX_CLS_LOC_SPECIAL (ret=%d)",
		 model, ret);
	check(ret == 0, msg);
	check(nic.last_requested_location < nic.size,
	      "explicit location below the advertised size is requested");
	check(!uncertain && owned.location < nic.size &&
		  nic.used[owned.location],
	      "owned rule records the inserted location");
	check(nic.replaced == 0 && nic.open_fds == 0,
	      "no rule replaced; control socket closed");
	ret = xdev_ext_xsk_steer_remove("eth0", FAKE_IFINDEX, &owned, &err);
	check(ret == 0 && used_count() == 0, "remove deletes our rule");

	printf("# %s: rule already gone before remove\n", model);
	reset(false, cnt_size, 16);
	nic.get_absent_errno = absent;
	foreign(0);
	ret = add(&owned, &uncertain, &err);
	check(ret == 0 && owned.location == 1, "rule inserted at location 1");
	nic.used[owned.location] = false; /* removed behind our back */
	memset(&err, 0, sizeof(err));
	ret = xdev_ext_xsk_steer_remove("eth0", FAKE_IFINDEX, &owned, &err);
	snprintf(msg, sizeof(msg),
		 "%s: vanished rule (GRXCLSRULE errno %d) counts as removed "
		 "(ret=%d)", model, absent, ret);
	check(ret == 0 && err.error == 0, msg);
	check(nic.deletes == 0 && nic.used[0] && nic.open_fds == 0,
	      "nothing deleted; foreign rule kept; socket closed");

	printf("# %s: GRXCLSRULE -EINVAL on a listed location\n", model);
	reset(false, cnt_size, 16);
	nic.get_absent_errno = absent;
	ret = add(&owned, &uncertain, &err);
	check(ret == 0, "rule inserted");
	nic.get_force_errno = EINVAL;
	ret = xdev_ext_xsk_steer_remove("eth0", FAKE_IFINDEX, &owned, &err);
	check(ret == -EINVAL && err.error == -EINVAL &&
		  nic.used[owned.location] && nic.deletes == 0,
	      "-EINVAL while the location is still listed is a failure");
	check(nic.open_fds == 0, "socket closed after failed remove");

	printf("# %s: existing foreign rules\n", model);
	reset(false, cnt_size, 16);
	foreign(0);
	foreign(1);
	foreign(3);
	saved[0] = nic.rule[0];
	saved[1] = nic.rule[1];
	saved[3] = nic.rule[3];
	ret = add(&owned, &uncertain, &err);
	check(ret == 0 && owned.location == 2,
	      "lowest free location (2) chosen between foreign rules");
	check(nic.replaced == 0, "no foreign rule replaced");
	ret = xdev_ext_xsk_steer_remove("eth0", FAKE_IFINDEX, &owned, &err);
	check(ret == 0 && nic.deletes == 1 && !nic.used[2],
	      "remove deletes only our rule");
	check(nic.used[0] && nic.used[1] && nic.used[3] &&
		  !memcmp(&nic.rule[0], &saved[0], sizeof(saved[0])) &&
		  !memcmp(&nic.rule[1], &saved[1], sizeof(saved[1])) &&
		  !memcmp(&nic.rule[3], &saved[3], sizeof(saved[3])),
	      "foreign rules intact after remove");

	printf("# %s: full table\n", model);
	reset(false, cnt_size, 4);
	foreign(0);
	foreign(1);
	foreign(2);
	foreign(3);
	ret = add(&owned, &uncertain, &err);
	check(ret == -ENOSPC && nic.inserts == 0 && !uncertain,
	      "full table reports -ENOSPC without inserting");
	check(err.error == -ENOSPC && strstr(err.reason, "full"),
	      "full table error names the full rule table");
	check(nic.replaced == 0 && used_count() == 4, "full table untouched");

	printf("# %s: hardware pool exhausted below the table size\n", model);
	reset(false, cnt_size, 8);
	nic.pool = 1;
	foreign(0);
	ret = add(&owned, &uncertain, &err);
	check(ret == -ENOSPC && !uncertain && strstr(err.reason, "full"),
	      "driver -ENOSPC on insert reported as a full table");

	printf("# %s: overlapping foreign rule still refused\n", model);
	reset(false, cnt_size, 8);
	nic.used[5] = true;
	nic.rule[5].flow_type = UDP_V4_FLOW;
	nic.rule[5].location = 5;
	ret = add(&owned, &uncertain, &err);
	check(ret == -EADDRINUSE && nic.inserts == 0,
	      "wildcard UDP rule overlaps and is not displaced");
}

static void driver_allocates(void)
{
	struct ethtool_rx_flow_spec owned;
	struct xdev_ext_xsk_shared_error err;
	bool uncertain;
	int ret;

	printf("# driver-allocates: existing rules\n");
	reset(true, true, 16);
	foreign(0);
	foreign(2);
	ret = add(&owned, &uncertain, &err);
	check(ret == 0 && nic.last_requested_location == RX_CLS_LOC_ANY,
	      "RX_CLS_LOC_ANY kept when the driver advertises it");
	check(owned.location == 1 && nic.replaced == 0,
	      "driver-chosen location recorded");
	ret = xdev_ext_xsk_steer_remove("eth0", FAKE_IFINDEX, &owned, &err);
	check(ret == 0 && nic.used[0] && nic.used[2] && !nic.used[1],
	      "remove deletes only our rule");

	printf("# driver-allocates: full table\n");
	reset(true, true, 2);
	foreign(0);
	foreign(1);
	ret = add(&owned, &uncertain, &err);
	check(ret == -ENOSPC && nic.inserts == 0 && !uncertain &&
		  strstr(err.reason, "full"),
	      "driver full table reported as -ENOSPC");
}

static void no_size(void)
{
	struct ethtool_rx_flow_spec owned;
	struct xdev_ext_xsk_shared_error err;
	bool uncertain;
	int ret;

	printf("# no table size and no RX_CLS_LOC_SPECIAL\n");
	reset(false, false, 0);
	ret = add(&owned, &uncertain, &err);
	check(ret == -EOPNOTSUPP && nic.inserts == 0,
	      "unknown table size refuses without inserting");
}

int main(void)
{
	fixed_location("ice-like", true, EINVAL);
	fixed_location("igb/mlx5-like", false, ENOENT);
	driver_allocates();
	no_size();
	printf("%s steer_location failures=%u\n", failures ? "FAIL" : "PASS",
	       failures);
	return failures ? 1 : 0;
}

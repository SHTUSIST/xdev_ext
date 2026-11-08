// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/xdev_ext_xsk_steer.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int error_set(struct xdev_ext_xsk_shared_error *error, int ret,
		     const char *operation, const char *reason)
{
	if (error) {
		memset(error, 0, sizeof(*error));
		error->error = ret;
		snprintf(error->operation, sizeof(error->operation), "%s",
			 operation);
		snprintf(error->reason, sizeof(error->reason), "%s", reason);
	}
	return ret;
}

int xdev_ext_xsk_steer_check_interface(const char *ifname,
				       uint32_t expected_ifindex)
{
	unsigned int current;
	if (!ifname || !*ifname || strlen(ifname) >= IF_NAMESIZE ||
	    !expected_ifindex)
		return -EINVAL;
	current = if_nametoindex(ifname);
	return current == expected_ifindex ? 0 : -EXDEV;
}

static int eth(int fd, const char *ifname, uint32_t expected_ifindex,
	       struct ethtool_rxnfc *req)
{
	struct ifreq ifr = {0};
	int ret = xdev_ext_xsk_steer_check_interface(ifname, expected_ifindex);
	if (ret)
		return ret;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	ifr.ifr_data = (void *)req;
	return ioctl(fd, SIOCETHTOOL, &ifr) < 0 ? -errno : 0;
}

/* Conservative intersection: unfamiliar rules are never displaced. */
static bool overlap(const struct ethtool_rx_flow_spec *a,
		    const struct ethtool_rx_flow_spec *b)
{
	uint32_t type = b->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS);
	const struct ethtool_tcpip4_spec *ah = &a->h_u.udp_ip4_spec;
	const struct ethtool_tcpip4_spec *am = &a->m_u.udp_ip4_spec;
	const struct ethtool_tcpip4_spec *bh = &b->h_u.udp_ip4_spec;
	const struct ethtool_tcpip4_spec *bm = &b->m_u.udp_ip4_spec;
	if (type == TCP_V4_FLOW || type == SCTP_V4_FLOW ||
	    type == TCP_V6_FLOW || type == UDP_V6_FLOW ||
	    type == SCTP_V6_FLOW || type == AH_V4_FLOW || type == ESP_V4_FLOW ||
	    type == AH_V6_FLOW || type == ESP_V6_FLOW)
		return false;
	if (type != UDP_V4_FLOW)
		return true;
	return !(((ah->ip4src ^ bh->ip4src) & am->ip4src & bm->ip4src) |
		 ((ah->ip4dst ^ bh->ip4dst) & am->ip4dst & bm->ip4dst) |
		 ((ah->psrc ^ bh->psrc) & am->psrc & bm->psrc) |
		 ((ah->pdst ^ bh->pdst) & am->pdst & bm->pdst) |
		 ((ah->tos ^ bh->tos) & am->tos & bm->tos));
}

/*
 * Lowest location below the advertised table size that no listed rule uses.
 * Drivers without RX_CLS_LOC_SPECIAL (ice, igb, mlx5) need an explicit
 * location and treat an occupied one as a replacement of that rule.
 */
static int free_location(const struct ethtool_rxnfc *all, uint32_t *location)
{
	uint32_t size = all->data, i;
	unsigned char *taken;
	if (!size)
		return -EOPNOTSUPP;
	if (size > 65536)
		size = 65536;
	taken = calloc(size, 1);
	if (!taken)
		return -ENOMEM;
	for (i = 0; i < all->rule_cnt; i++)
		if (all->rule_locs[i] < size)
			taken[all->rule_locs[i]] = 1;
	for (i = 0; i < size && taken[i]; i++)
		;
	free(taken);
	if (i == size)
		return -ENOSPC;
	*location = i;
	return 0;
}

static int admit_rules(int fd, const char *ifname, uint32_t expected_ifindex,
		       const struct ethtool_rx_flow_spec *wanted,
		       uint32_t *location)
{
	unsigned int attempt;
	for (attempt = 0; attempt < 3; attempt++) {
		struct ethtool_rxnfc cnt = {.cmd = ETHTOOL_GRXCLSRLCNT};
		struct ethtool_rxnfc *all;
		uint32_t i, count;
		int ret = eth(fd, ifname, expected_ifindex, &cnt);
		if (ret)
			return ret;
		count = cnt.rule_cnt;
		if (count > 65536)
			return -E2BIG;
		all =
		    calloc(1, sizeof(*all) + (size_t)count * sizeof(uint32_t));
		if (!all)
			return -ENOMEM;
		all->cmd = ETHTOOL_GRXCLSRLALL;
		all->rule_cnt = count;
		ret = eth(fd, ifname, expected_ifindex, all);
		if (ret == -EMSGSIZE || (!ret && all->rule_cnt > count)) {
			free(all);
			continue;
		}
		if (ret) {
			free(all);
			return ret;
		}
		for (i = 0; i < all->rule_cnt; i++) {
			struct ethtool_rxnfc one = {.cmd = ETHTOOL_GRXCLSRULE};
			one.fs.location = all->rule_locs[i];
			ret = eth(fd, ifname, expected_ifindex, &one);
			if (ret)
				break;
			if (overlap(wanted, &one.fs)) {
				ret = -EADDRINUSE;
				break;
			}
		}
		if (!ret) {
			*location = RX_CLS_LOC_ANY;
			if (!(cnt.data & RX_CLS_LOC_SPECIAL))
				ret = free_location(all, location);
		}
		free(all);
		return ret;
	}
	return -EAGAIN;
}

int xdev_ext_xsk_steer_add(const char *ifname, uint32_t expected_ifindex,
			   uint32_t queue,
			   const struct xdev_ext_xsk_flow_filter *filter,
			   struct ethtool_rx_flow_spec *owned,
			   bool *insert_uncertain,
			   struct xdev_ext_xsk_shared_error *error)
{
	struct ethtool_rxnfc req = {.cmd = ETHTOOL_GRXRINGS};
	int fd, ret;
	if (!ifname || !*ifname || strlen(ifname) >= IF_NAMESIZE || !filter ||
	    !owned || !insert_uncertain || !expected_ifindex)
		return error_set(error, -EINVAL, "ntuple",
				 "Invalid steering options");
	memset(owned, 0, sizeof(*owned));
	*insert_uncertain = false;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return error_set(error, -errno, "ntuple-socket",
				 "Cannot open ethtool control socket");
	ret = eth(fd, ifname, expected_ifindex, &req);
	if (ret)
		goto unsupported;
	if (queue >= req.data) {
		ret = -ERANGE;
		goto out;
	}
	memset(&req, 0, sizeof(req));
	req.cmd = ETHTOOL_SRXCLSRLINS;
	req.fs.flow_type = UDP_V4_FLOW;
	req.fs.ring_cookie = queue;
	req.fs.h_u.udp_ip4_spec.ip4dst = htonl(filter->dst_ipv4);
	req.fs.m_u.udp_ip4_spec.ip4dst = UINT32_MAX;
	req.fs.h_u.udp_ip4_spec.pdst = htons(filter->dst_port);
	req.fs.m_u.udp_ip4_spec.pdst = UINT16_MAX;
	if (filter->flags & XDEV_EXT_XSK_FILTER_F_SRC_IPV4) {
		req.fs.h_u.udp_ip4_spec.ip4src = htonl(filter->src_ipv4);
		req.fs.m_u.udp_ip4_spec.ip4src = UINT32_MAX;
	}
	if (filter->flags & XDEV_EXT_XSK_FILTER_F_SRC_PORT) {
		req.fs.h_u.udp_ip4_spec.psrc = htons(filter->src_port);
		req.fs.m_u.udp_ip4_spec.psrc = UINT16_MAX;
	}
	ret = admit_rules(fd, ifname, expected_ifindex, &req.fs,
			  &req.fs.location);
	if (ret)
		goto unsupported;
	ret = eth(fd, ifname, expected_ifindex, &req);
	if (ret)
		goto unsupported;
	*insert_uncertain = true;
	if (req.fs.location & RX_CLS_LOC_SPECIAL) {
		ret = -EPROTO;
		goto out;
	}
	*owned = req.fs;
	*insert_uncertain = false;
	goto out;
unsupported:
	if (ret == -EINVAL || ret == -ENOTTY || ret == -ENOSYS)
		ret = -EOPNOTSUPP;
out:
	close(fd);
	if (!ret)
		return 0;
	return error_set(
	    error, ret, "ntuple-add",
	    ret == -EOPNOTSUPP ? "Interface lacks safe ntuple/unused-location "
				 "allocation support; channels were not changed"
	    : ret == -EADDRINUSE
		? "Existing hardware rule overlaps this UDP tuple; payload "
		  "magic is not a hardware steering key"
	    : ret == -EXDEV
		? "Interface name no longer identifies the retained ifindex; "
		  "no ethtool mutation was performed"
	    : ret == -ERANGE
		? "Requested queue is outside the interface RX queue count"
	    : ret == -ENOSPC
		? "Hardware RX rule table is full; no session rule was "
		  "inserted"
		: "Cannot install the session's hardware RX rule");
}

/*
 * 1 when GRXCLSRLALL lists @location, 0 when it does not, -errno on failure.
 * ice answers GRXCLSRULE on an empty location with -EINVAL rather than
 * -ENOENT (ice_get_ethtool_fdir_entry), so -EINVAL alone cannot tell an
 * absent rule from a refused request.
 */
static int location_listed(int fd, const char *ifname,
			   uint32_t expected_ifindex, uint32_t location)
{
	unsigned int attempt;
	for (attempt = 0; attempt < 3; attempt++) {
		struct ethtool_rxnfc cnt = {.cmd = ETHTOOL_GRXCLSRLCNT};
		struct ethtool_rxnfc *all;
		uint32_t i, count;
		int ret = eth(fd, ifname, expected_ifindex, &cnt);
		if (ret)
			return ret;
		count = cnt.rule_cnt;
		if (count > 65536)
			return -E2BIG;
		all =
		    calloc(1, sizeof(*all) + (size_t)count * sizeof(uint32_t));
		if (!all)
			return -ENOMEM;
		all->cmd = ETHTOOL_GRXCLSRLALL;
		all->rule_cnt = count;
		ret = eth(fd, ifname, expected_ifindex, all);
		if (ret == -EMSGSIZE || (!ret && all->rule_cnt > count)) {
			free(all);
			continue;
		}
		if (!ret)
			for (i = 0; i < all->rule_cnt && !ret; i++)
				ret = all->rule_locs[i] == location;
		free(all);
		return ret;
	}
	return -EAGAIN;
}

int xdev_ext_xsk_steer_remove(const char *ifname, uint32_t expected_ifindex,
			      const struct ethtool_rx_flow_spec *owned,
			      struct xdev_ext_xsk_shared_error *error)
{
	struct ethtool_rxnfc req = {.cmd = ETHTOOL_GRXCLSRULE};
	int fd, ret;
	if (!ifname || !owned || !expected_ifindex ||
	    (owned->location & RX_CLS_LOC_SPECIAL))
		return error_set(error, -EINVAL, "ntuple-remove",
				 "Invalid owned rule");
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return error_set(error, -errno, "ntuple-socket",
				 "Cannot open ethtool control socket");
	req.fs.location = owned->location;
	ret = eth(fd, ifname, expected_ifindex, &req);
	if (ret == -EINVAL) {
		int listed = location_listed(fd, ifname, expected_ifindex,
					     owned->location);
		if (!listed)
			ret = -ENOENT;
		else if (listed < 0 && listed != -EOPNOTSUPP &&
			 listed != -EINVAL)
			ret = listed;
	}
	if (ret == -ENOENT)
		ret = 0;
	else if (!ret) {
		if (memcmp(&req.fs, owned, sizeof(*owned)))
			ret = -ESTALE;
		else {
			memset(&req, 0, sizeof(req));
			req.cmd = ETHTOOL_SRXCLSRLDEL;
			req.fs.location = owned->location;
			ret = eth(fd, ifname, expected_ifindex, &req);
			if (ret == -ENOENT)
				ret = 0;
		}
	}
	close(fd);
	return ret ? error_set(
			 error, ret, "ntuple-remove",
			 ret == -EXDEV ? "Interface name no longer identifies "
					 "the retained ifindex; no ethtool "
					 "mutation was performed"
			 : ret == -ESTALE
			     ? "Recorded ntuple location now belongs to a "
			       "different rule; it was not deleted"
			     : "Cannot remove the recorded session ntuple rule")
		   : 0;
}

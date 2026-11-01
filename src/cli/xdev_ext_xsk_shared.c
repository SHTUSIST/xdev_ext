// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/xdev_ext_xsk_shared.h"
#include "include/xdev_ext_xsk_shared_prog.h"
#include "include/xdev_ext_xsk_steer.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/magic.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/xdp_diag.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <unistd.h>

#define MAXQ XDEV_EXT_XSK_REDIRECT_MAX_QUEUES
#define PHASE_PREPARE 1U
#define PHASE_INSERT 2U
#define PHASE_RULE 3U
#define PHASE_ACTIVE 4U
#define PHASE_CLOSING 5U
struct shared_meta {
	uint64_t ns_dev, ns_ino, lock_dev, lock_ino;
	uint32_t abi, uid, ifindex, mode;
};
struct shared_owner {
	uint32_t phase, queue;
	struct xdev_ext_xsk_shared_key key;
	struct xdev_ext_xsk_shared_flow flow;
	struct ethtool_rx_flow_spec rule;
};
struct xdev_ext_xsk_shared {
	int global_fd, queue_fd, ns_fd, xsk_fd, state_fd, pin_fd;
	int xsks, flows, owners, meta, prog, link;
	pid_t pid;
	char ifname[IF_NAMESIZE], pins[PATH_MAX];
	struct shared_meta identity;
	struct shared_owner owner;
	bool registered, created, teardown, rule_valid, uncertain, mapped,
	    published, link_detached;
};

static int fail(struct xdev_ext_xsk_shared_error *e, int ret, const char *op,
		const char *reason)
{
	if (e) {
		memset(e, 0, sizeof(*e));
		e->error = ret;
		snprintf(e->operation, sizeof(e->operation), "%s", op);
		snprintf(e->reason, sizeof(e->reason), "%s", reason);
	}
	return ret;
}
static int neg(int ret)
{
	return ret < 0 ? -errno : ret;
}
static int close_fd(int *fd)
{
	int ret = 0;
	if (*fd >= 0) {
		ret = close(*fd) < 0 ? -errno : 0;
		*fd = -1;
	}
	return ret;
}
static void release(struct xdev_ext_xsk_shared *h)
{
	close_fd(&h->link);
	close_fd(&h->prog);
	close_fd(&h->xsks);
	close_fd(&h->flows);
	close_fd(&h->owners);
	close_fd(&h->meta);
	close_fd(&h->queue_fd);
	close_fd(&h->global_fd);
	close_fd(&h->ns_fd);
	close_fd(&h->xsk_fd);
	close_fd(&h->pin_fd);
	close_fd(&h->state_fd);
	free(h);
}
static int secure_dir(int parent, const char *name)
{
	struct stat st;
	int fd;
	if (mkdirat(parent, name, 0700) < 0 && errno != EEXIST)
		return -errno;
	fd = openat(parent, name,
		    O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0) {
		int ret = -errno;
		close(fd);
		return ret;
	}
	if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
	    (st.st_mode & 0777) != 0700) {
		close(fd);
		return -EACCES;
	}
	return fd;
}
static int lock_file(int parent, const char *name)
{
	struct stat st;
	int fd = openat(parent, name, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
			0600);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0) {
		int ret = -errno;
		close(fd);
		return ret;
	}
	if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
	    (st.st_mode & 0777) != 0600 || st.st_nlink != 1) {
		close(fd);
		return -EACCES;
	}
	return fd;
}
static int roots(struct xdev_ext_xsk_shared *h)
{
	char name[128];
	struct stat st;
	struct statfs fs;
	int run = -1, bpf = -1, a = -1, b = -1, ret;
	snprintf(name, sizeof(name), "n%llu-%llu-i%u",
		 (unsigned long long)h->identity.ns_dev,
		 (unsigned long long)h->identity.ns_ino, h->identity.ifindex);
	run = open("/run", O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
	bpf = open("/sys/fs/bpf",
		   O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
	if (run < 0 || bpf < 0) {
		ret = -errno;
		goto out;
	}
	if (fstatfs(bpf, &fs) < 0) {
		ret = -errno;
		goto out;
	}
	if ((unsigned long)fs.f_type != (unsigned long)BPF_FS_MAGIC) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	a = secure_dir(run, "xdev_ext");
	if (a < 0) {
		ret = a;
		goto out;
	}
	b = secure_dir(a, "xsk");
	if (b < 0) {
		ret = b;
		goto out;
	}
	h->state_fd = secure_dir(b, name);
	if (h->state_fd < 0) {
		ret = h->state_fd;
		goto out;
	}
	close_fd(&a);
	close_fd(&b);
	a = secure_dir(bpf, "xdev_ext");
	if (a < 0) {
		ret = a;
		goto out;
	}
	b = secure_dir(a, "xsk");
	if (b < 0) {
		ret = b;
		goto out;
	}
	h->pin_fd = secure_dir(b, name);
	if (h->pin_fd < 0) {
		ret = h->pin_fd;
		goto out;
	}
	snprintf(h->pins, sizeof(h->pins), "/sys/fs/bpf/xdev_ext/xsk/%s", name);
	h->global_fd = lock_file(h->state_fd, "global.lock");
	if (h->global_fd < 0) {
		ret = h->global_fd;
		goto out;
	}
	if (fstat(h->global_fd, &st) < 0) {
		ret = -errno;
		goto out;
	}
	h->identity.lock_dev = st.st_dev;
	h->identity.lock_ino = st.st_ino;
	ret = 0;
out:
	close_fd(&a);
	close_fd(&b);
	close_fd(&run);
	close_fd(&bpf);
	return ret;
}
static int ns_identity(struct shared_meta *m, int *fd)
{
	struct stat st;
	*fd = open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
	if (*fd < 0)
		return -errno;
	if (fstat(*fd, &st) < 0) {
		int ret = -errno;
		close_fd(fd);
		return ret;
	}
	m->ns_dev = st.st_dev;
	m->ns_ino = st.st_ino;
	return 0;
}
static int same_namespace(const struct xdev_ext_xsk_shared *h)
{
	struct shared_meta m = {0};
	int fd = -1, ret;
	if (getpid() != h->pid)
		return -ECHILD;
	ret = ns_identity(&m, &fd);
	close_fd(&fd);
	if (ret)
		return ret;
	return m.ns_dev == h->identity.ns_dev && m.ns_ino == h->identity.ns_ino
		   ? 0
		   : -EXDEV;
}

int xdev_ext_xsk_shared_preflight(const struct xdev_ext_xsk_shared *h,
				  struct xdev_ext_xsk_shared_error *error)
{
	int ret;
	if (error)
		memset(error, 0, sizeof(*error));
	if (!h)
		return fail(error, -EINVAL, "origin-preflight",
			    "A shared owner handle is required");
	ret = same_namespace(h);
	return ret ? fail(error, ret, "origin-preflight",
			  "Operation must run in the originating process and "
			  "network namespace")
		   : 0;
}

static int sock_option(int fd, int option, void *out, socklen_t size)
{
	socklen_t len = size;
	if (getsockopt(fd, SOL_SOCKET, option, out, &len) < 0)
		return -errno;
	return len == size ? 0 : -EPROTO;
}
static int validate_xsk(struct xdev_ext_xsk_shared *h)
{
	uint64_t cookie = 0, net_cookie = 0, control_cookie = 0;
	int type = 0, domain = 0, ctl = -1, nl = -1, ret;
	struct stat st;
	struct sockaddr_nl addr = {.nl_family = AF_NETLINK};
	struct timeval timeout = {.tv_sec = 2};
	struct {
		struct nlmsghdr n;
		struct xdp_diag_req r;
	} req = {.n = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct xdp_diag_req)),
		       .nlmsg_type = SOCK_DIAG_BY_FAMILY,
		       .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		       .nlmsg_seq = 1},
		 .r = {.sdiag_family = AF_XDP, .xdiag_show = XDP_SHOW_INFO}};
	unsigned int messages = 0;
	struct xdp_options opts = {0};
	socklen_t len = sizeof(opts);
	if (fstat(h->xsk_fd, &st) < 0)
		return -errno;
	if (!S_ISSOCK(st.st_mode))
		return -ENOTSOCK;
	if ((ret =
		 sock_option(h->xsk_fd, SO_DOMAIN, &domain, sizeof(domain))) ||
	    (ret = sock_option(h->xsk_fd, SO_TYPE, &type, sizeof(type))))
		return ret;
	if (domain != AF_XDP || type != SOCK_RAW)
		return -EPROTOTYPE;
	if ((ret =
		 sock_option(h->xsk_fd, SO_COOKIE, &cookie, sizeof(cookie))) ||
	    (ret = sock_option(h->xsk_fd, SO_NETNS_COOKIE, &net_cookie,
			       sizeof(net_cookie))))
		return ret == -ENOPROTOOPT || ret == -EINVAL ? -EOPNOTSUPP
							     : ret;
	ctl = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ctl < 0)
		return -errno;
	ret = sock_option(ctl, SO_NETNS_COOKIE, &control_cookie,
			  sizeof(control_cookie));
	close_fd(&ctl);
	if (ret)
		return ret == -ENOPROTOOPT || ret == -EINVAL ? -EOPNOTSUPP
							     : ret;
	if (!cookie || !net_cookie || net_cookie != control_cookie)
		return -EXDEV;
	if (getsockopt(h->xsk_fd, SOL_XDP, XDP_OPTIONS, &opts, &len) < 0)
		return -errno;
	if (len != sizeof(opts))
		return -EPROTO;
	nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
	if (nl < 0)
		return errno == EPROTONOSUPPORT ? -EOPNOTSUPP : -errno;
	if (setsockopt(nl, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) <
	    0) {
		ret = -errno;
		goto out;
	}
	if (sendto(nl, &req, req.n.nlmsg_len, 0, (void *)&addr, sizeof(addr)) !=
	    (ssize_t)req.n.nlmsg_len) {
		ret = -errno;
		if (!ret)
			ret = -EIO;
		goto out;
	}
	for (;;) {
		unsigned char buf[16384];
		struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
		struct msghdr msg = {.msg_name = &addr,
				     .msg_namelen = sizeof(addr),
				     .msg_iov = &iov,
				     .msg_iovlen = 1};
		struct nlmsghdr *nh;
		ssize_t got = recvmsg(nl, &msg, 0);
		int remain;
		if (got < 0) {
			ret = -errno;
			goto out;
		}
		if (!got || (msg.msg_flags & MSG_TRUNC) || addr.nl_pid) {
			ret = -EPROTO;
			goto out;
		}
		remain = (int)got;
		for (nh = (void *)buf; NLMSG_OK(nh, remain);
		     nh = NLMSG_NEXT(nh, remain)) {
			struct xdp_diag_msg *di;
			struct nlattr *na;
			int attrs;
			if (++messages > 65536) {
				ret = -E2BIG;
				goto out;
			}
			if (nh->nlmsg_seq != 1 ||
			    (nh->nlmsg_flags & NLM_F_DUMP_INTR)) {
				ret = -EAGAIN;
				goto out;
			}
			if (nh->nlmsg_type == NLMSG_DONE) {
				ret = -ENOENT;
				goto out;
			}
			if (nh->nlmsg_type == NLMSG_ERROR) {
				if (nh->nlmsg_len <
				    NLMSG_LENGTH(sizeof(struct nlmsgerr)))
					ret = -EPROTO;
				else
					ret =
					    ((struct nlmsgerr *)NLMSG_DATA(nh))
						->error;
				if (ret == -EINVAL || ret == -ENOENT ||
				    ret == -EAFNOSUPPORT ||
				    ret == -EPROTONOSUPPORT)
					ret = -EOPNOTSUPP;
				if (!ret)
					ret = -EPROTO;
				goto out;
			}
			if (nh->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
			    nh->nlmsg_len < NLMSG_LENGTH(sizeof(*di))) {
				ret = -EPROTO;
				goto out;
			}
			di = NLMSG_DATA(nh);
			if (di->xdiag_family != AF_XDP ||
			    di->xdiag_type != SOCK_RAW) {
				ret = -EPROTO;
				goto out;
			}
			if (di->xdiag_ino != (uint32_t)st.st_ino ||
			    ((uint64_t)di->xdiag_cookie[0] |
			     ((uint64_t)di->xdiag_cookie[1] << 32)) != cookie)
				continue;
			attrs =
			    (int)nh->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*di));
			na = (void *)((char *)di + NLMSG_ALIGN(sizeof(*di)));
			for (; attrs >= (int)sizeof(*na);) {
				if (na->nla_len < sizeof(*na) ||
				    na->nla_len > attrs) {
					ret = -EPROTO;
					goto out;
				}
				if ((na->nla_type & NLA_TYPE_MASK) ==
				    XDP_DIAG_INFO) {
					struct xdp_diag_info info;
					if (na->nla_len !=
					    NLA_HDRLEN + sizeof(info)) {
						ret = -EPROTO;
						goto out;
					}
					memcpy(&info, (char *)na + NLA_HDRLEN,
					       sizeof(info));
					ret = info.ifindex ==
							  h->identity.ifindex &&
						      info.queue_id ==
							  h->owner.queue
						  ? 0
						  : -EXDEV;
					goto out;
				}
				attrs -= NLA_ALIGN(na->nla_len);
				na = (void *)((char *)na +
					      NLA_ALIGN(na->nla_len));
			}
			ret = -ENOTCONN;
			goto out;
		}
		if (remain) {
			ret = -EPROTO;
			goto out;
		}
	}
out:
	close_fd(&nl);
	return ret;
}

static int pin_path(struct xdev_ext_xsk_shared *h, const char *name,
		    char path[PATH_MAX])
{
	int n = snprintf(path, PATH_MAX, "%s/%s", h->pins, name);
	return n < 0 || n >= PATH_MAX ? -ENAMETOOLONG : 0;
}
static int get_pin(struct xdev_ext_xsk_shared *h, const char *name)
{
	char path[PATH_MAX];
	int ret = pin_path(h, name, path);
	return ret ? ret : neg(bpf_obj_get(path));
}
static int set_pin(struct xdev_ext_xsk_shared *h, const char *name, int fd)
{
	char path[PATH_MAX];
	int ret = pin_path(h, name, path);
	return ret ? ret : neg(bpf_obj_pin(fd, path));
}
static int unpin(struct xdev_ext_xsk_shared *h, const char *name, int expected)
{
	char path[PATH_MAX];
	uint32_t a = 0, b = 0, len;
	struct bpf_map_info mi = {0};
	struct bpf_prog_info pi = {0};
	struct bpf_link_info li = {0};
	int fd, ret = pin_path(h, name, path);
	if (ret)
		return ret;
	fd = neg(bpf_obj_get(path));
	if (fd == -ENOENT)
		return 0;
	if (fd < 0)
		return fd;
	if (!strcmp(name, "link")) {
		len = sizeof(li);
		ret = neg(bpf_obj_get_info_by_fd(expected, &li, &len));
		a = li.id;
		memset(&li, 0, sizeof(li));
		len = sizeof(li);
		if (!ret)
			ret = neg(bpf_obj_get_info_by_fd(fd, &li, &len));
		b = li.id;
	} else if (!strcmp(name, "prog")) {
		len = sizeof(pi);
		ret = neg(bpf_obj_get_info_by_fd(expected, &pi, &len));
		a = pi.id;
		memset(&pi, 0, sizeof(pi));
		len = sizeof(pi);
		if (!ret)
			ret = neg(bpf_obj_get_info_by_fd(fd, &pi, &len));
		b = pi.id;
	} else {
		len = sizeof(mi);
		ret = neg(bpf_obj_get_info_by_fd(expected, &mi, &len));
		a = mi.id;
		memset(&mi, 0, sizeof(mi));
		len = sizeof(mi);
		if (!ret)
			ret = neg(bpf_obj_get_info_by_fd(fd, &mi, &len));
		b = mi.id;
	}
	close(fd);
	if (ret)
		return ret;
	if (!a || a != b)
		return -ESTALE;
	return unlink(path) < 0 && errno != ENOENT ? -errno : 0;
}
static int map_new(enum bpf_map_type type, const char *name, uint32_t value,
		   uint32_t max)
{
	return neg(
	    bpf_map_create(type, name, sizeof(uint32_t), value, max, NULL));
}
static int schema(int fd, uint32_t type, uint32_t key, uint32_t value,
		  uint32_t max, uint32_t *id)
{
	struct bpf_map_info mi = {0};
	uint32_t len = sizeof(mi);
	int ret = neg(bpf_obj_get_info_by_fd(fd, &mi, &len));
	if (ret)
		return ret;
	if (mi.type != type || mi.key_size != key || mi.value_size != value ||
	    mi.max_entries != max || mi.map_flags || !mi.id)
		return -ESTALE;
	if (id)
		*id = mi.id;
	return 0;
}
int xdev_ext_xsk_shared_build_program(int xsks, int flows, struct bpf_insn *p,
				      size_t cap, size_t *count)
{
	return xdev_ext_shared_program(xsks, flows, p, cap, count);
}
static int prog_new(int xsks, int flows)
{
	struct bpf_insn p[XDEV_EXT_XSK_SHARED_MAX_INSNS];
	char log[16384] = {0};
	size_t n = 0;
	struct bpf_prog_load_opts opts = {.sz = sizeof(opts),
					  .log_buf = log,
					  .log_size = sizeof(log),
					  .log_level = 1};
	int ret = xdev_ext_xsk_shared_build_program(
	    xsks, flows, p, XDEV_EXT_XSK_SHARED_MAX_INSNS, &n);
	return ret ? ret
		   : neg(bpf_prog_load(BPF_PROG_TYPE_XDP, "xdev_xsk_shared",
				       "GPL", p, n, &opts));
}
static int verify_objects(struct xdev_ext_xsk_shared *h)
{
	struct shared_meta meta = {0};
	struct bpf_prog_info pi = {0};
	struct bpf_link_info li = {0};
	uint32_t zero = 0, len, ids[2] = {0}, xid, fid, current = 0;
	int ret = schema(h->xsks, BPF_MAP_TYPE_XSKMAP, 4, 4, MAXQ, &xid);
	if (!ret)
		ret =
		    schema(h->flows, BPF_MAP_TYPE_HASH,
			   sizeof(struct xdev_ext_xsk_shared_key),
			   sizeof(struct xdev_ext_xsk_shared_flow), MAXQ, &fid);
	if (!ret)
		ret = schema(h->owners, BPF_MAP_TYPE_HASH, 4,
			     sizeof(struct shared_owner), MAXQ, NULL);
	if (!ret)
		ret = schema(h->meta, BPF_MAP_TYPE_ARRAY, 4,
			     sizeof(struct shared_meta), 1, NULL);
	if (!ret)
		ret = neg(bpf_map_lookup_elem(h->meta, &zero, &meta));
	if (ret)
		return ret;
	if (meta.mode != h->identity.mode) {
		uint32_t mode = meta.mode;
		meta.mode = h->identity.mode;
		if (!memcmp(&meta, &h->identity, sizeof(meta)))
			return -EBUSY;
		meta.mode = mode;
	}
	if (memcmp(&meta, &h->identity, sizeof(meta)))
		return -ESTALE;
	pi.nr_map_ids = 2;
	pi.map_ids = (uintptr_t)ids;
	len = sizeof(pi);
	ret = neg(bpf_obj_get_info_by_fd(h->prog, &pi, &len));
	if (ret)
		return ret;
	if (!pi.id || pi.type != BPF_PROG_TYPE_XDP || pi.nr_map_ids != 2 ||
	    !((ids[0] == xid && ids[1] == fid) ||
	      (ids[0] == fid && ids[1] == xid)))
		return -ESTALE;
	len = sizeof(li);
	ret = neg(bpf_obj_get_info_by_fd(h->link, &li, &len));
	if (ret)
		return ret;
	if (li.type != BPF_LINK_TYPE_XDP || !li.id || li.prog_id != pi.id ||
	    li.xdp.ifindex != h->identity.ifindex)
		return -ESTALE;
	ret = bpf_xdp_query_id(h->identity.ifindex, h->identity.mode, &current);
	if (ret)
		return ret;
	return current == pi.id ? 0 : -ESTALE;
}
static int device_create(struct xdev_ext_xsk_shared *h)
{
	static const uint32_t modes[] = {XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE,
					 XDP_FLAGS_HW_MODE};
	struct bpf_link_create_opts opts = {.sz = sizeof(opts),
					    .flags = h->identity.mode};
	uint32_t zero = 0, id = 0;
	size_t i;
	int ret;
	const char *names[] = {"xsks", "flows", "owners",
			       "meta", "prog",	"link"};
	int *fds[] = {&h->xsks, &h->flows, &h->owners,
		      &h->meta, &h->prog,  &h->link};
	for (i = 0; i < 3; i++) {
		ret = bpf_xdp_query_id(h->identity.ifindex, modes[i], &id);
		if (ret)
			return ret;
		if (id)
			return -EBUSY;
	}
	/* An absent metadata pin is not authority to overwrite leftover pins.
	 */
	for (i = 0; i < 6; i++) {
		int fd = get_pin(h, names[i]);
		if (fd >= 0) {
			close_fd(&fd);
			return -ESTALE;
		}
		if (fd != -ENOENT)
			return fd;
	}
	h->created = true;
	h->xsks = map_new(BPF_MAP_TYPE_XSKMAP, "xdev_xsks", 4, MAXQ);
	if (h->xsks < 0)
		return h->xsks;
	h->flows = neg(bpf_map_create(BPF_MAP_TYPE_HASH, "xdev_flows",
				      sizeof(struct xdev_ext_xsk_shared_key),
				      sizeof(struct xdev_ext_xsk_shared_flow),
				      MAXQ, NULL));
	if (h->flows < 0)
		return h->flows;
	h->owners = map_new(BPF_MAP_TYPE_HASH, "xdev_owners",
			    sizeof(struct shared_owner), MAXQ);
	if (h->owners < 0)
		return h->owners;
	h->meta = map_new(BPF_MAP_TYPE_ARRAY, "xdev_meta",
			  sizeof(struct shared_meta), 1);
	if (h->meta < 0)
		return h->meta;
	ret = neg(bpf_map_update_elem(h->meta, &zero, &h->identity, BPF_ANY));
	if (ret)
		return ret;
	h->prog = prog_new(h->xsks, h->flows);
	if (h->prog < 0)
		return h->prog;
	/* Maps/prog pins are durable before attaching the persistent link. */
	for (i = 0; i < 5; i++) {
		ret = set_pin(h, names[i], *fds[i]);
		if (ret)
			return ret;
	}
	h->link =
	    neg(bpf_link_create(h->prog, h->identity.ifindex, BPF_XDP, &opts));
	if (h->link < 0)
		return h->link;
	return set_pin(h, "link", h->link);
}
static int device_get(struct xdev_ext_xsk_shared *h)
{
	h->meta = get_pin(h, "meta");
	if (h->meta == -ENOENT)
		return device_create(h);
	if (h->meta < 0)
		return h->meta;
	h->xsks = get_pin(h, "xsks");
	h->flows = get_pin(h, "flows");
	h->owners = get_pin(h, "owners");
	h->prog = get_pin(h, "prog");
	h->link = get_pin(h, "link");
	if (h->xsks < 0 || h->flows < 0 || h->owners < 0 || h->prog < 0 ||
	    h->link < 0)
		return -ESTALE;
	return verify_objects(h);
}
static int delete_elem(int fd, const void *key)
{
	int ret = neg(bpf_map_delete_elem(fd, key));
	return ret == -ENOENT ? 0 : ret;
}
static int owner_write(struct xdev_ext_xsk_shared *h)
{
	return neg(bpf_map_update_elem(h->owners, &h->owner.queue, &h->owner,
				       BPF_EXIST));
}
static int own_flow_delete(struct xdev_ext_xsk_shared *h,
			   const struct shared_owner *o)
{
	struct xdev_ext_xsk_shared_flow f;
	int ret = neg(bpf_map_lookup_elem(h->flows, &o->key, &f));
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return ret;
	if (memcmp(&f, &o->flow, sizeof(f)))
		return -ESTALE;
	return delete_elem(h->flows, &o->key);
}
static int recover_owners(struct xdev_ext_xsk_shared *h)
{
	uint32_t keys[MAXQ], key, next, n = 0, i;
	int ret =
	    xdev_ext_xsk_steer_check_interface(h->ifname, h->identity.ifindex);
	if (ret)
		return ret;
	ret = neg(bpf_map_get_next_key(h->owners, NULL, &next));
	while (!ret) {
		if (n >= MAXQ)
			return -E2BIG;
		keys[n++] = next;
		key = next;
		ret = neg(bpf_map_get_next_key(h->owners, &key, &next));
	}
	if (ret != -ENOENT)
		return ret;
	for (i = 0; i < n; i++) {
		struct shared_owner o;
		char name[40];
		int fd;
		if (h->registered && keys[i] == h->owner.queue)
			continue;
		ret = neg(bpf_map_lookup_elem(h->owners, &keys[i], &o));
		if (ret)
			return ret;
		if (o.queue != keys[i] || o.queue >= MAXQ || o.key.reserved ||
		    o.flow.reserved || o.flow.queue_id != o.queue)
			return -ESTALE;
		snprintf(name, sizeof(name), "queue-%u.lock", o.queue);
		fd = -1;
		if (keys[i] != h->owner.queue) {
			fd = lock_file(h->state_fd, name);
			if (fd < 0)
				return fd;
		}
		if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) < 0) {
			ret = -errno;
			close(fd);
			if (ret == -EWOULDBLOCK || ret == -EAGAIN)
				continue;
			return ret;
		}
		if (o.phase == PHASE_INSERT) {
			close_fd(&fd);
			return -ESTALE;
		}
		if (o.phase < PHASE_PREPARE || o.phase > PHASE_CLOSING) {
			close_fd(&fd);
			return -ESTALE;
		}
		ret = own_flow_delete(h, &o);
		if (!ret)
			ret = delete_elem(h->xsks, &o.queue);
		if (!ret && o.phase >= PHASE_RULE)
			ret = xdev_ext_xsk_steer_remove(
			    h->ifname, h->identity.ifindex, &o.rule, NULL);
		if (!ret)
			ret = delete_elem(h->owners, &o.queue);
		close_fd(&fd);
		if (ret)
			return ret;
	}
	return 0;
}
static int pins_remove(struct xdev_ext_xsk_shared *h)
{
	const char *names[] = {"link",	"prog",	  "xsks",
			       "flows", "owners", "meta"};
	int fds[] = {h->link, h->prog, h->xsks, h->flows, h->owners, h->meta};
	size_t i;
	for (i = 0; i < 6; i++)
		if (fds[i] >= 0) {
			int ret = unpin(h, names[i], fds[i]);
			if (ret)
				return ret;
		}
	return 0;
}
static int no_owners(struct xdev_ext_xsk_shared *h)
{
	uint32_t key;
	int ret = neg(bpf_map_get_next_key(h->owners, NULL, &key));
	return ret == -ENOENT ? 1 : ret ? ret : 0;
}
static int options(const struct xdev_ext_xsk_shared_opts *o)
{
	const uint32_t need = XDEV_EXT_XSK_FILTER_F_DST_IPV4 |
			      XDEV_EXT_XSK_FILTER_F_DST_PORT |
			      XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC;
	size_t i;
	if (!o || o->sz < sizeof(*o) || !o->ifname || !*o->ifname ||
	    strlen(o->ifname) >= IF_NAMESIZE || o->xsk_fd < 0 ||
	    o->queue_id >= MAXQ ||
	    (o->xdp_flags != XDP_FLAGS_DRV_MODE &&
	     o->xdp_flags != XDP_FLAGS_SKB_MODE) ||
	    !o->filter.dst_port || (o->filter.flags & need) != need ||
	    (o->filter.flags & ~XDEV_EXT_XSK_FILTER_F_KNOWN))
		return -EINVAL;
	if (o->flags)
		return -EOPNOTSUPP;
	for (i = sizeof(*o); i < o->sz; i++)
		if (((const unsigned char *)o)[i])
			return -EOPNOTSUPP;
	if ((o->filter.flags & XDEV_EXT_XSK_FILTER_F_MAX_LEN) &&
	    o->filter.max_len < 46)
		return -EINVAL;
	if ((o->filter.flags & XDEV_EXT_XSK_FILTER_F_DST_MAC) &&
	    !xdev_ext_xsk_prog_unicast_mac(o->filter.dst_mac))
		return -EINVAL;
	return 0;
}

static int cleanup_locked(struct xdev_ext_xsk_shared *h,
			  struct xdev_ext_xsk_shared_error *error)
{
	int ret;
	if (h->registered || h->created || h->teardown) {
		ret = xdev_ext_xsk_steer_check_interface(h->ifname,
							 h->identity.ifindex);
		if (ret)
			return fail(error, ret, "interface-identity",
				    "Interface name no longer identifies the "
				    "retained ifindex; cleanup was retained");
	}
	if (h->uncertain)
		return fail(error, -ESTALE, "ownership-quarantine",
			    "A partially recorded transaction cannot prove "
			    "resource ownership; preserve this handle and "
			    "inspect the interface");
	if (h->registered) {
		ret = own_flow_delete(h, &h->owner);
		if (ret)
			return fail(
			    error, ret, "flow-remove",
			    "Cannot prove or remove this session's flow entry");
		h->published = false;
		if (h->mapped) {
			ret = delete_elem(h->xsks, &h->owner.queue);
			if (ret)
				return fail(error, ret, "xsk-remove",
					    "Cannot remove this session's "
					    "XSKMAP entry");
			h->mapped = false;
		}
		if (h->rule_valid) {
			ret = xdev_ext_xsk_steer_remove(h->ifname,
							h->identity.ifindex,
							&h->owner.rule, error);
			if (ret)
				return ret;
			h->rule_valid = false;
		}
		ret = delete_elem(h->owners, &h->owner.queue);
		if (ret)
			return fail(
			    error, ret, "owner-remove",
			    "Cannot remove the session ownership record");
		h->registered = false;
		h->teardown = true;
	}
	if (h->teardown) {
		ret = recover_owners(h);
		if (ret)
			return fail(error, ret, "owner-recover",
				    "A departed or quarantined owner prevents "
				    "last-owner cleanup");
		ret = no_owners(h);
		if (ret < 0)
			return fail(error, ret, "owners-query",
				    "Cannot determine remaining shared owners");
		if (!ret)
			return 0;
		if (!h->link_detached) {
			ret = verify_objects(h);
			if (ret)
				return fail(error, ret, "link-verify",
					    "Shared XDP ownership changed; no "
					    "foreign program was detached");
			ret = neg(bpf_link_detach(h->link));
			if (ret)
				return fail(error, ret, "link-detach",
					    "Cannot detach the verified final "
					    "shared link");
			h->link_detached = true;
		}
		ret = pins_remove(h);
		if (ret)
			return fail(error, ret, "pin-remove",
				    "Cannot remove verified shared XDP pins");
		close_fd(&h->link);
		return 0;
	}
	if (h->created) {
		if (h->link >= 0 && !h->link_detached) {
			ret = neg(bpf_link_detach(h->link));
			if (ret)
				return fail(error, ret, "link-rollback",
					    "Cannot detach the newly created "
					    "shared link");
			h->link_detached = true;
		}
		ret = pins_remove(h);
		if (ret)
			return fail(
			    error, ret, "pin-rollback",
			    "Cannot remove newly created shared XDP pins");
	}
	return 0;
}

int xdev_ext_xsk_shared_open(const struct xdev_ext_xsk_shared_opts *o,
			     struct xdev_ext_xsk_shared **out,
			     struct xdev_ext_xsk_shared_error *error)
{
	struct xdev_ext_xsk_shared *h;
	struct xdev_ext_xsk_shared_error original = {0}, cleanup = {0};
	char lockname[40];
	bool insert_uncertain = false, locked = false;
	struct xdev_ext_xsk_shared_flow prior;
	int ret, undo;
	if (error)
		memset(error, 0, sizeof(*error));
	if (out)
		*out = NULL;
	if (!out)
		return fail(error, -EINVAL, "options",
			    "Output handle is required");
	ret = options(o);
	if (ret)
		return fail(error, ret, "options",
			    "Invalid or unsupported shared receive options");
	h = calloc(1, sizeof(*h));
	if (!h)
		return fail(error, -ENOMEM, "allocate",
			    "Cannot allocate shared receive owner");
	h->global_fd = h->queue_fd = h->ns_fd = h->xsk_fd = h->state_fd =
	    h->pin_fd = -1;
	h->xsks = h->flows = h->owners = h->meta = h->prog = h->link = -1;
	h->pid = getpid();
	h->identity.abi = XDEV_EXT_XSK_SHARED_ABI;
	h->identity.uid = geteuid();
	h->identity.mode = o->xdp_flags;
	snprintf(h->ifname, sizeof(h->ifname), "%s", o->ifname);
	h->identity.ifindex = if_nametoindex(o->ifname);
	if (!h->identity.ifindex) {
		ret = -errno;
		if (!ret)
			ret = -ENODEV;
		goto failed;
	}
	h->owner.queue = o->queue_id;
	h->owner.phase = PHASE_PREPARE;
	h->owner.key = (struct xdev_ext_xsk_shared_key){
	    .dst_ipv4 = o->filter.dst_ipv4,
	    .payload_magic = o->filter.payload_magic,
	    .dst_port = o->filter.dst_port};
	h->owner.flow =
	    (struct xdev_ext_xsk_shared_flow){.queue_id = o->queue_id,
					      .flags = o->filter.flags,
					      .src_ipv4 = o->filter.src_ipv4,
					      .src_port = o->filter.src_port,
					      .max_len = o->filter.max_len};
	memcpy(h->owner.flow.dst_mac, o->filter.dst_mac, 6);
	ret = ns_identity(&h->identity, &h->ns_fd);
	if (ret)
		goto failed;
	h->xsk_fd = fcntl(o->xsk_fd, F_DUPFD_CLOEXEC, 0);
	if (h->xsk_fd < 0) {
		ret = -errno;
		goto failed;
	}
	ret = validate_xsk(h);
	if (ret) {
		fail(error, ret, "xsk-identity",
		     ret == -EOPNOTSUPP
			 ? "AF_XDP socket diagnostic/cookie capability is "
			   "unavailable"
			 : "AF_XDP socket identity, network namespace, "
			   "interface or queue does not match");
		goto failed;
	}
	ret = roots(h);
	if (ret) {
		fail(error, ret, "shared-roots",
		     "Secure common control directories and mounted bpffs are "
		     "required");
		goto failed;
	}
	if (flock(h->global_fd, LOCK_EX) < 0) {
		ret = -errno;
		goto failed;
	}
	locked = true;
	snprintf(lockname, sizeof(lockname), "queue-%u.lock", o->queue_id);
	h->queue_fd = lock_file(h->state_fd, lockname);
	if (h->queue_fd < 0) {
		ret = h->queue_fd;
		goto failed;
	}
	if (flock(h->queue_fd, LOCK_EX | LOCK_NB) < 0) {
		ret = errno == EAGAIN || errno == EWOULDBLOCK ? -EBUSY : -errno;
		fail(error, ret, "queue-lease",
		     "AF_XDP permits one shared receive session per queue");
		goto failed;
	}
	ret =
	    xdev_ext_xsk_steer_check_interface(h->ifname, h->identity.ifindex);
	if (ret) {
		fail(error, ret, "interface-identity",
		     "Interface name no longer identifies the admitted socket "
		     "ifindex");
		goto failed;
	}
	ret = device_get(h);
	if (ret) {
		fail(error, ret, "dispatcher",
		     ret == -EBUSY ? "Interface already has an XDP program "
				     "owned outside this shared manager"
				   : "Pinned dispatcher ownership/schema/mode "
				     "is unavailable or inconsistent");
		goto failed;
	}
	ret = recover_owners(h);
	if (ret) {
		fail(error, ret, "owner-recover",
		     "Departed owner has ambiguous or changed resources; it "
		     "was quarantined");
		goto failed;
	}
	ret = neg(bpf_map_lookup_elem(h->flows, &h->owner.key, &prior));
	if (!ret) {
		ret = -EEXIST;
		fail(error, ret, "flow-conflict",
		     "This destination/port/magic flow already has a shared "
		     "owner");
		goto failed;
	}
	if (ret != -ENOENT)
		goto failed;
	ret = neg(bpf_map_update_elem(h->owners, &h->owner.queue, &h->owner,
				      BPF_NOEXIST));
	if (ret)
		goto failed;
	h->registered = true;
	h->created = false;
	h->owner.phase = PHASE_INSERT;
	ret = owner_write(h);
	if (ret)
		goto failed;
	ret = xdev_ext_xsk_steer_add(h->ifname, h->identity.ifindex,
				     o->queue_id, &o->filter, &h->owner.rule,
				     &insert_uncertain, error);
	if (ret) {
		h->uncertain = insert_uncertain;
		goto failed;
	}
	h->rule_valid = true;
	h->owner.phase = PHASE_RULE;
	ret = owner_write(h);
	if (ret)
		goto failed;
	ret = neg(bpf_map_update_elem(h->xsks, &h->owner.queue, &h->xsk_fd,
				      BPF_NOEXIST));
	if (ret) {
		if (ret == -EEXIST) {
			h->uncertain = true;
			ret = -ESTALE;
		}
		goto failed;
	}
	h->mapped = true;
	ret = neg(bpf_map_update_elem(h->flows, &h->owner.key, &h->owner.flow,
				      BPF_NOEXIST));
	if (ret)
		goto failed;
	h->published = true;
	h->owner.phase = PHASE_ACTIVE;
	ret = owner_write(h);
	if (ret)
		goto failed;
	ret = verify_objects(h);
	if (ret)
		goto failed;
	flock(h->global_fd, LOCK_UN);
	*out = h;
	return 0;
failed:
	if (!error || !error->error)
		fail(error, ret, "shared-open",
		     "Cannot configure shared AF_XDP receive");
	if (error)
		original = *error;
	undo = locked ? cleanup_locked(h, &cleanup) : 0;
	if (locked)
		flock(h->global_fd, LOCK_UN);
	if (undo) {
		*out = h;
		if (error) {
			*error = original;
			snprintf(error->reason, sizeof(error->reason),
				 "Open failed (%d); cleanup retained owner "
				 "(%d): %.90s",
				 ret, undo, cleanup.reason);
		}
	} else
		release(h);
	return ret;
}

int xdev_ext_xsk_shared_close(struct xdev_ext_xsk_shared *h,
			      struct xdev_ext_xsk_shared_error *error)
{
	int ret;
	if (error)
		memset(error, 0, sizeof(*error));
	if (!h)
		return fail(error, -EINVAL, "shared-close",
			    "A retained shared owner handle is required");
	ret = xdev_ext_xsk_shared_preflight(h, error);
	if (ret)
		return fail(error, ret, "shared-close",
			    "Close must run in the originating process and "
			    "network namespace");
	if (flock(h->global_fd, LOCK_EX) < 0)
		return fail(error, -errno, "owner-lock",
			    "Cannot lock the shared receive control plane");
	ret = cleanup_locked(h, error);
	flock(h->global_fd, LOCK_UN);
	if (!ret)
		release(h);
	return ret;
}

// SPDX-License-Identifier: GPL-2.0
#include "include/xdev_ext_xsk_redirect.h"
#include "include/xdev_ext_xsk_redirect_prog.h"

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
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int production_map_create(uint32_t max_entries)
{
#if LIBBPF_MAJOR_VERSION >= 1
	int fd = bpf_map_create(BPF_MAP_TYPE_XSKMAP, "xdev_ext_xsks",
				sizeof(uint32_t), sizeof(uint32_t),
				max_entries, NULL);

	return fd;
#else
	int fd = bpf_create_map_name(BPF_MAP_TYPE_XSKMAP, "xdev_ext_xsks",
				     sizeof(uint32_t), sizeof(uint32_t),
				     max_entries, 0);

	return fd < 0 ? -errno : fd;
#endif
}

int xdev_ext_xsk_redirect_build_program(int map_fd,
				   const struct xdev_ext_xsk_flow_filter *filter,
				   struct bpf_insn *program,
				   size_t program_capacity,
				   size_t *program_count)
{
	return xdev_ext_xsk_prog_build(map_fd, filter, 0, program, program_capacity,
				  program_count);
}

static int production_prog_load(int map_fd,
				const struct xdev_ext_xsk_flow_filter *filter)
{
	struct bpf_insn program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS];
	char verifier_log[16 * 1024] = { 0 };
	size_t program_count = 0;
	int fd;
	int ret;

	ret = xdev_ext_xsk_redirect_build_program(map_fd, filter, program,
					     XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
					     &program_count);
	if (ret)
		return ret;

#if LIBBPF_MAJOR_VERSION >= 1
	{
		struct bpf_prog_load_opts opts = {
			.sz = sizeof(opts),
			.log_buf = verifier_log,
			.log_size = sizeof(verifier_log),
			.log_level = 1,
		};

		fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "xdev_ext_xsk_redirect",
				   "GPL", program,
				   program_count, &opts);
	}
#else
	fd = bpf_load_program(BPF_PROG_TYPE_XDP, program,
			      program_count, "GPL", 0,
			      verifier_log, sizeof(verifier_log));
	fd = fd < 0 ? -errno : fd;
#endif
	if (fd < 0)
		fprintf(stderr,
			"xdev_ext_xsk_redirect: XDP program load failed (%d), verifier log:\n%s\n",
			fd, verifier_log);
	return fd;
}

static int production_prog_id(int prog_fd, uint32_t *prog_id)
{
	struct bpf_prog_info info = { 0 };
	uint32_t info_len = sizeof(info);
	int ret;

	if (!prog_id)
		return -EINVAL;
	ret = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (ret < 0)
		return -errno;
	*prog_id = info.id;
	return info.id ? 0 : -EPROTO;
}

static int production_attach(int ifindex, int prog_fd, uint32_t xdp_flags)
{
#if LIBBPF_MAJOR_VERSION >= 1
	int ret = bpf_xdp_attach(ifindex, prog_fd,
				 xdp_flags | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
#else
	int ret = bpf_set_link_xdp_fd(ifindex, prog_fd,
				      xdp_flags | XDP_FLAGS_UPDATE_IF_NOEXIST);
#endif

	return ret < 0 ? ret : 0;
}

static int production_query_id(int ifindex, uint32_t xdp_flags,
			       uint32_t *prog_id)
{
#if LIBBPF_MAJOR_VERSION >= 1
	int ret = bpf_xdp_query_id(ifindex, xdp_flags, prog_id);
#else
	int ret = bpf_get_link_xdp_id(ifindex, prog_id, xdp_flags);
#endif

	return ret < 0 ? ret : 0;
}

static int production_map_update(int map_fd, uint32_t queue_id, int xsk_fd)
{
	int ret = bpf_map_update_elem(map_fd, &queue_id, &xsk_fd, BPF_ANY);

	return ret < 0 ? -errno : 0;
}

static int production_map_delete(int map_fd, uint32_t queue_id)
{
	int ret = bpf_map_delete_elem(map_fd, &queue_id);

	return ret < 0 ? -errno : 0;
}

static int production_detach(int ifindex, int expected_prog_fd,
			     uint32_t xdp_flags)
{
#if LIBBPF_MAJOR_VERSION >= 1
	struct bpf_xdp_attach_opts opts = {
		.sz = sizeof(opts),
		.old_prog_fd = expected_prog_fd,
	};
	int ret = bpf_xdp_detach(ifindex, xdp_flags | XDP_FLAGS_REPLACE,
				 &opts);
#else
	struct bpf_xdp_set_link_opts opts = {
		.sz = sizeof(opts),
		.old_fd = expected_prog_fd,
	};
	int ret = bpf_set_link_xdp_fd_opts(ifindex, -1,
					   xdp_flags | XDP_FLAGS_REPLACE,
					   &opts);
#endif

	return ret < 0 ? ret : 0;
}

static int production_close_fd(int fd)
{
	return close(fd) < 0 ? -errno : 0;
}

static const struct xdev_ext_xsk_redirect_ops production_ops = {
	.map_create = production_map_create,
	.prog_load = production_prog_load,
	.prog_id = production_prog_id,
	.attach = production_attach,
	.query_id = production_query_id,
	.map_update = production_map_update,
	.map_delete = production_map_delete,
	.detach = production_detach,
	.close_fd = production_close_fd,
};

void xdev_ext_xsk_redirect_init(struct xdev_ext_xsk_redirect *redirect)
{
	if (redirect)
		*redirect = (struct xdev_ext_xsk_redirect)XDEV_EXT_XSK_REDIRECT_INIT;
}

bool xdev_ext_xsk_redirect_is_active(const struct xdev_ext_xsk_redirect *redirect)
{
	return redirect && (redirect->mapped || redirect->attached);
}

static bool valid_ops(const struct xdev_ext_xsk_redirect_ops *ops)
{
	return ops && ops->map_create && ops->prog_load && ops->prog_id &&
		ops->attach &&
		ops->query_id && ops->map_update && ops->map_delete &&
		ops->detach && ops->close_fd;
}

static int close_owned_fds(struct xdev_ext_xsk_redirect *redirect,
			   const struct xdev_ext_xsk_redirect_ops *ops)
{
	int first = 0;
	int ret;

	if (redirect->prog_fd >= 0) {
		ret = ops->close_fd(redirect->prog_fd);
		if (ret && !first)
			first = ret;
		redirect->prog_fd = -1;
	}
	if (redirect->map_fd >= 0) {
		ret = ops->close_fd(redirect->map_fd);
		if (ret && !first)
			first = ret;
		redirect->map_fd = -1;
	}
	return first;
}

int xdev_ext_xsk_redirect_detach_with(struct xdev_ext_xsk_redirect *redirect,
				 const struct xdev_ext_xsk_redirect_ops *ops)
{
	uint32_t current_id = 0;
	int first = 0;
	int ret;

	if (!redirect || !valid_ops(ops))
		return -EINVAL;
	if (redirect->mapped && redirect->map_fd >= 0) {
		ret = ops->map_delete(redirect->map_fd, redirect->queue_id);
		/* Until the XSKMAP entry is gone, destroying the socket or UMEM
		 * could leave an attached program redirecting into released backing.
		 * Keep every owned fd and bit of state so the caller can retry. */
		if (ret && ret != -ENOENT)
			return ret;
		redirect->mapped = false;
	}
	if (redirect->attached) {
		ret = ops->query_id(redirect->ifindex, redirect->xdp_flags,
				    &current_id);
		if (ret && !first)
			first = ret;
		else if (!ret && current_id != redirect->prog_id) {
			/* Another owner replaced or removed our program.  Never detach
			 * that owner's link.  Our private map entry is already gone, so
			 * closing our now-unattached program and map is safe. */
			first = -ESTALE;
			redirect->attached = false;
			goto close_fds;
		}
		/* XDP_FLAGS_REPLACE plus old_fd makes the ownership check atomic;
		 * a query-only check would race another process replacing the link. */
		ret = ops->detach(redirect->ifindex, redirect->prog_fd,
				  redirect->xdp_flags);
		/* A failed compare-and-replace is not proof of quiescence.  Keep
		 * prog_fd for an exact-owner retry and do not discard the state. */
		if (ret)
			return ret;
		redirect->attached = false;
	}

close_fds:
	ret = close_owned_fds(redirect, ops);
	if (ret && !first)
		first = ret;
	xdev_ext_xsk_redirect_init(redirect);
	return first;
}

int xdev_ext_xsk_redirect_attach_with(struct xdev_ext_xsk_redirect *redirect,
				 const struct xdev_ext_xsk_redirect_ops *ops,
				 const struct xdev_ext_xsk_flow_filter *filter,
				 int ifindex, uint32_t queue_id, int xsk_fd,
				 uint32_t xdp_flags)
{
	uint32_t id = 0;
	int ret;

	if (!redirect || !valid_ops(ops) || xdev_ext_xsk_prog_validate(filter) ||
	    ifindex <= 0 || xsk_fd < 0 ||
	    queue_id >= XDEV_EXT_XSK_REDIRECT_MAX_QUEUES ||
	    (xdp_flags != XDP_FLAGS_DRV_MODE &&
	     xdp_flags != XDP_FLAGS_SKB_MODE))
		return -EINVAL;
	if (redirect->attached || redirect->mapped || redirect->map_fd >= 0 ||
	    redirect->prog_fd >= 0)
		return -EBUSY;
	redirect->ifindex = ifindex;
	redirect->queue_id = queue_id;
	redirect->xdp_flags = xdp_flags;
	redirect->map_fd = ops->map_create(XDEV_EXT_XSK_REDIRECT_MAX_QUEUES);
	if (redirect->map_fd < 0)
		return redirect->map_fd;
	redirect->prog_fd = ops->prog_load(redirect->map_fd, filter);
	if (redirect->prog_fd < 0) {
		ret = redirect->prog_fd;
		(void)close_owned_fds(redirect, ops);
		xdev_ext_xsk_redirect_init(redirect);
		return ret;
	}
	ret = ops->prog_id(redirect->prog_fd, &id);
	if (ret || !id) {
		ret = ret ? ret : -EPROTO;
		goto fail;
	}
	redirect->prog_id = id;
	ret = ops->map_update(redirect->map_fd, queue_id, xsk_fd);
	if (ret)
		goto fail;
	redirect->mapped = true;
	ret = ops->attach(ifindex, redirect->prog_fd, xdp_flags);
	if (ret)
		goto fail;
	redirect->attached = true;
	ret = ops->query_id(ifindex, xdp_flags, &id);
	if (ret || !id) {
		ret = ret ? ret : -EPROTO;
		goto fail;
	}
	if (id != redirect->prog_id) {
		ret = -ESTALE;
		goto fail;
	}
	return 0;

fail:
	(void)xdev_ext_xsk_redirect_detach_with(redirect, ops);
	return ret;
}

int xdev_ext_xsk_redirect_attach(struct xdev_ext_xsk_redirect *redirect,
			    const struct xdev_ext_xsk_flow_filter *filter, int ifindex,
			    uint32_t queue_id, int xsk_fd,
			    uint32_t xdp_flags)
{
	return xdev_ext_xsk_redirect_attach_with(redirect, &production_ops, filter,
					 ifindex, queue_id, xsk_fd, xdp_flags);
}

int xdev_ext_xsk_redirect_detach(struct xdev_ext_xsk_redirect *redirect)
{
	return xdev_ext_xsk_redirect_detach_with(redirect, &production_ops);
}

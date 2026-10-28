// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xdev_ext_reference_policy_core.h"

struct xdev_ext_reference_policy_object {
	struct bpf_object *object;
	const char *last_map;
};

static int xdev_ext_reference_policy_attach(void *opaque, const char *map_name,
				       void **link_out)
{
	struct xdev_ext_reference_policy_object *policy = opaque;
	struct bpf_map *map;
	struct bpf_link *link;
	long error;

	policy->last_map = map_name;
	map = bpf_object__find_map_by_name(policy->object, map_name);
	if (!map)
		return -ENOENT;
	link = bpf_map__attach_struct_ops(map);
	error = libbpf_get_error(link);
	if (error)
		return (int)error;
	*link_out = link;
	return 0;
}

static void xdev_ext_reference_policy_destroy_link(void *opaque)
{
	bpf_link__destroy(opaque);
}

static void xdev_ext_reference_policy_close_object(void *opaque)
{
	struct xdev_ext_reference_policy_object *policy = opaque;

	bpf_object__close(policy->object);
	policy->object = NULL;
}

static const struct xdev_ext_reference_policy_ops xdev_ext_reference_policy_libbpf_ops = {
	.attach = xdev_ext_reference_policy_attach,
	.destroy_link = xdev_ext_reference_policy_destroy_link,
	.close_object = xdev_ext_reference_policy_close_object,
};

static int xdev_ext_reference_policy_read_stats(
	const struct xdev_ext_reference_policy_object *policy,
	struct xdev_ext_reference_policy_stats *stats)
{
	struct bpf_map *map;
	__u32 key = 0;
	int fd;

	if (!policy || !policy->object || !stats)
		return -EINVAL;
	map = bpf_object__find_map_by_name(policy->object, ".bss");
	if (!map)
		return -ENOENT;
	if (!xdev_ext_reference_policy_stats_value_size_valid(
		    bpf_map__value_size(map)))
		return -EOVERFLOW;
	fd = bpf_map__fd(map);
	if (fd < 0)
		return fd;
	if (bpf_map_lookup_elem(fd, &key, stats))
		return -errno;
	return 0;
}

static int xdev_ext_reference_policy_put_line(const char *line, void *opaque)
{
	return fputs(line, opaque) == EOF ? -EIO : 0;
}

static int xdev_ext_reference_policy_print_stats(
	const struct xdev_ext_reference_policy_object *policy)
{
	struct xdev_ext_reference_policy_stats stats = {};
	int ret;

	ret = xdev_ext_reference_policy_read_stats(policy, &stats);
	if (ret)
		return ret;
	ret = xdev_ext_reference_policy_emit_snapshot(
		&stats, xdev_ext_reference_policy_put_line, stdout);
	if (ret)
		return ret;
	return fflush(stdout) ? -EIO : 0;
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream, "Usage: %s --object PATH\n", program);
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "object", required_argument, NULL, 'o' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	struct xdev_ext_reference_policy_object policy = {};
	struct xdev_ext_reference_policy_runtime runtime = {};
	const char *object_path = NULL;
	sigset_t signals;
	size_t attached;
	int received_signal = 0;
	int stats_ret;
	int option;
	int ret;

	while ((option = getopt_long(argc, argv, "o:h", options, NULL)) != -1) {
		switch (option) {
		case 'o':
			object_path = optarg;
			break;
		case 'h':
			usage(stdout, argv[0]);
			return 0;
		default:
			usage(stderr, argv[0]);
			return 2;
		}
	}
	if (!object_path || optind != argc) {
		usage(stderr, argv[0]);
		return 2;
	}
	if (setvbuf(stdout, NULL, _IOLBF, 0)) {
		fprintf(stderr, "cannot configure line-buffered output\n");
		return 1;
	}

	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGTERM);
	sigaddset(&signals, SIGHUP);
	ret = pthread_sigmask(SIG_BLOCK, &signals, NULL);
	if (ret) {
		fprintf(stderr, "cannot block termination signals: %s\n",
			strerror(ret));
		return 1;
	}

	policy.object = bpf_object__open_file(object_path, NULL);
	ret = (int)libbpf_get_error(policy.object);
	if (ret) {
		policy.object = NULL;
		fprintf(stderr,
			"XDEV_EXT_REFERENCE_POLICY_OPEN_FAILED object=%s error=%d (%s)\n",
			object_path, ret, strerror(-ret));
		return 1;
	}
	ret = bpf_object__load(policy.object);
	if (ret) {
		fprintf(stderr,
			"XDEV_EXT_REFERENCE_POLICY_LOAD_FAILED object=%s error=%d (%s)\n",
			object_path, ret, strerror(-ret));
		bpf_object__close(policy.object);
		return 1;
	}

	ret = xdev_ext_reference_policy_start(&runtime, &policy,
					 &xdev_ext_reference_policy_libbpf_ops);
	if (ret) {
		fprintf(stderr,
			"XDEV_EXT_REFERENCE_POLICY_ATTACH_FAILED map=%s error=%d (%s)\n",
			policy.last_map ? policy.last_map : "none", ret,
			strerror(-ret));
		return 1;
	}
	if (printf("XDEV_EXT_REFERENCE_POLICY_READY attached=%zu pid=%ld object=%s\n",
		   runtime.attached, (long)getpid(), object_path) < 0 ||
	    fflush(stdout)) {
		fprintf(stderr, "XDEV_EXT_REFERENCE_POLICY_READY_FAILED error=%d (%s)\n",
			errno, strerror(errno));
		xdev_ext_reference_policy_stop(&runtime,
					  &xdev_ext_reference_policy_libbpf_ops);
		return 1;
	}

	ret = sigwait(&signals, &received_signal);
	if (ret) {
		fprintf(stderr, "XDEV_EXT_REFERENCE_POLICY_WAIT_FAILED error=%d (%s)\n",
			ret, strerror(ret));
		stats_ret = -ret;
	} else {
		stats_ret = xdev_ext_reference_policy_print_stats(&policy);
		if (stats_ret)
			fprintf(stderr,
				"XDEV_EXT_REFERENCE_POLICY_STATS_FAILED error=%d (%s)\n",
				stats_ret, strerror(-stats_ret));
	}

	attached = runtime.attached;
	xdev_ext_reference_policy_stop(&runtime, &xdev_ext_reference_policy_libbpf_ops);
	printf("XDEV_EXT_REFERENCE_POLICY_STOPPED detached=%zu signal=%d\n",
	       attached, received_signal);
	return stats_ret ? 1 : 0;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Traditional send-path baseline for the NIC -> NVMe A/B comparison.
 *
 * Receives ordinary UDP datagrams with recv() into an application buffer,
 * copies each validated payload into an aligned per-request buffer, and when
 * a wire v2 group (40-byte NXP2 header, 64-bit session, generation, segment
 * index/count/range, CRC32C) is complete, writes the whole logical request
 * with O_DIRECT at the locally configured window.  Datagram acceptance,
 * ordering, generation, timeout, and window mapping come from
 * xdev_ext_sendpath_baseline_core.h, which reuses nvme_xdp_pipeline_core.h, so this
 * program and the pipeline's rx-write mode process the same wire format.
 *
 * Attribution tiers (everything else held constant):
 *   tier 1: --io pwrite -Q 1, or --io uring -Q <depth>   (application buffer)
 *   tier 2: --io uring -Q <depth> --fixed-buffer          (registered buffer)
 *   tier 3: the XDEV_EXT pipeline (nvme_xdp_pipeline -m rx-write)
 *
 * Durability matches the pipeline's NVMe WRITE: no FUA, no flush, no O_DSYNC.
 * Completions are reaped from the CQ (no IOPOLL, no SQPOLL), matching the
 * pipeline's default nvme_completion=cq-wait.
 *
 * Each tier's defining property is reported from what actually happened: the
 * Target line's odirect= is fcntl(F_GETFL) of the target fd (the program
 * refuses to run without O_DIRECT), and the SUMMARY counts the write
 * operations at the submission site (IORING_OP_WRITE and
 * IORING_OP_WRITE_FIXED from the submitted SQE's opcode, and pwrite() calls)
 * and the maximum number of writes in flight.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <liburing.h>
#include <linux/fs.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "xdev_ext_sendpath_baseline_core.h"

#define SPB_RECV_BUFFER_BYTES 65536u
#define SPB_DEFAULT_GROUPS 10u
#define SPB_DEFAULT_BIND_IP "192.168.1.1"
#define SPB_DEFAULT_PORT 12345u
#define SPB_DEFAULT_PEER_PORT 54321u
#define SPB_DEFAULT_MTU 1500u
#define SPB_DEFAULT_LBA_SIZE 512u
#define SPB_DEFAULT_BYTES 8192u
#define SPB_DRAIN_ROUNDS 10u
#define SPB_SYSFS_ROOT "/sys"

enum spb_io_mode {
	SPB_IO_PWRITE = 0,
	SPB_IO_URING,
};

enum {
	SPB_OPT_IO = 1000,
	SPB_OPT_FIXED_BUFFER,
	SPB_OPT_TIMEOUT_MS,
};

struct spb_options {
	const char *target;
	const char *bind_ip;
	const char *peer_ip;
	uint64_t start_lba;
	uint64_t session_id;
	uint32_t groups;
	uint32_t lba_size;
	uint32_t bytes;
	uint32_t depth;
	uint32_t mtu;
	uint32_t timeout_ms;
	uint16_t port;
	uint16_t peer_port;
	enum spb_io_mode io;
	bool fixed_buffer;
};

struct spb_runtime {
	struct spb_options options;
	struct spb_config config;
	struct spb_receiver rx;
	struct spb_group *groups;
	uint8_t **buffers;
	uint8_t *recv_buffer;
	uint64_t *service_ns;
	uint64_t *post_arrival_ns;
	const char *target_kind;
	struct io_uring ring;
	bool ring_ready;
	bool buffers_registered;
	int target_fd;
	int target_flags;
	int socket_fd;
	int event_fd;
	uint64_t written;
	uint64_t bytes_written;
	uint64_t write_errors;
	uint64_t first_datagram_ns;
	uint64_t end_ns;
	int first_error;
	bool stop;
	bool undrained;
};

static void spb_latch(struct spb_runtime *rt, int error)
{
	if (!rt->first_error && error)
		rt->first_error = error < 0 ? error : -EIO;
	rt->stop = true;
}

static int spb_now_ns(uint64_t *now)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return -errno;
	*now = (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
	return 0;
}

static uint64_t spb_timeval_us(const struct timeval *tv)
{
	return (uint64_t)tv->tv_sec * UINT64_C(1000000) + (uint64_t)tv->tv_usec;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s -k <target> -e <session> [options]\n", prog);
	fprintf(stderr, "\nTraditional send path: UDP recv() -> user-space copy -> O_DIRECT write\n\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -k <target>       Block device or regular file, opened O_RDWR|O_DIRECT (required)\n");
	fprintf(stderr, "  -l <lba>          Start LBA of the local write window (default: 0)\n");
	fprintf(stderr, "  -n <groups>       Number of logical requests to write (default: %u)\n", SPB_DEFAULT_GROUPS);
	fprintf(stderr, "  -b <lba_size>     LBA size; asserted against a block device's logical block size (default: %u)\n", SPB_DEFAULT_LBA_SIZE);
	fprintf(stderr, "  -B <bytes>        Bytes per logical request (default: %u; multiple of -b)\n", SPB_DEFAULT_BYTES);
	fprintf(stderr, "  -Q <depth>        Requests in flight (default: 1; --io pwrite requires 1)\n");
	fprintf(stderr, "  -e <session>      Required nonzero 64-bit session identity; peers must match\n");
	fprintf(stderr, "  -a <ip>           Local IPv4 address to bind (default: %s)\n", SPB_DEFAULT_BIND_IP);
	fprintf(stderr, "  -p <port>         Local UDP port (default: %u; 0 selects a free port)\n", SPB_DEFAULT_PORT);
	fprintf(stderr, "  -s <ip>           Optional peer IPv4 address; connect() so only that peer is received\n");
	fprintf(stderr, "  -P <port>         Peer UDP port with -s (default: %u)\n", SPB_DEFAULT_PEER_PORT);
	fprintf(stderr, "  -M <mtu>          Path MTU the sender segmented for (default: %u)\n", SPB_DEFAULT_MTU);
	fprintf(stderr, "  --io <mode>       pwrite (synchronous pwrite) or uring (IORING_OP_WRITE at depth -Q)\n");
	fprintf(stderr, "  --fixed-buffer    uring only: io_uring_register_buffers + IORING_OP_WRITE_FIXED\n");
	fprintf(stderr, "  --timeout-ms <ms> Fail after this long without a datagram or completion (default: %llu)\n",
		(unsigned long long)(SPB_IDLE_TIMEOUT_NS / UINT64_C(1000000)));
	fprintf(stderr, "  -h                Show this help\n");
}

static int spb_parse_u16(const char *text, uint16_t *out)
{
	uint32_t value;
	int ret = nxp_parse_u32(text, &value);

	if (ret)
		return ret;
	if (value > UINT16_MAX)
		return -ERANGE;
	*out = (uint16_t)value;
	return 0;
}

static int spb_parse_options(int argc, char **argv, struct spb_options *opt)
{
	static const struct option long_options[] = {
		{ "io", required_argument, NULL, SPB_OPT_IO },
		{ "fixed-buffer", no_argument, NULL, SPB_OPT_FIXED_BUFFER },
		{ "timeout-ms", required_argument, NULL, SPB_OPT_TIMEOUT_MS },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int c;

	*opt = (struct spb_options) {
		.bind_ip = SPB_DEFAULT_BIND_IP,
		.groups = SPB_DEFAULT_GROUPS,
		.lba_size = SPB_DEFAULT_LBA_SIZE,
		.bytes = SPB_DEFAULT_BYTES,
		.depth = 1,
		.mtu = SPB_DEFAULT_MTU,
		.timeout_ms = (uint32_t)(SPB_IDLE_TIMEOUT_NS / UINT64_C(1000000)),
		.port = SPB_DEFAULT_PORT,
		.peer_port = SPB_DEFAULT_PEER_PORT,
		.io = SPB_IO_PWRITE,
	};
	while ((c = getopt_long(argc, argv, "k:l:n:b:B:Q:e:a:p:s:P:M:h",
				long_options, NULL)) != -1) {
		int value;

		switch (c) {
		case 'k':
			opt->target = optarg;
			break;
		case 'l':
			if (nxp_parse_u64(optarg, &opt->start_lba)) {
				fprintf(stderr, "Invalid -l start LBA\n");
				return -EINVAL;
			}
			break;
		case 'n':
			if (nxp_parse_positive_int(optarg, INT_MAX, &value)) {
				fprintf(stderr, "Invalid -n groups: must be >= 1\n");
				return -EINVAL;
			}
			opt->groups = (uint32_t)value;
			break;
		case 'b':
			if (nxp_parse_u32(optarg, &opt->lba_size)) {
				fprintf(stderr, "Invalid -b LBA size\n");
				return -EINVAL;
			}
			break;
		case 'B':
			if (nxp_parse_u32(optarg, &opt->bytes) || !opt->bytes) {
				fprintf(stderr, "Invalid -B bytes\n");
				return -EINVAL;
			}
			break;
		case 'Q':
			if (nxp_parse_positive_int(optarg, SPB_MAX_DEPTH, &value)) {
				fprintf(stderr, "Invalid -Q depth: must be in [1, %d]\n",
					SPB_MAX_DEPTH);
				return -EINVAL;
			}
			opt->depth = (uint32_t)value;
			break;
		case 'e':
			if (nxp_parse_u64(optarg, &opt->session_id) ||
			    !opt->session_id) {
				fprintf(stderr, "Invalid session identity: must be nonzero\n");
				return -EINVAL;
			}
			break;
		case 'a':
			opt->bind_ip = optarg;
			break;
		case 'p':
			if (spb_parse_u16(optarg, &opt->port)) {
				fprintf(stderr, "Invalid -p port\n");
				return -EINVAL;
			}
			break;
		case 's':
			opt->peer_ip = optarg;
			break;
		case 'P':
			if (spb_parse_u16(optarg, &opt->peer_port) ||
			    !opt->peer_port) {
				fprintf(stderr, "Invalid -P peer port\n");
				return -EINVAL;
			}
			break;
		case 'M':
			if (nxp_parse_u32(optarg, &opt->mtu)) {
				fprintf(stderr, "Invalid -M MTU\n");
				return -EINVAL;
			}
			break;
		case SPB_OPT_IO:
			if (!strcmp(optarg, "pwrite")) {
				opt->io = SPB_IO_PWRITE;
			} else if (!strcmp(optarg, "uring")) {
				opt->io = SPB_IO_URING;
			} else {
				fprintf(stderr, "Invalid --io: use pwrite or uring\n");
				return -EINVAL;
			}
			break;
		case SPB_OPT_FIXED_BUFFER:
			opt->fixed_buffer = true;
			break;
		case SPB_OPT_TIMEOUT_MS:
			if (nxp_parse_positive_int(optarg, INT_MAX, &value)) {
				fprintf(stderr, "Invalid --timeout-ms: must be >= 1\n");
				return -EINVAL;
			}
			opt->timeout_ms = (uint32_t)value;
			break;
		case 'h':
			usage(argv[0]);
			return 1;
		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	if (!opt->target) {
		fprintf(stderr, "A target block device or file is required with -k\n");
		return -EINVAL;
	}
	if (!opt->session_id) {
		fprintf(stderr, "A nonzero per-run session identity is required with -e\n");
		return -EINVAL;
	}
	if (opt->io == SPB_IO_PWRITE && opt->depth != 1) {
		fprintf(stderr, "--io pwrite is synchronous and requires -Q 1\n");
		return -EINVAL;
	}
	if (opt->fixed_buffer && opt->io != SPB_IO_URING) {
		fprintf(stderr, "--fixed-buffer requires --io uring\n");
		return -EINVAL;
	}
	return 0;
}

/* Open the target with O_DIRECT and derive its capacity in LBAs.  The open
 * file description must really carry O_DIRECT (fcntl(F_GETFL)), and a block
 * device must be a whole device, not a partition (as in the pipeline).  A
 * block device's logical block size must equal -b (an assertion, as in the
 * pipeline); a regular file uses -b as its I/O unit. */
static int spb_open_target(struct spb_runtime *rt, uint64_t *capacity_lbas)
{
	const struct spb_options *opt = &rt->options;
	uint64_t size_bytes;
	struct stat st;
	int ret;

	rt->target_fd = open(opt->target, O_RDWR | O_DIRECT | O_CLOEXEC);
	if (rt->target_fd < 0) {
		ret = -errno;
		fprintf(stderr, "open %s O_RDWR|O_DIRECT: %s\n", opt->target,
			strerror(-ret));
		return ret;
	}
	rt->target_flags = fcntl(rt->target_fd, F_GETFL);
	if (rt->target_flags < 0) {
		ret = -errno;
		fprintf(stderr, "fcntl(F_GETFL) %s: %s\n", opt->target,
			strerror(-ret));
		return ret;
	}
	ret = spb_target_flags_check(rt->target_flags);
	if (ret) {
		fprintf(stderr, "%s is not open with O_DIRECT (flags %#o); refusing to measure buffered I/O\n",
			opt->target, (unsigned int)rt->target_flags);
		return ret;
	}
	if (fstat(rt->target_fd, &st)) {
		ret = -errno;
		fprintf(stderr, "fstat %s: %s\n", opt->target, strerror(-ret));
		return ret;
	}
	ret = spb_target_classify(&st, SPB_SYSFS_ROOT, &rt->target_kind);
	if (ret == -EXDEV) {
		fprintf(stderr, "%s is a partition; use the whole-namespace block device, as nvme_xdp_pipeline requires (-l names namespace LBAs)\n",
			opt->target);
		return ret;
	}
	if (ret == -ENOTBLK) {
		fprintf(stderr, "%s is neither a block device nor a regular file\n",
			opt->target);
		return ret;
	}
	if (ret) {
		fprintf(stderr, "Cannot show that %s is a whole block device from %s/dev/block: %s\n",
			opt->target, SPB_SYSFS_ROOT, strerror(-ret));
		return ret;
	}
	if (S_ISBLK(st.st_mode)) {
		int logical = 0;

		if (ioctl(rt->target_fd, BLKSSZGET, &logical) ||
		    ioctl(rt->target_fd, BLKGETSIZE64, &size_bytes)) {
			ret = -errno;
			fprintf(stderr, "Cannot read block geometry of %s: %s\n",
				opt->target, strerror(-ret));
			return ret;
		}
		if (logical <= 0 || (uint32_t)logical != opt->lba_size) {
			fprintf(stderr, "-b assertion %u disagrees with device logical block size %d\n",
				opt->lba_size, logical);
			return -EINVAL;
		}
	} else {
		if (st.st_size < 0)
			return -EINVAL;
		size_bytes = (uint64_t)st.st_size;
	}
	if (!opt->lba_size) {
		fprintf(stderr, "Invalid -b LBA size\n");
		return -EINVAL;
	}
	*capacity_lbas = size_bytes / opt->lba_size;
	return 0;
}

static int spb_alloc_buffers(struct spb_runtime *rt)
{
	const uint32_t depth = rt->config.depth;
	size_t alignment = rt->config.lba_size > 4096 ? rt->config.lba_size : 4096;
	void *memory;

	rt->groups = calloc(depth, sizeof(*rt->groups));
	rt->buffers = calloc(depth, sizeof(*rt->buffers));
	rt->service_ns = calloc(rt->config.groups, sizeof(*rt->service_ns));
	rt->post_arrival_ns = calloc(rt->config.groups,
				     sizeof(*rt->post_arrival_ns));
	if (!rt->groups || !rt->buffers || !rt->service_ns ||
	    !rt->post_arrival_ns)
		return -ENOMEM;
	for (uint32_t i = 0; i < depth; i++) {
		if (posix_memalign(&memory, alignment, rt->config.bytes))
			return -ENOMEM;
		memset(memory, 0, rt->config.bytes);
		rt->buffers[i] = memory;
	}
	if (posix_memalign(&memory, 4096, SPB_RECV_BUFFER_BYTES))
		return -ENOMEM;
	rt->recv_buffer = memory;
	return 0;
}

static int spb_open_socket(struct spb_runtime *rt, uint16_t *bound_port)
{
	const struct spb_options *opt = &rt->options;
	struct sockaddr_in local = { .sin_family = AF_INET };
	socklen_t len = sizeof(local);
	int ret;

	if (inet_pton(AF_INET, opt->bind_ip, &local.sin_addr) != 1) {
		fprintf(stderr, "Invalid -a address %s\n", opt->bind_ip);
		return -EINVAL;
	}
	local.sin_port = htons(opt->port);
	rt->socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (rt->socket_fd < 0)
		return -errno;
	if (bind(rt->socket_fd, (struct sockaddr *)&local, sizeof(local))) {
		ret = -errno;
		fprintf(stderr, "bind %s:%u: %s\n", opt->bind_ip, opt->port,
			strerror(-ret));
		return ret;
	}
	if (getsockname(rt->socket_fd, (struct sockaddr *)&local, &len))
		return -errno;
	*bound_port = ntohs(local.sin_port);
	if (opt->peer_ip) {
		struct sockaddr_in peer = {
			.sin_family = AF_INET,
			.sin_port = htons(opt->peer_port),
		};

		if (inet_pton(AF_INET, opt->peer_ip, &peer.sin_addr) != 1) {
			fprintf(stderr, "Invalid -s address %s\n", opt->peer_ip);
			return -EINVAL;
		}
		if (connect(rt->socket_fd, (struct sockaddr *)&peer,
			    sizeof(peer))) {
			ret = -errno;
			fprintf(stderr, "connect %s:%u: %s\n", opt->peer_ip,
				opt->peer_port, strerror(-ret));
			return ret;
		}
	}
	return 0;
}

static int spb_init_ring(struct spb_runtime *rt)
{
	int ret;

	ret = io_uring_queue_init(rt->config.depth, &rt->ring, 0);
	if (ret) {
		fprintf(stderr, "io_uring_queue_init(%u): %s\n", rt->config.depth,
			strerror(-ret));
		return ret;
	}
	rt->ring_ready = true;
	rt->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (rt->event_fd < 0)
		return -errno;
	ret = io_uring_register_eventfd(&rt->ring, rt->event_fd);
	if (ret) {
		fprintf(stderr, "io_uring_register_eventfd: %s\n", strerror(-ret));
		return ret;
	}
	if (rt->options.fixed_buffer) {
		struct iovec *vectors = calloc(rt->config.depth, sizeof(*vectors));

		if (!vectors)
			return -ENOMEM;
		for (uint32_t i = 0; i < rt->config.depth; i++)
			vectors[i] = (struct iovec) {
				.iov_base = rt->buffers[i],
				.iov_len = rt->config.bytes,
			};
		ret = io_uring_register_buffers(&rt->ring, vectors,
						rt->config.depth);
		free(vectors);
		if (ret) {
			fprintf(stderr, "io_uring_register_buffers: %s\n",
				strerror(-ret));
			return ret;
		}
		rt->buffers_registered = true;
	}
	return 0;
}

/* The write's own completion ends this request's use of its buffer. */
static void spb_finish_write(struct spb_runtime *rt, int group, int result)
{
	/* Read the request's identity before completion clears the slot. */
	const uint64_t first = rt->groups[group].first_accept_ns;
	const uint64_t arrival = rt->groups[group].last_arrival_ns;
	const uint64_t request_index = rt->groups[group].request_index;
	uint64_t now = 0;
	int ret;

	ret = spb_receiver_retire(&rt->rx, group);
	if (ret) {
		spb_latch(rt, ret);
		return;
	}
	if (spb_now_ns(&now) == 0)
		rt->end_ns = now;
	if (result == (int)rt->config.bytes) {
		if (rt->written < rt->config.groups) {
			rt->service_ns[rt->written] = now > first ? now - first : 0;
			rt->post_arrival_ns[rt->written] =
				now > arrival ? now - arrival : 0;
		}
		rt->written++;
		rt->bytes_written += rt->config.bytes;
		return;
	}
	rt->write_errors++;
	fprintf(stderr, "write of request %llu failed: %s\n",
		(unsigned long long)request_index,
		result < 0 ? strerror(-result) : "short write");
	spb_latch(rt, result < 0 ? result : -EIO);
}

/* The submission site: every write is counted here by the operation that
 * carried it (spb_receiver_issue), so the SUMMARY's write_ops,
 * write_fixed_ops and pwrite_calls describe the path actually taken. */
static int spb_submit_write(struct spb_runtime *rt, int group)
{
	struct spb_group *request = &rt->groups[group];
	struct io_uring_sqe prepared, *sqe;
	enum spb_write_op prepared_op;
	ssize_t written;
	int ret;

	if (rt->options.io == SPB_IO_PWRITE) {
		ret = spb_receiver_issue(&rt->rx, group, SPB_WRITE_OP_PWRITE);
		if (ret)
			return ret;
		do {
			written = pwrite(rt->target_fd, request->buffer,
					 rt->config.bytes,
					 (off_t)request->byte_offset);
		} while (written < 0 && errno == EINTR);
		spb_finish_write(rt, group, written < 0 ? -errno : (int)written);
		return 0;
	}
	/* Prepare and classify before taking an SQE, so a refused preparation
	 * never leaves an SQE in the ring. */
	memset(&prepared, 0, sizeof(prepared));
	ret = spb_prep_uring_write(&rt->rx, group, rt->target_fd,
				   rt->options.fixed_buffer, &prepared,
				   &prepared_op);
	if (ret)
		return ret;
	sqe = io_uring_get_sqe(&rt->ring);
	if (!sqe)
		return -EBUSY;
	*sqe = prepared;
	ret = io_uring_submit(&rt->ring);
	if (ret != 1) {
		/* The SQE may still be visible to the kernel: never reuse or free
		 * this buffer without its completion. */
		rt->undrained = true;
		return ret < 0 ? ret : -EIO;
	}
	/* Count the SQE the kernel was given, by its own opcode. */
	ret = spb_receiver_issue_sqe(&rt->rx, group, sqe);
	if (ret) {
		/* Submitted but not accounted: its completion is not provable. */
		rt->undrained = true;
		return ret;
	}
	return 0;
}

static int spb_reap(struct spb_runtime *rt, unsigned int *reaped)
{
	struct io_uring_cqe *cqe;

	*reaped = 0;
	if (rt->options.io != SPB_IO_URING)
		return 0;
	while (io_uring_peek_cqe(&rt->ring, &cqe) == 0) {
		uint64_t token = cqe->user_data;
		int result = cqe->res;
		uint32_t group = (uint32_t)token;

		io_uring_cqe_seen(&rt->ring, cqe);
		if (group >= rt->config.depth ||
		    rt->groups[group].state != SPB_GROUP_WRITING ||
		    rt->groups[group].request_index != token >> 32 ||
		    !rt->rx.writes.inflight) {
			fprintf(stderr, "Unattributable write completion %#llx\n",
				(unsigned long long)token);
			rt->undrained = true;
			return -EPROTO;
		}
		(*reaped)++;
		spb_finish_write(rt, (int)group, result);
	}
	return 0;
}

static int spb_wait_ms(const struct spb_runtime *rt, uint64_t now,
		       uint64_t idle_deadline)
{
	uint64_t until = idle_deadline;
	uint64_t remaining;

	if (!rt->stop && rt->rx.active >= 0) {
		const struct spb_group *group = &rt->groups[rt->rx.active];
		uint64_t expiry = group->begin_ns + rt->config.group_timeout_ns;

		if (expiry >= group->begin_ns && expiry < until)
			until = expiry;
	}
	if (now >= until)
		return 0;
	remaining = (until - now + UINT64_C(999999)) / UINT64_C(1000000);
	return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

static void spb_run(struct spb_runtime *rt)
{
	const uint64_t timeout_ns = (uint64_t)rt->options.timeout_ms *
				    UINT64_C(1000000);
	uint64_t now, idle_deadline;
	int ret;

	if (spb_now_ns(&now)) {
		spb_latch(rt, -EIO);
		return;
	}
	idle_deadline = now + timeout_ns;
	for (;;) {
		struct pollfd fds[2];
		unsigned int reaped = 0;
		nfds_t nfds = 0;
		bool receive;
		ssize_t got;
		int wait_ms;

		if (!rt->stop && rt->written == rt->config.groups)
			break;
		if (rt->stop && !rt->rx.writes.inflight)
			break;
		ret = spb_reap(rt, &reaped);
		if (ret) {
			spb_latch(rt, ret);
			break;
		}
		if (spb_now_ns(&now)) {
			spb_latch(rt, -EIO);
			continue;
		}
		if (reaped)
			idle_deadline = now + timeout_ns;
		if (!rt->stop) {
			ret = spb_receiver_expire(&rt->rx, now);
			if (ret < 0)
				spb_latch(rt, ret);
			else if (ret > 0)
				idle_deadline = now + timeout_ns;
		}
		/* Up to -Q writes stay outstanding while later groups are
		 * received; the guard lives in the core and is tested there. */
		receive = spb_loop_may_receive(&rt->rx, rt->stop);
		if (receive) {
			got = recv(rt->socket_fd, rt->recv_buffer,
				   SPB_RECV_BUFFER_BYTES, MSG_DONTWAIT);
			if (got >= 0) {
				struct spb_feed_result result;

				if (spb_now_ns(&now)) {
					spb_latch(rt, -EIO);
					continue;
				}
				if (!rt->first_datagram_ns)
					rt->first_datagram_ns = now;
				idle_deadline = now + timeout_ns;
				ret = spb_receiver_feed(&rt->rx, rt->recv_buffer,
							(size_t)got, now, &result);
				if (ret) {
					spb_latch(rt, ret);
					continue;
				}
				if (result.outcome == SPB_FEED_COMPLETED) {
					ret = spb_submit_write(rt, result.group);
					if (ret) {
						rt->write_errors++;
						fprintf(stderr, "Cannot submit write: %s\n",
							strerror(-ret));
						spb_latch(rt, ret);
					}
				}
				continue;
			}
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				fprintf(stderr, "recv: %s\n", strerror(errno));
				spb_latch(rt, -errno);
				continue;
			}
		}
		if (reaped)
			continue;

		if (receive)
			fds[nfds++] = (struct pollfd) {
				.fd = rt->socket_fd,
				.events = POLLIN,
			};
		if (rt->rx.writes.inflight)
			fds[nfds++] = (struct pollfd) {
				.fd = rt->event_fd,
				.events = POLLIN,
			};
		if (!nfds) {
			/* Nothing can make progress: fail closed. */
			spb_latch(rt, -EPROTO);
			break;
		}
		if (rt->undrained && rt->stop) {
			/* A submit failure left an SQE whose fate is unknown. */
			break;
		}
		wait_ms = spb_wait_ms(rt, now, idle_deadline);
		ret = poll(fds, nfds, wait_ms);
		if (ret < 0 && errno != EINTR) {
			spb_latch(rt, -errno);
			if (rt->rx.writes.inflight)
				rt->undrained = true;
			break;
		}
		if (spb_now_ns(&now)) {
			spb_latch(rt, -EIO);
			continue;
		}
		if (ret > 0 && receive) {
			int idle = nxp_rx_idle_poll_result(ret, fds[0].revents,
							   now, UINT64_MAX);

			if (idle != -EAGAIN) {
				fprintf(stderr, "UDP socket error: %s\n",
					strerror(-idle));
				spb_latch(rt, idle);
			}
		}
		if (rt->rx.writes.inflight && ret > 0) {
			uint64_t value;

			if (read(rt->event_fd, &value, sizeof(value)) < 0 &&
			    errno != EAGAIN)
				spb_latch(rt, -errno);
		}
		if (ret == 0 && now >= idle_deadline) {
			if (!rt->stop)
				fprintf(stderr,
					"No datagram or write completion for %u ms "
					"(%llu of %u requests written)\n",
					rt->options.timeout_ms,
					(unsigned long long)rt->written,
					rt->config.groups);
			if (rt->stop && rt->rx.writes.inflight) {
				rt->undrained = true;
				break;
			}
			spb_latch(rt, -ETIMEDOUT);
			idle_deadline = now + timeout_ns * SPB_DRAIN_ROUNDS;
		}
	}
	if (spb_now_ns(&now) == 0 && !rt->end_ns)
		rt->end_ns = now;
}

static void spb_print_summary(const struct spb_runtime *rt,
			      const struct rusage *start,
			      const struct rusage *end)
{
	const struct spb_counters *counters = &rt->rx.counters;
	const struct spb_write_stats *writes = &rt->rx.writes;
	uint64_t user_us = spb_timeval_us(&end->ru_utime) -
			   spb_timeval_us(&start->ru_utime);
	uint64_t sys_us = spb_timeval_us(&end->ru_stime) -
			  spb_timeval_us(&start->ru_stime);
	uint64_t wall_us = 0, p50 = 0, p99 = 0;
	size_t samples = rt->written < rt->config.groups ?
			 (size_t)rt->written : rt->config.groups;
	struct spb_arrival_report arrival;

	if (rt->first_datagram_ns && rt->end_ns > rt->first_datagram_ns)
		wall_us = (rt->end_ns - rt->first_datagram_ns) / UINT64_C(1000);
	if (samples) {
		spb_sort_u64(rt->service_ns, samples);
		p50 = spb_nearest_rank(rt->service_ns, samples, 50) / UINT64_C(1000);
		p99 = spb_nearest_rank(rt->service_ns, samples, 99) / UINT64_C(1000);
	}
	spb_arrival_report(rt->first_datagram_ns, rt->rx.last_arrival_ns,
			   rt->end_ns, rt->post_arrival_ns, samples, &arrival);
	printf("SENDPATH_BASELINE_DROPS datagrams=%llu",
	       (unsigned long long)counters->datagrams);
	for (int i = 0; i < SPB_DROP_REASON_COUNT; i++)
		printf(" %s=%llu", spb_drop_reason_name((enum spb_drop_reason)i),
		       (unsigned long long)counters->dropped[i]);
	printf(" groups_expired=%llu\n",
	       (unsigned long long)counters->groups_expired);
	/* The first ten fields are the original format, in order; the write
	 * operation counts and the depth reached are appended after them, and
	 * the arrival fields after those. */
	printf("SENDPATH_BASELINE_SUMMARY groups=%llu packets_accepted=%llu "
	       "packets_dropped=%llu bytes_written=%llu write_errors=%llu "
	       "cpu_user_us=%llu cpu_sys_us=%llu wall_us=%llu "
	       "group_service_us_p50=%llu group_service_us_p99=%llu "
	       "write_ops=%llu write_fixed_ops=%llu pwrite_calls=%llu "
	       "max_inflight=%u rx_span_us=%llu tail_us=%llu "
	       "group_post_arrival_us_p50=%llu "
	       "group_post_arrival_us_p99=%llu\n",
	       (unsigned long long)rt->written,
	       (unsigned long long)counters->packets_accepted,
	       (unsigned long long)counters->packets_dropped,
	       (unsigned long long)rt->bytes_written,
	       (unsigned long long)rt->write_errors,
	       (unsigned long long)user_us, (unsigned long long)sys_us,
	       (unsigned long long)wall_us, (unsigned long long)p50,
	       (unsigned long long)p99,
	       (unsigned long long)writes->ops[SPB_WRITE_OP_WRITE],
	       (unsigned long long)writes->ops[SPB_WRITE_OP_WRITE_FIXED],
	       (unsigned long long)writes->ops[SPB_WRITE_OP_PWRITE],
	       writes->max_inflight,
	       (unsigned long long)arrival.rx_span_us,
	       (unsigned long long)arrival.tail_us,
	       (unsigned long long)arrival.post_arrival_us_p50,
	       (unsigned long long)arrival.post_arrival_us_p99);
}

static void spb_cleanup(struct spb_runtime *rt)
{
	/* Without proof that every submitted write completed, keep every
	 * request buffer alive until process exit. */
	bool release_buffers = !rt->undrained && !rt->rx.writes.inflight;

	if (rt->ring_ready) {
		if (release_buffers && rt->buffers_registered)
			(void)io_uring_unregister_buffers(&rt->ring);
		if (release_buffers)
			io_uring_queue_exit(&rt->ring);
	}
	if (rt->event_fd >= 0 && release_buffers)
		close(rt->event_fd);
	if (rt->socket_fd >= 0)
		close(rt->socket_fd);
	if (rt->target_fd >= 0 && release_buffers)
		close(rt->target_fd);
	if (!release_buffers)
		return;
	if (rt->buffers)
		for (uint32_t i = 0; i < rt->config.depth; i++)
			free(rt->buffers[i]);
	free(rt->buffers);
	free(rt->groups);
	free(rt->service_ns);
	free(rt->post_arrival_ns);
	free(rt->recv_buffer);
}

int main(int argc, char **argv)
{
	struct spb_runtime rt = {
		.target_fd = -1,
		.socket_fd = -1,
		.event_fd = -1,
	};
	struct nxp_wire_layout layout;
	struct rusage usage_start, usage_end;
	uint64_t capacity_lbas = 0;
	uint16_t bound_port = 0;
	int exit_status = 1;
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 0);
	ret = spb_parse_options(argc, argv, &rt.options);
	if (ret)
		return ret > 0 ? 0 : 1;
	ret = spb_open_target(&rt, &capacity_lbas);
	if (ret)
		goto out;
	rt.config = (struct spb_config) {
		.session_id = rt.options.session_id,
		.start_lba = rt.options.start_lba,
		.capacity_lbas = capacity_lbas,
		.lba_size = rt.options.lba_size,
		.bytes = rt.options.bytes,
		.mtu = rt.options.mtu,
		.groups = rt.options.groups,
		.depth = rt.options.depth,
		.group_timeout_ns = SPB_GROUP_TIMEOUT_NS,
	};
	ret = spb_config_validate(&rt.config, &layout);
	if (ret) {
		fprintf(stderr, "Unsafe geometry (lba_size=%u bytes=%u mtu=%u window=%u groups at LBA %llu, capacity %llu LBAs): %s\n",
			rt.config.lba_size, rt.config.bytes, rt.config.mtu,
			rt.config.groups, (unsigned long long)rt.config.start_lba,
			(unsigned long long)capacity_lbas, strerror(-ret));
		goto out;
	}
	ret = spb_alloc_buffers(&rt);
	if (ret) {
		fprintf(stderr, "Cannot allocate request buffers: %s\n",
			strerror(-ret));
		goto out;
	}
	ret = spb_receiver_init(&rt.rx, &rt.config, rt.groups, rt.buffers);
	if (ret)
		goto out;
	ret = spb_open_socket(&rt, &bound_port);
	if (ret)
		goto out;
	if (rt.options.io == SPB_IO_URING) {
		ret = spb_init_ring(&rt);
		if (ret)
			goto out;
	}

	printf("Starting UDP recv -> O_DIRECT write baseline: depth=%u session=%llu io=%s buffer=%s\n",
	       rt.config.depth, (unsigned long long)rt.config.session_id,
	       rt.options.io == SPB_IO_URING ? "uring" : "pwrite",
	       rt.options.fixed_buffer ? "fixed" : "heap");
	printf("Target: path=%s type=%s lba_size=%u capacity_lbas=%llu window_lba=%llu+%llu sync=none completion=cq-wait odirect=%d\n",
	       rt.options.target, rt.target_kind, rt.config.lba_size,
	       (unsigned long long)capacity_lbas,
	       (unsigned long long)rt.config.start_lba,
	       (unsigned long long)rt.config.groups *
		       (rt.config.bytes / rt.config.lba_size),
	       (rt.target_flags & O_DIRECT) ? 1 : 0);
	printf("Wire: bytes=%u mtu=%u segments_per_group=%u segment_bytes=%u\n",
	       rt.config.bytes, rt.config.mtu, layout.segment_count,
	       layout.segment_data_limit);
	printf("SENDPATH_BASELINE_LISTEN addr=%s port=%u\n", rt.options.bind_ip,
	       bound_port);

	if (getrusage(RUSAGE_SELF, &usage_start)) {
		ret = -errno;
		goto out;
	}
	spb_run(&rt);
	if (getrusage(RUSAGE_SELF, &usage_end))
		usage_end = usage_start;
	spb_print_summary(&rt, &usage_start, &usage_end);
	if (!rt.first_error && rt.written == rt.config.groups &&
	    !rt.write_errors) {
		printf("Baseline completed\n");
		exit_status = 0;
	} else {
		fprintf(stderr, "Baseline failed: %s (%llu of %u requests written)\n",
			strerror(rt.first_error ? -rt.first_error : EIO),
			(unsigned long long)rt.written, rt.config.groups);
	}
	ret = 0;
out:
	if (ret)
		exit_status = 1;
	spb_cleanup(&rt);
	return exit_status;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Runtime test for xdev_ext_sendpath_baseline (traditional UDP recv() -> O_DIRECT
 * write).  A loopback UDP sender built from the nvme_xdp_pipeline wire helpers
 * sends 4 logical groups x 8192 bytes in 1500-MTU segments to the baseline on
 * 127.0.0.1.  Each group is sent once shuffled and then once in order (a
 * same-generation retry, which the pipeline receiver also accepts); one
 * wrong-session datagram and one duplicate datagram are added.  The target
 * is a temporary file on a filesystem that supports O_DIRECT.  The file bytes
 * must equal the sent bytes at the locally configured window, and the
 * baseline's summary counters must be exact.  The run is repeated for
 * --io pwrite -Q 1, --io uring -Q 4, and --io uring -Q 4 --fixed-buffer.
 *
 * Each tier's defining property is checked, not only printed:
 *  - O_DIRECT: the Target line must report odirect=1 (fcntl(F_GETFL) of the
 *    program's target fd), /proc/<pid>/fdinfo of that fd must carry O_DIRECT
 *    while the program runs, no page of the target may be in the page cache
 *    after the run (mincore(); the target filesystem is first shown to leave
 *    none after an O_DIRECT write), and the written bytes are read back with
 *    an O_DIRECT read;
 *  - the write operation: the SUMMARY counts IORING_OP_WRITE SQEs,
 *    IORING_OP_WRITE_FIXED SQEs and pwrite() calls at the submission site,
 *    and each arm must have used only its own operation, once per group;
 *    /proc/<pid>/fdinfo of the program's io_uring must list exactly -Q
 *    registered buffers of -B bytes with --fixed-buffer and none without;
 *  - depth: max_inflight must be at least 1 and at most -Q, and exact where
 *    the number of writes fixes it (0 without a write, 1 with one write, at
 *    -Q 4 in the expiry case).  That up to -Q writes may be outstanding is
 *    proven deterministically by the core test (withheld completions),
 *    because loopback timing cannot force it here.
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../../xdev_ext_sendpath_baseline_core.h"

#define KSFT_SKIP 4
#define RT_GROUPS 4
#define RT_BYTES UINT32_C(8192)
#define RT_MTU UINT32_C(1500)
#define RT_LBA_SIZE UINT32_C(512)
#define RT_START_LBA UINT64_C(16)
#define RT_BLOCKS (RT_BYTES / RT_LBA_SIZE)
#define RT_FILE_BYTES ((RT_START_LBA + RT_GROUPS * RT_BLOCKS) * RT_LBA_SIZE)
#define RT_MAX_SEGMENTS 16
#define RT_DATAGRAM_MAX 2048
#define RT_LINE_MAX 1024
/* rt_spawn() sender plan: partial group, pause past the group timeout, retry. */
#define RT_SEND_EXPIRE_RETRY UINT_MAX

struct rt_arm {
	const char *name;
	const char *io;
	int depth;
	bool fixed_buffer;
};

struct rt_summary {
	unsigned long long groups;
	unsigned long long packets_accepted;
	unsigned long long packets_dropped;
	unsigned long long bytes_written;
	unsigned long long write_errors;
	unsigned long long cpu_user_us;
	unsigned long long cpu_sys_us;
	unsigned long long wall_us;
	unsigned long long p50;
	unsigned long long p99;
	unsigned long long write_ops;
	unsigned long long write_fixed_ops;
	unsigned long long pwrite_calls;
	unsigned long long max_inflight;
	unsigned long long rx_span_us;
	unsigned long long tail_us;
	unsigned long long post_p50;
	unsigned long long post_p99;
};

static uint8_t group_data[RT_GROUPS][RT_BYTES];

static void fill_pattern(uint8_t *data, size_t len, uint32_t seed)
{
	uint32_t state = seed * UINT32_C(2654435761) + 7;

	for (size_t i = 0; i < len; i++) {
		state = state * UINT32_C(1103515245) + UINT32_C(12345);
		data[i] = (uint8_t)(state >> 16);
	}
}

static int baseline_path(char *out, size_t size)
{
	const char *env = getenv("SPB_BASELINE_BIN");
	char self[PATH_MAX];
	ssize_t len;
	char *slash;

	if (env && env[0]) {
		if ((size_t)snprintf(out, size, "%s", env) >= size)
			return -ENAMETOOLONG;
		return 0;
	}
	len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (len < 0)
		return -errno;
	self[len] = '\0';
	slash = strrchr(self, '/');
	if (!slash)
		return -ENOENT;
	*slash = '\0';
	if ((size_t)snprintf(out, size, "%s/xdev_ext_sendpath_baseline", self) >= size)
		return -ENAMETOOLONG;
	return 0;
}

/* Pages of the first RT_FILE_BYTES of path that are in the page cache,
 * counted with mincore() on a read-only shared mapping.  Neither the open,
 * the mapping nor mincore() reads the file.  Returns the count or a
 * negative errno. */
static int resident_pages(const char *path)
{
	unsigned char vec[(RT_FILE_BYTES + 4095) / 4096];
	long page = sysconf(_SC_PAGESIZE);
	size_t pages;
	int fd, n = 0;
	void *map;

	if (page < 4096)
		return -EINVAL;
	pages = (RT_FILE_BYTES + (size_t)page - 1) / (size_t)page;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	map = mmap(NULL, RT_FILE_BYTES, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return -errno;
	if (mincore(map, RT_FILE_BYTES, vec)) {
		int err = -errno;

		munmap(map, RT_FILE_BYTES);
		return err;
	}
	munmap(map, RT_FILE_BYTES);
	for (size_t i = 0; i < pages; i++)
		n += vec[i] & 1;
	return n;
}

/* Write 4096 zero bytes at offset 0 (before the window, which stays zero)
 * through fd, opened O_DIRECT.  Returns 0, -EINVAL when the filesystem
 * refuses the direct write, or another errno. */
static int direct_zero_page(int fd)
{
	void *zero = NULL;
	ssize_t got;
	int ret = 0;

	if (posix_memalign(&zero, 4096, 4096))
		return -ENOMEM;
	memset(zero, 0, 4096);
	got = pwrite(fd, zero, 4096, 0);
	if (got != 4096)
		ret = got < 0 ? -errno : -EIO;
	free(zero);
	return ret;
}

/* Create a zeroed target file on the first candidate filesystem that accepts
 * O_DIRECT and leaves no page in the page cache after an O_DIRECT write (so
 * a page found there after the run was put there by the baseline; a
 * filesystem on which O_DIRECT still goes through the page cache is not
 * used).  Returns 0, -EOPNOTSUPP when none does, or another errno. */
static int create_target(char *path, size_t size)
{
	const char *candidates[2] = { getenv("TMPDIR"), "/var/tmp" };

	for (size_t i = 0; i < 2; i++) {
		const char *dir = candidates[i];
		int fd, direct_fd, ret;

		if (!dir || !dir[0])
			continue;
		if ((size_t)snprintf(path, size, "%s/spb-runtime-XXXXXX", dir) >= size)
			continue;
		fd = mkstemp(path);
		if (fd < 0)
			continue;
		if (ftruncate(fd, (off_t)RT_FILE_BYTES)) {
			close(fd);
			unlink(path);
			continue;
		}
		close(fd);
		direct_fd = open(path, O_RDWR | O_DIRECT);
		if (direct_fd < 0) {
			int err = errno;

			unlink(path);
			if (err == EINVAL)
				continue;
			return -err;
		}
		ret = direct_zero_page(direct_fd);
		close(direct_fd);
		if (ret == -EINVAL) {
			unlink(path);
			continue;
		}
		if (!ret)
			ret = resident_pages(path);
		if (ret == 0)
			return 0;
		unlink(path);
		if (ret < 0)
			return ret;
		printf("# %s: an O_DIRECT write left %d page(s) in the page cache; not used\n",
		       dir, ret);
	}
	return -EOPNOTSUPP;
}

static size_t encode_segment(const struct nxp_wire_layout *layout,
			     uint16_t index, const uint8_t *data, uint8_t *out)
{
	struct nxp_wire_segment segment;
	struct nxp_wire_span span;

	if (nxp_wire_segment_at(layout, NXP_IO_WRITE, index, &segment))
		return 0;
	if (NXP_WIRE_HEADER_LEN + (size_t)segment.payload_len > RT_DATAGRAM_MAX)
		return 0;
	span.data = data + segment.relative_offset;
	span.len = segment.payload_len;
	if (nxp_wire_header_encode(out, NXP_WIRE_HEADER_LEN, &segment, &span, 1))
		return 0;
	memcpy(out + NXP_WIRE_HEADER_LEN, span.data, span.len);
	return NXP_WIRE_HEADER_LEN + span.len;
}

static void pace(void)
{
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000 };

	nanosleep(&delay, NULL);
}

static int send_one(int fd, const uint8_t *bytes, size_t len,
		    unsigned int *sent)
{
	ssize_t ret = send(fd, bytes, len, 0);

	if (ret < 0)
		return -errno;
	if ((size_t)ret != len)
		return -EIO;
	(*sent)++;
	pace();
	return 0;
}

/* A fixed non-identity permutation of 0..count-1 for each group. */
static void shuffled_order(uint16_t count, unsigned int group, uint16_t *order)
{
	for (uint16_t i = 0; i < count; i++)
		order[i] = (uint16_t)((i * 5u + group + 1u) % count);
	if (count > 1 && order[0] == 0 && order[1] == 1) {
		uint16_t first = order[0];

		order[0] = order[1];
		order[1] = first;
	}
}

static int send_groups(uint16_t port, uint64_t session, unsigned int groups,
		       unsigned int *sent)
{
	struct sockaddr_in peer = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	uint8_t datagrams[RT_MAX_SEGMENTS][RT_DATAGRAM_MAX];
	size_t lengths[RT_MAX_SEGMENTS];
	uint16_t order[RT_MAX_SEGMENTS];
	int fd, ret = 0;

	*sent = 0;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) {
		ret = -errno;
		goto out;
	}
	for (unsigned int g = 0; g < groups && g < RT_GROUPS && !ret; g++) {
		struct nxp_wire_layout layout;

		ret = nxp_wire_mtu_layout_plan(session, g + 1, RT_BYTES, RT_MTU,
					       SPB_PIPELINE_FRAME_SIZE,
					       SPB_PIPELINE_RX_DATA_OFFSET,
					       SPB_PIPELINE_VECTOR_ALIGNMENT,
					       &layout);
		if (ret)
			break;
		if (layout.segment_count > RT_MAX_SEGMENTS) {
			ret = -E2BIG;
			break;
		}
		for (uint16_t i = 0; i < layout.segment_count; i++) {
			lengths[i] = encode_segment(&layout, i, group_data[g],
						    datagrams[i]);
			if (!lengths[i]) {
				ret = -EINVAL;
				break;
			}
		}
		if (ret)
			break;
		/* Pass 1: shuffled; group 1 also carries a wrong-session datagram. */
		shuffled_order(layout.segment_count, g, order);
		for (uint16_t i = 0; i < layout.segment_count && !ret; i++) {
			ret = send_one(fd, datagrams[order[i]], lengths[order[i]],
				       sent);
			if (!ret && g == 1 && i == 2) {
				struct nxp_wire_layout foreign = layout;
				uint8_t bytes[RT_DATAGRAM_MAX];
				size_t len;

				foreign.session_id = session + 1;
				len = encode_segment(&foreign, 0, group_data[g],
						     bytes);
				ret = len ? send_one(fd, bytes, len, sent) :
					    -EINVAL;
			}
		}
		/* Pass 2: same-generation ordered retry; group 2 repeats one. */
		for (uint16_t i = 0; i < layout.segment_count && !ret; i++) {
			ret = send_one(fd, datagrams[i], lengths[i], sent);
			if (!ret && g == 2 && i == 3)
				ret = send_one(fd, datagrams[i], lengths[i], sent);
		}
	}
out:
	close(fd);
	return ret;
}

/* Send segments 0..2 of group 0, wait longer than the 1 s group timeout,
 * then send all of group 0 in order: the first attempt must expire and the
 * same generation must be accepted again from segment 0. */
static int send_expire_retry(uint16_t port, uint64_t session,
			     unsigned int *sent)
{
	struct sockaddr_in peer = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct timespec pause = { .tv_sec = 1, .tv_nsec = 200000000 };
	uint8_t datagram[RT_DATAGRAM_MAX];
	struct nxp_wire_layout layout;
	int fd, ret;

	*sent = 0;
	ret = nxp_wire_mtu_layout_plan(session, 1, RT_BYTES, RT_MTU,
				       SPB_PIPELINE_FRAME_SIZE,
				       SPB_PIPELINE_RX_DATA_OFFSET,
				       SPB_PIPELINE_VECTOR_ALIGNMENT, &layout);
	if (ret)
		return ret;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) {
		ret = -errno;
		goto out;
	}
	for (uint16_t i = 0; i < 3 && !ret; i++) {
		size_t len = encode_segment(&layout, i, group_data[0], datagram);

		ret = len ? send_one(fd, datagram, len, sent) : -EINVAL;
	}
	if (!ret)
		nanosleep(&pause, NULL);
	for (uint16_t i = 0; i < layout.segment_count && !ret; i++) {
		size_t len = encode_segment(&layout, i, group_data[0], datagram);

		ret = len ? send_one(fd, datagram, len, sent) : -EINVAL;
	}
out:
	close(fd);
	return ret;
}

/* The existing ten fields keep their order; the four operation and depth
 * fields follow them, then the four arrival fields, at the end of the line,
 * which ends there. */
static bool parse_summary(const char *line, struct rt_summary *summary)
{
	int end = -1;

	return sscanf(line,
		      "SENDPATH_BASELINE_SUMMARY groups=%llu packets_accepted=%llu "
		      "packets_dropped=%llu bytes_written=%llu write_errors=%llu "
		      "cpu_user_us=%llu cpu_sys_us=%llu wall_us=%llu "
		      "group_service_us_p50=%llu group_service_us_p99=%llu "
		      "write_ops=%llu write_fixed_ops=%llu pwrite_calls=%llu "
		      "max_inflight=%llu rx_span_us=%llu tail_us=%llu "
		      "group_post_arrival_us_p50=%llu "
		      "group_post_arrival_us_p99=%llu%n",
		      &summary->groups, &summary->packets_accepted,
		      &summary->packets_dropped, &summary->bytes_written,
		      &summary->write_errors, &summary->cpu_user_us,
		      &summary->cpu_sys_us, &summary->wall_us, &summary->p50,
		      &summary->p99, &summary->write_ops,
		      &summary->write_fixed_ops, &summary->pwrite_calls,
		      &summary->max_inflight, &summary->rx_span_us,
		      &summary->tail_us, &summary->post_p50,
		      &summary->post_p99, &end) == 18 &&
	       end > 0 && (line[end] == '\0' || line[end] == '\n');
}

/* Read len bytes at offset with O_DIRECT into a 4096-aligned buffer.  A
 * direct read is served by the file's storage, never by the page cache, so
 * the bytes compared afterwards are the bytes the baseline's writes left on
 * storage.  Offset and length are multiples of 4096. */
static int read_direct(const char *path, uint64_t offset, size_t len,
		       uint8_t **out)
{
	void *memory = NULL;
	ssize_t got;
	int fd, ret = 0;

	*out = NULL;
	if (posix_memalign(&memory, 4096, len))
		return -ENOMEM;
	fd = open(path, O_RDONLY | O_DIRECT | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		free(memory);
		return ret;
	}
	got = pread(fd, memory, len, (off_t)offset);
	if (got != (ssize_t)len) {
		ret = got < 0 ? -errno : -EIO;
		printf("# O_DIRECT read-back of %zu bytes at %" PRIu64 ": %s\n",
		       len, offset, got < 0 ? strerror(-ret) : "short read");
	}
	close(fd);
	if (ret) {
		free(memory);
		return ret;
	}
	*out = memory;
	return 0;
}

/* The O_DIRECT bit of the child's open file description for target, read
 * from /proc/<pid>/fdinfo independently of what the program prints.  Every
 * fd of the child that refers to target must carry it.  Returns 1, 0, or a
 * negative errno when no fd of the child refers to target. */
static int child_target_direct(pid_t pid, const char *target)
{
	char dir_path[64], path[PATH_MAX], line[256];
	struct stat want, st;
	struct dirent *entry;
	int found = -ENOENT;
	DIR *dir;

	if (stat(target, &want))
		return -errno;
	snprintf(dir_path, sizeof(dir_path), "/proc/%d/fd", (int)pid);
	dir = opendir(dir_path);
	if (!dir)
		return -errno;
	while ((entry = readdir(dir))) {
		unsigned int flags = 0;
		bool have_flags = false;
		FILE *info;

		if (entry->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir_path,
				     entry->d_name) >= sizeof(path) ||
		    stat(path, &st) || st.st_dev != want.st_dev ||
		    st.st_ino != want.st_ino)
			continue;
		if ((size_t)snprintf(path, sizeof(path), "/proc/%d/fdinfo/%s",
				     (int)pid, entry->d_name) >= sizeof(path)) {
			found = -ENAMETOOLONG;
			break;
		}
		info = fopen(path, "r");
		if (!info) {
			found = -errno;
			break;
		}
		while (fgets(line, sizeof(line), info))
			if (sscanf(line, "flags: %o", &flags) == 1) {
				have_flags = true;
				break;
			}
		fclose(info);
		if (!have_flags) {
			found = -EIO;
			break;
		}
		if (!(flags & O_DIRECT)) {
			found = 0;
			break;
		}
		found = 1;
	}
	closedir(dir);
	return found;
}

/* The registered buffers of the child's io_uring, read from
 * /proc/<pid>/fdinfo of its anon_inode:[io_uring] fd independently of what
 * the program prints: the UserBufs count, the number of listed buffers, and
 * how many of them are exactly bytes long.  The child is waiting in poll()
 * when this runs, so the ring lock fdinfo needs to list the buffers is free.
 * Returns 0, -ENOENT when the child has no io_uring fd, or another errno. */
static int child_ring_buffers(pid_t pid, uint32_t bytes,
			      unsigned int *user_bufs, unsigned int *listed,
			      unsigned int *right_len)
{
	char dir_path[64], path[PATH_MAX], link[128], line[256];
	struct dirent *entry;
	int found = -ENOENT;
	DIR *dir;

	*user_bufs = *listed = *right_len = 0;
	snprintf(dir_path, sizeof(dir_path), "/proc/%d/fd", (int)pid);
	dir = opendir(dir_path);
	if (!dir)
		return -errno;
	while ((entry = readdir(dir))) {
		unsigned long long addr;
		unsigned int index, len;
		bool have_count = false;
		ssize_t n;
		FILE *info;

		if (entry->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir_path,
				     entry->d_name) >= sizeof(path))
			continue;
		n = readlink(path, link, sizeof(link) - 1);
		if (n < 0)
			continue;
		link[n] = '\0';
		if (strcmp(link, "anon_inode:[io_uring]"))
			continue;
		if (found == 0) {
			/* The baseline sets up a single ring. */
			found = -EEXIST;
			break;
		}
		if ((size_t)snprintf(path, sizeof(path), "/proc/%d/fdinfo/%s",
				     (int)pid, entry->d_name) >= sizeof(path)) {
			found = -ENAMETOOLONG;
			break;
		}
		info = fopen(path, "r");
		if (!info) {
			found = -errno;
			break;
		}
		while (fgets(line, sizeof(line), info)) {
			if (sscanf(line, "UserBufs: %u", user_bufs) == 1) {
				have_count = true;
				continue;
			}
			if (have_count &&
			    sscanf(line, " %u: 0x%llx/%u", &index, &addr, &len) == 3) {
				(*listed)++;
				*right_len += len == bytes;
			}
		}
		fclose(info);
		if (!have_count) {
			found = -EIO;
			break;
		}
		found = 0;
	}
	closedir(dir);
	return found;
}

static int verify_file(const char *path)
{
	uint8_t *contents = NULL;
	struct stat st;
	int ret;

	if (stat(path, &st) || st.st_size != (off_t)RT_FILE_BYTES) {
		printf("# target size changed: %lld\n", (long long)st.st_size);
		return -EIO;
	}
	/* Before any read-back: create_target() showed that an O_DIRECT write
	 * leaves no page of this file in the page cache, so a resident page
	 * now means the baseline wrote (or read) through the page cache. */
	ret = resident_pages(path);
	if (ret) {
		printf("# %d target page(s) in the page cache after the run: the writes did not bypass it\n",
		       ret);
		return -EIO;
	}
	ret = read_direct(path, 0, RT_FILE_BYTES, &contents);
	if (ret)
		return ret;
	for (uint64_t i = 0; i < RT_START_LBA * RT_LBA_SIZE; i++) {
		if (contents[i]) {
			printf("# byte %" PRIu64 " before the window was written\n", i);
			ret = -EIO;
			goto out;
		}
	}
	for (unsigned int g = 0; g < RT_GROUPS; g++) {
		uint64_t offset = (RT_START_LBA + (uint64_t)g * RT_BLOCKS) *
				  RT_LBA_SIZE;

		if (memcmp(contents + offset, group_data[g], RT_BYTES)) {
			printf("# group %u bytes differ at file offset %" PRIu64 "\n",
			       g, offset);
			ret = -EIO;
			goto out;
		}
	}
out:
	free(contents);
	return ret;
}

struct rt_run {
	bool listening;
	bool started;
	bool completed;
	bool have_summary;
	bool have_drops;
	struct rt_summary summary;
	unsigned long long session_drops;
	unsigned long long groups_expired;
	unsigned int sent;
	int exit_status;
	int sender_error;
	char start_io[16];
	char start_buffer[16];
	int start_depth;
	unsigned long long start_session;
	/* odirect=<n> from the Target line; -1 when absent. */
	int target_odirect;
	/* O_DIRECT of the child's target fd per /proc fdinfo; -1 unchecked. */
	int fd_direct;
	/* child_ring_buffers() of the child at LISTEN; 1 unchecked. */
	int ring;
	unsigned int ring_user_bufs;
	unsigned int ring_listed;
	unsigned int ring_right_len;
};

/* Run the baseline with argv; when it reports its port, check the O_DIRECT
 * bit of its target fd (when target is given) and send the first
 * groups_to_send groups.  Every output line is echoed as a TAP comment. */
static int rt_spawn(const char *const *argv, const char *label,
		    const char *target, uint64_t session,
		    unsigned int groups_to_send, struct rt_run *run)
{
	char line[RT_LINE_MAX];
	int pipe_fds[2], status = 0;
	pid_t child;
	FILE *out;

	memset(run, 0, sizeof(*run));
	run->session_drops = ~0ULL;
	run->groups_expired = ~0ULL;
	run->exit_status = -1;
	run->target_odirect = -1;
	run->fd_direct = -1;
	run->ring = 1;
	if (pipe(pipe_fds))
		return -errno;
	child = fork();
	if (child < 0) {
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -errno;
	}
	if (child == 0) {
		close(pipe_fds[0]);
		if (dup2(pipe_fds[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(pipe_fds[1]);
		execv(argv[0], (char *const *)argv);
		fprintf(stderr, "cannot execute %s: %s\n", argv[0],
			strerror(errno));
		_exit(127);
	}
	close(pipe_fds[1]);
	out = fdopen(pipe_fds[0], "r");
	if (!out) {
		close(pipe_fds[0]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -ENOMEM;
	}
	while (fgets(line, sizeof(line), out)) {
		unsigned int parsed_port;

		printf("# [%s] %s", label, line);
		if (sscanf(line,
			   "Starting UDP recv -> O_DIRECT write baseline: depth=%d "
			   "session=%llu io=%15s buffer=%15s",
			   &run->start_depth, &run->start_session,
			   run->start_io, run->start_buffer) == 4)
			run->started = true;
		if (!strncmp(line, "Target: ", 8)) {
			const char *field = strstr(line, " odirect=");

			if (field && sscanf(field, " odirect=%d",
					    &run->target_odirect) != 1)
				run->target_odirect = -1;
		}
		if (!run->listening &&
		    sscanf(line, "SENDPATH_BASELINE_LISTEN addr=127.0.0.1 port=%u",
			   &parsed_port) == 1 && parsed_port && parsed_port < 65536) {
			run->listening = true;
			/* The program is now waiting for datagrams with its
			 * target open; its fd table cannot change before the
			 * first datagram is sent. */
			if (target) {
				run->fd_direct = child_target_direct(child, target);
				if (run->fd_direct < 0)
					printf("# [%s] cannot read the target fd flags: %s\n",
					       label, strerror(-run->fd_direct));
				run->ring = child_ring_buffers(child, RT_BYTES,
							       &run->ring_user_bufs,
							       &run->ring_listed,
							       &run->ring_right_len);
			}
			if (groups_to_send == RT_SEND_EXPIRE_RETRY)
				run->sender_error = send_expire_retry(
					(uint16_t)parsed_port, session,
					&run->sent);
			else if (groups_to_send)
				run->sender_error = send_groups(
					(uint16_t)parsed_port, session,
					groups_to_send, &run->sent);
		}
		if (!strcmp(line, "Baseline completed\n"))
			run->completed = true;
		if (parse_summary(line, &run->summary))
			run->have_summary = true;
		if (!strncmp(line, "SENDPATH_BASELINE_DROPS ", 24)) {
			const char *field = strstr(line, " session=");
			const char *expired = strstr(line, " groups_expired=");

			run->have_drops = true;
			if (field)
				sscanf(field, " session=%llu", &run->session_drops);
			if (expired)
				sscanf(expired, " groups_expired=%llu",
				       &run->groups_expired);
		}
	}
	fclose(out);
	if (waitpid(child, &status, 0) != child)
		return -ECHILD;
	run->exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	return 0;
}

/* The io_uring registered buffers that fdinfo showed at LISTEN must match the
 * arm: no io_uring fd for pwrite, a ring without registered buffers for
 * plain uring, and exactly depth buffers of RT_BYTES for --fixed-buffer.
 * Returns true when they match. */
static bool ring_buffers_match(const char *label, const struct rt_run *run,
			       bool uring, bool fixed, unsigned int depth)
{
	bool match;

	if (!uring)
		match = run->ring == -ENOENT;
	else if (!fixed)
		match = run->ring == 0 && run->ring_user_bufs == 0 &&
			run->ring_listed == 0;
	else
		match = run->ring == 0 && run->ring_user_bufs == depth &&
			run->ring_listed == depth && run->ring_right_len == depth;
	if (match)
		return true;
	if (run->ring == 1) {
		printf("# [%s] io_uring fdinfo not read: no LISTEN line\n", label);
		return false;
	}
	printf("# [%s] io_uring fdinfo: ring=%d UserBufs=%u listed=%u of %" PRIu32 " bytes=%u; ",
	       label, run->ring, run->ring_user_bufs, run->ring_listed,
	       RT_BYTES, run->ring_right_len);
	if (!uring)
		printf("want no io_uring fd\n");
	else if (!fixed)
		printf("want UserBufs=0\n");
	else
		printf("want %u registered buffers of %" PRIu32 " bytes\n", depth,
		       RT_BYTES);
	return false;
}

static int run_arm(const char *baseline, const struct rt_arm *arm,
		   uint64_t session)
{
	char target[PATH_MAX], depth[16], session_text[32];
	const unsigned long long accepted = (unsigned long long)RT_GROUPS * 6;
	struct rt_run run;
	int ret, failed = 0;

	ret = create_target(target, sizeof(target));
	if (ret == -EOPNOTSUPP)
		return KSFT_SKIP;
	if (ret) {
		printf("# cannot create target: %s\n", strerror(-ret));
		return 1;
	}
	snprintf(depth, sizeof(depth), "%d", arm->depth);
	snprintf(session_text, sizeof(session_text), "%llu",
		 (unsigned long long)session);
	{
		const char *argv[] = {
			baseline, "-k", target, "-l", "16", "-n", "4",
			"-b", "512", "-B", "8192", "-Q", depth,
			"-e", session_text, "-a", "127.0.0.1", "-p", "0",
			"-M", "1500", "--io", arm->io, "--timeout-ms", "5000",
			arm->fixed_buffer ? "--fixed-buffer" : NULL, NULL,
		};

		ret = rt_spawn(argv, arm->name, target, session, RT_GROUPS,
			       &run);
	}
	if (ret) {
		printf("# cannot run baseline: %s\n", strerror(-ret));
		unlink(target);
		return 1;
	}
	if (run.sender_error) {
		printf("# sender failed: %s\n", strerror(-run.sender_error));
		failed = 1;
	}
	if (run.exit_status != 0) {
		printf("# baseline exit status %d\n", run.exit_status);
		failed = 1;
	}
	if (!run.listening || !run.started || !run.completed ||
	    !run.have_summary || !run.have_drops) {
		printf("# missing output: listen=%d start=%d completed=%d summary=%d drops=%d\n",
		       run.listening, run.started, run.completed,
		       run.have_summary, run.have_drops);
		failed = 1;
	}
	if (run.started &&
	    (run.start_depth != arm->depth || run.start_session != session ||
	     strcmp(run.start_io, arm->io) ||
	     strcmp(run.start_buffer, arm->fixed_buffer ? "fixed" : "heap"))) {
		printf("# start line does not describe this arm\n");
		failed = 1;
	}
	if (run.have_summary &&
	    (run.summary.groups != RT_GROUPS ||
	     run.summary.packets_accepted != accepted ||
	     run.summary.packets_dropped != run.sent - accepted ||
	     run.summary.bytes_written != (unsigned long long)RT_GROUPS * RT_BYTES ||
	     run.summary.write_errors != 0 || !run.summary.wall_us ||
	     run.summary.p50 > run.summary.p99 ||
	     run.summary.p99 > run.summary.wall_us)) {
		printf("# summary mismatch: sent=%u groups=%llu accepted=%llu "
		       "dropped=%llu bytes=%llu errors=%llu wall=%llu p50=%llu p99=%llu\n",
		       run.sent, run.summary.groups, run.summary.packets_accepted,
		       run.summary.packets_dropped, run.summary.bytes_written,
		       run.summary.write_errors, run.summary.wall_us,
		       run.summary.p50, run.summary.p99);
		failed = 1;
	}
	/* The receive span and the tail add up to wall_us to within the
	 * truncation of each to whole microseconds; a group's post-arrival
	 * time starts at its last datagram, its service time at its first. */
	if (run.have_summary &&
	    (!run.summary.rx_span_us ||
	     run.summary.rx_span_us + run.summary.tail_us >
		     run.summary.wall_us ||
	     run.summary.rx_span_us + run.summary.tail_us + 1 <
		     run.summary.wall_us ||
	     run.summary.post_p50 > run.summary.post_p99 ||
	     run.summary.post_p50 > run.summary.p50 ||
	     run.summary.post_p99 > run.summary.p99)) {
		printf("# arrival fields inconsistent: wall=%llu rx_span=%llu "
		       "tail=%llu post_p50=%llu post_p99=%llu p50=%llu "
		       "p99=%llu\n",
		       run.summary.wall_us, run.summary.rx_span_us,
		       run.summary.tail_us, run.summary.post_p50,
		       run.summary.post_p99, run.summary.p50, run.summary.p99);
		failed = 1;
	}
	if (run.have_drops && run.session_drops != 1) {
		printf("# expected exactly one session drop, got %llu\n",
		       run.session_drops);
		failed = 1;
	}
	if (run.target_odirect != 1 || run.fd_direct != 1) {
		printf("# target not written with O_DIRECT: Target odirect=%d, "
		       "fdinfo O_DIRECT=%d\n", run.target_odirect, run.fd_direct);
		failed = 1;
	}
	/* Tier 2 registers one buffer per slot; tier 1 registers none. */
	if (!ring_buffers_match(arm->name, &run, strcmp(arm->io, "pwrite") != 0,
				arm->fixed_buffer, (unsigned int)arm->depth))
		failed = 1;
	if (run.have_summary) {
		const bool pwrite_arm = !strcmp(arm->io, "pwrite");
		const unsigned long long want_write =
			!pwrite_arm && !arm->fixed_buffer ? RT_GROUPS : 0;
		const unsigned long long want_fixed =
			!pwrite_arm && arm->fixed_buffer ? RT_GROUPS : 0;
		const unsigned long long want_pwrite = pwrite_arm ? RT_GROUPS : 0;

		/* Tier 1 uses only IORING_OP_WRITE or only pwrite(); tier 2
		 * only IORING_OP_WRITE_FIXED; each exactly once per group. */
		if (run.summary.write_ops != want_write ||
		    run.summary.write_fixed_ops != want_fixed ||
		    run.summary.pwrite_calls != want_pwrite) {
			printf("# write operations do not match the arm: "
			       "write_ops=%llu (want %llu) write_fixed_ops=%llu "
			       "(want %llu) pwrite_calls=%llu (want %llu)\n",
			       run.summary.write_ops, want_write,
			       run.summary.write_fixed_ops, want_fixed,
			       run.summary.pwrite_calls, want_pwrite);
			failed = 1;
		}
		if (run.summary.max_inflight < 1 ||
		    run.summary.max_inflight > (unsigned long long)arm->depth) {
			printf("# max_inflight=%llu outside [1, %d]\n",
			       run.summary.max_inflight, arm->depth);
			failed = 1;
		}
	}
	if (!failed && verify_file(target))
		failed = 1;
	unlink(target);
	return failed;
}

struct rt_reject {
	const char *name;
	const char *extra[6];
	unsigned int groups_to_send;
	long long expect_groups;
};

/* The baseline must exit nonzero, and never print "Baseline completed", for
 * an unsafe configuration, an idle timeout, or fewer than -n written groups. */
static int run_rejections(const char *baseline, unsigned int *count)
{
	static const struct rt_reject cases[] = {
		{ "pwrite-requires-q1", { "--io", "pwrite", "-Q", "4" }, 0, -1 },
		{ "fixed-buffer-requires-uring",
		  { "--io", "pwrite", "--fixed-buffer" }, 0, -1 },
		{ "zero-session", { "-e", "0" }, 0, -1 },
		{ "bytes-not-lba-multiple", { "-B", "8000" }, 0, -1 },
		{ "window-exceeds-target", { "-n", "1000" }, 0, -1 },
		{ "idle-timeout", { "-n", "2" }, 0, 0 },
		{ "fewer-than-n-groups", { "-n", "2" }, 1, 1 },
		/* connect() to a peer port the sender does not use: the kernel
		 * delivers none of its datagrams, so no group can complete. */
		{ "peer-filter", { "-n", "1", "-s", "127.0.0.1", "-P", "9" }, 1, 0 },
	};
	char target[PATH_MAX];
	int failures = 0, ret;

	ret = create_target(target, sizeof(target));
	if (ret == -EOPNOTSUPP)
		return KSFT_SKIP;
	if (ret)
		return 1;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct rt_reject *c = &cases[i];
		const char *argv[40];
		struct rt_run run;
		size_t n = 0;
		int failed = 0;

		argv[n++] = baseline;
		argv[n++] = "-k";
		argv[n++] = target;
		argv[n++] = "-l";
		argv[n++] = "16";
		argv[n++] = "-n";
		argv[n++] = "4";
		argv[n++] = "-e";
		argv[n++] = "6003370871052304400";
		argv[n++] = "-a";
		argv[n++] = "127.0.0.1";
		argv[n++] = "-p";
		argv[n++] = "0";
		argv[n++] = "--timeout-ms";
		argv[n++] = "300";
		for (size_t e = 0; e < 6 && c->extra[e]; e++)
			argv[n++] = c->extra[e];
		argv[n] = NULL;
		ret = rt_spawn(argv, c->name, NULL,
			       UINT64_C(6003370871052304400),
			       c->groups_to_send, &run);
		if (ret || run.exit_status == 0 || run.exit_status == -1 ||
		    run.completed) {
			printf("# %s: exit=%d completed=%d\n", c->name,
			       run.exit_status, run.completed);
			failed = 1;
		}
		if (c->expect_groups >= 0 &&
		    (!run.have_summary ||
		     run.summary.groups != (unsigned long long)c->expect_groups)) {
			printf("# %s: expected groups=%lld in the summary\n",
			       c->name, c->expect_groups);
			failed = 1;
		}
		/* At the default -Q 1 at most one write is in flight, so the
		 * depth reached is exactly 1 with a write and 0 without one. */
		if (c->expect_groups >= 0 && run.have_summary &&
		    run.summary.max_inflight !=
		    (unsigned long long)(c->expect_groups ? 1 : 0)) {
			printf("# %s: max_inflight=%llu with %lld write(s)\n",
			       c->name, run.summary.max_inflight,
			       c->expect_groups);
			failed = 1;
		}
		if (c->expect_groups < 0 && run.listening) {
			printf("# %s: an unsafe configuration started listening\n",
			       c->name);
			failed = 1;
		}
		(*count)++;
		printf("%s %u - reject %s\n", failed ? "not ok" : "ok", *count,
		       c->name);
		failures += failed;
	}
	unlink(target);
	return failures ? 1 : 0;
}

/* An incomplete group expires after the pipeline's 1 s group timeout and
 * the same generation is then accepted again from segment 0.  The case runs
 * at -Q 4 and writes exactly one group, so max_inflight must be exactly 1
 * whatever the timing: a value of -Q would not be the depth reached. */
static int run_expiry(const char *baseline, unsigned int *count)
{
	char target[PATH_MAX];
	struct rt_run run;
	int failed = 0, ret;

	ret = create_target(target, sizeof(target));
	if (ret == -EOPNOTSUPP)
		return KSFT_SKIP;
	if (ret)
		return 1;
	{
		const char *argv[] = {
			baseline, "-k", target, "-l", "16", "-n", "1",
			"-e", "6003370871052304500", "-a", "127.0.0.1",
			"-p", "0", "--io", "uring", "-Q", "4",
			"--timeout-ms", "5000", NULL,
		};

		ret = rt_spawn(argv, "expire-retry", target,
			       UINT64_C(6003370871052304500),
			       RT_SEND_EXPIRE_RETRY, &run);
	}
	if (ret || run.sender_error || run.exit_status != 0 ||
	    !run.completed || !run.have_summary || !run.have_drops ||
	    run.summary.groups != 1 || run.summary.packets_accepted != 3 + 6 ||
	    run.summary.packets_dropped != 0 || run.groups_expired != 1 ||
	    run.sent != 3 + 6 || run.target_odirect != 1 ||
	    run.fd_direct != 1 || run.summary.write_ops != 1 ||
	    run.summary.write_fixed_ops != 0 || run.summary.pwrite_calls != 0 ||
	    run.summary.max_inflight != 1) {
		printf("# expire-retry: exit=%d groups=%llu accepted=%llu dropped=%llu expired=%llu sent=%u "
		       "odirect=%d fdinfo_direct=%d write_ops=%llu write_fixed_ops=%llu pwrite_calls=%llu max_inflight=%llu\n",
		       run.exit_status, run.summary.groups,
		       run.summary.packets_accepted, run.summary.packets_dropped,
		       run.groups_expired, run.sent, run.target_odirect,
		       run.fd_direct, run.summary.write_ops,
		       run.summary.write_fixed_ops, run.summary.pwrite_calls,
		       run.summary.max_inflight);
		failed = 1;
	}
	if (!ring_buffers_match("expire-retry", &run, true, false, 4))
		failed = 1;
	if (!failed) {
		/* Before the read-back, as in verify_file(). */
		ret = resident_pages(target);
		if (ret) {
			printf("# expire-retry: %d target page(s) in the page cache after the run\n",
			       ret);
			failed = 1;
		}
	}
	if (!failed) {
		uint8_t *contents = NULL;

		if (read_direct(target, RT_START_LBA * RT_LBA_SIZE, RT_BYTES,
				&contents) ||
		    memcmp(contents, group_data[0], RT_BYTES)) {
			printf("# expire-retry: written bytes differ\n");
			failed = 1;
		}
		free(contents);
	}
	unlink(target);
	printf("%s %u - expired group retried with the same generation\n",
	       failed ? "not ok" : "ok", ++*count);
	return failed;
}

int main(void)
{
	static const struct rt_arm arms[] = {
		{ "pwrite-q1", "pwrite", 1, false },
		{ "uring-q4", "uring", 4, false },
		{ "uring-q4-fixed", "uring", 4, true },
	};
	char baseline[PATH_MAX];
	unsigned int count = 0;
	int failures = 0;
	int ret;

	for (unsigned int g = 0; g < RT_GROUPS; g++)
		fill_pattern(group_data[g], RT_BYTES, 101 + g);
	ret = baseline_path(baseline, sizeof(baseline));
	if (ret) {
		printf("not ok - cannot locate baseline: %s\n", strerror(-ret));
		return 1;
	}
	if (access(baseline, X_OK)) {
		printf("not ok - baseline %s is not executable: %s\n", baseline,
		       strerror(errno));
		return 1;
	}
	for (size_t i = 0; i < sizeof(arms) / sizeof(arms[0]); i++) {
		ret = run_arm(baseline, &arms[i],
			      UINT64_C(0x5350420000000001) + i);
		if (ret == KSFT_SKIP) {
			printf("# SKIP: no filesystem under $TMPDIR or /var/tmp accepts O_DIRECT writes that bypass the page cache\n");
			return KSFT_SKIP;
		}
		printf("%s %u - %s\n", ret ? "not ok" : "ok", ++count,
		       arms[i].name);
		failures += ret ? 1 : 0;
	}
	ret = run_expiry(baseline, &count);
	if (ret == KSFT_SKIP) {
		printf("# SKIP: no filesystem under $TMPDIR or /var/tmp accepts O_DIRECT writes that bypass the page cache\n");
		return KSFT_SKIP;
	}
	failures += ret ? 1 : 0;
	ret = run_rejections(baseline, &count);
	if (ret == KSFT_SKIP) {
		printf("# SKIP: no filesystem under $TMPDIR or /var/tmp accepts O_DIRECT writes that bypass the page cache\n");
		return KSFT_SKIP;
	}
	failures += ret ? 1 : 0;
	if (failures) {
		printf("FAIL: %d runtime group(s) failed\n", failures);
		return 1;
	}
	printf("PASS: %u runtime checks\n", count);
	return 0;
}

// SPDX-License-Identifier: GPL-2.0

#include <assert.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Use this tree's UAPI before mini_liburing can include its tools copy. */
#include "../../../../../include/uapi/linux/io_uring.h"
#include "../../../../../include/uapi/linux/xdev_ext_binding.h"
#include <io_uring/mini_liburing.h>
#include <bpf/btf.h>
#include <test_progs.h>
#include <xsk.h>

#include "../xdev_ext_binding_test.h"
/* The skeleton's .bss names this type; it is the shipped loader's layout. */
#include "../../../../xdev_ext_reference_policy_abi.h"
#include "xdev_ext_binding_fail_fabricated_ctx.skel.h"
#include "xdev_ext_binding_fail_foreign_ops.skel.h"
#include "xdev_ext_binding_fail_kfunc.skel.h"
#include "xdev_ext_binding_fail_kfunc_complete.skel.h"
#include "xdev_ext_binding_fail_sleepable.skel.h"
#include "xdev_ext_binding_fail_write.skel.h"
#include "xdev_ext_binding_fail_write_kernel.skel.h"
#include "xdev_ext_binding_invalid_decision.skel.h"
#include "xdev_ext_binding_legacy.skel.h"
#include "xdev_ext_binding_missing_select.skel.h"
#include "xdev_ext_binding_success.skel.h"
#include "xdev_ext_binding_xsk_rx.skel.h"
#include "xdev_ext_reference_policy_wrap.skel.h"

#define XDEV_EXT_SUCCESS_FALLBACK		0U
#define XDEV_EXT_SUCCESS_USE_PLAN		1U
#define XDEV_EXT_SUCCESS_TERMINAL		2U
#define XDEV_EXT_SUCCESS_RETURN_MISMATCH	3U
#define XDEV_EXT_SUCCESS_ZERO_CALLS		4U
#define XDEV_EXT_SUCCESS_DUPLICATE_CALLS	5U
#define XDEV_EXT_SUCCESS_INVALID_PLAN	6U
#define XDEV_EXT_SUCCESS_HOLD_DISPATCH	7U
#define XDEV_EXT_SUCCESS_FORGED_CTX		9U
#define XDEV_EXT_SUCCESS_FOREIGN_THEN_VALID	10U
#define XDEV_EXT_SUCCESS_VALID_THEN_FOREIGN	11U

#define XDEV_EXT_TEST_RING_ENTRIES		8U
#define XDEV_EXT_TEST_RECV_MAX		256U
#define XDEV_EXT_TEST_CQE_TIMEOUT_MS		2000U
#define XDEV_EXT_TEST_WINDOW_TIMEOUT_MS	3000U
#define XDEV_EXT_TEST_CONCURRENT_ROUNDS	8U
#define XDEV_EXT_TEST_NVME_CHILD_TIMEOUT_MS	120000U
#define XDEV_EXT_TEST_NVME_KILL_REAP_TIMEOUT_MS 5000U
#define XDEV_EXT_TEST_PACKET_TIMEOUT_MS	2000U
#define XDEV_EXT_TEST_NO_PACKET_TIMEOUT_MS	250U
#define XDEV_EXT_TEST_IAA_TIMEOUT_MS		10000U
#define XDEV_EXT_TEST_XSK_FRAMES		4U
#define XDEV_EXT_TEST_XSK_FRAME_SIZE		4096U
#define XDEV_EXT_TEST_AFXDP_FRAME_LEN	64U
/* The native RX test sends EtherTypes 0x88c1, 0x88c2 and 0x88c3. */
#define XDEV_EXT_TEST_RX_ETHERTYPE_FIRST	0x88c1U
#define XDEV_EXT_TEST_RX_ETHERTYPE_LAST	0x88c3U
#define XDEV_EXT_TEST_MSG_SENDPAGE_DECRYPTED	UINT64_C(0x00100000)
#define XDEV_EXT_NSEC_PER_MSEC		1000000ULL
#define XDEV_EXT_NSEC_PER_SEC		1000000000ULL

#ifndef __NR_pidfd_open
#ifdef __alpha__
#define __NR_pidfd_open		544
#else
#define __NR_pidfd_open		434
#endif
#endif

#ifndef __NR_pidfd_send_signal
#ifdef __alpha__
#define __NR_pidfd_send_signal	534
#else
#define __NR_pidfd_send_signal	424
#endif
#endif

static_assert(offsetof(struct io_uring_sqe, off) ==
	      offsetof(struct io_uring_sqe, addr2),
	      "UNIFIED_OPS off and addr2 share one SQE union slot");

struct xdev_ext_runtime_fixture {
	struct io_uring ring;
	struct io_uring_unified_shared *shared;
	void *umem;
	size_t page_size;
	size_t umem_size;
	int sockets[2];
	bool ring_ready;
	bool umem_registered;
};

static int xdev_ext_register_umem(struct xdev_ext_runtime_fixture *fixture)
{
	struct io_uring_xdev_ext_umem_reg reg = {
		.addr = (uintptr_t)fixture->umem,
		.size = fixture->umem_size,
		.shared_addr = (uintptr_t)fixture->shared,
		.frame_size = fixture->page_size,
		.flags = 0,
	};
	int ret;

	ret = syscall(__NR_io_uring_register, fixture->ring.ring_fd,
		      IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1);
	return ret < 0 ? -errno : ret;
}

static int xdev_ext_runtime_fixture_cleanup(struct xdev_ext_runtime_fixture *fixture)
{
	int cleanup_err = 0;
	int ret;

	if (fixture->umem_registered) {
		ret = syscall(__NR_io_uring_register, fixture->ring.ring_fd,
			      IORING_UNREGISTER_XDEV_EXT_UMEM, NULL, 0);
		if (ret < 0)
			cleanup_err = -errno;
		fixture->umem_registered = false;
	}

	if (fixture->ring_ready) {
		ret = io_uring_queue_exit(&fixture->ring);
		fixture->ring_ready = false;
		if (ret && !cleanup_err)
			cleanup_err = ret;
	}

	if (fixture->sockets[0] >= 0)
		close(fixture->sockets[0]);
	if (fixture->sockets[1] >= 0)
		close(fixture->sockets[1]);
	fixture->sockets[0] = -1;
	fixture->sockets[1] = -1;

	if (fixture->shared && fixture->shared != MAP_FAILED)
		munmap(fixture->shared, fixture->page_size);
	if (fixture->umem && fixture->umem != MAP_FAILED)
		munmap(fixture->umem, fixture->umem_size);
	fixture->shared = NULL;
	fixture->umem = NULL;
	return cleanup_err;
}

static int xdev_ext_runtime_fixture_init_pages(struct xdev_ext_runtime_fixture *fixture,
					  unsigned int nr_pages)
{
	long page_size;
	int ret;

	memset(fixture, 0, sizeof(*fixture));
	fixture->sockets[0] = -1;
	fixture->sockets[1] = -1;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return -EINVAL;
	if (!nr_pages || (size_t)page_size > SIZE_MAX / nr_pages)
		return -EOVERFLOW;
	fixture->page_size = page_size;
	fixture->umem_size = (size_t)page_size * nr_pages;

	ret = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
			 fixture->sockets);
	if (ret) {
		ret = -errno;
		goto err;
	}

	fixture->umem = mmap(NULL, fixture->umem_size,
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (fixture->umem == MAP_FAILED) {
		ret = -errno;
		goto err;
	}
	fixture->shared = mmap(NULL, fixture->page_size,
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (fixture->shared == MAP_FAILED) {
		ret = -errno;
		goto err;
	}
	memset(fixture->shared, 0, fixture->page_size);

	ret = io_uring_queue_init(XDEV_EXT_TEST_RING_ENTRIES, &fixture->ring, 0);
	if (ret) {
		if (ret == -1)
			ret = -errno;
		goto err;
	}
	fixture->ring_ready = true;

	ret = xdev_ext_register_umem(fixture);
	if (ret)
		goto err;
	fixture->umem_registered = true;
	return 0;

err:
	xdev_ext_runtime_fixture_cleanup(fixture);
	return ret;
}

static int xdev_ext_runtime_fixture_init(struct xdev_ext_runtime_fixture *fixture)
{
	return xdev_ext_runtime_fixture_init_pages(fixture, 1);
}

static int xdev_ext_monotonic_ns(uint64_t *now_ns)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -errno;
	*now_ns = (uint64_t)now.tv_sec * XDEV_EXT_NSEC_PER_SEC + now.tv_nsec;
	return 0;
}

static int xdev_ext_peek_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr)
{
	unsigned int head, tail;

	/* The bounded users of this helper have exactly one CQ consumer. */
	head = __atomic_load_n(ring->cq.khead, __ATOMIC_RELAXED);
	tail = __atomic_load_n(ring->cq.ktail, __ATOMIC_ACQUIRE);
	if (head == tail) {
		*cqe_ptr = NULL;
		return -EAGAIN;
	}

	*cqe_ptr = &ring->cq.cqes[head & *ring->cq.kring_mask];
	return 0;
}

static int xdev_ext_wait_cqe_bounded(struct io_uring *ring,
				struct io_uring_cqe **cqe_ptr,
				unsigned int timeout_ms)
{
	uint64_t deadline_ns, now_ns, remaining_ns;
	struct io_uring_getevents_arg arg = {};
	struct __kernel_timespec timeout;
	int err;
	long ret;

	err = xdev_ext_monotonic_ns(&now_ns);
	if (err)
		return err;
	deadline_ns = now_ns + (uint64_t)timeout_ms * XDEV_EXT_NSEC_PER_MSEC;

	for (;;) {
		if (!xdev_ext_peek_cqe(ring, cqe_ptr))
			return 0;

		err = xdev_ext_monotonic_ns(&now_ns);
		if (err)
			return err;
		if (now_ns >= deadline_ns)
			return -ETIMEDOUT;

		remaining_ns = deadline_ns - now_ns;
		timeout.tv_sec = remaining_ns / XDEV_EXT_NSEC_PER_SEC;
		timeout.tv_nsec = remaining_ns % XDEV_EXT_NSEC_PER_SEC;
		arg.ts = (uintptr_t)&timeout;

		ret = syscall(__NR_io_uring_enter, ring->ring_fd, 0, 1,
			      IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
			      &arg, sizeof(arg));
		if (ret >= 0)
			continue;
		if (errno == EINTR)
			continue;
		if (errno == ETIME || errno == ETIMEDOUT) {
			if (!xdev_ext_peek_cqe(ring, cqe_ptr))
				return 0;
			return -ETIMEDOUT;
		}
		return -errno;
	}
}

static int xdev_ext_submit_send_with_wait(struct xdev_ext_runtime_fixture *fixture,
				     int fd, uint64_t umem_offset,
				     uint32_t length, uint64_t send_flags,
				     bool bounded_wait, int *cqe_res)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&fixture->ring);
	if (!sqe)
		return -ENOSPC;
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_UNIFIED_OPS;
	sqe->flags = IOSQE_XDEV_EXT_UMEM;
	sqe->fd = fd;
	sqe->addr = umem_offset;
	sqe->len = IO_UNIFIED_OP_SEND;
	sqe->rw_flags = length;
	sqe->off = send_flags;

	ret = io_uring_submit(&fixture->ring);
	if (ret < 0)
		return ret;
	if (ret != 1)
		return -EIO;
	if (bounded_wait)
		ret = xdev_ext_wait_cqe_bounded(&fixture->ring, &cqe,
					   XDEV_EXT_TEST_CQE_TIMEOUT_MS);
	else
		ret = io_uring_wait_cqe(&fixture->ring, &cqe);
	if (ret)
		return ret;
	*cqe_res = cqe->res;
	io_uring_cqe_seen(&fixture->ring);
	return 0;
}

static int xdev_ext_submit_send(struct xdev_ext_runtime_fixture *fixture, int fd,
			   uint64_t umem_offset, uint32_t length,
			   uint64_t send_flags)
{
	int cqe_res = -EINPROGRESS;
	int ret;

	ret = xdev_ext_submit_send_with_wait(fixture, fd, umem_offset, length,
					send_flags, false, &cqe_res);
	return ret ? ret : cqe_res;
}

static int xdev_ext_submit_send_bounded(struct xdev_ext_runtime_fixture *fixture, int fd,
				   uint64_t umem_offset, uint32_t length,
				   uint64_t send_flags, int *cqe_res)
{
	return xdev_ext_submit_send_with_wait(fixture, fd, umem_offset, length,
					  send_flags, true, cqe_res);
}

static int
xdev_ext_submit_user_send_bounded(struct xdev_ext_runtime_fixture *fixture, int fd,
			     const void *buffer, uint32_t length,
			     uint64_t send_flags, bool legacy, int *cqe_res)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	if (legacy && send_flags)
		return -EINVAL;
	sqe = io_uring_get_sqe(&fixture->ring);
	if (!sqe)
		return -ENOSPC;
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_UNIFIED_OPS;
	sqe->fd = fd;
	sqe->addr = (uintptr_t)buffer;
	sqe->len = IO_UNIFIED_OP_SEND;
	sqe->rw_flags = length;
	if (legacy) {
		sqe->off = (uintptr_t)fixture->shared;
	} else {
		sqe->off = send_flags;
		sqe->addr3 = (uintptr_t)fixture->shared;
	}

	ret = io_uring_submit(&fixture->ring);
	if (ret < 0)
		return ret;
	if (ret != 1)
		return -EIO;
	ret = xdev_ext_wait_cqe_bounded(&fixture->ring, &cqe,
				   XDEV_EXT_TEST_CQE_TIMEOUT_MS);
	if (ret)
		return ret;
	*cqe_res = cqe->res;
	io_uring_cqe_seen(&fixture->ring);
	return 0;
}

static int
xdev_ext_submit_afxdp_copy_bounded(struct xdev_ext_runtime_fixture *fixture, int fd,
			      uint64_t xsk_offset, uint32_t length,
			      uint64_t send_flags,
			      int *cqe_res)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&fixture->ring);
	if (!sqe)
		return -ENOSPC;
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_UNIFIED_OPS;
	sqe->fd = fd;
	sqe->addr = xsk_offset;
	sqe->len = IO_UNIFIED_OP_SEND;
	sqe->rw_flags = length;
	/* Keep off for flags; addr2 aliases it in the SQE layout. */
	sqe->off = send_flags;
	sqe->addr3 = (uintptr_t)fixture->shared;

	ret = io_uring_submit(&fixture->ring);
	if (ret < 0)
		return ret;
	if (ret != 1)
		return -EIO;
	ret = xdev_ext_wait_cqe_bounded(&fixture->ring, &cqe,
				   XDEV_EXT_TEST_CQE_TIMEOUT_MS);
	if (ret)
		return ret;
	*cqe_res = cqe->res;
	io_uring_cqe_seen(&fixture->ring);
	return 0;
}

static int xdev_ext_submit_iaa_bounded(struct xdev_ext_runtime_fixture *fixture,
				  uint32_t opcode, uint64_t src_offset,
				  uint64_t dst_offset, uint32_t src_length,
				  uint64_t dst_capacity, int *cqe_res)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&fixture->ring);
	if (!sqe)
		return -ENOSPC;
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_UNIFIED_OPS;
	sqe->flags = IOSQE_XDEV_EXT_UMEM;
	sqe->fd = -1;
	sqe->addr = src_offset;
	sqe->off = dst_offset;
	sqe->len = opcode;
	sqe->rw_flags = src_length;
	sqe->addr3 = dst_capacity;

	ret = io_uring_submit(&fixture->ring);
	if (ret < 0)
		return ret;
	if (ret != 1)
		return -EIO;
	ret = xdev_ext_wait_cqe_bounded(&fixture->ring, &cqe,
				   XDEV_EXT_TEST_IAA_TIMEOUT_MS);
	if (ret)
		return ret;
	*cqe_res = cqe->res;
	io_uring_cqe_seen(&fixture->ring);
	return 0;
}

static int xdev_ext_receive_payload(int fd, const void *expected, size_t length)
{
	unsigned char received[XDEV_EXT_TEST_RECV_MAX];
	ssize_t ret;

	if (length > sizeof(received))
		return -E2BIG;
	ret = recv(fd, received, sizeof(received), MSG_DONTWAIT);
	if (ret < 0)
		return -errno;
	if ((size_t)ret != length)
		return -EMSGSIZE;
	return memcmp(received, expected, length) ? -EBADMSG : 0;
}

static int xdev_ext_expect_no_payload(int fd)
{
	unsigned char byte;
	ssize_t ret;

	ret = recv(fd, &byte, sizeof(byte), MSG_DONTWAIT);
	if (ret >= 0)
		return -EEXIST;
	return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -errno;
}

static int xdev_ext_read_u64_file(const char *path, uint64_t *value)
{
	char buffer[64];
	char *end;
	unsigned long long parsed;
	ssize_t bytes;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	bytes = read(fd, buffer, sizeof(buffer) - 1);
	if (bytes < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}
	close(fd);
	if (!bytes)
		return -EINVAL;
	buffer[bytes] = '\0';
	errno = 0;
	parsed = strtoull(buffer, &end, 10);
	if (errno || end == buffer)
		return -EINVAL;
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (*end)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int xdev_ext_wait_child_bounded(pid_t child, unsigned int timeout_ms,
				  int *status)
{
	const struct timespec pause = { .tv_nsec = 10 * XDEV_EXT_NSEC_PER_MSEC };
	uint64_t deadline_ns, now_ns;
	pid_t waited;
	int pidfd;
	int ret;

	/* Keep a stable reference for timeout signalling.  A numeric PID is not
	 * safe after an unexpected ECHILD because it may already be reusable.
	 */
	pidfd = syscall(__NR_pidfd_open, child, 0);
	ret = xdev_ext_monotonic_ns(&now_ns);
	if (ret)
		goto terminate;
	deadline_ns = now_ns + (uint64_t)timeout_ms * XDEV_EXT_NSEC_PER_MSEC;
	for (;;) {
		waited = waitpid(child, status, WNOHANG);
		if (waited == child) {
			ret = 0;
			goto out;
		}
		if (waited < 0 && errno != EINTR) {
			ret = -errno;
			goto terminate;
		}
		ret = xdev_ext_monotonic_ns(&now_ns);
		if (ret)
			goto terminate;
		if (now_ns >= deadline_ns)
			break;
		nanosleep(&pause, NULL);
	}

	ret = -ETIMEDOUT;
terminate:
	if (pidfd < 0)
		goto out;
	if (syscall(__NR_pidfd_send_signal, pidfd, SIGKILL, NULL, 0) &&
	    errno != ESRCH)
		goto out;

	/* SIGKILL cannot complete while a task is stuck in uninterruptible sleep.
	 * Reap opportunistically for a bounded grace period, then let the outer
	 * disposable-VM watchdog recover instead of hanging test_progs forever.
	 */
	if (xdev_ext_monotonic_ns(&now_ns))
		goto out;
	deadline_ns = now_ns +
		(uint64_t)XDEV_EXT_TEST_NVME_KILL_REAP_TIMEOUT_MS * XDEV_EXT_NSEC_PER_MSEC;
	for (;;) {
		waited = waitpid(child, status, WNOHANG);
		if (waited == child || (waited < 0 && errno == ECHILD))
			break;
		if (waited < 0 && errno != EINTR)
			break;
		if (xdev_ext_monotonic_ns(&now_ns) || now_ns >= deadline_ns)
			break;
		nanosleep(&pause, NULL);
	}
out:
	if (pidfd >= 0)
		close(pidfd);
	return ret;
}

static int xdev_ext_run_nvme_runtime(const char *runtime, const char *device,
				bool allow_write, int *status)
{
	pid_t child;

	child = fork();
	if (child < 0)
		return -errno;
	if (!child) {
		if (allow_write)
			execl(runtime, runtime, "--device", device,
			      "--allow-file-backed-write", NULL);
		else
			execl(runtime, runtime, "--device", device, NULL);
		_exit(127);
	}
	return xdev_ext_wait_child_bounded(child, XDEV_EXT_TEST_NVME_CHILD_TIMEOUT_MS,
				      status);
}

static int xdev_ext_core_command(struct bpf_testmod_xdev_ext_binding *command)
{
	ssize_t len;
	int err = 0;
	int fd;

	fd = open(BPF_TESTMOD_XDEV_EXT_BINDING_FILE, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	len = pwrite(fd, command, sizeof(*command), 0);
	if (len != sizeof(*command)) {
		err = len < 0 ? -errno : -EIO;
		goto out;
	}
	memset(command, 0, sizeof(*command));
	len = pread(fd, command, sizeof(*command), 0);
	if (len != sizeof(*command))
		err = len < 0 ? -errno : -EIO;
out:
	close(fd);
	return err;
}

static int run_xdev_ext_command(__u32 command, __u32 backend, __u32 flags,
			   __s32 completion_result,
			   struct bpf_testmod_xdev_ext_binding *response)
{
	*response = (struct bpf_testmod_xdev_ext_binding) {
		.command = command,
		.backend = backend,
		.flags = flags,
		.completion_result = completion_result,
		.length = 4096,
	};
	return xdev_ext_core_command(response);
}

static int run_xdev_ext_fake_afxdp_command(__u32 flags, __s32 native_result,
				      __u64 src_offset, __u64 length,
				      struct bpf_testmod_xdev_ext_binding *response)
{
	*response = (struct bpf_testmod_xdev_ext_binding) {
		.command = BPF_TESTMOD_XDEV_EXT_FAKE_AFXDP_SEND,
		.backend = XDEV_EXT_BINDING_BACKEND_AFXDP,
		.flags = flags,
		.completion_result = native_result,
		.src_offset = src_offset,
		.length = length,
	};
	return xdev_ext_core_command(response);
}

static bool xdev_ext_core_seam_available(void)
{
	if (!access(BPF_TESTMOD_XDEV_EXT_BINDING_FILE, R_OK | W_OK))
		return true;
	test__skip();
	return false;
}

static void assert_fallback_plan(const struct bpf_testmod_xdev_ext_binding *response,
				 const char *name)
{
	ASSERT_EQ(response->action, XDEV_EXT_BINDING_ACTION_FALLBACK, name);
	ASSERT_EQ(response->recipe, 0, name);
	ASSERT_EQ(response->next_stage, 0, name);
	ASSERT_EQ(response->profile, 0, name);
}

static bool btf_struct_member_offset(const struct btf *btf,
				     const struct btf_type *type,
				     const char *member_name, __u32 *offset)
{
	const struct btf_member *members;
	int i;

	if (!type || !btf_is_struct(type))
		return false;
	members = btf_members(type);
	for (i = 0; i < btf_vlen(type); i++) {
		const char *name = btf__name_by_offset(btf, members[i].name_off);
		__u32 bit_offset;

		if (!name || strcmp(name, member_name))
			continue;
		bit_offset = btf_member_bit_offset(type, i);
		if (bit_offset % 8)
			return false;
		*offset = bit_offset / 8;
		return true;
	}
	return false;
}

static bool xdev_ext_binding_struct_ops_available(void)
{
	const struct btf_type *ctx_type, *ops_type, *value_type;
	__u32 dispatch_offset = 0, complete_offset = 0, data_offset = 0;
	struct btf *btf;
	long err;
	int ctx_id, ops_id, value_id;

	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err) {
		test__skip();
		return false;
	}
	ops_id = btf__find_by_name_kind(btf, "xdev_ext_binding_ops",
					BTF_KIND_STRUCT);
	value_id = btf__find_by_name_kind(btf,
					  "bpf_struct_ops_xdev_ext_binding_ops",
					  BTF_KIND_STRUCT);
	ctx_id = btf__find_by_name_kind(btf, "xdev_ext_binding_ctx_v2",
					BTF_KIND_STRUCT);
	ops_type = ops_id > 0 ? btf__type_by_id(btf, ops_id) : NULL;
	value_type = value_id > 0 ? btf__type_by_id(btf, value_id) : NULL;
	ctx_type = ctx_id > 0 ? btf__type_by_id(btf, ctx_id) : NULL;
	if (!ops_type || !value_type || !ctx_type) {
		btf__free(btf);
		test__skip();
		return false;
	}

	if (!ASSERT_EQ(ops_type->size, 32, "ops_btf_size") ||
	    !ASSERT_TRUE(btf_struct_member_offset(btf, ops_type, "dispatch",
						  &dispatch_offset),
			 "dispatch_btf_member") ||
	    !ASSERT_TRUE(btf_struct_member_offset(btf, ops_type, "complete",
						  &complete_offset),
			 "complete_btf_member") ||
	    !ASSERT_EQ(dispatch_offset, 16, "dispatch_btf_offset") ||
	    !ASSERT_EQ(complete_offset, 24, "complete_btf_offset") ||
	    !ASSERT_EQ(ctx_type->size, sizeof(struct xdev_ext_binding_ctx_v2),
		       "ctx_btf_size") ||
	    !ASSERT_TRUE(btf_struct_member_offset(btf, value_type, "data",
						  &data_offset),
			 "struct_ops_value_data")) {
		btf__free(btf);
		return false;
	}

	btf__free(btf);
	return true;
}

static void expect_attach_error(struct bpf_map *map, int expected,
				const char *name)
{
	struct bpf_link *link = bpf_map__attach_struct_ops(map);
	long err = libbpf_get_error(link);

	ASSERT_EQ(err, expected, name);
	if (!err)
		bpf_link__destroy(link);
}

static void test_config_boundary_contract(void)
{
	struct bpf_testmod_xdev_ext_binding response;
	bool config_enabled;

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "boundary_reset");
	config_enabled = response.config_enabled;

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET,
				  BPF_TESTMOD_XDEV_EXT_F_BAD_EVENT, 0,
				  &response), "dispatch_bad_event_command");
	ASSERT_EQ(response.return_value, -EINVAL, "dispatch_bad_event");
	ASSERT_FALSE(response.token_live, "dispatch_bad_event_empty");
	assert_fallback_plan(&response, "dispatch_bad_event_plan");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET,
				  BPF_TESTMOD_XDEV_EXT_F_BAD_EVENT, 0,
				  &response), "complete_bad_event_command");
	ASSERT_EQ(response.return_value, -EINVAL, "complete_bad_event");
	ASSERT_FALSE(response.token_live, "complete_bad_event_empty");
	assert_fallback_plan(&response, "complete_bad_event_plan");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET,
				  BPF_TESTMOD_XDEV_EXT_F_NULL_CTX, 0,
				  &response), "dispatch_null_ctx_command");
	ASSERT_EQ(response.return_value, -EINVAL, "dispatch_null_ctx");
	assert_fallback_plan(&response, "dispatch_null_ctx_plan");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET,
				  BPF_TESTMOD_XDEV_EXT_F_NULL_CTX, 0,
				  &response), "complete_null_ctx_command");
	ASSERT_EQ(response.return_value, -EINVAL, "complete_null_ctx");
	ASSERT_FALSE(response.token_live, "complete_null_ctx_empty");
	assert_fallback_plan(&response, "complete_null_ctx_plan");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET,
				  BPF_TESTMOD_XDEV_EXT_F_NULL_TOKEN, 0,
				  &response), "complete_null_token_command");
	ASSERT_EQ(response.return_value, -EINVAL, "complete_null_token");
	assert_fallback_plan(&response, "complete_null_token_plan");

	if (config_enabled)
		return;

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_INJECT_OFF_TOKEN,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "off_inject_token");
	ASSERT_TRUE(response.token_live, "off_injected_token_live");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "off_dispatch_nonempty_command");
	ASSERT_EQ(response.return_value, -EBUSY, "off_dispatch_nonempty");
	ASSERT_TRUE(response.token_live, "off_dispatch_preserves_token");
	assert_fallback_plan(&response, "off_dispatch_nonempty_plan");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET,
				  BPF_TESTMOD_XDEV_EXT_F_NULL_PLAN, 0,
				  &response), "off_complete_null_plan_command");
	ASSERT_EQ(response.return_value, -EINVAL, "off_complete_null_plan");
	ASSERT_FALSE(response.token_live, "off_complete_consumes_token");
}

static void test_no_plugin_then_attach(void)
{
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_success *skel = NULL;
	struct bpf_link *link = NULL;
	long err;

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "no_plugin_reset");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "no_plugin_dispatch_command");
	ASSERT_OK(response.return_value, "no_plugin_dispatch");
	ASSERT_FALSE(response.token_live, "no_plugin_empty_token");
	assert_fallback_plan(&response, "no_plugin_fallback");

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "no_plugin_open"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	err = libbpf_get_error(link);
	if (!ASSERT_OK(err, "no_plugin_attach")) {
		link = NULL;
		goto out;
	}
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "old_completion_command");
	ASSERT_OK(response.return_value, "old_completion_noop");
	ASSERT_FALSE(response.token_live, "old_completion_empty");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "new_plugin_did_not_complete_old_request");
out:
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
}

static void test_all_backends_and_duplicate(void)
{
	static const struct {
		__u32 backend;
		__u32 stage;
		__u32 direction;
		__u32 recipe;
	} expected[] = {
		{ XDEV_EXT_BINDING_BACKEND_SOCKET, XDEV_EXT_BINDING_STAGE_SEND,
		  XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
		  XDEV_EXT_BINDING_RECIPE_SOCKET_SEND },
		{ XDEV_EXT_BINDING_BACKEND_AFXDP, XDEV_EXT_BINDING_STAGE_AFXDP_TX,
		  XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
		  XDEV_EXT_BINDING_RECIPE_AFXDP_COPY },
		{ XDEV_EXT_BINDING_BACKEND_NVME, XDEV_EXT_BINDING_STAGE_NVME_READ,
		  XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
		  XDEV_EXT_BINDING_RECIPE_NVME_PT_READ },
		{ XDEV_EXT_BINDING_BACKEND_IAA, XDEV_EXT_BINDING_STAGE_IAA_COMPRESS,
		  XDEV_EXT_BINDING_DIRECTION_INTERNAL,
		  XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS },
		{ XDEV_EXT_BINDING_BACKEND_GPU, XDEV_EXT_BINDING_STAGE_GPU_COPY,
		  XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
		  XDEV_EXT_BINDING_RECIPE_GPU_COPY },
	};
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_success *skel = NULL;
	struct bpf_link *links[5] = {};
	struct bpf_link *duplicate = NULL;
	struct bpf_map *maps[5];
	long err;
	int i;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "success_open_and_load"))
		return;
	maps[0] = skel->maps.socket_policy;
	maps[1] = skel->maps.afxdp_policy;
	maps[2] = skel->maps.nvme_policy;
	maps[3] = skel->maps.iaa_policy;
	maps[4] = skel->maps.gpu_policy;
	for (i = 0; i < 5; i++) {
		links[i] = bpf_map__attach_struct_ops(maps[i]);
		err = libbpf_get_error(links[i]);
		if (!ASSERT_OK(err, "distinct_backend_attach")) {
			links[i] = NULL;
			goto out;
		}
	}

	/* Keep all five callback plugins live while exercising one valid
	 * dispatch/complete classification for every backend through the shared
	 * phase-kfunc collection. Direction variants are covered by the backend
	 * builders and their production-path suites.
	 */
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_USE_PLAN;
	/* An error completion may only select FALLBACK; USE_PLAN is rejected. */
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;
	for (i = 0; i < (int)ARRAY_SIZE(expected); i++) {
		__u64 dispatch_before =
			skel->bss->dispatch_count[expected[i].backend];
		__u64 complete_before =
			skel->bss->complete_count[expected[i].backend];

		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
					  expected[i].backend, 0, 0, &response),
			  "all_backends_reset");
		ASSERT_FALSE(response.token_live, "all_backends_reset_empty");
		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
					  expected[i].backend, 0, 0, &response),
			  "all_backends_dispatch_command");
		ASSERT_OK(response.return_value, "all_backends_dispatch");
		ASSERT_TRUE(response.token_live, "all_backends_token_pinned");
		ASSERT_EQ(response.action, (__u32)XDEV_EXT_BINDING_ACTION_USE_PLAN,
			  "all_backends_dispatch_action");
		ASSERT_EQ(response.recipe, expected[i].recipe,
			  "all_backends_dispatch_recipe");
		ASSERT_EQ(response.next_stage,
			  (__u32)XDEV_EXT_BINDING_STAGE_COMPLETE,
			  "all_backends_dispatch_next");
		ASSERT_EQ(response.profile, (__u32)XDEV_EXT_BINDING_PROFILE_NATIVE,
			  "all_backends_dispatch_profile");
		ASSERT_EQ(skel->bss->dispatch_count[expected[i].backend],
			  dispatch_before + 1, "all_backends_dispatch_once");
		ASSERT_EQ(skel->bss->observed_dispatch_backend,
			  expected[i].backend, "all_backends_dispatch_backend");
		ASSERT_EQ(skel->bss->observed_dispatch_event,
			  (__u32)XDEV_EXT_BINDING_EVENT_DISPATCH,
			  "all_backends_dispatch_event");
		ASSERT_EQ(skel->bss->observed_dispatch_stage,
			  expected[i].stage, "all_backends_dispatch_stage");
		ASSERT_EQ(skel->bss->observed_dispatch_direction,
			  expected[i].direction,
			  "all_backends_dispatch_direction");
		ASSERT_EQ(skel->bss->observed_recipe, expected[i].recipe,
			  "all_backends_observed_recipe");

		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
					  expected[i].backend, 0, -EIO, &response),
			  "all_backends_complete_command");
		ASSERT_OK(response.return_value, "all_backends_complete");
		assert_fallback_plan(&response, "all_backends_complete_plan");
		ASSERT_FALSE(response.token_live, "all_backends_token_empty");
		ASSERT_EQ(skel->bss->complete_count[expected[i].backend],
			  complete_before + 1, "all_backends_complete_once");
		ASSERT_EQ(skel->bss->observed_complete_backend,
			  expected[i].backend, "all_backends_complete_backend");
		ASSERT_EQ(skel->bss->observed_complete_event,
			  (__u32)XDEV_EXT_BINDING_EVENT_COMPLETE,
			  "all_backends_complete_event");
		ASSERT_EQ(skel->bss->observed_complete_stage,
			  expected[i].stage, "all_backends_complete_stage");
		ASSERT_EQ(skel->bss->observed_complete_direction,
			  expected[i].direction,
			  "all_backends_complete_direction");
		ASSERT_EQ(skel->bss->observed_complete_recipe,
			  expected[i].recipe, "all_backends_complete_recipe");
		ASSERT_EQ(skel->bss->observed_result, -EIO,
			  "all_backends_complete_result");
		ASSERT_EQ(skel->bss->observed_bytes_done, (__u64)0,
			  "all_backends_complete_bytes");
	}

	/* Removing a non-socket slot must not disable the still-live socket. */
	bpf_link__destroy(links[4]);
	links[4] = NULL;
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "five_backend_reset");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "socket_after_gpu_detach_command");
	ASSERT_OK(response.return_value, "socket_after_gpu_detach");
	ASSERT_TRUE(response.token_live, "socket_policy_still_active");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)2, "socket_callback_after_nonzero_detach");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_TOKEN_PUT,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "five_backend_put");
	ASSERT_FALSE(response.token_live, "five_backend_put_empty");

	duplicate = bpf_map__attach_struct_ops(skel->maps.duplicate_socket_policy);
	err = libbpf_get_error(duplicate);
	ASSERT_EQ(err, -EBUSY, "duplicate_backend_rejected");
	if (!err)
		bpf_link__destroy(duplicate);
	duplicate = NULL;

	bpf_link__destroy(links[0]);
	links[0] = NULL;
	duplicate = bpf_map__attach_struct_ops(skel->maps.duplicate_socket_policy);
	err = libbpf_get_error(duplicate);
	if (!ASSERT_OK(err, "socket_reattach_with_others_live"))
		duplicate = NULL;
out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_SOCKET,
			0, 0, &response);
	bpf_link__destroy(duplicate);
	for (i = 0; i < 5; i++)
		bpf_link__destroy(links[i]);
	xdev_ext_binding_success__destroy(skel);
}

static void test_duplicate_generation_and_link_update(void)
{
	struct xdev_ext_binding_success *first = NULL, *second = NULL;
	struct bpf_link *first_link = NULL, *second_link = NULL, *rejected;
	long err;

	first = xdev_ext_binding_success__open_and_load();
	second = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(first, "first_open") ||
	    !ASSERT_OK_PTR(second, "second_open"))
		goto out;
	first_link = bpf_map__attach_struct_ops(first->maps.socket_policy);
	err = libbpf_get_error(first_link);
	if (!ASSERT_OK(err, "first_attach")) {
		first_link = NULL;
		goto out;
	}
	rejected = bpf_map__attach_struct_ops(second->maps.socket_policy);
	err = libbpf_get_error(rejected);
	ASSERT_EQ(err, -EBUSY, "same_backend_busy");
	if (!err)
		bpf_link__destroy(rejected);
	ASSERT_EQ(bpf_link__update_map(first_link, second->maps.socket_policy),
		  -EOPNOTSUPP, "link_update_rejected");
	bpf_link__destroy(first_link);
	first_link = NULL;
	second_link = bpf_map__attach_struct_ops(second->maps.socket_policy);
	err = libbpf_get_error(second_link);
	if (!ASSERT_OK(err, "second_attach_after_detach"))
		second_link = NULL;
out:
	bpf_link__destroy(second_link);
	bpf_link__destroy(first_link);
	xdev_ext_binding_success__destroy(second);
	xdev_ext_binding_success__destroy(first);
}

static void test_registration_validation(void)
{
	struct xdev_ext_binding_invalid_decision *invalid = NULL;
	struct xdev_ext_binding_missing_select *missing = NULL;
	struct xdev_ext_binding_legacy *legacy = NULL;

	invalid = xdev_ext_binding_invalid_decision__open_and_load();
	if (ASSERT_OK_PTR(invalid, "invalid_open")) {
		expect_attach_error(invalid->maps.bad_abi_policy, -EINVAL,
				    "bad_abi");
		expect_attach_error(invalid->maps.bad_backend_policy, -EINVAL,
				    "bad_backend");
		expect_attach_error(invalid->maps.bad_flags_policy, -EINVAL,
				    "bad_flags");
		expect_attach_error(invalid->maps.bad_unknown_flags_policy, -EINVAL,
				    "bad_unknown_flags");
		expect_attach_error(invalid->maps.bad_reserved_policy, -EINVAL,
				    "bad_reserved");
	}
	missing = xdev_ext_binding_missing_select__open_and_load();
	if (ASSERT_OK_PTR(missing, "missing_open")) {
		expect_attach_error(missing->maps.missing_complete_policy, -EINVAL,
				    "missing_complete");
		expect_attach_error(missing->maps.missing_dispatch_policy, -EINVAL,
				    "missing_dispatch");
	}
	legacy = xdev_ext_binding_legacy__open_and_load();
	if (ASSERT_OK_PTR(legacy, "legacy_open"))
		expect_attach_error(legacy->maps.legacy_policy, -EOPNOTSUPP,
				    "legacy_registration");
	xdev_ext_binding_legacy__destroy(legacy);
	xdev_ext_binding_missing_select__destroy(missing);
	xdev_ext_binding_invalid_decision__destroy(invalid);
}

static void test_afxdp_rx_opt_in(void)
{
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_success *skel = NULL;
	struct bpf_link *link = NULL;
	__u64 dispatch_before, complete_before;
	long err;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "afxdp_rx_open"))
		return;

	/* Existing flags=0 AF_XDP plugins must not see the new RX domain. */
	link = bpf_map__attach_struct_ops(skel->maps.afxdp_policy);
	err = libbpf_get_error(link);
	if (!ASSERT_OK(err, "afxdp_rx_legacy_attach")) {
		link = NULL;
		goto out;
	}
	dispatch_before =
		skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP];
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
				  XDEV_EXT_BINDING_BACKEND_AFXDP, 0, 0,
				  &response), "afxdp_rx_legacy_reset");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_AFXDP,
				  BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX, 0,
				  &response), "afxdp_rx_legacy_dispatch_command");
	ASSERT_OK(response.return_value, "afxdp_rx_legacy_fallback");
	assert_fallback_plan(&response, "afxdp_rx_legacy_plan");
	ASSERT_FALSE(response.token_live, "afxdp_rx_legacy_no_token");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  dispatch_before, "afxdp_rx_legacy_not_called");

	/* Even a malformed caller cannot use a TX token to widen the old
	 * plugin's completion input domain to RX.
	 */
	complete_before =
		skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP];
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_AFXDP, 0, 0,
				  &response), "afxdp_rx_legacy_tx_dispatch_command");
	ASSERT_TRUE(response.token_live, "afxdp_rx_legacy_tx_token");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_AFXDP,
				  BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX, 0,
				  &response), "afxdp_rx_legacy_complete_command");
	ASSERT_OK(response.return_value, "afxdp_rx_legacy_complete_fallback");
	ASSERT_FALSE(response.token_live, "afxdp_rx_legacy_complete_consumed");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  complete_before, "afxdp_rx_legacy_complete_not_called");
	bpf_link__destroy(link);
	link = NULL;

	link = bpf_map__attach_struct_ops(skel->maps.afxdp_rx_policy);
	err = libbpf_get_error(link);
	if (!ASSERT_OK(err, "afxdp_rx_opted_attach")) {
		link = NULL;
		goto out;
	}
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;
	dispatch_before =
		skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP];
	complete_before =
		skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP];
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_AFXDP,
				  BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX, 0,
				  &response), "afxdp_rx_opted_dispatch_command");
	ASSERT_OK(response.return_value, "afxdp_rx_opted_dispatch");
	ASSERT_TRUE(response.token_live, "afxdp_rx_opted_token");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  dispatch_before + 1, "afxdp_rx_opted_called_once");
	ASSERT_EQ(skel->bss->observed_dispatch_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_AFXDP_RX,
		  "afxdp_rx_opted_stage");
	ASSERT_EQ(skel->bss->observed_dispatch_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
		  "afxdp_rx_opted_direction");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_RX,
		  "afxdp_rx_opted_recipe");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_AFXDP,
				  BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX, 0,
				  &response), "afxdp_rx_opted_complete_command");
	ASSERT_OK(response.return_value, "afxdp_rx_opted_complete");
	ASSERT_FALSE(response.token_live, "afxdp_rx_opted_token_consumed");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  complete_before + 1, "afxdp_rx_opted_complete_once");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_TERMINAL;
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_AFXDP,
				  BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX, 0,
				  &response), "afxdp_rx_terminal_command");
	ASSERT_OK(response.return_value, "afxdp_rx_terminal_dispatch");
	ASSERT_EQ(response.action, (__u32)XDEV_EXT_BINDING_ACTION_TERMINAL,
		  "afxdp_rx_terminal_action");
	ASSERT_FALSE(response.token_live, "afxdp_rx_terminal_no_token");

out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_AFXDP,
			0, 0, &response);
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
}

#define XDEV_EXT_REFERENCE_POLICY_MAPS	5U

/* One context per stage the testmod seam builds for each backend. */
static const struct xdev_ext_reference_policy_case {
	const char *name;
	__u32 backend;
	__u32 flags;
	__u32 stage;
} xdev_ext_reference_policy_cases[] = {
	{ "socket", XDEV_EXT_BINDING_BACKEND_SOCKET, 0, XDEV_EXT_BINDING_STAGE_SEND },
	{ "afxdp_tx", XDEV_EXT_BINDING_BACKEND_AFXDP, 0, XDEV_EXT_BINDING_STAGE_AFXDP_TX },
	{ "afxdp_rx", XDEV_EXT_BINDING_BACKEND_AFXDP, BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX,
	  XDEV_EXT_BINDING_STAGE_AFXDP_RX },
	{ "nvme", XDEV_EXT_BINDING_BACKEND_NVME, 0, XDEV_EXT_BINDING_STAGE_NVME_READ },
	{ "iaa", XDEV_EXT_BINDING_BACKEND_IAA, 0, XDEV_EXT_BINDING_STAGE_IAA_COMPRESS },
	{ "gpu", XDEV_EXT_BINDING_BACKEND_GPU, 0, XDEV_EXT_BINDING_STAGE_GPU_COPY },
};

static int xdev_ext_reference_policy_attach(struct xdev_ext_reference_policy_wrap *skel,
				       struct bpf_link **links)
{
	struct bpf_map *maps[XDEV_EXT_REFERENCE_POLICY_MAPS] = {
		skel->maps.socket_policy, skel->maps.afxdp_policy,
		skel->maps.nvme_policy, skel->maps.iaa_policy,
		skel->maps.gpu_policy,
	};
	long err;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(maps); i++) {
		links[i] = bpf_map__attach_struct_ops(maps[i]);
		err = libbpf_get_error(links[i]);
		if (err) {
			links[i] = NULL;
			return (int)err;
		}
	}
	return 0;
}

/* The testmod seam reports no bytes, so a served call moves only counts. */
static void
xdev_ext_reference_add_call(struct xdev_ext_reference_policy_backend_stats *row)
{
	row->dispatch_callbacks++;
	row->dispatch_kfunc_ok++;
	row->complete_callbacks++;
	row->complete_kfunc_ok++;
	row->result_ok++;
	row->last_result = 0;
}

static void
xdev_ext_reference_print_row(const char *label, unsigned int index,
			const struct xdev_ext_reference_policy_backend_stats *row)
{
	printf("%s[%u] dispatch_callback=%llu dispatch_kfunc_ok=%llu "
	       "dispatch_kfunc_errors=%llu complete_callback=%llu "
	       "complete_kfunc_ok=%llu complete_kfunc_errors=%llu "
	       "result_ok=%llu result_errors=%llu bytes=%llu last_result=%lld\n",
	       label, index,
	       (unsigned long long)row->dispatch_callbacks,
	       (unsigned long long)row->dispatch_kfunc_ok,
	       (unsigned long long)row->dispatch_kfunc_errors,
	       (unsigned long long)row->complete_callbacks,
	       (unsigned long long)row->complete_kfunc_ok,
	       (unsigned long long)row->complete_kfunc_errors,
	       (unsigned long long)row->result_ok,
	       (unsigned long long)row->result_errors,
	       (unsigned long long)row->bytes_done,
	       (long long)row->last_result);
}

/* Every backend row and every stage row must equal its expected value. */
static void
xdev_ext_reference_expect_stats(const struct xdev_ext_reference_policy_stats *actual,
			   const struct xdev_ext_reference_policy_stats *expected,
			   const char *name)
{
	unsigned int i;

	for (i = 0; i < XDEV_EXT_BINDING_BACKEND_MAX; i++) {
		if (!memcmp(&actual->backend[i], &expected->backend[i],
			    sizeof(actual->backend[i])))
			continue;
		printf("%s: backend row %u differs\n", name, i);
		xdev_ext_reference_print_row("actual backend", i, &actual->backend[i]);
		xdev_ext_reference_print_row("expected backend", i,
					&expected->backend[i]);
	}
	for (i = 0; i < XDEV_EXT_BINDING_STAGE_MAX; i++) {
		if (!memcmp(&actual->stage[i], &expected->stage[i],
			    sizeof(actual->stage[i])))
			continue;
		printf("%s: stage row %u differs\n", name, i);
		xdev_ext_reference_print_row("actual stage", i, &actual->stage[i]);
		xdev_ext_reference_print_row("expected stage", i,
					&expected->stage[i]);
	}
	ASSERT_OK(memcmp(actual, expected, sizeof(*actual)), name);
}

/* One dispatch and one successful completion through the testmod seam. */
static void xdev_ext_reference_dispatch_complete(__u32 backend, __u32 flags,
					    bool served, const char *name)
{
	struct bpf_testmod_xdev_ext_binding response;

	if (!ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, backend, 0, 0,
				       &response), name))
		return;
	ASSERT_FALSE(response.token_live, "reference_reset_empty");
	if (!ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH, backend,
				       flags, 0, &response), name))
		return;
	ASSERT_OK(response.return_value, "reference_dispatch");
	assert_fallback_plan(&response, "reference_dispatch_plan");
	/* A served dispatch pins the policy until its completion. */
	ASSERT_EQ(response.token_live, (__u32)served, "reference_dispatch_token");
	if (!ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE, backend,
				       flags, 0, &response), name))
		return;
	ASSERT_OK(response.return_value, "reference_complete");
	assert_fallback_plan(&response, "reference_complete_plan");
	ASSERT_FALSE(response.token_live, "reference_complete_token_consumed");
}

/*
 * The shipped reference object, all five maps attached: each backend's
 * dispatch and completion move only that backend's row and that stage's row,
 * by exactly one call, and every phase kfunc call is accepted.
 */
static void test_reference_policy_per_backend(void)
{
	struct bpf_link *links[XDEV_EXT_REFERENCE_POLICY_MAPS] = {};
	struct xdev_ext_reference_policy_stats before, expected;
	struct xdev_ext_reference_policy_wrap *skel;
	struct bpf_testmod_xdev_ext_binding response;
	const struct xdev_ext_reference_policy_stats *stats;
	unsigned int i;

	skel = xdev_ext_reference_policy_wrap__open_and_load();
	if (!ASSERT_OK_PTR(skel, "reference_open_and_load"))
		return;
	stats = &skel->bss->xdev_ext_reference_stats;
	memset(&expected, 0, sizeof(expected));
	xdev_ext_reference_expect_stats(stats, &expected, "reference_starts_zero");
	if (!ASSERT_OK(xdev_ext_reference_policy_attach(skel, links),
		       "reference_attach_five"))
		goto out;

	for (i = 0; i < ARRAY_SIZE(xdev_ext_reference_policy_cases); i++) {
		const struct xdev_ext_reference_policy_case *test_case =
			&xdev_ext_reference_policy_cases[i];

		before = *stats;
		xdev_ext_reference_dispatch_complete(test_case->backend,
						test_case->flags, true,
						test_case->name);
		expected = before;
		xdev_ext_reference_add_call(&expected.backend[test_case->backend]);
		xdev_ext_reference_add_call(&expected.stage[test_case->stage]);
		xdev_ext_reference_expect_stats(stats, &expected, test_case->name);
	}

	/* The AF_XDP backend row is exactly its TX row plus its RX row. */
	ASSERT_EQ(stats->backend[XDEV_EXT_BINDING_BACKEND_AFXDP].dispatch_callbacks,
		  (__u64)2, "reference_afxdp_backend_calls");
	ASSERT_EQ(stats->stage[XDEV_EXT_BINDING_STAGE_AFXDP_TX].complete_callbacks,
		  (__u64)1, "reference_afxdp_tx_calls");
	ASSERT_EQ(stats->stage[XDEV_EXT_BINDING_STAGE_AFXDP_RX].complete_callbacks,
		  (__u64)1, "reference_afxdp_rx_calls");
	for (i = 0; i < XDEV_EXT_BINDING_BACKEND_MAX; i++) {
		ASSERT_EQ(stats->backend[i].dispatch_kfunc_errors, (__u64)0,
			  "reference_dispatch_kfunc_errors");
		ASSERT_EQ(stats->backend[i].complete_kfunc_errors, (__u64)0,
			  "reference_complete_kfunc_errors");
	}

out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_SOCKET,
			0, 0, &response);
	for (i = 0; i < ARRAY_SIZE(links); i++)
		bpf_link__destroy(links[i]);
	xdev_ext_reference_policy_wrap__destroy(skel);
}

/*
 * Same object with the AF_XDP map's RX opt-in cleared before load: trusted C
 * must not call it for an RX context, so the RX dispatch and completion fall
 * back natively and no counter moves, while the same map still serves TX.
 */
static void test_reference_policy_rx_opt_in_cleared(void)
{
	struct bpf_link *links[XDEV_EXT_REFERENCE_POLICY_MAPS] = {};
	struct xdev_ext_reference_policy_stats before, expected;
	struct xdev_ext_reference_policy_wrap *skel;
	struct bpf_testmod_xdev_ext_binding response;
	const struct xdev_ext_reference_policy_stats *stats;
	unsigned int i;

	skel = xdev_ext_reference_policy_wrap__open();
	if (!ASSERT_OK_PTR(skel, "reference_gate_open"))
		return;
	ASSERT_EQ(skel->struct_ops.afxdp_policy->flags,
		  (__u32)XDEV_EXT_BINDING_OPS_F_AFXDP_RX, "reference_shipped_rx_opt_in");
	skel->struct_ops.afxdp_policy->flags = 0;
	if (!ASSERT_OK(xdev_ext_reference_policy_wrap__load(skel),
		       "reference_gate_load"))
		goto out;
	stats = &skel->bss->xdev_ext_reference_stats;
	if (!ASSERT_OK(xdev_ext_reference_policy_attach(skel, links),
		       "reference_gate_attach_five"))
		goto out;

	before = *stats;
	xdev_ext_reference_dispatch_complete(XDEV_EXT_BINDING_BACKEND_AFXDP,
					BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX, false,
					"reference_gate_rx");
	xdev_ext_reference_expect_stats(stats, &before, "reference_gate_rx_not_called");

	expected = before;
	xdev_ext_reference_add_call(&expected.backend[XDEV_EXT_BINDING_BACKEND_AFXDP]);
	xdev_ext_reference_add_call(&expected.stage[XDEV_EXT_BINDING_STAGE_AFXDP_TX]);
	xdev_ext_reference_dispatch_complete(XDEV_EXT_BINDING_BACKEND_AFXDP, 0, true,
					"reference_gate_tx");
	xdev_ext_reference_expect_stats(stats, &expected, "reference_gate_tx_served");

out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_AFXDP,
			0, 0, &response);
	for (i = 0; i < ARRAY_SIZE(links); i++)
		bpf_link__destroy(links[i]);
	xdev_ext_reference_policy_wrap__destroy(skel);
}

static void test_dispatch_contract(void)
{
	static const struct {
		__u32 mode;
		int expected;
	} errors[] = {
		{ XDEV_EXT_SUCCESS_RETURN_MISMATCH, -EPROTO },
		{ XDEV_EXT_SUCCESS_ZERO_CALLS, -EPROTO },
		{ XDEV_EXT_SUCCESS_DUPLICATE_CALLS, -EPROTO },
		{ XDEV_EXT_SUCCESS_INVALID_PLAN, -EPERM },
	};
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_success *skel = NULL;
	struct bpf_link *link = NULL;
	long err;
	int i;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "dispatch_open"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	err = libbpf_get_error(link);
	if (!ASSERT_OK(err, "dispatch_attach")) {
		link = NULL;
		goto out;
	}

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "dispatch_reset");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "dispatch_first_command");
	ASSERT_OK(response.return_value, "dispatch_first");
	ASSERT_TRUE(response.token_live, "dispatch_first_token");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "dispatch_nonempty_command");
	ASSERT_EQ(response.return_value, -EBUSY, "dispatch_nonempty");
	ASSERT_TRUE(response.token_live, "dispatch_preserves_old_token");
	assert_fallback_plan(&response, "dispatch_nonempty_plan");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)1, "dispatch_nonempty_skips_callback");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "dispatch_old_complete");
	ASSERT_FALSE(response.token_live, "dispatch_old_complete_consumed");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_USE_PLAN;
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "dispatch_use_plan_command");
	ASSERT_OK(response.return_value, "dispatch_use_plan");
	ASSERT_EQ(response.action, XDEV_EXT_BINDING_ACTION_USE_PLAN,
		  "dispatch_use_plan_action");
	ASSERT_EQ(response.recipe, XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
		  "dispatch_use_plan_recipe");
	ASSERT_EQ(response.next_stage, XDEV_EXT_BINDING_STAGE_COMPLETE,
		  "dispatch_use_plan_next");
	ASSERT_EQ(response.profile, XDEV_EXT_BINDING_PROFILE_NATIVE,
		  "dispatch_use_plan_profile");
	ASSERT_EQ(skel->bss->observed_recipe,
		  XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
		  "dispatch_use_plan_backend_recipe");
	ASSERT_TRUE(response.token_live, "dispatch_use_plan_live");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "dispatch_use_plan_complete_command");
	ASSERT_OK(response.return_value, "dispatch_use_plan_complete");
	ASSERT_FALSE(response.token_live, "dispatch_use_plan_consumed");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_TERMINAL;
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "dispatch_terminal_command");
	ASSERT_OK(response.return_value, "dispatch_terminal");
	ASSERT_EQ(response.action, XDEV_EXT_BINDING_ACTION_TERMINAL,
		  "dispatch_terminal_action");
	ASSERT_FALSE(response.token_live, "dispatch_terminal_empty");

	for (i = 0; i < ARRAY_SIZE(errors); i++) {
		skel->bss->dispatch_mode = errors[i].mode;
		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
					  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
					  &response), "dispatch_error_command");
		ASSERT_EQ(response.return_value, errors[i].expected,
			  "dispatch_error");
		ASSERT_FALSE(response.token_live, "dispatch_error_empty");
		assert_fallback_plan(&response, "dispatch_error_plan");
	}

	/* A verifier-readable scalar copy is not this callback's active argument.
	 * The kfunc must reject it before using any state associated with the
	 * active invocation.
	 */
	skel->bss->fabricated_kfunc_ret = 0;
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FORGED_CTX;
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "forged_ctx_command");
	ASSERT_EQ(response.return_value, -EPROTO, "forged_ctx_dispatch");
	ASSERT_EQ(skel->bss->fabricated_kfunc_ret, -EPROTO,
		  "forged_ctx_kfunc_rejected");
	ASSERT_FALSE(response.token_live, "forged_ctx_no_token");

	/* A rejected foreign pointer still invalidates the active invocation.  The
	 * callback cannot hide that protocol violation by making one valid call
	 * and returning its success, regardless of call order.
	 */
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FOREIGN_THEN_VALID;
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "foreign_then_valid_command");
	ASSERT_EQ(response.return_value, -EPROTO, "foreign_then_valid_rejected");
	ASSERT_EQ(skel->bss->fabricated_kfunc_ret, -EPROTO,
		  "foreign_then_valid_kfunc_rejected");
	ASSERT_FALSE(response.token_live, "foreign_then_valid_no_token");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_VALID_THEN_FOREIGN;
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "valid_then_foreign_command");
	ASSERT_EQ(response.return_value, -EPROTO, "valid_then_foreign_rejected");
	ASSERT_EQ(skel->bss->fabricated_kfunc_ret, -EPROTO,
		  "valid_then_foreign_kfunc_rejected");
	ASSERT_FALSE(response.token_live, "valid_then_foreign_no_token");
out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_SOCKET,
			0, 0, &response);
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
}

static void test_completion_contract(void)
{
	static const struct {
		__u32 mode;
		int expected;
		__u32 expected_action;
	} cases[] = {
		{ XDEV_EXT_SUCCESS_ZERO_CALLS, -EPROTO, XDEV_EXT_BINDING_ACTION_FALLBACK },
		{ XDEV_EXT_SUCCESS_DUPLICATE_CALLS, -EPROTO, XDEV_EXT_BINDING_ACTION_FALLBACK },
		{ XDEV_EXT_SUCCESS_RETURN_MISMATCH, -EPROTO, XDEV_EXT_BINDING_ACTION_FALLBACK },
		{ XDEV_EXT_SUCCESS_INVALID_PLAN, -EPERM, XDEV_EXT_BINDING_ACTION_FALLBACK },
		{ XDEV_EXT_SUCCESS_TERMINAL, 0, XDEV_EXT_BINDING_ACTION_TERMINAL },
		{ XDEV_EXT_SUCCESS_FORGED_CTX, -EPROTO, XDEV_EXT_BINDING_ACTION_FALLBACK },
		{ XDEV_EXT_SUCCESS_FOREIGN_THEN_VALID, -EPROTO,
		  XDEV_EXT_BINDING_ACTION_FALLBACK },
		{ XDEV_EXT_SUCCESS_VALID_THEN_FOREIGN, -EPROTO,
		  XDEV_EXT_BINDING_ACTION_FALLBACK },
	};
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_success *skel = NULL;
	struct bpf_link *link = NULL;
	__u64 before;
	long err;
	int i;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "complete_open"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	err = libbpf_get_error(link);
	if (!ASSERT_OK(err, "complete_attach")) {
		link = NULL;
		goto out;
	}
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "complete_use_plan_reset");
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_USE_PLAN;
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "complete_use_plan_dispatch_command");
	ASSERT_OK(response.return_value, "complete_use_plan_dispatch");
	ASSERT_TRUE(response.token_live, "complete_use_plan_live");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "complete_use_plan_command");
	ASSERT_OK(response.return_value, "complete_use_plan");
	ASSERT_EQ(response.action, XDEV_EXT_BINDING_ACTION_USE_PLAN,
		  "complete_use_plan_action");
	ASSERT_EQ(response.recipe, XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
		  "complete_use_plan_recipe");
	ASSERT_EQ(response.next_stage, XDEV_EXT_BINDING_STAGE_COMPLETE,
		  "complete_use_plan_next");
	ASSERT_EQ(response.profile, XDEV_EXT_BINDING_PROFILE_NATIVE,
		  "complete_use_plan_profile");
	ASSERT_FALSE(response.token_live, "complete_use_plan_consumed");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
					  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
					  &response), "complete_case_reset");
		skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
		skel->bss->complete_mode = cases[i].mode;
		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
					  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
					  &response), "complete_case_dispatch");
		ASSERT_OK(response.return_value, "complete_case_dispatch_ret");
		ASSERT_TRUE(response.token_live, "complete_case_live");
		before = skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
					  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
					  &response), "complete_case_command");
		ASSERT_EQ(response.return_value, cases[i].expected,
			  "complete_case_ret");
		ASSERT_EQ(response.action, cases[i].expected_action,
			  "complete_case_action");
		ASSERT_FALSE(response.token_live, "complete_case_consumed");
		ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
			  before + 1, "complete_case_callback_once");
	}
out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_SOCKET,
			0, 0, &response);
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
}

static void test_token_edges(void)
{
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_success *skel = NULL;
	struct bpf_link *link = NULL;
	__u64 complete_before;
	long err;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "token_open"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	err = libbpf_get_error(link);
	if (!ASSERT_OK(err, "token_attach")) {
		link = NULL;
		goto out;
	}
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "wrong_backend_reset");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "wrong_backend_dispatch");
	complete_before = skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_AFXDP, 0, 0,
				  &response), "wrong_backend_complete_command");
	ASSERT_EQ(response.return_value, -EXDEV, "wrong_backend_complete");
	ASSERT_FALSE(response.token_live, "wrong_backend_consumed");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  complete_before, "wrong_backend_skips_callback");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "null_ctx_dispatch");
	complete_before = skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET,
				  BPF_TESTMOD_XDEV_EXT_F_NULL_CTX, 0,
				  &response), "null_ctx_complete_command");
	ASSERT_EQ(response.return_value, -EINVAL, "null_ctx_complete");
	ASSERT_FALSE(response.token_live, "null_ctx_consumed");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  complete_before, "null_ctx_skips_callback");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "double_complete_dispatch");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "first_complete_command");
	ASSERT_OK(response.return_value, "first_complete");
	complete_before = skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "second_complete_command");
	ASSERT_OK(response.return_value, "second_complete_noop");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  complete_before, "second_complete_skips_callback");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_TOKEN_PUT,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "put_after_complete");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_TOKEN_PUT,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "double_put");
	ASSERT_FALSE(response.token_live, "double_put_empty");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "presubmit_dispatch");
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_TOKEN_PUT,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "presubmit_put");
	complete_before = skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "complete_after_put_command");
	ASSERT_OK(response.return_value, "complete_after_put");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  complete_before, "complete_after_put_skips_callback");

	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "null_plan_dispatch");
	complete_before = skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
				  XDEV_EXT_BINDING_BACKEND_SOCKET,
				  BPF_TESTMOD_XDEV_EXT_F_NULL_PLAN, 0,
				  &response), "null_plan_complete_command");
	ASSERT_EQ(response.return_value, -EINVAL, "null_plan_complete");
	ASSERT_FALSE(response.token_live, "null_plan_consumed");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  complete_before, "null_plan_skips_callback");
out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_SOCKET,
			0, 0, &response);
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
}

struct xdev_ext_command_thread_arg {
	struct bpf_testmod_xdev_ext_binding response;
	int result;
};

struct xdev_ext_detach_thread_arg {
	struct bpf_link *link;
	bool done;
};

static void *xdev_ext_dispatch_thread(void *opaque)
{
	struct xdev_ext_command_thread_arg *arg = opaque;

	arg->result = run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_DISPATCH,
				      XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				      &arg->response);
	return NULL;
}

static void *xdev_ext_detach_thread(void *opaque)
{
	struct xdev_ext_detach_thread_arg *arg = opaque;

	bpf_link__destroy(arg->link);
	__atomic_store_n(&arg->done, true, __ATOMIC_RELEASE);
	return NULL;
}

static bool wait_for_u32(__u32 *value, __u32 expected,
			 unsigned int timeout_ms)
{
	struct timespec pause = { .tv_nsec = 100000 };
	struct timespec now;
	uint64_t deadline;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return false;
	deadline = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec +
		   (uint64_t)timeout_ms * XDEV_EXT_NSEC_PER_MSEC;
	do {
		if (__atomic_load_n(value, __ATOMIC_ACQUIRE) == expected)
			return true;
		nanosleep(&pause, NULL);
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			return false;
	} while ((uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec < deadline);
	return false;
}

static bool wait_for_bool(bool *value, unsigned int timeout_ms)
{
	struct timespec pause = { .tv_nsec = 100000 };
	unsigned int waited = 0;

	while (waited++ < timeout_ms * 10) {
		if (__atomic_load_n(value, __ATOMIC_ACQUIRE))
			return true;
		nanosleep(&pause, NULL);
	}
	return false;
}

static void test_pinned_generation(void)
{
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_success *old = NULL, *replacement = NULL;
	struct xdev_ext_command_thread_arg dispatch = {};
	struct xdev_ext_detach_thread_arg detach = {};
	struct bpf_link *old_link = NULL, *new_link = NULL;
	__u64 replacement_completes;
	pthread_t dispatch_tid, detach_tid;
	bool dispatch_started = false, detach_started = false;
	long err;
	int ret;

	old = xdev_ext_binding_success__open_and_load();
	replacement = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(old, "pinned_old_open") ||
	    !ASSERT_OK_PTR(replacement, "pinned_replacement_open"))
		goto out;
	old_link = bpf_map__attach_struct_ops(old->maps.socket_policy);
	err = libbpf_get_error(old_link);
	if (!ASSERT_OK(err, "pinned_old_attach")) {
		old_link = NULL;
		goto out;
	}
	ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
				  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
				  &response), "pinned_reset");
	old->bss->dispatch_mode = XDEV_EXT_SUCCESS_HOLD_DISPATCH;
	old->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;
	ret = pthread_create(&dispatch_tid, NULL, xdev_ext_dispatch_thread, &dispatch);
	if (!ASSERT_OK(ret, "pinned_dispatch_thread"))
		goto out;
	dispatch_started = true;
	if (!ASSERT_TRUE(wait_for_u32(&old->bss->dispatch_entered, 1, 1000),
			 "pinned_dispatch_entered"))
		goto release;

	detach.link = old_link;
	ret = pthread_create(&detach_tid, NULL, xdev_ext_detach_thread, &detach);
	if (!ASSERT_OK(ret, "pinned_detach_thread"))
		goto release;
	detach_started = true;
	old_link = NULL;
	if (!ASSERT_TRUE(wait_for_bool(&detach.done, 1000),
			 "detach_while_generation_pinned"))
		goto release;

	new_link = bpf_map__attach_struct_ops(replacement->maps.socket_policy);
	err = libbpf_get_error(new_link);
	if (!ASSERT_OK(err, "replacement_attach_before_complete"))
		new_link = NULL;

release:
	__atomic_store_n(&old->bss->dispatch_release, 1, __ATOMIC_RELEASE);
	if (detach_started)
		ASSERT_OK(pthread_join(detach_tid, NULL), "pinned_detach_join");
	if (dispatch_started)
		ASSERT_OK(pthread_join(dispatch_tid, NULL), "pinned_dispatch_join");
	if (dispatch_started) {
		ASSERT_OK(dispatch.result, "pinned_dispatch_command");
		ASSERT_OK(dispatch.response.return_value, "pinned_dispatch_ret");
		ASSERT_TRUE(dispatch.response.token_live, "pinned_token_live");
		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_COMPLETE,
					  XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0,
					  &response), "pinned_complete_command");
		ASSERT_OK(response.return_value, "pinned_complete");
		ASSERT_EQ(old->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
			  (__u64)1, "old_generation_completed");
		replacement_completes =
			replacement->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
		ASSERT_EQ(replacement_completes, (__u64)0,
			  "replacement_did_not_complete_old_request");
	}
out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_SOCKET,
			0, 0, &response);
	bpf_link__destroy(new_link);
	bpf_link__destroy(old_link);
	xdev_ext_binding_success__destroy(replacement);
	xdev_ext_binding_success__destroy(old);
}

static void test_runtime_no_policy(void)
{
	static const char payload[] = "xdev_ext-no-policy";
	struct xdev_ext_runtime_fixture fixture;
	int cleanup_err;
	int ret;

	ret = xdev_ext_runtime_fixture_init(&fixture);
	if (!ASSERT_OK(ret, "no_policy_fixture_init"))
		return;

	memcpy(fixture.umem, payload, sizeof(payload));
	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0], 0,
			      sizeof(payload), 0);
	ASSERT_EQ(ret, (int)sizeof(payload), "no_policy_cqe");
	ASSERT_OK(xdev_ext_receive_payload(fixture.sockets[1], payload,
				      sizeof(payload)),
		  "no_policy_peer_payload");
	ASSERT_EQ(fixture.shared->send_count, (__u64)1,
		  "no_policy_send_count");
	ASSERT_EQ(fixture.shared->send_bytes, sizeof(payload),
		  "no_policy_send_bytes");
	ASSERT_EQ(fixture.shared->send_errors, (__u32)0,
		  "no_policy_send_errors");

	cleanup_err = xdev_ext_runtime_fixture_cleanup(&fixture);
	ASSERT_OK(cleanup_err, "no_policy_fixture_cleanup");
}

static void test_runtime_success_policy(void)
{
	static const char default_payload[] = "xdev_ext-policy-default";
	static const char selected_payload[] = "xdev_ext-policy-explicit-send";
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_runtime_fixture fixture;
	struct bpf_link *link = NULL;
	bool fixture_ready = false;
	long link_err;
	int cleanup_err;
	int ret;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "runtime_success_open_and_load"))
		goto out;

	link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	link_err = libbpf_get_error(link);
	if (!ASSERT_EQ(link_err, 0, "runtime_success_attach")) {
		link = NULL;
		goto out;
	}

	ret = xdev_ext_runtime_fixture_init(&fixture);
	if (!ASSERT_OK(ret, "runtime_success_fixture_init"))
		goto out;
	fixture_ready = true;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	memcpy(fixture.umem, default_payload, sizeof(default_payload));
	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0], 0,
			      sizeof(default_payload), 0);
	ASSERT_EQ(ret, (int)sizeof(default_payload), "default_policy_cqe");
	ASSERT_OK(xdev_ext_receive_payload(fixture.sockets[1], default_payload,
				      sizeof(default_payload)),
		  "default_policy_peer_payload");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)1,
		  "default_policy_invocation_count");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)1,
		  "default_policy_completion_count");
	ASSERT_EQ(skel->bss->observed_length, (__u64)sizeof(default_payload),
		  "default_policy_observed_length");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
		  "default_policy_observed_recipe");
	ASSERT_EQ(skel->bss->observed_dispatch_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_SOCKET,
		  "default_policy_dispatch_backend");
	ASSERT_EQ(skel->bss->observed_dispatch_event,
		  (__u32)XDEV_EXT_BINDING_EVENT_DISPATCH,
		  "default_policy_dispatch_event");
	ASSERT_EQ(skel->bss->observed_dispatch_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_SEND,
		  "default_policy_dispatch_stage");
	ASSERT_EQ(skel->bss->observed_dispatch_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
		  "default_policy_dispatch_direction");
	ASSERT_EQ(skel->bss->observed_complete_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_SOCKET,
		  "default_policy_complete_backend");
	ASSERT_EQ(skel->bss->observed_complete_event,
		  (__u32)XDEV_EXT_BINDING_EVENT_COMPLETE,
		  "default_policy_complete_event");
	ASSERT_EQ(skel->bss->observed_result, 0,
		  "default_policy_normalized_result");
	ASSERT_EQ(skel->bss->observed_bytes_done,
		  (__u64)sizeof(default_payload),
		  "default_policy_bytes_done");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_USE_PLAN;
	memcpy(fixture.umem, selected_payload, sizeof(selected_payload));
	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0], 0,
			      sizeof(selected_payload), 0);
	ASSERT_EQ(ret, (int)sizeof(selected_payload), "selected_policy_cqe");
	ASSERT_OK(xdev_ext_receive_payload(fixture.sockets[1], selected_payload,
				      sizeof(selected_payload)),
		  "selected_policy_peer_payload");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)2,
		  "selected_policy_invocation_count");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)2,
		  "selected_policy_completion_count");
	ASSERT_EQ(skel->bss->observed_length, (__u64)sizeof(selected_payload),
		  "selected_policy_observed_length");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
		  "selected_policy_observed_recipe");
	ASSERT_EQ(skel->bss->observed_result, 0,
		  "selected_policy_normalized_result");
	ASSERT_EQ(skel->bss->observed_bytes_done,
		  (__u64)sizeof(selected_payload),
		  "selected_policy_bytes_done");
	ASSERT_EQ(fixture.shared->send_count, (__u64)2,
		  "success_policy_send_count");
	ASSERT_EQ(fixture.shared->send_bytes,
		  (__u64)(sizeof(default_payload) + sizeof(selected_payload)),
		  "success_policy_send_bytes");
	ASSERT_EQ(fixture.shared->send_errors, (__u32)0,
		  "success_policy_send_errors");

out:
	bpf_link__destroy(link);
	link = NULL;
	if (fixture_ready) {
		cleanup_err = xdev_ext_runtime_fixture_cleanup(&fixture);
		ASSERT_OK(cleanup_err, "runtime_success_fixture_cleanup");
	}
	xdev_ext_binding_success__destroy(skel);
}

static void test_runtime_non_umem_send_encodings(void)
{
	static const char modern_payload[] = "xdev_ext-addr3-send";
	static const char legacy_payload[] = "xdev_ext-legacy-send";
	struct io_uring_unified_shared stats_before;
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_runtime_fixture fixture;
	struct bpf_link *link = NULL;
	__u64 shared_high;
	bool fixture_ready = false;
	long link_err;
	int cleanup_err;
	int cqe_res = -EINPROGRESS;
	int ret;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "send_encoding_open"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	link_err = libbpf_get_error(link);
	if (!ASSERT_OK(link_err, "send_encoding_attach")) {
		link = NULL;
		goto out;
	}
	ret = xdev_ext_runtime_fixture_init(&fixture);
	if (!ASSERT_OK(ret, "send_encoding_fixture"))
		goto out;
	fixture_ready = true;
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;
	shared_high = ((__u64)(uintptr_t)fixture.shared) >> 32;
	if (sizeof(uintptr_t) > sizeof(__u32) &&
	    !ASSERT_NEQ(shared_high, (__u64)0, "send_encoding_addr3_high32"))
		goto out;
	memcpy(&stats_before, fixture.shared, sizeof(stats_before));

	ret = xdev_ext_submit_user_send_bounded(&fixture, fixture.sockets[0],
					   modern_payload,
					   sizeof(modern_payload),
					   UINT64_C(1) << 32, false,
					   &cqe_res);
	if (!ASSERT_OK(ret, "send_encoding_wide_flags_wait"))
		goto out;
	ASSERT_EQ(cqe_res, -EINVAL, "send_encoding_wide_flags_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "send_encoding_wide_flags_no_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "send_encoding_wide_flags_no_complete");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "send_encoding_wide_flags_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "send_encoding_wide_flags_stats_unchanged");

	ret = xdev_ext_submit_user_send_bounded(&fixture, fixture.sockets[0],
					   modern_payload,
					   sizeof(modern_payload),
					   XDEV_EXT_TEST_MSG_SENDPAGE_DECRYPTED,
					   false, &cqe_res);
	if (!ASSERT_OK(ret, "send_encoding_internal_flags_wait"))
		goto out;
	ASSERT_EQ(cqe_res, -EINVAL, "send_encoding_internal_flags_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "send_encoding_internal_flags_no_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "send_encoding_internal_flags_no_complete");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "send_encoding_internal_flags_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "send_encoding_internal_flags_stats_unchanged");

	ret = xdev_ext_submit_user_send_bounded(&fixture, fixture.sockets[0],
					   modern_payload,
					   sizeof(modern_payload),
					   MSG_DONTWAIT, false, &cqe_res);
	if (!ASSERT_OK(ret, "send_encoding_addr3_wait") ||
	    !ASSERT_EQ(cqe_res, (int)sizeof(modern_payload),
		       "send_encoding_addr3_cqe") ||
	    !ASSERT_OK(xdev_ext_receive_payload(fixture.sockets[1], modern_payload,
					  sizeof(modern_payload)),
		       "send_encoding_addr3_payload"))
		goto out;
	ASSERT_EQ(fixture.shared->send_count, (__u64)1,
		  "send_encoding_addr3_stats_count");
	ASSERT_EQ(fixture.shared->send_bytes, (__u64)sizeof(modern_payload),
		  "send_encoding_addr3_stats_bytes");

	ret = xdev_ext_submit_user_send_bounded(&fixture, fixture.sockets[0],
					   legacy_payload,
					   sizeof(legacy_payload),
					   0, true, &cqe_res);
	if (!ASSERT_OK(ret, "send_encoding_legacy_wait") ||
	    !ASSERT_EQ(cqe_res, (int)sizeof(legacy_payload),
		       "send_encoding_legacy_cqe") ||
	    !ASSERT_OK(xdev_ext_receive_payload(fixture.sockets[1], legacy_payload,
					  sizeof(legacy_payload)),
		       "send_encoding_legacy_payload"))
		goto out;
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)2, "send_encoding_dispatch_twice");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)2, "send_encoding_complete_twice");
	ASSERT_EQ(fixture.shared->send_count, (__u64)2,
		  "send_encoding_stats_count");
	ASSERT_EQ(fixture.shared->send_bytes,
		  (__u64)(sizeof(modern_payload) + sizeof(legacy_payload)),
		  "send_encoding_stats_bytes");
	ASSERT_EQ(fixture.shared->send_errors, (__u32)0,
		  "send_encoding_stats_errors");

out:
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
	if (fixture_ready) {
		cleanup_err = xdev_ext_runtime_fixture_cleanup(&fixture);
		ASSERT_OK(cleanup_err, "send_encoding_fixture_cleanup");
	}
}

static void test_runtime_nvme_file_backed(void)
{
	static const char lba_size_path[] =
		"/sys/class/block/nvme0n1/queue/logical_block_size";
	const char *gate = getenv("XDEV_EXT_RUN_NVME_FILE_BACKED");
	const char *device = getenv("XDEV_EXT_NVME_RUNTIME_DEVICE");
	const char *runtime = getenv("XDEV_EXT_NVME_RUNTIME_BIN");
	const char *write_gate = getenv("XDEV_EXT_NVME_RUNTIME_ALLOW_WRITE");
	const char *runtime_name;
	struct xdev_ext_binding_success *skel = NULL;
	struct bpf_link *link = NULL;
	__u64 dispatch_before[XDEV_EXT_BINDING_BACKEND_MAX];
	__u64 complete_before[XDEV_EXT_BINDING_BACKEND_MAX];
	__u64 read_dispatch_before, read_complete_before;
	__u64 write_dispatch_before, write_complete_before;
	bool allow_write = false;
	uint64_t lba_size;
	int status = 0;
	long link_err;
	int ret;
	int i;

	if (!gate) {
		printf("%s:SKIP: set XDEV_EXT_RUN_NVME_FILE_BACKED=1 only inside",
		       __func__);
		printf(" the guarded file-backed KVM\n");
		test__skip();
		return;
	}
	if (!ASSERT_STREQ(gate, "1", "nvme_runtime_gate") ||
	    !ASSERT_OK_PTR(device, "nvme_runtime_device_env") ||
	    !ASSERT_STREQ(device, "/dev/ng0n1", "nvme_runtime_exact_device") ||
	    !ASSERT_OK_PTR(runtime, "nvme_runtime_bin_env") ||
	    !ASSERT_EQ(runtime[0], '/', "nvme_runtime_absolute_bin"))
		return;
	runtime_name = strrchr(runtime, '/');
	if (!ASSERT_STREQ(runtime_name ? runtime_name + 1 : runtime,
			  "nvme_xdev_ext_passthru_runtime",
			  "nvme_runtime_guarded_binary") ||
	    !ASSERT_OK(access(runtime, X_OK), "nvme_runtime_bin_executable"))
		return;
	if (write_gate) {
		if (!ASSERT_STREQ(write_gate, "1", "nvme_runtime_write_gate"))
			return;
		allow_write = true;
	}

	ret = xdev_ext_read_u64_file(lba_size_path, &lba_size);
	if (!ASSERT_OK(ret, "nvme_runtime_lba_size") ||
	    !ASSERT_GE(lba_size, (__u64)512, "nvme_runtime_lba_min"))
		return;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "nvme_runtime_open"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.nvme_policy);
	link_err = libbpf_get_error(link);
	if (!ASSERT_OK(link_err, "nvme_runtime_attach")) {
		link = NULL;
		goto out;
	}
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;
	for (i = 0; i < XDEV_EXT_BINDING_BACKEND_MAX; i++) {
		dispatch_before[i] = skel->bss->dispatch_count[i];
		complete_before[i] = skel->bss->complete_count[i];
	}
	read_dispatch_before = skel->bss->nvme_read_dispatch_count;
	read_complete_before = skel->bss->nvme_read_complete_count;
	write_dispatch_before = skel->bss->nvme_write_dispatch_count;
	write_complete_before = skel->bss->nvme_write_complete_count;

	/* Read-only validation always precedes the separately gated write run. */
	ret = xdev_ext_run_nvme_runtime(runtime, device, false, &status);
	if (!ASSERT_OK(ret, "nvme_runtime_bounded_wait") ||
	    !ASSERT_TRUE(WIFEXITED(status), "nvme_runtime_child_exited") ||
	    !ASSERT_EQ(WEXITSTATUS(status), 0, "nvme_runtime_child_status"))
		goto out;

	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_NVME],
		  dispatch_before[XDEV_EXT_BINDING_BACKEND_NVME] + 3,
		  "nvme_runtime_dispatch_three");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_NVME],
		  complete_before[XDEV_EXT_BINDING_BACKEND_NVME] + 3,
		  "nvme_runtime_complete_three");
	ASSERT_EQ(skel->bss->nvme_read_dispatch_count,
		  read_dispatch_before + 3, "nvme_runtime_read_dispatch_three");
	ASSERT_EQ(skel->bss->nvme_read_complete_count,
		  read_complete_before + 3, "nvme_runtime_read_complete_three");
	ASSERT_EQ(skel->bss->nvme_write_dispatch_count,
		  write_dispatch_before, "nvme_runtime_write_dispatch_zero");
	ASSERT_EQ(skel->bss->nvme_write_complete_count,
		  write_complete_before, "nvme_runtime_write_complete_zero");
	for (i = XDEV_EXT_BINDING_BACKEND_SOCKET;
	     i < XDEV_EXT_BINDING_BACKEND_MAX; i++) {
		if (i == XDEV_EXT_BINDING_BACKEND_NVME)
			continue;
		ASSERT_EQ(skel->bss->dispatch_count[i], dispatch_before[i],
			  "nvme_runtime_other_dispatch_zero");
		ASSERT_EQ(skel->bss->complete_count[i], complete_before[i],
			  "nvme_runtime_other_complete_zero");
	}
	ASSERT_EQ(skel->bss->observed_dispatch_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_NVME,
		  "nvme_runtime_dispatch_backend");
	ASSERT_EQ(skel->bss->observed_dispatch_event,
		  (__u32)XDEV_EXT_BINDING_EVENT_DISPATCH,
		  "nvme_runtime_dispatch_event");
	ASSERT_EQ(skel->bss->observed_dispatch_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_NVME_READ,
		  "nvme_runtime_dispatch_stage");
	ASSERT_EQ(skel->bss->observed_dispatch_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
		  "nvme_runtime_dispatch_direction");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_NVME_PT_READ,
		  "nvme_runtime_dispatch_recipe");
	ASSERT_EQ(skel->bss->observed_length, lba_size,
		  "nvme_runtime_dispatch_length");
	ASSERT_EQ(skel->bss->observed_logical_offset, 8 * lba_size,
		  "nvme_runtime_logical_offset");
	ASSERT_EQ(skel->bss->observed_complete_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_NVME,
		  "nvme_runtime_complete_backend");
	ASSERT_EQ(skel->bss->observed_complete_event,
		  (__u32)XDEV_EXT_BINDING_EVENT_COMPLETE,
		  "nvme_runtime_complete_event");
	ASSERT_EQ(skel->bss->observed_complete_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_NVME_READ,
		  "nvme_runtime_complete_stage");
	ASSERT_EQ(skel->bss->observed_complete_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
		  "nvme_runtime_complete_direction");
	ASSERT_EQ(skel->bss->observed_complete_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_NVME_PT_READ,
		  "nvme_runtime_complete_recipe");
	ASSERT_EQ(skel->bss->observed_complete_logical_offset, 8 * lba_size,
		  "nvme_runtime_complete_logical_offset");
	ASSERT_EQ(skel->bss->observed_result, 0,
		  "nvme_runtime_complete_result");
	ASSERT_EQ(skel->bss->observed_bytes_done, lba_size,
		  "nvme_runtime_complete_bytes");
	ASSERT_EQ(skel->bss->observed_capabilities,
		  (__u32)(XDEV_EXT_BINDING_CAP_ASYNC |
			  XDEV_EXT_BINDING_CAP_FIXED_BUFFER |
			  XDEV_EXT_BINDING_CAP_MULTIBUFFER),
		  "nvme_runtime_fixed_vector_capabilities");

	if (!allow_write)
		goto out;

	for (i = 0; i < XDEV_EXT_BINDING_BACKEND_MAX; i++) {
		dispatch_before[i] = skel->bss->dispatch_count[i];
		complete_before[i] = skel->bss->complete_count[i];
	}
	read_dispatch_before = skel->bss->nvme_read_dispatch_count;
	read_complete_before = skel->bss->nvme_read_complete_count;
	write_dispatch_before = skel->bss->nvme_write_dispatch_count;
	write_complete_before = skel->bss->nvme_write_complete_count;
	status = 0;
	ret = xdev_ext_run_nvme_runtime(runtime, device, true, &status);
	if (!ASSERT_OK(ret, "nvme_write_runtime_bounded_wait") ||
	    !ASSERT_TRUE(WIFEXITED(status), "nvme_write_runtime_child_exited") ||
	    !ASSERT_EQ(WEXITSTATUS(status), 0,
		       "nvme_write_runtime_child_status"))
		goto out;

	/* Three READ variants plus scalar and vector write/restore rounds. */
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_NVME],
		  dispatch_before[XDEV_EXT_BINDING_BACKEND_NVME] + 11,
		  "nvme_write_runtime_dispatch_eleven");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_NVME],
		  complete_before[XDEV_EXT_BINDING_BACKEND_NVME] + 11,
		  "nvme_write_runtime_complete_eleven");
	ASSERT_EQ(skel->bss->nvme_read_dispatch_count,
		  read_dispatch_before + 7,
		  "nvme_write_runtime_read_dispatch_seven");
	ASSERT_EQ(skel->bss->nvme_read_complete_count,
		  read_complete_before + 7,
		  "nvme_write_runtime_read_complete_seven");
	ASSERT_EQ(skel->bss->nvme_write_dispatch_count,
		  write_dispatch_before + 4,
		  "nvme_write_runtime_write_dispatch_four");
	ASSERT_EQ(skel->bss->nvme_write_complete_count,
		  write_complete_before + 4,
		  "nvme_write_runtime_write_complete_four");
	for (i = XDEV_EXT_BINDING_BACKEND_SOCKET;
	     i < XDEV_EXT_BINDING_BACKEND_MAX; i++) {
		if (i == XDEV_EXT_BINDING_BACKEND_NVME)
			continue;
		ASSERT_EQ(skel->bss->dispatch_count[i], dispatch_before[i],
			  "nvme_write_runtime_other_dispatch_zero");
		ASSERT_EQ(skel->bss->complete_count[i], complete_before[i],
			  "nvme_write_runtime_other_complete_zero");
	}
	/* The guarded harness finishes by reading back the restored LBA. */
	ASSERT_EQ(skel->bss->observed_dispatch_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_NVME,
		  "nvme_write_runtime_last_dispatch_backend");
	ASSERT_EQ(skel->bss->observed_dispatch_event,
		  (__u32)XDEV_EXT_BINDING_EVENT_DISPATCH,
		  "nvme_write_runtime_last_dispatch_event");
	ASSERT_EQ(skel->bss->observed_dispatch_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_NVME_READ,
		  "nvme_write_runtime_last_dispatch_read");
	ASSERT_EQ(skel->bss->observed_dispatch_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
		  "nvme_write_runtime_last_dispatch_direction");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_NVME_PT_READ,
		  "nvme_write_runtime_last_dispatch_recipe");
	ASSERT_EQ(skel->bss->observed_logical_offset, 8 * lba_size,
		  "nvme_write_runtime_last_dispatch_offset");
	ASSERT_EQ(skel->bss->observed_length, lba_size,
		  "nvme_write_runtime_last_dispatch_length");
	ASSERT_EQ(skel->bss->observed_complete_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_NVME,
		  "nvme_write_runtime_last_complete_backend");
	ASSERT_EQ(skel->bss->observed_complete_event,
		  (__u32)XDEV_EXT_BINDING_EVENT_COMPLETE,
		  "nvme_write_runtime_last_complete_event");
	ASSERT_EQ(skel->bss->observed_complete_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_NVME_READ,
		  "nvme_write_runtime_last_complete_read");
	ASSERT_EQ(skel->bss->observed_complete_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
		  "nvme_write_runtime_last_complete_direction");
	ASSERT_EQ(skel->bss->observed_complete_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_NVME_PT_READ,
		  "nvme_write_runtime_last_complete_recipe");
	ASSERT_EQ(skel->bss->observed_complete_logical_offset, 8 * lba_size,
		  "nvme_write_runtime_last_complete_offset");
	ASSERT_EQ(skel->bss->observed_result, 0,
		  "nvme_write_runtime_last_complete_result");
	ASSERT_EQ(skel->bss->observed_bytes_done, lba_size,
		  "nvme_write_runtime_last_complete_bytes");
	ASSERT_EQ(skel->bss->observed_capabilities,
		  (__u32)(XDEV_EXT_BINDING_CAP_ASYNC |
			  XDEV_EXT_BINDING_CAP_FIXED_BUFFER |
			  XDEV_EXT_BINDING_CAP_MULTIBUFFER),
		  "nvme_write_runtime_fixed_vector_capabilities");

out:
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
}

static void test_runtime_preflight_before_policy(void)
{
	static const char payload[] = "xdev_ext-policy-preflight";
	struct io_uring_unified_shared stats_before;
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_runtime_fixture fixture;
	struct bpf_link *link = NULL;
	bool fixture_ready = false;
	long link_err;
	int cleanup_err;
	int cqe_res;
	int null_fd = -1;
	int ret;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "preflight_open_and_load"))
		goto out;

	link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	link_err = libbpf_get_error(link);
	if (!ASSERT_EQ(link_err, 0, "preflight_attach")) {
		link = NULL;
		goto out;
	}

	ret = xdev_ext_runtime_fixture_init(&fixture);
	if (!ASSERT_OK(ret, "preflight_fixture_init"))
		goto out;
	fixture_ready = true;
	memcpy(fixture.umem, payload, sizeof(payload));
	memcpy(&stats_before, fixture.shared, sizeof(stats_before));
	ret = xdev_ext_submit_send_bounded(&fixture, fixture.sockets[0], 0,
				      sizeof(payload), UINT64_C(1) << 32,
				      &cqe_res);
	if (!ASSERT_OK(ret, "preflight_wide_flags_wait"))
		goto out;
	ASSERT_EQ(cqe_res, -EINVAL, "preflight_wide_flags_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)0,
		  "preflight_wide_flags_not_invoked");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)0,
		  "preflight_wide_flags_not_completed");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "preflight_wide_flags_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "preflight_wide_flags_stats_unchanged");

	null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (!ASSERT_GE(null_fd, 0, "preflight_open_dev_null"))
		goto out;
	ret = xdev_ext_submit_send(&fixture, null_fd, 0, sizeof(payload), 0);
	ASSERT_EQ(ret, -ENOTSOCK, "preflight_non_socket_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)0,
		  "preflight_non_socket_not_invoked");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)0,
		  "preflight_non_socket_not_completed");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "preflight_non_socket_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "preflight_non_socket_stats_unchanged");

	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0], 0,
			      sizeof(payload), MSG_ZEROCOPY);
	ASSERT_EQ(ret, -EOPNOTSUPP, "preflight_zerocopy_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)0,
		  "preflight_zerocopy_not_invoked");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)0,
		  "preflight_zerocopy_not_completed");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "preflight_zerocopy_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "preflight_zerocopy_stats_unchanged");

	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0],
			      fixture.page_size - 1, 2, 0);
	ASSERT_EQ(ret, -EINVAL, "preflight_range_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)0,
		  "preflight_range_not_invoked");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET], (__u64)0,
		  "preflight_range_not_completed");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "preflight_range_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "preflight_range_stats_unchanged");

out:
	if (null_fd >= 0)
		close(null_fd);
	bpf_link__destroy(link);
	link = NULL;
	if (fixture_ready) {
		cleanup_err = xdev_ext_runtime_fixture_cleanup(&fixture);
		ASSERT_OK(cleanup_err, "preflight_fixture_cleanup");
	}
	xdev_ext_binding_success__destroy(skel);
}

static void test_runtime_invalid_policy(void)
{
	static const char fallback_payload[] = "xdev_ext-v2-after-invalid";
	struct io_uring_unified_shared stats_before;
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_runtime_fixture fixture;
	struct bpf_link *link = NULL;
	bool fixture_ready = false;
	long link_err;
	int cleanup_err;
	int ret;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "runtime_invalid_open"))
		goto out;
	link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	link_err = libbpf_get_error(link);
	if (!ASSERT_OK(link_err, "runtime_invalid_attach")) {
		link = NULL;
		goto out;
	}
	ret = xdev_ext_runtime_fixture_init(&fixture);
	if (!ASSERT_OK(ret, "runtime_invalid_fixture_init"))
		goto out;
	fixture_ready = true;
	memset(fixture.umem, 0, fixture.page_size);
	memcpy(&stats_before, fixture.shared, sizeof(stats_before));

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_TERMINAL;
	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0], 0, 1, 0);
	ASSERT_EQ(ret, -EPERM, "runtime_terminal_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)1, "runtime_terminal_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "runtime_terminal_no_complete");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "runtime_terminal_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "runtime_terminal_stats_unchanged");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_INVALID_PLAN;
	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0], 0, 1, 0);
	ASSERT_EQ(ret, -EPERM, "runtime_invalid_plan_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)2, "runtime_invalid_plan_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "runtime_invalid_plan_no_complete");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "runtime_invalid_plan_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "runtime_invalid_plan_stats_unchanged");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_RETURN_MISMATCH;
	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0], 0, 1, 0);
	ASSERT_EQ(ret, -EPROTO, "runtime_protocol_error_cqe");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)3, "runtime_protocol_error_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "runtime_protocol_error_no_complete");
	ASSERT_OK(xdev_ext_expect_no_payload(fixture.sockets[1]),
		  "runtime_protocol_error_no_payload");
	ASSERT_EQ(memcmp(&stats_before, fixture.shared, sizeof(stats_before)), 0,
		  "runtime_protocol_error_stats_unchanged");

	bpf_link__destroy(link);
	link = NULL;
	memcpy(fixture.umem, fallback_payload, sizeof(fallback_payload));
	ret = xdev_ext_submit_send(&fixture, fixture.sockets[0], 0,
			      sizeof(fallback_payload), 0);
	ASSERT_EQ(ret, (int)sizeof(fallback_payload),
		  "post_invalid_fallback_cqe");
	ASSERT_OK(xdev_ext_receive_payload(fixture.sockets[1], fallback_payload,
				      sizeof(fallback_payload)),
		  "post_invalid_fallback_payload");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)3, "post_invalid_no_dispatch");
	ASSERT_EQ(fixture.shared->send_count, (__u64)1,
		  "post_invalid_send_count");

out:
	bpf_link__destroy(link);
	if (fixture_ready) {
		cleanup_err = xdev_ext_runtime_fixture_cleanup(&fixture);
		ASSERT_OK(cleanup_err, "runtime_invalid_fixture_cleanup");
	}
	xdev_ext_binding_success__destroy(skel);
}

struct xdev_ext_xsk_fixture {
	struct xsk_ring_prod fill;
	struct xsk_ring_cons completion;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem *umem;
	struct xsk_socket *xsk;
	struct xdev_ext_binding_xsk_rx *rx_redirect;
	void *area;
	size_t area_size;
	char tx_name[IFNAMSIZ];
	char peer_name[IFNAMSIZ];
	int packet_fd;
	unsigned int peer_ifindex;
	unsigned int xdp_ifindex;
	__u32 xdp_flags;
	bool xdp_attached;
	bool veth_created;
};

/*
 * BusyBox shells run their own "ip" applet ahead of PATH, and that applet
 * ignores "peer name" when it creates a veth pair.  XDEV_EXT_IP_BIN may name the
 * iproute2 binary instead; it reaches system(), so only a plain path is used.
 */
static bool xdev_ext_ip_bin_valid(const char *path)
{
	if (!path || !*path)
		return false;
	for (; *path; path++) {
		if (!isalnum((unsigned char)*path) && *path != '/' &&
		    *path != '_' && *path != '-' && *path != '.')
			return false;
	}
	return true;
}

static int xdev_ext_run_ip(const char *format, const char *first,
		      const char *second)
{
	const char *ip_bin = getenv("XDEV_EXT_IP_BIN");
	char arguments[224];
	char command[256];
	int length;
	int status;

	if (!ip_bin || !*ip_bin)
		ip_bin = "ip";
	else if (!xdev_ext_ip_bin_valid(ip_bin))
		return -EINVAL;
	length = snprintf(arguments, sizeof(arguments), format, first, second);
	if (length < 0 || (size_t)length >= sizeof(arguments))
		return -E2BIG;
	length = snprintf(command, sizeof(command), "%s %s", ip_bin, arguments);
	if (length < 0 || (size_t)length >= sizeof(command))
		return -E2BIG;
	status = system(command);
	if (status < 0)
		return -errno;
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return -EIO;
	return 0;
}

static void xdev_ext_xsk_fixture_cleanup(struct xdev_ext_xsk_fixture *fixture)
{
	if (fixture->xdp_attached) {
		bpf_xdp_detach(fixture->xdp_ifindex, fixture->xdp_flags, NULL);
		fixture->xdp_attached = false;
	}
	if (fixture->xsk) {
		xsk_socket__delete(fixture->xsk);
		fixture->xsk = NULL;
	}
	if (fixture->rx_redirect) {
		xdev_ext_binding_xsk_rx__destroy(fixture->rx_redirect);
		fixture->rx_redirect = NULL;
	}
	if (fixture->umem) {
		xsk_umem__delete(fixture->umem);
		fixture->umem = NULL;
	}
	if (fixture->area && fixture->area != MAP_FAILED) {
		munmap(fixture->area, fixture->area_size);
		fixture->area = NULL;
	}
	if (fixture->packet_fd >= 0) {
		close(fixture->packet_fd);
		fixture->packet_fd = -1;
	}
	if (fixture->veth_created) {
		xdev_ext_run_ip("link del dev %s", fixture->tx_name, NULL);
		fixture->veth_created = false;
	}
}

static int xdev_ext_xsk_fixture_init_mode(struct xdev_ext_xsk_fixture *fixture,
				     bool enable_rx, __u32 rx_xdp_flags)
{
	const struct xsk_umem_config umem_config = {
		.fill_size = 64,
		.comp_size = 64,
		.frame_size = XDEV_EXT_TEST_XSK_FRAME_SIZE,
	};
	const struct xsk_socket_config socket_config = {
		.rx_size = 64,
		.tx_size = 64,
		.bind_flags = XDP_COPY,
	};
	struct sockaddr_ll address = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
	};
	unsigned int suffix = (unsigned int)getpid() % 100000U;
	unsigned int tx_ifindex, peer_ifindex;
	int ret;

	memset(fixture, 0, sizeof(*fixture));
	fixture->packet_fd = -1;
	fixture->area_size = XDEV_EXT_TEST_XSK_FRAMES * XDEV_EXT_TEST_XSK_FRAME_SIZE;
	snprintf(fixture->tx_name, sizeof(fixture->tx_name), "ubt%05u", suffix);
	snprintf(fixture->peer_name, sizeof(fixture->peer_name), "ubp%05u", suffix);

	ret = xdev_ext_run_ip("link add %s type veth peer name %s",
			 fixture->tx_name, fixture->peer_name);
	if (ret)
		goto err;
	fixture->veth_created = true;
	ret = xdev_ext_run_ip("link set dev %s up", fixture->tx_name, NULL);
	if (ret)
		goto err;
	ret = xdev_ext_run_ip("link set dev %s up", fixture->peer_name, NULL);
	if (ret)
		goto err;

	tx_ifindex = if_nametoindex(fixture->tx_name);
	peer_ifindex = if_nametoindex(fixture->peer_name);
	if (!tx_ifindex || !peer_ifindex) {
		ret = -ENODEV;
		goto err;
	}
	fixture->peer_ifindex = peer_ifindex;

	fixture->packet_fd = socket(AF_PACKET,
				    SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
				    htons(ETH_P_ALL));
	if (fixture->packet_fd < 0) {
		ret = -errno;
		goto err;
	}
	address.sll_ifindex = peer_ifindex;
	if (bind(fixture->packet_fd, (struct sockaddr *)&address,
		 sizeof(address))) {
		ret = -errno;
		goto err;
	}

	fixture->area = mmap(NULL, fixture->area_size, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (fixture->area == MAP_FAILED) {
		ret = -errno;
		goto err;
	}
	ret = xsk_umem__create(&fixture->umem, fixture->area,
			       fixture->area_size, &fixture->fill,
			       &fixture->completion, &umem_config);
	if (ret)
		goto err;
	ret = xsk_socket__create(&fixture->xsk, tx_ifindex, 0,
				 fixture->umem,
				 enable_rx ? &fixture->rx : NULL,
				 &fixture->tx,
				 &socket_config);
	if (ret)
		goto err;
	if (!enable_rx)
		return 0;

	/* AF_XDP publishes an RX descriptor only for a frame that an XDP
	 * program redirects into an XSKMAP entry, so the RX fixture installs
	 * its own program for the test EtherTypes on the socket's queue.
	 */
	fixture->rx_redirect = xdev_ext_binding_xsk_rx__open();
	if (!fixture->rx_redirect) {
		ret = errno ? -errno : -ENOMEM;
		goto err;
	}
	fixture->rx_redirect->rodata->xdev_ext_rx_ethertype_first =
		XDEV_EXT_TEST_RX_ETHERTYPE_FIRST;
	fixture->rx_redirect->rodata->xdev_ext_rx_ethertype_last =
		XDEV_EXT_TEST_RX_ETHERTYPE_LAST;
	ret = xdev_ext_binding_xsk_rx__load(fixture->rx_redirect);
	if (ret)
		goto err;
	ret = xsk_update_xskmap(fixture->rx_redirect->maps.xdev_ext_rx_xsks,
				fixture->xsk, 0);
	if (ret)
		goto err;
	ret = bpf_xdp_attach(tx_ifindex,
			     bpf_program__fd(fixture->rx_redirect->progs.xdev_ext_xsk_rx_redirect),
			     rx_xdp_flags | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
	if (ret)
		goto err;
	fixture->xdp_ifindex = tx_ifindex;
	fixture->xdp_flags = rx_xdp_flags;
	fixture->xdp_attached = true;
	return 0;

err:
	xdev_ext_xsk_fixture_cleanup(fixture);
	return ret;
}

static int xdev_ext_xsk_fixture_init(struct xdev_ext_xsk_fixture *fixture)
{
	return xdev_ext_xsk_fixture_init_mode(fixture, false, 0);
}

static int xdev_ext_xsk_rx_fixture_init(struct xdev_ext_xsk_fixture *fixture,
				   __u32 xdp_flags)
{
	return xdev_ext_xsk_fixture_init_mode(fixture, true, xdp_flags);
}

static int xdev_ext_packet_match_bounded(int fd, const void *expected,
				    size_t expected_length, bool expect_match,
				    unsigned int timeout_ms)
{
	unsigned char packet[256];
	uint64_t deadline_ns, now_ns;
	struct pollfd pollfd = {
		.fd = fd,
		.events = POLLIN,
	};
	ssize_t received;
	int timeout;
	int ret;

	if (expected_length > sizeof(packet))
		return -E2BIG;
	ret = xdev_ext_monotonic_ns(&now_ns);
	if (ret)
		return ret;
	deadline_ns = now_ns + (uint64_t)timeout_ms * XDEV_EXT_NSEC_PER_MSEC;
	for (;;) {
		ret = xdev_ext_monotonic_ns(&now_ns);
		if (ret)
			return ret;
		if (now_ns >= deadline_ns)
			return expect_match ? -ETIMEDOUT : 0;
		timeout = (int)((deadline_ns - now_ns + XDEV_EXT_NSEC_PER_MSEC - 1) /
				XDEV_EXT_NSEC_PER_MSEC);
		ret = poll(&pollfd, 1, timeout);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!ret)
			return expect_match ? -ETIMEDOUT : 0;
		received = recv(fd, packet, sizeof(packet), MSG_DONTWAIT);
		if (received < 0) {
			if (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				continue;
			return -errno;
		}
		if ((size_t)received == expected_length &&
		    !memcmp(packet, expected, expected_length))
			return expect_match ? 0 : -EEXIST;
	}
}

static int xdev_ext_receive_packet_bounded(int fd, const void *expected,
				      size_t expected_length)
{
	return xdev_ext_packet_match_bounded(fd, expected, expected_length, true,
					XDEV_EXT_TEST_PACKET_TIMEOUT_MS);
}

static int xdev_ext_expect_no_matching_packet_bounded(int fd,
						 const void *unexpected,
						 size_t unexpected_length)
{
	return xdev_ext_packet_match_bounded(fd, unexpected, unexpected_length, false,
					XDEV_EXT_TEST_NO_PACKET_TIMEOUT_MS);
}

static int xdev_ext_xsk_fill_rx(struct xdev_ext_xsk_fixture *fixture, __u64 addr)
{
	__u32 index;
	int ret;

	if (!fixture || !fixture->xsk || addr >= fixture->area_size ||
	    addr % XDEV_EXT_TEST_XSK_FRAME_SIZE)
		return -EINVAL;
	ret = xsk_ring_prod__reserve(&fixture->fill, 1, &index);
	if (ret != 1)
		return ret < 0 ? ret : -ENOSPC;
	*xsk_ring_prod__fill_addr(&fixture->fill, index) = addr;
	xsk_ring_prod__submit(&fixture->fill, 1);
	return 0;
}

static int xdev_ext_xsk_peer_inject(struct xdev_ext_xsk_fixture *fixture,
			       const void *packet, size_t length)
{
	struct sockaddr_ll address = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = fixture ? fixture->peer_ifindex : 0,
		.sll_halen = ETH_ALEN,
	};
	const struct ethhdr *ethernet = packet;
	ssize_t sent;

	if (!fixture || fixture->packet_fd < 0 || !packet ||
	    length < sizeof(*ethernet) || !fixture->peer_ifindex)
		return -EINVAL;
	memcpy(address.sll_addr, ethernet->h_dest, ETH_ALEN);
	sent = sendto(fixture->packet_fd, packet, length, 0,
		      (struct sockaddr *)&address, sizeof(address));
	if (sent < 0)
		return -errno;
	return (size_t)sent == length ? 0 : -EIO;
}

static int xdev_ext_xsk_receive_bounded(struct xdev_ext_xsk_fixture *fixture,
				   const void *expected,
				   size_t expected_length)
{
	uint64_t deadline_ns, now_ns;
	struct pollfd pfd;
	int ret;

	if (!fixture || !fixture->xsk || !expected || !expected_length)
		return -EINVAL;
	ret = xdev_ext_monotonic_ns(&now_ns);
	if (ret)
		return ret;
	deadline_ns = now_ns +
		(uint64_t)XDEV_EXT_TEST_PACKET_TIMEOUT_MS * XDEV_EXT_NSEC_PER_MSEC;
	pfd = (struct pollfd) {
		.fd = xsk_socket__fd(fixture->xsk),
		.events = POLLIN,
	};

	for (;;) {
		__u32 index;

		if (xsk_ring_cons__peek(&fixture->rx, 1, &index) == 1) {
			const struct xdp_desc *desc =
				xsk_ring_cons__rx_desc(&fixture->rx, index);
			/* The aligned-mode UMEM reports the packet data inside
			 * its chunk; the fill ring takes the chunk base.
			 */
			__u64 original = desc->addr &
					 ~((__u64)XDEV_EXT_TEST_XSK_FRAME_SIZE - 1);
			__u64 data_addr = xsk_umem__add_offset_to_addr(desc->addr);
			int result = 0;

			if (desc->options || desc->len != expected_length ||
			    data_addr >= fixture->area_size ||
			    expected_length > fixture->area_size - data_addr ||
			    memcmp((unsigned char *)fixture->area + data_addr,
				   expected, expected_length))
				result = -EBADMSG;
			xsk_ring_cons__release(&fixture->rx, 1);
			ret = xdev_ext_xsk_fill_rx(fixture, original);
			return result ? result : ret;
		}

		ret = xdev_ext_monotonic_ns(&now_ns);
		if (ret)
			return ret;
		if (now_ns >= deadline_ns)
			return -ETIMEDOUT;
		ret = poll(&pfd, 1, 1);
		if (ret < 0 && errno != EINTR)
			return -errno;
	}
}

static int xdev_ext_xsk_expect_no_rx_bounded(struct xdev_ext_xsk_fixture *fixture,
					unsigned int timeout_ms)
{
	uint64_t deadline_ns, now_ns;
	struct timespec pause = { .tv_nsec = XDEV_EXT_NSEC_PER_MSEC };
	int ret;

	if (!fixture || !fixture->xsk)
		return -EINVAL;
	ret = xdev_ext_monotonic_ns(&now_ns);
	if (ret)
		return ret;
	deadline_ns = now_ns + (uint64_t)timeout_ms * XDEV_EXT_NSEC_PER_MSEC;
	for (;;) {
		__u32 index;

		if (xsk_ring_cons__peek(&fixture->rx, 1, &index) != 0)
			return -EEXIST;
		ret = xdev_ext_monotonic_ns(&now_ns);
		if (ret)
			return ret;
		if (now_ns >= deadline_ns)
			return 0;
		if (nanosleep(&pause, NULL) && errno != EINTR)
			return -errno;
	}
}

static int xdev_ext_wait_count_at_least(const __u64 *count, __u64 target,
				   unsigned int timeout_ms)
{
	uint64_t deadline_ns, now_ns;
	struct timespec pause = { .tv_nsec = XDEV_EXT_NSEC_PER_MSEC };
	int ret;

	if (!count)
		return -EINVAL;
	ret = xdev_ext_monotonic_ns(&now_ns);
	if (ret)
		return ret;
	deadline_ns = now_ns + (uint64_t)timeout_ms * XDEV_EXT_NSEC_PER_MSEC;
	for (;;) {
		if (__atomic_load_n(count, __ATOMIC_ACQUIRE) >= target)
			return 0;
		ret = xdev_ext_monotonic_ns(&now_ns);
		if (ret)
			return ret;
		if (now_ns >= deadline_ns)
			return -ETIMEDOUT;
		if (nanosleep(&pause, NULL) && errno != EINTR)
			return -errno;
	}
}

static void test_runtime_bound_afxdp_copy(void)
{
	unsigned char expected[XDEV_EXT_TEST_AFXDP_FRAME_LEN] = {};
	const char *gate = getenv("XDEV_EXT_RUN_AFXDP_VETH");
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_runtime_fixture ring_fixture;
	struct xdev_ext_xsk_fixture xsk_fixture;
	struct bpf_link *afxdp_link = NULL;
	struct bpf_link *socket_link = NULL;
	struct ethhdr *ethernet = (struct ethhdr *)expected;
	bool ring_ready = false;
	long link_err;
	int cleanup_err;
	int cqe_res;
	int ret;

	if (!gate) {
		printf("%s:SKIP: set XDEV_EXT_RUN_AFXDP_VETH=1 in an isolated root netns/KVM\n",
		       __func__);
		test__skip();
		return;
	}
	if (!ASSERT_STREQ(gate, "1", "bound_afxdp_gate"))
		return;

	ret = xdev_ext_xsk_fixture_init(&xsk_fixture);
	if (!ASSERT_OK(ret, "bound_afxdp_xsk_fixture"))
		return;
	ret = xdev_ext_runtime_fixture_init(&ring_fixture);
	if (!ASSERT_OK(ret, "bound_afxdp_ring_fixture"))
		goto out;
	ring_ready = true;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bound_afxdp_open"))
		goto out;
	socket_link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	link_err = libbpf_get_error(socket_link);
	if (!ASSERT_OK(link_err, "bound_afxdp_socket_attach")) {
		socket_link = NULL;
		goto out;
	}
	afxdp_link = bpf_map__attach_struct_ops(skel->maps.afxdp_policy);
	link_err = libbpf_get_error(afxdp_link);
	if (!ASSERT_OK(link_err, "bound_afxdp_policy_attach")) {
		afxdp_link = NULL;
		goto out;
	}

	memset(ethernet->h_dest, 0x22, ETH_ALEN);
	memset(ethernet->h_source, 0x11, ETH_ALEN);
	ethernet->h_dest[0] = 0x02;
	ethernet->h_source[0] = 0x02;
	ethernet->h_proto = htons(0x88b5);
	for (ret = sizeof(*ethernet); ret < (int)sizeof(expected); ret++)
		expected[ret] = (unsigned char)(ret ^ 0xa5);
	memcpy(xsk_fixture.area, expected, sizeof(expected));
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;

	ret = xdev_ext_submit_afxdp_copy_bounded(&ring_fixture,
					    xsk_socket__fd(xsk_fixture.xsk),
					    0, sizeof(expected), 1, &cqe_res);
	if (!ASSERT_OK(ret, "bound_afxdp_flags_wait"))
		goto out;
	ASSERT_EQ(cqe_res, -EOPNOTSUPP, "bound_afxdp_flags_cqe");
	ret = xdev_ext_expect_no_matching_packet_bounded(xsk_fixture.packet_fd,
						    expected, sizeof(expected));
	ASSERT_OK(ret, "bound_afxdp_flags_no_peer_frame");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)0, "bound_afxdp_flags_no_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)0, "bound_afxdp_flags_no_complete");
	ASSERT_EQ(ring_fixture.shared->send_count, (__u64)0,
		  "bound_afxdp_flags_no_send_count");
	ASSERT_EQ(ring_fixture.shared->send_errors, (__u32)0,
		  "bound_afxdp_flags_no_send_error");

	ret = xdev_ext_submit_afxdp_copy_bounded(&ring_fixture,
					    xsk_socket__fd(xsk_fixture.xsk),
					    0, sizeof(expected), 0, &cqe_res);
	if (!ASSERT_OK(ret, "bound_afxdp_wait"))
		goto out;
	ASSERT_EQ(cqe_res, (int)sizeof(expected), "bound_afxdp_native_cqe");
	ASSERT_OK(xdev_ext_receive_packet_bounded(xsk_fixture.packet_fd, expected,
					     sizeof(expected)),
		  "bound_afxdp_peer_frame");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)1, "bound_afxdp_dispatch_once");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)1, "bound_afxdp_complete_once");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "bound_afxdp_socket_dispatch_zero");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "bound_afxdp_socket_complete_zero");
	ASSERT_EQ(skel->bss->observed_dispatch_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_AFXDP,
		  "bound_afxdp_dispatch_backend");
	ASSERT_EQ(skel->bss->observed_dispatch_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_AFXDP_TX,
		  "bound_afxdp_dispatch_stage");
	ASSERT_EQ(skel->bss->observed_dispatch_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
		  "bound_afxdp_dispatch_direction");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_COPY,
		  "bound_afxdp_dispatch_recipe");
	ASSERT_EQ(skel->bss->observed_length, (__u64)sizeof(expected),
		  "bound_afxdp_dispatch_length");
	ASSERT_EQ(skel->bss->observed_complete_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_AFXDP,
		  "bound_afxdp_complete_backend");
	ASSERT_EQ(skel->bss->observed_complete_event,
		  (__u32)XDEV_EXT_BINDING_EVENT_COMPLETE,
		  "bound_afxdp_complete_event");
	ASSERT_EQ(skel->bss->observed_complete_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_AFXDP_TX,
		  "bound_afxdp_complete_stage");
	ASSERT_EQ(skel->bss->observed_complete_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
		  "bound_afxdp_complete_direction");
	ASSERT_EQ(skel->bss->observed_complete_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_COPY,
		  "bound_afxdp_complete_recipe");
	ASSERT_EQ(skel->bss->observed_result, 0,
		  "bound_afxdp_complete_result");
	ASSERT_EQ(skel->bss->observed_bytes_done, (__u64)sizeof(expected),
		  "bound_afxdp_complete_bytes");
	ASSERT_EQ(ring_fixture.shared->send_count, (__u64)1,
		  "bound_afxdp_send_count");
	ASSERT_EQ(ring_fixture.shared->send_bytes, (__u64)sizeof(expected),
		  "bound_afxdp_send_bytes");
	ASSERT_EQ(ring_fixture.shared->send_errors, (__u32)0,
		  "bound_afxdp_send_errors");

out:
	bpf_link__destroy(afxdp_link);
	bpf_link__destroy(socket_link);
	xdev_ext_binding_success__destroy(skel);
	if (ring_ready) {
		cleanup_err = xdev_ext_runtime_fixture_cleanup(&ring_fixture);
		ASSERT_OK(cleanup_err, "bound_afxdp_ring_cleanup");
	}
	xdev_ext_xsk_fixture_cleanup(&xsk_fixture);
}

static int xdev_ext_xsk_tx_ring_submit(struct xdev_ext_xsk_fixture *fixture, __u64 addr,
				  __u32 length)
{
	struct xdp_desc *desc;
	__u32 index;
	int ret;

	ret = xsk_ring_prod__reserve(&fixture->tx, 1, &index);
	if (ret != 1)
		return ret < 0 ? ret : -ENOSPC;
	desc = xsk_ring_prod__tx_desc(&fixture->tx, index);
	desc->addr = addr;
	desc->len = length;
	desc->options = 0;
	xsk_ring_prod__submit(&fixture->tx, 1);

	ret = sendto(xsk_socket__fd(fixture->xsk), NULL, 0, MSG_DONTWAIT,
		     NULL, 0);
	return ret < 0 ? -errno : ret;
}

static int xdev_ext_xsk_wait_completion(struct xdev_ext_xsk_fixture *fixture,
				   __u64 expected_addr)
{
	const struct timespec pause = { .tv_nsec = XDEV_EXT_NSEC_PER_MSEC };
	uint64_t deadline_ns, now_ns;
	__u64 completed_addr;
	__u32 index;
	int ret;

	ret = xdev_ext_monotonic_ns(&now_ns);
	if (ret)
		return ret;
	deadline_ns = now_ns + XDEV_EXT_TEST_PACKET_TIMEOUT_MS * XDEV_EXT_NSEC_PER_MSEC;
	for (;;) {
		if (xsk_ring_cons__peek(&fixture->completion, 1, &index) == 1) {
			completed_addr =
				*xsk_ring_cons__comp_addr(&fixture->completion, index);
			xsk_ring_cons__release(&fixture->completion, 1);
			return completed_addr == expected_addr ? 0 : -EUCLEAN;
		}
		ret = xdev_ext_monotonic_ns(&now_ns);
		if (ret)
			return ret;
		if (now_ns >= deadline_ns)
			return -ETIMEDOUT;
		nanosleep(&pause, NULL);
	}
}

static void test_runtime_afxdp_native_tx_ring_copy(void)
{
	unsigned char terminal_packet[XDEV_EXT_TEST_AFXDP_FRAME_LEN] = {};
	unsigned char use_plan_packet[XDEV_EXT_TEST_AFXDP_FRAME_LEN] = {};
	unsigned char native_packet[XDEV_EXT_TEST_AFXDP_FRAME_LEN] = {};
	const char *gate = getenv("XDEV_EXT_RUN_AFXDP_VETH");
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_xsk_fixture fixture;
	struct bpf_link *link = NULL;
	struct ethhdr *ethernet;
	const __u64 use_plan_addr = XDEV_EXT_TEST_XSK_FRAME_SIZE;
	const __u64 terminal_addr = 2 * XDEV_EXT_TEST_XSK_FRAME_SIZE;
	long link_err;
	int ret;

	if (!gate) {
		printf("%s:SKIP: set XDEV_EXT_RUN_AFXDP_VETH=1 in an isolated root netns/KVM\n",
		       __func__);
		test__skip();
		return;
	}
	if (!ASSERT_STREQ(gate, "1", "native_tx_ring_gate"))
		return;
	ret = xdev_ext_xsk_fixture_init(&fixture);
	if (!ASSERT_OK(ret, "native_tx_ring_fixture"))
		return;

	ethernet = (struct ethhdr *)native_packet;
	memset(ethernet->h_dest, 0x42, ETH_ALEN);
	memset(ethernet->h_source, 0x24, ETH_ALEN);
	ethernet->h_dest[0] = 0x02;
	ethernet->h_source[0] = 0x02;
	ethernet->h_proto = htons(0x88b6);
	for (ret = sizeof(*ethernet); ret < (int)sizeof(native_packet); ret++)
		native_packet[ret] = (unsigned char)(ret ^ 0x3c);
	memcpy(use_plan_packet, native_packet, sizeof(use_plan_packet));
	((struct ethhdr *)use_plan_packet)->h_proto = htons(0x88b7);
	use_plan_packet[sizeof(*ethernet)] ^= 0x5a;
	memcpy(terminal_packet, native_packet, sizeof(terminal_packet));
	((struct ethhdr *)terminal_packet)->h_proto = htons(0x88b8);
	terminal_packet[sizeof(*ethernet)] ^= 0xff;
	memcpy(fixture.area, native_packet, sizeof(native_packet));
	memcpy((char *)fixture.area + use_plan_addr, use_plan_packet,
	       sizeof(use_plan_packet));
	memcpy((char *)fixture.area + terminal_addr, terminal_packet,
	       sizeof(terminal_packet));

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "native_tx_ring_open"))
		goto out;
	link = bpf_map__attach_struct_ops(skel->maps.afxdp_policy);
	link_err = libbpf_get_error(link);
	if (!ASSERT_OK(link_err, "native_tx_ring_attach")) {
		link = NULL;
		goto out;
	}
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;

	ret = xdev_ext_xsk_tx_ring_submit(&fixture, 0, sizeof(native_packet));
	ASSERT_GE(ret, 0, "native_tx_ring_fallback_kick");
	ASSERT_OK(xdev_ext_receive_packet_bounded(fixture.packet_fd, native_packet,
					     sizeof(native_packet)),
		  "native_tx_ring_fallback_packet");
	ASSERT_OK(xdev_ext_xsk_wait_completion(&fixture, 0),
		  "native_tx_ring_fallback_cq");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)1, "native_tx_ring_dispatch_once");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)1, "native_tx_ring_complete_once");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX,
		  "native_tx_ring_recipe");
	ASSERT_EQ(skel->bss->observed_complete_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX,
		  "native_tx_ring_complete_recipe");
	ASSERT_EQ(skel->bss->observed_capabilities,
		  (__u32)XDEV_EXT_BINDING_CAP_ASYNC,
		  "native_tx_ring_copy_capabilities");
	ASSERT_EQ(skel->bss->observed_src_offset, (__u64)0,
		  "native_tx_ring_src_offset");
	ASSERT_EQ(skel->bss->observed_bytes_done,
		  (__u64)sizeof(native_packet), "native_tx_ring_complete_bytes");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_USE_PLAN;
	ret = xdev_ext_xsk_tx_ring_submit(&fixture, use_plan_addr,
				     sizeof(use_plan_packet));
	ASSERT_GE(ret, 0, "native_tx_ring_use_plan_kick");
	ASSERT_OK(xdev_ext_receive_packet_bounded(fixture.packet_fd,
					     use_plan_packet,
					     sizeof(use_plan_packet)),
		  "native_tx_ring_use_plan_packet");
	ASSERT_OK(xdev_ext_xsk_wait_completion(&fixture, use_plan_addr),
		  "native_tx_ring_use_plan_cq");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)2, "native_tx_ring_use_plan_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)2, "native_tx_ring_use_plan_complete");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX,
		  "native_tx_ring_use_plan_recipe");
	ASSERT_EQ(skel->bss->observed_src_offset, use_plan_addr,
		  "native_tx_ring_use_plan_src_offset");

	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_TERMINAL;
	ret = xdev_ext_xsk_tx_ring_submit(&fixture, terminal_addr,
				     sizeof(terminal_packet));
	ASSERT_EQ(ret, -EPERM, "native_tx_ring_terminal_kick");
	ASSERT_OK(xdev_ext_xsk_wait_completion(&fixture, terminal_addr),
		  "native_tx_ring_terminal_cq");
	ASSERT_OK(xdev_ext_expect_no_matching_packet_bounded(fixture.packet_fd,
							terminal_packet,
							sizeof(terminal_packet)),
		  "native_tx_ring_terminal_no_packet");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)3, "native_tx_ring_terminal_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)2, "native_tx_ring_terminal_no_complete");

out:
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
	xdev_ext_xsk_fixture_cleanup(&fixture);
}

static void test_runtime_afxdp_native_rx_copy(__u32 xdp_flags)
{
	unsigned char fallback_packet[XDEV_EXT_TEST_AFXDP_FRAME_LEN] = {};
	unsigned char terminal_packet[XDEV_EXT_TEST_AFXDP_FRAME_LEN] = {};
	unsigned char recovery_packet[XDEV_EXT_TEST_AFXDP_FRAME_LEN] = {};
	const char *gate = getenv("XDEV_EXT_RUN_AFXDP_VETH");
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_xsk_fixture fixture;
	struct bpf_link *link = NULL;
	struct ethhdr *ethernet;
	__u64 dispatch_before, complete_before;
	__u64 terminal_dispatch_before, terminal_complete_before;
	long link_err;
	int ret;

	if (!gate) {
		printf("%s:SKIP: set XDEV_EXT_RUN_AFXDP_VETH=1 in an isolated root netns/KVM\n",
		       __func__);
		test__skip();
		return;
	}
	if (!ASSERT_STREQ(gate, "1", "native_rx_gate"))
		return;
	ret = xdev_ext_xsk_rx_fixture_init(&fixture, xdp_flags);
	if (!ASSERT_OK(ret, "native_rx_fixture"))
		return;
	/* A single circulating FQ frame proves that TERMINAL neither publishes
	 * an RX descriptor nor consumes hidden fill-ring ownership: the recovery
	 * packet below must reuse this exact one-frame budget. */
	ret = xdev_ext_xsk_fill_rx(&fixture, 0);
	if (!ASSERT_OK(ret, "native_rx_initial_fill"))
		goto out;

	ethernet = (struct ethhdr *)fallback_packet;
	memset(ethernet->h_dest, 0x52, ETH_ALEN);
	memset(ethernet->h_source, 0x25, ETH_ALEN);
	ethernet->h_dest[0] = 0x02;
	ethernet->h_source[0] = 0x02;
	ethernet->h_proto = htons(0x88c1);
	for (ret = sizeof(*ethernet); ret < (int)sizeof(fallback_packet); ret++)
		fallback_packet[ret] = (unsigned char)(ret ^ 0x69);
	memcpy(terminal_packet, fallback_packet, sizeof(terminal_packet));
	((struct ethhdr *)terminal_packet)->h_proto = htons(0x88c2);
	terminal_packet[sizeof(*ethernet)] ^= 0xa5;
	memcpy(recovery_packet, fallback_packet, sizeof(recovery_packet));
	((struct ethhdr *)recovery_packet)->h_proto = htons(0x88c3);
	recovery_packet[sizeof(*ethernet)] ^= 0x5a;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "native_rx_open"))
		goto out;
	link = bpf_map__attach_struct_ops(skel->maps.afxdp_rx_policy);
	link_err = libbpf_get_error(link);
	if (!ASSERT_OK(link_err, "native_rx_attach")) {
		link = NULL;
		goto out;
	}

	dispatch_before = __atomic_load_n(
		&skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		__ATOMIC_ACQUIRE);
	complete_before = __atomic_load_n(
		&skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		__ATOMIC_ACQUIRE);
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;
	ret = xdev_ext_xsk_peer_inject(&fixture, fallback_packet,
				  sizeof(fallback_packet));
	if (!ASSERT_OK(ret, "native_rx_fallback_inject"))
		goto out;
	ret = xdev_ext_xsk_receive_bounded(&fixture, fallback_packet,
				      sizeof(fallback_packet));
	if (!ASSERT_OK(ret, "native_rx_fallback_descriptor"))
		goto out;
	/* The descriptor becomes visible before the complete callback runs,
	 * possibly on another CPU, so wait for the callback before reading
	 * what it recorded.
	 */
	ret = xdev_ext_wait_count_at_least(
		&skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		complete_before + 1, XDEV_EXT_TEST_PACKET_TIMEOUT_MS);
	if (!ASSERT_OK(ret, "native_rx_fallback_complete_wait"))
		goto out;
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  dispatch_before + 1, "native_rx_fallback_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  complete_before + 1, "native_rx_fallback_complete");
	ASSERT_EQ(skel->bss->observed_dispatch_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_AFXDP_RX,
		  "native_rx_dispatch_stage");
	ASSERT_EQ(skel->bss->observed_dispatch_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
		  "native_rx_dispatch_direction");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_RX,
		  "native_rx_dispatch_recipe");
	ASSERT_EQ(skel->bss->observed_capabilities, (__u32)0,
		  "native_rx_copy_capabilities");
	ASSERT_EQ(skel->bss->observed_length,
		  (__u64)sizeof(fallback_packet), "native_rx_dispatch_length");
	ASSERT_EQ(skel->bss->observed_complete_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_AFXDP_RX,
		  "native_rx_complete_stage");
	ASSERT_EQ(skel->bss->observed_complete_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
		  "native_rx_complete_direction");
	ASSERT_EQ(skel->bss->observed_complete_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_RX,
		  "native_rx_complete_recipe");
	ASSERT_EQ(skel->bss->observed_result, 0,
		  "native_rx_complete_result");
	ASSERT_EQ(skel->bss->observed_bytes_done,
		  (__u64)sizeof(fallback_packet), "native_rx_complete_bytes");

	terminal_dispatch_before = skel->bss->
		dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP];
	terminal_complete_before = skel->bss->
		complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP];
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_TERMINAL;
	ret = xdev_ext_xsk_peer_inject(&fixture, terminal_packet,
				  sizeof(terminal_packet));
	if (!ASSERT_OK(ret, "native_rx_terminal_inject"))
		goto out;
	ret = xdev_ext_wait_count_at_least(
		&skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		terminal_dispatch_before + 1, XDEV_EXT_TEST_PACKET_TIMEOUT_MS);
	if (!ASSERT_OK(ret, "native_rx_terminal_dispatch_wait"))
		goto out;
	ASSERT_OK(xdev_ext_xsk_expect_no_rx_bounded(
			  &fixture, XDEV_EXT_TEST_NO_PACKET_TIMEOUT_MS),
		  "native_rx_terminal_no_descriptor");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  terminal_dispatch_before + 1, "native_rx_terminal_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  terminal_complete_before, "native_rx_terminal_no_complete");

	/* Recovery with the same one-frame FQ budget detects a hidden FQ consume
	 * in the terminal path even when no descriptor was exposed to userspace. */
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	ret = xdev_ext_xsk_peer_inject(&fixture, recovery_packet,
				  sizeof(recovery_packet));
	if (!ASSERT_OK(ret, "native_rx_recovery_inject"))
		goto out;
	ASSERT_OK(xdev_ext_xsk_receive_bounded(&fixture, recovery_packet,
					  sizeof(recovery_packet)),
		  "native_rx_recovery_descriptor");
	ASSERT_OK(xdev_ext_wait_count_at_least(
			  &skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
			  terminal_complete_before + 1,
			  XDEV_EXT_TEST_PACKET_TIMEOUT_MS),
		  "native_rx_recovery_complete_wait");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  terminal_dispatch_before + 2, "native_rx_recovery_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  terminal_complete_before + 1, "native_rx_recovery_complete");

out:
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
	xdev_ext_xsk_fixture_cleanup(&fixture);
}

static void test_runtime_iaa_no_provider_rollback(void)
{
	const char *gate = getenv("XDEV_EXT_RUN_IAA_NO_PROVIDER");
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_runtime_fixture fixture;
	struct bpf_link *link = NULL;
	bool fixture_ready = false;
	long link_err;
	int cleanup_err;
	int first_result;
	int second_result;
	int ret;

	if (!gate) {
		printf("%s:SKIP: set XDEV_EXT_RUN_IAA_NO_PROVIDER=1 only when deflate-iaa is absent\n",
		       __func__);
		test__skip();
		return;
	}
	if (!ASSERT_STREQ(gate, "1", "iaa_no_provider_gate"))
		return;

	ret = xdev_ext_runtime_fixture_init_pages(&fixture, 2);
	if (!ASSERT_OK(ret, "iaa_no_provider_fixture"))
		return;
	fixture_ready = true;
	memset(fixture.umem, 0x5a, 128);
	memset((char *)fixture.umem + fixture.page_size, 0, 1024);

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "iaa_no_provider_open"))
		goto out;
	link = bpf_map__attach_struct_ops(skel->maps.iaa_policy);
	link_err = libbpf_get_error(link);
	if (!ASSERT_OK(link_err, "iaa_no_provider_attach")) {
		link = NULL;
		goto out;
	}
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;

	ret = xdev_ext_submit_iaa_bounded(&fixture, IO_UNIFIED_OP_IAA_COMPRESS,
				     0, fixture.page_size, 128, 1024,
				     &first_result);
	if (!ASSERT_OK(ret, "iaa_no_provider_first_wait"))
		goto out;
	ASSERT_EQ(first_result, -ENOENT, "iaa_no_provider_first_errno");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_IAA],
		  (__u64)1, "iaa_no_provider_first_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_IAA],
		  (__u64)0, "iaa_no_provider_first_no_complete");
	ASSERT_EQ(skel->bss->observed_dispatch_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_IAA,
		  "iaa_no_provider_dispatch_backend");
	ASSERT_EQ(skel->bss->observed_dispatch_event,
		  (__u32)XDEV_EXT_BINDING_EVENT_DISPATCH,
		  "iaa_no_provider_dispatch_event");
	ASSERT_EQ(skel->bss->observed_dispatch_stage,
		  (__u32)XDEV_EXT_BINDING_STAGE_IAA_COMPRESS,
		  "iaa_no_provider_dispatch_stage");
	ASSERT_EQ(skel->bss->observed_dispatch_direction,
		  (__u32)XDEV_EXT_BINDING_DIRECTION_INTERNAL,
		  "iaa_no_provider_dispatch_direction");
	ASSERT_EQ(skel->bss->observed_recipe,
		  (__u32)XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS,
		  "iaa_no_provider_dispatch_recipe");
	ASSERT_EQ(skel->bss->observed_src_offset, (__u64)0,
		  "iaa_no_provider_src_offset");
	ASSERT_EQ(skel->bss->observed_length, (__u64)128,
		  "iaa_no_provider_src_length");
	ASSERT_EQ(fixture.shared->calc_errors, (__u32)1,
		  "iaa_no_provider_first_error_stats");

	/*
	 * The same two frames must be claimable again. A leaked frame claim
	 * would stop this request before the second production-path dispatch.
	 */
	ret = xdev_ext_submit_iaa_bounded(&fixture, IO_UNIFIED_OP_IAA_COMPRESS,
				     0, fixture.page_size, 128, 1024,
				     &second_result);
	if (!ASSERT_OK(ret, "iaa_no_provider_second_wait"))
		goto out;
	ASSERT_EQ(second_result, first_result,
		  "iaa_no_provider_stable_errno");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_IAA],
		  (__u64)2, "iaa_no_provider_second_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_IAA],
		  (__u64)0, "iaa_no_provider_second_no_complete");
	ASSERT_EQ(fixture.shared->calc_errors, (__u32)2,
		  "iaa_no_provider_second_error_stats");
	ASSERT_EQ(fixture.shared->calc_result, (__u64)0,
		  "iaa_no_provider_no_result");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)0, "iaa_no_provider_socket_zero");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)0, "iaa_no_provider_afxdp_zero");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_NVME],
		  (__u64)0, "iaa_no_provider_nvme_zero");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_GPU],
		  (__u64)0, "iaa_no_provider_gpu_zero");

out:
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
	if (fixture_ready) {
		cleanup_err = xdev_ext_runtime_fixture_cleanup(&fixture);
		ASSERT_OK(cleanup_err, "iaa_no_provider_fixture_cleanup");
	}
}

static void test_runtime_unbound_xdp_socket_fallback(void)
{
	static const char payload[] = "xdev_ext-v2-unbound-xdp";
	struct io_uring_unified_shared stats_before;
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_runtime_fixture fixture;
	struct bpf_link *afxdp_link = NULL;
	struct bpf_link *socket_link = NULL;
	bool fixture_ready = false;
	long link_err;
	int cleanup_err;
	int cqe_res;
	int xdp_fd = -1;
	int ret;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "unbound_xdp_open"))
		goto out;

	socket_link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
	link_err = libbpf_get_error(socket_link);
	if (!ASSERT_OK(link_err, "unbound_xdp_socket_attach")) {
		socket_link = NULL;
		goto out;
	}
	afxdp_link = bpf_map__attach_struct_ops(skel->maps.afxdp_policy);
	link_err = libbpf_get_error(afxdp_link);
	if (!ASSERT_OK(link_err, "unbound_xdp_afxdp_attach")) {
		afxdp_link = NULL;
		goto out;
	}

	xdp_fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (xdp_fd < 0 &&
	    (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)) {
		printf("%s:SKIP: AF_XDP sockets are not supported\n", __func__);
		test__skip();
		goto out;
	}
	if (!ASSERT_GE(xdp_fd, 0, "unbound_xdp_socket"))
		goto out;

	ret = xdev_ext_runtime_fixture_init(&fixture);
	if (!ASSERT_OK(ret, "unbound_xdp_fixture_init"))
		goto out;
	fixture_ready = true;
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;
	memcpy(fixture.umem, payload, sizeof(payload));
	memcpy(&stats_before, fixture.shared, sizeof(stats_before));

	/* An unbound XSK is not TX-capable, so it uses the SOCKET backend. */
	ret = xdev_ext_submit_send_bounded(&fixture, xdp_fd, 0, sizeof(payload), 0,
				      &cqe_res);
	if (!ASSERT_OK(ret, "unbound_xdp_wait"))
		goto out;
	ASSERT_LT(cqe_res, 0, "unbound_xdp_native_errno");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)1, "unbound_xdp_socket_dispatch_once");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET],
		  (__u64)1, "unbound_xdp_socket_complete_once");
	ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)0, "unbound_xdp_no_afxdp_dispatch");
	ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
		  (__u64)0, "unbound_xdp_no_afxdp_complete");
	ASSERT_EQ(skel->bss->observed_dispatch_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_SOCKET,
		  "unbound_xdp_dispatch_backend");
	ASSERT_EQ(skel->bss->observed_complete_backend,
		  (__u32)XDEV_EXT_BINDING_BACKEND_SOCKET,
		  "unbound_xdp_complete_backend");
	ASSERT_EQ(skel->bss->observed_result, cqe_res,
		  "unbound_xdp_completion_errno");
	ASSERT_EQ(skel->bss->observed_bytes_done, (__u64)0,
		  "unbound_xdp_completion_bytes");
	ASSERT_EQ(fixture.shared->send_errors, stats_before.send_errors + 1,
		  "unbound_xdp_send_errors");
	ASSERT_EQ(fixture.shared->send_count, stats_before.send_count,
		  "unbound_xdp_send_count");
	ASSERT_EQ(fixture.shared->send_bytes, stats_before.send_bytes,
		  "unbound_xdp_send_bytes");

out:
	if (xdp_fd >= 0)
		close(xdp_fd);
	bpf_link__destroy(afxdp_link);
	bpf_link__destroy(socket_link);
	if (fixture_ready) {
		cleanup_err = xdev_ext_runtime_fixture_cleanup(&fixture);
		ASSERT_OK(cleanup_err, "unbound_xdp_fixture_cleanup");
	}
	xdev_ext_binding_success__destroy(skel);
}

static __u64 xdev_ext_load_count(const __u64 *count)
{
	return __atomic_load_n(count, __ATOMIC_ACQUIRE);
}

struct xdev_ext_concurrent_payload {
	uint64_t sequence;
	uint64_t inverse;
};

struct xdev_ext_concurrent_worker {
	struct xdev_ext_runtime_fixture *fixture;
	atomic_bool stop;
	atomic_int error;
	atomic_uint_fast64_t progress;
};

static void xdev_ext_concurrent_worker_fail(struct xdev_ext_concurrent_worker *worker,
				       int error)
{
	if (error >= 0)
		error = -EIO;
	atomic_store_explicit(&worker->error, error, memory_order_release);
}

static void *xdev_ext_concurrent_sender(void *arg)
{
	struct xdev_ext_concurrent_worker *worker = arg;
	struct xdev_ext_runtime_fixture *fixture = worker->fixture;
	struct xdev_ext_concurrent_payload payload;
	uint64_t sequence = 1;
	int cqe_res;
	int ret;

	while (!atomic_load_explicit(&worker->stop, memory_order_acquire)) {
		payload.sequence = sequence++;
		payload.inverse = ~payload.sequence;
		memcpy(fixture->umem, &payload, sizeof(payload));

		ret = xdev_ext_submit_send_bounded(fixture, fixture->sockets[0], 0,
					      sizeof(payload), 0, &cqe_res);
		if (ret) {
			xdev_ext_concurrent_worker_fail(worker, ret);
			break;
		}
		if (cqe_res != (int)sizeof(payload)) {
			xdev_ext_concurrent_worker_fail(worker, cqe_res);
			break;
		}
		ret = xdev_ext_receive_payload(fixture->sockets[1], &payload,
					  sizeof(payload));
		if (ret) {
			xdev_ext_concurrent_worker_fail(worker, ret);
			break;
		}
		atomic_fetch_add_explicit(&worker->progress, 1,
					  memory_order_release);
	}

	return NULL;
}

static int xdev_ext_wait_pause(uint64_t deadline_ns)
{
	struct timespec delay;
	uint64_t now_ns, remaining_ns;
	int ret;

	ret = xdev_ext_monotonic_ns(&now_ns);
	if (ret)
		return ret;
	if (now_ns >= deadline_ns)
		return -ETIMEDOUT;

	remaining_ns = deadline_ns - now_ns;
	if (remaining_ns > XDEV_EXT_NSEC_PER_MSEC)
		remaining_ns = XDEV_EXT_NSEC_PER_MSEC;
	delay.tv_sec = 0;
	delay.tv_nsec = remaining_ns;
	if (nanosleep(&delay, NULL) && errno != EINTR)
		return -errno;
	return 0;
}

static int xdev_ext_wait_worker_progress(struct xdev_ext_concurrent_worker *worker,
				    uint_fast64_t target,
				    unsigned int timeout_ms)
{
	uint64_t deadline_ns, now_ns;
	int error;

	error = xdev_ext_monotonic_ns(&now_ns);
	if (error)
		return error;
	deadline_ns = now_ns + (uint64_t)timeout_ms * XDEV_EXT_NSEC_PER_MSEC;

	for (;;) {
		error = atomic_load_explicit(&worker->error,
					     memory_order_acquire);
		if (error)
			return error;
		if (atomic_load_explicit(&worker->progress,
					 memory_order_acquire) >= target)
			return 0;
		error = xdev_ext_wait_pause(deadline_ns);
		if (error)
			return error;
	}
}

static int xdev_ext_wait_policy_invocation(struct xdev_ext_concurrent_worker *worker,
				      const __u64 *invocation_count,
				      __u64 previous_count,
				      unsigned int timeout_ms)
{
	uint64_t deadline_ns, now_ns;
	int error;

	error = xdev_ext_monotonic_ns(&now_ns);
	if (error)
		return error;
	deadline_ns = now_ns + (uint64_t)timeout_ms * XDEV_EXT_NSEC_PER_MSEC;

	for (;;) {
		error = atomic_load_explicit(&worker->error,
					     memory_order_acquire);
		if (error)
			return error;
		if (xdev_ext_load_count(invocation_count) > previous_count)
			return 0;
		error = xdev_ext_wait_pause(deadline_ns);
		if (error)
			return error;
	}
}

static void test_runtime_concurrent_lifetime(void)
{
	struct xdev_ext_concurrent_worker worker;
	struct xdev_ext_binding_success *skel = NULL;
	struct xdev_ext_runtime_fixture fixture;
	struct bpf_link *link = NULL;
	bool fixture_ready = false;
	bool worker_started = false;
	const __u64 *socket_dispatch_count;
	const __u64 *socket_complete_count;
	pthread_t thread;
	uint_fast64_t progress;
	__u64 invocation_count;
	__u64 completion_count;
	long link_err;
	unsigned int round;
	int cleanup_err;
	int ret;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "concurrent_open_and_load"))
		goto out;
	socket_dispatch_count =
		&skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
	socket_complete_count =
		&skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_SOCKET];
	skel->bss->dispatch_mode = XDEV_EXT_SUCCESS_FALLBACK;
	skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;

	ret = xdev_ext_runtime_fixture_init(&fixture);
	if (!ASSERT_OK(ret, "concurrent_fixture_init"))
		goto out;
	fixture_ready = true;

	worker.fixture = &fixture;
	atomic_init(&worker.stop, false);
	atomic_init(&worker.error, 0);
	atomic_init(&worker.progress, 0);
	ret = pthread_create(&thread, NULL, xdev_ext_concurrent_sender, &worker);
	if (!ASSERT_OK(ret ? -ret : 0, "concurrent_thread_create"))
		goto out;
	worker_started = true;

	ret = xdev_ext_wait_worker_progress(&worker, 1,
				       XDEV_EXT_TEST_WINDOW_TIMEOUT_MS);
	if (!ASSERT_OK(ret, "concurrent_initial_fallback"))
		goto out;
	invocation_count = xdev_ext_load_count(socket_dispatch_count);
	if (!ASSERT_EQ(invocation_count, (__u64)0,
		       "concurrent_initial_policy_count"))
		goto out;

	for (round = 0; round < XDEV_EXT_TEST_CONCURRENT_ROUNDS; round++) {
		invocation_count = xdev_ext_load_count(socket_dispatch_count);
		link = bpf_map__attach_struct_ops(skel->maps.socket_policy);
		link_err = libbpf_get_error(link);
		if (!ASSERT_EQ(link_err, 0, "concurrent_attach")) {
			link = NULL;
			goto out;
		}

		ret = xdev_ext_wait_policy_invocation(&worker, socket_dispatch_count,
						 invocation_count,
						 XDEV_EXT_TEST_WINDOW_TIMEOUT_MS);
		if (!ASSERT_OK(ret, "concurrent_attached_invocation"))
			goto out;

		ret = bpf_link__destroy(link);
		link = NULL;
		if (!ASSERT_OK(ret, "concurrent_detach"))
			goto out;
		invocation_count = xdev_ext_load_count(socket_dispatch_count);
		progress = atomic_load_explicit(&worker.progress,
						memory_order_acquire);

		/* At most one sequential send can have passed policy before detach
		 * and finish afterward.  Two further completions therefore include
		 * at least one request that began in this detached window.
		 */
		ret = xdev_ext_wait_worker_progress(&worker, progress + 2,
					       XDEV_EXT_TEST_WINDOW_TIMEOUT_MS);
		if (!ASSERT_OK(ret, "concurrent_detached_fallback"))
			goto out;
		if (!ASSERT_EQ(xdev_ext_load_count(socket_dispatch_count),
			       invocation_count,
			       "concurrent_detached_policy_stable"))
			goto out;
	}

out:
	/* Detach first so no active policy can outlive worker shutdown. */
	ret = bpf_link__destroy(link);
	link = NULL;
	ASSERT_OK(ret, "concurrent_cleanup_detach");
	if (worker_started) {
		atomic_store_explicit(&worker.stop, true, memory_order_release);
		/* The worker's only blocking operation has a hard CQE timeout; its
		 * receive is nonblocking, so this join cannot wait on unbounded I/O.
		 */
		ret = pthread_join(thread, NULL);
		ASSERT_OK(ret ? -ret : 0, "concurrent_thread_join");
		if (!ret) {
			progress = atomic_load_explicit(&worker.progress,
							memory_order_acquire);
			ASSERT_EQ(atomic_load_explicit(&worker.error,
						       memory_order_acquire),
				  0, "concurrent_worker_error");
			ASSERT_EQ(fixture.shared->send_count, (__u64)progress,
				  "concurrent_send_count");
			ASSERT_EQ(fixture.shared->send_bytes,
				  (__u64)progress *
				  sizeof(struct xdev_ext_concurrent_payload),
				  "concurrent_send_bytes");
			ASSERT_EQ(fixture.shared->send_errors, (__u32)0,
				  "concurrent_send_errors");
			invocation_count = xdev_ext_load_count(socket_dispatch_count);
			completion_count = xdev_ext_load_count(socket_complete_count);
			ASSERT_EQ(invocation_count, completion_count,
				  "concurrent_dispatch_complete_balanced");
		}
	}
	if (fixture_ready) {
		cleanup_err = xdev_ext_runtime_fixture_cleanup(&fixture);
		ASSERT_OK(cleanup_err, "concurrent_fixture_cleanup");
	}
	xdev_ext_binding_success__destroy(skel);
}

static void test_afxdp_fake_native(void)
{
	static const struct {
		__u32 mode;
		__u32 flags;
		__u64 src_offset;
		__u64 length;
		int native_result;
		int expected_result;
		__u32 native_calls;
		__u64 dispatch_delta;
		__u64 complete_delta;
		int expected_policy_result;
	} cases[] = {
		{ XDEV_EXT_SUCCESS_FALLBACK, 0, 64, 4096,
		  4096, 4096, 1, 1, 1, 0 },
		{ XDEV_EXT_SUCCESS_USE_PLAN, 0, 8192, 128,
		  128, 128, 1, 1, 1, 0 },
		{ XDEV_EXT_SUCCESS_TERMINAL, 0, 96, 512,
		  4096, -EPERM, 0, 1, 0, 0 },
		{ XDEV_EXT_SUCCESS_INVALID_PLAN, 0, 128, 1024,
		  4096, -EPERM, 0, 1, 0, -EPERM },
		{ XDEV_EXT_SUCCESS_FALLBACK, BPF_TESTMOD_XDEV_EXT_F_PRE_NATIVE_FAIL,
		  160, 2048, -EINVAL, -EINVAL, 0, 1, 0, 0 },
		{ XDEV_EXT_SUCCESS_FALLBACK, 0, 192, 256,
		  -ENXIO, -ENXIO, 1, 1, 1, 0 },
		{ XDEV_EXT_SUCCESS_FALLBACK, 0, 224, 384,
		  -ENETDOWN, -ENETDOWN, 1, 1, 1, 0 },
		{ XDEV_EXT_SUCCESS_FALLBACK,
		  BPF_TESTMOD_XDEV_EXT_F_USE_IO_URING_UMEM, 256, 512,
		  0, -EOPNOTSUPP, 0, 0, 0, 0 },
	};
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_success *skel = NULL;
	struct bpf_link *link = NULL;
	__u64 dispatch_before, complete_before;
	long err;
	size_t i;

	skel = xdev_ext_binding_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "afxdp_fake_open"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.afxdp_policy);
	err = libbpf_get_error(link);
	if (!ASSERT_OK(err, "afxdp_fake_attach")) {
		link = NULL;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		__s32 expected_normalized = 0;
		__u64 expected_bytes = 0;

		if (cases[i].native_result < 0)
			expected_normalized = cases[i].native_result;
		else if (cases[i].native_result > 0)
			expected_bytes = cases[i].native_result;

		ASSERT_OK(run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET,
					  XDEV_EXT_BINDING_BACKEND_AFXDP, 0, 0,
					  &response), "afxdp_fake_reset");
		skel->bss->dispatch_mode = cases[i].mode;
		skel->bss->complete_mode = XDEV_EXT_SUCCESS_FALLBACK;
		dispatch_before =
			skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP];
		complete_before =
			skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP];
		ASSERT_OK(run_xdev_ext_fake_afxdp_command(cases[i].flags,
						     cases[i].native_result,
						     cases[i].src_offset,
						     cases[i].length, &response),
			  "afxdp_fake_command");
		ASSERT_EQ(response.return_value, cases[i].expected_result,
			  "afxdp_fake_result");
		ASSERT_EQ(response.policy_return_value,
			  cases[i].expected_policy_result,
			  "afxdp_fake_policy_result");
		ASSERT_EQ(response.native_calls, cases[i].native_calls,
			  "afxdp_fake_native_calls");
		ASSERT_FALSE(response.token_live, "afxdp_fake_token_unwound");
		ASSERT_EQ(skel->bss->dispatch_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
			  dispatch_before + cases[i].dispatch_delta,
			  "afxdp_fake_dispatch_count");
		ASSERT_EQ(skel->bss->complete_count[XDEV_EXT_BINDING_BACKEND_AFXDP],
			  complete_before + cases[i].complete_delta,
			  "afxdp_fake_complete_count");
		if (cases[i].dispatch_delta) {
			ASSERT_EQ(skel->bss->observed_dispatch_backend,
				  (__u32)XDEV_EXT_BINDING_BACKEND_AFXDP,
				  "afxdp_fake_dispatch_backend");
			ASSERT_EQ(skel->bss->observed_dispatch_event,
				  (__u32)XDEV_EXT_BINDING_EVENT_DISPATCH,
				  "afxdp_fake_dispatch_event");
			ASSERT_EQ(skel->bss->observed_dispatch_stage,
				  (__u32)XDEV_EXT_BINDING_STAGE_AFXDP_TX,
				  "afxdp_fake_dispatch_stage");
			ASSERT_EQ(skel->bss->observed_dispatch_direction,
				  (__u32)XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
				  "afxdp_fake_dispatch_direction");
			ASSERT_EQ(skel->bss->observed_src_offset,
				  cases[i].src_offset,
				  "afxdp_fake_src_offset");
			ASSERT_EQ(skel->bss->observed_length,
				  cases[i].length, "afxdp_fake_length");
			ASSERT_EQ(skel->bss->observed_recipe,
				  (__u32)XDEV_EXT_BINDING_RECIPE_AFXDP_COPY,
				  "afxdp_fake_recipe");
		}
		if (cases[i].complete_delta) {
			ASSERT_EQ(skel->bss->observed_complete_backend,
				  (__u32)XDEV_EXT_BINDING_BACKEND_AFXDP,
				  "afxdp_fake_complete_backend");
			ASSERT_EQ(skel->bss->observed_complete_event,
				  (__u32)XDEV_EXT_BINDING_EVENT_COMPLETE,
				  "afxdp_fake_complete_event");
			ASSERT_EQ(skel->bss->observed_result,
				  expected_normalized,
				  "afxdp_fake_normalized_result");
			ASSERT_EQ(skel->bss->observed_bytes_done,
				  expected_bytes,
				  "afxdp_fake_bytes_done");
		}
	}

out:
	run_xdev_ext_command(BPF_TESTMOD_XDEV_EXT_RESET, XDEV_EXT_BINDING_BACKEND_AFXDP,
			0, 0, &response);
	bpf_link__destroy(link);
	xdev_ext_binding_success__destroy(skel);
}

void serial_test_xdev_ext_binding(void)
{
	if (!xdev_ext_core_seam_available())
		return;
	if (test__start_subtest("config_boundary_contract"))
		test_config_boundary_contract();
	if (!xdev_ext_binding_struct_ops_available())
		return;
	if (test__start_subtest("no_plugin_then_attach"))
		test_no_plugin_then_attach();
	if (test__start_subtest("all_backends_and_duplicate"))
		test_all_backends_and_duplicate();
	if (test__start_subtest("duplicate_generation_and_link_update"))
		test_duplicate_generation_and_link_update();
	if (test__start_subtest("registration_validation"))
		test_registration_validation();
	if (test__start_subtest("afxdp_rx_opt_in"))
		test_afxdp_rx_opt_in();
	if (test__start_subtest("reference_policy_per_backend")) {
		test_reference_policy_per_backend();
		test_reference_policy_rx_opt_in_cleared();
	}
	if (test__start_subtest("dispatch_contract"))
		test_dispatch_contract();
	if (test__start_subtest("completion_contract"))
		test_completion_contract();
	if (test__start_subtest("token_edges"))
		test_token_edges();
	if (test__start_subtest("pinned_generation"))
		test_pinned_generation();
	if (test__start_subtest("runtime_no_policy"))
		test_runtime_no_policy();
	if (test__start_subtest("runtime_success_policy"))
		test_runtime_success_policy();
	if (test__start_subtest("runtime_non_umem_send_encodings"))
		test_runtime_non_umem_send_encodings();
	if (test__start_subtest("runtime_nvme_file_backed"))
		test_runtime_nvme_file_backed();
	if (test__start_subtest("runtime_preflight_before_policy"))
		test_runtime_preflight_before_policy();
	if (test__start_subtest("runtime_invalid_policy"))
		test_runtime_invalid_policy();
	if (test__start_subtest("runtime_bound_afxdp_copy"))
		test_runtime_bound_afxdp_copy();
	if (test__start_subtest("runtime_afxdp_native_tx_ring_copy"))
		test_runtime_afxdp_native_tx_ring_copy();
	if (test__start_subtest("runtime_afxdp_native_rx_copy"))
		test_runtime_afxdp_native_rx_copy(XDP_FLAGS_SKB_MODE);
	if (test__start_subtest("runtime_afxdp_native_rx_copy_drv"))
		test_runtime_afxdp_native_rx_copy(XDP_FLAGS_DRV_MODE);
	if (test__start_subtest("runtime_iaa_no_provider_rollback"))
		test_runtime_iaa_no_provider_rollback();
	if (test__start_subtest("runtime_unbound_xdp_socket_fallback"))
		test_runtime_unbound_xdp_socket_fallback();
	if (test__start_subtest("runtime_concurrent_lifetime"))
		test_runtime_concurrent_lifetime();
	if (test__start_subtest("afxdp_fake_native"))
		test_afxdp_fake_native();

	RUN_TESTS(xdev_ext_binding_fail_kfunc);
	RUN_TESTS(xdev_ext_binding_fail_kfunc_complete);
	RUN_TESTS(xdev_ext_binding_fail_fabricated_ctx);
	RUN_TESTS(xdev_ext_binding_fail_foreign_ops);
	RUN_TESTS(xdev_ext_binding_fail_write);
	RUN_TESTS(xdev_ext_binding_fail_write_kernel);
	RUN_TESTS(xdev_ext_binding_fail_sleepable);
}

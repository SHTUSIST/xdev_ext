// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include "xdev_ext_preload_core.h"
#if __has_include("../../../../io_uring/xdev_ext_mech_ce_lease.h")
#include "../../../../io_uring/xdev_ext_mech_ce_lease.h"
#else
/* Before the kernel ownership fix, foreign sessions are admitted without any
 * CE ownership check. Keep that exact permissive behavior as the RED seam. */
struct xdev_ext_ce_lease_slot { __u64 generation; bool active; };
struct xdev_ext_ce_lease_state { __u32 active_batches; bool quarantined; };
static bool xdev_ext_ce_lease_overlap(const void *a, __u64 as, __u64 al,
				    const void *b, __u64 bs, __u64 bl)
{ return a == b && as < bs+bl && bs < as+al; }
static int xdev_ext_ce_lease_acquire(struct xdev_ext_ce_lease_state *s,
		struct xdev_ext_ce_lease_slot *slot, __u64 generation, bool conflict)
{ (void)conflict; slot->active = true; slot->generation = generation; s->active_batches++; return 0; }
static int xdev_ext_ce_lease_finish(struct xdev_ext_ce_lease_state *s,
		struct xdev_ext_ce_lease_slot *slot, __u64 generation, bool sequestered)
{ (void)generation; (void)sequestered; slot->active = false; s->active_batches--; return 0; }
#endif

static long native_syscall(long nr, ...);
#define syscall native_syscall
#include "xdev_ext_preload_socket_mech.h"
#undef syscall

/* Substitute only unavailable custom-kernel operations. Real production
 * runtimes own their own frames, rings and eventfds and use real UDP peers.
 * Both simulated CE writes must complete before either simulated CE read:
 * this is a legal interleaving of two independent native queues. A mutex
 * protects model memory, so corruption is not a C test data race.
 */
struct native_session {
	void *frame;
	int sink, wake;
	uint64_t ce_addr, ce_len;
	struct xdev_ext_mech_stats stats;
	struct xdev_ext_ce_lease_state ownership;
	struct xdev_ext_ce_lease_slot slot;
};
static struct native_session sessions[4096];
static pthread_mutex_t device_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ownership_returned = PTHREAD_COND_INITIALIZER;
static pthread_barrier_t attempted_admission;
static pthread_barrier_t writes_complete;
static unsigned char device_window[65536];
static unsigned initially_admitted;

static int try_claim(struct native_session *n, uint64_t generation)
{
	bool conflict = false;
	for (unsigned i = 0; i < 4096; i++) {
		struct native_session *other = &sessions[i];
		if (other != n && other->ownership.active_batches &&
		    xdev_ext_ce_lease_overlap(device_window, n->ce_addr, n->ce_len,
					device_window, other->ce_addr, other->ce_len))
			conflict = true;
	}
	return xdev_ext_ce_lease_acquire(&n->ownership, &n->slot, generation, conflict);
}

static long native_syscall(long nr, ...)
{
	va_list ap;
	long ret = 0;
	va_start(ap, nr);
	if (nr == SYS_io_uring_setup) {
		(void)va_arg(ap, int); (void)va_arg(ap, void *);
		ret = eventfd(0, EFD_CLOEXEC);
		assert(ret >= 0 && ret < 4096);
	} else if (nr == SYS_io_uring_register) {
		int ring = va_arg(ap, int);
		unsigned opcode = va_arg(ap, unsigned);
		void *arg = va_arg(ap, void *);
		struct native_session *n = &sessions[ring];
		(void)va_arg(ap, int);
		if (opcode == IORING_REGISTER_XDEV_EXT_UMEM) {
			n->frame = (void *)(uintptr_t)((struct io_uring_xdev_ext_umem_reg *)arg)->addr;
		} else {
			struct io_uring_xdev_ext_mech *r = arg;
			void *p = (void *)(uintptr_t)r->arg;
			if (r->op == XDEV_EXT_MECH_OP_CREATE) {
				struct xdev_ext_mech_create *c = p;
				assert(c->nr_stages == 3 && c->depth == 1);
				assert(c->st[0].class_id == XDEV_EXT_MECH_CLASS_CE);
				assert(c->st[1].class_id == XDEV_EXT_MECH_CLASS_CE);
				assert(c->st[0].arg0 == c->st[1].arg0);
				n->ce_addr = c->st[0].arg0;
				n->ce_len = c->st[0].arg1;
				assert(n->ce_addr <= sizeof(device_window) &&
				       n->ce_len <= sizeof(device_window)-n->ce_addr);
				n->sink = dup(c->st[2].fd);
				n->wake = c->eventfd;
				c->session_id = ring;
				n->stats = (struct xdev_ext_mech_stats) {
					.session_id = ring, .state = XDEV_EXT_MECH_SESSION_ACTIVE,
				};
			} else if (r->op == XDEV_EXT_MECH_OP_NOTIFY_ARM) {
				struct xdev_ext_mech_notify_arm *a = p;
				assert(a->batches_target == n->stats.batches_done+1);
			} else if (r->op == XDEV_EXT_MECH_OP_START) {
				struct xdev_ext_mech_start *s = p;
				struct xdev_ext_mech_user_span *span = (void *)(uintptr_t)s->user_frames;
				uint64_t one = 1;
				uint64_t generation = s->first_seq+1;
				int barrier, claim;
				assert(span->len <= n->ce_len);
				pthread_mutex_lock(&device_lock);
				claim = try_claim(n, generation);
				if (!claim) initially_admitted++;
				pthread_mutex_unlock(&device_lock);
				barrier = pthread_barrier_wait(&attempted_admission);
				assert(!barrier || barrier == PTHREAD_BARRIER_SERIAL_THREAD);
				pthread_mutex_lock(&device_lock);
				while (claim) {
					claim = try_claim(n, generation);
					if (claim) pthread_cond_wait(&ownership_returned, &device_lock);
				}
				memcpy(device_window+n->ce_addr, n->frame, span->len);
				pthread_mutex_unlock(&device_lock);
				if (initially_admitted == 2) {
					barrier = pthread_barrier_wait(&writes_complete);
					assert(!barrier || barrier == PTHREAD_BARRIER_SERIAL_THREAD);
				}
				pthread_mutex_lock(&device_lock);
				memcpy(n->frame, device_window+n->ce_addr, span->len);
				pthread_mutex_unlock(&device_lock);
				assert(send(n->sink, n->frame, span->len, MSG_NOSIGNAL) == (ssize_t)span->len);
				n->stats.batches_done++; n->stats.published++;
				for (unsigned i = 0; i < 3; i++) {
					n->stats.submitted[i]++; n->stats.completed[i]++;
				}
				pthread_mutex_lock(&device_lock);
				assert(!xdev_ext_ce_lease_finish(&n->ownership, &n->slot, generation, false));
				pthread_cond_broadcast(&ownership_returned);
				pthread_mutex_unlock(&device_lock);
				assert(write(n->wake, &one, sizeof(one)) == sizeof(one));
			} else if (r->op == XDEV_EXT_MECH_OP_STATS) {
				*(struct xdev_ext_mech_stats *)p = n->stats;
			} else if (r->op == XDEV_EXT_MECH_OP_STOP) {
				assert(!close(n->sink));
			} else {
				assert(0);
			}
		}
	} else if (nr == SYS_getsockopt) {
		int fd = va_arg(ap, int), level = va_arg(ap, int), opt = va_arg(ap, int);
		void *out = va_arg(ap, void *); socklen_t *len = va_arg(ap, socklen_t *);
		ret = getsockopt(fd, level, opt, out, len);
	} else if (nr == SYS_getpeername) {
		int fd = va_arg(ap, int); void *out = va_arg(ap, void *);
		socklen_t *len = va_arg(ap, socklen_t *);
		ret = getpeername(fd, out, len);
	} else if (nr == SYS_openat) {
		(void)va_arg(ap, int); (void)va_arg(ap, const char *);
		int flags = va_arg(ap, int); (void)va_arg(ap, int);
		ret = open("/dev/null", flags);
	} else if (nr == SYS_close) {
		ret = close(va_arg(ap, int));
	} else if (nr == SYS_eventfd2) {
		int initial = va_arg(ap, int), flags = va_arg(ap, int);
		ret = eventfd(initial, flags);
	} else if (nr == SYS_read) {
		int fd = va_arg(ap, int); void *buf = va_arg(ap, void *);
		size_t len = va_arg(ap, size_t); ret = read(fd, buf, len);
	} else if (nr == SYS_process_vm_readv) {
		pid_t pid = va_arg(ap, pid_t); void *local = va_arg(ap, void *);
		int ln = va_arg(ap, int); void *remote = va_arg(ap, void *);
		int rn = va_arg(ap, int), flags = va_arg(ap, int);
		/* Forward full machine words to the untyped syscall ABI. Clang may
		 * store only four bytes of an int stack argument, leaving flags' high
		 * word uninitialized even though the decoded flag value is zero.
		 */
		ret = syscall(nr, (long)pid, local, (unsigned long)ln,
			      remote, (unsigned long)rn, (unsigned long)flags);
	} else {
		assert(0);
	}
	va_end(ap);
	return ret;
}

struct actor {
	struct xdev_ext_socket_mech_runtime runtime;
	int rx, tx;
	unsigned char expected[9], received[9];
	ssize_t sent, received_len;
};
static void *send_one(void *opaque)
{
	struct actor *a = opaque;
	struct xdev_ext_socket_mech_config cfg = {
		.enabled = true, .ce_device = "/dev/shared-ce", .ce_addr = 0, .ce_len = 65536,
	};
	a->sent = xdev_ext_socket_mech_send(&a->runtime, &cfg, a->tx,
					 a->expected, sizeof(a->expected), 4096);
	a->received_len = recv(a->rx, a->received, sizeof(a->received), 0);
	return NULL;
}
int main(void)
{
	struct actor actors[2] = {0};
	pthread_t threads[2];
	unsigned corrupt = 0;
	assert(!pthread_barrier_init(&attempted_admission, NULL, 2));
	assert(!pthread_barrier_init(&writes_complete, NULL, 2));
	for (unsigned i = 0; i < 2; i++) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		socklen_t len = sizeof(addr);
		struct timeval timeout = {.tv_sec = 3};
		struct actor *a = &actors[i];
		a->rx = socket(AF_INET, SOCK_DGRAM, 0);
		a->tx = socket(AF_INET, SOCK_DGRAM, 0);
		assert(a->rx >= 0 && a->tx >= 0);
		assert(!setsockopt(a->rx, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
		assert(!bind(a->rx, (void *)&addr, sizeof(addr)));
		assert(!getsockname(a->rx, (void *)&addr, &len));
		assert(!connect(a->tx, (void *)&addr, len));
		memset(a->expected, 0x71+i, sizeof(a->expected));
		assert(!pthread_create(&threads[i], NULL, send_one, a));
	}
	for (unsigned i = 0; i < 2; i++) {
		struct actor *a = &actors[i];
		assert(!pthread_join(threads[i], NULL));
		bool same = a->received_len == (ssize_t)sizeof(a->expected) &&
			!memcmp(a->expected, a->received, sizeof(a->expected));
		printf("actor=%u send_ret=%zd recv_ret=%zd full_compare=%u calls=%llu errors=%llu "
		       "stage_completed=%llu,%llu,%llu ce_addr=%llu ce_len=%llu\n", i,
		       a->sent, a->received_len, same,
		       (unsigned long long)a->runtime.calls, (unsigned long long)a->runtime.errors,
		       (unsigned long long)a->runtime.completed[0], (unsigned long long)a->runtime.completed[1],
		       (unsigned long long)a->runtime.completed[2],
		       (unsigned long long)sessions[a->runtime.ring].ce_addr,
		       (unsigned long long)sessions[a->runtime.ring].ce_len);
		assert(a->sent == 9 && a->received_len == 9 && a->runtime.calls == 1 && !a->runtime.errors);
		corrupt += !same;
		assert(!xdev_ext_socket_mech_release(&a->runtime));
		close(a->rx); close(a->tx);
	}
	assert(!pthread_barrier_destroy(&writes_complete));
	assert(!pthread_barrier_destroy(&attempted_admission));
	if (corrupt) {
		fprintf(stderr, "not ok - actual two-thread CE runtimes reused one native window; %u payload corrupted despite completed stages\n", corrupt);
		return 1;
	}
	puts("ok - concurrent CE runtimes preserve every UDP payload byte");
	return 0;
}

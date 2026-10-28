// SPDX-License-Identifier: GPL-2.0
/*
 * Cancellation and the transparent front end.
 *
 * "wait" mode: a deferred cancellation request that arrives while a taken-over
 * pread or preadv waits for its CQE must not act inside the front end.  The
 * published request runs to its terminal completion, the front end releases
 * its duplicate descriptor, the call returns its result, and the cancellation
 * acts at the caller's next cancellation point.  Run under
 * LD_PRELOAD=libio_uring_unified.so:libxdev_ext_preload_kernel_model.so with
 * XDEV_EXT_MODEL_UMEM=1, XDEV_EXT_MODEL_DIOALIGN, XDEV_EXT_PRELOAD_ENABLED=1 and
 * XDEV_EXT_PRELOAD_PATHS=<file>.
 *
 * "state" mode: every scalar and vectored positional call on the allowlisted
 * file, whether it is taken over or falls back at any admission step, returns
 * with the caller's cancellation state unchanged, both when the caller has
 * cancellation enabled and when it has it disabled.  It needs no model hooks
 * and runs under any front-end configuration.
 *
 * "entry" mode: for every exported positional entry point, a cancellation
 * pending at entry acts there, where the libc entry point would act on it:
 * the call does not return, no descriptor is left open, and no cancelled
 * write reaches the file.  Run it with the model's XDEV_EXT_MODEL_UMEM=1 so that
 * each call would otherwise be taken over; it then first checks that each
 * entry point, called with nothing pending, makes exactly one READ_COMPAT or
 * WRITE_COMPAT SQE, that a cleanup handler run by a cancellation at entry of
 * pread or send is still taken over (one READ_COMPAT SQE), and that no
 * cancelled call publishes an SQE.
 *
 * "return-pending" mode: a thread makes one pread on the allowlisted file,
 * gets a cancellation request from another thread after its last
 * cancellation point, and then returns normally.  pthread_join() must report
 * the value it returned, not PTHREAD_CANCELED, and no descriptor may be left
 * open: the front end's teardown of the thread's ring, which runs after the
 * return, does not act on the request.  Three rounds, so a leak adds up.
 * With XDEV_EXT_MODEL_UMEM=1 each pread must make exactly one READ_COMPAT SQE, so
 * the thread owns a ring; it also runs under libc and with registration
 * rejected.
 *
 * The send modes cover send, sendto and sendmsg, which are cancellation
 * points too.  They run with or without XDEV_EXT_PRELOAD_SOCKET_ENABLED=1 and need
 * the model loaded (for its SEND counter); the file argument is only set up.
 *   "send-entry": a cancellation pending at entry acts there, before the front
 *	end duplicates the descriptor or publishes an SQE: the call does not
 *	return, no descriptor is left open, and nothing reaches the peer.  On a
 *	connected UDP socket (eligible) and an AF_UNIX datagram pair (not).
 *   "send-wait": a cancellation that arrives while a taken-over send waits
 *	for its CQE acts after the call returned the CQE's result, and no
 *	descriptor is left open.  Needs XDEV_EXT_MODEL_UMEM=1 and socket takeover.
 *   "send-blocked": a cancellation that arrives while the libc send on the
 *	front end's duplicate (AF_UNIX stream pair, full buffer) is blocked acts
 *	there, as it would in libc, no descriptor is left open, and the caller's
 *	descriptor stays open.
 *   "send-seam": with XDEV_EXT_MODEL_UMEM=1 and XDEV_EXT_MODEL_SQ_BUSY=1 the front end
 *	takes a connected UDP send over, finds its SQ busy, and sends with libc
 *	on its duplicate before publishing anything.  Uncancelled, the datagram
 *	arrives once and no SEND SQE is made; a cancellation that arrives while
 *	the ring is being registered acts in that libc send, nothing reaches
 *	the peer, no descriptor is left open, and the caller's descriptor stays
 *	open.  With XDEV_EXT_MODEL_REJECT_UMEM=1 instead of XDEV_EXT_MODEL_UMEM=1 the
 *	model rejects the held registration, whatever the host kernel would
 *	answer, and the same checks cover the libc send on the duplicate after
 *	ring setup failed: the cancellation must not act inside ring setup.
 *   "send-state": every send kind on every path returns with the caller's
 *	cancellation state unchanged, also on a descriptor the front end
 *	cannot duplicate (closed, or -1), where the call returns EBADF.  A send
 *	on a valid socket returns the full length and the peer gets exactly one
 *	datagram, also at the descriptor limit, where the front end cannot
 *	duplicate the socket and libc sends on the caller's descriptor.  A
 *	caller that has cancellation disabled and a request pending sends in
 *	full, and the request acts only once the caller enables cancellation
 *	again: the front end's libc send on its duplicate runs in the caller's
 *	own cancellation state.
 *   "send-close": a cancellation that arrives after the libc send on the
 *	front end's duplicate (or the published send) returned, while the front
 *	end closes its duplicate, acts after the call returned the full length:
 *	the close runs, no descriptor is left open, and the peer gets exactly
 *	one datagram.  The model holds that close() until the request is made.
 *	Run with socket takeover, and with XDEV_EXT_MODEL_UMEM=1 or
 *	XDEV_EXT_MODEL_REJECT_UMEM=1; the connected UDP pair only with
 *	XDEV_EXT_MODEL_UMEM=1, because with the registration rejected the first
 *	close() in the sending thread is the failed ring's, which "send-seam"
 *	already covers.
 * "send-seam", "send-state" and "send-close" also require that no close()
 * fails with EBADF (a descriptor closed twice), as counted by the model.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define CANCEL_WAIT_LENGTH 4096U
#define CANCEL_WAIT_FD_SCAN 1024
#define CANCEL_WAIT_FD_LIMIT 64
#define CANCEL_WAIT_TIMEOUT_S 5

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct reader {
	int fd;
	bool vectored;
	unsigned char *buffer;
	ssize_t result;
	bool returned;
};

struct state_case {
	const char *what;
	bool buffered;
	size_t offset;
	size_t length;
};

typedef int (*hook_fn)(void);
typedef uint64_t (*count_fn)(void);

static hook_fn block;
static hook_fn block_registration;
static hook_fn wait_blocked;
static hook_fn release;
static hook_fn block_close;
static count_fn read_requests;
static count_fn write_requests;
static count_fn send_requests;
static count_fn ebadf_closes;

static void *reader_main(void *opaque)
{
	struct reader *reader = opaque;
	struct iovec iov = {
		.iov_base = reader->buffer,
		.iov_len = CANCEL_WAIT_LENGTH,
	};

	if (reader->vectored)
		reader->result = preadv(reader->fd, &iov, 1, 0);
	else
		reader->result = pread(reader->fd, reader->buffer,
				       CANCEL_WAIT_LENGTH, 0);
	reader->returned = true;
	pthread_testcancel();
	return NULL;
}

static int open_fd_count(void)
{
	int count = 0;
	int fd;

	for (fd = 0; fd < CANCEL_WAIT_FD_SCAN; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			count++;
	return count;
}

static int fail(const char *message)
{
	fprintf(stderr, "XDEV_EXT_PRELOAD_CANCEL_WAIT=FAIL %s\n", message);
	return 1;
}

static int wait_scenario(int fd, const unsigned char *pattern, bool vectored)
{
	struct reader reader = {
		.fd = fd,
		.vectored = vectored,
		.result = -1,
	};
	pthread_t thread;
	uint64_t requests;
	void *result = NULL;
	int before;
	int after;
	int ret = 0;

	if (posix_memalign((void **)&reader.buffer, CANCEL_WAIT_LENGTH,
			   CANCEL_WAIT_LENGTH))
		return fail("posix_memalign");
	memset(reader.buffer, 0, CANCEL_WAIT_LENGTH);
	fprintf(stderr, "call=%s\n", vectored ? "preadv" : "pread");
	requests = read_requests();
	before = open_fd_count();
	block();
	if (pthread_create(&thread, NULL, reader_main, &reader)) {
		free(reader.buffer);
		return fail("pthread_create");
	}
	if (wait_blocked()) {
		release();
		pthread_join(thread, NULL);
		free(reader.buffer);
		return fail("the call was not taken over");
	}
	pthread_cancel(thread);
	release();
	if (pthread_join(thread, &result)) {
		free(reader.buffer);
		return fail("pthread_join");
	}
	after = open_fd_count();
	if (result != PTHREAD_CANCELED) {
		ret = fail("the cancellation request was lost");
	} else if (after != before) {
		fprintf(stderr, "descriptors before=%d after=%d\n", before,
			after);
		ret = fail("the front end left a descriptor open");
	} else if (!reader.returned ||
		   reader.result != (ssize_t)CANCEL_WAIT_LENGTH ||
		   memcmp(reader.buffer, pattern, CANCEL_WAIT_LENGTH)) {
		ret = fail("the published request did not complete before the cancellation acted");
	} else if (read_requests() != requests + 1) {
		ret = fail("expected exactly one READ_COMPAT request");
	}
	free(reader.buffer);
	return ret;
}

static int wait_mode(const char *path, int fd, const unsigned char *pattern)
{
	unsigned char *buffer = NULL;
	int ret = 0;

	(void)path;
	block = (hook_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_block_next_request");
	wait_blocked = (hook_fn)dlsym(RTLD_DEFAULT,
				      "xdev_ext_model_wait_until_blocked");
	release = (hook_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_release_request");
	read_requests = (count_fn)dlsym(RTLD_DEFAULT,
					"xdev_ext_model_read_requests");
	if (!block || !wait_blocked || !release || !read_requests)
		return fail("kernel model hooks are not loaded");
	if (wait_scenario(fd, pattern, false) ||
	    wait_scenario(fd, pattern, true))
		return 1;
	if (posix_memalign((void **)&buffer, CANCEL_WAIT_LENGTH,
			   CANCEL_WAIT_LENGTH))
		return fail("posix_memalign");
	memset(buffer, 0, CANCEL_WAIT_LENGTH);
	if (pread(fd, buffer, CANCEL_WAIT_LENGTH, 0) !=
	    (ssize_t)CANCEL_WAIT_LENGTH ||
	    memcmp(buffer, pattern, CANCEL_WAIT_LENGTH))
		ret = fail("the front end is unusable after the cancellation");
	free(buffer);
	return ret;
}

/* The two cancellation states a caller can have. */
static const int caller_states[] = {
	PTHREAD_CANCEL_ENABLE,
	PTHREAD_CANCEL_DISABLE,
};

/*
 * Each case reaches a different exit of the front end: a takeover (or, with
 * registration rejected, the ring-setup fallback), the alignment check, the
 * one-frame check, and the descriptor check on a buffered descriptor.
 */
static const struct state_case state_cases[] = {
	{ "one frame", false, 0, CANCEL_WAIT_LENGTH },
	{ "misaligned buffer", false, 1, CANCEL_WAIT_LENGTH },
	{ "two frames", false, 0, 2 * CANCEL_WAIT_LENGTH },
	{ "buffered descriptor", true, 0, CANCEL_WAIT_LENGTH },
};

static int state_check(int fd, unsigned char *buffer, bool vectored,
		       int caller_state, const struct state_case *c)
{
	struct iovec iov = {
		.iov_base = buffer + c->offset,
		.iov_len = c->length,
	};
	int old = -1;

	pthread_setcancelstate(caller_state, NULL);
	/* Only the cancellation state is checked here; results may differ. */
	if (vectored)
		(void)!preadv(fd, &iov, 1, 0);
	else
		(void)!pread(fd, buffer + c->offset, c->length, 0);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old);
	if (old == caller_state)
		return 0;
	fprintf(stderr, "%s, %s: caller had cancellation %s, call left it %s\n",
		vectored ? "preadv" : "pread", c->what,
		caller_state == PTHREAD_CANCEL_ENABLE ? "enabled" : "disabled",
		old == PTHREAD_CANCEL_ENABLE ? "enabled" : "disabled");
	return fail("a positional call changed the caller's cancellation state");
}

static int state_mode(const char *path, int fd, const unsigned char *pattern)
{
	unsigned char *buffer = NULL;
	unsigned int s;
	unsigned int v;
	unsigned int i;
	int buffered;
	int ret = 0;

	(void)pattern;
	buffered = open(path, O_RDWR);
	if (buffered < 0)
		return fail("open buffered");
	if (posix_memalign((void **)&buffer, CANCEL_WAIT_LENGTH,
			   3 * CANCEL_WAIT_LENGTH)) {
		close(buffered);
		return fail("posix_memalign");
	}
	for (s = 0; s < 2 && !ret; s++)
		for (v = 0; v < 2 && !ret; v++)
			for (i = 0; i < ARRAY_SIZE(state_cases) && !ret; i++)
				ret = state_check(state_cases[i].buffered ?
						  buffered : fd, buffer, v,
						  caller_states[s],
						  &state_cases[i]);
	close(buffered);
	free(buffer);
	return ret;
}

enum send_kind {
	SEND_PLAIN,
	SEND_TO,
	SEND_MSG,
	SEND_KINDS,
};

static const char *const send_names[SEND_KINDS] = {
	"send", "sendto", "sendmsg",
};

static const char send_payload[] = "cancel-send";

struct sender {
	int fd;
	enum send_kind kind;
	bool cancel_first;
	pid_t tid;
	ssize_t result;
	bool returned;
};

struct socket_pair {
	const char *what;
	int receiver;
	int sender;
};

static ssize_t send_one(int fd, enum send_kind kind)
{
	struct iovec iov = {
		.iov_base = (void *)send_payload,
		.iov_len = sizeof(send_payload),
	};
	struct msghdr message = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	switch (kind) {
	case SEND_PLAIN:
		return send(fd, send_payload, sizeof(send_payload), 0);
	case SEND_TO:
		return sendto(fd, send_payload, sizeof(send_payload), 0, NULL,
			      0);
	default:
		return sendmsg(fd, &message, 0);
	}
}

static void *sender_main(void *opaque)
{
	struct sender *sender = opaque;

	__atomic_store_n(&sender->tid, (pid_t)syscall(SYS_gettid),
			 __ATOMIC_RELEASE);
	if (sender->cancel_first)
		pthread_cancel(pthread_self());
	sender->result = send_one(sender->fd, sender->kind);
	sender->returned = true;
	pthread_testcancel();
	return NULL;
}

static void close_pair(struct socket_pair *pair)
{
	if (pair->sender >= 0)
		close(pair->sender);
	if (pair->receiver >= 0)
		close(pair->receiver);
	pair->sender = -1;
	pair->receiver = -1;
}

/* A loopback receiver and a sender connected to it: eligible for takeover. */
static int udp_pair(struct socket_pair *pair)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t length = sizeof(address);

	pair->what = "connected UDP";
	pair->receiver = socket(AF_INET, SOCK_DGRAM, 0);
	pair->sender = socket(AF_INET, SOCK_DGRAM, 0);
	if (pair->receiver < 0 || pair->sender < 0 ||
	    bind(pair->receiver, (struct sockaddr *)&address,
		 sizeof(address)) ||
	    getsockname(pair->receiver, (struct sockaddr *)&address,
			&length) ||
	    connect(pair->sender, (struct sockaddr *)&address,
		    sizeof(address))) {
		close_pair(pair);
		return -1;
	}
	return 0;
}

static int unix_pair(struct socket_pair *pair, int type)
{
	int fds[2];

	pair->what = type == SOCK_STREAM ? "AF_UNIX stream" :
					   "AF_UNIX datagram";
	pair->receiver = -1;
	pair->sender = -1;
	if (socketpair(AF_UNIX, type, 0, fds))
		return -1;
	pair->receiver = fds[0];
	pair->sender = fds[1];
	return 0;
}

/* 0 when nothing is queued at the receiver, 1 when something is. */
static int peer_has_data(int receiver)
{
	unsigned char buffer[256];

	if (recv(receiver, buffer, sizeof(buffer), MSG_DONTWAIT) >= 0)
		return 1;
	return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : 1;
}

static void drain_peer(int receiver)
{
	while (peer_has_data(receiver))
		;
}

static int send_case_fail(const struct socket_pair *pair, enum send_kind kind,
			  const char *message)
{
	fprintf(stderr, "%s, %s: %s\n", send_names[kind], pair->what,
		message);
	return 1;
}

/* A cancelled libc send on the duplicate closes only the duplicate. */
static int caller_fd_closed(const struct socket_pair *pair,
			    enum send_kind kind)
{
	if (fcntl(pair->sender, F_GETFD) != -1)
		return 0;
	return send_case_fail(pair, kind, "the caller's descriptor was closed");
}

static int load_send_counter(void)
{
	send_requests = (count_fn)dlsym(RTLD_DEFAULT,
					"xdev_ext_model_send_requests");
	if (!send_requests)
		return fail("kernel model hooks are not loaded");
	return 0;
}

static int load_close_counter(void)
{
	ebadf_closes = (count_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_ebadf_closes");
	if (!ebadf_closes)
		return fail("kernel model hooks are not loaded");
	return 0;
}

/* A close() that fails with EBADF closed a descriptor a second time. */
static int closed_twice(uint64_t before)
{
	uint64_t count = ebadf_closes() - before;

	if (!count)
		return 0;
	fprintf(stderr, "a descriptor was closed twice: close() failed with EBADF %llu times\n",
		(unsigned long long)count);
	return 1;
}

static int send_entry_case(struct socket_pair *pair, enum send_kind kind)
{
	struct sender sender = {
		.fd = pair->sender,
		.kind = kind,
		.cancel_first = true,
		.result = -1,
	};
	pthread_t thread;
	uint64_t requests = send_requests();
	void *result = NULL;
	int before = open_fd_count();
	int after;
	int failures = 0;

	if (pthread_create(&thread, NULL, sender_main, &sender) ||
	    pthread_join(thread, &result))
		return send_case_fail(pair, kind, "pthread_create/join");
	after = open_fd_count();
	if (result != PTHREAD_CANCELED || sender.returned)
		failures += send_case_fail(pair, kind,
			"a pending cancellation did not act at entry");
	if (after != before) {
		fprintf(stderr, "descriptors before=%d after=%d\n", before,
			after);
		failures += send_case_fail(pair, kind,
			"the front end left a descriptor open");
	}
	if (peer_has_data(pair->receiver)) {
		drain_peer(pair->receiver);
		failures += send_case_fail(pair, kind,
			"a cancelled send reached the peer");
	}
	if (send_requests() != requests)
		failures += send_case_fail(pair, kind,
			"a cancelled send published an SQE");
	return failures;
}

static int send_entry_mode(void)
{
	struct socket_pair pairs[2];
	unsigned int p;
	unsigned int k;
	int failures = 0;

	if (load_send_counter())
		return 1;
	if (udp_pair(&pairs[0]))
		return fail("connected UDP setup");
	if (unix_pair(&pairs[1], SOCK_DGRAM)) {
		close_pair(&pairs[0]);
		return fail("AF_UNIX datagram setup");
	}
	for (p = 0; p < 2; p++)
		for (k = 0; k < SEND_KINDS; k++)
			failures += send_entry_case(&pairs[p], k);
	close_pair(&pairs[0]);
	close_pair(&pairs[1]);
	if (failures)
		return fail("a send did not act on a pending cancellation at entry");
	return 0;
}

static int send_wait_case(struct socket_pair *pair, enum send_kind kind)
{
	struct sender sender = {
		.fd = pair->sender,
		.kind = kind,
		.result = -1,
	};
	unsigned char received[sizeof(send_payload) + 1];
	pthread_t thread;
	uint64_t requests = send_requests();
	void *result = NULL;
	ssize_t length;
	int before = open_fd_count();
	int after;
	int failures = 0;

	block();
	if (pthread_create(&thread, NULL, sender_main, &sender)) {
		release();
		return send_case_fail(pair, kind, "pthread_create");
	}
	if (wait_blocked()) {
		release();
		pthread_join(thread, NULL);
		drain_peer(pair->receiver);
		return send_case_fail(pair, kind,
				      "the send was not taken over");
	}
	pthread_cancel(thread);
	release();
	if (pthread_join(thread, &result))
		return send_case_fail(pair, kind, "pthread_join");
	after = open_fd_count();
	if (result != PTHREAD_CANCELED)
		failures += send_case_fail(pair, kind,
			"the cancellation request was lost");
	if (after != before) {
		fprintf(stderr, "descriptors before=%d after=%d\n", before,
			after);
		failures += send_case_fail(pair, kind,
			"the front end left a descriptor open");
	}
	if (!sender.returned ||
	    sender.result != (ssize_t)sizeof(send_payload))
		failures += send_case_fail(pair, kind,
			"the published send did not complete before the cancellation acted");
	length = recv(pair->receiver, received, sizeof(received),
		      MSG_DONTWAIT);
	if (length != (ssize_t)sizeof(send_payload) ||
	    memcmp(received, send_payload, sizeof(send_payload)) ||
	    peer_has_data(pair->receiver))
		failures += send_case_fail(pair, kind,
			"the peer did not receive exactly one datagram");
	if (send_requests() != requests + 1)
		failures += send_case_fail(pair, kind,
			"expected exactly one SEND request");
	return failures;
}

static int send_wait_mode(void)
{
	struct socket_pair pair;
	unsigned int k;
	int failures = 0;

	block = (hook_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_block_next_request");
	wait_blocked = (hook_fn)dlsym(RTLD_DEFAULT,
				      "xdev_ext_model_wait_until_blocked");
	release = (hook_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_release_request");
	if (!block || !wait_blocked || !release || load_send_counter())
		return fail("kernel model hooks are not loaded");
	if (udp_pair(&pair))
		return fail("connected UDP setup");
	for (k = 0; k < SEND_KINDS; k++)
		failures += send_wait_case(&pair, k);
	close_pair(&pair);
	if (failures)
		return fail("a cancellation during a taken-over send was mishandled");
	return 0;
}

static bool is_send_syscall(long number)
{
#ifdef SYS_send
	if (number == SYS_send)
		return true;
#endif
	return number == SYS_sendto || number == SYS_sendmsg;
}

/* Wait until the thread sleeps inside a send system call. */
static int wait_in_send_syscall(const struct sender *sender)
{
	struct timespec pause = { .tv_nsec = 1000000 };
	char path[64];
	char line[64];
	pid_t tid;
	int tries;

	for (tries = 0; tries < CANCEL_WAIT_TIMEOUT_S * 1000; tries++) {
		FILE *file;
		char *end;
		long number;

		tid = __atomic_load_n(&sender->tid, __ATOMIC_ACQUIRE);
		if (tid) {
			snprintf(path, sizeof(path),
				 "/proc/self/task/%ld/syscall", (long)tid);
			file = fopen(path, "r");
			if (file) {
				if (fgets(line, sizeof(line), file)) {
					number = strtol(line, &end, 10);
					if (end != line && *end == ' ' &&
					    is_send_syscall(number)) {
						fclose(file);
						return 0;
					}
				}
				fclose(file);
			}
		}
		nanosleep(&pause, NULL);
	}
	return -1;
}

/* Fill the sender's buffer so that the next blocking send sleeps. */
static int fill_stream(int fd)
{
	static const unsigned char chunk[4096];
	int sndbuf = 4096;

	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)))
		return -1;
	while (send(fd, chunk, sizeof(chunk), MSG_DONTWAIT) > 0)
		;
	if (errno != EAGAIN && errno != EWOULDBLOCK)
		return -1;
	while (send(fd, chunk, 1, MSG_DONTWAIT) > 0)
		;
	return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
}

static int send_blocked_case(struct socket_pair *pair, enum send_kind kind)
{
	struct sender sender = {
		.fd = pair->sender,
		.kind = kind,
		.result = -1,
	};
	struct timespec deadline;
	pthread_t thread;
	void *result = NULL;
	int before = open_fd_count();
	int after;
	int failures = 0;
	int ret;

	if (pthread_create(&thread, NULL, sender_main, &sender))
		return send_case_fail(pair, kind, "pthread_create");
	if (wait_in_send_syscall(&sender))
		failures += send_case_fail(pair, kind,
			"the send never slept in a send system call");
	pthread_cancel(thread);
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += CANCEL_WAIT_TIMEOUT_S;
	ret = pthread_timedjoin_np(thread, &result, &deadline);
	if (ret == ETIMEDOUT) {
		failures += send_case_fail(pair, kind,
			"the blocked send did not act on the cancellation");
		drain_peer(pair->receiver);
		ret = pthread_join(thread, &result);
	}
	if (ret)
		return failures + send_case_fail(pair, kind, "pthread_join");
	after = open_fd_count();
	if (result != PTHREAD_CANCELED || sender.returned)
		failures += send_case_fail(pair, kind,
			"the cancellation did not act inside the blocked send");
	if (after != before) {
		fprintf(stderr, "descriptors before=%d after=%d\n", before,
			after);
		failures += send_case_fail(pair, kind,
			"the front end left a descriptor open");
	}
	return failures + caller_fd_closed(pair, kind);
}

static int send_blocked_mode(void)
{
	struct socket_pair pair;
	unsigned int k;
	int failures = 0;

	if (unix_pair(&pair, SOCK_STREAM))
		return fail("AF_UNIX stream setup");
	for (k = 0; k < SEND_KINDS; k++) {
		if (fill_stream(pair.sender)) {
			close_pair(&pair);
			return fail("could not fill the AF_UNIX stream buffer");
		}
		failures += send_blocked_case(&pair, k);
	}
	close_pair(&pair);
	if (failures)
		return fail("a cancellation during a blocked send was mishandled");
	return 0;
}

/* Publication refused (XDEV_EXT_MODEL_SQ_BUSY=1): libc on the duplicate instead. */
static int send_seam_sent(struct socket_pair *pair, enum send_kind kind)
{
	struct sender sender = {
		.fd = pair->sender,
		.kind = kind,
		.result = -1,
	};
	unsigned char received[sizeof(send_payload) + 1];
	pthread_t thread;
	uint64_t requests = send_requests();
	void *result = NULL;
	ssize_t length;
	int before = open_fd_count();
	int failures = 0;

	if (pthread_create(&thread, NULL, sender_main, &sender) ||
	    pthread_join(thread, &result))
		return send_case_fail(pair, kind, "pthread_create/join");
	if (result == PTHREAD_CANCELED || !sender.returned ||
	    sender.result != (ssize_t)sizeof(send_payload))
		failures += send_case_fail(pair, kind,
			"the send whose publication was refused failed");
	if (open_fd_count() != before)
		failures += send_case_fail(pair, kind,
			"the front end left a descriptor open");
	length = recv(pair->receiver, received, sizeof(received),
		      MSG_DONTWAIT);
	if (length != (ssize_t)sizeof(send_payload) ||
	    memcmp(received, send_payload, sizeof(send_payload)) ||
	    peer_has_data(pair->receiver))
		failures += send_case_fail(pair, kind,
			"the peer did not receive exactly one datagram");
	if (send_requests() != requests)
		failures += send_case_fail(pair, kind,
			"a SEND SQE was published");
	return failures;
}

/* A cancellation that arrives while the front end holds its duplicate. */
static int send_seam_cancelled(struct socket_pair *pair, enum send_kind kind)
{
	struct sender sender = {
		.fd = pair->sender,
		.kind = kind,
		.result = -1,
	};
	pthread_t thread;
	uint64_t requests = send_requests();
	void *result = NULL;
	int before = open_fd_count();
	int after;
	int failures = 0;

	block_registration();
	if (pthread_create(&thread, NULL, sender_main, &sender)) {
		release();
		return send_case_fail(pair, kind, "pthread_create");
	}
	if (wait_blocked()) {
		release();
		pthread_join(thread, NULL);
		drain_peer(pair->receiver);
		return send_case_fail(pair, kind,
				      "the send did not register a ring");
	}
	pthread_cancel(thread);
	release();
	if (pthread_join(thread, &result))
		return send_case_fail(pair, kind, "pthread_join");
	after = open_fd_count();
	if (result != PTHREAD_CANCELED || sender.returned)
		failures += send_case_fail(pair, kind,
			"the cancellation did not act in the libc send");
	if (after != before) {
		fprintf(stderr, "descriptors before=%d after=%d\n", before,
			after);
		failures += send_case_fail(pair, kind,
			"the front end left a descriptor open");
	}
	failures += caller_fd_closed(pair, kind);
	if (peer_has_data(pair->receiver)) {
		drain_peer(pair->receiver);
		failures += send_case_fail(pair, kind,
			"a cancelled send reached the peer");
	}
	if (send_requests() != requests)
		failures += send_case_fail(pair, kind,
			"a SEND SQE was published");
	return failures;
}

static int send_seam_mode(void)
{
	struct socket_pair pair;
	uint64_t closes;
	unsigned int k;
	int failures = 0;

	block_registration = (hook_fn)dlsym(RTLD_DEFAULT,
				"xdev_ext_model_block_next_registration");
	wait_blocked = (hook_fn)dlsym(RTLD_DEFAULT,
				      "xdev_ext_model_wait_until_blocked");
	release = (hook_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_release_request");
	if (!block_registration || !wait_blocked || !release ||
	    load_send_counter() || load_close_counter())
		return fail("kernel model hooks are not loaded");
	if (udp_pair(&pair))
		return fail("connected UDP setup");
	closes = ebadf_closes();
	for (k = 0; k < SEND_KINDS; k++) {
		failures += send_seam_sent(&pair, k);
		failures += send_seam_cancelled(&pair, k);
	}
	failures += closed_twice(closes);
	close_pair(&pair);
	if (failures)
		return fail("a send whose publication was refused was mishandled");
	return 0;
}

static int send_state_changed(const struct socket_pair *pair,
			      enum send_kind kind, int caller_state, int old)
{
	if (old == caller_state)
		return 0;
	if (caller_state == PTHREAD_CANCEL_ENABLE)
		return send_case_fail(pair, kind,
				      "caller had cancellation enabled, the call left it disabled");
	return send_case_fail(pair, kind,
			      "caller had cancellation disabled, the call left it enabled");
}

/*
 * One send with the caller's cancellation state set to caller_state; counts a
 * failure if the call changed it.  Returns the send's result and keeps errno.
 */
static ssize_t send_in_state(const struct socket_pair *pair,
			     enum send_kind kind, int caller_state,
			     int *failures)
{
	ssize_t ret;
	int error;
	int old = -1;

	pthread_setcancelstate(caller_state, NULL);
	errno = 0;
	ret = send_one(pair->sender, kind);
	error = errno;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old);
	*failures += send_state_changed(pair, kind, caller_state, old);
	errno = error;
	return ret;
}

/* The send returned the full length and the peer got exactly one datagram. */
static int send_delivered_once(const struct socket_pair *pair,
			       enum send_kind kind, ssize_t ret, int error)
{
	unsigned char received[sizeof(send_payload) + 1];
	ssize_t length;

	if (ret != (ssize_t)sizeof(send_payload)) {
		fprintf(stderr, "%s, %s: the send returned %zd (errno %d)\n",
			send_names[kind], pair->what, ret, error);
		drain_peer(pair->receiver);
		return 1;
	}
	length = recv(pair->receiver, received, sizeof(received),
		      MSG_DONTWAIT);
	if (length == (ssize_t)sizeof(send_payload) &&
	    !memcmp(received, send_payload, sizeof(send_payload)) &&
	    !peer_has_data(pair->receiver))
		return 0;
	drain_peer(pair->receiver);
	return send_case_fail(pair, kind,
			      "the peer did not receive exactly one datagram");
}

/* A valid socket: the full length, and exactly one datagram at the peer. */
static int send_valid_case(const struct socket_pair *pair,
			   enum send_kind kind, int caller_state)
{
	int failures = 0;
	ssize_t ret = send_in_state(pair, kind, caller_state, &failures);

	return failures + send_delivered_once(pair, kind, ret, errno);
}

/*
 * A descriptor the front end cannot duplicate: -1 with EBADF.  With live >= 0
 * the call uses a number that was just freed (a closed duplicate of live).
 */
static int send_invalid_case(struct socket_pair *pair, enum send_kind kind,
			     int caller_state, int live)
{
	int failures = 0;
	ssize_t ret;

	if (live >= 0) {
		int spare = dup(live);

		if (spare < 0 || close(spare))
			return send_case_fail(pair, kind, "dup/close setup");
		pair->sender = spare;
	}
	ret = send_in_state(pair, kind, caller_state, &failures);
	if (ret != -1 || errno != EBADF)
		failures += send_case_fail(pair, kind,
					   "expected -1 with EBADF");
	return failures;
}

/*
 * At the descriptor limit the front end cannot duplicate a valid socket; the
 * send still goes to libc on the caller's descriptor and delivers once.
 */
static int send_at_limit(const struct socket_pair *pairs)
{
	struct socket_pair limited[2] = { pairs[0], pairs[1] };
	int fillers[CANCEL_WAIT_FD_LIMIT];
	struct rlimit saved;
	struct rlimit limit;
	unsigned int filled = 0;
	unsigned int s;
	unsigned int p;
	unsigned int k;
	int failures = 0;
	int spare;
	bool full;

	limited[0].what = "connected UDP at the descriptor limit";
	limited[1].what = "AF_UNIX datagram at the descriptor limit";
	if (getrlimit(RLIMIT_NOFILE, &saved))
		return fail("getrlimit");
	limit = saved;
	limit.rlim_cur = CANCEL_WAIT_FD_LIMIT;
	if (setrlimit(RLIMIT_NOFILE, &limit))
		return fail("setrlimit");
	while (filled < CANCEL_WAIT_FD_LIMIT) {
		int filler = open("/dev/null", O_RDONLY | O_CLOEXEC);

		if (filler < 0)
			break;
		fillers[filled++] = filler;
	}
	/* The front end duplicates with F_DUPFD_CLOEXEC from descriptor 3. */
	spare = fcntl(limited[0].sender, F_DUPFD_CLOEXEC, 3);
	full = spare < 0 && errno == EMFILE;
	if (!full) {
		if (spare >= 0)
			close(spare);
		fprintf(stderr, "could not fill the descriptor table\n");
		failures++;
	}
	for (s = 0; full && s < 2; s++)
		for (p = 0; p < 2; p++)
			for (k = 0; k < SEND_KINDS; k++)
				failures += send_valid_case(&limited[p], k,
							    caller_states[s]);
	while (filled)
		close(fillers[--filled]);
	if (setrlimit(RLIMIT_NOFILE, &saved))
		failures += fail("setrlimit restore");
	return failures;
}

/* Cancellation disabled and a request pending: it acts once re-enabled. */
static void *pending_main(void *opaque)
{
	struct sender *sender = opaque;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_cancel(pthread_self());
	sender->result = send_one(sender->fd, sender->kind);
	sender->returned = true;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_testcancel();
	return NULL;
}

static int send_pending_case(const struct socket_pair *pair,
			     enum send_kind kind)
{
	struct sender sender = {
		.fd = pair->sender,
		.kind = kind,
		.result = -1,
	};
	pthread_t thread;
	void *result = NULL;
	int before = open_fd_count();
	int after;
	int failures = 0;

	if (pthread_create(&thread, NULL, pending_main, &sender) ||
	    pthread_join(thread, &result))
		return send_case_fail(pair, kind, "pthread_create/join");
	after = open_fd_count();
	if (!sender.returned) {
		drain_peer(pair->receiver);
		failures += send_case_fail(pair, kind,
			"a caller with cancellation disabled was cancelled inside the send");
	} else {
		if (result != PTHREAD_CANCELED)
			failures += send_case_fail(pair, kind,
				"the cancellation request was lost");
		failures += send_delivered_once(pair, kind, sender.result, 0);
	}
	if (after != before) {
		fprintf(stderr, "descriptors before=%d after=%d\n", before,
			after);
		failures += send_case_fail(pair, kind,
			"the front end left a descriptor open");
	}
	return failures;
}

static int send_state_mode(void)
{
	struct socket_pair pairs[2];
	/* The front end cannot duplicate these; libc reports EBADF. */
	struct socket_pair invalid[2] = {
		{ .what = "closed descriptor", .receiver = -1 },
		{ .what = "descriptor -1", .receiver = -1, .sender = -1 },
	};
	uint64_t closes;
	unsigned int s;
	unsigned int p;
	unsigned int k;
	int failures = 0;
	int live;

	if (load_close_counter())
		return 1;
	if (udp_pair(&pairs[0]))
		return fail("connected UDP setup");
	if (unix_pair(&pairs[1], SOCK_DGRAM)) {
		close_pair(&pairs[0]);
		return fail("AF_UNIX datagram setup");
	}
	closes = ebadf_closes();
	for (s = 0; s < 2; s++)
		for (p = 0; p < 2; p++)
			for (k = 0; k < SEND_KINDS; k++)
				failures += send_valid_case(&pairs[p], k,
							    caller_states[s]);
	for (p = 0; p < 2; p++)
		for (k = 0; k < SEND_KINDS; k++)
			failures += send_pending_case(&pairs[p], k);
	live = pairs[0].sender;
	for (s = 0; s < 2; s++)
		for (p = 0; p < 2; p++)
			for (k = 0; k < SEND_KINDS; k++)
				failures += send_invalid_case(&invalid[p], k,
							      caller_states[s],
							      p ? -1 : live);
	failures += send_at_limit(pairs);
	failures += closed_twice(closes);
	close_pair(&pairs[0]);
	close_pair(&pairs[1]);
	if (failures)
		return fail("a send mishandled the caller's descriptor or cancellation state");
	return 0;
}

/*
 * The model holds the next close(), which is the front end's close of its
 * duplicate once the libc send on it (or the published send) has returned.
 * A cancellation that arrives there must not act inside the front end.
 */
static int send_close_case(struct socket_pair *pair, enum send_kind kind)
{
	struct sender sender = {
		.fd = pair->sender,
		.kind = kind,
		.result = -1,
	};
	pthread_t thread;
	void *result = NULL;
	int before = open_fd_count();
	int after;
	int failures = 0;

	block_close();
	if (pthread_create(&thread, NULL, sender_main, &sender)) {
		release();
		return send_case_fail(pair, kind, "pthread_create");
	}
	if (wait_blocked()) {
		release();
		pthread_join(thread, NULL);
		drain_peer(pair->receiver);
		return send_case_fail(pair, kind,
				      "the front end closed no duplicate");
	}
	pthread_cancel(thread);
	release();
	if (pthread_join(thread, &result))
		return send_case_fail(pair, kind, "pthread_join");
	after = open_fd_count();
	if (!sender.returned) {
		drain_peer(pair->receiver);
		failures += send_case_fail(pair, kind,
			"the cancellation acted inside the front end");
	} else {
		if (result != PTHREAD_CANCELED)
			failures += send_case_fail(pair, kind,
				"the cancellation request was lost");
		failures += send_delivered_once(pair, kind, sender.result, 0);
	}
	if (after != before) {
		fprintf(stderr, "descriptors before=%d after=%d\n", before,
			after);
		failures += send_case_fail(pair, kind,
			"the front end left a descriptor open");
	}
	return failures;
}

static int send_close_mode(void)
{
	struct socket_pair pairs[2];
	const char *umem = getenv("XDEV_EXT_MODEL_UMEM");
	uint64_t closes;
	unsigned int p;
	unsigned int k;
	int failures = 0;

	block_close = (hook_fn)dlsym(RTLD_DEFAULT,
				     "xdev_ext_model_block_next_close");
	wait_blocked = (hook_fn)dlsym(RTLD_DEFAULT,
				      "xdev_ext_model_wait_until_blocked");
	release = (hook_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_release_request");
	if (!block_close || !wait_blocked || !release || load_close_counter())
		return fail("kernel model hooks are not loaded");
	if (udp_pair(&pairs[0]))
		return fail("connected UDP setup");
	if (unix_pair(&pairs[1], SOCK_DGRAM)) {
		close_pair(&pairs[0]);
		return fail("AF_UNIX datagram setup");
	}
	closes = ebadf_closes();
	/* Without the model's UMEM, the first close() is the failed ring's. */
	for (p = umem && !strcmp(umem, "1") ? 0 : 1; p < 2; p++)
		for (k = 0; k < SEND_KINDS; k++)
			failures += send_close_case(&pairs[p], k);
	failures += closed_twice(closes);
	close_pair(&pairs[0]);
	close_pair(&pairs[1]);
	if (failures)
		return fail("a cancellation during the duplicate's close was mishandled");
	return 0;
}

/* glibc's fortified reads; <unistd.h> declares them only under fortify. */
extern ssize_t __pread_chk(int fd, void *buffer, size_t count, off_t offset,
			   size_t buffer_length);
extern ssize_t __pread64_chk(int fd, void *buffer, size_t count,
			     off64_t offset, size_t buffer_length);

typedef ssize_t (*entry_fn)(int fd, unsigned char *buffer, off_t offset);

static ssize_t entry_pread(int fd, unsigned char *buffer, off_t offset)
{
	return pread(fd, buffer, CANCEL_WAIT_LENGTH, offset);
}

static ssize_t entry_pread64(int fd, unsigned char *buffer, off_t offset)
{
	return pread64(fd, buffer, CANCEL_WAIT_LENGTH, offset);
}

static ssize_t entry_pread_chk(int fd, unsigned char *buffer, off_t offset)
{
	return __pread_chk(fd, buffer, CANCEL_WAIT_LENGTH, offset,
			   CANCEL_WAIT_LENGTH);
}

static ssize_t entry_pread64_chk(int fd, unsigned char *buffer, off_t offset)
{
	return __pread64_chk(fd, buffer, CANCEL_WAIT_LENGTH, offset,
			     CANCEL_WAIT_LENGTH);
}

static ssize_t entry_pwrite(int fd, unsigned char *buffer, off_t offset)
{
	return pwrite(fd, buffer, CANCEL_WAIT_LENGTH, offset);
}

static ssize_t entry_pwrite64(int fd, unsigned char *buffer, off_t offset)
{
	return pwrite64(fd, buffer, CANCEL_WAIT_LENGTH, offset);
}

#define ENTRY_IOV(buffer) \
	{ .iov_base = (buffer), .iov_len = CANCEL_WAIT_LENGTH }

static ssize_t entry_preadv(int fd, unsigned char *buffer, off_t offset)
{
	struct iovec iov = ENTRY_IOV(buffer);

	return preadv(fd, &iov, 1, offset);
}

static ssize_t entry_preadv64(int fd, unsigned char *buffer, off_t offset)
{
	struct iovec iov = ENTRY_IOV(buffer);

	return preadv64(fd, &iov, 1, offset);
}

static ssize_t entry_pwritev(int fd, unsigned char *buffer, off_t offset)
{
	struct iovec iov = ENTRY_IOV(buffer);

	return pwritev(fd, &iov, 1, offset);
}

static ssize_t entry_pwritev64(int fd, unsigned char *buffer, off_t offset)
{
	struct iovec iov = ENTRY_IOV(buffer);

	return pwritev64(fd, &iov, 1, offset);
}

static ssize_t entry_preadv2(int fd, unsigned char *buffer, off_t offset)
{
	struct iovec iov = ENTRY_IOV(buffer);

	return preadv2(fd, &iov, 1, offset, 0);
}

static ssize_t entry_preadv64v2(int fd, unsigned char *buffer, off_t offset)
{
	struct iovec iov = ENTRY_IOV(buffer);

	return preadv64v2(fd, &iov, 1, offset, 0);
}

static ssize_t entry_pwritev2(int fd, unsigned char *buffer, off_t offset)
{
	struct iovec iov = ENTRY_IOV(buffer);

	return pwritev2(fd, &iov, 1, offset, 0);
}

static ssize_t entry_pwritev64v2(int fd, unsigned char *buffer, off_t offset)
{
	struct iovec iov = ENTRY_IOV(buffer);

	return pwritev64v2(fd, &iov, 1, offset, 0);
}

struct entry_case {
	const char *name;
	bool write;
	entry_fn call;
};

/* Every positional entry point the front end exports. */
static const struct entry_case entry_cases[] = {
	{ "pread", false, entry_pread },
	{ "pread64", false, entry_pread64 },
	{ "__pread_chk", false, entry_pread_chk },
	{ "__pread64_chk", false, entry_pread64_chk },
	{ "pwrite", true, entry_pwrite },
	{ "pwrite64", true, entry_pwrite64 },
	{ "preadv", false, entry_preadv },
	{ "preadv64", false, entry_preadv64 },
	{ "pwritev", true, entry_pwritev },
	{ "pwritev64", true, entry_pwritev64 },
	{ "preadv2", false, entry_preadv2 },
	{ "preadv64v2", false, entry_preadv64v2 },
	{ "pwritev2", true, entry_pwritev2 },
	{ "pwritev64v2", true, entry_pwritev64v2 },
};

struct entry_caller {
	int fd;
	const struct entry_case *c;
	unsigned char *buffer;
	off_t offset;
	bool returned;
};

static void *entry_main(void *opaque)
{
	struct entry_caller *caller = opaque;

	pthread_cancel(pthread_self());
	(void)!caller->c->call(caller->fd, caller->buffer, caller->offset);
	caller->returned = true;
	pthread_testcancel();
	return NULL;
}

/* Each entry point gets its own page, after the page the setup wrote. */
static off_t entry_offset(unsigned int i)
{
	return (off_t)(i + 1) * CANCEL_WAIT_LENGTH;
}

/*
 * Positive control: with nothing pending, each entry point is taken over, so
 * the cancelled call below is one the front end would otherwise take over.  A
 * write stores the pattern its page already holds.
 */
static int entry_taken_over(int fd, const unsigned char *pattern,
			    unsigned char *buffer)
{
	unsigned int i;
	int failures = 0;

	for (i = 0; i < ARRAY_SIZE(entry_cases); i++) {
		const struct entry_case *c = &entry_cases[i];
		uint64_t reads = read_requests();
		uint64_t writes = write_requests();
		ssize_t ret;

		if (c->write)
			memcpy(buffer, pattern, CANCEL_WAIT_LENGTH);
		else
			memset(buffer, 0, CANCEL_WAIT_LENGTH);
		ret = c->call(fd, buffer, entry_offset(i));
		if (ret != (ssize_t)CANCEL_WAIT_LENGTH ||
		    memcmp(buffer, pattern, CANCEL_WAIT_LENGTH)) {
			fprintf(stderr, "%s: the call without cancellation failed\n",
				c->name);
			failures++;
		}
		reads = read_requests() - reads;
		writes = write_requests() - writes;
		if (reads != (uint64_t)!c->write ||
		    writes != (uint64_t)c->write) {
			fprintf(stderr, "%s: not taken over (READ_COMPAT +%llu, WRITE_COMPAT +%llu)\n",
				c->name, (unsigned long long)reads,
				(unsigned long long)writes);
			failures++;
		}
	}
	return failures;
}

struct cleanup_caller {
	int fd;
	/* Cancel at entry of send on this socket, or of pread when -1. */
	int sender;
	unsigned char *buffer;
	uint64_t reads;
};

/* A cleanup handler's eligible pread, counted by the model. */
static void entry_cleanup(void *opaque)
{
	struct cleanup_caller *caller = opaque;
	uint64_t reads = read_requests();

	(void)!pread(caller->fd, caller->buffer, CANCEL_WAIT_LENGTH, 0);
	caller->reads = read_requests() - reads;
}

static void *entry_cleanup_main(void *opaque)
{
	struct cleanup_caller *caller = opaque;

	pthread_cleanup_push(entry_cleanup, caller);
	pthread_cancel(pthread_self());
	if (caller->sender >= 0)
		(void)!send(caller->sender, send_payload, sizeof(send_payload),
			    0);
	else
		(void)!pread(caller->fd, caller->buffer, CANCEL_WAIT_LENGTH,
			     0);
	pthread_cleanup_pop(0);
	return NULL;
}

/*
 * A cancellation that acts at entry leaves the front end's hook depth alone,
 * so the exiting thread's cleanup handlers are still taken over.
 */
static int entry_cleanup_taken_over(int fd, unsigned char *buffer)
{
	static const char *const calls[] = {
		"cancelled at entry of pread", "cancelled at entry of send",
	};
	struct socket_pair pair;
	unsigned int i;
	int failures = 0;

	if (unix_pair(&pair, SOCK_DGRAM))
		return fail("AF_UNIX datagram setup");
	for (i = 0; i < ARRAY_SIZE(calls); i++) {
		struct cleanup_caller caller = {
			.fd = fd,
			.sender = i ? pair.sender : -1,
			.buffer = buffer,
		};
		pthread_t thread;
		void *result = NULL;

		if (pthread_create(&thread, NULL, entry_cleanup_main,
				   &caller) ||
		    pthread_join(thread, &result)) {
			fprintf(stderr, "%s: pthread_create/join\n", calls[i]);
			failures++;
			continue;
		}
		if (result != PTHREAD_CANCELED) {
			fprintf(stderr, "%s: the thread was not cancelled\n",
				calls[i]);
			failures++;
		}
		if (caller.reads != 1) {
			fprintf(stderr, "%s: the cleanup handler's pread made %llu READ_COMPAT SQEs, expected 1\n",
				calls[i], (unsigned long long)caller.reads);
			failures++;
		}
	}
	close_pair(&pair);
	return failures;
}

static int entry_mode(const char *path, int fd, const unsigned char *pattern)
{
	unsigned char *update = NULL;
	unsigned char *check = NULL;
	const char *takeover;
	bool taken_over;
	unsigned int i;
	int failures = 0;

	(void)path;
	if (posix_memalign((void **)&update, CANCEL_WAIT_LENGTH,
			   CANCEL_WAIT_LENGTH) ||
	    posix_memalign((void **)&check, CANCEL_WAIT_LENGTH,
			   CANCEL_WAIT_LENGTH)) {
		free(update);
		return fail("posix_memalign");
	}
	memset(update, 0xc3, CANCEL_WAIT_LENGTH);
	for (i = 0; i < ARRAY_SIZE(entry_cases); i++)
		if (pwrite(fd, pattern, CANCEL_WAIT_LENGTH, entry_offset(i)) !=
		    (ssize_t)CANCEL_WAIT_LENGTH) {
			free(update);
			free(check);
			return fail("setup write");
		}
	takeover = getenv("XDEV_EXT_MODEL_UMEM");
	taken_over = takeover && !strcmp(takeover, "1");
	if (taken_over) {
		read_requests = (count_fn)dlsym(RTLD_DEFAULT,
						"xdev_ext_model_read_requests");
		write_requests = (count_fn)dlsym(RTLD_DEFAULT,
						 "xdev_ext_model_write_requests");
		if (!read_requests || !write_requests) {
			free(update);
			free(check);
			return fail("kernel model hooks are not loaded");
		}
		if (entry_taken_over(fd, pattern, check)) {
			free(update);
			free(check);
			return fail("a positional entry point was not taken over");
		}
		failures += entry_cleanup_taken_over(fd, check);
	}
	for (i = 0; i < ARRAY_SIZE(entry_cases); i++) {
		struct entry_caller caller = {
			.fd = fd,
			.c = &entry_cases[i],
			.buffer = entry_cases[i].write ? update : check,
			.offset = entry_offset(i),
		};
		pthread_t thread;
		void *result = NULL;
		uint64_t reads = taken_over ? read_requests() : 0;
		uint64_t writes = taken_over ? write_requests() : 0;
		int before = open_fd_count();
		int after;

		if (pthread_create(&thread, NULL, entry_main, &caller) ||
		    pthread_join(thread, &result)) {
			fprintf(stderr, "%s: pthread_create/join\n",
				entry_cases[i].name);
			failures++;
			continue;
		}
		after = open_fd_count();
		if (result != PTHREAD_CANCELED || caller.returned) {
			fprintf(stderr, "%s: pending cancellation did not act at entry\n",
				entry_cases[i].name);
			failures++;
		}
		if (after != before) {
			fprintf(stderr, "%s: descriptors before=%d after=%d\n",
				entry_cases[i].name, before, after);
			failures++;
		}
		if (!taken_over)
			continue;
		reads = read_requests() - reads;
		writes = write_requests() - writes;
		if (reads || writes) {
			fprintf(stderr, "%s: a cancelled call published an SQE (READ_COMPAT +%llu, WRITE_COMPAT +%llu)\n",
				entry_cases[i].name, (unsigned long long)reads,
				(unsigned long long)writes);
			failures++;
		}
	}
	for (i = 0; i < ARRAY_SIZE(entry_cases); i++) {
		if (!entry_cases[i].write)
			continue;
		memset(check, 0, CANCEL_WAIT_LENGTH);
		if (pread(fd, check, CANCEL_WAIT_LENGTH, entry_offset(i)) !=
		    (ssize_t)CANCEL_WAIT_LENGTH ||
		    memcmp(check, pattern, CANCEL_WAIT_LENGTH)) {
			fprintf(stderr, "%s: a cancelled write reached the file\n",
				entry_cases[i].name);
			failures++;
		}
	}
	free(update);
	free(check);
	if (failures)
		return fail("a positional entry point mishandled a pending cancellation");
	return 0;
}

#define RETURN_PENDING_ROUNDS 3

struct returner {
	int fd;
	unsigned char *buffer;
	ssize_t result;
	bool called;
	bool go;
};

/* Its address is the value a returning thread hands to pthread_join(). */
static int return_value;

static void *returner_main(void *opaque)
{
	struct returner *returner = opaque;

	returner->result = pread(returner->fd, returner->buffer,
				 CANCEL_WAIT_LENGTH, 0);
	__atomic_store_n(&returner->called, true, __ATOMIC_RELEASE);
	/* No cancellation point from here on; sched_yield() is not one. */
	while (!__atomic_load_n(&returner->go, __ATOMIC_ACQUIRE))
		sched_yield();
	return &return_value;
}

static int wait_called(const struct returner *returner)
{
	struct timespec pause = { .tv_nsec = 1000000 };
	int tries;

	for (tries = 0; tries < CANCEL_WAIT_TIMEOUT_S * 1000; tries++) {
		if (__atomic_load_n(&returner->called, __ATOMIC_ACQUIRE))
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}

static int return_pending_round(int fd, const unsigned char *pattern,
				unsigned char *buffer, bool taken_over,
				unsigned int round)
{
	struct returner returner = {
		.fd = fd,
		.buffer = buffer,
		.result = -1,
	};
	pthread_t thread;
	void *result = NULL;
	uint64_t reads = taken_over ? read_requests() : 0;
	int before = open_fd_count();
	int after;
	int failures = 0;

	memset(buffer, 0, CANCEL_WAIT_LENGTH);
	if (pthread_create(&thread, NULL, returner_main, &returner))
		return fail("pthread_create");
	if (wait_called(&returner)) {
		__atomic_store_n(&returner.go, true, __ATOMIC_RELEASE);
		pthread_join(thread, NULL);
		return fail("the pread did not return");
	}
	pthread_cancel(thread);
	__atomic_store_n(&returner.go, true, __ATOMIC_RELEASE);
	if (pthread_join(thread, &result))
		return fail("pthread_join");
	after = open_fd_count();
	if (returner.result != (ssize_t)CANCEL_WAIT_LENGTH ||
	    memcmp(buffer, pattern, CANCEL_WAIT_LENGTH)) {
		fprintf(stderr, "round %u: pread returned %zd\n", round,
			returner.result);
		failures++;
	}
	if (taken_over && read_requests() - reads != 1) {
		fprintf(stderr, "round %u: %llu READ_COMPAT SQEs, expected 1\n",
			round, (unsigned long long)(read_requests() - reads));
		failures++;
	}
	if (result != &return_value) {
		fprintf(stderr, "round %u: pthread_join reported %s\n", round,
			result == PTHREAD_CANCELED ? "PTHREAD_CANCELED" :
						     "another value");
		failures++;
	}
	if (after != before) {
		fprintf(stderr, "round %u: descriptors before=%d after=%d\n",
			round, before, after);
		failures++;
	}
	return failures;
}

static int return_pending_mode(const char *path, int fd,
			       const unsigned char *pattern)
{
	unsigned char *buffer = NULL;
	const char *takeover;
	bool taken_over;
	unsigned int round;
	int failures = 0;

	(void)path;
	takeover = getenv("XDEV_EXT_MODEL_UMEM");
	taken_over = takeover && !strcmp(takeover, "1");
	if (taken_over) {
		read_requests = (count_fn)dlsym(RTLD_DEFAULT,
						"xdev_ext_model_read_requests");
		if (!read_requests)
			return fail("kernel model hooks are not loaded");
	}
	if (posix_memalign((void **)&buffer, CANCEL_WAIT_LENGTH,
			   CANCEL_WAIT_LENGTH))
		return fail("posix_memalign");
	for (round = 0; round < RETURN_PENDING_ROUNDS; round++)
		failures += return_pending_round(fd, pattern, buffer,
						 taken_over, round);
	free(buffer);
	if (failures)
		return fail("a thread that returned with a cancellation pending lost its value or a descriptor");
	return 0;
}

struct mode {
	const char *name;
	/* Exactly one is set. */
	int (*file_mode)(const char *path, int fd,
			 const unsigned char *pattern);
	int (*send_mode)(void);
};

static const struct mode modes[] = {
	{ "wait", wait_mode, NULL },
	{ "state", state_mode, NULL },
	{ "entry", entry_mode, NULL },
	{ "return-pending", return_pending_mode, NULL },
	{ "send-entry", NULL, send_entry_mode },
	{ "send-wait", NULL, send_wait_mode },
	{ "send-blocked", NULL, send_blocked_mode },
	{ "send-seam", NULL, send_seam_mode },
	{ "send-state", NULL, send_state_mode },
	{ "send-close", NULL, send_close_mode },
};

int main(int argc, char **argv)
{
	const struct mode *mode = NULL;
	unsigned char *pattern = NULL;
	unsigned int m;
	int fd;
	int ret;

	if (argc != 3)
		return 2;
	for (m = 0; m < ARRAY_SIZE(modes); m++)
		if (!strcmp(argv[2], modes[m].name))
			mode = &modes[m];
	if (!mode)
		return 2;
	if (posix_memalign((void **)&pattern, CANCEL_WAIT_LENGTH,
			   CANCEL_WAIT_LENGTH))
		return fail("posix_memalign");
	memset(pattern, 0x5a, CANCEL_WAIT_LENGTH);
	fd = open(argv[1], O_RDWR | O_DIRECT);
	if (fd < 0 ||
	    pwrite(fd, pattern, CANCEL_WAIT_LENGTH, 0) !=
	    (ssize_t)CANCEL_WAIT_LENGTH) {
		free(pattern);
		return fail("setup write");
	}
	ret = mode->send_mode ? mode->send_mode() :
				mode->file_mode(argv[1], fd, pattern);
	close(fd);
	free(pattern);
	if (ret)
		return ret;
	printf("XDEV_EXT_PRELOAD_CANCEL_WAIT=PASS mode=%s\n", argv[2]);
	return 0;
}

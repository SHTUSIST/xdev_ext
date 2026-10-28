// SPDX-License-Identifier: GPL-2.0
/* Requirement: appendix III R1 of the Odin capability/algorithm review.
 * Real endpoint/session/USER objects, real shared metadata and eventfds.
 * Only kernel replies, clock/syscall boundaries and atomic observations are
 * controlled. No sleeps, devices, performance claims or source-text checks.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "include/uapi/linux/io_uring.h"
#include "libxdev_ext_peer_message.h"
#include "libxdev_ext_internal.h"

#define RO 4096U
#define DO 8192U
#define SO 12288U
#define TX XDEV_EXT_MECH_DIR_TO_DEVICE
#define RX XDEV_EXT_MECH_DIR_FROM_DEVICE
#define PROD XDEV_EXT_PEER_PRODUCER
#define TERM XDEV_EXT_PEER_TX_TERMINAL
#define CONS XDEV_EXT_PEER_RX_CONSUMER
static unsigned failures, tests;
#define EQ(got, want) do { long long a_ = (long long)(got), b_ = (long long)(want); \
 if (a_ != b_) { failures++; fprintf(stderr, "# line %d %s = %lld; expected %lld\n", \
 __LINE__, #got, a_, b_); } } while (0)
#define REQUIRE(v) do { if (!(v)) { perror(#v); exit(2); } } while (0)

struct ring {
 int fd, efd; void *map, *cpu_map; size_t bytes; __u32 entries;
};
static struct ring rings[2];
static unsigned nr;
static struct xdev_ext_peer_endpoint *ep;
static int allocfd, ctlfd;
static bool active, injected;
static unsigned polls, sleeps, reads, arm_seen, fence_seen, empty_seen;
static int poll_timeout[8];
static int64_t clock_ns;
enum scenario { NONE, FIRST_EMPTY, FIRST_ARM, FINAL_FENCE, IN_POLL,
 DEADLINE_EINTR, OLD_HINT, AGGREGATE, STOP_POLL, READ_EINTR,
 BOTH_POLL, POLL_ERROR, INFINITE_WAIT, POLL_NVAL, POLL_ERR, POLL_HUP };
static enum scenario scenario;
static unsigned target;

static struct xdev_ext_user_ring_hdr *hdr(unsigned i) { return rings[i].map; }
static struct xdev_ext_user_ready *ready(unsigned i) { return (void *)((char *)rings[i].map + RO); }
static struct xdev_ext_user_slot *slots(unsigned i) { return (void *)((char *)rings[i].map + SO); }
static bool sleeping(unsigned i) {
 return __atomic_load_n(&hdr(i)->user_flags, __ATOMIC_ACQUIRE) & XDEV_EXT_USER_F_SLEEPING;
}
static void signal_ring(unsigned i, uint64_t count) {
 REQUIRE(write(rings[i].efd, &count, sizeof(count)) == sizeof(count));
}
static void publish(unsigned i, unsigned slot, uint64_t ticket) {
 struct xdev_ext_user_slot *s = &slots(i)[slot];
 __u32 p = hdr(i)->ready_prod;
 *s = (struct xdev_ext_user_slot) { .ticket = ticket, .nr_frames = 1 };
 s->f[0] = (struct xdev_ext_user_frame) { .capacity = 64, .data_len = 17, .out_len = 17 };
 ready(i)[p & (rings[i].entries - 1)] = (struct xdev_ext_user_ready) {
  .slot = slot, .ticket = ticket, .batch_id = ticket + 100,
  .nr_frames = 1, .key = ticket + 200, .arg = ticket + 300 };
 __atomic_store_n(&hdr(i)->ready_prod, p + 1, __ATOMIC_RELEASE);
 /* The real kernel only signals this efd when it observes SLEEPING. */
 if (sleeping(i)) signal_ring(i, 1);
}
static void inject(void) { if (!injected) { injected = true; publish(target, 0, 41); } }

/* These hooks run AFTER the real atomic operation. Returning the previously
 * loaded value makes FIRST_EMPTY a precise old-empty observation, not a race
 * that depends on host scheduling. */
void peer_wait_after_load(const void *p) {
 if (!active || injected || scenario != FIRST_EMPTY) return;
 struct xdev_ext_user_ring_hdr *cpu = rings[0].cpu_map;
 if (p == &cpu->ready_prod && ++empty_seen == 1) inject();
}
void peer_wait_after_arm(const void *p) {
 if (!active) return;
 for (unsigned i = 0; i < nr; i++) {
  struct xdev_ext_user_ring_hdr *cpu = rings[i].cpu_map;
  if (p != &cpu->user_flags) continue;
  arm_seen++;
  if (scenario == FIRST_ARM && !injected) inject();
 }
}
void peer_wait_after_fence(void) {
 if (!active) return;
 bool all = true;
 for (unsigned i = 0; i < nr; i++) all &= sleeping(i);
 if (all) {
  fence_seen++;
  if (scenario == FINAL_FENCE) inject();
 }
}

void *__real_mmap(void *, size_t, int, int, int, off_t);
void *__wrap_mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset) {
 void *map = __real_mmap(address, length, protection, flags, fd, offset);
 for (unsigned i = 0; i < nr; i++)
  if (rings[i].fd == fd && rings[i].map) rings[i].cpu_map = map;
 return map;
}
int __real_poll(struct pollfd *, nfds_t, int);
ssize_t __real_read(int, void *, size_t);
int __wrap_clock_gettime(clockid_t id, struct timespec *ts) {
 EQ(id, CLOCK_MONOTONIC);
 ts->tv_sec = clock_ns / 1000000000;
 ts->tv_nsec = clock_ns % 1000000000;
 return 0;
}
int __wrap_nanosleep(const struct timespec *request, struct timespec *remaining) {
 (void)request; (void)remaining;
 if (active) { sleeps++; if (scenario == INFINITE_WAIT) inject(); }
 /* Terminate the legacy polling loop deterministically; no wall-clock delay. */
 clock_ns += 20000000;
 return 0;
}
ssize_t __wrap_read(int fd, void *buf, size_t bytes) {
 if (active) for (unsigned i = 0; i < nr; i++) if (fd == rings[i].efd) {
  reads++;
  if (scenario == READ_EINTR && reads == 1) { errno = EINTR; return -1; }
 }
 return __real_read(fd, buf, bytes);
}
int __wrap_poll(struct pollfd *p, nfds_t n, int timeout) {
 if (!active) return __real_poll(p, n, timeout);
 polls++;
 if (polls <= 8) poll_timeout[polls - 1] = timeout;
 EQ(n, nr);
 for (unsigned i = 0; i < nr; i++) {
  unsigned matched = 0;
  for (nfds_t j = 0; j < n; j++) matched += p[j].fd == rings[i].efd && (p[j].events & POLLIN);
  EQ(matched, 1); EQ(sleeping(i), true);
 }
 if (polls > 8) { clock_ns += 1000000000; return 0; }
 if (scenario == POLL_ERROR) { errno = EIO; return -1; }
 if (scenario == POLL_NVAL || scenario == POLL_ERR || scenario == POLL_HUP) {
  for (nfds_t j = 0; j < n; j++) p[j].revents = 0;
  p[0].revents = scenario == POLL_NVAL ? POLLNVAL : scenario == POLL_ERR ? POLLERR : POLLHUP;
  return 1;
 }
 if (scenario == DEADLINE_EINTR) {
  if (polls == 1) { clock_ns += 3000000; errno = EINTR; return -1; }
  if (polls == 2) { clock_ns += 4000000; errno = EINTR; return -1; }
  clock_ns += 3000000; return 0;
 }
 if (scenario == OLD_HINT && polls == 1) return __real_poll(p, n, 0);
 if (scenario == STOP_POLL) {
  for (unsigned i = 0; i < nr; i++) {
   __atomic_store_n(&hdr(i)->kernel_flags, XDEV_EXT_USER_K_STOPPED, __ATOMIC_RELEASE);
   signal_ring(i, 1);
  }
 } else if (scenario == BOTH_POLL) {
  if (!injected) { injected = true; publish(0, 0, 41); publish(1, 0, 42); }
 } else if (scenario == AGGREGATE) {
  if (!injected) { injected = true; publish(target, 0, 41); publish(target, 1, 42); }
 } else inject();
 return __real_poll(p, n, 0);
}

static int setup(unsigned int n, struct io_uring_params *p) {
 (void)n; (void)p; return eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
}
static int regcall(int fd, unsigned opcode, void *arg, unsigned n) {
 (void)fd;
 struct io_uring_xdev_ext_mech *r = arg;
 if (opcode != IORING_REGISTER_XDEV_EXT_MECH || n != 1 ||
     r->op != XDEV_EXT_MECH_OP_USER_STAGE || nr == 2) return -EINVAL;
 struct xdev_ext_mech_user_stage *u = (void *)(uintptr_t)r->arg;
 struct ring *v = &rings[nr++];
 v->efd = u->eventfd; v->entries = u->entries;
 v->fd = memfd_create("peer-wait-user", MFD_CLOEXEC);
 v->bytes = SO + v->entries * sizeof(struct xdev_ext_user_slot) + 4096;
 REQUIRE(v->fd >= 0 && ftruncate(v->fd, v->bytes) == 0);
 v->map = mmap(NULL, v->bytes, PROT_READ | PROT_WRITE, MAP_SHARED, v->fd, 0);
 REQUIRE(v->map != MAP_FAILED);
 u->fd = v->fd;
 u->off = (struct xdev_ext_user_ring_offsets) { .mmap_size = v->bytes,
  .hdr = 0, .ready = RO, .done = DO, .slots = SO };
 return 0;
}
static int ioctlcall(int fd, unsigned long request, unsigned long arg) {
 (void)fd; (void)arg;
 if (request == XDEV_EXT_USER_IOC_CTL_ATTACH || request == XDEV_EXT_USER_IOC_CTL_DETACH ||
     request == XDEV_EXT_USER_IOC_KICK) return 0;
 return -ENOTTY;
}
static const struct xdev_ext_sys sys = { .io_uring_setup = setup,
 .io_uring_register = regcall, .ioctl = ioctlcall };
static void open_endpoint(unsigned direction, bool external) {
 nr = polls = sleeps = reads = arm_seen = fence_seen = empty_seen = 0;
 memset(rings, 0, sizeof(rings)); memset(poll_timeout, 0, sizeof(poll_timeout));
 active = injected = false; scenario = NONE; clock_ns = 123000000000LL;
 allocfd = memfd_create("peer-wait-allocation", MFD_CLOEXEC);
 ctlfd = memfd_create("peer-wait-control", MFD_CLOEXEC);
 REQUIRE(allocfd >= 0 && ctlfd >= 0);
 struct xdev_ext_peer_endpoint_opts o = {
  .sz = sizeof(o), .allocation_fd = allocfd, .control_fd = ctlfd, .link_token = 1,
  .direction = direction, .depth = 2, .group_bytes = 4096, .deadline_ms = 1000,
  .layout = { .frame_size = 4096, .seg_len = 4096, .group_bytes = 4096 },
  .flags = external ? XDEV_EXT_PEER_ENDPOINT_F_EXTERNAL_CTL : 0 };
 REQUIRE(xdev_ext_peer_endpoint_open(&o, &ep) == 0);
}
static void close_endpoint(void) {
 active = false;
 EQ(xdev_ext_peer_endpoint_close(ep), 0);
 for (unsigned i = 0; i < nr; i++) EQ(munmap(rings[i].map, rings[i].bytes), 0);
 EQ(close(allocfd), 0); EQ(close(ctlfd), 0);
}
static int next(int timeout, struct xdev_ext_peer_message *m) {
 active = true;
 int ret = xdev_ext_peer_endpoint_next(ep, timeout, m);
 active = false;
 return ret;
}
static void clean_sleep(void) {
 for (unsigned i = 0; i < nr; i++) EQ(sleeping(i), false);
}
static void run_arrival(enum scenario when, unsigned which, unsigned direction) {
 struct xdev_ext_peer_message m;
 open_endpoint(direction, false);
 scenario = when; target = which;
 EQ(next(10, &m), 0);
 if (injected) {
  EQ(m.batch.ticket, 41);
  EQ(m.role, direction == RX ? CONS : which == 0 ? PROD : TERM);
  EQ(next(0, &m), -EAGAIN); /* one delivery only */
 }
 EQ(injected, true); EQ(sleeps, 0);
 if (when == FIRST_ARM || when == FINAL_FENCE) EQ(polls, 0);
 if (when == IN_POLL) EQ(polls, 1);
 clean_sleep(); close_endpoint();
}
static void first_empty_producer(void) { run_arrival(FIRST_EMPTY, 0, TX); }
static void first_empty_terminal(void) { run_arrival(FIRST_EMPTY, 1, TX); }
static void arm_producer(void) { run_arrival(FIRST_ARM, 0, TX); }
static void arm_terminal(void) { run_arrival(FIRST_ARM, 1, TX); }
static void fence_producer(void) { run_arrival(FINAL_FENCE, 0, TX); }
static void fence_terminal(void) { run_arrival(FINAL_FENCE, 1, TX); }
static void poll_producer(void) { run_arrival(IN_POLL, 0, TX); }
static void poll_terminal(void) { run_arrival(IN_POLL, 1, TX); }
static void rx_poll(void) { run_arrival(IN_POLL, 0, RX); }
static void priority(void) {
 struct xdev_ext_peer_message m, terminal;
 open_endpoint(TX, false); publish(0, 0, 41); publish(1, 0, 42);
 EQ(next(10, &terminal), 0); EQ(terminal.role, TERM); EQ(terminal.batch.ticket, 42);
 EQ(hdr(0)->ready_cons, 0);
 EQ(next(10, &m), 0); EQ(m.role, PROD); EQ(m.batch.ticket, 41);
 EQ(next(0, &m), -EAGAIN); EQ(sleeps, 0); EQ(polls, 0); close_endpoint();
}
static void simultaneous_wake(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); scenario = BOTH_POLL;
 EQ(next(10, &m), 0); if (injected) { EQ(m.role, TERM); EQ(m.batch.ticket, 42); }
 EQ(hdr(0)->ready_cons, 0);
 EQ(next(0, &m), 0); if (injected) { EQ(m.role, PROD); EQ(m.batch.ticket, 41); }
 EQ(next(0, &m), -EAGAIN); EQ(polls, 1); EQ(sleeps, 0);
 clean_sleep(); close_endpoint();
}
static void poll_error_cleanup(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); scenario = POLL_ERROR;
 EQ(next(10, &m), -EIO); EQ(polls, 1); EQ(sleeps, 0);
 clean_sleep(); close_endpoint();
}
static void poll_revent_error(enum scenario event, int expected) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); scenario = event;
 EQ(next(10, &m), expected); EQ(polls, 1); EQ(sleeps, 0);
 clean_sleep(); close_endpoint();
}
static void poll_nval(void) { poll_revent_error(POLL_NVAL, -EBADF); }
static void poll_err(void) { poll_revent_error(POLL_ERR, -EIO); }
static void poll_hup(void) { poll_revent_error(POLL_HUP, -EIO); }
static void infinite_wait(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(RX, false); scenario = INFINITE_WAIT; target = 0;
 EQ(next(-1, &m), 0); if (injected) EQ(m.batch.ticket, 41);
 EQ(polls, 1); EQ(poll_timeout[0], -1); EQ(sleeps, 0);
 clean_sleep(); close_endpoint();
}
static void zero_timeout(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); EQ(next(0, &m), -EAGAIN);
 EQ(sleeps, 0); EQ(polls, 0); clean_sleep(); close_endpoint();
}
static void deadline_eintr(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); scenario = DEADLINE_EINTR;
 EQ(next(10, &m), -ETIMEDOUT); EQ(sleeps, 0); EQ(polls, 3);
 EQ(poll_timeout[0], 10); EQ(poll_timeout[1], 7); EQ(poll_timeout[2], 3);
 clean_sleep(); close_endpoint();
}
static void old_hint(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); scenario = OLD_HINT; target = 0;
 signal_ring(0, 7); /* old notifications have no ready entry */
 EQ(next(10, &m), 0); if (injected) EQ(m.batch.ticket, 41);
 EQ(polls, 2); EQ(sleeps, 0); EQ(next(0, &m), -EAGAIN);
 clean_sleep(); close_endpoint();
}
static void aggregate(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); scenario = AGGREGATE; target = 1;
 EQ(next(10, &m), 0); if (injected) EQ(m.batch.ticket, 41);
 EQ(next(0, &m), 0); if (injected) EQ(m.batch.ticket, 42);
 EQ(next(0, &m), -EAGAIN); EQ(polls, 1); EQ(sleeps, 0);
 clean_sleep(); close_endpoint();
}
static void stop_poll(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); scenario = STOP_POLL;
 EQ(next(10, &m), -ESHUTDOWN); EQ(polls, 1); EQ(sleeps, 0);
 clean_sleep(); close_endpoint();
}
static void interrupted_drain(void) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, false); scenario = READ_EINTR; target = 0;
 EQ(next(10, &m), 0); if (injected) EQ(m.batch.ticket, 41);
 EQ(sleeps, 0); EQ(reads >= 2, true); clean_sleep(); close_endpoint();
}
static void external_owner_case(unsigned attached_mask) {
 struct xdev_ext_peer_message m;
 open_endpoint(TX, true);
 struct xdev_ext_user_stage *p = xdev_ext_peer_endpoint_user(ep, PROD);
 struct xdev_ext_user_stage *t = xdev_ext_peer_endpoint_user(ep, TERM);
 if (attached_mask & 1) EQ(xdev_ext_user_stage_ctl_attach(p), 0);
 if (attached_mask & 2) EQ(xdev_ext_user_stage_ctl_attach(t), 0);
 publish(0, 0, 41); publish(1, 0, 42);
 hdr(0)->user_flags = hdr(1)->user_flags = XDEV_EXT_USER_F_SLEEPING;
 signal_ring(0, 7); signal_ring(1, 9);
 EQ(next(10, &m), -EBUSY); EQ(next(0, &m), -EBUSY);
 EQ(hdr(0)->ready_cons, 0); EQ(hdr(1)->ready_cons, 0);
 EQ(polls, 0); EQ(sleeps, 0); EQ(sleeping(0), true); EQ(sleeping(1), true);
 uint64_t count = 0;
 EQ(__real_read(rings[0].efd, &count, sizeof(count)), sizeof(count)); EQ(count, 7);
 EQ(__real_read(rings[1].efd, &count, sizeof(count)), sizeof(count)); EQ(count, 9);
 if (attached_mask & 1) EQ(xdev_ext_user_stage_ctl_detach(p), 0);
 if (attached_mask & 2) EQ(xdev_ext_user_stage_ctl_detach(t), 0);
 hdr(0)->user_flags = hdr(1)->user_flags = 0;
 close_endpoint();
}
static void external_owner(void) { external_owner_case(3); }
static void external_producer_owner(void) { external_owner_case(1); }
static void external_terminal_owner(void) { external_owner_case(2); }
/* Positive controls prove that observation hooks target the library's
 * own mapping and preserve real single-ring arm/recheck behavior. */
static void single_ring_control(enum scenario when) {
 struct xdev_ext_user_batch b;
 open_endpoint(RX, false); scenario = when; target = 0;
 active = true;
 int ret = xdev_ext_user_stage_next(xdev_ext_peer_endpoint_user(ep, CONS), 10, &b);
 active = false;
 EQ(ret, 0); EQ(injected, true); if (!ret) EQ(b.ticket, 41);
 EQ(polls, when == IN_POLL ? 1 : 0); EQ(sleeps, 0); clean_sleep(); close_endpoint();
}
static void control_empty(void) { single_ring_control(FIRST_EMPTY); }
static void control_arm(void) { single_ring_control(FIRST_ARM); }
static void control_fence(void) { single_ring_control(FINAL_FENCE); }
static void control_poll(void) { single_ring_control(IN_POLL); }
static void test(const char *name, void (*fn)(void)) {
 unsigned before = failures; fn(); tests++;
 printf("%s %u - %s\n", failures == before ? "ok" : "not ok", tests, name);
}
int main(void) {
 xdev_ext__set_sys(&sys); puts("TAP version 13");
 test("arrival after empty producer observation is not timer-polled", first_empty_producer);
 test("arrival after empty terminal observation is not timer-polled", first_empty_terminal);
 test("producer arrival during arm skips poll", arm_producer);
 test("terminal arrival during arm skips poll", arm_terminal);
 test("producer arrival after all arms and fence skips poll", fence_producer);
 test("terminal arrival after all arms and fence skips poll", fence_terminal);
 test("producer poll event wakes combined USER wait", poll_producer);
 test("terminal poll event wakes combined USER wait", poll_terminal);
 test("RX-only endpoint waits on its consumer USER eventfd", rx_poll);
 test("terminal priority preserves producer and prevents duplicate delivery", priority);
 test("simultaneous poll wake retains terminal priority and producer custody", simultaneous_wake);
 test("poll error clears every armed sleeping flag", poll_error_cleanup);
 test("POLLNVAL returns EBADF after clearing every armed flag", poll_nval);
 test("POLLERR returns EIO after clearing every armed flag", poll_err);
 test("POLLHUP returns EIO after clearing every armed flag", poll_hup);
 test("negative timeout waits indefinitely on USER events", infinite_wait);
 test("zero timeout performs no blocking syscall", zero_timeout);
 test("repeated EINTR keeps original absolute deadline", deadline_eintr);
 test("old aggregated eventfd hint does not invent work or prevent fresh wake", old_hint);
 test("aggregated wake count does not limit or duplicate ready tickets", aggregate);
 test("STOP during poll wakes and clears every sleeping flag", stop_poll);
 test("EINTR during eventfd drain is retried", interrupted_drain);
 test("attached GPU external owner keeps metadata and notification custody", external_owner);
 test("attached producer blocks CPU takes on every ring including timeout zero", external_producer_owner);
 test("attached terminal blocks CPU takes on every ring including timeout zero", external_terminal_owner);
 test("control: real USER waiter observes post-empty arrival", control_empty);
 test("control: real USER waiter observes post-arm arrival", control_arm);
 test("control: real USER waiter observes post-fence arrival", control_fence);
 test("control: real USER waiter polls and drains its actual eventfd", control_poll);
 printf("1..%u\n# %u assertion failures\n", tests, failures);
 return failures ? 1 : 0;
}

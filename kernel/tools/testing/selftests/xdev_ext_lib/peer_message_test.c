// SPDX-License-Identifier: GPL-2.0
/*
 * Independent Q10 oracle: plans/2026-10-27-peer-message-user-custody.md
 * section 4.1 and the root's cumulative NOTIFY_ARM contract. The real library
 * is linked. Only the kernel register/ioctl boundary is replaced; descriptors,
 * CLOEXEC duplication, eventfds, mappings and close lifetime remain real.
 * These host tests do not establish actual authority validity or GPU safety.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "include/uapi/linux/io_uring.h"
#ifndef XDEV_EXT_TEST_CONTRACT
#define XDEV_EXT_TEST_CONTRACT "tools/xdev_ext_mech/lib/libxdev_ext.h"
#endif
#include XDEV_EXT_TEST_CONTRACT
#include "tools/xdev_ext_mech/lib/libxdev_ext_internal.h"

/* Absent baseline APIs must produce a runtime RED, not a passing stub. */
#pragma weak xdev_ext_session_open_peer
#pragma weak xdev_ext_session_start_frames
#pragma weak xdev_ext_user_batch_peer_span
#pragma weak xdev_ext_user_stage_control
#pragma weak xdev_ext_user_stage_ctl_attach
#pragma weak xdev_ext_user_stage_ctl_detach

static unsigned int tests, checks, failures;
#define EXPECT_EQ(actual, expected) do { \
 long long a_ = (long long)(actual), e_ = (long long)(expected); \
 checks++; \
 if (a_ != e_) { \
  fprintf(stderr, "# line %d %s: got %lld expected %lld\n", \
          __LINE__, #actual, a_, e_); \
  failures++; \
 } \
} while (0)
#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define REQUIRE_API(fn) do { EXPECT_TRUE(fn != NULL); if (!(fn)) return; } while (0)

#define FRAME_SIZE 4096U
#define POOL_FRAMES 16U
#define USER_ENTRIES 4U
#define USER_READY 512U
#define USER_DONE 1024U
#define USER_SLOTS 2048U
#define USER_MAP (USER_SLOTS + USER_ENTRIES * sizeof(struct xdev_ext_user_slot) + 4096U)
#define TRACE_MAX 128U

static unsigned int trace[TRACE_MAX], trace_nr, umem_registers, setup_calls;
static unsigned int creates, starts, arms, stops, attaches, detaches, kicks;
static struct xdev_ext_mech_create seen_create;
static struct xdev_ext_mech_start seen_start;
static struct xdev_ext_mech_notify_arm seen_arm;
static struct xdev_ext_mech_user_stage seen_user;
static struct xdev_ext_mech_stats reply_stats;
static __u32 seen_indices[64];
static const __u32 *caller_indices;
static int setup_ret, create_ret, start_ret, arm_ret, stop_ret, stats_ret;
static int attach_ret, detach_ret, user_ret;
static bool bound, attached;
static int user_fd;
static void *kernel_map;
static unsigned long seen_ioctl_arg;

static int fd_count(void)
{
 DIR *d = opendir("/proc/self/fd");
 struct dirent *e;
 int n = 0;

 if (!d)
  return -1;
 while ((e = readdir(d)))
  if (e->d_name[0] != '.')
   n++;
 closedir(d);
 return n - 1;
}

static int payload_maps(void)
{
 FILE *f = fopen("/proc/self/maps", "r");
 char line[1024];
 int n = 0;

 if (!f)
  return -1;
 while (fgets(line, sizeof(line), f))
  n += strstr(line, "q10-peer-authority") != NULL;
 fclose(f);
 return n;
}

static int authority(void)
{
 int fd = memfd_create("q10-peer-authority", MFD_CLOEXEC);

 EXPECT_TRUE(fd >= 0);
 if (fd >= 0)
  EXPECT_EQ(ftruncate(fd, POOL_FRAMES * FRAME_SIZE), 0);
 return fd;
}

static int fake_setup(unsigned int entries, struct io_uring_params *p)
{
 (void)entries;
 (void)p;
 setup_calls++;
 if (setup_ret)
  return setup_ret;
 return eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
}

static int fake_register(int fd, unsigned int opcode, void *arg, unsigned int nr)
{
 struct io_uring_xdev_ext_mech *r = arg;
 void *p;

 EXPECT_TRUE(fd >= 0);
 EXPECT_EQ(nr, 1);
 if (opcode == IORING_REGISTER_XDEV_EXT_UMEM) {
  umem_registers++;
  return 0;
 }
 if (opcode != IORING_REGISTER_XDEV_EXT_MECH)
  return -EINVAL;
 p = (void *)(uintptr_t)r->arg;
 if (trace_nr < TRACE_MAX)
  trace[trace_nr++] = r->op;
 switch (r->op) {
 case XDEV_EXT_MECH_OP_CREATE:
  creates++;
  seen_create = *(struct xdev_ext_mech_create *)p;
  if (!create_ret)
   ((struct xdev_ext_mech_create *)p)->session_id = 77;
  return create_ret;
 case XDEV_EXT_MECH_OP_START:
  starts++;
  seen_start = *(struct xdev_ext_mech_start *)p;
  EXPECT_TRUE(seen_start.nr_user_frames <= 64);
  if (seen_start.user_frames && seen_start.nr_user_frames <= 64)
   memcpy(seen_indices, (void *)(uintptr_t)seen_start.user_frames,
          seen_start.nr_user_frames * sizeof(*seen_indices));
  if (caller_indices)
   EXPECT_TRUE(seen_start.user_frames != (uintptr_t)caller_indices);
  return start_ret;
 case XDEV_EXT_MECH_OP_NOTIFY_ARM:
  arms++;
  seen_arm = *(struct xdev_ext_mech_notify_arm *)p;
  return arm_ret;
 case XDEV_EXT_MECH_OP_STATS:
  if (stats_ret)
   return stats_ret;
  reply_stats.session_id = *(__u64 *)p;
  *(struct xdev_ext_mech_stats *)p = reply_stats;
  return 0;
 case XDEV_EXT_MECH_OP_STOP:
  stops++;
  EXPECT_EQ(r->arg, 77);
  return stop_ret;
 case XDEV_EXT_MECH_OP_USER_STAGE: {
  struct xdev_ext_mech_user_stage *u = p;

  seen_user = *u;
  if (user_ret)
   return user_ret;
  user_fd = memfd_create("q10-user-control", MFD_CLOEXEC);
  if (user_fd < 0 || ftruncate(user_fd, USER_MAP))
   return -ENOMEM;
  kernel_map = mmap(NULL, USER_MAP, PROT_READ | PROT_WRITE,
                    MAP_SHARED, user_fd, 0);
  if (kernel_map == MAP_FAILED)
   return -ENOMEM;
  u->fd = user_fd;
  u->off = (struct xdev_ext_user_ring_offsets) {
   .mmap_size = USER_MAP, .hdr = 0, .ready = USER_READY,
   .done = USER_DONE, .slots = USER_SLOTS,
  };
  return 0;
 }
 default:
  return -EINVAL;
 }
}

static int fake_ioctl(int fd, unsigned long request, unsigned long arg)
{
 EXPECT_EQ(fd, user_fd);
 seen_ioctl_arg = arg;
 if (request == XDEV_EXT_USER_IOC_KICK) {
  kicks++;
  return 0;
 }
 if (request == XDEV_EXT_USER_IOC_CTL_ATTACH) {
  attaches++;
  if (attach_ret)
   return attach_ret;
  if (attached)
   return -EALREADY;
  if (bound)
   return -EBUSY;
  if (!(seen_user.flags & XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL))
   return -EOPNOTSUPP;
  attached = true;
  return 0;
 }
 if (request == XDEV_EXT_USER_IOC_CTL_DETACH) {
  detaches++;
  if (detach_ret)
   return detach_ret;
  if (!attached)
   return -ENOENT;
  if (bound)
   return -EBUSY;
  attached = false;
  return 0;
 }
 return -ENOTTY;
}

static void fake_sleep(unsigned int usec) { (void)usec; }
static const struct xdev_ext_sys fake_sys = {
 .io_uring_setup = fake_setup, .io_uring_register = fake_register,
 .ioctl = fake_ioctl, .usleep = fake_sleep,
};

static void reset(void)
{
 if (kernel_map && kernel_map != MAP_FAILED)
  EXPECT_EQ(munmap(kernel_map, USER_MAP), 0);
 kernel_map = NULL;
 user_fd = -1;
 trace_nr = umem_registers = setup_calls = 0;
 creates = starts = arms = stops = attaches = detaches = kicks = 0;
 memset(&seen_create, 0, sizeof(seen_create));
 memset(&seen_start, 0, sizeof(seen_start));
 memset(&seen_arm, 0, sizeof(seen_arm));
 memset(&seen_user, 0, sizeof(seen_user));
 memset(seen_indices, 0, sizeof(seen_indices));
 reply_stats = (struct xdev_ext_mech_stats) {
  .state = XDEV_EXT_MECH_SESSION_ACTIVE,
 };
 caller_indices = NULL;
 setup_ret = create_ret = start_ret = arm_ret = stop_ret = stats_ret = 0;
 attach_ret = detach_ret = user_ret = 0;
 bound = attached = false;
 seen_ioctl_arg = ULONG_MAX;
}

static struct xdev_ext_create_opts create_opts(void)
{
 struct xdev_ext_create_opts c = XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
  .group_bytes = 8192, .depth = 2, .nr_stages = 1);

 c.layout = (struct xdev_ext_mech_layout) {
  .frame_size = FRAME_SIZE, .seg_len = FRAME_SIZE, .group_bytes = 8192,
 };
 c.st[0] = (struct xdev_ext_mech_stage_uapi) {
  .class_id = XDEV_EXT_MECH_CLASS_USER, .fd = 101,
  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
  .flags = XDEV_EXT_USER_F_STRICT_ASYNC, .arg0 = 1000,
 };
 return c;
}

static struct xdev_ext_session *opened_peer(int fd, bool create)
{
 struct xdev_ext_peer_pool_opts p = XDEV_EXT_OPTS_INIT(xdev_ext_peer_pool_opts,
  .allocation_fd = fd);
 struct xdev_ext_create_opts c = create_opts();
 struct xdev_ext_session *s = NULL;

 EXPECT_EQ(xdev_ext_session_open_peer(&p, &s), 0);
 EXPECT_TRUE(s != NULL);
 if (s && create)
  EXPECT_EQ(xdev_ext_session_create(s, &c), 0);
 return s;
}

static void finished(__u64 batches)
{
 unsigned int i;

 reply_stats.batches_done = batches;
 reply_stats.inflight = 0;
 reply_stats.published = batches * 2;
 for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++)
  reply_stats.submitted[i] = reply_stats.completed[i] = batches;
}

static void test_peer_fd_ownership(void)
{
 struct xdev_ext_session *s;
 struct stat original, duplicate;
 int fd, before = fd_count(), maps = payload_maps(), own;

 REQUIRE_API(xdev_ext_session_open_peer);
 fd = authority();
 EXPECT_EQ(fstat(fd, &original), 0);
 s = opened_peer(fd, false);
 if (!s) { close(fd); return; }
 /* The caller may close its reference before CREATE; only the duplicate lives. */
 EXPECT_EQ(close(fd), 0);
 {
  struct xdev_ext_create_opts c = create_opts();
  EXPECT_EQ(xdev_ext_session_create(s, &c), 0);
 }
 own = seen_create.pool_fd;
 EXPECT_EQ(seen_create.pool_kind, XDEV_EXT_MECH_POOL_PEER);
 EXPECT_TRUE(own >= 0 && own != fd);
 EXPECT_EQ(fstat(own, &duplicate), 0);
 EXPECT_EQ(duplicate.st_dev, original.st_dev);
 EXPECT_EQ(duplicate.st_ino, original.st_ino);
 EXPECT_TRUE(fcntl(own, F_GETFD) & FD_CLOEXEC);
 EXPECT_EQ(umem_registers, 0);
 EXPECT_EQ(payload_maps(), maps);
 EXPECT_EQ(xdev_ext_session_xsk_fd(s), -1);
 EXPECT_TRUE(xdev_ext_session_ring_fd(s) >= 0);
 EXPECT_TRUE(xdev_ext_session_eventfd(s) >= 0);
 EXPECT_EQ(seen_create.eventfd, xdev_ext_session_eventfd(s));
 EXPECT_EQ(xdev_ext_session_close(s), 0);
 EXPECT_EQ(fcntl(own, F_GETFD), -1);
 EXPECT_EQ(fd_count(), before);
}

static void test_peer_validation_cleanup(void)
{
 struct xdev_ext_peer_pool_opts p = XDEV_EXT_OPTS_INIT(xdev_ext_peer_pool_opts,
  .allocation_fd = -1);
 struct xdev_ext_session *s = (void *)1;
 int fd, before = fd_count();

 REQUIRE_API(xdev_ext_session_open_peer);
 EXPECT_TRUE(xdev_ext_session_open_peer(NULL, &s) < 0);
 EXPECT_TRUE(xdev_ext_session_open_peer(&p, NULL) < 0);
 EXPECT_TRUE(xdev_ext_session_open_peer(&p, &s) < 0);
 EXPECT_EQ((uintptr_t)s, 1);
 fd = authority();
 p.allocation_fd = fd;
 p.flags = 1U << 17;
 EXPECT_TRUE(xdev_ext_session_open_peer(&p, &s) < 0);
 EXPECT_EQ((uintptr_t)s, 1);
 p.flags = 0;
 p.sz--;
 EXPECT_TRUE(xdev_ext_session_open_peer(&p, &s) < 0);
 p.sz = sizeof(p);
 setup_ret = -EMFILE;
 EXPECT_EQ(xdev_ext_session_open_peer(&p, &s), -EMFILE);
 EXPECT_EQ((uintptr_t)s, 1);
 EXPECT_TRUE(fcntl(fd, F_GETFD) >= 0);
 EXPECT_EQ(fd_count(), before + 1);
 setup_ret = 0;
 s = opened_peer(fd, false);
 if (s) {
  struct xdev_ext_create_opts c = create_opts();
  create_ret = -EXDEV;
  EXPECT_EQ(xdev_ext_session_create(s, &c), -EXDEV);
  EXPECT_TRUE(fcntl(seen_create.pool_fd, F_GETFD) >= 0);
  EXPECT_EQ(xdev_ext_session_close(s), 0);
 }
 EXPECT_TRUE(fcntl(fd, F_GETFD) >= 0);
 EXPECT_EQ(close(fd), 0);
 EXPECT_EQ(fd_count(), before);
}

static void test_ordered_frames_and_arm(void)
{
 __u32 indices[] = { 7, 3, 9, 1 };
 struct xdev_ext_start_frames_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_start_frames_opts,
  .nr_batches = 2, .first_seq = 101, .indices = indices, .nr_indices = 4);
 struct xdev_ext_session *s;
 int fd;

 REQUIRE_API(xdev_ext_session_open_peer);
 REQUIRE_API(xdev_ext_session_start_frames);
 fd = authority();
 s = opened_peer(fd, true);
 if (!s) { close(fd); return; }
 caller_indices = indices;
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), 0);
 EXPECT_EQ(starts, 1);
 EXPECT_EQ(arms, 1);
 EXPECT_EQ(trace[trace_nr - 2], XDEV_EXT_MECH_OP_NOTIFY_ARM);
 EXPECT_EQ(trace[trace_nr - 1], XDEV_EXT_MECH_OP_START);
 EXPECT_EQ(seen_arm.batches_target, 2);
 EXPECT_EQ(seen_arm.published_target, 0);
 EXPECT_EQ(seen_start.flags, XDEV_EXT_MECH_START_F_USER_FRAMES |
                           XDEV_EXT_MECH_START_F_ORDERED_FRAMES);
 EXPECT_EQ(seen_start.first_seq, 101);
 EXPECT_EQ(seen_start.nr_batches, 2);
 EXPECT_EQ(seen_start.nr_user_frames, 4);
 EXPECT_EQ(memcmp(seen_indices, indices, sizeof(indices)), 0);
 EXPECT_EQ(indices[0], 7);
 EXPECT_EQ(indices[3], 1);
 EXPECT_EQ(xdev_ext_session_close(s), 0);
 EXPECT_TRUE(fcntl(fd, F_GETFD) >= 0);
 close(fd);
}

static void test_ordered_recycle_choice(void)
{
 __u32 indices[] = { 7, 3, 9, 1 };
 struct xdev_ext_start_frames_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_start_frames_opts,
  .nr_batches = 6, .first_seq = 9, .indices = indices, .nr_indices = 4,
  .flags = XDEV_EXT_MECH_START_F_RECYCLE);
 struct xdev_ext_session *s;
 int fd;

 REQUIRE_API(xdev_ext_session_open_peer);
 REQUIRE_API(xdev_ext_session_start_frames);
 fd = authority();
 s = opened_peer(fd, true);
 if (!s) { close(fd); return; }
 caller_indices = indices;
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), 0);
 EXPECT_EQ(seen_arm.batches_target, 6);
 EXPECT_EQ(seen_start.flags, XDEV_EXT_MECH_START_F_USER_FRAMES |
  XDEV_EXT_MECH_START_F_ORDERED_FRAMES | XDEV_EXT_MECH_START_F_RECYCLE);
 EXPECT_EQ(memcmp(seen_indices, indices, sizeof(indices)), 0);
 EXPECT_EQ(xdev_ext_session_close(s), 0);
 close(fd);
}

static void test_start_failures_do_not_commit(void)
{
 __u32 indices[] = { 7, 3, 9, 1 };
 struct xdev_ext_start_frames_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_start_frames_opts,
  .nr_batches = 2, .first_seq = 101, .indices = indices, .nr_indices = 4);
 struct xdev_ext_session *s;
 int fd;

 REQUIRE_API(xdev_ext_session_open_peer);
 REQUIRE_API(xdev_ext_session_start_frames);
 fd = authority();
 s = opened_peer(fd, true);
 if (!s) { close(fd); return; }
 arm_ret = -ESHUTDOWN;
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), -ESHUTDOWN);
 EXPECT_EQ(starts, 0);
 arm_ret = 0;
 start_ret = -EIO;
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), -EIO);
 EXPECT_EQ(seen_arm.batches_target, 2);
 start_ret = 0;
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), 0);
 EXPECT_EQ(seen_arm.batches_target, 2);
 EXPECT_EQ(arms, 3);
 EXPECT_EQ(starts, 2);
 EXPECT_EQ(xdev_ext_session_close(s), 0);
 close(fd);
}

static void test_start_validation(void)
{
 __u32 indices[] = { 7, 3, 9, 1 };
 struct xdev_ext_start_frames_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_start_frames_opts,
  .nr_batches = 2, .first_seq = 101, .indices = indices, .nr_indices = 4);
 struct xdev_ext_start_frames_opts bad;
 struct xdev_ext_session *s;
 int fd;

 REQUIRE_API(xdev_ext_session_open_peer);
 REQUIRE_API(xdev_ext_session_start_frames);
 fd = authority();
 s = opened_peer(fd, true);
 if (!s) { close(fd); return; }
 EXPECT_TRUE(xdev_ext_session_start_frames(NULL, &o) < 0);
 EXPECT_TRUE(xdev_ext_session_start_frames(s, NULL) < 0);
 bad = o; bad.sz--;
 EXPECT_TRUE(xdev_ext_session_start_frames(s, &bad) < 0);
 bad = o; bad.nr_batches = 0;
 EXPECT_TRUE(xdev_ext_session_start_frames(s, &bad) < 0);
 bad = o; bad.indices = NULL;
 EXPECT_TRUE(xdev_ext_session_start_frames(s, &bad) < 0);
 bad = o; bad.nr_indices = 0;
 EXPECT_TRUE(xdev_ext_session_start_frames(s, &bad) < 0);
 bad = o; bad.flags = 1U << 17;
 EXPECT_TRUE(xdev_ext_session_start_frames(s, &bad) < 0);
 bad = o; bad.first_seq = UINT64_MAX;
 EXPECT_TRUE(xdev_ext_session_start_frames(s, &bad) < 0);
 EXPECT_EQ(starts, 0);
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), 0);
 EXPECT_EQ(seen_arm.batches_target, 2);
 EXPECT_EQ(xdev_ext_session_close(s), 0);
 close(fd);
}

static void test_repeat_requires_drain_and_accumulates_target(void)
{
 __u32 first[] = { 7, 3, 9, 1 }, second[] = { 10, 2, 12, 4, 14, 6 };
 struct xdev_ext_start_frames_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_start_frames_opts,
  .nr_batches = 2, .first_seq = 101, .indices = first, .nr_indices = 4);
 struct xdev_ext_mech_stats out;
 struct xdev_ext_session *s;
 __u64 one = 1;
 int fd;

 REQUIRE_API(xdev_ext_session_open_peer);
 REQUIRE_API(xdev_ext_session_start_frames);
 fd = authority();
 s = opened_peer(fd, true);
 if (!s) { close(fd); return; }
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), 0);
 reply_stats.inflight = 1;
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), -EBUSY);
 EXPECT_EQ(starts, 1);
 finished(1); /* Empty current inflight alone does not prove all START work ended. */
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), -EBUSY);
 EXPECT_EQ(starts, 1);
 finished(2);
 EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), sizeof(one));
 EXPECT_EQ(xdev_ext_session_wait(s, 100, &out), 0);
 o.indices = second; o.nr_indices = 6; o.nr_batches = 3; o.first_seq = 103;
 start_ret = -EIO;
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), -EIO);
 EXPECT_EQ(seen_arm.batches_target, 5);
 start_ret = 0;
 EXPECT_EQ(xdev_ext_session_start_frames(s, &o), 0);
 EXPECT_EQ(starts, 3);
 EXPECT_EQ(arms, 3);
 EXPECT_EQ(seen_arm.batches_target, 5);
 EXPECT_EQ(seen_arm.published_target, 0);
 EXPECT_EQ(memcmp(seen_indices, second, sizeof(second)), 0);
 /* A stale/early wake must not confuse the cumulative local completion goal. */
 finished(2);
 EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), sizeof(one));
 EXPECT_EQ(xdev_ext_session_wait(s, 100, &out), -EIO);
 finished(5);
 EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), sizeof(one));
 EXPECT_EQ(xdev_ext_session_wait(s, 100, &out), 0);
 EXPECT_EQ(out.batches_done, 5);
 EXPECT_EQ(xdev_ext_session_close(s), 0);
 close(fd);
}

static void test_unknown_retains_authority(void)
{
 struct xdev_ext_session *s;
 int fd, own, before;

 REQUIRE_API(xdev_ext_session_open_peer);
 fd = authority();
 before = fd_count();
 s = opened_peer(fd, true);
 if (!s) { close(fd); return; }
 own = seen_create.pool_fd;
 stop_ret = -EBUSY;
 reply_stats.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
 reply_stats.sequestered = 1;
 EXPECT_EQ(xdev_ext_session_stop(s), -EBUSY);
 EXPECT_TRUE(xdev_ext_session_retained(s));
 EXPECT_EQ(xdev_ext_session_close(s), -EBUSY);
 EXPECT_EQ(stops, 1);
 EXPECT_EQ(xdev_ext_session_id(s), 77);
 EXPECT_TRUE(fcntl(own, F_GETFD) >= 0);
 EXPECT_TRUE(fcntl(fd, F_GETFD) >= 0);
 EXPECT_EQ(fd_count(), before + 3);
 stats_ret = -EIO;
 EXPECT_EQ(xdev_ext_session_close(s), -EBUSY);
 EXPECT_TRUE(fcntl(own, F_GETFD) >= 0);
 /* Only a definite kernel ENOENT permits freeing the retained handle. */
 stats_ret = -ENOENT;
 EXPECT_EQ(xdev_ext_session_close(s), 0);
 EXPECT_EQ(fcntl(own, F_GETFD), -1);
 EXPECT_EQ(fd_count(), before);
 close(fd);
}

static struct xdev_ext_user_batch sample_batch(void)
{
 struct xdev_ext_user_batch b = { .slot = 1, .nr_frames = 2, .ticket = 17 };

 b.f[0] = (struct xdev_ext_user_frame) {
  .umem_addr = 7ULL * FRAME_SIZE, .data_off = 64, .data_len = 1024,
  .capacity = FRAME_SIZE - 64, .out_len = 1024,
 };
 b.f[1] = b.f[0];
 b.f[1].umem_addr = 3ULL * FRAME_SIZE;
 return b;
}

static void test_peer_span_valid(void)
{
 struct xdev_ext_user_batch b = sample_batch();
 struct xdev_ext_peer_span out;
 const __u64 va = 0x100000000ULL;

 REQUIRE_API(xdev_ext_user_batch_peer_span);
 memset(&out, 0, sizeof(out));
 EXPECT_EQ(xdev_ext_user_batch_peer_span(&b, 0, va,
  POOL_FRAMES * FRAME_SIZE, FRAME_SIZE, &out), 0);
 EXPECT_EQ(out.offset, 7ULL * FRAME_SIZE + 64);
 EXPECT_EQ(out.device_address, va + 7ULL * FRAME_SIZE + 64);
 EXPECT_EQ(out.frame_index, 7);
 EXPECT_EQ(out.data_len, 1024);
 EXPECT_EQ(out.capacity, FRAME_SIZE - 64);
 EXPECT_EQ(xdev_ext_user_batch_peer_span(&b, 1, va,
  POOL_FRAMES * FRAME_SIZE, FRAME_SIZE, &out), 0);
 EXPECT_EQ(out.frame_index, 3);
 EXPECT_EQ(out.device_address, va + 3ULL * FRAME_SIZE + 64);
}

static void expect_bad_span(const struct xdev_ext_user_batch *b, __u32 pos,
 __u64 va, __u64 bytes, __u32 frame_size)
{
 struct xdev_ext_peer_span out, before;

 memset(&before, 0xa5, sizeof(before));
 out = before;
 EXPECT_TRUE(xdev_ext_user_batch_peer_span(b, pos, va, bytes, frame_size, &out) < 0);
 EXPECT_EQ(memcmp(&out, &before, sizeof(out)), 0);
}

static void test_peer_span_errors_are_atomic(void)
{
 struct xdev_ext_user_batch b = sample_batch(), bad;
 const __u64 bytes = POOL_FRAMES * FRAME_SIZE;

 REQUIRE_API(xdev_ext_user_batch_peer_span);
 expect_bad_span(NULL, 0, 0, bytes, FRAME_SIZE);
 expect_bad_span(&b, 2, 0, bytes, FRAME_SIZE);
 expect_bad_span(&b, XDEV_EXT_MECH_MAX_FRAMES, 0, bytes, FRAME_SIZE);
 expect_bad_span(&b, 0, 0, bytes, 0);
 expect_bad_span(&b, 0, UINT64_MAX - 4095, bytes, FRAME_SIZE);
 /* A valid start address alone is insufficient when its payload span wraps. */
 expect_bad_span(&b, 0, UINT64_MAX - (7ULL * FRAME_SIZE + 64) - 511,
                 bytes, FRAME_SIZE);
 expect_bad_span(&b, 0, 0, 7ULL * FRAME_SIZE, FRAME_SIZE);
 expect_bad_span(&b, 0, 0, 8ULL * FRAME_SIZE - 1, FRAME_SIZE);
 bad = b; bad.f[0].umem_addr++;
 expect_bad_span(&bad, 0, 0, bytes, FRAME_SIZE);
 bad = b; bad.f[0].umem_addr = UINT64_MAX - 63;
 expect_bad_span(&bad, 0, 0, UINT64_MAX, FRAME_SIZE);
 bad = b; bad.f[0].data_off = FRAME_SIZE;
 expect_bad_span(&bad, 0, 0, bytes, FRAME_SIZE);
 bad = b; bad.f[0].capacity++;
 expect_bad_span(&bad, 0, 0, bytes, FRAME_SIZE);
 bad = b; bad.f[0].data_len = FRAME_SIZE;
 expect_bad_span(&bad, 0, 0, bytes, FRAME_SIZE);
 bad = b; bad.f[0].umem_addr = ((uint64_t)UINT32_MAX + 1) * FRAME_SIZE;
 expect_bad_span(&bad, 0, 0, UINT64_MAX, FRAME_SIZE);
 EXPECT_TRUE(xdev_ext_user_batch_peer_span(&b, 0, 0, bytes, FRAME_SIZE, NULL) < 0);
}

static struct xdev_ext_user_stage *opened_user(bool external)
{
 struct xdev_ext_user_stage_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_user_stage_opts,
  .ring_fd = 3, .entries = USER_ENTRIES,
  .flags = external ? XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL : 0);
 struct xdev_ext_user_stage *u = NULL;

 EXPECT_EQ(xdev_ext_user_stage_open(&o, &u), 0);
 EXPECT_TRUE(u != NULL);
 return u;
}

static void test_control_mapping_and_peer_metadata(void)
{
 struct xdev_ext_user_stage *u;
 struct xdev_ext_user_ring_offsets off;
 struct xdev_ext_user_ring_hdr *h;
 struct xdev_ext_user_slot *slots;
 struct xdev_ext_user_ready *r;
 struct xdev_ext_user_batch b = sample_batch(), got;
 void *base = NULL;
 unsigned int i;

 REQUIRE_API(xdev_ext_user_stage_control);
 u = opened_user(true);
 if (!u)
  return;
 EXPECT_EQ(seen_user.flags, XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL);
 EXPECT_EQ(xdev_ext_user_stage_control(u, &base, &off), 0);
 EXPECT_TRUE(base != NULL && base != MAP_FAILED);
 EXPECT_EQ(off.mmap_size, USER_MAP);
 EXPECT_EQ(off.ready, USER_READY);
 EXPECT_EQ(off.done, USER_DONE);
 EXPECT_EQ(off.slots, USER_SLOTS);
 h = base;
 slots = (void *)((char *)base + off.slots);
 r = (void *)((char *)base + off.ready);
 slots[1].ticket = b.ticket;
 slots[1].nr_frames = b.nr_frames;
 for (i = 0; i < b.nr_frames; i++)
  slots[1].f[i] = b.f[i];
 r[0] = (struct xdev_ext_user_ready) {
  .slot = 1, .nr_frames = 2, .ticket = b.ticket, .batch_id = 42, .key = 101,
 };
 __atomic_store_n(&h->ready_prod, 1, __ATOMIC_RELEASE);
 EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &got), 0);
 EXPECT_EQ(got.f[0].umem_addr, 7ULL * FRAME_SIZE);
 EXPECT_EQ(got.f[1].umem_addr, 3ULL * FRAME_SIZE);
 for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++)
  EXPECT_TRUE(got.data[i] == NULL);
 EXPECT_EQ(got.ticket, 17);
 EXPECT_EQ(got.key, 101);
 EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

static void test_attach_detach_and_close_retention(void)
{
 struct xdev_ext_user_stage *u;
 struct xdev_ext_user_ring_offsets off, after;
 void *base = NULL, *again = NULL;
 int before = fd_count();

 REQUIRE_API(xdev_ext_user_stage_control);
 REQUIRE_API(xdev_ext_user_stage_ctl_attach);
 REQUIRE_API(xdev_ext_user_stage_ctl_detach);
 u = opened_user(true);
 if (!u)
  return;
 EXPECT_EQ(xdev_ext_user_stage_control(u, &base, &off), 0);
 EXPECT_EQ(xdev_ext_user_stage_ctl_attach(u), 0);
 EXPECT_EQ(seen_ioctl_arg, 0);
 EXPECT_EQ(xdev_ext_user_stage_ctl_attach(u), -EALREADY);
 EXPECT_EQ(xdev_ext_user_stage_close(u), -EBUSY);
 bound = true;
 EXPECT_EQ(xdev_ext_user_stage_ctl_detach(u), -EBUSY);
 EXPECT_EQ(xdev_ext_user_stage_close(u), -EBUSY);
 EXPECT_EQ(xdev_ext_user_stage_control(u, &again, &after), 0);
 EXPECT_TRUE(again == base);
 EXPECT_EQ(memcmp(&off, &after, sizeof(off)), 0);
 EXPECT_TRUE(fcntl(user_fd, F_GETFD) >= 0);
 bound = false;
 detach_ret = -EIO;
 EXPECT_EQ(xdev_ext_user_stage_ctl_detach(u), -EIO);
 EXPECT_EQ(xdev_ext_user_stage_close(u), -EBUSY);
 detach_ret = 0;
 EXPECT_EQ(xdev_ext_user_stage_ctl_detach(u), 0);
 EXPECT_EQ(seen_ioctl_arg, 0);
 EXPECT_EQ(xdev_ext_user_stage_ctl_detach(u), -ENOENT);
 EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
 EXPECT_EQ(fd_count(), before);
}

static void test_failed_attach_does_not_pin_local_handle(void)
{
 struct xdev_ext_user_stage *u;
 int before = fd_count();

 REQUIRE_API(xdev_ext_user_stage_ctl_attach);
 REQUIRE_API(xdev_ext_user_stage_ctl_detach);
 u = opened_user(true);
 if (!u)
  return;
 attach_ret = -EIO;
 EXPECT_EQ(xdev_ext_user_stage_ctl_attach(u), -EIO);
 EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
 EXPECT_EQ(fd_count(), before);
 EXPECT_EQ(munmap(kernel_map, USER_MAP), 0);
 kernel_map = NULL;
 attach_ret = 0;
 u = opened_user(false);
 if (!u)
  return;
 EXPECT_EQ(xdev_ext_user_stage_ctl_attach(u), -EOPNOTSUPP);
 EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
 EXPECT_EQ(fd_count(), before);
}

static void test_unknown_done_does_not_release_control_pin(void)
{
 struct xdev_ext_user_stage *u;
 struct xdev_ext_user_ring_offsets off;
 struct xdev_ext_user_ring_hdr *h;
 struct xdev_ext_user_done *d;
 struct xdev_ext_user_ready *r;
 struct xdev_ext_user_slot *ss;
 struct xdev_ext_user_batch b;
 void *base = NULL;

 REQUIRE_API(xdev_ext_user_stage_control);
 REQUIRE_API(xdev_ext_user_stage_ctl_attach);
 REQUIRE_API(xdev_ext_user_stage_ctl_detach);
 u = opened_user(true);
 if (!u)
  return;
 EXPECT_EQ(xdev_ext_user_stage_ctl_attach(u), 0);
 EXPECT_EQ(xdev_ext_user_stage_control(u, &base, &off), 0);
 h = base;
 d = (void *)((char *)base + off.done);
 r = (void *)((char *)base + off.ready);
 ss = (void *)((char *)base + off.slots);
 ss[0].ticket = 901;
 ss[0].nr_frames = 1;
 ss[0].f[0] = sample_batch().f[0];
 r[0] = (struct xdev_ext_user_ready) { .slot = 0, .nr_frames = 1, .ticket = 901 };
 __atomic_store_n(&h->ready_prod, 1, __ATOMIC_RELEASE);
 EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), 0);
 EXPECT_EQ(xdev_ext_user_stage_complete(u, &b, -EIO), 0);
 EXPECT_EQ(h->done_prod, 1);
 EXPECT_EQ(d[0].ticket, 901);
 EXPECT_EQ(d[0].status, -EIO);
 h->kernel_flags = XDEV_EXT_USER_K_DRAINING | XDEV_EXT_USER_K_STOPPED;
 EXPECT_EQ(xdev_ext_user_stage_close(u), -EBUSY);
 EXPECT_TRUE(fcntl(user_fd, F_GETFD) >= 0);
 bound = true;
 EXPECT_EQ(xdev_ext_user_stage_ctl_detach(u), -EBUSY);
 EXPECT_EQ(xdev_ext_user_stage_close(u), -EBUSY);
 /* Test cleanup represents an owner proving quiescence and successful unbind. */
 bound = false;
 EXPECT_EQ(xdev_ext_user_stage_ctl_detach(u), 0);
 EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

static void run(void (*fn)(void), const char *name)
{
 unsigned int before = failures;
 int initial_fds;

 reset();
 xdev_ext__set_sys(&fake_sys);
 initial_fds = fd_count();
 fn();
 EXPECT_EQ(fd_count(), initial_fds);
 xdev_ext__set_sys(NULL);
 printf("%s %u - %s\n", failures == before ? "ok" : "not ok", ++tests, name);
}

#define RUN(fn) run(fn, #fn)
int main(void)
{
 printf("TAP version 13\n1..14\n");
 RUN(test_peer_fd_ownership);
 RUN(test_peer_validation_cleanup);
 RUN(test_ordered_frames_and_arm);
 RUN(test_ordered_recycle_choice);
 RUN(test_start_failures_do_not_commit);
 RUN(test_start_validation);
 RUN(test_repeat_requires_drain_and_accumulates_target);
 RUN(test_unknown_retains_authority);
 RUN(test_peer_span_valid);
 RUN(test_peer_span_errors_are_atomic);
 RUN(test_control_mapping_and_peer_metadata);
 RUN(test_attach_detach_and_close_retention);
 RUN(test_failed_attach_does_not_pin_local_handle);
 RUN(test_unknown_done_does_not_release_control_pin);
 reset();
 printf("# checks=%u failures=%u\n", checks, failures);
 return failures ? 1 : 0;
}

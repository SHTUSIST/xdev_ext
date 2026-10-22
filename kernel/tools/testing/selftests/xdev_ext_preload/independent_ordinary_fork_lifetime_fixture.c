/* SPDX-License-Identifier: GPL-2.0 */
/* Included in the generated actual-function translation unit by the driver.
 * Setup/register are substitutes; this is not a kernel or DMA integration test.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "@TOOLS@/xdev_ext_preload_core.h"
static int watched_mutex_lock(pthread_mutex_t *m);
#define pthread_mutex_lock watched_mutex_lock
#include "@TOOLS@/xdev_ext_preload_fd_shard.h"
#undef pthread_mutex_lock
#include "@TOOLS@/../include/uapi/linux/xdev_ext_mech.h"

static int watched_close(int fd);
static int watched_munmap(void *p, size_t n);
/* Keep the actual mini_liburing queue_exit body, instrumenting its syscalls. */
#define close watched_close
#define munmap watched_munmap
#include "@TOOLS@/include/io_uring/mini_liburing.h"
#undef close
#undef munmap

/* ACTUAL_TYPES */

enum { MAX_RINGS = 8, PAGE = 4096 };
struct observation {
 int fd, closes, unmaps, registered;
 void *maps[3];
 struct io_uring *ring;
};
static struct observation records[MAX_RINGS];
static int nr_records, duplicate_closes, child_stop, child_unregister, stop_count;
static int child_hook_allocations, child_admission_reset, register_failure;
static int queue_failure, allocation_failure, stop_failure, gate_kind, target_record = -1;
static int gate_hit, gate_removed, notice_pipe[2], baseline_fds;
static pid_t parent_pid;
static __thread bool gated_worker, in_prepare, inside_child_hook, did_remove;
static sem_t gate_ready, gate_release, worker_ready, worker_release;
static struct xdev_ext_thread_ctx *contexts[3];
static pthread_mutex_t records_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { size_t frame_size; } xdev_ext_cfg = { .frame_size = PAGE };
static pthread_mutex_t xdev_ext_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static struct xdev_ext_preload_fd_lockset xdev_ext_fd_locks = XDEV_EXT_PRELOAD_FD_LOCKSET_INITIALIZER;
static struct xdev_ext_thread_ctx *xdev_ext_threads;
static __thread unsigned xdev_ext_in_hook;

static struct timespec deadline(void)
{
 struct timespec t; assert(!clock_gettime(CLOCK_REALTIME, &t)); t.tv_sec += 5; return t;
}
static void sem_wait_bounded(sem_t *s)
{
 struct timespec t = deadline(); int ret;
 do { ret = sem_timedwait(s, &t); } while (ret && errno == EINTR);
 assert(!ret);
}
static void join_bounded(pthread_t t)
{ struct timespec d = deadline(); assert(!pthread_timedjoin_np(t, NULL, &d)); }
static void emit_notice(char c)
{ assert(write(notice_pipe[1], &c, 1) == 1); }
static void pause_resource(int kind)
{
 if (!gated_worker || gate_kind != kind) return;
 gate_hit++; gate_removed = did_remove;
 assert(!sem_post(&gate_ready)); sem_wait_bounded(&gate_release);
}
static int watched_mutex_lock(pthread_mutex_t *m)
{
 if (in_prepare) {
  int ret = pthread_mutex_trylock(m);
  if (!ret) return 0;
  assert(ret == EBUSY);
  /* Exact evidence of a protecting lock blocking fork, never a timing guess. */
  emit_notice('B');
 }
 return pthread_mutex_lock(m);
}
static int watched_close(int fd)
{
 for (int i = 0; i < nr_records; i++) if (records[i].fd == fd) {
  if (records[i].closes++) duplicate_closes++;
 }
 return close(fd);
}
static int watched_munmap(void *p, size_t n)
{
 for (int i = 0; i < nr_records; i++)
  for (int j = 0; j < 3; j++) if (records[i].maps[j] == p) records[i].unmaps++;
 return munmap(p, n);
}
static void watched_free(void *p)
{ if (inside_child_hook && p) child_hook_allocations++; free(p); }
static void *watched_calloc(size_t n, size_t s)
{
 if (inside_child_hook) child_hook_allocations++;
 return allocation_failure == 2 ? NULL : calloc(n, s);
}
static int watched_posix_memalign(void **p, size_t a, size_t s)
{
 if (inside_child_hook) child_hook_allocations++;
 return allocation_failure == 1 ? ENOMEM : posix_memalign(p, a, s);
}
static long watched_syscall(long nr, ...)
{
 va_list ap; va_start(ap, nr); long ret;
 if (nr == SYS_gettid) ret = syscall(SYS_gettid);
 else if (nr == SYS_close) ret = watched_close(va_arg(ap, int));
 else if (nr == SYS_io_uring_register) {
  int fd = va_arg(ap, int); unsigned op = va_arg(ap, unsigned);
  int i; for (i = 0; i < nr_records && records[i].fd != fd; i++) {}
  assert(i < nr_records);
  if (op == IORING_REGISTER_XDEV_EXT_UMEM) {
   if (register_failure) { errno = EIO; ret = -1; }
   else { records[i].registered = 1; ret = 0; }
  } else {
   assert(op == IORING_UNREGISTER_XDEV_EXT_UMEM);
   if (getpid() != parent_pid) child_unregister++;
   records[i].registered = 0; ret = 0;
  }
 } else { fprintf(stderr, "unexpected seam syscall %ld\n", nr); abort(); }
 va_end(ap); return ret;
}
static int seam_queue_init(unsigned entries, struct io_uring *ring, unsigned flags)
{
 assert(entries == 2 && !flags); if (queue_failure) return -EIO;
 pthread_mutex_lock(&records_lock); assert(nr_records < MAX_RINGS);
 int i = nr_records++; struct observation *r = &records[i]; r->ring = ring;
 r->fd = ring->ring_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK); assert(r->fd >= 0);
 for (int j = 0; j < 3; j++) {
  r->maps[j] = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(r->maps[j] != MAP_FAILED); *(unsigned *)r->maps[j] = 2;
 }
 ring->sq.ring_ptr = r->maps[0]; ring->sq.ring_sz = PAGE;
 ring->sq.kring_entries = r->maps[0]; ring->sq.sqes = r->maps[1];
 ring->cq.ring_ptr = r->maps[2]; ring->cq.ring_sz = PAGE;
 if (gated_worker) target_record = i;
 pthread_mutex_unlock(&records_lock);
 pause_resource(1); return 0;
}
static int watched_queue_exit(struct io_uring *ring)
{ pause_resource(2); return io_uring_queue_exit(ring); }
static void xdev_ext_report_thread_locked(struct xdev_ext_thread_ctx *t) { (void)t; }
static void xdev_ext_admission_after_fork_child(void) { child_admission_reset++; }
static int xdev_ext_socket_mech_control(struct xdev_ext_socket_mech_runtime *m, unsigned op, uint64_t arg)
{
 assert(m && op == XDEV_EXT_MECH_OP_STOP && arg == 7);
 if (getpid() != parent_pid) child_stop++;
 stop_count++; return stop_failure ? -EBUSY : 0;
}
static void mark_remove(struct xdev_ext_thread_ctx *t);
#define xdev_ext_remove_thread_locked mark_remove
#define pthread_mutex_lock watched_mutex_lock
#define syscall watched_syscall
#define close watched_close
#define munmap watched_munmap
#define free watched_free
#define calloc watched_calloc
#define posix_memalign watched_posix_memalign
#define io_uring_queue_init seam_queue_init
#define io_uring_queue_exit watched_queue_exit

/* ACTUAL_FUNCTIONS */

#undef xdev_ext_remove_thread_locked
#undef pthread_mutex_lock
#undef syscall
#undef close
#undef munmap
#undef free
#undef calloc
#undef posix_memalign
#undef io_uring_queue_init
#undef io_uring_queue_exit

/* The production remove body above runs unchanged. Mark its completion for
 * the real queue_exit barrier, without rewriting a statement of that body. */
static void mark_remove(struct xdev_ext_thread_ctx *t)
{ actual_remove_thread_locked(t); did_remove = true; }

static int descriptor_count(void)
{
 DIR *d = opendir("/proc/self/fd"); struct dirent *e; int count = 0; assert(d);
 while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) count++;
 assert(!closedir(d)); return count;
}
static int mapped(void *p)
{
 unsigned char byte; errno = 0; int ret = mincore(p, PAGE, &byte);
 assert(!ret || (ret == -1 && errno == ENOMEM)); return ret == 0;
}
static bool closed_record(int i)
{
 bool fd_closed = fcntl(records[i].fd, F_GETFD) == -1 && errno == EBADF;
 bool maps_closed = true;
 for (int j = 0; j < 3; j++) maps_closed &= !mapped(records[i].maps[j]);
 return fd_closed && maps_closed;
}
static void parent_usable(int i)
{
 struct observation *r = &records[i]; uint64_t one = 1, got = 0;
 assert(fcntl(r->fd, F_GETFD) >= 0 && !r->closes && !r->unmaps && r->registered);
 assert(write(r->fd, &one, sizeof(one)) == sizeof(one));
 assert(read(r->fd, &got, sizeof(got)) == sizeof(got) && got == one);
 for (int j = 0; j < 3; j++) {
  assert(mapped(r->maps[j])); *(unsigned *)r->maps[j] = 2;
 }
}
static void prepare(void) { in_prepare = true; xdev_ext_atfork_prepare(); in_prepare = false; }
static void parent_hook(void) { xdev_ext_atfork_parent(); }
static void child_hook(void)
{ inside_child_hook = true; xdev_ext_atfork_child(); inside_child_hook = false; }
static struct xdev_ext_thread_ctx *new_context(void)
{
 struct xdev_ext_thread_ctx *c = calloc(1, sizeof(*c)); assert(c);
 int ret = xdev_ext_thread_init(c); assert(!ret && c->ring_ready && c->umem_registered);
 return c;
}
static void *live_worker(void *arg)
{
 int slot = (int)(intptr_t)arg; contexts[slot] = new_context();
 assert(!sem_post(&worker_ready)); sem_wait_bounded(&worker_release); return NULL;
}
static int check_child(int first_worker, bool allow_main)
{
 int inherited = 0, dropped = 0;
 /* First observation: no preload I/O or lazy refresh has run in this child. */
 for (int i = first_worker; i < nr_records; i++) {
  if (!closed_record(i)) inherited++;
  else dropped++;
 }
 if (allow_main && closed_record(0)) dropped++;
 int current = descriptor_count();
 assert(!child_stop && !child_unregister && !child_hook_allocations && !duplicate_closes);
 if (inherited) {
  dprintf(2, "RED: first child observation retains %d ordinary worker fd/VMA bundle(s); no child preload call preceded observation\n", inherited);
 }
 if (!inherited) assert(current == baseline_fds - dropped);
 if (allow_main) xdev_ext_discard_inherited_thread(contexts[0]);
 for (int i = 0; i < nr_records; i++) {
  if (inherited && !(allow_main && i == 0) && !closed_record(i)) continue;
  assert(closed_record(i)); assert(records[i].closes == 1 && records[i].unmaps == 3);
 }
 assert(!duplicate_closes && !child_stop && !child_unregister);
 assert(child_admission_reset == 1);
 if (allow_main)
  dprintf(2, "# child main lazy cleanup close=1 unmaps=3 STOP=0 unregister=0 allocator-in-atfork=0\n");
 return inherited ? 41 : 0;
}
static int wait_child(pid_t pid)
{
 int status; pid_t ret; do { ret = waitpid(pid, &status, 0); } while (ret < 0 && errno == EINTR);
 assert(ret == pid);
 return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
static int steady(const char *name)
{
 pthread_t workers[2]; contexts[0] = new_context();
 for (int i = 0; i < 2; i++) assert(!pthread_create(&workers[i], NULL, live_worker, (void *)(intptr_t)(i + 1)));
 for (int i = 0; i < 2; i++) sem_wait_bounded(&worker_ready);
 if (!strcmp(name, "unknown-worker")) contexts[1]->quiescence_unknown = true;
 int failure = 0, rounds = !strcmp(name, "repeated-fork") ? 3 : 1;
 for (int round = 0; round < rounds; round++) {
  baseline_fds = descriptor_count(); pid_t pid = fork(); assert(pid >= 0);
  if (!pid) _exit(check_child(1, true));
  int status = wait_child(pid); if (status) failure = status;
  for (int i = 0; i < nr_records; i++) parent_usable(i);
  assert(!stop_count && !child_unregister && !duplicate_closes && !child_admission_reset);
  printf("# parent round=%d usable=%d registered=%d STOP=0 unregister=0 child_status=%d\n", round + 1, nr_records, nr_records, status);
 }
 for (int i = 0; i < 2; i++) assert(!sem_post(&worker_release));
 for (int i = 0; i < 2; i++) join_bounded(workers[i]);
 if (contexts[1]->quiescence_unknown) {
  int held = -1; bool retained = false;
  for (int i = 0; i < nr_records; i++) if (records[i].ring == &contexts[1]->ring) held = i;
  assert(held >= 0);
  xdev_ext_thread_destroy(contexts[1]);
  for (struct xdev_ext_thread_ctx *c = xdev_ext_threads; c; c = c->next) retained |= c == contexts[1];
  parent_usable(held); assert(retained && contexts[1]->quiescence_unknown);
  printf("# parent UNKNOWN destructor retained registry/fd/3-VMAs/registration; child drop is not quiescence evidence\n");
  contexts[1]->quiescence_unknown = false;
 }
 for (int i = 0; i < 3; i++) xdev_ext_thread_destroy(contexts[i]);
 for (int i = 0; i < nr_records; i++) assert(closed_record(i) && records[i].closes == 1 && records[i].unmaps == 3);
 assert(!duplicate_closes); return failure;
}
static int fork_result;
static void *window_fork(void *arg)
{
 (void)arg; baseline_fds = descriptor_count(); pid_t pid = fork(); assert(pid >= 0);
 if (!pid) { emit_notice('C'); _exit(check_child(0, false)); }
 fork_result = wait_child(pid); return NULL;
}
static void *window_worker(void *arg)
{
 (void)arg; gated_worker = true;
 if (gate_kind == 1) contexts[0] = new_context();
 else xdev_ext_thread_destroy(contexts[0]);
 return NULL;
}
static int window(int kind)
{
 pthread_t worker, forker; gate_kind = kind;
 if (kind == 2) contexts[0] = new_context();
 assert(!pthread_create(&worker, NULL, window_worker, NULL)); sem_wait_bounded(&gate_ready);
 assert(gate_hit == 1 && nr_records == 1 && target_record <= 0);
 assert(fcntl(records[0].fd, F_GETFD) >= 0);
 for (int j = 0; j < 3; j++) assert(mapped(records[0].maps[j]));
 printf("# barrier reached=%d kind=%s actual_registry_remove_completed=%d fd_live=1 vmas_live=3\n", gate_hit, kind == 1 ? "created-before-publication" : "queue-exit-before-close", gate_removed);
 fflush(stdout); assert(!pthread_create(&forker, NULL, window_fork, NULL));
 struct pollfd p = { .fd = notice_pipe[0], .events = POLLIN }; int pollret;
 do { pollret = poll(&p, 1, 5000); } while (pollret < 0 && errno == EINTR);
 assert(pollret == 1); char event; assert(read(notice_pipe[0], &event, 1) == 1);
 assert(event == 'B' || event == 'C');
 printf("# window event=%s; barrier released only after exact event\n", event == 'B' ? "atfork-protecting-lock-blocked" : "child-fork-completed-while-resource-paused");
 assert(!sem_post(&gate_release)); join_bounded(worker); join_bounded(forker);
 if (kind == 1) { parent_usable(0); xdev_ext_thread_destroy(contexts[0]); }
 assert(closed_record(0) && records[0].closes == 1 && records[0].unmaps == 3 && !duplicate_closes);
 assert(!child_stop && !child_unregister && !stop_count);
 printf("# barrier campaign child_status=%d parent_close=1 parent_unmaps=3\n", fork_result);
 return fork_result;
}
static int empty_case(bool inert)
{
 assert(!xdev_ext_threads && !nr_records); if (inert) xdev_ext_thread_destroy(NULL);
 baseline_fds = descriptor_count(); pid_t pid = fork(); assert(pid >= 0);
 if (!pid) { assert(descriptor_count() == baseline_fds && !xdev_ext_threads && child_admission_reset == 1); _exit(0); }
 int ret = wait_child(pid); assert(!child_admission_reset && !nr_records); return ret;
}
static int partial(bool queue)
{
 struct xdev_ext_thread_ctx *c = calloc(1, sizeof(*c)); assert(c);
 if (queue) queue_failure = 1; else register_failure = 1;
 assert(xdev_ext_thread_init(c) == -EIO); assert(!xdev_ext_threads && !c->ring_ready && !c->umem && !c->shared);
 assert(nr_records == (queue ? 0 : 1));
 for (int i = 0; i < nr_records; i++) assert(closed_record(i) && records[i].closes == 1 && records[i].unmaps == 3);
 assert(!duplicate_closes); free(c);
 baseline_fds = descriptor_count(); pid_t pid = fork(); assert(pid >= 0);
 if (!pid) { assert(descriptor_count() == baseline_fds && !child_stop && !child_unregister); _exit(0); }
 return wait_child(pid);
}
static int partial_allocation(int failure)
{
 struct xdev_ext_thread_ctx *c = calloc(1, sizeof(*c)); assert(c);
 allocation_failure = failure;
 assert(xdev_ext_thread_init(c) == -ENOMEM);
 assert(!xdev_ext_threads && !nr_records && !c->umem && !c->shared && !c->ring_ready);
 allocation_failure = 0; free(c); return empty_case(false);
}
static int main_only(void)
{
 contexts[0] = new_context(); baseline_fds = descriptor_count();
 pid_t pid = fork(); assert(pid >= 0); if (!pid) _exit(check_child(1, true));
 int ret = wait_child(pid); parent_usable(0); xdev_ext_thread_destroy(contexts[0]);
 assert(closed_record(0) && records[0].closes == 1 && !duplicate_closes); return ret;
}
static int failed_teardown(void)
{
 contexts[0] = new_context(); struct xdev_ext_thread_ctx *c = contexts[0];
 c->socket_mech.owner = parent_pid; c->socket_mech.session = 7;
 c->socket_mech.ring = c->socket_mech.event = c->socket_mech.ce_fd = -1;
 stop_failure = 1; xdev_ext_thread_destroy(c);
 assert(stop_count == 1 && c->socket_mech.unknown && xdev_ext_threads == c); parent_usable(0);
 baseline_fds = descriptor_count(); pid_t pid = fork(); assert(pid >= 0);
 if (!pid) _exit(check_child(0, false));
 int ret = wait_child(pid); assert(stop_count == 1 && c->socket_mech.session == 7); parent_usable(0);
 stop_failure = 0; c->socket_mech.unknown = false; xdev_ext_thread_destroy(c);
 assert(stop_count == 2 && !duplicate_closes && closed_record(0)); return ret;
}
int main(int argc, char **argv)
{
 assert(argc == 2); alarm(10); parent_pid = getpid();
 assert(!pipe2(notice_pipe, O_CLOEXEC));
 assert(!sem_init(&gate_ready, 0, 0) && !sem_init(&gate_release, 0, 0));
 assert(!sem_init(&worker_ready, 0, 0) && !sem_init(&worker_release, 0, 0));
 assert(!pthread_atfork(prepare, parent_hook, child_hook));
 if (!strcmp(argv[1], "no-context")) return empty_case(false);
 if (!strcmp(argv[1], "inert")) return empty_case(true);
 if (!strcmp(argv[1], "init-publication-gap")) return window(1);
 if (!strcmp(argv[1], "destroy-removal-gap")) return window(2);
 if (!strcmp(argv[1], "partial-register-failure")) return partial(false);
 if (!strcmp(argv[1], "partial-queue-failure")) return partial(true);
 if (!strcmp(argv[1], "partial-umem-allocation-failure")) return partial_allocation(1);
 if (!strcmp(argv[1], "partial-shared-allocation-failure")) return partial_allocation(2);
 if (!strcmp(argv[1], "main-lazy-only")) return main_only();
 if (!strcmp(argv[1], "teardown-stop-failure")) return failed_teardown();
 return steady(argv[1]);
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Independent OS/kernel boundary fixture. No USER worker is implemented here.
 * Compile real chain_bench + chain_session + lib USER; linker wraps kernel entry
 * points. Real pthreads, atomics, eventfds, shared mapping and CE file readback
 * remain. This fixture is software correctness evidence, never DMA/performance.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "kernel/include/uapi/linux/io_uring.h"
#include "kernel/include/uapi/linux/xdev_ext_mech.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int ring_fd = -1, token_fd = -1, source_fd = -1, ce_fd = -1, user_efd = -1;
static int terminal_efd = -1;
static bool created, stopped;
static struct xdev_ext_mech_create create_req;
static struct xdev_ext_mech_stats stats;
static struct xdev_ext_user_ring_hdr *hdr;
static struct xdev_ext_user_ready *ready;
static struct xdev_ext_user_done *done;
static struct xdev_ext_user_slot *slots;
static void *kernel_map, *client_map, *pool;
static size_t user_map_size, pool_size;
static unsigned int entries;
static uint64_t pending_seq, submitted, completed, ticket = 1000, lent;
static unsigned int thread_count, worker_affinity_ok, affinity_overrides;
static unsigned int ring_count, pool_count, create_count, user_open_count;
static unsigned int stop_calls, token_closes, pool_unmaps, user_unmaps;
static unsigned int release_before_stop, after_failed_stop, bad_lengths, bad_payload;
static unsigned int one_ack_errors, user_done_calls;
static unsigned int premature_terminal, entered_worker_before_create;
static bool stop_failed;
static const char *mode(void) { const char *p = getenv("UC_SCENARIO"); return p ? p : "success"; }
static bool scenario(const char *s) { return !strcmp(mode(), s); }

extern long __real_syscall(long number, ...);
extern int __real_open64(const char *, int, ...);
extern int __real_open(const char *, int, ...);
extern int __real_close(int);
extern int __real_ioctl(int, unsigned long, ...);
extern void *__real_mmap64(void *, size_t, int, int, int, off64_t);
extern int __real_munmap(void *, size_t);
extern int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

static void notify(int fd)
{
    uint64_t n = 1;
    if (fd >= 0 && write(fd, &n, sizeof(n)) != sizeof(n)) abort();
}

static int fixture_open(const char *path, int flags, mode_t perm)
{
    if (!strcmp(path, "/dev/ng_contract_src")) {
        source_fd = __real_open64(getenv("UC_SOURCE"), O_RDONLY | O_CLOEXEC);
        return source_fd;
    }
    if (!strcmp(path, "/dev/xdev_ext_ce_sim")) {
        ce_fd = __real_open64(getenv("UC_CE"), O_RDWR | O_CLOEXEC);
        return ce_fd;
    }
    return __real_open64(path, flags, perm);
}
int __wrap_open64(const char *path, int flags, ...)
{
    va_list ap; mode_t perm = 0;
    va_start(ap, flags);
    if (flags & O_CREAT) perm = (mode_t)va_arg(ap, int);
    va_end(ap);
    return fixture_open(path, flags, perm);
}
int __wrap_open(const char *path, int flags, ...)
{
    va_list ap; mode_t perm = 0;
    va_start(ap, flags);
    if (flags & O_CREAT) perm = (mode_t)va_arg(ap, int);
    va_end(ap);
    return fixture_open(path, flags, perm);
}

/* glibc _FORTIFY_SOURCE redirects two-argument open/open64 here. */
int __wrap___open64_2(const char *path, int flags)
{
    return fixture_open(path, flags, 0);
}
int __wrap___open_2(const char *path, int flags)
{
    return fixture_open(path, flags, 0);
}

void *__wrap_mmap64(void *addr, size_t len, int prot, int flags, int fd, off64_t off)
{
    void *result = __real_mmap64(addr, len, prot, flags, fd, off);
    if (fd == token_fd && fd >= 0 && result != MAP_FAILED) client_map = result;
    return result;
}
int __wrap_munmap(void *addr, size_t len)
{
    if (addr == pool || addr == client_map) {
        if (!stopped) release_before_stop++;
        if (stop_failed) after_failed_stop++;
        if (addr == pool) pool_unmaps++;
        if (addr == client_map) user_unmaps++;
    }
    return __real_munmap(addr, len);
}
int __wrap_close(int fd)
{
    if (created && (fd == ring_fd || fd == token_fd || fd == source_fd || fd == ce_fd)) {
        if (!stopped) release_before_stop++;
        if (stop_failed) after_failed_stop++;
        if (fd == token_fd) token_closes++;
    }
    return __real_close(fd);
}

static void copy_device_record(uint64_t seq)
{
    unsigned char b[4096];
    off_t src = (off_t)(create_req.st[0].arg0 * 512 + (seq - 1) * 4096);
    off_t dst = (off_t)create_req.st[2].arg0;
    if (pread(source_fd, b, sizeof(b), src) != sizeof(b)) abort();
    if (pwrite(ce_fd, b, sizeof(b), dst) != sizeof(b)) abort();
}

static int publish(uint64_t seq)
{
    struct xdev_ext_user_slot *s = &slots[0];
    struct xdev_ext_user_ready *r = &ready[hdr->ready_prod & (entries - 1)];
    unsigned char b[4096];
    if (pread(source_fd, b, sizeof(b), (off_t)(create_req.st[0].arg0 * 512 + (seq - 1) * 4096)) != sizeof(b)) return -EIO;
    memcpy(pool, b, sizeof(b));
    memset(s, 0, sizeof(*s));
    s->nr_frames = 1;
    s->f[0] = (struct xdev_ext_user_frame){ .umem_addr = 0, .data_off = 0,
        .data_len = 4096, .capacity = 4096, .out_len = 4096 };
    __atomic_store_n(&s->ticket, ++ticket, __ATOMIC_RELEASE);
    *r = (struct xdev_ext_user_ready){ .slot = 0, .nr_frames = 1,
        .ticket = ticket, .batch_id = seq, .key = seq };
    if (scenario("malformed-ready")) r->nr_frames = 0;
    if (scenario("stale-ready")) r->ticket = ticket - 1;
    __atomic_store_n(&hdr->ready_prod, hdr->ready_prod + 1, __ATOMIC_RELEASE);
    notify(user_efd);
    return 0;
}

static void terminal_success(void)
{
    unsigned int i;
    stats.state = XDEV_EXT_MECH_SESSION_ACTIVE;
    stats.batches_done = submitted;
    stats.published = lent;
    for (i = 0; i < create_req.nr_stages; i++) stats.submitted[i] = stats.completed[i] = submitted;
    notify(terminal_efd);
}

static int mech(unsigned int op, uint64_t arg)
{
    if (op == XDEV_EXT_MECH_OP_USER_STAGE) {
        struct xdev_ext_mech_user_stage *u = (void *)(uintptr_t)arg;
        user_open_count++;
        if (u->entries != 4 || u->flags) return -EINVAL;
        entries = u->entries;
        user_efd = u->eventfd;
        token_fd = memfd_create("independent-user-kernel-boundary", MFD_CLOEXEC);
        u->fd = token_fd;
        u->off.hdr = 0;
        u->off.ready = 4096;
        u->off.done = 8192;
        u->off.slots = 12288;
        u->off.mmap_size = user_map_size = 32768;
        if (ftruncate(token_fd, (off_t)user_map_size)) return -errno;
        kernel_map = __real_mmap64(NULL, user_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, token_fd, 0);
        if (kernel_map == MAP_FAILED) return -errno;
        hdr = kernel_map;
        ready = (void *)((char *)kernel_map + u->off.ready);
        done = (void *)((char *)kernel_map + u->off.done);
        slots = (void *)((char *)kernel_map + u->off.slots);
        hdr->kernel_flags = XDEV_EXT_USER_K_NEED_KICK;
        return 0;
    }
    if (op == XDEV_EXT_MECH_OP_CREATE) {
        struct xdev_ext_mech_create *c = (void *)(uintptr_t)arg;
        create_count++;
        if (!hdr || c->nr_stages != 3 || c->pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM ||
            c->st[0].class_id != XDEV_EXT_MECH_CLASS_NVME ||
            c->st[1].class_id != XDEV_EXT_MECH_CLASS_USER ||
            c->st[2].class_id != XDEV_EXT_MECH_CLASS_CE ||
            c->st[1].direction != XDEV_EXT_MECH_DIR_TO_DEVICE ||
            c->st[1].fd != token_fd || c->st[1].flags || c->st[1].arg1 ||
            c->st[1].arg0 != 17 || c->depth != 3) return -EINVAL;
        c->session_id = 77;
        create_req = *c;
        terminal_efd = c->eventfd;
        stats.session_id = 77;
        created = true;
        return 0;
    }
    if (op == XDEV_EXT_MECH_OP_NOTIFY_ARM) return 0;
    if (op == XDEV_EXT_MECH_OP_START) {
        struct xdev_ext_mech_start *s = (void *)(uintptr_t)arg;
        if (s->session_id != 77 || s->nr_batches != 1 || !created) return -EINVAL;
        pending_seq = s->first_seq;
        submitted += s->nr_batches;
        lent += s->nr_user_frames;
        if (scenario("timeout") || scenario("stale-ready")) {
            /* Adversarial terminal event: helper outcome must still prevent pass. */
            copy_device_record(pending_seq);
            premature_terminal++;
            terminal_success();
            if (scenario("stale-ready")) return publish(pending_seq);
            return 0;
        }
        return publish(pending_seq);
    }
    if (op == XDEV_EXT_MECH_OP_STATS) {
        struct xdev_ext_mech_stats *s = (void *)(uintptr_t)arg;
        *s = stats;
        if (scenario("terminal-error")) { s->last_err = -EIO; s->batches_abort = 1; }
        return 0;
    }
    if (op == XDEV_EXT_MECH_OP_STOP) {
        stop_calls++;
        if (scenario("stop-fails")) { stop_failed = true; return -EBUSY; }
        stopped = true;
        if (hdr) {
            __atomic_or_fetch(&hdr->kernel_flags, XDEV_EXT_USER_K_STOPPED, __ATOMIC_RELEASE);
            notify(user_efd);
        }
        return 0;
    }
    return -EOPNOTSUPP;
}

long __wrap_syscall(long number, ...)
{
    va_list ap;
    long result;
    va_start(ap, number);
    if (number == __NR_io_uring_setup) {
        ring_count++;
        result = ring_fd = eventfd(0, EFD_CLOEXEC);
    } else if (number == __NR_io_uring_register) {
        int fd = va_arg(ap, int);
        unsigned int op = va_arg(ap, unsigned int);
        void *arg = va_arg(ap, void *);
        (void)va_arg(ap, unsigned int);
        pthread_mutex_lock(&lock);
        if (fd != ring_fd) result = -EBADF;
        else if (op == IORING_REGISTER_XDEV_EXT_UMEM) {
            struct io_uring_xdev_ext_umem_reg *u = arg;
            pool_count++;
            pool = (void *)(uintptr_t)u->addr;
            pool_size = u->size;
            result = 0;
        } else if (op == IORING_REGISTER_XDEV_EXT_MECH) {
            struct io_uring_xdev_ext_mech *r = arg;
            result = mech(r->op, r->arg);
        } else result = -EOPNOTSUPP;
        pthread_mutex_unlock(&lock);
        if (result < 0) { errno = (int)-result; result = -1; }
    } else {
        /* All unrelated production syscalls must retain native semantics. */
        unsigned long a[6];
        for (unsigned int i = 0; i < 6; i++) a[i] = va_arg(ap, unsigned long);
        result = __real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    }
    va_end(ap);
    return result;
}

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list ap; unsigned long arg;
    va_start(ap, request); arg = va_arg(ap, unsigned long); va_end(ap);
    if (fd == token_fd && request == XDEV_EXT_USER_IOC_KICK) {
        int result = 0;
        pthread_mutex_lock(&lock);
        while (hdr->done_cons != __atomic_load_n(&hdr->done_prod, __ATOMIC_ACQUIRE)) {
            struct xdev_ext_user_done *d = &done[hdr->done_cons & (entries - 1)];
            struct xdev_ext_user_slot *s = &slots[d->slot < entries ? d->slot : 0];
            unsigned char b[4096];
            user_done_calls++;
            if (d->slot >= entries || d->ticket != ticket || completed >= submitted) { one_ack_errors++; result = -ESTALE; }
            if (d->status) result = d->status;
            if (s->f[0].out_len != 4096 || s->f[0].data_len != 4096) { bad_lengths++; result = -EMSGSIZE; }
            if (pread(source_fd, b, sizeof(b), (off_t)(create_req.st[0].arg0 * 512 + (pending_seq - 1) * 4096)) != sizeof(b)) abort();
            if (memcmp(pool, b, sizeof(b))) { bad_payload++; result = -EBADMSG; }
            hdr->done_cons++;
            if (scenario("completion-error")) result = -EIO;
            if (scenario("completion-stale")) result = -ESTALE;
            if (scenario("completion-short")) result = -EMSGSIZE;
            if (!result) {
                completed++;
                copy_device_record(pending_seq);
                if (!scenario("no-terminal")) terminal_success();
            } else {
                /* A deceptive terminal notification cannot erase USER failure. */
                copy_device_record(pending_seq);
                premature_terminal++;
                terminal_success();
            }
        }
        pthread_mutex_unlock(&lock);
        if (result < 0) { errno = -result; return -1; }
        return 0;
    }
    return __real_ioctl(fd, request, arg);
}

struct worker_context { void *(*run)(void *); void *arg; cpu_set_t cpus; };
static void *worker_entry(void *arg)
{
    struct worker_context *c = arg;
    cpu_set_t cpus;
    void *(*run)(void *) = c->run;
    void *data = c->arg;
    if (!created) entered_worker_before_create++;
    if (!sched_getaffinity(0, sizeof(cpus), &cpus) && CPU_EQUAL(&cpus, &c->cpus)) worker_affinity_ok++;
    free(c);
    return run(data);
}
int __wrap_pthread_create(pthread_t *tid, const pthread_attr_t *attr, void *(*run)(void *), void *arg)
{
    struct worker_context *c = malloc(sizeof(*c));
    if (!c) return ENOMEM;
    c->run = run; c->arg = arg;
    if (sched_getaffinity(0, sizeof(c->cpus), &c->cpus)) abort();
    thread_count++;
    return __real_pthread_create(tid, attr, worker_entry, c);
}
int __wrap_sched_setaffinity(pid_t pid, size_t size, const cpu_set_t *mask)
{
    (void)pid; (void)size; (void)mask;
    affinity_overrides++;
    errno = EPERM;
    return -1;
}

__attribute__((destructor)) static void receipt(void)
{
    const char *path = getenv("UC_RECEIPT");
    if (!path) return;
    FILE *f = fopen(path, "w");
    if (!f) abort();
    fprintf(f, "{\"scenario\":\"%s\",\"threads\":%u,\"worker_affinity_ok\":%u,"
        "\"affinity_overrides\":%u,\"worker_before_create\":%u,\"rings\":%u,\"pools\":%u,"
        "\"creates\":%u,\"user_opens\":%u,\"stop_calls\":%u,\"stop_succeeded\":%s,"
        "\"token_closes\":%u,\"pool_unmaps\":%u,\"user_unmaps\":%u,"
        "\"release_before_stop\":%u,\"release_after_failed_stop\":%u,"
        "\"completed\":%llu,\"user_done_calls\":%u,\"ack_errors\":%u,\"bad_lengths\":%u,"
        "\"bad_payload\":%u,\"premature_terminal\":%u,\"pool_bytes\":%zu}\n",
        mode(), thread_count, worker_affinity_ok, affinity_overrides, entered_worker_before_create,
        ring_count, pool_count, create_count, user_open_count, stop_calls, stopped ? "true" : "false",
        token_closes, pool_unmaps, user_unmaps, release_before_stop, after_failed_stop,
        (unsigned long long)completed, user_done_calls, one_ack_errors, bad_lengths, bad_payload,
        premature_terminal, pool_size);
    fclose(f);
}

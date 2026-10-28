/* SPDX-License-Identifier: MIT */
/* Host-only CQ/lifetime control injection, never a simulated IAA execution. */
#define syscall fixture_syscall
#define clock_gettime fixture_clock_gettime
#define poll fixture_poll
#define munmap forbidden_munmap
#define free forbidden_free
#define main iaa_program_main
#include "test_iaa_unified_ops.c"
#undef main
#undef syscall
#undef clock_gettime
#undef poll
#undef munmap
#undef free
#include <sys/wait.h>

static unsigned ticks;
long fixture_syscall(long number, ...)
{
    /* Only submission/task_work kicks are allowed; no registration/device I/O. */
    if (number != __NR_io_uring_enter) _Exit(99);
    return 1;
}
int fixture_clock_gettime(clockid_t clock, struct timespec *t)
{
    (void)clock;
    *t = (struct timespec) {.tv_sec = ticks++};
    return 0;
}
int fixture_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    (void)fds; (void)count; (void)timeout;
    return 0;
}
int forbidden_munmap(void *p, size_t n)
{
    (void)p; (void)n;
    _Exit(99); /* No explicit free/unmap is permitted on an UNKNOWN path. */
}
void forbidden_free(void *p)
{
    (void)p;
    _Exit(99);
}

static int exercise(unsigned mode)
{
    struct context ctx = {0};
    struct io_uring_sqe sqe = {0};
    struct io_uring_cqe cqe = {.user_data = COOKIE_BASE, .res = PLAIN_LEN};
    unsigned head = 0, tail = 0, entries = 1, mask = 0, array = 0, cq_tail = 1;
    struct case_spec spec = case_specification(CASE_A, 1234);
    ctx.ring.sq = (struct io_uring_sq) {
        .khead = &head, .ktail = &tail, .kring_entries = &entries,
        .kring_mask = &mask, .array = &array, .sqes = &sqe,
    };
    ctx.ring.cq = (struct io_uring_cq) {
        .khead = &head, .ktail = &cq_tail, .kring_mask = &mask, .cqes = &cqe,
    };
    ticks = 0;
    if (mode == 1) cqe.user_data++;
    if (mode == 2) cqe.flags = IORING_CQE_F_MORE;
    if (mode == 3) cq_tail = 0;
    if (mode == 4) { ctx.inflight = true; return release_context(&ctx); }
    struct observation out = submit_iaa_decompress(&ctx, &spec, COOKIE_BASE);
    if (mode || ctx.inflight || out.result != PLAIN_LEN || out.cookie != COOKIE_BASE)
        return 98;
    return 0;
}

int main(void)
{
    if (exercise(0)) return 1;
    for (unsigned mode = 1; mode <= 4; mode++) {
        int status;
        pid_t child = fork();
        if (child < 0) return 1;
        if (!child) {
            /* Expected UNKNOWN refusals are checked by exit, not test output. */
            if (!freopen("/dev/null", "w", stderr)) _Exit(97);
            _Exit(exercise(mode));
        }
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 1)
            return 1;
    }
    puts("PASS: host lifetime control rejects wrong cookie, nonterminal CQE, timeout, premature cleanup without explicit free/unmap; no device execution");
    return 0;
}

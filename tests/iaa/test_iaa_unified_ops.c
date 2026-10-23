// SPDX-License-Identifier: MIT
// Migrated from the historical IAA syscall gate; see README.md for provenance.
// Retains deterministic payload/raw-DEFLATE generation and five syscall cases.
// UAPI, lifecycle, completion validation and teardown adapted to current kernel.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

/* Consume only the canonical header; its dependencies use exported host UAPI.
 * Adding the entire raw kernel include/uapi directory breaks clean overlays. */
#include "../../kernel/include/uapi/linux/io_uring.h"
#include "../../kernel/tools/include/io_uring/mini_liburing.h"

#define UMEM_SIZE (64U * 1024)
#define FRAME_SIZE (16U * 1024)
#define SRC_OFF 0U
#define DST_OFF 0x4000U
#define DST_CAP 0x4000U
#define PLAIN_LEN (9U * 1024)
#define TINY_CAP 256U
#define GUARD_LEN 8U
#define GUARD_LO_OFF (DST_OFF - GUARD_LEN)
#define GUARD_HI_OFF (DST_OFF + DST_CAP)
#define GUARD_BYTE 0xAB
#define COOKIE_BASE UINT64_C(0xDEC0DE0000)
#define WAIT_MILLISECONDS 5000
#define EXIT_UNAVAILABLE 4
/* 2KiB history: deflate-generic inflates with an 11-bit window (crypto/deflate.c). */
#define RAW_WINDOW_BITS 11
#define SELECTION_PATH "/sys/module/xdev_ext_iaa/parameters/acomp_driver"
#define SERVED_PATH "/sys/module/xdev_ext_iaa/parameters/acomp_served"
#define DRIVER_MAX 128

_Static_assert(FRAME_SIZE >= DST_CAP && FRAME_SIZE >= PLAIN_LEN, "logical output frame");
_Static_assert(DST_OFF % FRAME_SIZE == 0, "output begins at frame boundary");
_Static_assert(IO_UNIFIED_OP_IAA_DECOMPRESS == 5, "decompression UAPI");

enum case_id { CASE_A, CASE_B, CASE_C, CASE_D, CASE_E };
struct case_spec { uint64_t src, dst, capacity; uint32_t length; };
struct observation { uint64_t cookie; int result; uint32_t flags; };
struct served { uint64_t requests, errors, bytes; };
/* Per-driver result for a too-small destination; unknown drivers are not run. */
struct provider_contract { const char *driver; int overflow; const char *execution; };
static const struct provider_contract provider_contracts[] = {
    {"deflate-iaa", EOVERFLOW, "IAA CryptoAPI driver; device execution still needs IAA/IDXD counters"},
    {"deflate-generic", ENOSPC, "software CryptoAPI DEFLATE; no IAA device was used"},
};
static int overflow_errno = EOVERFLOW;
struct context {
    struct io_uring ring;
    uint8_t *umem;
    struct io_uring_unified_shared *shared;
    bool ring_open, registered, inflight;
};
static void fill_plaintext(uint8_t *p, size_t n)
{
    // Mix a repeating pattern (compresses well) with a per-index byte (so a
    // truncated/garbage output is detectably wrong, not accidentally equal).
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)((i * 31u + (i >> 4)) ^ 0x5Au);
}

// Raw DEFLATE (RFC1951, no zlib/gzip wrapper) so it matches IAA/QPL
// qpl_op_decompress with QPL_FLAG_FIRST|QPL_FLAG_LAST (TEST_CONTRACT C1).
// The 2KiB window keeps every match distance decodable by deflate-generic.
static size_t raw_deflate(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED,
                     -RAW_WINDOW_BITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        fprintf(stderr, "deflateInit2 failed\n");
        exit(2);
    }
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)in_len;
    zs.next_out = out;
    zs.avail_out = (uInt)out_cap;
    int rc = deflate(&zs, Z_FINISH);
    if (rc != Z_STREAM_END) {
        fprintf(stderr, "deflate did not finish (rc=%d)\n", rc);
        exit(2);
    }
    size_t produced = zs.total_out;
    deflateEnd(&zs);
    return produced;
}

static struct case_spec case_specification(enum case_id id, uint32_t blob_len)
{
    struct case_spec s = {SRC_OFF, DST_OFF, DST_CAP, blob_len};
    if (id == CASE_B) s.capacity = TINY_CAP;
    if (id == CASE_C) { s.src = UMEM_SIZE - 8; s.length = 64; }
    if (id == CASE_D) s.length = 0;
    if (id == CASE_E) { s.dst = UMEM_SIZE - 16; s.capacity = 4096; }
    return s;
}

static void prepare_sqe(struct io_uring_sqe *sqe, const struct case_spec *s,
                        uint64_t cookie)
{
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_UNIFIED_OPS;
    sqe->fd = -1;
    sqe->flags = IOSQE_XDEV_EXT_UMEM;
    sqe->len = IO_UNIFIED_OP_IAA_DECOMPRESS;
    sqe->addr = s->src;
    sqe->off = s->dst;
    sqe->rw_flags = s->length;
    sqe->addr3 = s->capacity;
    sqe->user_data = cookie;
}

/* This validator consumes observations; host tests inject independently built
 * good/bad observations. Those tests do not emulate a device or submit SQEs. */
static bool validate_result(enum case_id id, uint64_t cookie,
                            const struct observation *c,
                            const uint8_t *data, const uint8_t *before,
                            const uint8_t *plain,
                            const struct io_uring_unified_shared *s, bool report)
{
    bool success = id == CASE_A;
    int expected = success ? (int)PLAIN_LEN : id == CASE_B ? -overflow_errno : -EINVAL;
    size_t allowed = success ? PLAIN_LEN : id == CASE_B ? TINY_CAP : 0;
    bool valid = c->cookie == cookie && c->flags == 0 && c->result == expected;
    valid &= s->calc_count == (success ? 1U : 0U);
    valid &= s->calc_errors == (success ? 0U : 1U);
    valid &= s->calc_result == (success ? PLAIN_LEN : 0U);
    valid &= s->read_count == 0 && s->send_count == 0;
    valid &= s->read_bytes == 0 && s->send_bytes == 0;
    valid &= s->read_errors == 0 && s->send_errors == 0 && s->lock == 0;
    valid &= s->timestamp != 0;
    if (success) valid &= memcmp(data + DST_OFF, plain, PLAIN_LEN) == 0;
    /* All source bytes, guards, unused output tail and unrelated UMEM bytes.
     * Overflow may partially modify ONLY the capacity-sized output window. */
    valid &= memcmp(data, before, DST_OFF) == 0;
    valid &= memcmp(data + DST_OFF + allowed, before + DST_OFF + allowed,
                    UMEM_SIZE - DST_OFF - allowed) == 0;
    if (report) {
        fprintf(stderr, "%s case %c: cookie=%llx flags=%x res=%d expected=%d "
                "calc=(%llu,%llu,%u), full bytes/guards/stats\n",
                valid ? "ok" : "FAIL", 'A' + id,
                (unsigned long long)c->cookie, c->flags, c->result, expected,
                (unsigned long long)s->calc_count,
                (unsigned long long)s->calc_result, s->calc_errors);
    }
    return valid;
}

static int register_op(int fd, unsigned opcode, const void *arg, unsigned nr)
{
    int ret = syscall(__NR_io_uring_register, fd, opcode, arg, nr);
    return ret < 0 ? -errno : ret;
}

static int open_ring(struct io_uring *ring)
{
    int ret = io_uring_queue_init(8, ring, 0);
    /* mini_liburing preserves syscall's -1 for setup, but -errno for mmap. */
    return ret == -1 ? -errno : ret;
}

static bool provider_in_stream(FILE *f, const char *wanted)
{
    char line[512], driver[DRIVER_MAX];
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "driver : %127s", driver) == 1 && !strcmp(driver, wanted))
            return true;
    return false;
}

static bool provider_registered(const char *wanted)
{
    FILE *f = fopen("/proc/crypto", "r");
    bool found;
    if (!f) return false;
    found = provider_in_stream(f, wanted);
    fclose(f);
    return found;
}

static const struct provider_contract *provider_contract(const char *driver)
{
    for (size_t i = 0; i < sizeof(provider_contracts) / sizeof(provider_contracts[0]); i++)
        if (!strcmp(provider_contracts[i].driver, driver)) return &provider_contracts[i];
    return NULL;
}

/* The kernel parameter names the selected driver followed by one newline. */
static bool selection_from_stream(FILE *f, char *driver)
{
    char line[DRIVER_MAX + 2];
    size_t n;
    if (!fgets(line, sizeof(line), f)) return false;
    n = strlen(line);
    if (n < 2 || n > DRIVER_MAX || line[n - 1] != '\n' || fgetc(f) != EOF) return false;
    line[n - 1] = 0;
    memcpy(driver, line, n);
    return true;
}

/* "<driver> requests=R errors=E bytes=B" per actual serving driver. */
static int served_from_stream(FILE *f, const char *driver, struct served *out,
                              struct served *others)
{
    char line[512], name[DRIVER_MAX];
    unsigned long long r, e, b;
    bool found = false;
    memset(out, 0, sizeof(*out));
    memset(others, 0, sizeof(*others));
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "untracked requests=%llu", &r) == 1) {
            others->requests += r;
            continue;
        }
        if (sscanf(line, "%127s requests=%llu errors=%llu bytes=%llu", name, &r, &e, &b) != 4)
            return -1;
        struct served *dst = !strcmp(name, driver) ? out : others;
        if (dst == out) {
            if (found) return -1;
            found = true;
        }
        dst->requests += r; dst->errors += e; dst->bytes += b;
    }
    return 0;
}

static int read_served(const char *driver, struct served *out, struct served *others)
{
    FILE *f = fopen(SERVED_PATH, "r");
    int ret;
    if (!f) return -1;
    ret = served_from_stream(f, driver, out, others);
    fclose(f);
    return ret;
}

/* A and B reach the provider; C-E are refused by the kernel before it. */
static bool served_delta_valid(const struct served *before, const struct served *after,
                               const struct served *others_before,
                               const struct served *others_after)
{
    return after->requests - before->requests == 2 &&
           after->errors - before->errors == 1 &&
           after->bytes - before->bytes == PLAIN_LEN &&
           !memcmp(others_before, others_after, sizeof(*others_after));
}

static int preflight(char *driver)
{
    struct io_uring ring;
    struct io_uring_probe *probe;
    const struct provider_contract *contract;
    struct served served, others;
    bool supported = false;
    FILE *f;
    int ret;
    if (sysconf(_SC_PAGESIZE) != 4096) {
        fprintf(stderr, "UNAVAILABLE: this three-physical-page case requires 4KiB host pages\n");
        return EXIT_UNAVAILABLE;
    }
    f = fopen(SELECTION_PATH, "r");
    if (!f) {
        fprintf(stderr, "UNAVAILABLE: kernel exposes no acomp driver selection (%s)\n", SELECTION_PATH);
        return EXIT_UNAVAILABLE;
    }
    ret = selection_from_stream(f, driver);
    fclose(f);
    if (!ret) { fprintf(stderr, "FAIL: unreadable acomp driver selection\n"); return 1; }
    contract = provider_contract(driver);
    if (!contract) {
        fprintf(stderr, "UNAVAILABLE: selected acomp driver %s has no recorded overflow contract\n", driver);
        return EXIT_UNAVAILABLE;
    }
    overflow_errno = contract->overflow;
    if (!provider_registered(driver)) {
        fprintf(stderr, "UNAVAILABLE: no registered %s CryptoAPI provider; no native request submitted\n", driver);
        return EXIT_UNAVAILABLE;
    }
    if (read_served(driver, &served, &others)) {
        fprintf(stderr, "UNAVAILABLE: kernel exposes no served-driver statistics (%s)\n", SERVED_PATH);
        return EXIT_UNAVAILABLE;
    }
    ret = open_ring(&ring);
    if (ret) {
        fprintf(stderr, "UNAVAILABLE: io_uring setup: %s\n", strerror(-ret));
        return EXIT_UNAVAILABLE;
    }
    probe = calloc(1, sizeof(*probe) + 256 * sizeof(struct io_uring_probe_op));
    if (!probe) { io_uring_queue_exit(&ring); return 2; }
    ret = register_op(ring.ring_fd, IORING_REGISTER_PROBE, probe, 256);
    if (!ret) {
        for (unsigned i = 0; i < probe->ops_len; i++)
            if (probe->ops[i].op == IORING_OP_UNIFIED_OPS &&
                (probe->ops[i].flags & IO_URING_OP_SUPPORTED)) supported = true;
    }
    free(probe);
    if (io_uring_queue_exit(&ring)) return 1;
    if (!supported) {
        fprintf(stderr, "UNAVAILABLE: canonical IORING_OP_UNIFIED_OPS not advertised (probe=%d)\n", ret);
        return EXIT_UNAVAILABLE;
    }
    fprintf(stderr, "preflight: canonical opcode and %s visible (%s); physical IAA execution is not certified\n",
            driver, contract->execution);
    return 0;
}

/* No payload/stats mapping is freed or explicitly unmapped with unknown native
 * ownership. Process teardown relies on the kernel's request/page references;
 * it is not evidence that an unresponsive device has drained. */
static _Noreturn void unknown_ownership(const char *reason)
{
    fprintf(stderr, "FAIL: UNKNOWN native ownership (%s); no explicit unregister/free/unmap; "
            "kernel must retain outstanding request pins through process teardown\n", reason);
    fflush(stderr);
    _Exit(1);
}

static int release_context(struct context *ctx)
{
    int failed = 0;
    if (ctx->inflight) unknown_ownership("cleanup before terminal CQE");
    if (ctx->registered) {
        int ret = register_op(ctx->ring.ring_fd, IORING_UNREGISTER_XDEV_EXT_UMEM, NULL, 0);
        if (ret) { fprintf(stderr, "FAIL: UMEM unregister: %s\n", strerror(-ret)); failed = 1; }
    }
    /* Terminal CQE precedes unregister and ring close, then user memory release. */
    if (ctx->ring_open && io_uring_queue_exit(&ctx->ring)) failed = 1;
    if (ctx->umem && munmap(ctx->umem, UMEM_SIZE)) failed = 1;
    if (ctx->shared && munmap(ctx->shared, 4096)) failed = 1;
    memset(ctx, 0, sizeof(*ctx));
    return failed;
}

static int prepare_context(struct context *ctx, const uint8_t *before)
{
    struct io_uring_xdev_ext_umem_reg reg;
    int ret;
    memset(ctx, 0, sizeof(*ctx));
    ctx->umem = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (ctx->umem == MAP_FAILED) { ctx->umem = NULL; return 2; }
    ctx->shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (ctx->shared == MAP_FAILED) { ctx->shared = NULL; release_context(ctx); return 2; }
    memcpy(ctx->umem, before, UMEM_SIZE);
    ret = open_ring(&ctx->ring);
    if (ret) { release_context(ctx); return 1; }
    ctx->ring_open = true;
    reg = (struct io_uring_xdev_ext_umem_reg) {
        .addr = (uint64_t)(uintptr_t)ctx->umem, .size = UMEM_SIZE,
        .shared_addr = (uint64_t)(uintptr_t)ctx->shared, .frame_size = FRAME_SIZE,
    };
    ret = register_op(ctx->ring.ring_fd, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1);
    if (ret) {
        fprintf(stderr, "FAIL: valid UMEM registration after preflight: %s\n", strerror(-ret));
        release_context(ctx);
        return 1;
    }
    ctx->registered = true;
    return 0;
}

static int64_t monotonic_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) unknown_ownership("clock_gettime");
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static struct observation submit_iaa_decompress(struct context *ctx,
                                               const struct case_spec *spec,
                                               uint64_t cookie)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    struct io_uring_cq *cq = &ctx->ring.cq;
    struct observation out;
    int64_t deadline = monotonic_ms() + WAIT_MILLISECONDS;
    if (!sqe) unknown_ownership("no SQE");
    prepare_sqe(sqe, spec, cookie);
    ctx->inflight = true;
    if (io_uring_submit(&ctx->ring) != 1) unknown_ownership("submission count not exactly one");
    for (;;) {
        unsigned head = __atomic_load_n(cq->khead, __ATOMIC_RELAXED);
        unsigned tail = __atomic_load_n(cq->ktail, __ATOMIC_ACQUIRE);
        if (head != tail) {
            struct io_uring_cqe *cqe = &cq->cqes[head & *cq->kring_mask];
            out = (struct observation) {cqe->user_data, cqe->res, cqe->flags};
            io_uring_cqe_seen(&ctx->ring);
            if (out.cookie != cookie || (out.flags & IORING_CQE_F_MORE))
                unknown_ownership("CQE identity/nonterminal flags");
            ctx->inflight = false;
            return out;
        }
        if (monotonic_ms() >= deadline) unknown_ownership("bounded CQE wait expired");
        /* min_complete=0 services task_work without an unbounded wait. */
        if (io_uring_enter(ctx->ring.ring_fd, 0, 0, IORING_ENTER_GETEVENTS, NULL) < 0 &&
            errno != EINTR) unknown_ownership("io_uring_enter while awaiting CQE");
        (void)poll(NULL, 0, 1);
    }
}

int main(int argc, char **argv)
{
    uint8_t plain[PLAIN_LEN], blob[PLAIN_LEN + 1024], before[UMEM_SIZE] = {0};
    char driver[DRIVER_MAX] = "";
    struct served served_before, served_after, others_before, others_after;
    size_t blob_len;
    bool only_preflight = argc == 2 && !strcmp(argv[1], "--preflight");
    int failed = 0, ret;
    if (argc != 1 && !only_preflight) {
        fprintf(stderr, "usage: %s [--preflight]\n", argv[0]); return 2;
    }
    ret = preflight(driver);
    if (ret || only_preflight) return ret;
    if (read_served(driver, &served_before, &others_before)) return 1;
    fill_plaintext(plain, PLAIN_LEN);
    blob_len = raw_deflate(plain, PLAIN_LEN, blob, sizeof(blob));
    if (blob_len > FRAME_SIZE - GUARD_LEN) return 2;
    memcpy(before + SRC_OFF, blob, blob_len);
    memset(before + GUARD_LO_OFF, GUARD_BYTE, GUARD_LEN);
    memset(before + GUARD_HI_OFF, GUARD_BYTE, GUARD_LEN);
    for (enum case_id id = CASE_A; id <= CASE_E; id++) {
        struct context ctx;
        struct case_spec spec = case_specification(id, (uint32_t)blob_len);
        struct observation completion;
        uint8_t expected[UMEM_SIZE];
        memcpy(expected, before, sizeof(expected));
        if (id == CASE_B) memset(expected + DST_OFF + TINY_CAP, GUARD_BYTE, GUARD_LEN);
        ret = prepare_context(&ctx, expected);
        if (ret) return ret;
        completion = submit_iaa_decompress(&ctx, &spec, COOKIE_BASE + id);
        /* EINVAL on the valid first request is FAIL, not provider detection.
         * Any provider that disappears after preflight is also a test failure. */
        if (!validate_result(id, COOKIE_BASE + id, &completion, ctx.umem,
                             expected, plain, ctx.shared, true)) failed = 1;
        if (release_context(&ctx)) failed = 1;
        if (failed) break;
    }
    if (!failed && (read_served(driver, &served_after, &others_after) ||
                    !served_delta_valid(&served_before, &served_after,
                                        &others_before, &others_after))) {
        fprintf(stderr, "FAIL: %s did not serve exactly cases A and B (or another driver/request interfered)\n",
                driver);
        failed = 1;
    }
    if (failed) { fprintf(stderr, "RESULT: FAIL\n"); return 1; }
    fprintf(stderr, "RESULT: PASS CryptoAPI syscall contract served-by=%s (%s); "
            "physical IAA execution/performance not certified\n",
            driver, provider_contract(driver)->execution);
    return 0;
}

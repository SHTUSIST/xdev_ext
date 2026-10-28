/*
 * SPDK NVMe -> TCP loopback QD1 pipeline, ported from the author's
 * bench_spdk_nvme_pipeline.c (raw sha256 a11c028d94ab62d1f42059aa9e2ffdd8ba0e7aa14c1ed9535e73fd4fb2e6dd69).
 * Preserved: the QD1 read -> optional uint64 sum -> TCP send shape, the
 * unsigned xorshift* slot sequence, the warmup and one DMA buffer reused by
 * every operation.  Two executables come from this file:
 *
 *   default build         plan/offline host fixture only: a regular file
 *                         feeds the same TCP producer/receiver; no SPDK.
 *   -DXDEV_EXT_SPDK_NATIVE  adds native-correctness/native-performance:
 *                         official SPDK against one explicitly named,
 *                         userspace-bound PCIe NVMe namespace (build.py).
 *
 * README.md lists what changed from the original and why.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "spdk_owner.h"

#define GUARD 64u
#define STREAM_LIMIT (64u * 1024u * 1024u)
#define MASK_BYTE 0xa7

struct config {
    const char *mode, *bdf, *capture, *faults, *reference_sha256;
    bool native, performance;
    uint64_t nsid, sector, namespace_lbas, start, window, block;
    uint64_t iterations, warmup, calc, deadline_ms;
    size_t send_max, recv_max, stream;
    int reference;
};

struct receiver {
    const struct config *cfg;
    int fd;
    unsigned char *bytes;
    uint64_t deadline;
    size_t count;
    bool eintr_once;
    int error;
    pthread_mutex_t mutex;
    pthread_cond_t progress;
    /* Protected by mutex; capture bytes are read only after join. */
    size_t delivered;
    bool finished;
};

static bool has_fault(const struct config *c, const char *needle)
{
    const char *p = c->faults;
    size_t n = strlen(needle);
    while (*p) {
        size_t len = strcspn(p, ",");
        if (len == n && !strncmp(p, needle, n))
            return true;
        p += len;
        if (*p == ',')
            ++p;
    }
    return false;
}

/* Exactly the original unsigned-64-bit xorshift* schedule. */
static uint64_t rand_slot(uint64_t i, uint64_t count)
{
    uint64_t x = i + 1;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x *= UINT64_C(2685821657736338717);
    return x % count;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        abort();
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int remaining_ms(uint64_t deadline)
{
    uint64_t now = now_ns();
    if (now >= deadline)
        return 0;
    return (int)((deadline - now + 999999) / 1000000);
}

static int ready(int fd, short events, uint64_t deadline)
{
    struct pollfd p = {.fd = fd, .events = events};
    for (;;) {
        int ms = remaining_ms(deadline);
        if (!ms) {
            errno = ETIMEDOUT;
            return -1;
        }
        int n = poll(&p, 1, ms);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (!n)
                errno = ETIMEDOUT;
            return -1;
        }
        if (p.revents & POLLNVAL) {
            errno = EBADF;
            return -1;
        }
        /* recv consumes buffered data before reporting EOF on HUP. */
        if (p.revents & (events | POLLERR | POLLHUP))
            return 0;
    }
}

static int tcp_pair(int *sender, int *sink, uint64_t deadline)
{
    int lfd = -1, cfd = -1, rfd = -1, one = 1;
    struct sockaddr_in addr = {.sin_family = AF_INET,
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(addr);
    lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, len) || listen(lfd, 1) ||
        getsockname(lfd, (struct sockaddr *)&addr, &len))
        goto fail;
    cfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (cfd < 0 || setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)))
        goto fail;
    if (connect(cfd, (struct sockaddr *)&addr, len)) {
        if (errno != EINPROGRESS || ready(cfd, POLLOUT, deadline))
            goto fail;
        int err = 0;
        socklen_t size = sizeof(err);
        if (getsockopt(cfd, SOL_SOCKET, SO_ERROR, &err, &size) || err) {
            if (err)
                errno = err;
            goto fail;
        }
    }
    if (ready(lfd, POLLIN, deadline))
        goto fail;
    rfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (rfd < 0)
        goto fail;
    close(lfd);
    *sender = cfd;
    *sink = rfd;
    return 0;
fail:
    if (lfd >= 0) close(lfd);
    if (cfd >= 0) close(cfd);
    if (rfd >= 0) close(rfd);
    return -1;
}

static ssize_t fixture_recv(struct receiver *r, void *buf, size_t len)
{
    if (has_fault(r->cfg, "recv-eintr") && !r->eintr_once) {
        r->eintr_once = true;
        errno = EINTR;
        return -1;
    }
    return recv(r->fd, buf, len, 0);
}

static void *receive_stream(void *arg)
{
    struct receiver *r = arg;
    const struct config *c = r->cfg;
    for (;;) {
        size_t max = c->stream + 1 - r->count;
        if (!max) {
            r->error = 1; /* A real extra byte already arrived. */
            break;
        }
        if (has_fault(c, "receiver-early-eof")) {
            if (r->count == c->stream - 1) {
                shutdown(r->fd, SHUT_RD);
                r->error = 1;
                break;
            }
            if (max > c->stream - 1 - r->count)
                max = c->stream - 1 - r->count;
        }
        if (has_fault(c, "receiver-stall")) {
            size_t limit = c->stream - c->block;
            if (r->count >= limit) {
                /* Actual missing receiver progress until the common deadline. */
                while (remaining_ms(r->deadline))
                    (void)poll(NULL, 0, remaining_ms(r->deadline));
                r->error = 1;
                break;
            }
            if (max > limit - r->count)
                max = limit - r->count;
        }
        if (max > c->recv_max)
            max = c->recv_max;
        if (ready(r->fd, POLLIN, r->deadline)) {
            r->error = 1;
            break;
        }
        ssize_t n = fixture_recv(r, r->bytes + r->count, max);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n < 0) {
            r->error = 1;
            break;
        }
        if (!n) {
            if (r->count != c->stream)
                r->error = 1;
            break;
        }
        r->count += (size_t)n;
        pthread_mutex_lock(&r->mutex);
        r->delivered = r->count;
        pthread_cond_broadcast(&r->progress);
        pthread_mutex_unlock(&r->mutex);
    }
    pthread_mutex_lock(&r->mutex);
    r->finished = true;
    pthread_cond_broadcast(&r->progress);
    pthread_mutex_unlock(&r->mutex);
    return NULL;
}

static int delivery_barrier(struct receiver *r, size_t expected)
{
    struct timespec end = {.tv_sec = (time_t)(r->deadline / 1000000000),
                          .tv_nsec = (long)(r->deadline % 1000000000)};
    int rc = 0;
    pthread_mutex_lock(&r->mutex);
    while (r->delivered < expected && !r->finished) {
        rc = pthread_cond_timedwait(&r->progress, &r->mutex, &end);
        if (rc)
            break;
    }
    if (r->delivered < expected)
        rc = -1;
    pthread_mutex_unlock(&r->mutex);
    return rc;
}

static int send_full(int fd, const unsigned char *buf, size_t length,
                     const struct config *c, uint64_t deadline, bool *interrupted,
                     bool final)
{
    size_t offset = 0;
    while (offset < length) {
        if (ready(fd, POLLOUT, deadline))
            return -1;
        size_t chunk = length - offset;
        if (chunk > c->send_max)
            chunk = c->send_max;
        ssize_t n;
        if (has_fault(c, "send-eintr") && !*interrupted) {
            *interrupted = true;
            errno = EINTR;
            n = -1;
        } else if (final && has_fault(c, "send-zero")) {
            n = 0; /* Exercise the same zero-progress transport handling. */
        } else {
            n = send(fd, buf + offset, chunk, MSG_NOSIGNAL);
        }
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n <= 0)
            return -1;
        offset += (size_t)n;
    }
    return 0;
}

static uint64_t calculate(const unsigned char *buf, uint64_t bytes)
{
    uint64_t sum = 0;
    for (uint64_t i = 0; i < bytes; i += 8) {
        uint64_t word = 0;
        for (unsigned j = 0; j < 8; ++j)
            word |= (uint64_t)buf[i + j] << (8 * j);
        sum += word;
    }
    return sum;
}

static bool guards_ok(const unsigned char *base, size_t size, size_t guard)
{
    for (size_t i = 0; i < guard; ++i)
        if (base[i] != MASK_BYTE || base[guard + size + i] != MASK_BYTE)
            return false;
    return true;
}

static int write_full(int fd, const unsigned char *bytes, size_t count)
{
    while (count) {
        ssize_t n = write(fd, bytes, count);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        bytes += n;
        count -= (size_t)n;
    }
    return 0;
}

static int offline_check(const struct config *c)
{
    int result = 1, sender = -1, sink = -1, output = -1;
    uint64_t window_bytes = c->window * c->sector;
    uint64_t operations = c->warmup + c->iterations;
    const unsigned char *reference = MAP_FAILED;
    unsigned char *payload_base = NULL, *capture_base = NULL;
    bool thread_started = false, mutex_ready = false, cond_ready = false;
    bool send_interrupted = false;
    pthread_t thread;
    pthread_condattr_t attrs;
    struct receiver r = {.cfg = c};
    uint64_t actual_calc = 0, expected_calc = 0;
    reference = mmap(NULL, (size_t)window_bytes, PROT_READ, MAP_PRIVATE, c->reference, 0);
    if (reference == MAP_FAILED)
        goto done;
    payload_base = malloc((size_t)c->block + 2 * GUARD);
    capture_base = malloc(c->stream + 1 + 2 * GUARD);
    if (!payload_base || !capture_base)
        goto done;
    memset(payload_base, MASK_BYTE, (size_t)c->block + 2 * GUARD);
    memset(capture_base, MASK_BYTE, c->stream + 1 + 2 * GUARD);
    unsigned char *payload = payload_base + GUARD;
    r.bytes = capture_base + GUARD;
    /* Exclusivity and no-follow remain atomic at the actual creation point. */
    output = open(c->capture, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) {
        result = 2;
        goto done;
    }
    r.deadline = now_ns() + c->deadline_ms * UINT64_C(1000000);
    if (tcp_pair(&sender, &sink, r.deadline))
        goto done;
    r.fd = sink;
    if (pthread_mutex_init(&r.mutex, NULL))
        goto done;
    mutex_ready = true;
    if (pthread_condattr_init(&attrs))
        goto done;
    int rc = pthread_condattr_setclock(&attrs, CLOCK_MONOTONIC);
    if (!rc)
        rc = pthread_cond_init(&r.progress, &attrs);
    pthread_condattr_destroy(&attrs);
    if (rc)
        goto done;
    cond_ready = true;
    if (pthread_create(&thread, NULL, receive_stream, &r))
        goto done;
    thread_started = true;
    for (uint64_t i = 0; i < operations; ++i) {
        bool final = i + 1 == operations;
        size_t offset = (size_t)(rand_slot(i, window_bytes / c->block) * c->block);
        memcpy(payload, reference + offset, (size_t)c->block);
        if (final) {
            if (has_fault(c, "payload-first")) payload[0] ^= 1;
            if (has_fault(c, "payload-middle")) payload[c->block / 2] ^= 1;
            if (has_fault(c, "payload-last")) payload[c->block - 1] ^= 1;
            if (has_fault(c, "guard-head")) payload_base[GUARD - 1] ^= 1;
            if (has_fault(c, "guard-tail")) payload[c->block] ^= 1;
        }
        /* Preserved optional workload calculation, not an integrity oracle. */
        actual_calc ^= calculate(payload, c->calc);
        if (send_full(sender, payload, (size_t)c->block, c, r.deadline,
                      &send_interrupted, final))
            goto done;
        if (i + 1 == c->warmup && delivery_barrier(&r, (size_t)(i + 1) * c->block))
            goto done;
    }
    if (has_fault(c, "receiver-extra")) {
        unsigned char extra = 0x3c;
        if (send_full(sender, &extra, 1, c, r.deadline, &send_interrupted, false))
            goto done;
    }
    if (shutdown(sender, SHUT_WR) || delivery_barrier(&r, c->stream))
        goto done;
    if (pthread_join(thread, NULL))
        abort(); /* Ownership cannot be freed if a join unexpectedly failed. */
    thread_started = false;
    if (r.error || r.count != c->stream)
        goto done;
    /* All byte/guard/reference validation is after producer and receiver finish.
     * There is no performance measurement in this offline executable. */
    if (!guards_ok(payload_base, (size_t)c->block, GUARD) ||
        !guards_ok(capture_base, c->stream + 1, GUARD))
        goto done;
    for (uint64_t i = 0; i < operations; ++i) {
        size_t offset = (size_t)(rand_slot(i, window_bytes / c->block) * c->block);
        const unsigned char *expected = reference + offset;
        if (memcmp(r.bytes + i * c->block, expected, (size_t)c->block))
            goto done;
        expected_calc ^= calculate(expected, c->calc);
    }
    if (actual_calc != expected_calc || write_full(output, r.bytes, c->stream))
        goto done;
    if (close(output)) {
        output = -1;
        goto done;
    }
    output = -1;
    result = 0;
done:
    if (thread_started) {
        /* Shutdown wakes real socket I/O; the deliberate stall is deadline-bounded. */
        if (sender >= 0) shutdown(sender, SHUT_RDWR);
        if (sink >= 0) shutdown(sink, SHUT_RDWR);
        if (pthread_join(thread, NULL))
            abort();
    }
    if (sender >= 0 && close(sender)) result = 1;
    if (sink >= 0 && close(sink)) result = 1;
    if (cond_ready && pthread_cond_destroy(&r.progress)) result = 1;
    if (mutex_ready && pthread_mutex_destroy(&r.mutex)) result = 1;
    if (output >= 0 && close(output)) result = 1;
    free(capture_base);
    free(payload_base);
    if (reference != MAP_FAILED && munmap((void *)reference, (size_t)window_bytes)) result = 1;
    if (result) {
        fprintf(stderr, "offline file→TCP integrity/progress or resource error\n");
        return result;
    }
    printf("{\"schema\":\"spdk-pipeline-v1\",\"mode\":\"offline-check\","
           "\"execution\":\"offline-host-file-tcp\",\"status\":\"pass\","
           "\"performance_measured\":false,\"physical_execution\":false,"
           "\"operations\":%" PRIu64 ",\"received_bytes\":%zu,\"verified_bytes\":%zu,"
           "\"guards_ok\":true,\"payload_allocations\":1,\"steady_payload_allocations\":0,"
           "\"native_submissions\":0,\"calc_xor\":\"%016" PRIx64 "\"}\n",
           operations, c->stream, c->stream, actual_calc);
    return 0;
}

#ifdef XDEV_EXT_SPDK_NATIVE
/*
 * Native arm: official SPDK, one explicitly named PCIe function and
 * namespace, one guarded DMA buffer allocated once, one thread owning the
 * qpair.  Everything that could reconfigure the host (setup.sh, binding,
 * hugepage reservation, namespace format/write/trim/reset) stays outside.
 *
 * Environment: the PCI allowlist holds exactly --traddr, shm_id -1 gives a
 * private --file-prefix and --no-shconf (no shared primary process), and
 * spdk_nvme_connect() attaches that one controller (no probe/discovery).
 * transport_retry_count 0: on PCIe the library otherwise resubmits a
 * request whose completion it classifies as retryable (nvme_pcie_common.c,
 * pqpair->retry_count), which would replay an accepted read.
 *
 * Ownership (spdk_owner.h): a read is accepted exactly once; its buffer and
 * callback storage are reused only after a healthy completion.  At the
 * deadline the command is UNKNOWN: an abort is requested and the owner
 * keeps polling for a bounded grace; if no healthy completion arrives the
 * process becomes the quarantine owner (native_quarantine): it keeps the DMA
 * buffer, qpair, controller and environment, closes its output so run.py can
 * report exit 1, and polls until the command completes.  A failed transport
 * is never taken as proof that the device stopped writing.  This is the
 * documented limit: without a controller reset (outside this program's
 * remit) a failed controller's quiescence cannot be proven here.
 */
#include "spdk/stdinc.h"
#include "spdk/env.h"
#include "spdk/nvme.h"

#define NATIVE_GUARD 4096u			/* keeps the payload 4 KiB aligned */
#define NATIVE_ABORT_GRACE_NS (1000ull * 1000000ull)
#define NATIVE_REAPER_NAP_NS 1000000L

struct native {
    const struct config *c;
    struct spdk_pci_addr addr;
    struct spdk_nvme_transport_id trid;
    struct spdk_nvme_ctrlr *ctrlr;
    struct spdk_nvme_ns *ns;
    struct spdk_nvme_qpair *qpair;
    unsigned char *dma;			/* guard | block | guard */
    struct sp_owner owner;
    bool env_ready, vm;
};

static void native_read_done(void *arg, const struct spdk_nvme_cpl *cpl)
{
    struct native *n = arg;
    sp_on_callback(&n->owner, spdk_nvme_cpl_is_error(cpl));
}

static void native_abort_done(void *arg, const struct spdk_nvme_cpl *cpl)
{
    (void)arg;
    (void)cpl;	/* Only the read's own completion proves anything. */
}

static void native_poll(struct native *n)
{
    int32_t rc = spdk_nvme_qpair_process_completions(n->qpair, 0);
    bool healthy = spdk_nvme_qpair_get_failure_reason(n->qpair) == SPDK_NVME_QPAIR_FAILURE_NONE &&
                   !spdk_nvme_ctrlr_is_failed(n->ctrlr);
    sp_after_poll(&n->owner, rc, healthy);
}

static bool native_virtual_machine(void)
{
    char line[4096];
    bool vm = false;
    FILE *f = fopen("/sys/hypervisor/type", "r");
    if (f) {
        vm = fgets(line, sizeof(line), f) && line[0] && line[0] != '\n';
        fclose(f);
    }
    f = fopen("/proc/cpuinfo", "r");
    while (!vm && f && fgets(line, sizeof(line), f))
        vm = !strncmp(line, "flags", 5) && strstr(line, " hypervisor");
    if (f)
        fclose(f);
    return vm;
}

/* Reverse acquisition order; only for a known-idle command.  0 or 1. */
static int native_release(struct native *n)
{
    int result = 0;
    if (!sp_can_release(&n->owner))
        abort();
    if (n->dma)
        spdk_free(n->dma);
    n->dma = NULL;
    if (n->qpair && spdk_nvme_ctrlr_free_io_qpair(n->qpair))
        result = 1;
    n->qpair = NULL;
    if (n->ctrlr && spdk_nvme_detach(n->ctrlr))
        result = 1;
    n->ctrlr = NULL;
    if (n->env_ready)
        spdk_env_fini();
    n->env_ready = false;
    return result;
}

/* Abort request plus a bounded grace for a healthy completion.  true: known. */
static bool native_settle_unknown(struct native *n)
{
    uint64_t end = now_ns() + NATIVE_ABORT_GRACE_NS;
    if (spdk_nvme_ctrlr_cmd_abort_ext(n->ctrlr, n->qpair, n, native_abort_done, NULL))
        fprintf(stderr, "abort request for the UNKNOWN read was not submitted\n");
    while (!sp_can_release(&n->owner) && now_ns() < end) {
        (void)spdk_nvme_ctrlr_process_admin_completions(n->ctrlr);
        native_poll(n);
    }
    return sp_can_release(&n->owner);
}

/* Never returns: owns every native resource until the read completes. */
static void native_quarantine(struct native *n)
{
    struct timespec nap = {.tv_sec = 0, .tv_nsec = NATIVE_REAPER_NAP_NS};
    int null;
    fprintf(stderr, "SPDK_PIPELINE_UNKNOWN pid=%ld traddr=%s nsid=%" PRIu64
            " accepted=%" PRIu64 " transport_failed=%d dma_buffer=retained qpair=retained"
            " controller=attached environment=initialized; polling until the read completes,"
            " terminating this process forfeits DMA safety\n", (long)getpid(), n->c->bdf,
            n->c->nsid, n->owner.accepted, n->owner.transport_failed);
    fflush(stderr);
    null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null >= 0) {
        dup2(null, STDOUT_FILENO);
        dup2(null, STDERR_FILENO);
        close(null);
    }
    for (;;) {
        (void)spdk_nvme_ctrlr_process_admin_completions(n->ctrlr);
        native_poll(n);
        if (sp_can_release(&n->owner))
            break;
        nanosleep(&nap, NULL);
    }
    (void)native_release(n);
    _exit(1);
}

/* Before any command: the qualified geometry and a plain NVM layout. 0, 2 or 4. */
static int native_namespace_ok(const struct native *n)
{
    const struct config *c = n->c;
    if (spdk_nvme_ns_get_csi(n->ns) != SPDK_NVME_CSI_NVM || spdk_nvme_ns_get_md_size(n->ns) ||
        spdk_nvme_ns_get_pi_type(n->ns) != SPDK_NVME_FMT_NVM_PROTECTION_DISABLE ||
        spdk_nvme_ns_supports_extended_lba(n->ns) ||
        spdk_nvme_ns_get_extended_sector_size(n->ns) != spdk_nvme_ns_get_sector_size(n->ns)) {
        fprintf(stderr, "namespace %" PRIu64 " uses metadata, protection information or a "
                "non-NVM command set; unsupported\n", c->nsid);
        return 4;
    }
    if (spdk_nvme_ns_get_sector_size(n->ns) != c->sector ||
        spdk_nvme_ns_get_num_sectors(n->ns) != c->namespace_lbas) {
        fprintf(stderr, "namespace geometry %" PRIu32 " x %" PRIu64 " differs from the "
                "qualification %" PRIu64 " x %" PRIu64 "\n", spdk_nvme_ns_get_sector_size(n->ns),
                spdk_nvme_ns_get_num_sectors(n->ns), c->sector, c->namespace_lbas);
        return 2;
    }
    if (spdk_nvme_ns_get_max_io_xfer_size(n->ns) < c->block) {
        fprintf(stderr, "block %" PRIu64 " exceeds the namespace's maximum transfer\n", c->block);
        return 4;
    }
    return 0;
}

static int native_run(const struct config *c)
{
    struct native n = {.c = c};
    struct spdk_env_opts opts = {.opts_size = sizeof(opts)};
    struct spdk_nvme_ctrlr_opts copts;
    struct spdk_nvme_io_qpair_opts qopts;
    struct spdk_pci_addr attached;
    int result = 1, sender = -1, sink = -1, output = -1, rc;
    uint64_t window_bytes = c->window * c->sector, operations = c->warmup + c->iterations;
    uint64_t lbas = c->block / c->sector, actual_calc = 0, expected_calc = 0, t0 = 0, t1 = 0;
    const unsigned char *reference = MAP_FAILED;
    unsigned char *capture_base = NULL, *payload;
    bool thread_started = false, mutex_ready = false, cond_ready = false, interrupted = false;
    pthread_t thread;
    pthread_condattr_t attrs;
    struct receiver r = {.cfg = c};

    sp_init(&n.owner);
    n.vm = native_virtual_machine();
    if (c->performance && n.vm) {
        fprintf(stderr, "native performance refused inside a virtual machine\n");
        return 4;
    }
    if (spdk_pci_addr_parse(&n.addr, c->bdf)) {
        fprintf(stderr, "invalid PCI address %s\n", c->bdf);
        return 2;
    }
    spdk_env_opts_init(&opts);
    opts.name = "xdev_spdk_pipeline";
    opts.core_mask = "0x1";
    opts.shm_id = -1;
    opts.pci_allowed = &n.addr;
    opts.num_pci_addr = 1;
    if (spdk_env_init(&opts) < 0) {
        fprintf(stderr, "spdk_env_init failed (hugepages, permissions or the allowlisted device)\n");
        return 4;
    }
    n.env_ready = true;
    result = 4;
    spdk_nvme_trid_populate_transport(&n.trid, SPDK_NVME_TRANSPORT_PCIE);
    snprintf(n.trid.traddr, sizeof(n.trid.traddr), "%s", c->bdf);
    spdk_nvme_ctrlr_get_default_ctrlr_opts(&copts, sizeof(copts));
    copts.transport_retry_count = 0;
    n.ctrlr = spdk_nvme_connect(&n.trid, &copts, sizeof(copts));
    if (!n.ctrlr) {
        fprintf(stderr, "cannot attach the NVMe controller at %s\n", c->bdf);
        goto done;
    }
    if (spdk_pci_addr_parse(&attached, spdk_nvme_ctrlr_get_transport_id(n.ctrlr)->traddr) ||
        spdk_pci_addr_compare(&attached, &n.addr)) {
        fprintf(stderr, "attached controller is not %s\n", c->bdf);
        result = 1;
        goto done;
    }
    n.ns = spdk_nvme_ctrlr_get_ns(n.ctrlr, (uint32_t)c->nsid);
    if (!n.ns || !spdk_nvme_ns_is_active(n.ns)) {
        fprintf(stderr, "namespace %" PRIu64 " is not active on %s\n", c->nsid, c->bdf);
        goto done;
    }
    rc = native_namespace_ok(&n);
    if (rc) {
        result = rc;
        goto done;
    }
    result = 1;
    spdk_nvme_ctrlr_get_default_io_qpair_opts(n.ctrlr, &qopts, sizeof(qopts));
    n.qpair = spdk_nvme_ctrlr_alloc_io_qpair(n.ctrlr, &qopts, sizeof(qopts));
    /* The one DMA allocation, reused by every operation. */
    n.dma = spdk_zmalloc((size_t)c->block + 2 * NATIVE_GUARD, NATIVE_GUARD, NULL,
                         SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);
    capture_base = malloc(c->stream + 1 + 2 * GUARD);
    reference = mmap(NULL, (size_t)window_bytes, PROT_READ, MAP_PRIVATE, c->reference, 0);
    if (!n.qpair || !n.dma || !capture_base || reference == MAP_FAILED) {
        fprintf(stderr, "qpair, DMA buffer, capture or reference mapping unavailable\n");
        goto done;
    }
    memset(n.dma, MASK_BYTE, (size_t)c->block + 2 * NATIVE_GUARD);
    memset(capture_base, MASK_BYTE, c->stream + 1 + 2 * GUARD);
    payload = n.dma + NATIVE_GUARD;
    r.bytes = capture_base + GUARD;
    output = open(c->capture, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) {
        result = 2;
        goto done;
    }
    r.deadline = now_ns() + c->deadline_ms * UINT64_C(1000000);
    if (tcp_pair(&sender, &sink, r.deadline))
        goto done;
    /* As the original: a 4 MiB send buffer (best effort, as there). */
    (void)setsockopt(sender, SOL_SOCKET, SO_SNDBUF, &(int){4 * 1024 * 1024}, sizeof(int));
    r.fd = sink;
    if (pthread_mutex_init(&r.mutex, NULL))
        goto done;
    mutex_ready = true;
    if (pthread_condattr_init(&attrs))
        goto done;
    rc = pthread_condattr_setclock(&attrs, CLOCK_MONOTONIC);
    if (!rc)
        rc = pthread_cond_init(&r.progress, &attrs);
    pthread_condattr_destroy(&attrs);
    if (rc)
        goto done;
    cond_ready = true;
    if (pthread_create(&thread, NULL, receive_stream, &r))
        goto done;
    thread_started = true;
    for (uint64_t i = 0; i < operations; ++i) {
        uint64_t lba = c->start + rand_slot(i, window_bytes / c->block) * lbas;
        if (i == c->warmup) {
            /* Warmup fully delivered first; warmup 0 starts before operation 0. */
            if (i && delivery_barrier(&r, (size_t)(i * c->block)))
                goto done;
            t0 = now_ns();
        }
        if (n.owner.state != SP_IDLE)
            abort();
        rc = spdk_nvme_ns_cmd_read(n.ns, n.qpair, payload, lba, (uint32_t)lbas,
                                   native_read_done, &n, 0);
        if (sp_submit(&n.owner, rc)) {
            fprintf(stderr, "read %" PRIu64 " not accepted (%d); not replayed\n", i, rc);
            goto done;
        }
        while (n.owner.state == SP_SUBMITTED) {
            native_poll(&n);
            if (n.owner.state == SP_SUBMITTED && now_ns() >= r.deadline)
                sp_on_deadline(&n.owner);
        }
        if (n.owner.state == SP_UNKNOWN)
            goto done;	/* settled or quarantined below */
        if (sp_next(&n.owner)) {
            fprintf(stderr, "read %" PRIu64 " completed with an error\n", i);
            goto done;
        }
        /* The original workload's optional calculation, then the send. */
        actual_calc ^= calculate(payload, c->calc);
        if (send_full(sender, payload, (size_t)c->block, c, r.deadline, &interrupted, false))
            goto done;
    }
    if (shutdown(sender, SHUT_WR) || delivery_barrier(&r, c->stream))
        goto done;
    t1 = now_ns();
    if (pthread_join(thread, NULL))
        abort();
    thread_started = false;
    if (r.error || r.count != c->stream)
        goto done;
    /* Every byte and both guards of both buffers, after timing. */
    if (!guards_ok(n.dma, (size_t)c->block, NATIVE_GUARD) ||
        !guards_ok(capture_base, c->stream + 1, GUARD))
        goto done;
    for (uint64_t i = 0; i < operations; ++i) {
        size_t offset = (size_t)(rand_slot(i, window_bytes / c->block) * c->block);
        if (memcmp(r.bytes + i * c->block, reference + offset, (size_t)c->block))
            goto done;
        expected_calc ^= calculate(reference + offset, c->calc);
    }
    if (actual_calc != expected_calc || write_full(output, r.bytes, c->stream) || close(output)) {
        output = -1;
        goto done;
    }
    output = -1;
    result = 0;
done:
    if (thread_started) {
        if (sender >= 0) shutdown(sender, SHUT_RDWR);
        if (sink >= 0) shutdown(sink, SHUT_RDWR);
        if (pthread_join(thread, NULL))
            abort();
    }
    if (sender >= 0 && close(sender)) result = 1;
    if (sink >= 0 && close(sink)) result = 1;
    if (cond_ready && pthread_cond_destroy(&r.progress)) result = 1;
    if (mutex_ready && pthread_mutex_destroy(&r.mutex)) result = 1;
    if (output >= 0 && close(output)) result = 1;
    free(capture_base);
    if (reference != MAP_FAILED && munmap((void *)reference, (size_t)window_bytes)) result = 1;
    if (!sp_can_release(&n.owner)) {
        /* Sockets and host buffers are gone; DMA ownership is not. */
        if (!native_settle_unknown(&n))
            native_quarantine(&n);
        result = 1;
    }
    if (native_release(&n))
        result = 1;
    if (result) {
        fprintf(stderr, "native SPDK pipeline failed (exit %d)\n", result);
        return result;
    }
    printf("{\"schema\":\"spdk-pipeline-v1\",\"mode\":\"%s\",\"execution\":\"native-spdk-pcie\","
           "\"status\":\"pass\",\"performance_measured\":%s,\"physical_execution\":%s,"
           "\"virtual_machine\":%s,\"queue_depth\":1,\"read_only\":true,\"traddr\":\"%s\","
           "\"nsid\":%" PRIu64 ",\"spdk_retry_count\":0,\"operations\":%" PRIu64 ","
           "\"received_bytes\":%zu,\"verified_bytes\":%zu,\"guards_ok\":true,"
           "\"payload_allocations\":1,\"steady_payload_allocations\":0,"
           "\"native_submissions\":%" PRIu64 ",\"calc_xor\":\"%016" PRIx64 "\","
           "\"reference_sha256\":\"%s\"", c->mode, c->performance ? "true" : "false",
           n.vm ? "false" : "true", n.vm ? "true" : "false", c->bdf, c->nsid, operations,
           c->stream, c->stream, n.owner.accepted, actual_calc, c->reference_sha256);
    if (c->performance)
        printf(",\"measured_operations\":%" PRIu64 ",\"measured_bytes\":%" PRIu64
               ",\"measured_ns\":%" PRIu64, c->iterations, c->iterations * c->block, t1 - t0);
    printf("}\n");
    return fflush(stdout) ? 1 : 0;
}
#endif /* XDEV_EXT_SPDK_NATIVE */

static bool parse_number(const char *s, uint64_t *out)
{
    char *end;
    if (!*s || strspn(s, "0123456789") != strlen(s))
        return false;
    errno = 0;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno || *end)
        return false;
    *out = value;
    return true;
}

int main(int argc, char **argv)
{
    struct config c = {0};
    uint64_t numbers[13];
    if (argc < 2)
        goto invalid;
    c.native = !strcmp(argv[1], "native-correctness") || !strcmp(argv[1], "native-performance");
    c.performance = !strcmp(argv[1], "native-performance");
    if (argc != (c.native ? 19 : 18))
        goto invalid;
    c.mode = argv[1]; c.bdf = argv[2]; c.capture = argv[14]; c.faults = argv[17];
    c.reference_sha256 = c.native ? argv[18] : "";
    /* Internal executable still refuses malformed input when invoked directly. */
    for (int i = 0; i < 11; ++i)
        if (!parse_number(argv[i + 3], &numbers[i]))
            goto invalid;
    if (!parse_number(argv[15], &numbers[11]) || !parse_number(argv[16], &numbers[12]))
        goto invalid;
    c.nsid = numbers[0]; c.sector = numbers[1]; c.namespace_lbas = numbers[2];
    c.start = numbers[3]; c.window = numbers[4]; c.block = numbers[5];
    c.iterations = numbers[6]; c.warmup = numbers[7]; c.calc = numbers[8];
    c.deadline_ms = numbers[9];
    if (numbers[10] > INT_MAX)
        goto invalid;
    c.reference = (int)numbers[10];
    c.send_max = numbers[11]; c.recv_max = numbers[12];
    if ((!c.native && strcmp(c.mode, "offline-check")) || !c.nsid || c.nsid >= UINT32_MAX ||
        (c.sector != 512 && c.sector != 4096) ||
        !c.namespace_lbas || !c.window || c.start > c.namespace_lbas ||
        c.window > c.namespace_lbas - c.start || c.window > UINT64_MAX / c.sector ||
        c.window > SIZE_MAX / c.sector || c.block < 512 || c.block > 1048576 ||
        c.block % c.sector || c.window * c.sector < c.block ||
        !c.iterations || c.iterations > 65536 || c.warmup > 4096 ||
        c.calc > c.block || c.calc % 8 || !c.deadline_ms || c.deadline_ms > 60000 ||
        (c.iterations + c.warmup) > STREAM_LIMIT / c.block ||
        !c.send_max || c.send_max > 1048576 || !c.recv_max || c.recv_max > 1048576)
        goto invalid;
    struct stat info;
    if (fstat(c.reference, &info) || !S_ISREG(info.st_mode) ||
        info.st_size < 0 || (uint64_t)info.st_size != c.window * c.sector)
        goto invalid;
    if (c.native && (*c.faults || c.send_max != 1048576 || c.recv_max != 1048576 ||
                     strlen(c.reference_sha256) != 64 ||
                     strspn(c.reference_sha256, "0123456789abcdef") != 64))
        goto invalid;
    c.stream = (size_t)((c.iterations + c.warmup) * c.block);
    if (c.native) {
#ifdef XDEV_EXT_SPDK_NATIVE
        return native_run(&c);
#else
        fprintf(stderr, "native SPDK modes need a build with -DXDEV_EXT_SPDK_NATIVE against an "
                "official SPDK tree (tests/eval/spdk/build.py --spdk-root)\n");
        return 4;
#endif
    }
    return offline_check(&c);
invalid:
    fprintf(stderr, "invalid internal offline fixture arguments\n");
    return 2;
}

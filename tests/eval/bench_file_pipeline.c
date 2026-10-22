/* SPDX-License-Identifier: GPL-2.0-only
 * Adapted workload from bench_nvme_pipeline_compare.c / _cost.c:
 * file -> optional CPU byte-work -> TCP loopback. See README.md for scope.
 */
#define _GNU_SOURCE
#include "eval_common.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#ifdef EVAL_HAVE_LIBURING
#include <liburing.h>
#endif

struct backend {
    const char *name;
#ifdef EVAL_HAVE_LIBURING
    struct io_uring ring;
    bool initialized;
#endif
};
struct sink {
    int socket_fd, file_fd, error;
    uint64_t bytes, iterations, verified;
};

static void *receive_stream(void *arg)
{
    struct sink *sink = arg;
    unsigned char storage[65536 + 64], expected[65536];
    unsigned char *received = storage + 32;
    memset(storage, 0xa5, sizeof(storage));
    uint64_t total = sink->bytes * sink->iterations;
    for (;;) {
        ssize_t n = recv(sink->socket_fd, received, 65536, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            perror("receiver recv");
            sink->error = 1;
            break;
        }
        if (!n) {
            if (sink->verified != total) {
                fprintf(stderr, "truncated stream: received=%" PRIu64 " expected=%" PRIu64 "\n",
                        sink->verified, total);
                sink->error = 1;
            }
            break;
        }
        if ((uint64_t)n > total - sink->verified) {
            fprintf(stderr, "extra stream bytes\n");
            sink->error = 1;
            break;
        }
        size_t done = 0;
        while (done < (size_t)n) {
            uint64_t offset = (sink->verified + done) % sink->bytes;
            size_t part = (size_t)n - done;
            if (part > sink->bytes - offset)
                part = (size_t)(sink->bytes - offset);
            if (eval_pread(sink->file_fd, expected + done, part, offset)) {
                perror("receiver reference pread");
                sink->error = 1;
                break;
            }
            done += part;
        }
        if (sink->error)
            break;
        if (memcmp(expected, received, (size_t)n)) {
            fprintf(stderr, "receiver byte mismatch at stream block=%" PRIu64 "\n", sink->verified);
            sink->error = 1;
            break;
        }
        for (size_t i = 0; i < 32; i++) {
            if (storage[i] != 0xa5 || storage[65536 + 32 + i] != 0xa5) {
                fprintf(stderr, "receiver guard corruption\n");
                sink->error = 1;
            }
        }
        if (sink->error) break;
        sink->verified += (uint64_t)n;
    }
    /* Wake a producer if verification failed while it was sending. */
    shutdown(sink->socket_fd, SHUT_RDWR);
    return NULL;
}

static int tcp_pair(int sockets[2])
{
    int listener = -1, client = -1, server = -1;
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    struct timeval timeout = {.tv_sec = 30};
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, length) ||
        listen(listener, 1) || getsockname(listener, (struct sockaddr *)&address, &length))
        goto error;
    client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0 || connect(client, (struct sockaddr *)&address, length))
        goto error;
    server = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (server < 0)
        goto error;
    if (setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)))
        goto error;
    close(listener);
    sockets[0] = client;
    sockets[1] = server;
    return 0;
error:
    perror("TCP loopback setup");
    if (listener >= 0) close(listener);
    if (client >= 0) close(client);
    if (server >= 0) close(server);
    return -1;
}

#ifdef EVAL_HAVE_LIBURING
static int uring_result(struct backend *backend)
{
    struct io_uring_cqe *cqe;
    int result;
    do { result = io_uring_submit(&backend->ring); } while (result == -EINTR);
    if (result != 1) return result < 0 ? result : -EIO;
    do { result = io_uring_wait_cqe(&backend->ring, &cqe); } while (result == -EINTR);
    if (result < 0) return result;
    result = cqe->res;
    io_uring_cqe_seen(&backend->ring, cqe);
    return result;
}
#endif

static int backend_init(struct backend *backend, void *buffer, size_t chunk)
{
    if (!strcmp(backend->name, "posix")) return 0;
#ifdef EVAL_HAVE_LIBURING
    int result = io_uring_queue_init(8, &backend->ring, 0);
    if (result < 0) {
        fprintf(stderr, "io_uring unavailable: %s\n", strerror(-result));
        return 4;
    }
    backend->initialized = true;
    if (!strcmp(backend->name, "io_uring-fixed")) {
        struct iovec iov = {.iov_base = buffer, .iov_len = chunk};
        result = io_uring_register_buffers(&backend->ring, &iov, 1);
        if (result < 0) {
            fprintf(stderr, "registered buffers unavailable: %s\n", strerror(-result));
            return 4;
        }
    }
#else
    (void)buffer;
    (void)chunk;
    fprintf(stderr, "io_uring unavailable: rebuild with ENABLE_URING=1 and liburing\n");
    return 4;
#endif
    return 0;
}

static ssize_t backend_io(struct backend *backend, int fd, void *buf,
                          size_t bytes, uint64_t offset, bool sending)
{
    if (!strcmp(backend->name, "posix"))
        return sending ? send(fd, buf, bytes, MSG_NOSIGNAL) : pread(fd, buf, bytes, (off_t)offset);
#ifdef EVAL_HAVE_LIBURING
    struct io_uring_sqe *sqe = io_uring_get_sqe(&backend->ring);
    if (!sqe) { errno = EIO; return -1; }
    if (sending)
        io_uring_prep_send(sqe, fd, buf, (unsigned)bytes, MSG_NOSIGNAL);
    else if (!strcmp(backend->name, "io_uring-fixed"))
        io_uring_prep_read_fixed(sqe, fd, buf, (unsigned)bytes, offset, 0);
    else
        io_uring_prep_read(sqe, fd, buf, (unsigned)bytes, offset);
    int result = uring_result(backend);
    if (result < 0) { errno = -result; return -1; }
    return result;
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int transfer(struct backend *backend, int fd, void *buffer, size_t bytes,
                    uint64_t offset, bool sending)
{
    size_t done = 0;
    while (done < bytes) {
        ssize_t n = backend_io(backend, fd, (char *)buffer + done, bytes - done,
                               offset + done, sending);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (!n) errno = sending ? EIO : ENODATA;
            perror(sending ? "send" : "pread");
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s --file FILE --bytes N [--chunk N] [--iterations N]\n"
            "  [--backend posix|io_uring|io_uring-fixed] [--compute-bytes N]\n"
            "  [--fault corrupt|truncate|backend-error] (validation only)\n", program);
}

int main(int argc, char **argv)
{
    const char *path = NULL, *fault = "none";
    struct backend backend = {.name = "posix"};
    uint64_t bytes = 0, iterations = 1, chunk = 65536, compute = 0;
    uint64_t read_bytes = 0, sent_bytes = 0, compute_bytes = 0, checksum = 0;
    struct stat statbuf;
    unsigned char *buffer = NULL, *allocation = NULL;
    int fd = -1, sockets[2] = {-1, -1}, rc = 1, option;
    bool started = false;
    pthread_t thread;
    struct sink sink = {0};
    const struct option options[] = {
        {"file", required_argument, NULL, 'f'}, {"bytes", required_argument, NULL, 'b'},
        {"chunk", required_argument, NULL, 'c'},
        {"block-size", required_argument, NULL, 'c'}, {"iterations", required_argument, NULL, 'i'},
        {"backend", required_argument, NULL, 'm'}, {"compute-bytes", required_argument, NULL, 'w'},
        {"fault", required_argument, NULL, 'x'}, {"help", no_argument, NULL, 'h'}, {0}
    };
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'f': path = optarg; break;
        case 'b': bytes = eval_number(optarg, EVAL_MAX_BYTES, "bytes"); break;
        case 'c': chunk = eval_number(optarg, EVAL_MAX_CHUNK, "chunk"); break;
        case 'i': iterations = eval_number(optarg, 1000000, "iterations"); break;
        case 'm': backend.name = optarg; break;
        case 'w': compute = eval_number(optarg, EVAL_MAX_CHUNK, "compute-bytes"); break;
        case 'x': fault = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }
    if (!path || !bytes || !chunk || !iterations || compute > chunk || optind != argc ||
        (strcmp(backend.name, "posix") && strcmp(backend.name, "io_uring") && strcmp(backend.name, "io_uring-fixed")) ||
        (strcmp(fault, "none") && strcmp(fault, "corrupt") && strcmp(fault, "truncate") && strcmp(fault, "backend-error"))) {
        usage(argv[0]); return 2;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { perror("input open"); goto out; }
    if (fstat(fd, &statbuf) || !S_ISREG(statbuf.st_mode) || statbuf.st_size < 0 || bytes > (uint64_t)statbuf.st_size) {
        fprintf(stderr, "input must be a regular file with at least --bytes bytes\n"); goto out;
    }
    if (posix_memalign((void **)&allocation, 4096, (size_t)chunk + 8192)) {
        fprintf(stderr, "buffer allocation failed\n"); goto out;
    }
    buffer = allocation + 4096;
    memset(buffer - 32, 0xa5, 32);
    memset(buffer + chunk, 0xa5, 32);
    rc = backend_init(&backend, buffer, (size_t)chunk);
    if (rc) goto out;
    rc = 1;
    if (tcp_pair(sockets)) goto out;
    sink = (struct sink){.socket_fd = sockets[1], .file_fd = fd, .bytes = bytes, .iterations = iterations};
    int error = pthread_create(&thread, NULL, receive_stream, &sink);
    if (error) { fprintf(stderr, "pthread_create: %s\n", strerror(error)); goto out; }
    started = true;
    uint64_t start = eval_now();
    struct rusage before = {0}, after = {0};
    if (getrusage(RUSAGE_SELF, &before)) { perror("getrusage"); goto finish; }
    for (uint64_t iteration = 0; iteration < iterations; iteration++) {
        for (uint64_t offset = 0; offset < bytes; ) {
            size_t part = (size_t)((bytes - offset < chunk) ? bytes - offset : chunk);
            if (!strcmp(fault, "backend-error")) {
                fprintf(stderr, "injected backend error\n"); goto finish;
            }
            if (transfer(&backend, fd, buffer, part, offset, false)) goto finish;
            read_bytes += part;
            size_t work = (compute < part) ? (size_t)compute : part;
            for (size_t i = 0; i < work; i++) checksum = checksum * 33 + buffer[i];
            compute_bytes += work;
            if (!iteration && !offset && !strcmp(fault, "corrupt")) buffer[0] ^= 1;
            size_t send_bytes = part;
            if (iteration + 1 == iterations && offset + part == bytes && !strcmp(fault, "truncate")) send_bytes--;
            if (transfer(&backend, sockets[0], buffer, send_bytes, 0, true)) goto finish;
            sent_bytes += send_bytes;
            offset += part;
        }
    }
    rc = 0;
finish:
    shutdown(sockets[0], SHUT_WR);
    pthread_join(thread, NULL);
    started = false;
    uint64_t elapsed = eval_now() - start;
    if (sink.error || read_bytes != bytes * iterations || sent_bytes != bytes * iterations ||
        sink.verified != bytes * iterations) rc = 1;
    for (size_t i = 0; i < 32; i++)
        if (buffer[-32 + (int)i] != 0xa5 || buffer[chunk + i] != 0xa5) {
            fprintf(stderr, "producer guard corruption\n"); rc = 1;
        }
    uint64_t cpu_us = 0;
    if (getrusage(RUSAGE_SELF, &after)) { perror("getrusage"); rc = 1; }
    else cpu_us = (uint64_t)(after.ru_utime.tv_sec - before.ru_utime.tv_sec) * 1000000 +
        after.ru_utime.tv_usec - before.ru_utime.tv_usec +
        (uint64_t)(after.ru_stime.tv_sec - before.ru_stime.tv_sec) * 1000000 +
        after.ru_stime.tv_usec - before.ru_stime.tv_usec;
#ifdef EVAL_HAVE_LIBURING
    if (backend.initialized && !strcmp(backend.name, "io_uring-fixed")) {
        int unregister_result = io_uring_unregister_buffers(&backend.ring);
        if (unregister_result < 0) {
            fprintf(stderr, "unregister buffers: %s\n", strerror(-unregister_result)); rc = 1;
        }
    }
#endif
    if (!rc)
        printf("{\"status\":\"ok\",\"backend\":\"%s\",\"route\":\"buffered-file-to-tcp-loopback\","
               "\"completion\":\"receiver-full-byte-compare\",\"bytes\":%" PRIu64 ",\"iterations\":%" PRIu64 ","
               "\"chunk\":%" PRIu64 ",\"read_bytes\":%" PRIu64 ",\"sent_bytes\":%" PRIu64 ","
               "\"verified_bytes\":%" PRIu64 ",\"compute_bytes\":%" PRIu64 ",\"compute_checksum\":%" PRIu64 ","
               "\"elapsed_ns\":%" PRIu64 ",\"cpu_us\":%" PRIu64 ",\"chunks\":%" PRIu64 "}\n", backend.name, bytes, iterations, chunk,
               read_bytes, sent_bytes, sink.verified, compute_bytes, checksum, elapsed, cpu_us, ((bytes + chunk - 1) / chunk) * iterations);
out:
    if (started) { shutdown(sockets[0], SHUT_RDWR); pthread_join(thread, NULL); }
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
#ifdef EVAL_HAVE_LIBURING
    if (backend.initialized) io_uring_queue_exit(&backend.ring);
#endif
    free(allocation);
    if (fd >= 0) close(fd);
    return rc;
}

/* SPDX-License-Identifier: GPL-2.0-only
 * Workload port of bench_llm_load.c and bench_gpu_checkpoint.c; ordinary
 * buffered file I/O + synchronous CUDA copies, not an xdev_ext backend.
 */
#define _GNU_SOURCE
#include "eval_common.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/stat.h>

typedef unsigned long long deviceptr;
struct cuda_api {
    int (*init)(unsigned);
    int (*device_get)(int *, int);
    int (*context_create)(void **, unsigned, int);
    int (*context_destroy)(void *);
    int (*synchronize)(void);
    int (*allocate)(deviceptr *, size_t);
    int (*release)(deviceptr);
    int (*host_allocate)(void **, size_t, unsigned);
    int (*host_release)(void *);
    int (*to_device)(deviceptr, const void *, size_t);
    int (*to_host)(void *, deviceptr, size_t);
};

static int cuda_call(int result, const char *operation)
{
    if (result) fprintf(stderr, "CUDA %s failed: %d\n", operation, result);
    return result ? -1 : 0;
}

static unsigned char pattern(uint64_t index)
{
    return (unsigned char)((index * 37 + index / 251) % 256);
}

static bool guards(const unsigned char *host, size_t chunk)
{
    for (size_t i = 0; i < 32; i++)
        if (host[i] != 0xa5 || host[chunk + 32 + i] != 0xa5) return false;
    return true;
}

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s --direction load|checkpoint --memory pageable|pinned\n"
            "  --input FILE (load) | --output NEW_FILE (checkpoint) --bytes N\n"
            "  [--chunk N] [--cuda-library libcuda.so.1]\n", name);
}

int main(int argc, char **argv)
{
    const char *direction = NULL, *memory = NULL, *input = NULL, *output = NULL;
    const char *library = "libcuda.so.1";
    uint64_t bytes = 0, chunk = 65536, verified = 0, io_bytes = 0;
    uint64_t transfer_ns = 0, file_ns = 0;
    int option, fd = -1, rc = 1, device;
    bool checkpoint, pinned, created = false;
    void *handle = NULL, *context = NULL, *allocation = NULL;
    unsigned char *host = NULL, *verify = NULL;
    deviceptr gpu = 0;
    struct cuda_api api = {0};
    struct stat statbuf;
    const struct option options[] = {
        {"direction", required_argument, NULL, 'd'}, {"memory", required_argument, NULL, 'm'},
        {"host-memory", required_argument, NULL, 'm'},
        {"input", required_argument, NULL, 'i'}, {"output", required_argument, NULL, 'o'},
        {"bytes", required_argument, NULL, 'b'}, {"chunk", required_argument, NULL, 'c'},
        {"chunk-size", required_argument, NULL, 'c'},
        {"cuda-library", required_argument, NULL, 'l'}, {"help", no_argument, NULL, 'h'}, {0}
    };
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'd': direction = optarg; break;
        case 'm': memory = optarg; break;
        case 'i': input = optarg; break;
        case 'o': output = optarg; break;
        case 'b': bytes = eval_number(optarg, EVAL_MAX_BYTES, "bytes"); break;
        case 'c': chunk = eval_number(optarg, EVAL_MAX_CHUNK, "chunk"); break;
        case 'l': library = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }
    if (!direction || !memory || !bytes || !chunk || optind != argc ||
        (strcmp(direction, "load") && strcmp(direction, "checkpoint")) ||
        (strcmp(memory, "pageable") && strcmp(memory, "pinned"))) {
        usage(argv[0]); return 2;
    }
    checkpoint = !strcmp(direction, "checkpoint");
    pinned = !strcmp(memory, "pinned");
    if ((checkpoint && (!output || input)) || (!checkpoint && (!input || output))) {
        usage(argv[0]); return 2;
    }
    if (!checkpoint) {
        fd = open(input, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) { perror("input open"); goto out; }
        if (fstat(fd, &statbuf) || !S_ISREG(statbuf.st_mode) || statbuf.st_size < 0 || bytes > (uint64_t)statbuf.st_size) {
            fprintf(stderr, "input must be a regular file with at least --bytes bytes\n"); goto out;
        }
    }
    handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "CUDA unavailable: %s\n", dlerror()); rc = 4; goto out;
    }
#define LOAD(field, symbol) do { \
    *(void **)(&api.field) = dlsym(handle, symbol); \
    if (!api.field) { fprintf(stderr, "CUDA unavailable: missing %s\n", symbol); rc = 4; goto out; } \
} while (0)
    LOAD(init, "cuInit"); LOAD(device_get, "cuDeviceGet");
    LOAD(context_create, "cuCtxCreate_v2"); LOAD(context_destroy, "cuCtxDestroy_v2");
    LOAD(synchronize, "cuCtxSynchronize"); LOAD(allocate, "cuMemAlloc_v2");
    LOAD(release, "cuMemFree_v2"); LOAD(to_device, "cuMemcpyHtoD_v2");
    LOAD(to_host, "cuMemcpyDtoH_v2");
    if (pinned) { LOAD(host_allocate, "cuMemHostAlloc"); LOAD(host_release, "cuMemFreeHost"); }
#undef LOAD
    int result = api.init(0);
    if (!result) result = api.device_get(&device, 0);
    if (result) { fprintf(stderr, "CUDA unavailable: initialization/device error %d\n", result); rc = 4; goto out; }
    if (cuda_call(api.context_create(&context, 0, device), "context create")) goto out;
    if (pinned) {
        if (cuda_call(api.host_allocate(&allocation, (size_t)chunk + 64, 0), "pinned host allocate")) goto out;
    } else {
        allocation = malloc((size_t)chunk + 64);
        if (!allocation) { perror("host allocate"); goto out; }
    }
    host = (unsigned char *)allocation + 32;
    verify = malloc((size_t)chunk + 64);
    if (!verify) { perror("verify allocate"); goto out; }
    memset(allocation, 0xa5, (size_t)chunk + 64);
    if (cuda_call(api.allocate(&gpu, (size_t)chunk + 64), "device allocate") ||
        cuda_call(api.to_device(gpu, allocation, (size_t)chunk + 64), "initialize guards") ||
        cuda_call(api.synchronize(), "initialize synchronize")) goto out;
    if (checkpoint) {
        fd = open(output, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) { perror("exclusive output open"); goto out; }
        created = true;
    }
    uint64_t start = eval_now();
    struct rusage before, after;
    if (getrusage(RUSAGE_SELF, &before)) { perror("getrusage"); goto out; }
    for (uint64_t offset = 0; offset < bytes; ) {
        size_t part = (size_t)((bytes - offset < chunk) ? bytes - offset : chunk);
        uint64_t t;
        if (checkpoint) {
            for (size_t i = 0; i < part; i++) host[i] = pattern(offset + i);
            /* Synthetic GPU state initialization is outside transfer_ns/file_ns. */
            if (cuda_call(api.to_device(gpu + 32, host, part), "initialize GPU payload") ||
                cuda_call(api.synchronize(), "payload initialize synchronize")) goto out;
            memset(host, 0, part);
            t = eval_now();
            if (cuda_call(api.to_host(host, gpu + 32, part), "device to host") ||
                cuda_call(api.synchronize(), "checkpoint synchronize")) goto out;
            transfer_ns += eval_now() - t;
            for (size_t i = 0; i < part; i++)
                if (host[i] != pattern(offset + i)) { fprintf(stderr, "GPU payload byte mismatch\n"); goto out; }
            t = eval_now();
            if (eval_pwrite(fd, host, part, offset)) { perror("checkpoint pwrite"); goto out; }
            file_ns += eval_now() - t;
        } else {
            t = eval_now();
            if (eval_pread(fd, host, part, offset)) { perror("load pread"); goto out; }
            file_ns += eval_now() - t;
            t = eval_now();
            if (cuda_call(api.to_device(gpu + 32, host, part), "host to device") ||
                cuda_call(api.synchronize(), "load synchronize")) goto out;
            transfer_ns += eval_now() - t;
        }
        io_bytes += part;
        /* Includes device guards, not just the valid tail. Not a throughput-only timer. */
        if (cuda_call(api.to_host(verify, gpu, (size_t)chunk + 64), "validation readback") ||
            cuda_call(api.synchronize(), "validation synchronize")) goto out;
        if (memcmp(host, verify + 32, part) || !guards(verify, (size_t)chunk) ||
            !guards(allocation, (size_t)chunk)) {
            fprintf(stderr, "GPU/host byte mismatch or guard corruption\n"); goto out;
        }
        verified += part;
        offset += part;
    }
    if (checkpoint) {
        uint64_t t = eval_now();
        if (fsync(fd)) { perror("checkpoint fsync"); goto out; }
        file_ns += eval_now() - t;
        if (fstat(fd, &statbuf) || (uint64_t)statbuf.st_size != bytes) {
            fprintf(stderr, "checkpoint file length mismatch\n"); goto out;
        }
        for (uint64_t offset = 0; offset < bytes; ) {
            size_t part = (size_t)((bytes - offset < chunk) ? bytes - offset : chunk);
            if (eval_pread(fd, verify, part, offset)) { perror("checkpoint verify pread"); goto out; }
            for (size_t i = 0; i < part; i++)
                if (verify[i] != pattern(offset + i)) { fprintf(stderr, "checkpoint file byte mismatch\n"); goto out; }
            offset += part;
        }
    }
    if (getrusage(RUSAGE_SELF, &after)) { perror("getrusage"); goto out; }
    uint64_t elapsed = eval_now() - start;
    uint64_t cpu_us = (uint64_t)(after.ru_utime.tv_sec - before.ru_utime.tv_sec) * 1000000 +
        after.ru_utime.tv_usec - before.ru_utime.tv_usec +
        (uint64_t)(after.ru_stime.tv_sec - before.ru_stime.tv_sec) * 1000000 +
        after.ru_stime.tv_usec - before.ru_stime.tv_usec;
    rc = 0;
    /* Cleanup is checked before emitting any success record. */
    if (cuda_call(api.release(gpu), "device free")) rc = 1;
    gpu = 0;
    if (pinned) {
        if (cuda_call(api.host_release(allocation), "pinned host free")) rc = 1;
    } else free(allocation);
    allocation = NULL;
    if (cuda_call(api.context_destroy(context), "context destroy")) rc = 1;
    context = NULL;
    if (close(fd)) { perror("file close"); rc = 1; }
    fd = -1;
    if (!rc)
        printf("{\"status\":\"ok\",\"backend\":\"cuda_%s_staging\",\"direction\":\"%s\","
               "\"route\":\"%s\",\"completion\":\"synchronous-copy-full-byte-compare%s\","
               "\"bytes\":%" PRIu64 ",\"chunk\":%" PRIu64 ",\"io_bytes\":%" PRIu64 ","
               "\"verified_bytes\":%" PRIu64 ",\"file_ns\":%" PRIu64 ",\"transfer_ns\":%" PRIu64 ","
               "\"elapsed_ns\":%" PRIu64 ",\"cpu_us\":%" PRIu64 "}\n", memory, direction, checkpoint ? "cuda-host-buffered-file" : "buffered-file-host-cuda",
               checkpoint ? "-fsync-file-reread" : "", bytes, chunk, io_bytes, verified,
               file_ns, transfer_ns, elapsed, cpu_us);
out:
    if (gpu && api.release && cuda_call(api.release(gpu), "device cleanup")) rc = 1;
    if (allocation) {
        if (pinned) { if (cuda_call(api.host_release(allocation), "host cleanup")) rc = 1; }
        else free(allocation);
    }
    free(verify);
    if (context && cuda_call(api.context_destroy(context), "context cleanup")) rc = 1;
    if (handle) dlclose(handle);
    if (fd >= 0 && close(fd)) { perror("file cleanup close"); rc = 1; }
    if (rc && created) unlink(output);
    return rc;
}

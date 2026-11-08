/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_XDG_GPU_H
#define XDEV_EVAL_XDG_GPU_H
/*
 * GPU memory for the E4 baselines through the CUDA driver API, opened at run
 * time (libcuda.so.1), so the tools build without an SDK.  The calls are the
 * ones the runtime API makes for the plan's baseline: cuMemHostAlloc(0) is
 * cudaHostAlloc(cudaHostAllocDefault), and the synchronous cuMemcpyDtoH /
 * cuMemcpyHtoD on that pinned buffer are cudaMemcpy D2H / H2D.  The primary
 * context of the device is used, as the runtime does.
 *
 * --fake-gpu (host checks only) puts "device" memory in malloc'd host memory
 * and copies with memcpy; a record made that way says execution host-fake and
 * performance_claim none.
 */
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct xdg_gpu {
	int fake, ordinal, driver_version;
	void *lib, *ctx;
	int dev;
	int (*init)(unsigned int);
	int (*driver_get_version)(int *);
	int (*device_get)(int *, int);
	int (*primary_retain)(void **, int);
	int (*primary_release)(int);
	int (*ctx_set)(void *);
	int (*mem_alloc)(uint64_t *, size_t);
	int (*mem_free)(uint64_t);
	int (*host_alloc)(void **, size_t, unsigned int);
	int (*host_free)(void *);
	int (*htod)(uint64_t, const void *, size_t);
	int (*dtoh)(void *, uint64_t, size_t);
	int (*stream_create)(void **, unsigned int);
	int (*stream_sync)(void *);
	int (*stream_destroy)(void *);
};

static inline int xdg_gpu_sym(struct xdg_gpu *g, void *slot, const char *name)
{
	void *f = dlsym(g->lib, name);

	if (!f) {
		fprintf(stderr, "CUDA driver lacks %s\n", name);
		return -ENOSYS;
	}
	memcpy(slot, &f, sizeof(f));
	return 0;
}

/* 0, -ENOSYS (no CUDA driver: capability unavailable) or -EIO. */
static inline int xdg_gpu_open(struct xdg_gpu *g, int ordinal, int fake)
{
	memset(g, 0, sizeof(*g));
	g->fake = fake;
	g->ordinal = ordinal;
	if (fake)
		return 0;
	g->lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!g->lib)
		return -ENOSYS;
	if (xdg_gpu_sym(g, &g->init, "cuInit") ||
	    xdg_gpu_sym(g, &g->driver_get_version, "cuDriverGetVersion") ||
	    xdg_gpu_sym(g, &g->device_get, "cuDeviceGet") ||
	    xdg_gpu_sym(g, &g->primary_retain, "cuDevicePrimaryCtxRetain") ||
	    xdg_gpu_sym(g, &g->primary_release, "cuDevicePrimaryCtxRelease_v2") ||
	    xdg_gpu_sym(g, &g->ctx_set, "cuCtxSetCurrent") ||
	    xdg_gpu_sym(g, &g->mem_alloc, "cuMemAlloc_v2") ||
	    xdg_gpu_sym(g, &g->mem_free, "cuMemFree_v2") ||
	    xdg_gpu_sym(g, &g->host_alloc, "cuMemHostAlloc") ||
	    xdg_gpu_sym(g, &g->host_free, "cuMemFreeHost") ||
	    xdg_gpu_sym(g, &g->htod, "cuMemcpyHtoD_v2") ||
	    xdg_gpu_sym(g, &g->dtoh, "cuMemcpyDtoH_v2") ||
	    xdg_gpu_sym(g, &g->stream_create, "cuStreamCreate") ||
	    xdg_gpu_sym(g, &g->stream_sync, "cuStreamSynchronize") ||
	    xdg_gpu_sym(g, &g->stream_destroy, "cuStreamDestroy_v2"))
		return -ENOSYS;
	if (g->init(0) || g->driver_get_version(&g->driver_version) ||
	    g->device_get(&g->dev, ordinal) || g->primary_retain(&g->ctx, g->dev) ||
	    g->ctx_set(g->ctx))
		return -EIO;
	return 0;
}

static inline void xdg_gpu_close(struct xdg_gpu *g)
{
	if (!g->fake && g->ctx)
		g->primary_release(g->dev);
	g->ctx = NULL;
}

static inline int xdg_gpu_alloc(struct xdg_gpu *g, uint64_t bytes, uint64_t *dptr)
{
	if (g->fake) {
		void *p = malloc(bytes);

		*dptr = (uint64_t)(uintptr_t)p;
		return p ? 0 : -ENOMEM;
	}
	return g->mem_alloc(dptr, bytes) ? -ENOMEM : 0;
}

static inline void xdg_gpu_free(struct xdg_gpu *g, uint64_t dptr)
{
	if (!dptr)
		return;
	if (g->fake)
		free((void *)(uintptr_t)dptr);
	else
		g->mem_free(dptr);
}

static inline int xdg_gpu_host_alloc(struct xdg_gpu *g, uint64_t bytes, void **p)
{
	if (g->fake) {
		*p = malloc(bytes);
		return *p ? 0 : -ENOMEM;
	}
	return g->host_alloc(p, bytes, 0) ? -ENOMEM : 0;
}

static inline void xdg_gpu_host_free(struct xdg_gpu *g, void *p)
{
	if (!p)
		return;
	if (g->fake)
		free(p);
	else
		g->host_free(p);
}

static inline int xdg_gpu_htod(struct xdg_gpu *g, uint64_t dst, const void *src, uint64_t n)
{
	if (g->fake) {
		memcpy((void *)(uintptr_t)dst, src, n);
		return 0;
	}
	return g->htod(dst, src, n) ? -EIO : 0;
}

static inline int xdg_gpu_dtoh(struct xdg_gpu *g, void *dst, uint64_t src, uint64_t n)
{
	if (g->fake) {
		memcpy(dst, (const void *)(uintptr_t)src, n);
		return 0;
	}
	return g->dtoh(dst, src, n) ? -EIO : 0;
}

/* Fill slot @slot (of @size bytes) of a device buffer with the slot image. */
static inline int xdg_gpu_seed(struct xdg_gpu *g, uint64_t dptr, uint64_t size, uint64_t seed,
			       uint64_t slot, void *scratch)
{
	xdg_fill(scratch, size, seed, slot);
	return xdg_gpu_htod(g, dptr + slot * size, scratch, size);
}

static inline const char *xdg_gpu_execution(const struct xdg_gpu *g)
{
	return g->fake ? "host-fake" : "cuda";
}

#endif /* XDEV_EVAL_XDG_GPU_H */

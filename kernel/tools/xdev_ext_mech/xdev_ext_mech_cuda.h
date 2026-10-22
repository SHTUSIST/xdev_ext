/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CUDA_H
#define XDEV_EXT_MECH_CUDA_H

/* Control-plane CUDA driver ABI only: no CUDA SDK or payload operations. */
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

struct xdev_ext_mech_cuda {
	uint64_t va;
	void *lib, *ctx, *restore_ctx;
	int device, retained, restore_pending;
	int (*init)(unsigned int);
	int (*device_count)(int *);
	int (*device_get)(int *, int);
	int (*device_bdf)(char *, int, int);
	int (*ctx_get)(void **);
	int (*ctx_set)(void *);
	int (*ctx_retain)(void **, int);
	int (*ctx_release)(int);
	int (*mem_alloc)(uint64_t *, size_t);
	int (*mem_free)(uint64_t);
};

static inline int xdev_ext_mech_cuda_result(int status, const char *operation)
{
	if (!status)
		return 0;
	fprintf(stderr, "xdev_ext_mech_cuda: %s failed: CUDA status %d\n",
		operation, status);
	return -EIO;
}

/* Accept PCI identity, never a CUDA ordinal or a prefix match. */
static inline int xdev_ext_mech_cuda_bdf_valid(const char *bdf)
{
	unsigned int domain, bus, slot, function;
	char tail;

	if (!bdf || strlen(bdf) != 12 || bdf[4] != ':' ||
	    bdf[7] != ':' || bdf[10] != '.')
		return 0;
	for (unsigned int i = 0; i < 12; i++) {
		char c = bdf[i];

		if (i == 4 || i == 7 || i == 10)
			continue;
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		      (c >= 'A' && c <= 'F')))
			return 0;
	}
	return sscanf(bdf, "%4x:%2x:%2x.%1x%c", &domain, &bus, &slot,
		      &function, &tail) == 4 && slot <= 31 && function <= 7;
}

/*
 * Call only after STOP/ring close and all stage fd closes.  cuMemFree is
 * not a DMA-quiescence proof: kernel RM duplicates/quarantine own that rule.
 * On an unsafe cleanup failure keep ownership so the caller can retry.
 */
static inline int xdev_ext_mech_cuda_close(struct xdev_ext_mech_cuda *cuda)
{
	void *previous = NULL;
	int ret, restore;

	if (!cuda)
		return -EINVAL;
	if (!cuda->lib)
		return 0;
	if (cuda->restore_pending) {
		ret = xdev_ext_mech_cuda_result(cuda->ctx_get(&previous),
					   "cuCtxGetCurrent(retry restore)");
		if (ret)
			return ret;
		/*
		 * Recover a context we left current after a failed restore.
		 * A caller-selected different current supersedes that old target;
		 * this close must preserve the context of its own invocation.
		 */
		if (previous == cuda->ctx) {
			ret = xdev_ext_mech_cuda_result(cuda->ctx_set(cuda->restore_ctx),
						   "cuCtxSetCurrent(retry restore)");
			if (ret)
				return ret;
		}
		cuda->restore_pending = 0;
	}
	if (cuda->va) {
		ret = xdev_ext_mech_cuda_result(cuda->ctx_get(&previous),
					   "cuCtxGetCurrent(close)");
		if (ret)
			return ret;
		ret = xdev_ext_mech_cuda_result(cuda->ctx_set(cuda->ctx),
					   "cuCtxSetCurrent(close)");
		if (!ret) {
			ret = xdev_ext_mech_cuda_result(cuda->mem_free(cuda->va),
						   "cuMemFree_v2");
			if (!ret)
				cuda->va = 0;
		}
		restore = xdev_ext_mech_cuda_result(cuda->ctx_set(previous),
					       "cuCtxSetCurrent(restore close)");
		if (restore) {
			cuda->restore_ctx = previous;
			cuda->restore_pending = 1;
		}
		if (ret || restore)
			return ret ? ret : restore;
	}
	if (cuda->retained) {
		ret = xdev_ext_mech_cuda_result(cuda->ctx_release(cuda->device),
					   "cuDevicePrimaryCtxRelease");
		if (ret)
			return ret;
		cuda->retained = 0;
	}
	ret = dlclose(cuda->lib);
	if (ret) {
		fprintf(stderr, "xdev_ext_mech_cuda: dlclose: %s\n", dlerror());
		return -EIO;
	}
	memset(cuda, 0, sizeof(*cuda));
	return 0;
}

static inline int xdev_ext_mech_cuda_open(struct xdev_ext_mech_cuda *cuda,
				     const char *bdf, uint64_t bytes)
{
	void *previous = NULL;
	int count = 0, matches = 0, ret, restore;

	if (!cuda || !xdev_ext_mech_cuda_bdf_valid(bdf) || !bytes || bytes > SIZE_MAX) {
		fprintf(stderr, "xdev_ext_mech_cuda: invalid BDF or allocation length\n");
		return -EINVAL;
	}
	if (cuda->lib || cuda->va || cuda->retained)
		return -EBUSY;
	cuda->lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!cuda->lib) {
		fprintf(stderr, "xdev_ext_mech_cuda: libcuda.so.1: %s\n", dlerror());
		return -ENOENT;
	}
#define XDEV_EXT_CUDA_LOAD(member, symbol) do { \
	*(void **)(&cuda->member) = dlsym(cuda->lib, symbol); \
	if (!cuda->member) { \
		fprintf(stderr, "xdev_ext_mech_cuda: missing %s: %s\n", symbol, dlerror()); \
		ret = -ENOSYS; \
		goto fail; \
	} \
} while (0)
	XDEV_EXT_CUDA_LOAD(init, "cuInit");
	XDEV_EXT_CUDA_LOAD(device_count, "cuDeviceGetCount");
	XDEV_EXT_CUDA_LOAD(device_get, "cuDeviceGet");
	XDEV_EXT_CUDA_LOAD(device_bdf, "cuDeviceGetPCIBusId");
	XDEV_EXT_CUDA_LOAD(ctx_get, "cuCtxGetCurrent");
	XDEV_EXT_CUDA_LOAD(ctx_set, "cuCtxSetCurrent");
	XDEV_EXT_CUDA_LOAD(ctx_retain, "cuDevicePrimaryCtxRetain");
	*(void **)(&cuda->ctx_release) = dlsym(cuda->lib,
					     "cuDevicePrimaryCtxRelease_v2");
	if (!cuda->ctx_release)
		XDEV_EXT_CUDA_LOAD(ctx_release, "cuDevicePrimaryCtxRelease");
	XDEV_EXT_CUDA_LOAD(mem_alloc, "cuMemAlloc_v2");
	XDEV_EXT_CUDA_LOAD(mem_free, "cuMemFree_v2");
#undef XDEV_EXT_CUDA_LOAD
	ret = xdev_ext_mech_cuda_result(cuda->init(0), "cuInit");
	if (!ret)
		ret = xdev_ext_mech_cuda_result(cuda->device_count(&count),
					   "cuDeviceGetCount");
	for (int i = 0; !ret && i < count; i++) {
		char found[32] = { 0 };
		int device;

		ret = xdev_ext_mech_cuda_result(cuda->device_get(&device, i),
					   "cuDeviceGet");
		if (!ret)
			ret = xdev_ext_mech_cuda_result(cuda->device_bdf(found,
						 sizeof(found), device),
						 "cuDeviceGetPCIBusId");
		if (!ret && memchr(found, 0, sizeof(found)) &&
		    !strcasecmp(found, bdf)) {
			cuda->device = device;
			matches++;
		}
	}
	if (ret)
		goto fail;
	if (matches != 1) {
		fprintf(stderr, "xdev_ext_mech_cuda: %d CUDA devices match BDF %s\n",
			matches, bdf);
		ret = -EXDEV;
		goto fail;
	}
	ret = xdev_ext_mech_cuda_result(cuda->ctx_get(&previous), "cuCtxGetCurrent");
	if (ret)
		goto fail;
	ret = xdev_ext_mech_cuda_result(cuda->ctx_retain(&cuda->ctx, cuda->device),
				   "cuDevicePrimaryCtxRetain");
	if (ret)
		goto fail;
	cuda->retained = 1;
	ret = xdev_ext_mech_cuda_result(cuda->ctx_set(cuda->ctx), "cuCtxSetCurrent");
	if (!ret)
		ret = xdev_ext_mech_cuda_result(cuda->mem_alloc(&cuda->va, (size_t)bytes),
					   "cuMemAlloc_v2");
	restore = xdev_ext_mech_cuda_result(cuda->ctx_set(previous),
				       "cuCtxSetCurrent(restore open)");
	if (restore) {
		cuda->restore_ctx = previous;
		cuda->restore_pending = 1;
	}
	if (!ret)
		ret = restore;
	if (!ret && !cuda->va) {
		fprintf(stderr, "xdev_ext_mech_cuda: cuMemAlloc_v2 returned a null address\n");
		ret = -EIO;
	}
	if (!ret)
		return 0;
fail:
	/* No session exists yet; reclaim every successfully acquired resource. */
	if (xdev_ext_mech_cuda_close(cuda))
		fprintf(stderr, "xdev_ext_mech_cuda: setup cleanup incomplete; retry close\n");
	return ret;
}

#endif /* XDEV_EXT_MECH_CUDA_H */

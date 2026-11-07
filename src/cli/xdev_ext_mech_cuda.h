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
#include <unistd.h>

/*
 * CUDA VMM Driver ABI (cuda.h CUmemAllocationProp, CUmemAccessDesc and the
 * enumerators used here), for xdev_ext_mech_cuda_open_vmm().
 */
struct xdev_ext_mech_cuda_mem_prop {
	int type;
	int requested_handle_types;
	struct { int type, id; } location;
	void *win32_handle_metadata;
	struct {
		unsigned char compression_type, gpu_direct_rdma_capable;
		unsigned short usage;
		unsigned char reserved[4];
	} alloc_flags;
};
struct xdev_ext_mech_cuda_access {
	struct { int type, id; } location;
	int flags;
};
#define XDEV_EXT_MECH_CUDA_ALLOCATION_PINNED	1 /* CU_MEM_ALLOCATION_TYPE_PINNED */
#define XDEV_EXT_MECH_CUDA_HANDLE_POSIX_FD	1 /* CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR */
#define XDEV_EXT_MECH_CUDA_LOCATION_DEVICE	1 /* CU_MEM_LOCATION_TYPE_DEVICE */
#define XDEV_EXT_MECH_CUDA_ACCESS_READWRITE	3 /* CU_MEM_ACCESS_FLAGS_PROT_READWRITE */
#define XDEV_EXT_MECH_CUDA_GRANULARITY_MINIMUM	0 /* CU_MEM_ALLOC_GRANULARITY_MINIMUM */

struct xdev_ext_mech_cuda {
	uint64_t va;
	void *lib, *ctx, *restore_ctx;
	int device, retained, restore_pending;
	/*
	 * VMM allocation (xdev_ext_mech_cuda_open_vmm): a cuMemCreate handle,
	 * its POSIX file descriptor export (export_fd, valid while exported)
	 * and its mapping at va.  A GPU without GPUDirect RDMA cannot resolve
	 * a cuMemAlloc address for a CE window, but its CE stage fd can carry
	 * this export (xdev_ext_nv_ce_attach_memory()).
	 */
	int vmm, created, exported, export_fd, reserved, mapped;
	uint64_t vmm_handle, vmm_bytes;
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
	int (*granularity)(size_t *, const struct xdev_ext_mech_cuda_mem_prop *, int);
	int (*mem_create)(uint64_t *, size_t, const struct xdev_ext_mech_cuda_mem_prop *,
			  unsigned long long);
	int (*mem_export)(void *, uint64_t, int, unsigned long long);
	int (*address_reserve)(uint64_t *, size_t, size_t, uint64_t, unsigned long long);
	int (*mem_map)(uint64_t, size_t, size_t, uint64_t, unsigned long long);
	int (*set_access)(uint64_t, size_t, const struct xdev_ext_mech_cuda_access *, size_t);
	int (*mem_unmap)(uint64_t, size_t);
	int (*address_free)(uint64_t, size_t);
	int (*mem_release)(uint64_t);
	/* Optional: CE chain device-window oracle (fill and read back). */
	int (*memset_d8)(uint64_t, unsigned char, size_t);
	int (*memcpy_dtoh)(void *, uint64_t, size_t);
	int (*ctx_sync)(void);
};

_Static_assert(sizeof(struct xdev_ext_mech_cuda_access) == 12,
	       "CUmemAccessDesc ABI size changed");
_Static_assert(sizeof(void *) != 8 || sizeof(struct xdev_ext_mech_cuda_mem_prop) == 32,
	       "CUmemAllocationProp ABI size changed");

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
	if (cuda->vmm && (cuda->mapped || cuda->reserved || cuda->created)) {
		ret = xdev_ext_mech_cuda_result(cuda->ctx_get(&previous),
					   "cuCtxGetCurrent(close)");
		if (ret)
			return ret;
		ret = xdev_ext_mech_cuda_result(cuda->ctx_set(cuda->ctx),
					   "cuCtxSetCurrent(close)");
		/* Unmap, then the VA range, then the physical allocation. */
		if (!ret && cuda->mapped) {
			ret = xdev_ext_mech_cuda_result(cuda->mem_unmap(cuda->va,
						 (size_t)cuda->vmm_bytes), "cuMemUnmap");
			if (!ret)
				cuda->mapped = 0;
		}
		if (!ret && cuda->reserved) {
			ret = xdev_ext_mech_cuda_result(cuda->address_free(cuda->va,
						 (size_t)cuda->vmm_bytes), "cuMemAddressFree");
			if (!ret) {
				cuda->reserved = 0;
				cuda->va = 0;
			}
		}
		if (!ret && cuda->created) {
			ret = xdev_ext_mech_cuda_result(cuda->mem_release(cuda->vmm_handle),
						   "cuMemRelease");
			if (!ret) {
				cuda->created = 0;
				cuda->vmm_handle = 0;
			}
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
	/* The kernel holds its own reference on an attached export. */
	if (cuda->exported) {
		close(cuda->export_fd);
		cuda->exported = 0;
		cuda->export_fd = -1;
	}
	if (!cuda->vmm && cuda->va) {
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

/*
 * VMM allocation on the current (retained) context: bytes rounded up to the
 * allocation granularity, created with a POSIX file descriptor export, then
 * reserved, mapped and made device read/write at cuda->va.  Each acquired
 * resource is recorded at once, so xdev_ext_mech_cuda_close() releases
 * exactly what exists.
 */
static inline int xdev_ext_mech_cuda_vmm_alloc(struct xdev_ext_mech_cuda *cuda,
					  uint64_t bytes)
{
	struct xdev_ext_mech_cuda_mem_prop prop = {
		.type = XDEV_EXT_MECH_CUDA_ALLOCATION_PINNED,
		.requested_handle_types = XDEV_EXT_MECH_CUDA_HANDLE_POSIX_FD,
		.location = { XDEV_EXT_MECH_CUDA_LOCATION_DEVICE, cuda->device },
	};
	struct xdev_ext_mech_cuda_access access = {
		.location = { XDEV_EXT_MECH_CUDA_LOCATION_DEVICE, cuda->device },
		.flags = XDEV_EXT_MECH_CUDA_ACCESS_READWRITE,
	};
	size_t granularity = 0;
	uint64_t handle = 0, va = 0;
	int fd = -1, ret;

	ret = xdev_ext_mech_cuda_result(cuda->granularity(&granularity, &prop,
					 XDEV_EXT_MECH_CUDA_GRANULARITY_MINIMUM),
				   "cuMemGetAllocationGranularity");
	if (ret)
		return ret;
	if (!granularity || bytes > SIZE_MAX - (granularity - 1)) {
		fprintf(stderr, "xdev_ext_mech_cuda: no usable VMM granularity (%zu)\n",
			granularity);
		return -EINVAL;
	}
	cuda->vmm_bytes = (bytes + granularity - 1) / granularity * granularity;
	ret = xdev_ext_mech_cuda_result(cuda->mem_create(&handle,
					 (size_t)cuda->vmm_bytes, &prop, 0), "cuMemCreate");
	if (ret)
		return ret;
	cuda->vmm_handle = handle;
	cuda->created = 1;
	ret = xdev_ext_mech_cuda_result(cuda->mem_export(&fd, handle,
					 XDEV_EXT_MECH_CUDA_HANDLE_POSIX_FD, 0),
				   "cuMemExportToShareableHandle");
	if (ret)
		return ret;
	if (fd < 0) {
		fprintf(stderr, "xdev_ext_mech_cuda: export returned no file descriptor\n");
		return -EIO;
	}
	cuda->export_fd = fd;
	cuda->exported = 1;
	ret = xdev_ext_mech_cuda_result(cuda->address_reserve(&va,
					 (size_t)cuda->vmm_bytes, 0, 0, 0), "cuMemAddressReserve");
	if (ret)
		return ret;
	if (!va) {
		fprintf(stderr, "xdev_ext_mech_cuda: cuMemAddressReserve returned a null address\n");
		return -EIO;
	}
	cuda->va = va;
	cuda->reserved = 1;
	ret = xdev_ext_mech_cuda_result(cuda->mem_map(va, (size_t)cuda->vmm_bytes, 0,
					 handle, 0), "cuMemMap");
	if (ret)
		return ret;
	cuda->mapped = 1;
	return xdev_ext_mech_cuda_result(cuda->set_access(va, (size_t)cuda->vmm_bytes,
					 &access, 1), "cuMemSetAccess");
}

static inline int xdev_ext_mech_cuda_open_alloc(struct xdev_ext_mech_cuda *cuda,
					   const char *bdf, uint64_t bytes, int vmm)
{
	void *previous = NULL;
	int count = 0, matches = 0, ret, restore;

	if (!cuda || !xdev_ext_mech_cuda_bdf_valid(bdf) || !bytes || bytes > SIZE_MAX) {
		fprintf(stderr, "xdev_ext_mech_cuda: invalid BDF or allocation length\n");
		return -EINVAL;
	}
	if (cuda->lib || cuda->va || cuda->retained || cuda->created || cuda->exported)
		return -EBUSY;
	cuda->vmm = vmm;
	cuda->export_fd = -1;
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
	if (vmm) {
		XDEV_EXT_CUDA_LOAD(granularity, "cuMemGetAllocationGranularity");
		XDEV_EXT_CUDA_LOAD(mem_create, "cuMemCreate");
		XDEV_EXT_CUDA_LOAD(mem_export, "cuMemExportToShareableHandle");
		XDEV_EXT_CUDA_LOAD(address_reserve, "cuMemAddressReserve");
		XDEV_EXT_CUDA_LOAD(mem_map, "cuMemMap");
		XDEV_EXT_CUDA_LOAD(set_access, "cuMemSetAccess");
		XDEV_EXT_CUDA_LOAD(mem_unmap, "cuMemUnmap");
		XDEV_EXT_CUDA_LOAD(address_free, "cuMemAddressFree");
		XDEV_EXT_CUDA_LOAD(mem_release, "cuMemRelease");
	} else {
		XDEV_EXT_CUDA_LOAD(mem_alloc, "cuMemAlloc_v2");
		XDEV_EXT_CUDA_LOAD(mem_free, "cuMemFree_v2");
	}
#undef XDEV_EXT_CUDA_LOAD
	*(void **)(&cuda->memset_d8) = dlsym(cuda->lib, "cuMemsetD8_v2");
	*(void **)(&cuda->memcpy_dtoh) = dlsym(cuda->lib, "cuMemcpyDtoH_v2");
	*(void **)(&cuda->ctx_sync) = dlsym(cuda->lib, "cuCtxSynchronize");
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
		ret = vmm ? xdev_ext_mech_cuda_vmm_alloc(cuda, bytes) :
			xdev_ext_mech_cuda_result(cuda->mem_alloc(&cuda->va, (size_t)bytes),
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

/* cuMemAlloc: a GPU with GPUDirect RDMA resolves its address for a CE window. */
static inline int xdev_ext_mech_cuda_open(struct xdev_ext_mech_cuda *cuda,
				     const char *bdf, uint64_t bytes)
{
	return xdev_ext_mech_cuda_open_alloc(cuda, bdf, bytes, 0);
}

/* VMM with a POSIX file descriptor export; see struct xdev_ext_mech_cuda. */
static inline int xdev_ext_mech_cuda_open_vmm(struct xdev_ext_mech_cuda *cuda,
					 const char *bdf, uint64_t bytes)
{
	return xdev_ext_mech_cuda_open_alloc(cuda, bdf, bytes, 1);
}

/*
 * Fill the allocation with @value (@out NULL) or copy it to @out, in its
 * primary context, restoring the caller's current context.  -ENOSYS when
 * the driver library lacks the optional entry points.
 */
static inline int xdev_ext_mech_cuda_window(struct xdev_ext_mech_cuda *cuda, void *out,
					    unsigned char value, uint64_t bytes)
{
	void *previous = NULL;
	int ret, restore;

	if (!cuda || !cuda->lib || !cuda->va || !bytes || bytes > SIZE_MAX)
		return -EINVAL;
	if (!cuda->memset_d8 || !cuda->memcpy_dtoh || !cuda->ctx_sync)
		return -ENOSYS;
	ret = xdev_ext_mech_cuda_result(cuda->ctx_get(&previous), "cuCtxGetCurrent(window)");
	if (ret)
		return ret;
	ret = xdev_ext_mech_cuda_result(cuda->ctx_set(cuda->ctx), "cuCtxSetCurrent(window)");
	if (!ret)
		ret = out ? xdev_ext_mech_cuda_result(cuda->memcpy_dtoh(out, cuda->va, (size_t)bytes),
						      "cuMemcpyDtoH_v2") :
			    xdev_ext_mech_cuda_result(cuda->memset_d8(cuda->va, value, (size_t)bytes),
						      "cuMemsetD8_v2");
	if (!ret)
		ret = xdev_ext_mech_cuda_result(cuda->ctx_sync(), "cuCtxSynchronize");
	restore = xdev_ext_mech_cuda_result(cuda->ctx_set(previous), "cuCtxSetCurrent(window restore)");
	return ret ? ret : restore;
}

#endif /* XDEV_EXT_MECH_CUDA_H */

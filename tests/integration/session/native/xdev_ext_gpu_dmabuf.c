// SPDX-License-Identifier: GPL-2.0
/*
 * Export real VRAM as a DMA-BUF and hand it to a PEER program.
 *
 *   xdev_ext_gpu_dmabuf --bdf PCI_BDF --bytes N --expect SOURCE_FILE
 *       --group-bytes G --frame-bytes F -- PROGRAM ARG... ('{fd}' -> fd)
 *   xdev_ext_gpu_dmabuf --caps --bdf PCI_BDF
 *
 * --caps prints what CUDA reports for that GPU: GPUDirect RDMA and dma_buf
 * device support, whether a fresh 64 KiB cuMemAlloc block can be used
 * with the GPUDirect RDMA API (nvidia_p2p_get_pages*), then frees it, and
 * whether VMM allocations with POSIX file descriptor exports exist (the CE
 * window of a GPU without GPUDirect RDMA).
 *
 * Allocates N bytes of VRAM on the CUDA device with that PCI address, exports
 * the whole range with cuMemGetHandleForAddressRange(DMA_BUF_FD), registers
 * the export with /dev/xdev_ext_peer (XDEV_EXT_PEER_REGISTER_F_DMABUF) and
 * runs PROGRAM with the allocation fd.  Afterwards it copies the VRAM back
 * and reports whether the last G-byte group of SOURCE_FILE starts at an F-byte
 * frame boundary: evidence that the NVMe READ landed in VRAM.  The VRAM is
 * released only after every fd is closed.  Correctness only, no timing.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/xdev_ext_peer.h"

typedef int CUresult;
typedef int CUdevice;
typedef void *CUcontext;
typedef unsigned long long CUdeviceptr;
#define CU_DEVICE_ATTRIBUTE_VIRTUAL_MEMORY_MANAGEMENT_SUPPORTED 102
#define CU_DEVICE_ATTRIBUTE_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED 103
#define CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED 116
#define CU_DEVICE_ATTRIBUTE_DMA_BUF_SUPPORTED 124
#define CU_POINTER_ATTRIBUTE_IS_GPU_DIRECT_RDMA_CAPABLE 15
#define CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD 1

static struct {
	CUresult (*init)(unsigned int);
	CUresult (*count)(int *);
	CUresult (*get)(CUdevice *, int);
	CUresult (*bus_id)(char *, int, CUdevice);
	CUresult (*attribute)(int *, int, CUdevice);
	CUresult (*retain)(CUcontext *, CUdevice);
	CUresult (*release)(CUdevice);
	CUresult (*set)(CUcontext);
	CUresult (*alloc)(CUdeviceptr *, size_t);
	CUresult (*free)(CUdeviceptr);
	CUresult (*memset)(CUdeviceptr, unsigned char, size_t);
	CUresult (*to_host)(void *, CUdeviceptr, size_t);
	CUresult (*sync)(void);
	CUresult (*handle)(void *, CUdeviceptr, size_t, int, unsigned long long);
	CUresult (*pointer_attribute)(void *, int, CUdeviceptr);
} cu;

static int load(void)
{
	void *lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!lib) {
		fprintf(stderr, "dlopen libcuda.so.1: %s\n", dlerror());
		return -1;
	}
#define LOAD(member, name) do { \
		*(void **)&cu.member = dlsym(lib, name); \
		if (!cu.member) { fprintf(stderr, "missing %s\n", name); return -1; } \
	} while (0)
	LOAD(init, "cuInit");
	LOAD(count, "cuDeviceGetCount");
	LOAD(get, "cuDeviceGet");
	LOAD(bus_id, "cuDeviceGetPCIBusId");
	LOAD(attribute, "cuDeviceGetAttribute");
	LOAD(retain, "cuDevicePrimaryCtxRetain");
	LOAD(release, "cuDevicePrimaryCtxRelease_v2");
	LOAD(set, "cuCtxSetCurrent");
	LOAD(alloc, "cuMemAlloc_v2");
	LOAD(free, "cuMemFree_v2");
	LOAD(memset, "cuMemsetD8_v2");
	LOAD(to_host, "cuMemcpyDtoH_v2");
	LOAD(sync, "cuCtxSynchronize");
	LOAD(handle, "cuMemGetHandleForAddressRange");
	LOAD(pointer_attribute, "cuPointerGetAttribute");
#undef LOAD
	return 0;
}

#define CHECK(call, what) do { CUresult r_ = (call); \
	if (r_) { fprintf(stderr, "%s failed: CUDA status %d\n", what, r_); goto out; } } while (0)

/* The CUDA device whose PCI bus id is bdf, or -1; text gets that id. */
static CUdevice find_device(const char *bdf, char *text, int size)
{
	int n, i;

	if (cu.init(0) || cu.count(&n))
		return -1;
	for (i = 0; i < n; i++) {
		CUdevice candidate;

		if (cu.get(&candidate, i) || cu.bus_id(text, size, candidate))
			return -1;
		if (!strcasecmp(text, bdf))
			return candidate;
	}
	return -1;
}

static int caps(const char *bdf)
{
	CUdeviceptr pointer = 0;
	CUcontext context = NULL;
	CUdevice device;
	int rdma = -1, dma_buf = -1, pointer_rdma = -1, vmm = -1, posix_fd = -1, ret = 1;
	char text[32];

	if (load())
		return 1;
	device = find_device(bdf, text, sizeof(text));
	if (device < 0) {
		fprintf(stderr, "no CUDA device at %s\n", bdf);
		return 1;
	}
	CHECK(cu.attribute(&rdma, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED, device),
	      "cuDeviceGetAttribute(GPU_DIRECT_RDMA_SUPPORTED)");
	CHECK(cu.attribute(&dma_buf, CU_DEVICE_ATTRIBUTE_DMA_BUF_SUPPORTED, device),
	      "cuDeviceGetAttribute(DMA_BUF_SUPPORTED)");
	CHECK(cu.attribute(&vmm, CU_DEVICE_ATTRIBUTE_VIRTUAL_MEMORY_MANAGEMENT_SUPPORTED, device),
	      "cuDeviceGetAttribute(VIRTUAL_MEMORY_MANAGEMENT_SUPPORTED)");
	CHECK(cu.attribute(&posix_fd, CU_DEVICE_ATTRIBUTE_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED,
			   device), "cuDeviceGetAttribute(HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED)");
	CHECK(cu.retain(&context, device), "cuDevicePrimaryCtxRetain");
	CHECK(cu.set(context), "cuCtxSetCurrent");
	CHECK(cu.alloc(&pointer, 65536), "cuMemAlloc");
	/* A refusal leaves -1: never evidence that the API is unsupported. */
	if (cu.pointer_attribute(&pointer_rdma, CU_POINTER_ATTRIBUTE_IS_GPU_DIRECT_RDMA_CAPABLE,
				 pointer))
		pointer_rdma = -1;
	printf("XDEV_EXT_GPU_CAPS bdf=%s gpu_direct_rdma=%d dma_buf=%d pointer_rdma=%d "
	       "vmm=%d posix_fd=%d\n", text, rdma, dma_buf, pointer_rdma, vmm, posix_fd);
	ret = 0;
out:
	fflush(stdout);
	if (pointer && cu.free(pointer)) {
		fprintf(stderr, "cuMemFree failed\n");
		ret = 1;
	}
	if (context)
		cu.release(device);
	return ret;
}

static int read_file(const char *path, unsigned char **data, size_t *size)
{
	FILE *file = fopen(path, "rb");
	long length;

	if (!file || fseek(file, 0, SEEK_END) || (length = ftell(file)) <= 0 ||
	    fseek(file, 0, SEEK_SET))
		return -1;
	*data = malloc(length);
	*size = length;
	if (!*data || fread(*data, 1, length, file) != (size_t)length)
		return -1;
	fclose(file);
	return 0;
}

int main(int argc, char **argv)
{
	const char *bdf = NULL, *expect = NULL;
	unsigned long long bytes = 0, group = 0, frame = 0;
	unsigned char *source = NULL, *vram = NULL;
	size_t source_size = 0;
	CUdeviceptr pointer = 0;
	CUcontext context = NULL;
	CUdevice device = -1;
	int export_fd = -1, allocation = -1, control = -1, ret = 1, i, n, program = -1;
	char text[32], fd_text[16];

	if (argc == 4 && !strcmp(argv[1], "--caps") && !strcmp(argv[2], "--bdf"))
		return caps(argv[3]);
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--") && i + 1 < argc) { program = i + 1; break; }
		if (i + 1 >= argc) return 2;
		if (!strcmp(argv[i], "--bdf")) bdf = argv[++i];
		else if (!strcmp(argv[i], "--bytes")) bytes = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--expect")) expect = argv[++i];
		else if (!strcmp(argv[i], "--group-bytes")) group = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--frame-bytes")) frame = strtoull(argv[++i], NULL, 0);
		else return 2;
	}
	if (!bdf || !expect || !bytes || !group || !frame || program < 0 || bytes % frame ||
	    group > frame || read_file(expect, &source, &source_size) || source_size < group ||
	    source_size % group) {
		fprintf(stderr, "usage: see source header\n");
		return 2;
	}
	if (load())
		return 1;
	CHECK(cu.init(0), "cuInit");
	CHECK(cu.count(&n), "cuDeviceGetCount");
	for (i = 0; i < n; i++) {
		CUdevice candidate;
		CHECK(cu.get(&candidate, i), "cuDeviceGet");
		CHECK(cu.bus_id(text, sizeof(text), candidate), "cuDeviceGetPCIBusId");
		if (!strcasecmp(text, bdf)) { device = candidate; break; }
	}
	if (device < 0) {
		fprintf(stderr, "no CUDA device at %s\n", bdf);
		goto out;
	}
	CHECK(cu.attribute(&n, CU_DEVICE_ATTRIBUTE_DMA_BUF_SUPPORTED, device), "cuDeviceGetAttribute");
	printf("XDEV_EXT_GPU_DMABUF device=%s dma_buf_supported=%d\n", text, n);
	if (!n)
		goto out;
	CHECK(cu.retain(&context, device), "cuDevicePrimaryCtxRetain");
	CHECK(cu.set(context), "cuCtxSetCurrent");
	CHECK(cu.alloc(&pointer, bytes), "cuMemAlloc");
	/* A sentinel that no source group equals. */
	CHECK(cu.memset(pointer, 0xa5, bytes), "cuMemsetD8");
	CHECK(cu.sync(), "cuCtxSynchronize");
	CHECK(cu.handle(&export_fd, pointer, bytes, CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD, 0),
	      "cuMemGetHandleForAddressRange(DMA_BUF_FD)");
	control = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC);
	if (control < 0) {
		perror("open /dev/xdev_ext_peer");
		goto out;
	}
	{
		struct xdev_ext_peer_register reg = {
			.gpu_fd = export_fd, .flags = XDEV_EXT_PEER_REGISTER_F_DMABUF,
			.gpu_va = 0, .len = bytes,
		};
		allocation = ioctl(control, XDEV_EXT_PEER_REGISTER, &reg);
		if (allocation < 0) {
			fprintf(stderr, "REGISTER F_DMABUF: %s (%d)\n", strerror(errno), -errno);
			goto out;
		}
		printf("XDEV_EXT_GPU_DMABUF registered bytes=%llu generation=%llu\n",
		       bytes, (unsigned long long)reg.generation);
	}
	/* The program inherits only the allocation fd. */
	if (fcntl(allocation, F_SETFD, 0)) {
		perror("fcntl");
		goto out;
	}
	snprintf(fd_text, sizeof(fd_text), "%d", allocation);
	for (i = program; i < argc; i++)
		if (!strcmp(argv[i], "{fd}"))
			argv[i] = fd_text;
	fflush(stdout);
	{
		int status;
		pid_t child = fork();

		if (child < 0)
			goto out;
		if (!child) {
			execv(argv[program], argv + program);
			_exit(127);
		}
		if (waitpid(child, &status, 0) != child)
			goto out;
		ret = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
		printf("XDEV_EXT_GPU_DMABUF program_exit=%d\n", ret);
	}
	{
		int program_ret = ret, found = 0;
		const unsigned char *last = source + source_size - group;
		unsigned long long offset;

		ret = 1;
		vram = malloc(bytes);
		if (!vram)
			goto out;
		CHECK(cu.to_host(vram, pointer, bytes), "cuMemcpyDtoH");
		for (offset = 0; offset + group <= bytes; offset += frame)
			found |= !memcmp(vram + offset, last, group);
		printf("XDEV_EXT_GPU_DMABUF vram_holds_last_group=%s\n", found ? "yes" : "no");
		ret = program_ret ? program_ret : !found;
	}
out:
	fflush(stdout);
	if (allocation >= 0)
		close(allocation);
	if (control >= 0)
		close(control);
	if (export_fd >= 0)
		close(export_fd);
	if (pointer && cu.free(pointer))
		fprintf(stderr, "cuMemFree failed\n");
	if (context)
		cu.release(device);
	free(vram);
	free(source);
	return ret;
}

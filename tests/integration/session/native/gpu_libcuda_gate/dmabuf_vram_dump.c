// SPDX-License-Identifier: GPL-2.0
/*
 * Diagnostic variant of xdev_ext_gpu_dmabuf: export a cuMemAlloc buffer
 * (filled with the sentinel byte 0xa5) as DMA-BUF, register it as a PEER
 * allocation, run PROGRAM with '{fd}' replaced by the allocation fd, then copy
 * the whole buffer back with cuMemcpyDtoH and report where, if anywhere, each
 * source group appears (any 512-byte offset), how many bytes differ from the
 * sentinel, and the first such offset.
 *
 *   dmabuf_vram_dump --bdf BDF --bytes N --expect SOURCE --group-bytes G -- PROGRAM ARG...
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/xdev_ext_peer.h>

typedef int CUresult;
typedef int CUdevice;
typedef void *CUcontext;
typedef unsigned long long CUdeviceptr;
#define CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD 1

static struct {
	CUresult (*init)(unsigned int);
	CUresult (*by_bus)(CUdevice *, const char *);
	CUresult (*retain)(CUcontext *, CUdevice);
	CUresult (*set)(CUcontext);
	CUresult (*alloc)(CUdeviceptr *, size_t);
	CUresult (*memset)(CUdeviceptr, unsigned char, size_t);
	CUresult (*to_host)(void *, CUdeviceptr, size_t);
	CUresult (*sync)(void);
	CUresult (*handle)(void *, CUdeviceptr, size_t, int, unsigned long long);
} cu;

#define CHECK(call, what) do { CUresult r_ = (call); \
	if (r_) { fprintf(stderr, "%s failed: CUDA status %d\n", what, r_); return 1; } } while (0)

int main(int argc, char **argv)
{
	const char *bdf = NULL, *expect = NULL;
	unsigned long long bytes = 0, group = 0, off, differ = 0, first = ~0ULL;
	unsigned char *source, *vram;
	CUdeviceptr pointer;
	CUcontext context;
	CUdevice device;
	int i, program = -1, export_fd = -1, control, allocation, status;
	long source_size;
	char fd_text[16];
	FILE *f;
	void *lib;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--") && i + 1 < argc) { program = i + 1; break; }
		if (i + 1 >= argc) return 2;
		if (!strcmp(argv[i], "--bdf")) bdf = argv[++i];
		else if (!strcmp(argv[i], "--bytes")) bytes = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--expect")) expect = argv[++i];
		else if (!strcmp(argv[i], "--group-bytes")) group = strtoull(argv[++i], NULL, 0);
		else return 2;
	}
	if (!bdf || !expect || !bytes || !group || program < 0)
		return 2;
	f = fopen(expect, "rb");
	if (!f || fseek(f, 0, SEEK_END) || (source_size = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET))
		return 2;
	source = malloc(source_size);
	vram = malloc(bytes);
	if (!source || !vram || fread(source, 1, source_size, f) != (size_t)source_size)
		return 2;
	fclose(f);
	lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!lib)
		return 1;
#define LOAD(m, n) do { *(void **)&cu.m = dlsym(lib, n); if (!cu.m) return 1; } while (0)
	LOAD(init, "cuInit"); LOAD(by_bus, "cuDeviceGetByPCIBusId");
	LOAD(retain, "cuDevicePrimaryCtxRetain"); LOAD(set, "cuCtxSetCurrent");
	LOAD(alloc, "cuMemAlloc_v2"); LOAD(memset, "cuMemsetD8_v2");
	LOAD(to_host, "cuMemcpyDtoH_v2"); LOAD(sync, "cuCtxSynchronize");
	LOAD(handle, "cuMemGetHandleForAddressRange");
	CHECK(cu.init(0), "cuInit");
	CHECK(cu.by_bus(&device, bdf), "cuDeviceGetByPCIBusId");
	CHECK(cu.retain(&context, device), "cuDevicePrimaryCtxRetain");
	CHECK(cu.set(context), "cuCtxSetCurrent");
	CHECK(cu.alloc(&pointer, bytes), "cuMemAlloc");
	CHECK(cu.memset(pointer, 0xa5, bytes), "cuMemsetD8");
	CHECK(cu.sync(), "cuCtxSynchronize");
	CHECK(cu.handle(&export_fd, pointer, bytes, CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD, 0),
	      "cuMemGetHandleForAddressRange(DMA_BUF_FD)");
	control = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC);
	{
		struct xdev_ext_peer_register reg = {
			.gpu_fd = export_fd, .flags = XDEV_EXT_PEER_REGISTER_F_DMABUF, .len = bytes,
		};
		allocation = control < 0 ? -1 : ioctl(control, XDEV_EXT_PEER_REGISTER, &reg);
		if (allocation < 0) {
			perror("REGISTER F_DMABUF");
			return 1;
		}
		printf("DUMP registered va=0x%llx bytes=%llu generation=%llu\n", pointer, bytes,
		       (unsigned long long)reg.generation);
	}
	if (fcntl(allocation, F_SETFD, 0))
		return 1;
	snprintf(fd_text, sizeof(fd_text), "%d", allocation);
	for (i = program; i < argc; i++)
		if (!strcmp(argv[i], "{fd}"))
			argv[i] = fd_text;
	fflush(stdout);
	if (!fork()) {
		execv(argv[program], argv + program);
		_exit(127);
	}
	wait(&status);
	printf("DUMP program_exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	CHECK(cu.sync(), "cuCtxSynchronize");
	CHECK(cu.to_host(vram, pointer, bytes), "cuMemcpyDtoH");
	for (off = 0; off < bytes; off++)
		if (vram[off] != 0xa5) {
			differ++;
			if (first == ~0ULL)
				first = off;
		}
	printf("DUMP non_sentinel_bytes=%llu first_non_sentinel=%lld\n", differ,
	       first == ~0ULL ? -1LL : (long long)first);
	for (long g = 0; g + (long)group <= source_size; g += group) {
		int hits = 0;

		printf("DUMP group_offset=%ld found_at=", g);
		for (off = 0; off + group <= bytes; off += 512)
			if (!memcmp(vram + off, source + g, group)) {
				printf("%s0x%llx", hits++ ? "," : "", off);
				if (hits == 8)
					break;
			}
		printf("%s\n", hits ? "" : "none");
	}
	printf("DUMP head=");
	for (off = 0; off < 16; off++)
		printf("%02x", vram[off]);
	printf("\n");
	return 0;
}

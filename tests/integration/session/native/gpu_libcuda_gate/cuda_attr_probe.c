// SPDX-License-Identifier: GPL-2.0
/*
 * Print the CUDA device attributes that gate GPUDirect RDMA and DMA-BUF
 * export, together with the path of the libcuda that the dynamic loader
 * actually resolved for "libcuda.so.1".  LD_LIBRARY_PATH selects the library;
 * the path line is the evidence for which copy answered.
 *
 *   cuda_attr_probe PCI_BDF
 *
 * One line: XDEV_EXT_CUDA_ATTRS lib=PATH bdf=BDF a110=N a116=N a124=N ...
 * Exit status 0 only when every query returned CUDA_SUCCESS.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>

typedef int CUresult;
typedef int CUdevice;

#define CU_DEVICE_ATTRIBUTE_VIRTUAL_MEMORY_MANAGEMENT_SUPPORTED 102
#define CU_DEVICE_ATTRIBUTE_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED 103
#define CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_WITH_CUDA_VMM_SUPPORTED 110
#define CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED 116
#define CU_DEVICE_ATTRIBUTE_DMA_BUF_SUPPORTED 124

int main(int argc, char **argv)
{
	static const int attrs[] = { 110, 116, 124, 102, 103 };
	CUresult (*init)(unsigned int);
	CUresult (*by_bus)(CUdevice *, const char *);
	CUresult (*attribute)(int *, int, CUdevice);
	CUresult (*version)(int *);
	struct link_map *map = NULL;
	int driver = 0, value, failed = 0;
	CUdevice device;
	CUresult r;
	void *lib;

	if (argc != 2) {
		fprintf(stderr, "usage: %s PCI_BDF\n", argv[0]);
		return 2;
	}
	lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!lib) {
		fprintf(stderr, "dlopen libcuda.so.1: %s\n", dlerror());
		return 1;
	}
	if (dlinfo(lib, RTLD_DI_LINKMAP, &map) || !map) {
		fprintf(stderr, "dlinfo: %s\n", dlerror());
		return 1;
	}
	init = (CUresult (*)(unsigned int))dlsym(lib, "cuInit");
	by_bus = (CUresult (*)(CUdevice *, const char *))dlsym(lib, "cuDeviceGetByPCIBusId");
	attribute = (CUresult (*)(int *, int, CUdevice))dlsym(lib, "cuDeviceGetAttribute");
	version = (CUresult (*)(int *))dlsym(lib, "cuDriverGetVersion");
	if (!init || !by_bus || !attribute || !version) {
		fprintf(stderr, "dlsym: missing CUDA entry point\n");
		return 1;
	}
	r = init(0);
	if (r) {
		fprintf(stderr, "cuInit: %d\n", r);
		return 1;
	}
	r = by_bus(&device, argv[1]);
	if (r) {
		fprintf(stderr, "cuDeviceGetByPCIBusId(%s): %d\n", argv[1], r);
		return 1;
	}
	if (version(&driver))
		driver = -1;
	printf("XDEV_EXT_CUDA_ATTRS lib=%s bdf=%s driver=%d", map->l_name, argv[1], driver);
	for (unsigned int i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
		r = attribute(&value, attrs[i], device);
		if (r) {
			printf(" a%d=err%d", attrs[i], r);
			failed = 1;
		} else {
			printf(" a%d=%d", attrs[i], value);
		}
	}
	printf("\n");
	return failed;
}

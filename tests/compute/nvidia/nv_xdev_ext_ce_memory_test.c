// SPDX-License-Identifier: MIT
/*
 * A CE stage fd may carry one CUDA allocation the caller exported
 * (NV_ESC_XDEV_EXT_CE_ATTACH_MEMORY): the caller names it by the GPU VA
 * range it mapped, and a CE window [start, start + len) must lie inside
 * that range.  The window's offset in the allocation is start - gpu_va.
 * Pure arithmetic of nv-xdev_ext-ce-memory.h; no kernel, RM or GPU.
 */
#include <stdint.h>
#include <stdio.h>

typedef uint32_t NvU32;
typedef uint64_t NvU64;
typedef uint8_t NvBool;
#define NV_TRUE ((NvBool)1)
#define NV_FALSE ((NvBool)0)

#include "../kernel-open/nvidia/nv-xdev_ext-ce-memory.h"

static unsigned int failures;
#define CHECK(c) do { if (!(c)) { failures++; printf("FAIL %s:%d: %s\n", __func__, __LINE__, #c); } } while (0)

static void attach_arguments(void)
{
	const NvU64 va = 0x7a4879200000ULL;

	CHECK(nv_xdev_ext_ce_memory_args_ok(va, 2 << 20, 0, 0));
	CHECK(nv_xdev_ext_ce_memory_args_ok(UINT64_MAX - 4095, 4096, 0, 0));
	/* No range, a wrapping range, and the NULL VA name nothing. */
	CHECK(!nv_xdev_ext_ce_memory_args_ok(va, 0, 0, 0));
	CHECK(!nv_xdev_ext_ce_memory_args_ok(UINT64_MAX - 4095, 8192, 0, 0));
	CHECK(!nv_xdev_ext_ce_memory_args_ok(0, 4096, 0, 0));
	/* Unknown flags and nonzero reserved bits are refused, not ignored. */
	CHECK(!nv_xdev_ext_ce_memory_args_ok(va, 4096, 1, 0));
	CHECK(!nv_xdev_ext_ce_memory_args_ok(va, 4096, 0, 1));
}

static void window_offsets(void)
{
	const NvU64 va = 0x7a4879200000ULL, size = 2 << 20;
	NvU64 off = 77;

	CHECK(nv_xdev_ext_ce_memory_window(va, size, va, size, &off) && off == 0);
	off = 77;
	CHECK(nv_xdev_ext_ce_memory_window(va, size, va + 65536, 65536, &off) && off == 65536);
	off = 77;
	CHECK(nv_xdev_ext_ce_memory_window(va, size, va + size - 4096, 4096, &off) &&
	      off == size - 4096);
	/* Before, past, straddling the end, empty, and wrapping windows. */
	off = 77;
	CHECK(!nv_xdev_ext_ce_memory_window(va, size, va - 4096, 8192, &off) && off == 77);
	CHECK(!nv_xdev_ext_ce_memory_window(va, size, va + size, 4096, &off) && off == 77);
	CHECK(!nv_xdev_ext_ce_memory_window(va, size, va + size - 4096, 8192, &off) && off == 77);
	CHECK(!nv_xdev_ext_ce_memory_window(va, size, va, 0, &off) && off == 77);
	CHECK(!nv_xdev_ext_ce_memory_window(va, size, va + 4096, UINT64_MAX, &off) && off == 77);
	CHECK(!nv_xdev_ext_ce_memory_window(UINT64_MAX - 4095, 4096, UINT64_MAX - 4095, 8192, &off) &&
	      off == 77);
}

int main(void)
{
	attach_arguments();
	window_offsets();
	if (failures) {
		printf("nv_xdev_ext_ce_memory_test: %u failure(s)\n", failures);
		return 1;
	}
	printf("PASS nv_xdev_ext_ce_memory_test\n");
	return 0;
}

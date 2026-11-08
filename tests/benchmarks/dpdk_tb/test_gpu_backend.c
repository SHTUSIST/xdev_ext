// SPDX-License-Identifier: GPL-2.0
/*
 * Round trip through one GPU backend of dpdk_tb, the same calls and buffer
 * kinds the program uses: page-aligned heap staging buffers registered with
 * tb_host_register, a device buffer, host->device then device->host copies
 * of every message size, byte comparison.  Link with tb_gpu_cuda.c on a GPU
 * host before the first testbed run; CI links tb_gpu_host.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tb_gpu.h"
#include "tb_wire.h"

int main(void)
{
	const size_t max = 4194304;
	uint8_t *src, *dst;
	void *dev;
	char name[128];

	if (tb_gpu_init(0, name, sizeof(name))) {
		fprintf(stderr, "init: %s\n", tb_gpu_error());
		return 1;
	}
	if (posix_memalign((void **)&src, 4096, max) || posix_memalign((void **)&dst, 4096, max))
		return 1;
	if (tb_host_register(src, max) || tb_host_register(dst, max) || tb_gpu_alloc(&dev, max)) {
		fprintf(stderr, "buffers: %s\n", tb_gpu_error());
		return 1;
	}
	for (size_t size = 64; size <= max; size *= 2) {
		long bad;

		tb_pattern_fill(src, size, (uint32_t)size);
		memset(dst, 0, size);
		if (tb_gpu_h2d(dev, src, size) || tb_gpu_d2h(dst, dev, size)) {
			fprintf(stderr, "copy %zu: %s\n", size, tb_gpu_error());
			return 1;
		}
		bad = tb_pattern_check(dst, size, (uint32_t)size);
		if (bad >= 0) {
			fprintf(stderr, "size %zu: byte %ld differs\n", size, bad);
			return 1;
		}
	}
	tb_gpu_free(dev);
	tb_host_unregister(src);
	tb_host_unregister(dst);
	printf("dpdk_tb gpu backend: PASS gpu=%s sizes=64..%zu\n", name, max);
	free(src);
	free(dst);
	return 0;
}

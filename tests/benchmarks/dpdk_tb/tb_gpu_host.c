// SPDX-License-Identifier: GPL-2.0
/*
 * Host-memory stand-in for the GPU side of dpdk_tb, for correctness runs on
 * machines without a GPU (VM guests).  "Device" buffers are ordinary heap
 * memory and copies are memcpy.  Records from this build say gpu="none";
 * correctness only, never performance data.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tb_gpu.h"

const char *tb_gpu_error(void)
{
	return "host stand-in (no GPU; correctness only)";
}

int tb_gpu_init(int device, char *name, size_t name_len)
{
	(void)device;
	snprintf(name, name_len, "none");
	return 0;
}

int tb_gpu_alloc(void **dev, size_t bytes)
{
	*dev = malloc(bytes);
	return *dev ? 0 : -ENOMEM;
}

int tb_host_register(void *host, size_t bytes)
{
	(void)host;
	(void)bytes;
	return 0;
}

int tb_host_unregister(void *host)
{
	(void)host;
	return 0;
}

int tb_gpu_h2d(void *dev, const void *host, size_t bytes)
{
	memcpy(dev, host, bytes);
	return 0;
}

int tb_gpu_d2h(void *host, const void *dev, size_t bytes)
{
	memcpy(host, dev, bytes);
	return 0;
}

void tb_gpu_free(void *dev)
{
	free(dev);
}

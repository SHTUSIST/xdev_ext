// SPDX-License-Identifier: GPL-2.0
/* CUDA backend of dpdk_tb: ordinary runtime defaults, one stream per process. */
#include <errno.h>
#include <stdio.h>

#include <cuda_runtime_api.h>

#include "tb_gpu.h"

static cudaStream_t stream;
static char last_error[256];

static int fail(const char *what, cudaError_t e)
{
	snprintf(last_error, sizeof(last_error), "%s: %s", what, cudaGetErrorString(e));
	return -EIO;
}

const char *tb_gpu_error(void)
{
	return last_error;
}

int tb_gpu_init(int device, char *name, size_t name_len)
{
	struct cudaDeviceProp prop;
	cudaError_t e;

	if ((e = cudaSetDevice(device)) != cudaSuccess)
		return fail("cudaSetDevice", e);
	if ((e = cudaGetDeviceProperties(&prop, device)) != cudaSuccess)
		return fail("cudaGetDeviceProperties", e);
	snprintf(name, name_len, "%s", prop.name);
	if ((e = cudaStreamCreate(&stream)) != cudaSuccess)
		return fail("cudaStreamCreate", e);
	return 0;
}

int tb_gpu_alloc(void **dev, size_t bytes)
{
	cudaError_t e = cudaMalloc(dev, bytes);

	return e == cudaSuccess ? 0 : fail("cudaMalloc", e);
}

int tb_host_register(void *host, size_t bytes)
{
	cudaError_t e = cudaHostRegister(host, bytes, cudaHostRegisterDefault);

	return e == cudaSuccess ? 0 : fail("cudaHostRegister", e);
}

int tb_host_unregister(void *host)
{
	cudaError_t e = cudaHostUnregister(host);

	return e == cudaSuccess ? 0 : fail("cudaHostUnregister", e);
}

int tb_gpu_h2d(void *dev, const void *host, size_t bytes)
{
	cudaError_t e = cudaMemcpyAsync(dev, host, bytes, cudaMemcpyHostToDevice, stream);

	if (e != cudaSuccess)
		return fail("cudaMemcpyAsync H2D", e);
	e = cudaStreamSynchronize(stream);
	return e == cudaSuccess ? 0 : fail("cudaStreamSynchronize", e);
}

int tb_gpu_d2h(void *host, const void *dev, size_t bytes)
{
	cudaError_t e = cudaMemcpyAsync(host, dev, bytes, cudaMemcpyDeviceToHost, stream);

	if (e != cudaSuccess)
		return fail("cudaMemcpyAsync D2H", e);
	e = cudaStreamSynchronize(stream);
	return e == cudaSuccess ? 0 : fail("cudaStreamSynchronize", e);
}

void tb_gpu_free(void *dev)
{
	cudaFree(dev);
}

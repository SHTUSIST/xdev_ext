/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_DPDK_TB_GPU_H
#define XDEV_EVAL_DPDK_TB_GPU_H
/*
 * GPU side of dpdk_tb.  tb_gpu_cuda.c: CUDA runtime, one stream, copies with
 * cudaMemcpyAsync and cudaStreamSynchronize between cudaHostRegister'ed
 * staging buffers and cudaMalloc'ed device buffers.  tb_gpu_host.c: memcpy
 * into ordinary memory, for correctness runs without a GPU only.
 * Every function returns 0 or a negative errno-style value.
 */
#include <stddef.h>

int tb_gpu_init(int device, char *name, size_t name_len);
int tb_gpu_alloc(void **dev, size_t bytes);
int tb_host_register(void *host, size_t bytes);
int tb_host_unregister(void *host);
int tb_gpu_h2d(void *dev, const void *host, size_t bytes);
int tb_gpu_d2h(void *host, const void *dev, size_t bytes);
void tb_gpu_free(void *dev);
const char *tb_gpu_error(void);
#endif

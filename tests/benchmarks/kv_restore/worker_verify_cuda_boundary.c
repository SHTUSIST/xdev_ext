/* SPDX-License-Identifier: GPL-2.0 */
/* CUDA boundary only: worker code uses real dlopen/dlsym on this CPU DSO. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
int cuCtxGetCurrent(void **ctx) { *ctx = NULL; return 0; }
int cuCtxSetCurrent(void *ctx) { (void)ctx; return 0; }
int cuMemcpyDtoH_v2(void *dst, uint64_t src, size_t n)
{ memcpy(dst, (const void *)(uintptr_t)src, n); return 0; }
int cuMemcpyHtoD_v2(uint64_t dst, const void *src, size_t n)
{ memcpy((void *)(uintptr_t)dst, src, n); return 0; }

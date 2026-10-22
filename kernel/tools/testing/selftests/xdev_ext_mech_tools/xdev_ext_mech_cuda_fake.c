/* SPDX-License-Identifier: GPL-2.0 */
/* CUDA Driver ABI test double: no SDK and no GPU required. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef void *CUcontext;
static CUcontext current = (void *)(uintptr_t)0x111;
static int retained, live;
#ifndef OMIT_SET
static int restore_failed;
#endif

static void event(const char *fmt, ...)
{
	const char *path = getenv("CUDA_TEST_TRACE");
	FILE *f = path ? fopen(path, "a") : NULL;
	va_list ap;
	if (!f)
		return;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fclose(f);
}

static int fails(const char *op)
{
	const char *s = getenv("CUDA_TEST_FAIL");
	return s && !strcmp(s, op);
}

__attribute__((destructor)) static void unload(void)
{
	event("unload retained=%d live=%d current=%llx", retained, live,
	      (unsigned long long)(uintptr_t)current);
}

#ifndef OMIT_INIT
int cuInit(unsigned int flags)
{
	event("init %u", flags);
	return fails("init") ? 999 : 0;
}
#endif
#ifndef OMIT_COUNT
int cuDeviceGetCount(int *count)
{
	event("count");
	*count = fails("zero_devices") ? 0 : 3;
	return fails("count") ? 999 : 0;
}
#endif
#ifndef OMIT_DEVICE
int cuDeviceGet(int *device, int ordinal)
{
	event("device %d", ordinal);
	*device = ordinal + 10;
	return fails("device") ? 999 : 0;
}
#endif
#ifndef OMIT_BDF
int cuDeviceGetPCIBusId(char *out, int len, int device)
{
	const char *bdf = device == 11 ? "0000:65:00.0" : "0000:66:00.0";
	event("bdf %d", device);
	if (fails("duplicate") && device == 12)
		bdf = "0000:65:00.0";
	snprintf(out, (size_t)len, "%s", bdf);
	return fails("bdf") ? 999 : 0;
}
#endif
#ifndef OMIT_RETAIN
int cuDevicePrimaryCtxRetain(CUcontext *ctx, int device)
{
	event("retain %d", device);
	if (fails("retain"))
		return 999;
	if (device != 11)
		return 999;
	*ctx = (void *)(uintptr_t)0x222;
	retained++;
	return 0;
}
#endif
#ifndef OMIT_RELEASE
int cuDevicePrimaryCtxRelease(int device)
{
	event("release %d", device);
	retained--;
	return 0;
}
/* Both names are in real Driver ABIs; do not freeze which alias is chosen. */
int cuDevicePrimaryCtxRelease_v2(int device)
{
	return cuDevicePrimaryCtxRelease(device);
}
#endif
#ifndef OMIT_GET
int cuCtxGetCurrent(CUcontext *ctx)
{
	event("get %llx", (unsigned long long)(uintptr_t)current);
	*ctx = current;
	return fails("get") ? 999 : 0;
}
#endif
#ifndef OMIT_SET
int cuCtxSetCurrent(CUcontext ctx)
{
	event("set %llx", (unsigned long long)(uintptr_t)ctx);
	if (fails("set") && ctx == (void *)(uintptr_t)0x222)
		return 999;
	if (fails("restore") && live && ctx == (void *)(uintptr_t)0x111 &&
	    !restore_failed++)
		return 999;
	if (fails("close_restore") && !live && ctx == (void *)(uintptr_t)0x333 &&
	    !restore_failed++)
		return 999;
	current = ctx;
	return 0;
}
#endif
#ifndef OMIT_ALLOC
int cuMemAlloc_v2(uint64_t *va, size_t bytes)
{
	event("alloc %zu current=%llx", bytes,
	      (unsigned long long)(uintptr_t)current);
	if (fails("alloc") || bytes > (1ULL << 40) ||
	    current != (void *)(uintptr_t)0x222)
		return 2;
	*va = 0x123456789abcULL;
	live++;
	return 0;
}
#endif
#ifndef OMIT_FREE
int cuMemFree_v2(uint64_t va)
{
	event("free %llx current=%llx", (unsigned long long)va,
	      (unsigned long long)(uintptr_t)current);
	if (va != 0x123456789abcULL || current != (void *)(uintptr_t)0x222)
		return 999;
	live--;
	return 0;
}
#endif

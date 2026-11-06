/* SPDX-License-Identifier: GPL-2.0 */
/* CUDA Driver ABI test double: no SDK and no GPU required. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>

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

static int exported_fd_open(void);
__attribute__((destructor)) static void unload(void)
{
	event("export_open=%d", exported_fd_open());
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
/*
 * CUDA VMM: cuMemCreate + POSIX file descriptor export + cuMemMap.  The
 * structures are the Driver ABI layouts (CUmemAllocationProp,
 * CUmemAccessDesc); each live VMM resource counts in live as well.
 */
struct fake_prop {
	int type, handles;
	struct { int type, id; } loc;
	void *win32;
	unsigned char compression, rdma;
	unsigned short usage;
	unsigned char reserved[4];
};
struct fake_access { struct { int type, id; } loc; int flags; };
static int created, reserved_va, mapped, exported_fd = -1;
/* Whether the fd handed out by the export is still open in the caller. */
static int exported_fd_open(void)
{
	return exported_fd >= 0 && fcntl(exported_fd, F_GETFD) != -1;
}
static int prop_ok(const struct fake_prop *p)
{
	return p && p->type == 1 && p->handles == 1 && p->loc.type == 1 &&
	       p->loc.id == 11 && !p->win32 && !p->compression && !p->rdma && !p->usage;
}
#ifndef OMIT_GRANULARITY
int cuMemGetAllocationGranularity(size_t *granularity, const struct fake_prop *p, int option)
{
	const char *g = getenv("CUDA_TEST_GRANULARITY");
	event("granularity type=%d handles=%d loc=%d:%d option=%d", p->type, p->handles,
	      p->loc.type, p->loc.id, option);
	if (fails("granularity") || !prop_ok(p) || option != 0)
		return 999;
	*granularity = g ? (size_t)strtoull(g, NULL, 0) : (size_t)2 << 20;
	return 0;
}
#endif
#ifndef OMIT_CREATE
int cuMemCreate(uint64_t *handle, size_t size, const struct fake_prop *p,
		unsigned long long flags)
{
	event("create %zu flags=%llu current=%llx", size, flags,
	      (unsigned long long)(uintptr_t)current);
	if (fails("create") || !prop_ok(p) || flags || current != (void *)(uintptr_t)0x222)
		return 2;
	*handle = 0xabc0;
	created++;
	live++;
	return 0;
}
#endif
#ifndef OMIT_EXPORT
int cuMemExportToShareableHandle(void *out, uint64_t handle, int type,
				 unsigned long long flags)
{
	event("export %llx type=%d flags=%llu", (unsigned long long)handle, type, flags);
	if (fails("export") || handle != 0xabc0 || type != 1 || flags)
		return 999;
	*(int *)out = exported_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return *(int *)out < 0 ? 999 : 0;
}
#endif
#ifndef OMIT_RESERVE
int cuMemAddressReserve(uint64_t *ptr, size_t size, size_t align, uint64_t addr,
			unsigned long long flags)
{
	event("reserve %zu align=%zu addr=%llx flags=%llu", size, align,
	      (unsigned long long)addr, flags);
	if (fails("reserve") || align || addr || flags)
		return 2;
	*ptr = 0x7a4879200000ULL;
	reserved_va++;
	live++;
	return 0;
}
#endif
#ifndef OMIT_MAP
int cuMemMap(uint64_t ptr, size_t size, size_t offset, uint64_t handle,
	     unsigned long long flags)
{
	event("map %llx %zu offset=%zu handle=%llx current=%llx", (unsigned long long)ptr,
	      size, offset, (unsigned long long)handle, (unsigned long long)(uintptr_t)current);
	if (fails("map") || ptr != 0x7a4879200000ULL || offset || handle != 0xabc0 ||
	    flags || !reserved_va || !created)
		return 999;
	mapped++;
	live++;
	return 0;
}
#endif
#ifndef OMIT_ACCESS
int cuMemSetAccess(uint64_t ptr, size_t size, const struct fake_access *d, size_t count)
{
	event("access %llx %zu loc=%d:%d flags=%d count=%zu current=%llx",
	      (unsigned long long)ptr, size, d->loc.type, d->loc.id, d->flags, count,
	      (unsigned long long)(uintptr_t)current);
	if (fails("access") || count != 1 || d->loc.type != 1 || d->loc.id != 11 ||
	    d->flags != 3 || !mapped)
		return 999;
	return 0;
}
#endif
#ifndef OMIT_UNMAP
static int unmap_failed;
int cuMemUnmap(uint64_t ptr, size_t size)
{
	event("unmap %llx %zu current=%llx", (unsigned long long)ptr, size,
	      (unsigned long long)(uintptr_t)current);
	if ((fails("unmap_once") && !unmap_failed++) || !mapped ||
	    current != (void *)(uintptr_t)0x222)
		return 999;
	mapped--;
	live--;
	return 0;
}
#endif
#ifndef OMIT_ADDRESS_FREE
int cuMemAddressFree(uint64_t ptr, size_t size)
{
	event("address_free %llx %zu", (unsigned long long)ptr, size);
	if (mapped || !reserved_va || ptr != 0x7a4879200000ULL)
		return 999;
	reserved_va--;
	live--;
	return 0;
}
#endif
#ifndef OMIT_RELEASE_MEM
int cuMemRelease(uint64_t handle)
{
	event("release_mem %llx", (unsigned long long)handle);
	if (!created || handle != 0xabc0)
		return 999;
	created--;
	live--;
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

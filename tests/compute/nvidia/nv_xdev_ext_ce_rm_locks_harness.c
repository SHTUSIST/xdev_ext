/* SPDX-License-Identifier: MIT */
/*
 * Host fixture for the RM lock contract of the CE host entry points: the
 * actual rm_p2p_umem_ce_host_bind / _unbind / _async_submit / _progress
 * bodies (osapi.c) against stubs that follow RM's own lock rules:
 *  - rmapiLockAcquire() refuses with NV_ERR_INVALID_LOCK_STATE while the
 *    thread owns any GPU lock ("GPU locks are NEVER acquired before the API
 *    lock", rmapi.c), and when it already owns the API lock;
 *  - rmGpuLocksAcquire() refuses with NV_ERR_STATE_IN_USE when the thread
 *    already owns the GPU locks ("GPU lock already acquired by this thread",
 *    locks.c);
 *  - rmGpuLocksRelease() does nothing when no GPU lock is held, and
 *    otherwise releases every GPU lock that is held, whichever thread owns
 *    it: it reads the global gpusLockedMask and only asserts ownership
 *    (locks.c); rmGpuLockIsOwner() says whether this thread owns them.
 * The RM CE calls model NVIDIA's CeUtils contract: NV_CE_UTILS is allocated
 * and freed with RS_FLAGS_ACQUIRE_GPUS_LOCK and its memcopy/check-progress
 * controls run without RMCTRL_FLAGS_NO_GPUS_LOCK, i.e. under the API lock and
 * every GPU lock; CeUtils construction (memmgrMemUtilsChannelInitialize_GM107)
 * releases all GPU locks around its allocations and acquires them again,
 * returning with them held whatever the caller held on entry.
 */
#include <stddef.h>
#include "nv_xdev_ext_host_env.h"

static struct {
	int api, gpus;                  /* locks owned by this thread */
	int other_gpus;                 /* GPU locks another thread owns */
	int lose_gpus;                  /* RM returns without the GPU locks */
	unsigned int foreign_releases;  /* another thread's GPU locks released */
	NV_STATUS api_status, gpu_status;
	unsigned int api_acquires, api_releases, gpu_acquires, gpu_releases;
	unsigned int calls, bad_entry;
	const char *last;
} L;

#define NV_ENTER_RM_RUNTIME(sp, fp) ((void)(sp), (fp) = NULL)
#define NV_EXIT_RM_RUNTIME(sp, fp) ((void)(sp), (void)(fp))
#define NV_API_CALL
#define API_LOCK_FLAGS_NONE 0
#define GPUS_LOCK_FLAGS_NONE 0
#define RM_LOCK_MODULES_P2P 7
typedef struct { int unused; } nvidia_stack_t;
typedef struct { int unused; } THREAD_STATE_NODE;
typedef struct OBJGPU OBJGPU;
#define THREAD_STATE_FLAGS_NONE 0
static void threadStateInit(THREAD_STATE_NODE *t, int f) { (void)t; (void)f; }
static void threadStateFree(THREAD_STATE_NODE *t, int f) { (void)t; (void)f; }

static NV_STATUS rmapiLockAcquire(NvU32 flags, NvU32 module)
{
	(void)flags; (void)module;
	if (L.api || L.gpus)
		return NV_ERR_INVALID_LOCK_STATE;
	if (L.api_status != NV_OK)
		return L.api_status;
	L.api = 1;
	L.api_acquires++;
	return NV_OK;
}
static void rmapiLockRelease(void) { L.api = 0; L.api_releases++; }
static NV_STATUS rmGpuLocksAcquire(NvU32 flags, NvU32 module)
{
	(void)flags; (void)module;
	if (L.gpus)
		return NV_ERR_STATE_IN_USE;
	if (L.gpu_status != NV_OK)
		return L.gpu_status;
	L.gpus = 1;
	L.gpu_acquires++;
	return NV_OK;
}
static NvU32 rmGpuLocksRelease(NvU32 flags, OBJGPU *dpc)
{
	(void)flags; (void)dpc;
	if (L.gpus) {
		L.gpus = 0;
		L.gpu_releases++;
	} else if (L.other_gpus) {
		L.other_gpus = 0;
		L.foreign_releases++;
	}
	return 0;
}
static NvBool rmGpuLockIsOwner(void) { return L.gpus ? NV_TRUE : NV_FALSE; }

typedef struct { NvU64 umemOffset, gpuOffset, size; } P2P_UMEM_XFER;
typedef void (*P2P_UMEM_CE_EVENT)(void *, NvU64);
typedef struct MEMORY_DESCRIPTOR MEMORY_DESCRIPTOR;
typedef struct { NvU8 gpuUuid[16]; NvU64 offset, length; } P2P_UMEM_VIDMEM_BINDING;
struct OBJGPU { int unused; };
static OBJGPU gpu0;
#define NV_P2P_UMEM_STRICT_SECURITY_CHECKS 1
#define DRF_DEF(d, r, f, c) 0
static OBJGPU *gpumgrGetGpuFromUuid(const NvU8 *uuid, NvU32 flags)
{
	(void)uuid; (void)flags;
	return &gpu0;
}

/* The RM CE side: each call checks it entered under both locks. */
static void entered(const char *what)
{
	L.calls++;
	L.last = what;
	if (!L.api || !L.gpus) {
		L.bad_entry++;
		printf("note: %s entered with api=%d gpus=%d\n", what, L.api, L.gpus);
	}
}
static NV_STATUS RmP2PUmemCeHostBind(void *b, NvU64 *phys, NvU32 count, NvU32 pageSize,
	NvU64 bytes, P2P_UMEM_CE_EVENT event, void *eventArg, void **out)
{
	(void)b; (void)phys; (void)count; (void)pageSize; (void)bytes; (void)event; (void)eventArg;
	entered("bind");
	rmGpuLocksRelease(GPUS_LOCK_FLAGS_NONE, NULL);          /* channel setup */
	if (L.lose_gpus) {
		/* Its reacquire failed, or an error path between the release
		 * and the reacquire; the bottom half takes the GPU locks. */
		L.other_gpus = 1;
		return NV_ERR_NO_MEMORY;
	}
	if (rmGpuLocksAcquire(GPUS_LOCK_FLAGS_NONE, 0) != NV_OK) /* ...and back */
		return NV_ERR_GENERIC;
	*out = (void *)0x1;
	return NV_OK;
}
static NV_STATUS RmP2PUmemCeHostUnbind(void *h) { (void)h; entered("unbind"); return NV_OK; }
static NV_STATUS RmP2PUmemCeAsyncSubmit(void *h, const P2P_UMEM_XFER *x, NvU32 n, NvU32 dir,
	NvBool *issued, NvU64 *token)
{
	(void)h; (void)x; (void)n; (void)dir;
	entered("submit");
	*issued = NV_TRUE;
	*token = 1;
	return NV_OK;
}
static NV_STATUS RmP2PUmemCeProgress(void *h, NvU64 *watermark)
{
	(void)h;
	entered("progress");
	*watermark = 1;
	return NV_OK;
}
/* RM asserts rmapiLockIsOwner() here (p2p.c). */
static NV_STATUS RmP2PUmemVidmemResolve(P2P_UMEM_VIDMEM_BINDING *b, OBJGPU *g, MEMORY_DESCRIPTOR **out)
{
	(void)b; (void)g;
	if (!L.api)
		return NV_ERR_INVALID_LOCK_STATE;
	*out = (MEMORY_DESCRIPTOR *)0x10;
	return NV_OK;
}
/* The old synchronous request copies through memmgrMemCopy() on RM's own
 * shared CeUtils (pMemoryManager->pCeUtils), which RM's scrubber and memset
 * use under the GPU locks. */
static NV_STATUS RmP2PUmemDmaRequestDirect(OBJGPU *g, NvU64 *p, NvU32 count, NvU32 pageSize,
	NvU64 bytes, MEMORY_DESCRIPTOR *md, NvU64 off, NvU64 len, const P2P_UMEM_XFER *x, NvU32 n,
	NvU32 flags, NvBool *hw, NvU64 *done)
{
	(void)g; (void)p; (void)count; (void)pageSize; (void)bytes; (void)md; (void)off; (void)len;
	(void)n; (void)flags;
	entered("dma");
	*hw = NV_TRUE;
	*done = x[0].size;
	return NV_OK;
}

#include "nv_xdev_ext_ce_rm_locks_actual.inc"

static nvidia_stack_t sp;
static NvU64 phys[4];

static void all_released(const char *what)
{
	CHECK(!L.api && !L.gpus, "%s returned owning api=%d gpus=%d", what, L.api, L.gpus);
	CHECK(L.api_acquires == L.api_releases && L.gpu_acquires == L.gpu_releases,
	      "%s: api %u/%u gpu %u/%u acquires/releases", what, L.api_acquires,
	      L.api_releases, L.gpu_acquires, L.gpu_releases);
}

/* A CREATE binds two CE stages in one thread: the second bind must find no
 * lock left behind by the first (the RTX 5090 window: stage 1 then refused
 * the API lock with NV_ERR_INVALID_LOCK_STATE, 0x2f). */
static void case_bind(void)
{
	void *out = NULL;
	CHECK(rm_p2p_umem_ce_host_bind(&sp, (void *)0x2, phys, 4, 4096, 16384, NULL, NULL, &out) ==
	      NV_OK && out, "first bind");
	all_released("first bind");
	out = NULL;
	CHECK(rm_p2p_umem_ce_host_bind(&sp, (void *)0x2, phys, 4, 4096, 16384, NULL, NULL, &out) ==
	      NV_OK && out, "second bind after the first returned");
	all_released("second bind");
	CHECK(L.bad_entry == 0 && L.calls == 2, "CeUtils construction ran without the GPU locks");
}

static void case_controls(void)
{
	P2P_UMEM_XFER x = { 0, 0, 4096 };
	NvBool issued = NV_FALSE;
	NvU64 token = 0, watermark = 0;
	CHECK(rm_p2p_umem_ce_async_submit(&sp, (void *)0x1, &x, 1, 1, &issued, &token) == NV_OK &&
	      issued && token == 1, "submit");
	all_released("submit");
	CHECK(rm_p2p_umem_ce_progress(&sp, (void *)0x1, &watermark) == NV_OK && watermark == 1,
	      "progress");
	all_released("progress");
	CHECK(rm_p2p_umem_ce_host_unbind(&sp, (void *)0x1) == NV_OK, "unbind");
	all_released("unbind");
	CHECK(L.bad_entry == 0 && L.calls == 3, "a CeUtils call ran without the GPU locks");
}

/* The old synchronous CE request (NV_ESC_P2P_DMA_XFER) copies on RM's shared
 * CeUtils: it must run under the same locks as RM's own CeUtils users. */
static void case_dma_request(void)
{
	P2P_UMEM_VIDMEM_BINDING binding = { { 0 }, 0, 1 << 20 };
	P2P_UMEM_XFER x = { 0, 0, 4096 };
	NvBool hw = NV_FALSE;
	NvU64 done = 0;
	CHECK(rm_p2p_umem_dma_request(&sp, phys, 4, 4096, 16384, &binding, &x, 1, 1, &hw, &done) ==
	      NV_OK && hw && done == 4096, "synchronous request");
	all_released("synchronous request");
	CHECK(L.bad_entry == 0 && L.calls == 1, "the synchronous CE copy ran without the GPU locks");
	L.gpu_status = NV_ERR_TIMEOUT;
	CHECK(rm_p2p_umem_dma_request(&sp, phys, 4, 4096, 16384, &binding, &x, 1, 1, &hw, &done) ==
	      NV_ERR_TIMEOUT && !hw && done == 0, "synchronous request GPU lock failure status");
	all_released("synchronous request GPU lock failure");
	CHECK(L.calls == 1, "the synchronous CE copy ran without its locks");
}

/* RM's channel setup can return without the GPU locks (mem_utils_gm107.c:
 * the reacquire failed, or an error path between the release and the
 * reacquire); the release must then leave alone the GPU locks another
 * thread owns by now. */
static void case_lost_gpu_locks(void)
{
	void *out = NULL;
	L.lose_gpus = 1;
	CHECK(rm_p2p_umem_ce_host_bind(&sp, (void *)0x2, phys, 4, 4096, 16384, NULL, NULL, &out) ==
	      NV_ERR_NO_MEMORY, "bind status");
	CHECK(L.foreign_releases == 0 && L.other_gpus,
	      "released the GPU locks another thread owns (%u)", L.foreign_releases);
	CHECK(!L.api && L.api_acquires == 1 && L.api_releases == 1, "API lock api=%d %u/%u",
	      L.api, L.api_acquires, L.api_releases);
}

/* Lock failures return the status, call no RM CE code, and leave no lock. */
static void case_lock_failures(void)
{
	void *out = (void *)0x9;
	NvU64 watermark = 0;
	L.gpu_status = NV_ERR_TIMEOUT;
	CHECK(rm_p2p_umem_ce_host_bind(&sp, (void *)0x2, phys, 4, 4096, 16384, NULL, NULL, &out) ==
	      NV_ERR_TIMEOUT, "GPU lock failure status");
	CHECK(rm_p2p_umem_ce_progress(&sp, (void *)0x1, &watermark) == NV_ERR_TIMEOUT,
	      "progress GPU lock failure status");
	all_released("GPU lock failure");
	L.gpu_status = NV_OK;
	L.api_status = NV_ERR_INVALID_LOCK_STATE;
	CHECK(rm_p2p_umem_ce_host_unbind(&sp, (void *)0x1) == NV_ERR_INVALID_LOCK_STATE,
	      "API lock failure status");
	CHECK(L.gpu_acquires == 0, "a GPU lock was taken without the API lock");
	all_released("API lock failure");
	CHECK(L.calls == 0, "RM CE code ran without its locks");
}

struct named_case { const char *name; void (*fn)(void); };
static const struct named_case cases[] = {
	{ "bind", case_bind },
	{ "controls", case_controls },
	{ "lock-failures", case_lock_failures },
	{ "dma-request", case_dma_request },
	{ "lost-gpu-locks", case_lost_gpu_locks },
};

int main(int argc, char **argv)
{
	unsigned int i;
	setvbuf(stdout, NULL, _IONBF, 0);
	for (i = 0; argc == 2 && i < sizeof(cases) / sizeof(cases[0]); i++)
		if (!strcmp(argv[1], cases[i].name)) {
			cases[i].fn();
			return env_report(argv[1]);
		}
	printf("usage: case name\n");
	return 2;
}

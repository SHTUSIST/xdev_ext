/* SPDX-License-Identifier: MIT */
/*
 * Host fixture for the RM side of the native CE host bind (p2p_umem.c CE
 * host group) and the real CeUtils completion-callback list functions
 * (ce_utils.c).  The production bodies are copied unchanged by the runner.
 * Stubs: object creation, memdesc construction, the GPU property query, the
 * bound-allocation resolve, and ceutilsMemcopy (it only advances the
 * submitted payload and registers the callback through the real
 * _ceutilsInsertCallback).  "Hardware" completion writes the low 32 bits of
 * the channel semaphore and, when the CeUtils was created with completion
 * callbacks, runs the real _ceutilsProcessCompletionCallbacks exactly as the
 * channel's non-stall event handler does.  No GPU or DMA exists here.
 */
#include <stddef.h>
#include "nv_xdev_ext_host_env.h"

#ifndef HARNESS_RM_EVENT_API
#define HARNESS_RM_EVENT_API 0
#endif

#define NV_INLINE inline
#define NV_ASSERT(c) ((void)0)
#define NV_ASSERT_OR_RETURN(c, e) do { if (!(c)) return (e); } while (0)
#define NV_ASSERT_OK(c) ((void)(c))
#define NV_PRINTF(...) ((void)0)
#define LEVEL_INFO 0
#define LEVEL_ERROR 1
#define RM_SHA1_GID_SIZE 16

/* DRF field helpers, as in nvmisc.h. */
#define DRF_SHIFT(drf) ((0 ? drf) % 32)
#define DRF_MASK(drf) (0xFFFFFFFFU >> (31 - ((1 ? drf) % 32) + ((0 ? drf) % 32)))
#define DRF_DEF(d, r, f, c) ((NV##d##r##f##c) << DRF_SHIFT(NV##d##r##f))
#define DRF_VAL(d, r, f, v) (((v) >> DRF_SHIFT(NV##d##r##f)) & DRF_MASK(NV##d##r##f))
#define FLD_TEST_DRF(d, r, f, c, v) (DRF_VAL(d, r, f, v) == NV##d##r##f##c)
/* NV0050 CeUtils allocation flags, values from class/cl0050.h (590.48.01). */
#define NV0050_CEUTILS_FLAGS_NO_BAR1_USE 3:3
#define NV0050_CEUTILS_FLAGS_NO_BAR1_USE_FALSE (0x00000000)
#define NV0050_CEUTILS_FLAGS_NO_BAR1_USE_TRUE (0x00000001)
#define NV0050_CEUTILS_FLAGS_ENABLE_COMPLETION_CB 6:6
#define NV0050_CEUTILS_FLAGS_ENABLE_COMPLETION_CB_FALSE (0x00000000)
#define NV0050_CEUTILS_FLAGS_ENABLE_COMPLETION_CB_TRUE (0x00000001)
#define NV0050_CTRL_MEMCOPY_FLAGS_ASYNC (1u << 1)
typedef struct { NvU64 flags; NvU32 forceCeId; NvHandle hVaspace; } NV0050_ALLOCATION_PARAMETERS;

/* GPU and memory-manager objects: only the members the bodies read. */
enum { PDB_PROP_GPU_IS_LOST, PDB_PROP_GPU_IN_FULLCHIP_RESET,
       PDB_PROP_GPU_IN_SECONDARY_BUS_RESET, PDB_PROP_GPU_IN_GC6_RESET, PDB_PROP_COUNT };
typedef struct OBJGPU OBJGPU;
struct OBJGPU {
	NvBool bIsSOC;
	NvBool props[PDB_PROP_COUNT];
	NvBool (*getProperty)(OBJGPU *, int);
	int id;
};
static NvBool harness_get_property(OBJGPU *g, int p) { return g->props[p]; }
typedef struct { NvBool bCePhysicalVidmemAccessNotSupported; } MemoryManager;
typedef struct { NvBool blocked; } KernelBus;
static MemoryManager harness_mm;
static KernelBus harness_bus;
#define GPU_GET_MEMORY_MANAGER(g) ((void)(g), &harness_mm)
#define GPU_GET_KERNEL_BUS(g) ((void)(g), &harness_bus)
#define IS_VIRTUAL(g) ((void)(g), 0)
#define IS_MIG_IN_USE(g) ((void)(g), 0)
#define IsTURINGorBetter(g) ((void)(g), 1)
static NvBool kbusIsBarAccessBlocked(KernelBus *b) { return b->blocked; }

/* Memory descriptors */
typedef struct MEMORY_DESCRIPTOR { NvU64 size; NvU64 pages[64]; NvU32 count, pageSize; int live; } MEMORY_DESCRIPTOR;
#define ADDR_SYSMEM 1
#define NV_MEMORY_CACHED 1
#define MEMDESC_FLAGS_NONE 0
#define AT_GPU 1
static unsigned int md_created, md_destroyed;
static NV_STATUS memdescCreate(MEMORY_DESCRIPTOR **out, OBJGPU *g, NvU64 size, NvU64 align,
	NvBool contig, int aspace, int attr, int flags)
{
	(void)g; (void)align; (void)contig; (void)aspace; (void)attr; (void)flags;
	*out = calloc(1, sizeof(**out));
	(*out)->size = size;
	(*out)->live = 1;
	md_created++;
	return NV_OK;
}
static void memdescFillPages(MEMORY_DESCRIPTOR *m, NvU32 start, RmPhysAddr *pa, NvU32 n, NvU64 ps)
{
	NvU32 i;
	for (i = 0; i < n && start + i < 64; i++)
		m->pages[start + i] = pa[i];
	m->count = n;
	m->pageSize = (NvU32)ps;
}
static void memdescSetPageSize(MEMORY_DESCRIPTOR *m, int at, NvU64 ps) { (void)at; m->pageSize = (NvU32)ps; }
static void memdescDestroy(MEMORY_DESCRIPTOR *m) { if (m) { m->live = 0; free(m); md_destroyed++; } }
#define portMemAllocNonPaged(n) calloc(1, (n))
#define portMemFree(p) free(p)
#define portMemSet(p, v, n) memset((p), (v), (n))

/* CeUtils: the real list functions operate on this layout. */
typedef void (*ChannelCompletionCallback)(void *);
typedef struct { void *prev, *next; } ListNode;
#include "nv_xdev_ext_ce_rm_event_types.h"     /* CeUtilsCallback, CEUTILS_MEMCOPY_PARAMS, P2P types */
typedef struct { CeUtilsCallback *head, *tail; } CeUtilsCallbackList;
typedef struct {
	NvU32 sema;   /* low 32 bits written by the semaphore release */
	void *pbCpuVA, *pControlGPFifo, *pTokenFromNotifier;
	NvBool bUseDoorbellRegister;
} OBJCHANNEL;
typedef struct {
	OBJCHANNEL *pChannel;
	NvU64 lastSubmittedPayload, lastCompletedPayload;
	NvBool bCompletionCallbackEnabled;
	NvBool paused;
	void *pCallbackLock;
	CeUtilsCallbackList completionCallbacks;
} CeUtils;
typedef struct {
	NvU32 payload;
	ChannelCompletionCallback pCompletionCallback;
	void *pCompletionCallbackArg;
} CHANNEL_PB_INFO;
#define READ_CHANNEL_PAYLOAD_SEMA(c) ((c)->sema)
static void listInitIntrusive(CeUtilsCallbackList *l) { l->head = l->tail = NULL; }
static CeUtilsCallback *listHead(CeUtilsCallbackList *l) { return l->head; }
static void listAppendExisting(CeUtilsCallbackList *l, CeUtilsCallback *n)
{
	n->listNode.prev = l->tail;
	n->listNode.next = NULL;
	if (l->tail)
		((CeUtilsCallback *)l->tail)->listNode.next = n;
	else
		l->head = n;
	l->tail = n;
}
static void listRemove(CeUtilsCallbackList *l, CeUtilsCallback *n)
{
	CeUtilsCallback *p = n->listNode.prev, *q = n->listNode.next;
	if (p) p->listNode.next = q; else l->head = q;
	if (q) q->listNode.prev = p; else l->tail = p;
}
static void listDestroy(CeUtilsCallbackList *l) { (void)l; }
static unsigned int listCount(CeUtilsCallbackList *l)
{
	unsigned int n = 0;
	CeUtilsCallback *c;
	for (c = l->head; c; c = c->listNode.next)
		n++;
	return n;
}
static void portSyncSpinlockAcquire(void *l) { (void)l; }
static void portSyncSpinlockRelease(void *l) { (void)l; }
static NvBool ceutilsIsSubmissionPaused(CeUtils *c) { return c->paused; }

#include "nv_xdev_ext_ce_rm_event_ceutils.inc"   /* real ce_utils.c bodies */

static struct {
	NvU64 alloc_flags;
	unsigned int created, deleted, pushes, callbacks_set, last_callback_push;
	unsigned int resolve_calls, fail_resolve, memcopy_fail_at, async_pushes;
	void *last_callback_arg;
	NV_STATUS resolve_status;
} R;
static NV_STATUS harness_objCreate_CeUtils(CeUtils **out, OBJGPU *g, void *mig,
					   NV0050_ALLOCATION_PARAMETERS *p)
{
	CeUtils *c = calloc(1, sizeof(*c));
	(void)g; (void)mig;
	c->pChannel = calloc(1, sizeof(*c->pChannel));
	c->pChannel->pbCpuVA = c->pChannel->pControlGPFifo = (void *)1;
	/* The one constructor line that decides callback support, from
	 * ceutilsConstruct_IMPL(). */
	c->bCompletionCallbackEnabled = FLD_TEST_DRF(0050_CEUTILS, _FLAGS, _ENABLE_COMPLETION_CB,
						     _TRUE, p->flags);
	listInitIntrusive(&c->completionCallbacks);
	R.alloc_flags = p->flags;
	R.created++;
	*out = c;
	return NV_OK;
}
#define objCreate(pp, parent, Class, ...) harness_objCreate_##Class(pp, __VA_ARGS__)
static void objDelete(CeUtils *c)
{
	/* ceutilsDestruct_IMPL: process remaining callbacks while functional. */
	_ceutilsProcessCompletionCallbacks(c);
	if (listCount(&c->completionCallbacks))
		printf("NOTE: callbacks left at CeUtils destruction\n");
	free(c->pChannel);
	free(c);
	R.deleted++;
}
static NV_STATUS ceutilsMemcopy(CeUtils *c, CEUTILS_MEMCOPY_PARAMS *p)
{
	CHANNEL_PB_INFO pb = { 0 };
	NV_STATUS st;
	R.pushes++;
	if (p->flags & NV0050_CTRL_MEMCOPY_FLAGS_ASYNC)
		R.async_pushes++;
	if (R.memcopy_fail_at && R.pushes == R.memcopy_fail_at)
		return NV_ERR_GENERIC;
	pb.payload = (NvU32)++c->lastSubmittedPayload;
	pb.pCompletionCallback = p->pCompletionCallback;
	pb.pCompletionCallbackArg = p->pCompletionCallbackArg;
	if (p->pCompletionCallback) {
		R.callbacks_set++;
		R.last_callback_push = R.pushes;
		R.last_callback_arg = p->pCompletionCallbackArg;
		st = _ceutilsInsertCallback(c, &pb);
		if (st != NV_OK)
			return st;
	}
	p->submittedWorkId = c->lastSubmittedPayload;
	return NV_OK;
}

static MEMORY_DESCRIPTOR harness_gpu_md;
static NV_STATUS RmP2PUmemVidmemResolve(P2P_UMEM_VIDMEM_BINDING *b, OBJGPU *g,
					MEMORY_DESCRIPTOR **md)
{
	R.resolve_calls++;
	if (g != b->pGpu)
		return NV_ERR_INVALID_DEVICE;
	if (R.resolve_status != NV_OK)
		return R.resolve_status;
	*md = &harness_gpu_md;
	return NV_OK;
}

#include "nv_xdev_ext_ce_rm_event_actual.inc"     /* real p2p_umem.c CE host group */

/* ================================================================ cases */
static OBJGPU gpu_a = { .getProperty = harness_get_property, .id = 1 };
static OBJGPU gpu_b = { .getProperty = harness_get_property, .id = 2 };
static P2P_UMEM_VIDMEM_BINDING binding_a = { .pGpu = &gpu_a, .offset = 0, .length = 1 << 20 };
static NvU64 addrs[4] = { 0xA00000000ULL, 0xA00001000ULL, 0xA00002000ULL, 0xA00003000ULL };
static struct { unsigned int calls; NvU64 watermark; void *arg; } E;
static int event_arg;

#if HARNESS_RM_EVENT_API
static void event_cb(void *arg, NvU64 watermark)
{
	E.calls++;
	E.watermark = watermark;
	E.arg = arg;
}
#endif

static NV_STATUS bind(P2P_UMEM_CE_HOST **out, int with_event)
{
	void *h = NULL;
	NV_STATUS st;
#if HARNESS_RM_EVENT_API
	st = RmP2PUmemCeHostBind(&binding_a, addrs, 4, 4096, 4 * 4096,
				 with_event ? event_cb : NULL, with_event ? &event_arg : NULL, &h);
#else
	(void)with_event;
	st = RmP2PUmemCeHostBind(&binding_a, addrs, 4, 4096, 4 * 4096, &h);
#endif
	*out = h;
	return st;
}

static CeUtils *ce(P2P_UMEM_CE_HOST *h) { return h->pCeUtils; }

/* Semaphore release with optional non-stall event, as the channel delivers. */
static void hw_complete(P2P_UMEM_CE_HOST *h, NvU64 payload)
{
	ce(h)->pChannel->sema = (NvU32)payload;
	if (ce(h)->bCompletionCallbackEnabled)
		_ceutilsSemaphoreEventCallback(ce(h), NULL, 0, 0, 0);
}

static NV_STATUS submit(P2P_UMEM_CE_HOST *h, NvU32 n, NvU64 *token)
{
	P2P_UMEM_XFER x[4] = { { 0, 0, 4096 }, { 4096, 4096, 4096 }, { 8192, 8192, 4096 },
			       { 12288, 12288, 4096 } };
	NvBool issued = NV_FALSE;
	return RmP2PUmemCeAsyncSubmit(h, x, n, 1, &issued, token);
}

static void require_event_api(void)
{
	CHECK(HARNESS_RM_EVENT_API,
	      "G1: RmP2PUmemCeHostBind has no completion-event parameter (P2P_UMEM_CE_EVENT "
	      "not declared in p2p.h)");
}

static void case_bind_flags(void)
{
	P2P_UMEM_CE_HOST *h;
	require_event_api();
	REQUIRE(bind(&h, 1) == NV_OK, "event bind");
	CHECK(FLD_TEST_DRF(0050_CEUTILS, _FLAGS, _ENABLE_COMPLETION_CB, _TRUE, R.alloc_flags),
	      "G1: event bind did not create CeUtils with ENABLE_COMPLETION_CB (flags=0x%llx)",
	      (unsigned long long)R.alloc_flags);
	CHECK(FLD_TEST_DRF(0050_CEUTILS, _FLAGS, _NO_BAR1_USE, _TRUE, R.alloc_flags),
	      "NO_BAR1_USE lost (flags=0x%llx)", (unsigned long long)R.alloc_flags);
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK, "unbind");
	REQUIRE(bind(&h, 0) == NV_OK, "polled bind");
	CHECK(!FLD_TEST_DRF(0050_CEUTILS, _FLAGS, _ENABLE_COMPLETION_CB, _TRUE, R.alloc_flags),
	      "polled bind must not request completion callbacks");
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK, "unbind polled");
}

static void case_one_callback_per_plan(void)
{
	P2P_UMEM_CE_HOST *h;
	NvU64 token = 0;
	require_event_api();
	REQUIRE(bind(&h, 1) == NV_OK, "bind");
	REQUIRE(submit(h, 3, &token) == NV_OK, "submit");
	CHECK(R.pushes == 3 && R.async_pushes == 3, "pushes=%u async=%u", R.pushes, R.async_pushes);
	CHECK(R.callbacks_set == 1,
	      "G1: a 3-entry plan registered %u completion callbacks, expected exactly 1",
	      R.callbacks_set);
	CHECK(R.last_callback_push == 3, "G1: the callback must ride on the last entry (push %u)",
	      R.last_callback_push);
	CHECK(token == 3, "token %llu", (unsigned long long)token);
	hw_complete(h, token);
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK, "unbind");
	/* polled mode registers none */
	R.pushes = R.callbacks_set = 0;
	REQUIRE(bind(&h, 0) == NV_OK, "polled bind");
	REQUIRE(submit(h, 2, &token) == NV_OK, "polled submit");
	CHECK(R.callbacks_set == 0, "polled bind registered %u callbacks", R.callbacks_set);
	hw_complete(h, token);
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK, "unbind polled");
}

static void case_event_forward(void)
{
	P2P_UMEM_CE_HOST *h;
	NvU64 t1 = 0, t2 = 0;
	require_event_api();
	REQUIRE(bind(&h, 1) == NV_OK, "bind");
	REQUIRE(submit(h, 2, &t1) == NV_OK, "submit 1");
	REQUIRE(submit(h, 1, &t2) == NV_OK, "submit 2");
	hw_complete(h, t1);
	CHECK(E.calls == 1 && E.watermark == t1 && E.arg == &event_arg,
	      "G1: semaphore event for token %llu delivered calls=%u watermark=%llu",
	      (unsigned long long)t1, E.calls, (unsigned long long)E.watermark);
	hw_complete(h, t1);
	CHECK(E.calls == 1, "G1: repeated semaphore value re-delivered (%u)", E.calls);
	hw_complete(h, t2);
	CHECK(E.calls == 2 && E.watermark == t2, "G1: second plan event calls=%u wm=%llu",
	      E.calls, (unsigned long long)E.watermark);
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK, "unbind drained");
	CHECK(E.calls == 2, "event after unbind");
}

static void case_event_poisoned(void)
{
	P2P_UMEM_CE_HOST *h;
	NvU64 t = 0;
	require_event_api();
	REQUIRE(bind(&h, 1) == NV_OK, "bind");
	REQUIRE(submit(h, 1, &t) == NV_OK, "submit");
	RmP2PUmemCeInvalidate(&gpu_a);
	hw_complete(h, t);
	CHECK(E.calls == 0, "G1: event forwarded from a poisoned (invalidated) channel");
}

static void case_event_unbind_pending(void)
{
	P2P_UMEM_CE_HOST *h;
	NvU64 t = 0;
	require_event_api();
	REQUIRE(bind(&h, 1) == NV_OK, "bind");
	REQUIRE(submit(h, 1, &t) == NV_OK, "submit");
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_ERR_BUSY_RETRY, "unbind with work outstanding");
	CHECK(R.deleted == 0 && E.calls == 0, "destroyed or delivered while busy");
	hw_complete(h, t);
	CHECK(E.calls == 1, "G1: event not delivered (%u)", E.calls);
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK && R.deleted == 1, "drained unbind");
	CHECK(E.calls == 1, "event delivered during or after unbind of a drained host");
}

/* ---- G11 controls on the active async path (expected to hold today) ---- */
static void case_invalidate(void)
{
	P2P_UMEM_CE_HOST *h;
	NvU64 t = 0, wm = 0;
	REQUIRE(bind(&h, 0) == NV_OK, "bind");
	RmP2PUmemCeInvalidate(&gpu_b);   /* another GPU */
	CHECK(submit(h, 1, &t) == NV_OK, "unrelated GPU invalidation poisoned this bind");
	hw_complete(h, t);
	RmP2PUmemCeInvalidate(&gpu_a);
	R.pushes = 0;
	CHECK(submit(h, 1, &t) == NV_ERR_INVALID_STATE && R.pushes == 0,
	      "G11: poisoned bind reached the channel");
	CHECK(RmP2PUmemCeProgress(h, &wm) == NV_ERR_INVALID_STATE, "G11: poisoned progress");
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_ERR_INVALID_STATE && R.deleted == 0,
	      "G11: poisoned bind destroyed its channel/descriptor");
}

static void case_progress_watermark(void)
{
	P2P_UMEM_CE_HOST *h;
	NvU64 t = 0, wm = 0;
	REQUIRE(bind(&h, 0) == NV_OK, "bind");
	REQUIRE(submit(h, 2, &t) == NV_OK, "submit");
	ce(h)->pChannel->sema = (NvU32)(t - 1);
	CHECK(RmP2PUmemCeProgress(h, &wm) == NV_OK && wm == t - 1, "below watermark");
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_ERR_BUSY_RETRY && R.deleted == 0,
	      "G11: unbind below lastSubmitted must be busy");
	ce(h)->pChannel->sema = (NvU32)t;
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK && R.deleted == 1 && md_destroyed == 1,
	      "G11: equal watermark releases exactly once (deleted=%u md=%u)", R.deleted,
	      md_destroyed);
	REQUIRE(bind(&h, 0) == NV_OK, "bind 2");
	REQUIRE(submit(h, 1, &t) == NV_OK, "submit 2");
	ce(h)->pChannel->sema = (NvU32)(t + 1);
	CHECK(RmP2PUmemCeProgress(h, &wm) == NV_ERR_INVALID_STATE && h->poisoned,
	      "G11: watermark above lastSubmitted must poison");
}

static void case_resolve_before_push(void)
{
	P2P_UMEM_CE_HOST *h;
	NvU64 t = 0;
	REQUIRE(bind(&h, 0) == NV_OK, "bind");
	R.resolve_status = NV_ERR_INVALID_STATE;
	R.pushes = 0;
	CHECK(submit(h, 2, &t) == NV_ERR_INVALID_STATE && R.pushes == 0 && R.resolve_calls >= 1,
	      "G11: submit must resolve the bound allocation before the first push");
	R.resolve_status = NV_OK;
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK, "unbind");
}

static void case_plan_before_push(void)
{
	P2P_UMEM_CE_HOST *h;
	P2P_UMEM_XFER x[2] = { { 0, 0, 4096 }, { 4 * 4096, 0, 4096 } };   /* 2nd beyond host bytes */
	NvBool issued = NV_TRUE;
	NvU64 t = 7;
	REQUIRE(bind(&h, 0) == NV_OK, "bind");
	R.pushes = 0;
	CHECK(RmP2PUmemCeAsyncSubmit(h, x, 2, 1, &issued, &t) == NV_ERR_INVALID_ARGUMENT &&
	      R.pushes == 0 && !issued && t == 0,
	      "G11: an invalid later entry must fail before the first push");
	CHECK(RmP2PUmemCeHostUnbind(h) == NV_OK, "unbind");
}

struct named_case { const char *name; void (*fn)(void); };
static const struct named_case cases[] = {
	{ "bind-flags", case_bind_flags },
	{ "one-callback-per-plan", case_one_callback_per_plan },
	{ "event-forward", case_event_forward },
	{ "event-poisoned", case_event_poisoned },
	{ "event-unbind-pending", case_event_unbind_pending },
	{ "invalidate", case_invalidate },
	{ "progress-watermark", case_progress_watermark },
	{ "resolve-before-push", case_resolve_before_push },
	{ "plan-before-push", case_plan_before_push },
};

int main(int argc, char **argv)
{
	unsigned int i;
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc != 2) {
		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
			printf("%s\n", cases[i].name);
		return 2;
	}
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		if (!strcmp(argv[1], cases[i].name)) {
			cases[i].fn();
			return env_report(argv[1]);
		}
	printf("unknown case %s\n", argv[1]);
	return 2;
}

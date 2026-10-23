/* SPDX-License-Identifier: MIT */
/*
 * Host fixture for the vidmem window owner chain (G07 controls, G12-G14):
 * actual RmP2PUmemVidmemResolve / RmP2PUmemVidmemUnbind (p2p.c), the
 * rm_p2p_umem_vidmem_bind / _unbind bridges (osapi.c) and nv_p2p_vidmem_bind /
 * _unbind (nv-p2p.c) compiled together.  Stubs: the RM API lock, the RM
 * client/handle lookup, RM Free/DupObject, allocation lookup, device
 * references and allocation. RmP2PUmemVidmemBind is also the actual body.
 * No GPU exists.
 * HARNESS_RM_UNBIND_STATUS / HARNESS_NV_UNBIND_STATUS select the return type
 * the production bodies declare (void today, NV_STATUS per the contract).
 */
#include <stddef.h>
#include "nv_xdev_ext_host_env.h"

#ifndef HARNESS_RM_UNBIND_STATUS
#define HARNESS_RM_UNBIND_STATUS 0
#endif
#ifndef HARNESS_NV_UNBIND_STATUS
#define HARNESS_NV_UNBIND_STATUS 0
#endif

static struct {
	int lock_held;
	NV_STATUS lock_status, free_status, dup_status;
	unsigned int frees, lock_acquires, lock_releases, assert_fail;
	unsigned int inner_allocs, inner_frees, outer_allocs, outer_frees;
	int dev_refs;
	unsigned int dev_gets, dev_puts;
	int stack_fail, dev_get_fail, uuid_null;
	NvU8 rm_uuid[16];
	char order[256];
	void *outer;
	unsigned int lookups, wrong_gpu;
	NvU64 allocation_offset;
} T;
static void order(const char *s)
{
	if (strlen(T.order) + strlen(s) + 2 < sizeof(T.order)) {
		strcat(T.order, s);
		strcat(T.order, " ");
	}
}

/* ---------------------------------------------------------------- RM */
#define NV_ASSERT(c) do { if (!(c)) T.assert_fail++; } while (0)
#define NV_ASSERT_OK(e) do { NV_STATUS s_ = (e); if (s_ != NV_OK) T.assert_fail++; } while (0)
#define NV_ASSERT_OR_RETURN(c, e) do { if (!(c)) { T.assert_fail++; return (e); } } while (0)
#define NV_PRINTF(...) ((void)0)
#define RM_SHA1_GID_SIZE 16
#define GPU_UUID_LEN 16
#define ct_assert(c) _Static_assert(c, #c)
typedef struct OBJGPU { int id; } OBJGPU;
typedef struct MEMORY_DESCRIPTOR { int id; } MEMORY_DESCRIPTOR;
typedef struct { MEMORY_DESCRIPTOR *pMemDesc; } Memory;
typedef struct { int id; } RsClient;
typedef struct RM_API RM_API;
struct RM_API {
	NV_STATUS (*Free)(RM_API *, NvHandle, NvHandle);
	NV_STATUS (*DupObject)(RM_API *, NvHandle, NvHandle, NvHandle *, NvHandle, NvHandle, NvU32);
};
#define RMAPI_GPU_LOCK_INTERNAL 1
static NV_STATUS stub_free(RM_API *api, NvHandle client, NvHandle object)
{
	(void)api; (void)client; (void)object;
	T.frees++;
	order("rm_free");
	return T.free_status;
}
static NV_STATUS stub_dup(RM_API *api, NvHandle client, NvHandle parent,
	NvHandle *out, NvHandle src_client, NvHandle src, NvU32 flags)
{
	(void)api; (void)client; (void)parent; (void)src_client; (void)src; (void)flags;
	*out = 0xd1;
	return NV_OK;
}
static RM_API stub_api = { stub_free, stub_dup };
static RM_API *rmapiGetInterface(int which) { (void)which; return &stub_api; }
static int rmapiLockIsOwner(void) { return T.lock_held; }
static struct { int unused; } g_resServ;
static RsClient stub_client;
static MEMORY_DESCRIPTOR md_bound, md_other;
static Memory stub_memory = { &md_bound };
static NV_STATUS serverGetClientUnderLock(void *srv, NvHandle h, RsClient **c)
{
	(void)srv; (void)h;
	*c = &stub_client;
	return NV_OK;
}
static NV_STATUS memGetByHandle(RsClient *c, NvHandle h, Memory **m)
{
	(void)c; (void)h;
	if (T.dup_status != NV_OK)
		return T.dup_status;
	*m = &stub_memory;
	return NV_OK;
}
#define portMemFree(p) do { T.inner_frees++; order("inner_free"); free(p); } while (0)

#include "nv_xdev_ext_vidmem_owner_types.h"   /* P2P_UMEM_VIDMEM_BINDING (p2p.h) */

static OBJGPU gpu0 = { 0 }, gpu1 = { 1 };
typedef struct { NvHandle hClient; } ThirdPartyP2P;
typedef struct { int unused; } CLI_THIRD_PARTY_P2P_VASPACE_INFO;
typedef struct { NvHandle hMemory; } CLI_THIRD_PARTY_P2P_VIDMEM_INFO;
typedef struct { NvHandle hClient, hDevice, hSubdevice; } MemoryManager;
static ThirdPartyP2P third_party = { 0xc0 };
static CLI_THIRD_PARTY_P2P_VIDMEM_INFO vidmem_info = { 0xd0 };
static MemoryManager manager = { 0xc1, 0xe1, 0xf1 };
#define GPU_GET_MEMORY_MANAGER(g) ((void)(g), &manager)
#define NV01_NULL_OBJECT 0
#define ADDR_FBMEM 2
#define AT_GPU 1
#define NV_INLINE inline
#include "../src/nvidia/inc/kernel/mem_mgr/p2p_umem_vidmem.h"
static NV_STATUS RmP2PGetInfoWithoutToken(NvU64 va, NvU64 len, void *unused,
	ThirdPartyP2P **p, CLI_THIRD_PARTY_P2P_VASPACE_INFO **v, void *other)
{
	(void)va; (void)len; (void)unused; (void)v; (void)other;
	T.lookups++;
	*p = &third_party;
	return NV_OK;
}
static NV_STATUS RmP2PValidateSubDevice(ThirdPartyP2P *p, OBJGPU **g)
{ (void)p; *g = T.wrong_gpu ? &gpu1 : &gpu0; return NV_OK; }
static NvBool gpuIsApmFeatureEnabled(OBJGPU *g) { (void)g; return NV_FALSE; }
#define IS_MIG_ENABLED(g) ((void)(g), 0)
static NV_STATUS CliGetThirdPartyP2PVidmemInfoFromAddress(ThirdPartyP2P *p,
	NvU64 va, NvU64 len, NvU64 *off, CLI_THIRD_PARTY_P2P_VIDMEM_INFO **v)
{ (void)p; (void)va; (void)len; *off = T.allocation_offset; *v = &vidmem_info; return NV_OK; }
static int memdescGetAddressSpace(MEMORY_DESCRIPTOR *m) { (void)m; return ADDR_FBMEM; }
static NvU64 memdescGetSize(MEMORY_DESCRIPTOR *m) { (void)m; return 1 << 22; }
static NvU64 memdescGetPteAdjust(MEMORY_DESCRIPTOR *m) { (void)m; return 0; }
static NvU64 memdescGetPageSize(MEMORY_DESCRIPTOR *m, int at) { (void)m; (void)at; return 65536; }
static NvBool memdescGetContiguity(MEMORY_DESCRIPTOR *m, int at) { (void)m; (void)at; return NV_FALSE; }
#define portMemSet(p, v, n) memset((p), (v), (n))
static void *portMemAllocNonPaged(size_t size)
{
	T.inner_allocs++;
	return calloc(1, size);
}

/* osapi bridge environment */
typedef struct { int unused; } nvidia_stack_t;
typedef struct { int unused; } THREAD_STATE_NODE;
#define THREAD_STATE_FLAGS_NONE 0
#define API_LOCK_FLAGS_NONE 0
#define RM_LOCK_MODULES_P2P 0
#define NV_ENTER_RM_RUNTIME(sp, fp) ((void)(sp), (fp) = NULL)
#define NV_EXIT_RM_RUNTIME(sp, fp) ((void)(sp), (void)(fp))
static void threadStateInit(THREAD_STATE_NODE *t, int f) { (void)t; (void)f; }
static void threadStateFree(THREAD_STATE_NODE *t, int f) { (void)t; (void)f; }
static NV_STATUS rmapiLockAcquire(int flags, int module)
{
	(void)flags; (void)module;
	T.lock_acquires++;
	if (T.lock_status != NV_OK)
		return T.lock_status;
	T.lock_held = 1;
	return NV_OK;
}
static void rmapiLockRelease(void) { T.lock_held = 0; T.lock_releases++; }
#define DRF_DEF(a, b, c, d) 0
static OBJGPU *gpumgrGetGpuFromUuid(const NvU8 *id, unsigned int flags)
{ (void)id; (void)flags; return &gpu0; }
#define NV_GET_NV_STATE(g) ((void *)(g))
static const NvU8 *RmGetGpuUuidRaw(void *nv) { (void)nv; return T.uuid_null ? NULL : T.rm_uuid; }
#define os_mem_copy(d, s, n) memcpy((d), (s), (n))

/* ---------------------------------------------------------- kernel-open */
#define NVIDIA_P2P_GPU_UUID_LEN 16
#define NV_DBG_ERRORS 4
#define nv_printf(...) ((void)0)
#define WARN_ON(c) ({ int w_ = !!(c); w_; })
#define GFP_KERNEL 0
static void *kzalloc(size_t n, int g)
{
	void *p = calloc(1, n);
	(void)g;
	T.outer_allocs++;
	T.outer = p;
	return p;
}
static void kfree(void *p)
{
	if (!p)
		return;
	if (p == T.outer) {
		T.outer_frees++;
		order("outer_free");
	}
	free(p);
}
static nvidia_stack_t stack_storage;
static int nv_kmem_cache_alloc_stack(nvidia_stack_t **sp)
{
	if (T.stack_fail)
		return -ENOMEM;
	*sp = &stack_storage;
	return 0;
}
static void nv_kmem_cache_free_stack(nvidia_stack_t *sp) { (void)sp; }
static int nvidia_dev_get_uuid(const NvU8 *uuid, nvidia_stack_t *sp)
{
	(void)uuid; (void)sp;
	if (T.dev_get_fail)
		return -ENODEV;
	T.dev_gets++;
	T.dev_refs++;
	return 0;
}
static void nvidia_dev_put_uuid(const NvU8 *uuid, nvidia_stack_t *sp)
{
	(void)uuid; (void)sp;
	T.dev_puts++;
	T.dev_refs--;
	order("dev_put");
}
#include "../kernel-open/nvidia/nv-p2p-gpu-identity.h"
typedef struct nv_p2p_vidmem_binding nv_p2p_vidmem_binding_t;

#define THIS_MODULE NULL
#define __module_get(m) ((void)(m))
#include "nv_xdev_ext_vidmem_owner_actual.inc"

/* ================================================================ cases */
static nv_p2p_vidmem_binding_t *outer_residual;
static P2P_UMEM_VIDMEM_BINDING *inner_residual;
static void *bridge_residual;
static const NvU8 opened_uuid[16] = { 0x10, 0x20, 0x30 };

static nv_p2p_vidmem_binding_t *bind_ok(void)
{
	nv_p2p_vidmem_binding_t *b = NULL;
	NvU32 seg = 0;
	NV_STATUS st;
	memcpy(T.rm_uuid, opened_uuid, 16);
	st = nv_p2p_vidmem_bind(opened_uuid, 0x7f0000000000ULL, 1 << 20, &b, &seg, &outer_residual);
	if (st != NV_OK || !b)
		printf("FAIL bind_ok: status 0x%x\n", st);
	return b;
}

#if HARNESS_NV_UNBIND_STATUS
#define NV_UNBIND(b) nv_p2p_vidmem_unbind(b)
#else
#define NV_UNBIND(b) (nv_p2p_vidmem_unbind(b), (NV_STATUS)NV_OK)
#endif
#if HARNESS_RM_UNBIND_STATUS
#define RM_UNBIND(b) RmP2PUmemVidmemUnbind(b)
#else
#define RM_UNBIND(b) (RmP2PUmemVidmemUnbind(b), (NV_STATUS)NV_OK)
#endif

/* G07 controls */
static void case_bind_range(void)
{
	const NvU64 va[] = { 0, UINT64_MAX - 4095, 4096 };
	const NvU64 len[] = { 4096, 8192, 0 };
	unsigned int i;
	T.lock_held = 1;
	for (i = 0; i < 3; i++) {
		P2P_UMEM_VIDMEM_BINDING *b = (void *)1;
		CHECK(RmP2PUmemVidmemBind(va[i], len[i], &gpu0, &b, &inner_residual) == NV_ERR_INVALID_ARGUMENT && !b,
		      "G08: invalid VA range %u accepted", i);
	}
	CHECK(T.lookups == 0 && T.inner_allocs == 0, "G08: invalid VA reached allocation lookup");
	T.allocation_offset = (1 << 22) - 4096;
	{
		P2P_UMEM_VIDMEM_BINDING *b = NULL;
		CHECK(RmP2PUmemVidmemBind(4096, 8192, &gpu0, &b, &inner_residual) == NV_ERR_INVALID_ARGUMENT && !b,
		      "G08: allocation window overflow accepted");
		CHECK(T.frees == 1, "G08: rejected window must release its acquired dup");
	}
}
static void case_resolve(void)
{
	P2P_UMEM_VIDMEM_BINDING b = { .pGpu = &gpu0, .hClient = 1, .hMemory = 2,
				      .pMemDesc = &md_bound };
	MEMORY_DESCRIPTOR *md = NULL;
	T.lock_held = 1;
	CHECK(RmP2PUmemVidmemResolve(&b, &gpu1, &md) == NV_ERR_INVALID_DEVICE && !md,
	      "G07: wrong GPU must fail resolve");
	T.dup_status = NV_ERR_OBJECT_NOT_FOUND;
	CHECK(RmP2PUmemVidmemResolve(&b, &gpu0, &md) == NV_ERR_INVALID_STATE && !md,
	      "G07: missing dup must fail resolve");
	T.dup_status = NV_OK;
	stub_memory.pMemDesc = &md_other;
	CHECK(RmP2PUmemVidmemResolve(&b, &gpu0, &md) == NV_ERR_INVALID_STATE && !md,
	      "G07: changed memdesc identity must fail resolve");
	stub_memory.pMemDesc = &md_bound;
	CHECK(RmP2PUmemVidmemResolve(&b, &gpu0, &md) == NV_OK && md == &md_bound,
	      "G07: bound allocation must resolve");
	T.lock_held = 0;
	md = NULL;
	CHECK(RmP2PUmemVidmemResolve(&b, &gpu0, &md) != NV_OK && !md,
	      "G07: resolve without the API lock must fail");
}

static void case_bind_wrong_gpu_before_dup(void)
{
    nv_p2p_vidmem_binding_t *b = NULL;
    NV_STATUS status;
    memcpy(T.rm_uuid, opened_uuid, 16);
    T.wrong_gpu = 1;
    status = nv_p2p_vidmem_bind(opened_uuid, 4096, 4096, &b, NULL, &outer_residual);
    CHECK(status == NV_ERR_INVALID_DEVICE && !b && !outer_residual,
          "binding accepted an allocation on a GPU whose device is not held");
    CHECK(T.inner_allocs == 0 && T.frees == 0 && T.dev_refs == 0,
          "wrong GPU reached allocation dup before device identity check");
}

static void case_bind_uuid_mismatch(void)
{
	nv_p2p_vidmem_binding_t *b = (void *)0x1;
	NV_STATUS st;
	static const NvU8 other[16] = { 0x99 };
	memcpy(T.rm_uuid, other, 16);
	st = nv_p2p_vidmem_bind(opened_uuid, 0x7f0000000000ULL, 1 << 20, &b, NULL, &outer_residual);
	CHECK(st == NV_ERR_INVALID_DEVICE && b == NULL, "G07: mismatched UUID status 0x%x", st);
	CHECK(T.frees == 1 && T.inner_frees == 1, "G07: dup not dropped once (free=%u inner=%u)",
	      T.frees, T.inner_frees);
	CHECK(T.dev_refs == 0 && T.outer_frees == 1, "G07: device ref %d outer frees %u",
	      T.dev_refs, T.outer_frees);
	CHECK(T.lock_held == 0 && T.lock_acquires == T.lock_releases, "lock imbalance");
}

/* G12: API-lock failure in the outer unbind keeps every owner. */
static void case_unbind_lock_fail(void)
{
	nv_p2p_vidmem_binding_t *b = bind_ok();
	NV_STATUS st;
	REQUIRE(b, "bind");
	T.order[0] = 0;
	T.lock_status = NV_ERR_INVALID_LOCK_STATE;
	st = NV_UNBIND(b);
	CHECK(HARNESS_NV_UNBIND_STATUS, "G12: nv_p2p_vidmem_unbind returns void; its caller "
	      "cannot learn that the window is still bound");
	CHECK(st != NV_OK, "G12: lock failure reported success");
	CHECK(T.frees == 0 && T.inner_frees == 0, "G12: RM dup or inner binding released");
	CHECK(T.dev_puts == 0 && T.dev_refs == 1,
	      "G12: device reference dropped after a failed RM unbind (puts=%u)", T.dev_puts);
	CHECK(T.outer_frees == 0, "G12: outer binding freed after a failed RM unbind");
	T.lock_status = NV_OK;
	if (T.outer_frees == 0) {
		st = NV_UNBIND(b);    /* explicit retry succeeds and releases once */
		CHECK(st == NV_OK && T.frees == 1 && T.dev_puts == 1 && T.outer_frees == 1,
		      "G12: retry after lock failure (st=0x%x free=%u put=%u outer=%u)", st,
		      T.frees, T.dev_puts, T.outer_frees);
	}
}

static void case_bridge_lock_fail(void)
{
	nvidia_stack_t *sp = &stack_storage;
	P2P_UMEM_VIDMEM_BINDING *inner = NULL;
	NvU8 uuid[16];
	NvU32 seg;
	memcpy(T.rm_uuid, opened_uuid, 16);
	REQUIRE(rm_p2p_umem_vidmem_bind(sp, 1, 1 << 20, opened_uuid, uuid, &seg, (void **)&inner, &bridge_residual) == NV_OK,
		"bridge bind");
	T.lock_status = NV_ERR_INVALID_LOCK_STATE;
	CHECK(rm_p2p_umem_vidmem_unbind(sp, inner) == NV_ERR_INVALID_LOCK_STATE,
	      "G12: bridge must report the lock failure");
	CHECK(T.inner_frees == 0 && T.frees == 0, "G12: bridge released under lock failure");
	T.lock_status = NV_OK;
	CHECK(rm_p2p_umem_vidmem_unbind(sp, inner) == NV_OK && T.inner_frees == 1,
	      "bridge retry");
}

/* G13: RM Free failure is propagated and preserves the binding. */
static void case_rm_free_fail(void)
{
	P2P_UMEM_VIDMEM_BINDING *inner = calloc(1, sizeof(*inner));
	NV_STATUS st;
	inner->pGpu = &gpu0;
	inner->hClient = 5;
	inner->hMemory = 6;
	T.lock_held = 1;
	T.free_status = NV_ERR_INVALID_OBJECT;
	st = RM_UNBIND(inner);
	CHECK(HARNESS_RM_UNBIND_STATUS, "G13: RmP2PUmemVidmemUnbind returns void; Free "
	      "failure cannot be propagated");
	CHECK(st == NV_ERR_INVALID_OBJECT, "G13: Free failure not propagated (0x%x)", st);
	CHECK(T.inner_frees == 0, "G13: binding freed although RM Free failed; the dup "
	      "handle 0x%x is now unrecoverable", 6);
	T.lock_held = 0;
}

static void case_outer_rm_free_fail(void)
{
	nv_p2p_vidmem_binding_t *b = bind_ok();
	NV_STATUS st;
	REQUIRE(b, "bind");
	T.free_status = NV_ERR_INVALID_OBJECT;
	st = NV_UNBIND(b);
	CHECK(st != NV_OK, "G13: outer unbind reported success after RM Free failed");
	CHECK(T.inner_frees == 0, "G13: inner binding freed after RM Free failed");
	CHECK(T.dev_puts == 0 && T.outer_frees == 0,
	      "G13: device ref dropped (%u) or outer freed (%u) after RM Free failed",
	      T.dev_puts, T.outer_frees);
}

static void case_bind_cleanup_free_fail(void)
{
	nv_p2p_vidmem_binding_t *b = (void *)0x1;
	static const NvU8 other[16] = { 0x99 };
	NV_STATUS st;
	memcpy(T.rm_uuid, other, 16);
	T.free_status = NV_ERR_INVALID_OBJECT;
	st = nv_p2p_vidmem_bind(opened_uuid, 0x7f0000000000ULL, 1 << 20, &b, NULL, &outer_residual);
	CHECK(st != NV_OK && b == NULL, "mismatch must fail");
	CHECK(outer_residual && outer_residual->rm, "failed bind lost residual ownership");
	CHECK(T.inner_frees == 0, "G13: mismatch cleanup freed the binding after Free failed");
	CHECK(T.dev_puts == 0 && T.dev_refs == 1 && T.outer_frees == 0,
	      "G12: mismatch cleanup dropped the device ref (%u) or outer binding (%u) after "
	      "the RM unbind failed", T.dev_puts, T.outer_frees);
}

static void case_bridge_uuid_null_free_fail(void)
{
	nvidia_stack_t *sp = &stack_storage;
	void *inner = (void *)0x1;
	NvU8 uuid[16];
	NvU32 seg;
	T.uuid_null = 1;
	T.free_status = NV_ERR_INVALID_OBJECT;
	CHECK(rm_p2p_umem_vidmem_bind(sp, 1, 1 << 20, opened_uuid, uuid, &seg, &inner, &bridge_residual) ==
	      NV_ERR_GPU_UUID_NOT_FOUND && inner == NULL, "uuid lookup failure");
	CHECK(bridge_residual != NULL, "UUID failure lost retained RM binding");
	CHECK(T.inner_frees == 0, "G13: bridge cleanup freed a binding whose dup Free failed");
	CHECK(T.lock_held == 0, "lock left held");
}

/* G14: success releases once in order, stack failure keeps everything. */
static void case_unbind_success_order(void)
{
	nv_p2p_vidmem_binding_t *b = bind_ok();
	REQUIRE(b, "bind");
	T.order[0] = 0;
	CHECK(NV_UNBIND(b) == NV_OK, "unbind");
	CHECK(T.frees == 1 && T.inner_frees == 1 && T.dev_puts == 1 && T.outer_frees == 1,
	      "G14: free=%u inner=%u put=%u outer=%u", T.frees, T.inner_frees, T.dev_puts,
	      T.outer_frees);
	{
		const char *f = strstr(T.order, "rm_free"), *p = strstr(T.order, "dev_put"),
			   *o = strstr(T.order, "outer_free");
		CHECK(f && p && o && f < p && p < o,
		      "G14: order must be rm_free < dev_put < outer_free: '%s'", T.order);
	}
	CHECK(T.assert_fail == 0 && T.dev_refs == 0, "asserts=%u refs=%d", T.assert_fail,
	      T.dev_refs);
}

static void case_unbind_stack_fail(void)
{
	nv_p2p_vidmem_binding_t *b = bind_ok();
	NV_STATUS st;
	REQUIRE(b, "bind");
	T.stack_fail = 1;
	st = NV_UNBIND(b);
	(void)st;
#if HARNESS_NV_UNBIND_STATUS
	CHECK(st == NV_ERR_NO_MEMORY, "G14: stack failure status 0x%x", st);
#endif
	CHECK(T.frees == 0 && T.dev_puts == 0 && T.outer_frees == 0,
	      "G14 control: stack failure must retain everything");
}

struct named_case { const char *name; void (*fn)(void); };
static const struct named_case cases[] = {
	{ "resolve", case_resolve },
	{ "bind-range", case_bind_range },
	{ "bind-uuid-mismatch", case_bind_uuid_mismatch },
    { "bind-wrong-gpu-before-dup", case_bind_wrong_gpu_before_dup },
	{ "unbind-lock-fail", case_unbind_lock_fail },
	{ "bridge-lock-fail", case_bridge_lock_fail },
	{ "rm-free-fail", case_rm_free_fail },
	{ "outer-rm-free-fail", case_outer_rm_free_fail },
	{ "bind-cleanup-free-fail", case_bind_cleanup_free_fail },
	{ "bridge-uuid-null-free-fail", case_bridge_uuid_null_free_fail },
	{ "unbind-success-order", case_unbind_success_order },
	{ "unbind-stack-fail", case_unbind_stack_fail },
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

/* SPDX-License-Identifier: MIT */
/*
 * Host fixture for the native peer cleanup boundary (G15-G17): actual
 * nv_p2p_put_pages / nvidia_p2p_put_pages_persistent / nv_p2p_free_page_table,
 * nv_p2p_remove_dma_mapping / nv_p2p_free_dma_mapping /
 * nvidia_p2p_dma_unmap_pages (nv-p2p.c) and the owned provider's
 * nv_xdev_ext_peer_pin / _unpin / _unmap (nv-xdev_ext-peer.c).  Stubs: RM
 * persistent put, OS allocation, the OS DMA unmap helpers, device references
 * and a persistent-get that builds a page table the way the real one returns
 * it (mem_info with page_table, device reference taken).  No GPU, peer device
 * or DMA mapping exists here.
 */
#include <stddef.h>
#include <stdbool.h>
#include "nv_xdev_ext_host_env.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define GFP_KERNEL 0
#define NV_DBG_ERRORS 4
#define nv_printf(...) ((void)0)
#define WARN_ON(c) ({ int w_ = !!(c); if (w_) S.warns++; w_; })
#define BUG_ON(c) do { if (c) { printf("BUG_ON(%s)\n", #c); abort(); } } while (0)
#define NV_EXPORT_SYMBOL(x)
#define NV_ARRAY_ELEMENTS(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define do_div(n, base) ({ uint32_t r_ = (uint32_t)((n) % (base)); (n) /= (base); r_; })
#define os_mem_copy(d, s, n) memcpy((d), (s), (n))
#define NVRM_P2P_PAGESIZE_SMALL_4K (4u << 10)
#define NVRM_P2P_PAGESIZE_BIG_64K (64u << 10)
#define NVRM_P2P_PAGESIZE_BIG_128K (128u << 10)

struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(h) do { (h)->next = (h); (h)->prev = (h); } while (0)
static void list_add_tail(struct list_head *n, struct list_head *h)
{ n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n; }
static void list_del(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; n->next = n->prev = NULL; }
static int list_empty(const struct list_head *h) { return h->next == h; }
#define list_for_each_entry(pos, head, member) \
	for (pos = container_of((head)->next, __typeof__(*pos), member); \
	     &pos->member != (head); \
	     pos = container_of(pos->member.next, __typeof__(*pos), member))
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }
struct semaphore { int count; };
#define DEFINE_MUTEX(n) struct semaphore n
#define mutex_lock(s) down(s)
#define mutex_unlock(s) up(s)
static void down(struct semaphore *s) { s->count--; }
static void up(struct semaphore *s) { s->count++; }

struct device { int id; };
struct pci_dev { struct device dev; u64 dma_mask; };
struct module { int refs; };
struct file_operations { int unused; };
struct inode { int minor; };
struct file { struct inode *inode; void *private_data; };
static struct module harness_module;
#define THIS_MODULE (&harness_module)
#define __module_get(m) ((void)((m)->refs++))
struct nv_dma_device {
	struct { NvU64 start; NvU64 limit; } addressable_range;
	struct device *dev;
};
typedef struct nv_dma_device nv_dma_device_t;

static struct {
	unsigned int os_allocs, os_frees, fail_os_alloc_at, warns;
	int live_os;
	NV_STATUS rm_put_status, unmap_status;
	unsigned int rm_puts, rm_maps, unmap_alloc_calls, unmap_peer_calls;
	NvU64 unmap_count, unmap_addrs[64];
	int dev_refs;
	unsigned int dev_puts, kfrees, kallocs;
	void *live_k[16];
	unsigned int live_k_count;
	const NvU8 *opened_uuid;
	NvU8 table_uuid[16];
} S;

static NV_STATUS os_alloc_mem(void **p, NvU64 n)
{
	S.os_allocs++;
	if (S.fail_os_alloc_at && S.os_allocs == S.fail_os_alloc_at) {
		*p = NULL;
		return NV_ERR_NO_MEMORY;
	}
	*p = calloc(1, n ? n : 1);
	S.live_os++;
	return NV_OK;
}
static void os_free_mem(void *p) { if (p) { S.os_frees++; S.live_os--; free(p); } }
static void *nvidia_p2p_page_t_cache;
#define NV_KMEM_CACHE_FREE(p, cache) ((void)(cache), os_free_mem(p))
static NV_STATUS nv_dma_unmap_alloc(nv_dma_device_t *d, NvU64 count, NvU64 *va, void **priv)
{
	NvU64 i;
	(void)d;
	S.unmap_alloc_calls++;
	S.unmap_count = count;
	for (i = 0; i < count && i < 64; i++)
		S.unmap_addrs[i] = va[i];
	if (S.unmap_status != NV_OK)
		return S.unmap_status;
	*priv = NULL;
	return NV_OK;
}
static void nv_dma_unmap_peer(nv_dma_device_t *d, NvU64 n, NvU64 va)
{ (void)d; (void)n; (void)va; S.unmap_peer_calls++; }

typedef struct { int unused; } nvidia_stack_t;
static nvidia_stack_t stack_storage;
static int nv_kmem_cache_alloc_stack(nvidia_stack_t **sp) { *sp = &stack_storage; return 0; }
static void nv_kmem_cache_free_stack(nvidia_stack_t *sp) { (void)sp; }
static NV_STATUS rm_p2p_put_pages_persistent(nvidia_stack_t *sp, void *priv, void *pt, void *mig)
{ (void)sp; (void)priv; (void)pt; (void)mig; S.rm_puts++; return S.rm_put_status; }
static NV_STATUS rm_p2p_put_pages(nvidia_stack_t *sp, uint64_t t, uint32_t v, uint64_t va,
				  void *pt)
{ (void)sp; (void)t; (void)v; (void)va; (void)pt; S.rm_puts++; return S.rm_put_status; }
static void nvidia_dev_put_uuid(const NvU8 *uuid, nvidia_stack_t *sp)
{ (void)uuid; (void)sp; S.dev_puts++; S.dev_refs--; }

#include "nv_xdev_ext_native_peer_public.h"   /* nv-p2p.h public structs, exact bytes */
static NV_STATUS rm_p2p_dma_map_pages(nvidia_stack_t *sp, nv_dma_device_t *dev,
    NvU8 *uuid, NvU64 page_size, NvU32 count, NvU64 *addresses, void **private)
{
    (void)sp; (void)dev; (void)uuid; (void)page_size; (void)count; (void)addresses;
    S.rm_maps++; *private = (void *)0x1234; return NV_OK;
}
#include "nv_xdev_ext_native_peer_p2p.inc"    /* nv-p2p.c actual bodies */

/* ---------------------------------------------- owned provider environment */
typedef struct {
	NvBool mem_has_struct_page;
	NvBool coherent;
	NvBool is_external_gpu;
} nv_state_t;
typedef struct { nv_state_t nv_state; struct pci_dev *pci_dev; } nv_linux_state_t;
typedef struct { int open_rc; nv_linux_state_t *nvptr; } nv_linux_file_private_t;
#define NV_GET_LINUX_FILE_PRIVATE(f) ((nv_linux_file_private_t *)(f)->private_data)
#define NV_FILE_INODE(f) ((f)->inode)
#define NV_STATE_PTR(nvl) (&(nvl)->nv_state)
static int nv_is_control_device(struct inode *i) { return i->minor == 255; }
static int nv_wait_open_complete_interruptible(nv_linux_file_private_t *p) { (void)p; return 0; }
struct rw_semaphore { int readers; };
static struct rw_semaphore nv_system_pm_lock;
static void down_read(struct rw_semaphore *s) { s->readers++; }
static void up_read(struct rw_semaphore *s) { s->readers--; }
static int nv_down_read_interruptible(struct rw_semaphore *s) { down_read(s); return 0; }
static const NvU8 *rm_get_gpu_uuid_raw(nvidia_stack_t *sp, nv_state_t *nv)
{ (void)sp; (void)nv; return S.opened_uuid; }
static void *kzalloc(size_t n, int g)
{
	void *p = calloc(1, n);
	(void)g;
	S.kallocs++;
	if (S.live_k_count < 16)
		S.live_k[S.live_k_count++] = p;
	return p;
}
static void kfree(void *p)
{
	unsigned int i;
	if (!p)
		return;
	for (i = 0; i < S.live_k_count; i++)
		if (S.live_k[i] == p) {
			S.live_k[i] = S.live_k[--S.live_k_count];
			break;
		}
	S.kfrees++;
	free(p);
}
/* Persistent get: the real one allocates mem_info and takes a device ref. */
int nvidia_p2p_get_pages_persistent(uint64_t va, uint64_t len,
	struct nvidia_p2p_page_table **out, uint32_t flags)
{
	nv_p2p_mem_info_t *m;
	(void)va; (void)len; (void)flags;
	if (os_alloc_mem((void **)&m, sizeof(*m)) != NV_OK)
		return -ENOMEM;
	INIT_LIST_HEAD(&m->dma_mapping_list.list_head);
	m->page_table.version = NVIDIA_P2P_PAGE_TABLE_VERSION;
	m->page_table.page_size = NVIDIA_P2P_PAGE_SIZE_64KB;
	os_alloc_mem((void **)&m->page_table.gpu_uuid, NVIDIA_P2P_GPU_UUID_LEN);
	memcpy(m->page_table.gpu_uuid, S.table_uuid, NVIDIA_P2P_GPU_UUID_LEN);
	S.dev_refs++;
	*out = &m->page_table;
	return 0;
}
struct xdev_ext_peer_dma { void *private; const u64 *addresses; u32 entries; u8 page_shift; };
struct xdev_ext_peer_provider_ops {
	struct module *owner;
	const struct file_operations *fops;
	int (*pin)(struct file *, u64, u64, void **);
	int (*unpin)(void *);
	int (*map)(void *, struct pci_dev *, struct xdev_ext_peer_dma *);
	int (*unmap)(void *, struct pci_dev *, struct xdev_ext_peer_dma *);
};
#include "nv_xdev_ext_native_peer_provider.inc"   /* nv-xdev_ext-peer.c actual bodies */

/* ================================================================ cases */
static struct pci_dev peer = { .dev = { 3 }, .dma_mask = ~0ULL };
static const NvU8 uuid_a[16] = { 0xa };
static const NvU8 uuid_b[16] = { 0xb };

static struct nvidia_p2p_page_table *table(void)
{
	struct nvidia_p2p_page_table *pt = NULL;
	memcpy(S.table_uuid, uuid_a, 16);
	if (nvidia_p2p_get_pages_persistent(0x10000, 1 << 16, &pt, 0))
		return NULL;
	return pt;
}

static struct nvidia_p2p_dma_mapping *mapping(struct nvidia_p2p_page_table *pt)
{
	nv_p2p_mem_info_t *m = container_of(pt, nv_p2p_mem_info_t, page_table);
	struct nvidia_p2p_dma_mapping *d;
	os_alloc_mem((void **)&d, sizeof(*d));
	d->version = NVIDIA_P2P_DMA_MAPPING_VERSION;
	d->page_size_type = NVIDIA_P2P_PAGE_SIZE_64KB;
	d->entries = 2;
	d->pci_dev = &peer;
	d->private = (void *)0x1234;
	os_alloc_mem((void **)&d->dma_addresses, 2 * sizeof(NvU64));
	d->dma_addresses[0] = 0xC0000000ULL;
	d->dma_addresses[1] = 0xC0100000ULL;
	#if HARNESS_PREALLOC_API
	if (nv_p2p_insert_dma_mapping(m, d, NULL) != NV_OK)
#else
	if (nv_p2p_insert_dma_mapping(m, d) != NV_OK)
#endif
		return NULL;
	return d;
}

static int still_listed(struct nvidia_p2p_page_table *pt, struct nvidia_p2p_dma_mapping *d)
{
	nv_p2p_mem_info_t *m = container_of(pt, nv_p2p_mem_info_t, page_table);
	struct nv_p2p_dma_mapping *cur;
	list_for_each_entry(cur, &m->dma_mapping_list.list_head, list_node)
		if (cur->dma_mapping == d)
			return 1;
	return 0;
}

/* G15 */
static void case_put_fail_keeps_ref(void)
{
	struct nvidia_p2p_page_table *pt = table();
	int live, rc;
	REQUIRE(pt && S.dev_refs == 1, "table");
	live = S.live_os;
	S.rm_put_status = NV_ERR_INVALID_STATE;
	rc = nvidia_p2p_put_pages_persistent(0x10000, pt, 0);
	CHECK(rc != 0, "G15: failed persistent put reported success");
	CHECK(S.dev_puts == 0 && S.dev_refs == 1,
	      "G15: device reference dropped although the persistent table is still live "
	      "(puts=%u)", S.dev_puts);
	CHECK(S.live_os == live, "G15: page table storage freed after a failed put");
	S.rm_put_status = NV_OK;
	rc = nvidia_p2p_put_pages_persistent(0x10000, pt, 0);
	CHECK(rc == 0 && S.dev_puts == 1 && S.dev_refs == 0,
	      "G15: retry must release the table and the device ref exactly once "
	      "(rc=%d puts=%u refs=%d)", rc, S.dev_puts, S.dev_refs);
}

static void case_table_cleanup_failure(void)
{
    struct nvidia_p2p_page_table *pt = table();
    struct nvidia_p2p_dma_mapping *d = mapping(pt);
    int live = S.live_os;
    REQUIRE(pt && d, "table and mapping");
    S.unmap_status = NV_ERR_INVALID_STATE;
    nv_p2p_free_page_table(pt);
    CHECK(S.live_os == live, "failed native table cleanup released retained objects");
    /* Avoid touching freed storage on a failing implementation. */
    if (S.live_os == live)
        CHECK(still_listed(pt, d), "failed native table cleanup lost mapping owner");
}

static void case_map_owner_preallocated(void)
{
    struct nvidia_p2p_page_table *pt = table();
    struct nvidia_p2p_dma_mapping *d = NULL;
    int live, rc;
    REQUIRE(pt, "table");
    os_alloc_mem((void **)&pt->pages, sizeof(*pt->pages));
    os_alloc_mem((void **)&pt->pages[0], sizeof(*pt->pages[0]));
    pt->entries = 1;
    pt->pages[0]->physical_address = 0xb0000000;
    live = S.live_os;
    /* mapping record, address array, then owner node: the third failure must
     * happen before the native RM mapping obtains device reachability. */
    S.fail_os_alloc_at = S.os_allocs + 3;
    rc = nvidia_p2p_dma_map_pages(&peer, pt, &d);
    CHECK(rc != 0 && !d && S.rm_maps == 0 && S.live_os == live,
          "native mapping acquired reachability before fallible owner allocation");
    S.fail_os_alloc_at = 0;
    CHECK(nvidia_p2p_dma_map_pages(&peer, pt, &d) == 0 && d && S.rm_maps == 1,
          "native mapping positive control");
    CHECK(nvidia_p2p_put_pages_persistent(0x10000, pt, 0) != 0 && S.rm_puts == 0,
          "persistent allocation released with a live DMA mapping");
    CHECK(nvidia_p2p_dma_unmap_pages(&peer, pt, d) == 0, "unmap");
    CHECK(nvidia_p2p_put_pages_persistent(0x10000, pt, 0) == 0 && S.live_os == 0,
          "unmap then put must release every owner");
}

static void case_put_success(void)
{
	struct nvidia_p2p_page_table *pt = table();
	REQUIRE(pt, "table");
	CHECK(nvidia_p2p_put_pages_persistent(0x10000, pt, 0) == 0, "put");
	CHECK(S.dev_puts == 1 && S.dev_refs == 0 && S.live_os == 0,
	      "control: puts=%u refs=%d live=%d", S.dev_puts, S.dev_refs, S.live_os);
}

/* G16 */
static void case_unmap_alloc_fail(void)
{
	struct nvidia_p2p_page_table *pt = table();
	struct nvidia_p2p_dma_mapping *d;
	int rc, live;
	REQUIRE(pt, "table");
	d = mapping(pt);
	REQUIRE(d, "mapping");
	live = S.live_os;
	S.fail_os_alloc_at = S.os_allocs + 1;   /* the temporary OS-page address array */
	rc = nvidia_p2p_dma_unmap_pages(&peer, pt, d);
	S.fail_os_alloc_at = 0;
	CHECK(S.unmap_alloc_calls == 0, "OS unmap ran without its address array");
	CHECK(rc != 0, "G16: unmap reported success although nothing was unmapped");
	CHECK(S.live_os == live, "G16: mapping record/address list freed with the mapping live "
	      "(live %d -> %d)", live, S.live_os);
	CHECK(S.live_os != live || still_listed(pt, d),
	      "G16: live mapping no longer owned by its page table");
	if (S.live_os == live) {
		rc = nvidia_p2p_dma_unmap_pages(&peer, pt, d);
		CHECK(rc == 0 && S.unmap_alloc_calls == 1 && S.unmap_count == 32,
		      "G16: retry must unmap 32 OS pages once (rc=%d calls=%u count=%llu)", rc,
		      S.unmap_alloc_calls, (unsigned long long)S.unmap_count);
	}
}

static void case_unmap_os_fail(void)
{
	struct nvidia_p2p_page_table *pt = table();
	struct nvidia_p2p_dma_mapping *d;
	int rc, live;
	REQUIRE(pt, "table");
	d = mapping(pt);
	REQUIRE(d, "mapping");
	live = S.live_os;
	S.unmap_status = NV_ERR_INVALID_STATE;
	rc = nvidia_p2p_dma_unmap_pages(&peer, pt, d);
	CHECK(S.unmap_alloc_calls == 1, "OS unmap not attempted");
	CHECK(rc != 0, "G16: failed OS unmap reported success");
	CHECK(S.live_os == live, "G16: mapping freed after failed OS unmap (live %d -> %d)", live,
	      S.live_os);
	S.unmap_status = NV_OK;
}

static void case_unmap_success(void)
{
	struct nvidia_p2p_page_table *pt = table();
	struct nvidia_p2p_dma_mapping *d;
	nv_p2p_mem_info_t *m;
	REQUIRE(pt, "table");
	d = mapping(pt);
	REQUIRE(d, "mapping");
	m = container_of(pt, nv_p2p_mem_info_t, page_table);
	CHECK(nvidia_p2p_dma_unmap_pages(&peer, pt, d) == 0, "unmap");
	CHECK(S.unmap_alloc_calls == 1 && S.unmap_count == 32 &&
	      S.unmap_addrs[0] == 0xC0000000ULL && S.unmap_addrs[1] == 0xC0001000ULL &&
	      S.unmap_addrs[16] == 0xC0100000ULL,
	      "control: inflated OS unmap list wrong (count=%llu)",
	      (unsigned long long)S.unmap_count);
	CHECK(list_empty(&m->dma_mapping_list.list_head), "control: mapping still listed");
}

static void case_peer_unmap_propagates(void)
{
	struct nvidia_p2p_page_table *pt = table();
	struct nv_xdev_ext_peer_allocation a;
	struct xdev_ext_peer_dma dma = { 0 };
	int rc;
	REQUIRE(pt, "table");
	a.pages = pt;
	a.va = 0x10000;
	dma.private = mapping(pt);
	REQUIRE(dma.private, "mapping");
	S.unmap_status = NV_ERR_INVALID_STATE;
	rc = nv_xdev_ext_peer_unmap(&a, &peer, &dma);
	CHECK(rc != 0, "G16: provider unmap returned success for a failed native unmap; the "
	      "common core cannot quarantine it");
	S.unmap_status = NV_OK;
}

/* G15 composed through the owned provider */
static void case_peer_unpin_fail(void)
{
	struct nvidia_p2p_page_table *pt = table();
	struct nv_xdev_ext_peer_allocation *a = kzalloc(sizeof(*a), 0);
	int rc;
	REQUIRE(pt, "table");
	a->pages = pt;
	a->va = 0x10000;
	S.rm_put_status = NV_ERR_INVALID_STATE;
	rc = nv_xdev_ext_peer_unpin(a);
	CHECK(rc != 0, "provider unpin reported success");
	CHECK(S.live_k_count == 1, "provider freed its allocation after a failed put");
	CHECK(S.dev_refs == 1, "G15: device reference dropped under a live persistent "
	      "allocation (refs=%d)", S.dev_refs);
	S.rm_put_status = NV_OK;
}

/* G17 */
static struct file gpu_file;
static struct inode gpu_inode;
static nv_linux_state_t gpu_nvl;
static nv_linux_file_private_t gpu_fpriv;
static void prepare_file(void)
{
	gpu_fpriv.nvptr = &gpu_nvl;
	gpu_file.inode = &gpu_inode;
	gpu_file.private_data = &gpu_fpriv;
}

static void case_peer_pin_mismatch_put_fail(void)
{
	void *out = NULL;
	int rc;
	prepare_file();
	S.opened_uuid = uuid_a;
	memcpy(S.table_uuid, uuid_b, 16);
	S.rm_put_status = NV_ERR_INVALID_STATE;
	rc = nv_xdev_ext_peer_pin(&gpu_file, 0x10000, 0x10000, &out);
	CHECK(rc == -EXDEV && out == NULL, "mismatch rc=%d", rc);
	CHECK(harness_module.refs == 1, "G17: module not pinned for the retained allocation");
	CHECK(!list_empty(&nv_xdev_ext_peer_quarantined), "G17: retained allocation is not reachable from quarantine");
	CHECK(S.dev_refs == 1, "G17: GPU device reference dropped although the persistent "
	      "allocation could not be released (refs=%d)", S.dev_refs);
	CHECK(S.live_os > 0, "G17: persistent page table freed after failed put");
}

static void case_peer_pin_mismatch_put_ok(void)
{
	void *out = NULL;
	int rc;
	prepare_file();
	S.opened_uuid = uuid_a;
	memcpy(S.table_uuid, uuid_b, 16);
	rc = nv_xdev_ext_peer_pin(&gpu_file, 0x10000, 0x10000, &out);
	CHECK(rc == -EXDEV && out == NULL, "mismatch rc=%d", rc);
	CHECK(harness_module.refs == 0 && S.dev_refs == 0 && S.live_os == 0 &&
	      S.live_k_count == 0,
	      "control: clean mismatch must release everything (mod=%d refs=%d os=%d k=%u)",
	      harness_module.refs, S.dev_refs, S.live_os, S.live_k_count);
}

struct named_case { const char *name; void (*fn)(void); };
static const struct named_case cases[] = {
	{ "put-fail-keeps-ref", case_put_fail_keeps_ref },
	{ "put-success", case_put_success },
    { "table-cleanup-failure", case_table_cleanup_failure },
    { "map-owner-preallocated", case_map_owner_preallocated },
	{ "unmap-alloc-fail", case_unmap_alloc_fail },
	{ "unmap-os-fail", case_unmap_os_fail },
	{ "unmap-success", case_unmap_success },
	{ "peer-unmap-propagates", case_peer_unmap_propagates },
	{ "peer-unpin-fail", case_peer_unpin_fail },
	{ "peer-pin-mismatch-put-fail", case_peer_pin_mismatch_put_fail },
	{ "peer-pin-mismatch-put-ok", case_peer_pin_mismatch_put_ok },
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

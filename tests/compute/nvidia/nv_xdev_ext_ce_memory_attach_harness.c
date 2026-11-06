/* SPDX-License-Identifier: MIT */
/*
 * Host fixture for NV_ESC_XDEV_EXT_CE_ATTACH_MEMORY: the actual
 * nv_xdev_ext_ce_memory_attach() and _release() bodies (nv.c) with the ioctl
 * struct (nv-ioctl.h) and nv-xdev_ext-ce-memory.h.  Stubs: the export fd
 * lookup (nv_get_file_private / nv_put_file_private) and allocation.
 */
#include <stddef.h>
#include "nv_xdev_ext_host_env.h"

#define NV_ALIGN_BYTES(n) __attribute__((aligned(n)))
#define GFP_KERNEL 0
#define cmpxchg(p, o, n) __sync_val_compare_and_swap(p, o, n)
#define xchg(p, v) __atomic_exchange_n(p, v, __ATOMIC_SEQ_CST)
#include "../kernel-open/nvidia/nv-xdev_ext-ce-memory.h"
#include "nv_xdev_ext_ce_memory_attach_types.h"   /* the ioctl struct, exact bytes */

#include "nv_xdev_ext_ce_memory_attach_nvfp.h"   /* NVFP_TYPE_* (nv.h), exact bytes */
typedef struct nv_file_private_t { int id; NvU32 register_or_refcount; } nv_file_private_t;
typedef struct {
	nv_file_private_t nvfp;
	nv_xdev_ext_ce_memory_t *xdev_ext_ce_memory;
} nv_linux_file_private_t;
/* Only this driver's files carry an nv_linux_file_private_t. */
struct file_operations { int id; };
static struct file_operations nvidia_fops = { 1 }, foreign_fops = { 2 };
struct file { const struct file_operations *f_op; };

static struct {
	int lookups, puts, refs, allocs, frees, alloc_fail, not_ctl;
	int last_fd, last_ctl;
} S;
static nv_file_private_t export_fp = { 42, NVFP_TYPE_NONE };
static struct file export_file = { &nvidia_fops };

static nv_file_private_t *nv_get_file_private(NvS32 fd, NvBool ctl, void **os_private)
{
	S.lookups++;
	S.last_fd = fd;
	S.last_ctl = ctl;
	if (S.not_ctl)
		return NULL;
	S.refs++;
	*os_private = &export_file;
	return &export_fp;
}
static void nv_put_file_private(void *os_private)
{
	if (os_private != &export_file)
		S.puts += 1000;
	S.puts++;
	S.refs--;
}
static void *kzalloc(size_t n, int gfp)
{
	(void)gfp;
	if (S.alloc_fail)
		return NULL;
	S.allocs++;
	return calloc(1, n);
}
static void kfree(void *p)
{
	if (p)
		S.frees++;
	free(p);
}

#include "nv_xdev_ext_ce_memory_attach_actual.inc"

static nv_ioctl_xdev_ext_ce_attach_memory_t args(void)
{
	nv_ioctl_xdev_ext_ce_attach_memory_t p;
	memset(&p, 0, sizeof(p));
	p.mem_fd = 38;
	p.gpu_va = 0x7a4879200000ULL;
	p.size = 2 << 20;
	return p;
}

static void case_attach(void)
{
	nv_linux_file_private_t f = { 0 };
	nv_ioctl_xdev_ext_ce_attach_memory_t p = args();
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_OK, "attach");
	REQUIRE(f.xdev_ext_ce_memory, "nothing attached");
	CHECK(S.lookups == 1 && S.last_fd == 38 && S.last_ctl == NV_TRUE,
	      "export fd must be looked up once as a control fd (fd=%d ctl=%d)", S.last_fd, S.last_ctl);
	CHECK(f.xdev_ext_ce_memory->nvfp == &export_fp && f.xdev_ext_ce_memory->file == &export_file &&
	      f.xdev_ext_ce_memory->gpu_va == p.gpu_va && f.xdev_ext_ce_memory->size == p.size,
	      "attached record does not name the export and the mapping");
	CHECK(S.refs == 1, "the stage fd must hold the export fd (refs=%d)", S.refs);
	nv_xdev_ext_ce_memory_release(&f);
	CHECK(!f.xdev_ext_ce_memory && S.refs == 0 && S.puts == 1 && S.frees == 1,
	      "release: refs=%d puts=%d frees=%d", S.refs, S.puts, S.frees);
	nv_xdev_ext_ce_memory_release(&f);
	CHECK(S.puts == 1 && S.frees == 1, "a second release must do nothing");
}

static void case_bad_args(void)
{
	nv_linux_file_private_t f = { 0 };
	nv_ioctl_xdev_ext_ce_attach_memory_t p;
	p = args(); p.flags = 1;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_ERR_INVALID_ARGUMENT, "flags");
	p = args(); p.reserved = 1;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_ERR_INVALID_ARGUMENT, "reserved");
	p = args(); p.size = 0;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_ERR_INVALID_ARGUMENT, "size");
	p = args(); p.gpu_va = UINT64_MAX - 4095; p.size = 8192;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_ERR_INVALID_ARGUMENT, "wrap");
	CHECK(!f.xdev_ext_ce_memory && S.lookups == 0 && S.allocs == 0,
	      "invalid arguments reached the fd lookup (%d) or allocation (%d)", S.lookups, S.allocs);
}

static void case_not_control_fd(void)
{
	nv_linux_file_private_t f = { 0 };
	nv_ioctl_xdev_ext_ce_attach_memory_t p = args();
	S.not_ctl = 1;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_ERR_INVALID_OBJECT_HANDLE,
	      "an fd that is no NVIDIA control fd must be refused");
	CHECK(!f.xdev_ext_ce_memory && S.refs == 0 && S.allocs == S.frees,
	      "refused fd left state: refs=%d allocs=%d frees=%d", S.refs, S.allocs, S.frees);
}

static void case_alloc_fail(void)
{
	nv_linux_file_private_t f = { 0 };
	nv_ioctl_xdev_ext_ce_attach_memory_t p = args();
	S.alloc_fail = 1;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_ERR_NO_MEMORY, "allocation failure");
	CHECK(!f.xdev_ext_ce_memory && S.refs == 0, "allocation failure kept a reference");
}

/* Like NV_ESC_REGISTER_FD the stage fd now holds a control fd, so it takes
 * part in escape.c's cycle guard: an fd an RM object already holds through
 * its secInfo (NVFP_TYPE_REFCOUNTED) is refused, and an attached fd is
 * marked NVFP_TYPE_REGISTERED so no RM object can take it afterwards. */
static void case_reference_cycle_guard(void)
{
	nv_ioctl_xdev_ext_ce_attach_memory_t p = args();
	nv_linux_file_private_t f = { 0 };
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_OK &&
	      f.nvfp.register_or_refcount == NVFP_TYPE_REGISTERED,
	      "attach must register the stage fd (state %u)", f.nvfp.register_or_refcount);
	nv_xdev_ext_ce_memory_release(&f);
	f = (nv_linux_file_private_t){ .nvfp = { 7, NVFP_TYPE_REGISTERED } };
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_OK &&
	      f.nvfp.register_or_refcount == NVFP_TYPE_REGISTERED,
	      "a stage fd already registered by NV_ESC_REGISTER_FD may attach");
	nv_xdev_ext_ce_memory_release(&f);
	f = (nv_linux_file_private_t){ .nvfp = { 7, NVFP_TYPE_REFCOUNTED } };
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_ERR_IN_USE && !f.xdev_ext_ce_memory,
	      "a stage fd an RM object refcounts must not hold a control fd");
	CHECK(f.nvfp.register_or_refcount == NVFP_TYPE_REFCOUNTED, "refused attach changed the state");
	CHECK(S.refs == 0 && S.allocs == S.frees, "refused attach leaked: refs=%d allocs=%d frees=%d",
	      S.refs, S.allocs, S.frees);
}

static void case_foreign_file(void)
{
	nv_ioctl_xdev_ext_ce_attach_memory_t p = args();
	nv_linux_file_private_t f = { 0 };
	export_file.f_op = &foreign_fops;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_ERR_INVALID_OBJECT_HANDLE &&
	      !f.xdev_ext_ce_memory, "a file of another driver must be refused");
	CHECK(S.refs == 0 && S.allocs == S.frees && f.nvfp.register_or_refcount == NVFP_TYPE_NONE,
	      "foreign file left state: refs=%d", S.refs);
}

static void case_attach_twice(void)
{
	nv_linux_file_private_t f = { 0 };
	nv_ioctl_xdev_ext_ce_attach_memory_t p = args(), q = args();
	nv_xdev_ext_ce_memory_t *first;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &p) == NV_OK, "first attach");
	first = f.xdev_ext_ce_memory;
	q.gpu_va = 0x7a4879400000ULL;
	CHECK(nv_xdev_ext_ce_memory_attach(&f, &q) == NV_ERR_STATE_IN_USE,
	      "a stage fd names one allocation; a second attach must be refused");
	CHECK(f.xdev_ext_ce_memory == first && first->gpu_va == p.gpu_va,
	      "the second attach replaced the first");
	CHECK(S.refs == 1 && S.allocs == 2 && S.frees == 1,
	      "refused attach leaked: refs=%d allocs=%d frees=%d", S.refs, S.allocs, S.frees);
	nv_xdev_ext_ce_memory_release(&f);
	CHECK(S.refs == 0, "release");
}

struct named_case { const char *name; void (*fn)(void); };
static const struct named_case cases[] = {
	{ "attach", case_attach },
	{ "bad-args", case_bad_args },
	{ "not-control-fd", case_not_control_fd },
	{ "alloc-fail", case_alloc_fail },
	{ "attach-twice", case_attach_twice },
	{ "reference-cycle-guard", case_reference_cycle_guard },
	{ "foreign-file", case_foreign_file },
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

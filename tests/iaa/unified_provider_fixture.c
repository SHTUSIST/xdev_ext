/* SPDX-License-Identifier: GPL-2.0 */
/* Host fixture for the unified IAA operation's provider handling.
 * unified_provider_test.py inserts the actual declarations and function
 * bodies of kernel/io_uring/iaa/xdev_ext_iaa.c at the markers below. Only
 * CryptoAPI, locking, workqueue and sysfs boundaries are shims here: they
 * record calls and never decide caching, selection or attribution. No
 * compression is performed and no device is emulated.
 */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../kernel/io_uring/iaa/xdev_ext_iaa_core.h"

typedef uint32_t u32;
typedef uint64_t u64;
#define __user
#define HZ 100
#define GFP_KERNEL 0
#define CRYPTO_MAX_ALG_NAME 128
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define ERR_CAST(p) ((void *)(p))
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define MODULE_PARM_DESC(name, text)
#define module_param_cb(name, ops, arg, perm) \
	static const void *const name##_param_ref __attribute__((unused)) = (ops)

/* Locks: the fixture is single-threaded; balance is still checked. */
typedef struct { int held; } spinlock_t;
struct mutex { int held; };
#define DEFINE_SPINLOCK(x) spinlock_t x
#define DEFINE_MUTEX(x) struct mutex x
static void spin_lock(spinlock_t *l) { assert(!l->held); l->held = 1; }
static void spin_unlock(spinlock_t *l) { assert(l->held); l->held = 0; }
static void mutex_lock(struct mutex *m) { assert(!m->held); m->held = 1; }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held = 0; }

typedef struct { long long v; } atomic64_t;
static void atomic64_inc(atomic64_t *a) { a->v++; }
static void atomic64_add(long long n, atomic64_t *a) { a->v += n; }
static long long atomic64_read(const atomic64_t *a) { return a->v; }
typedef struct { unsigned int r; } refcount_t;
static void refcount_set(refcount_t *r, unsigned int n) { r->r = n; }
static void refcount_inc(refcount_t *r) { assert(r->r); r->r++; }
static bool refcount_dec_and_test(refcount_t *r) { assert(r->r); return !--r->r; }

static unsigned long jiffies = 1000;
struct work_struct { int unused; };
struct delayed_work { struct work_struct work; void (*fn)(struct work_struct *); };
#define DECLARE_DELAYED_WORK(n, f) struct delayed_work n = { .fn = (f) }
static struct delayed_work *armed_work;
static unsigned long armed_delay;
static unsigned int arm_calls;
static bool schedule_delayed_work(struct delayed_work *w, unsigned long delay)
{
	armed_work = w;
	armed_delay = delay;
	arm_calls++;
	return true;
}

static void *kzalloc(size_t n, int gfp) { (void)gfp; return calloc(1, n); }
static void kfree(const void *p) { free((void *)p); }
static size_t strscpy(char *d, const char *s, size_t n)
{
	snprintf(d, n, "%s", s);
	return strlen(d);
}

static char page_buffer[4096];
static int sysfs_emit_at(char *buf, int at, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf + at, sizeof(page_buffer) - at, fmt, ap);
	va_end(ap);
	return n;
}
#define sysfs_emit(buf, ...) sysfs_emit_at(buf, 0, __VA_ARGS__)
struct kernel_param { int unused; };
struct kernel_param_ops {
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
};

/* CryptoAPI boundary: a registry of drivers; lookup by driver or cra_name. */
struct crypto_tfm { const char *name, *driver; };
struct crypto_acomp { struct crypto_tfm base; bool live; };
struct acomp_req { int unused; };
struct scatterlist { int unused; };
struct registered { const char *name, *driver; bool present; };
static struct registered registry[] = {
	{ "deflate", "deflate-iaa", true },
	{ "deflate", "deflate-generic", true },
	{ "lz4", "lz4-generic", true },
};
static struct crypto_acomp transforms[16];
static unsigned int tfm_allocs, tfm_frees, req_frees;
static char last_lookup[CRYPTO_MAX_ALG_NAME];
static struct crypto_acomp *crypto_alloc_acomp(const char *name, u32 type, u32 mask)
{
	(void)type; (void)mask;
	snprintf(last_lookup, sizeof(last_lookup), "%s", name);
	for (size_t i = 0; i < sizeof(registry) / sizeof(registry[0]); i++) {
		if (!registry[i].present || (strcmp(name, registry[i].driver) &&
					     strcmp(name, registry[i].name)))
			continue;
		assert(tfm_allocs < 16);
		transforms[tfm_allocs] = (struct crypto_acomp) {
			{ registry[i].name, registry[i].driver }, true };
		return &transforms[tfm_allocs++];
	}
	return ERR_PTR(-ENOENT);
}
static void crypto_free_acomp(struct crypto_acomp *t)
{
	if (!t)
		return;
	assert(t->live);
	t->live = false;
	tfm_frees++;
}
static struct crypto_tfm *crypto_acomp_tfm(struct crypto_acomp *t) { return &t->base; }
static const char *crypto_tfm_alg_name(struct crypto_tfm *t) { return t->name; }
static const char *crypto_tfm_alg_driver_name(struct crypto_tfm *t) { return t->driver; }
static void acomp_request_free(struct acomp_req *r) { if (r) req_frees++; }

/* Opaque members of the production request state. */
struct io_kiocb { int unused; };
struct io_xdev_ext_umem { int unused; };
struct io_uring_unified_shared { int unused; };
struct xdev_ext_binding_ctx_v2 { int unused; };
struct xdev_ext_binding_token { int unused; };

/* PRODUCTION_DECLARATIONS */
/* PRODUCTION_FUNCTIONS */

/* Runtime seam: the production provider callback; the rest record nothing. */
static int fake_op(void *opaque) { (void)opaque; return 0; }
static void fake_void(void *opaque) { (void)opaque; }
static int fake_complete(void *opaque, int result) { (void)opaque; (void)result; return 0; }
static int fake_submit(void *opaque, bool decompress, xdev_ext_sm_u32 *produced)
{
	(void)opaque; (void)decompress; (void)produced;
	return 0;
}
static const struct xdev_ext_iaa_runtime_ops seam = {
	.dispatch = fake_op, .prepare_provider = io_xdev_ext_iaa_runtime_prepare_provider,
	.token_put = fake_void,
	.umem_get = fake_void, .umem_put = fake_void, .complete = fake_complete,
	.submit = fake_submit, .queue_task_work = fake_void,
};

static int failures;
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } } while (0)

struct op {
	struct io_xdev_ext_iaa_async state;
	struct xdev_ext_frame frames[4];
	struct xdev_ext_pool pool;
};

/* One request through the actual prepare_provider seam. */
static int begin(struct op *op)
{
	memset(op, 0, sizeof(*op));
	assert(!xdev_ext_iaa_runtime_init(&op->state.runtime, &seam, &op->state));
	assert(!xdev_ext_iaa_runtime_dispatch(&op->state.runtime));
	return xdev_ext_iaa_runtime_prepare_provider(&op->state.runtime);
}

/* Terminal: real frame ownership, completion and statistics bodies. */
static int finish(struct op *op, int crypto_result, u32 produced)
{
	struct xdev_ext_iaa_sqe_fields fields =
		xdev_ext_iaa_sqe_fields_from_words(0, 4096, 100, 4096);
	struct xdev_ext_iaa_window_plan plan;

	assert(!xdev_ext_iaa_decode_windows(&fields, 16384, 4096, &plan));
	assert(!xdev_ext_pool_init(&op->pool, op->frames, 4, false));
	assert(!xdev_ext_iaa_frames_claim(&op->state.frames, &op->pool, &plan,
				     XDEV_EXT_IAA_CLAIM_DEST_FIRST));
	return io_xdev_ext_iaa_finish_terminal(&op->state, crypto_result, produced);
}

static void end(struct op *op)
{
	io_xdev_ext_iaa_release_resources(&op->state);
}

#ifdef HAVE_SELECTION
static int select_driver(const char *value)
{
	struct kernel_param kp = { 0 };

	return io_xdev_ext_iaa_driver_ops.set(value, &kp);
}

static const char *served(void)
{
	struct kernel_param kp = { 0 };

	memset(page_buffer, 0, sizeof(page_buffer));
	assert(io_xdev_ext_iaa_served_ops.get(page_buffer, &kp) > 0);
	return page_buffer;
}
#endif

static void expire_idle_cache(void)
{
	jiffies += 10 * HZ;
	if (armed_work)
		armed_work->fn(&armed_work->work);
}

int main(int argc, char **argv)
{
	struct op a, b;
	const char *mode;

	assert(argc == 2);
	mode = argv[1];
	if (!strcmp(mode, "reuse")) {
		CHECK(!begin(&a), "first lookup failed");
		end(&a);
		CHECK(!begin(&b), "second lookup failed");
		CHECK(tfm_allocs == 1, "a transform was allocated for every operation");
		CHECK(b.state.tfm == &transforms[0] && transforms[0].live,
		      "the second operation did not reuse the first transform");
		end(&b);
		CHECK(!tfm_frees, "releasing a request freed the shared transform");
		CHECK(!strcmp(last_lookup, "deflate-iaa"), "default lookup is not deflate-iaa");
		return !!failures;
	}
	if (!strcmp(mode, "lookup_retry")) {
		/* A provider registered after a failed lookup is still found. */
		registry[0].present = false;
		CHECK(begin(&a) == -ENOENT && !a.state.tfm, "missing provider was not reported");
		end(&a);
		registry[0].present = true;
		CHECK(!begin(&b) && b.state.tfm, "later provider was not looked up");
		end(&b);
		return !!failures;
	}
#ifndef HAVE_TFM_CACHE
	fprintf(stderr, "FAIL: no cached transform: every operation allocates its own\n");
	return 1;
#else
	if (!strcmp(mode, "concurrent")) {
		CHECK(!begin(&a) && !begin(&b), "concurrent lookups failed");
		CHECK(a.state.tfm == b.state.tfm && tfm_allocs == 1, "concurrent requests did not share one transform");
		end(&a);
		CHECK(!tfm_frees && transforms[0].live, "one release freed a transform still in use");
		end(&b);
		return !!failures;
	}
	if (!strcmp(mode, "provider_failure")) {
		CHECK(!begin(&a), "first lookup failed");
		CHECK(finish(&a, -EOVERFLOW, 0) == -EOVERFLOW, "content error changed");
		end(&a);
		CHECK(!begin(&b) && tfm_allocs == 1, "a request-content error dropped the cache");
		CHECK(finish(&b, -ENODEV, 0) == -ENODEV, "provider error changed");
		end(&b);
		CHECK(tfm_frees == 1, "a provider failure kept the failed transform cached");
		CHECK(!begin(&a) && tfm_allocs == 2 && a.state.tfm == &transforms[1],
		      "the operation after a provider failure did not look up again");
		end(&a);
		return !!failures;
	}
	if (!strcmp(mode, "idle")) {
		CHECK(!begin(&a), "lookup failed");
		CHECK(arm_calls == 1 && armed_delay == 5 * HZ, "idle release was not armed");
		jiffies += HZ;
		armed_work->fn(&armed_work->work);
		CHECK(!tfm_frees && arm_calls == 2 && armed_delay == 4 * HZ, "recent use did not keep the cache");
		end(&a);
		expire_idle_cache();
		CHECK(tfm_frees == 1, "an idle cache kept pinning the provider");
		CHECK(!begin(&b) && tfm_allocs == 2, "lookup after idle release failed");
		end(&b);
		return !!failures;
	}
#endif
#ifndef HAVE_SELECTION
	fprintf(stderr, "FAIL: no acomp driver selection or served-driver statistics\n");
	return 1;
#else
	if (!strcmp(mode, "select")) {
		CHECK(!begin(&a), "default lookup failed");
		end(&a);
		CHECK(!select_driver("deflate-generic\n"), "valid selection refused");
		CHECK(tfm_frees == 1, "selection change kept the old provider cached");
		CHECK(!begin(&b) && !strcmp(last_lookup, "deflate-generic") &&
		      !strcmp(b.state.tfm->base.driver, "deflate-generic"),
		      "selected software driver was not used");
		CHECK(finish(&b, 0, 900) == 900, "successful terminal changed");
		end(&b);
		CHECK(!begin(&a), "cached software lookup failed");
		CHECK(finish(&a, -ENOSPC, 0) == -ENOSPC, "capacity terminal changed");
		end(&a);
		CHECK(strstr(served(), "deflate-generic requests=2 errors=1 bytes=900\n") != NULL,
		      "served statistics do not attribute requests to the actual driver");
		CHECK(!strstr(served(), "deflate-iaa requests=") ||
		      strstr(served(), "deflate-iaa requests=0 errors=0 bytes=0\n"),
		      "a driver that served nothing was attributed requests");
		return !!failures;
	}
	if (!strcmp(mode, "algorithm")) {
		/* A cra_name selection is attributed to the driver that served it. */
		registry[0].present = false;
		CHECK(!select_driver("deflate"), "algorithm selection refused");
		CHECK(!begin(&a), "algorithm lookup failed");
		CHECK(finish(&a, 0, 77) == 77, "terminal changed");
		end(&a);
		CHECK(strstr(served(), "deflate-generic requests=1 errors=0 bytes=77\n") != NULL,
		      "served statistics recorded the requested name instead of the actual driver");
		return !!failures;
	}
	if (!strcmp(mode, "refusal")) {
		CHECK(select_driver("") == -EINVAL && select_driver("\n") == -EINVAL,
		      "empty selection accepted");
		CHECK(select_driver("deflate generic") == -EINVAL, "selection with whitespace accepted");
		char longname[CRYPTO_MAX_ALG_NAME + 1];
		memset(longname, 'a', CRYPTO_MAX_ALG_NAME);
		longname[CRYPTO_MAX_ALG_NAME] = 0;
		CHECK(select_driver(longname) == -EINVAL, "overlong selection accepted");
		CHECK(!select_driver("lz4-generic"), "syntactically valid selection refused");
		CHECK(begin(&a) == -EOPNOTSUPP, "a non-DEFLATE algorithm served the operation");
		CHECK(tfm_allocs == 1 && tfm_frees == 1, "refused transform leaked");
		end(&a);
		return !!failures;
	}
#endif
	fprintf(stderr, "unknown mode %s\n", mode);
	return 2;
}

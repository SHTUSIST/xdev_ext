// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring XDEV_EXT IAA compression/decompression over registered UMEM pages.
 * Crypto API sees truthful page scatterlists; no vmap-backed fake segment or
 * hidden bounce buffer is used.
 */

#include "../xdev_ext_config.h"

#if defined(XDEV_EXT_UMEM_ZEROCOPY) && defined(XDEV_EXT_LIFECYCLE_SM)

#include <crypto/acompress.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/io_uring_types.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/workqueue.h>
#include <linux/xdev_ext_binding.h>
#include <linux/xarray.h>

#include "../io_uring.h"
#include "xdev_ext_iaa.h"
#include "../xdev_ext_umem.h"

struct io_xdev_ext_iaa_tfm;

struct io_xdev_ext_iaa_async {
	struct io_kiocb *io_req;
	struct io_xdev_ext_umem *umem;
	struct io_uring_unified_shared __user *shared;
	io_xdev_ext_iaa_stats_fn update_stats;
	struct io_xdev_ext_iaa_params params;
	struct xdev_ext_iaa_window_plan windows;
	struct xdev_ext_iaa_frame_claim frames;
	struct io_xdev_ext_iaa_tfm *provider;
	struct crypto_acomp *tfm;
	struct acomp_req *acomp;
	struct scatterlist *src_sg;
	struct scatterlist *dst_sg;
	u32 src_nents;
	u32 dst_nents;
	struct xdev_ext_binding_ctx_v2 binding_ctx;
	struct xdev_ext_binding_token token;
	struct xdev_ext_iaa_runtime runtime;
	bool installed;
};

static atomic64_t io_xdev_ext_iaa_policy_errors;

/*
 * Transform selection and reuse.  The acomp driver is chosen by the
 * xdev_ext_iaa.acomp_driver parameter (default deflate-iaa; deflate-generic is
 * the software CryptoAPI implementation, not a device stand-in).  Concurrent
 * requests share one transform: each acomp request carries its own state.
 * The cached transform is looked up again after a provider-level failure, a
 * selection change, or IO_XDEV_EXT_IAA_TFM_IDLE without requests, so an idle
 * cache does not pin the provider module.  acomp_served reports, per actual
 * serving driver name, the requests that reached the provider.
 */
#define IO_XDEV_EXT_IAA_DRIVER_DEFAULT "deflate-iaa"
#define IO_XDEV_EXT_IAA_TFM_IDLE (5 * HZ)
#define IO_XDEV_EXT_IAA_SERVED_MAX 8

struct io_xdev_ext_iaa_served {
	char driver[CRYPTO_MAX_ALG_NAME];
	atomic64_t requests;
	atomic64_t errors;
	atomic64_t bytes;
};

struct io_xdev_ext_iaa_tfm {
	struct crypto_acomp *tfm;
	struct io_xdev_ext_iaa_served *served;
	refcount_t ref;
};

/* tfm_lock: selection, cached pointer, last use.  tfm_mutex: lookups, slots. */
static DEFINE_SPINLOCK(io_xdev_ext_iaa_tfm_lock);
static DEFINE_MUTEX(io_xdev_ext_iaa_tfm_mutex);
static char io_xdev_ext_iaa_driver[CRYPTO_MAX_ALG_NAME] = IO_XDEV_EXT_IAA_DRIVER_DEFAULT;
static u64 io_xdev_ext_iaa_generation;
static struct io_xdev_ext_iaa_tfm *io_xdev_ext_iaa_cached;
static unsigned long io_xdev_ext_iaa_last_use;
static struct io_xdev_ext_iaa_served io_xdev_ext_iaa_served[IO_XDEV_EXT_IAA_SERVED_MAX];
static atomic64_t io_xdev_ext_iaa_served_untracked;
static void io_xdev_ext_iaa_tfm_idle(struct work_struct *work);
static DECLARE_DELAYED_WORK(io_xdev_ext_iaa_tfm_idle_work, io_xdev_ext_iaa_tfm_idle);

static void io_xdev_ext_iaa_tfm_put(struct io_xdev_ext_iaa_tfm *t)
{
	if (!t || !refcount_dec_and_test(&t->ref))
		return;
	crypto_free_acomp(t->tfm);
	kfree(t);
}

/* Caller holds tfm_mutex; a full table counts the driver as untracked. */
static struct io_xdev_ext_iaa_served *io_xdev_ext_iaa_served_slot(const char *driver)
{
	struct io_xdev_ext_iaa_served *slot;
	int i;

	for (i = 0; i < IO_XDEV_EXT_IAA_SERVED_MAX; i++) {
		slot = &io_xdev_ext_iaa_served[i];
		if (!slot->driver[0]) {
			strscpy(slot->driver, driver, sizeof(slot->driver));
			return slot;
		}
		if (!strcmp(slot->driver, driver))
			return slot;
	}
	return NULL;
}

/* Caller holds tfm_mutex.  Only raw DEFLATE satisfies the operation contract. */
static struct io_xdev_ext_iaa_tfm *io_xdev_ext_iaa_tfm_alloc(const char *driver)
{
	struct io_xdev_ext_iaa_tfm *t;
	struct crypto_acomp *tfm;

	tfm = crypto_alloc_acomp(driver, 0, 0);
	if (IS_ERR(tfm))
		return ERR_CAST(tfm);
	if (strcmp(crypto_tfm_alg_name(crypto_acomp_tfm(tfm)), "deflate")) {
		crypto_free_acomp(tfm);
		return ERR_PTR(-EOPNOTSUPP);
	}
	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t) {
		crypto_free_acomp(tfm);
		return ERR_PTR(-ENOMEM);
	}
	t->tfm = tfm;
	t->served = io_xdev_ext_iaa_served_slot(
		crypto_tfm_alg_driver_name(crypto_acomp_tfm(tfm)));
	refcount_set(&t->ref, 1);
	return t;
}

/* Process context.  A failed lookup is not cached: a later provider is seen. */
static struct io_xdev_ext_iaa_tfm *io_xdev_ext_iaa_tfm_get(void)
{
	struct io_xdev_ext_iaa_tfm *t;
	char driver[CRYPTO_MAX_ALG_NAME];
	bool installed = false;
	u64 generation;

	spin_lock(&io_xdev_ext_iaa_tfm_lock);
	t = io_xdev_ext_iaa_cached;
	if (t) {
		refcount_inc(&t->ref);
		io_xdev_ext_iaa_last_use = jiffies;
	}
	spin_unlock(&io_xdev_ext_iaa_tfm_lock);
	if (t)
		return t;

	mutex_lock(&io_xdev_ext_iaa_tfm_mutex);
	spin_lock(&io_xdev_ext_iaa_tfm_lock);
	t = io_xdev_ext_iaa_cached;
	if (t)
		refcount_inc(&t->ref);
	strscpy(driver, io_xdev_ext_iaa_driver, sizeof(driver));
	generation = io_xdev_ext_iaa_generation;
	spin_unlock(&io_xdev_ext_iaa_tfm_lock);
	if (!t) {
		t = io_xdev_ext_iaa_tfm_alloc(driver);
		if (!IS_ERR(t)) {
			spin_lock(&io_xdev_ext_iaa_tfm_lock);
			/* A selection written during the lookup keeps its own cache. */
			if (generation == io_xdev_ext_iaa_generation &&
			    !io_xdev_ext_iaa_cached) {
				refcount_inc(&t->ref);
				io_xdev_ext_iaa_cached = t;
				io_xdev_ext_iaa_last_use = jiffies;
				installed = true;
			}
			spin_unlock(&io_xdev_ext_iaa_tfm_lock);
		}
	}
	mutex_unlock(&io_xdev_ext_iaa_tfm_mutex);
	if (installed)
		schedule_delayed_work(&io_xdev_ext_iaa_tfm_idle_work,
				      IO_XDEV_EXT_IAA_TFM_IDLE);
	return t;
}

static void io_xdev_ext_iaa_tfm_invalidate(struct io_xdev_ext_iaa_tfm *t)
{
	bool drop = false;

	spin_lock(&io_xdev_ext_iaa_tfm_lock);
	if (t && io_xdev_ext_iaa_cached == t) {
		io_xdev_ext_iaa_cached = NULL;
		drop = true;
	}
	spin_unlock(&io_xdev_ext_iaa_tfm_lock);
	if (drop)
		io_xdev_ext_iaa_tfm_put(t);
}

static void io_xdev_ext_iaa_tfm_idle(struct work_struct *work)
{
	struct io_xdev_ext_iaa_tfm *t = NULL;
	unsigned long delay = 0;

	spin_lock(&io_xdev_ext_iaa_tfm_lock);
	if (io_xdev_ext_iaa_cached) {
		unsigned long expires = io_xdev_ext_iaa_last_use +
					IO_XDEV_EXT_IAA_TFM_IDLE;

		if (time_after_eq(jiffies, expires)) {
			t = io_xdev_ext_iaa_cached;
			io_xdev_ext_iaa_cached = NULL;
		} else {
			delay = expires - jiffies;
		}
	}
	spin_unlock(&io_xdev_ext_iaa_tfm_lock);
	if (t)
		io_xdev_ext_iaa_tfm_put(t);
	else if (delay)
		schedule_delayed_work(&io_xdev_ext_iaa_tfm_idle_work, delay);
}

/* Request-content outcomes say nothing about the provider's availability. */
static bool io_xdev_ext_iaa_provider_failed(int crypto_result)
{
	switch (crypto_result) {
	case 0:
	case -EINVAL:
	case -EOVERFLOW:
	case -ENOSPC:
	case -EBADMSG:
	case -E2BIG:
	case -EAGAIN:
		return false;
	default:
		return crypto_result < 0;
	}
}

static void io_xdev_ext_iaa_record_served(struct io_xdev_ext_iaa_tfm *t,
				     int crypto_result, int result)
{
	if (!t)
		return;
	if (!t->served) {
		atomic64_inc(&io_xdev_ext_iaa_served_untracked);
	} else {
		atomic64_inc(&t->served->requests);
		if (result < 0)
			atomic64_inc(&t->served->errors);
		else
			atomic64_add(result, &t->served->bytes);
	}
	if (io_xdev_ext_iaa_provider_failed(crypto_result))
		io_xdev_ext_iaa_tfm_invalidate(t);
}

static int io_xdev_ext_iaa_driver_set(const char *val, const struct kernel_param *kp)
{
	struct io_xdev_ext_iaa_tfm *old;
	size_t len = strlen(val);
	size_t i;

	if (len && val[len - 1] == '\n')
		len--;
	if (!len || len >= sizeof(io_xdev_ext_iaa_driver))
		return -EINVAL;
	for (i = 0; i < len; i++)
		if (val[i] <= ' ' || val[i] > '~')
			return -EINVAL;
	spin_lock(&io_xdev_ext_iaa_tfm_lock);
	memcpy(io_xdev_ext_iaa_driver, val, len);
	io_xdev_ext_iaa_driver[len] = '\0';
	io_xdev_ext_iaa_generation++;
	old = io_xdev_ext_iaa_cached;
	io_xdev_ext_iaa_cached = NULL;
	spin_unlock(&io_xdev_ext_iaa_tfm_lock);
	io_xdev_ext_iaa_tfm_put(old);
	return 0;
}

static int io_xdev_ext_iaa_driver_get(char *buf, const struct kernel_param *kp)
{
	int n;

	spin_lock(&io_xdev_ext_iaa_tfm_lock);
	n = sysfs_emit(buf, "%s\n", io_xdev_ext_iaa_driver);
	spin_unlock(&io_xdev_ext_iaa_tfm_lock);
	return n;
}

static int io_xdev_ext_iaa_served_get(char *buf, const struct kernel_param *kp)
{
	const struct io_xdev_ext_iaa_served *slot;
	int i, n = 0;

	mutex_lock(&io_xdev_ext_iaa_tfm_mutex);
	for (i = 0; i < IO_XDEV_EXT_IAA_SERVED_MAX; i++) {
		slot = &io_xdev_ext_iaa_served[i];
		if (!slot->driver[0])
			break;
		n += sysfs_emit_at(buf, n, "%s requests=%lld errors=%lld bytes=%lld\n",
				   slot->driver,
				   (long long)atomic64_read(&slot->requests),
				   (long long)atomic64_read(&slot->errors),
				   (long long)atomic64_read(&slot->bytes));
	}
	n += sysfs_emit_at(buf, n, "untracked requests=%lld\n",
			   (long long)atomic64_read(&io_xdev_ext_iaa_served_untracked));
	mutex_unlock(&io_xdev_ext_iaa_tfm_mutex);
	return n;
}

static const struct kernel_param_ops io_xdev_ext_iaa_driver_ops = {
	.set = io_xdev_ext_iaa_driver_set,
	.get = io_xdev_ext_iaa_driver_get,
};
static const struct kernel_param_ops io_xdev_ext_iaa_served_ops = {
	.get = io_xdev_ext_iaa_served_get,
};
module_param_cb(acomp_driver, &io_xdev_ext_iaa_driver_ops, NULL, 0644);
MODULE_PARM_DESC(acomp_driver, "CryptoAPI raw DEFLATE acomp driver or algorithm for unified IAA operations");
module_param_cb(acomp_served, &io_xdev_ext_iaa_served_ops, NULL, 0444);
MODULE_PARM_DESC(acomp_served, "Requests, errors and produced bytes per actual serving acomp driver");

static void io_xdev_ext_iaa_task_work(struct io_kiocb *req, io_tw_token_t tw);

struct io_xdev_ext_iaa_alias_ctx {
	struct io_xdev_ext_umem *umem;
	struct xarray source_pages;
	struct xdev_ext_iaa_phys_extent *extents;
	u32 capacity;
	u32 used;
};

static int
io_xdev_ext_iaa_record_source_page(void *opaque,
			      const struct xdev_ext_iaa_sg_segment *segment)
{
	struct io_xdev_ext_iaa_alias_ctx *ctx = opaque;
	struct xdev_ext_iaa_phys_extent *extent;
	unsigned long page_id;
	int ret;

	if (segment->page_index >= ctx->umem->nr_pages)
		return -EFAULT;
	page_id = page_to_pfn(ctx->umem->pages[segment->page_index]);
	extent = xa_load(&ctx->source_pages, page_id);
	if (extent)
		return xdev_ext_iaa_phys_extent_merge(extent, segment->page_offset,
						 segment->length);
	if (ctx->used >= ctx->capacity)
		return -EFAULT;
	extent = &ctx->extents[ctx->used++];
	ret = xdev_ext_iaa_phys_extent_init(extent, segment->page_offset,
				       segment->length);
	if (ret)
		return ret;
	ret = xa_insert(&ctx->source_pages, page_id, extent, GFP_KERNEL);
	return ret;
}

static int
io_xdev_ext_iaa_check_destination_page(void *opaque,
				  const struct xdev_ext_iaa_sg_segment *segment)
{
	struct io_xdev_ext_iaa_alias_ctx *ctx = opaque;
	struct xdev_ext_iaa_phys_extent *extent;
	unsigned long page_id;

	if (segment->page_index >= ctx->umem->nr_pages)
		return -EFAULT;
	page_id = page_to_pfn(ctx->umem->pages[segment->page_index]);
	extent = xa_load(&ctx->source_pages, page_id);
	if (!extent)
		return 0;
	return xdev_ext_iaa_phys_extent_overlaps(extent, segment->page_offset,
					    segment->length) ? -EINVAL : 0;
}

static const struct xdev_ext_iaa_phys_walk_ops io_xdev_ext_iaa_phys_walk_ops = {
	.source = io_xdev_ext_iaa_record_source_page,
	.destination = io_xdev_ext_iaa_check_destination_page,
};

static int
io_xdev_ext_iaa_check_physical_alias(struct io_xdev_ext_umem *umem,
				const struct xdev_ext_iaa_window_plan *windows)
{
	struct io_xdev_ext_iaa_alias_ctx ctx = {
		.umem = umem,
	};
	struct xdev_ext_iaa_sg_cursor cursor;
	int ret;

	ret = xdev_ext_iaa_sg_cursor_init(&cursor, umem->page_offset,
				     umem->nr_pages, windows->src_off,
				     windows->src_len);
	if (ret)
		return ret;
	ctx.extents = kvmalloc_array(cursor.nents, sizeof(*ctx.extents), GFP_KERNEL);
	if (!ctx.extents)
		return -ENOMEM;
	ctx.capacity = cursor.nents;

	xa_init(&ctx.source_pages);
	ret = xdev_ext_iaa_walk_physical_windows(umem->page_offset, umem->nr_pages,
					    windows,
					    &io_xdev_ext_iaa_phys_walk_ops, &ctx);
	xa_destroy(&ctx.source_pages);
	kvfree(ctx.extents);
	return ret;
}

static int io_xdev_ext_iaa_runtime_dispatch(void *opaque)
{
	struct io_xdev_ext_iaa_async *state = opaque;
	struct xdev_ext_binding_plan plan;
	int ret;

	ret = xdev_ext_binding_dispatch(&state->binding_ctx, &state->token, &plan);
	if (ret)
		return ret;
	switch (plan.action) {
	case XDEV_EXT_BINDING_ACTION_FALLBACK:
	case XDEV_EXT_BINDING_ACTION_USE_PLAN:
		return 0;
	case XDEV_EXT_BINDING_ACTION_TERMINAL:
		return -EPERM;
	default:
		return -EPROTO;
	}
}

static int io_xdev_ext_iaa_runtime_prepare_provider(void *opaque)
{
	struct io_xdev_ext_iaa_async *state = opaque;
	struct io_xdev_ext_iaa_tfm *t;

	/* Cached across requests; an uncached lookup observes a later provider. */
	t = io_xdev_ext_iaa_tfm_get();
	if (IS_ERR(t))
		return PTR_ERR(t);
	state->provider = t;
	state->tfm = t->tfm;
	return 0;
}

static void io_xdev_ext_iaa_runtime_token_put(void *opaque)
{
	struct io_xdev_ext_iaa_async *state = opaque;

	xdev_ext_binding_token_put(&state->token);
}

static void io_xdev_ext_iaa_runtime_umem_get(void *opaque)
{
	struct io_xdev_ext_iaa_async *state = opaque;

	io_xdev_ext_umem_get(state->umem);
}

static void io_xdev_ext_iaa_runtime_umem_put(void *opaque)
{
	struct io_xdev_ext_iaa_async *state = opaque;

	io_xdev_ext_umem_put(state->umem);
}

static int io_xdev_ext_iaa_runtime_complete(void *opaque, int result)
{
	struct io_xdev_ext_iaa_async *state = opaque;
	struct xdev_ext_binding_normalized_result normalized;
	struct xdev_ext_binding_plan plan;
	int ret;

	normalized = xdev_ext_binding_normalize_byte_result(result);
	state->binding_ctx.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	state->binding_ctx.result = normalized.result;
	state->binding_ctx.bytes_done = normalized.bytes_done;
	ret = xdev_ext_binding_complete(&state->binding_ctx, &state->token, &plan);
	return ret;
}

static int io_xdev_ext_iaa_runtime_submit(void *opaque, bool decompress,
				     u32 *produced)
{
	struct io_xdev_ext_iaa_async *state = opaque;
	int ret;

	ret = decompress ?
		crypto_acomp_decompress(state->acomp) :
		crypto_acomp_compress(state->acomp);
	if (ret > 0)
		ret = -EIO;
	*produced = ret ? 0 : READ_ONCE(state->acomp->dlen);
	return ret;
}

static void io_xdev_ext_iaa_runtime_queue_task_work(void *opaque)
{
	struct io_xdev_ext_iaa_async *state = opaque;

	state->io_req->io_task_work.func = io_xdev_ext_iaa_task_work;
	io_req_task_work_add(state->io_req);
}

static const struct xdev_ext_iaa_runtime_ops io_xdev_ext_iaa_runtime_ops = {
	.dispatch = io_xdev_ext_iaa_runtime_dispatch,
	.prepare_provider = io_xdev_ext_iaa_runtime_prepare_provider,
	.token_put = io_xdev_ext_iaa_runtime_token_put,
	.umem_get = io_xdev_ext_iaa_runtime_umem_get,
	.umem_put = io_xdev_ext_iaa_runtime_umem_put,
	.complete = io_xdev_ext_iaa_runtime_complete,
	.submit = io_xdev_ext_iaa_runtime_submit,
	.queue_task_work = io_xdev_ext_iaa_runtime_queue_task_work,
};

static int io_xdev_ext_iaa_build_sg(struct io_xdev_ext_umem *umem, u64 offset,
			       u32 length, struct scatterlist **sg_out,
			       u32 *nents_out)
{
	struct xdev_ext_iaa_sg_segment segment;
	struct xdev_ext_iaa_sg_cursor cursor;
	struct scatterlist *sg;
	u32 i = 0;
	int ret;

	ret = xdev_ext_iaa_sg_cursor_init(&cursor, umem->page_offset,
				     umem->nr_pages, offset, length);
	if (ret)
		return ret;
	if (!cursor.nents)
		return -EINVAL;

	sg = kcalloc(cursor.nents, sizeof(*sg), GFP_KERNEL);
	if (!sg)
		return -ENOMEM;
	sg_init_table(sg, cursor.nents);

	while ((ret = xdev_ext_iaa_sg_cursor_next(&cursor, &segment)) > 0) {
		if (WARN_ON_ONCE(i >= cursor.nents ||
				 segment.page_index >= umem->nr_pages)) {
			ret = -EFAULT;
			goto err_free;
		}
		sg_set_page(&sg[i++], umem->pages[segment.page_index],
			    segment.length, segment.page_offset);
	}
	if (ret < 0)
		goto err_free;
	if (WARN_ON_ONCE(i != cursor.nents || cursor.remaining)) {
		ret = -EFAULT;
		goto err_free;
	}

	*sg_out = sg;
	*nents_out = i;
	return 0;

err_free:
	kfree(sg);
	return ret;
}

static void io_xdev_ext_iaa_release_resources(struct io_xdev_ext_iaa_async *state)
{
	acomp_request_free(state->acomp);
	state->acomp = NULL;
	kfree(state->src_sg);
	state->src_sg = NULL;
	kfree(state->dst_sg);
	state->dst_sg = NULL;
	xdev_ext_iaa_runtime_release(&state->runtime);
	state->tfm = NULL;
	io_xdev_ext_iaa_tfm_put(state->provider);
	state->provider = NULL;
}

static void io_xdev_ext_iaa_uninstall(struct io_xdev_ext_iaa_async *state)
{
	if (!state->installed)
		return;
	state->io_req->async_data = NULL;
	state->io_req->flags &= ~REQ_F_ASYNC_DATA;
	state->installed = false;
}

static void io_xdev_ext_iaa_update_stats(struct io_xdev_ext_iaa_async *state, int result)
{
	if (state->shared && state->update_stats)
		state->update_stats(state->shared, result > 0 ? result : 0,
				    result < 0);
}

/* Called only before crypto_acomp_{compress,decompress} has been entered. */
static int io_xdev_ext_iaa_unwind_pre_submit(struct io_xdev_ext_iaa_async *state,
					int error)
{
	int rollback_ret;

	rollback_ret = xdev_ext_iaa_frames_rollback(&state->frames);
	if (rollback_ret)
		error = rollback_ret;
	io_xdev_ext_iaa_update_stats(state, error);
	io_xdev_ext_iaa_release_resources(state);
	io_xdev_ext_iaa_uninstall(state);
	kfree(state);
	return error;
}

static int io_xdev_ext_iaa_finish_terminal(struct io_xdev_ext_iaa_async *state,
				      int crypto_result, u32 produced)
{
	int result;

	result = xdev_ext_iaa_frames_finish(&state->frames, crypto_result, produced);
	/* Completion-policy errors affect diagnostics, not the terminal result. */
	if (xdev_ext_iaa_runtime_complete(&state->runtime, result))
		atomic64_inc(&io_xdev_ext_iaa_policy_errors);
	io_xdev_ext_iaa_update_stats(state, result);
	io_xdev_ext_iaa_record_served(state->provider, crypto_result, result);
	return result;
}

static void io_xdev_ext_iaa_task_work(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_xdev_ext_iaa_async *state = req->async_data;
	u32 produced = xdev_ext_iaa_terminal_produced(&state->runtime.terminal);
	int crypto_result = xdev_ext_iaa_terminal_result(&state->runtime.terminal);
	int result;

	/* Frame release-publication precedes plugin completion and CQE delivery. */
	result = io_xdev_ext_iaa_finish_terminal(state, crypto_result, produced);
	io_xdev_ext_iaa_release_resources(state);
	io_xdev_ext_iaa_uninstall(state);
	kfree(state);

	if (result < 0)
		req_set_fail(req);
	io_req_set_res(req, result, 0);
	io_req_task_complete(req, tw);
}

static void io_xdev_ext_iaa_crypto_complete(void *data, int error)
{
	struct io_xdev_ext_iaa_async *state = data;
	u32 produced = 0;

	/* -EINPROGRESS is only the MAY_BACKLOG promotion notification. */
	if (!error)
		produced = READ_ONCE(state->acomp->dlen);
	if (error > 0 || error < -XDEV_EXT_BINDING_LINUX_ERRNO_MAX)
		error = -EIO;
	xdev_ext_iaa_runtime_callback(&state->runtime, error, produced);
}

static int io_xdev_ext_iaa_final_validate(const struct io_xdev_ext_iaa_async *state)
{
	struct xdev_ext_iaa_sqe_fields fields = {
		.src_off = state->params.src_off,
		.dst_off = state->params.dst_off,
		.src_len = state->params.src_len,
		.dst_cap = state->params.dst_cap,
	};
	struct xdev_ext_iaa_window_plan windows;
	int ret;

	ret = xdev_ext_iaa_decode_windows(&fields, state->umem->size,
				     state->umem->frame_size, &windows);
	if (ret)
		return ret;
	if (windows.src_off != state->windows.src_off ||
	    windows.dst_off != state->windows.dst_off ||
	    windows.src_len != state->windows.src_len ||
	    windows.dst_cap != state->windows.dst_cap ||
	    windows.src_frame != state->windows.src_frame ||
	    windows.dst_frame != state->windows.dst_frame ||
	    windows.src_frame_offset != state->windows.src_frame_offset)
		return -ESTALE;

 if (!state->frames.source_owned || !state->frames.destination_owned ||
     !xdev_ext_mech_life_matches(smp_load_acquire(&state->umem->frames[windows.src_frame].ctrl),
                                state->frames.source_claim) ||
     !xdev_ext_mech_life_matches(smp_load_acquire(&state->umem->frames[windows.dst_frame].ctrl),
                                state->frames.destination_claim))
  return -ESTALE;
	if (!state->src_sg || !state->dst_sg || !state->src_nents ||
	    !state->dst_nents || !state->acomp ||
	    !state->runtime.dispatch_accepted ||
	    !state->runtime.provider_prepared || !state->runtime.umem_ref ||
	    state->acomp->src != state->src_sg ||
	    state->acomp->dst != state->dst_sg ||
	    state->acomp->slen != windows.src_len ||
	    state->acomp->dlen != windows.dst_cap)
		return -EINVAL;
	return 0;
}

int io_xdev_ext_iaa_issue(struct io_kiocb *req, struct io_xdev_ext_umem *umem,
		     struct io_uring_unified_shared __user *shared,
		     const struct io_xdev_ext_iaa_params *params,
		     io_xdev_ext_iaa_stats_fn update_stats)
{
	struct xdev_ext_iaa_sqe_fields fields;
	struct io_xdev_ext_iaa_async *state;
	enum xdev_ext_iaa_submit_action action;
	bool decompress;
	u32 produced;
	int terminal_result;
	int ret;

	BUILD_BUG_ON(XDEV_EXT_IAA_DST_MAX != CRYPTO_ACOMP_DST_MAX);
	if (!req || !umem || !params || !xdev_ext_iaa_opcode_valid(params->opcode))
		return -EINVAL;
	if (!umem->frames || umem->frame_pool.frames != umem->frames)
		return -EOPNOTSUPP;

	fields = xdev_ext_iaa_sqe_fields_from_words(params->src_off,
					       params->dst_off, params->src_len,
					       params->dst_cap);
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	state->io_req = req;
	state->umem = umem;
	state->shared = shared;
	state->update_stats = update_stats;
	state->params = *params;
	ret = xdev_ext_iaa_runtime_init(&state->runtime, &io_xdev_ext_iaa_runtime_ops,
				   state);
	if (ret)
		goto err_free_state;

	ret = xdev_ext_iaa_decode_windows(&fields, umem->size, umem->frame_size,
				     &state->windows);
	if (ret)
		goto err_free_state;
	ret = io_xdev_ext_iaa_check_physical_alias(umem, &state->windows);
	if (ret)
		goto err_free_state;
	ret = xdev_ext_iaa_frames_claim(&state->frames, &umem->frame_pool,
				   &state->windows, XDEV_EXT_IAA_CLAIM_DEST_FIRST);
	if (ret)
		goto err_free_state;

	decompress = xdev_ext_iaa_is_decompress(params->opcode);
	state->binding_ctx =
		xdev_ext_binding_make_iaa_ctx(decompress, params->src_off,
					 params->dst_off, params->src_len);
	state->binding_ctx.capabilities = XDEV_EXT_BINDING_CAP_ASYNC |
					  XDEV_EXT_BINDING_CAP_ZERO_COPY;
	state->binding_ctx.src_buffer_id = state->windows.src_frame;
	state->binding_ctx.dst_buffer_id = state->windows.dst_frame;
	ret = xdev_ext_iaa_runtime_dispatch(&state->runtime);
	if (ret)
		return io_xdev_ext_iaa_unwind_pre_submit(state, ret);

	ret = xdev_ext_iaa_runtime_prepare_provider(&state->runtime);
	if (ret)
		return io_xdev_ext_iaa_unwind_pre_submit(state, ret);
	state->acomp = acomp_request_alloc(state->tfm, GFP_KERNEL);
	if (!state->acomp)
		return io_xdev_ext_iaa_unwind_pre_submit(state, -ENOMEM);
	ret = io_xdev_ext_iaa_build_sg(umem, state->windows.src_off,
				  state->windows.src_len, &state->src_sg,
				  &state->src_nents);
	if (ret)
		return io_xdev_ext_iaa_unwind_pre_submit(state, ret);
	ret = io_xdev_ext_iaa_build_sg(umem, state->windows.dst_off,
				  state->windows.dst_cap, &state->dst_sg,
				  &state->dst_nents);
	if (ret)
		return io_xdev_ext_iaa_unwind_pre_submit(state, ret);

	/* The outer issue reference may be dropped as soon as this returns async. */
	ret = xdev_ext_iaa_runtime_acquire_umem(&state->runtime);
	if (ret)
		return io_xdev_ext_iaa_unwind_pre_submit(state, ret);
	acomp_request_set_params(state->acomp, state->src_sg, state->dst_sg,
				 state->windows.src_len,
				 state->windows.dst_cap);
	acomp_request_set_callback(state->acomp, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   io_xdev_ext_iaa_crypto_complete, state);
	ret = io_xdev_ext_iaa_final_validate(state);
	if (ret)
		return io_xdev_ext_iaa_unwind_pre_submit(state, ret);

	req->async_data = state;
	req->flags |= REQ_F_ASYNC_DATA;
	state->installed = true;

	action = xdev_ext_iaa_runtime_submit(&state->runtime, decompress);
	switch (action) {
	case XDEV_EXT_IAA_SUBMIT_WAIT:
		return -EIOCBQUEUED;
	case XDEV_EXT_IAA_SUBMIT_QUEUE_EARLY:
		return -EIOCBQUEUED;
	case XDEV_EXT_IAA_SUBMIT_FINISH_INLINE:
		terminal_result =
			xdev_ext_iaa_terminal_result(&state->runtime.terminal);
		produced = xdev_ext_iaa_terminal_produced(&state->runtime.terminal);
		ret = io_xdev_ext_iaa_finish_terminal(state, terminal_result, produced);
		io_xdev_ext_iaa_release_resources(state);
		io_xdev_ext_iaa_uninstall(state);
		kfree(state);
		return ret;
	default:
		/* A provider violated the callback/return ownership contract. */
		return -EIOCBQUEUED;
	}

err_free_state:
	io_xdev_ext_iaa_update_stats(state, ret);
	xdev_ext_iaa_runtime_release(&state->runtime);
	kfree(state);
	return ret;
}

#else /* !XDEV_EXT_UMEM_ZEROCOPY || !XDEV_EXT_LIFECYCLE_SM */

#include <linux/errno.h>

#include "xdev_ext_iaa.h"

int io_xdev_ext_iaa_issue(struct io_kiocb *req, struct io_xdev_ext_umem *umem,
		     struct io_uring_unified_shared __user *shared,
		     const struct io_xdev_ext_iaa_params *params,
		     io_xdev_ext_iaa_stats_fn update_stats)
{
	return -EOPNOTSUPP;
}

#endif

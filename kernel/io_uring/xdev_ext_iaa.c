// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring XDEV_EXT IAA compression/decompression over registered UMEM pages.
 * Crypto API sees truthful page scatterlists; no vmap-backed fake segment or
 * hidden bounce buffer is used.
 */

#include "xdev_ext_config.h"

#if defined(XDEV_EXT_UMEM_ZEROCOPY) && defined(XDEV_EXT_LIFECYCLE_SM)

#include <crypto/acompress.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/io_uring_types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/xdev_ext_binding.h>
#include <linux/xarray.h>

#include "io_uring.h"
#include "xdev_ext_iaa.h"
#include "xdev_ext_umem.h"

struct io_xdev_ext_iaa_async {
	struct io_kiocb *io_req;
	struct io_xdev_ext_umem *umem;
	struct io_uring_unified_shared __user *shared;
	io_xdev_ext_iaa_stats_fn update_stats;
	struct io_xdev_ext_iaa_params params;
	struct xdev_ext_iaa_window_plan windows;
	struct xdev_ext_iaa_frame_claim frames;
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

	/* A fresh lookup per request observes a provider registered later. */
	state->tfm = crypto_alloc_acomp("deflate-iaa", 0, 0);
	if (IS_ERR(state->tfm)) {
		int ret = PTR_ERR(state->tfm);

		state->tfm = NULL;
		return ret;
	}
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
	crypto_free_acomp(state->tfm);
	state->tfm = NULL;
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
	u32 expected_source_state;
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

	expected_source_state = state->frames.source_mode ==
		XDEV_EXT_IAA_SOURCE_READY ? XDEV_EXT_FRAME_TX_PENDING : XDEV_EXT_FRAME_IO_PENDING;
	if (!state->frames.source_owned || !state->frames.destination_owned ||
	    xdev_ext_frame_state(&state->umem->frame_pool, windows.src_frame) !=
		expected_source_state ||
	    xdev_ext_frame_state(&state->umem->frame_pool, windows.dst_frame) !=
		XDEV_EXT_FRAME_IO_PENDING)
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

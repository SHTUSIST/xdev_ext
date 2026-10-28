// SPDX-License-Identifier: MIT
/*
 * Userspace concurrency model for nv.c's ioctl handle registry.
 *
 * The source-contract test ties this ordering to the kernel implementation.
 * This test exercises the two races which the ordering must resolve:
 *   1. unpin waits for a DMA already inside operation_lock;
 *   2. a referenced transfer which loses the race to unpin observes !live
 *      and never begins DMA.
 */
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned int checks;
static unsigned int failures;

#define EXPECT_TRUE(expr)                                                       \
	do {                                                                     \
		checks++;                                                        \
		if (!(expr)) {                                                   \
			fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n",       \
				__FILE__, __LINE__, #expr);                         \
			failures++;                                               \
		}                                                                \
	} while (0)

#define EXPECT_EQ(expected, actual)                                             \
	do {                                                                     \
		long long _expected = (long long)(expected);                     \
		long long _actual = (long long)(actual);                         \
		checks++;                                                        \
		if (_expected != _actual) {                                     \
			fprintf(stderr, "%s:%d: expected %lld, got %lld\n",      \
				__FILE__, __LINE__, _expected, _actual);            \
			failures++;                                               \
		}                                                                \
	} while (0)

struct handle_model {
	pthread_mutex_t registry_lock;
	pthread_mutex_t operation_lock;
	pthread_mutex_t event_lock;
	pthread_cond_t event;
	bool registered;
	bool live;
	bool backing_freed;
	bool freed;
	unsigned int refs;
	uintptr_t owner;
	uintptr_t owner_mm;
	uintptr_t owner_tgid;
	uint64_t user_handle;

	bool permit_transfer_lock;
	bool permit_dma_completion;
	bool transfer_has_ref;
	bool dma_started;
	bool transfer_done;
	bool unpin_started;
	bool unpin_returned;
	unsigned int dma_count;
	unsigned int rejected_count;
};

static void model_init(struct handle_model *model)
{
	memset(model, 0, sizeof(*model));
	pthread_mutex_init(&model->registry_lock, NULL);
	pthread_mutex_init(&model->operation_lock, NULL);
	pthread_mutex_init(&model->event_lock, NULL);
	pthread_cond_init(&model->event, NULL);
	model->registered = true;
	model->live = true;
	model->refs = 1; /* xarray reference */
	model->owner = 0x101;
	model->owner_mm = 0x202;
	model->owner_tgid = 0x303;
	model->user_handle = (UINT64_C(1) << 32) | 7;
}

static void model_destroy(struct handle_model *model)
{
	pthread_cond_destroy(&model->event);
	pthread_mutex_destroy(&model->event_lock);
	pthread_mutex_destroy(&model->operation_lock);
	pthread_mutex_destroy(&model->registry_lock);
}

static bool model_get(struct handle_model *model, uintptr_t owner,
		      uintptr_t owner_mm, uintptr_t owner_tgid,
		      uint64_t user_handle)
{
	bool found = false;

	pthread_mutex_lock(&model->registry_lock);
	if (model->registered && model->owner == owner &&
	    model->owner_mm == owner_mm && model->owner_tgid == owner_tgid &&
	    model->user_handle == user_handle) {
		model->refs++;
		found = true;
	}
	pthread_mutex_unlock(&model->registry_lock);
	return found;
}

static void model_put(struct handle_model *model)
{
	pthread_mutex_lock(&model->registry_lock);
	EXPECT_TRUE(model->refs > 0);
	model->refs--;
	if (!model->refs)
		model->freed = true;
	pthread_mutex_unlock(&model->registry_lock);
}

static bool model_unpin(struct handle_model *model, uintptr_t owner,
			uintptr_t owner_mm, uintptr_t owner_tgid,
			uint64_t user_handle)
{
	bool found = false;

	pthread_mutex_lock(&model->event_lock);
	model->unpin_started = true;
	pthread_cond_broadcast(&model->event);
	pthread_mutex_unlock(&model->event_lock);

	/* Mirrors xa_load/owner check/xa_erase under the registry mutex. */
	pthread_mutex_lock(&model->registry_lock);
	if (model->registered && model->owner == owner &&
	    model->owner_mm == owner_mm && model->owner_tgid == owner_tgid &&
	    model->user_handle == user_handle) {
		model->registered = false;
		found = true;
	}
	pthread_mutex_unlock(&model->registry_lock);
	if (!found)
		return false;

	/* Mirrors the post-erase operation_lock liveness transition. */
	pthread_mutex_lock(&model->operation_lock);
	model->live = false;
	model->backing_freed = true;
	pthread_mutex_unlock(&model->operation_lock);
	model_put(model);

	pthread_mutex_lock(&model->event_lock);
	model->unpin_returned = true;
	pthread_cond_broadcast(&model->event);
	pthread_mutex_unlock(&model->event_lock);
	return true;
}

static void *transfer_thread(void *arg)
{
	struct handle_model *model = arg;

	if (!model_get(model, model->owner, model->owner_mm, model->owner_tgid,
		       model->user_handle))
		return NULL;

	pthread_mutex_lock(&model->event_lock);
	model->transfer_has_ref = true;
	pthread_cond_broadcast(&model->event);
	while (!model->permit_transfer_lock)
		pthread_cond_wait(&model->event, &model->event_lock);
	pthread_mutex_unlock(&model->event_lock);

	pthread_mutex_lock(&model->operation_lock);
	if (model->live) {
		pthread_mutex_lock(&model->event_lock);
		model->dma_started = true;
		model->dma_count++;
		pthread_cond_broadcast(&model->event);
		while (!model->permit_dma_completion)
			pthread_cond_wait(&model->event, &model->event_lock);
		pthread_mutex_unlock(&model->event_lock);
	} else {
		model->rejected_count++;
	}
	pthread_mutex_unlock(&model->operation_lock);
	model_put(model);

	pthread_mutex_lock(&model->event_lock);
	model->transfer_done = true;
	pthread_cond_broadcast(&model->event);
	pthread_mutex_unlock(&model->event_lock);
	return NULL;
}

static void *unpin_thread(void *arg)
{
	struct handle_model *model = arg;

	(void)model_unpin(model, model->owner, model->owner_mm,
			  model->owner_tgid, model->user_handle);
	return NULL;
}

static void wait_event(struct handle_model *model, const bool *flag)
{
	pthread_mutex_lock(&model->event_lock);
	while (!*flag)
		pthread_cond_wait(&model->event, &model->event_lock);
	pthread_mutex_unlock(&model->event_lock);
}

static void test_unpin_waits_for_active_dma(void)
{
	struct handle_model model;
	pthread_t transfer;
	pthread_t unpin;

	model_init(&model);
	model.permit_transfer_lock = true;
	pthread_create(&transfer, NULL, transfer_thread, &model);
	wait_event(&model, &model.dma_started);
	pthread_create(&unpin, NULL, unpin_thread, &model);
	wait_event(&model, &model.unpin_started);

	pthread_mutex_lock(&model.event_lock);
	EXPECT_TRUE(!model.unpin_returned);
	model.permit_dma_completion = true;
	pthread_cond_broadcast(&model.event);
	pthread_mutex_unlock(&model.event_lock);

	pthread_join(transfer, NULL);
	pthread_join(unpin, NULL);
	EXPECT_EQ(1, model.dma_count);
	EXPECT_EQ(0, model.rejected_count);
	EXPECT_TRUE(model.unpin_returned);
	EXPECT_TRUE(model.backing_freed);
	EXPECT_TRUE(model.transfer_done);
	EXPECT_TRUE(model.freed);
	EXPECT_EQ(0, model.refs);
	model_destroy(&model);
}

static void test_unpin_wins_before_dma_lock(void)
{
	struct handle_model model;
	pthread_t transfer;

	model_init(&model);
	pthread_create(&transfer, NULL, transfer_thread, &model);
	wait_event(&model, &model.transfer_has_ref);
	EXPECT_TRUE(model_unpin(&model, model.owner, model.owner_mm,
				model.owner_tgid, model.user_handle));
	EXPECT_TRUE(model.backing_freed);
	EXPECT_TRUE(!model.freed);

	pthread_mutex_lock(&model.event_lock);
	model.permit_transfer_lock = true;
	pthread_cond_broadcast(&model.event);
	pthread_mutex_unlock(&model.event_lock);
	pthread_join(transfer, NULL);

	EXPECT_EQ(0, model.dma_count);
	EXPECT_EQ(1, model.rejected_count);
	EXPECT_TRUE(model.freed);
	EXPECT_EQ(0, model.refs);
	model_destroy(&model);
}

static void test_owner_and_double_unpin_fail_closed(void)
{
	struct handle_model model;

	model_init(&model);
	EXPECT_TRUE(!model_get(&model, model.owner + 1, model.owner_mm,
			       model.owner_tgid, model.user_handle));
	EXPECT_TRUE(!model_get(&model, model.owner, model.owner_mm + 1,
			       model.owner_tgid, model.user_handle));
	EXPECT_TRUE(!model_get(&model, model.owner, model.owner_mm,
			       model.owner_tgid + 1, model.user_handle));
	EXPECT_TRUE(!model_get(&model, model.owner, model.owner_mm,
			       model.owner_tgid, model.user_handle + (UINT64_C(1) << 32)));
	EXPECT_TRUE(!model_unpin(&model, model.owner + 1, model.owner_mm,
				 model.owner_tgid, model.user_handle));
	EXPECT_TRUE(model.registered);
	EXPECT_TRUE(model_unpin(&model, model.owner, model.owner_mm,
				model.owner_tgid, model.user_handle));
	EXPECT_TRUE(!model_unpin(&model, model.owner, model.owner_mm,
				 model.owner_tgid, model.user_handle));
	EXPECT_TRUE(model.freed);
	EXPECT_EQ(0, model.refs);
	model_destroy(&model);
}

static void test_reused_slot_rejects_stale_generation(void)
{
	struct handle_model old;
	struct handle_model replacement;
	uint64_t stale_handle;

	model_init(&old);
	stale_handle = old.user_handle;
	EXPECT_TRUE(model_unpin(&old, old.owner, old.owner_mm, old.owner_tgid,
				stale_handle));
	model_destroy(&old);

	model_init(&replacement);
	/* Same low 32-bit xarray slot, distinct nonzero generation. */
	replacement.user_handle += UINT64_C(1) << 32;
	EXPECT_EQ((uint32_t)stale_handle, (uint32_t)replacement.user_handle);
	EXPECT_TRUE(!model_get(&replacement, replacement.owner,
			       replacement.owner_mm, replacement.owner_tgid,
			       stale_handle));
	EXPECT_TRUE(model_get(&replacement, replacement.owner,
			      replacement.owner_mm, replacement.owner_tgid,
			      replacement.user_handle));
	model_put(&replacement);
	EXPECT_TRUE(model_unpin(&replacement, replacement.owner,
				replacement.owner_mm, replacement.owner_tgid,
				replacement.user_handle));
	model_destroy(&replacement);
}

int main(void)
{
	test_unpin_waits_for_active_dma();
	test_unpin_wins_before_dma_lock();
	test_owner_and_double_unpin_fail_closed();
	test_reused_slot_rejects_stale_generation();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return 1;
	}
	printf("PASS: %u checks\n", checks);
	return 0;
}

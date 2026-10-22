/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_UMEM_KERNEL_SHIM_H
#define XDEV_EXT_UMEM_KERNEL_SHIM_H

#define IOU_CORE_H
#define IO_URING_XDEV_EXT_UMEM_H

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define __user
#define GFP_KERNEL 0
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define FOLL_WRITE 1
#define FOLL_LONGTERM 2
#define VM_MAP 0
#define PAGE_KERNEL 0

typedef uint32_t u32;
typedef uint64_t u64;

struct page { unsigned char unused; };

/* Model an unmap/remap at the same virtual address by changing the physical
 * page identities returned by the next pin_user_pages_fast() call. */
static atomic_uint test_page_generation;

struct mm_struct {
	atomic_int mm_count;
	unsigned int id;
};

struct task_struct {
	struct mm_struct *mm;
};

static _Thread_local struct task_struct *current;

struct io_uring_unified_shared {
	u64 marker;
};

struct io_uring_xdev_ext_umem_reg {
	u64 addr;
	u64 size;
	u64 shared_addr;
	u32 frame_size;
	u32 flags;
};

typedef struct {
	atomic_int refs;
} atomic_t;

typedef atomic_t refcount_t;

struct mutex {
	pthread_mutex_t native;
};

#define DEFINE_MUTEX(name) \
	struct mutex name = { .native = PTHREAD_MUTEX_INITIALIZER }

static inline void mutex_lock(struct mutex *lock)
{
	if (pthread_mutex_lock(&lock->native))
		abort();
}

static inline void mutex_unlock(struct mutex *lock)
{
	if (pthread_mutex_unlock(&lock->native))
		abort();
}

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

#define LIST_HEAD(name) \
	struct list_head name = { .next = &name, .prev = &name }

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define list_entry(ptr, type, member) container_of(ptr, type, member)

static inline void list_add_tail(struct list_head *entry, struct list_head *head)
{
	entry->prev = head->prev;
	entry->next = head;
	head->prev->next = entry;
	head->prev = entry;
}

static inline void list_del(struct list_head *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->next = NULL;
	entry->prev = NULL;
}

#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member); \
	     &(pos)->member != (head); \
	     pos = list_entry((pos)->member.next, __typeof__(*pos), member))

#define list_for_each_entry_safe(pos, tmp, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member), \
	     tmp = list_entry((pos)->member.next, __typeof__(*pos), member); \
	     &(pos)->member != (head); \
	     pos = tmp, tmp = list_entry((tmp)->member.next, __typeof__(*tmp), member))

#define WRITE_ONCE(x, value) ((x) = (value))
#define READ_ONCE(x) (x)

static pthread_mutex_t test_pause_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t test_pause_cond = PTHREAD_COND_INITIALIZER;
static bool test_pause_enabled;
static bool test_put_paused;
static bool test_put_holds_registry_lock;
static bool test_continue_put;
static atomic_t *test_pause_ref;

static void test_pause_final_put(bool holds_registry_lock)
{
	pthread_mutex_lock(&test_pause_lock);
	test_put_paused = true;
	test_put_holds_registry_lock = holds_registry_lock;
	pthread_cond_broadcast(&test_pause_cond);
	while (!test_continue_put)
		pthread_cond_wait(&test_pause_cond, &test_pause_lock);
	pthread_mutex_unlock(&test_pause_lock);
}

static inline void atomic_set(atomic_t *ref, int value)
{
	atomic_store(&ref->refs, value);
}

static inline void atomic_inc(atomic_t *ref)
{
	atomic_fetch_add(&ref->refs, 1);
}

static inline bool atomic_dec_and_test(atomic_t *ref)
{
	bool zero = atomic_fetch_sub(&ref->refs, 1) == 1;

	if (zero && test_pause_enabled && ref == test_pause_ref)
		test_pause_final_put(false);
	return zero;
}

static inline void refcount_set(refcount_t *ref, int value)
{
	atomic_set(ref, value);
}

static inline void refcount_inc(refcount_t *ref)
{
	atomic_inc(ref);
}

static inline bool refcount_dec_and_mutex_lock(refcount_t *ref,
					       struct mutex *lock)
{
	int value = atomic_load(&ref->refs);

	while (value > 1) {
		if (atomic_compare_exchange_weak(&ref->refs, &value, value - 1))
			return false;
	}
	mutex_lock(lock);
	if (test_pause_enabled && ref == test_pause_ref)
		test_pause_final_put(true);
	if (atomic_fetch_sub(&ref->refs, 1) != 1) {
		mutex_unlock(lock);
		return false;
	}
	return true;
}

static inline void mmgrab(struct mm_struct *mm)
{
	atomic_fetch_add(&mm->mm_count, 1);
}

static inline void mmdrop(struct mm_struct *mm)
{
	atomic_fetch_sub(&mm->mm_count, 1);
}

static void *test_watched_umem;
static atomic_int test_watched_free_count;

static inline void *kzalloc(size_t size, int flags)
{
	(void)flags;
	return calloc(1, size);
}

static inline void kfree(void *ptr)
{
	if (ptr == test_watched_umem) {
		atomic_fetch_add(&test_watched_free_count, 1);
	}
	/* Keep freed objects addressable so race assertions can diagnose UAF. */
}

static inline void *kvmalloc_array(size_t count, size_t size, int flags)
{
	(void)flags;
	return calloc(count, size);
}

static inline void kvfree(void *ptr)
{
	(void)ptr;
}

static inline int copy_from_user(void *to, const void *from, size_t size)
{
	memcpy(to, from, size);
	return 0;
}

static inline int pin_user_pages_fast(unsigned long start, unsigned int nr_pages,
				      unsigned int flags, struct page **pages)
{
	unsigned int i;
	uintptr_t generation = atomic_load(&test_page_generation);

	(void)start;
	(void)flags;
	for (i = 0; i < nr_pages; i++)
		pages[i] = (struct page *)((generation << 20) + i + 1);
	return nr_pages;
}

static inline void unpin_user_pages(struct page **pages, unsigned int nr_pages)
{
	(void)pages;
	(void)nr_pages;
}

static inline void *vmap(struct page **pages, unsigned int nr_pages,
			 int flags, int prot)
{
	(void)pages;
	(void)flags;
	(void)prot;
	return calloc(nr_pages, PAGE_SIZE);
}

static inline void vunmap(void *addr)
{
	(void)addr;
}

struct io_xdev_ext_umem {
	struct page **pages;
	void *vmap_addr;
	u32 page_offset;
	u64 user_addr;
	u64 size;
	u32 nr_pages;
	u32 frame_size;
	u32 nr_frames;
	struct io_uring_unified_shared __user *shared;
	struct mm_struct *mm;
	refcount_t refcount;
};

struct io_ring_ctx {
	struct io_xdev_ext_umem *xdev_ext_umem;
	struct io_uring_unified_shared __user *xdev_ext_umem_shared;
};

#endif /* XDEV_EXT_UMEM_KERNEL_SHIM_H */

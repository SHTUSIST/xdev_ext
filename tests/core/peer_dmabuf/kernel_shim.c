// SPDX-License-Identifier: GPL-2.0
#include "kernel_shim.h"
struct test_env env;
struct task_struct *current;
struct user_struct *test_current_user;
unsigned test_mutex_acquisitions;
union alloc_header { max_align_t align; size_t bytes; };
struct fake_attachment {
	struct dma_buf_attachment base;
	struct scatterlist sg[2];
	struct sg_table table;
	bool pinned, mapped;
};

void *test_kalloc(size_t n, bool zero)
{
	union alloc_header *h;
	env.alloc_calls++;
	if (env.fail_alloc && env.alloc_calls == env.fail_alloc)
		return NULL;
	/* The fixture never allocates huge malformed geometry. A request past
	 * this cap returns ENOMEM; the production rule must reject overflow
	 * before invoking it, while ordinary allocations are below 1 MiB. */
	if (n > (1U << 24) || n > SIZE_MAX - sizeof(*h)) return NULL;
	h = malloc(sizeof(*h) + n);
	assert(h);
	h->bytes = n;
	env.live_allocs++;
	if (zero) memset(h + 1, 0, n);
	return h + 1;
}

void *test_karray(size_t n, size_t size, bool zero)
{
	if (size && n > SIZE_MAX / size) return NULL;
	return test_kalloc(n * size, zero);
}

void test_kfree(const void *p)
{
	if (!p) return;
	assert(env.live_allocs);
	env.live_allocs--;
	free((union alloc_header *)p - 1);
}

struct user_struct *get_current_user(void) { return get_uid(test_current_user); }
unsigned long test_rlimit(unsigned int resource)
{ assert(resource == RLIMIT_MEMLOCK); return env.limit; }

void test_env_init(const struct dma_buf_ops *ops)
{
	memset(&env, 0, sizeof(env));
	env.user.refs = env.mm.refs = 1;
	env.exporter.refs = 1;
	env.file = (struct file){.refs = 1, .exporter = &env.exporter};
	mutex_init(&env.resv.lock);
	env.buf = (struct dma_buf){.size = 12288, .ops = ops, .file = &env.file,
		.resv = &env.resv, .exp_name = "system"};
	env.sg[0] = (struct scatterlist){.dma_address = 0x10000, .dma_length = 8192,
		.length = 8192, .next = &env.sg[1]};
	env.sg[1] = (struct scatterlist){.dma_address = 0x90000, .dma_length = 4096,
		.length = 4096};
	env.task.mm = &env.mm;
	current = &env.task;
	test_current_user = &env.user;
	env.limit = 3 * PAGE_SIZE;
	env.needs_sync_address = UINT64_MAX;
}

void test_notify(struct dma_buf_attachment *a)
{
	unsigned before = test_mutex_acquisitions;
	assert(a && a->importer_ops && a->importer_ops->move_notify);
	dma_resv_assert_held(a->dmabuf->resv);
	a->importer_ops->move_notify(a);
	assert(test_mutex_acquisitions == before);
}

struct dma_buf_attachment *dma_buf_dynamic_attach(struct dma_buf *b,
		struct device *d, const struct dma_buf_attach_ops *ops, void *priv)
{
	struct fake_attachment *a;
	assert(!b->resv->lock.held);
	assert(ops && ops->move_notify && ops->allow_peer2peer);
	env.attaches++;
	if (env.attach_error) return ERR_PTR(env.attach_error);
	a = calloc(1, sizeof(*a));
	assert(a);
	a->base = (struct dma_buf_attachment){.dmabuf = b, .dev = d,
		.importer_ops = ops, .importer_priv = priv, .peer2peer = true};
	a->sg[0] = env.sg[0];
	a->sg[0].next = &a->sg[1];
	a->sg[1] = env.sg[1];
	a->table = (struct sg_table){.sgl = a->sg, .nents = 2, .orig_nents = 2};
	env.last_attach = &a->base;
	return &a->base;
}

void dma_buf_detach(struct dma_buf *b, struct dma_buf_attachment *base)
{
	struct fake_attachment *a = container_of(base, struct fake_attachment, base);
	assert(base->dmabuf == b && !b->resv->lock.held);
	assert(!a->pinned && !a->mapped);
	env.detaches++;
	if (env.last_attach == base) env.last_attach = NULL;
	free(a);
}

int dma_buf_pin(struct dma_buf_attachment *base)
{
	struct fake_attachment *a = container_of(base, struct fake_attachment, base);
	dma_resv_assert_held(base->dmabuf->resv);
	assert(!a->pinned);
	env.pins++;
	if (env.move_on_pin) test_notify(base);
	if (env.pin_error) return env.pin_error;
	a->pinned = true;
	return 0;
}

void dma_buf_unpin(struct dma_buf_attachment *base)
{
	struct fake_attachment *a = container_of(base, struct fake_attachment, base);
	dma_resv_assert_held(base->dmabuf->resv);
	assert(a->pinned && !a->mapped);
	a->pinned = false;
	env.unpins++;
}

struct sg_table *dma_buf_map_attachment(struct dma_buf_attachment *base,
				      enum dma_data_direction direction)
{
	struct fake_attachment *a = container_of(base, struct fake_attachment, base);
	dma_resv_assert_held(base->dmabuf->resv);
	assert(direction == DMA_BIDIRECTIONAL && a->pinned && !a->mapped);
	env.maps++;
	if (env.move_on_map) test_notify(base);
	if (env.map_error) return ERR_PTR(env.map_error);
	a->mapped = true;
	return &a->table;
}

void dma_buf_unmap_attachment(struct dma_buf_attachment *base, struct sg_table *sgt,
			     enum dma_data_direction direction)
{
	struct fake_attachment *a = container_of(base, struct fake_attachment, base);
	dma_resv_assert_held(base->dmabuf->resv);
	assert(direction == DMA_BIDIRECTIONAL && a->pinned && a->mapped);
	assert(sgt == &a->table && sgt->nents == 2 && sgt->orig_nents == 2);
	a->mapped = false;
	env.unmaps++;
}

long dma_resv_wait_timeout(struct dma_resv *r, enum dma_resv_usage usage,
			   bool intr, unsigned long timeout)
{
	(void)intr; (void)timeout;
	assert(r == &env.resv && usage == DMA_RESV_USAGE_KERNEL);
	env.waits++;
	return env.wait_error ? env.wait_error : 1;
}

struct dma_buf *dma_buf_get(int fd)
{
	assert(!env.resv.lock.held);
	if (fd < 0) return ERR_PTR(-EBADF);
	if (fd != 7) return ERR_PTR(-EINVAL);
	get_dma_buf(&env.buf);
	return &env.buf;
}

void dma_buf_put(struct dma_buf *b)
{
	assert(!b->resv->lock.held);
	env.puts++;
	fput(b->file);
}

bool dma_need_sync(struct device *d, dma_addr_t address)
{ return !d->dma_coherent || address == env.needs_sync_address; }

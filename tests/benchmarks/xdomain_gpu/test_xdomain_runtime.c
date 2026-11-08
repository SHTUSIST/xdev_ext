// SPDX-License-Identifier: GPL-2.0
/* Exercise the production orchestration and JSON, replacing device/control I/O only.
 * This is host correctness evidence, not a CUDA/CE/XDOMAIN execution or benchmark.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <dlfcn.h>
#include "xdg_net.h"

static int control_barrier(int fd, uint8_t tag);
static int control_send(int fd, const void *buf, size_t size);
static int control_recv(int fd, void *buf, size_t size);

/* Keep all production loop, oracle and reporting bodies unchanged. */
#define xdg_barrier control_barrier
#define xdg_send_all control_send
#define xdg_recv_all control_recv
#define main xdomain_gpu_unused_main
#include "xdomain_gpu.c"
#undef main
#undef xdg_barrier
#undef xdg_send_all
#undef xdg_recv_all

struct xdev_ext_session {
	bool rx;
	uint64_t pending, done;
};

static struct run *active;
static const struct plan *active_plan;
static bool drop_all, fail_poison;
static uint64_t skip_prefix, starts;

static int context_get(void **ctx) { *ctx = NULL; return 0; }
static int context_set(void *ctx) { (void)ctx; return 0; }
static int context_sync(void) { return 0; }
static int memory_set(uint64_t ptr, unsigned char value, size_t size)
{
	if (fail_poison)
		return 7;
	memset((void *)(uintptr_t)ptr, value, size);
	return 0;
}
static int copy_htod(uint64_t ptr, const void *buf, size_t size)
{
	memcpy((void *)(uintptr_t)ptr, buf, size);
	return 0;
}
static int copy_dtoh(void *buf, uint64_t ptr, size_t size)
{
	memcpy(buf, (void *)(uintptr_t)ptr, size);
	return 0;
}

void *__wrap_dlsym(void *handle, const char *name)
{
	(void)handle;
	if (!strcmp(name, "cuMemcpyHtoD_v2"))
		return (void *)copy_htod;
	if (!strcmp(name, "cuMemcpyDtoH_v2"))
		return (void *)copy_dtoh;
	return NULL;
}

static int control_barrier(int fd, uint8_t tag)
{
	(void)fd; (void)tag;
	return 0;
}
static int control_send(int fd, const void *buf, size_t size)
{
	(void)fd; (void)buf; (void)size;
	return 0;
}
static int control_recv(int fd, void *buf, size_t size)
{
	(void)fd;
	memset(buf, 1, size); /* peer's successful final-window verdict */
	return 0;
}

int xdev_ext_session_start_frames(struct xdev_ext_session *s,
				 const struct xdev_ext_start_frames_opts *opts)
{
	starts++;
	s->pending += opts->nr_batches;
	return 0;
}

int xdev_ext_session_wait(struct xdev_ext_session *s, int timeout_ms,
			 struct xdev_ext_mech_stats *stats)
{
	const struct plan *p = active_plan;
	uint64_t seed = active->o.seed;
	uint8_t *peer_image;

	(void)timeout_ms;
	assert(s->pending);
	if (s->rx && !drop_all) {
		if (active->o.mode == MODE_PINGPONG)
			seed += (uint64_t)(1 - active->o.rank);
		peer_image = malloc(p->group);
		assert(peer_image);
		for (uint64_t i = 0; i < p->depth; i++) {
			/* A remote sender supplies a whole slot, or loses a prefix. */
			xdg_fill(peer_image, p->group, seed, i);
			assert(skip_prefix <= p->group);
			memcpy((uint8_t *)(uintptr_t)active->rx.cuda.va + i * p->group + skip_prefix,
			       peer_image + skip_prefix, p->group - skip_prefix);
		}
		free(peer_image);
	}
	s->done += s->pending;
	s->pending = 0;
	*stats = (struct xdev_ext_mech_stats){ .batches_done = s->done };
	return 0;
}

static void setup(struct run *r, enum mode mode)
{
	*r = (struct run){ .o = { .mode = mode, .rank = mode == MODE_STREAM ? 1 : 0,
		.seed = 7, .window = 2, .iters = 2, .messages = 100, .timeout_ms = 1 } };
	r->scratch = malloc(XDG_MAX_GROUP);
	assert(r->scratch);
	for (int i = 0; i < 2; i++) {
		struct dir *d = i ? &r->rx : &r->tx;
		d->s = calloc(1, sizeof(*d->s));
		assert(d->s);
		d->s->rx = i;
		d->cuda = (struct xdev_ext_mech_cuda){ .lib = (void *)1,
			.va = (uintptr_t)malloc(2 * XDG_MAX_GROUP), .vmm_bytes = 2 * XDG_MAX_GROUP,
			.ctx_get = context_get, .ctx_set = context_set, .ctx_sync = context_sync,
			.memset_d8 = memory_set, .memcpy_dtoh = copy_dtoh };
		assert(d->cuda.va);
		memset((void *)(uintptr_t)d->cuda.va, POISON, d->cuda.vmm_bytes);
	}
	active = r;
}

static int run_size(struct run *r, struct plan *p, uint64_t size)
{
	assert(!make_plan(&r->o, size, p));
	active_plan = p;
	r->rx.done = r->tx.done = 0;
	r->rx.s->done = r->tx.s->done = 0;
	return r->o.mode == MODE_STREAM ? stream(r, p) : pingpong(r, p);
}

int main(int argc, char **argv)
{
	struct run r;
	struct plan p;
	bool pp;

	assert(argc == 2);
	pp = !strcmp(argv[1], "stale-pingpong");
	setup(&r, pp ? MODE_PINGPONG : MODE_STREAM);
	if (!strcmp(argv[1], "stale-stream") || pp) {
		assert(!run_size(&r, &p, pp ? 64 : XDG_MAX_GROUP));
		if (pp)
			skip_prefix = 64; /* The prior size left an identical valid prefix. */
		else
			drop_all = true; /* Above the split limit the same slots are reused. */
		assert(run_size(&r, &p, pp ? 128 : 2 * XDG_MAX_GROUP) == -EIO);
	} else if (!strcmp(argv[1], "count")) {
		assert(!run_size(&r, &p, 64));
	} else if (!strcmp(argv[1], "poison-failure")) {
		fail_poison = true;
		assert(run_size(&r, &p, 64) == -EIO);
		assert(!starts);
	} else {
		assert(!"unknown scenario");
	}
	free((void *)(uintptr_t)r.tx.cuda.va);
	free((void *)(uintptr_t)r.rx.cuda.va);
	free(r.tx.s);
	free(r.rx.s);
	free(r.scratch);
	return 0;
}

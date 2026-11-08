// SPDX-License-Identifier: GPL-2.0
/* Actual library allocation/free and production caller. Only kernel registration
 * and CUDA entry points are host boundaries; no device execution is claimed.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <sys/mman.h>
#include "../../../kernel/include/uapi/linux/io_uring.h"
#define main xdg_unused_main
#include "xdomain_gpu.c"
#undef main
#include "../../../kernel/tools/xdev_ext_mech/lib/libxdev_ext_internal.h"

static int stop_result, stats_result, stop_calls, unmaps, releases, fail_unmap, retained_ring = -1;
static void *registered_umem;

static int setup(unsigned entries, struct io_uring_params *p)
{
	(void)entries; (void)p;
	return open("/dev/null", O_RDWR | O_CLOEXEC);
}

static int registration(int fd, unsigned opcode, void *arg, unsigned count)
{
	struct io_uring_xdev_ext_mech *op = arg;

	assert(fd >= 0 && count == 1);
	if (opcode == IORING_REGISTER_XDEV_EXT_UMEM) {
		registered_umem = (void *)(uintptr_t)((struct io_uring_xdev_ext_umem_reg *)arg)->addr;
		return 0;
	}
	assert(opcode == IORING_REGISTER_XDEV_EXT_MECH);
	switch (op->op) {
	case XDEV_EXT_MECH_OP_CREATE:
		((struct xdev_ext_mech_create *)(uintptr_t)op->arg)->session_id = 42;
		return 0;
	case XDEV_EXT_MECH_OP_STOP:
		stop_calls++;
		return retained_ring >= 0 ? (fd == retained_ring ? -EBUSY : 0) : stop_result;
	case XDEV_EXT_MECH_OP_STATS:
		return stats_result;
	default:
		assert(!"unexpected operation");
		return -EINVAL;
	}
}

static void no_sleep(unsigned usec) { (void)usec; }
static int context_get(void **ctx) { *ctx = NULL; return 0; }
static int context_set(void *ctx) { (void)ctx; return 0; }
static int unmap_window(uint64_t ptr, size_t size)
{
	assert(ptr == 4096 && size == 4096); unmaps++; return fail_unmap;
}
static int address_free(uint64_t ptr, size_t size)
{
	assert(ptr == 4096 && size == 4096); return 0;
}
static int release_window(uint64_t handle)
{
	assert(handle == 7); releases++; return 0;
}
int __wrap_dlclose(void *handle) { assert(handle == (void *)1); return 0; }

static struct dir fresh(bool created)
{
	struct xdev_ext_pool_opts pool = { .sz = sizeof(pool),
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .nr_frames = 1 };
	struct xdev_ext_create_opts c = { .sz = sizeof(c), .group_bytes = 4096,
		.depth = 1, .nr_stages = 1, .layout = { XDEV_EXT_FRAME_SIZE, 0, 4096, 4096 } };
	struct dir d = { .ce_fd = open("/dev/null", O_RDWR | O_CLOEXEC) };

	assert(d.ce_fd >= 0);
	assert(!xdev_ext_session_open(&pool, &d.s));
	if (created)
		assert(!xdev_ext_session_create(d.s, &c));
	d.cuda = (struct xdev_ext_mech_cuda){ .lib = (void *)1, .vmm = 1, .mapped = 1,
		.reserved = 1, .created = 1, .exported = 1, .export_fd = open("/dev/null", O_RDWR),
		.va = 4096, .vmm_bytes = 4096, .vmm_handle = 7, .ctx_get = context_get,
		.ctx_set = context_set, .mem_unmap = unmap_window, .address_free = address_free,
		.mem_release = release_window };
	assert(d.cuda.export_fd >= 0);
	return d;
}

static void held(const struct dir *d, int ring)
{
	unsigned char resident;

	assert(d->s != NULL);
	assert(fcntl(ring, F_GETFD) >= 0);
	assert(!mincore(registered_umem, 4096, &resident));
	assert(fcntl(d->ce_fd, F_GETFD) >= 0);
	assert(fcntl(d->cuda.export_fd, F_GETFD) >= 0);
	assert(d->cuda.mapped && d->cuda.lib);
}

int main(int argc, char **argv)
{
	const struct xdev_ext_sys hooks = { .io_uring_setup = setup,
		.io_uring_register = registration, .usleep = no_sleep };
	struct dir d;
	int ring, ret;

	assert(argc == 2);
	xdev_ext__set_sys(&hooks);
	if (!strcmp(argv[1], "none")) {
		d = (struct dir){ .ce_fd = -1 };
		assert(!close_dir_session(&d));
		return 0;
	}
	d = fresh(strcmp(argv[1], "uncreated") != 0);
	ring = xdev_ext_session_ring_fd(d.s);
	if (!strcmp(argv[1], "mixed-rx")) {
		struct run r = { .tx = d, .rx = fresh(true), .ctl = open("/dev/null", O_RDWR) };

		retained_ring = xdev_ext_session_ring_fd(r.rx.s);
		assert(close_resources(&r) == -EBUSY);
		assert(!r.tx.s && !r.tx.cuda.lib && r.tx.ce_fd == -1);
		held(&r.rx, retained_ring);
		assert(fcntl(r.ctl, F_GETFD) >= 0 && unmaps == 1 && releases == 1);
		stats_result = -ENOENT;
		assert(close_resources(&r) == -EBUSY);
		assert(!r.rx.s && !r.rx.cuda.lib && r.rx.ce_fd == -1 && r.ctl == -1);
		assert(unmaps == 2 && releases == 2);
		assert(!close_resources(&r));
		return 0;
	}
	if (!strcmp(argv[1], "resources-none") || !strcmp(argv[1], "cuda-retry")) {
		struct run r = { .tx = d, .rx.ce_fd = -1, .ctl = open("/dev/null", O_RDWR) };

		assert(!close_dir_session(&r.tx));
		if (!strcmp(argv[1], "cuda-retry")) {
			fail_unmap = 7;
			assert(close_resources(&r) == -EIO);
			assert(!r.tx.s && r.tx.cuda.lib && r.tx.cuda.mapped && r.tx.cuda.created);
			assert(unmaps == 1 && releases == 0);
			fail_unmap = 0;
		}
		assert(!close_resources(&r));
		assert(!r.tx.s && !r.tx.cuda.lib && r.tx.ce_fd == -1 && r.ctl == -1);
		assert(releases == 1);
		assert(!close_resources(&r));
		return 0;
	}
	if (!strncmp(argv[1], "resources-", 10)) {
		struct run r = { .tx = d, .rx.ce_fd = -1, .ctl = open("/dev/null", O_RDWR) };
		int control = r.ctl, ce = d.ce_fd, exported = d.cuda.export_fd;

		assert(control >= 0);
		stop_result = !strcmp(argv[1], "resources-retained") ? -EBUSY : -EAGAIN;
		assert(close_resources(&r) == stop_result);
		held(&r.tx, ring);
		assert(!unmaps && !releases);
		assert(r.ctl == control && fcntl(control, F_GETFD) >= 0);
		if (stop_result == -EBUSY)
			stats_result = -ENOENT;
		else
			stop_result = 0;
		assert(close_resources(&r) == stop_result);
		assert(!r.tx.s && !r.tx.cuda.lib && r.tx.ce_fd == -1 && r.ctl == -1);
		assert(fcntl(ce, F_GETFD) == -1 && errno == EBADF);
		assert(fcntl(exported, F_GETFD) == -1 && errno == EBADF);
		assert(fcntl(control, F_GETFD) == -1 && errno == EBADF);
		assert(unmaps == 1 && releases == 1);
		assert(!close_resources(&r));
		return 0;
	}
	if (!strcmp(argv[1], "retained")) {
		stop_result = -EBUSY;
		assert(close_dir_session(&d) == -EBUSY);
		held(&d, ring);
		assert(xdev_ext_session_retained(d.s));
		stats_result = -ENOENT;
		assert(close_dir_session(&d) == -EBUSY); /* preserve the observed STOP error */
	} else if (!strcmp(argv[1], "eagain")) {
		stop_result = -EAGAIN;
		assert(close_dir_session(&d) == -EAGAIN);
		held(&d, ring);
		assert(!xdev_ext_session_retained(d.s));
		stop_result = 0;
		assert(!close_dir_session(&d));
	} else {
		if (!strcmp(argv[1], "released-error")) {
			stop_result = -EIO;
			stats_result = -ENOENT;
		}
		ret = close_dir_session(&d);
		assert(ret == (!strcmp(argv[1], "uncreated") ? -ENOTCONN : stop_result));
	}
	assert(d.s == NULL);
	assert(fcntl(ring, F_GETFD) == -1 && errno == EBADF);
	assert(!close_dir_session(&d));
	assert(!xdev_ext_mech_cuda_close(&d.cuda));
	close(d.ce_fd);
	assert(unmaps == 1 && releases == 1);
	return 0;
}

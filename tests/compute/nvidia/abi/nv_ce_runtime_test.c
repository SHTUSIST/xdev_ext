// SPDX-License-Identifier: GPL-2.0
/*
 * nv_ce_runtime_test - copy-engine round trips on a real GPU through the
 * XDEV_EXT P2P ioctls, the first thing run in a user-approved GPU window.
 *
 * It pins a host region, allocates GPU memory with the CUDA driver API on
 * the GPU behind --gpu-device, and for every case of nv_ce_runtime_cases.h
 * copies host to GPU with the copy engine and reads the GPU back through
 * CUDA, then writes the GPU through CUDA and copies GPU to host with the
 * copy engine; both checks cover the guard bytes around the copy, so data
 * landing anywhere else shows.  A batch of 64 copies goes through the batch
 * ioctl.  Then come requests the driver must refuse before any copy, a
 * round trip that shows the refusals left the copy path usable, and a
 * double unpin.
 *
 * Without --i-have-the-gpu-window it refuses before touching any device,
 * and the -host build (no CUDA) always refuses.  Exit status: 0 every check
 * passed, 1 a check failed, 2 refused or bad arguments, 3 setup failed.
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "nv_ce_runtime_cases.h"

#ifdef XDEV_EXT_NV_CE_WITH_CUDA
#include <cuda.h>
#include <strings.h>

#include "../../../include/xdev_ext_gpu_identity.h"
#include "../../../include/xdev_ext_nv_p2p_ioctl.h"
#define NV_CE_WITH_CUDA		true
#else
#define NV_CE_WITH_CUDA		false
#endif

enum {
	NV_CE_EXIT_PASS,
	NV_CE_EXIT_FAIL,
	NV_CE_EXIT_REFUSED,
	NV_CE_EXIT_SETUP,
};

struct nv_ce_opts {
	const char *gpu_device;
	bool window;
};

#ifdef XDEV_EXT_NV_CE_WITH_CUDA
struct nv_ce_rt {
	int fd;
	CUdevice dev;
	CUcontext ctx;
	bool ctx_retained;
	CUdeviceptr gpu;
	uint8_t *host;		/* NV_CE_HOST_BYTES, pinned */
	uint8_t *check;		/* NV_CE_AREA, CUDA's view of the GPU */
	uint64_t handle;
};

static int nv_ce_cuda(CUresult result, const char *what)
{
	const char *name = NULL;

	if (result == CUDA_SUCCESS)
		return 0;
	(void)cuGetErrorName(result, &name);
	fprintf(stderr, "nv_ce_runtime: %s: %s\n", what,
		name ? name : "CUDA error");
	return -EIO;
}

/* The CUDA device with the PCI address of the opened NVIDIA device node. */
static int nv_ce_cuda_setup(struct nv_ce_rt *rt, const char *gpu_device)
{
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };
	int count = 0, matches = 0, ret, i;

	ret = xdev_ext_gpu_identity_from_opened(rt->fd, gpu_device,
					   XDEV_EXT_GPU_IDENTITY_ANY_MINOR, bdf);
	if (ret) {
		fprintf(stderr, "nv_ce_runtime: identity of %s: %s\n",
			gpu_device, strerror(-ret));
		return ret;
	}
	ret = nv_ce_cuda(cuInit(0), "cuInit");
	if (!ret)
		ret = nv_ce_cuda(cuDeviceGetCount(&count), "cuDeviceGetCount");
	for (i = 0; !ret && i < count; i++) {
		char cuda_bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };
		CUdevice dev;

		ret = nv_ce_cuda(cuDeviceGet(&dev, i), "cuDeviceGet");
		if (!ret)
			ret = nv_ce_cuda(cuDeviceGetPCIBusId(cuda_bdf,
							     sizeof(cuda_bdf),
							     dev),
					 "cuDeviceGetPCIBusId");
		if (!ret && !strcasecmp(cuda_bdf, bdf)) {
			rt->dev = dev;
			matches++;
		}
	}
	if (ret)
		return ret;
	if (matches != 1) {
		fprintf(stderr, "nv_ce_runtime: %d CUDA devices at %s\n",
			matches, bdf);
		return -EXDEV;
	}
	ret = nv_ce_cuda(cuDevicePrimaryCtxRetain(&rt->ctx, rt->dev),
			 "cuDevicePrimaryCtxRetain");
	if (ret)
		return ret;
	rt->ctx_retained = true;
	ret = nv_ce_cuda(cuCtxSetCurrent(rt->ctx), "cuCtxSetCurrent");
	if (!ret)
		ret = nv_ce_cuda(cuMemAlloc(&rt->gpu, NV_CE_AREA), "cuMemAlloc");
	if (!ret)
		printf("XDEV_EXT_NV_CE_GPU bdf=%s gpu=0x%llx bytes=%llu\n", bdf,
		       (unsigned long long)rt->gpu,
		       (unsigned long long)NV_CE_AREA);
	return ret;
}

/* @buf: the guard, @size bytes of pattern @seed, the guard. */
static bool nv_ce_matches(const uint8_t *buf, uint32_t seed, uint64_t size)
{
	uint64_t i;

	for (i = 0; i < NV_CE_GUARD; i++)
		if (buf[i] != NV_CE_GUARD_BYTE ||
		    buf[NV_CE_GUARD + size + i] != NV_CE_GUARD_BYTE)
			return false;
	for (i = 0; i < size; i++)
		if (buf[NV_CE_GUARD + i] != nv_ce_pattern(seed, i))
			return false;
	return true;
}

static void nv_ce_fill(uint8_t *buf, uint32_t seed, uint64_t size)
{
	uint64_t i;

	for (i = 0; i < size; i++)
		buf[i] = nv_ce_pattern(seed, i);
}

/*
 * Copy @size bytes from host area offset @host_off to GPU offset @gpu_off by
 * the copy engine, then check them and their guards through CUDA.  1 on a
 * failed check, -EIO when CUDA itself failed.
 */
static int nv_ce_h2d_check(struct nv_ce_rt *rt, const char *name,
			   uint64_t host_off, uint64_t gpu_off, uint64_t size,
			   uint32_t seed, bool *ok)
{
	CUdeviceptr gpu = rt->gpu + gpu_off;
	uint64_t span = size + 2 * NV_CE_GUARD;
	struct xdev_ext_nv_p2p_dma_xfer xfer = {
		.handle = rt->handle,
		.gpu_offset = gpu,
		.umem_offset = host_off,
		.size = size,
		.direction = XDEV_EXT_NV_P2P_UMEM_TO_GPU,
	};

	nv_ce_fill(rt->host + host_off, seed, size);
	if (nv_ce_cuda(cuMemsetD8(gpu - NV_CE_GUARD, NV_CE_GUARD_BYTE, span),
		       "cuMemsetD8") ||
	    nv_ce_cuda(cuCtxSynchronize(), "cuCtxSynchronize"))
		return -EIO;
	if (xdev_ext_nv_p2p_dma_xfer(rt->fd, &xfer)) {
		fprintf(stderr, "nv_ce_runtime: %s h2d: %s status=0x%x\n", name,
			strerror(errno), xfer.status);
		*ok = false;
		return 1;
	}
	if (nv_ce_cuda(cuMemcpyDtoH(rt->check, gpu - NV_CE_GUARD, span),
		       "cuMemcpyDtoH"))
		return -EIO;
	*ok = nv_ce_matches(rt->check, seed, size);
	return !*ok;
}

/* GPU offset @gpu_off, written through CUDA, to the destination area. */
static int nv_ce_d2h_check(struct nv_ce_rt *rt, const char *name,
			   uint64_t host_off, uint64_t gpu_off, uint64_t size,
			   uint32_t seed, bool *ok)
{
	uint8_t *dst = rt->host + NV_CE_AREA + host_off;
	struct xdev_ext_nv_p2p_dma_xfer xfer = {
		.handle = rt->handle,
		.gpu_offset = rt->gpu + gpu_off,
		.umem_offset = NV_CE_AREA + host_off,
		.size = size,
		.direction = XDEV_EXT_NV_P2P_GPU_TO_UMEM,
	};

	nv_ce_fill(rt->check, seed, size);
	if (nv_ce_cuda(cuMemcpyHtoD(rt->gpu + gpu_off, rt->check, size),
		       "cuMemcpyHtoD"))
		return -EIO;
	memset(dst - NV_CE_GUARD, NV_CE_GUARD_BYTE, size + 2 * NV_CE_GUARD);
	if (xdev_ext_nv_p2p_dma_xfer(rt->fd, &xfer)) {
		fprintf(stderr, "nv_ce_runtime: %s d2h: %s status=0x%x\n", name,
			strerror(errno), xfer.status);
		*ok = false;
		return 1;
	}
	*ok = nv_ce_matches(dst - NV_CE_GUARD, seed, size);
	return !*ok;
}

/* One case both ways; the number of failed checks or -EIO. */
static int nv_ce_round_trip(struct nv_ce_rt *rt, const struct nv_ce_case *c,
			    uint32_t seed)
{
	bool h2d = false, d2h = false;
	int a, b;

	a = nv_ce_h2d_check(rt, c->name, c->host_off, c->gpu_off, c->size,
			    seed, &h2d);
	if (a < 0)
		return a;
	b = nv_ce_d2h_check(rt, c->name, c->host_off, c->gpu_off, c->size,
			    seed ^ 0xffffU, &d2h);
	if (b < 0)
		return b;
	printf("XDEV_EXT_NV_CE_CASE name=%s size=%llu host_off=%llu gpu_off=%llu "
	       "h2d=%s d2h=%s\n", c->name, (unsigned long long)c->size,
	       (unsigned long long)c->host_off, (unsigned long long)c->gpu_off,
	       h2d ? "PASS" : "FAIL", d2h ? "PASS" : "FAIL");
	return a + b;
}

/* NV_CE_BATCH back-to-back copies per direction in one batch ioctl each. */
static int nv_ce_batch_round_trip(struct nv_ce_rt *rt, uint32_t seed)
{
	struct xdev_ext_nv_p2p_dma_batch batch;
	struct nv_ce_case first, last, c;
	uint64_t size, span;
	uint8_t *dst;
	bool h2d = false, d2h = false;
	uint32_t i;

	nv_ce_batch_entry(0, &first);
	nv_ce_batch_entry(NV_CE_BATCH - 1, &last);
	size = last.gpu_off + last.size - first.gpu_off;
	span = size + 2 * NV_CE_GUARD;

	memset(&batch, 0, sizeof(batch));
	batch.handle = rt->handle;
	batch.count = NV_CE_BATCH;
	for (i = 0; i < NV_CE_BATCH; i++) {
		nv_ce_batch_entry(i, &c);
		batch.entries[i] = (struct xdev_ext_nv_p2p_dma_batch_entry) {
			.gpu_offset = rt->gpu + c.gpu_off,
			.umem_offset = c.host_off,
			.size = c.size,
			.direction = XDEV_EXT_NV_P2P_UMEM_TO_GPU,
		};
	}
	nv_ce_fill(rt->host + first.host_off, seed, size);
	if (nv_ce_cuda(cuMemsetD8(rt->gpu + first.gpu_off - NV_CE_GUARD,
				  NV_CE_GUARD_BYTE, span), "cuMemsetD8") ||
	    nv_ce_cuda(cuCtxSynchronize(), "cuCtxSynchronize"))
		return -EIO;
	if (xdev_ext_nv_p2p_dma_batch(rt->fd, &batch)) {
		fprintf(stderr, "nv_ce_runtime: batch h2d: %s completed=%u\n",
			strerror(errno), batch.completed);
	} else {
		if (nv_ce_cuda(cuMemcpyDtoH(rt->check, rt->gpu + first.gpu_off -
					    NV_CE_GUARD, span), "cuMemcpyDtoH"))
			return -EIO;
		h2d = nv_ce_matches(rt->check, seed, size);
	}

	nv_ce_fill(rt->check, seed ^ 0xffffU, size);
	if (nv_ce_cuda(cuMemcpyHtoD(rt->gpu + first.gpu_off, rt->check, size),
		       "cuMemcpyHtoD"))
		return -EIO;
	dst = rt->host + NV_CE_AREA + first.host_off;
	memset(dst - NV_CE_GUARD, NV_CE_GUARD_BYTE, span);
	memset(&batch, 0, sizeof(batch));
	batch.handle = rt->handle;
	batch.count = NV_CE_BATCH;
	for (i = 0; i < NV_CE_BATCH; i++) {
		nv_ce_batch_entry(i, &c);
		batch.entries[i] = (struct xdev_ext_nv_p2p_dma_batch_entry) {
			.gpu_offset = rt->gpu + c.gpu_off,
			.umem_offset = NV_CE_AREA + c.host_off,
			.size = c.size,
			.direction = XDEV_EXT_NV_P2P_GPU_TO_UMEM,
		};
	}
	if (xdev_ext_nv_p2p_dma_batch(rt->fd, &batch))
		fprintf(stderr, "nv_ce_runtime: batch d2h: %s completed=%u\n",
			strerror(errno), batch.completed);
	else
		d2h = nv_ce_matches(dst - NV_CE_GUARD, seed ^ 0xffffU, size);
	printf("XDEV_EXT_NV_CE_CASE name=batch entries=%u size=%llu h2d=%s d2h=%s\n",
	       NV_CE_BATCH, (unsigned long long)size, h2d ? "PASS" : "FAIL",
	       d2h ? "PASS" : "FAIL");
	return !h2d + !d2h;
}

/* A request the driver must refuse; 0 when it did. */
static int nv_ce_error_case(struct nv_ce_rt *rt, const struct nv_ce_error *e)
{
	struct xdev_ext_nv_p2p_dma_xfer xfer = {
		.handle = rt->handle ^ e->handle_xor,
		.gpu_offset = rt->gpu + e->gpu_off,
		.umem_offset = e->host_off,
		.size = e->size,
		.direction = e->direction,
	};
	bool refused;

	/* Printed first: a wedged driver then names the request. */
	printf("XDEV_EXT_NV_CE_ERROR_START name=%s\n", e->name);
	fflush(stdout);
	refused = xdev_ext_nv_p2p_dma_xfer(rt->fd, &xfer) != 0;
	printf("XDEV_EXT_NV_CE_ERROR name=%s refused=%d status=0x%x errno=%d\n",
	       e->name, refused, xfer.status, refused ? errno : 0);
	return !refused;
}

/* Unpin succeeds once; the second unpin and a copy on the handle fail. */
static int nv_ce_unpin_twice(struct nv_ce_rt *rt)
{
	struct xdev_ext_nv_p2p_unpin_umem unpin = { .handle = rt->handle };
	struct xdev_ext_nv_p2p_dma_xfer xfer = {
		.handle = rt->handle,
		.gpu_offset = rt->gpu + 4096,
		.umem_offset = 4096,
		.size = 4096,
		.direction = XDEV_EXT_NV_P2P_UMEM_TO_GPU,
	};
	bool first, second, copy;

	first = !xdev_ext_nv_p2p_unpin_umem(rt->fd, &unpin);
	if (first)
		rt->handle = 0;
	unpin = (struct xdev_ext_nv_p2p_unpin_umem) { .handle = xfer.handle };
	second = xdev_ext_nv_p2p_unpin_umem(rt->fd, &unpin) != 0;
	copy = xdev_ext_nv_p2p_dma_xfer(rt->fd, &xfer) != 0;
	printf("XDEV_EXT_NV_CE_UNPIN first=%s second_refused=%d copy_refused=%d\n",
	       first ? "PASS" : "FAIL", second, copy);
	return !first + !second + !copy;
}

static int nv_ce_run(const struct nv_ce_opts *o)
{
	struct nv_ce_rt rt = { .fd = -1 };
	struct xdev_ext_nv_p2p_pin_umem pin;
	unsigned int checks = 0, failed = 0;
	int ret = NV_CE_EXIT_SETUP, r;
	size_t i;

	rt.fd = open(o->gpu_device, O_RDWR | O_CLOEXEC);
	if (rt.fd < 0) {
		fprintf(stderr, "nv_ce_runtime: %s: %s\n", o->gpu_device,
			strerror(errno));
		return NV_CE_EXIT_SETUP;
	}
	if (nv_ce_cuda_setup(&rt, o->gpu_device))
		goto out;
	rt.host = mmap(NULL, NV_CE_HOST_BYTES, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	rt.check = malloc(NV_CE_AREA);
	if (rt.host == MAP_FAILED || !rt.check) {
		if (rt.host == MAP_FAILED)
			rt.host = NULL;
		fprintf(stderr, "nv_ce_runtime: buffers: %s\n", strerror(errno));
		goto out;
	}
	pin = (struct xdev_ext_nv_p2p_pin_umem) {
		.umem_addr = (uint64_t)(uintptr_t)rt.host,
		.size = NV_CE_HOST_BYTES,
		.frame_size = NV_CE_FRAME,
		.xsk_fd = -1,
		.flags = XDEV_EXT_NV_P2P_PIN_F_HOST_REGION,
	};
	if (xdev_ext_nv_p2p_pin_umem(rt.fd, &pin)) {
		fprintf(stderr, "nv_ce_runtime: pin: %s status=0x%x\n",
			strerror(errno), pin.status);
		goto out;
	}
	rt.handle = pin.handle;

	for (i = 0; i < NV_CE_NR_CASES; i++, checks += 2) {
		r = nv_ce_round_trip(&rt, &nv_ce_cases[i], (uint32_t)i + 1);
		if (r < 0)
			goto out;
		failed += (unsigned int)r;
	}
	r = nv_ce_batch_round_trip(&rt, 1000);
	if (r < 0)
		goto out;
	failed += (unsigned int)r;
	checks += 2;
	for (i = 0; i < NV_CE_NR_ERRORS; i++, checks++)
		failed += (unsigned int)nv_ce_error_case(&rt, &nv_ce_errors[i]);
	/* The refused requests left the copy path usable. */
	r = nv_ce_round_trip(&rt, &nv_ce_cases[0], 2000);
	if (r < 0)
		goto out;
	failed += (unsigned int)r;
	checks += 2;
	failed += (unsigned int)nv_ce_unpin_twice(&rt);
	checks += 3;

	printf("XDEV_EXT_NV_CE_RUNTIME=%s cases=%u errors=%u\n",
	       failed ? "FAIL" : "PASS", checks, failed);
	ret = failed ? NV_CE_EXIT_FAIL : NV_CE_EXIT_PASS;
out:
	if (rt.handle) {
		struct xdev_ext_nv_p2p_unpin_umem unpin = { .handle = rt.handle };

		if (xdev_ext_nv_p2p_unpin_umem(rt.fd, &unpin))
			fprintf(stderr, "nv_ce_runtime: unpin: %s status=0x%x\n",
				strerror(errno), unpin.status);
	}
	free(rt.check);
	if (rt.host)
		munmap(rt.host, NV_CE_HOST_BYTES);
	if (rt.gpu)
		(void)nv_ce_cuda(cuMemFree(rt.gpu), "cuMemFree");
	if (rt.ctx_retained)
		(void)nv_ce_cuda(cuDevicePrimaryCtxRelease(rt.dev),
				 "cuDevicePrimaryCtxRelease");
	close(rt.fd);
	return ret;
}
#endif /* XDEV_EXT_NV_CE_WITH_CUDA */

static void usage(FILE *f, const char *prog)
{
	fprintf(f,
		"usage: %s --i-have-the-gpu-window [--gpu-device /dev/nvidiaN]\n"
		"Copy-engine round trips on the GPU behind the device node; run\n"
		"only inside a user-approved, exclusive GPU window.\n", prog);
}

static int parse_options(int argc, char **argv, struct nv_ce_opts *o)
{
	static const struct option options[] = {
		{ "i-have-the-gpu-window", no_argument, NULL, 'w' },
		{ "gpu-device", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "h", options, NULL)) != -1) {
		switch (opt) {
		case 'w':
			o->window = true;
			break;
		case 'd':
			o->gpu_device = optarg;
			break;
		case 'h':
			usage(stdout, argv[0]);
			exit(NV_CE_EXIT_PASS);
		default:
			return -EINVAL;
		}
	}
	return optind == argc ? 0 : -EINVAL;
}

int main(int argc, char **argv)
{
	struct nv_ce_opts o = { .gpu_device = "/dev/nvidia0" };
	enum nv_ce_gate gate;

	if (parse_options(argc, argv, &o)) {
		usage(stderr, argv[0]);
		return NV_CE_EXIT_REFUSED;
	}
	gate = nv_ce_runtime_gate(o.window, NV_CE_WITH_CUDA);
	if (gate != NV_CE_GATE_RUN) {
		printf("XDEV_EXT_NV_CE_RUNTIME=REFUSED reason=%s\n",
		       nv_ce_gate_reason(gate));
		return NV_CE_EXIT_REFUSED;
	}
#ifdef XDEV_EXT_NV_CE_WITH_CUDA
	return nv_ce_run(&o);
#else
	return NV_CE_EXIT_REFUSED;
#endif
}

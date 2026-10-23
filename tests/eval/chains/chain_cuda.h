/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_CUDA_H
#define CHAIN_CUDA_H

/*
 * CUDA driver API through dlopen("libcuda.so.1") for the user-space arms:
 * page-lock an existing host region (cuMemHostRegister), one device buffer,
 * one stream per in-flight slot and asynchronous host<->device copies.  No
 * CUDA SDK is needed to build it; without a driver every call fails with
 * -ENOENT and the arm refuses.  The GPU is selected by PCI BDF only.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHAIN_CUDA_MAX_STREAMS	64
#define CHAIN_CUDA_NOT_READY	600	/* CUDA_ERROR_NOT_READY */
#define CHAIN_CUDA_HOSTREGISTER_PORTABLE 0x01

struct chain_cuda {
	void *lib, *ctx;
	int device, retained;
	uint64_t dbuf;
	size_t dlen;
	void *host;			/* registered host region */
	unsigned int nr_streams;
	void *streams[CHAIN_CUDA_MAX_STREAMS];
	int (*init)(unsigned int);
	int (*by_bdf)(int *, const char *);
	int (*retain)(void **, int);
	int (*release)(int);
	int (*ctx_set)(void *);
	int (*alloc)(uint64_t *, size_t);
	int (*free_)(uint64_t);
	int (*host_register)(void *, size_t, unsigned int);
	int (*host_unregister)(void *);
	int (*h2d)(uint64_t, const void *, size_t, void *);
	int (*d2h)(void *, uint64_t, size_t, void *);
	int (*d2h_sync)(void *, uint64_t, size_t);
	int (*h2d_sync)(uint64_t, const void *, size_t);
	int (*stream_create)(void **, unsigned int);
	int (*stream_destroy)(void *);
	int (*stream_query)(void *);
	int (*stream_sync)(void *);
};

static inline int chain_cuda_ok(int status, const char *what)
{
	if (!status)
		return 0;
	fprintf(stderr, "chain_cuda: %s failed: CUDA status %d\n", what, status);
	return -EIO;
}

static inline int chain_cuda_close(struct chain_cuda *c)
{
	unsigned int i;
	int ret = 0;

	if (!c->lib)
		return 0;
	if (c->ctx && c->ctx_set(c->ctx))
		ret = -EIO;
	for (i = 0; i < c->nr_streams; i++)
		if (c->streams[i] && c->stream_destroy(c->streams[i]))
			ret = -EIO;
	if (c->host && c->host_unregister(c->host))
		ret = -EIO;
	if (c->dbuf && c->free_(c->dbuf))
		ret = -EIO;
	if (c->retained && c->release(c->device))
		ret = -EIO;
	dlclose(c->lib);
	memset(c, 0, sizeof(*c));
	return ret;
}

/* Device buffer of @bytes and @streams streams on the GPU at @bdf. */
static inline int chain_cuda_open(struct chain_cuda *c, const char *bdf,
				  size_t bytes, unsigned int streams)
{
	unsigned int i;
	int ret;

	memset(c, 0, sizeof(*c));
	if (!bdf || !*bdf || !bytes || !streams || streams > CHAIN_CUDA_MAX_STREAMS)
		return -EINVAL;
	c->lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!c->lib)
		return -ENOENT;
#define CHAIN_CUDA_SYM(member, name) do { \
	*(void **)&c->member = dlsym(c->lib, name); \
	if (!c->member) { ret = -ENOSYS; goto fail; } \
} while (0)
	CHAIN_CUDA_SYM(init, "cuInit");
	CHAIN_CUDA_SYM(by_bdf, "cuDeviceGetByPCIBusId");
	CHAIN_CUDA_SYM(retain, "cuDevicePrimaryCtxRetain");
	CHAIN_CUDA_SYM(release, "cuDevicePrimaryCtxRelease_v2");
	CHAIN_CUDA_SYM(ctx_set, "cuCtxSetCurrent");
	CHAIN_CUDA_SYM(alloc, "cuMemAlloc_v2");
	CHAIN_CUDA_SYM(free_, "cuMemFree_v2");
	CHAIN_CUDA_SYM(host_register, "cuMemHostRegister_v2");
	CHAIN_CUDA_SYM(host_unregister, "cuMemHostUnregister");
	CHAIN_CUDA_SYM(h2d, "cuMemcpyHtoDAsync_v2");
	CHAIN_CUDA_SYM(d2h, "cuMemcpyDtoHAsync_v2");
	CHAIN_CUDA_SYM(d2h_sync, "cuMemcpyDtoH_v2");
	CHAIN_CUDA_SYM(h2d_sync, "cuMemcpyHtoD_v2");
	CHAIN_CUDA_SYM(stream_create, "cuStreamCreate");
	CHAIN_CUDA_SYM(stream_destroy, "cuStreamDestroy_v2");
	CHAIN_CUDA_SYM(stream_query, "cuStreamQuery");
	CHAIN_CUDA_SYM(stream_sync, "cuStreamSynchronize");
#undef CHAIN_CUDA_SYM
	ret = chain_cuda_ok(c->init(0), "cuInit");
	if (!ret)
		ret = chain_cuda_ok(c->by_bdf(&c->device, bdf), "cuDeviceGetByPCIBusId");
	if (!ret)
		ret = chain_cuda_ok(c->retain(&c->ctx, c->device), "cuDevicePrimaryCtxRetain");
	if (ret)
		goto fail;
	c->retained = 1;
	ret = chain_cuda_ok(c->ctx_set(c->ctx), "cuCtxSetCurrent");
	if (!ret)
		ret = chain_cuda_ok(c->alloc(&c->dbuf, bytes), "cuMemAlloc_v2");
	if (ret)
		goto fail;
	c->dlen = bytes;
	for (i = 0; i < streams; i++) {
		ret = chain_cuda_ok(c->stream_create(&c->streams[i], 1 /* non-blocking */),
				    "cuStreamCreate");
		if (ret)
			goto fail;
		c->nr_streams++;
	}
	return 0;
fail:
	chain_cuda_close(c);
	return ret;
}

/* Page-lock @len bytes at @host for the copies; one region per handle. */
static inline int chain_cuda_register(struct chain_cuda *c, void *host, size_t len)
{
	int ret = chain_cuda_ok(c->host_register(host, len,
				CHAIN_CUDA_HOSTREGISTER_PORTABLE), "cuMemHostRegister_v2");

	if (!ret)
		c->host = host;
	return ret;
}

static inline int chain_cuda_h2d(struct chain_cuda *c, unsigned int s, uint64_t off,
				 const void *host, size_t len)
{
	if (s >= c->nr_streams || off > c->dlen || len > c->dlen - off)
		return -ERANGE;
	return chain_cuda_ok(c->h2d(c->dbuf + off, host, len, c->streams[s]),
			     "cuMemcpyHtoDAsync_v2");
}

static inline int chain_cuda_d2h(struct chain_cuda *c, unsigned int s, void *host,
				 uint64_t off, size_t len)
{
	if (s >= c->nr_streams || off > c->dlen || len > c->dlen - off)
		return -ERANGE;
	return chain_cuda_ok(c->d2h(host, c->dbuf + off, len, c->streams[s]),
			     "cuMemcpyDtoHAsync_v2");
}

/* 0 when stream @s finished, 1 while it runs, -errno on failure. */
static inline int chain_cuda_query(struct chain_cuda *c, unsigned int s)
{
	int status = c->stream_query(c->streams[s]);

	if (status == CHAIN_CUDA_NOT_READY)
		return 1;
	return chain_cuda_ok(status, "cuStreamQuery");
}

/*
 * Synchronous device-to-host read of @len bytes at device address @va in
 * the primary context of the GPU at @bdf: the session's post-campaign
 * oracle readback of a natively allocated CE window.
 */
static inline int chain_cuda_access(const char *bdf, uint64_t va, void *buf,
				    size_t len, int write)
{
	struct chain_cuda c;
	int ret = chain_cuda_open(&c, bdf, 1, 1);

	if (ret)
		return ret;
	ret = write ? chain_cuda_ok(c.h2d_sync(va, buf, len), "cuMemcpyHtoD_v2") :
		      chain_cuda_ok(c.d2h_sync(buf, va, len), "cuMemcpyDtoH_v2");
	if (chain_cuda_close(&c) && !ret)
		ret = -EIO;
	return ret;
}

static inline int chain_cuda_readback(const char *bdf, uint64_t va, void *buf,
				      size_t len)
{
	return chain_cuda_access(bdf, va, buf, len, 0);
}

/* Before the campaign: the pristine fill the window oracle relies on. */
static inline int chain_cuda_fill(const char *bdf, uint64_t va, const void *buf,
				  size_t len)
{
	return chain_cuda_access(bdf, va, (void *)buf, len, 1);
}

#endif /* CHAIN_CUDA_H */

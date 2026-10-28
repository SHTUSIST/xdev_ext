// SPDX-License-Identifier: GPL-2.0
#include "libxdev_ext_cuda_device.h"
#include "libxdev_ext_internal.h"
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>

struct xdev_ext_cuda_user {
	xdev_ext_user_stage *user = nullptr;
	CUcontext context = nullptr;
	CUmodule module = nullptr;
	CUfunction wait = nullptr, done = nullptr;
	xdev_cuda_ring ring{};
	void *mapping = nullptr;
	bool registered = false, attached = false;
	std::atomic<bool> launched{false};
	bool native_order = false, memop_flush = false;
};
static thread_local xdev_ext_cuda_diagnostic diagnostic{};
static int driver(CUresult rc, const char *operation)
{
	if (rc == CUDA_SUCCESS) return 0;
	if (!diagnostic.cuda_result) {
		diagnostic.cuda_result = int(rc);
		std::snprintf(diagnostic.operation, sizeof(diagnostic.operation), "%s", operation);
	}
	if (rc == CUDA_ERROR_NOT_SUPPORTED || rc == CUDA_ERROR_NO_DEVICE ||
	    rc == CUDA_ERROR_SYSTEM_DRIVER_MISMATCH || rc == CUDA_ERROR_STUB_LIBRARY)
		return -EOPNOTSUPP;
	return -EIO;
}
#define DRV(call) driver((call), #call)
static int current(CUcontext expected)
{
	CUcontext actual = nullptr;
	int ret = DRV(cuCtxGetCurrent(&actual));
	return ret ? ret : !actual || actual != expected ? -EINVAL : 0;
}
static int stream_identity(CUcontext expected, CUstream stream,
	unsigned long long *context_id, unsigned long long *stream_id)
{
	int ret = current(expected);
	if (ret) return ret;
	CUcontext context;
	ret = DRV(cuStreamGetCtx(stream, &context));
	if (ret) return ret;
	if (context != expected) return -EINVAL;
	ret = DRV(cuCtxGetId(context, context_id));
	if (ret) return ret;
	return DRV(cuStreamGetId(stream, stream_id));
}
static int stream_check(xdev_ext_cuda_user *u, CUstream stream)
{
	if (!u) return -EINVAL;
	unsigned long long context_id, stream_id;
	int ret = stream_identity(u->context, stream, &context_id, &stream_id);
	return ret ? ret : xdev_ext__user_bind_stream(u->user, context_id, stream_id);
}
extern "C" int xdev_ext_cuda_last_diagnostic(xdev_ext_cuda_diagnostic *out)
{
	if (!out) return -EINVAL;
	*out = diagnostic; return 0;
}

static int dispose_setup(xdev_ext_cuda_user *u)
{
	int ret;
	if (u->registered) {
		ret = DRV(cuMemHostUnregister(u->mapping));
		if (ret) return ret;
		u->registered = false;
	}
	if (u->attached) {
		ret = xdev_ext_user_stage_ctl_detach(u->user);
		if (ret) return ret;
		u->attached = false;
	}
	if (u->module) {
		ret = DRV(cuModuleUnload(u->module));
		if (ret) return ret;
		u->module = nullptr;
	}
	return 0;
}

extern "C" int xdev_ext_cuda_user_open(xdev_ext_user_stage *user, CUcontext context,
	CUdeviceptr va, unsigned long long bytes, unsigned int frame_size,
	xdev_ext_cuda_user **out)
{
	diagnostic = {};
	if (out) *out = nullptr;
	const char *ptx = std::getenv("XDEV_EXT_CUDA_PTX");
	if (!user || !out || !context || !va || !bytes || !frame_size ||
	    bytes % frame_size || va > UINT64_MAX - bytes || !ptx || !*ptx) return -EINVAL;
	int ret = current(context);
	if (ret) return ret;
	CUdevice device;
	int mapped, atoms, registration, rdma, ordering, options, flush;
	if ((ret = DRV(cuCtxGetDevice(&device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&mapped, CU_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY, device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&atoms, CU_DEVICE_ATTRIBUTE_HOST_NATIVE_ATOMIC_SUPPORTED, device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&registration, CU_DEVICE_ATTRIBUTE_HOST_REGISTER_SUPPORTED, device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&rdma, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED, device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&ordering, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_WRITES_ORDERING, device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&options, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_FLUSH_WRITES_OPTIONS, device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&flush, CU_DEVICE_ATTRIBUTE_CAN_FLUSH_REMOTE_WRITES, device)))) return ret;
	/* Mapped naturally aligned32/64-bit system-scope loads/stores have an
	 * independent NVIDIA atomicity guarantee. No host atomic RMW is used.
	 * Keep the native-atomic query fail-closed, but value0 is qualified here. */
	if (!mapped || !registration || !rdma) return -EOPNOTSUPP;
	bool native = ordering == CU_GPU_DIRECT_RDMA_WRITES_ORDERING_OWNER ||
		ordering == CU_GPU_DIRECT_RDMA_WRITES_ORDERING_ALL_DEVICES;
	if (!native && ordering != CU_GPU_DIRECT_RDMA_WRITES_ORDERING_NONE) return -EOPNOTSUPP;
	/* This object is the GPU d2 controller: no host-flag-only visibility. */
	if (!native && (!flush || !(options & CU_FLUSH_GPU_DIRECT_RDMA_WRITES_OPTION_MEMOPS))) return -EOPNOTSUPP;
	CUcontext owner;
	CUmemorytype memory;
	unsigned managed, sync = 1;
	CUdeviceptr base;
	size_t allocation_size;
	if ((ret = DRV(cuPointerGetAttribute(&owner, CU_POINTER_ATTRIBUTE_CONTEXT, va))) ||
	    (ret = DRV(cuPointerGetAttribute(&memory, CU_POINTER_ATTRIBUTE_MEMORY_TYPE, va))) ||
	    (ret = DRV(cuPointerGetAttribute(&managed, CU_POINTER_ATTRIBUTE_IS_MANAGED, va))) ||
	    (ret = DRV(cuMemGetAddressRange(&base, &allocation_size, va)))) return ret;
	if (owner != context || memory != CU_MEMORYTYPE_DEVICE || managed ||
	    va < base || va - base > allocation_size || bytes > allocation_size - (va - base)) return -EINVAL;
	if ((ret = DRV(cuPointerSetAttribute(&sync, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, va)))) return ret;
	xdev_ext_cuda_user *u = new(std::nothrow) xdev_ext_cuda_user;
	if (!u) return -ENOMEM;
	u->user = user; u->context = context; u->native_order = native;
	u->memop_flush = !native;
	xdev_ext_user_ring_offsets off{};
	ret = xdev_ext_user_stage_control(user, &u->mapping, &off);
	CUdeviceptr address = 0;
	if (!ret) ret = DRV(cuModuleLoad(&u->module, ptx));
	if (!ret) ret = DRV(cuModuleGetFunction(&u->wait, u->module, "xdev_user_wait"));
	if (!ret) ret = DRV(cuModuleGetFunction(&u->done, u->module, "xdev_user_done"));
	if (!ret) {
		ret = DRV(cuMemHostRegister(u->mapping, off.mmap_size, CU_MEMHOSTREGISTER_DEVICEMAP));
		if (!ret) u->registered = true;
	}
	if (!ret) ret = DRV(cuMemHostGetDevicePointer(&address, u->mapping, 0));
	if (!ret) {
		ret = xdev_ext_user_stage_ctl_attach(user);
		if (!ret) u->attached = true;
	}
	if (ret) {
		if (dispose_setup(u)) { *out = u; return ret; }
		delete u; return ret;
	}
	unsigned entries = xdev_ext_user_stage_entries(user);
	/* Both CPU and GPU aliases must preserve alignment of every32/64-bit
	 * field used by system-scope operations, with complete registered extents. */
	if (!entries || entries > XDEV_EXT_USER_RING_MAX || (entries & (entries - 1)) ||
	    address % 8 || off.hdr % 4 || off.ready % 8 || off.done % 8 || off.slots % 8 ||
	    address > UINT64_MAX - off.mmap_size ||
	    off.hdr > off.mmap_size || sizeof(xdev_ext_user_ring_hdr) > off.mmap_size - off.hdr ||
	    off.ready > off.mmap_size || entries > (off.mmap_size - off.ready) / sizeof(xdev_ext_user_ready) ||
	    off.done > off.mmap_size || entries > (off.mmap_size - off.done) / sizeof(xdev_ext_user_done) ||
	    off.slots > off.mmap_size || entries > (off.mmap_size - off.slots) / sizeof(xdev_ext_user_slot)) {
		ret = -EPROTO;
		if (dispose_setup(u)) { *out = u; return ret; }
		delete u; return ret;
	}
	u->ring = {
		reinterpret_cast<xdev_ext_user_ring_hdr *>(address + off.hdr),
		reinterpret_cast<xdev_ext_user_ready *>(address + off.ready),
		reinterpret_cast<xdev_ext_user_done *>(address + off.done),
		reinterpret_cast<xdev_ext_user_slot *>(address + off.slots),
		va, bytes,
		entries,
		frame_size,
	};
	if (entries > XDEV_EXT_USER_RING_MAX ||
	    off.ready + entries * sizeof(xdev_ext_user_ready) > off.done ||
	    off.done + entries * sizeof(xdev_ext_user_done) > off.slots ||
	    off.slots + entries * sizeof(xdev_ext_user_slot) > off.mmap_size) {
		ret = -EPROTO;
		if (dispose_setup(u)) { *out = u; return ret; }
		delete u; return ret;
	}
	u->ring.entries = entries;
	*out = u;
	return 0;
}

static int enqueue(xdev_ext_cuda_user *u, CUstream stream,
	xdev_ext_cuda_message *message, bool done)
{
	diagnostic = {};
	if (!u || !message) return -EINVAL;
	unsigned long long context_id, stream_id;
	int ret = stream_identity(u->context, stream, &context_id, &stream_id);
	if (ret) return ret;
	CUcontext owner;
	CUmemorytype memory;
	if ((ret = DRV(cuPointerGetAttribute(&owner, CU_POINTER_ATTRIBUTE_CONTEXT,
	    reinterpret_cast<CUdeviceptr>(message)))) ||
	    (ret = DRV(cuPointerGetAttribute(&memory, CU_POINTER_ATTRIBUTE_MEMORY_TYPE,
	    reinterpret_cast<CUdeviceptr>(message))))) return ret;
	if (owner != u->context || memory != CU_MEMORYTYPE_DEVICE || !u->registered || !u->attached) return -EINVAL;
	ret = xdev_ext__user_bind_stream(u->user, context_id, stream_id);
	if (ret) return ret;
	void *args[] = {&u->ring, &message};
	ret = DRV(cuLaunchKernel(done ? u->done : u->wait, 1, 1, 1, 1, 1, 1, 0, stream, args, nullptr));
	if (!ret) u->launched.store(true, std::memory_order_release);
	return ret;
}
extern "C" int xdev_ext_cuda_user_wait(xdev_ext_cuda_user *u, CUstream stream, xdev_ext_cuda_message *message)
{ return enqueue(u, stream, message, false); }
extern "C" int xdev_ext_cuda_user_done(xdev_ext_cuda_user *u, CUstream stream, xdev_ext_cuda_message *message)
{ return enqueue(u, stream, message, true); }

extern "C" int xdev_ext_cuda_receive_visible(xdev_ext_cuda_user *u, CUstream stream)
{
	diagnostic = {};
	int ret = stream_check(u, stream);
	if (ret || u->native_order) return ret;
	if (!u->memop_flush) return -EOPNOTSUPP;
	CUstreamBatchMemOpParams op{};
	op.operation = CU_STREAM_MEM_OP_FLUSH_REMOTE_WRITES;
	CUstreamCaptureStatus status;
	ret = DRV(cuStreamIsCapturing(stream, &status));
	if (ret) return ret;
	if (status == CU_STREAM_CAPTURE_STATUS_ACTIVE) {
		CUgraph graph;
		const CUgraphNode *dependencies;
		const CUgraphEdgeData *edges;
		size_t count;
		cuuint64_t id;
		if ((ret = DRV(cuStreamGetCaptureInfo(stream, &status, &id, &graph, &dependencies, &edges, &count)))) return ret;
		CUDA_BATCH_MEM_OP_NODE_PARAMS params{};
		params.ctx = u->context; params.count = 1; params.paramArray = &op;
		CUgraphNode node;
		if ((ret = DRV(cuGraphAddBatchMemOpNode(&node, graph, dependencies, count, &params)))) return ret;
		return DRV(cuStreamUpdateCaptureDependencies(stream, &node, nullptr, 1, CU_STREAM_SET_CAPTURE_DEPENDENCIES));
	}
	if (status != CU_STREAM_CAPTURE_STATUS_NONE) return -EINVAL;
	return DRV(cuStreamBatchMemOp(stream, 1, &op, 0));
}

extern "C" int xdev_ext_cuda_user_close(xdev_ext_cuda_user *u, CUstream stream)
{
	diagnostic = {};
	int ret = stream_check(u, stream);
	if (ret) return ret;
	CUstreamCaptureStatus status;
	if ((ret = DRV(cuStreamIsCapturing(stream, &status)))) return ret;
	if (status != CU_STREAM_CAPTURE_STATUS_NONE) return -EOPNOTSUPP;
	if (u->launched.load(std::memory_order_acquire) && (ret = DRV(cuStreamSynchronize(stream)))) return ret;
	ret = dispose_setup(u);
	if (ret) return ret;
	delete u; return 0;
}

extern "C" int xdev_ext_cuda_host_receive_visible(CUcontext context)
{
	diagnostic = {};
	int ret = current(context);
	if (ret) return ret;
	CUdevice device;
	int supported, ordering, options;
	if ((ret = DRV(cuCtxGetDevice(&device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&supported, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED, device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&ordering, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_WRITES_ORDERING, device))) ||
	    (ret = DRV(cuDeviceGetAttribute(&options, CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_FLUSH_WRITES_OPTIONS, device)))) return ret;
	if (!supported) return -EOPNOTSUPP;
	if (ordering == CU_GPU_DIRECT_RDMA_WRITES_ORDERING_OWNER ||
	    ordering == CU_GPU_DIRECT_RDMA_WRITES_ORDERING_ALL_DEVICES) return 0;
	if (ordering != CU_GPU_DIRECT_RDMA_WRITES_ORDERING_NONE ||
	    !(options & CU_FLUSH_GPU_DIRECT_RDMA_WRITES_OPTION_HOST)) return -EOPNOTSUPP;
	return DRV(cuFlushGPUDirectRDMAWrites(CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TARGET_CURRENT_CTX,
		CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TO_OWNER));
}

extern "C" int xdev_ext_cuda_event_complete(xdev_ext_user_stage *u,
	const xdev_ext_user_batch *batch, CUcontext context, CUstream stream, CUevent event)
{
	diagnostic = {};
	if (!u || !batch || !event) return -EINVAL;
	unsigned long long context_id, stream_id;
	int ret = stream_identity(context, stream, &context_id, &stream_id);
	CUstreamCaptureStatus status = CU_STREAM_CAPTURE_STATUS_NONE;
	if (!ret) ret = DRV(cuStreamIsCapturing(stream, &status));
	if (!ret && status != CU_STREAM_CAPTURE_STATUS_NONE) ret = -EOPNOTSUPP;
	if (ret) return ret; /* qualification errors produce no completion entry */
	ret = xdev_ext__user_bind_stream(u, context_id, stream_id);
	if (ret) return ret;
	ret = DRV(cuEventRecord(event, stream));
	if (!ret) ret = DRV(cuEventSynchronize(event));
	int done = xdev_ext_user_stage_complete(u, batch, ret);
	return ret ? ret : done;
}

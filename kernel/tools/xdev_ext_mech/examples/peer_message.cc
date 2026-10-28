// SPDX-License-Identifier: GPL-2.0
/* Minimal real-GPU owner of the ordinary PEER message library. Run --rx on
 * one host and --tx on the other with their local never-reused link tokens.
 * No payload host mapping, no host-copy fallback, no large test agent. */
#include "../lib/libxdev_ext_peer_message.h"
#include "../lib/libxdev_ext_cuda.h"
#include "../../../include/uapi/linux/xdev_ext_peer.h"
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct owner {
	CUcontext context = nullptr;
	CUstream stream = nullptr;
	CUevent event = nullptr;
	CUmodule module = nullptr;
	CUfunction produce = nullptr, consume = nullptr;
	CUdeviceptr raw = 0, va = 0, mismatches = 0;
	int gpu = -1, control = -1, allocation = -1;
	xdev_ext_prog *program = nullptr;
	xdev_ext_peer_endpoint *endpoint = nullptr;
};
static int cuda_error(CUresult result, const char *operation)
{
	if (result == CUDA_SUCCESS) return 0;
	fprintf(stderr, "CUDA_ERROR operation=%s result=%d\n", operation, int(result));
	return -EIO;
}
#define CUDA(call) cuda_error((call), #call)
static int number(const char *text, unsigned long long *value)
{
	char *end;
	if (!text || !*text || *text == '-' || *text == '+') return -EINVAL;
	errno = 0; *value = strtoull(text, &end, 0);
	return errno || *end ? -EINVAL : 0;
}

/* Callbacks return success only after real CUDA producer or last-use events.
 * An error is submitted as UNKNOWN and never fabricated into done0. */
static int gpu_owner_callback(owner &o, xdev_ext_user_batch &batch, xdev_ext_peer_role role)
{
	int ret = 0;
	if (role == XDEV_EXT_PEER_RX_CONSUMER) {
		ret = xdev_ext_cuda_host_receive_visible(o.context);
		if (!ret) ret = CUDA(cuMemsetD32Async(o.mismatches, 0, 1, o.stream));
	}
	for (unsigned i = 0; !ret && i < batch.nr_frames; i++) {
		xdev_ext_peer_span span;
		ret = xdev_ext_user_batch_peer_span(&batch, i, o.va, 65536, 4096, &span);
		if (ret) break;
		CUdeviceptr payload = span.device_address;
		unsigned bytes = span.data_len;
		unsigned long long key = batch.key;
		void *args[] = {&payload, &bytes, &key, &o.mismatches};
		if (role != XDEV_EXT_PEER_TX_TERMINAL)
			ret = CUDA(cuLaunchKernel(role == XDEV_EXT_PEER_PRODUCER ? o.produce : o.consume,
				16, 1, 1, 256, 1, 1, 0, o.stream, args, nullptr));
	}
	if (!ret) ret = CUDA(cuEventRecord(o.event, o.stream));
	if (!ret) ret = CUDA(cuEventSynchronize(o.event));
	if (!ret && role == XDEV_EXT_PEER_RX_CONSUMER) {
		unsigned bad;
		ret = CUDA(cuMemcpyDtoH(&bad, o.mismatches, sizeof(bad)));
		if (!ret && bad) ret = -EBADMSG;
	}
	return ret;
}

int main(int argc, char **argv)
{
	const char *node = nullptr, *ptx = nullptr, *bpf = nullptr;
	unsigned long long token = 0, batches = 0, ordinal = 0;
	bool receive = false, have_mode = false;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--rx")) { receive = true; have_mode = true; }
		else if (!strcmp(argv[i], "--tx")) { receive = false; have_mode = true; }
		else if (!strcmp(argv[i], "--nvidia-node") && i + 1 < argc) node = argv[++i];
		else if (!strcmp(argv[i], "--ptx") && i + 1 < argc) ptx = argv[++i];
		else if (!strcmp(argv[i], "--bpf-object") && i + 1 < argc) bpf = argv[++i];
		else if (!strcmp(argv[i], "--link") && i + 1 < argc) { if (number(argv[++i], &token)) return 2; }
		else if (!strcmp(argv[i], "--batches") && i + 1 < argc) { if (number(argv[++i], &batches)) return 2; }
		else if (!strcmp(argv[i], "--device") && i + 1 < argc) { if (number(argv[++i], &ordinal)) return 2; }
		else return 2;
	}
	if (!have_mode || !node || !ptx || !bpf || !token || !batches || ordinal > INT_MAX) {
		fputs("usage: peer_message --rx|--tx --link TOKEN --batches N --device N "
		      "--nvidia-node /dev/nvidiaN --ptx peer_message_owner.ptx --bpf-object xdomain_peer.bpf.o\n", stderr);
		return 2;
	}
	owner o;
	CUdevice device;
	int ret;
	xdev_ext_link_snapshot link;
	ret = xdev_ext_link_discover("/sys/bus/thunderbolt/devices", token, &link);
	if (ret) { fprintf(stderr, "LINK_UNAVAILABLE errno=%d\n", ret); return 3; }
	if ((ret = CUDA(cuInit(0))) || (ret = CUDA(cuDeviceGet(&device, int(ordinal)))) ||
	    (ret = CUDA(cuCtxCreate(&o.context, nullptr, 0, device))) ||
	    (ret = CUDA(cuStreamCreate(&o.stream, CU_STREAM_NON_BLOCKING))) ||
	    (ret = CUDA(cuEventCreate(&o.event, CU_EVENT_DISABLE_TIMING))) ||
	    (ret = CUDA(cuMemAlloc(&o.raw, 131072))) ||
	    (ret = CUDA(cuMemAlloc(&o.mismatches, sizeof(unsigned))))) return 3;
	o.va = (o.raw + 65535) & ~CUdeviceptr(65535);
	unsigned sync = 1;
	if (CUDA(cuPointerSetAttribute(&sync, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, o.va)) ||
	    CUDA(cuModuleLoad(&o.module, ptx)) ||
	    CUDA(cuModuleGetFunction(&o.produce, o.module, "peer_message_produce")) ||
	    CUDA(cuModuleGetFunction(&o.consume, o.module, "peer_message_consume"))) return 3;
	o.gpu = open(node, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	o.control = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (o.gpu < 0 || o.control < 0) return 3;
	xdev_ext_peer_register registration{};
	registration.gpu_fd = o.gpu; registration.gpu_va = o.va; registration.len = 65536;
	o.allocation = ioctl(o.control, XDEV_EXT_PEER_REGISTER, &registration);
	if (o.allocation < 0 || !registration.generation) return 3;
	xdev_ext_prog_opts program{};
	program.sz = sizeof(program); program.obj_path = bpf; program.map_name = "xdomain_peer_ops";
	if (xdev_ext_prog_attach(&program, &o.program)) return 3;
	xdev_ext_peer_endpoint_opts opts{};
	opts.sz = sizeof(opts); opts.allocation_fd = o.allocation; opts.control_fd = o.control;
	opts.link_token = token; opts.direction = receive ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE;
	opts.depth = 1; opts.group_bytes = 4096; opts.deadline_ms = 600000;
	opts.layout = {4096, 0, 4096, 4096};
	ret = xdev_ext_peer_endpoint_open(&opts, &o.endpoint);
	if (!ret) ret = xdev_ext_peer_endpoint_create(o.endpoint);
	__u32 selected = 7;
	xdev_ext_start_frames_opts start{};
	start.sz = sizeof(start); start.nr_batches = batches; start.first_seq = 101;
	start.indices = &selected; start.nr_indices = 1; start.flags = XDEV_EXT_MECH_START_F_RECYCLE;
	if (!ret) ret = xdev_ext_peer_endpoint_start(o.endpoint, &start);
	unsigned long long producer = 0, terminal = 0;
	while (!ret && terminal < batches) {
		xdev_ext_peer_message message;
		ret = xdev_ext_peer_endpoint_next(o.endpoint, 600000, &message);
		if (ret) break;
		int work = gpu_owner_callback(o, message.batch, message.role);
		int done = xdev_ext_peer_endpoint_complete(o.endpoint, &message, work);
		ret = work ? work : done;
		if (!ret && message.role == XDEV_EXT_PEER_PRODUCER) producer++;
		else if (!ret) terminal++;
	}
	xdev_ext_mech_stats stats{};
	if (!ret) ret = xdev_ext_session_wait(xdev_ext_peer_endpoint_session(o.endpoint), 600000, &stats);
	int stopped = o.endpoint ? xdev_ext_peer_endpoint_stop(o.endpoint) : 0;
	int closed = o.endpoint ? xdev_ext_peer_endpoint_close(o.endpoint) : 0;
	printf("PEER_MESSAGE result=%d stop=%d close=%d producer=%llu terminal=%llu batches_done=%llu\n",
		ret, stopped, closed, producer, terminal, (unsigned long long)stats.batches_done);
	fflush(stdout);
	int synchronized = closed ? 0 : CUDA(cuStreamSynchronize(o.stream));
	if (!ret && stopped) ret = stopped;
	if (!ret && closed) ret = closed;
	if (!ret && synchronized) ret = synchronized;
	if (closed || synchronized) {
		/* Keep CUDA allocation, authority and class program alive when native
		 * DMA or GPU last use is unknown. No success or implicit safe cleanup. */
		fputs("PEER_MESSAGE_HELD resources=retained\n", stderr);
		for (;;) pause();
	}
	int detached = xdev_ext_prog_detach(o.program);
	if (!ret && detached) ret = detached;
	if (close(o.allocation) && !ret) ret = -errno;
	if (close(o.control) && !ret) ret = -errno;
	if (close(o.gpu) && !ret) ret = -errno;
	/* Short-circuit at the first CUDA cleanup error. A failed free/destroy
	 * does not authorize destroying the remaining context/resources. */
	if (CUDA(cuMemFree(o.mismatches)) || CUDA(cuMemFree(o.raw)) ||
	    CUDA(cuModuleUnload(o.module)) || CUDA(cuEventDestroy(o.event)) ||
	    CUDA(cuStreamDestroy(o.stream)) || CUDA(cuCtxDestroy(o.context))) {
		if (!ret) ret = -EIO;
		fputs("PEER_MESSAGE_HELD resources=retained\n", stderr);
		for (;;) pause();
	}
	printf("PEER_MESSAGE_CLEANUP result=%d\n", ret);
	return ret || stopped ? 1 : 0;
}

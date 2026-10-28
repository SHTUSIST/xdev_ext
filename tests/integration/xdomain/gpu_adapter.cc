/* SPDX-License-Identifier: GPL-2.0 */
#include "gpu_adapter.h"
#include "xdomain_gpu_pattern.h"
#include <cuda.h>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

struct tb_gpu {
 tb_guard *guard = nullptr;
 CUcontext context = nullptr;
 CUstream stream = nullptr;
 CUmodule module = nullptr;
 CUfunction fill = nullptr, verify = nullptr;
 CUdeviceptr base = 0, address = 0, metadata = 0, summary = 0;
 uint64_t bytes = 0;
 int fd = -1;
 tb_gpu_visibility visibility = TB_GPU_NATIVE_OWNER;
};

static thread_local struct tb_gpu_diagnostic diagnostic = {
 sizeof(struct tb_gpu_diagnostic), TB_GPU_DIAGNOSTIC_VERSION, 0, 0, 0, 0, {0}
};
static void diagnostic_reset()
{
 diagnostic = {};
 diagnostic.size = sizeof(diagnostic);
 diagnostic.version = TB_GPU_DIAGNOSTIC_VERSION;
}
static void diagnostic_operation(const char *name)
{
 if (diagnostic.operation[0]) return;
 size_t len = strcspn(name, "(");
 if (len >= sizeof(diagnostic.operation)) len = sizeof(diagnostic.operation)-1;
 memcpy(diagnostic.operation, name, len);
 diagnostic.operation[len] = 0;
}
static int guard_result(int rc, const char *operation)
{
 if (rc < 0) {
  if (!(diagnostic.flags & TB_GPU_DIAG_GUARD)) diagnostic.guard_error = rc;
  diagnostic.flags |= TB_GPU_DIAG_GUARD;
  diagnostic_operation(operation);
 }
 return rc;
}
static void system_error(const char *operation, int error)
{
 if (!(diagnostic.flags & TB_GPU_DIAG_SYSTEM)) diagnostic.system_errno = error;
 diagnostic.flags |= TB_GPU_DIAG_SYSTEM;
 diagnostic_operation(operation);
}
extern "C" int tb_gpu_last_diagnostic(struct tb_gpu_diagnostic *out)
{
 if (!out || out->size != sizeof(*out) || out->version != TB_GPU_DIAGNOSTIC_VERSION)
  return TB_GPU_UNPROVED;
 *out = diagnostic;
 return TB_GPU_OK;
}

static bool bdf(const char *s, char out[16])
{
 unsigned domain, bus, dev, fn; int used = 0;
 if (!s || sscanf(s, "%x:%x:%x.%x%n", &domain, &bus, &dev, &fn, &used) != 4 ||
     s[used] || domain > 65535 || bus > 255 || dev > 31 || fn > 7) return false;
 snprintf(out, 16, "%04x:%02x:%02x.%x", domain, bus, dev, fn);
 return true;
}
static bool decimal(const std::string &s, unsigned *value)
{
 if (s.empty()) return false;
 unsigned n = 0;
 for (char c : s) {
  if (c < '0' || c > '9' || n > (UINT_MAX - unsigned(c-'0')) / 10) return false;
  n = n * 10 + unsigned(c-'0');
 }
 *value = n; return true;
}
static int node_open(const char *node, const char *pci, tb_gpu *g)
{
 const char *prefix = "/dev/nvidia";
 if (!node || strncmp(node, prefix, strlen(prefix))) return -EINVAL;
 unsigned node_minor;
 if (!decimal(node + strlen(prefix), &node_minor)) return -EINVAL;
 char path[160];
 snprintf(path, sizeof(path), "/proc/driver/nvidia/gpus/%s/information", pci);
 int info = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
 if (info < 0) { system_error("open",errno); return -ENODEV; }
 std::string text; char buf[1024]; bool good = true;
 for (;;) {
  ssize_t n = read(info, buf, sizeof(buf));
  if (n < 0 && errno == EINTR) continue;
  if (n < 0) system_error("read",errno);
  if (n < 0 || text.size() + (n > 0 ? size_t(n) : 0) > 16384) { good = false; break; }
  if (!n) break;
  text.append(buf, size_t(n));
 }
 if (close(info)) { system_error("close",errno); good=false; }
 unsigned found = 0, proc_minor = 0;
 for (size_t off = 0; off < text.size();) {
  size_t end = text.find('\n', off);
  if (end == std::string::npos) end = text.size();
  std::string line = text.substr(off, end-off); off = end+1;
  if (line.compare(0, 13, "Device Minor:") != 0) continue;
  ++found; std::string value = line.substr(13);
  size_t first = value.find_first_not_of(" \t\r");
  size_t last = value.find_last_not_of(" \t\r");
  if (first == std::string::npos || !decimal(value.substr(first, last-first+1), &proc_minor)) good=false;
 }
 if (!good || found != 1 || proc_minor != node_minor) return -ENODEV;
 struct tb_guard_snapshot state{}; tb_guard_snapshot(g->guard, &state);
 if (state.held) return -ECANCELED;
 int fd = open(node, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
 if (fd < 0) { system_error("open",errno); return -ENODEV; }
 struct stat st{};
 int stat_rc = fstat(fd, &st);
 if (stat_rc) system_error("fstat",errno);
 if (stat_rc || !S_ISCHR(st.st_mode) || minor(st.st_rdev) != proc_minor) {
  tb_guard_snapshot(g->guard, &state);
  if (state.held) return fd; // Owner retains even a setup FD on late cancellation.
  if (close(fd)) system_error("close",errno);
  return -ENODEV;
 }
 return fd;
}
static int denied(tb_guard *guard)
{
 struct tb_guard_snapshot s{}; tb_guard_snapshot(guard, &s);
 return s.held ? TB_GPU_HELD : TB_GPU_UNPROVED;
}
static int held(tb_gpu *g)
{
 tb_guard_hold(g->guard, TB_HOLD_CUDA_UNKNOWN);
 return TB_GPU_HELD;
}
static bool live(tb_gpu *g)
{
 struct tb_guard_snapshot s{}; tb_guard_snapshot(g->guard, &s); return !s.held;
}
static int latched_hold(tb_gpu *g)
{
 uint64_t ignored;
 guard_result(tb_guard_begin(g->guard,TB_OP_GPU_CLOSE,&ignored), "tb_guard_begin");
 return TB_GPU_HELD;
}
template <typename Call> static CUresult cuda_call(tb_gpu *g, const char *name, Call call)
{
 if (!live(g)) {
  latched_hold(g);
  return CUDA_ERROR_NOT_READY; // Internal control flow only; not a native result.
 }
 CUresult rc = call();
 if (rc != CUDA_SUCCESS) {
  if (!(diagnostic.flags & TB_GPU_DIAG_CUDA)) diagnostic.cuda_result = int32_t(rc);
  diagnostic.flags |= TB_GPU_DIAG_CUDA;
  diagnostic_operation(name);
 }
 return rc;
}
#define TB_CUDA(call) cuda_call(g, #call, [&]() { return (call); })
/* This path is only used before asynchronous work, or after a successful sync. */
static int safe_end(tb_gpu *g, uint64_t ticket, int error)
{
 int rc = guard_result(tb_guard_end(g->guard, ticket, TB_PHASE_FAILED_SAFE, true, true),"tb_guard_end");
 return rc ? denied(g->guard) : error;
}
extern "C" int tb_gpu_open(tb_gpu **out, tb_guard *guard, const tb_gpu_request *r)
{
 diagnostic_reset();
 if (out) *out = nullptr;
 if (!out || !guard || !r || !r->ptx_path || !*r->ptx_path || !r->registered_bytes ||
     r->registered_bytes > TB_MAX_ALLOCATION) return TB_GPU_UNPROVED;
 uint64_t bytes = (r->registered_bytes + TB_GPU_ALIGN-1) & ~(uint64_t(TB_GPU_ALIGN)-1);
 if (bytes > TB_MAX_ALLOCATION || bytes > SIZE_MAX - (TB_GPU_ALIGN-1)) return TB_GPU_UNPROVED;
 char expected[16], actual[16], canonical[16];
 if (!bdf(r->pci_bdf, expected)) return TB_GPU_UNPROVED;
 uint64_t ticket;
 int rc = guard_result(tb_guard_begin(guard, TB_OP_GPU_OPEN, &ticket),"tb_guard_begin"); if (rc) return denied(guard);
 tb_gpu *g = new(std::nothrow) tb_gpu;
 if (!g) {
  rc = guard_result(tb_guard_end(guard,ticket,TB_PHASE_FAILED_SAFE,true,true),"tb_guard_end");
  return rc ? denied(guard) : TB_GPU_FAILED_SAFE;
 }
 g->guard = guard; g->bytes = bytes;
 *out = g; // Explicit ownership also on failed setup; close requires the guard.
 CUdevice device;
 if (TB_CUDA(cuInit(0)) != CUDA_SUCCESS || TB_CUDA(cuDeviceGetByPCIBusId(&device, expected)) != CUDA_SUCCESS ||
     TB_CUDA(cuDeviceGetPCIBusId(actual, sizeof(actual), device)) != CUDA_SUCCESS ||
     !bdf(actual, canonical) || strcmp(expected, canonical))
  return safe_end(g,ticket,TB_GPU_UNAVAILABLE);
 int supported, ordering, options;
 if (TB_CUDA(cuDeviceGetAttribute(&supported,CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED,device)) != CUDA_SUCCESS ||
     TB_CUDA(cuDeviceGetAttribute(&ordering,CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_WRITES_ORDERING,device)) != CUDA_SUCCESS ||
     TB_CUDA(cuDeviceGetAttribute(&options,CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_FLUSH_WRITES_OPTIONS,device)) != CUDA_SUCCESS)
  return safe_end(g,ticket,TB_GPU_UNAVAILABLE);
 if (supported != 1 || (ordering != CU_GPU_DIRECT_RDMA_WRITES_ORDERING_NONE &&
     ordering != CU_GPU_DIRECT_RDMA_WRITES_ORDERING_OWNER &&
     ordering != CU_GPU_DIRECT_RDMA_WRITES_ORDERING_ALL_DEVICES))
  return safe_end(g,ticket,TB_GPU_UNSUPPORTED);
 if (ordering == CU_GPU_DIRECT_RDMA_WRITES_ORDERING_NONE) {
  if (!(options & CU_FLUSH_GPU_DIRECT_RDMA_WRITES_OPTION_HOST)) return safe_end(g,ticket,TB_GPU_UNSUPPORTED);
  g->visibility = TB_GPU_HOST_FLUSH_OWNER;
 }
 g->fd = node_open(r->nvidia_node, expected, g);
 if (g->fd < 0) return safe_end(g,ticket,TB_GPU_UNAVAILABLE);
 if (!live(g)) return latched_hold(g);
#if CUDA_VERSION >= 13000
 CUresult created = TB_CUDA(cuCtxCreate(&g->context,nullptr,0,device));
#else
 CUresult created = TB_CUDA(cuCtxCreate(&g->context,0,device));
#endif
 if (created != CUDA_SUCCESS ||
     TB_CUDA(cuStreamCreate(&g->stream,CU_STREAM_NON_BLOCKING)) != CUDA_SUCCESS ||
     TB_CUDA(cuMemAlloc(&g->base, size_t(bytes + TB_GPU_ALIGN-1))) != CUDA_SUCCESS)
  return safe_end(g,ticket,TB_GPU_FAILED_SAFE);
 if (g->base > UINT64_MAX-(TB_GPU_ALIGN-1)) return safe_end(g,ticket,TB_GPU_FAILED_SAFE);
 g->address = (g->base + TB_GPU_ALIGN-1) & ~(uint64_t(TB_GPU_ALIGN)-1);
 if (g->address > UINT64_MAX-bytes) return safe_end(g,ticket,TB_GPU_FAILED_SAFE);
 CUmemorytype memory; unsigned managed, sync=1, queried=0; CUcontext owner; int ordinal;
 if (TB_CUDA(cuPointerGetAttribute(&memory,CU_POINTER_ATTRIBUTE_MEMORY_TYPE,g->address)) != CUDA_SUCCESS ||
     TB_CUDA(cuPointerGetAttribute(&managed,CU_POINTER_ATTRIBUTE_IS_MANAGED,g->address)) != CUDA_SUCCESS ||
     TB_CUDA(cuPointerGetAttribute(&owner,CU_POINTER_ATTRIBUTE_CONTEXT,g->address)) != CUDA_SUCCESS ||
     TB_CUDA(cuPointerGetAttribute(&ordinal,CU_POINTER_ATTRIBUTE_DEVICE_ORDINAL,g->address)) != CUDA_SUCCESS ||
     memory != CU_MEMORYTYPE_DEVICE || managed || owner != g->context || ordinal != device ||
     TB_CUDA(cuPointerSetAttribute(&sync,CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,g->address)) != CUDA_SUCCESS ||
     TB_CUDA(cuPointerGetAttribute(&queried,CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,g->address)) != CUDA_SUCCESS || queried != 1 ||
     TB_CUDA(cuModuleLoad(&g->module,r->ptx_path)) != CUDA_SUCCESS ||
     TB_CUDA(cuModuleGetFunction(&g->fill,g->module,TB_PATTERN_FILL_ENTRY)) != CUDA_SUCCESS ||
     TB_CUDA(cuModuleGetFunction(&g->verify,g->module,TB_PATTERN_VERIFY_ENTRY)) != CUDA_SUCCESS)
  return safe_end(g,ticket,TB_GPU_FAILED_SAFE);
 rc = guard_result(tb_guard_end(guard,ticket,TB_PHASE_GPU_READY,true,true),"tb_guard_end");
 return rc ? denied(guard) : TB_GPU_OK;
}
extern "C" int tb_gpu_registration(const tb_gpu *g, struct tb_gpu_registration *out)
{
 if (!g || !out) return TB_GPU_UNPROVED;
 struct tb_guard_snapshot s{}; tb_guard_snapshot(g->guard,&s);
 if (s.held || !s.gpu_safe || !s.native_safe || s.phase != TB_PHASE_GPU_READY) return denied(g->guard);
 if (!g->address || g->fd < 0) return TB_GPU_UNPROVED;
 *out = {g->address,g->bytes,g->fd,uint32_t(g->visibility)}; return 0;
}
extern "C" int tb_gpu_fill(tb_gpu *g, uint64_t seed, bool receiver)
{
 diagnostic_reset();
 if (!g) return TB_GPU_UNPROVED;
 uint64_t ticket; int rc = guard_result(tb_guard_begin(g->guard,TB_OP_GPU_FILL,&ticket),"tb_guard_begin"); if (rc) return denied(g->guard);
 if (TB_CUDA(cuCtxSetCurrent(g->context)) != CUDA_SUCCESS) return held(g);
 uint32_t guard = receiver;
 void *args[] = {&g->address,&g->bytes,&seed,&guard};
 unsigned grid = unsigned((g->bytes+255)/256); if (grid > 65535) grid=65535;
 if (TB_CUDA(cuLaunchKernel(g->fill,grid,1,1,256,1,1,0,g->stream,args,nullptr)) != CUDA_SUCCESS ||
     TB_CUDA(cuStreamSynchronize(g->stream)) != CUDA_SUCCESS) return held(g);
 rc = guard_result(tb_guard_end(g->guard,ticket,TB_PHASE_GPU_READY,true,true),"tb_guard_end");
 return rc ? denied(g->guard) : TB_GPU_OK;
}
extern "C" int tb_gpu_receive_visible(tb_gpu *g)
{
 diagnostic_reset();
 if (!g) return TB_GPU_UNPROVED;
 uint64_t ticket; int rc = guard_result(tb_guard_begin(g->guard,TB_OP_VISIBLE,&ticket),"tb_guard_begin"); if (rc) return denied(g->guard);
 if (TB_CUDA(cuCtxSetCurrent(g->context)) != CUDA_SUCCESS) return held(g);
 if (g->visibility == TB_GPU_HOST_FLUSH_OWNER &&
     TB_CUDA(cuFlushGPUDirectRDMAWrites(CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TARGET_CURRENT_CTX,
                              CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TO_OWNER)) != CUDA_SUCCESS) return held(g);
 rc = guard_result(tb_guard_end(g->guard,ticket,TB_PHASE_DRAINED_SAFE,true,true),"tb_guard_end");
 return rc ? denied(g->guard) : TB_GPU_OK;
}
extern "C" int tb_gpu_verify(tb_gpu *g, const tb_verify_extent *e, size_t nr,
                             uint64_t cookie, tb_verify_result *out)
{
 diagnostic_reset();
 if (g && !live(g)) {
  uint64_t ignored; guard_result(tb_guard_begin(g->guard,TB_OP_GPU_VERIFY,&ignored),"tb_guard_begin");
  return TB_GPU_HELD;
 }
 if (!g || !e || !out || !cookie || !nr || nr > g->bytes/TB_NATIVE_TILE || nr > UINT32_MAX) return TB_GPU_UNPROVED;
 uint64_t end = 0;
 for (size_t i=0;i<nr;++i) {
  if (e[i].reserved || e[i].dst_off != end || !e[i].len || e[i].len > g->bytes-end ||
      (e[i].kind != TB_EXPECT_PAYLOAD && e[i].kind != TB_EXPECT_GUARD) ||
      (e[i].kind == TB_EXPECT_PAYLOAD && e[i].src_off > UINT64_MAX-e[i].len)) return TB_GPU_UNPROVED;
  end += e[i].len;
 }
 if (end != g->bytes) return TB_GPU_UNPROVED;
 uint64_t ticket; int rc = guard_result(tb_guard_begin(g->guard,TB_OP_GPU_VERIFY,&ticket),"tb_guard_begin"); if (rc) return denied(g->guard);
 if (TB_CUDA(cuCtxSetCurrent(g->context)) != CUDA_SUCCESS) return held(g);
 if ((!g->metadata && TB_CUDA(cuMemAlloc(&g->metadata,(g->bytes/TB_NATIVE_TILE)*sizeof(*e))) != CUDA_SUCCESS) ||
     (!g->summary && TB_CUDA(cuMemAlloc(&g->summary,sizeof(*out))) != CUDA_SUCCESS)) return held(g);
 tb_verify_result sentinel{0,UINT64_MAX,0,0};
 if (TB_CUDA(cuMemcpyHtoD(g->metadata,e,nr*sizeof(*e))) != CUDA_SUCCESS ||
     TB_CUDA(cuMemcpyHtoD(g->summary,&sentinel,sizeof(sentinel))) != CUDA_SUCCESS) return held(g);
 uint32_t count = uint32_t(nr);
 void *args[] = {&g->address,&g->bytes,&g->metadata,&count,&cookie,&g->summary};
 if (TB_CUDA(cuLaunchKernel(g->verify,1,1,1,256,1,1,0,g->stream,args,nullptr)) != CUDA_SUCCESS ||
     TB_CUDA(cuStreamSynchronize(g->stream)) != CUDA_SUCCESS ||
     TB_CUDA(cuMemcpyDtoH(out,g->summary,sizeof(*out))) != CUDA_SUCCESS) return held(g);
 if (!live(g)) return latched_hold(g);
 bool valid = out->bytes == g->bytes && out->launch_cookie == cookie &&
              out->mismatches <= g->bytes &&
              (out->mismatches ? out->first_bad < g->bytes : out->first_bad == UINT64_MAX);
 rc=guard_result(tb_guard_end(g->guard,ticket,TB_PHASE_VERIFIED,true,true),"tb_guard_end");
 if (rc) return denied(g->guard);
 return valid && !out->mismatches ? 0 : TB_GPU_UNPROVED;
}
extern "C" int tb_gpu_close(tb_gpu *g)
{
 diagnostic_reset();
 if (!g) return TB_GPU_UNPROVED;
 // Snapshot proves eligible resources; begin is the common admission point.
 // A concurrent HELD between these steps must still make begin fail.
 uint32_t p=tb_guard_cleanup_permissions(g->guard);
 bool missing_permission = (g->base && !(p & TB_CLEANUP_GPU_FREE)) ||
     (g->context && !(p & TB_CLEANUP_CONTEXT_DESTROY)) ||
     (g->fd >= 0 && !(p & TB_CLEANUP_PEER_FD));
 uint64_t ticket; int rc=guard_result(tb_guard_begin(g->guard,TB_OP_GPU_CLOSE,&ticket),"tb_guard_begin"); if (rc) return denied(g->guard);
 if (missing_permission) {
  tb_guard_hold(g->guard,TB_HOLD_PROTOCOL);
  return latched_hold(g);
 }
 if (g->context && TB_CUDA(cuCtxSetCurrent(g->context)) != CUDA_SUCCESS) return held(g);
 if (!live(g)) return latched_hold(g);
 if (g->metadata && TB_CUDA(cuMemFree(g->metadata)) != CUDA_SUCCESS) return held(g);
 g->metadata=0;
 if (!live(g)) return latched_hold(g);
 if (g->summary && TB_CUDA(cuMemFree(g->summary)) != CUDA_SUCCESS) return held(g);
 g->summary=0;
 if (!live(g)) return latched_hold(g);
 if (g->base && TB_CUDA(cuMemFree(g->base)) != CUDA_SUCCESS) return held(g);
 g->base=0;
 if (!live(g)) return latched_hold(g);
 if (g->module && TB_CUDA(cuModuleUnload(g->module)) != CUDA_SUCCESS) return held(g);
 g->module=nullptr;
 if (!live(g)) return latched_hold(g);
 if (g->stream && TB_CUDA(cuStreamDestroy(g->stream)) != CUDA_SUCCESS) return held(g);
 g->stream=nullptr;
 if (!live(g)) return latched_hold(g);
 if (g->context && TB_CUDA(cuCtxDestroy(g->context)) != CUDA_SUCCESS) return held(g);
 g->context=nullptr;
 if (!live(g)) return latched_hold(g);
 if (g->fd >= 0 && close(g->fd)) {
  system_error("close",errno);
  return held(g);
 }
 g->fd=-1;
 rc=guard_result(tb_guard_end(g->guard,ticket,TB_PHASE_CLOSED,true,true),"tb_guard_end");
 if (rc) return denied(g->guard);
 delete g; return 0;
}

// SPDX-License-Identifier: GPL-2.0
// Driver ABI only: no CUDA runtime/PyTorch CUDA headers or .cu compilation.
#include <torch/extension.h>
#include <ATen/ATen.h>
#include <cuda.h>
#include "xdev_tp.h"
#include "peer_endpoint_owner.h"
#include <cerrno>
#include <chrono>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace py = pybind11;
namespace {
struct TensorPlan {
  std::vector<int64_t> shape;
  uint64_t rows = 1, width = 0;
  xdev_tp_dtype dtype;
  bool output = true;
};
uint64_t mul(uint64_t a, uint64_t b) {
  TORCH_CHECK(!b || a <= uint64_t(std::numeric_limits<int64_t>::max()) / b,
              "xdev TP tensor size overflow");
  return a * b;
}
TensorPlan plan(const at::Tensor &input, const py::dict &cfg,
                const std::string &operation, int dim, int dst) {
  auto rank = cfg["rank"].cast<unsigned>();
  TORCH_CHECK(cfg["world_size"].cast<unsigned>() == 2 && rank < 2,
              "xdev TP requires exactly two ranks");
  TORCH_CHECK(input.defined() && input.is_cuda() && input.layout() == at::kStrided &&
              input.is_contiguous(), "xdev TP requires contiguous CUDA Tensor storage");
  TORCH_CHECK(input.get_device() == cfg["device_index"].cast<int>(),
              "Tensor device differs from admitted communicator");
  TensorPlan p;
  switch (input.scalar_type()) {
    case at::kHalf: p.dtype = XDEV_TP_F16; break;
    case at::kBFloat16: p.dtype = XDEV_TP_BF16; break;
    case at::kFloat: p.dtype = XDEV_TP_F32; break;
    default: TORCH_CHECK(false, "xdev TP supports F16/BF16/F32 only");
  }
  TORCH_CHECK(dst == 0 || dst == 1, "invalid TP destination");
  p.shape = input.sizes().vec();
  uint64_t elements = 1;
  for (auto n : p.shape) elements = mul(elements, uint64_t(n));
  const uint64_t bytes = mul(elements, input.element_size());
  TORCH_CHECK(bytes <= cfg["max_payload_bytes"].cast<uint64_t>() && bytes <= UINT32_MAX,
              "Tensor payload exceeds admitted native capacity");
  if (operation == "all_reduce") {
    p.width = elements;
  } else {
    TORCH_CHECK(operation == "gather" || operation == "all_gather", "unsupported operation");
    TORCH_CHECK(input.dim() > 0 && (dim == -1 || dim == input.dim()-1),
                "xdev TP gather supports the last dimension only");
    p.width = uint64_t(p.shape.back());
    p.shape.back() = int64_t(mul(p.width, 2));
    for (int64_t i = 0; i+1 < input.dim(); ++i) p.rows = mul(p.rows, uint64_t(input.size(i)));
    (void)mul(mul(elements, 2), input.element_size());
    p.output = operation == "all_gather" || int(rank) == dst;
  }
  return p;
}
py::object output_shape(const TensorPlan &p) {
  if (!p.output) return py::none();
  return py::cast(p.shape);
}
py::dict work_stats(xdev_tp_work *work) {
  xdev_tp_work_stats s{}; s.size = sizeof(s); s.version = XDEV_TP_ABI_VERSION;
  int rc = xdev_tp_work_get_stats(work, &s);
  TORCH_CHECK(!rc, "xdev TP work statistics failed: ", rc);
  py::dict d;
#define FIELD(name) d[#name] = s.name
  FIELD(state); FIELD(invocations); FIELD(completed); FIELD(failed);
  FIELD(first_sequence); FIELD(last_sequence); FIELD(payload_bytes); FIELD(wire_bytes);
  FIELD(error); FIELD(retained);
#undef FIELD
  return d;
}
struct Work {
  xdev_tp_work *handle;
  // at::Tensor owns its StorageImpl; raw data_ptr alone would be insufficient.
  at::Tensor input, output;
  std::string operation;
  std::vector<int64_t> shape;
  int dtype, dst;
};
struct State {
  xdev_tp_config cfg{};
  xdev_tp_comm *comm = nullptr;
  xdev_ext_cuda_peer_owner *endpoint_owner = nullptr;
  py::dict settings;
  py::object owner;
  std::string ptx;
  uint64_t setup_sequence = 0;
  CUstream bound_stream = nullptr;
  bool stream_bound = false;
  std::vector<Work> works;
  py::list finished;
  py::dict final_stats;
  explicit State(py::dict d, py::object o): settings(d), owner(o) {}
};
py::dict summary(const Work &w) {
  py::dict d = work_stats(w.handle);
  d["operation"] = w.operation; d["input_shape"] = w.shape;
  d["dtype"] = w.dtype; d["dst"] = w.dst;
  return d;
}
void outside_capture(const State &s) {
  if (!s.stream_bound) return;
  CUstreamCaptureStatus capture;
  TORCH_CHECK(cuStreamIsCapturing(s.bound_stream, &capture) == CUDA_SUCCESS &&
                capture == CU_STREAM_CAPTURE_STATUS_NONE,
              "statistics/storage release must run outside CUDA graph capture");
}
// Never call during stream capture. work_destroy checks actual CUDA graph user
// ownership and completion; query==success by itself cannot release graph refs.
void reap(State &s) {
  for (auto it = s.works.begin(); it != s.works.end();) {
    auto report = summary(*it);
    s.finished.append(report); // allocate the summary before native destruction
    const int rc = xdev_tp_work_destroy(it->handle);
    if (rc == 0) {
      it = s.works.erase(it);
    } else {
      s.finished.attr("pop")();
      ++it; // pending or stable error: Tensor and endpoint owner remain in custody.
    }
  }
}
py::dict statistics(State &s) {
  if (!s.comm) return s.final_stats;
  outside_capture(s);
  xdev_tp_stats v{}; v.size = sizeof(v); v.version = XDEV_TP_ABI_VERSION;
  const int rc = xdev_tp_get_stats(s.comm, &v);
  TORCH_CHECK(!rc, "xdev TP statistics failed: ", rc);
  py::dict d;
#define FIELD(name) d[#name] = v.name
  FIELD(rank); FIELD(api_attempts); FIELD(preflight_rejected);
  FIELD(attempts); FIELD(submitted); FIELD(completed); FIELD(failed);
  FIELD(tx_done); FIELD(rx_delivered); FIELD(last_use_released);
  FIELD(first_sequence); FIELD(last_sequence);
  FIELD(payload_tx_bytes); FIELD(payload_rx_bytes); FIELD(wire_tx_bytes); FIELD(wire_rx_bytes);
  FIELD(logical_inflight); FIELD(logical_inflight_high_water);
  FIELD(gpu_invocations); FIELD(host_control_calls); FIELD(trace_dropped);
  FIELD(fallback_calls); FIELD(error); FIELD(retained);
#undef FIELD
  py::list detail;
  for (auto item : s.finished) detail.append(item);
  for (const auto &w : s.works) detail.append(summary(w));
  d["work_statistics"] = detail;
  d["storage_custody_count"] = s.works.size();
  if (s.cfg.mode == XDEV_TP_D2_GPU && v.last_sequence) {
    TORCH_CHECK(v.last_sequence != UINT64_MAX, "collective sequence exhausted");
    s.setup_sequence = v.last_sequence + 1;
  }
  return d;
}
int close_native(State &s, bool drain = false) {
  if (s.comm) {
    outside_capture(s);
    const auto start = std::chrono::steady_clock::now();
    for (;;) {
      reap(s);
      if (s.works.empty()) break;
      for (const auto &work : s.works) {
        const int rc = xdev_tp_work_query(work.handle);
        if (rc < 0) return rc;
      }
      if (!drain || !s.cfg.timeout_ns) return -EBUSY;
      const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - start).count();
      if (uint64_t(elapsed) >= s.cfg.timeout_ns) return -ETIMEDOUT;
      // A graph user-object callback may release its last reference after
      // graph destruction returns. Only actual work_destroy success releases
      // Tensor storage; timeout/external references preserve the whole registry.
      std::this_thread::yield();
    }
    s.final_stats = statistics(s);
    int rc = xdev_tp_destroy(s.comm, s.cfg.timeout_ns);
    if (rc) return rc;
    s.comm = nullptr;
  }
  if (s.endpoint_owner) {
    int rc = xdev_ext_cuda_peer_owner_close(&s.endpoint_owner);
    if (rc) {
      s.final_stats["retained"] = 1; s.final_stats["error"] = rc;
      return rc;
    }
  }
  s.owner = py::none();
  return 0;
}

class Communicator {
  std::unique_ptr<State> s_;
  struct Internal {};
  explicit Communicator(Internal): s_(new State(py::dict(), py::none())) {}
  void preserve_on_failure() noexcept {
    if (!s_ || (!s_->comm && !s_->endpoint_owner)) return;
    try { if (close_native(*s_) == 0) return; } catch (...) {}
    (void)s_.release();
  }
  void initialize(py::dict config) {
    s_->settings = config.attr("copy")().cast<py::dict>();
    auto &s = *s_;
    auto &c = s.cfg;
    c.size = sizeof(c); c.version = XDEV_TP_ABI_VERSION;
#define NUMBER(field, type) c.field = config[#field].cast<type>()
    NUMBER(rank, uint32_t); NUMBER(world_size, uint32_t); NUMBER(mode, uint32_t);
    NUMBER(tx_va, CUdeviceptr); NUMBER(rx_va, CUdeviceptr);
    NUMBER(tx_bytes, uint64_t); NUMBER(rx_bytes, uint64_t);
    NUMBER(frame_size, uint32_t); NUMBER(logical_depth, uint32_t);
    NUMBER(max_payload_bytes, uint64_t); NUMBER(first_sequence, uint64_t);
    NUMBER(communicator_id, uint64_t); NUMBER(epoch, uint64_t); NUMBER(timeout_ns, uint64_t);
#undef NUMBER
    c.context = reinterpret_cast<CUcontext>(config["context"].cast<uintptr_t>());
    c.tx_endpoint = reinterpret_cast<xdev_ext_peer_endpoint *>(config["tx_endpoint"].cast<uintptr_t>());
    c.rx_endpoint = reinterpret_cast<xdev_ext_peer_endpoint *>(config["rx_endpoint"].cast<uintptr_t>());
    c.trace_capacity = config.contains("trace_capacity") ? config["trace_capacity"].cast<uint32_t>() : 0;
    TORCH_CHECK(!config.contains("flags") || config["flags"].cast<unsigned>() == 0,
                "unsupported native configuration flags");
    TORCH_CHECK(!config.contains("version") ||
                  config["version"].cast<unsigned>() == XDEV_TP_ABI_VERSION,
                "unsupported native ABI version");
    c.flags = 0;
    if (c.mode == XDEV_TP_D2_GPU) {
      c.d2_tx_producer = reinterpret_cast<xdev_ext_cuda_user *>(config["d2_tx_producer"].cast<uintptr_t>());
      c.d2_tx_terminal = reinterpret_cast<xdev_ext_cuda_user *>(config["d2_tx_terminal"].cast<uintptr_t>());
      c.d2_rx_consumer = reinterpret_cast<xdev_ext_cuda_user *>(config["d2_rx_consumer"].cast<uintptr_t>());
    }
    s.ptx = config["ptx_path"].cast<std::string>(); c.ptx_path = s.ptx.c_str();
    TORCH_CHECK(c.world_size == 2 && c.rank < 2 &&
                  (c.mode == XDEV_TP_D1_EAGER || c.mode == XDEV_TP_D2_GPU),
                "unsupported TP rank/world/mode");
    CUdevice device;
    TORCH_CHECK(cuCtxGetDevice(&device) == CUDA_SUCCESS &&
                  int(device) == config["device_index"].cast<int>(),
                "admitted CUDA context device differs from Tensor device");
    const int rc = xdev_tp_create(&c, &s.comm);
    TORCH_CHECK(!rc, "xdev TP creation failed: ", rc);
    s.setup_sequence = c.first_sequence;
  }
public:
  Communicator(py::dict config, py::object owner): s_(new State(config, owner)) {
    TORCH_CHECK(!owner.is_none(), "endpoint/context owner reference required");
    try { initialize(config); } catch (...) { preserve_on_failure(); throw; }
  }
  static std::unique_ptr<Communicator> from_options(py::dict options, uint64_t stream_handle,
                                                   py::object stream_owner) {
    auto result = std::unique_ptr<Communicator>(new Communicator(Internal{}));
    auto &s = *result->s_;
    TORCH_CHECK(!stream_owner.is_none(), "actual CUDA stream owner reference required");
    s.owner = stream_owner;
    for (const char *key : {"context", "stream", "tx_endpoint", "rx_endpoint", "tx_va",
                            "rx_va", "d2_tx_producer", "d2_tx_terminal", "d2_rx_consumer"})
      TORCH_CHECK(!options.contains(key), "serialized process-local pointers are not admission input");
    auto rank = options["rank"].cast<unsigned>();
    TORCH_CHECK(rank < 2 && options["world_size"].cast<unsigned>() == 2,
                "bootstrap requires rank 0/1 and world_size 2");
    xdev_ext_cuda_peer_owner_opts o{}; o.size = sizeof(o); o.version = 1;
    o.mode = options["mode"].cast<uint32_t>();
    o.context_mode = XDEV_EXT_CUDA_PEER_BORROW_CURRENT;
    o.device = options["device_index"].cast<uint32_t>();
    TORCH_CHECK(cuCtxGetCurrent(&o.context) == CUDA_SUCCESS && o.context,
                "bootstrap requires the actual current PyTorch CUDA context");
    CUdevice actual_device;
    TORCH_CHECK(cuCtxGetDevice(&actual_device) == CUDA_SUCCESS &&
                  actual_device == int(o.device), "bootstrap CUDA device mismatch");
    o.stream = reinterpret_cast<CUstream>(uintptr_t(stream_handle));
    std::string node = options["nvidia_node"].cast<std::string>();
    std::string bpf = options["bpf_object"].cast<std::string>();
    std::string user_bpf = options["user_bpf_object"].cast<std::string>();
    o.nvidia_node = node.c_str(); o.bpf_object = bpf.c_str();
    o.user_bpf_object = user_bpf.c_str();
#define OPTION(field, type) o.field = options[#field].cast<type>()
    OPTION(link_token, uint64_t); OPTION(allocation_bytes, uint64_t);
    OPTION(nr_batches, uint64_t); OPTION(first_sequence, uint64_t); OPTION(timeout_ns, uint64_t);
    OPTION(group_bytes, uint32_t); OPTION(depth, uint32_t);
#undef OPTION
    const auto payload = options["max_payload_bytes"].cast<uint64_t>();
    const auto id = options["communicator_id"].cast<uint64_t>();
    const auto epoch = options["epoch"].cast<uint64_t>();
    TORCH_CHECK(o.group_bytes >= 64 && payload <= o.group_bytes-64 && id && epoch,
                "bootstrap payload/namespace does not fit actual geometry");
    int rc = xdev_ext_cuda_peer_owner_open(&o, &s.endpoint_owner);
    TORCH_CHECK(!rc, "native endpoint bootstrap failed; partial ownership retained: ", rc);
    xdev_ext_cuda_peer_owner_view v{}; v.size = sizeof(v);
    rc = xdev_ext_cuda_peer_owner_get_view(s.endpoint_owner, &v);
    TORCH_CHECK(!rc, "native endpoint view failed: ", rc);
    py::dict cfg;
    cfg["version"] = XDEV_TP_ABI_VERSION; cfg["rank"] = rank; cfg["world_size"] = 2;
    cfg["mode"] = o.mode; cfg["device_index"] = o.device;
    cfg["context"] = reinterpret_cast<uintptr_t>(v.context);
    cfg["tx_endpoint"] = reinterpret_cast<uintptr_t>(v.tx_endpoint);
    cfg["rx_endpoint"] = reinterpret_cast<uintptr_t>(v.rx_endpoint);
    cfg["tx_va"] = v.tx_va; cfg["rx_va"] = v.rx_va;
    cfg["tx_bytes"] = v.allocation_bytes; cfg["rx_bytes"] = v.allocation_bytes;
    cfg["frame_size"] = v.frame_size; cfg["logical_depth"] = o.depth;
    cfg["max_payload_bytes"] = payload; cfg["first_sequence"] = o.first_sequence;
    cfg["communicator_id"] = id; cfg["epoch"] = epoch; cfg["timeout_ns"] = o.timeout_ns;
    cfg["ptx_path"] = options["ptx_path"];
    if (options.contains("trace_capacity")) cfg["trace_capacity"] = options["trace_capacity"];
    if (o.mode == XDEV_TP_D2_GPU) {
      cfg["d2_tx_producer"] = reinterpret_cast<uintptr_t>(v.tx_producer);
      cfg["d2_tx_terminal"] = reinterpret_cast<uintptr_t>(v.tx_terminal);
      cfg["d2_rx_consumer"] = reinterpret_cast<uintptr_t>(v.rx_consumer);
    }
    result->initialize(cfg);
    s.bound_stream = o.stream; s.stream_bound = true;
    rc = xdev_ext_cuda_peer_owner_start(s.endpoint_owner);
    TORCH_CHECK(!rc, "native endpoint START failed; resources retained: ", rc);
    return result;
  }
  ~Communicator() {
    // Actual Tensor/stream/endpoint ownership outlives Python wrappers whenever
    // native close cannot establish quiescence. No destructor invents success.
    preserve_on_failure();
  }
  py::object submit(at::Tensor input, uint64_t handle, const std::string &op, int dst) {
    auto &s = *s_; TORCH_CHECK(s.comm, "xdev TP communicator is closed");
    TensorPlan p = plan(input, s.settings, op, -1, dst);
    auto stream = reinterpret_cast<CUstream>(uintptr_t(handle));
    CUstreamCaptureStatus capture;
    TORCH_CHECK(cuStreamIsCapturing(stream, &capture) == CUDA_SUCCESS,
                "cannot qualify actual caller stream capture state");
    const bool capturing = capture != CU_STREAM_CAPTURE_STATUS_NONE;
    TORCH_CHECK(!capturing || s.cfg.mode == XDEV_TP_D2_GPU,
                "d1 does not support CUDA graph capture");
    if (!capturing) { reap(s); (void)statistics(s); }
    at::Tensor output;
    if (p.output) output = at::empty(p.shape, input.options());
    // Allocate all custody bookkeeping before any possible native side effect.
    s.works.push_back({nullptr, input, output, op, input.sizes().vec(), int(p.dtype), dst});
    Work &custody = s.works.back();
    xdev_tp_work *work = nullptr;
    const CUdeviceptr in = reinterpret_cast<uintptr_t>(input.data_ptr());
    const CUdeviceptr out = output.defined() ? reinterpret_cast<uintptr_t>(output.data_ptr()) : 0;
    int rc;
    if (op == "all_reduce") {
      rc = xdev_tp_allreduce_sum(s.comm, in, out, p.width, p.dtype, stream, s.setup_sequence, &work);
    } else {
      rc = xdev_tp_logits_gather(s.comm, in, out, p.rows, p.width, p.dtype, dst,
                                op == "all_gather", stream, s.setup_sequence, &work);
    }
    // The handle may be returned with a stable accepted error: retain it before
    // raising. A failed Python call is never permission to retry native I/O.
    if (work) {
      custody.handle = work;
      s.bound_stream = stream; s.stream_bound = true;
      if (s.cfg.mode == XDEV_TP_D1_EAGER && !rc) {
        TORCH_CHECK(s.setup_sequence != UINT64_MAX, "collective sequence exhausted");
        ++s.setup_sequence;
      }
    } else {
      s.works.pop_back(); // no accepted handle: no native custody was transferred
    }
    TORCH_CHECK(!rc, "xdev TP collective failed (no fallback): ", rc);
    TORCH_CHECK(work, "native submit returned no accepted work handle");
    if (!capturing) reap(s);
    return output.defined() ? py::cast(output) : py::none();
  }
  py::object all_reduce(at::Tensor input, uint64_t stream) {
    return submit(input, stream, "all_reduce", 0);
  }
  py::object gather(at::Tensor input, uint64_t stream, int dst, bool all_gather) {
    return submit(input, stream, all_gather ? "all_gather" : "gather", dst);
  }
  void wait(uint64_t timeout) {
    auto &s = *s_; TORCH_CHECK(s.comm, "xdev TP communicator is closed");
    outside_capture(s);
    const auto start = std::chrono::steady_clock::now();
    for (;;) {
      // In particular, do not wait forever on a captured template that never
      // ran: actual graph-release and no-entry proof can make destroy safe.
      reap(s);
      bool pending = false;
      for (const auto &work : s.works) {
        const int rc = xdev_tp_work_query(work.handle);
        TORCH_CHECK(rc >= 0, "native completion wait failed; work retained: ", rc);
        pending = pending || rc == 1;
      }
      if (!pending) return; // close separately requires graph future-use release
      const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - start).count();
      TORCH_CHECK(!timeout || uint64_t(elapsed) < timeout,
                  "native completion wait timed out; work retained");
      std::this_thread::yield();
    }
  }
  py::dict stats() { return statistics(*s_); }
  size_t retained_work_count() const { return s_->works.size(); }
  void close() {
    const int rc = close_native(*s_, true);
    TORCH_CHECK(!rc, "xdev TP close retained live work/resources: ", rc);
  }
};
}
PYBIND11_MODULE(TORCH_EXTENSION_NAME, m) {
  m.def("qualify_tensor", [](const at::Tensor &t, py::dict config,
                            const std::string &op, int dim, int dst) {
    auto p = plan(t, config, op, dim, dst);
    py::dict result; result["output_shape"] = output_shape(p);
    result["rows"] = p.rows; result["width"] = p.width;
    return result;
  }, py::arg("tensor"), py::arg("config"), py::arg("operation"),
     py::arg("dim") = -1, py::arg("dst") = 0);
  py::class_<Communicator>(m, "Communicator")
    .def(py::init<py::dict, py::object>())
    .def_static("from_options", &Communicator::from_options)
    .def("all_reduce", &Communicator::all_reduce)
    .def("gather", &Communicator::gather)
    .def("stats", &Communicator::stats)
    .def("wait", &Communicator::wait)
    .def("retained_work_count", &Communicator::retained_work_count)
    .def("close", &Communicator::close);
}

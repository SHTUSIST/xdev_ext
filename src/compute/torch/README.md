# PyTorch Tensor bridge

This package passes contiguous CUDA F16/BF16/F32 tensors to the Driver API
collective library. It requires torch 2.8.0 and two ranks. All-reduce is
out-of-place sum; gather and all-gather concatenate rank 0 followed by rank 1
inside each row of the final dimension, preserving the leading dimensions.
Non-destination gather returns `None` after participating in the native operation.

Build the native collective library first, then use:

```sh
python tools/build/tp_framework.py --cuda-home /path/to/cuda \
  --native-library /path/to/native/libxdev_tp.so --out /path/to/framework
```

Use the Python interpreter containing the required torch installation. The
builder uses GCC and `CppExtension`, compiles no CUDA runtime source, and links
against the independent Driver library. It compiles and links without importing
its result. CUDA link stubs are never execution libraries. Runtime loading
requires the real NVIDIA driver and the native library's runtime dependencies.
The build receipt identifies canonical sources and the generated native header
view; it separately records that execution has not run.

`TorchCommunicator.from_options(options)` is the default production bootstrap.
It accepts the rank-local scalar/path options documented with the vLLM plugin,
opens the shared production endpoint owner, borrows the actual current PyTorch
context, creates native TP, then starts endpoints. It owns a persistent
nondefault stream and scopes eager calls with event dependencies from and back
to the actual caller stream. It restores the caller's stream on return. The
native owner stays alive through partial failures and closes only after TP,
work and graph users are gone.

Optional `early_cts` (0 or 1, default 0) opens both endpoints with
`XDEV_EXT_PEER_ENDPOINT_F_EARLY` through `xdev_ext_cuda_peer_owner_open_flags`
or `xdev_ext_cuda_peer_owner_open_programs`. Both ranks must request the same
value; the agreement check rejects a mismatch before either owner opens.

Optional `frames` (`peer` or `host`, default `peer`) chooses the transport.
`host` opens `xdev_ext_cuda_frame_owner` (`src/compute/cuda/frame_endpoint_owner.h`)
on the current context and stream instead of the PEER owner and creates the
communicator with `XDEV_TP_F_HOST_FRAMES`; it is d1 only and needs
`ce_bpf_object`. Both ranks must request the same value.

Optional `tx_program_pins` and `rx_program_pins` arrays select existing PRIVATE
struct_ops link pins per stage. TX has three entries: USER producer, XDOMAIN
TX, USER terminal. RX has two: XDOMAIN RX, USER consumer. A null entry keeps
that stage's global default; an absent array is all null. For example:

```json
{"tx_program_pins": ["/sys/fs/bpf/tx-producer", "/sys/fs/bpf/tx-link", null],
 "rx_program_pins": ["/sys/fs/bpf/rx-link", "/sys/fs/bpf/rx-consumer"]}
```

Only PRIVATE pin paths must be absolute. `bpf_object` is required when either
XDOMAIN entry is null; `user_bpf_object` is required when any USER entry is
null. When all entries of a class are PRIVATE its object may be absent or
null, and no global object of that class is attached. Existing relative ELF
paths stay valid. Pin paths are rank-local and are not cross-rank agreement
fields. An explicit selection error never falls back to a global program.
The owner holds one link FD reference per explicit entry through partial or
retained close; it never unpins or detaches another owner's supplied link.

Native C/C++ callers use the additive `xdev_ext_cuda_peer_owner_open_programs`
API with `XDEV_EXT_CUDA_PEER_PROGRAMS_OPTS_INIT`; old owner option layouts and
open APIs retain their behavior. The standalone TP driver accepts the five
corresponding flags `--tx-producer-program-pin`, `--tx-xdomain-program-pin`,
`--tx-terminal-program-pin`, `--rx-xdomain-program-pin` and
`--rx-consumer-program-pin`, independently of `--early-cts`.

The advanced `TorchCommunicator(config, owner)` borrows already admitted endpoints, context
and CUDA controls from the `owner`. The config keys match `xdev_tp_config`:
`rank`, `world_size`, `mode`, `context`, `tx_endpoint`, `rx_endpoint`, `tx_va`,
`rx_va`, `tx_bytes`, `rx_bytes`, `frame_size`, `logical_depth`,
`max_payload_bytes`, `first_sequence`, `communicator_id`, `epoch`, `timeout_ns`
and `ptx_path`. `device_index` identifies the associated PyTorch CUDA device.
`trace_capacity` defaults to zero. `template_capacity` (1 to 1,048,576)
sets the native template pool; absent or zero keeps 256. In GPU mode the keys `d2_tx_producer`,
`d2_tx_terminal` and `d2_rx_consumer` supply the borrowed CUDA control pointers.
Pointers are process-local handles from actual admission, never serialized
handles from another process. Numeric pointers alone do not prove authority.

The native ABI remains version 1 with append-only configuration fields. Both
the original prefix (`XDEV_TP_CONFIG_SIZE_V1_BASE`) and the graph-cap prefix
(`XDEV_TP_CONFIG_SIZE_V1_GRAPH`) remain accepted; fields after the caller's
declared size are zero-filled. Host-frame endpoint pointers follow the graph
capacity fields, so a pre-host-frame caller keeps its requested template pool.

The Python adapter obtains `torch.cuda.current_stream(tensor.device).cuda_stream`
inside the tensor's device context. The Driver library independently qualifies
that stream and context. No wrapper substitutes a hardcoded default stream. The default bootstrap uses
its admitted owned stream with explicit event dependencies; advanced borrowed
communicators use the actual caller stream directly. Eager d1 is
host-synchronous and rejects capture. In d2, capture-time arguments are setup
checks; the native GPU counter supplies actual invocation sequences on replay.

Use `all_reduce(tensor)`, `all_gather(tensor, dim=-1)` or
`gather(tensor, dst=0, dim=-1)`. Unsupported inputs fail before native submission.
There is no fallback after an accepted operation. Fake/meta calls perform shape
propagation without native submission or runtime counters.

One native message carries at most `max_payload_bytes`, and the native group
holds at most 32 frames of 4 KiB, so a message never exceeds 128 KiB minus the
64-byte header. An all-reduce larger than `max_payload_bytes` is split into
consecutive element ranges of `max_payload_bytes // itemsize` elements (the
last range may be shorter). Each range is a complete native all-reduce with its
own sequence, written into the matching range of one output tensor. Both ranks
derive the same split from the agreed geometry; the elementwise sum makes each
range independent. d1 submits one range per native call. d2 submits windows of
at most the logical depth through `xdev_tp_submit_batch`, so every TX in a
window is published before its receives. Each range consumes one native batch
of the finite START count (`nr_batches`). The only rejected all-reduce geometry
is a `max_payload_bytes` smaller than one element. Gather and all-gather remain
exactly one message and are rejected when larger.

Each accepted range holds one of the communicator's native work templates
until it completes and is destroyed. The pool has `template_capacity` templates
(default 256, at most 1,048,576), each 4,984 bytes of device memory allocated
and zeroed when the communicator is created, never during capture. CUDA graph
capture keeps every captured range's template while the graph lives, so size
the pool for every graph kept at once: `xdev_tp_torch.policy.capture_template_budget`
computes it from the capture sizes, hidden size, all-reduces per forward and
`max_payload_bytes`. With vLLM 0.10.2 defaults on a 32 GB GPU (67 piecewise
capture sizes 1, 2, 4, 8..512; 131,008-byte messages) Qwen3-32B (129 all-reduces
per forward) needs 172,731 templates (about 861 MB per rank) and Qwen3-30B-A3B
(97 per forward) needs 54,611 (about 272 MB); one batch-1 forward alone needs
129 and 97, and one batch-16 Qwen3-32B forward 258. Outside capture, the adapter reserves
templates before each window; in eager d2 this waits until earlier accepted work
on the stream has completed. During CUDA graph capture every range keeps its
template while the graph lives, so a split all-reduce whose range count exceeds
the free templates is rejected before any native call and no partial collective
is recorded. `stats()["framework"]` reports `segmented_calls` and
`segments_submitted`.

`synchronize(timeout_ns=...)` waits on actual native work and reports stable
errors. Timeout preserves work and storage; it does not revoke transport or
retry a collective. `stats()` returns both framework preflight accounting and
native invocation/custody counters, plus actual per-work dtype/shape/sequence
statistics. Call statistics and synchronization outside stream capture.

Call `close()` before releasing the endpoint owner. Actual `at::Tensor`
references keep input/output storage alive until `xdev_tp_work_destroy` succeeds.
A completed captured template still holds references while CUDA graph/exec
objects can replay it. Release caller-owned graph/exec references before
closing the communicator. Explicit close waits for actual native graph-release callbacks
up to its configured timeout; it preserves storage and owners on failure.
If Python drops a communicator whose native work cannot be released, the bridge deliberately preserves its
state and owner for the process lifetime rather than freeing unknown users.

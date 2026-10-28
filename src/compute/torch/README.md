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

The advanced `TorchCommunicator(config, owner)` borrows already admitted endpoints, context
and CUDA controls from the `owner`. The config keys match `xdev_tp_config`:
`rank`, `world_size`, `mode`, `context`, `tx_endpoint`, `rx_endpoint`, `tx_va`,
`rx_va`, `tx_bytes`, `rx_bytes`, `frame_size`, `logical_depth`,
`max_payload_bytes`, `first_sequence`, `communicator_id`, `epoch`, `timeout_ns`
and `ptx_path`. `device_index` identifies the associated PyTorch CUDA device.
`trace_capacity` defaults to zero. In GPU mode the keys `d2_tx_producer`,
`d2_tx_terminal` and `d2_rx_consumer` supply the borrowed CUDA control pointers.
Pointers are process-local handles from actual admission, never serialized
handles from another process. Numeric pointers alone do not prove authority.

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

`synchronize(timeout_ns=...)` waits on actual native work and reports stable
errors. Timeout preserves work and storage; it does not revoke transport or
retry a collective. `stats()` returns both framework preflight accounting and
native invocation/custody counters, plus actual per-work dtype/shape/sequence
statistics. Call statistics and synchronization outside stream capture.

Call `close()` before releasing the endpoint owner. Actual `at::Tensor`
references keep input/output storage alive until `xdev_tp_work_destroy` succeeds.
A completed captured template still holds references while CUDA graph/exec
objects can replay it. Destroy/reset those graph objects before closing the
communicator. A failed close retains resources. If Python drops a communicator
whose native work cannot be released, the bridge deliberately preserves its
state and owner for the process lifetime rather than freeing unknown users.
